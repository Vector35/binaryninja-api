use binaryninja::{
    architecture::{Architecture as _, CoreRegister, Register as _, RegisterInfo as _},
    binary_view::{BinaryView, BinaryViewExt as _},
    low_level_il::{
        expression::{ExpressionHandler, LowLevelILExpressionKind},
        function::{LowLevelILFunction, Mutable, NonSSA},
        instruction::{
            InstructionHandler, LowLevelILInstruction, LowLevelILInstructionKind,
            LowLevelInstructionIndex,
        },
        lifting::LowLevelILLabel,
        LowLevelILRegisterKind,
    },
    variable::PossibleValueSet,
    workflow::AnalysisContext,
};

use crate::{error::ILLevel, metadata::GlobalState, Error};

// TODO: We should also handle `objc_retain_x` / `objc_release_x` variants
// that use a custom calling convention.
const IGNORABLE_MEMORY_MANAGEMENT_FUNCTIONS: &[&[u8]] = &[
    b"_objc_autorelease",
    b"_objc_autoreleaseReturnValue",
    b"_objc_release",
    b"_objc_retain",
    b"_objc_retainAutorelease",
    b"_objc_retainAutoreleaseReturnValue",
    b"_objc_retainAutoreleasedReturnValue",
    b"_objc_retainBlock",
    b"_objc_unsafeClaimAutoreleasedReturnValue",
];

fn is_call_to_ignorable_memory_management_function<'func>(
    view: &binaryninja::binary_view::BinaryView,
    instr: &'func LowLevelILInstruction<'func, Mutable, NonSSA>,
) -> bool {
    let target = match instr.kind() {
        LowLevelILInstructionKind::Call(call) | LowLevelILInstructionKind::TailCall(call) => {
            match call.target().possible_values() {
                PossibleValueSet::ConstantValue { value }
                | PossibleValueSet::ConstantPointerValue { value }
                | PossibleValueSet::ImportedAddressValue { value } => value as u64,
                _ => return false,
            }
        }
        LowLevelILInstructionKind::Goto(target) => target.address(),
        _ => return false,
    };
    let Some(symbol) = view.symbol_by_address(target) else {
        return false;
    };

    let symbol_name = symbol.full_name();
    let symbol_name = symbol_name.to_bytes();

    // Remove any j_ prefix that the shared cache workflow adds to stub functions.
    let symbol_name = symbol_name.strip_prefix(b"j_").unwrap_or(symbol_name);

    IGNORABLE_MEMORY_MANAGEMENT_FUNCTIONS.contains(&symbol_name)
}

fn process_instruction(
    bv: &BinaryView,
    llil: &LowLevelILFunction<Mutable, NonSSA>,
    insn: &LowLevelILInstruction<Mutable, NonSSA>,
    link_register: LowLevelILRegisterKind<CoreRegister>,
    link_register_size: usize,
) -> Result<bool, &'static str> {
    if !is_call_to_ignorable_memory_management_function(bv, insn) {
        return Ok(false);
    }

    // TODO: Removing calls to `objc_release` can sometimes leave behind a load of a struct field
    // that appears to be unused. It's not clear whether we should be trying to detect and remove
    // those here, or if some later analysis pass should be cleaning them up but isn't.

    match insn.kind() {
        LowLevelILInstructionKind::TailCall(_) => unsafe {
            llil.set_current_address(insn.address());
            llil.replace_expression(
                insn.expr_idx(),
                llil.ret(llil.reg(link_register_size, link_register)),
            );
        },
        LowLevelILInstructionKind::Call(_) => unsafe {
            // The memory management functions that are currently supported either return void
            // or return their first argument. For arm64, the first argument is passed in `x0`
            // and results are returned in `x0`, so we can replace the call with a nop. We'll need
            // to revisit this to support other architectures, and to support the `objc_retain_x`
            // `objc_release_x` functions that accept their argument in a different register.
            llil.set_current_address(insn.address());
            llil.replace_expression(insn.expr_idx(), llil.nop());
        },
        LowLevelILInstructionKind::Goto(_) if insn.index.0 == 0 => unsafe {
            // If the `objc_retain` is the first instruction in the function, this function
            // can only contain the call to the memory management function since when the
            // memory management function returns, it will return to this function's caller.
            llil.set_current_address(insn.address());
            llil.replace_expression(
                insn.expr_idx(),
                llil.ret(llil.reg(link_register_size, link_register)),
            );
        },
        LowLevelILInstructionKind::Goto(_) => {
            // The shared cache workflow inlines calls to stub functions, which causes them
            // to show up as a `lr = <next instruction>; goto <stub function instruction>;`
            // sequence. We need to remove the load of `lr`  and update the `goto` to jump
            // to the next instruction.

            let Some(prev) =
                llil.instruction_from_index(LowLevelInstructionIndex(insn.index.0 - 1))
            else {
                return Ok(false);
            };

            let target = match prev.kind() {
                LowLevelILInstructionKind::SetReg(op) if op.dest_reg() == link_register => {
                    let LowLevelILExpressionKind::ConstPtr(value) = op.source_expr().kind() else {
                        return Ok(false);
                    };
                    value.value()
                }
                _ => return Ok(false),
            };

            let Some(LowLevelInstructionIndex(target_idx)) = llil.instruction_index_at(target)
            else {
                return Ok(false);
            };

            // TODO: Manually creating a label like this is fragile and relies on a) knowledge of
            // how labels are used by core, and b) that the target is the first instruction in
            // a basic block. We should do this differently.
            let mut label = LowLevelILLabel::new();
            label.operand = target_idx;

            unsafe {
                llil.set_current_address(prev.address());
                llil.replace_expression(prev.expr_idx(), llil.nop());
                llil.set_current_address(insn.address());
                llil.replace_expression(insn.expr_idx(), llil.goto(&mut label));
            }
        }
        _ => return Ok(false),
    }

    Ok(true)
}

pub fn process(ac: &AnalysisContext) -> Result<(), Error> {
    let view = ac.view();
    if GlobalState::should_ignore_view(&view) {
        return Ok(());
    }

    let func = ac.function();

    let Some(link_register) = func.arch().link_reg() else {
        return Ok(());
    };
    let link_register_size = link_register.info().size();
    let link_register = LowLevelILRegisterKind::Arch(link_register);

    let Some(llil) = (unsafe { ac.llil_function() }) else {
        return Err(Error::MissingIL {
            level: ILLevel::Low,
            func_start: func.start(),
        });
    };

    let mut function_changed = false;
    for block in llil.basic_blocks().iter() {
        for insn in block.iter() {
            match process_instruction(&view, &llil, &insn, link_register, link_register_size) {
                Ok(true) => function_changed = true,
                Ok(_) => {}
                Err(err) => {
                    tracing::error!(
                        "Error processing instruction at {:#x}: {}",
                        insn.address(),
                        err
                    );
                    continue;
                }
            }
        }
    }

    if function_changed {
        // Regenerate SSA form after modifications
        llil.generate_ssa_form();
    }
    Ok(())
}
