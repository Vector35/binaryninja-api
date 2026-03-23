use binaryninja::{
    architecture::{Architecture as _, CoreRegister, Register as _, RegisterId, RegisterInfo as _},
    binary_view::BinaryView,
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
    platform::Platform,
    variable::{PossibleValueSet, VariableSourceType},
    workflow::AnalysisContext,
};

use crate::{error::ILLevel, metadata::GlobalState, Error};

const IGNORABLE_MEMORY_MANAGEMENT_FUNCTIONS: &[&[u8]] = &[
    b"_objc_autorelease",
    b"_objc_autoreleaseReturnValue",
    b"_objc_claimAutoreleasedReturnValue",
    b"_objc_release",
    b"_objc_retain",
    b"_objc_retainAutorelease",
    b"_objc_retainAutoreleasedReturnValue",
    b"_objc_retainAutoreleaseReturnValue",
    b"_objc_retainBlock",
    b"_objc_unsafeClaimAutoreleasedReturnValue",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryManagementFunctionCategory {
    ReturnVoid,
    ReturnObject,
}

struct MemoryManagementCall {
    category: MemoryManagementFunctionCategory,
    /// Register the target receives its object argument in.
    object_register: CoreRegister,
    /// Register the target returns its result in.
    return_register: Option<CoreRegister>,
}

fn classify_memory_management_call(
    view: &binaryninja::binary_view::BinaryView,
    platform: &Platform,
    instr: &LowLevelILInstruction<Mutable, NonSSA>,
) -> Option<MemoryManagementCall> {
    let target = match instr.kind() {
        LowLevelILInstructionKind::Call(call) | LowLevelILInstructionKind::TailCall(call) => {
            match call.target().possible_values() {
                PossibleValueSet::ConstantValue { value }
                | PossibleValueSet::ConstantPointerValue { value }
                | PossibleValueSet::ImportedAddressValue { value } => value as u64,
                _ => return None,
            }
        }
        LowLevelILInstructionKind::Goto(target) => target.address(),
        _ => return None,
    };
    let symbol = view.symbol_by_address(target)?;

    let symbol_name = symbol.full_name();
    let symbol_name = symbol_name.to_bytes();

    // Remove any j_ prefix that the shared cache workflow adds to stub functions.
    let symbol_name = symbol_name.strip_prefix(b"j_").unwrap_or(symbol_name);

    if !IGNORABLE_MEMORY_MANAGEMENT_FUNCTIONS.contains(&symbol_name)
        && !symbol_name.starts_with(b"_objc_retain_x")
        && !symbol_name.starts_with(b"_objc_release_x")
    {
        return None;
    }

    let category = if symbol_name.starts_with(b"_objc_release") {
        MemoryManagementFunctionCategory::ReturnVoid
    } else {
        MemoryManagementFunctionCategory::ReturnObject
    };

    // The `objc_retain_xN` / `objc_release_xN` variants take their object in `xN` rather than
    // `x0`. The target's parameter and return value locations name the registers.
    let target_function = view.function_at(platform, target)?;
    let arch = target_function.arch();
    let object_register = target_function
        .parameter_variables()
        .contents
        .first()
        .filter(|var| var.ty == VariableSourceType::RegisterVariableSourceType)
        .and_then(|var| arch.register_from_id(RegisterId::from(var.storage as u32)))?;
    let return_register = target_function.return_registers().contents.iter().next();

    Some(MemoryManagementCall {
        category,
        object_register,
        return_register,
    })
}

fn process_instruction(
    bv: &BinaryView,
    platform: &Platform,
    llil: &LowLevelILFunction<Mutable, NonSSA>,
    insn: &LowLevelILInstruction<Mutable, NonSSA>,
    link_register: LowLevelILRegisterKind<CoreRegister>,
    link_register_size: usize,
) -> Result<bool, &'static str> {
    let Some(call) = classify_memory_management_call(bv, platform, insn) else {
        return Ok(false);
    };

    // A target that returns its object in a register other than the one it received it in
    // needs a move before any return that replaces it. A single expression replacement cannot
    // express that, so such tail calls and stub gotos are left in place.
    let returns_object_in_place = call.category == MemoryManagementFunctionCategory::ReturnVoid
        || call.return_register == Some(call.object_register);

    // TODO: Removing calls to `objc_release` can sometimes leave behind a load of a struct field
    // that appears to be unused. It's not clear whether we should be trying to detect and remove
    // those here, or if some later analysis pass should be cleaning them up but isn't.

    match insn.kind() {
        LowLevelILInstructionKind::TailCall(_) if returns_object_in_place => unsafe {
            llil.set_current_address(insn.address());
            llil.replace_expression(
                insn.expr_idx(),
                llil.ret(llil.reg(link_register_size, link_register)),
            );
        },
        LowLevelILInstructionKind::TailCall(_) => return Ok(false),
        LowLevelILInstructionKind::Call(_) if returns_object_in_place => unsafe {
            llil.set_current_address(insn.address());
            llil.replace_expression(insn.expr_idx(), llil.nop());
        },
        LowLevelILInstructionKind::Call(_) => unsafe {
            // The target returns the object it was given, so the call is equivalent to a move
            // from the object register to the return register.
            let Some(return_register) = call.return_register else {
                return Ok(false);
            };
            let size = call.object_register.info().size();

            llil.set_current_address(insn.address());
            llil.replace_expression(
                insn.expr_idx(),
                llil.set_reg(
                    size,
                    LowLevelILRegisterKind::Arch(return_register),
                    llil.reg(size, LowLevelILRegisterKind::Arch(call.object_register)),
                ),
            );
        },
        LowLevelILInstructionKind::Goto(_) if insn.index.0 == 0 && !returns_object_in_place => {
            return Ok(false)
        }
        LowLevelILInstructionKind::Goto(_) if insn.index.0 == 0 => unsafe {
            // If a goto to a memory management function is the first instruction in the function,
            // this function can only contain the call to the memory management function. When the
            // memory management function returns, it will return to this function's caller.
            // This means we can replace the goto with a return.
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
    let platform = func.platform();

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
            match process_instruction(
                &view,
                &platform,
                &llil,
                &insn,
                link_register,
                link_register_size,
            ) {
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
