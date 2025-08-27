use crate::cache::{cached_constraints, cached_function_guid};
use crate::convert::{bn_comment_to_comment, bn_var_to_location, from_bn_symbol, from_bn_type};
use binaryninja::architecture::{
    Architecture, ImplicitRegisterExtend, Register as BNRegister, RegisterInfo,
};
use binaryninja::basic_block::BasicBlock as BNBasicBlock;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::confidence::MAX_CONFIDENCE;
use binaryninja::function::{Function as BNFunction, NativeBlock};
use binaryninja::low_level_il::expression::{
    ExpressionHandler, LowLevelILExpression, LowLevelILExpressionKind, ValueExpr,
};
use binaryninja::low_level_il::function::{FunctionMutability, LowLevelILFunction, NonSSA};
use binaryninja::low_level_il::instruction::{
    InstructionHandler, LowLevelILInstruction, LowLevelILInstructionKind,
};
use binaryninja::low_level_il::{LowLevelILRegisterKind, VisitorAction};
use binaryninja::rc::{Ref as BNRef, Ref};
use binaryninja::tags::TagType;
use binaryninja::variable::RegisterValueType;
use itertools::Itertools;
use std::ops::Range;
use std::path::PathBuf;
use warp::signature::basic_block::BasicBlockGUID;
use warp::signature::function::{Function, FunctionGUID};
use warp::signature::variable::FunctionVariable;

/// Re-export the warp crate that is used, this is useful for consumers of this crate.
pub use warp;

pub mod cache;
pub mod container;
pub mod convert;
pub mod matcher;
pub mod processor;
pub mod report;

/// Only used when compiled for cdylib target.
mod plugin;

// TODO: Make this 4kb
/// If the address is within this range before or after a relocatable region, we will assume the address to be relocatable.
const ADDRESS_RELOCATION_THRESHOLD: u64 = 0x10000;

const TAG_ICON: &str = "🌐";
const TAG_NAME: &str = "WARP";

fn get_warp_tag_type(view: &BinaryView) -> Ref<TagType> {
    view.tag_type_by_name(TAG_NAME)
        .unwrap_or_else(|| view.create_tag_type(TAG_NAME, TAG_ICON))
}

const INCLUDE_TAG_ICON: &str = "🚀";
const INCLUDE_TAG_NAME: &str = "WARP: Selected Function";

fn get_warp_include_tag_type(view: &BinaryView) -> Ref<TagType> {
    view.tag_type_by_name(INCLUDE_TAG_NAME)
        .unwrap_or_else(|| view.create_tag_type(INCLUDE_TAG_NAME, INCLUDE_TAG_ICON))
}

pub fn core_signature_dir() -> PathBuf {
    // Get core signatures for the given platform
    let install_dir = binaryninja::install_directory();
    // macOS core dir is separate from the install dir.
    #[cfg(target_os = "macos")]
    let core_dir = install_dir.parent().unwrap().join("Resources");
    #[cfg(not(target_os = "macos"))]
    let core_dir = install_dir;
    core_dir.join("signatures")
}

pub fn user_signature_dir() -> PathBuf {
    binaryninja::user_directory().join("signatures/")
}

pub fn build_variables(func: &BNFunction) -> Vec<FunctionVariable> {
    let func_start = func.start();
    // It is important that we only retrieve the medium-level IL if the function has
    // any user-defined variables, otherwise, we will possibly be generating MLIL for no reason.
    // For the above reason, we do a filter on user-defined variables first.
    func.variables()
        .iter()
        .filter(|var| func.is_variable_user_defined(&var.variable))
        .filter_map(|var| {
            // Get the first instruction that uses the variable, this is the "placement" location we store.
            // TODO: live_instruction_for_variable only works for register types.
            let first_instr = func
                .medium_level_il()
                .ok()?
                .live_instruction_for_variable(&var.variable, true)
                .iter()
                .sorted_by_key(|i| i.instr_index)
                .next()?;
            Some((var, first_instr))
        })
        .filter_map(|(var, instr)| {
            // Build the WARP function variable using the placement location, and the variable itself.
            let var_loc = bn_var_to_location(var.variable)?;
            let var_type = from_bn_type(&func.view(), &var.ty.contents, var.ty.confidence);
            Some(FunctionVariable {
                offset: (instr.address as i64) - (func_start as i64),
                location: var_loc,
                name: Some(var.name),
                ty: Some(var_type),
            })
        })
        .collect()
}

// TODO: Get rid of the minimal bool.
/// Build the WARP [`Function`] from the Binary Ninja [`BNFunction`].
///
/// The `lifted_il_accessor` is passed in such that a function with a guid already cached will not
/// require us to regenerate the IL. This is important in the event of someone generating signatures
/// off of an existing BNDB or when the IL is no longer present.
pub fn build_function<M: FunctionMutability>(
    func: &BNFunction,
    lifted_il_accessor: impl Fn() -> Option<BNRef<LowLevelILFunction<M, NonSSA>>>,
    minimal: bool,
) -> Option<Function> {
    let mut function = Function {
        guid: cached_function_guid(func, lifted_il_accessor)?,
        symbol: from_bn_symbol(&func.symbol()),
        // NOTE: Adding adjacent only works if analysis is complete.
        // NOTE: We do not filter out adjacent functions here.
        constraints: cached_constraints(func, |_| true),
        ty: None,
        comments: vec![],
        variables: vec![],
    };

    if minimal {
        return Some(function);
    }

    // Currently we only store the type if its a user type.
    // TODO: In the future we might want to make this configurable.
    function.ty = match func.has_user_type() || func.has_explicitly_defined_type() {
        true => Some(from_bn_type(
            &func.view(),
            &func.function_type(),
            MAX_CONFIDENCE,
        )),
        false => None,
    };
    function.comments = func
        .comments()
        .iter()
        .map(|c| bn_comment_to_comment(func, c))
        .collect();
    function.variables = build_variables(func);
    Some(function)
}

/// Basic blocks sorted from high to low.
pub fn sorted_basic_blocks(func: &BNFunction) -> Vec<BNRef<BNBasicBlock<NativeBlock>>> {
    let mut basic_blocks = func
        .basic_blocks()
        .iter()
        .map(|bb| bb.clone())
        .collect::<Vec<_>>();
    // NOTE: start_index is actually the address with [`NativeBlock`].
    basic_blocks.sort_by_key(|f| f.start_index());
    basic_blocks
}

pub fn function_guid<M: FunctionMutability>(
    func: &BNFunction,
    lifted_il: &LowLevelILFunction<M, NonSSA>,
) -> FunctionGUID {
    // TODO: We might want to make this configurable, or otherwise _not_ retrieve from the view here.
    let relocatable_regions = relocatable_regions(&func.view());
    let basic_blocks = sorted_basic_blocks(func);
    let basic_block_guids = basic_blocks
        .iter()
        .map(|bb| basic_block_guid(&relocatable_regions, bb, lifted_il))
        .collect::<Vec<_>>();
    FunctionGUID::from_basic_blocks(&basic_block_guids)
}

pub fn basic_block_guid<M: FunctionMutability>(
    relocatable_regions: &[Range<u64>],
    basic_block: &BNBasicBlock<NativeBlock>,
    lifted_il: &LowLevelILFunction<M, NonSSA>,
) -> BasicBlockGUID {
    let func = basic_block.function();
    // TODO: We really should never consult another IL, no guarantee that it exists.
    let low_level_il = func.low_level_il();
    let view = func.view();
    let arch = func.arch();
    let max_instr_len = arch.max_instr_len();

    // NOTE: Whenever you make a change here, prefer being "additive", that is, make a smaller change that
    // only increases the masked contents, instead of making a larger change that could *remove* masked
    // contents. The reason is that we assume any change that is purely additive to increase the ability
    // to match previously "unmatchable" functions, whereas the latter would take away. This is not always
    // the case, but it is generally a good rule to follow.
    let basic_block_range = basic_block.start_index()..basic_block.end_index();
    let mut basic_block_bytes = Vec::with_capacity(basic_block_range.count());
    for instr_addr in basic_block.into_iter() {
        let mut instr_bytes = view.read_vec(instr_addr, max_instr_len);
        if let Some(instr_info) = arch.instruction_info(&instr_bytes, instr_addr) {
            instr_bytes.truncate(instr_info.length);

            // Find variant and blacklisted instructions using lifted il.
            for lifted_il_instr in filtered_instructions_at(lifted_il, instr_addr) {
                // If instruction is blacklisted, don't include the bytes.
                if is_blacklisted_instruction(&lifted_il_instr) {
                    continue;
                }

                if is_variant_instruction(relocatable_regions, &lifted_il_instr) {
                    // Found a variant instruction, mask off the entire instruction.
                    instr_bytes.fill(0);
                    break;
                }
            }

            // TODO: We cannot access the values of expression in lifted IL, we have to go and consult low level IL.
            // TODO: But because of some extremely annoying simplifications that are happening at LLIL, namely
            // TODO: Folding of expressions into other instructions, we cannot use only LLIL. Therefor
            // TODO: We only put the checks that require the expr value here.
            // TODO: This still has the issue of, some (if (rax + 44) => 28) expression being masked,
            // TODO: But the only way to remove that is to not consult LLIL at all and have the values
            // TODO: Available at lifted IL, I have not found a good way to do this without making
            // TODO: A "mapped llil" or having some simple data flow, the simple data flow is the most attractive
            // TODO: "solution", but it would require
            if let Ok(llil) = &low_level_il {
                for low_level_instr in filtered_instructions_at(llil, instr_addr) {
                    if is_computed_variant_instruction(relocatable_regions, &low_level_instr) {
                        // Found a computed variant instruction, mask off the entire instruction.
                        instr_bytes.fill(0);
                        break;
                    }
                }
            }

            // Add the instruction bytes to the basic blocks bytes
            basic_block_bytes.extend(instr_bytes);
        }
    }

    BasicBlockGUID::from(basic_block_bytes.as_slice())
}

pub fn filtered_instructions_at<M: FunctionMutability>(
    il: &LowLevelILFunction<M, NonSSA>,
    addr: u64,
) -> Vec<LowLevelILInstruction<M, NonSSA>> {
    il.instructions_at(addr)
        .into_iter()
        .enumerate()
        .take_while(|(i, instr)| match instr.kind() {
            // Stop collecting instructions after we see a LLIL_RET, LLIL_NO_RET.
            LowLevelILInstructionKind::NoRet(_) | LowLevelILInstructionKind::Ret(_) => false,
            // Stop collecting instruction if we are probably the end function jump in lifted IL. This
            // is emitted at the end of the function and will mess with our GUID.
            LowLevelILInstructionKind::Jump(_) => *i == 0,
            _ => true,
        })
        .map(|(_, instr)| instr)
        .collect()
}

/// Is the instruction not included in the masked byte sequence?
///
/// Blacklisted instructions will make an otherwise identical function GUID fail to match.
///
/// Example: NOPs and useless moves are blacklisted to allow for hot-patchable functions.
pub fn is_blacklisted_instruction<M: FunctionMutability>(
    instr: &LowLevelILInstruction<M, NonSSA>,
) -> bool {
    match instr.kind() {
        LowLevelILInstructionKind::Nop(_) => true,
        LowLevelILInstructionKind::SetReg(op) => {
            match op.source_expr().kind() {
                LowLevelILExpressionKind::Reg(source_op)
                    if op.dest_reg() == source_op.source_reg() =>
                {
                    match op.dest_reg() {
                        LowLevelILRegisterKind::Arch(r) => {
                            // If this register has no implicit extend, we can safely assume it's a NOP.
                            // Ex. on x86_64 we don't want to remove `mov edi, edi` as it will zero the upper 32 bits.
                            // Ex. on x86 we do want to remove `mov edi, edi` as it will not have a side effect like above.
                            matches!(r.info().implicit_extend(), ImplicitRegisterExtend::NoExtend)
                        }
                        LowLevelILRegisterKind::Temp(_) => false,
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

pub fn is_variant_instruction<M: FunctionMutability>(
    relocatable_regions: &[Range<u64>],
    instr: &LowLevelILInstruction<M, NonSSA>,
) -> bool {
    let is_variant_expr = |expr: &LowLevelILExpression<M, NonSSA, ValueExpr>| {
        match expr.kind() {
            LowLevelILExpressionKind::ConstPtr(op)
                if is_address_relocatable(relocatable_regions, op.value()) =>
            {
                // Constant Pointer must be in a section for it to be relocatable.
                true
            }
            LowLevelILExpressionKind::Const(op)
                if is_address_relocatable(relocatable_regions, op.value()) =>
            {
                // Constant value must be in a section for it to be relocatable.
                true
            }
            LowLevelILExpressionKind::ExternPtr(_) => true,
            _ => false,
        }
    };

    // Visit instruction expressions looking for variant expression, [VisitorAction::Halt] means variant.
    instr.visit_tree(&mut |expr| {
        if is_variant_expr(expr) {
            // Found a variant expression.
            VisitorAction::Halt
        } else {
            // Keep looking for a variant expression.
            VisitorAction::Descend
        }
    }) == VisitorAction::Halt
}

/// NOTE: This will only work at LLIL, **NOT** lifted IL. You must do this in a second pass.
///
/// This was previously done inside `is_variant_instruction` but had to be moved to access expr value.
pub fn is_computed_variant_instruction<M: FunctionMutability>(
    relocatable_regions: &[Range<u64>],
    instr: &LowLevelILInstruction<M, NonSSA>,
) -> bool {
    let is_expr_constant = |expr: &LowLevelILExpression<M, NonSSA, ValueExpr>| match expr.kind() {
        LowLevelILExpressionKind::Const(_) | LowLevelILExpressionKind::ConstPtr(_) => true,
        _ => false,
    };

    let is_variant_observed_expr = |expr: &LowLevelILExpression<M, NonSSA, ValueExpr>| {
        match expr.kind() {
            // TODO: Skip problematic expressions like IF?
            LowLevelILExpressionKind::Add(op) | LowLevelILExpressionKind::Sub(op) => {
                // For now, we limit to only expressions that contain some constant; this keeps add expressions
                // with two registers with known values from being marked variant.
                let constant_expressed =
                    is_expr_constant(&op.left()) || is_expr_constant(&op.right());
                // NOTE: Lifted IL does not have the value ever, we must consult Low Level IL.
                // If the expression value is known, we check to see if it's a relocatable address.
                let expr_value = expr.value();
                match expr_value.state {
                    RegisterValueType::EntryValue
                    | RegisterValueType::ConstantValue
                    | RegisterValueType::ConstantPointerValue
                    | RegisterValueType::ExternalPointerValue
                    | RegisterValueType::StackFrameOffset
                    | RegisterValueType::ReturnAddressValue
                    | RegisterValueType::ImportedAddressValue
                        if constant_expressed
                            && is_address_relocatable(
                                relocatable_regions,
                                expr_value.value as u64,
                            ) =>
                    {
                        // Concrete arithmetic operation with a relocatable result.
                        true
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    };

    // Visit instruction expressions looking for an observed variant expression, [VisitorAction::Halt] means variant.
    instr.visit_tree(&mut |expr| {
        if is_variant_observed_expr(expr) {
            // Found a variant expression.
            VisitorAction::Halt
        } else {
            // Keep looking for an observed variant expression.
            VisitorAction::Descend
        }
    }) == VisitorAction::Halt
}

/// If the address is inside any of the given ranges, we will assume the address to be relocatable.
pub fn is_address_relocatable(relocatable_regions: &[Range<u64>], address: u64) -> bool {
    relocatable_regions
        .iter()
        .any(|range| {
            // Check if the address is within the range itself
            (range.contains(&address))
                // Check if the address is within the threshold **AFTER** the range
                // NOTE: The address must at least be larger than the threshold itself, for lower image-based binaries.
                || (address > range.end && address > ADDRESS_RELOCATION_THRESHOLD && address <= range.end + ADDRESS_RELOCATION_THRESHOLD)
                // Check if the address is within the threshold **BEFORE** the range
                // NOTE: The address must at least be larger than the threshold itself, for lower image-based binaries.
                || (address < range.start && address > ADDRESS_RELOCATION_THRESHOLD && address >= range.start.saturating_sub(ADDRESS_RELOCATION_THRESHOLD))
        })
}

// TODO: This might need to be configurable, in that case we better remove this function.
/// Get the relocatable regions of the view.
///
/// Currently, segments are used by default, however, if the only segment is based at 0, then we fall
/// back to using sections.
pub fn relocatable_regions(view: &BinaryView) -> Vec<Range<u64>> {
    // NOTE: We used to use sections because the image base for some object files would start
    // at zero, masking non-relocatable instructions, since then we have started adjusting the
    // image base to 0x10000 or higher so we can use segments directly, which improves the accuracy
    // of function GUIDs for binaries which have no or bad section definitions, common of firmware.
    let mut ranges = view
        .segments()
        .iter()
        .filter(|s| s.address_range().start != 0)
        .map(|s| s.address_range())
        .collect::<Vec<_>>();

    if ranges.is_empty() {
        // Realistically only happens if the only defined segment was based at 0, in which case
        // we hope the user has set up correct sections. If not we are going to be masking off too many
        // or too little instructions.
        ranges = view
            .sections()
            .iter()
            .map(|s| s.address_range())
            .collect::<Vec<_>>();
    }

    ranges
}
