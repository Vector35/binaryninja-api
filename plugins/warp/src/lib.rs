use crate::cache::{
    cached_adjacency_constraints, cached_call_site_constraints, cached_function_guid,
};
use crate::convert::{from_bn_symbol, from_bn_type};
use binaryninja::architecture::{
    Architecture, ImplicitRegisterExtend, Register as BNRegister, RegisterInfo,
};
use binaryninja::basic_block::BasicBlock as BNBasicBlock;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::confidence::MAX_CONFIDENCE;
use binaryninja::function::{Function as BNFunction, NativeBlock};
use binaryninja::low_level_il::expression::{ExpressionHandler, LowLevelILExpressionKind};
use binaryninja::low_level_il::function::{FunctionMutability, LowLevelILFunction, NonSSA};
use binaryninja::low_level_il::instruction::{
    InstructionHandler, LowLevelILInstruction, LowLevelILInstructionKind,
};
use binaryninja::low_level_il::{LowLevelILRegisterKind, VisitorAction};
use binaryninja::rc::Ref as BNRef;
use std::ops::Range;
use std::path::PathBuf;
use warp::signature::basic_block::BasicBlockGUID;
use warp::signature::function::constraints::FunctionConstraints;
use warp::signature::function::{Function, FunctionGUID};

pub mod cache;
pub mod convert;
mod matcher;
/// Only used when compiled for cdylib target.
mod plugin;

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

pub fn build_function<M: FunctionMutability>(
    func: &BNFunction,
    llil: &LowLevelILFunction<M, NonSSA>,
) -> Function {
    let bn_fn_ty = func.function_type();
    Function {
        guid: cached_function_guid(func, llil),
        symbol: from_bn_symbol(&func.symbol()),
        ty: from_bn_type(&func.view(), &bn_fn_ty, MAX_CONFIDENCE),
        constraints: FunctionConstraints {
            // NOTE: Adding adjacent only works if analysis is complete.
            // NOTE: We do not filter out adjacent functions here.
            adjacent: cached_adjacency_constraints(func, |_| true),
            call_sites: cached_call_site_constraints(func),
            // TODO: Add caller sites (when adjacent and call sites are minimal)
            // NOTE: Adding caller sites only works if analysis is complete.
            caller_sites: Default::default(),
        },
    }
}

/// Basic blocks sorted from high to low.
pub fn sorted_basic_blocks(func: &BNFunction) -> Vec<BNRef<BNBasicBlock<NativeBlock>>> {
    let mut basic_blocks = func
        .basic_blocks()
        .iter()
        .map(|bb| bb.clone())
        .collect::<Vec<_>>();
    basic_blocks.sort_by_key(|f| f.start_index());
    basic_blocks
}

pub fn function_guid<M: FunctionMutability>(
    func: &BNFunction,
    llil: &LowLevelILFunction<M, NonSSA>,
) -> FunctionGUID {
    // TODO: We might want to make this configurable, or otherwise _not_ retrieve from the view here.
    let relocatable_regions = relocatable_regions(&func.view());
    let basic_blocks = sorted_basic_blocks(func);
    let basic_block_guids = basic_blocks
        .iter()
        .map(|bb| basic_block_guid(&relocatable_regions, bb, llil))
        .collect::<Vec<_>>();
    FunctionGUID::from_basic_blocks(&basic_block_guids)
}

pub fn basic_block_guid<M: FunctionMutability>(
    relocatable_regions: &[Range<u64>],
    basic_block: &BNBasicBlock<NativeBlock>,
    llil: &LowLevelILFunction<M, NonSSA>,
) -> BasicBlockGUID {
    let func = basic_block.function();
    let view = func.view();
    let arch = func.arch();
    let max_instr_len = arch.max_instr_len();

    let basic_block_range = basic_block.start_index()..basic_block.end_index();
    let mut basic_block_bytes = Vec::with_capacity(basic_block_range.count());
    for instr_addr in basic_block.into_iter() {
        let mut instr_bytes = view.read_vec(instr_addr, max_instr_len);
        if let Some(instr_info) = arch.instruction_info(&instr_bytes, instr_addr) {
            instr_bytes.truncate(instr_info.length);
            if let Some(instr_llil) = llil.instruction_at(instr_addr) {
                // If instruction is blacklisted don't include the bytes.
                if !is_blacklisted_instruction(&instr_llil) {
                    if is_variant_instruction(relocatable_regions, &instr_llil) {
                        // Found a variant instruction, mask off entire instruction.
                        instr_bytes.fill(0);
                    }
                    // Add the instructions bytes to the basic blocks bytes
                    basic_block_bytes.extend(instr_bytes);
                }
            }
        }
    }

    BasicBlockGUID::from(basic_block_bytes.as_slice())
}

/// Is the instruction not included in the masked byte sequence?
///
/// Blacklisted instructions will make an otherwise identical function GUID fail to match.
///
/// Example: NOPs and useless moves are blacklisted to allow for hot-patchable functions.
pub fn is_blacklisted_instruction<A: Architecture, M: FunctionMutability>(
    instr: &LowLevelILInstruction<A, M, NonSSA<RegularNonSSA>>,
) -> bool {
    match instr.kind() {
        LowLevelILInstructionKind::Nop(_) => true,
        LowLevelILInstructionKind::SetReg(op) => {
            match op.source_expr().kind() {
                LowLevelILExpressionKind::Reg(source_op)
                    if op.dest_reg() == source_op.source_reg() =>
                {
                    match op.dest_reg() {
                        LowLevelILRegister::ArchReg(r) => {
                            // If this register has no implicit extend then we can safely assume it's a NOP.
                            // Ex. on x86_64 we don't want to remove `mov edi, edi` as it will zero the upper 32 bits.
                            // Ex. on x86 we do want to remove `mov edi, edi` as it will not have a side effect like above.
                            matches!(r.info().implicit_extend(), ImplicitRegisterExtend::NoExtend)
                        }
                        LowLevelILRegister::Temp(_) => false,
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

pub fn is_variant_instruction<A: Architecture, M: FunctionMutability>(
    relocatable_regions: &[Range<u64>],
    instr: &LowLevelILInstruction<A, M, NonSSA<RegularNonSSA>>,
) -> bool {
    let is_variant_expr = |expr: &LowLevelILExpressionKind<A, M, NonSSA<RegularNonSSA>>| {
        match expr {
            LowLevelILExpressionKind::ConstPtr(op)
                if is_address_relocatable(relocatable_regions, op.value()) =>
            {
                // Constant Pointer must be in a section for it to be relocatable.
                // NOTE: We cannot utilize segments here as there will be a zero based segment.
                true
            }
            LowLevelILExpressionKind::Const(op)
                if is_address_relocatable(relocatable_regions, op.value()) =>
            {
                // Constant value must be in a section for it to be relocatable.
                // NOTE: We cannot utilize segments here as there will be a zero based segment.
                true
            }
            LowLevelILExpressionKind::ExternPtr(_) => true,
            _ => false,
        }
    };

    // Visit instruction expressions looking for variant expression, [VisitorAction::Halt] means variant.
    instr.visit_tree(&mut |expr| {
        if is_variant_expr(&expr.kind()) {
            // Found a variant expression.
            VisitorAction::Halt
        } else {
            // Keep looking for a variant expression.
            VisitorAction::Descend
        }
    }) == VisitorAction::Halt
}

/// If the address is inside any of the given ranges we will assume the address to be relocatable.
pub fn is_address_relocatable(relocatable_regions: &[Range<u64>], address: u64) -> bool {
    relocatable_regions
        .iter()
        .any(|range| range.contains(&address))
}

// TODO: This might need to be configurable, in that case we better remove this function.
/// Get the relocatable regions of the view.
///
/// Currently, this is all the sections, however this might be refined later.
pub fn relocatable_regions(view: &BinaryView) -> Vec<Range<u64>> {
    view.sections()
        .iter()
        .map(|s| Range {
            start: s.start(),
            end: s.end(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::cache::cached_function_guid;
    use binaryninja::binary_view::BinaryViewExt;
    use binaryninja::headless::Session;
    use std::path::PathBuf;
    use std::sync::OnceLock;

    static INIT: OnceLock<Session> = OnceLock::new();

    fn get_session<'a>() -> &'a Session {
        // TODO: This is not shared between other test modules, should still be fine (mutex in core now).
        INIT.get_or_init(|| Session::new().expect("Failed to initialize session"))
    }

    #[test]
    fn insta_signatures() {
        let session = get_session();
        let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
        for entry in std::fs::read_dir(out_dir).expect("Failed to read OUT_DIR") {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();
            if path.is_file() {
                let view = session.load(&path).expect("Failed to load view");
                let mut functions = view
                    .functions()
                    .iter()
                    .map(|f| cached_function_guid(&f, &f.low_level_il().unwrap()))
                    .collect::<Vec<_>>();
                functions.sort_by_key(|guid| guid.guid);
                let snapshot_name =
                    format!("snapshot_{}", path.file_stem().unwrap().to_string_lossy());
                insta::assert_debug_snapshot!(snapshot_name, functions);
            }
        }
    }
}
