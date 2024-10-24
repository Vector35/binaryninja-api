use binaryninja::architecture::Architecture;
use binaryninja::basicblock::BasicBlock as BNBasicBlock;
use binaryninja::binaryview::BinaryViewExt;
use binaryninja::function::{Function as BNFunction, NativeBlock};
use binaryninja::llil;
use binaryninja::llil::{ExprInfo, FunctionMutability, NonSSA, NonSSAVariant, VisitorAction};
use binaryninja::rc::Ref as BNRef;
use warp::signature::basic_block::{BasicBlock, BasicBlockGUID};
use warp::signature::function::constraints::FunctionConstraints;
use warp::signature::function::{Function, FunctionGUID};

use crate::cache::{
    cached_adjacency_constraints, cached_call_site_constraints, cached_function_guid,
};
use crate::convert::{from_bn_symbol, from_bn_type};

pub mod cache;
pub mod convert;
mod matcher;
/// Only used when compiled for cdylib target.
mod plugin;

pub fn build_function<A: Architecture, M: FunctionMutability, V: NonSSAVariant>(
    func: &BNFunction,
    llil: &llil::Function<A, M, NonSSA<V>>,
) -> Function {
    let bn_fn_ty = func.function_type();
    Function {
        guid: cached_function_guid(func, llil),
        symbol: from_bn_symbol(&func.symbol()),
        // TODO: Confidence should be derived from function type.
        ty: from_bn_type(&func.view(), bn_fn_ty, 255),
        constraints: FunctionConstraints {
            // NOTE: Adding adjacent only works if analysis is complete.
            adjacent: cached_adjacency_constraints(func),
            call_sites: cached_call_site_constraints(func),
            // TODO: Add caller sites (when adjacent and call sites are minimal)
            // NOTE: Adding caller sites only works if analysis is complete.
            caller_sites: Default::default(),
        },
        // TODO: We need more than one entry block.
        entry: entry_basic_block_guid(func, llil).map(BasicBlock::new),
    }
}

pub fn entry_basic_block_guid<A: Architecture, M: FunctionMutability, V: NonSSAVariant>(
    func: &BNFunction,
    llil: &llil::Function<A, M, NonSSA<V>>,
) -> Option<BasicBlockGUID> {
    // NOTE: This is not actually the entry point. This is the highest basic block.
    let first_basic_block = sorted_basic_blocks(func).into_iter().next()?;
    Some(basic_block_guid(&first_basic_block, llil))
}

/// Basic blocks sorted from high to low.
pub fn sorted_basic_blocks(func: &BNFunction) -> Vec<BNRef<BNBasicBlock<NativeBlock>>> {
    let mut basic_blocks = func
        .basic_blocks()
        .iter()
        .map(|bb| bb.clone())
        .collect::<Vec<_>>();
    basic_blocks.sort_by_key(|f| f.raw_start());
    basic_blocks
}

pub fn function_guid<A: Architecture, M: FunctionMutability, V: NonSSAVariant>(
    func: &BNFunction,
    llil: &llil::Function<A, M, NonSSA<V>>,
) -> FunctionGUID {
    // TODO: Sort the basic blocks.
    let basic_blocks = sorted_basic_blocks(func);
    let basic_block_guids = basic_blocks
        .iter()
        .map(|bb| basic_block_guid(bb, llil))
        .collect::<Vec<_>>();
    FunctionGUID::from_basic_blocks(&basic_block_guids)
}

pub fn basic_block_guid<A: Architecture, M: FunctionMutability, V: NonSSAVariant>(
    basic_block: &BNBasicBlock<NativeBlock>,
    llil: &llil::Function<A, M, NonSSA<V>>,
) -> BasicBlockGUID {
    let func = basic_block.function();
    let view = func.view();
    let arch = func.arch();
    let max_instr_len = arch.max_instr_len();
    // TODO: Add all the hacks here to remove stuff like function prolog...
    // TODO mov edi, edi on windows x86
    // TODO: Ugh i really dislike the above and REALLY don't wanna do that.
    // TODO: The above invalidates our "all function bytes" approach.
    // TODO: Could we keep the bytes and just zero mask them? At least then we don't completely get rid of them.

    let basic_block_range = basic_block.raw_start()..basic_block.raw_end();
    let mut basic_block_bytes = Vec::with_capacity(basic_block_range.count());
    for instr_addr in basic_block.into_iter() {
        let mut instr_bytes = view.read_vec(instr_addr, max_instr_len);
        if let Some(instr_info) = arch.instruction_info(&instr_bytes, instr_addr) {
            let instr_len = instr_info.len();
            instr_bytes.truncate(instr_len);
            if let Some(instr_llil) = llil.instruction_at(instr_addr) {
                if instr_llil.visit_tree(&mut |_expr, expr_info| match expr_info {
                    ExprInfo::ConstPtr(_) | ExprInfo::ExternPtr(_) => VisitorAction::Halt,
                    _ => VisitorAction::Descend,
                }) == VisitorAction::Halt
                {
                    // Found a variant instruction, mask off entire instruction.
                    instr_bytes.fill(0);
                }
            }
            // Add the instructions bytes to the functions bytes
            basic_block_bytes.extend(instr_bytes);
        }
    }

    BasicBlockGUID::from(basic_block_bytes.as_slice())
}

#[cfg(test)]
mod tests {
    use crate::cache::cached_function_guid;
    use crate::convert::from_bn_type;
    use binaryninja::binaryview::BinaryViewExt;
    use binaryninja::headless::Session;
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use warp::r#type::guid::TypeGUID;

    static INIT: OnceLock<Session> = OnceLock::new();

    fn get_session<'a>() -> &'a Session {
        // TODO: This is not shared between other test modules, should still be fine (mutex in core now).
        INIT.get_or_init(|| Session::new())
    }

    #[test]
    fn insta_signatures() {
        let session = get_session();
        let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
        for entry in std::fs::read_dir(out_dir).expect("Failed to read OUT_DIR") {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();
            if path.is_file() {
                if let Some(path_str) = path.to_str() {
                    if path_str.ends_with("library.o") {
                        if let Some(inital_bv) = session.load(path_str) {
                            let mut functions = inital_bv
                                .functions()
                                .iter()
                                .map(|f| cached_function_guid(&f, &f.low_level_il().unwrap()))
                                .collect::<Vec<_>>();
                            functions.sort_by_key(|guid| guid.guid);
                            insta::assert_debug_snapshot!(functions);
                        }
                    }
                }
            }
        }
    }
}
