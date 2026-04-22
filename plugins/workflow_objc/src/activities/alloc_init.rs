use binaryninja::{
    binary_view::BinaryView, medium_level_il::MediumLevelILLiftedInstruction, rc::Ref, types::Type,
    workflow::AnalysisContext,
};
use bstr::ByteSlice;

use super::util;
use crate::{error::ILLevel, metadata::GlobalState, workflow::Confidence, Error};

// j_ prefixes are for stub functions in the dyld shared cache.
// The prefix is added by Binary Ninja's shared cache workflow.
const ALLOC_INIT_FUNCTIONS: &[&[u8]] = &[
    b"_objc_alloc_init",
    b"_objc_alloc_initWithZone",
    b"_objc_alloc",
    b"_objc_allocWithZone",
    b"_objc_opt_new",
    b"j__objc_alloc_init",
    b"j__objc_alloc_initWithZone",
    b"j__objc_alloc",
    b"j__objc_allocWithZone",
    b"j__objc_opt_new",
];

fn return_type_for_alloc_call(call: &util::Call<'_>, view: &BinaryView) -> Option<Ref<Type>> {
    if call.call.params.is_empty() {
        return None;
    }

    let class_addr =
        util::match_constant_pointer_or_load_of_constant_pointer(&call.call.params[0])?;
    let class_symbol_name = view.symbol_by_address(class_addr)?.full_name();
    let class_name = util::class_name_from_symbol_name(class_symbol_name.to_bytes().as_bstr())?;

    let class_type = view.type_by_name(class_name.to_str_lossy())?;
    Some(Type::pointer(&call.target.arch(), &class_type))
}

fn process_instruction(instr: &MediumLevelILLiftedInstruction, view: &BinaryView) -> Option<()> {
    let call = util::match_call_to_function_named(instr, view, ALLOC_INIT_FUNCTIONS)?;

    util::adjust_return_type_of_call(
        &call,
        return_type_for_alloc_call(&call, view)?.as_ref(),
        Confidence::AllocInit as u8,
    );

    Some(())
}

pub fn process(ac: &AnalysisContext) -> Result<(), Error> {
    let bv = ac.view();
    if GlobalState::should_ignore_view(&bv) {
        return Ok(());
    }

    let mlil = ac.mlil_function().ok_or(Error::MissingIL {
        level: ILLevel::Medium,
        func_start: ac.function().start(),
    })?;
    let mlil_ssa = mlil.ssa_form();

    for block in &mlil_ssa.basic_blocks() {
        for instr in block.iter() {
            process_instruction(&instr.lift(), &bv);
        }
    }

    Ok(())
}
