use std::mem::MaybeUninit;

use binaryninjacore_sys::*;

use crate::{
    binaryview::BinaryView,
    disassembly::{DisassemblyTextLine, InstructionTextToken},
    types::{Type, TypeContext},
};

#[repr(transparent)]
pub struct CoreDataRenderer(*mut BNDataRenderer);

pub trait DataRenderer: 'static + Sized {
    fn is_valid_for_data(
        &mut self,
        view: &BinaryView,
        addr: u64,
        data_type: &Type,
        type_ctx: &[TypeContext],
    ) -> bool;
    fn get_lines_for_data(
        &mut self,
        view: &BinaryView,
        addr: u64,
        data_type: &Type,
        prefix: &[InstructionTextToken],
        width: usize,
        type_ctx: &[TypeContext],
    ) -> Vec<DisassemblyTextLine>;
}

// TODO 'static? where the `free_object` happen? can this static out-live that?
pub fn register_datarenderer<S, F>(func: F) -> &'static S
where
    S: DataRenderer + Send + Sync,
    // TODO I assume there is no need for the DataRenderer to store it's own
    // handle, I'm using this builder function just in case it is.
    F: FnOnce(CoreDataRenderer) -> S,
{
    let mut slf_uninit: Box<MaybeUninit<S>> = Box::new(MaybeUninit::zeroed());
    let mut custom = BNCustomDataRenderer {
        context: slf_uninit.as_mut_ptr() as *mut _,
        freeObject: Some(free_object::<S>),
        isValidForData: Some(is_valid_for_data::<S>),
        getLinesForData: Some(get_lines_for_data::<S>),
        freeLines: Some(free_lines),
    };
    let handle = unsafe { BNCreateDataRenderer(&mut custom as *mut _) };
    assert!(!handle.is_null());
    let slf = func(CoreDataRenderer(handle));

    // initialize the context and return it
    slf_uninit.write(slf);
    // NOTE: this is freed by the `free_object` function
    unsafe { Box::leak(slf_uninit).assume_init_ref() }
}

unsafe extern "C" fn is_valid_for_data<R: DataRenderer + Sized>(
    ctxt: *mut ::std::os::raw::c_void,
    view: *mut BNBinaryView,
    addr: u64,
    data_type: *mut BNType,
    type_ctx: *mut BNTypeContext,
    ctx_count: usize,
) -> bool {
    let slf: &mut R = &mut *(ctxt as *mut R);
    let type_ctx = core::slice::from_raw_parts(type_ctx as *mut TypeContext, ctx_count);

    // NOTE not owned, so don't use Ref, to avoid the drop
    let view = BinaryView { handle: view };
    let data_type = Type { handle: data_type };

    slf.is_valid_for_data(&view, addr, &data_type, type_ctx)
}

unsafe extern "C" fn get_lines_for_data<R: DataRenderer + Sized>(
    ctxt: *mut ::std::os::raw::c_void,
    view: *mut BNBinaryView,
    addr: u64,
    data_type: *mut BNType,
    prefix: *const BNInstructionTextToken,
    prefix_count: usize,
    width: usize,
    count: *mut usize,
    type_ctx: *mut BNTypeContext,
    ctx_count: usize,
) -> *mut BNDisassemblyTextLine {
    let slf: &mut R = &mut *(ctxt as *mut R);

    // NOTE not owned, so don't use Ref, to avoid the drop
    let view = BinaryView { handle: view };
    let data_type = Type { handle: data_type };

    let prefix = core::slice::from_raw_parts(prefix as *const InstructionTextToken, prefix_count);
    let type_ctx = core::slice::from_raw_parts(type_ctx as *mut TypeContext, ctx_count);

    let result: Box<[DisassemblyTextLine]> = slf
        .get_lines_for_data(&view, addr, &data_type, prefix, width, type_ctx)
        .into();
    unsafe { *count = result.len() };
    // NOTE drop happen on `free_lines`
    Box::into_raw(result) as *mut BNDisassemblyTextLine
}

unsafe extern "C" fn free_object<R: DataRenderer + Sized>(ctxt: *mut ::std::os::raw::c_void) {
    let slf: Box<R> = Box::from_raw(ctxt as *mut R);
    // TODO this should call BNFreeDataRenderer? Or vise-versa?
    drop(slf);
}

unsafe extern "C" fn free_lines(
    _ctx: *mut ::std::os::raw::c_void,
    lines: *mut BNDisassemblyTextLine,
    count: usize,
) {
    let lines_ptr = core::slice::from_raw_parts_mut(lines as *mut DisassemblyTextLine, count);
    let _lines = unsafe { Box::from_raw(lines_ptr) };
}
