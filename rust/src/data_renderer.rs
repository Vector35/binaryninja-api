use binaryninjacore_sys::*;
use core::ffi;
use ffi::c_void;
use std::ptr::NonNull;

use crate::binary_view::BinaryView;
use crate::disassembly::{DisassemblyTextLine, InstructionTextToken};
use crate::types::Type;

// NOTE the type_ inside the context can be both owned or borrowed, because
// this type only exist as a reference and is never created by itself (AKA
// don't have a *from_raw function, it don't need to worry about drop it.
#[repr(transparent)]
pub struct TypeContext {
    handle: BNTypeContext,
}

impl TypeContext {
    pub fn type_(&self) -> &Type {
        // debug!("TypeContext type_");
        // SAFETY Type and `*mut BNType` are transparent
        unsafe { core::mem::transmute::<&*mut BNType, &Type>(&self.handle.type_) }
    }

    pub fn offset(&self) -> usize {
        // debug!("TypeContext offset");
        self.handle.offset
    }
}

pub trait CustomDataRenderer: Sized + Sync + Send + 'static {
    fn is_valid_for_data(
        &self,
        view: &BinaryView,
        addr: u64,
        type_: &Type,
        types: &[TypeContext],
    ) -> bool;
    fn lines_for_data(
        &self,
        view: &BinaryView,
        addr: u64,
        type_: &Type,
        prefix: Vec<InstructionTextToken>,
        width: usize,
        types_ctx: &[TypeContext],
        language: &str,
    ) -> Vec<DisassemblyTextLine>;
}

trait CustomDataRendererFFI: CustomDataRenderer {
    unsafe extern "C" fn free_object_ffi(ctxt: *mut c_void) {
        // debug!("free_object_ffi");
        drop(Box::from_raw(ctxt as *mut Self))
    }

    unsafe extern "C" fn is_valid_for_data_ffi(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        addr: u64,
        type_: *mut BNType,
        type_ctx: *mut BNTypeContext,
        ctx_count: usize,
    ) -> bool {
        // debug!("is_valid_for_data_ffi");
        let ctxt = ctxt as *mut Self;
        // SAFETY BNTypeContext and TypeContext are transparent
        let types = core::slice::from_raw_parts(type_ctx as *mut TypeContext, ctx_count);
        (*ctxt).is_valid_for_data(
            &BinaryView::from_raw(view),
            addr,
            &Type::from_raw(type_),
            types,
        )
    }

    unsafe extern "C" fn get_lines_for_data_ffi(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        addr: u64,
        type_: *mut BNType,
        prefix: *const BNInstructionTextToken,
        prefix_count: usize,
        width: usize,
        count: *mut usize,
        type_ctx: *mut BNTypeContext,
        ctx_count: usize,
        language: *const ffi::c_char,
    ) -> *mut BNDisassemblyTextLine {
        // debug!("get_lines_for_data_ffi");
        let ctxt = ctxt as *mut Self;
        // SAFETY BNTypeContext and TypeContext are transparent
        let types = core::slice::from_raw_parts(type_ctx as *mut TypeContext, ctx_count);
        let prefix = core::slice::from_raw_parts(prefix, prefix_count)
            .iter()
            .map(InstructionTextToken::from_raw)
            .collect::<Vec<_>>();
        let result = (*ctxt).lines_for_data(
            &BinaryView::from_raw(view),
            addr,
            &Type::from_raw(type_),
            prefix,
            width,
            types,
            ffi::CStr::from_ptr(language).to_str().unwrap(),
        );
        let result: Box<[BNDisassemblyTextLine]> = result
            .into_iter()
            .map(DisassemblyTextLine::into_raw)
            .collect();
        *count = result.len();
        Box::leak(result).as_mut_ptr()
    }

    unsafe extern "C" fn free_lines_ffi(
        _ctx: *mut c_void,
        lines: *mut BNDisassemblyTextLine,
        count: usize,
    ) {
        // debug!("free_lines_ffi");
        let lines = Box::from_raw(core::slice::from_raw_parts_mut(lines, count));
        drop(
            lines
                .iter()
                .map(DisassemblyTextLine::from_raw)
                .collect::<Box<[_]>>(),
        );
    }
}

impl<C: CustomDataRenderer> CustomDataRendererFFI for C {}

pub struct CoreDataRenderer {
    pub(crate) handle: NonNull<BNDataRenderer>,
}

impl CoreDataRenderer {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNDataRenderer>) -> CoreDataRenderer {
        Self { handle }
    }
}

fn create_custom_data_renderer<T: CustomDataRenderer>(
    renderer: T,
) -> (&'static mut T, CoreDataRenderer) {
    let renderer = Box::leak(Box::new(renderer));
    let mut callbacks = BNCustomDataRenderer {
        context: renderer as *mut _ as *mut c_void,
        freeObject: Some(<T as CustomDataRendererFFI>::free_object_ffi),
        isValidForData: Some(<T as CustomDataRendererFFI>::is_valid_for_data_ffi),
        getLinesForData: Some(<T as CustomDataRendererFFI>::get_lines_for_data_ffi),
        freeLines: Some(<T as CustomDataRendererFFI>::free_lines_ffi),
    };
    let result = unsafe { BNCreateDataRenderer(&mut callbacks) };
    let core = unsafe { CoreDataRenderer::from_raw(NonNull::new(result).unwrap()) };
    (renderer, core)
}

pub fn register_generic_data_renderer<T: CustomDataRenderer>(
    custom: T,
) -> (&'static mut T, CoreDataRenderer) {
    let (renderer, core) = create_custom_data_renderer(custom);
    // debug!("register_generic_data_renderer: core={:?}", core.handle);
    let container = DataRendererContainer::get();
    unsafe { BNRegisterGenericDataRenderer(container.handle, core.handle.as_ptr()) }
    (renderer, core)
}

pub fn register_specific_data_renderer<C: CustomDataRenderer>(
    custom: C,
) -> (&'static mut C, CoreDataRenderer) {
    let (renderer, core) = create_custom_data_renderer(custom);
    // debug!("register_specific_data_renderer: core={:?}", core.handle);
    let container = DataRendererContainer::get();
    unsafe { BNRegisterTypeSpecificDataRenderer(container.handle, core.handle.as_ptr()) }
    (renderer, core)
}

#[derive(Clone, Copy)]
struct DataRendererContainer {
    pub(crate) handle: *mut BNDataRendererContainer,
}

impl DataRendererContainer {
    pub fn get() -> Self {
        Self {
            handle: unsafe { BNGetDataRendererContainer() },
        }
    }
}
