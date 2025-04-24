use core::ffi;

use binaryninjacore_sys::*;

use crate::binary_view::BinaryView;
use crate::disassembly::{DisassemblyTextLine, InstructionTextToken};
use crate::rc::{Ref, RefCountable};
use crate::types::Type;

// NOTE the type_ inside the context can be both owned or borrowed, because
// this type only exist as a reference and is never created by itself (AKA
// don't have a *from_raw function, it don't need to worry about drop it.
#[repr(transparent)]
pub struct TypeContext(BNTypeContext);

impl TypeContext {
    pub fn type_(&self) -> &Type {
        // SAFETY Type and `*mut BNType` are transparent
        unsafe { core::mem::transmute::<&*mut BNType, &Type>(&self.0.type_) }
    }

    pub fn offset(&self) -> usize {
        self.0.offset
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
        prefix: &InstructionTextToken,
        prefix_count: usize,
        width: usize,
        types_ctx: &[TypeContext],
        language: &str,
    ) -> Vec<DisassemblyTextLine>;
}

trait CustomDataRendererFFI: CustomDataRenderer {
    unsafe extern "C" fn free_object_ffi(ctxt: *mut ffi::c_void) {
        drop(Box::from_raw(ctxt as *mut Self))
    }

    unsafe extern "C" fn is_valid_for_data_ffi(
        ctxt: *mut ffi::c_void,
        view: *mut BNBinaryView,
        addr: u64,
        type_: *mut BNType,
        type_ctx: *mut BNTypeContext,
        ctx_count: usize,
    ) -> bool {
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
        ctxt: *mut ffi::c_void,
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
        let ctxt = ctxt as *mut Self;
        // SAFETY BNTypeContext and TypeContext are transparent
        let types = core::slice::from_raw_parts(type_ctx as *mut TypeContext, ctx_count);
        let result = (*ctxt).lines_for_data(
            &BinaryView::from_raw(view),
            addr,
            &Type::from_raw(type_),
            &InstructionTextToken::from_raw(&*prefix),
            prefix_count,
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
        _ctx: *mut ffi::c_void,
        lines: *mut BNDisassemblyTextLine,
        count: usize,
    ) {
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

pub struct CoreDataRenderer(*mut BNDataRenderer);

impl CoreDataRenderer {
    pub(crate) unsafe fn ref_from_raw(raw: *mut BNDataRenderer) -> Ref<Self> {
        Ref::new(Self(raw))
    }
    pub(crate) fn as_raw(&self) -> *mut BNDataRenderer {
        self.0
    }
}

unsafe impl RefCountable for CoreDataRenderer {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(BNNewDataRendererReference(handle.0))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeDataRenderer(handle.0);
    }
}

impl ToOwned for CoreDataRenderer {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { <Self as RefCountable>::inc_ref(self) }
    }
}

fn create_custom_data_renderer<C: CustomDataRenderer>(custom: C) -> Ref<CoreDataRenderer> {
    let custom = Box::leak(Box::new(custom));
    let mut callbacks = BNCustomDataRenderer {
        context: custom as *mut C as *mut ffi::c_void,
        freeObject: Some(<C as CustomDataRendererFFI>::free_object_ffi),
        isValidForData: Some(<C as CustomDataRendererFFI>::is_valid_for_data_ffi),
        getLinesForData: Some(<C as CustomDataRendererFFI>::get_lines_for_data_ffi),
        freeLines: Some(<C as CustomDataRendererFFI>::free_lines_ffi),
    };
    unsafe { CoreDataRenderer::ref_from_raw(BNCreateDataRenderer(&mut callbacks)) }
}

pub fn register_generic_data_renderer<C: CustomDataRenderer>(custom: C) -> Ref<CoreDataRenderer> {
    let renderer = create_custom_data_renderer(custom);
    register_generic_renderer(&renderer);
    renderer
}

pub fn register_specific_data_renderer<C: CustomDataRenderer>(custom: C) -> Ref<CoreDataRenderer> {
    let renderer = create_custom_data_renderer(custom);
    register_specific_renderer(&renderer);
    renderer
}

#[derive(Clone, Copy)]
struct DataRendererContainer(*mut BNDataRendererContainer);

impl DataRendererContainer {
    pub(crate) fn as_raw(&self) -> *mut BNDataRendererContainer {
        self.0
    }

    pub fn get() -> Self {
        Self(unsafe { BNGetDataRendererContainer() })
    }
}

fn register_generic_renderer(renderer: &CoreDataRenderer) {
    let container = DataRendererContainer::get();
    unsafe { BNRegisterGenericDataRenderer(container.as_raw(), renderer.as_raw()) }
}

fn register_specific_renderer(renderer: &CoreDataRenderer) {
    let container = DataRendererContainer::get();
    unsafe { BNRegisterTypeSpecificDataRenderer(container.as_raw(), renderer.as_raw()) }
}
