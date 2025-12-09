//! Render data variables using builtin renderers as well as add custom rendering.

use binaryninjacore_sys::*;
use core::ffi;
use ffi::c_void;
use std::fmt::Debug;
use std::ptr::NonNull;

use crate::binary_view::BinaryView;
use crate::disassembly::{DisassemblyTextLine, InstructionTextToken};
use crate::rc::Array;
use crate::string::BnString;
use crate::types::Type;

/// Registers a custom data renderer, this allows you to customize the representation of data variables.
pub fn register_data_renderer<C: CustomDataRenderer>(
    custom: C,
) -> (&'static mut C, CoreDataRenderer) {
    let renderer = Box::leak(Box::new(custom));
    let mut callbacks = BNCustomDataRenderer {
        context: renderer as *mut _ as *mut c_void,
        freeObject: Some(cb_free_object::<C>),
        isValidForData: Some(cb_is_valid_for_data::<C>),
        getLinesForData: Some(cb_get_lines_for_data::<C>),
        freeLines: Some(cb_free_lines),
    };
    let result = unsafe { BNCreateDataRenderer(&mut callbacks) };
    let core = unsafe { CoreDataRenderer::from_raw(NonNull::new(result).unwrap()) };
    let container = DataRendererContainer::get();
    match C::REGISTRATION_TYPE {
        RegistrationType::Generic => container.register_data_renderer(&core),
        RegistrationType::Specific => container.register_specific_data_renderer(&core),
    }
    (renderer, core)
}

/// Renders the data at the given address using the registered data renderers, returning associated lines.
pub fn render_lines_for_data(
    view: &BinaryView,
    addr: u64,
    type_: &Type,
    prefix: Vec<InstructionTextToken>,
    width: usize,
    types_ctx: &[TypeContext],
    language: Option<&str>,
) -> Vec<DisassemblyTextLine> {
    let bn_prefix: Vec<BNInstructionTextToken> = prefix
        .into_iter()
        .map(InstructionTextToken::into_raw)
        .collect();
    let bn_language = BnString::from(language.unwrap_or(""));

    let mut count: usize = 0;
    let lines_ptr = unsafe {
        BNRenderLinesForData(
            view.handle,
            addr,
            type_.handle,
            bn_prefix.as_ptr(),
            bn_prefix.len(),
            width,
            &mut count as *mut usize,
            types_ctx.as_ptr() as *mut BNTypeContext,
            types_ctx.len(),
            bn_language.as_ptr(),
        )
    };

    for token in bn_prefix {
        InstructionTextToken::free_raw(token);
    }

    let lines_arr: Array<DisassemblyTextLine> = unsafe { Array::new(lines_ptr, count, ()) };
    lines_arr.to_vec()
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

    pub fn register_data_renderer(&self, renderer: &CoreDataRenderer) {
        unsafe { BNRegisterGenericDataRenderer(self.handle, renderer.handle.as_ptr()) };
    }

    pub fn register_specific_data_renderer(&self, renderer: &CoreDataRenderer) {
        unsafe { BNRegisterTypeSpecificDataRenderer(self.handle, renderer.handle.as_ptr()) };
    }
}

/// Used by [`CustomDataRenderer`] to determine the priority of the renderer relative to other registered renderers.
pub enum RegistrationType {
    Generic,
    /// This data renderer wants to run before any generic data renderers.
    ///
    /// Use this if you want to take priority over rendering of specific types.
    Specific,
}

pub trait CustomDataRenderer: Sized + Sync + Send + 'static {
    /// The registration type for the renderer really only determines the priority for the renderer.
    ///
    /// If you are overriding the behavior of a specific type, you should use [`RegistrationType::Specific`].
    const REGISTRATION_TYPE: RegistrationType;

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

pub struct CoreDataRenderer {
    pub(crate) handle: NonNull<BNDataRenderer>,
}

impl CoreDataRenderer {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNDataRenderer>) -> CoreDataRenderer {
        Self { handle }
    }
}

/// Data renderers are recursive, so we keep track of observed types.
///
/// This can be used to influence the rendering of structure fields and related nested types.
#[repr(transparent)]
pub struct TypeContext {
    handle: BNTypeContext,
}

impl TypeContext {
    /// The [`Type`] in the context.
    pub fn ty(&self) -> &Type {
        // SAFETY Type and `*mut BNType` are transparent, and the type is expected to be valid for the lifetime of the context.
        unsafe { core::mem::transmute::<&*mut BNType, &Type>(&self.handle.type_) }
    }

    /// The offset with which the type is associated.
    ///
    /// The offset in many cases refers to a structure byte offset.
    pub fn offset(&self) -> usize {
        self.handle.offset
    }
}

impl Debug for TypeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeContext")
            .field("ty", &self.ty())
            .field("offset", &self.offset())
            .finish()
    }
}

unsafe extern "C" fn cb_free_object<C: CustomDataRenderer>(ctxt: *mut c_void) {
    let _ = Box::from_raw(ctxt as *mut C);
}

unsafe extern "C" fn cb_is_valid_for_data<C: CustomDataRenderer>(
    ctxt: *mut c_void,
    view: *mut BNBinaryView,
    addr: u64,
    type_: *mut BNType,
    type_ctx: *mut BNTypeContext,
    ctx_count: usize,
) -> bool {
    let ctxt = ctxt as *mut C;
    // SAFETY BNTypeContext and TypeContext are transparent
    let types = core::slice::from_raw_parts(type_ctx as *mut TypeContext, ctx_count);
    (*ctxt).is_valid_for_data(
        &BinaryView::from_raw(view),
        addr,
        &Type::from_raw(type_),
        types,
    )
}

unsafe extern "C" fn cb_get_lines_for_data<C: CustomDataRenderer>(
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
    let ctxt = ctxt as *mut C;
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

unsafe extern "C" fn cb_free_lines(
    _ctx: *mut c_void,
    lines: *mut BNDisassemblyTextLine,
    count: usize,
) {
    let lines = Box::from_raw(std::ptr::slice_from_raw_parts_mut(lines, count));
    for line in lines {
        let _ = DisassemblyTextLine::from_raw(&line);
    }
}
