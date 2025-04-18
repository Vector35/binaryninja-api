use core::ffi;
use std::mem::MaybeUninit;
use std::ptr;

use binaryninjacore_sys::*;

use crate::architecture::{Architecture, CoreArchitecture};
use crate::basic_block::{BasicBlock, BlockContext};
use crate::binary_view::BinaryView;
use crate::disassembly::{
    DisassemblySettings, DisassemblyTextLine, InstructionTextToken, InstructionTextTokenType,
};
use crate::function::{Function, HighlightColor};
use crate::high_level_il::{HighLevelILFunction, HighLevelInstructionIndex};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};
use crate::type_parser::CoreTypeParser;
use crate::type_printer::CoreTypePrinter;
use crate::variable::Variable;

pub type InstructionTextTokenContext = BNInstructionTextTokenContext;
pub type ScopeType = BNScopeType;
pub type BraceRequirement = BNBraceRequirement;
pub type TokenEmitterExpr = BNTokenEmitterExpr;
pub type SymbolDisplayType = BNSymbolDisplayType;
pub type OperatorPrecedence = BNOperatorPrecedence;
pub type SymbolDisplayResult = BNSymbolDisplayResult;
pub type LineFormatterSettings = BNLineFormatterSettings;

macro_rules! impl_simple_functions {
    (
        $type_name:ident,
        $(
            $function_name:ident -> $function_name_ffi:ident(
                $(
                    $arg_name:ident:
                    $arg_type:ty
                    $(
                        : $arg_type_ffi:ty =
                            $( $rust2ffi:expr )?
                    )?
                ),* $(,)?
            ) $(-> $ret_type:ty $(| $ret_name:ident = $ret2rust:expr)?)?
        ),* $(,)?
    ) => {
        impl $type_name {
            $(
            pub fn $function_name(&self, $($arg_name: $arg_type),*) $(-> $ret_type)* {
                $(
                    $($(
                        let $arg_name: $arg_type_ffi = $rust2ffi;
                    )*)*
                )*
                let result = unsafe { $function_name_ffi(self.as_raw(), $($arg_name),*) };
                $($(
                    let $ret_name = result;
                    let result = $ret2rust;
                )*)*
                result
            }
            )*
        }
    };
}

pub trait CustomLanguageRepresentationFunction: Send + Sync + 'static {
    fn init_token_emitter(&self, tokens: &HighLevelILTokenEmitter);
    fn expr_text(
        &self,
        il: &HighLevelILFunction,
        expr_index: HighLevelInstructionIndex,
        tokens: &HighLevelILTokenEmitter,
        settings: &DisassemblySettings,
        as_full_ast: bool,
        precedence: OperatorPrecedence,
        statement: bool,
    );
    fn begin_lines(
        &self,
        il: &HighLevelILFunction,
        expr_index: HighLevelInstructionIndex,
        tokens: &HighLevelILTokenEmitter,
    );
    fn end_lines(
        &self,
        il: &HighLevelILFunction,
        expr_index: HighLevelInstructionIndex,
        tokens: &HighLevelILTokenEmitter,
    );
    fn comment_start_string(&self) -> &str;
    fn comment_end_string(&self) -> &str;
    fn annotation_start_string(&self) -> &str;
    fn annotation_end_string(&self) -> &str;
}

pub struct CoreLanguageRepresentationFunction {
    handle: ptr::NonNull<BNLanguageRepresentationFunction>,
}

impl CoreLanguageRepresentationFunction {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNLanguageRepresentationFunction>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(
        handle: ptr::NonNull<BNLanguageRepresentationFunction>,
    ) -> Ref<Self> {
        unsafe { Ref::new(Self { handle }) }
    }

    pub(crate) unsafe fn into_raw(self) -> *mut BNLanguageRepresentationFunction {
        // NOTE don't drop self, leak in the ptr form
        let Self { handle } = self;
        handle.as_ptr()
    }

    pub(crate) fn as_raw(&self) -> *mut BNLanguageRepresentationFunction {
        self.handle.as_ptr()
    }
}

unsafe impl RefCountable for CoreLanguageRepresentationFunction {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(
            ptr::NonNull::new(BNNewLanguageRepresentationFunctionReference(
                handle.as_raw(),
            ))
            .unwrap(),
        )
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeLanguageRepresentationFunction(handle.as_raw())
    }
}

impl ToOwned for CoreLanguageRepresentationFunction {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { <Self as RefCountable>::inc_ref(self) }
    }
}

impl_simple_functions! {
    CoreLanguageRepresentationFunction,
    get_type -> BNGetLanguageRepresentationType(
    ) -> CoreLanguageRepresentationFunctionType | result
        = unsafe { CoreLanguageRepresentationFunctionType::from_raw(ptr::NonNull::new(result).unwrap()) },
    arch -> BNGetLanguageRepresentationArchitecture() -> CoreArchitecture | result
        = unsafe { CoreArchitecture::from_raw(result) },
    owner_function ->  BNGetLanguageRepresentationOwnerFunction() -> Ref<Function> | result
        = unsafe { Function::ref_from_raw(result) },
    il_function -> BNGetLanguageRepresentationILFunction() -> Ref<HighLevelILFunction> | result
        // TODO full_ast here is unclear
        = unsafe { HighLevelILFunction::ref_from_raw(result, false) },
    comment_start_string -> BNGetLanguageRepresentationFunctionCommentStartString(
    ) -> BnString | result = unsafe{ BnString::from_raw(result) },
    comment_end_string -> BNGetLanguageRepresentationFunctionCommentEndString(
    ) -> BnString | result = unsafe{ BnString::from_raw(result) },
    annotation_start_string-> BNGetLanguageRepresentationFunctionAnnotationStartString(
    ) -> BnString | result = unsafe{ BnString::from_raw(result) },
    annotation_end_string-> BNGetLanguageRepresentationFunctionAnnotationEndString(
    ) -> BnString | result = unsafe{ BnString::from_raw(result) },
}

impl CoreLanguageRepresentationFunction {
    pub fn expr_text(
        &self,
        il: &HighLevelILFunction,
        expr_index: HighLevelInstructionIndex,
        settings: &DisassemblySettings,
        as_full_ast: bool,
        precedence: OperatorPrecedence,
        statement: bool,
    ) -> Array<DisassemblyTextLine> {
        let mut count = 0;
        let result = unsafe {
            BNGetLanguageRepresentationFunctionExprText(
                self.as_raw(),
                il.handle,
                expr_index.0,
                settings.handle,
                as_full_ast,
                precedence,
                statement,
                &mut count,
            )
        };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn linear_lines(
        &self,
        il: &HighLevelILFunction,
        expr_index: HighLevelInstructionIndex,
        settings: &DisassemblySettings,
        as_full_ast: bool,
    ) -> Array<DisassemblyTextLine> {
        let mut count = 0;
        let result = unsafe {
            BNGetLanguageRepresentationFunctionLinearLines(
                self.as_raw(),
                il.handle,
                expr_index.0,
                settings.handle,
                as_full_ast,
                &mut count,
            )
        };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn block_lines<C: BlockContext>(
        &self,
        block: &BasicBlock<C>,
        settings: &DisassemblySettings,
    ) -> Array<DisassemblyTextLine> {
        let mut count = 0;
        let result = unsafe {
            BNGetLanguageRepresentationFunctionBlockLines(
                self.as_raw(),
                block.handle,
                settings.handle,
                &mut count,
            )
        };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn highlight<C: BlockContext>(&self, block: &BasicBlock<C>) -> HighlightColor {
        let result =
            unsafe { BNGetLanguageRepresentationFunctionHighlight(self.as_raw(), block.handle) };
        result.into()
    }
}

pub fn create_language_representation_function<
    C: CustomLanguageRepresentationFunction,
    A: Architecture,
>(
    context: C,
    type_: &CoreLanguageRepresentationFunctionType,
    arch: &A,
    func: &Function,
    high_level_il: &HighLevelILFunction,
) -> CoreLanguageRepresentationFunction {
    let core_arch: &CoreArchitecture = arch.as_ref();
    let context: &mut C = Box::leak(Box::new(context));
    let mut callbacks = BNCustomLanguageRepresentationFunction {
        context: context as *mut C as *mut ffi::c_void,
        freeObject: Some(function_free_ffi::<C>),
        externalRefTaken: Some(function_external_ref_taken::<C>),
        externalRefReleased: Some(function_external_ref_released::<C>),
        initTokenEmitter: Some(function_init_token_emitter::<C>),
        getExprText: Some(function_get_expr_text::<C>),
        beginLines: Some(function_begin_lines::<C>),
        endLines: Some(function_end_lines::<C>),
        getCommentStartString: Some(function_get_comment_start_string::<C>),
        getCommentEndString: Some(function_get_comment_end_string::<C>),
        getAnnotationStartString: Some(function_get_annotation_start_string::<C>),
        getAnnotationEndString: Some(function_get_annotation_end_string::<C>),
    };
    let handle = unsafe {
        BNCreateCustomLanguageRepresentationFunction(
            type_.as_raw(),
            core_arch.handle,
            func.handle,
            high_level_il.handle,
            &mut callbacks,
        )
    };
    unsafe { CoreLanguageRepresentationFunction::from_raw(ptr::NonNull::new(handle).unwrap()) }
}

unsafe extern "C" fn function_free_ffi<C: CustomLanguageRepresentationFunction>(
    ctxt: *mut ffi::c_void,
) {
    let ctxt = ctxt as *mut C;
    drop(Box::from_raw(ctxt))
}

unsafe extern "C" fn function_external_ref_taken<C: CustomLanguageRepresentationFunction>(
    _ctxt: *mut ffi::c_void,
) {
    // TODO Make an Arc? conflict with free?
}

unsafe extern "C" fn function_external_ref_released<C: CustomLanguageRepresentationFunction>(
    _ctxt: *mut ffi::c_void,
) {
    // TODO Make an Arc? conflict with free?
}

unsafe extern "C" fn function_init_token_emitter<C: CustomLanguageRepresentationFunction>(
    ctxt: *mut ffi::c_void,
    tokens: *mut BNHighLevelILTokenEmitter,
) {
    let ctxt = ctxt as *mut C;
    let tokens = HighLevelILTokenEmitter::from_raw(ptr::NonNull::new(tokens).unwrap());
    (*ctxt).init_token_emitter(&tokens)
}

unsafe extern "C" fn function_get_expr_text<C: CustomLanguageRepresentationFunction>(
    ctxt: *mut ffi::c_void,
    il: *mut BNHighLevelILFunction,
    expr_index: usize,
    tokens: *mut BNHighLevelILTokenEmitter,
    settings: *mut BNDisassemblySettings,
    as_full_ast: bool,
    precedence: BNOperatorPrecedence,
    statement: bool,
) {
    let ctxt = ctxt as *mut C;
    let il = HighLevelILFunction {
        full_ast: as_full_ast,
        handle: il,
    };
    let tokens = HighLevelILTokenEmitter::from_raw(ptr::NonNull::new(tokens).unwrap());
    let settings = DisassemblySettings { handle: settings };
    (*ctxt).expr_text(
        &il,
        expr_index.into(),
        &tokens,
        &settings,
        as_full_ast,
        precedence,
        statement,
    );
}

unsafe extern "C" fn function_begin_lines<C: CustomLanguageRepresentationFunction>(
    ctxt: *mut ffi::c_void,
    il: *mut BNHighLevelILFunction,
    expr_index: usize,
    tokens: *mut BNHighLevelILTokenEmitter,
) {
    let ctxt = ctxt as *mut C;
    let il = HighLevelILFunction {
        full_ast: false,
        handle: il,
    };
    let tokens = HighLevelILTokenEmitter::from_raw(ptr::NonNull::new(tokens).unwrap());
    (*ctxt).begin_lines(&il, expr_index.into(), &tokens)
}

unsafe extern "C" fn function_end_lines<C: CustomLanguageRepresentationFunction>(
    ctxt: *mut ffi::c_void,
    il: *mut BNHighLevelILFunction,
    expr_index: usize,
    tokens: *mut BNHighLevelILTokenEmitter,
) {
    let ctxt = ctxt as *mut C;
    let il = HighLevelILFunction {
        full_ast: false,
        handle: il,
    };
    let tokens = HighLevelILTokenEmitter::from_raw(ptr::NonNull::new(tokens).unwrap());
    (*ctxt).end_lines(&il, expr_index.into(), &tokens)
}

unsafe extern "C" fn function_get_comment_start_string<C: CustomLanguageRepresentationFunction>(
    ctxt: *mut ffi::c_void,
) -> *mut ffi::c_char {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).comment_start_string();
    BnString::into_raw(BnString::new(result))
}

unsafe extern "C" fn function_get_comment_end_string<C: CustomLanguageRepresentationFunction>(
    ctxt: *mut ffi::c_void,
) -> *mut ffi::c_char {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).comment_end_string();
    BnString::into_raw(BnString::new(result))
}

unsafe extern "C" fn function_get_annotation_start_string<
    C: CustomLanguageRepresentationFunction,
>(
    ctxt: *mut ffi::c_void,
) -> *mut ffi::c_char {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).annotation_start_string();
    BnString::into_raw(BnString::new(result))
}

unsafe extern "C" fn function_get_annotation_end_string<C: CustomLanguageRepresentationFunction>(
    ctxt: *mut ffi::c_void,
) -> *mut ffi::c_char {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).annotation_end_string();
    BnString::into_raw(BnString::new(result))
}

pub trait CustomLanguageRepresentationFunctionType {
    fn create(
        &self,
        arch: &CoreArchitecture,
        owner: &Function,
        high_level_il: &HighLevelILFunction,
    ) -> CoreLanguageRepresentationFunction;
    fn is_valid(&self, view: &BinaryView) -> bool;
    fn type_printer(&self) -> &CoreTypePrinter;
    fn type_parser(&self) -> &CoreTypeParser;
    fn line_formatter(&self) -> &CoreLineFormatter;
    fn function_type_tokens(
        &self,
        func: &Function,
        settings: &DisassemblySettings,
    ) -> Vec<DisassemblyTextLine>;
}

// NOTE static, it never gets freed, so we can clone/copy it
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct CoreLanguageRepresentationFunctionType {
    handle: ptr::NonNull<BNLanguageRepresentationFunctionType>,
}

impl CoreLanguageRepresentationFunctionType {
    pub(crate) unsafe fn from_raw(
        handle: ptr::NonNull<BNLanguageRepresentationFunctionType>,
    ) -> Self {
        Self { handle }
    }

    pub(crate) fn as_raw(&self) -> *mut BNLanguageRepresentationFunctionType {
        self.handle.as_ptr()
    }

    pub fn get_by_name<B: BnStrCompatible>(name: B) -> Option<Self> {
        let name = name.into_bytes_with_nul();
        let result = unsafe {
            BNGetLanguageRepresentationFunctionTypeByName(
                name.as_ref().as_ptr() as *const ffi::c_char
            )
        };
        ptr::NonNull::new(result).map(|handle| unsafe { Self::from_raw(handle) })
    }

    pub fn get_all() -> Array<Self> {
        let mut count = 0;
        let result = unsafe { BNGetLanguageRepresentationFunctionTypeList(&mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn tokens(
        &self,
        func: &Function,
        settings: &DisassemblySettings,
    ) -> Array<DisassemblyTextLine> {
        let mut count = 0;
        let result = unsafe {
            BNGetLanguageRepresentationFunctionTypeFunctionTypeTokens(
                self.as_raw(),
                func.handle,
                settings.handle,
                &mut count,
            )
        };
        unsafe { Array::new(result, count, ()) }
    }
}

impl_simple_functions! {
    CoreLanguageRepresentationFunctionType,
    name -> BNGetLanguageRepresentationFunctionTypeName(
    ) -> BnString | result = unsafe { BnString::from_raw(result) },
    create -> BNCreateLanguageRepresentationFunction(
        arch: &CoreArchitecture: *mut BNArchitecture = arch.handle,
        func: &Function: *mut BNFunction = func.handle,
        high_level_il: &HighLevelILFunction: *mut BNHighLevelILFunction = high_level_il.handle,
    ) -> CoreLanguageRepresentationFunction | result
        = unsafe{ CoreLanguageRepresentationFunction::from_raw(ptr::NonNull::new(result).unwrap()) },
    is_valid -> BNIsLanguageRepresentationFunctionTypeValid(
        view: &BinaryView: *mut BNBinaryView = view.handle,
    ) -> bool,
    printer -> BNGetLanguageRepresentationFunctionTypePrinter(
    ) -> CoreTypePrinter | result
        = unsafe { CoreTypePrinter::from_raw(ptr::NonNull::new(result).unwrap()) },
    parser -> BNGetLanguageRepresentationFunctionTypeParser(
    ) -> CoreTypeParser | result
        = unsafe { CoreTypeParser::from_raw(ptr::NonNull::new(result).unwrap()) },
    line_formatter -> BNGetLanguageRepresentationFunctionTypeLineFormatter(
    ) -> CoreLineFormatter | result
        = unsafe { CoreLineFormatter::from_raw(ptr::NonNull::new(result).unwrap()) },
}

impl CoreArrayProvider for CoreLanguageRepresentationFunctionType {
    type Raw = *mut BNLanguageRepresentationFunctionType;
    type Context = ();
    type Wrapped<'a> = &'a CoreLanguageRepresentationFunctionType;
}

unsafe impl CoreArrayProviderInner for CoreLanguageRepresentationFunctionType {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeLanguageRepresentationFunctionTypeList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // SAFETY: CoreLanguageRepresentationFunctionType and BNCoreLanguageRepresentationFunctionType
        // transparent
        core::mem::transmute::<
            &*mut BNLanguageRepresentationFunctionType,
            &CoreLanguageRepresentationFunctionType,
        >(raw)
    }
}

pub fn register_language_representation_function_type<
    C: CustomLanguageRepresentationFunctionType,
    F: FnOnce(CoreLanguageRepresentationFunctionType) -> C,
    B: BnStrCompatible,
>(
    creator: F,
    name: B,
) -> CoreLanguageRepresentationFunctionType {
    let custom = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut callbacks = BNCustomLanguageRepresentationFunctionType {
        context: custom as *mut MaybeUninit<C> as *mut ffi::c_void,
        create: Some(function_type_create_ffi::<C>),
        isValid: Some(function_type_is_valid_ffi::<C>),
        getTypePrinter: Some(function_type_get_type_printer_ffi::<C>),
        getTypeParser: Some(function_type_get_type_parser_ffi::<C>),
        getLineFormatter: Some(function_type_get_line_formatter_ffi::<C>),
        getFunctionTypeTokens: Some(function_type_get_function_type_tokens::<C>),
        freeLines: Some(function_type_free_lines_ffi),
    };
    let name = name.into_bytes_with_nul();
    let core = unsafe {
        BNRegisterLanguageRepresentationFunctionType(
            name.as_ref().as_ptr() as *const ffi::c_char,
            &mut callbacks,
        )
    };
    let core = unsafe {
        CoreLanguageRepresentationFunctionType::from_raw(ptr::NonNull::new(core).unwrap())
    };
    custom.write(creator(core));
    core
}

unsafe extern "C" fn function_type_create_ffi<C: CustomLanguageRepresentationFunctionType>(
    ctxt: *mut ffi::c_void,
    arch: *mut BNArchitecture,
    owner: *mut BNFunction,
    high_level_il: *mut BNHighLevelILFunction,
) -> *mut BNLanguageRepresentationFunction {
    let ctxt = ctxt as *mut C;
    let arch = CoreArchitecture::from_raw(arch);
    let owner = Function::from_raw(owner);
    let high_level_il = HighLevelILFunction {
        full_ast: false,
        handle: high_level_il,
    };
    let result = (*ctxt).create(&arch, &owner, &high_level_il);
    result.into_raw()
}

unsafe extern "C" fn function_type_is_valid_ffi<C: CustomLanguageRepresentationFunctionType>(
    ctxt: *mut ffi::c_void,
    view: *mut BNBinaryView,
) -> bool {
    let ctxt = ctxt as *mut C;
    let view = BinaryView::from_raw(view);
    (*ctxt).is_valid(&view)
}

unsafe extern "C" fn function_type_get_type_printer_ffi<
    C: CustomLanguageRepresentationFunctionType,
>(
    ctxt: *mut ffi::c_void,
) -> *mut BNTypePrinter {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).type_printer();
    result.as_raw()
}

unsafe extern "C" fn function_type_get_type_parser_ffi<
    C: CustomLanguageRepresentationFunctionType,
>(
    ctxt: *mut ffi::c_void,
) -> *mut BNTypeParser {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).type_parser();
    result.as_raw()
}

unsafe extern "C" fn function_type_get_line_formatter_ffi<
    C: CustomLanguageRepresentationFunctionType,
>(
    ctxt: *mut ffi::c_void,
) -> *mut BNLineFormatter {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).line_formatter();
    result.as_raw()
}

unsafe extern "C" fn function_type_get_function_type_tokens<
    C: CustomLanguageRepresentationFunctionType,
>(
    ctxt: *mut ffi::c_void,
    func: *mut BNFunction,
    settings: *mut BNDisassemblySettings,
    count: *mut usize,
) -> *mut BNDisassemblyTextLine {
    let ctxt = ctxt as *mut C;
    let func = Function::from_raw(func);
    let settings = DisassemblySettings { handle: settings };
    let result = (*ctxt).function_type_tokens(&func, &settings);
    *count = result.len();
    let result: Box<[BNDisassemblyTextLine]> = result
        .into_iter()
        .map(DisassemblyTextLine::into_raw)
        .collect();
    // NOTE freed by function_type_free_lines_ffi
    Box::leak(result).as_mut_ptr()
}

unsafe extern "C" fn function_type_free_lines_ffi(
    _ctxt: *mut ffi::c_void,
    lines: *mut BNDisassemblyTextLine,
    count: usize,
) {
    let lines: Box<[BNDisassemblyTextLine]> =
        Box::from_raw(core::slice::from_raw_parts_mut(lines, count));
    drop(lines);
}

pub trait CustomLineFormatter {
    fn format_lines(
        &self,
        lines: &[DisassemblyTextLine],
        settings: &LineFormatterSettings,
    ) -> Vec<DisassemblyTextLine>;
}

pub struct CoreLineFormatter {
    handle: ptr::NonNull<BNLineFormatter>,
}

impl CoreLineFormatter {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNLineFormatter>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn as_raw(&self) -> *mut BNLineFormatter {
        self.handle.as_ptr()
    }
}

pub fn register_line_formatter<C: CustomLineFormatter, B: BnStrCompatible>(
    name: B,
    custom: C,
) -> CoreLineFormatter {
    let custom = Box::leak(Box::new(custom));
    let mut callbacks = BNCustomLineFormatter {
        context: custom as *mut C as *mut ffi::c_void,
        formatLines: Some(line_formatter_format_lines_ffi::<C>),
        freeLines: Some(line_formatter_free_lines_ffi),
    };
    let name = name.into_bytes_with_nul();
    let handle = unsafe {
        BNRegisterLineFormatter(name.as_ref().as_ptr() as *const ffi::c_char, &mut callbacks)
    };
    unsafe { CoreLineFormatter::from_raw(ptr::NonNull::new(handle).unwrap()) }
}

unsafe extern "C" fn line_formatter_format_lines_ffi<C: CustomLineFormatter>(
    ctxt: *mut ffi::c_void,
    in_lines: *mut BNDisassemblyTextLine,
    in_count: usize,
    settings: *const BNLineFormatterSettings,
    out_count: *mut usize,
) -> *mut BNDisassemblyTextLine {
    // NOTE dropped by line_formatter_free_lines_ffi
    let ctxt = ctxt as *mut C;
    let lines = core::slice::from_raw_parts(in_lines, in_count);
    let lines: Vec<_> = lines.iter().map(DisassemblyTextLine::from_raw).collect();
    let result = (*ctxt).format_lines(&lines, &*settings);
    *out_count = result.len();
    let result: Box<[BNDisassemblyTextLine]> = result
        .into_iter()
        .map(DisassemblyTextLine::into_raw)
        .collect();
    Box::leak(result).as_mut_ptr()
}

unsafe extern "C" fn line_formatter_free_lines_ffi(
    _ctxt: *mut ffi::c_void,
    lines: *mut BNDisassemblyTextLine,
    count: usize,
) {
    let lines: Box<[BNDisassemblyTextLine]> =
        Box::from_raw(core::slice::from_raw_parts_mut(lines, count));
    drop(lines);
}

/// High level token emitter
#[derive(PartialEq, Eq, Hash)]
pub struct HighLevelILTokenEmitter {
    handle: ptr::NonNull<BNHighLevelILTokenEmitter>,
}

unsafe impl Send for HighLevelILTokenEmitter {}
unsafe impl Sync for HighLevelILTokenEmitter {}

unsafe impl RefCountable for HighLevelILTokenEmitter {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        let handle = BNNewHighLevelILTokenEmitterReference(handle.handle.as_ptr());
        let handle = ptr::NonNull::new(handle).unwrap();
        Ref::new(HighLevelILTokenEmitter { handle })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeHighLevelILTokenEmitter(handle.handle.as_ptr())
    }
}

impl ToOwned for HighLevelILTokenEmitter {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { <Self as RefCountable>::inc_ref(self) }
    }
}

impl HighLevelILTokenEmitter {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNHighLevelILTokenEmitter>) -> Self {
        Self { handle }
    }

    pub(crate) fn as_raw(&self) -> *mut BNHighLevelILTokenEmitter {
        self.handle.as_ptr()
    }
}

impl_simple_functions! {
    HighLevelILTokenEmitter,
    prepend_collapse_blank_indicator -> BNHighLevelILTokenPrependCollapseBlankIndicator(),
    prepend_collapse_indicator -> BNHighLevelILTokenPrependCollapseIndicator(
        context: InstructionTextTokenContext: BNInstructionTextTokenContext = context,
        hash: u64,
    ),
    has_collapsable_regions -> BNHighLevelILTokenEmitterHasCollapsableRegions() -> bool,
    set_has_collapsable_regions -> BNHighLevelILTokenEmitterSetHasCollapsableRegions(
        state: bool,
    ),
    append -> BNHighLevelILTokenEmitterAppend (
        token: InstructionTextToken: *mut BNInstructionTextToken = &mut InstructionTextToken::into_raw(token),
    ),
    init_line -> BNHighLevelILTokenEmitterInitLine(),
    new_line -> BNHighLevelILTokenEmitterNewLine(),
    increase_indent -> BNHighLevelILTokenEmitterIncreaseIndent(),
    decrease_indent -> BNHighLevelILTokenEmitterDecreaseIndent(),
    scope_separator -> BNHighLevelILTokenEmitterScopeSeparator(),
    begin_scope -> BNHighLevelILTokenEmitterBeginScope(
        type_: ScopeType,
    ),
    end_scope -> BNHighLevelILTokenEmitterEndScope(
        type_: ScopeType,
    ),
    scope_continuation -> BNHighLevelILTokenEmitterScopeContinuation(
        force_same_line: bool,
    ),
    finalize_scope -> BNHighLevelILTokenEmitterFinalizeScope(),
    no_indent_for_this_line -> BNHighLevelILTokenEmitterNoIndentForThisLine(),
    begin_force_zero_confidence -> BNHighLevelILTokenEmitterBeginForceZeroConfidence(),
    end_force_zero_confidence -> BNHighLevelILTokenEmitterEndForceZeroConfidence(),
    set_current_expr -> BNHighLevelILTokenEmitterSetCurrentExpr(
        expr: TokenEmitterExpr,
    ) -> TokenEmitterExpr,
    restore_current_expr -> BNHighLevelILTokenEmitterRestoreCurrentExpr(
        expr: TokenEmitterExpr,
    ),
    finalize -> BNHighLevelILTokenEmitterFinalize(),
    append_open_paren -> BNHighLevelILTokenEmitterAppendOpenParen(),
    append_close_paren -> BNHighLevelILTokenEmitterAppendCloseParen(),
    append_open_bracket -> BNHighLevelILTokenEmitterAppendOpenBracket(),
    append_close_bracket -> BNHighLevelILTokenEmitterAppendCloseBracket(),
    append_open_brace -> BNHighLevelILTokenEmitterAppendOpenBrace(),
    append_close_brace -> BNHighLevelILTokenEmitterAppendCloseBrace(),
    append_semicolon -> BNHighLevelILTokenEmitterAppendSemicolon(),
    set_brace_requirement -> BNHighLevelILTokenEmitterSetBraceRequirement(
        required: BraceRequirement,
    ),
    set_braces_around_switch_cases -> BNHighLevelILTokenEmitterSetBracesAroundSwitchCases(
        braces: bool,
    ),
    set_default_braces_on_same_line -> BNHighLevelILTokenEmitterSetDefaultBracesOnSameLine(
        same_line: bool,
    ),
    set_simple_scope_allowed -> BNHighLevelILTokenEmitterSetSimpleScopeAllowed(
        allowed: bool,
    ),
    brace_requirement -> BNHighLevelILTokenEmitterGetBraceRequirement() -> BraceRequirement,
    has_braces_around_switch_cases -> BNHighLevelILTokenEmitterHasBracesAroundSwitchCases() -> bool,
    default_braces_on_same_line -> BNHighLevelILTokenEmitterGetDefaultBracesOnSameLine() -> bool,
    is_simple_scope_allowed -> BNHighLevelILTokenEmitterIsSimpleScopeAllowed() -> bool,
}

impl HighLevelILTokenEmitter {
    pub fn current_tokens(&self) -> Array<InstructionTextToken> {
        let mut count = 0;
        let array = unsafe { BNHighLevelILTokenEmitterGetCurrentTokens(self.as_raw(), &mut count) };
        unsafe { Array::new(array, count, ()) }
    }
    pub fn lines(&self) -> Array<DisassemblyTextLine> {
        let mut count = 0;
        let array = unsafe { BNHighLevelILTokenEmitterGetLines(self.as_raw(), &mut count) };
        unsafe { Array::new(array, count, ()) }
    }

    pub fn append_size_token(&self, size: usize, type_: InstructionTextTokenType) {
        unsafe { BNAddHighLevelILSizeToken(size, type_, self.as_raw()) }
    }

    pub fn append_float_size_token(&self, size: usize, type_: InstructionTextTokenType) {
        unsafe { BNAddHighLevelILFloatSizeToken(size, type_, self.as_raw()) }
    }

    pub fn append_var_text_token(
        &self,
        func: &HighLevelILFunction,
        var: Variable,
        expr_index: usize,
        size: usize,
    ) {
        unsafe {
            BNAddHighLevelILVarTextToken(
                func.handle,
                &BNVariable::from(var),
                self.as_raw(),
                expr_index,
                size,
            )
        }
    }

    pub fn append_integer_text_token(
        &self,
        func: &HighLevelILFunction,
        expr_index: usize,
        val: i64,
        size: usize,
    ) {
        unsafe {
            BNAddHighLevelILIntegerTextToken(func.handle, expr_index, val, size, self.as_raw())
        }
    }

    pub fn append_array_index_token(
        &self,
        func: &HighLevelILFunction,
        expr_index: usize,
        val: i64,
        size: usize,
        address: u64,
    ) {
        unsafe {
            BNAddHighLevelILArrayIndexToken(
                func.handle,
                expr_index,
                val,
                size,
                self.as_raw(),
                address,
            )
        }
    }

    pub fn append_pointer_text_token(
        &self,
        func: &HighLevelILFunction,
        expr_index: usize,
        val: i64,
        settings: &DisassemblySettings,
        symbol_display: SymbolDisplayType,
        precedence: OperatorPrecedence,
        allow_short_string: bool,
    ) -> SymbolDisplayResult {
        unsafe {
            BNAddHighLevelILPointerTextToken(
                func.handle,
                expr_index,
                val,
                self.as_raw(),
                settings.handle,
                symbol_display,
                precedence,
                allow_short_string,
            )
        }
    }

    pub fn append_constant_text_token(
        &self,
        func: &HighLevelILFunction,
        expr_index: usize,
        val: i64,
        size: usize,
        settings: &DisassemblySettings,
        precedence: OperatorPrecedence,
    ) {
        unsafe {
            BNAddHighLevelILConstantTextToken(
                func.handle,
                expr_index,
                val,
                size,
                self.as_raw(),
                settings.handle,
                precedence,
            )
        }
    }
}

pub fn get_function_language_representation<B: BnStrCompatible>(
    func: &Function,
    lang_name: B,
) -> Option<CoreLanguageRepresentationFunction> {
    let lang_name = lang_name.into_bytes_with_nul();
    let repr = unsafe {
        BNGetFunctionLanguageRepresentationIfAvailable(
            func.handle,
            lang_name.as_ref().as_ptr() as *const ffi::c_char,
        )
    };
    ptr::NonNull::new(repr)
        .map(|handle| unsafe { CoreLanguageRepresentationFunction::from_raw(handle) })
}
