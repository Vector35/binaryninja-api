use std::ffi::{c_char, c_void};
use std::mem::MaybeUninit;
use std::ptr::NonNull;

use binaryninjacore_sys::*;

use crate::architecture::{Architecture, CoreArchitecture};
use crate::basic_block::{BasicBlock, BlockContext};
use crate::binary_view::BinaryView;
use crate::disassembly::{DisassemblySettings, DisassemblyTextLine};
use crate::function::{Function, HighlightColor};
use crate::high_level_il::token_emitter::HighLevelILTokenEmitter;
use crate::high_level_il::{HighLevelExpressionIndex, HighLevelILFunction};
use crate::line_formatter::CoreLineFormatter;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref, RefCountable};
use crate::string::{BnString, IntoCStr};
use crate::type_parser::CoreTypeParser;
use crate::type_printer::CoreTypePrinter;

pub type InstructionTextTokenContext = BNInstructionTextTokenContext;
pub type ScopeType = BNScopeType;
pub type BraceRequirement = BNBraceRequirement;
pub type SymbolDisplayType = BNSymbolDisplayType;
pub type OperatorPrecedence = BNOperatorPrecedence;
pub type SymbolDisplayResult = BNSymbolDisplayResult;

pub fn register_language_representation_function_type<
    C: LanguageRepresentationFunctionType,
    F: FnOnce(CoreLanguageRepresentationFunctionType) -> C,
>(
    creator: F,
    name: &str,
) -> CoreLanguageRepresentationFunctionType {
    let custom = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut callbacks = BNCustomLanguageRepresentationFunctionType {
        context: custom as *mut MaybeUninit<C> as *mut c_void,
        create: Some(cb_create::<C>),
        isValid: Some(cb_is_valid::<C>),
        getTypePrinter: Some(cb_get_type_printer::<C>),
        getTypeParser: Some(cb_get_type_parser::<C>),
        getLineFormatter: Some(cb_get_line_formatter::<C>),
        getFunctionTypeTokens: Some(cb_get_function_type_tokens::<C>),
        freeLines: Some(cb_free_lines),
    };
    let name = name.to_cstr();
    let core =
        unsafe { BNRegisterLanguageRepresentationFunctionType(name.as_ptr(), &mut callbacks) };
    let core =
        unsafe { CoreLanguageRepresentationFunctionType::from_raw(NonNull::new(core).unwrap()) };
    custom.write(creator(core));
    core
}

pub trait LanguageRepresentationFunction: Send + Sync {
    fn on_token_emitter_init(&self, tokens: &HighLevelILTokenEmitter);

    fn expr_text(
        &self,
        il: &HighLevelILFunction,
        expr_index: HighLevelExpressionIndex,
        tokens: &HighLevelILTokenEmitter,
        settings: &DisassemblySettings,
        as_full_ast: bool,
        precedence: OperatorPrecedence,
        statement: bool,
    );

    fn begin_lines(
        &self,
        il: &HighLevelILFunction,
        expr_index: HighLevelExpressionIndex,
        tokens: &HighLevelILTokenEmitter,
    );

    fn end_lines(
        &self,
        il: &HighLevelILFunction,
        expr_index: HighLevelExpressionIndex,
        tokens: &HighLevelILTokenEmitter,
    );

    fn comment_start_string(&self) -> &str;

    fn comment_end_string(&self) -> &str;

    fn annotation_start_string(&self) -> &str;

    fn annotation_end_string(&self) -> &str;
}

pub trait LanguageRepresentationFunctionType: Send + Sync {
    fn create(
        &self,
        arch: &CoreArchitecture,
        owner: &Function,
        high_level_il: &HighLevelILFunction,
    ) -> Ref<CoreLanguageRepresentationFunction>;

    fn is_valid(&self, view: &BinaryView) -> bool;

    fn type_printer(&self) -> Option<CoreTypePrinter> {
        None
    }

    fn type_parser(&self) -> Option<CoreTypeParser> {
        None
    }

    fn line_formatter(&self) -> Option<CoreLineFormatter> {
        None
    }

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
    handle: NonNull<BNLanguageRepresentationFunctionType>,
}

impl CoreLanguageRepresentationFunctionType {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNLanguageRepresentationFunctionType>) -> Self {
        Self { handle }
    }

    pub(crate) fn as_raw(&self) -> *mut BNLanguageRepresentationFunctionType {
        self.handle.as_ptr()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.to_cstr();
        let result = unsafe { BNGetLanguageRepresentationFunctionTypeByName(name.as_ptr()) };
        NonNull::new(result).map(|handle| unsafe { Self::from_raw(handle) })
    }

    pub fn all() -> Array<Self> {
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
                self.handle.as_ptr(),
                func.handle,
                settings.handle,
                &mut count,
            )
        };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn name(&self) -> BnString {
        unsafe {
            BnString::from_raw(BNGetLanguageRepresentationFunctionTypeName(
                self.handle.as_ptr(),
            ))
        }
    }

    pub fn create(&self, func: &Function) -> Ref<CoreLanguageRepresentationFunction> {
        let repr_func = unsafe {
            BNCreateLanguageRepresentationFunction(
                self.handle.as_ptr(),
                func.arch().handle,
                func.handle,
                match func.high_level_il(false) {
                    Ok(hlil) => hlil.handle,
                    Err(_) => std::ptr::null_mut(),
                },
            )
        };

        unsafe {
            CoreLanguageRepresentationFunction::ref_from_raw(NonNull::new(repr_func).unwrap())
        }
    }

    pub fn is_valid(&self, view: &BinaryView) -> bool {
        unsafe { BNIsLanguageRepresentationFunctionTypeValid(self.handle.as_ptr(), view.handle) }
    }

    pub fn printer(&self) -> CoreTypePrinter {
        let type_printer =
            unsafe { BNGetLanguageRepresentationFunctionTypePrinter(self.handle.as_ptr()) };
        unsafe { CoreTypePrinter::from_raw(NonNull::new(type_printer).unwrap()) }
    }

    pub fn parser(&self) -> CoreTypeParser {
        let type_parser =
            unsafe { BNGetLanguageRepresentationFunctionTypeParser(self.handle.as_ptr()) };
        unsafe { CoreTypeParser::from_raw(NonNull::new(type_parser).unwrap()) }
    }

    pub fn line_formatter(&self) -> CoreLineFormatter {
        let formatter =
            unsafe { BNGetLanguageRepresentationFunctionTypeLineFormatter(self.handle.as_ptr()) };
        CoreLineFormatter::from_raw(NonNull::new(formatter).unwrap())
    }
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
        std::mem::transmute::<
            &*mut BNLanguageRepresentationFunctionType,
            &CoreLanguageRepresentationFunctionType,
        >(raw)
    }
}

pub struct CoreLanguageRepresentationFunction {
    handle: NonNull<BNLanguageRepresentationFunction>,
}

impl CoreLanguageRepresentationFunction {
    pub(crate) unsafe fn ref_from_raw(
        handle: NonNull<BNLanguageRepresentationFunction>,
    ) -> Ref<Self> {
        unsafe { Ref::new(Self { handle }) }
    }

    pub fn new<C: LanguageRepresentationFunction, A: Architecture>(
        repr_type: &CoreLanguageRepresentationFunctionType,
        repr_context: C,
        arch: &A,
        func: &Function,
        high_level_il: &HighLevelILFunction,
    ) -> Ref<Self> {
        let core_arch: &CoreArchitecture = arch.as_ref();
        let context: &mut C = Box::leak(Box::new(repr_context));
        let mut callbacks = BNCustomLanguageRepresentationFunction {
            context: context as *mut C as *mut c_void,
            freeObject: Some(cb_free_object::<C>),
            externalRefTaken: Some(cb_external_ref_taken::<C>),
            externalRefReleased: Some(cb_external_ref_released::<C>),
            initTokenEmitter: Some(cb_init_token_emitter::<C>),
            getExprText: Some(cb_get_expr_text::<C>),
            beginLines: Some(cb_begin_lines::<C>),
            endLines: Some(cb_end_lines::<C>),
            getCommentStartString: Some(cb_get_comment_start_string::<C>),
            getCommentEndString: Some(cb_get_comment_end_string::<C>),
            getAnnotationStartString: Some(cb_get_annotation_start_string::<C>),
            getAnnotationEndString: Some(cb_get_annotation_end_string::<C>),
        };
        let handle = unsafe {
            BNCreateCustomLanguageRepresentationFunction(
                repr_type.as_raw(),
                core_arch.handle,
                func.handle,
                high_level_il.handle,
                &mut callbacks,
            )
        };
        unsafe { Self::ref_from_raw(NonNull::new(handle).unwrap()) }
    }

    pub fn expr_text(
        &self,
        il: &HighLevelILFunction,
        expr_index: HighLevelExpressionIndex,
        settings: &DisassemblySettings,
        as_full_ast: bool,
        precedence: OperatorPrecedence,
        statement: bool,
    ) -> Array<DisassemblyTextLine> {
        let mut count = 0;
        let result = unsafe {
            BNGetLanguageRepresentationFunctionExprText(
                self.handle.as_ptr(),
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
        expr_index: HighLevelExpressionIndex,
        settings: &DisassemblySettings,
        as_full_ast: bool,
    ) -> Array<DisassemblyTextLine> {
        let mut count = 0;
        let result = unsafe {
            BNGetLanguageRepresentationFunctionLinearLines(
                self.handle.as_ptr(),
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
                self.handle.as_ptr(),
                block.handle,
                settings.handle,
                &mut count,
            )
        };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn highlight<C: BlockContext>(&self, block: &BasicBlock<C>) -> HighlightColor {
        let result = unsafe {
            BNGetLanguageRepresentationFunctionHighlight(self.handle.as_ptr(), block.handle)
        };
        result.into()
    }

    pub fn get_type(&self) -> CoreLanguageRepresentationFunctionType {
        let repr_type = unsafe { BNGetLanguageRepresentationType(self.handle.as_ptr()) };
        unsafe {
            CoreLanguageRepresentationFunctionType::from_raw(NonNull::new(repr_type).unwrap())
        }
    }

    pub fn arch(&self) -> CoreArchitecture {
        let arch = unsafe { BNGetLanguageRepresentationArchitecture(self.handle.as_ptr()) };
        unsafe { CoreArchitecture::from_raw(arch) }
    }

    pub fn owner_function(&self) -> Ref<Function> {
        let func = unsafe { BNGetLanguageRepresentationOwnerFunction(self.handle.as_ptr()) };
        unsafe { Function::ref_from_raw(func) }
    }

    pub fn hlil(&self) -> Ref<HighLevelILFunction> {
        let hlil = unsafe { BNGetLanguageRepresentationILFunction(self.handle.as_ptr()) };
        unsafe { HighLevelILFunction::ref_from_raw(hlil, false) }
    }

    pub fn comment_start_string(&self) -> BnString {
        unsafe {
            BnString::from_raw(BNGetLanguageRepresentationFunctionCommentStartString(
                self.handle.as_ptr(),
            ))
        }
    }

    pub fn comment_end_string(&self) -> BnString {
        unsafe {
            BnString::from_raw(BNGetLanguageRepresentationFunctionCommentEndString(
                self.handle.as_ptr(),
            ))
        }
    }

    pub fn annotation_start_string(&self) -> BnString {
        unsafe {
            BnString::from_raw(BNGetLanguageRepresentationFunctionAnnotationStartString(
                self.handle.as_ptr(),
            ))
        }
    }

    pub fn annotation_end_string(&self) -> BnString {
        unsafe {
            BnString::from_raw(BNGetLanguageRepresentationFunctionAnnotationEndString(
                self.handle.as_ptr(),
            ))
        }
    }
}

unsafe impl RefCountable for CoreLanguageRepresentationFunction {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(
            NonNull::new(BNNewLanguageRepresentationFunctionReference(
                handle.handle.as_ptr(),
            ))
            .unwrap(),
        )
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeLanguageRepresentationFunction(handle.handle.as_ptr())
    }
}

impl ToOwned for CoreLanguageRepresentationFunction {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { <Self as RefCountable>::inc_ref(self) }
    }
}

unsafe extern "C" fn cb_create<C: LanguageRepresentationFunctionType>(
    ctxt: *mut c_void,
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
    Ref::into_raw(result).handle.as_ptr()
}

unsafe extern "C" fn cb_is_valid<C: LanguageRepresentationFunctionType>(
    ctxt: *mut c_void,
    view: *mut BNBinaryView,
) -> bool {
    let ctxt = ctxt as *mut C;
    let view = BinaryView::from_raw(view);
    (*ctxt).is_valid(&view)
}

unsafe extern "C" fn cb_get_type_printer<C: LanguageRepresentationFunctionType>(
    ctxt: *mut c_void,
) -> *mut BNTypePrinter {
    let ctxt = ctxt as *mut C;
    match (*ctxt).type_printer() {
        None => std::ptr::null_mut(),
        Some(printer) => printer.handle.as_ptr(),
    }
}

unsafe extern "C" fn cb_get_type_parser<C: LanguageRepresentationFunctionType>(
    ctxt: *mut c_void,
) -> *mut BNTypeParser {
    let ctxt = ctxt as *mut C;
    match (*ctxt).type_parser() {
        None => std::ptr::null_mut(),
        Some(parser) => parser.handle.as_ptr(),
    }
}

unsafe extern "C" fn cb_get_line_formatter<C: LanguageRepresentationFunctionType>(
    ctxt: *mut c_void,
) -> *mut BNLineFormatter {
    let ctxt = ctxt as *mut C;
    match (*ctxt).line_formatter() {
        None => std::ptr::null_mut(),
        Some(formatter) => formatter.handle.as_ptr(),
    }
}

unsafe extern "C" fn cb_get_function_type_tokens<C: LanguageRepresentationFunctionType>(
    ctxt: *mut c_void,
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

unsafe extern "C" fn cb_free_lines(
    _ctxt: *mut c_void,
    lines: *mut BNDisassemblyTextLine,
    count: usize,
) {
    let lines: Box<[BNDisassemblyTextLine]> =
        Box::from_raw(core::slice::from_raw_parts_mut(lines, count));
    for line in lines {
        DisassemblyTextLine::free_raw(line);
    }
}

unsafe extern "C" fn cb_free_object<C: LanguageRepresentationFunction>(ctxt: *mut c_void) {
    let ctxt = ctxt as *mut C;
    drop(Box::from_raw(ctxt))
}

unsafe extern "C" fn cb_external_ref_taken<C: LanguageRepresentationFunction>(_ctxt: *mut c_void) {
    // TODO Make an Arc? conflict with free?
}

unsafe extern "C" fn cb_external_ref_released<C: LanguageRepresentationFunction>(
    _ctxt: *mut c_void,
) {
    // TODO Make an Arc? conflict with free?
}

unsafe extern "C" fn cb_init_token_emitter<C: LanguageRepresentationFunction>(
    ctxt: *mut c_void,
    tokens: *mut BNHighLevelILTokenEmitter,
) {
    let ctxt = ctxt as *mut C;
    let tokens = HighLevelILTokenEmitter::from_raw(NonNull::new(tokens).unwrap());
    (*ctxt).on_token_emitter_init(&tokens)
}

unsafe extern "C" fn cb_get_expr_text<C: LanguageRepresentationFunction>(
    ctxt: *mut c_void,
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
    let tokens = HighLevelILTokenEmitter::from_raw(NonNull::new(tokens).unwrap());
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

unsafe extern "C" fn cb_begin_lines<C: LanguageRepresentationFunction>(
    ctxt: *mut c_void,
    il: *mut BNHighLevelILFunction,
    expr_index: usize,
    tokens: *mut BNHighLevelILTokenEmitter,
) {
    let ctxt = ctxt as *mut C;
    let il = HighLevelILFunction {
        full_ast: false,
        handle: il,
    };
    let tokens = HighLevelILTokenEmitter::from_raw(NonNull::new(tokens).unwrap());
    (*ctxt).begin_lines(&il, expr_index.into(), &tokens)
}

unsafe extern "C" fn cb_end_lines<C: LanguageRepresentationFunction>(
    ctxt: *mut c_void,
    il: *mut BNHighLevelILFunction,
    expr_index: usize,
    tokens: *mut BNHighLevelILTokenEmitter,
) {
    let ctxt = ctxt as *mut C;
    let il = HighLevelILFunction {
        full_ast: false,
        handle: il,
    };
    let tokens = HighLevelILTokenEmitter::from_raw(NonNull::new(tokens).unwrap());
    (*ctxt).end_lines(&il, expr_index.into(), &tokens)
}

unsafe extern "C" fn cb_get_comment_start_string<C: LanguageRepresentationFunction>(
    ctxt: *mut c_void,
) -> *mut c_char {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).comment_start_string();
    BnString::into_raw(BnString::new(result))
}

unsafe extern "C" fn cb_get_comment_end_string<C: LanguageRepresentationFunction>(
    ctxt: *mut c_void,
) -> *mut c_char {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).comment_end_string();
    BnString::into_raw(BnString::new(result))
}

unsafe extern "C" fn cb_get_annotation_start_string<C: LanguageRepresentationFunction>(
    ctxt: *mut c_void,
) -> *mut c_char {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).annotation_start_string();
    BnString::into_raw(BnString::new(result))
}

unsafe extern "C" fn cb_get_annotation_end_string<C: LanguageRepresentationFunction>(
    ctxt: *mut c_void,
) -> *mut c_char {
    let ctxt = ctxt as *mut C;
    let result = (*ctxt).annotation_end_string();
    BnString::into_raw(BnString::new(result))
}
