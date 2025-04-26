use crate::disassembly::{
    DisassemblySettings, DisassemblyTextLine, InstructionTextToken, InstructionTextTokenType,
};
use crate::high_level_il::HighLevelILFunction;
use crate::language_representation::{OperatorPrecedence, SymbolDisplayResult, SymbolDisplayType};
use crate::rc::{Array, Ref, RefCountable};
use crate::variable::Variable;
use binaryninjacore_sys::{
    BNAddHighLevelILArrayIndexToken, BNAddHighLevelILConstantTextToken,
    BNAddHighLevelILFloatSizeToken, BNAddHighLevelILIntegerTextToken,
    BNAddHighLevelILPointerTextToken, BNAddHighLevelILSizeToken, BNAddHighLevelILVarTextToken,
    BNFreeHighLevelILTokenEmitter, BNHighLevelILTokenEmitter,
    BNHighLevelILTokenEmitterGetCurrentTokens, BNHighLevelILTokenEmitterGetLines,
    BNNewHighLevelILTokenEmitterReference, BNVariable,
};
use std::ptr;

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
        unsafe { RefCountable::inc_ref(self) }
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

crate::impl_simple_functions! {
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
