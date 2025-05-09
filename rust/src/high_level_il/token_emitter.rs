use std::ptr::NonNull;

use binaryninjacore_sys::*;

use crate::disassembly::{
    DisassemblySettings, DisassemblyTextLine, InstructionTextToken, InstructionTextTokenContext,
    InstructionTextTokenType,
};
use crate::high_level_il::HighLevelILFunction;
use crate::language_representation::{OperatorPrecedence, SymbolDisplayResult, SymbolDisplayType};
use crate::rc::{Array, Ref, RefCountable};
use crate::variable::Variable;

pub type ScopeType = BNScopeType;
pub type TokenEmitterExpr = BNTokenEmitterExpr;
pub type BraceRequirement = BNBraceRequirement;

#[derive(PartialEq, Eq, Hash)]
pub struct HighLevelILTokenEmitter {
    handle: NonNull<BNHighLevelILTokenEmitter>,
}

impl HighLevelILTokenEmitter {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNHighLevelILTokenEmitter>) -> Self {
        Self { handle }
    }

    /// Returns the list of [`InstructionTextToken`] on the current line.
    pub fn current_tokens(&self) -> Array<InstructionTextToken> {
        let mut count = 0;
        let array =
            unsafe { BNHighLevelILTokenEmitterGetCurrentTokens(self.handle.as_ptr(), &mut count) };
        unsafe { Array::new(array, count, ()) }
    }

    /// Returns the list of [`DisassemblyTextLine`] in the output.
    pub fn lines(&self) -> Array<DisassemblyTextLine> {
        let mut count = 0;
        let array = unsafe { BNHighLevelILTokenEmitterGetLines(self.handle.as_ptr(), &mut count) };
        unsafe { Array::new(array, count, ()) }
    }

    pub fn prepend_collapse_blank_indicator(&self) {
        unsafe { BNHighLevelILTokenPrependCollapseBlankIndicator(self.handle.as_ptr()) };
    }

    pub fn prepend_collapse_indicator(&self, context: InstructionTextTokenContext, hash: u64) {
        unsafe {
            BNHighLevelILTokenPrependCollapseIndicator(self.handle.as_ptr(), context.into(), hash)
        };
    }

    pub fn has_collapsible_regions(&self) -> bool {
        unsafe { BNHighLevelILTokenEmitterHasCollapsableRegions(self.handle.as_ptr()) }
    }

    pub fn set_has_collapsible_regions(&self, state: bool) {
        unsafe { BNHighLevelILTokenEmitterSetHasCollapsableRegions(self.handle.as_ptr(), state) };
    }

    pub fn append(&self, token: InstructionTextToken) {
        let mut raw_token = InstructionTextToken::into_raw(token);
        unsafe { BNHighLevelILTokenEmitterAppend(self.handle.as_ptr(), &mut raw_token) };
        InstructionTextToken::free_raw(raw_token);
    }

    /// Starts a new line in the output.
    pub fn init_line(&self) {
        unsafe { BNHighLevelILTokenEmitterInitLine(self.handle.as_ptr()) };
    }

    // TODO: Difference from `init_line`?
    /// Starts a new line in the output.
    pub fn new_line(&self) {
        unsafe { BNHighLevelILTokenEmitterNewLine(self.handle.as_ptr()) };
    }

    /// Increases the indentation level by one.
    pub fn increase_indent(&self) {
        unsafe { BNHighLevelILTokenEmitterIncreaseIndent(self.handle.as_ptr()) };
    }

    /// Decreases the indentation level by one.
    pub fn decrease_indent(&self) {
        unsafe { BNHighLevelILTokenEmitterDecreaseIndent(self.handle.as_ptr()) };
    }

    /// Indicates that visual separation of scopes is desirable at the current position.
    ///
    /// By default, this will insert a blank line, but this can be configured by the user.
    pub fn scope_separator(&self) {
        unsafe { BNHighLevelILTokenEmitterScopeSeparator(self.handle.as_ptr()) };
    }

    /// Begins a new scope. Insertion of newlines and braces will be handled using the current settings.
    pub fn begin_scope(&self, ty: ScopeType) {
        unsafe { BNHighLevelILTokenEmitterBeginScope(self.handle.as_ptr(), ty) };
    }

    /// Ends the current scope.
    ///
    /// The type `ty` should be equal to what was passed to [`HighLevelILTokenEmitter::begin_scope`].
    pub fn end_scope(&self, ty: ScopeType) {
        unsafe { BNHighLevelILTokenEmitterEndScope(self.handle.as_ptr(), ty) };
    }

    /// Continues the previous scope with a new associated scope. This is most commonly used for else statements.
    ///
    /// If `force_same_line` is true, the continuation will always be placed on the same line as the previous scope.
    pub fn scope_continuation(&self, force_same_line: bool) {
        unsafe {
            BNHighLevelILTokenEmitterScopeContinuation(self.handle.as_ptr(), force_same_line)
        };
    }

    /// Finalizes the previous scope, indicating that there are no more associated scopes.
    pub fn finalize_scope(&self) {
        unsafe { BNHighLevelILTokenEmitterFinalizeScope(self.handle.as_ptr()) };
    }

    /// Forces there to be no indentation for the next line.
    pub fn no_indent_for_this_line(&self) {
        unsafe { BNHighLevelILTokenEmitterNoIndentForThisLine(self.handle.as_ptr()) };
    }

    /// Begins a region of tokens that always have zero confidence.
    pub fn begin_force_zero_confidence(&self) {
        unsafe { BNHighLevelILTokenEmitterBeginForceZeroConfidence(self.handle.as_ptr()) };
    }

    /// Ends a region of tokens that always have zero confidence.
    pub fn end_force_zero_confidence(&self) {
        unsafe { BNHighLevelILTokenEmitterEndForceZeroConfidence(self.handle.as_ptr()) };
    }

    /// Sets the current expression. Returning the [`CurrentTokenEmitterExpr`] which when dropped
    /// will restore the previously active [`TokenEmitterExpr`].
    pub fn set_current_expr(&self, expr: TokenEmitterExpr) -> CurrentTokenEmitterExpr {
        let previous_expr =
            unsafe { BNHighLevelILTokenEmitterSetCurrentExpr(self.handle.as_ptr(), expr) };
        CurrentTokenEmitterExpr::new(self.to_owned(), expr, previous_expr)
    }

    fn restore_current_expr(&self, expr: TokenEmitterExpr) {
        unsafe { BNHighLevelILTokenEmitterRestoreCurrentExpr(self.handle.as_ptr(), expr) };
    }

    /// Finalizes the outputted lines.
    pub fn finalize(&self) {
        unsafe { BNHighLevelILTokenEmitterFinalize(self.handle.as_ptr()) };
    }

    /// Appends `(`.
    pub fn append_open_paren(&self) {
        unsafe { BNHighLevelILTokenEmitterAppendOpenParen(self.handle.as_ptr()) };
    }

    /// Appends `)`.
    pub fn append_close_paren(&self) {
        unsafe { BNHighLevelILTokenEmitterAppendCloseParen(self.handle.as_ptr()) };
    }

    /// Appends `[`.
    pub fn append_open_bracket(&self) {
        unsafe { BNHighLevelILTokenEmitterAppendOpenBracket(self.handle.as_ptr()) };
    }

    /// Appends `]`.
    pub fn append_close_bracket(&self) {
        unsafe { BNHighLevelILTokenEmitterAppendCloseBracket(self.handle.as_ptr()) };
    }

    /// Appends `{`.
    pub fn append_open_brace(&self) {
        unsafe { BNHighLevelILTokenEmitterAppendOpenBrace(self.handle.as_ptr()) };
    }

    /// Appends `}`.
    pub fn append_close_brace(&self) {
        unsafe { BNHighLevelILTokenEmitterAppendCloseBrace(self.handle.as_ptr()) };
    }

    /// Appends `;`.
    pub fn append_semicolon(&self) {
        unsafe { BNHighLevelILTokenEmitterAppendSemicolon(self.handle.as_ptr()) };
    }

    /// Sets the requirement for insertion of braces around scopes in the output.
    pub fn set_brace_requirement(&self, required: BraceRequirement) {
        unsafe { BNHighLevelILTokenEmitterSetBraceRequirement(self.handle.as_ptr(), required) };
    }

    /// Sets whether cases within switch statements should always have braces around them.
    pub fn set_braces_around_switch_cases(&self, braces: bool) {
        unsafe {
            BNHighLevelILTokenEmitterSetBracesAroundSwitchCases(self.handle.as_ptr(), braces)
        };
    }

    /// Sets whether braces should default to being on the same line as the statement that begins the scope.
    ///
    /// If the user has explicitly set a preference, this setting will be ignored and the user's preference will be used instead.
    pub fn set_default_braces_on_same_line(&self, same_line: bool) {
        unsafe {
            BNHighLevelILTokenEmitterSetDefaultBracesOnSameLine(self.handle.as_ptr(), same_line)
        };
    }

    /// Sets whether omitting braces around single-line scopes is allowed.
    pub fn set_simple_scope_allowed(&self, allowed: bool) {
        unsafe { BNHighLevelILTokenEmitterSetSimpleScopeAllowed(self.handle.as_ptr(), allowed) };
    }

    pub fn brace_requirement(&self) -> BraceRequirement {
        unsafe { BNHighLevelILTokenEmitterGetBraceRequirement(self.handle.as_ptr()) }
    }

    pub fn has_braces_around_switch_cases(&self) -> bool {
        unsafe { BNHighLevelILTokenEmitterHasBracesAroundSwitchCases(self.handle.as_ptr()) }
    }

    pub fn default_braces_on_same_line(&self) -> bool {
        unsafe { BNHighLevelILTokenEmitterGetDefaultBracesOnSameLine(self.handle.as_ptr()) }
    }

    pub fn is_simple_scope_allowed(&self) -> bool {
        unsafe { BNHighLevelILTokenEmitterIsSimpleScopeAllowed(self.handle.as_ptr()) }
    }

    /// Appends a size token for the given size in the High Level IL syntax.
    pub fn append_size_token(&self, size: usize, ty: InstructionTextTokenType) {
        unsafe { BNAddHighLevelILSizeToken(size, ty, self.handle.as_ptr()) }
    }

    /// Appends a floating point size token for the given size in the High Level IL syntax.
    pub fn append_float_size_token(&self, size: usize, ty: InstructionTextTokenType) {
        unsafe { BNAddHighLevelILFloatSizeToken(size, ty, self.handle.as_ptr()) }
    }

    /// Appends tokens for access to a variable.
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
                self.handle.as_ptr(),
                expr_index,
                size,
            )
        }
    }

    /// Appends tokens for a constant integer value.
    pub fn append_integer_text_token(
        &self,
        func: &HighLevelILFunction,
        expr_index: usize,
        val: i64,
        size: usize,
    ) {
        unsafe {
            BNAddHighLevelILIntegerTextToken(
                func.handle,
                expr_index,
                val,
                size,
                self.handle.as_ptr(),
            )
        }
    }

    /// Appends tokens for accessing an array by constant index.
    pub fn append_array_index_token(
        &self,
        func: &HighLevelILFunction,
        expr_index: usize,
        val: i64,
        size: usize,
        address: Option<u64>,
    ) {
        unsafe {
            BNAddHighLevelILArrayIndexToken(
                func.handle,
                expr_index,
                val,
                size,
                self.handle.as_ptr(),
                address.unwrap_or(0),
            )
        }
    }

    /// Appends tokens for displaying a constant pointer value.
    ///
    /// If `allow_short_string` is true, then a string will be shown even if it is "short".
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
                self.handle.as_ptr(),
                settings.handle,
                symbol_display,
                precedence,
                allow_short_string,
            )
        }
    }

    /// Appends tokens for a constant value.
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
                self.handle.as_ptr(),
                settings.handle,
                precedence,
            )
        }
    }
}

unsafe impl Send for HighLevelILTokenEmitter {}
unsafe impl Sync for HighLevelILTokenEmitter {}

unsafe impl RefCountable for HighLevelILTokenEmitter {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        let handle = BNNewHighLevelILTokenEmitterReference(handle.handle.as_ptr());
        let handle = NonNull::new(handle).unwrap();
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

/// Manages the currently active [`TokenEmitterExpr`] for the given [`HighLevelILTokenEmitter`].
///
/// When this object is destroyed, the previously active [`TokenEmitterExpr`] will become active again.
pub struct CurrentTokenEmitterExpr {
    pub emitter: Ref<HighLevelILTokenEmitter>,
    pub expr: TokenEmitterExpr,
    pub previous_expr: TokenEmitterExpr,
}

impl CurrentTokenEmitterExpr {
    pub fn new(
        emitter: Ref<HighLevelILTokenEmitter>,
        expr: TokenEmitterExpr,
        previous_expr: TokenEmitterExpr,
    ) -> Self {
        Self {
            emitter,
            expr,
            previous_expr,
        }
    }
}

impl Drop for CurrentTokenEmitterExpr {
    fn drop(&mut self) {
        self.emitter.restore_current_expr(self.previous_expr);
    }
}
