// Copyright 2021-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TODO : Combine this with the architecture implementation

use binaryninjacore_sys::*;

use crate::architecture::{Architecture, CoreArchitecture};
use crate::basicblock::BasicBlock;
use crate::function::{Function, NativeBlock};
use crate::llil::{FunctionForm, FunctionMutability};
use crate::string::{BnStrCompatible, BnString};
use crate::types::StackVariableReference;
use crate::{hlil, llil, mlil, BN_FULL_CONFIDENCE, BN_INVALID_EXPR};

use crate::rc::*;

use core::ffi;
use std::convert::From;
use std::ffi::CStr;
use std::mem;
use std::ptr;

pub type InstructionTextTokenType = BNInstructionTextTokenType;
pub type InstructionTextTokenContext = BNInstructionTextTokenContext;

// InstructionTextTokenType's; * = Implemented
// *TextToken = 0,
// *InstructionToken = 1,
// *OperandSeparatorToken = 2,
// *RegisterToken = 3,
// *IntegerToken = 4,
// *PossibleAddressToken = 5,
// *BeginMemoryOperandToken = 6,
// *EndMemoryOperandToken = 7,
// *FloatingPointToken = 8,
// AnnotationToken = 9,
// *CodeRelativeAddressToken = 10,
// ArgumentNameToken = 11,
// HexDumpByteValueToken = 12,
// HexDumpSkippedByteToken = 13,
// HexDumpInvalidByteToken = 14,
// HexDumpTextToken = 15,
// OpcodeToken = 16,
// *StringToken = 17,
// CharacterConstantToken = 18,
// *KeywordToken = 19,
// *TypeNameToken = 20,
// *FieldNameToken = 21,
// *NameSpaceToken = 22,
// NameSpaceSeparatorToken = 23,
// TagToken = 24,
// StructOffsetToken = 25,
// StructOffsetByteValueToken = 26,
// StructureHexDumpTextToken = 27,
// *GotoLabelToken = 28,
// CommentToken = 29,
// PossibleValueToken = 30,
// PossibleValueTypeToken = 31,
// ArrayIndexToken = 32,
// *IndentationToken = 33,
// UnknownMemoryToken = 34,
// CodeSymbolToken = 64,
// DataSymbolToken = 65,
// LocalVariableToken = 66,
// ImportToken = 67,
// AddressDisplayToken = 68,
// IndirectImportToken = 69,
// ExternalSymbolToken = 70,

#[repr(transparent)]
pub struct InstructionTextToken(pub(crate) BNInstructionTextToken);

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum InstructionTextTokenContents {
    Text,
    Instruction,
    OperandSeparator,
    Register,
    Integer(u64),         // TODO size?
    PossibleAddress(u64), // TODO size?
    BeginMemoryOperand,
    EndMemoryOperand,
    FloatingPoint,
    CodeRelativeAddress(u64),
    String(u64),
    Keyword,
    TypeName,
    FieldName,
    NameSpace,
    GotoLabel(u64),
    Indentation,
    Brace,
}

impl InstructionTextToken {
    pub(crate) unsafe fn from_raw(raw: &BNInstructionTextToken) -> &Self {
        mem::transmute(raw)
    }

    pub(crate) fn into_raw(self) -> BNInstructionTextToken {
        mem::ManuallyDrop::new(self).0
    }

    pub fn new(text: &str, contents: InstructionTextTokenContents) -> Self {
        let (value, address) = match contents {
            InstructionTextTokenContents::Integer(v) => (v, 0),
            InstructionTextTokenContents::PossibleAddress(v)
            | InstructionTextTokenContents::CodeRelativeAddress(v)
            | InstructionTextTokenContents::GotoLabel(v) => (v, v),
            InstructionTextTokenContents::String(v) => (v, 0),
            _ => (0, 0),
        };

        let type_ = match contents {
            InstructionTextTokenContents::Text => InstructionTextTokenType::TextToken,
            InstructionTextTokenContents::Instruction => InstructionTextTokenType::InstructionToken,
            InstructionTextTokenContents::OperandSeparator => {
                InstructionTextTokenType::OperandSeparatorToken
            }
            InstructionTextTokenContents::Register => InstructionTextTokenType::RegisterToken,
            InstructionTextTokenContents::Integer(_) => InstructionTextTokenType::IntegerToken,
            InstructionTextTokenContents::PossibleAddress(_) => {
                InstructionTextTokenType::PossibleAddressToken
            }
            InstructionTextTokenContents::BeginMemoryOperand => {
                InstructionTextTokenType::BeginMemoryOperandToken
            }
            InstructionTextTokenContents::EndMemoryOperand => {
                InstructionTextTokenType::EndMemoryOperandToken
            }
            InstructionTextTokenContents::FloatingPoint => {
                InstructionTextTokenType::FloatingPointToken
            }
            InstructionTextTokenContents::CodeRelativeAddress(_) => {
                InstructionTextTokenType::CodeRelativeAddressToken
            }
            InstructionTextTokenContents::String(_) => InstructionTextTokenType::StringToken,
            InstructionTextTokenContents::Keyword => InstructionTextTokenType::KeywordToken,
            InstructionTextTokenContents::TypeName => InstructionTextTokenType::TypeNameToken,
            InstructionTextTokenContents::FieldName => InstructionTextTokenType::FieldNameToken,
            InstructionTextTokenContents::NameSpace => InstructionTextTokenType::NameSpaceToken,
            InstructionTextTokenContents::GotoLabel(_) => InstructionTextTokenType::GotoLabelToken,
            InstructionTextTokenContents::Indentation => InstructionTextTokenType::IndentationToken,
            InstructionTextTokenContents::Brace => InstructionTextTokenType::BraceToken,
        };

        let width = text.len() as u64;

        InstructionTextToken(BNInstructionTextToken {
            type_,
            text: BnString::new(text).into_raw(),
            value,
            width,
            size: 0,
            operand: 0xffff_ffff,
            context: InstructionTextTokenContext::NoTokenContext,
            confidence: BN_FULL_CONFIDENCE,
            address,
            typeNames: ptr::null_mut(),
            namesCount: 0,
            exprIndex: BN_INVALID_EXPR,
        })
    }

    pub fn set_value(&mut self, value: u64) {
        self.0.value = value;
    }

    pub fn set_context(&mut self, context: InstructionTextTokenContext) {
        self.0.context = context;
    }

    pub fn text(&self) -> &str {
        unsafe { CStr::from_ptr(self.0.text) }.to_str().unwrap()
    }

    pub fn contents(&self) -> InstructionTextTokenContents {
        use self::BNInstructionTextTokenType::*;
        use self::InstructionTextTokenContents::*;

        match self.0.type_ {
            TextToken => Text,
            InstructionToken => Instruction,
            OperandSeparatorToken => OperandSeparator,
            RegisterToken => Register,
            IntegerToken => Integer(self.0.value),
            PossibleAddressToken => PossibleAddress(self.0.value),
            BeginMemoryOperandToken => BeginMemoryOperand,
            EndMemoryOperandToken => EndMemoryOperand,
            FloatingPointToken => FloatingPoint,
            CodeRelativeAddressToken => CodeRelativeAddress(self.0.value),
            _ => unimplemented!("woops"),
        }
    }

    pub fn context(&self) -> InstructionTextTokenContext {
        self.0.context
    }

    pub fn size(&self) -> usize {
        self.0.size
    }

    pub fn operand(&self) -> usize {
        self.0.operand
    }

    pub fn address(&self) -> u64 {
        self.0.address
    }

    pub fn expr_index(&self) -> usize {
        self.0.exprIndex
    }
}

impl Default for InstructionTextToken {
    fn default() -> Self {
        InstructionTextToken(BNInstructionTextToken {
            type_: InstructionTextTokenType::TextToken,
            text: ptr::null_mut(),
            value: 0,
            width: 0,
            size: 0,
            operand: 0,
            context: InstructionTextTokenContext::NoTokenContext,
            confidence: BN_FULL_CONFIDENCE,
            address: 0,
            typeNames: ptr::null_mut(),
            namesCount: 0,
            exprIndex: BN_INVALID_EXPR,
        })
    }
}

impl Clone for InstructionTextToken {
    fn clone(&self) -> Self {
        InstructionTextToken(BNInstructionTextToken {
            type_: self.0.type_,
            context: self.0.context,
            address: self.0.address,
            size: self.0.size,
            operand: self.0.operand,
            value: self.0.value,
            width: 0,
            text: BnString::new(self.text()).into_raw(),
            confidence: 0xff,
            typeNames: ptr::null_mut(),
            namesCount: 0,
            exprIndex: self.0.exprIndex,
        })
    }
}

impl Drop for InstructionTextToken {
    fn drop(&mut self) {
        if !self.0.text.is_null() {
            let _owned = unsafe { BnString::from_raw(self.0.text) };
        }
        if !self.0.typeNames.is_null() && self.0.namesCount != 0 {
            unsafe { BNFreeStringList(self.0.typeNames, self.0.namesCount) }
        }
    }
}

impl CoreArrayProvider for InstructionTextToken {
    type Raw = BNInstructionTextToken;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}
unsafe impl CoreArrayProviderInner for InstructionTextToken {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeInstructionText(raw, count)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        core::mem::transmute(raw)
    }
}

impl CoreArrayProvider for Array<InstructionTextToken> {
    type Raw = BNInstructionTextLine;
    type Context = ();
    type Wrapped<'a> = mem::ManuallyDrop<Self>;
}
unsafe impl CoreArrayProviderInner for Array<InstructionTextToken> {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeInstructionTextLines(raw, count)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        mem::ManuallyDrop::new(Self::new(raw.tokens, raw.count, ()))
    }
}

#[repr(transparent)]
pub struct DisassemblyTextLine(pub(crate) BNDisassemblyTextLine);

impl DisassemblyTextLine {
    // TODO : this should probably be removed, though it doesn't actually hurt anything
    pub fn debug_print(&self) {
        println!("{}", self);
    }

    pub fn addr(&self) -> u64 {
        self.0.addr
    }

    pub fn instr_idx(&self) -> usize {
        self.0.instrIndex
    }

    pub fn count(&self) -> usize {
        self.0.count
    }

    pub fn tag_count(&self) -> usize {
        self.0.tagCount
    }

    pub fn tokens(&self) -> Vec<InstructionTextToken> {
        unsafe {
            std::slice::from_raw_parts::<BNInstructionTextToken>(self.0.tokens, self.0.count)
                .iter()
                .map(|x| InstructionTextToken::from_raw(x).clone())
                .collect()
        }
    }
}

impl std::fmt::Display for DisassemblyTextLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for token in self.tokens() {
            write!(f, "{}", token.text())?;
        }

        Ok(())
    }
}

impl From<Vec<InstructionTextToken>> for DisassemblyTextLine {
    fn from(tokens: Vec<InstructionTextToken>) -> Self {
        let mut tokens: Box<[_]> = tokens.into();

        // TODO: let (tokens_pointer, tokens_len, _) = unsafe { tokens.into_raw_parts() }; // Can't use for now...still a rust nightly feature
        let tokens_pointer = tokens.as_mut_ptr();
        let tokens_len = tokens.len();
        mem::forget(tokens);

        DisassemblyTextLine(BNDisassemblyTextLine {
            addr: 0,
            instrIndex: BN_INVALID_EXPR,
            tokens: tokens_pointer as *mut _,
            count: tokens_len,
            highlight: BNHighlightColor {
                style: BNHighlightColorStyle::StandardHighlightColor,
                color: BNHighlightStandardColor::NoHighlightColor,
                mixColor: BNHighlightStandardColor::NoHighlightColor,
                mix: 0,
                r: 0,
                g: 0,
                b: 0,
                alpha: 0,
            },
            tags: ptr::null_mut(),
            tagCount: 0,
            typeInfo: BNDisassemblyTextLineTypeInfo {
                hasTypeInfo: false,
                parentType: ptr::null_mut(),
                fieldIndex: usize::MAX,
                offset: 0,
            },
        })
    }
}

impl From<&Vec<&str>> for DisassemblyTextLine {
    fn from(string_tokens: &Vec<&str>) -> Self {
        let mut tokens: Box<[BNInstructionTextToken]> = string_tokens
            .iter()
            .map(|&token| InstructionTextToken::new(token, InstructionTextTokenContents::Text).into_raw())
            .collect();

        // let (tokens_pointer, tokens_len, _) = unsafe { tokens.into_raw_parts() };  // Can't use for now...still a rust nighly feature
        let tokens_pointer = tokens.as_mut_ptr();
        let tokens_len = tokens.len();
        mem::forget(tokens);

        DisassemblyTextLine(BNDisassemblyTextLine {
            addr: 0,
            instrIndex: BN_INVALID_EXPR,
            tokens: tokens_pointer as *mut _,
            count: tokens_len,
            highlight: BNHighlightColor {
                style: BNHighlightColorStyle::StandardHighlightColor,
                color: BNHighlightStandardColor::NoHighlightColor,
                mixColor: BNHighlightStandardColor::NoHighlightColor,
                mix: 0,
                r: 0,
                g: 0,
                b: 0,
                alpha: 0,
            },
            tags: ptr::null_mut(),
            tagCount: 0,
            typeInfo: BNDisassemblyTextLineTypeInfo {
                hasTypeInfo: false,
                parentType: ptr::null_mut(),
                fieldIndex: usize::MAX,
                offset: 0,
            },
        })
    }
}

impl Default for DisassemblyTextLine {
    fn default() -> Self {
        DisassemblyTextLine(BNDisassemblyTextLine {
            addr: 0,
            instrIndex: BN_INVALID_EXPR,
            tokens: ptr::null_mut(),
            count: 0,
            highlight: BNHighlightColor {
                style: BNHighlightColorStyle::StandardHighlightColor,
                color: BNHighlightStandardColor::NoHighlightColor,
                mixColor: BNHighlightStandardColor::NoHighlightColor,
                mix: 0,
                r: 0,
                g: 0,
                b: 0,
                alpha: 0,
            },
            tags: ptr::null_mut(),
            tagCount: 0,
            typeInfo: BNDisassemblyTextLineTypeInfo {
                hasTypeInfo: false,
                parentType: ptr::null_mut(),
                fieldIndex: usize::MAX,
                offset: 0,
            },
        })
    }
}

impl Drop for DisassemblyTextLine {
    fn drop(&mut self) {
        if !self.0.tokens.is_null() {
            let ptr = core::ptr::slice_from_raw_parts_mut(self.0.tokens, self.0.count);
            let _ = unsafe { Box::from_raw(ptr) };
        }
    }
}

impl CoreArrayProvider for DisassemblyTextLine {
    type Raw = BNDisassemblyTextLine;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for DisassemblyTextLine {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeDisassemblyTextLines(raw, count)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        core::mem::transmute(raw)
    }
}

pub type DisassemblyOption = BNDisassemblyOption;

#[derive(PartialEq, Eq, Hash)]
pub struct DisassemblySettings {
    pub(crate) handle: *mut BNDisassemblySettings,
}

impl DisassemblySettings {
    pub fn new() -> Ref<Self> {
        unsafe {
            let handle = BNCreateDisassemblySettings();

            debug_assert!(!handle.is_null());

            Ref::new(Self { handle })
        }
    }

    pub fn set_option(&self, option: DisassemblyOption, state: bool) {
        unsafe { BNSetDisassemblySettingsOption(self.handle, option, state) }
    }

    pub fn is_option_set(&self, option: DisassemblyOption) -> bool {
        unsafe { BNIsDisassemblySettingsOptionSet(self.handle, option) }
    }
}

impl ToOwned for DisassemblySettings {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for DisassemblySettings {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewDisassemblySettingsReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeDisassemblySettings(handle.handle);
    }
}

#[repr(transparent)]
pub struct DisassemblyTextRenderer {
    handle: ptr::NonNull<BNDisassemblyTextRenderer>,
}

impl DisassemblyTextRenderer {
    pub unsafe fn from_raw(handle: ptr::NonNull<BNDisassemblyTextRenderer>) -> Self {
        Self { handle }
    }

    #[allow(clippy::mut_from_ref)]
    pub unsafe fn as_raw(&self) -> &mut BNDisassemblyTextRenderer {
        unsafe { &mut *self.handle.as_ptr() }
    }

    pub fn from_function(func: &Function, settings: Option<&DisassemblySettings>) -> Self {
        let settings_ptr = settings.map(|s| s.handle).unwrap_or(ptr::null_mut());
        let result = unsafe { BNCreateDisassemblyTextRenderer(func.handle, settings_ptr) };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    pub fn from_llil_function<A: Architecture, M: FunctionMutability, F: FunctionForm>(
        func: &llil::Function<A, M, F>,
        settings: Option<&DisassemblySettings>,
    ) -> Self {
        let settings_ptr = settings.map(|s| s.handle).unwrap_or(ptr::null_mut());
        let result =
            unsafe { BNCreateLowLevelILDisassemblyTextRenderer(func.handle, settings_ptr) };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    pub fn from_mlil_function(
        func: &mlil::MediumLevelILFunction,
        settings: Option<&DisassemblySettings>,
    ) -> Self {
        let settings_ptr = settings.map(|s| s.handle).unwrap_or(ptr::null_mut());
        let result =
            unsafe { BNCreateMediumLevelILDisassemblyTextRenderer(func.handle, settings_ptr) };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    pub fn from_hlil_function(
        func: &hlil::HighLevelILFunction,
        settings: Option<&DisassemblySettings>,
    ) -> Self {
        let settings_ptr = settings.map(|s| s.handle).unwrap_or(ptr::null_mut());
        let result =
            unsafe { BNCreateHighLevelILDisassemblyTextRenderer(func.handle, settings_ptr) };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    pub fn function(&self) -> Ref<Function> {
        let result = unsafe { BNGetDisassemblyTextRendererFunction(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { Function::from_raw(result) }
    }

    pub fn llil_function<M: FunctionMutability, F: FunctionForm>(
        &self,
    ) -> Ref<llil::Function<CoreArchitecture, M, F>> {
        let arch = self.arch();
        let result = unsafe { BNGetDisassemblyTextRendererLowLevelILFunction(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { llil::Function::from_raw(arch.handle(), result) }
    }

    pub fn mlil_function(&self) -> Ref<mlil::MediumLevelILFunction> {
        let result = unsafe { BNGetDisassemblyTextRendererMediumLevelILFunction(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { mlil::MediumLevelILFunction::ref_from_raw(result) }
    }

    pub fn hlil_function(&self) -> Ref<hlil::HighLevelILFunction> {
        let result = unsafe { BNGetDisassemblyTextRendererHighLevelILFunction(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { hlil::HighLevelILFunction::ref_from_raw(result, true) }
    }

    pub fn basic_block(&self) -> Option<Ref<BasicBlock<NativeBlock>>> {
        let result = unsafe { BNGetDisassemblyTextRendererBasicBlock(self.as_raw()) };
        if result.is_null() {
            return None;
        }
        Some(unsafe { Ref::new(BasicBlock::from_raw(result, NativeBlock::new())) })
    }

    pub fn set_basic_block(&self, value: Option<&BasicBlock<NativeBlock>>) {
        let block_ptr = value.map(|b| b.handle).unwrap_or(ptr::null_mut());
        unsafe { BNSetDisassemblyTextRendererBasicBlock(self.as_raw(), block_ptr) }
    }

    pub fn arch(&self) -> CoreArchitecture {
        let result = unsafe { BNGetDisassemblyTextRendererArchitecture(self.as_raw()) };
        assert!(!result.is_null());
        CoreArchitecture(result)
    }

    pub fn set_arch(&self, value: CoreArchitecture) {
        unsafe { BNSetDisassemblyTextRendererArchitecture(self.as_raw(), value.0) }
    }

    pub fn settings(&self) -> DisassemblySettings {
        DisassemblySettings {
            handle: unsafe { BNGetDisassemblyTextRendererSettings(self.as_raw()) },
        }
    }

    pub fn set_settings(&self, settings: Option<&DisassemblySettings>) {
        let settings_ptr = settings.map(|s| s.handle).unwrap_or(ptr::null_mut());
        unsafe { BNSetDisassemblyTextRendererSettings(self.as_raw(), settings_ptr) }
    }

    pub fn is_il(&self) -> bool {
        unsafe { BNIsILDisassemblyTextRenderer(self.as_raw()) }
    }

    pub fn has_data_flow(&self) -> bool {
        unsafe { BNDisassemblyTextRendererHasDataFlow(self.as_raw()) }
    }

    pub fn instruction_annotations(&self, addr: u64) -> Array<InstructionTextToken> {
        let mut count = 0;
        let result = unsafe {
            BNGetDisassemblyTextRendererInstructionAnnotations(self.as_raw(), addr, &mut count)
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn instruction_text(&self, addr: u64) -> Option<(Array<DisassemblyTextLine>, usize)> {
        let mut count = 0;
        let mut length = 0;
        let mut lines: *mut BNDisassemblyTextLine = ptr::null_mut();
        let result = unsafe {
            BNGetDisassemblyTextRendererInstructionText(
                self.as_raw(),
                addr,
                &mut length,
                &mut lines,
                &mut count,
            )
        };
        result.then(|| (unsafe { Array::new(lines, count, ()) }, length))
    }

    pub fn disassembly_text(&self, addr: u64) -> Option<(Array<DisassemblyTextLine>, usize)> {
        let mut count = 0;
        let mut length = 0;
        let mut lines: *mut BNDisassemblyTextLine = ptr::null_mut();
        let result = unsafe {
            BNGetDisassemblyTextRendererLines(
                self.as_raw(),
                addr,
                &mut length,
                &mut lines,
                &mut count,
            )
        };
        result.then(|| (unsafe { Array::new(lines, count, ()) }, length))
    }

    // TODO post_process_lines BNPostProcessDisassemblyTextRendererLines

    pub fn is_integer_token(token_type: InstructionTextTokenType) -> bool {
        unsafe { BNIsIntegerToken(token_type) }
    }

    pub fn reset_deduplicated_comments(&self) {
        unsafe { BNResetDisassemblyTextRendererDeduplicatedComments(self.as_raw()) }
    }

    pub fn symbol_tokens(
        &self,
        addr: u64,
        size: usize,
        operand: Option<usize>,
    ) -> Option<Array<InstructionTextToken>> {
        let operand = operand.unwrap_or(0xffffffff);
        let mut count = 0;
        let mut tokens: *mut BNInstructionTextToken = ptr::null_mut();
        let result = unsafe {
            BNGetDisassemblyTextRendererSymbolTokens(
                self.as_raw(),
                addr,
                size,
                operand,
                &mut tokens,
                &mut count,
            )
        };
        result.then(|| unsafe { Array::new(tokens, count, ()) })
    }

    pub fn stack_var_reference_tokens(
        &self,
        ref_: &StackVariableReference,
    ) -> Array<InstructionTextToken> {
        let name = ref_.name().into_bytes_with_nul();
        let mut stack_ref = BNStackVariableReference {
            sourceOperand: ref_.source_operand().unwrap_or(0xffffffff),
            typeConfidence: ref_.variable_type().confidence,
            type_: ref_.variable_type().contents.handle,
            name: name.as_ptr() as *mut ffi::c_char,
            varIdentifier: ref_.variable().identifier(),
            referencedOffset: ref_.offset(),
            size: ref_.size(),
        };
        let mut count = 0;
        let tokens = unsafe {
            BNGetDisassemblyTextRendererStackVariableReferenceTokens(
                self.as_raw(),
                &mut stack_ref,
                &mut count,
            )
        };
        assert!(!tokens.is_null());
        unsafe { Array::new(tokens, count, ()) }
    }

    pub fn integer_token(
        &self,
        int_token: &InstructionTextToken,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<InstructionTextToken> {
        let arch = arch.map(|a| a.0).unwrap_or(ptr::null_mut());
        let mut count = 0;
        let tokens = unsafe {
            BNGetDisassemblyTextRendererIntegerTokens(
                self.as_raw(),
                &int_token.0 as *const BNInstructionTextToken as *mut _,
                arch,
                addr,
                &mut count,
            )
        };
        assert!(!tokens.is_null());
        unsafe { Array::new(tokens, count, ()) }
    }

    pub fn wrap_comment<S1: BnStrCompatible, S2: BnStrCompatible, S3: BnStrCompatible>(
        &self,
        cur_line: &DisassemblyTextLine,
        comment: S1,
        has_auto_annotations: bool,
        leading_spaces: S2,
        indent_spaces: S3,
    ) -> Array<DisassemblyTextLine> {
        //// //leading_spaces: str = "  ", indent_spaces: str = ""
        let tokens = cur_line.tokens();
        let mut tokens_raw: Vec<_> = tokens.iter().map(|x| x.0).collect();
        let mut cur_line_obj = BNDisassemblyTextLine {
            addr: cur_line.addr(),
            instrIndex: cur_line.instr_idx(),
            tokens: tokens_raw.as_mut_ptr(),
            count: tokens.len(),
            highlight: cur_line.0.highlight,
            ..Default::default()
        };
        let mut count = 0;
        let comment_raw = comment.into_bytes_with_nul();
        let leading_spaces_raw = leading_spaces.into_bytes_with_nul();
        let indent_spaces_raw = indent_spaces.into_bytes_with_nul();
        let lines = unsafe {
            BNDisassemblyTextRendererWrapComment(
                self.as_raw(),
                &mut cur_line_obj,
                &mut count,
                comment_raw.as_ref().as_ptr() as *const ffi::c_char,
                has_auto_annotations,
                leading_spaces_raw.as_ref().as_ptr() as *const ffi::c_char,
                indent_spaces_raw.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        assert!(!lines.is_null());
        unsafe { Array::new(lines, count, ()) }
    }
}

impl Clone for DisassemblyTextRenderer {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNNewDisassemblyTextRendererReference(self.as_raw())).unwrap(),
            )
        }
    }
}

impl Drop for DisassemblyTextRenderer {
    fn drop(&mut self) {
        unsafe { BNFreeDisassemblyTextRenderer(self.as_raw()) }
    }
}
