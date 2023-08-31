// Copyright 2021-2023 Vector 35 Inc.
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

use crate::string::{BnStr, BnString};
use crate::{BN_FULL_CONFIDENCE, BN_INVALID_EXPR};

use crate::rc::*;

use std::convert::From;
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

#[repr(C)]
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
}

impl InstructionTextToken {
    pub(crate) unsafe fn from_raw(raw: &BNInstructionTextToken) -> Self {
        Self(*raw)
    }

    pub fn new(text: BnString, contents: InstructionTextTokenContents) -> Self {
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
        };

        let width = text.len() as u64;

        InstructionTextToken(BNInstructionTextToken {
            type_,
            text: text.into_raw(),
            value,
            width,
            size: 0,
            operand: 0xffff_ffff,
            context: InstructionTextTokenContext::NoTokenContext,
            confidence: BN_FULL_CONFIDENCE,
            address,
            typeNames: ptr::null_mut(),
            namesCount: 0,
            ilExprIndex: usize::MAX,
        })
    }

    pub fn set_value(&mut self, value: u64) {
        self.0.value = value;
    }

    pub fn set_context(&mut self, context: InstructionTextTokenContext) {
        self.0.context = context;
    }

    pub fn text(&self) -> &BnStr {
        unsafe { BnStr::from_raw(self.0.text) }
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
            ilExprIndex: usize::MAX,
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
            ilExprIndex: usize::MAX,
        })
    }
}

// TODO : There is almost certainly a memory leak here - in the case where
//  `impl CoreOwnedArrayProvider for InstructionTextToken` doesn't get triggered
// impl Drop for InstructionTextToken {
//     fn drop(&mut self) {
//         let _owned = unsafe { BnString::from_raw(self.0.text) };
//     }
// }

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
                .map(|&x| InstructionTextToken::from_raw(&x))
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
    fn from(mut tokens: Vec<InstructionTextToken>) -> Self {
        tokens.shrink_to_fit();

        assert!(tokens.len() == tokens.capacity());
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
        let mut tokens: Vec<BNInstructionTextToken> = Vec::with_capacity(string_tokens.len());
        tokens.extend(string_tokens.iter().map(|&token| {
            InstructionTextToken::new(BnString::new(token), InstructionTextTokenContents::Text).0
        }));

        assert!(tokens.len() == tokens.capacity());
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
        unsafe {
            Vec::from_raw_parts(self.0.tokens, self.0.count, self.0.count);
        }
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
