// Copyright 2021 Vector 35 Inc.
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

use crate::string::BnString;
use crate::{BN_FULL_CONFIDENCE, BN_INVALID_EXPR};

use std::convert::From;
use std::mem;
use std::ptr;

pub type InstructionTextTokenType = BNInstructionTextTokenType;
pub type InstructionTextTokenContext = BNInstructionTextTokenContext;

pub struct InstructionTextToken(pub(crate) BNInstructionTextToken);

// TODO : Consider remodeling this after types::EnumerationMember
impl InstructionTextToken {
    // TODO : New vs new_with_value ?

    pub fn new(type_: InstructionTextTokenType, text: &str, value: u64) -> Self {
        let raw_name = BnString::new(text);

        // TODO : Maybe impl Drop for this newtype and perhaps call from_raw for the BnString..I think it's a memory leak otherwise

        InstructionTextToken(BNInstructionTextToken {
            type_: type_,
            text: raw_name.into_raw(),
            value: value,
            width: text.chars().count() as u64,
            size: 0,
            operand: 0xffffffff,
            context: InstructionTextTokenContext::NoTokenContext,
            confidence: BN_FULL_CONFIDENCE,
            address: 0,
            typeNames: ptr::null_mut(),
            namesCount: 0,
        })
    }

    pub fn set_value(&mut self, value: u64) {
        self.0.value = value;
    }

    pub fn set_context(&mut self, context: InstructionTextTokenContext) {
        self.0.context = context;
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
        })
    }
}

pub struct DisassemblyTextLine(pub(crate) BNDisassemblyTextLine);

impl DisassemblyTextLine {
    // TODO : this should probably be removed, though it doesn't actually hurt anything
    pub fn debug_print(&self) {
        let tokens: Vec<InstructionTextToken> =
            unsafe { Vec::from_raw_parts(self.0.tokens as *mut _, self.0.count, self.0.count) };

        for token in &tokens {
            let token_string = unsafe { BnString::from_raw(token.0.text) };
            print!("{}", token_string);
            token_string.into_raw();
        }

        mem::forget(tokens);
    }
}

impl From<Vec<InstructionTextToken>> for DisassemblyTextLine {
    fn from(mut tokens: Vec<InstructionTextToken>) -> Self {
        tokens.shrink_to_fit();

        assert!(tokens.len() == tokens.capacity());
        // let (tokens_pointer, tokens_len, _) = unsafe { tokens.into_raw_parts() }; // Can't use for now...still a rust nighly feature
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
            },
        })
    }
}

impl From<&Vec<&str>> for DisassemblyTextLine {
    fn from(string_tokens: &Vec<&str>) -> Self {
        let mut tokens: Vec<BNInstructionTextToken> = Vec::with_capacity(string_tokens.len());
        tokens.extend(string_tokens.iter().map(|token| {
            InstructionTextToken::new(InstructionTextTokenType::TextToken, token, 0).0
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
