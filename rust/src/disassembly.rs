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

use crate::string::{BnStr, BnString};
use crate::{BN_FULL_CONFIDENCE, BN_INVALID_EXPR};

use crate::rc::*;

use std::convert::From;
use std::mem;
use std::ptr;

pub type InstructionTextTokenType = BNInstructionTextTokenType;
pub type InstructionTextTokenContext = BNInstructionTextTokenContext;

pub struct InstructionTextToken(pub(crate) BNInstructionTextToken);

// TODO : Consider remodeling this after types::EnumerationMember
impl InstructionTextToken {
    // TODO : New vs new_with_value ?
    pub(crate) unsafe fn from_raw(raw: &BNInstructionTextToken) -> Self {
        Self(raw.clone())
    }

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

    pub fn text(&self) -> &BnStr {
        unsafe { BnStr::from_raw(self.0.text) }
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

impl CoreArrayProvider for InstructionTextToken {
    type Raw = BNInstructionTextToken;
    type Context = ();
}

unsafe impl CoreOwnedArrayProvider for InstructionTextToken {
    unsafe fn free(raw: *mut BNInstructionTextToken, count: usize, _context: &()) {
        BNFreeInstructionText(raw, count);
    }
}

unsafe impl<'a> CoreArrayWrapper<'a> for InstructionTextToken {
    type Wrapped = Guard<'a, InstructionTextToken>;

    unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
        Guard::new(InstructionTextToken::from_raw(raw), _context)
    }
}

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

    pub fn tokens(&self) -> ArrayGuard<InstructionTextToken> {
        unsafe { ArrayGuard::new(self.0.tokens, self.0.count, ()) }
    }
}

impl std::fmt::Display for DisassemblyTextLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tokens: Vec<InstructionTextToken> =
            unsafe { Vec::from_raw_parts(self.0.tokens as *mut _, self.0.count, self.0.count) };

        for token in &tokens {
            let token_string = unsafe { BnString::from_raw(token.0.text) };
            let result = write!(f, "{}", token_string);
            token_string.into_raw();

            if result.is_err() {
                mem::forget(tokens);
                return result;
            }
        }

        mem::forget(tokens);

        Ok(())
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
                offset: 0,
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

impl AsRef<DisassemblySettings> for DisassemblySettings {
    fn as_ref(&self) -> &Self {
        self
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
