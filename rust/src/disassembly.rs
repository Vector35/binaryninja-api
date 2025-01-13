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
#![allow(unused)]

use binaryninjacore_sys::*;

use crate::string::{raw_to_string, strings_to_string_list, BnString};

use crate::rc::*;

use crate::confidence::MAX_CONFIDENCE;
use crate::function::HighlightColor;
use crate::tags::Tag;
use crate::types::Type;
use std::convert::From;
use std::fmt::{Display, Formatter};

pub type DisassemblyOption = BNDisassemblyOption;
pub type InstructionTextTokenType = BNInstructionTextTokenType;
pub type StringType = BNStringType;

#[derive(Clone, PartialEq, Debug, Default)]
pub struct DisassemblyTextLine {
    pub address: u64,
    pub instruction_index: usize,
    pub tokens: Vec<InstructionTextToken>,
    pub highlight: HighlightColor,
    pub tags: Vec<Ref<Tag>>,
    pub type_info: DisassemblyTextLineTypeInfo,
}

impl DisassemblyTextLine {
    pub(crate) fn from_raw(value: &BNDisassemblyTextLine) -> Self {
        let raw_tokens = unsafe { std::slice::from_raw_parts(value.tokens, value.count) };
        let tokens: Vec<_> = raw_tokens
            .iter()
            .map(InstructionTextToken::from_raw)
            .collect();
        // SAFETY: Increment the tag ref as we are going from ref to owned.
        let raw_tags = unsafe { std::slice::from_raw_parts(value.tags, value.tagCount) };
        let tags: Vec<_> = raw_tags
            .iter()
            .map(|&t| unsafe { Tag::from_raw(t) }.to_owned())
            .collect();
        Self {
            address: value.addr,
            instruction_index: value.instrIndex,
            tokens,
            highlight: value.highlight.into(),
            tags,
            type_info: DisassemblyTextLineTypeInfo::from_raw(&value.typeInfo),
        }
    }

    /// Convert into a raw [BNDisassemblyTextLine], use with caution.
    ///
    /// NOTE: The allocations here for tokens and tags MUST be freed by rust using [Self::free_raw].
    pub(crate) fn into_raw(value: Self) -> BNDisassemblyTextLine {
        // NOTE: The instruction text and type names fields are being leaked here. To be freed with [Self::free_raw].
        let tokens: Box<[BNInstructionTextToken]> = value
            .tokens
            .into_iter()
            .map(InstructionTextToken::into_raw)
            .collect();
        let tags: Box<[*mut BNTag]> = value
            .tags
            .into_iter()
            .map(|t| {
                // SAFETY: The tags ref will be temporarily incremented here, until [Self::free_raw] is called.
                // SAFETY: This is so that tags lifetime is long enough, as we might be the last holders of the ref.
                unsafe { Ref::into_raw(t) }.handle
            })
            .collect();
        BNDisassemblyTextLine {
            addr: value.address,
            instrIndex: value.instruction_index,
            count: tokens.len(),
            // NOTE: Leaking tokens here to be freed with [Self::free_raw].
            tokens: Box::leak(tokens).as_mut_ptr(),
            highlight: value.highlight.into(),
            tagCount: tags.len(),
            // NOTE: Leaking tags here to be freed with [Self::free_raw].
            tags: Box::leak(tags).as_mut_ptr(),
            typeInfo: DisassemblyTextLineTypeInfo::into_raw(value.type_info),
        }
    }

    /// Frees raw object created with [Self::into_raw], use with caution.
    ///
    /// NOTE: The allocations freed MUST have been created in rust using [Self::into_raw].
    pub(crate) fn free_raw(value: BNDisassemblyTextLine) {
        // Free the token list
        let raw_tokens = unsafe { std::slice::from_raw_parts_mut(value.tokens, value.count) };
        let boxed_tokens = unsafe { Box::from_raw(raw_tokens) };
        for token in boxed_tokens {
            // SAFETY: As we have leaked the token contents we need to now free them (text and typeNames).
            InstructionTextToken::free_raw(token);
        }
        // Free the tag list
        let raw_tags = unsafe { std::slice::from_raw_parts_mut(value.tags, value.tagCount) };
        let boxed_tags = unsafe { Box::from_raw(raw_tags) };
        for tag in boxed_tags {
            // SAFETY: As we have incremented the tags ref in [Self::into_raw] we must now decrement.
            let _ = unsafe { Tag::ref_from_raw(tag) };
        }
        // Free the type info
        DisassemblyTextLineTypeInfo::free_raw(value.typeInfo);
    }

    pub fn new(tokens: Vec<InstructionTextToken>) -> Self {
        Self {
            tokens,
            ..Default::default()
        }
    }
}

impl From<&str> for DisassemblyTextLine {
    fn from(value: &str) -> Self {
        Self::new(vec![InstructionTextToken::new(
            value,
            InstructionTextTokenKind::Text,
        )])
    }
}

impl From<String> for DisassemblyTextLine {
    fn from(value: String) -> Self {
        Self::new(vec![InstructionTextToken::new(
            value,
            InstructionTextTokenKind::Text,
        )])
    }
}

impl Display for DisassemblyTextLine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for token in &self.tokens {
            write!(f, "{}", token)?;
        }
        Ok(())
    }
}

impl CoreArrayProvider for DisassemblyTextLine {
    type Raw = BNDisassemblyTextLine;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for DisassemblyTextLine {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeDisassemblyTextLines(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(raw)
    }
}

#[derive(Default, Clone, PartialEq, Eq, Debug, Hash)]
pub struct DisassemblyTextLineTypeInfo {
    pub has_type_info: bool,
    pub parent_type: Option<Ref<Type>>,
    pub field_index: usize,
    pub offset: u64,
}

impl DisassemblyTextLineTypeInfo {
    pub(crate) fn from_raw(value: &BNDisassemblyTextLineTypeInfo) -> Self {
        Self {
            has_type_info: value.hasTypeInfo,
            parent_type: match value.parentType.is_null() {
                false => Some(unsafe { Type::from_raw(value.parentType).to_owned() }),
                true => None,
            },
            field_index: value.fieldIndex,
            offset: value.offset,
        }
    }

    pub(crate) fn from_owned_raw(value: BNDisassemblyTextLineTypeInfo) -> Self {
        Self {
            has_type_info: value.hasTypeInfo,
            parent_type: match value.parentType.is_null() {
                false => Some(unsafe { Type::ref_from_raw(value.parentType) }),
                true => None,
            },
            field_index: value.fieldIndex,
            offset: value.offset,
        }
    }

    pub(crate) fn into_raw(value: Self) -> BNDisassemblyTextLineTypeInfo {
        BNDisassemblyTextLineTypeInfo {
            hasTypeInfo: value.has_type_info,
            parentType: value
                .parent_type
                .map(|t| unsafe { Ref::into_raw(t) }.handle)
                .unwrap_or(std::ptr::null_mut()),
            fieldIndex: value.field_index,
            offset: value.offset,
        }
    }

    pub(crate) fn into_owned_raw(value: &Self) -> BNDisassemblyTextLineTypeInfo {
        BNDisassemblyTextLineTypeInfo {
            hasTypeInfo: value.has_type_info,
            parentType: value
                .parent_type
                .as_ref()
                .map(|t| t.handle)
                .unwrap_or(std::ptr::null_mut()),
            fieldIndex: value.field_index,
            offset: value.offset,
        }
    }

    pub(crate) fn free_raw(value: BNDisassemblyTextLineTypeInfo) {
        if !value.parentType.is_null() {
            let _ = unsafe { Type::ref_from_raw(value.parentType) };
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InstructionTextToken {
    pub address: u64,
    pub text: String,
    pub confidence: u8,
    pub context: InstructionTextTokenContext,
    // TODO: Document that this is not necessary to set and that this is valid in a limited context.
    pub expr_index: usize,
    pub kind: InstructionTextTokenKind,
}

impl InstructionTextToken {
    pub(crate) fn from_raw(value: &BNInstructionTextToken) -> Self {
        Self {
            address: value.address,
            text: raw_to_string(value.text).unwrap(),
            confidence: value.confidence,
            context: value.context.into(),
            expr_index: value.exprIndex,
            kind: InstructionTextTokenKind::from_raw(value),
        }
    }

    pub(crate) fn into_raw(value: Self) -> BNInstructionTextToken {
        let bn_text = BnString::new(value.text);
        // These can be gathered from value.kind
        let kind_value = value.kind.try_value().unwrap_or(0);
        let operand = value.kind.try_operand().unwrap_or(0);
        let size = value.kind.try_size().unwrap_or(0);
        let type_names = value.kind.try_type_names().unwrap_or_default();
        BNInstructionTextToken {
            type_: value.kind.into(),
            // NOTE: Expected to be freed with `InstructionTextToken::free_raw`.
            text: BnString::into_raw(bn_text),
            value: kind_value,
            // TODO: Where is this even used?
            width: 0,
            size,
            operand,
            context: value.context.into(),
            confidence: value.confidence,
            address: value.address,
            // NOTE: Expected to be freed with `InstructionTextToken::free_raw`.
            typeNames: strings_to_string_list(&type_names),
            namesCount: type_names.len(),
            exprIndex: value.expr_index,
        }
    }

    pub(crate) fn free_raw(value: BNInstructionTextToken) {
        if !value.text.is_null() {
            unsafe { BNFreeString(value.text) };
        }
        if !value.typeNames.is_null() {
            unsafe { BNFreeStringList(value.typeNames, value.namesCount) };
        }
    }

    pub fn new(text: impl Into<String>, kind: InstructionTextTokenKind) -> Self {
        Self {
            address: 0,
            text: text.into(),
            confidence: MAX_CONFIDENCE,
            context: InstructionTextTokenContext::Normal,
            expr_index: 0,
            kind,
        }
    }

    pub fn new_with_address(
        address: u64,
        text: impl Into<String>,
        kind: InstructionTextTokenKind,
    ) -> Self {
        Self {
            address,
            text: text.into(),
            confidence: MAX_CONFIDENCE,
            context: InstructionTextTokenContext::Normal,
            expr_index: 0,
            kind,
        }
    }
}

impl Display for InstructionTextToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.text.fmt(f)
    }
}

impl CoreArrayProvider for InstructionTextToken {
    type Raw = BNInstructionTextToken;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for InstructionTextToken {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        // SAFETY: The Array MUST have been allocated on the core side. This will `delete[] raw`.
        BNFreeInstructionText(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(raw)
    }
}

impl CoreArrayProvider for Array<InstructionTextToken> {
    type Raw = BNInstructionTextLine;
    type Context = ();
    type Wrapped<'a> = std::mem::ManuallyDrop<Self>;
}

unsafe impl CoreArrayProviderInner for Array<InstructionTextToken> {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        // SAFETY: The Array MUST have been allocated on the core side. This will `delete[] raw`.
        BNFreeInstructionTextLines(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // TODO: This is insane.
        std::mem::ManuallyDrop::new(Self::new(raw.tokens, raw.count, ()))
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum InstructionTextTokenKind {
    Text,
    Instruction,
    OperandSeparator,
    Register,
    Integer {
        value: u64,
        /// Size of the integer
        size: Option<usize>,
    },
    PossibleAddress {
        value: u64,
        /// Size of the address
        size: Option<usize>,
    },
    BeginMemoryOperand,
    EndMemoryOperand,
    FloatingPoint {
        value: f64,
        /// Size of the floating point
        size: Option<usize>,
    },
    Annotation,
    CodeRelativeAddress {
        value: u64,
        size: Option<usize>,
    },
    ArgumentName {
        // TODO: The argument index?
        value: u64,
    },
    HexDumpByteValue {
        value: u8,
    },
    HexDumpSkippedByte,
    HexDumpInvalidByte,
    HexDumpText {
        // TODO: Explain what this does
        width: u64,
    },
    Opcode,
    String {
        ty: StringType,
    },
    CharacterConstant,
    Keyword,
    TypeName,
    FieldName {
        /// Offset to this field in the respective structure
        offset: u64,
        /// Stores the type names for the referenced field name.
        ///
        /// This is typically just the members name.
        /// For example MyStructure.my_field will have type_names be \["my_field"\].
        type_names: Vec<String>,
    },
    NameSpace,
    NameSpaceSeparator,
    Tag,
    StructOffset {
        /// Offset to this field in the respective structure
        offset: u64,
        // TODO: This makes no sense for struct offset, they dont have types?
        /// Stores the type names for the referenced field name.
        type_names: Vec<String>,
    },
    // TODO: Unused?
    StructOffsetByteValue,
    // TODO: Unused?
    StructureHexDumpText {
        // TODO: Explain what this does
        width: u64,
    },
    GotoLabel {
        target: u64,
    },
    Comment {
        target: u64,
    },
    PossibleValue {
        value: u64,
    },
    // TODO: This is weird, you pass the value type as the text, we should restrict this behavior and type it
    PossibleValueType,
    ArrayIndex {
        index: u64,
    },
    Indentation,
    UnknownMemory,
    EnumerationMember {
        value: u64,
        // TODO: Document where this type id comes from
        // TODO: Can we type this to something other than a string?
        /// The enumerations type id
        type_id: Option<String>,
    },
    /// Operations like +, -, %
    Operation,
    BaseStructureName,
    BaseStructureSeparator,
    Brace {
        // TODO: Explain what this is
        hash: Option<u64>,
    },
    CodeSymbol {
        // TODO: Value of what?
        value: u64,
        // TODO: Size of what?
        size: usize, // TODO: Operand?
    },
    DataSymbol {
        // TODO: Value of what?
        value: u64,
        // TODO: Size of what?
        size: usize, // TODO: Operand?
    },
    LocalVariable {
        // This comes from the token.value
        // TODO: Do we have a variable id type we can attach to this?
        // TODO: Probably not considering this is used at multiple IL levels.
        variable_id: u64,
        /// NOTE: This is only valid in SSA form
        ssa_version: usize,
    },
    Import {
        // TODO: Looks to be the target address from the import.
        target: u64,
    },
    AddressDisplay {
        address: u64,
    },
    // TODO: BAD
    IndirectImport {
        /// The address of the import
        ///
        /// If you want the address of the import token use [`InstructionTextToken::address`] instead.
        target: u64,
        /// Size of the instruction this token is apart of
        size: usize,
        // TODO: Type this
        source_operand: usize,
    },
    ExternalSymbol {
        // TODO: Value of what?
        value: u64,
    },
    StackVariable {
        // TODO: Do we have a variable id type we can attach to this?
        // TODO: Probably not considering this is used at multiple IL levels.
        variable_id: u64,
    },
    AddressSeparator,
    CollapsedInformation,
    CollapseStateIndicator {
        // TODO: Explain what this is
        hash: Option<u64>,
    },
}

impl InstructionTextTokenKind {
    pub(crate) fn from_raw(value: &BNInstructionTextToken) -> Self {
        match value.type_ {
            BNInstructionTextTokenType::TextToken => Self::Text,
            BNInstructionTextTokenType::InstructionToken => Self::Instruction,
            BNInstructionTextTokenType::OperandSeparatorToken => Self::OperandSeparator,
            BNInstructionTextTokenType::RegisterToken => Self::Register,
            BNInstructionTextTokenType::IntegerToken => Self::Integer {
                value: value.value,
                size: match value.size {
                    0 => None,
                    size => Some(size),
                },
            },
            BNInstructionTextTokenType::PossibleAddressToken => Self::PossibleAddress {
                value: value.value,
                size: match value.size {
                    0 => None,
                    size => Some(size),
                },
            },
            BNInstructionTextTokenType::BeginMemoryOperandToken => Self::BeginMemoryOperand,
            BNInstructionTextTokenType::EndMemoryOperandToken => Self::EndMemoryOperand,
            BNInstructionTextTokenType::FloatingPointToken => Self::FloatingPoint {
                value: value.value as f64,
                size: match value.size {
                    0 => None,
                    size => Some(size),
                },
            },
            BNInstructionTextTokenType::AnnotationToken => Self::Annotation,
            BNInstructionTextTokenType::CodeRelativeAddressToken => Self::CodeRelativeAddress {
                value: value.value,
                size: match value.size {
                    0 => None,
                    size => Some(size),
                },
            },
            BNInstructionTextTokenType::ArgumentNameToken => {
                Self::ArgumentName { value: value.value }
            }
            BNInstructionTextTokenType::HexDumpByteValueToken => Self::HexDumpByteValue {
                value: value.value as u8,
            },
            BNInstructionTextTokenType::HexDumpSkippedByteToken => Self::HexDumpSkippedByte,
            BNInstructionTextTokenType::HexDumpInvalidByteToken => Self::HexDumpInvalidByte,
            BNInstructionTextTokenType::HexDumpTextToken => {
                Self::HexDumpText { width: value.value }
            }
            BNInstructionTextTokenType::OpcodeToken => Self::Opcode,
            BNInstructionTextTokenType::StringToken => Self::String {
                ty: match value.value {
                    0 => StringType::AsciiString,
                    1 => StringType::Utf8String,
                    2 => StringType::Utf16String,
                    3 => StringType::Utf32String,
                    _ => unreachable!(),
                },
            },
            BNInstructionTextTokenType::CharacterConstantToken => Self::CharacterConstant,
            BNInstructionTextTokenType::KeywordToken => Self::Keyword,
            BNInstructionTextTokenType::TypeNameToken => Self::TypeName,
            BNInstructionTextTokenType::FieldNameToken => Self::FieldName {
                offset: value.value,
                type_names: {
                    // NOTE: Do not need to free, this is a part of the From<&> impl
                    let raw_names =
                        unsafe { std::slice::from_raw_parts(value.typeNames, value.namesCount) };
                    raw_names.iter().filter_map(|&r| raw_to_string(r)).collect()
                },
            },
            BNInstructionTextTokenType::NameSpaceToken => Self::NameSpace,
            BNInstructionTextTokenType::NameSpaceSeparatorToken => Self::NameSpaceSeparator,
            BNInstructionTextTokenType::TagToken => Self::Tag,
            BNInstructionTextTokenType::StructOffsetToken => Self::StructOffset {
                offset: value.value,
                type_names: {
                    // NOTE: Do not need to free, this is a part of the From<&> impl
                    let raw_names =
                        unsafe { std::slice::from_raw_parts(value.typeNames, value.namesCount) };
                    raw_names.iter().filter_map(|&r| raw_to_string(r)).collect()
                },
            },
            BNInstructionTextTokenType::StructOffsetByteValueToken => Self::StructOffsetByteValue,
            BNInstructionTextTokenType::StructureHexDumpTextToken => {
                Self::StructureHexDumpText { width: value.value }
            }
            BNInstructionTextTokenType::GotoLabelToken => Self::GotoLabel {
                target: value.value,
            },
            BNInstructionTextTokenType::CommentToken => Self::Comment {
                target: value.value,
            },
            BNInstructionTextTokenType::PossibleValueToken => {
                Self::PossibleValue { value: value.value }
            }
            // NOTE: See my comment about this type in [`Self::PossibleValueType`]
            BNInstructionTextTokenType::PossibleValueTypeToken => Self::PossibleValueType,
            BNInstructionTextTokenType::ArrayIndexToken => Self::ArrayIndex { index: value.value },
            BNInstructionTextTokenType::IndentationToken => Self::Indentation,
            BNInstructionTextTokenType::UnknownMemoryToken => Self::UnknownMemory,
            BNInstructionTextTokenType::EnumerationMemberToken => Self::EnumerationMember {
                value: value.value,
                type_id: {
                    // NOTE: Type id comes from value.typeNames, it should be the first one (hence the .next)
                    // NOTE: Do not need to free, this is a part of the From<&> impl
                    let raw_names =
                        unsafe { std::slice::from_raw_parts(value.typeNames, value.namesCount) };
                    raw_names.iter().filter_map(|&r| raw_to_string(r)).next()
                },
            },
            BNInstructionTextTokenType::OperationToken => Self::Operation,
            BNInstructionTextTokenType::BaseStructureNameToken => Self::BaseStructureName,
            BNInstructionTextTokenType::BaseStructureSeparatorToken => Self::BaseStructureSeparator,
            BNInstructionTextTokenType::BraceToken => Self::Brace {
                hash: match value.value {
                    0 => None,
                    hash => Some(hash),
                },
            },
            BNInstructionTextTokenType::CodeSymbolToken => Self::CodeSymbol {
                value: value.value,
                size: value.size,
            },
            BNInstructionTextTokenType::DataSymbolToken => Self::DataSymbol {
                value: value.value,
                size: value.size,
            },
            BNInstructionTextTokenType::LocalVariableToken => Self::LocalVariable {
                variable_id: value.value,
                ssa_version: value.operand,
            },
            BNInstructionTextTokenType::ImportToken => Self::Import {
                target: value.value,
            },
            BNInstructionTextTokenType::AddressDisplayToken => Self::AddressDisplay {
                address: value.value,
            },
            BNInstructionTextTokenType::IndirectImportToken => Self::IndirectImport {
                target: value.value,
                size: value.size,
                source_operand: value.operand,
            },
            BNInstructionTextTokenType::ExternalSymbolToken => {
                Self::ExternalSymbol { value: value.value }
            }
            BNInstructionTextTokenType::StackVariableToken => Self::StackVariable {
                variable_id: value.value,
            },
            BNInstructionTextTokenType::AddressSeparatorToken => Self::AddressSeparator,
            BNInstructionTextTokenType::CollapsedInformationToken => Self::CollapsedInformation,
            BNInstructionTextTokenType::CollapseStateIndicatorToken => {
                Self::CollapseStateIndicator {
                    hash: match value.value {
                        0 => None,
                        hash => Some(hash),
                    },
                }
            }
        }
    }

    /// Mapping to the [`BNInstructionTextTokenType::value`] field.
    fn try_value(&self) -> Option<u64> {
        // TODO: Double check to make sure these are correct.
        match self {
            InstructionTextTokenKind::Integer { value, .. } => Some(*value),
            InstructionTextTokenKind::PossibleAddress { value, .. } => Some(*value),
            InstructionTextTokenKind::PossibleValue { value, .. } => Some(*value),
            InstructionTextTokenKind::FloatingPoint { value, .. } => Some(*value as u64),
            InstructionTextTokenKind::CodeRelativeAddress { value, .. } => Some(*value),
            InstructionTextTokenKind::ArgumentName { value, .. } => Some(*value),
            InstructionTextTokenKind::HexDumpByteValue { value, .. } => Some(*value as u64),
            InstructionTextTokenKind::HexDumpText { width, .. } => Some(*width),
            InstructionTextTokenKind::String { ty, .. } => Some(*ty as u64),
            InstructionTextTokenKind::FieldName { offset, .. } => Some(*offset),
            InstructionTextTokenKind::StructOffset { offset, .. } => Some(*offset),
            InstructionTextTokenKind::StructureHexDumpText { width, .. } => Some(*width),
            InstructionTextTokenKind::GotoLabel { target, .. } => Some(*target),
            InstructionTextTokenKind::Comment { target, .. } => Some(*target),
            InstructionTextTokenKind::ArrayIndex { index, .. } => Some(*index),
            InstructionTextTokenKind::EnumerationMember { value, .. } => Some(*value),
            InstructionTextTokenKind::LocalVariable { variable_id, .. } => Some(*variable_id),
            InstructionTextTokenKind::Import { target, .. } => Some(*target),
            InstructionTextTokenKind::AddressDisplay { address, .. } => Some(*address),
            InstructionTextTokenKind::IndirectImport { target, .. } => Some(*target),
            InstructionTextTokenKind::Brace { hash, .. } => *hash,
            InstructionTextTokenKind::CodeSymbol { value, .. } => Some(*value),
            InstructionTextTokenKind::DataSymbol { value, .. } => Some(*value),
            InstructionTextTokenKind::ExternalSymbol { value, .. } => Some(*value),
            InstructionTextTokenKind::StackVariable { variable_id, .. } => Some(*variable_id),
            InstructionTextTokenKind::CollapseStateIndicator { hash, .. } => *hash,
            _ => None,
        }
    }

    /// Mapping to the [`BNInstructionTextTokenType::size`] field.
    fn try_size(&self) -> Option<usize> {
        match self {
            InstructionTextTokenKind::Integer { size, .. } => *size,
            InstructionTextTokenKind::FloatingPoint { size, .. } => *size,
            InstructionTextTokenKind::PossibleAddress { size, .. } => *size,
            InstructionTextTokenKind::CodeRelativeAddress { size, .. } => *size,
            InstructionTextTokenKind::CodeSymbol { size, .. } => Some(*size),
            InstructionTextTokenKind::DataSymbol { size, .. } => Some(*size),
            InstructionTextTokenKind::IndirectImport { size, .. } => Some(*size),
            _ => None,
        }
    }

    /// Mapping to the [`BNInstructionTextTokenType::operand`] field.
    fn try_operand(&self) -> Option<usize> {
        match self {
            InstructionTextTokenKind::LocalVariable { ssa_version, .. } => Some(*ssa_version),
            InstructionTextTokenKind::IndirectImport { source_operand, .. } => {
                Some(*source_operand)
            }
            _ => None,
        }
    }

    /// Mapping to the [`BNInstructionTextTokenType::typeNames`] field.
    fn try_type_names(&self) -> Option<Vec<String>> {
        match self {
            InstructionTextTokenKind::FieldName { type_names, .. } => Some(type_names.clone()),
            InstructionTextTokenKind::StructOffset { type_names, .. } => Some(type_names.clone()),
            InstructionTextTokenKind::EnumerationMember { type_id, .. } => {
                Some(vec![type_id.clone()?])
            }
            _ => None,
        }
    }
}

impl From<InstructionTextTokenKind> for BNInstructionTextTokenType {
    fn from(value: InstructionTextTokenKind) -> Self {
        match value {
            InstructionTextTokenKind::Text => BNInstructionTextTokenType::TextToken,
            InstructionTextTokenKind::Instruction => BNInstructionTextTokenType::InstructionToken,
            InstructionTextTokenKind::OperandSeparator => {
                BNInstructionTextTokenType::OperandSeparatorToken
            }
            InstructionTextTokenKind::Register => BNInstructionTextTokenType::RegisterToken,
            InstructionTextTokenKind::Integer { .. } => BNInstructionTextTokenType::IntegerToken,
            InstructionTextTokenKind::PossibleAddress { .. } => {
                BNInstructionTextTokenType::PossibleAddressToken
            }
            InstructionTextTokenKind::BeginMemoryOperand => {
                BNInstructionTextTokenType::BeginMemoryOperandToken
            }
            InstructionTextTokenKind::EndMemoryOperand => {
                BNInstructionTextTokenType::EndMemoryOperandToken
            }
            InstructionTextTokenKind::FloatingPoint { .. } => {
                BNInstructionTextTokenType::FloatingPointToken
            }
            InstructionTextTokenKind::Annotation => BNInstructionTextTokenType::AnnotationToken,
            InstructionTextTokenKind::CodeRelativeAddress { .. } => {
                BNInstructionTextTokenType::CodeRelativeAddressToken
            }
            InstructionTextTokenKind::ArgumentName { .. } => {
                BNInstructionTextTokenType::ArgumentNameToken
            }
            InstructionTextTokenKind::HexDumpByteValue { .. } => {
                BNInstructionTextTokenType::HexDumpByteValueToken
            }
            InstructionTextTokenKind::HexDumpSkippedByte => {
                BNInstructionTextTokenType::HexDumpSkippedByteToken
            }
            InstructionTextTokenKind::HexDumpInvalidByte => {
                BNInstructionTextTokenType::HexDumpInvalidByteToken
            }
            InstructionTextTokenKind::HexDumpText { .. } => {
                BNInstructionTextTokenType::HexDumpTextToken
            }
            InstructionTextTokenKind::Opcode => BNInstructionTextTokenType::OpcodeToken,
            InstructionTextTokenKind::String { .. } => BNInstructionTextTokenType::StringToken,
            InstructionTextTokenKind::CharacterConstant => {
                BNInstructionTextTokenType::CharacterConstantToken
            }
            InstructionTextTokenKind::Keyword => BNInstructionTextTokenType::KeywordToken,
            InstructionTextTokenKind::TypeName => BNInstructionTextTokenType::TypeNameToken,
            InstructionTextTokenKind::FieldName { .. } => {
                BNInstructionTextTokenType::FieldNameToken
            }
            InstructionTextTokenKind::NameSpace => BNInstructionTextTokenType::NameSpaceToken,
            InstructionTextTokenKind::NameSpaceSeparator => {
                BNInstructionTextTokenType::NameSpaceSeparatorToken
            }
            InstructionTextTokenKind::Tag => BNInstructionTextTokenType::TagToken,
            InstructionTextTokenKind::StructOffset { .. } => {
                BNInstructionTextTokenType::StructOffsetToken
            }
            InstructionTextTokenKind::StructOffsetByteValue => {
                BNInstructionTextTokenType::StructOffsetByteValueToken
            }
            InstructionTextTokenKind::StructureHexDumpText { .. } => {
                BNInstructionTextTokenType::StructureHexDumpTextToken
            }
            InstructionTextTokenKind::GotoLabel { .. } => {
                BNInstructionTextTokenType::GotoLabelToken
            }
            InstructionTextTokenKind::Comment { .. } => BNInstructionTextTokenType::CommentToken,
            InstructionTextTokenKind::PossibleValue { .. } => {
                BNInstructionTextTokenType::PossibleValueToken
            }
            InstructionTextTokenKind::PossibleValueType => {
                BNInstructionTextTokenType::PossibleValueTypeToken
            }
            InstructionTextTokenKind::ArrayIndex { .. } => {
                BNInstructionTextTokenType::ArrayIndexToken
            }
            InstructionTextTokenKind::Indentation => BNInstructionTextTokenType::IndentationToken,
            InstructionTextTokenKind::UnknownMemory => {
                BNInstructionTextTokenType::UnknownMemoryToken
            }
            InstructionTextTokenKind::EnumerationMember { .. } => {
                BNInstructionTextTokenType::EnumerationMemberToken
            }
            InstructionTextTokenKind::Operation => BNInstructionTextTokenType::OperationToken,
            InstructionTextTokenKind::BaseStructureName => {
                BNInstructionTextTokenType::BaseStructureNameToken
            }
            InstructionTextTokenKind::BaseStructureSeparator => {
                BNInstructionTextTokenType::BaseStructureSeparatorToken
            }
            InstructionTextTokenKind::Brace { .. } => BNInstructionTextTokenType::BraceToken,
            InstructionTextTokenKind::CodeSymbol { .. } => {
                BNInstructionTextTokenType::CodeSymbolToken
            }
            InstructionTextTokenKind::DataSymbol { .. } => {
                BNInstructionTextTokenType::DataSymbolToken
            }
            InstructionTextTokenKind::LocalVariable { .. } => {
                BNInstructionTextTokenType::LocalVariableToken
            }
            InstructionTextTokenKind::Import { .. } => BNInstructionTextTokenType::ImportToken,
            InstructionTextTokenKind::AddressDisplay { .. } => {
                BNInstructionTextTokenType::AddressDisplayToken
            }
            InstructionTextTokenKind::IndirectImport { .. } => {
                BNInstructionTextTokenType::IndirectImportToken
            }
            InstructionTextTokenKind::ExternalSymbol { .. } => {
                BNInstructionTextTokenType::ExternalSymbolToken
            }
            InstructionTextTokenKind::StackVariable { .. } => {
                BNInstructionTextTokenType::StackVariableToken
            }
            InstructionTextTokenKind::AddressSeparator => {
                BNInstructionTextTokenType::AddressSeparatorToken
            }
            InstructionTextTokenKind::CollapsedInformation => {
                BNInstructionTextTokenType::CollapsedInformationToken
            }
            InstructionTextTokenKind::CollapseStateIndicator { .. } => {
                BNInstructionTextTokenType::CollapseStateIndicatorToken
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstructionTextTokenContext {
    Normal,
    LocalVariable,
    DataVariable,
    FunctionReturn,
    InstructionAddress,
    ILInstructionIndex,
    ConstData,
    /// Use only with [`InstructionTextTokenKind::String`]
    ConstStringData,
    /// Use only with [`InstructionTextTokenKind::String`]
    StringReference,
    /// Use only with [`InstructionTextTokenKind::String`]
    StringDataVariable,
    /// For displaying strings which aren't associated with an address
    ///
    /// Use only with [`InstructionTextTokenKind::String`]
    StringDisplay,
    /// Use only with [`InstructionTextTokenKind::CollapseStateIndicator`]
    Collapsed,
    /// Use only with [`InstructionTextTokenKind::CollapseStateIndicator`]
    Expanded,
    /// Use only with [`InstructionTextTokenKind::CollapseStateIndicator`]
    CollapsiblePadding,
}

impl From<BNInstructionTextTokenContext> for InstructionTextTokenContext {
    fn from(value: BNInstructionTextTokenContext) -> Self {
        match value {
            BNInstructionTextTokenContext::NoTokenContext => Self::Normal,
            BNInstructionTextTokenContext::LocalVariableTokenContext => Self::LocalVariable,
            BNInstructionTextTokenContext::DataVariableTokenContext => Self::DataVariable,
            BNInstructionTextTokenContext::FunctionReturnTokenContext => Self::FunctionReturn,
            BNInstructionTextTokenContext::InstructionAddressTokenContext => {
                Self::InstructionAddress
            }
            BNInstructionTextTokenContext::ILInstructionIndexTokenContext => {
                Self::ILInstructionIndex
            }
            BNInstructionTextTokenContext::ConstDataTokenContext => Self::ConstData,
            // For use with [`InstructionTextTokenKind::String`]
            BNInstructionTextTokenContext::ConstStringDataTokenContext => Self::ConstStringData,
            BNInstructionTextTokenContext::StringReferenceTokenContext => Self::StringReference,
            BNInstructionTextTokenContext::StringDataVariableTokenContext => {
                Self::StringDataVariable
            }
            BNInstructionTextTokenContext::StringDisplayTokenContext => Self::StringDisplay,
            // For use with [`InstructionTextTokenKind::CollapseStateIndicator`]
            BNInstructionTextTokenContext::ContentCollapsedContext => Self::Collapsed,
            BNInstructionTextTokenContext::ContentExpandedContext => Self::Expanded,
            BNInstructionTextTokenContext::ContentCollapsiblePadding => Self::CollapsiblePadding,
        }
    }
}

impl From<InstructionTextTokenContext> for BNInstructionTextTokenContext {
    fn from(value: InstructionTextTokenContext) -> Self {
        match value {
            InstructionTextTokenContext::Normal => Self::NoTokenContext,
            InstructionTextTokenContext::LocalVariable => Self::LocalVariableTokenContext,
            InstructionTextTokenContext::DataVariable => Self::DataVariableTokenContext,
            InstructionTextTokenContext::FunctionReturn => Self::FunctionReturnTokenContext,
            InstructionTextTokenContext::InstructionAddress => Self::InstructionAddressTokenContext,
            InstructionTextTokenContext::ILInstructionIndex => Self::ILInstructionIndexTokenContext,
            InstructionTextTokenContext::ConstData => Self::ConstDataTokenContext,
            InstructionTextTokenContext::ConstStringData => Self::ConstStringDataTokenContext,
            InstructionTextTokenContext::StringReference => Self::StringReferenceTokenContext,
            InstructionTextTokenContext::StringDataVariable => Self::StringDataVariableTokenContext,
            InstructionTextTokenContext::StringDisplay => Self::StringDisplayTokenContext,
            InstructionTextTokenContext::Collapsed => Self::ContentCollapsedContext,
            InstructionTextTokenContext::Expanded => Self::ContentExpandedContext,
            InstructionTextTokenContext::CollapsiblePadding => Self::ContentCollapsiblePadding,
        }
    }
}

// TODO: Make a builder for this.
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
