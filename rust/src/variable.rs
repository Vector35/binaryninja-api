#![allow(unused)]

use crate::architecture::{Architecture, CoreArchitecture, CoreRegister, RegisterId};
use crate::confidence::Conf;
use crate::function::{Function, Location};
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{raw_to_string, BnString};
use crate::types::Type;
use binaryninjacore_sys::{
    BNDataVariable, BNDataVariableAndName, BNFreeDataVariableAndName, BNFreeDataVariables,
    BNFreeILInstructionList, BNFreeIndirectBranchList, BNFreeMergedVariableList,
    BNFreePossibleValueSet, BNFreeStackVariableReferenceList, BNFreeUserVariableValues,
    BNFreeVariableList, BNFreeVariableNameAndTypeList, BNFromVariableIdentifier,
    BNIndirectBranchInfo, BNLookupTableEntry, BNMergedVariable, BNPossibleValueSet,
    BNRegisterValue, BNRegisterValueType, BNStackVariableReference, BNToVariableIdentifier,
    BNTypeWithConfidence, BNUserVariableValue, BNValueRange, BNVariable, BNVariableNameAndType,
    BNVariableSourceType,
};
use std::collections::HashSet;

pub type VariableSourceType = BNVariableSourceType;
pub type RegisterValueType = BNRegisterValueType;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DataVariable {
    pub address: u64,
    pub ty: Conf<Ref<Type>>,
    pub auto_discovered: bool,
}

impl DataVariable {
    pub(crate) fn from_raw(value: &BNDataVariable) -> Self {
        Self {
            address: value.address,
            ty: Conf::new(
                unsafe { Type::from_raw(value.type_).to_owned() },
                value.typeConfidence,
            ),
            auto_discovered: value.autoDiscovered,
        }
    }

    pub(crate) fn from_owned_raw(value: BNDataVariable) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNDataVariable {
        BNDataVariable {
            address: value.address,
            type_: unsafe { Ref::into_raw(value.ty.contents) }.handle,
            autoDiscovered: value.auto_discovered,
            typeConfidence: value.ty.confidence,
        }
    }

    pub(crate) fn into_owned_raw(value: &Self) -> BNDataVariable {
        BNDataVariable {
            address: value.address,
            type_: value.ty.contents.handle,
            autoDiscovered: value.auto_discovered,
            typeConfidence: value.ty.confidence,
        }
    }

    pub(crate) fn free_raw(value: BNDataVariable) {
        let _ = unsafe { Type::ref_from_raw(value.type_) };
    }

    pub fn new(address: u64, ty: Conf<Ref<Type>>, auto_discovered: bool) -> Self {
        Self {
            address,
            ty,
            auto_discovered,
        }
    }
}

impl CoreArrayProvider for DataVariable {
    type Raw = BNDataVariable;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for DataVariable {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeDataVariables(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        DataVariable::from_raw(raw)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NamedDataVariableWithType {
    pub address: u64,
    pub ty: Conf<Ref<Type>>,
    pub name: String,
    pub auto_discovered: bool,
}

impl NamedDataVariableWithType {
    pub(crate) fn from_raw(value: &BNDataVariableAndName) -> Self {
        Self {
            address: value.address,
            ty: Conf::new(
                unsafe { Type::from_raw(value.type_).to_owned() },
                value.typeConfidence,
            ),
            // TODO: I dislike using this function here.
            name: raw_to_string(value.name as *mut _).unwrap(),
            auto_discovered: value.autoDiscovered,
        }
    }

    pub(crate) fn from_owned_raw(value: BNDataVariableAndName) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNDataVariableAndName {
        let bn_name = BnString::new(value.name);
        BNDataVariableAndName {
            address: value.address,
            type_: unsafe { Ref::into_raw(value.ty.contents) }.handle,
            name: BnString::into_raw(bn_name),
            autoDiscovered: value.auto_discovered,
            typeConfidence: value.ty.confidence,
        }
    }

    pub(crate) fn free_raw(value: BNDataVariableAndName) {
        let _ = unsafe { Type::ref_from_raw(value.type_) };
        let _ = unsafe { BnString::from_raw(value.name) };
    }

    pub fn new(address: u64, ty: Conf<Ref<Type>>, name: String, auto_discovered: bool) -> Self {
        Self {
            address,
            ty,
            name,
            auto_discovered,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NamedVariableWithType {
    pub variable: Variable,
    pub ty: Conf<Ref<Type>>,
    pub name: String,
    pub auto_defined: bool,
}

impl NamedVariableWithType {
    pub(crate) fn from_raw(value: &BNVariableNameAndType) -> Self {
        Self {
            variable: value.var.into(),
            ty: Conf::new(
                unsafe { Type::from_raw(value.type_) }.to_owned(),
                value.typeConfidence,
            ),
            // TODO: I dislike using this function here.
            name: raw_to_string(value.name as *mut _).unwrap(),
            auto_defined: value.autoDefined,
        }
    }

    pub(crate) fn from_owned_raw(value: BNVariableNameAndType) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNVariableNameAndType {
        let bn_name = BnString::new(value.name);
        BNVariableNameAndType {
            var: value.variable.into(),
            type_: unsafe { Ref::into_raw(value.ty.contents) }.handle,
            name: BnString::into_raw(bn_name),
            autoDefined: value.auto_defined,
            typeConfidence: value.ty.confidence,
        }
    }

    pub(crate) fn free_raw(value: BNVariableNameAndType) {
        let _ = unsafe { Type::ref_from_raw(value.type_) };
        unsafe { BnString::free_raw(value.name) };
    }

    pub fn new(variable: Variable, ty: Conf<Ref<Type>>, name: String, auto_defined: bool) -> Self {
        Self {
            variable,
            ty,
            name,
            auto_defined,
        }
    }
}

impl CoreArrayProvider for NamedVariableWithType {
    type Raw = BNVariableNameAndType;
    type Context = ();
    type Wrapped<'a> = NamedVariableWithType;
}

unsafe impl CoreArrayProviderInner for NamedVariableWithType {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeVariableNameAndTypeList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(raw)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserVariableValue {
    pub variable: Variable,
    pub def_site: Location,
    pub after: bool,
    pub value: PossibleValueSet,
}

impl UserVariableValue {
    pub(crate) fn from_raw(value: &BNUserVariableValue) -> Self {
        Self {
            variable: value.var.into(),
            def_site: value.defSite.into(),
            after: value.after,
            value: PossibleValueSet::from_raw(&value.value),
        }
    }

    pub(crate) fn into_raw(value: Self) -> BNUserVariableValue {
        BNUserVariableValue {
            var: value.variable.into(),
            defSite: value.def_site.into(),
            after: value.after,
            // TODO: This returns a rust allocated value, we should at some point provide allocators for the
            // TODO: internal state of BNPossibleValueSet, so we can store rust created object in core objects.
            value: PossibleValueSet::into_rust_raw(value.value),
        }
    }
}

impl CoreArrayProvider for UserVariableValue {
    type Raw = BNUserVariableValue;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for UserVariableValue {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeUserVariableValues(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        UserVariableValue::from_raw(raw)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StackVariableReference {
    source_operand: u32,
    pub variable_type: Conf<Ref<Type>>,
    pub name: String,
    pub variable: Variable,
    pub offset: i64,
    pub size: usize,
}

impl StackVariableReference {
    pub(crate) fn from_raw(value: &BNStackVariableReference) -> Self {
        Self {
            source_operand: value.sourceOperand,
            variable_type: Conf::new(
                unsafe { Type::from_raw(value.type_) }.to_owned(),
                value.typeConfidence,
            ),
            // TODO: I dislike using this function here.
            name: raw_to_string(value.name).unwrap(),
            // TODO: It might be beneficial to newtype the identifier as VariableIdentifier.
            variable: Variable::from_identifier(value.varIdentifier),
            offset: value.referencedOffset,
            size: value.size,
        }
    }

    pub(crate) fn from_owned_raw(value: BNStackVariableReference) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNStackVariableReference {
        let bn_name = BnString::new(value.name);
        BNStackVariableReference {
            sourceOperand: value.source_operand,
            typeConfidence: value.variable_type.confidence,
            type_: unsafe { Ref::into_raw(value.variable_type.contents) }.handle,
            name: BnString::into_raw(bn_name),
            varIdentifier: value.variable.to_identifier(),
            referencedOffset: value.offset,
            size: value.size,
        }
    }

    pub(crate) fn free_raw(value: BNStackVariableReference) {
        let _ = unsafe { Type::ref_from_raw(value.type_) };
        unsafe { BnString::free_raw(value.name) };
    }
}

impl CoreArrayProvider for StackVariableReference {
    type Raw = BNStackVariableReference;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for StackVariableReference {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeStackVariableReferenceList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        StackVariableReference::from_raw(raw)
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct SSAVariable {
    pub variable: Variable,
    pub version: usize,
}

impl SSAVariable {
    pub fn new(variable: Variable, version: usize) -> Self {
        Self { variable, version }
    }
}

impl CoreArrayProvider for SSAVariable {
    type Raw = usize;
    type Context = Variable;
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for SSAVariable {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeILInstructionList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        SSAVariable::new(*context, *raw)
    }
}

/// Variables exist within functions at Medium Level IL or higher.
///
/// As such, they are to be used within the context of a [`Function`].
/// See [`Function::variable_name`] as an example of how to interact with variables.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Variable {
    pub ty: VariableSourceType,
    // TODO: VariableIndex type?
    pub index: u32,
    // TODO: Type this to `VariableStorage`
    pub storage: i64,
}

impl Variable {
    pub fn new(ty: VariableSourceType, index: u32, storage: i64) -> Self {
        Self { ty, index, storage }
    }

    // TODO: Retype this...
    // TODO: Add VariableIdentifier
    // TODO: StackVariableReference has a varIdentifier, i think thats really it.
    pub fn from_identifier(ident: u64) -> Self {
        unsafe { BNFromVariableIdentifier(ident) }.into()
    }

    pub fn to_identifier(&self) -> u64 {
        let raw = BNVariable::from(*self);
        unsafe { BNToVariableIdentifier(&raw) }
    }

    pub fn to_register(&self, arch: CoreArchitecture) -> Option<CoreRegister> {
        match self.ty {
            VariableSourceType::RegisterVariableSourceType => {
                arch.register_from_id(RegisterId(self.storage as u32))
            }
            VariableSourceType::StackVariableSourceType => None,
            VariableSourceType::FlagVariableSourceType => None,
        }
    }
}

impl From<BNVariable> for Variable {
    fn from(value: BNVariable) -> Self {
        Self {
            ty: value.type_,
            index: value.index,
            storage: value.storage,
        }
    }
}

impl From<&BNVariable> for Variable {
    fn from(value: &BNVariable) -> Self {
        Self::from(*value)
    }
}

impl From<Variable> for BNVariable {
    fn from(value: Variable) -> Self {
        Self {
            type_: value.ty,
            index: value.index,
            storage: value.storage,
        }
    }
}

impl From<&Variable> for BNVariable {
    fn from(value: &Variable) -> Self {
        BNVariable::from(*value)
    }
}

impl CoreArrayProvider for Variable {
    type Raw = BNVariable;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for Variable {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeVariableList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Variable::from(raw)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct MergedVariable {
    pub target: Variable,
    pub sources: Vec<Variable>,
}

impl MergedVariable {
    pub(crate) fn from_raw(value: &BNMergedVariable) -> Self {
        let raw_sources = unsafe { std::slice::from_raw_parts(value.sources, value.sourceCount) };
        Self {
            target: value.target.into(),
            sources: raw_sources.iter().map(Into::into).collect(),
        }
    }

    // TODO: If we want from_owned_raw/free_raw/into_raw we need a way to allocate sources.
}

impl CoreArrayProvider for MergedVariable {
    type Raw = BNMergedVariable;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for MergedVariable {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeMergedVariableList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(raw)
    }
}

// TODO: This is used in MLIL and HLIL, this really should exist in each of those.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct ConstantData {
    // TODO: We really do not want to store a ref to function here.
    pub function: Ref<Function>,
    pub value: RegisterValue,
}

impl ConstantData {
    pub fn new(function: Ref<Function>, value: RegisterValue) -> Self {
        Self { function, value }
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct RegisterValue {
    pub state: RegisterValueType,
    // TODO: This value can be anything. Make `T`
    pub value: i64,
    pub offset: i64,
    pub size: usize,
}

impl RegisterValue {
    pub fn new(state: RegisterValueType, value: i64, offset: i64, size: usize) -> Self {
        Self {
            state,
            value,
            offset,
            size,
        }
    }
}

impl From<BNRegisterValue> for RegisterValue {
    fn from(value: BNRegisterValue) -> Self {
        Self {
            state: value.state,
            value: value.value,
            offset: value.offset,
            size: value.size,
        }
    }
}

impl From<RegisterValue> for BNRegisterValue {
    fn from(value: RegisterValue) -> Self {
        Self {
            state: value.state,
            value: value.value,
            offset: value.offset,
            size: value.size,
        }
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct ValueRange<T> {
    pub start: T,
    pub end: T,
    pub step: u64,
}

impl From<BNValueRange> for ValueRange<u64> {
    fn from(value: BNValueRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
            step: value.step,
        }
    }
}

impl From<ValueRange<u64>> for BNValueRange {
    fn from(value: ValueRange<u64>) -> Self {
        Self {
            start: value.start,
            end: value.end,
            step: value.step,
        }
    }
}

impl From<BNValueRange> for ValueRange<i64> {
    fn from(value: BNValueRange) -> Self {
        Self {
            start: value.start as i64,
            end: value.end as i64,
            step: value.step,
        }
    }
}

impl From<ValueRange<i64>> for BNValueRange {
    fn from(value: ValueRange<i64>) -> Self {
        Self {
            start: value.start as u64,
            end: value.end as u64,
            step: value.step,
        }
    }
}

// TODO: Document where its used and why it exists.
// TODO: What if we are looking up u64?
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupTableEntry {
    /// The set of integers that correspond with [`Self::to`].
    pub from: HashSet<i64>,
    /// The associated "mapped" value.
    pub to: i64,
}

impl LookupTableEntry {
    pub(crate) fn from_raw(value: &BNLookupTableEntry) -> Self {
        let from_values = unsafe { std::slice::from_raw_parts(value.fromValues, value.fromCount) };
        Self {
            // TODO: Better way to construct HashSet<i64>?
            from: HashSet::from_iter(from_values.iter().copied()),
            to: value.toValue,
        }
    }

    pub(crate) fn from_owned_raw(value: BNLookupTableEntry) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNLookupTableEntry {
        let from_values: Box<[i64]> = value.from.into_iter().collect();
        let from_values_len = from_values.len();
        BNLookupTableEntry {
            // Freed in [`Self::free_raw`]
            fromValues: Box::leak(from_values).as_mut_ptr(),
            fromCount: from_values_len,
            toValue: value.to,
        }
    }

    pub(crate) fn free_raw(value: BNLookupTableEntry) {
        let raw_from = unsafe { std::slice::from_raw_parts_mut(value.fromValues, value.fromCount) };
        let boxed_from = unsafe { Box::from_raw(raw_from) };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PossibleValueSet {
    UndeterminedValue,
    EntryValue {
        // TODO: This is actually the BNVariable storage.
        // TODO: Type this to `VariableStorage` or something.
        reg: i64,
    },
    ConstantValue {
        // TODO: Make this T
        // TODO: This can be really anything (signed, unsigned or even a float).
        value: i64,
    },
    ConstantPointerValue {
        // TODO: Shouldn't this be u64?
        value: i64,
    },
    ExternalPointerValue {
        // TODO: Shouldn't this be u64?
        value: i64,
        offset: i64,
    },
    StackFrameOffset {
        value: i64,
    },
    ReturnAddressValue,
    ImportedAddressValue {
        value: i64,
    },
    SignedRangeValue {
        value: i64,
        ranges: Vec<ValueRange<i64>>,
    },
    UnsignedRangeValue {
        value: i64,
        ranges: Vec<ValueRange<u64>>,
    },
    LookupTableValue {
        table: Vec<LookupTableEntry>,
    },
    InSetOfValues {
        values: HashSet<i64>,
    },
    NotInSetOfValues {
        values: HashSet<i64>,
    },
    // TODO: Can you even get _just_ a constant data value?
    ConstantDataValue {
        value: i64,
        size: usize,
    },
    ConstantDataZeroExtendValue {
        // TODO: Zero extend should be u64?
        value: i64,
        size: usize,
    },
    ConstantDataSignExtendValue {
        value: i64,
        size: usize,
    },
    ConstantDataAggregateValue {
        // WTF is aggregate??
        value: i64,
        size: usize,
    },
}

impl PossibleValueSet {
    pub(crate) fn from_raw(value: &BNPossibleValueSet) -> Self {
        match value.state {
            RegisterValueType::UndeterminedValue => Self::UndeterminedValue,
            RegisterValueType::EntryValue => Self::EntryValue { reg: value.value },
            RegisterValueType::ConstantValue => Self::ConstantValue { value: value.value },
            RegisterValueType::ConstantPointerValue => {
                Self::ConstantPointerValue { value: value.value }
            }
            RegisterValueType::ExternalPointerValue => Self::ExternalPointerValue {
                value: value.value,
                offset: value.offset,
            },
            RegisterValueType::StackFrameOffset => Self::StackFrameOffset { value: value.value },
            RegisterValueType::ReturnAddressValue => Self::ReturnAddressValue,
            RegisterValueType::ImportedAddressValue => {
                Self::ImportedAddressValue { value: value.value }
            }
            RegisterValueType::SignedRangeValue => {
                let raw_ranges = unsafe { std::slice::from_raw_parts(value.ranges, value.count) };
                Self::SignedRangeValue {
                    value: value.value,
                    ranges: raw_ranges.iter().map(|&r| r.into()).collect(),
                }
            }
            RegisterValueType::UnsignedRangeValue => {
                let raw_ranges = unsafe { std::slice::from_raw_parts(value.ranges, value.count) };
                Self::UnsignedRangeValue {
                    value: value.value,
                    ranges: raw_ranges.iter().map(|&r| r.into()).collect(),
                }
            }
            RegisterValueType::LookupTableValue => {
                let raw_entries = unsafe { std::slice::from_raw_parts(value.table, value.count) };
                Self::LookupTableValue {
                    table: raw_entries.iter().map(LookupTableEntry::from_raw).collect(),
                }
            }
            RegisterValueType::InSetOfValues => {
                let raw_values = unsafe { std::slice::from_raw_parts(value.valueSet, value.count) };
                Self::InSetOfValues {
                    values: raw_values.iter().copied().collect(),
                }
            }
            RegisterValueType::NotInSetOfValues => {
                let raw_values = unsafe { std::slice::from_raw_parts(value.valueSet, value.count) };
                Self::NotInSetOfValues {
                    values: raw_values.iter().copied().collect(),
                }
            }
            RegisterValueType::ConstantDataValue => Self::ConstantDataValue {
                value: value.value,
                size: value.size,
            },
            RegisterValueType::ConstantDataZeroExtendValue => Self::ConstantDataZeroExtendValue {
                value: value.value,
                size: value.size,
            },
            RegisterValueType::ConstantDataSignExtendValue => Self::ConstantDataSignExtendValue {
                value: value.value,
                size: value.size,
            },
            RegisterValueType::ConstantDataAggregateValue => Self::ConstantDataAggregateValue {
                value: value.value,
                size: value.size,
            },
        }
    }

    /// Take ownership over an "owned" **core allocated** value. Do not call this for a rust allocated value.
    pub(crate) fn from_owned_core_raw(mut value: BNPossibleValueSet) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_core_raw(&mut value);
        owned
    }

    pub(crate) fn into_rust_raw(value: Self) -> BNPossibleValueSet {
        let mut raw = BNPossibleValueSet {
            state: value.value_type(),
            ..Default::default()
        };
        match value {
            PossibleValueSet::UndeterminedValue => {}
            PossibleValueSet::EntryValue { reg } => {
                raw.value = reg;
            }
            PossibleValueSet::ConstantValue { value } => {
                raw.value = value;
            }
            PossibleValueSet::ConstantPointerValue { value } => {
                raw.value = value;
            }
            PossibleValueSet::ExternalPointerValue { value, offset } => {
                raw.value = value;
                raw.offset = offset;
            }
            PossibleValueSet::StackFrameOffset { value } => {
                raw.value = value;
            }
            PossibleValueSet::ReturnAddressValue => {}
            PossibleValueSet::ImportedAddressValue { value } => {
                raw.value = value;
            }
            PossibleValueSet::SignedRangeValue { value, ranges } => {
                let boxed_raw_ranges: Box<[BNValueRange]> =
                    ranges.into_iter().map(BNValueRange::from).collect();
                raw.value = value;
                raw.count = boxed_raw_ranges.len();
                // NOTE: We are allocating this in rust, meaning core MUST NOT free this.
                raw.ranges = Box::leak(boxed_raw_ranges).as_mut_ptr();
            }
            PossibleValueSet::UnsignedRangeValue { value, ranges } => {
                let boxed_raw_ranges: Box<[BNValueRange]> =
                    ranges.into_iter().map(BNValueRange::from).collect();
                raw.value = value;
                raw.count = boxed_raw_ranges.len();
                // NOTE: We are allocating this in rust, meaning core MUST NOT free this.
                raw.ranges = Box::leak(boxed_raw_ranges).as_mut_ptr();
            }
            PossibleValueSet::LookupTableValue { table } => {
                let boxed_raw_entries: Box<[BNLookupTableEntry]> =
                    table.into_iter().map(LookupTableEntry::into_raw).collect();
                raw.count = boxed_raw_entries.len();
                // NOTE: We are allocating this in rust, meaning core MUST NOT free this.
                raw.table = Box::leak(boxed_raw_entries).as_mut_ptr();
            }
            PossibleValueSet::InSetOfValues { values } => {
                let boxed_raw_values: Box<[i64]> = values.into_iter().collect();
                raw.count = boxed_raw_values.len();
                // NOTE: We are allocating this in rust, meaning core MUST NOT free this.
                raw.valueSet = Box::leak(boxed_raw_values).as_mut_ptr();
            }
            PossibleValueSet::NotInSetOfValues { values } => {
                let boxed_raw_values: Box<[i64]> = values.into_iter().collect();
                raw.count = boxed_raw_values.len();
                // NOTE: We are allocating this in rust, meaning core MUST NOT free this.
                raw.valueSet = Box::leak(boxed_raw_values).as_mut_ptr();
            }
            PossibleValueSet::ConstantDataValue { value, size } => {
                raw.value = value;
                raw.size = size;
            }
            PossibleValueSet::ConstantDataZeroExtendValue { value, size } => {
                raw.value = value;
                raw.size = size;
            }
            PossibleValueSet::ConstantDataSignExtendValue { value, size } => {
                raw.value = value;
                raw.size = size;
            }
            PossibleValueSet::ConstantDataAggregateValue { value, size } => {
                raw.value = value;
                raw.size = size;
            }
        };
        raw
    }

    /// Free a CORE ALLOCATED possible value set. Do not use this with [Self::into_rust_raw] values.
    pub(crate) fn free_core_raw(value: &mut BNPossibleValueSet) {
        unsafe { BNFreePossibleValueSet(value) }
    }

    /// Free a RUST ALLOCATED possible value set. Do not use this with CORE ALLOCATED values.
    pub(crate) fn free_rust_raw(value: BNPossibleValueSet) {
        // Free the range list
        if !value.ranges.is_null() {
            let raw_ranges = unsafe { std::slice::from_raw_parts_mut(value.ranges, value.count) };
            let boxed_ranges = unsafe { Box::from_raw(raw_ranges) };
        }

        if !value.table.is_null() {
            unsafe { LookupTableEntry::free_raw(*value.table) };
        }

        if !value.valueSet.is_null() {
            let raw_value_set =
                unsafe { std::slice::from_raw_parts_mut(value.valueSet, value.count) };
            let boxed_value_set = unsafe { Box::from_raw(raw_value_set) };
        }
    }

    pub fn value_type(&self) -> RegisterValueType {
        match self {
            PossibleValueSet::UndeterminedValue => RegisterValueType::UndeterminedValue,
            PossibleValueSet::EntryValue { .. } => RegisterValueType::EntryValue,
            PossibleValueSet::ConstantValue { .. } => RegisterValueType::ConstantValue,
            PossibleValueSet::ConstantPointerValue { .. } => {
                RegisterValueType::ConstantPointerValue
            }
            PossibleValueSet::ExternalPointerValue { .. } => {
                RegisterValueType::ExternalPointerValue
            }
            PossibleValueSet::StackFrameOffset { .. } => RegisterValueType::StackFrameOffset,
            PossibleValueSet::ReturnAddressValue => RegisterValueType::ReturnAddressValue,
            PossibleValueSet::ImportedAddressValue { .. } => {
                RegisterValueType::ImportedAddressValue
            }
            PossibleValueSet::SignedRangeValue { .. } => RegisterValueType::SignedRangeValue,
            PossibleValueSet::UnsignedRangeValue { .. } => RegisterValueType::UnsignedRangeValue,
            PossibleValueSet::LookupTableValue { .. } => RegisterValueType::LookupTableValue,
            PossibleValueSet::InSetOfValues { .. } => RegisterValueType::InSetOfValues,
            PossibleValueSet::NotInSetOfValues { .. } => RegisterValueType::NotInSetOfValues,
            PossibleValueSet::ConstantDataValue { .. } => RegisterValueType::ConstantDataValue,
            PossibleValueSet::ConstantDataZeroExtendValue { .. } => {
                RegisterValueType::ConstantDataZeroExtendValue
            }
            PossibleValueSet::ConstantDataSignExtendValue { .. } => {
                RegisterValueType::ConstantDataSignExtendValue
            }
            PossibleValueSet::ConstantDataAggregateValue { .. } => {
                RegisterValueType::ConstantDataAggregateValue
            }
        }
    }
}
