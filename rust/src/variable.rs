#![allow(unused)]

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
    BNUserVariableValue, BNValueRange, BNVariable, BNVariableNameAndType, BNVariableSourceType,
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

    pub(crate) unsafe fn from_ref_raw(value: *mut BNDataVariableAndName) -> Self {
        let owned = Self::from_raw(&*value);
        Self::free_ref_raw(value);
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

    pub(crate) fn free_ref_raw(value: *mut BNDataVariableAndName) {
        unsafe { BNFreeDataVariableAndName(value) }
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
        let _ = unsafe { BnString::from_raw(value.name) };
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
    pub value: PossibleValueSet,
}

impl UserVariableValue {
    pub(crate) fn from_raw(value: &BNUserVariableValue) -> Self {
        Self {
            variable: value.var.into(),
            def_site: value.defSite.into(),
            value: PossibleValueSet::from_raw(&value.value),
        }
    }

    pub(crate) fn into_raw(value: Self) -> BNUserVariableValue {
        BNUserVariableValue {
            var: value.variable.into(),
            defSite: value.def_site.into(),
            value: PossibleValueSet::into_raw(value.value),
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
        let _ = unsafe { BnString::from_raw(value.name) };
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
    from: HashSet<i64>,
    /// The associated "mapped" value.
    to: i64,
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
    ImportedAddressValue,
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
            RegisterValueType::ImportedAddressValue => Self::ImportedAddressValue,
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

    /// Take ownership over an "owned" core allocated value. Do not call this for a rust allocated value.
    pub(crate) fn from_owned_raw(mut value: BNPossibleValueSet) -> Self {
        let owned = Self::from_raw(&value);
        // TODO: This entire function is a little wonky.
        Self::free_raw(&mut value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNPossibleValueSet {
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
            PossibleValueSet::ImportedAddressValue => {}
            PossibleValueSet::SignedRangeValue { value, ranges } => {
                raw.value = value;
                // TODO: raw.ranges
                // TODO: requires core allocation and freeing.
                // TODO: See `BNFreePossibleValueSet` for why this sucks.
            }
            PossibleValueSet::UnsignedRangeValue { value, ranges } => {
                raw.value = value;
                // TODO: raw.ranges
                // TODO: requires core allocation and freeing.
                // TODO: See `BNFreePossibleValueSet` for why this sucks.
            }
            PossibleValueSet::LookupTableValue { table } => {
                // TODO: raw.table
                // TODO: requires core allocation and freeing.
                // TODO: See `BNFreePossibleValueSet` for why this sucks.
            }
            PossibleValueSet::InSetOfValues { values } => {
                // TODO: raw.valueSet
                // TODO: requires core allocation and freeing.
                // TODO: See `BNFreePossibleValueSet` for why this sucks.
            }
            PossibleValueSet::NotInSetOfValues { values } => {
                // TODO: raw.valueSet
                // TODO: requires core allocation and freeing.
                // TODO: See `BNFreePossibleValueSet` for why this sucks.
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

    /// Free a CORE ALLOCATED possible value set. Do not use this with [Self::into_raw] values.
    pub(crate) fn free_raw(value: &mut BNPossibleValueSet) {
        unsafe { BNFreePossibleValueSet(value) }
    }

    /// Free a RUST ALLOCATED possible value set. Do not use this with CORE ALLOCATED values.
    pub(crate) fn free_owned_raw(value: BNPossibleValueSet) {
        // TODO: Once we fill out allocation of the possible value set then we should fill this out as well.
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
            PossibleValueSet::ImportedAddressValue => RegisterValueType::ImportedAddressValue,
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

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct IndirectBranchInfo {
    pub source: Location,
    pub dest: Location,
    pub auto_defined: bool,
}

impl From<BNIndirectBranchInfo> for IndirectBranchInfo {
    fn from(value: BNIndirectBranchInfo) -> Self {
        Self {
            source: Location::from_raw(value.sourceAddr, value.sourceArch),
            dest: Location::from_raw(value.destAddr, value.destArch),
            auto_defined: value.autoDefined,
        }
    }
}

impl From<IndirectBranchInfo> for BNIndirectBranchInfo {
    fn from(value: IndirectBranchInfo) -> Self {
        let source_arch = value
            .source
            .arch
            .map(|a| a.handle)
            .unwrap_or(std::ptr::null_mut());
        let dest_arch = value
            .source
            .arch
            .map(|a| a.handle)
            .unwrap_or(std::ptr::null_mut());
        Self {
            sourceArch: source_arch,
            sourceAddr: value.source.addr,
            destArch: dest_arch,
            destAddr: value.dest.addr,
            autoDefined: value.auto_defined,
        }
    }
}

impl CoreArrayProvider for IndirectBranchInfo {
    type Raw = BNIndirectBranchInfo;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for IndirectBranchInfo {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeIndirectBranchList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from(*raw)
    }
}
