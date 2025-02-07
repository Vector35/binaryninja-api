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

use binaryninjacore_sys::*;

use crate::{
    architecture::{Architecture, CoreArchitecture, CoreRegister, Register},
    basic_block::{BasicBlock, BlockContext},
    binary_view::{BinaryView, BinaryViewExt},
    calling_convention::CoreCallingConvention,
    component::Component,
    disassembly::{DisassemblySettings, DisassemblyTextLine},
    flowgraph::FlowGraph,
    medium_level_il::FunctionGraphType,
    platform::Platform,
    references::CodeReference,
    string::*,
    symbol::Symbol,
    tags::{Tag, TagReference, TagType},
    types::{IntegerDisplayType, QualifiedName, Type},
};
use crate::{data_buffer::DataBuffer, disassembly::InstructionTextToken, rc::*};
pub use binaryninjacore_sys::BNAnalysisSkipReason as AnalysisSkipReason;
pub use binaryninjacore_sys::BNBuiltinType as BuiltinType;
pub use binaryninjacore_sys::BNFunctionAnalysisSkipOverride as FunctionAnalysisSkipOverride;
pub use binaryninjacore_sys::BNFunctionUpdateType as FunctionUpdateType;
pub use binaryninjacore_sys::BNHighlightStandardColor as HighlightStandardColor;

use crate::architecture::RegisterId;
use crate::confidence::Conf;
use crate::high_level_il::HighLevelILFunction;
use crate::low_level_il::{LiftedILFunction, RegularLowLevelILFunction};
use crate::medium_level_il::MediumLevelILFunction;
use crate::variable::{
    IndirectBranchInfo, MergedVariable, NamedVariableWithType, RegisterValue, RegisterValueType,
    StackVariableReference, Variable,
};
use crate::workflow::Workflow;
use std::fmt::{Debug, Formatter};
use std::ptr::NonNull;
use std::time::Duration;
use std::{ffi::c_char, hash::Hash, ops::Range};

/// Used to describe a location within a [`Function`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Location {
    pub arch: Option<CoreArchitecture>,
    pub addr: u64,
}

impl Location {
    pub(crate) fn from_raw(addr: u64, arch: *mut BNArchitecture) -> Self {
        Self {
            addr,
            arch: Some(unsafe { CoreArchitecture::from_raw(arch) }),
        }
    }
}

impl From<u64> for Location {
    fn from(addr: u64) -> Self {
        Location { arch: None, addr }
    }
}

impl From<(CoreArchitecture, u64)> for Location {
    fn from(loc: (CoreArchitecture, u64)) -> Self {
        Location {
            arch: Some(loc.0),
            addr: loc.1,
        }
    }
}

impl From<BNArchitectureAndAddress> for Location {
    fn from(value: BNArchitectureAndAddress) -> Self {
        Self::from_raw(value.address, value.arch)
    }
}

impl From<Location> for BNArchitectureAndAddress {
    fn from(value: Location) -> Self {
        Self {
            arch: value.arch.map(|a| a.handle).unwrap_or(std::ptr::null_mut()),
            address: value.addr,
        }
    }
}

pub struct NativeBlockIter {
    arch: CoreArchitecture,
    bv: Ref<BinaryView>,
    cur: u64,
    end: u64,
}

impl Iterator for NativeBlockIter {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        let res = self.cur;

        if res >= self.end {
            None
        } else {
            self.bv
                .instruction_len(&self.arch, res)
                .map(|x| {
                    self.cur += x as u64;
                    res
                })
                .or_else(|| {
                    self.cur = self.end;
                    None
                })
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeBlock {
    _priv: (),
}

impl NativeBlock {
    pub(crate) fn new() -> Self {
        NativeBlock { _priv: () }
    }
}

impl Default for NativeBlock {
    fn default() -> Self {
        NativeBlock::new()
    }
}

impl BlockContext for NativeBlock {
    type Instruction = u64;
    type InstructionIndex = u64;
    type Iter = NativeBlockIter;

    fn start(&self, block: &BasicBlock<Self>) -> u64 {
        block.start_index()
    }

    fn iter(&self, block: &BasicBlock<Self>) -> NativeBlockIter {
        NativeBlockIter {
            arch: block.arch(),
            bv: block.function().view(),
            cur: block.start_index(),
            end: block.end_index(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FunctionViewType {
    Normal,
    LowLevelIL,
    LiftedIL,
    LowLevelILSSAForm,
    MediumLevelIL,
    MediumLevelILSSAForm,
    MappedMediumLevelIL,
    MappedMediumLevelILSSAForm,
    HighLevelIL,
    HighLevelILSSAForm,
    HighLevelLanguageRepresentation(String),
}

#[allow(unused)]
impl FunctionViewType {
    pub(crate) fn from_raw(value: &BNFunctionViewType) -> Option<Self> {
        match value.type_ {
            BNFunctionGraphType::InvalidILViewType => None,
            BNFunctionGraphType::NormalFunctionGraph => Some(FunctionViewType::Normal),
            BNFunctionGraphType::LowLevelILFunctionGraph => Some(FunctionViewType::LowLevelIL),
            BNFunctionGraphType::LiftedILFunctionGraph => Some(FunctionViewType::LiftedIL),
            BNFunctionGraphType::LowLevelILSSAFormFunctionGraph => {
                Some(FunctionViewType::LowLevelILSSAForm)
            }
            BNFunctionGraphType::MediumLevelILFunctionGraph => {
                Some(FunctionViewType::MediumLevelIL)
            }
            BNFunctionGraphType::MediumLevelILSSAFormFunctionGraph => {
                Some(FunctionViewType::MediumLevelILSSAForm)
            }
            BNFunctionGraphType::MappedMediumLevelILFunctionGraph => {
                Some(FunctionViewType::MappedMediumLevelIL)
            }
            BNFunctionGraphType::MappedMediumLevelILSSAFormFunctionGraph => {
                Some(FunctionViewType::MappedMediumLevelILSSAForm)
            }
            BNFunctionGraphType::HighLevelILFunctionGraph => Some(FunctionViewType::HighLevelIL),
            BNFunctionGraphType::HighLevelILSSAFormFunctionGraph => {
                Some(FunctionViewType::HighLevelILSSAForm)
            }
            BNFunctionGraphType::HighLevelLanguageRepresentationFunctionGraph => {
                Some(FunctionViewType::HighLevelLanguageRepresentation(
                    raw_to_string(value.name).unwrap(),
                ))
            }
        }
    }

    pub(crate) fn from_owned_raw(value: BNFunctionViewType) -> Option<Self> {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNFunctionViewType {
        let view_type = match value {
            FunctionViewType::Normal => BNFunctionGraphType::NormalFunctionGraph,
            FunctionViewType::LowLevelIL => BNFunctionGraphType::LowLevelILFunctionGraph,
            FunctionViewType::LiftedIL => BNFunctionGraphType::LiftedILFunctionGraph,
            FunctionViewType::LowLevelILSSAForm => {
                BNFunctionGraphType::LowLevelILSSAFormFunctionGraph
            }
            FunctionViewType::MediumLevelIL => BNFunctionGraphType::MediumLevelILFunctionGraph,
            FunctionViewType::MediumLevelILSSAForm => {
                BNFunctionGraphType::MediumLevelILSSAFormFunctionGraph
            }
            FunctionViewType::MappedMediumLevelIL => {
                BNFunctionGraphType::MappedMediumLevelILFunctionGraph
            }
            FunctionViewType::MappedMediumLevelILSSAForm => {
                BNFunctionGraphType::MappedMediumLevelILSSAFormFunctionGraph
            }
            FunctionViewType::HighLevelIL => BNFunctionGraphType::HighLevelILFunctionGraph,
            FunctionViewType::HighLevelILSSAForm => {
                BNFunctionGraphType::HighLevelILSSAFormFunctionGraph
            }
            FunctionViewType::HighLevelLanguageRepresentation(_) => {
                BNFunctionGraphType::HighLevelLanguageRepresentationFunctionGraph
            }
        };
        let view_name = match value {
            FunctionViewType::HighLevelLanguageRepresentation(name) => Some(BnString::new(name)),
            _ => None,
        };
        BNFunctionViewType {
            type_: view_type,
            name: view_name
                .map(|n| BnString::into_raw(n) as *mut _)
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    pub(crate) fn free_raw(value: BNFunctionViewType) {
        let _ = unsafe { BnString::from_raw(value.name as *mut _) };
    }
}

impl From<FunctionGraphType> for FunctionViewType {
    fn from(view_type: FunctionGraphType) -> Self {
        match view_type {
            BNFunctionGraphType::LowLevelILFunctionGraph => FunctionViewType::LowLevelIL,
            BNFunctionGraphType::LiftedILFunctionGraph => FunctionViewType::LiftedIL,
            BNFunctionGraphType::LowLevelILSSAFormFunctionGraph => {
                FunctionViewType::LowLevelILSSAForm
            }
            BNFunctionGraphType::MediumLevelILFunctionGraph => FunctionViewType::MediumLevelIL,
            BNFunctionGraphType::MediumLevelILSSAFormFunctionGraph => {
                FunctionViewType::MediumLevelILSSAForm
            }
            BNFunctionGraphType::MappedMediumLevelILFunctionGraph => {
                FunctionViewType::MappedMediumLevelIL
            }
            BNFunctionGraphType::MappedMediumLevelILSSAFormFunctionGraph => {
                FunctionViewType::MappedMediumLevelILSSAForm
            }
            BNFunctionGraphType::HighLevelILFunctionGraph => FunctionViewType::HighLevelIL,
            BNFunctionGraphType::HighLevelILSSAFormFunctionGraph => {
                FunctionViewType::HighLevelILSSAForm
            }
            BNFunctionGraphType::HighLevelLanguageRepresentationFunctionGraph => {
                // Historically this was the only language representation.
                FunctionViewType::HighLevelLanguageRepresentation("Pseudo C".into())
            }
            BNFunctionGraphType::InvalidILViewType | BNFunctionGraphType::NormalFunctionGraph => {
                FunctionViewType::Normal
            }
        }
    }
}

#[derive(Eq)]
pub struct Function {
    pub(crate) handle: *mut BNFunction,
}

impl Function {
    pub(crate) unsafe fn from_raw(handle: *mut BNFunction) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNFunction) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn arch(&self) -> CoreArchitecture {
        unsafe {
            let arch = BNGetFunctionArchitecture(self.handle);
            CoreArchitecture::from_raw(arch)
        }
    }

    pub fn platform(&self) -> Ref<Platform> {
        unsafe {
            let plat = BNGetFunctionPlatform(self.handle);
            Platform::ref_from_raw(plat)
        }
    }

    pub fn view(&self) -> Ref<BinaryView> {
        unsafe {
            let view = BNGetFunctionData(self.handle);
            BinaryView::ref_from_raw(view)
        }
    }

    pub fn symbol(&self) -> Ref<Symbol> {
        unsafe {
            let sym = BNGetFunctionSymbol(self.handle);
            Symbol::ref_from_raw(sym)
        }
    }

    pub fn workflow(&self) -> Option<Ref<Workflow>> {
        unsafe {
            let workflow = NonNull::new(BNGetWorkflowForFunction(self.handle))?;
            Some(Workflow::ref_from_raw(workflow))
        }
    }

    pub fn start(&self) -> u64 {
        unsafe { BNGetFunctionStart(self.handle) }
    }

    pub fn lowest_address(&self) -> u64 {
        unsafe { BNGetFunctionLowestAddress(self.handle) }
    }

    pub fn highest_address(&self) -> u64 {
        unsafe { BNGetFunctionHighestAddress(self.handle) }
    }

    pub fn address_ranges(&self) -> Array<AddressRange> {
        unsafe {
            let mut count = 0;
            let addresses = BNGetFunctionAddressRanges(self.handle, &mut count);

            Array::new(addresses, count, ())
        }
    }

    pub fn comment(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetFunctionComment(self.handle)) }
    }

    pub fn set_comment<S: BnStrCompatible>(&self, comment: S) {
        let raw = comment.into_bytes_with_nul();

        unsafe {
            BNSetFunctionComment(self.handle, raw.as_ref().as_ptr() as *mut _);
        }
    }

    pub fn set_can_return_auto<T: Into<Conf<bool>>>(&self, can_return: T) {
        let mut bool_with_confidence = can_return.into().into();
        unsafe { BNSetAutoFunctionCanReturn(self.handle, &mut bool_with_confidence) }
    }

    pub fn set_can_return_user<T: Into<Conf<bool>>>(&self, can_return: T) {
        let mut bool_with_confidence = can_return.into().into();
        unsafe { BNSetUserFunctionCanReturn(self.handle, &mut bool_with_confidence) }
    }

    pub fn comment_at(&self, addr: u64) -> BnString {
        unsafe { BnString::from_raw(BNGetCommentForAddress(self.handle, addr)) }
    }

    pub fn set_comment_at<S: BnStrCompatible>(&self, addr: u64, comment: S) {
        let raw = comment.into_bytes_with_nul();

        unsafe {
            BNSetCommentForAddress(self.handle, addr, raw.as_ref().as_ptr() as *mut _);
        }
    }

    /// All comments in the function
    pub fn comments(&self) -> Array<Comment> {
        let mut count = 0;
        let lines = unsafe { BNGetCommentedAddresses(self.handle, &mut count) };
        unsafe { Array::new(lines, count, self.to_owned()) }
    }

    pub fn basic_blocks(&self) -> Array<BasicBlock<NativeBlock>> {
        unsafe {
            let mut count = 0;
            let blocks = BNGetFunctionBasicBlockList(self.handle, &mut count);
            let context = NativeBlock { _priv: () };

            Array::new(blocks, count, context)
        }
    }

    /// Returns the BasicBlock that contains the given address `addr`.
    ///
    /// * `addr` - Address of the BasicBlock to retrieve.
    /// * `arch` - Architecture of the basic block if different from the Function's self.arch
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::function::Function;
    /// # let fun: Function = todo!();
    /// let blocks = fun.basic_block_containing(0x1000, None);
    /// ```
    pub fn basic_block_containing(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Option<Ref<BasicBlock<NativeBlock>>> {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe {
            let basic_block_ptr = BNGetFunctionBasicBlockAtAddress(self.handle, arch.handle, addr);
            let context = NativeBlock { _priv: () };
            match basic_block_ptr.is_null() {
                false => Some(BasicBlock::ref_from_raw(basic_block_ptr, context)),
                true => None,
            }
        }
    }

    pub fn block_annotations(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<Array<InstructionTextToken>> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let lines =
            unsafe { BNGetFunctionBlockAnnotations(self.handle, arch.handle, addr, &mut count) };
        assert!(!lines.is_null());
        unsafe { Array::new(lines, count, ()) }
    }

    pub fn variable_name(&self, var: &Variable) -> BnString {
        unsafe {
            let raw_var = BNVariable::from(var);
            let raw_name = BNGetVariableName(self.handle, &raw_var);
            BnString::from_raw(raw_name)
        }
    }

    pub fn high_level_il(&self, full_ast: bool) -> Result<Ref<HighLevelILFunction>, ()> {
        unsafe {
            let hlil_ptr = BNGetFunctionHighLevelIL(self.handle);
            match hlil_ptr.is_null() {
                false => Ok(HighLevelILFunction::ref_from_raw(hlil_ptr, full_ast)),
                true => Err(()),
            }
        }
    }

    pub fn high_level_il_if_available(&self) -> Option<Ref<HighLevelILFunction>> {
        let hlil_ptr = unsafe { BNGetFunctionHighLevelILIfAvailable(self.handle) };
        match hlil_ptr.is_null() {
            false => Some(unsafe { HighLevelILFunction::ref_from_raw(hlil_ptr, true) }),
            true => None,
        }
    }

    /// MediumLevelILFunction used to represent Function mapped medium level IL
    pub fn mapped_medium_level_il(&self) -> Result<Ref<MediumLevelILFunction>, ()> {
        let mlil_ptr = unsafe { BNGetFunctionMappedMediumLevelIL(self.handle) };
        match mlil_ptr.is_null() {
            false => Ok(unsafe { MediumLevelILFunction::ref_from_raw(mlil_ptr) }),
            true => Err(()),
        }
    }

    pub fn mapped_medium_level_il_if_available(&self) -> Option<Ref<MediumLevelILFunction>> {
        let mlil_ptr = unsafe { BNGetFunctionMappedMediumLevelILIfAvailable(self.handle) };
        match mlil_ptr.is_null() {
            false => Some(unsafe { MediumLevelILFunction::ref_from_raw(mlil_ptr) }),
            true => None,
        }
    }

    pub fn medium_level_il(&self) -> Result<Ref<MediumLevelILFunction>, ()> {
        unsafe {
            let mlil_ptr = BNGetFunctionMediumLevelIL(self.handle);
            match mlil_ptr.is_null() {
                false => Ok(MediumLevelILFunction::ref_from_raw(mlil_ptr)),
                true => Err(()),
            }
        }
    }

    pub fn medium_level_il_if_available(&self) -> Option<Ref<MediumLevelILFunction>> {
        let mlil_ptr = unsafe { BNGetFunctionMediumLevelILIfAvailable(self.handle) };
        match mlil_ptr.is_null() {
            false => Some(unsafe { MediumLevelILFunction::ref_from_raw(mlil_ptr) }),
            true => None,
        }
    }

    pub fn low_level_il(&self) -> Result<Ref<RegularLowLevelILFunction<CoreArchitecture>>, ()> {
        unsafe {
            let llil_ptr = BNGetFunctionLowLevelIL(self.handle);
            match llil_ptr.is_null() {
                false => Ok(RegularLowLevelILFunction::ref_from_raw(
                    self.arch(),
                    llil_ptr,
                )),
                true => Err(()),
            }
        }
    }

    pub fn low_level_il_if_available(
        &self,
    ) -> Option<Ref<RegularLowLevelILFunction<CoreArchitecture>>> {
        let llil_ptr = unsafe { BNGetFunctionLowLevelILIfAvailable(self.handle) };
        match llil_ptr.is_null() {
            false => {
                Some(unsafe { RegularLowLevelILFunction::ref_from_raw(self.arch(), llil_ptr) })
            }
            true => None,
        }
    }

    pub fn lifted_il(&self) -> Result<Ref<LiftedILFunction<CoreArchitecture>>, ()> {
        unsafe {
            let llil_ptr = BNGetFunctionLiftedIL(self.handle);
            match llil_ptr.is_null() {
                false => Ok(LiftedILFunction::ref_from_raw(self.arch(), llil_ptr)),
                true => Err(()),
            }
        }
    }

    pub fn lifted_il_if_available(&self) -> Option<Ref<LiftedILFunction<CoreArchitecture>>> {
        let llil_ptr = unsafe { BNGetFunctionLiftedILIfAvailable(self.handle) };
        match llil_ptr.is_null() {
            false => Some(unsafe { LiftedILFunction::ref_from_raw(self.arch(), llil_ptr) }),
            true => None,
        }
    }

    pub fn return_type(&self) -> Conf<Ref<Type>> {
        let raw_return_type = unsafe { BNGetFunctionReturnType(self.handle) };
        Conf::<Ref<Type>>::from_owned_raw(raw_return_type)
    }

    pub fn set_auto_return_type<'a, C>(&self, return_type: C)
    where
        C: Into<Conf<&'a Type>>,
    {
        let mut raw_return_type = Conf::<&Type>::into_raw(return_type.into());
        unsafe { BNSetAutoFunctionReturnType(self.handle, &mut raw_return_type) }
    }

    pub fn set_user_return_type<'a, C>(&self, return_type: C)
    where
        C: Into<Conf<&'a Type>>,
    {
        let mut raw_return_type = Conf::<&Type>::into_raw(return_type.into());
        unsafe { BNSetUserFunctionReturnType(self.handle, &mut raw_return_type) }
    }

    pub fn function_type(&self) -> Ref<Type> {
        unsafe { Type::ref_from_raw(BNGetFunctionType(self.handle)) }
    }

    pub fn has_user_type(&self) -> bool {
        unsafe { BNFunctionHasUserType(self.handle) }
    }

    pub fn set_user_type(&self, t: &Type) {
        unsafe { BNSetFunctionUserType(self.handle, t.handle) }
    }

    pub fn set_auto_type(&self, t: &Type) {
        unsafe { BNSetFunctionAutoType(self.handle, t.handle) }
    }

    pub fn stack_layout(&self) -> Array<NamedVariableWithType> {
        let mut count = 0;
        unsafe {
            let variables = BNGetStackLayout(self.handle, &mut count);
            Array::new(variables, count, ())
        }
    }

    /// Gets number of bytes removed from the stack after return
    pub fn stack_adjustment(&self) -> Conf<i64> {
        unsafe { BNGetFunctionStackAdjustment(self.handle) }.into()
    }

    /// Sets number of bytes removed from the stack after return
    pub fn set_user_stack_adjustment<C>(&self, value: C)
    where
        C: Into<Conf<i64>>,
    {
        let value: Conf<i64> = value.into();
        let mut value_raw = value.into();
        unsafe { BNSetUserFunctionStackAdjustment(self.handle, &mut value_raw) }
    }

    /// Sets number of bytes removed from the stack after return
    pub fn set_auto_stack_adjustment<C>(&self, value: C)
    where
        C: Into<Conf<i64>>,
    {
        let value: Conf<i64> = value.into();
        let mut value_raw = value.into();
        unsafe { BNSetAutoFunctionStackAdjustment(self.handle, &mut value_raw) }
    }

    pub fn call_stack_adjustment(&self, addr: u64, arch: Option<CoreArchitecture>) -> Conf<i64> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let result = unsafe { BNGetCallStackAdjustment(self.handle, arch.handle, addr) };
        result.into()
    }

    pub fn set_user_call_stack_adjustment<I>(
        &self,
        addr: u64,
        adjust: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: Into<Conf<i64>>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let adjust: Conf<i64> = adjust.into();
        unsafe {
            BNSetUserCallStackAdjustment(
                self.handle,
                arch.handle,
                addr,
                adjust.contents,
                adjust.confidence,
            )
        }
    }

    pub fn set_auto_call_stack_adjustment<I>(
        &self,
        addr: u64,
        adjust: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: Into<Conf<i64>>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let adjust: Conf<i64> = adjust.into();
        unsafe {
            BNSetAutoCallStackAdjustment(
                self.handle,
                arch.handle,
                addr,
                adjust.contents,
                adjust.confidence,
            )
        }
    }

    pub fn call_type_adjustment(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Option<Conf<Ref<Type>>> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let result = unsafe { BNGetCallTypeAdjustment(self.handle, arch.handle, addr) };
        match result.type_.is_null() {
            false => Some(Conf::<Ref<Type>>::from_owned_raw(result)),
            true => None,
        }
    }

    /// Sets or removes the call type override at a call site to the given type.
    ///
    /// * `addr` - virtual address of the call instruction to adjust
    /// * `adjust_type` - (optional) overridden call type, or `None` to remove an existing adjustment
    /// * `arch` - (optional) Architecture of the instruction if different from self.arch
    pub fn set_user_call_type_adjustment<'a, I>(
        &self,
        addr: u64,
        adjust_type: Option<I>,
        arch: Option<CoreArchitecture>,
    ) where
        I: Into<Conf<&'a Type>>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut adjust_type = adjust_type.map(|adjust_type| {
            let adjust_type = adjust_type.into();
            BNTypeWithConfidence {
                type_: adjust_type.contents.handle,
                confidence: adjust_type.confidence,
            }
        });
        let adjust_ptr = adjust_type
            .as_mut()
            .map(|x| x as *mut _)
            .unwrap_or(std::ptr::null_mut());
        unsafe { BNSetUserCallTypeAdjustment(self.handle, arch.handle, addr, adjust_ptr) }
    }

    pub fn set_auto_call_type_adjustment<'a, I>(
        &self,
        addr: u64,
        adjust_type: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: Into<Conf<&'a Type>>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let adjust_type: Conf<&Type> = adjust_type.into();
        unsafe {
            BNSetAutoCallTypeAdjustment(
                self.handle,
                arch.handle,
                addr,
                &mut BNTypeWithConfidence {
                    type_: adjust_type.contents.handle,
                    confidence: adjust_type.confidence,
                },
            )
        }
    }

    pub fn call_reg_stack_adjustment(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<RegisterStackAdjustment> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let adjust =
            unsafe { BNGetCallRegisterStackAdjustment(self.handle, arch.handle, addr, &mut count) };
        assert!(!adjust.is_null());
        unsafe { Array::new(adjust, count, ()) }
    }

    pub fn set_user_call_reg_stack_adjustment<I>(
        self,
        addr: u64,
        adjust: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: IntoIterator<Item = RegisterStackAdjustment>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let adjustments: Vec<BNRegisterStackAdjustment> =
            adjust.into_iter().map(Into::into).collect();
        unsafe {
            BNSetUserCallRegisterStackAdjustment(
                self.handle,
                arch.handle,
                addr,
                adjustments.as_ptr() as *mut _,
                adjustments.len(),
            )
        }
    }

    pub fn set_auto_call_reg_stack_adjustment<I>(
        &self,
        addr: u64,
        adjust: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: IntoIterator<Item = RegisterStackAdjustment>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let adjustments: Vec<BNRegisterStackAdjustment> =
            adjust.into_iter().map(Into::into).collect();
        unsafe {
            BNSetAutoCallRegisterStackAdjustment(
                self.handle,
                arch.handle,
                addr,
                adjustments.as_ptr() as *mut _,
                adjustments.len(),
            )
        }
    }

    pub fn call_reg_stack_adjustment_for_reg_stack(
        &self,
        addr: u64,
        reg_stack_id: u32,
        arch: Option<CoreArchitecture>,
    ) -> RegisterStackAdjustment {
        let arch = arch.unwrap_or_else(|| self.arch());
        let adjust = unsafe {
            BNGetCallRegisterStackAdjustmentForRegisterStack(
                self.handle,
                arch.handle,
                addr,
                reg_stack_id,
            )
        };
        RegisterStackAdjustment::from(adjust)
    }

    pub fn set_user_call_reg_stack_adjustment_for_reg_stack<I>(
        &self,
        addr: u64,
        reg_stack_id: u32,
        adjust: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: Into<Conf<i32>>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let adjust: Conf<i32> = adjust.into();
        unsafe {
            BNSetUserCallRegisterStackAdjustmentForRegisterStack(
                self.handle,
                arch.handle,
                addr,
                reg_stack_id,
                adjust.contents,
                adjust.confidence,
            )
        }
    }

    pub fn set_auto_call_reg_stack_adjustment_for_reg_stack<I>(
        &self,
        addr: u64,
        reg_stack_id: u32,
        adjust: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: Into<Conf<i32>>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let adjust: Conf<i32> = adjust.into();
        unsafe {
            BNSetAutoCallRegisterStackAdjustmentForRegisterStack(
                self.handle,
                arch.handle,
                addr,
                reg_stack_id,
                adjust.contents,
                adjust.confidence,
            )
        }
    }

    pub fn reg_stack_adjustments(&self) -> Array<RegisterStackAdjustment> {
        let mut count = 0;
        let adjust = unsafe { BNGetFunctionRegisterStackAdjustments(self.handle, &mut count) };
        assert!(!adjust.is_null());
        unsafe { Array::new(adjust, count, ()) }
    }

    pub fn set_user_reg_stack_adjustments<I>(&self, values: I)
    where
        I: IntoIterator<Item = RegisterStackAdjustment>,
    {
        let values: Vec<BNRegisterStackAdjustment> = values.into_iter().map(Into::into).collect();
        unsafe {
            BNSetUserFunctionRegisterStackAdjustments(
                self.handle,
                values.as_ptr() as *mut _,
                values.len(),
            )
        }
    }

    pub fn set_auto_reg_stack_adjustments<I>(&self, values: I)
    where
        I: IntoIterator<Item = RegisterStackAdjustment>,
    {
        let values: Vec<BNRegisterStackAdjustment> = values.into_iter().map(Into::into).collect();
        unsafe {
            BNSetAutoFunctionRegisterStackAdjustments(
                self.handle,
                values.as_ptr() as *mut _,
                values.len(),
            )
        }
    }

    // TODO: Turn this into an actual type?
    /// List of function variables: including name, variable and type
    pub fn variables(&self) -> Array<(&str, Variable, &Type)> {
        let mut count = 0;
        let vars = unsafe { BNGetFunctionVariables(self.handle, &mut count) };
        assert!(!vars.is_null());
        unsafe { Array::new(vars, count, ()) }
    }

    pub fn split_variables(&self) -> Array<Variable> {
        let mut count = 0;
        let vars = unsafe { BNGetSplitVariables(self.handle, &mut count) };
        assert!(!vars.is_null());
        unsafe { Array::new(vars, count, ()) }
    }

    pub fn parameter_variables(&self) -> Conf<Vec<Variable>> {
        unsafe {
            let mut raw_variables = BNGetFunctionParameterVariables(self.handle);
            let raw_var_list = std::slice::from_raw_parts(raw_variables.vars, raw_variables.count);
            let variables: Vec<Variable> = raw_var_list.iter().map(Into::into).collect();
            let confidence = raw_variables.confidence;
            BNFreeParameterVariables(&mut raw_variables);
            Conf::new(variables, confidence)
        }
    }

    pub fn set_user_parameter_variables<I>(&self, values: I, confidence: u8)
    where
        I: IntoIterator<Item = Variable>,
    {
        let vars: Vec<BNVariable> = values.into_iter().map(Into::into).collect();
        unsafe {
            BNSetUserFunctionParameterVariables(
                self.handle,
                &mut BNParameterVariablesWithConfidence {
                    vars: vars.as_ptr() as *mut _,
                    count: vars.len(),
                    confidence,
                },
            )
        }
    }

    pub fn set_auto_parameter_variables<I>(&self, values: I, confidence: u8)
    where
        I: IntoIterator<Item = Variable>,
    {
        let vars: Vec<BNVariable> = values.into_iter().map(Into::into).collect();
        unsafe {
            BNSetAutoFunctionParameterVariables(
                self.handle,
                &mut BNParameterVariablesWithConfidence {
                    vars: vars.as_ptr() as *mut _,
                    count: vars.len(),
                    confidence,
                },
            )
        }
    }

    pub fn parameter_at(
        &self,
        addr: u64,
        func_type: Option<&Type>,
        i: usize,
        arch: Option<CoreArchitecture>,
    ) -> RegisterValue {
        let arch = arch.unwrap_or_else(|| self.arch());
        let func_type = func_type.map(|f| f.handle).unwrap_or(std::ptr::null_mut());
        let value = unsafe {
            BNGetParameterValueAtInstruction(self.handle, arch.handle, addr, func_type, i)
        };
        value.into()
    }

    pub fn parameter_at_low_level_il_instruction(
        &self,
        instr: usize,
        func_type: &Type,
        i: usize,
    ) -> RegisterValue {
        let value = unsafe {
            BNGetParameterValueAtLowLevelILInstruction(self.handle, instr, func_type.handle, i)
        };
        value.into()
    }

    pub fn apply_imported_types(&self, sym: &Symbol, t: Option<&Type>) {
        unsafe {
            BNApplyImportedTypes(
                self.handle,
                sym.handle,
                t.map(|t| t.handle).unwrap_or(std::ptr::null_mut()),
            );
        }
    }

    pub fn apply_auto_discovered_type(&self, func_type: &Type) {
        unsafe { BNApplyAutoDiscoveredFunctionType(self.handle, func_type.handle) }
    }

    /// Whether automatic analysis was skipped for this function.
    /// Can be set to false to re-enable analysis.
    pub fn analysis_skipped(&self) -> bool {
        unsafe { BNIsFunctionAnalysisSkipped(self.handle) }
    }

    pub fn set_analysis_skipped(&self, skip: bool) {
        if skip {
            unsafe {
                BNSetFunctionAnalysisSkipOverride(
                    self.handle,
                    BNFunctionAnalysisSkipOverride::AlwaysSkipFunctionAnalysis,
                );
            }
        } else {
            unsafe {
                BNSetFunctionAnalysisSkipOverride(
                    self.handle,
                    BNFunctionAnalysisSkipOverride::NeverSkipFunctionAnalysis,
                );
            }
        }
    }

    pub fn analysis_skip_reason(&self) -> AnalysisSkipReason {
        unsafe { BNGetAnalysisSkipReason(self.handle) }
    }

    pub fn analysis_skip_override(&self) -> FunctionAnalysisSkipOverride {
        unsafe { BNGetFunctionAnalysisSkipOverride(self.handle) }
    }

    pub fn set_analysis_skip_override(&self, override_: FunctionAnalysisSkipOverride) {
        unsafe { BNSetFunctionAnalysisSkipOverride(self.handle, override_) }
    }

    ///Whether the function's IL should be inlined into all callers' IL
    pub fn inline_during_analysis(&self) -> Conf<bool> {
        let result = unsafe { BNIsFunctionInlinedDuringAnalysis(self.handle) };
        result.into()
    }

    pub fn set_auto_inline_during_analysis<C>(&self, value: C)
    where
        C: Into<Conf<bool>>,
    {
        let value: Conf<bool> = value.into();
        unsafe { BNSetAutoFunctionInlinedDuringAnalysis(self.handle, value.into()) }
    }

    pub fn set_user_inline_during_analysis<C>(&self, value: C)
    where
        C: Into<Conf<bool>>,
    {
        let value: Conf<bool> = value.into();
        unsafe { BNSetUserFunctionInlinedDuringAnalysis(self.handle, value.into()) }
    }

    pub fn analysis_performance_info(&self) -> Array<PerformanceInfo> {
        let mut count = 0;
        let info = unsafe { BNGetFunctionAnalysisPerformanceInfo(self.handle, &mut count) };
        assert!(!info.is_null());
        unsafe { Array::new(info, count, ()) }
    }

    /// Creates and adds a [Tag] object on either a function, or on
    /// an address inside of a function.
    ///
    /// "Function tags" appear at the top of a function and are a good way to label an
    /// entire function with some information. If you include an address when you call
    /// Function.add_tag, you'll create an "address tag". These are good for labeling
    /// specific instructions.
    ///
    /// For tagging arbitrary data, consider [BinaryViewExt::add_tag].
    ///
    /// * `tag_type_name` - The name of the tag type for this Tag.
    /// * `data` - Additional data for the Tag.
    /// * `addr` - Address at which to add the tag.
    /// * `user` - Whether or not a user tag.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use binaryninja::binary_view::{BinaryView, BinaryViewExt};
    /// # use binaryninja::function::Function;
    /// # let fun: Function = todo!();
    /// # let bv: BinaryView = todo!();
    /// let important = bv.create_tag_type("Important", "⚠️");
    /// fun.add_tag(
    ///     &important,
    ///     "I think this is the main function",
    ///     None,
    ///     false,
    ///     None,
    /// );
    /// let crash = bv.create_tag_type("Crashes", "🎯");
    /// fun.add_tag(&crash, "Nullpointer dereference", Some(0x1337), false, None);
    /// ```
    pub fn add_tag<S: BnStrCompatible>(
        &self,
        tag_type: &TagType,
        data: S,
        addr: Option<u64>,
        user: bool,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());

        // Create tag
        let tag = Tag::new(tag_type, data);
        let binaryview = unsafe { BinaryView::ref_from_raw(BNGetFunctionData(self.handle)) };
        unsafe { BNAddTag(binaryview.handle, tag.handle, user) };

        unsafe {
            match (user, addr) {
                (false, None) => BNAddAutoFunctionTag(self.handle, tag.handle),
                (false, Some(addr)) => {
                    BNAddAutoAddressTag(self.handle, arch.handle, addr, tag.handle)
                }
                (true, None) => BNAddUserFunctionTag(self.handle, tag.handle),
                (true, Some(addr)) => {
                    BNAddUserAddressTag(self.handle, arch.handle, addr, tag.handle)
                }
            }
        }
    }

    /// Remove [Tag] object on either a function, or on an address inside of a function.
    ///
    /// * `tag` - The tag to remove.
    /// * `addr` - (optional) Address at which to remove the tag.
    /// * `user` - Whether or not a user tag.
    pub fn remove_tag(
        &self,
        tag: &Tag,
        addr: Option<u64>,
        user: bool,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe {
            match (user, addr) {
                (false, None) => BNRemoveAutoFunctionTag(self.handle, tag.handle),
                (false, Some(addr)) => {
                    BNRemoveAutoAddressTag(self.handle, arch.handle, addr, tag.handle)
                }
                (true, None) => BNRemoveUserFunctionTag(self.handle, tag.handle),
                (true, Some(addr)) => {
                    BNRemoveUserAddressTag(self.handle, arch.handle, addr, tag.handle)
                }
            }
        }
    }

    /// Remove [Tag] object of type on either a function, or on an address
    /// inside of a function.
    ///
    /// * `tag_type` - The type of the to remove.
    /// * `addr` - Address at which to add the tag.
    /// * `user` - Whether or not a user tag.
    pub fn remove_tags_of_type(
        &self,
        tag_type: &TagType,
        addr: Option<u64>,
        user: bool,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe {
            match (user, addr) {
                (false, None) => BNRemoveAutoFunctionTagsOfType(self.handle, tag_type.handle),
                (false, Some(addr)) => {
                    BNRemoveAutoAddressTagsOfType(self.handle, arch.handle, addr, tag_type.handle)
                }
                (true, None) => BNRemoveUserFunctionTagsOfType(self.handle, tag_type.handle),
                (true, Some(addr)) => {
                    BNRemoveUserAddressTagsOfType(self.handle, arch.handle, addr, tag_type.handle)
                }
            }
        }
    }

    /// Places a user-defined cross-reference from the instruction at
    /// the given address and architecture to the specified target address. If the specified
    /// source instruction is not contained within this function, no action is performed.
    /// To remove the reference, use [Function::remove_user_code_ref].
    ///
    /// * `from_addr` - Virtual address of the source instruction.
    /// * `to_addr` - Virtual address of the xref's destination.
    /// * `arch` - Architecture of the source instruction.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use binaryninja::function::Function;
    /// # let fun: Function = todo!();
    /// fun.add_user_code_ref(0x1337, 0x400000, None);
    /// ```
    pub fn add_user_code_ref(&self, from_addr: u64, to_addr: u64, arch: Option<CoreArchitecture>) {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe { BNAddUserCodeReference(self.handle, arch.handle, from_addr, to_addr) }
    }

    /// Removes a user-defined cross-reference.
    /// If the given address is not contained within this function, or if there is no
    /// such user-defined cross-reference, no action is performed.
    ///
    /// * `from_addr` - virtual address of the source instruction
    /// * `to_addr` - virtual address of the xref's destination.
    /// * `arch` - architecture of the source instruction
    ///
    /// #Example
    ///
    /// ```no_run
    /// # use binaryninja::function::Function;
    /// # let fun: Function = todo!();
    /// fun.remove_user_code_ref(0x1337, 0x400000, None);
    /// ```
    pub fn remove_user_code_ref(
        self,
        from_addr: u64,
        to_addr: u64,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe { BNRemoveUserCodeReference(self.handle, arch.handle, from_addr, to_addr) }
    }

    /// Places a user-defined type cross-reference from the instruction at
    /// the given address and architecture to the specified type. If the specified
    /// source instruction is not contained within this function, no action is performed.
    /// To remove the reference, use [Function::remove_user_type_ref].
    ///
    /// * `from_addr` - Virtual address of the source instruction.
    /// * `name` - Name of the referenced type.
    /// * `arch` - Architecture of the source instruction.
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::function::Function;
    /// # let fun: Function = todo!();
    /// fun.add_user_type_ref(0x1337, "A", None);
    /// ```
    pub fn add_user_type_ref<T: Into<QualifiedName>>(
        &self,
        from_addr: u64,
        name: T,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe { BNAddUserTypeReference(self.handle, arch.handle, from_addr, &mut raw_name) };
        QualifiedName::free_raw(raw_name);
    }

    /// Removes a user-defined type cross-reference.
    /// If the given address is not contained within this function, or if there is no
    /// such user-defined cross-reference, no action is performed.
    ///
    /// * `from_addr` - Virtual address of the source instruction.
    /// * `name` - Name of the referenced type.
    /// * `from_arch` - Architecture of the source instruction.
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::function::Function;
    /// # let fun: Function = todo!();
    /// fun.remove_user_type_ref(0x1337, "A", None);
    /// ```
    pub fn remove_user_type_ref<T: Into<QualifiedName>>(
        &self,
        from_addr: u64,
        name: T,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe { BNRemoveUserTypeReference(self.handle, arch.handle, from_addr, &mut raw_name) };
        QualifiedName::free_raw(raw_name);
    }

    /// Places a user-defined type field cross-reference from the
    /// instruction at the given address and architecture to the specified type. If the specified
    /// source instruction is not contained within this function, no action is performed.
    /// To remove the reference, use [Function::remove_user_type_field_ref].
    ///
    /// * `from_addr` - Virtual address of the source instruction.
    /// * `name` - Name of the referenced type.
    /// * `offset` - Offset of the field, relative to the type.
    /// * `arch` - Architecture of the source instruction.
    /// * `size` - The size of the access.
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::function::Function;
    /// # let fun: Function = todo!();
    /// fun.add_user_type_field_ref(0x1337, "A", 0x8, None, None);
    /// ```
    pub fn add_user_type_field_ref<T: Into<QualifiedName>>(
        &self,
        from_addr: u64,
        name: T,
        offset: u64,
        arch: Option<CoreArchitecture>,
        size: Option<usize>,
    ) {
        let size = size.unwrap_or(0);
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            BNAddUserTypeFieldReference(
                self.handle,
                arch.handle,
                from_addr,
                &mut raw_name,
                offset,
                size,
            )
        };
        QualifiedName::free_raw(raw_name);
    }

    /// Removes a user-defined type field cross-reference.
    /// If the given address is not contained within this function, or if there is no
    /// such user-defined cross-reference, no action is performed.
    ///
    /// * `from_addr` - Virtual address of the source instruction
    /// * `name` - Name of the referenced type
    /// * `offset` - Offset of the field, relative to the type
    /// * `arch` - Architecture of the source instruction
    /// * `size` - The size of the access
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::function::Function;
    /// # let fun: Function = todo!();
    /// fun.remove_user_type_field_ref(0x1337, "A", 0x8, None, None);
    /// ```
    pub fn remove_user_type_field_ref<T: Into<QualifiedName>>(
        &self,
        from_addr: u64,
        name: T,
        offset: u64,
        arch: Option<CoreArchitecture>,
        size: Option<usize>,
    ) {
        let size = size.unwrap_or(0);
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            BNRemoveUserTypeFieldReference(
                self.handle,
                arch.handle,
                from_addr,
                &mut raw_name,
                offset,
                size,
            )
        }
        QualifiedName::free_raw(raw_name);
    }

    pub fn constant_data(
        &self,
        state: RegisterValueType,
        value: u64,
        size: Option<usize>,
    ) -> (DataBuffer, BuiltinType) {
        let size = size.unwrap_or(0);
        // TODO: Adjust `BuiltinType`?
        let mut builtin_type = BuiltinType::BuiltinNone;
        let buffer = DataBuffer::from_raw(unsafe {
            BNGetConstantData(self.handle, state, value, size, &mut builtin_type)
        });
        (buffer, builtin_type)
    }

    pub fn constants_referenced_by(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<ConstantReference> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let refs = unsafe {
            BNGetConstantsReferencedByInstruction(self.handle, arch.handle, addr, &mut count)
        };
        assert!(!refs.is_null());
        unsafe { Array::new(refs, count, ()) }
    }

    pub fn constants_referenced_by_address_if_available(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<ConstantReference> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let refs = unsafe {
            BNGetConstantsReferencedByInstructionIfAvailable(
                self.handle,
                arch.handle,
                addr,
                &mut count,
            )
        };
        assert!(!refs.is_null());
        unsafe { Array::new(refs, count, ()) }
    }

    /// Returns a list of function Tags for the function.
    ///
    /// `auto` - If `None`, gets all tags, if `true`, gets auto tags, if `false`, gets user tags
    /// `tag_type` - If `None`, gets all tags, otherwise only gets tags of the given type
    pub fn function_tags(&self, auto: Option<bool>, tag_type: Option<&str>) -> Array<Tag> {
        let mut count = 0;

        let tag_type = tag_type.map(|tag_type| self.view().tag_type_by_name(tag_type));

        let tags = unsafe {
            match (tag_type, auto) {
                // received a tag_type, BinaryView found none
                (Some(None), _) => return Array::new(std::ptr::null_mut(), 0, ()),

                // with tag_type
                (Some(Some(tag_type)), None) => {
                    BNGetFunctionTagsOfType(self.handle, tag_type.handle, &mut count)
                }
                (Some(Some(tag_type)), Some(true)) => {
                    BNGetAutoFunctionTagsOfType(self.handle, tag_type.handle, &mut count)
                }
                (Some(Some(tag_type)), Some(false)) => {
                    BNGetUserFunctionTagsOfType(self.handle, tag_type.handle, &mut count)
                }
                // without tag_type
                (None, None) => BNGetFunctionTags(self.handle, &mut count),
                (None, Some(true)) => BNGetAutoFunctionTags(self.handle, &mut count),
                (None, Some(false)) => BNGetUserFunctionTags(self.handle, &mut count),
            }
        };
        assert!(!tags.is_null());

        unsafe { Array::new(tags, count, ()) }
    }

    pub fn tags(&self) -> Array<TagReference> {
        let mut count = 0;
        let tags = unsafe { BNGetAddressTagReferences(self.handle, &mut count) };
        unsafe { Array::new(tags, count, ()) }
    }

    /// Gets a list of Tags at the address.
    ///
    /// * `addr` - Address to get tags from.
    /// * `auto` - If `None`, gets all tags, if `true`, gets auto tags, if `false`, gets user tags
    pub fn tags_at(
        &self,
        addr: u64,
        auto: Option<bool>,
        arch: Option<CoreArchitecture>,
    ) -> Array<Tag> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;

        let tags = match auto {
            None => unsafe { BNGetAddressTags(self.handle, arch.handle, addr, &mut count) },
            Some(true) => unsafe {
                BNGetAutoAddressTags(self.handle, arch.handle, addr, &mut count)
            },
            Some(false) => unsafe {
                BNGetUserAddressTags(self.handle, arch.handle, addr, &mut count)
            },
        };
        assert!(!tags.is_null());
        unsafe { Array::new(tags, count, ()) }
    }

    /// Gets a list of Tags in the address range.
    ///
    /// * `addr` - Address to get tags from.
    /// * `auto` - If `None`, gets all tags, if `true`, gets auto tags, if `false`, gets user tags
    pub fn tags_in_range(
        &self,
        range: Range<u64>,
        auto: Option<bool>,
        arch: Option<CoreArchitecture>,
    ) -> Array<TagReference> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;

        let tags = match auto {
            None => unsafe {
                BNGetAddressTagsInRange(
                    self.handle,
                    arch.handle,
                    range.start,
                    range.end,
                    &mut count,
                )
            },
            Some(true) => unsafe {
                BNGetAutoAddressTagsInRange(
                    self.handle,
                    arch.handle,
                    range.start,
                    range.end,
                    &mut count,
                )
            },
            Some(false) => unsafe {
                BNGetUserAddressTagsInRange(
                    self.handle,
                    arch.handle,
                    range.start,
                    range.end,
                    &mut count,
                )
            },
        };
        assert!(!tags.is_null());
        unsafe { Array::new(tags, count, ()) }
    }

    /// List of indirect branches
    pub fn indirect_branches(&self) -> Array<IndirectBranchInfo> {
        let mut count = 0;
        let branches = unsafe { BNGetIndirectBranches(self.handle, &mut count) };
        assert!(!branches.is_null());
        unsafe { Array::new(branches, count, ()) }
    }

    pub fn set_user_indirect_branches<I>(
        &self,
        source: u64,
        branches: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: IntoIterator<Item = u64>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut branches: Box<[BNArchitectureAndAddress]> = branches
            .into_iter()
            .map(|address| BNArchitectureAndAddress {
                address,
                arch: arch.handle,
            })
            .collect();
        unsafe {
            BNSetUserIndirectBranches(
                self.handle,
                arch.handle,
                source,
                branches.as_mut_ptr(),
                branches.len(),
            )
        }
    }

    pub fn set_auto_indirect_branches<I>(
        &self,
        source: u64,
        branches: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: IntoIterator<Item = u64>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut branches: Box<[BNArchitectureAndAddress]> = branches
            .into_iter()
            .map(|address| BNArchitectureAndAddress {
                address,
                arch: arch.handle,
            })
            .collect();
        unsafe {
            BNSetAutoIndirectBranches(
                self.handle,
                arch.handle,
                source,
                branches.as_mut_ptr(),
                branches.len(),
            )
        }
    }

    /// List of indirect branches at this address
    pub fn indirect_branches_at(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<IndirectBranchInfo> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let branches =
            unsafe { BNGetIndirectBranchesAt(self.handle, arch.handle, addr, &mut count) };
        assert!(!branches.is_null());
        unsafe { Array::new(branches, count, ()) }
    }

    /// # Example
    /// ```no_run
    /// # let fun: binaryninja::function::Function = todo!();
    /// let color = fun.instr_highlight(0x1337, None);
    /// ```
    pub fn instr_highlight(&self, addr: u64, arch: Option<CoreArchitecture>) -> HighlightColor {
        let arch = arch.unwrap_or_else(|| self.arch());
        let color = unsafe { BNGetInstructionHighlight(self.handle, arch.handle, addr) };
        HighlightColor::from(color)
    }

    /// Sets the highlights the instruction at the specified address with the supplied color
    ///
    /// <div class="warning">Use only in analysis plugins. Do not use in regular plugins, as colors won't be saved to the database.</div>
    ///
    /// * `addr` - virtual address of the instruction to be highlighted
    /// * `color` - Color value to use for highlighting
    /// * `arch` - (optional) Architecture of the instruction if different from self.arch
    pub fn set_auto_instr_highlight(
        &self,
        addr: u64,
        color: HighlightColor,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe { BNSetAutoInstructionHighlight(self.handle, arch.handle, addr, color.into()) }
    }

    /// Sets the highlights the instruction at the specified address with the supplied color
    ///
    /// * `addr` - virtual address of the instruction to be highlighted
    /// * `color` - Color value to use for highlighting
    /// * `arch` - (optional) Architecture of the instruction, pass this if not views default arch
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::function::{HighlightColor, HighlightStandardColor};
    /// # let function: binaryninja::function::Function = todo!();
    /// let color = HighlightColor::StandardHighlightColor {
    ///     color: HighlightStandardColor::RedHighlightColor,
    ///     alpha: u8::MAX,
    /// };
    /// function.set_user_instr_highlight(0x1337, color, None);
    /// ```
    pub fn set_user_instr_highlight(
        &self,
        addr: u64,
        color: HighlightColor,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe { BNSetUserInstructionHighlight(self.handle, arch.handle, addr, color.into()) }
    }

    /// return the address, if any, of the instruction that contains the
    /// provided address
    pub fn instruction_containing_address(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Option<u64> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut start = 0;
        unsafe { BNGetInstructionContainingAddress(self.handle, arch.handle, addr, &mut start) }
            .then_some(start)
    }

    /// Get the current text display type for an integer token in the disassembly or IL views
    ///
    /// See also see [Function::int_display_type_and_typeid]
    ///
    /// * `instr_addr`  - Address of the instruction or IL line containing the token
    /// * `value` - field of the InstructionTextToken object for the token, usually the constant displayed
    /// * `operand` - Operand index of the token, defined as the number of OperandSeparatorTokens in the disassembly line before the token
    /// * `arch` - (optional) Architecture of the instruction or IL line containing the token
    pub fn int_display_type(
        &self,
        instr_addr: u64,
        value: u64,
        operand: usize,
        arch: Option<CoreArchitecture>,
    ) -> IntegerDisplayType {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe {
            BNGetIntegerConstantDisplayType(self.handle, arch.handle, instr_addr, value, operand)
        }
    }

    /// Change the text display type for an integer token in the disassembly or IL views
    ///
    /// * `instr_addr` - Address of the instruction or IL line containing the token
    /// * `value` - Field of the InstructionTextToken object for the token, usually the constant displayed
    /// * `operand` - Operand index of the token, defined as the number of OperandSeparatorTokens in the disassembly line before the token
    /// * `display_type` - Desired display type
    /// * `arch` - (optional) Architecture of the instruction or IL line containing the token
    /// * `enum_display_typeid` - (optional) Whenever passing EnumDisplayType to `display_type`, passing a type ID here will specify the Enumeration display type. Must be a valid type ID and resolve to an enumeration type.
    pub fn set_int_display_type(
        &self,
        instr_addr: u64,
        value: u64,
        operand: usize,
        display_type: IntegerDisplayType,
        arch: Option<CoreArchitecture>,
        enum_display_typeid: Option<impl BnStrCompatible>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        let enum_display_typeid = enum_display_typeid.map(BnStrCompatible::into_bytes_with_nul);
        let enum_display_typeid_ptr = enum_display_typeid
            .map(|x| x.as_ref().as_ptr() as *const c_char)
            .unwrap_or(std::ptr::null());
        unsafe {
            BNSetIntegerConstantDisplayType(
                self.handle,
                arch.handle,
                instr_addr,
                value,
                operand,
                display_type,
                enum_display_typeid_ptr,
            )
        }
    }

    /// Get the current text display enum type for an integer token in the disassembly or IL views.
    ///
    /// See also see [Function::int_display_type_and_typeid]
    ///
    /// * `instr_addr` - Address of the instruction or IL line containing the token
    /// * `value` - field of the InstructionTextToken object for the token, usually the constant displayed
    /// * `operand` - Operand index of the token, defined as the number of OperandSeparatorTokens in the disassembly line before the token
    /// * `arch` - (optional) Architecture of the instruction or IL line containing the token
    pub fn int_enum_display_typeid(
        &self,
        instr_addr: u64,
        value: u64,
        operand: usize,
        arch: Option<CoreArchitecture>,
    ) -> BnString {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe {
            BnString::from_raw(BNGetIntegerConstantDisplayTypeEnumerationType(
                self.handle,
                arch.handle,
                instr_addr,
                value,
                operand,
            ))
        }
    }

    /// Get the current text display type for an integer token in the disassembly or IL views
    ///
    /// * `instr_addr` - Address of the instruction or IL line containing the token
    /// * `value` - field of the InstructionTextToken object for the token, usually the constant displayed
    /// * `operand` - Operand index of the token, defined as the number of OperandSeparatorTokens in the disassembly line before the token
    /// * `arch` - (optional) Architecture of the instruction or IL line containing the token
    pub fn int_display_type_and_typeid(
        &self,
        instr_addr: u64,
        value: u64,
        operand: usize,
        arch: Option<CoreArchitecture>,
    ) -> (IntegerDisplayType, BnString) {
        let arch = arch.unwrap_or_else(|| self.arch());
        let name = self.int_enum_display_typeid(instr_addr, value, operand, Some(arch));
        let display = self.int_display_type(instr_addr, value, operand, Some(arch));
        (display, name)
    }

    /// Get the value the provided string register address corresponding to the given virtual address
    ///
    /// * `addr` - virtual address of the instruction to query
    /// * `reg` - string value of native register to query
    /// * `arch` - (optional) Architecture for the given function
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::architecture::{ArchitectureExt, Register};
    /// # let fun: binaryninja::function::Function = todo!();
    /// let reg = fun.arch().register_by_name("rdi").unwrap();
    /// let value = fun.register_value_at(0x400dbe, reg.id(), None);
    /// ```
    pub fn register_value_at(
        &self,
        addr: u64,
        reg: RegisterId,
        arch: Option<CoreArchitecture>,
    ) -> RegisterValue {
        let arch = arch.unwrap_or_else(|| self.arch());
        let register =
            unsafe { BNGetRegisterValueAtInstruction(self.handle, arch.handle, addr, reg.0) };
        register.into()
    }

    /// Gets the value instruction address corresponding to the given virtual address
    ///
    /// * `addr` - virtual address of the instruction to query
    /// * `reg` - string value of native register to query
    /// * `arch` - (optional) Architecture for the given function
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::architecture::{ArchitectureExt, Register};
    /// # let fun: binaryninja::function::Function = todo!();
    /// let reg = fun.arch().register_by_name("rdi").unwrap();
    /// let value = fun.register_value_after(0x400dbe, reg.id(), None);
    /// ```
    pub fn register_value_after(
        &self,
        addr: u64,
        reg: RegisterId,
        arch: Option<CoreArchitecture>,
    ) -> RegisterValue {
        let arch = arch.unwrap_or_else(|| self.arch());
        let register =
            unsafe { BNGetRegisterValueAfterInstruction(self.handle, arch.handle, addr, reg.0) };
        register.into()
    }

    pub fn register_value_at_exit(&self, reg: u32) -> Conf<RegisterValue> {
        let register = unsafe { BNGetFunctionRegisterValueAtExit(self.handle, reg) };
        Conf::new(register.value.into(), register.confidence)
    }

    pub fn registers_read_by(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<CoreRegister> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let regs =
            unsafe { BNGetRegistersReadByInstruction(self.handle, arch.handle, addr, &mut count) };
        assert!(!regs.is_null());
        unsafe { Array::new(regs, count, arch) }
    }

    pub fn registers_written_by(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<CoreRegister> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let regs = unsafe {
            BNGetRegistersWrittenByInstruction(self.handle, arch.handle, addr, &mut count)
        };
        assert!(!regs.is_null());
        unsafe { Array::new(regs, count, arch) }
    }

    /// Registers that are modified by this function
    pub fn clobbered_registers(&self) -> Conf<Array<CoreRegister>> {
        let result = unsafe { BNGetFunctionClobberedRegisters(self.handle) };

        let reg_set = unsafe { Array::new(result.regs, result.count, self.arch().handle()) };
        Conf::new(reg_set, result.confidence)
    }

    pub fn set_user_clobbered_registers<I>(&self, registers: I, confidence: u8)
    where
        I: IntoIterator<Item = CoreRegister>,
    {
        let mut regs: Box<[u32]> = registers.into_iter().map(|reg| reg.id().0).collect();
        let mut regs = BNRegisterSetWithConfidence {
            regs: regs.as_mut_ptr(),
            count: regs.len(),
            confidence,
        };
        unsafe { BNSetUserFunctionClobberedRegisters(self.handle, &mut regs) }
    }

    pub fn set_auto_clobbered_registers<I>(&self, registers: I, confidence: u8)
    where
        I: IntoIterator<Item = CoreRegister>,
    {
        let mut regs: Box<[u32]> = registers.into_iter().map(|reg| reg.id().0).collect();
        let mut regs = BNRegisterSetWithConfidence {
            regs: regs.as_mut_ptr(),
            count: regs.len(),
            confidence,
        };
        unsafe { BNSetAutoFunctionClobberedRegisters(self.handle, &mut regs) }
    }

    pub fn stack_contents_at(
        &self,
        addr: u64,
        offset: i64,
        size: usize,
        arch: Option<CoreArchitecture>,
    ) -> RegisterValue {
        let arch = arch.unwrap_or_else(|| self.arch());
        let value = unsafe {
            BNGetStackContentsAtInstruction(self.handle, arch.handle, addr, offset, size)
        };
        value.into()
    }

    pub fn stack_contents_after(
        &self,
        addr: u64,
        offset: i64,
        size: usize,
        arch: Option<CoreArchitecture>,
    ) -> RegisterValue {
        let arch = arch.unwrap_or_else(|| self.arch());
        let value = unsafe {
            BNGetStackContentsAfterInstruction(self.handle, arch.handle, addr, offset, size)
        };
        value.into()
    }

    pub fn stack_var_at_frame_offset(
        &self,
        addr: u64,
        offset: i64,
        arch: Option<CoreArchitecture>,
    ) -> Option<(Variable, BnString, Conf<Ref<Type>>)> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut found_value = BNVariableNameAndType::default();
        let found = unsafe {
            BNGetStackVariableAtFrameOffset(
                self.handle,
                arch.handle,
                addr,
                offset,
                &mut found_value,
            )
        };
        if !found {
            return None;
        }
        let var = Variable::from(found_value.var);
        let name = unsafe { BnString::from_raw(found_value.name) };
        let var_type = Conf::new(
            unsafe { Type::ref_from_raw(found_value.type_) },
            found_value.typeConfidence,
        );
        Some((var, name, var_type))
    }

    pub fn stack_var_at_frame_offset_after_instruction(
        &self,
        addr: u64,
        offset: i64,
        arch: Option<CoreArchitecture>,
    ) -> Option<(Variable, BnString, Conf<Ref<Type>>)> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut found_value = BNVariableNameAndType::default();
        let found = unsafe {
            BNGetStackVariableAtFrameOffsetAfterInstruction(
                self.handle,
                arch.handle,
                addr,
                offset,
                &mut found_value,
            )
        };
        if !found {
            return None;
        }
        let var = Variable::from(found_value.var);
        let name = unsafe { BnString::from_raw(found_value.name) };
        let var_type = Conf::new(
            unsafe { Type::ref_from_raw(found_value.type_) },
            found_value.typeConfidence,
        );
        Some((var, name, var_type))
    }

    pub fn stack_variables_referenced_by(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<StackVariableReference> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let refs = unsafe {
            BNGetStackVariablesReferencedByInstruction(self.handle, arch.handle, addr, &mut count)
        };
        assert!(!refs.is_null());
        unsafe { Array::new(refs, count, ()) }
    }

    pub fn stack_variables_referenced_by_address_if_available(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<StackVariableReference> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let refs = unsafe {
            BNGetStackVariablesReferencedByInstructionIfAvailable(
                self.handle,
                arch.handle,
                addr,
                &mut count,
            )
        };
        assert!(!refs.is_null());
        unsafe { Array::new(refs, count, ()) }
    }

    /// Discovered value of the global pointer register, if the function uses one
    pub fn global_pointer_value(&self) -> Conf<RegisterValue> {
        let result = unsafe { BNGetFunctionGlobalPointerValue(self.handle) };
        Conf::new(result.value.into(), result.confidence)
    }

    pub fn type_tokens(
        &self,
        settings: Option<&DisassemblySettings>,
    ) -> Array<DisassemblyTextLine> {
        let settings = settings.map(|s| s.handle).unwrap_or(std::ptr::null_mut());
        let mut count = 0;
        let lines = unsafe { BNGetFunctionTypeTokens(self.handle, settings, &mut count) };
        assert!(!lines.is_null());
        unsafe { Array::new(lines, count, ()) }
    }

    pub fn is_call_instruction(&self, addr: u64, arch: Option<CoreArchitecture>) -> bool {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe { BNIsCallInstruction(self.handle, arch.handle, addr) }
    }

    pub fn is_variable_user_defined(&self, var: &Variable) -> bool {
        let raw_var = BNVariable::from(var);
        unsafe { BNIsVariableUserDefined(self.handle, &raw_var) }
    }

    pub fn is_pure(&self) -> Conf<bool> {
        unsafe { BNIsFunctionPure(self.handle) }.into()
    }

    pub fn set_user_pure<C>(&self, value: C)
    where
        C: Into<Conf<bool>>,
    {
        let value: Conf<bool> = value.into();
        let mut value_raw = value.into();
        unsafe { BNSetUserFunctionPure(self.handle, &mut value_raw) };
    }

    pub fn set_auto_pure<C>(&self, value: C)
    where
        C: Into<Conf<bool>>,
    {
        let value: Conf<bool> = value.into();
        let mut value_raw = value.into();
        unsafe { BNSetAutoFunctionPure(self.handle, &mut value_raw) };
    }

    pub fn is_too_large(&self) -> bool {
        unsafe { BNIsFunctionTooLarge(self.handle) }
    }

    pub fn is_update_needed(&self) -> bool {
        unsafe { BNIsFunctionUpdateNeeded(self.handle) }
    }

    /// Indicates that this function needs to be reanalyzed during the next update cycle
    ///
    /// * `update_type` - Desired update type
    pub fn mark_updates_required(&self, update_type: FunctionUpdateType) {
        unsafe { BNMarkUpdatesRequired(self.handle, update_type) }
    }

    /// Indicates that callers of this function need to be reanalyzed during the next update cycle
    ///
    /// * `update_type` - Desired update type
    pub fn mark_caller_updates_required(&self, update_type: FunctionUpdateType) {
        unsafe { BNMarkCallerUpdatesRequired(self.handle, update_type) }
    }

    pub fn mark_recent_use(&self) {
        unsafe { BNMarkFunctionAsRecentlyUsed(self.handle) }
    }

    // Gets the list of merged variables
    pub fn merged_variables(&self) -> Array<MergedVariable> {
        let mut count = 0;
        let vars = unsafe { BNGetMergedVariables(self.handle, &mut count) };
        assert!(!vars.is_null());
        unsafe { Array::new(vars, count, ()) }
    }

    /// Merge one or more variables in `sources` into the `target` variable. All
    /// variable accesses to the variables in `sources` will be rewritten to use `target`.
    ///
    /// * `target` - target variable
    /// * `sources` - list of source variables
    pub fn merge_variables<'a>(
        &self,
        target: &Variable,
        sources: impl IntoIterator<Item = &'a Variable>,
    ) {
        let raw_target_var = BNVariable::from(target);
        let sources_raw: Vec<BNVariable> = sources.into_iter().copied().map(Into::into).collect();
        unsafe {
            BNMergeVariables(
                self.handle,
                &raw_target_var,
                sources_raw.as_ptr(),
                sources_raw.len(),
            )
        }
    }

    /// Undoes variable merging performed with [Function::merge_variables]. The variables in
    /// `sources` will no longer be merged into the `target` variable.
    ///
    /// * `target` - target variable
    /// * `sources` - list of source variables
    pub fn unmerge_variables<'a>(
        &self,
        target: &Variable,
        sources: impl IntoIterator<Item = &'a Variable>,
    ) {
        let raw_target_var = BNVariable::from(target);
        let sources_raw: Vec<BNVariable> = sources.into_iter().copied().map(Into::into).collect();
        unsafe {
            BNUnmergeVariables(
                self.handle,
                &raw_target_var,
                sources_raw.as_ptr(),
                sources_raw.len(),
            )
        }
    }

    /// Splits a variable at the definition site. The given `var` must be the
    /// variable unique to the definition and should be obtained by using
    /// [crate::medium_level_il::MediumLevelILInstruction::get_split_var_for_definition] at the definition site.
    ///
    /// This function is not meant to split variables that have been previously merged. Use
    /// [Function::unmerge_variables] to split previously merged variables.
    ///
    /// <div class="warning">
    ///
    /// Binary Ninja automatically splits all variables that the analysis determines
    /// to be safely splittable. Splitting a variable manually with [Function::split_variable] can cause
    /// IL and decompilation to be incorrect. There are some patterns where variables can be safely
    /// split semantically but analysis cannot determine that it is safe. This function is provided
    /// to allow variable splitting to be performed in these cases by plugins or by the user.
    ///
    /// </div>
    ///
    /// * `var` - variable to split
    pub fn split_variable(&self, var: &Variable) {
        let raw_var = BNVariable::from(var);
        unsafe { BNSplitVariable(self.handle, &raw_var) }
    }

    /// Undoes variable splitting performed with [Function::split_variable]. The given `var`
    /// must be the variable unique to the definition and should be obtained by using
    /// [crate::medium_level_il::MediumLevelILInstruction::get_split_var_for_definition] at the definition site.
    ///
    /// * `var` - variable to unsplit
    pub fn unsplit_variable(&self, var: &Variable) {
        let raw_var = BNVariable::from(var);
        unsafe { BNUnsplitVariable(self.handle, &raw_var) }
    }

    /// Causes this function to be reanalyzed. This function does not wait for the analysis to finish.
    ///
    /// * `update_type` - Desired update type
    ///
    /// <div class="warning">
    ///
    /// If analysis_skipped is `true`, using this API will not trigger
    /// re-analysis. Instead, use [Function::set_analysis_skipped] with `false`.
    ///
    /// </div>
    pub fn reanalyze(&self, update_type: FunctionUpdateType) {
        unsafe { BNReanalyzeFunction(self.handle, update_type) }
    }

    /// Generate internal debug reports for a variety of analysis.
    /// Current list of possible values include:
    ///
    /// - mlil_translator
    /// - stack_adjust_graph
    /// - high_level_il
    ///
    /// * `name` - Name of the debug report
    pub fn request_debug_report(&self, name: &str) {
        const DEBUG_REPORT_ALIAS: &[(&str, &str)] = &[
            ("stack", "stack_adjust_graph\x00"),
            ("mlil", "mlil_translator\x00"),
            ("hlil", "high_level_il\x00"),
        ];

        if let Some(alias_idx) = DEBUG_REPORT_ALIAS
            .iter()
            .position(|(alias, _value)| *alias == name)
        {
            let name = DEBUG_REPORT_ALIAS[alias_idx].1.as_ptr() as *const c_char;
            unsafe { BNRequestFunctionDebugReport(self.handle, name) }
        } else {
            let name = std::ffi::CString::new(name.to_string()).unwrap();
            unsafe { BNRequestFunctionDebugReport(self.handle, name.as_ptr()) }
        }

        self.view().update_analysis()
    }

    /// Whether function was automatically discovered s a result of some creation of a 'user' function.
    /// 'user' functions may or may not have been created by a user through the or API. For instance the entry point
    /// into a function is always created a 'user' function. 'user' functions should be considered the root of auto
    /// analysis.
    pub fn is_auto(&self) -> bool {
        unsafe { BNWasFunctionAutomaticallyDiscovered(self.handle) }
    }

    /// Returns a list of possible call sites contained in this function.
    /// This includes ordinary calls, tail calls, and indirect jumps. Not all of
    /// the returned call sites are necessarily true call sites; some may simply
    /// be unresolved indirect jumps, for example.
    pub fn call_sites(&self) -> Array<CodeReference> {
        let mut count = 0;
        let refs = unsafe { BNGetFunctionCallSites(self.handle, &mut count) };
        assert!(!refs.is_null());
        unsafe { Array::new(refs, count, ()) }
    }

    /// Returns a list of ReferenceSource objects corresponding to the addresses
    /// in functions which reference this function
    pub fn caller_sites(&self) -> Array<CodeReference> {
        self.view().code_refs_to_addr(self.start())
    }

    /// Calling convention used by the function
    pub fn calling_convention(&self) -> Option<Conf<Ref<CoreCallingConvention>>> {
        let result = unsafe { BNGetFunctionCallingConvention(self.handle) };
        (!result.convention.is_null()).then(|| {
            Conf::new(
                unsafe { CoreCallingConvention::ref_from_raw(result.convention, self.arch()) },
                result.confidence,
            )
        })
    }

    /// Set the User calling convention used by the function
    pub fn set_user_calling_convention<'a, I>(&self, value: Option<I>)
    where
        I: Into<Conf<&'a CoreCallingConvention>>,
    {
        let mut conv_conf = BNCallingConventionWithConfidence::default();
        if let Some(value) = value {
            let value = value.into();
            conv_conf.convention = value.contents.handle;
            conv_conf.confidence = value.confidence;
        }
        unsafe { BNSetUserFunctionCallingConvention(self.handle, &mut conv_conf) }
    }

    /// Set the calling convention used by the function
    pub fn set_auto_calling_convention<'a, I>(&self, value: Option<I>)
    where
        I: Into<Conf<&'a CoreCallingConvention>>,
    {
        let mut conv_conf = BNCallingConventionWithConfidence::default();
        if let Some(value) = value {
            let value = value.into();
            conv_conf.convention = value.contents.handle;
            conv_conf.confidence = value.confidence;
        }
        unsafe { BNSetAutoFunctionCallingConvention(self.handle, &mut conv_conf) }
    }

    pub fn can_return(&self) -> Conf<bool> {
        unsafe { BNCanFunctionReturn(self.handle) }.into()
    }

    pub fn set_user_can_return<I>(&self, value: I)
    where
        I: Into<Conf<bool>>,
    {
        let value: Conf<bool> = value.into();
        let mut value_raw: BNBoolWithConfidence = value.into();
        unsafe { BNSetUserFunctionCanReturn(self.handle, &mut value_raw) }
    }

    pub fn set_auto_can_return<I>(&self, value: I)
    where
        I: Into<Conf<bool>>,
    {
        let value: Conf<bool> = value.into();
        let mut value_raw: BNBoolWithConfidence = value.into();
        unsafe { BNSetAutoFunctionCanReturn(self.handle, &mut value_raw) }
    }

    /// Whether function has explicitly defined types
    pub fn has_explicitly_defined_type(&self) -> bool {
        unsafe { BNFunctionHasExplicitlyDefinedType(self.handle) }
    }

    pub fn has_user_annotations(&self) -> bool {
        unsafe { BNFunctionHasUserAnnotations(self.handle) }
    }

    pub fn has_variable_arguments(&self) -> Conf<bool> {
        unsafe { BNFunctionHasVariableArguments(self.handle) }.into()
    }

    pub fn set_user_has_variable_arguments<I>(&self, value: I)
    where
        I: Into<Conf<bool>>,
    {
        let bc: Conf<bool> = value.into();
        let mut bc = bc.into();
        unsafe { BNSetUserFunctionHasVariableArguments(self.handle, &mut bc) }
    }

    pub fn set_auto_has_variable_arguments<I>(&self, value: I)
    where
        I: Into<Conf<bool>>,
    {
        let bc: Conf<bool> = value.into();
        let mut bc = bc.into();
        unsafe { BNSetAutoFunctionHasVariableArguments(self.handle, &mut bc) }
    }

    /// Has unresolved indirect branches
    pub fn has_unresolved_indirect_branches(&self) -> bool {
        unsafe { BNHasUnresolvedIndirectBranches(self.handle) }
    }

    /// List of address of unresolved indirect branches
    pub fn unresolved_indirect_branches(&self) -> Array<UnresolvedIndirectBranches> {
        let mut count = 0;
        let result = unsafe { BNGetUnresolvedIndirectBranches(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Returns a string representing the provenance. This portion of the API
    /// is under development. Currently the provenance information is
    /// undocumented, not persistent, and not saved to a database.
    pub fn provenance(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetProvenanceString(self.handle)) }
    }

    /// Get registers that are used for the return value
    pub fn return_registers(&self) -> Conf<Array<CoreRegister>> {
        let result = unsafe { BNGetFunctionReturnRegisters(self.handle) };
        let regs = unsafe { Array::new(result.regs, result.count, self.arch().handle()) };
        Conf::new(regs, result.confidence)
    }

    pub fn set_user_return_registers<I>(&self, values: I, confidence: u8)
    where
        I: IntoIterator<Item = CoreRegister>,
    {
        let mut regs: Box<[u32]> = values.into_iter().map(|reg| reg.id().0).collect();
        let mut regs = BNRegisterSetWithConfidence {
            regs: regs.as_mut_ptr(),
            count: regs.len(),
            confidence,
        };
        unsafe { BNSetUserFunctionReturnRegisters(self.handle, &mut regs) }
    }

    pub fn set_auto_return_registers<I>(&self, values: I, confidence: u8)
    where
        I: IntoIterator<Item = CoreRegister>,
    {
        let mut regs: Box<[u32]> = values.into_iter().map(|reg| reg.id().0).collect();
        let mut regs = BNRegisterSetWithConfidence {
            regs: regs.as_mut_ptr(),
            count: regs.len(),
            confidence,
        };
        unsafe { BNSetAutoFunctionReturnRegisters(self.handle, &mut regs) }
    }

    /// Flow graph of unresolved stack adjustments
    pub fn unresolved_stack_adjustment_graph(&self) -> Option<Ref<FlowGraph>> {
        let graph = unsafe { BNGetUnresolvedStackAdjustmentGraph(self.handle) };
        (!graph.is_null()).then(|| unsafe { FlowGraph::ref_from_raw(graph) })
    }

    pub fn create_graph(
        &self,
        view_type: FunctionViewType,
        settings: Option<&DisassemblySettings>,
    ) -> Ref<FlowGraph> {
        let settings_raw = settings.map(|s| s.handle).unwrap_or(std::ptr::null_mut());
        let raw_view_type = FunctionViewType::into_raw(view_type);
        let result = unsafe { BNCreateFunctionGraph(self.handle, raw_view_type, settings_raw) };
        FunctionViewType::free_raw(raw_view_type);
        unsafe { FlowGraph::ref_from_raw(result) }
    }

    pub fn parent_components(&self) -> Array<Component> {
        let mut count = 0;
        let result =
            unsafe { BNGetFunctionParentComponents(self.view().handle, self.handle, &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }
}

impl Debug for Function {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // TODO: I am sure there is more we should add to this.
        f.debug_struct("Function")
            .field("start", &self.start())
            .field("arch", &self.arch().name())
            .field("platform", &self.platform())
            .field("symbol", &self.symbol())
            .field("is_auto", &self.is_auto())
            .field("tags", &self.tags().to_vec())
            .field("comments", &self.comments().to_vec())
            .finish()
    }
}

unsafe impl Send for Function {}
unsafe impl Sync for Function {}

impl ToOwned for Function {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Function {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewFunctionReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeFunction(handle.handle);
    }
}

impl CoreArrayProvider for Function {
    type Raw = *mut BNFunction;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Function>;
}

unsafe impl CoreArrayProviderInner for Function {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeFunctionList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(*raw), context)
    }
}

impl Hash for Function {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let start_address = self.start();
        let architecture = self.arch();
        let platform = self.platform();
        (start_address, architecture, platform).hash(state)
    }
}

impl PartialEq for Function {
    fn eq(&self, other: &Self) -> bool {
        if self.handle == other.handle {
            return true;
        }
        self.start() == other.start()
            && self.arch() == other.arch()
            && self.platform() == other.platform()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl From<BNAddressRange> for AddressRange {
    fn from(raw: BNAddressRange) -> Self {
        Self {
            start: raw.start,
            end: raw.end,
        }
    }
}

impl From<AddressRange> for BNAddressRange {
    fn from(raw: AddressRange) -> Self {
        Self {
            start: raw.start,
            end: raw.end,
        }
    }
}

impl CoreArrayProvider for AddressRange {
    type Raw = BNAddressRange;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for AddressRange {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeAddressRanges(raw);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from(*raw)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PerformanceInfo {
    pub name: String,
    pub seconds: Duration,
}

impl From<BNPerformanceInfo> for PerformanceInfo {
    fn from(value: BNPerformanceInfo) -> Self {
        Self {
            name: unsafe { BnString::from_raw(value.name) }.to_string(),
            seconds: Duration::from_secs_f64(value.seconds),
        }
    }
}

impl From<&BNPerformanceInfo> for PerformanceInfo {
    fn from(value: &BNPerformanceInfo) -> Self {
        Self {
            // TODO: Name will be freed by this. FIX!
            name: unsafe { BnString::from_raw(value.name) }.to_string(),
            seconds: Duration::from_secs_f64(value.seconds),
        }
    }
}

impl CoreArrayProvider for PerformanceInfo {
    type Raw = BNPerformanceInfo;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for PerformanceInfo {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeAnalysisPerformanceInfo(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // TODO: Swap this to the ref version.
        Self::from(*raw)
    }
}

// NOTE: only exists as part of an Array, never owned
pub struct UnresolvedIndirectBranches(u64);

impl UnresolvedIndirectBranches {
    pub fn address(&self) -> u64 {
        self.0
    }
}

impl CoreArrayProvider for UnresolvedIndirectBranches {
    type Raw = u64;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for UnresolvedIndirectBranches {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeAddressList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self(*raw)
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct ConstantReference {
    pub value: i64,
    pub size: usize,
    pub pointer: bool,
    pub intermediate: bool,
}

impl From<BNConstantReference> for ConstantReference {
    fn from(value: BNConstantReference) -> Self {
        Self {
            value: value.value,
            size: value.size,
            pointer: value.pointer,
            intermediate: value.intermediate,
        }
    }
}

impl From<ConstantReference> for BNConstantReference {
    fn from(value: ConstantReference) -> Self {
        Self {
            value: value.value,
            size: value.size,
            pointer: value.pointer,
            intermediate: value.intermediate,
        }
    }
}

impl CoreArrayProvider for ConstantReference {
    type Raw = BNConstantReference;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for ConstantReference {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeConstantReferenceList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from(*raw)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RegisterStackAdjustment {
    pub register_id: u32,
    pub adjustment: Conf<i32>,
}

impl RegisterStackAdjustment {
    pub fn new(register_id: u32, adjustment: impl Into<Conf<i32>>) -> Self {
        Self {
            register_id,
            adjustment: adjustment.into(),
        }
    }
}

impl From<BNRegisterStackAdjustment> for RegisterStackAdjustment {
    fn from(value: BNRegisterStackAdjustment) -> Self {
        Self {
            register_id: value.regStack,
            adjustment: Conf::new(value.adjustment, value.confidence),
        }
    }
}

impl From<RegisterStackAdjustment> for BNRegisterStackAdjustment {
    fn from(value: RegisterStackAdjustment) -> Self {
        Self {
            regStack: value.register_id,
            adjustment: value.adjustment.contents,
            confidence: value.adjustment.confidence,
        }
    }
}

impl CoreArrayProvider for RegisterStackAdjustment {
    type Raw = BNRegisterStackAdjustment;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for RegisterStackAdjustment {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeRegisterStackAdjustments(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from(*raw)
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum HighlightColor {
    StandardHighlightColor {
        color: HighlightStandardColor,
        alpha: u8,
    },
    MixedHighlightColor {
        color: HighlightStandardColor,
        mix_color: HighlightStandardColor,
        mix: u8,
        alpha: u8,
    },
    CustomHighlightColor {
        r: u8,
        g: u8,
        b: u8,
        alpha: u8,
    },
}

impl From<BNHighlightColor> for HighlightColor {
    fn from(value: BNHighlightColor) -> Self {
        match value.style {
            BNHighlightColorStyle::StandardHighlightColor => Self::StandardHighlightColor {
                color: value.color,
                alpha: value.alpha,
            },
            BNHighlightColorStyle::MixedHighlightColor => Self::MixedHighlightColor {
                color: value.color,
                mix_color: value.mixColor,
                mix: value.mix,
                alpha: value.alpha,
            },
            BNHighlightColorStyle::CustomHighlightColor => Self::CustomHighlightColor {
                r: value.r,
                g: value.g,
                b: value.b,
                alpha: value.alpha,
            },
        }
    }
}

impl From<HighlightColor> for BNHighlightColor {
    fn from(value: HighlightColor) -> Self {
        match value {
            HighlightColor::StandardHighlightColor { color, alpha } => BNHighlightColor {
                style: BNHighlightColorStyle::StandardHighlightColor,
                color,
                alpha,
                ..Default::default()
            },
            HighlightColor::MixedHighlightColor {
                color,
                mix_color,
                mix,
                alpha,
            } => BNHighlightColor {
                style: BNHighlightColorStyle::MixedHighlightColor,
                color,
                mixColor: mix_color,
                mix,
                alpha,
                ..Default::default()
            },
            HighlightColor::CustomHighlightColor { r, g, b, alpha } => BNHighlightColor {
                style: BNHighlightColorStyle::CustomHighlightColor,
                r,
                g,
                b,
                alpha,
                ..Default::default()
            },
        }
    }
}

impl Default for HighlightColor {
    fn default() -> Self {
        Self::StandardHighlightColor {
            color: HighlightStandardColor::NoHighlightColor,
            alpha: 0,
        }
    }
}

// NOTE only exists as Array<Comments>, cant be owned
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Comment {
    pub addr: u64,
    pub comment: BnString,
}

impl CoreArrayProvider for Comment {
    type Raw = u64;
    type Context = Ref<Function>;
    type Wrapped<'a> = Comment;
}

unsafe impl CoreArrayProviderInner for Comment {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeAddressList(raw);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, function: &'a Self::Context) -> Self::Wrapped<'a> {
        Comment {
            addr: *raw,
            comment: function.comment_at(*raw),
        }
    }
}
