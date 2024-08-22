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
    basicblock::{BasicBlock, BlockContext},
    binaryview::{BinaryView, BinaryViewExt},
    callingconvention::CallingConvention,
    component::Component,
    disassembly::{DisassemblySettings, DisassemblyTextLine},
    flowgraph::FlowGraph,
    hlil, llil,
    mlil::{self, FunctionGraphType},
    platform::Platform,
    references::CodeReference,
    string::*,
    symbol::Symbol,
    tags::{Tag, TagReference, TagType},
    types::{
        Conf, ConstantReference, HighlightColor, IndirectBranchInfo, IntegerDisplayType,
        MergedVariable, NamedTypedVariable, QualifiedName, RegisterStackAdjustment, RegisterValue,
        RegisterValueType, StackVariableReference, Type, UnresolvedIndirectBranches, Variable,
    },
};
use crate::{databuffer::DataBuffer, disassembly::InstructionTextToken, rc::*};
pub use binaryninjacore_sys::BNAnalysisSkipReason as AnalysisSkipReason;
pub use binaryninjacore_sys::BNFunctionAnalysisSkipOverride as FunctionAnalysisSkipOverride;
pub use binaryninjacore_sys::BNFunctionUpdateType as FunctionUpdateType;
pub use binaryninjacore_sys::BNBuiltinType as BuiltinType;

use std::{fmt, mem};
use std::{ffi::c_char, hash::Hash, ops::Range};

pub struct Location {
    pub arch: Option<CoreArchitecture>,
    pub addr: u64,
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

#[derive(Clone)]
pub struct NativeBlock {
    _priv: (),
}

impl NativeBlock {
    pub(crate) fn new() -> Self {
        NativeBlock { _priv: () }
    }
}

impl BlockContext for NativeBlock {
    type Iter = NativeBlockIter;
    type Instruction = u64;

    fn start(&self, block: &BasicBlock<Self>) -> u64 {
        block.raw_start()
    }

    fn iter(&self, block: &BasicBlock<Self>) -> NativeBlockIter {
        NativeBlockIter {
            arch: block.arch(),
            bv: block.function().view(),
            cur: block.raw_start(),
            end: block.raw_end(),
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

pub(crate) struct RawFunctionViewType(pub BNFunctionViewType);

impl FunctionViewType {
    pub(crate) fn as_raw(&self) -> RawFunctionViewType {
        let view_type = match self {
            FunctionViewType::Normal => BNFunctionGraphType::NormalFunctionGraph,
            FunctionViewType::LowLevelIL => BNFunctionGraphType::LowLevelILFunctionGraph,
            FunctionViewType::LiftedIL => BNFunctionGraphType::LiftedILFunctionGraph,
            FunctionViewType::LowLevelILSSAForm => BNFunctionGraphType::LowLevelILSSAFormFunctionGraph,
            FunctionViewType::MediumLevelIL => BNFunctionGraphType::MediumLevelILFunctionGraph,
            FunctionViewType::MediumLevelILSSAForm => BNFunctionGraphType::MediumLevelILSSAFormFunctionGraph,
            FunctionViewType::MappedMediumLevelIL => BNFunctionGraphType::MappedMediumLevelILFunctionGraph,
            FunctionViewType::MappedMediumLevelILSSAForm => BNFunctionGraphType::MappedMediumLevelILSSAFormFunctionGraph,
            FunctionViewType::HighLevelIL => BNFunctionGraphType::HighLevelILFunctionGraph,
            FunctionViewType::HighLevelILSSAForm => BNFunctionGraphType::HighLevelILSSAFormFunctionGraph,
            FunctionViewType::HighLevelLanguageRepresentation(_) => BNFunctionGraphType::HighLevelLanguageRepresentationFunctionGraph,
        };
        RawFunctionViewType(BNFunctionViewType {
            type_: view_type,
            name: if let FunctionViewType::HighLevelLanguageRepresentation(ref name) = self {
                std::ffi::CString::new(name.to_string()).unwrap().into_raw()
            } else {
                std::ptr::null()
            },
        })
    }
}

impl Into<FunctionViewType> for FunctionGraphType {
    fn into(self) -> FunctionViewType {
        match self {
            BNFunctionGraphType::LowLevelILFunctionGraph => FunctionViewType::LowLevelIL,
            BNFunctionGraphType::LiftedILFunctionGraph => FunctionViewType::LiftedIL,
            BNFunctionGraphType::LowLevelILSSAFormFunctionGraph => FunctionViewType::LowLevelILSSAForm,
            BNFunctionGraphType::MediumLevelILFunctionGraph => FunctionViewType::MediumLevelIL,
            BNFunctionGraphType::MediumLevelILSSAFormFunctionGraph => FunctionViewType::MediumLevelILSSAForm,
            BNFunctionGraphType::MappedMediumLevelILFunctionGraph => FunctionViewType::MappedMediumLevelIL,
            BNFunctionGraphType::MappedMediumLevelILSSAFormFunctionGraph => FunctionViewType::MappedMediumLevelILSSAForm,
            BNFunctionGraphType::HighLevelILFunctionGraph => FunctionViewType::HighLevelIL,
            BNFunctionGraphType::HighLevelILSSAFormFunctionGraph => FunctionViewType::HighLevelILSSAForm,
            BNFunctionGraphType::HighLevelLanguageRepresentationFunctionGraph => {
                FunctionViewType::HighLevelLanguageRepresentation("Pseudo C".into()
                )
            }
            _ => FunctionViewType::Normal,
        }
    }
}

impl Drop for RawFunctionViewType {
    fn drop(&mut self) {
        if !self.0.name.is_null() {
            unsafe { let _ = std::ffi::CString::from_raw(self.0.name as *mut _); }
        }
    }
}

#[derive(Eq)]
pub struct Function {
    pub(crate) handle: *mut BNFunction,
}

unsafe impl Send for Function {}
unsafe impl Sync for Function {}

impl Function {
    pub(crate) unsafe fn from_raw(handle: *mut BNFunction) -> Ref<Self> {
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
            BinaryView::from_raw(view)
        }
    }

    pub fn symbol(&self) -> Ref<Symbol> {
        unsafe {
            let sym = BNGetFunctionSymbol(self.handle);
            Symbol::ref_from_raw(sym)
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
    pub fn comments(&self) -> Array<Comments> {
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
            let block = BNGetFunctionBasicBlockAtAddress(self.handle, arch.0, addr);
            let context = NativeBlock { _priv: () };

            if block.is_null() {
                return None;
            }

            Some(Ref::new(BasicBlock::from_raw(block, context)))
        }
    }

    pub fn block_annotations(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<Array<InstructionTextToken>> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let lines = unsafe { BNGetFunctionBlockAnnotations(self.handle, arch.0, addr, &mut count) };
        assert!(!lines.is_null());
        unsafe { Array::new(lines, count, ()) }
    }

    pub fn get_variable_name(&self, var: &Variable) -> BnString {
        unsafe {
            let raw_var = var.raw();
            let raw_name = BNGetVariableName(self.handle, &raw_var);
            BnString::from_raw(raw_name)
        }
    }

    pub fn high_level_il(&self, full_ast: bool) -> Result<Ref<hlil::HighLevelILFunction>, ()> {
        unsafe {
            let hlil = BNGetFunctionHighLevelIL(self.handle);

            if hlil.is_null() {
                return Err(());
            }

            Ok(hlil::HighLevelILFunction::ref_from_raw(hlil, full_ast))
        }
    }

    pub fn high_level_il_if_available(&self) -> Option<Ref<hlil::HighLevelILFunction>> {
        let hlil = unsafe { BNGetFunctionHighLevelILIfAvailable(self.handle) };
        (!hlil.is_null()).then(|| unsafe { hlil::HighLevelILFunction::ref_from_raw(hlil, true) })
    }

    /// MediumLevelILFunction used to represent Function mapped medium level IL
    pub fn mapped_medium_level_il(&self) -> Result<Ref<mlil::MediumLevelILFunction>, ()> {
        let mlil = unsafe { BNGetFunctionMappedMediumLevelIL(self.handle) };
        if mlil.is_null() {
            return Err(());
        }
        Ok(unsafe { mlil::MediumLevelILFunction::ref_from_raw(mlil) })
    }

    pub fn mapped_medium_level_il_if_available(
        &self,
    ) -> Result<Ref<mlil::MediumLevelILFunction>, ()> {
        let mlil = unsafe { BNGetFunctionMappedMediumLevelILIfAvailable(self.handle) };
        if mlil.is_null() {
            return Err(());
        }
        Ok(unsafe { mlil::MediumLevelILFunction::ref_from_raw(mlil) })
    }

    pub fn medium_level_il(&self) -> Result<Ref<mlil::MediumLevelILFunction>, ()> {
        unsafe {
            let mlil = BNGetFunctionMediumLevelIL(self.handle);

            if mlil.is_null() {
                return Err(());
            }

            Ok(mlil::MediumLevelILFunction::ref_from_raw(mlil))
        }
    }

    pub fn medium_level_il_if_available(&self) -> Option<Ref<mlil::MediumLevelILFunction>> {
        let mlil = unsafe { BNGetFunctionMediumLevelILIfAvailable(self.handle) };
        (!mlil.is_null()).then(|| unsafe { mlil::MediumLevelILFunction::ref_from_raw(mlil) })
    }

    pub fn low_level_il(&self) -> Result<Ref<llil::RegularFunction<CoreArchitecture>>, ()> {
        unsafe {
            let llil = BNGetFunctionLowLevelIL(self.handle);

            if llil.is_null() {
                return Err(());
            }

            Ok(llil::RegularFunction::from_raw(self.arch(), llil))
        }
    }

    pub fn low_level_il_if_available(
        &self,
    ) -> Option<Ref<llil::RegularFunction<CoreArchitecture>>> {
        let llil = unsafe { BNGetFunctionLowLevelILIfAvailable(self.handle) };
        (!llil.is_null()).then(|| unsafe { llil::RegularFunction::from_raw(self.arch(), llil) })
    }

    pub fn lifted_il(&self) -> Result<Ref<llil::LiftedFunction<CoreArchitecture>>, ()> {
        unsafe {
            let llil = BNGetFunctionLiftedIL(self.handle);

            if llil.is_null() {
                return Err(());
            }

            Ok(llil::LiftedFunction::from_raw(self.arch(), llil))
        }
    }

    pub fn lifted_il_if_available(&self) -> Option<Ref<llil::LiftedFunction<CoreArchitecture>>> {
        let llil = unsafe { BNGetFunctionLiftedILIfAvailable(self.handle) };
        (!llil.is_null()).then(|| unsafe { llil::LiftedFunction::from_raw(self.arch(), llil) })
    }

    pub fn return_type(&self) -> Conf<Ref<Type>> {
        let result = unsafe { BNGetFunctionReturnType(self.handle) };

        Conf::new(
            unsafe { Type::ref_from_raw(result.type_) },
            result.confidence,
        )
    }

    pub fn set_auto_return_type<'a, C>(&self, return_type: C)
    where
        C: Into<Conf<&'a Type>>,
    {
        let return_type: Conf<&Type> = return_type.into();
        unsafe {
            BNSetAutoFunctionReturnType(
                self.handle,
                &mut BNTypeWithConfidence {
                    type_: return_type.contents.handle,
                    confidence: return_type.confidence,
                },
            )
        }
    }

    pub fn set_user_return_type<'a, C>(&self, return_type: C)
    where
        C: Into<Conf<&'a Type>>,
    {
        let return_type: Conf<&Type> = return_type.into();
        unsafe {
            BNSetUserFunctionReturnType(
                self.handle,
                &mut BNTypeWithConfidence {
                    type_: return_type.contents.handle,
                    confidence: return_type.confidence,
                },
            )
        }
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

    pub fn stack_layout(&self) -> Array<NamedTypedVariable> {
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
        let result = unsafe { BNGetCallStackAdjustment(self.handle, arch.0, addr) };
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
                arch.0,
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
                arch.0,
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
        let result = unsafe { BNGetCallTypeAdjustment(self.handle, arch.0, addr) };
        (!result.type_.is_null())
            .then(|| unsafe { Conf::new(Type::ref_from_raw(result.type_), result.confidence) })
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
            .unwrap_or(core::ptr::null_mut());
        unsafe { BNSetUserCallTypeAdjustment(self.handle, arch.0, addr, adjust_ptr) }
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
                arch.0,
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
    ) -> Array<RegisterStackAdjustment<CoreArchitecture>> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let adjust =
            unsafe { BNGetCallRegisterStackAdjustment(self.handle, arch.0, addr, &mut count) };
        assert!(!adjust.is_null());
        unsafe { Array::new(adjust, count, arch.handle()) }
    }

    pub fn set_user_call_reg_stack_adjustment<I>(
        self,
        addr: u64,
        adjust: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: IntoIterator<Item = RegisterStackAdjustment<CoreArchitecture>>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut adjust_buf: Box<[BNRegisterStackAdjustment]> =
            adjust.into_iter().map(|adjust| adjust.into_raw()).collect();
        unsafe {
            BNSetUserCallRegisterStackAdjustment(
                self.handle,
                arch.0,
                addr,
                adjust_buf.as_mut_ptr(),
                adjust_buf.len(),
            )
        }
    }

    pub fn set_auto_call_reg_stack_adjustment<I>(
        &self,
        addr: u64,
        adjust: I,
        arch: Option<CoreArchitecture>,
    ) where
        I: IntoIterator<Item = RegisterStackAdjustment<CoreArchitecture>>,
    {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut adjust_buf: Box<[BNRegisterStackAdjustment]> =
            adjust.into_iter().map(|reg| reg.into_raw()).collect();

        unsafe {
            BNSetAutoCallRegisterStackAdjustment(
                self.handle,
                arch.0,
                addr,
                adjust_buf.as_mut_ptr(),
                adjust_buf.len(),
            )
        }
    }

    pub fn call_reg_stack_adjustment_for_reg_stack(
        &self,
        addr: u64,
        reg_stack_id: u32,
        arch: Option<CoreArchitecture>,
    ) -> RegisterStackAdjustment<CoreArchitecture> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let adjust = unsafe {
            BNGetCallRegisterStackAdjustmentForRegisterStack(
                self.handle,
                arch.0,
                addr,
                reg_stack_id,
            )
        };
        unsafe { RegisterStackAdjustment::from_raw(adjust, arch) }
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
                arch.0,
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
                arch.0,
                addr,
                reg_stack_id,
                adjust.contents,
                adjust.confidence,
            )
        }
    }

    pub fn reg_stack_adjustments(&self) -> Array<RegisterStackAdjustment<CoreArchitecture>> {
        let mut count = 0;
        let adjust = unsafe { BNGetFunctionRegisterStackAdjustments(self.handle, &mut count) };
        assert!(!adjust.is_null());
        unsafe { Array::new(adjust, count, self.arch().handle()) }
    }

    pub fn set_user_reg_stack_adjustments<I, A>(&self, values: I)
    where
        I: IntoIterator<Item = RegisterStackAdjustment<A>>,
        A: Architecture,
    {
        let mut values: Box<[BNRegisterStackAdjustment]> =
            values.into_iter().map(|r| r.into_raw()).collect();
        unsafe {
            BNSetUserFunctionRegisterStackAdjustments(
                self.handle,
                values.as_mut_ptr(),
                values.len(),
            )
        }
    }

    pub fn set_auto_reg_stack_adjustments<I, A>(&self, values: I)
    where
        I: IntoIterator<Item = RegisterStackAdjustment<A>>,
        A: Architecture,
    {
        let mut values: Box<[BNRegisterStackAdjustment]> =
            values.into_iter().map(|r| r.into_raw()).collect();
        unsafe {
            BNSetAutoFunctionRegisterStackAdjustments(
                self.handle,
                values.as_mut_ptr(),
                values.len(),
            )
        }
    }

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
            let mut variables = BNGetFunctionParameterVariables(self.handle);
            let mut result = Vec::with_capacity(variables.count);
            let confidence = variables.confidence;
            let vars = std::slice::from_raw_parts(variables.vars, variables.count);

            for var in vars.iter().take(variables.count) {
                result.push(Variable::from_raw(*var));
            }

            BNFreeParameterVariables(&mut variables);
            Conf::new(result, confidence)
        }
    }

    pub fn set_user_parameter_variables<I>(&self, values: I, confidence: u8)
    where
        I: IntoIterator<Item = Variable>,
    {
        let mut vars: Box<[BNVariable]> = values.into_iter().map(|var| var.raw()).collect();
        unsafe {
            BNSetUserFunctionParameterVariables(
                self.handle,
                &mut BNParameterVariablesWithConfidence {
                    vars: vars.as_mut_ptr(),
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
        let mut vars: Box<[BNVariable]> = values.into_iter().map(|var| var.raw()).collect();
        unsafe {
            BNSetAutoFunctionParameterVariables(
                self.handle,
                &mut BNParameterVariablesWithConfidence {
                    vars: vars.as_mut_ptr(),
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
        let func_type = func_type.map(|f| f.handle).unwrap_or(core::ptr::null_mut());
        let value =
            unsafe { BNGetParameterValueAtInstruction(self.handle, arch.0, addr, func_type, i) };
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
                if let Some(t) = t {
                    t.handle
                } else {
                    core::ptr::null_mut()
                },
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
        unsafe {
            BNSetAutoFunctionInlinedDuringAnalysis(
                self.handle,
                BNBoolWithConfidence {
                    value: value.contents,
                    confidence: value.confidence,
                },
            )
        }
    }

    pub fn set_user_inline_during_analysis<C>(&self, value: C)
    where
        C: Into<Conf<bool>>,
    {
        let value: Conf<bool> = value.into();
        unsafe {
            BNSetUserFunctionInlinedDuringAnalysis(
                self.handle,
                BNBoolWithConfidence {
                    value: value.contents,
                    confidence: value.confidence,
                },
            )
        }
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
    /// # use binaryninja::binaryview::{BinaryView, BinaryViewExt};
    /// # use binaryninja::function::Function;
    /// # let fun: Function = todo!();
    /// # let bv: BinaryView = todo!();
    /// let important = bv.create_tag_type("Important", "⚠️");
    /// fun.add_tag(&important, "I think this is the main function", None, false, None);
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
        let binaryview = unsafe { BinaryView::from_raw(BNGetFunctionData(self.handle)) };
        unsafe { BNAddTag(binaryview.handle, tag.handle, user) };

        unsafe {
            match (user, addr) {
                (false, None) => BNAddAutoFunctionTag(self.handle, tag.handle),
                (false, Some(addr)) => BNAddAutoAddressTag(self.handle, arch.0, addr, tag.handle),
                (true, None) => BNAddUserFunctionTag(self.handle, tag.handle),
                (true, Some(addr)) => BNAddUserAddressTag(self.handle, arch.0, addr, tag.handle),
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
                    BNRemoveAutoAddressTag(self.handle, arch.0, addr, tag.handle)
                }
                (true, None) => BNRemoveUserFunctionTag(self.handle, tag.handle),
                (true, Some(addr)) => BNRemoveUserAddressTag(self.handle, arch.0, addr, tag.handle),
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
                    BNRemoveAutoAddressTagsOfType(self.handle, arch.0, addr, tag_type.handle)
                }
                (true, None) => BNRemoveUserFunctionTagsOfType(self.handle, tag_type.handle),
                (true, Some(addr)) => {
                    BNRemoveUserAddressTagsOfType(self.handle, arch.0, addr, tag_type.handle)
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
        unsafe { BNAddUserCodeReference(self.handle, arch.0, from_addr, to_addr) }
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
        unsafe { BNRemoveUserCodeReference(self.handle, arch.0, from_addr, to_addr) }
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
    /// fun.add_user_type_ref(0x1337, &"A".into(), None);
    /// ```
    pub fn add_user_type_ref(
        &self,
        from_addr: u64,
        name: &QualifiedName,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        let name_ptr = &name.0 as *const BNQualifiedName as *mut _;
        unsafe { BNAddUserTypeReference(self.handle, arch.0, from_addr, name_ptr) }
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
    /// fun.remove_user_type_ref(0x1337, &"A".into(), None);
    /// ```
    pub fn remove_user_type_ref(
        &self,
        from_addr: u64,
        name: &QualifiedName,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        let name_ptr = &name.0 as *const BNQualifiedName as *mut _;
        unsafe { BNRemoveUserTypeReference(self.handle, arch.0, from_addr, name_ptr) }
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
    /// fun.add_user_type_field_ref(0x1337, &"A".into(), 0x8, None, None);
    /// ```
    pub fn add_user_type_field_ref(
        &self,
        from_addr: u64,
        name: &QualifiedName,
        offset: u64,
        arch: Option<CoreArchitecture>,
        size: Option<usize>,
    ) {
        let size = size.unwrap_or(0);
        let arch = arch.unwrap_or_else(|| self.arch());
        let name_ptr = &name.0 as *const _ as *mut _;
        unsafe {
            BNAddUserTypeFieldReference(self.handle, arch.0, from_addr, name_ptr, offset, size)
        }
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
    /// fun.remove_user_type_field_ref(0x1337, &"A".into(), 0x8, None, None);
    /// ```
    pub fn remove_user_type_field_ref(
        &self,
        from_addr: u64,
        name: &QualifiedName,
        offset: u64,
        arch: Option<CoreArchitecture>,
        size: Option<usize>,
    ) {
        let size = size.unwrap_or(0);
        let arch = arch.unwrap_or_else(|| self.arch());
        let name_ptr = &name.0 as *const _ as *mut _;
        unsafe {
            BNRemoveUserTypeFieldReference(self.handle, arch.0, from_addr, name_ptr, offset, size)
        }
    }

    pub fn constant_data(
        &self,
        state: RegisterValueType,
        value: u64,
        size: Option<usize>,
    ) -> (DataBuffer, BuiltinType) {
        let size = size.unwrap_or(0);
        let state_raw = state.into_raw_value();
        let mut builtin_type = BuiltinType::BuiltinNone;
        let buffer = DataBuffer::from_raw(unsafe { BNGetConstantData(self.handle, state_raw, value, size, &mut builtin_type) });
        (buffer, builtin_type)
    }

    pub fn constants_referenced_by(
        &self,
        addr: u64,
        arch: Option<CoreArchitecture>,
    ) -> Array<ConstantReference> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let refs =
            unsafe { BNGetConstantsReferencedByInstruction(self.handle, arch.0, addr, &mut count) };
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
            BNGetConstantsReferencedByInstructionIfAvailable(self.handle, arch.0, addr, &mut count)
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

        let tag_type = tag_type.map(|tag_type| self.view().get_tag_type(tag_type));

        let tags = unsafe {
            match (tag_type, auto) {
                // received a tag_type, BinaryView found none
                (Some(None), _) => return Array::new(core::ptr::null_mut(), 0, ()),

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
            None => unsafe { BNGetAddressTags(self.handle, arch.0, addr, &mut count) },
            Some(true) => unsafe { BNGetAutoAddressTags(self.handle, arch.0, addr, &mut count) },
            Some(false) => unsafe { BNGetUserAddressTags(self.handle, arch.0, addr, &mut count) },
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
                BNGetAddressTagsInRange(self.handle, arch.0, range.start, range.end, &mut count)
            },
            Some(true) => unsafe {
                BNGetAutoAddressTagsInRange(self.handle, arch.0, range.start, range.end, &mut count)
            },
            Some(false) => unsafe {
                BNGetUserAddressTagsInRange(self.handle, arch.0, range.start, range.end, &mut count)
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
                arch: arch.0,
            })
            .collect();
        unsafe {
            BNSetUserIndirectBranches(
                self.handle,
                arch.0,
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
                arch: arch.0,
            })
            .collect();
        unsafe {
            BNSetAutoIndirectBranches(
                self.handle,
                arch.0,
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
        let branches = unsafe { BNGetIndirectBranchesAt(self.handle, arch.0, addr, &mut count) };
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
        let color = unsafe { BNGetInstructionHighlight(self.handle, arch.0, addr) };
        HighlightColor::from_raw(color)
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
        let color_raw = color.into_raw();
        unsafe { BNSetAutoInstructionHighlight(self.handle, arch.0, addr, color_raw) }
    }

    /// Sets the highlights the instruction at the specified address with the supplied color
    ///
    /// * `addr` - virtual address of the instruction to be highlighted
    /// * `color` - Color value to use for highlighting
    /// * `arch` - (optional) Architecture of the instruction if different from self.arch
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::types::HighlightColor;
    /// # let fun: binaryninja::function::Function = todo!();
    /// let color = HighlightColor::NoHighlightColor { alpha: u8::MAX };
    /// fun.set_user_instr_highlight(0x1337, color, None);
    /// ```
    pub fn set_user_instr_highlight(
        &self,
        addr: u64,
        color: HighlightColor,
        arch: Option<CoreArchitecture>,
    ) {
        let arch = arch.unwrap_or_else(|| self.arch());
        let color_raw = color.into_raw();
        unsafe { BNSetUserInstructionHighlight(self.handle, arch.0, addr, color_raw) }
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
        unsafe { BNGetInstructionContainingAddress(self.handle, arch.0, addr, &mut start) }
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
        unsafe { BNGetIntegerConstantDisplayType(self.handle, arch.0, instr_addr, value, operand) }
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
            .unwrap_or(core::ptr::null());
        unsafe {
            BNSetIntegerConstantDisplayType(
                self.handle,
                arch.0,
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
                arch.0,
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
        reg: u32,
        arch: Option<CoreArchitecture>,
    ) -> RegisterValue {
        let arch = arch.unwrap_or_else(|| self.arch());
        let register = unsafe { BNGetRegisterValueAtInstruction(self.handle, arch.0, addr, reg) };
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
        reg: u32,
        arch: Option<CoreArchitecture>,
    ) -> RegisterValue {
        let arch = arch.unwrap_or_else(|| self.arch());
        let register =
            unsafe { BNGetRegisterValueAfterInstruction(self.handle, arch.0, addr, reg) };
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
            unsafe { BNGetRegistersReadByInstruction(self.handle, arch.0, addr, &mut count) };
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
        let regs =
            unsafe { BNGetRegistersWrittenByInstruction(self.handle, arch.0, addr, &mut count) };
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
        let mut regs: Box<[u32]> = registers.into_iter().map(|reg| reg.id()).collect();
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
        let mut regs: Box<[u32]> = registers.into_iter().map(|reg| reg.id()).collect();
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
        let value =
            unsafe { BNGetStackContentsAtInstruction(self.handle, arch.0, addr, offset, size) };
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
        let value =
            unsafe { BNGetStackContentsAfterInstruction(self.handle, arch.0, addr, offset, size) };
        value.into()
    }

    pub fn stack_var_at_frame_offset(
        &self,
        addr: u64,
        offset: i64,
        arch: Option<CoreArchitecture>,
    ) -> Option<(Variable, BnString, Conf<Ref<Type>>)> {
        let arch = arch.unwrap_or_else(|| self.arch());
        let mut found_value: BNVariableNameAndType = unsafe { mem::zeroed() };
        let found = unsafe {
            BNGetStackVariableAtFrameOffset(self.handle, arch.0, addr, offset, &mut found_value)
        };
        if !found {
            return None;
        }
        let var = unsafe { Variable::from_raw(found_value.var) };
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
            BNGetStackVariablesReferencedByInstruction(self.handle, arch.0, addr, &mut count)
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
                arch.0,
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
        let settings = settings.map(|s| s.handle).unwrap_or(core::ptr::null_mut());
        let mut count = 0;
        let lines = unsafe { BNGetFunctionTypeTokens(self.handle, settings, &mut count) };
        assert!(!lines.is_null());
        unsafe { Array::new(lines, count, ()) }
    }

    pub fn is_call_instruction(&self, addr: u64, arch: Option<CoreArchitecture>) -> bool {
        let arch = arch.unwrap_or_else(|| self.arch());
        unsafe { BNIsCallInstruction(self.handle, arch.0, addr) }
    }

    pub fn is_variable_user_defined(&self, var: &Variable) -> bool {
        unsafe { BNIsVariableUserDefined(self.handle, &var.raw()) }
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
    /// * `uppdate_type` - Desired update type
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

    /// Merge one or more varibles in `sources` into the `target` variable. All
    /// variable accesses to the variables in `sources` will be rewritten to use `target`.
    ///
    /// * `target` - target variable
    /// * `sources` - list of source variables
    pub fn merge_variables<'a>(
        &self,
        target: &Variable,
        sources: impl IntoIterator<Item = &'a Variable>,
    ) {
        let sources_raw: Box<[BNVariable]> = sources.into_iter().map(|s| s.raw()).collect();
        unsafe {
            BNMergeVariables(
                self.handle,
                &target.raw(),
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
        let sources_raw: Box<[BNVariable]> = sources.into_iter().map(|s| s.raw()).collect();
        unsafe {
            BNUnmergeVariables(
                self.handle,
                &target.raw(),
                sources_raw.as_ptr(),
                sources_raw.len(),
            )
        }
    }

    /// Splits a varible at the definition site. The given `var` must be the
    /// variable unique to the definition and should be obtained by using
    /// [mlil::MediumLevelILInstruction::get_split_var_for_definition] at the definition site.
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
        unsafe { BNSplitVariable(self.handle, &var.raw()) }
    }

    /// Undoes varible splitting performed with [Function::split_variable]. The given `var`
    /// must be the variable unique to the definition and should be obtained by using
    /// [mlil::MediumLevelILInstruction::get_split_var_for_definition] at the definition site.
    ///
    /// * `var` - variable to unsplit
    pub fn unsplit_variable(&self, var: &Variable) {
        unsafe { BNUnsplitVariable(self.handle, &var.raw()) }
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
    pub fn auto(&self) -> bool {
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
        self.view().get_code_refs(self.start())
    }

    /// Calling convention used by the function
    pub fn calling_convention(&self) -> Option<Conf<Ref<CallingConvention<CoreArchitecture>>>> {
        let result = unsafe { BNGetFunctionCallingConvention(self.handle) };
        (!result.convention.is_null()).then(|| {
            Conf::new(
                unsafe { CallingConvention::ref_from_raw(result.convention, self.arch()) },
                result.confidence,
            )
        })
    }

    /// Set the User calling convention used by the function
    pub fn set_user_calling_convention<'a, I>(&self, value: Option<I>)
    where
        I: Into<Conf<&'a CallingConvention<CoreArchitecture>>>,
    {
        let mut conv_conf: BNCallingConventionWithConfidence = unsafe { mem::zeroed() };
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
        I: Into<Conf<&'a CallingConvention<CoreArchitecture>>>,
    {
        let mut conv_conf: BNCallingConventionWithConfidence = unsafe { mem::zeroed() };
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
        let mut regs: Box<[u32]> = values.into_iter().map(|reg| reg.id()).collect();
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
        let mut regs: Box<[u32]> = values.into_iter().map(|reg| reg.id()).collect();
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
        (!graph.is_null()).then(|| unsafe { Ref::new(FlowGraph::from_raw(graph)) })
    }

    pub fn create_graph(
        &self,
        view_type: FunctionViewType,
        settings: Option<DisassemblySettings>,
    ) -> Ref<FlowGraph> {
        let settings_raw = settings.map(|s| s.handle).unwrap_or(core::ptr::null_mut());
        let result = unsafe { BNCreateFunctionGraph(self.handle, view_type.as_raw().0, settings_raw) };
        unsafe { Ref::new(FlowGraph::from_raw(result)) }
    }

    pub fn parent_components(&self) -> Array<Component> {
        let mut count = 0;
        let result = unsafe{ BNGetFunctionParentComponents(self.view().handle, self.handle, &mut count) };
        assert!(!result.is_null());
        unsafe{ Array::new(result, count, ()) }
    }
}

impl fmt::Debug for Function {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<func '{}' ({}) {:x}>",
            self.symbol().full_name(),
            self.platform().name(),
            self.start()
        )
    }
}

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
    unsafe fn free(raw: *mut *mut BNFunction, count: usize, _context: &()) {
        BNFreeFunctionList(raw, count);
    }
    unsafe fn wrap_raw<'a>(raw: &'a *mut BNFunction, context: &'a ()) -> Self::Wrapped<'a> {
        Guard::new(Function { handle: *raw }, context)
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

/////////////////
// AddressRange

#[repr(transparent)]
pub struct AddressRange(pub(crate) BNAddressRange);

impl AddressRange {
    pub fn start(&self) -> u64 {
        self.0.start
    }

    pub fn end(&self) -> u64 {
        self.0.end
    }
}

impl CoreArrayProvider for AddressRange {
    type Raw = BNAddressRange;
    type Context = ();
    type Wrapped<'a> = &'a AddressRange;
}
unsafe impl CoreArrayProviderInner for AddressRange {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeAddressRanges(raw);
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        mem::transmute(raw)
    }
}

/////////////////
// PerformanceInfo

// NOTE only exists as Array<PerformanceInfo>, cant be owned
#[repr(transparent)]
pub struct PerformanceInfo(BNPerformanceInfo);

impl PerformanceInfo {
    pub fn name(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.0.name) }
            .to_str()
            .unwrap()
    }
    pub fn seconds(&self) -> f64 {
        self.0.seconds
    }
}

impl CoreArrayProvider for PerformanceInfo {
    type Raw = BNPerformanceInfo;
    type Context = ();
    type Wrapped<'a> = Guard<'a, PerformanceInfo>;
}
unsafe impl CoreArrayProviderInner for PerformanceInfo {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeAnalysisPerformanceInfo(raw, count);
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self(*raw), context)
    }
}

/////////////////
// Comments

// NOTE only exists as Array<Comments>, cant be owned
pub struct Comments {
    addr: u64,
    comment: BnString,
}

impl Comments {
    pub fn address(&self) -> u64 {
        self.addr
    }
    pub fn comment(&self) -> &str {
        self.comment.as_str()
    }
}

impl CoreArrayProvider for Comments {
    type Raw = u64;
    type Context = Ref<Function>;
    type Wrapped<'a> = Comments;
}
unsafe impl CoreArrayProviderInner for Comments {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeAddressList(raw);
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, function: &'a Self::Context) -> Self::Wrapped<'a> {
        Comments {
            addr: *raw,
            comment: function.comment_at(*raw),
        }
    }
}
