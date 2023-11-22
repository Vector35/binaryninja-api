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

use crate::rc::*;
use crate::string::*;
use crate::types::Variable;
use crate::{
    architecture::CoreArchitecture,
    basicblock::{BasicBlock, BlockContext},
    binaryview::{BinaryView, BinaryViewExt},
    hlil, llil, mlil,
    platform::Platform,
    symbol::Symbol,
    types::{Conf, NamedTypedVariable, Type},
};

use std::hash::Hash;
use std::{fmt, mem};

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

    pub fn comment_at(&self, addr: u64) -> BnString {
        unsafe { BnString::from_raw(BNGetCommentForAddress(self.handle, addr)) }
    }

    pub fn set_comment_at<S: BnStrCompatible>(&self, addr: u64, comment: S) {
        let raw = comment.into_bytes_with_nul();

        unsafe {
            BNSetCommentForAddress(self.handle, addr, raw.as_ref().as_ptr() as *mut _);
        }
    }

    pub fn basic_blocks(&self) -> Array<BasicBlock<NativeBlock>> {
        unsafe {
            let mut count = 0;
            let blocks = BNGetFunctionBasicBlockList(self.handle, &mut count);
            let context = NativeBlock { _priv: () };

            Array::new(blocks, count, context)
        }
    }

    pub fn basic_block_containing(
        &self,
        arch: &CoreArchitecture,
        addr: u64,
    ) -> Option<Ref<BasicBlock<NativeBlock>>> {
        unsafe {
            let block = BNGetFunctionBasicBlockAtAddress(self.handle, arch.0, addr);
            let context = NativeBlock { _priv: () };

            if block.is_null() {
                return None;
            }

            Some(Ref::new(BasicBlock::from_raw(block, context)))
        }
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

    pub fn medium_level_il(&self) -> Result<Ref<mlil::MediumLevelILFunction>, ()> {
        unsafe {
            let mlil = BNGetFunctionMediumLevelIL(self.handle);

            if mlil.is_null() {
                return Err(());
            }

            Ok(mlil::MediumLevelILFunction::ref_from_raw(mlil))
        }
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

    pub fn lifted_il(&self) -> Result<Ref<llil::LiftedFunction<CoreArchitecture>>, ()> {
        unsafe {
            let llil = BNGetFunctionLiftedIL(self.handle);

            if llil.is_null() {
                return Err(());
            }

            Ok(llil::LiftedFunction::from_raw(self.arch(), llil))
        }
    }

    pub fn return_type(&self) -> Conf<Ref<Type>> {
        let result = unsafe { BNGetFunctionReturnType(self.handle) };

        Conf::new(
            unsafe { Type::ref_from_raw(result.type_) },
            result.confidence,
        )
    }

    pub fn function_type(&self) -> Ref<Type> {
        unsafe { Type::ref_from_raw(BNGetFunctionType(self.handle)) }
    }

    pub fn set_user_type(&self, t: Type) {
        unsafe {
            BNSetFunctionUserType(self.handle, t.handle);
        }
    }

    pub fn stack_layout(&self) -> Array<NamedTypedVariable> {
        let mut count = 0;
        unsafe {
            let variables = BNGetStackLayout(self.handle, &mut count);
            Array::new(variables, count, ())
        }
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
}

unsafe impl CoreOwnedArrayProvider for Function {
    unsafe fn free(raw: *mut *mut BNFunction, count: usize, _context: &()) {
        BNFreeFunctionList(raw, count);
    }
}

unsafe impl<'a> CoreArrayWrapper<'a> for Function {
    type Wrapped = Guard<'a, Function>;

    unsafe fn wrap_raw(raw: &'a *mut BNFunction, context: &'a ()) -> Guard<'a, Function> {
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
}
unsafe impl CoreOwnedArrayProvider for AddressRange {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeAddressRanges(raw);
    }
}

unsafe impl<'a> CoreArrayWrapper<'a> for AddressRange {
    type Wrapped = &'a AddressRange;

    unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
        mem::transmute(raw)
    }
}
