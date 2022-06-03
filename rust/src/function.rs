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

use std::fmt;

use binaryninjacore_sys::*;

use crate::architecture::CoreArchitecture;
use crate::basicblock::{BasicBlock, BlockContext};
use crate::binaryview::{BinaryView, BinaryViewExt};
use crate::platform::Platform;
use crate::symbol::Symbol;
use crate::types::Type;

use crate::llil;
use crate::mlil;

use crate::rc::*;
use crate::string::*;

pub struct Location {
    pub arch: Option<CoreArchitecture>,
    pub addr: u64,
}

impl From<u64> for Location {
    fn from(addr: u64) -> Self {
        Location {
            arch: None,
            addr: addr,
        }
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

#[derive(PartialEq, Eq, Hash)]
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
            Ref::new(Symbol::from_raw(sym))
        }
    }

    pub fn start(&self) -> u64 {
        unsafe { BNGetFunctionStart(self.handle) }
    }

    pub fn highest_address(&self) -> u64 {
        unsafe { BNGetFunctionHighestAddress(self.handle) }
    }

    pub fn comment(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetFunctionComment(self.handle)) }
    }

    pub fn set_comment<S: BnStrCompatible>(&self, comment: S) {
        let raw = comment.as_bytes_with_nul();

        unsafe {
            BNSetFunctionComment(self.handle, raw.as_ref().as_ptr() as *mut _);
        }
    }

    pub fn comment_at(&self, addr: u64) -> BnString {
        unsafe { BnString::from_raw(BNGetCommentForAddress(self.handle, addr)) }
    }

    pub fn set_comment_at<S: BnStrCompatible>(&self, addr: u64, comment: S) {
        let raw = comment.as_bytes_with_nul();

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

    pub fn low_level_il(&self) -> Result<Ref<llil::RegularFunction<CoreArchitecture>>, ()> {
        unsafe {
            let llil = BNGetFunctionLowLevelIL(self.handle);

            if llil.is_null() {
                return Err(());
            }

            Ok(Ref::new(llil::RegularFunction::from_raw(self.arch(), llil)))
        }
    }

    pub fn medium_level_il(&self) -> Result<Ref<mlil::RegularFunction<CoreArchitecture>>, ()> {
        unsafe {
            let mlil = BNGetFunctionMediumLevelIL(self.handle);

            if mlil.is_null() {
                return Err(());
            }

            Ok(Ref::new(mlil::RegularFunction::from_raw(self.arch(), mlil)))
        }
    }

    pub fn lifted_il(&self) -> Result<Ref<llil::LiftedFunction<CoreArchitecture>>, ()> {
        unsafe {
            let llil = BNGetFunctionLiftedIL(self.handle);

            if llil.is_null() {
                return Err(());
            }

            Ok(Ref::new(llil::LiftedFunction::from_raw(self.arch(), llil)))
        }
    }

    pub fn set_user_type(&self, t: Type) {
        unsafe {
            BNSetFunctionUserType(self.handle, t.handle);
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
