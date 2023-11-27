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

//! Interfaces for the various kinds of symbols in a binary.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::ptr;

use crate::rc::*;
use crate::string::*;
use binaryninjacore_sys::*;

// TODO : Rename
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SymbolType {
    Function,
    LibraryFunction,
    ImportAddress,
    ImportedFunction,
    Data,
    ImportedData,
    External,
    Symbolic,
}

impl From<BNSymbolType> for SymbolType {
    fn from(bn: BNSymbolType) -> SymbolType {
        use self::BNSymbolType::*;

        match bn {
            FunctionSymbol => SymbolType::Function,
            LibraryFunctionSymbol => SymbolType::LibraryFunction,
            ImportAddressSymbol => SymbolType::ImportAddress,
            ImportedFunctionSymbol => SymbolType::ImportedFunction,
            DataSymbol => SymbolType::Data,
            ImportedDataSymbol => SymbolType::ImportedData,
            ExternalSymbol => SymbolType::External,
            SymbolicFunctionSymbol => SymbolType::Symbolic,
        }
    }
}

impl From<SymbolType> for BNSymbolType {
    fn from(symbol_type: SymbolType) -> Self {
        use self::BNSymbolType::*;

        match symbol_type {
            SymbolType::Function => FunctionSymbol,
            SymbolType::LibraryFunction => LibraryFunctionSymbol,
            SymbolType::ImportAddress => ImportAddressSymbol,
            SymbolType::ImportedFunction => ImportedFunctionSymbol,
            SymbolType::Data => DataSymbol,
            SymbolType::ImportedData => ImportedDataSymbol,
            SymbolType::External => ExternalSymbol,
            SymbolType::Symbolic => SymbolicFunctionSymbol,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Binding {
    None,
    Local,
    Global,
    Weak,
}

impl From<BNSymbolBinding> for Binding {
    fn from(bn: BNSymbolBinding) -> Binding {
        use self::BNSymbolBinding::*;

        match bn {
            NoBinding => Binding::None,
            LocalBinding => Binding::Local,
            GlobalBinding => Binding::Global,
            WeakBinding => Binding::Weak,
        }
    }
}

impl From<Binding> for BNSymbolBinding {
    fn from(binding: Binding) -> Self {
        use self::BNSymbolBinding::*;

        match binding {
            Binding::None => NoBinding,
            Binding::Local => LocalBinding,
            Binding::Global => GlobalBinding,
            Binding::Weak => WeakBinding,
        }
    }
}

// TODO : Clean this up
#[must_use]
pub struct SymbolBuilder<S: BnStrCompatible> {
    ty: SymbolType,
    binding: Binding,
    addr: u64,
    raw_name: S,
    short_name: Option<S>,
    full_name: Option<S>,
    ordinal: u64,
}

impl<S: BnStrCompatible> SymbolBuilder<S> {
    pub fn new(ty: SymbolType, raw_name: S, addr: u64) -> Self {
        Self {
            ty,
            binding: Binding::None,
            addr,
            raw_name,
            short_name: None,
            full_name: None,
            ordinal: 0,
        }
    }

    pub fn binding(mut self, binding: Binding) -> Self {
        self.binding = binding;
        self
    }

    pub fn short_name(mut self, short_name: S) -> Self {
        self.short_name = Some(short_name);
        self
    }

    pub fn full_name(mut self, full_name: S) -> Self {
        self.full_name = Some(full_name);
        self
    }

    pub fn ordinal(mut self, ordinal: u64) -> Self {
        self.ordinal = ordinal;
        self
    }

    pub fn create(self) -> Ref<Symbol> {
        let raw_name = self.raw_name.into_bytes_with_nul();
        let short_name = self.short_name.map(|s| s.into_bytes_with_nul());
        let full_name = self.full_name.map(|s| s.into_bytes_with_nul());

        let raw_name = raw_name.as_ref().as_ptr() as *mut _;
        let short_name = short_name.map_or(raw_name, |s| s.as_ref().as_ptr() as *mut _);
        let full_name = full_name.map_or(raw_name, |s| s.as_ref().as_ptr() as *mut _);

        unsafe {
            let res = BNCreateSymbol(
                self.ty.into(),
                short_name,
                full_name,
                raw_name,
                self.addr,
                self.binding.into(),
                ptr::null_mut(),
                self.ordinal,
            );

            Symbol::ref_from_raw(res)
        }
    }
}

#[derive(Eq)]
pub struct Symbol {
    pub(crate) handle: *mut BNSymbol,
}

impl Symbol {
    pub(crate) unsafe fn ref_from_raw(raw: *mut BNSymbol) -> Ref<Self> {
        Ref::new(Self { handle: raw })
    }

    pub(crate) unsafe fn from_raw(raw: *mut BNSymbol) -> Self {
        Self { handle: raw }
    }

    /// To create a new symbol, you need to create a symbol builder, customize that symbol, then add `SymbolBuilder::create` it into a `Ref<Symbol>`:
    ///
    /// ```
    /// Symbol::new().short_name("hello").full_name("hello").create();
    /// ```
    pub fn builder<S: BnStrCompatible>(ty: SymbolType, raw_name: S, addr: u64) -> SymbolBuilder<S> {
        SymbolBuilder::new(ty, raw_name, addr)
    }

    pub fn sym_type(&self) -> SymbolType {
        unsafe { BNGetSymbolType(self.handle).into() }
    }

    pub fn binding(&self) -> Binding {
        unsafe { BNGetSymbolBinding(self.handle).into() }
    }

    pub fn full_name(&self) -> BnString {
        unsafe {
            let name = BNGetSymbolFullName(self.handle);
            BnString::from_raw(name)
        }
    }

    pub fn short_name(&self) -> BnString {
        unsafe {
            let name = BNGetSymbolShortName(self.handle);
            BnString::from_raw(name)
        }
    }

    pub fn raw_name(&self) -> BnString {
        unsafe {
            let name = BNGetSymbolRawName(self.handle);
            BnString::from_raw(name)
        }
    }

    pub fn address(&self) -> u64 {
        unsafe { BNGetSymbolAddress(self.handle) }
    }

    pub fn auto_defined(&self) -> bool {
        unsafe { BNIsSymbolAutoDefined(self.handle) }
    }

    /// Wether this symbol has external linkage
    pub fn external(&self) -> bool {
        self.binding() == Binding::Weak || self.binding() == Binding::Global
    }
}

unsafe impl Send for Symbol {}
unsafe impl Sync for Symbol {}

impl fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<sym {:?} '{}' @ {:x} (handle: {:?})>",
            self.sym_type(),
            self.full_name(),
            self.address(),
            self.handle
        )
    }
}

impl ToOwned for Symbol {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Symbol {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSymbolReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSymbol(handle.handle);
    }
}

impl CoreArrayProvider for Symbol {
    type Raw = *mut BNSymbol;
    type Context = ();
}

unsafe impl CoreOwnedArrayProvider for Symbol {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSymbolList(raw, count);
    }
}

unsafe impl<'a> CoreArrayWrapper<'a> for Symbol {
    type Wrapped = Guard<'a, Symbol>;

    unsafe fn wrap_raw(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped {
        Guard::new(Symbol::from_raw(*raw), context)
    }
}

impl Hash for Symbol {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl PartialEq for Symbol {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}
