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

//! Interfaces for the various kinds of symbols in a binary.

use std::fmt;
use std::fmt::Debug;
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
    LocalLabel,
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
            LocalLabelSymbol => SymbolType::LocalLabel,
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
            SymbolType::LocalLabel => LocalLabelSymbol,
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
pub struct SymbolBuilder {
    ty: SymbolType,
    binding: Binding,
    addr: u64,
    raw_name: String,
    short_name: Option<String>,
    full_name: Option<String>,
    ordinal: u64,
}

impl SymbolBuilder {
    pub fn new<T: Into<String>>(ty: SymbolType, raw_name: T, addr: u64) -> Self {
        Self {
            ty,
            binding: Binding::None,
            addr,
            raw_name: raw_name.into(),
            short_name: None,
            full_name: None,
            ordinal: 0,
        }
    }

    pub fn binding(mut self, binding: Binding) -> Self {
        self.binding = binding;
        self
    }

    pub fn short_name<T: Into<String>>(mut self, short_name: T) -> Self {
        self.short_name = Some(short_name.into());
        self
    }

    pub fn full_name<T: Into<String>>(mut self, full_name: T) -> Self {
        self.full_name = Some(full_name.into());
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

        // Lifetimes, man
        let raw_name = raw_name.as_ptr() as _;
        unsafe {
            if let Some(short_name) = short_name {
                if let Some(full_name) = full_name {
                    let res = BNCreateSymbol(
                        self.ty.into(),
                        short_name.as_ptr() as _,
                        full_name.as_ptr() as _,
                        raw_name,
                        self.addr,
                        self.binding.into(),
                        ptr::null_mut(),
                        self.ordinal,
                    );
                    Symbol::ref_from_raw(res)
                } else {
                    let res = BNCreateSymbol(
                        self.ty.into(),
                        short_name.as_ptr() as _,
                        raw_name,
                        raw_name,
                        self.addr,
                        self.binding.into(),
                        ptr::null_mut(),
                        self.ordinal,
                    );
                    Symbol::ref_from_raw(res)
                }
            } else if let Some(full_name) = full_name {
                let res = BNCreateSymbol(
                    self.ty.into(),
                    raw_name,
                    full_name.as_ptr() as _,
                    raw_name,
                    self.addr,
                    self.binding.into(),
                    ptr::null_mut(),
                    self.ordinal,
                );
                Symbol::ref_from_raw(res)
            } else {
                let res = BNCreateSymbol(
                    self.ty.into(),
                    raw_name,
                    raw_name,
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
    /// ```no_run
    /// # use binaryninja::symbol::Symbol;
    /// # use binaryninja::symbol::SymbolType;
    /// Symbol::builder(SymbolType::Data, "hello", 0x1337)
    ///     .short_name("hello")
    ///     .full_name("hello")
    ///     .create();
    /// ```
    pub fn builder(ty: SymbolType, raw_name: &str, addr: u64) -> SymbolBuilder {
        SymbolBuilder::new(ty, raw_name, addr)
    }

    pub fn sym_type(&self) -> SymbolType {
        unsafe { BNGetSymbolType(self.handle).into() }
    }

    pub fn binding(&self) -> Binding {
        unsafe { BNGetSymbolBinding(self.handle).into() }
    }

    pub fn full_name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetSymbolFullName(self.handle)) }
    }

    pub fn short_name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetSymbolShortName(self.handle)) }
    }

    pub fn raw_name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetSymbolRawName(self.handle)) }
    }

    pub fn address(&self) -> u64 {
        unsafe { BNGetSymbolAddress(self.handle) }
    }

    pub fn auto_defined(&self) -> bool {
        unsafe { BNIsSymbolAutoDefined(self.handle) }
    }

    /// Whether this symbol has external linkage
    pub fn external(&self) -> bool {
        self.binding() == Binding::Weak || self.binding() == Binding::Global
    }

    pub fn imported_function_from_import_address_symbol(sym: &Symbol, addr: u64) -> Ref<Symbol> {
        unsafe {
            let res = BNImportedFunctionFromImportAddressSymbol(sym.handle, addr);
            Symbol::ref_from_raw(res)
        }
    }
}

unsafe impl Send for Symbol {}
unsafe impl Sync for Symbol {}

impl Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Symbol")
            .field("type", &self.sym_type())
            .field("binding", &self.binding())
            .field("full_name", &self.full_name())
            .field("short_name", &self.short_name())
            .field("raw_name", &self.raw_name())
            .field("address", &self.address())
            .field("auto_defined", &self.auto_defined())
            .field("external", &self.external())
            .finish()
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
    type Wrapped<'a> = Guard<'a, Symbol>;
}

unsafe impl CoreArrayProviderInner for Symbol {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSymbolList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
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
