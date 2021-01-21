use std::fmt;
use std::ptr;

use binaryninjacore_sys::*;
use crate::string::*;
use crate::rc::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SymType {
    Function,
    LibraryFunction,
    ImportAddress,
    ImportedFunction,
    Data,
    ImportedData,
    External,
}

impl From<BNSymbolType> for SymType {
    fn from(bn: BNSymbolType) -> SymType {
        use self::BNSymbolType::*;

        match bn {
            FunctionSymbol => SymType::Function,
            LibraryFunctionSymbol => SymType::LibraryFunction,
            ImportAddressSymbol => SymType::ImportAddress,
            ImportedFunctionSymbol => SymType::ImportedFunction,
            DataSymbol => SymType::Data,
            ImportedDataSymbol => SymType::ImportedData,
            ExternalSymbol => SymType::External,
        }
    }
}

impl Into<BNSymbolType> for SymType {
    fn into(self) -> BNSymbolType {
        use self::BNSymbolType::*;

        match self {
            SymType::Function => FunctionSymbol,
            SymType::LibraryFunction => LibraryFunctionSymbol,
            SymType::ImportAddress => ImportAddressSymbol,
            SymType::ImportedFunction => ImportedFunctionSymbol,
            SymType::Data => DataSymbol,
            SymType::ImportedData => ImportedDataSymbol,
            SymType::External => ExternalSymbol,
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

impl Into<BNSymbolBinding> for Binding {
    fn into(self) -> BNSymbolBinding {
        use self::BNSymbolBinding::*;

        match self {
            Binding::None => NoBinding,
            Binding::Local => LocalBinding,
            Binding::Global => GlobalBinding,
            Binding::Weak => WeakBinding,
        }
    }
}

#[must_use]
pub struct SymbolBuilder<S: BnStrCompatible> {
    ty: SymType,
    binding: Binding,
    addr: u64,
    raw_name: S,
    short_name: Option<S>,
    full_name: Option<S>,
    ordinal: u64,
}

impl<S: BnStrCompatible> SymbolBuilder<S> {
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
        let raw_name = self.raw_name.as_bytes_with_nul();
        let short_name = self.short_name.map(|s| s.as_bytes_with_nul());
        let full_name = self.full_name.map(|s| s.as_bytes_with_nul());

        unsafe {
            let raw_name = raw_name.as_ref().as_ptr() as *mut _;
            let short_name = short_name.as_ref().map_or(raw_name, |s| s.as_ref().as_ptr() as *mut _);
            let full_name = full_name.as_ref().map_or(raw_name, |s| s.as_ref().as_ptr() as *mut _);

            let res = BNCreateSymbol(self.ty.into(),
                short_name, full_name, raw_name,
                self.addr, self.binding.into(), ptr::null_mut(),
                self.ordinal);

            Ref::new(Symbol::from_raw(res))
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct Symbol {
    pub(crate) handle: *mut BNSymbol,
}

unsafe impl Send for Symbol {}
unsafe impl Sync for Symbol {}

impl Symbol {
    pub(crate) unsafe fn from_raw(raw: *mut BNSymbol) -> Self {
        Self { handle: raw }
    }

    pub fn new<S: BnStrCompatible>(ty: SymType, raw_name: S, addr: u64) -> SymbolBuilder<S> {
        SymbolBuilder {
            ty: ty,
            binding: Binding::None,
            addr: addr,
            raw_name: raw_name,
            short_name: None,
            full_name: None,
            ordinal: 0,
        }
    }

    pub fn sym_type(&self) -> SymType {
        unsafe { BNGetSymbolType(self.handle).into() }
    }

    pub fn binding(&self) -> Binding {
        unsafe { BNGetSymbolBinding(self.handle).into() }
    }

    pub fn name(&self) -> BnString {
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
}

impl fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<sym {:?} '{}' @ {:x} (handle: {:?})>", self.sym_type(), self.name(), self.address(), self.handle)
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

unsafe impl CoreOwnedArrayProvider for Symbol {
    type Raw = *mut BNSymbol;
    type Context = ();

    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSymbolList(raw, count);
    }
}

unsafe impl<'a> CoreOwnedArrayWrapper<'a> for Symbol {
    type Wrapped = Guard<'a, Symbol>;

    unsafe fn wrap_raw(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped {
        Guard::new(Symbol::from_raw(*raw), context)
    }
}
