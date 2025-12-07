use crate::architecture::CoreArchitecture;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner};
use binaryninjacore_sys::*;
use std::borrow::Cow;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;

pub use binaryninjacore_sys::BNImplicitRegisterExtend as ImplicitRegisterExtend;

crate::new_id_type!(RegisterId, u32);

impl RegisterId {
    pub fn is_temporary(&self) -> bool {
        self.0 & 0x8000_0000 != 0
    }
}

crate::new_id_type!(RegisterStackId, u32);

pub trait RegisterInfo: Sized {
    type RegType: Register<InfoType = Self>;

    fn parent(&self) -> Option<Self::RegType>;
    fn size(&self) -> usize;
    fn offset(&self) -> usize;
    fn implicit_extend(&self) -> ImplicitRegisterExtend;
}

pub trait Register: Debug + Sized + Clone + Copy + Hash + Eq {
    type InfoType: RegisterInfo<RegType = Self>;

    fn name(&self) -> Cow<'_, str>;
    fn info(&self) -> Self::InfoType;

    /// Unique identifier for this `Register`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> RegisterId;
}

pub trait RegisterStackInfo: Sized {
    type RegStackType: RegisterStack<InfoType = Self>;
    type RegType: Register<InfoType = Self::RegInfoType>;
    type RegInfoType: RegisterInfo<RegType = Self::RegType>;

    fn storage_regs(&self) -> (Self::RegType, usize);
    fn top_relative_regs(&self) -> Option<(Self::RegType, usize)>;
    fn stack_top_reg(&self) -> Self::RegType;
}

/// Type for architectures that do not use register stacks. Will panic if accessed as a register stack.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedRegisterStackInfo<R: Register> {
    _reg: std::marker::PhantomData<R>,
}

impl<R: Register> RegisterStackInfo for UnusedRegisterStackInfo<R> {
    type RegStackType = UnusedRegisterStack<R>;
    type RegType = R;
    type RegInfoType = R::InfoType;

    fn storage_regs(&self) -> (Self::RegType, usize) {
        unreachable!()
    }
    fn top_relative_regs(&self) -> Option<(Self::RegType, usize)> {
        unreachable!()
    }
    fn stack_top_reg(&self) -> Self::RegType {
        unreachable!()
    }
}

pub trait RegisterStack: Debug + Sized + Clone + Copy {
    type InfoType: RegisterStackInfo<
        RegType = Self::RegType,
        RegInfoType = Self::RegInfoType,
        RegStackType = Self,
    >;
    type RegType: Register<InfoType = Self::RegInfoType>;
    type RegInfoType: RegisterInfo<RegType = Self::RegType>;

    fn name(&self) -> Cow<'_, str>;
    fn info(&self) -> Self::InfoType;

    /// Unique identifier for this `RegisterStack`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> RegisterStackId;
}

/// Type for architectures that do not use register stacks. Will panic if accessed as a register stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedRegisterStack<R: Register> {
    _reg: std::marker::PhantomData<R>,
}

impl<R: Register> RegisterStack for UnusedRegisterStack<R> {
    type InfoType = UnusedRegisterStackInfo<R>;
    type RegType = R;
    type RegInfoType = R::InfoType;

    fn name(&self) -> Cow<'_, str> {
        unreachable!()
    }
    fn info(&self) -> Self::InfoType {
        unreachable!()
    }
    fn id(&self) -> RegisterStackId {
        unreachable!()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CoreRegisterInfo {
    arch: CoreArchitecture,
    id: RegisterId,
    info: BNRegisterInfo,
}

impl CoreRegisterInfo {
    pub fn new(arch: CoreArchitecture, id: RegisterId, info: BNRegisterInfo) -> Self {
        Self { arch, id, info }
    }
}

impl RegisterInfo for CoreRegisterInfo {
    type RegType = CoreRegister;

    fn parent(&self) -> Option<CoreRegister> {
        if self.id != RegisterId::from(self.info.fullWidthRegister) {
            Some(CoreRegister::new(
                self.arch,
                RegisterId::from(self.info.fullWidthRegister),
            )?)
        } else {
            None
        }
    }

    fn size(&self) -> usize {
        self.info.size
    }

    fn offset(&self) -> usize {
        self.info.offset
    }

    fn implicit_extend(&self) -> ImplicitRegisterExtend {
        self.info.extend
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreRegister {
    arch: CoreArchitecture,
    id: RegisterId,
}

impl CoreRegister {
    pub fn new(arch: CoreArchitecture, id: RegisterId) -> Option<Self> {
        let register = Self { arch, id };
        register.is_valid().then_some(register)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the register is actually valid.
        let name = unsafe { BNGetArchitectureRegisterName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl Register for CoreRegister {
    type InfoType = CoreRegisterInfo;

    fn name(&self) -> Cow<'_, str> {
        unsafe {
            let name = BNGetArchitectureRegisterName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn info(&self) -> CoreRegisterInfo {
        CoreRegisterInfo::new(self.arch, self.id, unsafe {
            BNGetArchitectureRegisterInfo(self.arch.handle, self.id.into())
        })
    }

    fn id(&self) -> RegisterId {
        self.id
    }
}

impl Debug for CoreRegister {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreRegister")
            .field("id", &self.id)
            .field("name", &self.name())
            .finish()
    }
}

impl CoreArrayProvider for CoreRegister {
    type Raw = u32;
    type Context = CoreArchitecture;
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CoreRegister {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeRegisterList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::new(*context, RegisterId::from(*raw)).expect("Register list contains valid registers")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CoreRegisterStackInfo {
    arch: CoreArchitecture,
    // TODO: Wrap BNRegisterStackInfo
    info: BNRegisterStackInfo,
}

impl CoreRegisterStackInfo {
    pub fn new(arch: CoreArchitecture, info: BNRegisterStackInfo) -> Self {
        Self { arch, info }
    }
}

impl RegisterStackInfo for CoreRegisterStackInfo {
    type RegStackType = CoreRegisterStack;
    type RegType = CoreRegister;
    type RegInfoType = CoreRegisterInfo;

    fn storage_regs(&self) -> (Self::RegType, usize) {
        (
            CoreRegister::new(self.arch, RegisterId::from(self.info.firstStorageReg))
                .expect("Storage register is valid"),
            self.info.storageCount as usize,
        )
    }

    fn top_relative_regs(&self) -> Option<(Self::RegType, usize)> {
        if self.info.topRelativeCount == 0 {
            None
        } else {
            Some((
                CoreRegister::new(self.arch, RegisterId::from(self.info.firstTopRelativeReg))
                    .expect("Top relative register is valid"),
                self.info.topRelativeCount as usize,
            ))
        }
    }

    fn stack_top_reg(&self) -> Self::RegType {
        CoreRegister::new(self.arch, RegisterId::from(self.info.stackTopReg))
            .expect("Stack top register is valid")
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreRegisterStack {
    arch: CoreArchitecture,
    id: RegisterStackId,
}

impl CoreRegisterStack {
    pub fn new(arch: CoreArchitecture, id: RegisterStackId) -> Option<Self> {
        let register_stack = Self { arch, id };
        register_stack.is_valid().then_some(register_stack)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the stack register is actually valid.
        let name = unsafe { BNGetArchitectureRegisterStackName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl RegisterStack for CoreRegisterStack {
    type InfoType = CoreRegisterStackInfo;
    type RegType = CoreRegister;
    type RegInfoType = CoreRegisterInfo;

    fn name(&self) -> Cow<'_, str> {
        unsafe {
            let name = BNGetArchitectureRegisterStackName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn info(&self) -> CoreRegisterStackInfo {
        CoreRegisterStackInfo::new(self.arch, unsafe {
            BNGetArchitectureRegisterStackInfo(self.arch.handle, self.id.into())
        })
    }

    fn id(&self) -> RegisterStackId {
        self.id
    }
}
