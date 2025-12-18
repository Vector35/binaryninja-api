use crate::architecture::CoreArchitecture;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner};
use binaryninjacore_sys::*;
use std::borrow::Cow;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;

new_id_type!(RegisterId, u32);

impl RegisterId {
    pub fn is_temporary(&self) -> bool {
        self.0 & 0x8000_0000 != 0
    }
}

new_id_type!(RegisterStackId, u32);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ImplicitRegisterExtend {
    /// The upper bits of the parent register are preserved (untouched).
    ///
    /// # Example (x86-64)
    ///
    /// Executing `inc al` only modifies the lowest 8 bits of `rax`. The upper 56 bits of `rax` remain
    /// completely unchanged.
    NoExtend = 0,
    /// The upper bits of the parent register are zeroed out.
    ///
    /// # Example (x86-64)
    ///
    /// Executing `mov eax, 1` writes `1` to the lower 32 bits of `rax`, but implicitly **clears** the
    /// upper 32 bits of `rax` to zero.
    ZeroExtendToFullWidth,
    /// The upper bits of the parent register are filled with the sign bit (MSB) of the value written.
    SignExtendToFullWidth,
}

impl From<BNImplicitRegisterExtend> for ImplicitRegisterExtend {
    fn from(value: BNImplicitRegisterExtend) -> Self {
        match value {
            BNImplicitRegisterExtend::NoExtend => Self::NoExtend,
            BNImplicitRegisterExtend::ZeroExtendToFullWidth => Self::ZeroExtendToFullWidth,
            BNImplicitRegisterExtend::SignExtendToFullWidth => Self::SignExtendToFullWidth,
        }
    }
}

impl From<ImplicitRegisterExtend> for BNImplicitRegisterExtend {
    fn from(value: ImplicitRegisterExtend) -> Self {
        match value {
            ImplicitRegisterExtend::NoExtend => Self::NoExtend,
            ImplicitRegisterExtend::ZeroExtendToFullWidth => Self::ZeroExtendToFullWidth,
            ImplicitRegisterExtend::SignExtendToFullWidth => Self::SignExtendToFullWidth,
        }
    }
}

/// Information about a register.
pub trait RegisterInfo: Sized {
    type RegType: Register<InfoType = Self>;

    /// The register that this register is an alias of.
    ///
    /// # Example (x86-64)
    ///
    /// The register `rax` is a parent of the register `eax`.
    fn parent(&self) -> Option<Self::RegType>;

    /// Size of the register in bytes.
    fn size(&self) -> usize;

    /// Offset of the register in bytes from the start of the containing [`RegisterInfo::parent`].
    fn offset(&self) -> usize;

    /// Used when this register aliases a logical register to determine what happens to the upper bits.
    fn implicit_extend(&self) -> ImplicitRegisterExtend;
}

pub trait Register: Debug + Sized + Clone + Copy + Hash + Eq {
    type InfoType: RegisterInfo<RegType = Self>;

    /// The displayed name of the register, such as "eax".
    fn name(&self) -> Cow<'_, str>;

    fn info(&self) -> Self::InfoType;

    /// Unique identifier for this `Register`.
    ///
    /// NOTE: *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> RegisterId;
}

/// Information about a register stack.
pub trait RegisterStackInfo: Sized {
    type RegStackType: RegisterStack<InfoType = Self>;
    type RegType: Register<InfoType = Self::RegInfoType>;
    type RegInfoType: RegisterInfo<RegType = Self::RegType>;

    // TODO: Return a list of the registers instead?
    /// The sequence of physical registers that back this stack.
    ///
    /// This defines the absolute storage locations in the hardware, ignoring the current stack pointer.
    ///
    /// Return the start of the "fake" registers defined. The core requires that the id's be contiguous
    /// as you only return the **first** storage register and the count.
    ///
    /// # Example (x87 FPU)
    ///
    /// [`RegisterStackInfo::top_relative_regs`] with (REG_ST0, 8) and then define here (REG_PHYSICAL_0, 8).
    fn storage_regs(&self) -> (Self::RegType, usize);

    // TODO: Return a list of the registers instead?
    /// The sequence of registers used to access the stack relative to the current top.
    ///
    /// Return the start of the relative registers defined. The core requires that the id's be contiguous
    /// as you only return the **first** relative register and the count.
    ///
    /// # Example (x87 FPU)
    ///
    /// Returns (REG_ST0, 8), where the id's of all the later relative registers are contiguous.
    fn top_relative_regs(&self) -> Option<(Self::RegType, usize)>;

    /// The specific register that holds the index of the current stack top.
    ///
    /// The value in this register determines which physical `storage_reg` corresponds
    /// to the first `top_relative_reg`.
    ///
    /// # Example (x87 FPU)
    ///
    /// Returns the `TOP` as a fake register.
    ///
    /// * If `TOP` == 0: `top_relative_regs[0]` maps to `storage_regs[0]`.
    /// * If `TOP` == 1: `top_relative_regs[0]` maps to `storage_regs[1]`.
    fn stack_top_reg(&self) -> Self::RegType;
}

/// Register stacks are used in architectures where registers are accessed relative to a
/// dynamic stack pointer rather than by fixed names.
///
/// For more information see [`RegisterStackInfo`].
///
/// # Example
/// The **x87 FPU** on x86 uses a register stack (`ST(0)` through `ST(7)`).
/// Pushing a value decrements the stack top pointer; popping increments it.
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
    type InfoType = Self;
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

impl<R: Register> RegisterStackInfo for UnusedRegisterStack<R> {
    type RegStackType = Self;
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
        self.info.extend.into()
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
