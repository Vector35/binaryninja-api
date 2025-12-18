use crate::architecture::CoreArchitecture;
use binaryninjacore_sys::*;
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt::Debug;
use std::hash::Hash;

pub use binaryninjacore_sys::BNFlagRole as FlagRole;
pub use binaryninjacore_sys::BNLowLevelILFlagCondition as FlagCondition;

new_id_type!(FlagId, u32);
// TODO: Make this NonZero<u32>?
new_id_type!(FlagWriteId, u32);
new_id_type!(FlagClassId, u32);
new_id_type!(FlagGroupId, u32);

pub trait Flag: Debug + Sized + Clone + Copy + Hash + Eq {
    type FlagClass: FlagClass;

    fn name(&self) -> Cow<'_, str>;
    fn role(&self, class: Option<Self::FlagClass>) -> FlagRole;

    /// Unique identifier for this `Flag`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> FlagId;
}

pub trait FlagWrite: Sized + Clone + Copy {
    type FlagType: Flag;
    type FlagClass: FlagClass;

    fn name(&self) -> Cow<'_, str>;
    fn class(&self) -> Option<Self::FlagClass>;

    /// Unique identifier for this `FlagWrite`.
    ///
    /// *MUST NOT* be 0.
    /// *MUST* be in the range [1, 0x7fff_ffff]
    fn id(&self) -> FlagWriteId;

    fn flags_written(&self) -> Vec<Self::FlagType>;
}

pub trait FlagClass: Sized + Clone + Copy + Hash + Eq {
    fn name(&self) -> Cow<'_, str>;

    /// Unique identifier for this `FlagClass`.
    ///
    /// *MUST NOT* be 0.
    /// *MUST* be in the range [1, 0x7fff_ffff]
    fn id(&self) -> FlagClassId;
}

pub trait FlagGroup: Debug + Sized + Clone + Copy {
    type FlagType: Flag;
    type FlagClass: FlagClass;

    fn name(&self) -> Cow<'_, str>;

    /// Unique identifier for this `FlagGroup`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> FlagGroupId;

    /// Returns the list of flags that need to be resolved in order
    /// to take the clean flag resolution path -- at time of writing,
    /// all required flags must have been set by the same instruction,
    /// and the 'querying' instruction must be reachable from *one*
    /// instruction that sets all of these flags.
    fn flags_required(&self) -> Vec<Self::FlagType>;

    /// Returns the mapping of Semantic Flag Classes to Flag Conditions,
    /// in the context of this Flag Group.
    ///
    /// Example:
    ///
    /// If we have a group representing `cr1_lt` (as in PowerPC), we would
    /// have multiple Semantic Flag Classes used by the different Flag Write
    /// Types to represent the different comparisons, so for `cr1_lt` we
    /// would return a mapping along the lines of:
    ///
    /// ```text
    /// cr1_signed -> LLFC_SLT,
    /// cr1_unsigned -> LLFC_ULT,
    /// ```
    ///
    /// This allows the core to recover the semantics of the comparison and
    /// inline it into conditional branches when appropriate.
    fn flag_conditions(&self) -> HashMap<Self::FlagClass, FlagCondition>;
}

/// Type for architectures that do not use flags. Will panic if accessed as a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedFlag;

impl Flag for UnusedFlag {
    type FlagClass = Self;
    fn name(&self) -> Cow<'_, str> {
        unreachable!()
    }
    fn role(&self, _class: Option<Self::FlagClass>) -> FlagRole {
        unreachable!()
    }
    fn id(&self) -> FlagId {
        unreachable!()
    }
}

impl FlagWrite for UnusedFlag {
    type FlagType = Self;
    type FlagClass = Self;
    fn name(&self) -> Cow<'_, str> {
        unreachable!()
    }
    fn class(&self) -> Option<Self> {
        unreachable!()
    }
    fn id(&self) -> FlagWriteId {
        unreachable!()
    }
    fn flags_written(&self) -> Vec<Self::FlagType> {
        unreachable!()
    }
}

impl FlagClass for UnusedFlag {
    fn name(&self) -> Cow<'_, str> {
        unreachable!()
    }
    fn id(&self) -> FlagClassId {
        unreachable!()
    }
}

impl FlagGroup for UnusedFlag {
    type FlagType = Self;
    type FlagClass = Self;
    fn name(&self) -> Cow<'_, str> {
        unreachable!()
    }
    fn id(&self) -> FlagGroupId {
        unreachable!()
    }
    fn flags_required(&self) -> Vec<Self::FlagType> {
        unreachable!()
    }
    fn flag_conditions(&self) -> HashMap<Self, FlagCondition> {
        unreachable!()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreFlag {
    arch: CoreArchitecture,
    id: FlagId,
}

impl CoreFlag {
    pub fn new(arch: CoreArchitecture, id: FlagId) -> Option<Self> {
        let flag = Self { arch, id };
        flag.is_valid().then_some(flag)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the flag is actually valid.
        let name = unsafe { BNGetArchitectureFlagName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl Flag for CoreFlag {
    type FlagClass = CoreFlagClass;

    fn name(&self) -> Cow<'_, str> {
        unsafe {
            let name = BNGetArchitectureFlagName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn role(&self, class: Option<CoreFlagClass>) -> FlagRole {
        unsafe {
            BNGetArchitectureFlagRole(
                self.arch.handle,
                self.id.into(),
                class.map(|c| c.id.0).unwrap_or(0),
            )
        }
    }

    fn id(&self) -> FlagId {
        self.id
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreFlagWrite {
    arch: CoreArchitecture,
    id: FlagWriteId,
}

impl CoreFlagWrite {
    pub fn new(arch: CoreArchitecture, id: FlagWriteId) -> Option<Self> {
        let flag_write = Self { arch, id };
        flag_write.is_valid().then_some(flag_write)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the flag write is actually valid.
        let name = unsafe { BNGetArchitectureFlagWriteTypeName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl FlagWrite for CoreFlagWrite {
    type FlagType = CoreFlag;
    type FlagClass = CoreFlagClass;

    fn name(&self) -> Cow<'_, str> {
        unsafe {
            let name = BNGetArchitectureFlagWriteTypeName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn class(&self) -> Option<CoreFlagClass> {
        let class = unsafe {
            BNGetArchitectureSemanticClassForFlagWriteType(self.arch.handle, self.id.into())
        };

        match class {
            0 => None,
            class_id => Some(CoreFlagClass::new(self.arch, class_id.into())?),
        }
    }

    fn id(&self) -> FlagWriteId {
        self.id
    }

    fn flags_written(&self) -> Vec<CoreFlag> {
        let mut count: usize = 0;
        let regs: *mut u32 = unsafe {
            BNGetArchitectureFlagsWrittenByFlagWriteType(
                self.arch.handle,
                self.id.into(),
                &mut count,
            )
        };

        let ret = unsafe {
            std::slice::from_raw_parts(regs, count)
                .iter()
                .map(|id| FlagId::from(*id))
                .filter_map(|reg| CoreFlag::new(self.arch, reg))
                .collect()
        };

        unsafe {
            BNFreeRegisterList(regs);
        }

        ret
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreFlagClass {
    arch: CoreArchitecture,
    id: FlagClassId,
}

impl CoreFlagClass {
    pub fn new(arch: CoreArchitecture, id: FlagClassId) -> Option<Self> {
        let flag = Self { arch, id };
        flag.is_valid().then_some(flag)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the flag is actually valid.
        let name =
            unsafe { BNGetArchitectureSemanticFlagClassName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl FlagClass for CoreFlagClass {
    fn name(&self) -> Cow<'_, str> {
        unsafe {
            let name = BNGetArchitectureSemanticFlagClassName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn id(&self) -> FlagClassId {
        self.id
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CoreFlagGroup {
    arch: CoreArchitecture,
    id: FlagGroupId,
}

impl CoreFlagGroup {
    pub fn new(arch: CoreArchitecture, id: FlagGroupId) -> Option<Self> {
        let flag_group = Self { arch, id };
        flag_group.is_valid().then_some(flag_group)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the flag group is actually valid.
        let name =
            unsafe { BNGetArchitectureSemanticFlagGroupName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl FlagGroup for CoreFlagGroup {
    type FlagType = CoreFlag;
    type FlagClass = CoreFlagClass;

    fn name(&self) -> Cow<'_, str> {
        unsafe {
            let name = BNGetArchitectureSemanticFlagGroupName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn id(&self) -> FlagGroupId {
        self.id
    }

    fn flags_required(&self) -> Vec<CoreFlag> {
        let mut count: usize = 0;
        let regs: *mut u32 = unsafe {
            BNGetArchitectureFlagsRequiredForSemanticFlagGroup(
                self.arch.handle,
                self.id.into(),
                &mut count,
            )
        };

        let ret = unsafe {
            std::slice::from_raw_parts(regs, count)
                .iter()
                .map(|id| FlagId::from(*id))
                .filter_map(|reg| CoreFlag::new(self.arch, reg))
                .collect()
        };

        unsafe {
            BNFreeRegisterList(regs);
        }

        ret
    }

    fn flag_conditions(&self) -> HashMap<CoreFlagClass, FlagCondition> {
        let mut count: usize = 0;

        unsafe {
            let flag_conds = BNGetArchitectureFlagConditionsForSemanticFlagGroup(
                self.arch.handle,
                self.id.into(),
                &mut count,
            );

            let ret = std::slice::from_raw_parts_mut(flag_conds, count)
                .iter()
                .filter_map(|class_cond| {
                    Some((
                        CoreFlagClass::new(self.arch, class_cond.semanticClass.into())?,
                        class_cond.condition,
                    ))
                })
                .collect();

            BNFreeFlagConditionsForSemanticFlagGroup(flag_conds);

            ret
        }
    }
}
