use crate::architecture::CoreArchitecture;
use crate::confidence::Conf;
use crate::rc::Ref;
use crate::types::{NameAndType, Type};
use binaryninjacore_sys::{
    BNFreeNameAndTypeList, BNFreeOutputTypeList, BNFreeString, BNGetArchitectureIntrinsicClass,
    BNGetArchitectureIntrinsicInputs, BNGetArchitectureIntrinsicName,
    BNGetArchitectureIntrinsicOutputs, BNIntrinsicClass,
};
use std::borrow::Cow;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};

new_id_type!(IntrinsicId, u32);

pub trait Intrinsic: Debug + Sized + Clone + Copy {
    fn name(&self) -> Cow<'_, str>;

    /// Unique identifier for this `Intrinsic`.
    fn id(&self) -> IntrinsicId;

    /// The intrinsic class for this `Intrinsic`.
    fn class(&self) -> BNIntrinsicClass {
        BNIntrinsicClass::GeneralIntrinsicClass
    }

    // TODO: Maybe just return `(String, Conf<Ref<Type>>)`?
    /// List of the input names and types for this intrinsic.
    fn inputs(&self) -> Vec<NameAndType>;

    /// List of the output types for this intrinsic.
    fn outputs(&self) -> Vec<Conf<Ref<Type>>>;
}

/// Type for architectures that do not use intrinsics. Will panic if accessed as an intrinsic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedIntrinsic;

impl Intrinsic for UnusedIntrinsic {
    fn name(&self) -> Cow<'_, str> {
        unreachable!()
    }
    fn id(&self) -> IntrinsicId {
        unreachable!()
    }
    fn inputs(&self) -> Vec<NameAndType> {
        unreachable!()
    }
    fn outputs(&self) -> Vec<Conf<Ref<Type>>> {
        unreachable!()
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct CoreIntrinsic {
    pub arch: CoreArchitecture,
    pub id: IntrinsicId,
}

impl CoreIntrinsic {
    pub fn new(arch: CoreArchitecture, id: IntrinsicId) -> Option<Self> {
        let intrinsic = Self { arch, id };
        intrinsic.is_valid().then_some(intrinsic)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the intrinsic is actually valid.
        let name = unsafe { BNGetArchitectureIntrinsicName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl Intrinsic for CoreIntrinsic {
    fn name(&self) -> Cow<'_, str> {
        unsafe {
            let name = BNGetArchitectureIntrinsicName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            // TODO: ^ the above assertion nullifies any benefit to passing back Cow tho?
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn id(&self) -> IntrinsicId {
        self.id
    }

    fn class(&self) -> BNIntrinsicClass {
        unsafe { BNGetArchitectureIntrinsicClass(self.arch.handle, self.id.into()) }
    }

    fn inputs(&self) -> Vec<NameAndType> {
        let mut count: usize = 0;
        unsafe {
            let inputs =
                BNGetArchitectureIntrinsicInputs(self.arch.handle, self.id.into(), &mut count);

            let ret = std::slice::from_raw_parts_mut(inputs, count)
                .iter()
                .map(NameAndType::from_raw)
                .collect();

            BNFreeNameAndTypeList(inputs, count);

            ret
        }
    }

    fn outputs(&self) -> Vec<Conf<Ref<Type>>> {
        let mut count: usize = 0;
        unsafe {
            let inputs =
                BNGetArchitectureIntrinsicOutputs(self.arch.handle, self.id.into(), &mut count);

            let ret = std::slice::from_raw_parts_mut(inputs, count)
                .iter()
                .map(Conf::<Ref<Type>>::from_raw)
                .collect();

            BNFreeOutputTypeList(inputs, count);

            ret
        }
    }
}

impl Debug for CoreIntrinsic {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreIntrinsic")
            .field("id", &self.id)
            .field("name", &self.name())
            .field("class", &self.class())
            .field("inputs", &self.inputs())
            .field("outputs", &self.outputs())
            .finish()
    }
}
