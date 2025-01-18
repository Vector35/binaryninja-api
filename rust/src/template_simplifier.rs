use crate::{
    string::{BnStrCompatible, BnString},
    types::QualifiedName,
};
use binaryninjacore_sys::{BNRustSimplifyStrToFQN, BNRustSimplifyStrToStr};

pub fn simplify_str_to_str<S: BnStrCompatible>(input: S) -> BnString {
    let name = input.into_bytes_with_nul();
    unsafe { BnString::from_raw(BNRustSimplifyStrToStr(name.as_ref().as_ptr() as *mut _)) }
}

pub fn simplify_str_to_fqn<S: BnStrCompatible>(input: S, simplify: bool) -> QualifiedName {
    let name = input.into_bytes_with_nul();
    unsafe {
        QualifiedName::from_owned_raw(BNRustSimplifyStrToFQN(
            name.as_ref().as_ptr() as *mut _,
            simplify,
        ))
    }
}
