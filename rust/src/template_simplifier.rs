use crate::{
    string::{AsCStr, BnString},
    types::QualifiedName,
};
use binaryninjacore_sys::{BNRustSimplifyStrToFQN, BNRustSimplifyStrToStr};

pub fn simplify_str_to_str<S: AsCStr>(input: S) -> BnString {
    let name = input.to_cstr();
    unsafe { BnString::from_raw(BNRustSimplifyStrToStr(name.as_ref().as_ptr() as *mut _)) }
}

pub fn simplify_str_to_fqn<S: AsCStr>(input: S, simplify: bool) -> QualifiedName {
    let name = input.to_cstr();
    unsafe {
        QualifiedName::from_owned_raw(BNRustSimplifyStrToFQN(
            name.as_ref().as_ptr() as *mut _,
            simplify,
        ))
    }
}
