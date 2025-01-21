use crate::{
    string::{AsCStr, BnString},
    types::QualifiedName,
};
use binaryninjacore_sys::{BNRustSimplifyStrToFQN, BNRustSimplifyStrToStr};

pub fn simplify_str_to_str<S: AsCStr>(input: S) -> BnString {
    unsafe { BnString::from_raw(BNRustSimplifyStrToStr(input.as_cstr().as_ptr())) }
}

pub fn simplify_str_to_fqn<S: AsCStr>(input: S, simplify: bool) -> QualifiedName {
    unsafe {
        QualifiedName::from_owned_raw(BNRustSimplifyStrToFQN(input.as_cstr().as_ptr(), simplify))
    }
}
