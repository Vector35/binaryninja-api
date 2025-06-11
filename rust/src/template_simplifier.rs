use crate::{
    string::{BnString, IntoCStr},
    types::QualifiedName,
};
use binaryninjacore_sys::{BNRustSimplifyStrToFQN, BNRustSimplifyStrToStr};

pub fn simplify_str_to_str<S: IntoCStr>(input: S) -> BnString {
    let name = input.to_cstr();
    unsafe { BnString::from_raw(BNRustSimplifyStrToStr(name.as_ptr())) }
}

pub fn simplify_str_to_fqn<S: IntoCStr>(input: S, simplify: bool) -> QualifiedName {
    let name = input.to_cstr();
    unsafe { QualifiedName::from_owned_raw(BNRustSimplifyStrToFQN(name.as_ptr(), simplify)) }
}
