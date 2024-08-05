use crate::{
    string::{AsCStr, BnString},
    types::QualifiedName,
};
use binaryninjacore_sys::{BNRustSimplifyStrToFQN, BNRustSimplifyStrToStr};

pub fn simplify_str_to_str(input: impl AsCStr) -> BnString {
    unsafe { BnString::from_raw(BNRustSimplifyStrToStr(input.as_cstr().as_ptr())) }
}

pub fn simplify_str_to_fqn(input: impl AsCStr, simplify: bool) -> QualifiedName {
    unsafe { QualifiedName(BNRustSimplifyStrToFQN(input.as_cstr().as_ptr(), simplify)) }
}
