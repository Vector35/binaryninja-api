use std::ptr::NonNull;

use crate::{
    string::{BnStrCompatible, BnString},
    types::QualifiedName,
};
use binaryninjacore_sys::{BNRustSimplifyStrToFQN, BNRustSimplifyStrToStr};

pub fn simplify_str_to_str<S: BnStrCompatible>(input: S) -> BnString {
    let name = input.into_bytes_with_nul();
    let result = unsafe { BNRustSimplifyStrToStr(name.as_ref().as_ptr() as *mut _) };
    unsafe { BnString::from_raw(NonNull::new(result).unwrap()) }
}

pub fn simplify_str_to_fqn<S: BnStrCompatible>(input: S, simplify: bool) -> QualifiedName {
    let name = input.into_bytes_with_nul();
    unsafe {
        QualifiedName(BNRustSimplifyStrToFQN(
            name.as_ref().as_ptr() as *mut _,
            simplify,
        ))
    }
}
