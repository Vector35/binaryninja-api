// Copyright 2022-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Interfaces for demangling and simplifying mangled names in binaries.

use binaryninjacore_sys::*;
use std::ptr;
use std::result;

use crate::architecture::CoreArchitecture;
use crate::string::{AsCStr, BnString};
use crate::types::Type;

use crate::rc::*;

pub type Result<R> = result::Result<R, ()>;

pub fn demangle_llvm(mangled_name: impl AsCStr, simplify: bool) -> Result<Vec<String>> {
    let mangled_name = mangled_name.as_cstr();
    let mut out_name = ptr::null_mut();
    let mut out_size = 0;
    let res = unsafe {
        BNDemangleLLVM(
            mangled_name.as_ptr(),
            &mut out_name,
            &mut out_size,
            simplify,
        )
    };

    if !res || out_size == 0 {
        return Ok(vec![mangled_name.to_string_lossy().into_owned()]);
    }

    if out_name.is_null() {
        log::error!("demangle_llvm: out_name is NULL");
        return Err(());
    }

    let names = unsafe { Array::<BnString>::new(out_name, out_size, ()) }
        .iter()
        .map(|name| name.to_string())
        .collect();

    unsafe { BNFreeDemangledName(&mut out_name, out_size) };

    Ok(names)
}

pub fn demangle_gnu3(
    arch: &CoreArchitecture,
    mangled_name: impl AsCStr,
    simplify: bool,
) -> Result<(Option<Ref<Type>>, Vec<String>)> {
    let mangled_name = mangled_name.as_cstr();
    let mut out_type = ptr::null_mut();
    let mut out_name = ptr::null_mut();
    let mut out_size = 0;
    let res = unsafe {
        BNDemangleGNU3(
            arch.0,
            mangled_name.as_ptr(),
            &mut out_type,
            &mut out_name,
            &mut out_size,
            simplify,
        )
    };

    if !res || out_size == 0 {
        return Ok((None, vec![mangled_name.to_string_lossy().into_owned()]));
    }

    let out_type = match out_type.is_null() {
        true => {
            log::debug!("demangle_gnu3: out_type is NULL");
            None
        }
        false => Some(unsafe { Type::ref_from_raw(out_type) }),
    };

    if out_name.is_null() {
        log::error!("demangle_gnu3: out_name is NULL");
        return Err(());
    }

    let names = unsafe { Array::<BnString>::new(out_name, out_size, ()) }
        .iter()
        .map(|name| name.to_string())
        .collect();

    unsafe { BNFreeDemangledName(&mut out_name, out_size) };

    Ok((out_type, names))
}

pub fn demangle_ms(
    arch: &CoreArchitecture,
    mangled_name: impl AsCStr,
    simplify: bool,
) -> Result<(Option<Ref<Type>>, Vec<String>)> {
    let mangled_name = mangled_name.as_cstr();
    let mut out_type = ptr::null_mut();
    let mut out_name = ptr::null_mut();
    let mut out_size = 0;
    let res = unsafe {
        BNDemangleMS(
            arch.0,
            mangled_name.as_ptr(),
            &mut out_type,
            &mut out_name,
            &mut out_size,
            simplify,
        )
    };

    if !res || out_size == 0 {
        return Ok((None, vec![mangled_name.to_string_lossy().into_owned()]));
    }

    let out_type = match out_type.is_null() {
        true => {
            log::debug!("demangle_ms: out_type is NULL");
            None
        }
        false => Some(unsafe { Type::ref_from_raw(out_type) }),
    };

    if out_name.is_null() {
        log::error!("demangle_ms: out_name is NULL");
        return Err(());
    }

    let names = unsafe { Array::<BnString>::new(out_name, out_size, ()) }
        .iter()
        .map(|name| name.to_string())
        .collect();

    unsafe { BNFreeDemangledName(&mut out_name, out_size) };

    Ok((out_type, names))
}
