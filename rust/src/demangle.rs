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
use std::os::raw::c_char;
use std::{ffi::CStr, result};

use crate::architecture::CoreArchitecture;
use crate::string::{BnStrCompatible, BnString};
use crate::types::Type;

use crate::rc::*;

pub type Result<R> = result::Result<R, ()>;

pub fn demangle_gnu3<S: BnStrCompatible>(
    arch: &CoreArchitecture,
    mangled_name: S,
    simplify: bool,
) -> Result<(Option<Ref<Type>>, Vec<String>)> {
    let mangled_name_bwn = mangled_name.into_bytes_with_nul();
    let mangled_name_ptr = mangled_name_bwn.as_ref();
    let mut out_type: *mut BNType = unsafe { std::mem::zeroed() };
    let mut out_name: *mut *mut std::os::raw::c_char = unsafe { std::mem::zeroed() };
    let mut out_size: usize = 0;
    let res = unsafe {
        BNDemangleGNU3(
            arch.0,
            mangled_name_ptr.as_ptr() as *const c_char,
            &mut out_type,
            &mut out_name,
            &mut out_size,
            simplify,
        )
    };

    if !res || out_size == 0 {
        let cstr = match CStr::from_bytes_with_nul(mangled_name_ptr) {
            Ok(cstr) => cstr,
            Err(_) => {
                log::error!("demangle_gnu3: failed to parse mangled name");
                return Err(());
            }
        };
        return Ok((None, vec![cstr.to_string_lossy().into_owned()]));
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

    let names = unsafe { ArrayGuard::<BnString>::new(out_name, out_size, ()) }
        .iter()
        .map(|name| name.to_string())
        .collect();

    unsafe { BNFreeDemangledName(&mut out_name, out_size) };

    Ok((out_type, names))
}

pub fn demangle_ms<S: BnStrCompatible>(
    arch: &CoreArchitecture,
    mangled_name: S,
    simplify: bool,
) -> Result<(Option<Ref<Type>>, Vec<String>)> {
    let mangled_name_bwn = mangled_name.into_bytes_with_nul();
    let mangled_name_ptr = mangled_name_bwn.as_ref();

    let mut out_type: *mut BNType = unsafe { std::mem::zeroed() };
    let mut out_name: *mut *mut std::os::raw::c_char = unsafe { std::mem::zeroed() };
    let mut out_size: usize = 0;
    let res = unsafe {
        BNDemangleMS(
            arch.0,
            mangled_name_ptr.as_ptr() as *const c_char,
            &mut out_type,
            &mut out_name,
            &mut out_size,
            simplify,
        )
    };

    if !res || out_size == 0 {
        let cstr = match CStr::from_bytes_with_nul(mangled_name_ptr) {
            Ok(cstr) => cstr,
            Err(_) => {
                log::error!("demangle_ms: failed to parse mangled name");
                return Err(());
            }
        };
        return Ok((None, vec![cstr.to_string_lossy().into_owned()]));
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

    let names = unsafe { ArrayGuard::<BnString>::new(out_name, out_size, ()) }
        .iter()
        .map(|name| name.to_string())
        .collect();

    unsafe { BNFreeDemangledName(&mut out_name, out_size) };

    Ok((out_type, names))
}
