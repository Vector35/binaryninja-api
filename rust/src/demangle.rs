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
use std::ffi::c_void;

use crate::architecture::CoreArchitecture;
use crate::binaryview::BinaryView;
use crate::string::{BnStrCompatible, BnString, raw_to_string};
use crate::types::{QualifiedName, Type};

use crate::rc::*;

pub type Result<R> = result::Result<R, ()>;

pub fn demangle_generic<S: BnStrCompatible>(
    arch: &CoreArchitecture,
    mangled_name: S,
    view: Option<&BinaryView>,
    simplify: bool,
) -> Result<(Option<Ref<Type>>, Vec<String>)> {
    let mangled_name_bwn = mangled_name.into_bytes_with_nul();
    let mangled_name_ptr = mangled_name_bwn.as_ref();
    let mut out_type: *mut BNType = std::ptr::null_mut();
    let mut out_name = BNQualifiedName {
        name: std::ptr::null_mut(),
        join: std::ptr::null_mut(),
        nameCount: 0,
    };
    let view_ptr = match view {
        Some(v) => v.handle,
        None => std::ptr::null_mut(),
    };
    let res = unsafe {
        BNDemangleGeneric(
            arch.0,
            mangled_name_ptr.as_ptr() as *const c_char,
            &mut out_type,
            &mut out_name,
            view_ptr,
            simplify,
        )
    };

    if !res {
        let cstr = match CStr::from_bytes_with_nul(mangled_name_ptr) {
            Ok(cstr) => cstr,
            Err(_) => {
                log::error!("demangle_generic: failed to parse mangled name");
                return Err(());
            }
        };
        return Ok((None, vec![cstr.to_string_lossy().into_owned()]));
    }

    let out_type = match out_type.is_null() {
        true => {
            log::debug!("demangle_generic: out_type is NULL");
            None
        }
        false => Some(unsafe { Type::ref_from_raw(out_type) }),
    };

    Ok((
        out_type,
        QualifiedName(out_name)
            .strings()
            .iter()
            .map(|str| str.to_string())
            .collect::<Vec<_>>()
    ))
}

pub fn demangle_llvm<S: BnStrCompatible>(
    mangled_name: S,
    simplify: bool,
) -> Result<Vec<String>> {
    let mangled_name_bwn = mangled_name.into_bytes_with_nul();
    let mangled_name_ptr = mangled_name_bwn.as_ref();
    let mut out_name: *mut *mut std::os::raw::c_char = unsafe { std::mem::zeroed() };
    let mut out_size: usize = 0;
    let res = unsafe {
        BNDemangleLLVM(
            mangled_name_ptr.as_ptr() as *const c_char,
            &mut out_name,
            &mut out_size,
            simplify,
        )
    };

    if !res || out_size == 0 {
        let cstr = match CStr::from_bytes_with_nul(mangled_name_ptr) {
            Ok(cstr) => cstr,
            Err(_) => {
                log::error!("demangle_llvm: failed to parse mangled name");
                return Err(());
            }
        };
        return Ok(vec![cstr.to_string_lossy().into_owned()]);
    }

    if out_name.is_null() {
        log::error!("demangle_llvm: out_name is NULL");
        return Err(());
    }

    let names = unsafe { ArrayGuard::<BnString>::new(out_name, out_size, ()) }
        .iter()
        .map(str::to_string)
        .collect();

    unsafe { BNFreeDemangledName(&mut out_name, out_size) };

    Ok(names)
}

pub fn demangle_gnu3<S: BnStrCompatible>(
    arch: &CoreArchitecture,
    mangled_name: S,
    simplify: bool,
) -> Result<(Option<Ref<Type>>, Vec<String>)> {
    let mangled_name_bwn = mangled_name.into_bytes_with_nul();
    let mangled_name_ptr = mangled_name_bwn.as_ref();
    let mut out_type: *mut BNType = std::ptr::null_mut();
    let mut out_name: *mut *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut out_size: usize = 0;
    let res = unsafe {
        BNDemangleGNU3(
            arch.as_ptr(),
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
        .map(str::to_string)
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

    let mut out_type: *mut BNType = std::ptr::null_mut();
    let mut out_name: *mut *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut out_size: usize = 0;
    let res = unsafe {
        BNDemangleMS(
            arch.as_ptr(),
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

#[derive(PartialEq, Eq, Hash)]
pub struct Demangler {
    pub(crate) handle: *mut BNDemangler,
}

impl Demangler {
    pub(crate) unsafe fn from_raw(handle: *mut BNDemangler) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub fn is_mangled_string<S: BnStrCompatible>(&self, name: S) -> bool {
        let bytes = name.into_bytes_with_nul();
        unsafe { BNIsDemanglerMangledName(self.handle, bytes.as_ref().as_ptr() as *const _) }
    }

    pub fn demangle<S: BnStrCompatible>(
        &self,
        arch: &CoreArchitecture,
        name: S,
        view: Option<&BinaryView>,
    ) -> Result<(Option<Ref<Type>>, QualifiedName)> {
        let name_bytes = name.into_bytes_with_nul();

        let mut out_type = std::ptr::null_mut();
        let mut out_var_name = BNQualifiedName {
            name: std::ptr::null_mut(),
            join: std::ptr::null_mut(),
            nameCount: 0,
        };

        let view_ptr = match view {
            Some(v) => v.handle,
            None => std::ptr::null_mut()
        };

        if !unsafe { BNDemanglerDemangle(self.handle, arch.0, name_bytes.as_ref().as_ptr() as *const _, &mut out_type, &mut out_var_name, view_ptr) } {
            return Err(());
        }

        let var_type =
            if out_type.is_null() {
                None
            } else {
                Some(unsafe { Type::ref_from_raw(out_type) })
            };
        let var_name = QualifiedName(out_var_name);

        Ok((var_type, var_name))
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetDemanglerName(self.handle)) }
    }

    pub fn from_name<S: BnStrCompatible>(name: S) -> Option<Self> {
        let name_bytes = name.into_bytes_with_nul();
        let demangler = unsafe { BNGetDemanglerByName(name_bytes.as_ref().as_ptr() as *const _) };
        if demangler.is_null() {
            None
        } else {
            Some(unsafe { Demangler::from_raw(demangler) })
        }
    }

    pub fn list() -> Array<Self> {
        let mut count: usize = 0;
        let demanglers = unsafe { BNGetDemanglerList(&mut count) };
        unsafe { Array::<Demangler>::new(demanglers, count, ()) }
    }

    pub fn register<S, C>(name: S, callbacks: C) -> Self
    where
        S: BnStrCompatible,
        C: CustomDemangler,
    {
        extern "C" fn cb_is_mangled_string<C>(ctxt: *mut c_void, name: *const c_char) -> bool
        where
            C: CustomDemangler,
        {
            ffi_wrap!("CustomDemangler::cb_is_mangled_string", unsafe {
                let cmd = &*(ctxt as *const C);
                let name =
                    if let Some(n) = raw_to_string(name) {
                        n
                    } else {
                        return false;
                    };
                cmd.is_mangled_string(&name)
            })
        }
        extern "C" fn cb_demangle<C>(ctxt: *mut c_void, arch: *mut BNArchitecture, name: *const c_char, out_type: *mut *mut BNType, out_var_name: *mut BNQualifiedName, view: *mut BNBinaryView) -> bool
        where
            C: CustomDemangler,
        {
            ffi_wrap!("CustomDemangler::cb_demangle", unsafe {
                let cmd = &*(ctxt as *const C);
                let arch = CoreArchitecture::from_raw(arch);
                let name =
                    if let Some(n) = raw_to_string(name) {
                        n
                    } else {
                        return false;
                    };
                let view = if view.is_null() {
                    None
                } else {
                    Some(BinaryView::from_raw(BNNewViewReference(view)))
                };

                match cmd.demangle(&arch, &name, view) {
                    Ok((type_, name)) => {
                        *out_type = match type_ {
                            Some(t) => RefCountable::inc_ref(t.as_ref()).handle,
                            None => std::ptr::null_mut()
                        };
                        // TODO: Need to have a better way for api-owned QNames
                        (*out_var_name).nameCount = name.0.nameCount;
                        (*out_var_name).join = BNAllocString(name.0.join);
                        (*out_var_name).name = BNAllocStringList(name.0.name as *mut *const _, name.0.nameCount);
                        true
                    },
                    Err(_) => {
                        false
                    }
                }
            })
        }
        extern "C" fn cb_free_var_name<C>(_ctxt: *mut c_void, name: *mut BNQualifiedName)
        where
            C: CustomDemangler,
        {
            ffi_wrap!("CustomDemangler::cb_free_var_name", unsafe {
                BNFreeString((*name).join);
                BNFreeStringList((*name).name, (*name).nameCount);
            })
        }

        let name = name.into_bytes_with_nul();
        let name_ptr = name.as_ref().as_ptr() as *mut _;
        let ctxt = Box::into_raw(Box::new(callbacks));

        let callbacks = BNDemanglerCallbacks {
            context: ctxt as *mut c_void,
            isMangledString: Some(cb_is_mangled_string::<C>),
            demangle: Some(cb_demangle::<C>),
            freeVarName: Some(cb_free_var_name::<C>),
        };

        unsafe {
            Demangler::from_raw(BNRegisterDemangler(
                name_ptr,
                Box::leak(Box::new(callbacks)),
            ))
        }
    }

    pub fn promote(demangler: &Demangler) {
        unsafe { BNPromoteDemangler(demangler.handle); }
    }
}

unsafe impl Sync for Demangler {}

unsafe impl Send for Demangler {}

impl CoreArrayProvider for Demangler {
    type Raw = *mut BNDemangler;
    type Context = ();
    type Wrapped<'a> = Demangler;
}

unsafe impl CoreArrayProviderInner for Demangler {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeDemanglerList(raw);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Demangler::from_raw(*raw)
    }
}

pub trait CustomDemangler: 'static + Sync {
    fn is_mangled_string(&self, name: &str) -> bool;

    fn demangle(
        &self,
        arch: &CoreArchitecture,
        name: &str,
        view: Option<Ref<BinaryView>>,
    ) -> Result<(Option<Ref<Type>>, QualifiedName)>;
}
