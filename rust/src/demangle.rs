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
use std::ffi::{c_char, c_void};

use crate::architecture::CoreArchitecture;
use crate::binary_view::BinaryView;
use crate::string::{raw_to_string, BnStrCompatible, BnString};
use crate::types::{QualifiedName, Type};

use crate::rc::*;

pub type Result<R> = std::result::Result<R, ()>;

pub fn demangle_generic<S: BnStrCompatible>(
    arch: &CoreArchitecture,
    mangled_name: S,
    view: Option<&BinaryView>,
    simplify: bool,
) -> Option<(QualifiedName, Option<Ref<Type>>)> {
    let mangled_name_bwn = mangled_name.into_bytes_with_nul();
    let mangled_name_ptr = mangled_name_bwn.as_ref();
    let mut out_type: *mut BNType = std::ptr::null_mut();
    let mut out_name = BNQualifiedName::default();
    let res = unsafe {
        BNDemangleGeneric(
            arch.handle,
            mangled_name_ptr.as_ptr() as *const c_char,
            &mut out_type,
            &mut out_name,
            view.map(|v| v.handle).unwrap_or(std::ptr::null_mut()),
            simplify,
        )
    };

    if res {
        let out_type = match out_type.is_null() {
            true => None,
            false => Some(unsafe { Type::ref_from_raw(out_type) }),
        };
        Some((QualifiedName::from_owned_raw(out_name), out_type))
    } else {
        None
    }
}

pub fn demangle_llvm<S: BnStrCompatible>(mangled_name: S, simplify: bool) -> Option<QualifiedName> {
    let mangled_name_bwn = mangled_name.into_bytes_with_nul();
    let mangled_name_ptr = mangled_name_bwn.as_ref();
    let mut out_name: *mut *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut out_size: usize = 0;
    let res = unsafe {
        BNDemangleLLVM(
            mangled_name_ptr.as_ptr() as *const c_char,
            &mut out_name,
            &mut out_size,
            simplify,
        )
    };

    match res {
        true => {
            assert!(!out_name.is_null());
            let names: Vec<_> = unsafe { ArrayGuard::<BnString>::new(out_name, out_size, ()) }
                .iter()
                .map(str::to_string)
                .collect();
            unsafe { BNFreeDemangledName(&mut out_name, out_size) };

            Some(names.into())
        }
        false => None,
    }
}

pub fn demangle_gnu3<S: BnStrCompatible>(
    arch: &CoreArchitecture,
    mangled_name: S,
    simplify: bool,
) -> Option<(QualifiedName, Option<Ref<Type>>)> {
    let mangled_name_bwn = mangled_name.into_bytes_with_nul();
    let mangled_name_ptr = mangled_name_bwn.as_ref();
    let mut out_type: *mut BNType = std::ptr::null_mut();
    let mut out_name: *mut *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut out_size: usize = 0;
    let res = unsafe {
        BNDemangleGNU3(
            arch.handle,
            mangled_name_ptr.as_ptr() as *const c_char,
            &mut out_type,
            &mut out_name,
            &mut out_size,
            simplify,
        )
    };

    match res {
        true => {
            assert!(!out_name.is_null());
            let names: Vec<_> = unsafe { ArrayGuard::<BnString>::new(out_name, out_size, ()) }
                .iter()
                .map(str::to_string)
                .collect();
            unsafe { BNFreeDemangledName(&mut out_name, out_size) };

            let out_type = match out_type.is_null() {
                true => None,
                false => Some(unsafe { Type::ref_from_raw(out_type) }),
            };

            Some((names.into(), out_type))
        }
        false => None,
    }
}

pub fn demangle_ms<S: BnStrCompatible>(
    arch: &CoreArchitecture,
    mangled_name: S,
    simplify: bool,
) -> Option<(QualifiedName, Option<Ref<Type>>)> {
    let mangled_name_bwn = mangled_name.into_bytes_with_nul();
    let mangled_name_ptr = mangled_name_bwn.as_ref();

    let mut out_type: *mut BNType = std::ptr::null_mut();
    let mut out_name: *mut *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut out_size: usize = 0;
    let res = unsafe {
        BNDemangleMS(
            arch.handle,
            mangled_name_ptr.as_ptr() as *const c_char,
            &mut out_type,
            &mut out_name,
            &mut out_size,
            simplify,
        )
    };

    match res {
        true => {
            assert!(!out_name.is_null());
            let names: Vec<_> = unsafe { ArrayGuard::<BnString>::new(out_name, out_size, ()) }
                .iter()
                .map(str::to_string)
                .collect();
            unsafe { BNFreeDemangledName(&mut out_name, out_size) };

            let out_type = match out_type.is_null() {
                true => None,
                false => Some(unsafe { Type::ref_from_raw(out_type) }),
            };

            Some((names.into(), out_type))
        }
        false => None,
    }
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

    pub fn list() -> Array<Self> {
        let mut count: usize = 0;
        let demanglers = unsafe { BNGetDemanglerList(&mut count) };
        unsafe { Array::<Demangler>::new(demanglers, count, ()) }
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
    ) -> Option<(QualifiedName, Option<Ref<Type>>)> {
        let name_bytes = name.into_bytes_with_nul();

        let mut out_type = std::ptr::null_mut();
        let mut out_var_name = BNQualifiedName::default();

        let view_ptr = match view {
            Some(v) => v.handle,
            None => std::ptr::null_mut(),
        };

        let res = unsafe {
            BNDemanglerDemangle(
                self.handle,
                arch.handle,
                name_bytes.as_ref().as_ptr() as *const _,
                &mut out_type,
                &mut out_var_name,
                view_ptr,
            )
        };

        match res {
            true => {
                let var_type = match out_type.is_null() {
                    true => None,
                    false => Some(unsafe { Type::ref_from_raw(out_type) }),
                };

                Some((QualifiedName::from_owned_raw(out_var_name), var_type))
            }
            false => None,
        }
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

    pub fn register<S, C>(name: S, demangler: C) -> Self
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
                let Some(name) = raw_to_string(name) else {
                    return false;
                };
                cmd.is_mangled_string(&name)
            })
        }
        extern "C" fn cb_demangle<C>(
            ctxt: *mut c_void,
            arch: *mut BNArchitecture,
            name: *const c_char,
            out_type: *mut *mut BNType,
            out_var_name: *mut BNQualifiedName,
            view: *mut BNBinaryView,
        ) -> bool
        where
            C: CustomDemangler,
        {
            ffi_wrap!("CustomDemangler::cb_demangle", unsafe {
                let cmd = &*(ctxt as *const C);
                let arch = CoreArchitecture::from_raw(arch);
                let Some(name) = raw_to_string(name) else {
                    return false;
                };
                let view = match view.is_null() {
                    false => Some(BinaryView::from_raw(view).to_owned()),
                    true => None,
                };

                match cmd.demangle(&arch, &name, view) {
                    Some((name, ty)) => {
                        // NOTE: Leaked to the caller, who must pick the ref up.
                        *out_type = match ty {
                            Some(t) => Ref::into_raw(t).handle,
                            None => std::ptr::null_mut(),
                        };
                        // NOTE: Leaked to be freed with `cb_free_var_name`.
                        *out_var_name = QualifiedName::into_raw(name);
                        true
                    }
                    None => false,
                }
            })
        }

        extern "C" fn cb_free_var_name(_ctxt: *mut c_void, name: *mut BNQualifiedName) {
            ffi_wrap!("CustomDemangler::cb_free_var_name", unsafe {
                // TODO: What is the point of this free callback?
                QualifiedName::free_raw(*name)
            })
        }

        let name = name.into_bytes_with_nul();
        let name_ptr = name.as_ref().as_ptr() as *mut _;
        let ctxt = Box::into_raw(Box::new(demangler));

        let callbacks = BNDemanglerCallbacks {
            context: ctxt as *mut c_void,
            isMangledString: Some(cb_is_mangled_string::<C>),
            demangle: Some(cb_demangle::<C>),
            freeVarName: Some(cb_free_var_name),
        };

        unsafe {
            Demangler::from_raw(BNRegisterDemangler(
                name_ptr,
                Box::leak(Box::new(callbacks)),
            ))
        }
    }

    pub fn promote(demangler: &Demangler) {
        unsafe {
            BNPromoteDemangler(demangler.handle);
        }
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
    ) -> Option<(QualifiedName, Option<Ref<Type>>)>;
}
