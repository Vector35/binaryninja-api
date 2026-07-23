// Copyright 2022-2026 Vector 35 Inc.
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
use std::ptr;

use crate::architecture::{ArchitectureExt, CoreArchitecture};
use crate::binary_view::BinaryView;
use crate::platform::Platform;
use crate::qualified_name::QualifiedName;
use crate::rc::*;
use crate::string::{raw_to_string, BnString, IntoCStr};
use crate::types::Type;

pub type Result<R> = std::result::Result<R, ()>;

fn msvc_demangler() -> *mut BNDemangler {
    unsafe { BNGetMSVCDemangler() }
}

fn gnu3_demangler() -> *mut BNDemangler {
    unsafe { BNGetGNU3Demangler() }
}

fn llvm_demangler() -> *mut BNDemangler {
    unsafe { BNGetLLVMDemangler() }
}

/// Platform, view, and simplification options used by demangler APIs.
#[derive(Clone, Debug)]
pub struct DemanglerConfig {
    pub platform: Option<Ref<Platform>>,
    pub view: Option<Ref<BinaryView>>,
    pub simplify_templates: bool,
}

impl Default for DemanglerConfig {
    fn default() -> Self {
        let config = unsafe { BNGetDefaultDemanglerConfig() };
        Self::from_api_object(&config)
    }
}

impl DemanglerConfig {
    pub fn for_platform(platform: &Platform, simplify_templates: bool) -> Self {
        let config =
            unsafe { BNGetDemanglerConfigForPlatform(platform.handle, simplify_templates) };
        Self::from_api_object(&config)
    }

    pub fn for_binary_view(view: &BinaryView) -> Self {
        let config = unsafe { BNGetDemanglerConfigForBinaryView(view.handle) };
        Self::from_api_object(&config)
    }

    pub(crate) fn from_api_object(config: &BNDemanglerConfig) -> Self {
        let platform = match config.platform.is_null() {
            true => None,
            false => {
                Some(unsafe { Platform::ref_from_raw(BNNewPlatformReference(config.platform)) })
            }
        };
        let view = match config.view.is_null() {
            true => None,
            false => Some(unsafe { BinaryView::ref_from_raw(BNNewViewReference(config.view)) }),
        };
        Self {
            platform,
            view,
            simplify_templates: config.simplifyTemplates,
        }
    }

    pub fn get_platform(&self) -> Ref<Platform> {
        self.platform
            .clone()
            .or_else(|| Self::default().platform)
            .expect("default demangler config has no platform")
    }

    pub(crate) fn to_api_object(&self) -> BNDemanglerConfig {
        let platform = self.get_platform();
        BNDemanglerConfig {
            platform: platform.handle,
            view: self
                .view
                .as_ref()
                .map(|view| view.handle)
                .unwrap_or(ptr::null_mut()),
            simplifyTemplates: self.simplify_templates,
        }
    }
}

/// Demangled name and optional type recovered from a mangled name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DemanglerResult {
    pub name: QualifiedName,
    pub ty: Option<Ref<Type>>,
}

/// Compatibility alias matching the Python API name.
pub type DemangleResult = DemanglerResult;

impl DemanglerResult {
    pub fn new(name: impl Into<QualifiedName>, ty: Option<Ref<Type>>) -> Self {
        Self {
            name: name.into(),
            ty,
        }
    }

    pub(crate) fn from_api_object(result: &BNDemanglerResult) -> Self {
        let ty = match result.type_.is_null() {
            true => None,
            // The source result remains independently owned and is freed by the caller.
            false => Some(unsafe { Type::ref_from_raw(BNNewTypeReference(result.type_)) }),
        };
        Self {
            name: QualifiedName::from_raw(&result.name),
            ty,
        }
    }

    pub(crate) fn from_api_object_and_free(result: &mut BNDemanglerResult) -> Self {
        let demangler_result = Self::from_api_object(result);
        unsafe { BNFreeDemanglerResult(result) };
        demangler_result
    }

    pub(crate) fn to_api_object(&self) -> BNDemanglerResult {
        BNDemanglerResult {
            name: QualifiedName::into_raw(self.name.clone()),
            type_: self
                .ty
                .as_ref()
                .map(|ty| unsafe { BNNewTypeReference(ty.handle) })
                .unwrap_or(ptr::null_mut()),
        }
    }

    pub fn into_tuple(self) -> (QualifiedName, Option<Ref<Type>>) {
        (self.name, self.ty)
    }
}

impl From<(QualifiedName, Option<Ref<Type>>)> for DemanglerResult {
    fn from(value: (QualifiedName, Option<Ref<Type>>)) -> Self {
        Self {
            name: value.0,
            ty: value.1,
        }
    }
}

impl From<DemanglerResult> for (QualifiedName, Option<Ref<Type>>) {
    fn from(value: DemanglerResult) -> Self {
        value.into_tuple()
    }
}

fn collect_demangler_result(res: bool, result: &mut BNDemanglerResult) -> Option<DemanglerResult> {
    match res {
        true => Some(DemanglerResult::from_api_object_and_free(result)),
        false => None,
    }
}

fn demangle_with_demangler(
    demangler: *mut BNDemangler,
    mangled_name: &str,
    config: &DemanglerConfig,
) -> Option<DemanglerResult> {
    if demangler.is_null() {
        return None;
    }

    let mangled_name = mangled_name.to_cstr();
    let api_config = config.to_api_object();
    let mut result = BNDemanglerResult::default();
    let res = unsafe {
        BNDemangleWithDemangler(demangler, mangled_name.as_ptr(), &api_config, &mut result)
    };
    collect_demangler_result(res, &mut result)
}

pub fn demangle_any(mangled_name: &str, config: &DemanglerConfig) -> Option<DemanglerResult> {
    let mangled_name = mangled_name.to_cstr();
    let api_config = config.to_api_object();
    let mut result = BNDemanglerResult::default();
    let res = unsafe { BNDemangle(mangled_name.as_ptr(), &api_config, &mut result) };
    collect_demangler_result(res, &mut result)
}

pub fn demangle_generic(
    arch: &CoreArchitecture,
    mangled_name: &str,
    view: Option<&BinaryView>,
    simplify: bool,
) -> Option<DemanglerResult> {
    let mut config = match view {
        Some(view) => DemanglerConfig::for_binary_view(view),
        None => match arch.standalone_platform() {
            Some(platform) => DemanglerConfig::for_platform(&platform, simplify),
            None => DemanglerConfig::default(),
        },
    };
    config.simplify_templates = simplify;
    demangle_any(mangled_name, &config)
}

pub fn demangle_llvm(mangled_name: &str, simplify: bool) -> Option<DemanglerResult> {
    let config = DemanglerConfig {
        simplify_templates: simplify,
        ..DemanglerConfig::default()
    };
    demangle_llvm_with_config(mangled_name, &config)
}

pub fn demangle_llvm_with_config(
    mangled_name: &str,
    config: &DemanglerConfig,
) -> Option<DemanglerResult> {
    demangle_with_demangler(llvm_demangler(), mangled_name, config)
}

pub fn demangle_gnu3(
    arch: &CoreArchitecture,
    mangled_name: &str,
    simplify: bool,
) -> Option<DemanglerResult> {
    let mut config = arch
        .standalone_platform()
        .map(|platform| DemanglerConfig::for_platform(&platform, simplify))
        .unwrap_or_default();
    config.simplify_templates = simplify;
    demangle_gnu3_with_config(mangled_name, &config)
}

pub fn demangle_gnu3_with_config(
    mangled_name: &str,
    config: &DemanglerConfig,
) -> Option<DemanglerResult> {
    demangle_with_demangler(gnu3_demangler(), mangled_name, config)
}

pub fn demangle_ms(
    arch: &CoreArchitecture,
    mangled_name: &str,
    simplify: bool,
) -> Option<DemanglerResult> {
    let mut config = arch
        .standalone_platform()
        .map(|platform| DemanglerConfig::for_platform(&platform, simplify))
        .unwrap_or_default();
    config.simplify_templates = simplify;
    demangle_ms_with_config(mangled_name, &config)
}

pub fn demangle_ms_with_config(
    mangled_name: &str,
    config: &DemanglerConfig,
) -> Option<DemanglerResult> {
    demangle_with_demangler(msvc_demangler(), mangled_name, config)
}

pub fn simplify_demangled_template_name(name: impl Into<QualifiedName>) -> QualifiedName {
    let name = name.into();
    let raw_name = QualifiedName::into_raw(name.clone());
    let mut result = BNQualifiedName::default();
    let ok = unsafe { BNSimplifyDemangledTemplateName(&raw_name, &mut result) };
    QualifiedName::free_raw(raw_name);
    if ok {
        QualifiedName::from_owned_raw(result)
    } else {
        name
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

    pub fn is_mangled_string(&self, name: &str) -> bool {
        let bytes = name.to_cstr();
        unsafe { BNIsDemanglerMangledName(self.handle, bytes.as_ref().as_ptr() as *const _) }
    }

    pub fn demangle(&self, name: &str, config: &DemanglerConfig) -> Option<DemanglerResult> {
        demangle_with_demangler(self.handle, name, config)
    }

    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNGetDemanglerName(self.handle)) }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        let name_bytes = name.to_cstr();
        let demangler = unsafe { BNGetDemanglerByName(name_bytes.as_ref().as_ptr() as *const _) };
        if demangler.is_null() {
            None
        } else {
            Some(unsafe { Demangler::from_raw(demangler) })
        }
    }

    pub fn register<C: CustomDemangler>(name: &str, demangler: C) -> bool {
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
            name: *const c_char,
            config: *const BNDemanglerConfig,
            result: *mut BNDemanglerResult,
        ) -> bool
        where
            C: CustomDemangler,
        {
            ffi_wrap!("CustomDemangler::cb_demangle", unsafe {
                if result.is_null() {
                    return false;
                }

                let cmd = &*(ctxt as *const C);
                let Some(name) = raw_to_string(name) else {
                    return false;
                };
                let config = match config.as_ref() {
                    Some(config) => DemanglerConfig::from_api_object(config),
                    None => DemanglerConfig::default(),
                };

                match cmd.demangle(&name, &config) {
                    Some(demangle_result) => {
                        *result = demangle_result.to_api_object();
                        true
                    }
                    None => false,
                }
            })
        }

        extern "C" fn cb_free_result(_ctxt: *mut c_void, result: *mut BNDemanglerResult) {
            ffi_wrap!("CustomDemangler::cb_free_result", unsafe {
                if !result.is_null() {
                    BNFreeDemanglerResult(result);
                }
            })
        }

        let name = name.to_cstr();
        let name_ptr = name.as_ptr();
        let ctxt = Box::into_raw(Box::new(demangler));

        let callbacks = Box::into_raw(Box::new(BNDemanglerCallbacks {
            context: ctxt as *mut c_void,
            isMangledString: Some(cb_is_mangled_string::<C>),
            demangle: Some(cb_demangle::<C>),
            freeResult: Some(cb_free_result),
        }));

        let handle = unsafe { BNRegisterDemangler(name_ptr, callbacks) };
        if handle.is_null() {
            unsafe {
                drop(Box::from_raw(ctxt));
                drop(Box::from_raw(callbacks));
            }
            false
        } else {
            true
        }
    }

    pub fn demangle_any(name: &str, config: &DemanglerConfig) -> Option<DemanglerResult> {
        demangle_any(name, config)
    }

    pub fn promote(demangler: &Demangler) -> bool {
        if demangler.handle.is_null() {
            return false;
        }
        unsafe { BNPromoteDemangler(demangler.handle) }
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

    fn demangle(&self, name: &str, config: &DemanglerConfig) -> Option<DemanglerResult>;
}
