// Copyright 2021-2024 Vector 35 Inc.
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

//! Contains all information related to the execution environment of the binary, mainly the calling conventions used

use crate::type_container::TypeContainer;
use crate::type_parser::{TypeParserError, TypeParserErrorSeverity, TypeParserResult};
use crate::{
    architecture::{Architecture, CoreArchitecture},
    calling_convention::CoreCallingConvention,
    rc::*,
    string::*,
    type_library::TypeLibrary,
    types::QualifiedNameAndType,
};
use binaryninjacore_sys::*;
use std::fmt::Debug;
use std::ptr::NonNull;
use std::{borrow::Borrow, ffi, ptr};

#[derive(PartialEq, Eq, Hash)]
pub struct Platform {
    pub(crate) handle: *mut BNPlatform,
}

unsafe impl Send for Platform {}
unsafe impl Sync for Platform {}

macro_rules! cc_func {
    ($get_name:ident, $get_api:ident, $set_name:ident, $set_api:ident) => {
        pub fn $get_name(&self) -> Option<Ref<CoreCallingConvention>> {
            let arch = self.arch();

            unsafe {
                let cc = $get_api(self.handle);

                if cc.is_null() {
                    None
                } else {
                    Some(CoreCallingConvention::ref_from_raw(
                        cc,
                        arch.as_ref().handle(),
                    ))
                }
            }
        }

        pub fn $set_name(&self, cc: &CoreCallingConvention) {
            let arch = self.arch();

            assert!(
                cc.arch_handle.borrow().as_ref().handle == arch.handle,
                "use of calling convention with non-matching Platform architecture!"
            );

            unsafe {
                $set_api(self.handle, cc.handle);
            }
        }
    };
}

impl Platform {
    pub(crate) unsafe fn from_raw(handle: *mut BNPlatform) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNPlatform) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn by_name<S: BnStrCompatible>(name: S) -> Option<Ref<Self>> {
        let raw_name = name.into_bytes_with_nul();
        unsafe {
            let res = BNGetPlatformByName(raw_name.as_ref().as_ptr() as *mut _);

            if res.is_null() {
                None
            } else {
                Some(Self::ref_from_raw(res))
            }
        }
    }

    pub fn list_all() -> Array<Platform> {
        unsafe {
            let mut count = 0;
            let handles = BNGetPlatformList(&mut count);

            Array::new(handles, count, ())
        }
    }

    pub fn list_by_arch(arch: &CoreArchitecture) -> Array<Platform> {
        unsafe {
            let mut count = 0;
            let handles = BNGetPlatformListByArchitecture(arch.handle, &mut count);

            Array::new(handles, count, ())
        }
    }

    pub fn list_by_os<S: BnStrCompatible>(name: S) -> Array<Platform> {
        let raw_name = name.into_bytes_with_nul();

        unsafe {
            let mut count = 0;
            let handles = BNGetPlatformListByOS(raw_name.as_ref().as_ptr() as *mut _, &mut count);

            Array::new(handles, count, ())
        }
    }

    pub fn list_by_os_and_arch<S: BnStrCompatible>(
        name: S,
        arch: &CoreArchitecture,
    ) -> Array<Platform> {
        let raw_name = name.into_bytes_with_nul();

        unsafe {
            let mut count = 0;
            let handles = BNGetPlatformListByOSAndArchitecture(
                raw_name.as_ref().as_ptr() as *mut _,
                arch.handle,
                &mut count,
            );

            Array::new(handles, count, ())
        }
    }

    pub fn list_available_os() -> Array<BnString> {
        unsafe {
            let mut count = 0;
            let list = BNGetPlatformOSList(&mut count);

            Array::new(list, count, ())
        }
    }

    pub fn new<A: Architecture, S: BnStrCompatible>(arch: &A, name: S) -> Ref<Self> {
        let name = name.into_bytes_with_nul();
        unsafe {
            let handle = BNCreatePlatform(arch.as_ref().handle, name.as_ref().as_ptr() as *mut _);
            assert!(!handle.is_null());
            Ref::new(Self { handle })
        }
    }

    pub fn name(&self) -> BnString {
        unsafe {
            let raw_name = BNGetPlatformName(self.handle);
            BnString::from_raw(raw_name)
        }
    }

    pub fn arch(&self) -> CoreArchitecture {
        unsafe { CoreArchitecture::from_raw(BNGetPlatformArchitecture(self.handle)) }
    }

    pub fn type_container(&self) -> TypeContainer {
        let type_container_ptr = NonNull::new(unsafe { BNGetPlatformTypeContainer(self.handle) });
        // NOTE: I have no idea how this isn't a UAF, see the note in `TypeContainer::from_raw`
        // TODO: We are cloning here for platforms but we dont need to do this for [BinaryViewExt::type_container]
        // TODO: Why does this require that we, construct a TypeContainer, duplicate the type container, then drop the original.
        unsafe { TypeContainer::from_raw(type_container_ptr.unwrap()) }
    }

    pub fn get_type_libraries_by_name<T: BnStrCompatible>(&self, name: T) -> Array<TypeLibrary> {
        let mut count = 0;
        let name = name.into_bytes_with_nul();
        let result = unsafe {
            BNGetPlatformTypeLibrariesByName(
                self.handle,
                name.as_ref().as_ptr() as *mut _,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn register_os<S: BnStrCompatible>(&self, os: S) {
        let os = os.into_bytes_with_nul();

        unsafe {
            BNRegisterPlatform(os.as_ref().as_ptr() as *mut _, self.handle);
        }
    }

    cc_func!(
        get_default_calling_convention,
        BNGetPlatformDefaultCallingConvention,
        set_default_calling_convention,
        BNRegisterPlatformDefaultCallingConvention
    );

    cc_func!(
        get_cdecl_calling_convention,
        BNGetPlatformCdeclCallingConvention,
        set_cdecl_calling_convention,
        BNRegisterPlatformCdeclCallingConvention
    );

    cc_func!(
        get_stdcall_calling_convention,
        BNGetPlatformStdcallCallingConvention,
        set_stdcall_calling_convention,
        BNRegisterPlatformStdcallCallingConvention
    );

    cc_func!(
        get_fastcall_calling_convention,
        BNGetPlatformFastcallCallingConvention,
        set_fastcall_calling_convention,
        BNRegisterPlatformFastcallCallingConvention
    );

    cc_func!(
        get_syscall_convention,
        BNGetPlatformSystemCallConvention,
        set_syscall_convention,
        BNSetPlatformSystemCallConvention
    );

    pub fn calling_conventions(&self) -> Array<CoreCallingConvention> {
        unsafe {
            let mut count = 0;
            let handles = BNGetPlatformCallingConventions(self.handle, &mut count);
            Array::new(handles, count, self.arch())
        }
    }

    pub fn types(&self) -> Array<QualifiedNameAndType> {
        unsafe {
            let mut count = 0;
            let handles = BNGetPlatformTypes(self.handle, &mut count);
            Array::new(handles, count, ())
        }
    }

    pub fn variables(&self) -> Array<QualifiedNameAndType> {
        unsafe {
            let mut count = 0;
            let handles = BNGetPlatformVariables(self.handle, &mut count);
            Array::new(handles, count, ())
        }
    }

    pub fn functions(&self) -> Array<QualifiedNameAndType> {
        unsafe {
            let mut count = 0;
            let handles = BNGetPlatformFunctions(self.handle, &mut count);
            Array::new(handles, count, ())
        }
    }

    // TODO: system_calls
    // TODO: add a helper function to define a system call (platform function with a specific type)

    // TODO: Documentation, specifically how this differs from the TypeParser impl
    pub fn preprocess_source(
        &self,
        source: &str,
        file_name: &str,
        include_dirs: &[BnString],
    ) -> Result<BnString, TypeParserError> {
        let source_cstr = BnString::new(source);
        let file_name_cstr = BnString::new(file_name);

        let mut result = ptr::null_mut();
        let mut error_string = ptr::null_mut();
        let success = unsafe {
            BNPreprocessSource(
                source_cstr.as_ptr(),
                file_name_cstr.as_ptr(),
                &mut result,
                &mut error_string,
                include_dirs.as_ptr() as *mut *const ffi::c_char,
                include_dirs.len(),
            )
        };

        if success {
            assert!(!result.is_null());
            Ok(unsafe { BnString::from_raw(result) })
        } else {
            assert!(!error_string.is_null());
            Err(TypeParserError::new(
                TypeParserErrorSeverity::FatalSeverity,
                unsafe { BnString::from_raw(error_string) }.to_string(),
                file_name.to_string(),
                0,
                0,
            ))
        }
    }

    // TODO: Documentation, specifically how this differs from the TypeParser impl
    pub fn parse_types_from_source(
        &self,
        src: &str,
        filename: &str,
        include_dirs: &[BnString],
        auto_type_source: &str,
    ) -> Result<TypeParserResult, TypeParserError> {
        let source_cstr = BnString::new(src);
        let file_name_cstr = BnString::new(filename);
        let auto_type_source = BnString::new(auto_type_source);

        let mut raw_result = BNTypeParserResult::default();
        let mut error_string = ptr::null_mut();
        let success = unsafe {
            BNParseTypesFromSource(
                self.handle,
                source_cstr.as_ptr(),
                file_name_cstr.as_ptr(),
                &mut raw_result,
                &mut error_string,
                include_dirs.as_ptr() as *mut *const ffi::c_char,
                include_dirs.len(),
                auto_type_source.as_ptr(),
            )
        };

        if success {
            let result = TypeParserResult::from_raw(&raw_result);
            // NOTE: This is safe because the core allocated the TypeParserResult
            TypeParserResult::free_raw(raw_result);
            Ok(result)
        } else {
            assert!(!error_string.is_null());
            Err(TypeParserError::new(
                TypeParserErrorSeverity::FatalSeverity,
                unsafe { BnString::from_raw(error_string) }.to_string(),
                filename.to_string(),
                0,
                0,
            ))
        }
    }

    // TODO: Documentation, specifically how this differs from the TypeParser impl
    pub fn parse_types_from_source_file(
        &self,
        filename: &str,
        include_dirs: &[BnString],
        auto_type_source: &str,
    ) -> Result<TypeParserResult, TypeParserError> {
        let file_name_cstr = BnString::new(filename);
        let auto_type_source = BnString::new(auto_type_source);

        let mut raw_result = BNTypeParserResult::default();
        let mut error_string = ptr::null_mut();
        let success = unsafe {
            BNParseTypesFromSourceFile(
                self.handle,
                file_name_cstr.as_ptr(),
                &mut raw_result,
                &mut error_string,
                include_dirs.as_ptr() as *mut *const ffi::c_char,
                include_dirs.len(),
                auto_type_source.as_ptr(),
            )
        };

        if success {
            let result = TypeParserResult::from_raw(&raw_result);
            // NOTE: This is safe because the core allocated the TypeParserResult
            TypeParserResult::free_raw(raw_result);
            Ok(result)
        } else {
            assert!(!error_string.is_null());
            Err(TypeParserError::new(
                TypeParserErrorSeverity::FatalSeverity,
                unsafe { BnString::from_raw(error_string) }.to_string(),
                filename.to_string(),
                0,
                0,
            ))
        }
    }
}

impl Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Platform")
            .field("name", &self.name())
            .field("arch", &self.arch().name())
            .finish()
    }
}

impl ToOwned for Platform {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Platform {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewPlatformReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreePlatform(handle.handle);
    }
}

impl CoreArrayProvider for Platform {
    type Raw = *mut BNPlatform;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Platform>;
}

unsafe impl CoreArrayProviderInner for Platform {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreePlatformList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        debug_assert!(!raw.is_null());
        Guard::new(Self::from_raw(*raw), context)
    }
}
