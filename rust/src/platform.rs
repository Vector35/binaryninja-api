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

use std::{borrow::Borrow, ffi, ptr};

use binaryninjacore_sys::*;

use crate::{
    architecture::{Architecture, CoreArchitecture},
    callingconvention::CallingConvention,
    rc::*,
    string::*,
    typeparser::{TypeParserError, TypeParserErrorSeverity, TypeParserResult},
    types::QualifiedNameAndType,
};

#[derive(PartialEq, Eq, Hash)]
pub struct Platform {
    pub(crate) handle: *mut BNPlatform,
}

unsafe impl Send for Platform {}
unsafe impl Sync for Platform {}

macro_rules! cc_func {
    ($get_name:ident, $get_api:ident, $set_name:ident, $set_api:ident) => {
        pub fn $get_name(&self) -> Option<Ref<CallingConvention<CoreArchitecture>>> {
            let arch = self.arch();

            unsafe {
                let cc = $get_api(self.handle);

                if cc.is_null() {
                    None
                } else {
                    Some(CallingConvention::ref_from_raw(cc, arch))
                }
            }
        }

        pub fn $set_name<A: Architecture>(&self, cc: &CallingConvention<A>) {
            let arch = self.arch();

            assert!(
                cc.arch_handle.borrow().as_ref().0 == arch.0,
                "use of calling convention with non-matching Platform architecture!"
            );

            unsafe {
                $set_api(self.handle, cc.handle);
            }
        }
    };
}

impl Platform {
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
                Some(Ref::new(Self { handle: res }))
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
            let handles = BNGetPlatformListByArchitecture(arch.0, &mut count);

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
                arch.0,
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
            let handle = BNCreatePlatform(arch.as_ref().0, name.as_ref().as_ptr() as *mut _);

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

    pub fn calling_conventions(&self) -> Array<CallingConvention<CoreArchitecture>> {
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
                unsafe { BnString::from_raw(error_string) },
                file_name,
                0,
                0,
            ))
        }
    }

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

        let mut result = BNTypeParserResult::default();
        let mut error_string = ptr::null_mut();
        let success = unsafe {
            BNParseTypesFromSource(
                self.handle,
                source_cstr.as_ptr(),
                file_name_cstr.as_ptr(),
                &mut result,
                &mut error_string,
                include_dirs.as_ptr() as *mut *const ffi::c_char,
                include_dirs.len(),
                auto_type_source.as_ptr(),
            )
        };

        if success {
            Ok(unsafe { TypeParserResult::from_raw(result) })
        } else {
            assert!(!error_string.is_null());
            Err(TypeParserError::new(
                TypeParserErrorSeverity::FatalSeverity,
                unsafe { BnString::from_raw(error_string) },
                filename,
                0,
                0,
            ))
        }
    }

    pub fn parse_types_from_source_file(
        &self,
        filename: &str,
        include_dirs: &[BnString],
        auto_type_source: &str,
    ) -> Result<TypeParserResult, TypeParserError> {
        let file_name_cstr = BnString::new(filename);
        let auto_type_source = BnString::new(auto_type_source);

        let mut result = BNTypeParserResult::default();
        let mut error_string = ptr::null_mut();
        let success = unsafe {
            BNParseTypesFromSourceFile(
                self.handle,
                file_name_cstr.as_ptr(),
                &mut result,
                &mut error_string,
                include_dirs.as_ptr() as *mut *const ffi::c_char,
                include_dirs.len(),
                auto_type_source.as_ptr(),
            )
        };

        if success {
            Ok(unsafe { TypeParserResult::from_raw(result) })
        } else {
            assert!(!error_string.is_null());
            Err(TypeParserError::new(
                TypeParserErrorSeverity::FatalSeverity,
                unsafe { BnString::from_raw(error_string) },
                filename,
                0,
                0,
            ))
        }
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
    unsafe fn free(raw: *mut *mut BNPlatform, count: usize, _context: &()) {
        BNFreePlatformList(raw, count);
    }
    unsafe fn wrap_raw<'a>(raw: &'a *mut BNPlatform, context: &'a ()) -> Self::Wrapped<'a> {
        debug_assert!(!raw.is_null());
        Guard::new(Platform { handle: *raw }, context)
    }
}
