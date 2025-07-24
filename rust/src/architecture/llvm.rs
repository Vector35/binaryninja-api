use binaryninjacore_sys::*;
use std::ffi::{c_char, c_int, CString};

#[repr(i32)]
pub enum LlvmServicesDialect {
    Unspecified = 0,
    Att = 1,
    Intel = 2,
}

#[repr(i32)]
pub enum LlvmServicesCodeModel {
    Default = 0,
    Small = 1,
    Kernel = 2,
    Medium = 3,
    Large = 4,
}

#[repr(i32)]
pub enum LlvmServicesRelocMode {
    Static = 0,
    PIC = 1,
    DynamicNoPIC = 2,
}

pub fn llvm_assemble(
    code: &str,
    dialect: LlvmServicesDialect,
    arch_triple: &str,
    code_model: LlvmServicesCodeModel,
    reloc_mode: LlvmServicesRelocMode,
) -> Result<Vec<u8>, String> {
    let code = CString::new(code).map_err(|_| "Invalid encoding in code string".to_string())?;
    let arch_triple = CString::new(arch_triple)
        .map_err(|_| "Invalid encoding in architecture triple string".to_string())?;
    let mut out_bytes: *mut c_char = std::ptr::null_mut();
    let mut out_bytes_len: c_int = 0;
    let mut err_bytes: *mut c_char = std::ptr::null_mut();
    let mut err_len: c_int = 0;

    unsafe {
        BNLlvmServicesInit();
    }

    let result = unsafe {
        BNLlvmServicesAssemble(
            code.as_ptr(),
            dialect as i32,
            arch_triple.as_ptr(),
            code_model as i32,
            reloc_mode as i32,
            &mut out_bytes as *mut *mut c_char,
            &mut out_bytes_len as *mut c_int,
            &mut err_bytes as *mut *mut c_char,
            &mut err_len as *mut c_int,
        )
    };

    let out = if out_bytes_len == 0 {
        Vec::new()
    } else {
        unsafe {
            std::slice::from_raw_parts(
                out_bytes as *const c_char as *const u8,
                out_bytes_len as usize,
            )
        }
        .to_vec()
    };

    let errors = if err_len == 0 {
        "".into()
    } else {
        String::from_utf8_lossy(unsafe {
            std::slice::from_raw_parts(err_bytes as *const c_char as *const u8, err_len as usize)
        })
        .into_owned()
    };

    unsafe {
        BNLlvmServicesAssembleFree(out_bytes, err_bytes);
    }

    if result == 0 {
        Ok(out)
    } else {
        Err(errors)
    }
}
