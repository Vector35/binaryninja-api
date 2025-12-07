//! LLVM functionality exposed by the core.
//!
//! Also see [`crate::demangle::demangle_llvm`].

use binaryninjacore_sys::{
    BNLlvmServicesAssemble, BNLlvmServicesAssembleFree, BNLlvmServicesDisasmInstruction,
    BNLlvmServicesInit,
};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

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
    triplet: &str,
    code_model: LlvmServicesCodeModel,
    reloc_mode: LlvmServicesRelocMode,
) -> Result<Vec<u8>, String> {
    let code = CString::new(code).map_err(|_| "Invalid encoding in code string".to_string())?;
    let arch_triple = CString::new(triplet)
        .map_err(|_| "Invalid encoding in architecture triple string".to_string())?;
    let mut out_bytes: *mut std::ffi::c_char = std::ptr::null_mut();
    let mut out_bytes_len: std::ffi::c_int = 0;
    let mut err_bytes: *mut std::ffi::c_char = std::ptr::null_mut();
    let mut err_len: std::ffi::c_int = 0;

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
            &mut out_bytes as *mut *mut std::ffi::c_char,
            &mut out_bytes_len as *mut std::ffi::c_int,
            &mut err_bytes as *mut *mut std::ffi::c_char,
            &mut err_len as *mut std::ffi::c_int,
        )
    };

    let out = if out_bytes_len == 0 {
        Vec::new()
    } else {
        unsafe {
            std::slice::from_raw_parts(
                out_bytes as *const std::ffi::c_char as *const u8,
                out_bytes_len as usize,
            )
        }
        .to_vec()
    };

    let errors = if err_len == 0 {
        "".into()
    } else {
        String::from_utf8_lossy(unsafe {
            std::slice::from_raw_parts(
                err_bytes as *const std::ffi::c_char as *const u8,
                err_len as usize,
            )
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

pub fn llvm_disassemble(triplet: &str, data: &[u8], address: u64) -> Option<(usize, String)> {
    unsafe {
        let triplet = CString::new(triplet).ok()?;
        let mut src = data.to_vec();
        let mut buf = vec![0u8; 256];
        let instr_len = BNLlvmServicesDisasmInstruction(
            triplet.as_ptr(),
            src.as_mut_ptr(),
            src.len() as c_int,
            address,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        );

        if instr_len > 0 {
            // Convert buf (u8) → &CStr by finding the first NUL
            if let Some(z) = buf.iter().position(|&b| b == 0) {
                let s = CStr::from_bytes_with_nul(&buf[..=z])
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                Some((instr_len as usize, s))
            } else {
                // Callee didn't NULL terminate, return an empty string
                Some((instr_len as usize, String::new()))
            }
        } else {
            None
        }
    }
}
