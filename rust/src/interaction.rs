use binaryninjacore_sys::*;

use std::ffi::CString;
use std::path::PathBuf;

use crate::string::BnString;

pub fn get_text_line_input(prompt: &str, title: &str) -> Option<String> {
    let prompt = CString::new(prompt).unwrap();
    let title = CString::new(title).unwrap();
    let mut value: *mut libc::c_char = std::ptr::null_mut();

    let result = unsafe { BNGetTextLineInput(&mut value, prompt.into_raw(), title.into_raw()) };
    if !result {
        return None;
    }

    Some(unsafe { BnString::from_raw(value).to_string() })
}

pub fn get_integer_input(prompt: &str, title: &str) -> Option<i64> {
    let prompt = CString::new(prompt).unwrap();
    let title = CString::new(title).unwrap();
    let mut value: i64 = 0;

    let result = unsafe { BNGetIntegerInput(&mut value, prompt.into_raw(), title.into_raw()) };

    if !result {
        return None;
    }

    Some(value)
}

pub fn get_address_input(prompt: &str, title: &str) -> Option<u64> {
    let prompt = CString::new(prompt).unwrap();
    let title = CString::new(title).unwrap();
    let mut value: u64 = 0;

    let result = unsafe {
        BNGetAddressInput(
            &mut value,
            prompt.into_raw(),
            title.into_raw(),
            std::ptr::null_mut(),
            0,
        )
    };

    if !result {
        return None;
    }

    Some(value)
}

pub fn get_open_filename_input(prompt: &str, extension: &str) -> Option<PathBuf> {
    let prompt = CString::new(prompt).unwrap();
    let extension = CString::new(extension).unwrap();
    let mut value: *mut libc::c_char = std::ptr::null_mut();

    let result =
        unsafe { BNGetOpenFileNameInput(&mut value, prompt.into_raw(), extension.into_raw()) };
    if !result {
        return None;
    }

    let string = unsafe { BnString::from_raw(value) };
    Some(PathBuf::from(string.as_str()))
}

pub fn get_save_filename_input(prompt: &str, title: &str, default_name: &str) -> Option<PathBuf> {
    let prompt = CString::new(prompt).unwrap();
    let title = CString::new(title).unwrap();
    let default_name = CString::new(default_name).unwrap();
    let mut value: *mut libc::c_char = std::ptr::null_mut();

    let result = unsafe {
        BNGetSaveFileNameInput(
            &mut value,
            prompt.into_raw(),
            title.into_raw(),
            default_name.into_raw(),
        )
    };
    if !result {
        return None;
    }

    let string = unsafe { BnString::from_raw(value) };
    Some(PathBuf::from(string.as_str()))
}

pub fn get_directory_name_input(prompt: &str, default_name: &str) -> Option<PathBuf> {
    let prompt = CString::new(prompt).unwrap();
    let default_name = CString::new(default_name).unwrap();
    let mut value: *mut libc::c_char = std::ptr::null_mut();

    let result =
        unsafe { BNGetDirectoryNameInput(&mut value, prompt.into_raw(), default_name.into_raw()) };
    if !result {
        return None;
    }

    let string = unsafe { BnString::from_raw(value) };
    Some(PathBuf::from(string.as_str()))
}
