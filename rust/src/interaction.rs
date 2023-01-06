// Copyright 2022-2023 Vector 35 Inc.
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

//! Interfaces for asking the user for information: forms, opening files, etc.

use binaryninjacore_sys::*;

use std::ffi::CString;
use std::os::raw::c_void;
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

pub type MessageBoxButtonSet = BNMessageBoxButtonSet;
pub type MessageBoxIcon = BNMessageBoxIcon;
pub type MessageBoxButtonResult = BNMessageBoxButtonResult;
pub fn show_message_box(
    title: &str,
    text: &str,
    buttons: MessageBoxButtonSet,
    icon: MessageBoxIcon,
) -> MessageBoxButtonResult {
    let title = CString::new(title).unwrap();
    let text = CString::new(text).unwrap();

    unsafe { BNShowMessageBox(title.as_ptr(), text.as_ptr(), buttons, icon) }
}

struct TaskContext<F: Fn(Box<dyn Fn(usize, usize) -> Result<(), ()>>)>(F);

pub fn run_progress_dialog<F: Fn(Box<dyn Fn(usize, usize) -> Result<(), ()>>)>(
    title: &str,
    can_cancel: bool,
    task: F,
) -> Result<(), ()> {
    let title = CString::new(title).unwrap();

    let mut ctxt = TaskContext::<F>(task);

    unsafe extern "C" fn cb_task<F: Fn(Box<dyn Fn(usize, usize) -> Result<(), ()>>)>(
        ctxt: *mut c_void,
        progress: Option<unsafe extern "C" fn(*mut c_void, usize, usize) -> bool>,
        progress_ctxt: *mut c_void,
    ) {
        ffi_wrap!("run_progress_dialog", {
            let context = ctxt as *mut TaskContext<F>;
            let progress_fn = Box::new(move |cur: usize, max: usize| -> Result<(), ()> {
                match progress {
                    Some(func) => {
                        if (func)(progress_ctxt, cur, max) {
                            Ok(())
                        } else {
                            Err(())
                        }
                    }
                    None => Ok(()),
                }
            });
            ((*context).0)(progress_fn);
        })
    }

    if unsafe {
        BNRunProgressDialog(
            title.as_ptr(),
            can_cancel,
            Some(cb_task::<F>),
            &mut ctxt as *mut _ as *mut c_void,
        )
    } {
        Ok(())
    } else {
        Err(())
    }
}
