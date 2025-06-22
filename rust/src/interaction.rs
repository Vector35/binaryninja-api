// Copyright 2022-2025 Vector 35 Inc.
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

use std::ffi::{c_char, c_void};
use std::path::PathBuf;

use binaryninjacore_sys::*;

use crate::string::{BnString, IntoCStr};

pub mod form;
pub mod handler;
pub mod report;

// Re-export the public items from the submodules, for convenience.
pub use form::*;
pub use handler::*;
pub use report::*;

pub type MessageBoxButtonSet = BNMessageBoxButtonSet;
pub type MessageBoxIcon = BNMessageBoxIcon;
pub type MessageBoxButtonResult = BNMessageBoxButtonResult;

pub fn get_text_line_input(prompt: &str, title: &str) -> Option<String> {
    let mut value: *mut c_char = std::ptr::null_mut();

    let prompt = prompt.to_cstr();
    let title = title.to_cstr();
    let result = unsafe { BNGetTextLineInput(&mut value, prompt.as_ptr(), title.as_ptr()) };
    if !result {
        return None;
    }

    Some(unsafe { BnString::into_string(value) })
}

pub fn get_integer_input(prompt: &str, title: &str) -> Option<i64> {
    let mut value: i64 = 0;

    let prompt = prompt.to_cstr();
    let title = title.to_cstr();
    let result = unsafe { BNGetIntegerInput(&mut value, prompt.as_ptr(), title.as_ptr()) };

    if !result {
        return None;
    }

    Some(value)
}

pub fn get_address_input(prompt: &str, title: &str) -> Option<u64> {
    let mut value: u64 = 0;

    let prompt = prompt.to_cstr();
    let title = title.to_cstr();
    let result = unsafe {
        BNGetAddressInput(
            &mut value,
            prompt.as_ptr(),
            title.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };

    if !result {
        return None;
    }

    Some(value)
}

pub fn get_choice_input(prompt: &str, title: &str, choices: &[&str]) -> Option<usize> {
    let prompt = prompt.to_cstr();
    let title = title.to_cstr();
    let mut choices_inner: Vec<BnString> = choices.iter().copied().map(BnString::new).collect();
    // SAFETY BnString and *const c_char are transparent
    let choices: &mut [*const c_char] = unsafe {
        core::mem::transmute::<&mut [BnString], &mut [*const c_char]>(&mut choices_inner[..])
    };
    let mut result = 0;
    let succ = unsafe {
        BNGetChoiceInput(
            &mut result,
            prompt.as_ptr(),
            title.as_ptr(),
            choices.as_mut_ptr(),
            choices.len(),
        )
    };
    succ.then_some(result)
}

pub fn get_large_choice_input(prompt: &str, title: &str, choices: &[&str]) -> Option<usize> {
    let prompt = prompt.to_cstr();
    let title = title.to_cstr();
    let mut choices_inner: Vec<BnString> = choices.iter().copied().map(BnString::new).collect();
    // SAFETY BnString and *const c_char are transparent
    let choices: &mut [*const c_char] = unsafe {
        core::mem::transmute::<&mut [BnString], &mut [*const c_char]>(&mut choices_inner[..])
    };
    let mut result = 0;
    let succ = unsafe {
        BNGetLargeChoiceInput(
            &mut result,
            prompt.as_ptr(),
            title.as_ptr(),
            choices.as_mut_ptr(),
            choices.len(),
        )
    };
    succ.then_some(result)
}

pub fn get_open_filename_input(prompt: &str, extension: &str) -> Option<PathBuf> {
    let mut value: *mut c_char = std::ptr::null_mut();

    let prompt = prompt.to_cstr();
    let extension = extension.to_cstr();
    let result = unsafe { BNGetOpenFileNameInput(&mut value, prompt.as_ptr(), extension.as_ptr()) };
    if !result {
        return None;
    }

    let path = unsafe { BnString::into_string(value) };
    Some(PathBuf::from(path))
}

pub fn get_save_filename_input(
    prompt: &str,
    extension: &str,
    default_name: &str,
) -> Option<PathBuf> {
    let mut value: *mut c_char = std::ptr::null_mut();

    let prompt = prompt.to_cstr();
    let extension = extension.to_cstr();
    let default_name = default_name.to_cstr();
    let result = unsafe {
        BNGetSaveFileNameInput(
            &mut value,
            prompt.as_ptr(),
            extension.as_ptr(),
            default_name.as_ptr(),
        )
    };
    if !result {
        return None;
    }

    let path = unsafe { BnString::into_string(value) };
    Some(PathBuf::from(path))
}

pub fn get_directory_name_input(prompt: &str, default_name: &str) -> Option<PathBuf> {
    let mut value: *mut c_char = std::ptr::null_mut();

    let prompt = prompt.to_cstr();
    let default_name = default_name.to_cstr();
    let result =
        unsafe { BNGetDirectoryNameInput(&mut value, prompt.as_ptr(), default_name.as_ptr()) };
    if !result {
        return None;
    }

    let path = unsafe { BnString::into_string(value) };
    Some(PathBuf::from(path))
}

pub fn show_message_box(
    title: &str,
    text: &str,
    buttons: MessageBoxButtonSet,
    icon: MessageBoxIcon,
) -> MessageBoxButtonResult {
    let title = title.to_cstr();
    let text = text.to_cstr();
    unsafe { BNShowMessageBox(title.as_ptr(), text.as_ptr(), buttons, icon) }
}

struct TaskContext<F: Fn(Box<dyn Fn(usize, usize) -> Result<(), ()>>)>(F);

pub fn run_progress_dialog<F: Fn(Box<dyn Fn(usize, usize) -> Result<(), ()>>)>(
    title: &str,
    can_cancel: bool,
    task: F,
) -> Result<(), ()> {
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

    let title = title.to_cstr();
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
