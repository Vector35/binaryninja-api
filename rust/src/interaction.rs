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

//! Interfaces for asking the user for information: forms, opening files, etc.

use binaryninjacore_sys::*;

use std::ffi::{c_char, c_void, CStr};
use std::path::PathBuf;

use crate::binary_view::BinaryView;
use crate::rc::Ref;
use crate::string::{BnStrCompatible, BnString};

pub fn get_text_line_input(prompt: &str, title: &str) -> Option<String> {
    let mut value: *mut c_char = std::ptr::null_mut();

    let result = unsafe {
        BNGetTextLineInput(
            &mut value,
            prompt.into_bytes_with_nul().as_ptr() as *mut _,
            title.into_bytes_with_nul().as_ptr() as *mut _,
        )
    };
    if !result {
        return None;
    }

    Some(unsafe { BnString::from_raw(value).to_string() })
}

pub fn get_integer_input(prompt: &str, title: &str) -> Option<i64> {
    let mut value: i64 = 0;

    let result = unsafe {
        BNGetIntegerInput(
            &mut value,
            prompt.into_bytes_with_nul().as_ptr() as *mut _,
            title.into_bytes_with_nul().as_ptr() as *mut _,
        )
    };

    if !result {
        return None;
    }

    Some(value)
}

pub fn get_address_input(prompt: &str, title: &str) -> Option<u64> {
    let mut value: u64 = 0;

    let result = unsafe {
        BNGetAddressInput(
            &mut value,
            prompt.into_bytes_with_nul().as_ptr() as *mut _,
            title.into_bytes_with_nul().as_ptr() as *mut _,
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
    let mut value: *mut c_char = std::ptr::null_mut();

    let result = unsafe {
        BNGetOpenFileNameInput(
            &mut value,
            prompt.into_bytes_with_nul().as_ptr() as *mut _,
            extension.into_bytes_with_nul().as_ptr() as *mut _,
        )
    };
    if !result {
        return None;
    }

    let string = unsafe { BnString::from_raw(value) };
    Some(PathBuf::from(string.as_str()))
}

pub fn get_save_filename_input(
    prompt: &str,
    extension: &str,
    default_name: &str,
) -> Option<PathBuf> {
    let mut value: *mut c_char = std::ptr::null_mut();

    let result = unsafe {
        BNGetSaveFileNameInput(
            &mut value,
            prompt.into_bytes_with_nul().as_ptr() as *mut _,
            extension.into_bytes_with_nul().as_ptr() as *mut _,
            default_name.into_bytes_with_nul().as_ptr() as *mut _,
        )
    };
    if !result {
        return None;
    }

    let string = unsafe { BnString::from_raw(value) };
    Some(PathBuf::from(string.as_str()))
}

pub fn get_directory_name_input(prompt: &str, default_name: &str) -> Option<PathBuf> {
    let mut value: *mut c_char = std::ptr::null_mut();

    let result = unsafe {
        BNGetDirectoryNameInput(
            &mut value,
            prompt.into_bytes_with_nul().as_ptr() as *mut _,
            default_name.into_bytes_with_nul().as_ptr() as *mut _,
        )
    };
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
    unsafe {
        BNShowMessageBox(
            title.into_bytes_with_nul().as_ptr() as *mut _,
            text.into_bytes_with_nul().as_ptr() as *mut _,
            buttons,
            icon,
        )
    }
}

pub enum FormResponses {
    None,
    String(String),
    Integer(i64),
    Address(u64),
    Index(usize),
}

enum FormData {
    Label {
        _text: BnString,
    },
    Text {
        _prompt: BnString,
        _default: Option<BnString>,
    },
    Choice {
        _prompt: BnString,
        _choices: Vec<BnString>,
        _raw: Vec<*const c_char>,
    },
    File {
        _prompt: BnString,
        _ext: BnString,
        _default: Option<BnString>,
    },
    FileSave {
        _prompt: BnString,
        _ext: BnString,
        _default_name: BnString,
        _default: Option<BnString>,
    },
}

pub struct FormInputBuilder {
    fields: Vec<BNFormInputField>,
    data: Vec<FormData>,
}

impl FormInputBuilder {
    pub fn new() -> Self {
        Self {
            fields: vec![],
            data: vec![],
        }
    }

    /// Form Field: Text output
    pub fn label_field(mut self, text: &str) -> Self {
        let text = BnString::new(text);

        let mut result = unsafe { std::mem::zeroed::<BNFormInputField>() };
        result.type_ = BNFormInputFieldType::LabelFormField;
        result.hasDefault = false;
        result.prompt = text.as_ref().as_ptr() as *const c_char;
        self.fields.push(result);

        self.data.push(FormData::Label { _text: text });
        self
    }

    /// Form Field: Vertical spacing
    pub fn separator_field(mut self) -> Self {
        let mut result = unsafe { std::mem::zeroed::<BNFormInputField>() };
        result.type_ = BNFormInputFieldType::SeparatorFormField;
        result.hasDefault = false;
        self.fields.push(result);
        self
    }

    /// Form Field: Prompt for a string value
    pub fn text_field(mut self, prompt: &str, default: Option<&str>) -> Self {
        let prompt = BnString::new(prompt);
        let default = default.map(BnString::new);

        let mut result = unsafe { std::mem::zeroed::<BNFormInputField>() };
        result.type_ = BNFormInputFieldType::TextLineFormField;
        result.prompt = prompt.as_ref().as_ptr() as *const c_char;
        result.hasDefault = default.is_some();
        if let Some(ref default) = default {
            result.stringDefault = default.as_ref().as_ptr() as *const c_char;
        }
        self.fields.push(result);

        self.data.push(FormData::Text {
            _prompt: prompt,
            _default: default,
        });
        self
    }

    /// Form Field: Prompt for multi-line string value
    pub fn multiline_field(mut self, prompt: &str, default: Option<&str>) -> Self {
        let prompt = BnString::new(prompt);
        let default = default.map(BnString::new);

        let mut result = unsafe { std::mem::zeroed::<BNFormInputField>() };
        result.type_ = BNFormInputFieldType::MultilineTextFormField;
        result.prompt = prompt.as_ref().as_ptr() as *const c_char;
        result.hasDefault = default.is_some();
        if let Some(ref default) = default {
            result.stringDefault = default.as_ref().as_ptr() as *const c_char;
        }
        self.fields.push(result);

        self.data.push(FormData::Text {
            _prompt: prompt,
            _default: default,
        });
        self
    }

    /// Form Field: Prompt for an integer
    pub fn integer_field(mut self, prompt: &str, default: Option<i64>) -> Self {
        let prompt = BnString::new(prompt);

        let mut result = unsafe { std::mem::zeroed::<BNFormInputField>() };
        result.type_ = BNFormInputFieldType::IntegerFormField;
        result.prompt = prompt.as_ref().as_ptr() as *const c_char;
        result.hasDefault = default.is_some();
        if let Some(default) = default {
            result.intDefault = default;
        }
        self.fields.push(result);

        self.data.push(FormData::Label { _text: prompt });
        self
    }

    /// Form Field: Prompt for an address
    pub fn address_field(
        mut self,
        prompt: &str,
        view: Option<Ref<BinaryView>>,
        current_address: Option<u64>,
        default: Option<u64>,
    ) -> Self {
        let prompt = BnString::new(prompt);

        let mut result = unsafe { std::mem::zeroed::<BNFormInputField>() };
        result.type_ = BNFormInputFieldType::AddressFormField;
        result.prompt = prompt.as_ref().as_ptr() as *const c_char;
        if let Some(view) = view {
            // the view is being moved into result, there is no need to clone
            // and drop is intentionally being avoided with `Ref::into_raw`
            result.view = unsafe { Ref::into_raw(view) }.handle;
        }
        result.currentAddress = current_address.unwrap_or(0);
        result.hasDefault = default.is_some();
        if let Some(default) = default {
            result.addressDefault = default;
        }
        self.fields.push(result);

        self.data.push(FormData::Label { _text: prompt });
        self
    }

    /// Form Field: Prompt for a choice from provided options
    pub fn choice_field(mut self, prompt: &str, choices: &[&str], default: Option<usize>) -> Self {
        let prompt = BnString::new(prompt);
        let choices: Vec<BnString> = choices.iter().map(|&s| BnString::new(s)).collect();

        let mut result = unsafe { std::mem::zeroed::<BNFormInputField>() };
        result.type_ = BNFormInputFieldType::ChoiceFormField;
        result.prompt = prompt.as_ref().as_ptr() as *const c_char;
        let mut raw_choices: Vec<*const c_char> = choices
            .iter()
            .map(|c| c.as_ref().as_ptr() as *const c_char)
            .collect();
        result.choices = raw_choices.as_mut_ptr();
        result.count = choices.len();
        result.hasDefault = default.is_some();
        if let Some(default) = default {
            result.indexDefault = default;
        }
        self.fields.push(result);

        self.data.push(FormData::Choice {
            _prompt: prompt,
            _choices: choices,
            _raw: raw_choices,
        });
        self
    }

    /// Form Field: Prompt for file to open
    pub fn open_file_field(
        mut self,
        prompt: &str,
        ext: Option<&str>,
        default: Option<&str>,
    ) -> Self {
        let prompt = BnString::new(prompt);
        let ext = if let Some(ext) = ext {
            BnString::new(ext)
        } else {
            BnString::new("")
        };
        let default = default.map(BnString::new);

        let mut result = unsafe { std::mem::zeroed::<BNFormInputField>() };
        result.type_ = BNFormInputFieldType::OpenFileNameFormField;
        result.prompt = prompt.as_ref().as_ptr() as *const c_char;
        result.ext = ext.as_ref().as_ptr() as *const c_char;
        result.hasDefault = default.is_some();
        if let Some(ref default) = default {
            result.stringDefault = default.as_ref().as_ptr() as *const c_char;
        }
        self.fields.push(result);

        self.data.push(FormData::File {
            _prompt: prompt,
            _ext: ext,
            _default: default,
        });
        self
    }

    /// Form Field: Prompt for file to save to
    pub fn save_file_field(
        mut self,
        prompt: &str,
        ext: Option<&str>,
        default_name: Option<&str>,
        default: Option<&str>,
    ) -> Self {
        let prompt = BnString::new(prompt);
        let ext = if let Some(ext) = ext {
            BnString::new(ext)
        } else {
            BnString::new("")
        };
        let default_name = if let Some(default_name) = default_name {
            BnString::new(default_name)
        } else {
            BnString::new("")
        };
        let default = default.map(BnString::new);

        let mut result = unsafe { std::mem::zeroed::<BNFormInputField>() };
        result.type_ = BNFormInputFieldType::SaveFileNameFormField;
        result.prompt = prompt.as_ref().as_ptr() as *const c_char;
        result.ext = ext.as_ref().as_ptr() as *const c_char;
        result.defaultName = default_name.as_ref().as_ptr() as *const c_char;
        result.hasDefault = default.is_some();
        if let Some(ref default) = default {
            result.stringDefault = default.as_ref().as_ptr() as *const c_char;
        }
        self.fields.push(result);

        self.data.push(FormData::FileSave {
            _prompt: prompt,
            _ext: ext,
            _default_name: default_name,
            _default: default,
        });
        self
    }

    /// Form Field: Prompt for directory name
    pub fn directory_name_field(
        mut self,
        prompt: &str,
        default_name: Option<&str>,
        default: Option<&str>,
    ) -> Self {
        let prompt = BnString::new(prompt);
        let default_name = if let Some(default_name) = default_name {
            BnString::new(default_name)
        } else {
            BnString::new("")
        };
        let default = default.map(BnString::new);

        let mut result = unsafe { std::mem::zeroed::<BNFormInputField>() };
        result.type_ = BNFormInputFieldType::DirectoryNameFormField;
        result.prompt = prompt.as_ref().as_ptr() as *const c_char;
        result.defaultName = default_name.as_ref().as_ptr() as *const c_char;
        result.hasDefault = default.is_some();
        if let Some(ref default) = default {
            result.stringDefault = default.as_ref().as_ptr() as *const c_char;
        }
        self.fields.push(result);

        self.data.push(FormData::File {
            _prompt: prompt,
            _ext: default_name,
            _default: default,
        });
        self
    }

    /// Prompts the user for a set of inputs specified in `fields` with given title.
    /// The fields parameter is a list which can contain the following types:
    ///
    /// This API is flexible and works both in the UI via a pop-up dialog and on the command-line.
    ///
    /// ```no_run
    /// # use binaryninja::interaction::FormInputBuilder;
    /// # use binaryninja::interaction::FormResponses;
    /// let responses = FormInputBuilder::new()
    ///     .text_field("First Name", None)
    ///     .text_field("Last Name", None)
    ///     .choice_field(
    ///         "Favorite Food",
    ///         &vec![
    ///             "Pizza",
    ///             "Also Pizza",
    ///             "Also Pizza",
    ///             "Yummy Pizza",
    ///             "Wrong Answer",
    ///         ],
    ///         Some(0),
    ///     )
    ///     .get_form_input("Form Title");
    ///
    /// let food = match responses[2] {
    ///     FormResponses::Index(0) => "Pizza",
    ///     FormResponses::Index(1) => "Also Pizza",
    ///     FormResponses::Index(2) => "Also Pizza",
    ///     FormResponses::Index(3) => "Wrong Answer",
    ///     _ => panic!("This person doesn't like pizza?!?"),
    /// };
    ///
    /// let FormResponses::String(last_name) = &responses[0] else {
    ///     unreachable!()
    /// };
    /// let FormResponses::String(first_name) = &responses[1] else {
    ///     unreachable!()
    /// };
    ///
    /// println!("{} {} likes {}", &first_name, &last_name, food);
    /// ```
    pub fn get_form_input(&mut self, title: &str) -> Vec<FormResponses> {
        if unsafe {
            BNGetFormInput(
                self.fields.as_mut_ptr(),
                self.fields.len(),
                title.into_bytes_with_nul().as_ptr() as *const _,
            )
        } {
            let result = self
                .fields
                .iter()
                .map(|form_field| match form_field.type_ {
                    BNFormInputFieldType::LabelFormField
                    | BNFormInputFieldType::SeparatorFormField => FormResponses::None,

                    BNFormInputFieldType::TextLineFormField
                    | BNFormInputFieldType::MultilineTextFormField
                    | BNFormInputFieldType::OpenFileNameFormField
                    | BNFormInputFieldType::SaveFileNameFormField
                    | BNFormInputFieldType::DirectoryNameFormField => {
                        FormResponses::String(unsafe {
                            CStr::from_ptr(form_field.stringResult)
                                .to_str()
                                .unwrap()
                                .to_owned()
                        })
                    }

                    BNFormInputFieldType::IntegerFormField => {
                        FormResponses::Integer(form_field.intResult)
                    }
                    BNFormInputFieldType::AddressFormField => {
                        FormResponses::Address(form_field.addressResult)
                    }
                    BNFormInputFieldType::ChoiceFormField => {
                        FormResponses::Index(form_field.indexResult)
                    }
                })
                .collect();
            unsafe { BNFreeFormInputResults(self.fields.as_mut_ptr(), self.fields.len()) };
            result
        } else {
            vec![]
        }
    }
}

impl Default for FormInputBuilder {
    fn default() -> Self {
        Self::new()
    }
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

    if unsafe {
        BNRunProgressDialog(
            title.into_bytes_with_nul().as_ptr() as *mut _,
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
