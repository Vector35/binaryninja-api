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

use binaryninjacore_sys::*;

use core::ffi;
use std::ffi::{c_char, c_void, CStr};
use std::path::PathBuf;
use std::ptr;

use crate::binary_view::BinaryView;
use crate::flowgraph::FlowGraph;
use crate::rc::{Array, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};

pub type ReportType = BNReportType;
pub type MessageBoxButtonSet = BNMessageBoxButtonSet;
pub type MessageBoxIcon = BNMessageBoxIcon;
pub type MessageBoxButtonResult = BNMessageBoxButtonResult;

pub fn show_report_collection<B: BnStrCompatible>(title: B, reports: &ReportCollection) {
    let title = title.into_bytes_with_nul();
    unsafe {
        BNShowReportCollection(
            title.as_ref().as_ptr() as *const ffi::c_char,
            reports.as_raw(),
        )
    }
}

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

pub fn get_choice_input<S1: BnStrCompatible, S2: BnStrCompatible>(
    prompt: S1,
    title: S2,
    choices: &[&str],
) -> Option<usize> {
    let prompt = prompt.into_bytes_with_nul();
    let title = title.into_bytes_with_nul();
    let mut choices_inner: Vec<BnString> = choices.iter().copied().map(BnString::new).collect();
    // SAFETY BnString and *const ffi::c_char are transparent
    let choices: &mut [*const ffi::c_char] = unsafe {
        core::mem::transmute::<&mut [BnString], &mut [*const ffi::c_char]>(&mut choices_inner[..])
    };
    let mut result = 0;
    let succ = unsafe {
        BNGetChoiceInput(
            &mut result,
            prompt.as_ref().as_ptr() as *const ffi::c_char,
            title.as_ref().as_ptr() as *const ffi::c_char,
            choices.as_mut_ptr(),
            choices.len(),
        )
    };
    succ.then_some(result)
}

pub fn get_large_choice_input<S1: BnStrCompatible, S2: BnStrCompatible>(
    prompt: S1,
    title: S2,
    choices: &[&str],
) -> Option<usize> {
    let prompt = prompt.into_bytes_with_nul();
    let title = title.into_bytes_with_nul();
    let mut choices_inner: Vec<BnString> = choices.iter().copied().map(BnString::new).collect();
    // SAFETY BnString and *const ffi::c_char are transparent
    let choices: &mut [*const ffi::c_char] = unsafe {
        core::mem::transmute::<&mut [BnString], &mut [*const ffi::c_char]>(&mut choices_inner[..])
    };
    let mut result = 0;
    let succ = unsafe {
        BNGetLargeChoiceInput(
            &mut result,
            prompt.as_ref().as_ptr() as *const ffi::c_char,
            title.as_ref().as_ptr() as *const ffi::c_char,
            choices.as_mut_ptr(),
            choices.len(),
        )
    };
    succ.then_some(result)
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

/// Prompts the user for a set of inputs specified in `fields` with given title.
/// The fields parameter is a list which can contain the following types:
///
/// This API is flexible and works both in the UI via a pop-up dialog and on the
/// command-line.
///
/// ```no_run
/// # use binaryninja::interaction;
/// # use binaryninja::interaction::FormInput;
/// # use binaryninja::interaction::FormResponses;
/// let mut form = [
///     FormInput::text_field("First Name", Some("John")),
///     FormInput::text_field("Last Name", Some("Doe")),
///     FormInput::choice_field(
///         "Favorite Food",
///         &[
///             "Pizza",
///             "Also Pizza",
///             "Also Pizza",
///             "Yummy Pizza",
///             "Wrong Answer",
///         ],
///         Some(0),
///     ),
/// ];
/// let responses = interaction::get_form_input("Form Title", &mut form);
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
pub fn get_form_input(title: &str, fields: &mut [FormInput]) -> Vec<FormResponses> {
    // SAFETY BNFormInputField and FormInputField are transparent
    let succ = unsafe {
        BNGetFormInput(
            fields.as_mut_ptr() as *mut BNFormInputField,
            fields.len(),
            title.into_bytes_with_nul().as_ptr() as *const _,
        )
    };
    // I'm assuming there is no need to drop the result if false is returned
    if !succ {
        return vec![];
    }

    let result = fields.iter().map(FormInput::result).collect();
    unsafe { BNFreeFormInputResults(fields.as_mut_ptr() as *mut BNFormInputField, fields.len()) };
    result
}

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

#[derive(Debug, Clone)]
pub enum FormResponses {
    None,
    String(String),
    Integer(i64),
    Address(u64),
    Index(usize),
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

pub trait CustomInteractionHandler: Sync + Send + 'static {
    fn show_plain_text_report(&mut self, view: &BinaryView, title: &str, contents: &str);
    fn show_markdown_report(
        &mut self,
        view: &BinaryView,
        title: &str,
        contents: &str,
        plaintext: &str,
    );
    fn show_html_report(&mut self, view: &BinaryView, title: &str, contents: &str, plaintext: &str);
    fn show_graph_report(&mut self, view: &BinaryView, title: &str, graph: &FlowGraph);
    fn show_report_collection(&mut self, title: &str, reports: &ReportCollection);
    fn get_text_line_input(&mut self, prompt: &str, title: &str) -> Option<String> {
        let mut result =
            self.get_form_input(&[FormInput::text_field::<_, &str>(prompt, None)], title)?;
        let [FormResponses::String(result)] = &mut result[..] else {
            panic!("Invalid result from CustomIteractionHandler::get_form_input")
        };
        Some(core::mem::take(result))
    }
    fn get_integer_input(&mut self, prompt: &str, title: &str) -> Option<i64> {
        let result = self.get_form_input(&[FormInput::integer_field(prompt, None)], title)?;
        let [FormResponses::Integer(result)] = &result[..] else {
            panic!("Invalid result from CustomIteractionHandler::get_form_input")
        };
        Some(*result)
    }
    fn get_address_input(
        &mut self,
        prompt: &str,
        title: &str,
        view: Option<&BinaryView>,
        current_addr: u64,
    ) -> Option<u64> {
        let result = self.get_form_input(
            &[FormInput::address_field(prompt, view, current_addr, None)],
            title,
        )?;
        let [FormResponses::Address(result)] = &result[..] else {
            panic!("Invalid result from CustomIteractionHandler::get_form_input")
        };
        Some(*result)
    }
    fn get_choice_input(&mut self, prompt: &str, title: &str, choices: &[&str]) -> Option<usize> {
        let result =
            self.get_form_input(&[FormInput::choice_field(prompt, choices, None)], title)?;
        let [FormResponses::Index(result)] = &result[..] else {
            panic!("Invalid result from CustomIteractionHandler::get_form_input")
        };
        Some(*result)
    }
    fn get_large_choice_input(
        &mut self,
        prompt: &str,
        title: &str,
        choices: &[&str],
    ) -> Option<usize> {
        self.get_choice_input(prompt, title, choices)
    }
    fn get_open_file_name_input(&mut self, prompt: &str, ext: Option<&str>) -> Option<String> {
        let mut result = self.get_form_input(
            &[FormInput::open_file_field::<_, _, &str>(prompt, ext, None)],
            "Select a file",
        )?;
        let [FormResponses::String(result)] = &mut result[..] else {
            panic!("Invalid result from CustomIteractionHandler::get_form_input")
        };
        Some(core::mem::take(result))
    }
    fn get_save_file_name_input(
        &mut self,
        prompt: &str,
        ext: Option<&str>,
        default_name: Option<&str>,
    ) -> Option<String> {
        let mut result = self.get_form_input(
            &[FormInput::save_file_field::<_, _, _, &str>(
                prompt,
                ext,
                default_name,
                None,
            )],
            "Select a file",
        )?;
        let [FormResponses::String(result)] = &mut result[..] else {
            panic!("Invalid result from CustomIteractionHandler::get_form_input")
        };
        Some(core::mem::take(result))
    }
    fn get_directory_name_input(
        &mut self,
        prompt: &str,
        default_name: Option<&str>,
    ) -> Option<String> {
        let mut result = self.get_form_input(
            &[FormInput::directory_name_field::<_, _, &str>(
                prompt,
                default_name,
                None,
            )],
            "Select a directory",
        )?;
        let [FormResponses::String(result)] = &mut result[..] else {
            panic!("Invalid result from CustomIteractionHandler::get_form_input")
        };
        Some(core::mem::take(result))
    }
    fn get_form_input(&mut self, fields: &[FormInput], title: &str) -> Option<Vec<FormResponses>>;
    fn show_message_box(
        &mut self,
        title: &str,
        text: &str,
        buttons: MessageBoxButtonSet,
        icon: MessageBoxIcon,
    ) -> MessageBoxButtonResult;
    fn open_url(&mut self, url: &str) -> bool;
    fn run_progress_dialog(
        &mut self,
        title: &str,
        can_cancel: bool,
        task: &CustomInterationHandlerTask,
    ) -> bool;
}

pub fn register_custom_interaction_handler<R: CustomInteractionHandler>(custom: R) {
    let leak_custom = Box::leak(Box::new(custom));
    let mut callbacks = BNInteractionHandlerCallbacks {
        context: leak_custom as *mut R as *mut ffi::c_void,
        showPlainTextReport: Some(show_plain_text_report_ffi::<R>),
        showMarkdownReport: Some(show_markdown_report_ffi::<R>),
        showHTMLReport: Some(show_html_report_ffi::<R>),
        showGraphReport: Some(show_graph_report_ffi::<R>),
        showReportCollection: Some(show_report_collection_ffi::<R>),
        getTextLineInput: Some(get_text_line_input_ffi::<R>),
        getIntegerInput: Some(get_integer_input_ffi::<R>),
        getAddressInput: Some(get_address_input_ffi::<R>),
        getChoiceInput: Some(get_choice_input_ffi::<R>),
        getLargeChoiceInput: Some(get_large_choice_input_ffi::<R>),
        getOpenFileNameInput: Some(get_open_file_name_input_ffi::<R>),
        getSaveFileNameInput: Some(get_save_file_name_input_ffi::<R>),
        getDirectoryNameInput: Some(get_directory_name_input_ffi::<R>),
        getFormInput: Some(get_form_input_ffi::<R>),
        showMessageBox: Some(show_message_box_ffi::<R>),
        openUrl: Some(open_url_ffi::<R>),
        runProgressDialog: Some(run_progress_dialog_ffi::<R>),
    };
    unsafe { BNRegisterInteractionHandler(&mut callbacks) }
}

unsafe extern "C" fn show_plain_text_report_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    view: *mut BNBinaryView,
    title: *const ffi::c_char,
    contents: *const ffi::c_char,
) {
    let ctxt = ctxt as *mut R;
    let title = unsafe { CStr::from_ptr(title) };
    let contents = unsafe { CStr::from_ptr(contents) };
    (*ctxt).show_plain_text_report(
        &BinaryView::from_raw(view),
        title.to_str().unwrap(),
        contents.to_str().unwrap(),
    )
}

unsafe extern "C" fn show_markdown_report_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    view: *mut BNBinaryView,
    title: *const ffi::c_char,
    contents: *const ffi::c_char,
    plaintext: *const ffi::c_char,
) {
    let ctxt = ctxt as *mut R;
    let title = unsafe { CStr::from_ptr(title) };
    let contents = unsafe { CStr::from_ptr(contents) };
    let plaintext = unsafe { CStr::from_ptr(plaintext) };
    (*ctxt).show_markdown_report(
        &BinaryView::from_raw(view),
        title.to_str().unwrap(),
        contents.to_str().unwrap(),
        plaintext.to_str().unwrap(),
    )
}

unsafe extern "C" fn show_html_report_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    view: *mut BNBinaryView,
    title: *const ffi::c_char,
    contents: *const ffi::c_char,
    plaintext: *const ffi::c_char,
) {
    let ctxt = ctxt as *mut R;
    let title = unsafe { CStr::from_ptr(title) };
    let contents = unsafe { CStr::from_ptr(contents) };
    let plaintext = unsafe { CStr::from_ptr(plaintext) };
    (*ctxt).show_html_report(
        &BinaryView::from_raw(view),
        title.to_str().unwrap(),
        contents.to_str().unwrap(),
        plaintext.to_str().unwrap(),
    )
}

unsafe extern "C" fn show_graph_report_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    view: *mut BNBinaryView,
    title: *const ffi::c_char,
    graph: *mut BNFlowGraph,
) {
    let ctxt = ctxt as *mut R;
    let title = unsafe { CStr::from_ptr(title) };
    (*ctxt).show_graph_report(
        &BinaryView::from_raw(view),
        title.to_str().unwrap(),
        &FlowGraph::from_raw(graph),
    )
}

unsafe extern "C" fn show_report_collection_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    title: *const ffi::c_char,
    report: *mut BNReportCollection,
) {
    let ctxt = ctxt as *mut R;
    let title = unsafe { CStr::from_ptr(title) };
    (*ctxt).show_report_collection(
        title.to_str().unwrap(),
        &ReportCollection::from_raw(ptr::NonNull::new(report).unwrap()),
    )
}

unsafe extern "C" fn get_text_line_input_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    result_ffi: *mut *mut ffi::c_char,
    prompt: *const ffi::c_char,
    title: *const ffi::c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = unsafe { CStr::from_ptr(prompt) };
    let title = unsafe { CStr::from_ptr(title) };
    let result = (*ctxt).get_text_line_input(prompt.to_str().unwrap(), title.to_str().unwrap());
    if let Some(result) = result {
        unsafe { *result_ffi = BnString::into_raw(BnString::new(result)) };
        true
    } else {
        unsafe { *result_ffi = ptr::null_mut() };
        false
    }
}

unsafe extern "C" fn get_integer_input_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    result_ffi: *mut i64,
    prompt: *const ffi::c_char,
    title: *const ffi::c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = unsafe { CStr::from_ptr(prompt) };
    let title = unsafe { CStr::from_ptr(title) };
    let result = (*ctxt).get_integer_input(prompt.to_str().unwrap(), title.to_str().unwrap());
    if let Some(result) = result {
        unsafe { *result_ffi = result };
        true
    } else {
        unsafe { *result_ffi = 0 };
        false
    }
}

unsafe extern "C" fn get_address_input_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    result_ffi: *mut u64,
    prompt: *const ffi::c_char,
    title: *const ffi::c_char,
    view: *mut BNBinaryView,
    current_addr: u64,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = unsafe { CStr::from_ptr(prompt) };
    let title = unsafe { CStr::from_ptr(title) };
    let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
    let result = (*ctxt).get_address_input(
        prompt.to_str().unwrap(),
        title.to_str().unwrap(),
        view.as_ref(),
        current_addr,
    );
    if let Some(result) = result {
        unsafe { *result_ffi = result };
        true
    } else {
        unsafe { *result_ffi = 0 };
        false
    }
}

unsafe extern "C" fn get_choice_input_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    result_ffi: *mut usize,
    prompt: *const ffi::c_char,
    title: *const ffi::c_char,
    choices: *mut *const ffi::c_char,
    count: usize,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = unsafe { CStr::from_ptr(prompt) };
    let title = unsafe { CStr::from_ptr(title) };
    let choices = unsafe { core::slice::from_raw_parts(choices, count) };
    // SAFETY: BnString and *const ffi::c_char are transparent
    let choices = unsafe { core::mem::transmute::<&[*const ffi::c_char], &[BnString]>(choices) };
    let choices: Vec<&str> = choices.iter().map(|x| x.to_str().unwrap()).collect();
    let result =
        (*ctxt).get_choice_input(prompt.to_str().unwrap(), title.to_str().unwrap(), &choices);
    if let Some(result) = result {
        unsafe { *result_ffi = result };
        true
    } else {
        unsafe { *result_ffi = 0 };
        false
    }
}

unsafe extern "C" fn get_large_choice_input_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    result_ffi: *mut usize,
    prompt: *const ffi::c_char,
    title: *const ffi::c_char,
    choices: *mut *const ffi::c_char,
    count: usize,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = unsafe { CStr::from_ptr(prompt) };
    let title = unsafe { CStr::from_ptr(title) };
    let choices = unsafe { core::slice::from_raw_parts(choices, count) };
    // SAFETY: BnString and *const ffi::c_char are transparent
    let choices = unsafe { core::mem::transmute::<&[*const ffi::c_char], &[BnString]>(choices) };
    let choices: Vec<&str> = choices.iter().map(|x| x.to_str().unwrap()).collect();
    let result =
        (*ctxt).get_large_choice_input(prompt.to_str().unwrap(), title.to_str().unwrap(), &choices);
    if let Some(result) = result {
        unsafe { *result_ffi = result };
        true
    } else {
        unsafe { *result_ffi = 0 };
        false
    }
}

unsafe extern "C" fn get_open_file_name_input_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    result_ffi: *mut *mut ffi::c_char,
    prompt: *const ffi::c_char,
    ext: *const ffi::c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = unsafe { CStr::from_ptr(prompt) };
    let ext = (!ext.is_null()).then(|| unsafe { CStr::from_ptr(ext) });
    let result = (*ctxt)
        .get_open_file_name_input(prompt.to_str().unwrap(), ext.map(|x| x.to_str().unwrap()));
    if let Some(result) = result {
        unsafe { *result_ffi = BnString::into_raw(BnString::new(result)) };
        true
    } else {
        unsafe { *result_ffi = ptr::null_mut() };
        false
    }
}

unsafe extern "C" fn get_save_file_name_input_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    result_ffi: *mut *mut ffi::c_char,
    prompt: *const ffi::c_char,
    ext: *const ffi::c_char,
    default_name: *const ffi::c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = unsafe { CStr::from_ptr(prompt) };
    let ext = (!ext.is_null()).then(|| unsafe { CStr::from_ptr(ext) });
    let default_name = (!default_name.is_null()).then(|| unsafe { CStr::from_ptr(default_name) });
    let result = (*ctxt).get_save_file_name_input(
        prompt.to_str().unwrap(),
        ext.map(|x| x.to_str().unwrap()),
        default_name.map(|x| x.to_str().unwrap()),
    );
    if let Some(result) = result {
        unsafe { *result_ffi = BnString::into_raw(BnString::new(result)) };
        true
    } else {
        unsafe { *result_ffi = ptr::null_mut() };
        false
    }
}

unsafe extern "C" fn get_directory_name_input_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    result_ffi: *mut *mut ffi::c_char,
    prompt: *const ffi::c_char,
    default_name: *const ffi::c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = unsafe { CStr::from_ptr(prompt) };
    let default_name = (!default_name.is_null()).then(|| unsafe { CStr::from_ptr(default_name) });
    let result = (*ctxt).get_directory_name_input(
        prompt.to_str().unwrap(),
        default_name.map(|x| x.to_str().unwrap()),
    );
    if let Some(result) = result {
        unsafe { *result_ffi = BnString::into_raw(BnString::new(result)) };
        true
    } else {
        unsafe { *result_ffi = ptr::null_mut() };
        false
    }
}

unsafe extern "C" fn get_form_input_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    fields: *mut BNFormInputField,
    count: usize,
    title: *const ffi::c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let fields = unsafe { core::slice::from_raw_parts_mut(fields, count) };
    // SAFETY BNFormInputField and FormInput are transparent
    let fields =
        unsafe { core::mem::transmute::<&mut [BNFormInputField], &mut [FormInput]>(fields) };
    let title = unsafe { CStr::from_ptr(title) };
    let results = (*ctxt).get_form_input(fields, title.to_str().unwrap());
    let Some(results) = results else {
        return false;
    };
    // modify the fields, so they include the results
    for (field, result) in fields.iter_mut().zip(results) {
        use BNFormInputFieldType::*;
        use FormResponses::*;
        match (field.0.type_, result) {
            (LabelFormField, None) | (SeparatorFormField, None) => {}
            (IntegerFormField, Integer(i)) => field.0.intResult = i,
            (AddressFormField, Address(a)) => field.0.addressResult = a,
            (ChoiceFormField, Index(idx)) => field.0.indexResult = idx,
            (TextLineFormField, String(s))
            | (MultilineTextFormField, String(s))
            | (OpenFileNameFormField, String(s))
            | (SaveFileNameFormField, String(s))
            | (DirectoryNameFormField, String(s)) => {
                field.0.stringResult = BnString::into_raw(BnString::new(s))
            }
            (type_, result) => panic!("Unexpected result for type {type_:?} -> {result:?}"),
        }
    }
    true
}

unsafe extern "C" fn show_message_box_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    title: *const ffi::c_char,
    text: *const ffi::c_char,
    buttons: BNMessageBoxButtonSet,
    icon: BNMessageBoxIcon,
) -> BNMessageBoxButtonResult {
    let ctxt = ctxt as *mut R;
    let title = unsafe { CStr::from_ptr(title) };
    let text = unsafe { CStr::from_ptr(text) };
    (*ctxt).show_message_box(
        title.to_str().unwrap(),
        text.to_str().unwrap(),
        buttons,
        icon,
    )
}

unsafe extern "C" fn open_url_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    url: *const ffi::c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let url = unsafe { CStr::from_ptr(url) };
    (*ctxt).open_url(url.to_str().unwrap())
}

unsafe extern "C" fn run_progress_dialog_ffi<R: CustomInteractionHandler>(
    ctxt: *mut ffi::c_void,
    title: *const ffi::c_char,
    can_cancel: bool,
    task: Option<
        unsafe extern "C" fn(
            *mut ffi::c_void,
            Option<unsafe extern "C" fn(*mut ffi::c_void, usize, usize) -> bool>,
            *mut ffi::c_void,
        ),
    >,
    task_ctxt: *mut ffi::c_void,
) -> bool {
    let ctxt = ctxt as *mut R;
    let title = unsafe { CStr::from_ptr(title) };
    let task = CustomInterationHandlerTask {
        ctxt: task_ctxt,
        task,
    };
    (*ctxt).run_progress_dialog(title.to_str().unwrap(), can_cancel, &task)
}

pub struct CustomInterationHandlerTask {
    ctxt: *mut ffi::c_void,
    task: Option<
        unsafe extern "C" fn(
            taskCtxt: *mut ffi::c_void,
            progress: Option<
                unsafe extern "C" fn(
                    progressCtxt: *mut ffi::c_void,
                    cur: usize,
                    max: usize,
                ) -> bool,
            >,
            progressCtxt: *mut ffi::c_void,
        ),
    >,
}

impl CustomInterationHandlerTask {
    pub fn task<P: FnMut(usize, usize) -> bool>(&mut self, progress: &mut P) {
        let Some(task) = self.task else {
            // Assuming a nullptr task mean nothing need to be done
            return;
        };

        let progress_ctxt = progress as *mut P as *mut ffi::c_void;
        ffi_wrap!("custom_interation_run_progress_dialog", unsafe {
            task(
                self.ctxt,
                Some(custom_interation_handler_task_ffi::<P>),
                progress_ctxt,
            )
        })
    }
}

unsafe extern "C" fn custom_interation_handler_task_ffi<P: FnMut(usize, usize) -> bool>(
    ctxt: *mut ffi::c_void,
    cur: usize,
    max: usize,
) -> bool {
    let ctxt = ctxt as *mut P;
    (*ctxt)(cur, max)
}

#[repr(transparent)]
pub struct ReportCollection {
    handle: ptr::NonNull<BNReportCollection>,
}

unsafe impl RefCountable for ReportCollection {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        let raw = unsafe { BNNewReportCollectionReference(handle.handle.as_ptr()) };
        unsafe { Self::ref_from_raw(ptr::NonNull::new(raw).unwrap()) }
    }

    unsafe fn dec_ref(handle: &Self) {
        unsafe { BNFreeReportCollection(handle.handle.as_ptr()) }
    }
}

impl ToOwned for ReportCollection {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { <Self as RefCountable>::inc_ref(self) }
    }
}

impl ReportCollection {
    pub(crate) fn as_raw(&self) -> *mut BNReportCollection {
        self.handle.as_ptr()
    }

    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNReportCollection>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: ptr::NonNull<BNReportCollection>) -> Ref<Self> {
        unsafe { Ref::new(Self { handle }) }
    }

    pub fn new() -> Ref<Self> {
        let raw = unsafe { BNCreateReportCollection() };
        unsafe { Self::ref_from_raw(ptr::NonNull::new(raw).unwrap()) }
    }

    pub fn count(&self) -> usize {
        unsafe { BNGetReportCollectionCount(self.as_raw()) }
    }

    fn type_(&self, i: usize) -> ReportType {
        unsafe { BNGetReportType(self.as_raw(), i) }
    }

    pub fn get(&self, i: usize) -> Report<'_> {
        Report::new(self, i)
    }

    fn view(&self, i: usize) -> Ref<BinaryView> {
        // TODO is this owned? or just a reference?
        let raw = unsafe { BNGetReportView(self.as_raw(), i) };
        unsafe { BinaryView::ref_from_raw(raw) }
    }

    fn title(&self, i: usize) -> BnString {
        // TODO is this owned? or just a reference? Assuming owned because it
        // returns a `*mut ffi::c_char`
        let raw = unsafe { BNGetReportTitle(self.as_raw(), i) };
        unsafe { BnString::from_raw(raw) }
    }

    fn contents(&self, i: usize) -> BnString {
        // TODO is this owned? or just a reference? Assuming owned because it
        // returns a `*mut ffi::c_char`
        let raw = unsafe { BNGetReportContents(self.as_raw(), i) };
        unsafe { BnString::from_raw(raw) }
    }

    fn plain_text(&self, i: usize) -> BnString {
        // TODO is this owned? or just a reference? Assuming owned because it
        // returns a `*mut ffi::c_char`
        let raw = unsafe { BNGetReportPlainText(self.as_raw(), i) };
        unsafe { BnString::from_raw(raw) }
    }

    fn flow_graph(&self, i: usize) -> Ref<FlowGraph> {
        // TODO is this owned? or just a reference?
        let raw = unsafe { BNGetReportFlowGraph(self.as_raw(), i) };
        unsafe { FlowGraph::ref_from_raw(raw) }
    }

    pub fn add_text<B1: BnStrCompatible, B2: BnStrCompatible>(
        &self,
        view: &BinaryView,
        title: B1,
        contents: B2,
    ) {
        let title = title.into_bytes_with_nul();
        let contents = contents.into_bytes_with_nul();
        unsafe {
            BNAddPlainTextReportToCollection(
                self.as_raw(),
                view.handle,
                title.as_ref().as_ptr() as *const ffi::c_char,
                contents.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn add_markdown<B1: BnStrCompatible, B2: BnStrCompatible, B3: BnStrCompatible>(
        &self,
        view: &BinaryView,
        title: B1,
        contents: B2,
        plaintext: B3,
    ) {
        let title = title.into_bytes_with_nul();
        let contents = contents.into_bytes_with_nul();
        let plaintext = plaintext.into_bytes_with_nul();
        unsafe {
            BNAddMarkdownReportToCollection(
                self.as_raw(),
                view.handle,
                title.as_ref().as_ptr() as *const ffi::c_char,
                contents.as_ref().as_ptr() as *const ffi::c_char,
                plaintext.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn add_html<B1: BnStrCompatible, B2: BnStrCompatible, B3: BnStrCompatible>(
        &self,
        view: &BinaryView,
        title: B1,
        contents: B2,
        plaintext: B3,
    ) {
        let title = title.into_bytes_with_nul();
        let contents = contents.into_bytes_with_nul();
        let plaintext = plaintext.into_bytes_with_nul();
        unsafe {
            BNAddHTMLReportToCollection(
                self.as_raw(),
                view.handle,
                title.as_ref().as_ptr() as *const ffi::c_char,
                contents.as_ref().as_ptr() as *const ffi::c_char,
                plaintext.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn add_graph<B: BnStrCompatible>(&self, view: &BinaryView, title: B, graph: &FlowGraph) {
        let title = title.into_bytes_with_nul();
        unsafe {
            BNAddGraphReportToCollection(
                self.as_raw(),
                view.handle,
                title.as_ref().as_ptr() as *const ffi::c_char,
                graph.handle,
            )
        }
    }

    fn update_report_flow_graph(&self, i: usize, graph: &FlowGraph) {
        unsafe { BNUpdateReportFlowGraph(self.as_raw(), i, graph.handle) }
    }

    pub fn iter(&self) -> ReportCollectionIter<'_> {
        ReportCollectionIter::new(self)
    }
}

impl<'a> IntoIterator for &'a ReportCollection {
    type Item = Report<'a>;
    type IntoIter = ReportCollectionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub enum Report<'a> {
    PlainText(ReportPlainText<'a>),
    Markdown(ReportMarkdown<'a>),
    Html(ReportHtml<'a>),
    FlowGraph(ReportFlowGraph<'a>),
}

impl<'a> Report<'a> {
    fn new(collection: &'a ReportCollection, index: usize) -> Self {
        let inner = ReportInner { collection, index };
        match inner.type_() {
            ReportType::PlainTextReportType => Report::PlainText(ReportPlainText(inner)),
            ReportType::MarkdownReportType => Report::Markdown(ReportMarkdown(inner)),
            ReportType::HTMLReportType => Report::Html(ReportHtml(inner)),
            ReportType::FlowGraphReportType => Report::FlowGraph(ReportFlowGraph(inner)),
        }
    }

    fn _inner(&self) -> &ReportInner<'a> {
        match self {
            Report::PlainText(ReportPlainText(x))
            | Report::Markdown(ReportMarkdown(x))
            | Report::Html(ReportHtml(x))
            | Report::FlowGraph(ReportFlowGraph(x)) => x,
        }
    }

    pub fn view(&self) -> Ref<BinaryView> {
        self._inner().view()
    }

    pub fn title(&self) -> BnString {
        self._inner().title()
    }
}

pub struct ReportPlainText<'a>(ReportInner<'a>);
impl ReportPlainText<'_> {
    pub fn contents(&self) -> BnString {
        self.0.contents()
    }
}

pub struct ReportMarkdown<'a>(ReportInner<'a>);
impl ReportMarkdown<'_> {
    pub fn contents(&self) -> BnString {
        self.0.contents()
    }

    pub fn plaintext(&self) -> BnString {
        self.0.plain_text()
    }
}

pub struct ReportHtml<'a>(ReportInner<'a>);
impl ReportHtml<'_> {
    pub fn contents(&self) -> BnString {
        self.0.contents()
    }

    pub fn plaintext(&self) -> BnString {
        self.0.plain_text()
    }
}

pub struct ReportFlowGraph<'a>(ReportInner<'a>);
impl ReportFlowGraph<'_> {
    pub fn flow_graph(&self) -> Ref<FlowGraph> {
        self.0.flow_graph()
    }

    pub fn update_report_flow_graph(&self, graph: &FlowGraph) {
        self.0.update_report_flow_graph(graph)
    }
}

struct ReportInner<'a> {
    collection: &'a ReportCollection,
    index: usize,
}

impl ReportInner<'_> {
    fn type_(&self) -> ReportType {
        self.collection.type_(self.index)
    }

    fn view(&self) -> Ref<BinaryView> {
        self.collection.view(self.index)
    }

    fn title(&self) -> BnString {
        self.collection.title(self.index)
    }

    fn contents(&self) -> BnString {
        self.collection.contents(self.index)
    }

    fn plain_text(&self) -> BnString {
        self.collection.plain_text(self.index)
    }

    fn flow_graph(&self) -> Ref<FlowGraph> {
        self.collection.flow_graph(self.index)
    }

    fn update_report_flow_graph(&self, graph: &FlowGraph) {
        self.collection.update_report_flow_graph(self.index, graph)
    }
}

pub struct ReportCollectionIter<'a> {
    report: &'a ReportCollection,
    current_index: usize,
    count: usize,
}

impl<'a> ReportCollectionIter<'a> {
    pub fn new(report: &'a ReportCollection) -> Self {
        Self {
            report,
            current_index: 0,
            count: report.count(),
        }
    }

    pub fn collection(&self) -> &ReportCollection {
        self.report
    }
}

impl<'a> Iterator for ReportCollectionIter<'a> {
    type Item = Report<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        (self.current_index < self.count).then(|| {
            let result = Report::new(self.report, self.current_index);
            self.current_index += 1;
            result
        })
    }
}

// A Zero cost transmute compatible type with BNFormInputField
// NOTE: the result values WILL be leaked unless
// [BNFreeFormInputResults] is called after [FormInputField::result]
#[repr(transparent)]
pub struct FormInput(BNFormInputField);

impl Drop for FormInput {
    fn drop(&mut self) {
        fn drop_string(string: *mut ffi::c_char) {
            if !string.is_null() {
                drop(unsafe { BnString::from_raw(string) });
            }
        }

        let raw: &BNFormInputField = &self.0;
        // NOTE there is a function BNFreeFormInputResults, but that
        // only works with a list for BNFormInputField and only drop the result.
        // I'm assuming this those the same as this function with drop_result true.

        use BNFormInputFieldType::*;
        match raw.type_ {
            SeparatorFormField => {}
            LabelFormField => {
                drop_string(raw.prompt as *mut ffi::c_char);
            }
            MultilineTextFormField | TextLineFormField => {
                drop_string(raw.prompt as *mut ffi::c_char);
                if raw.hasDefault {
                    drop_string(raw.stringDefault as *mut ffi::c_char);
                }
            }
            IntegerFormField => {
                drop_string(raw.prompt as *mut ffi::c_char);
            }
            AddressFormField => {
                drop_string(raw.prompt as *mut ffi::c_char);
                // NOTE the BinaryView in `raw.view` can be both owned or
                // borrowed depending on the creation of FormInput. Currently
                // the implementation uses borrow BinaryView, so we don't need
                // to drop it.
            }
            ChoiceFormField => {
                drop_string(raw.prompt as *mut ffi::c_char);
                drop((!raw.choices.is_null()).then(|| unsafe {
                    Array::<BnString>::new(raw.choices as *mut *mut ffi::c_char, raw.count, ())
                }));
            }
            OpenFileNameFormField => {
                drop_string(raw.prompt as *mut ffi::c_char);
                drop_string(raw.ext as *mut ffi::c_char);
                if raw.hasDefault {
                    drop_string(raw.stringDefault as *mut ffi::c_char);
                }
            }
            SaveFileNameFormField => {
                drop_string(raw.prompt as *mut ffi::c_char);
                drop_string(raw.ext as *mut ffi::c_char);
                if raw.hasDefault {
                    drop_string(raw.stringDefault as *mut ffi::c_char);
                }
                drop_string(raw.defaultName as *mut ffi::c_char);
            }
            DirectoryNameFormField => {
                drop_string(raw.prompt as *mut ffi::c_char);
                if raw.hasDefault {
                    drop_string(raw.stringDefault as *mut ffi::c_char);
                }
                drop_string(raw.defaultName as *mut ffi::c_char);
            }
        }
    }
}

impl FormInput {
    pub(crate) fn as_raw(&self) -> &BNFormInputField {
        &self.0
    }

    // NOTE this don't free the result, you need to call BNFreeFormInputResults
    // manually after
    fn result(&self) -> FormResponses {
        use BNFormInputFieldType::*;
        match self.0.type_ {
            LabelFormField | SeparatorFormField => FormResponses::None,

            TextLineFormField
            | MultilineTextFormField
            | OpenFileNameFormField
            | SaveFileNameFormField
            | DirectoryNameFormField => FormResponses::String(unsafe {
                CStr::from_ptr(self.0.stringResult)
                    .to_str()
                    .unwrap()
                    .to_owned()
            }),

            IntegerFormField => FormResponses::Integer(self.0.intResult),
            AddressFormField => FormResponses::Address(self.0.addressResult),
            ChoiceFormField => FormResponses::Index(self.0.indexResult),
        }
    }

    pub fn type_(&self) -> FormInputType<'_> {
        use BNFormInputFieldType::*;
        use FormInputType::*;
        match self.0.type_ {
            SeparatorFormField => Separator,
            LabelFormField => Label(FormInputFieldLabel(self)),
            TextLineFormField => TextLine(FormInputFieldText(self)),
            MultilineTextFormField => MultilineText(FormInputFieldText(self)),
            IntegerFormField => Integer(FormInputFieldInteger(self)),
            AddressFormField => Address(FormInputFieldAddress(self)),
            ChoiceFormField => Choice(FormInputFieldChoice(self)),
            OpenFileNameFormField => OpenFileName(FormInputFieldOpenFile(self)),
            SaveFileNameFormField => SaveFileName(FormInputFieldSaveFile(self)),
            DirectoryNameFormField => DirectoryName(FormInputFieldDirectory(self)),
        }
    }

    /// Form Field: Text output
    pub fn label_field<S: BnStrCompatible>(text: S) -> Self {
        Self(BNFormInputField {
            type_: BNFormInputFieldType::LabelFormField,
            prompt: BnString::into_raw(BnString::new(text)) as *const ffi::c_char,
            ..Default::default()
        })
    }

    /// Form Field: Vertical spacing
    pub fn separator_field() -> Self {
        Self(BNFormInputField {
            type_: BNFormInputFieldType::SeparatorFormField,
            ..Default::default()
        })
    }

    fn _inner_text_field<S1, S2>(
        prompt: S1,
        default: Option<S2>,
        type_: BNFormInputFieldType,
    ) -> Self
    where
        S1: BnStrCompatible,
        S2: BnStrCompatible,
    {
        Self(BNFormInputField {
            type_,
            prompt: BnString::into_raw(BnString::new(BnString::new(prompt))) as *const ffi::c_char,
            hasDefault: default.is_some(),
            stringDefault: default
                .map(|d| BnString::into_raw(BnString::new(d)))
                .unwrap_or(ptr::null_mut()),
            ..Default::default()
        })
    }

    /// Form Field: Prompt for a string value
    pub fn text_field<S1, S2>(prompt: S1, default: Option<S2>) -> Self
    where
        S1: BnStrCompatible,
        S2: BnStrCompatible,
    {
        Self::_inner_text_field(prompt, default, BNFormInputFieldType::TextLineFormField)
    }

    /// Form Field: Prompt for multi-line string value
    pub fn multiline_field<S1, S2>(prompt: S1, default: Option<S2>) -> Self
    where
        S1: BnStrCompatible,
        S2: BnStrCompatible,
    {
        Self::_inner_text_field(prompt, default, BNFormInputFieldType::TextLineFormField)
    }

    /// Form Field: Prompt for an integer
    pub fn integer_field<S: BnStrCompatible>(prompt: S, default: Option<i64>) -> Self {
        Self(BNFormInputField {
            type_: BNFormInputFieldType::IntegerFormField,
            prompt: BnString::into_raw(BnString::new(BnString::new(prompt))) as *const ffi::c_char,
            hasDefault: default.is_some(),
            intDefault: default.unwrap_or_default(),
            ..Default::default()
        })
    }

    /// Form Field: Prompt for an address
    pub fn address_field<S: BnStrCompatible>(
        prompt: S,
        view: Option<&BinaryView>,
        current_address: u64,
        default: Option<u64>,
    ) -> Self {
        Self(BNFormInputField {
            type_: BNFormInputFieldType::AddressFormField,
            prompt: BnString::into_raw(BnString::new(BnString::new(prompt))) as *const ffi::c_char,
            view: view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
            currentAddress: current_address,
            hasDefault: default.is_some(),
            addressDefault: default.unwrap_or_default(),
            ..Default::default()
        })
    }

    /// Form Field: Prompt for a choice from provided options
    pub fn choice_field<S: BnStrCompatible>(
        prompt: S,
        choices: &[&str],
        default: Option<usize>,
    ) -> Self {
        Self(BNFormInputField {
            type_: BNFormInputFieldType::ChoiceFormField,
            prompt: BnString::into_raw(BnString::new(BnString::new(prompt))) as *const ffi::c_char,
            choices: crate::string::strings_to_string_list(choices) as *mut *const ffi::c_char,
            count: choices.len(),
            hasDefault: default.is_some(),
            indexDefault: default.unwrap_or_default(),
            ..Default::default()
        })
    }

    /// Form Field: Prompt for file to open
    pub fn open_file_field<S1, S2, S3>(prompt: S1, ext: Option<S2>, default: Option<S3>) -> Self
    where
        S1: BnStrCompatible,
        S2: BnStrCompatible,
        S3: BnStrCompatible,
    {
        Self(BNFormInputField {
            type_: BNFormInputFieldType::OpenFileNameFormField,
            prompt: BnString::into_raw(BnString::new(BnString::new(prompt))) as *const ffi::c_char,
            ext: ext
                .map(|ext| BnString::into_raw(BnString::new(ext)))
                .unwrap_or_else(|| BnString::into_raw(BnString::new(c""))),
            hasDefault: default.is_some(),
            stringDefault: default
                .map(|default| BnString::into_raw(BnString::new(default)))
                .unwrap_or(ptr::null_mut()),
            ..Default::default()
        })
    }

    /// Form Field: Prompt for file to save to
    pub fn save_file_field<S1, S2, S3, S4>(
        prompt: S1,
        ext: Option<S2>,
        default_name: Option<S3>,
        default: Option<S4>,
    ) -> Self
    where
        S1: BnStrCompatible,
        S2: BnStrCompatible,
        S3: BnStrCompatible,
        S4: BnStrCompatible,
    {
        Self(BNFormInputField {
            type_: BNFormInputFieldType::SaveFileNameFormField,
            prompt: BnString::into_raw(BnString::new(BnString::new(prompt))) as *const ffi::c_char,
            ext: ext
                .map(|ext| BnString::into_raw(BnString::new(ext)))
                .unwrap_or_else(|| BnString::into_raw(BnString::new(c""))),
            defaultName: default_name
                .map(|name| BnString::into_raw(BnString::new(name)))
                .unwrap_or_else(|| BnString::into_raw(BnString::new(c""))),
            hasDefault: default.is_some(),
            stringDefault: default
                .map(|default| BnString::into_raw(BnString::new(default)))
                .unwrap_or(ptr::null_mut()),
            ..Default::default()
        })
    }

    /// Form Field: Prompt for directory name
    pub fn directory_name_field<S1, S2, S3>(
        prompt: S1,
        default_name: Option<S2>,
        default: Option<S3>,
    ) -> Self
    where
        S1: BnStrCompatible,
        S2: BnStrCompatible,
        S3: BnStrCompatible,
    {
        Self(BNFormInputField {
            type_: BNFormInputFieldType::DirectoryNameFormField,
            prompt: BnString::into_raw(BnString::new(BnString::new(prompt))) as *const ffi::c_char,
            hasDefault: default.is_some(),
            defaultName: default_name
                .map(|name| BnString::into_raw(BnString::new(name)))
                .unwrap_or_else(|| BnString::into_raw(BnString::new(c""))),
            stringDefault: default
                .map(|default| BnString::into_raw(BnString::new(default)))
                .unwrap_or(ptr::null_mut()),
            ..Default::default()
        })
    }
}

pub enum FormInputType<'a> {
    Separator,
    Label(FormInputFieldLabel<'a>),
    TextLine(FormInputFieldText<'a>),
    MultilineText(FormInputFieldText<'a>),
    Integer(FormInputFieldInteger<'a>),
    Address(FormInputFieldAddress<'a>),
    Choice(FormInputFieldChoice<'a>),
    OpenFileName(FormInputFieldOpenFile<'a>),
    SaveFileName(FormInputFieldSaveFile<'a>),
    DirectoryName(FormInputFieldDirectory<'a>),
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct FormInputFieldLabel<'a>(&'a FormInput);
impl FormInputFieldLabel<'_> {
    pub fn prompt(&self) -> &str {
        form_input_field_prompt(self.0.as_raw())
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct FormInputFieldText<'a>(&'a FormInput);
impl FormInputFieldText<'_> {
    pub fn prompt(&self) -> &str {
        form_input_field_prompt(self.0.as_raw())
    }

    pub fn default(&self) -> Option<&str> {
        form_input_field_default_string(self.0.as_raw())
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct FormInputFieldInteger<'a>(&'a FormInput);
impl FormInputFieldInteger<'_> {
    pub fn prompt(&self) -> &str {
        form_input_field_prompt(self.0.as_raw())
    }

    pub fn default(&self) -> Option<i64> {
        self.0
            .as_raw()
            .hasDefault
            .then_some(self.0.as_raw().intDefault)
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct FormInputFieldAddress<'a>(&'a FormInput);
impl FormInputFieldAddress<'_> {
    pub fn prompt(&self) -> &str {
        form_input_field_prompt(self.0.as_raw())
    }

    pub fn view(&self) -> Option<BinaryView> {
        (!self.0.as_raw().view.is_null())
            .then(|| unsafe { BinaryView::from_raw(self.0.as_raw().view) })
    }

    pub fn default(&self) -> Option<u64> {
        self.0
            .as_raw()
            .hasDefault
            .then_some(self.0.as_raw().addressDefault)
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct FormInputFieldChoice<'a>(&'a FormInput);
impl FormInputFieldChoice<'_> {
    pub fn prompt(&self) -> &str {
        form_input_field_prompt(self.0.as_raw())
    }

    pub fn choices(&self) -> &[BnString] {
        let ptr: *mut *const ffi::c_char = self.0.as_raw().choices;
        let count = self.0.as_raw().count;
        if ptr.is_null() {
            return &[];
        }

        // SAFETY BnString and *const ffi::c_char are transparent
        unsafe { core::slice::from_raw_parts(ptr as *const BnString, count) }
    }

    pub fn default(&self) -> Option<usize> {
        self.0
            .as_raw()
            .hasDefault
            .then_some(self.0.as_raw().indexDefault)
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct FormInputFieldOpenFile<'a>(&'a FormInput);
impl FormInputFieldOpenFile<'_> {
    pub fn prompt(&self) -> &str {
        form_input_field_prompt(self.0.as_raw())
    }

    pub fn ext(&self) -> Option<&str> {
        form_input_field_ext(self.0.as_raw())
    }

    pub fn default(&self) -> Option<&str> {
        form_input_field_default_string(self.0.as_raw())
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct FormInputFieldSaveFile<'a>(&'a FormInput);
impl FormInputFieldSaveFile<'_> {
    pub fn prompt(&self) -> &str {
        form_input_field_prompt(self.0.as_raw())
    }

    pub fn ext(&self) -> Option<&str> {
        form_input_field_ext(self.0.as_raw())
    }

    pub fn default_name(&self) -> Option<&str> {
        form_input_field_default_name(self.0.as_raw())
    }

    pub fn default(&self) -> Option<&str> {
        form_input_field_default_string(self.0.as_raw())
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct FormInputFieldDirectory<'a>(&'a FormInput);
impl FormInputFieldDirectory<'_> {
    pub fn prompt(&self) -> &str {
        form_input_field_prompt(self.0.as_raw())
    }

    pub fn default_name(&self) -> Option<&str> {
        form_input_field_default_name(self.0.as_raw())
    }

    pub fn default(&self) -> Option<&str> {
        form_input_field_default_string(self.0.as_raw())
    }
}

fn form_input_field_prompt(raw: &BNFormInputField) -> &str {
    debug_assert!(!raw.prompt.is_null());
    unsafe { CStr::from_ptr(raw.prompt) }.to_str().unwrap()
}

fn form_input_field_ext(raw: &BNFormInputField) -> Option<&str> {
    (!raw.ext.is_null())
        .then(|| {
            let result = unsafe { CStr::from_ptr(raw.ext) }.to_str().unwrap();
            (!result.is_empty()).then_some(result)
        })
        .flatten()
}

fn form_input_field_default_name(raw: &BNFormInputField) -> Option<&str> {
    raw.hasDefault
        .then(|| {
            let result = unsafe { CStr::from_ptr(raw.defaultName) }.to_str().unwrap();
            (!result.is_empty()).then_some(result)
        })
        .flatten()
}

fn form_input_field_default_string(raw: &BNFormInputField) -> Option<&str> {
    raw.hasDefault
        .then(|| unsafe {
            (!raw.stringDefault.is_null())
                .then(|| CStr::from_ptr(raw.stringDefault).to_str().unwrap())
        })
        .flatten()
}
