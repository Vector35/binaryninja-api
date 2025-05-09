use std::ffi::{c_char, c_void, CStr};
use std::ptr;

use binaryninjacore_sys::*;

use crate::binary_view::BinaryView;
use crate::flowgraph::FlowGraph;
use crate::interaction::form::{Form, FormInputField};
use crate::interaction::report::{Report, ReportCollection};
use crate::interaction::{MessageBoxButtonResult, MessageBoxButtonSet, MessageBoxIcon};
use crate::string::{raw_to_string, BnString};

pub fn register_interaction_handler<R: InteractionHandler>(custom: R) {
    let leak_custom = Box::leak(Box::new(custom));
    let mut callbacks = BNInteractionHandlerCallbacks {
        context: leak_custom as *mut R as *mut c_void,
        showPlainTextReport: Some(cb_show_plain_text_report::<R>),
        showMarkdownReport: Some(cb_show_markdown_report::<R>),
        showHTMLReport: Some(cb_show_html_report::<R>),
        showGraphReport: Some(cb_show_graph_report::<R>),
        showReportCollection: Some(cb_show_report_collection::<R>),
        getTextLineInput: Some(cb_get_text_line_input::<R>),
        getIntegerInput: Some(cb_get_integer_input::<R>),
        getAddressInput: Some(cb_get_address_input::<R>),
        getChoiceInput: Some(cb_get_choice_input::<R>),
        getLargeChoiceInput: Some(cb_get_large_choice_input::<R>),
        getOpenFileNameInput: Some(cb_get_open_file_name_input::<R>),
        getSaveFileNameInput: Some(cb_get_save_file_name_input::<R>),
        getDirectoryNameInput: Some(cb_get_directory_name_input::<R>),
        getFormInput: Some(cb_get_form_input::<R>),
        showMessageBox: Some(cb_show_message_box::<R>),
        openUrl: Some(cb_open_url::<R>),
        runProgressDialog: Some(cb_run_progress_dialog::<R>),
    };
    unsafe { BNRegisterInteractionHandler(&mut callbacks) }
}

pub trait InteractionHandler: Sync + Send + 'static {
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
        task: &InteractionHandlerTask,
    ) -> bool;

    fn show_plain_text_report(&mut self, view: &BinaryView, title: &str, contents: &str);

    fn show_graph_report(&mut self, view: &BinaryView, title: &str, graph: &FlowGraph);

    fn show_markdown_report(
        &mut self,
        view: &BinaryView,
        title: &str,
        _contents: &str,
        plain_text: &str,
    ) {
        self.show_plain_text_report(view, title, plain_text);
    }

    fn show_html_report(
        &mut self,
        view: &BinaryView,
        title: &str,
        _contents: &str,
        plain_text: &str,
    ) {
        self.show_plain_text_report(view, title, plain_text);
    }

    fn show_report_collection(&mut self, _title: &str, reports: &ReportCollection) {
        for report in reports {
            match &report {
                Report::PlainText(rpt) => {
                    self.show_plain_text_report(&report.view(), &report.title(), &rpt.contents())
                }
                Report::Markdown(rm) => self.show_markdown_report(
                    &report.view(),
                    &report.title(),
                    &rm.contents(),
                    &rm.plaintext(),
                ),
                Report::Html(rh) => self.show_html_report(
                    &report.view(),
                    &report.title(),
                    &rh.contents(),
                    &rh.plaintext(),
                ),
                Report::FlowGraph(rfg) => {
                    self.show_graph_report(&report.view(), &report.title(), &rfg.flow_graph())
                }
            }
        }
    }

    fn get_form_input(&mut self, form: &mut Form) -> bool;

    fn get_text_line_input(&mut self, prompt: &str, title: &str) -> Option<String> {
        let mut form = Form::new(title.to_owned());
        form.add_field(FormInputField::TextLine {
            prompt: prompt.to_string(),
            default: None,
            value: None,
        });
        if !self.get_form_input(&mut form) {
            return None;
        }
        form.get_field_with_name(prompt)
            .and_then(|f| f.try_value_string())
    }

    fn get_integer_input(&mut self, prompt: &str, title: &str) -> Option<i64> {
        let mut form = Form::new(title.to_owned());
        form.add_field(FormInputField::Integer {
            prompt: prompt.to_string(),
            value: 0,
            default: None,
        });
        if !self.get_form_input(&mut form) {
            return None;
        }
        form.get_field_with_name(prompt)
            .and_then(|f| f.try_value_int())
    }

    fn get_address_input(
        &mut self,
        prompt: &str,
        title: &str,
        view: Option<&BinaryView>,
        current_addr: u64,
    ) -> Option<u64> {
        let mut form = Form::new(title.to_owned());
        form.add_field(FormInputField::Address {
            prompt: prompt.to_string(),
            view: view.map(|v| v.to_owned()),
            current_address: current_addr,
            value: 0,
            default: None,
        });
        if !self.get_form_input(&mut form) {
            return None;
        }
        form.get_field_with_name(prompt)
            .and_then(|f| f.try_value_address())
    }

    fn get_choice_input(
        &mut self,
        prompt: &str,
        title: &str,
        choices: Vec<String>,
    ) -> Option<usize> {
        let mut form = Form::new(title.to_owned());
        form.add_field(FormInputField::Choice {
            prompt: prompt.to_string(),
            choices,
            default: None,
            value: 0,
        });
        if !self.get_form_input(&mut form) {
            return None;
        }
        form.get_field_with_name(prompt)
            .and_then(|f| f.try_value_index())
    }

    fn get_large_choice_input(
        &mut self,
        prompt: &str,
        title: &str,
        choices: Vec<String>,
    ) -> Option<usize> {
        self.get_choice_input(prompt, title, choices)
    }

    fn get_open_file_name_input(
        &mut self,
        prompt: &str,
        extension: Option<String>,
    ) -> Option<String> {
        let mut form = Form::new(prompt.to_owned());
        form.add_field(FormInputField::OpenFileName {
            prompt: prompt.to_string(),
            default: None,
            value: None,
            extension,
        });
        if !self.get_form_input(&mut form) {
            return None;
        }
        form.get_field_with_name(prompt)
            .and_then(|f| f.try_value_string())
    }

    fn get_save_file_name_input(
        &mut self,
        prompt: &str,
        extension: Option<String>,
        default_name: Option<String>,
    ) -> Option<String> {
        let mut form = Form::new(prompt.to_owned());
        form.add_field(FormInputField::SaveFileName {
            prompt: prompt.to_string(),
            extension,
            default: None,
            value: None,
            default_name,
        });
        if !self.get_form_input(&mut form) {
            return None;
        }
        form.get_field_with_name(prompt)
            .and_then(|f| f.try_value_string())
    }

    fn get_directory_name_input(
        &mut self,
        prompt: &str,
        default_name: Option<String>,
    ) -> Option<String> {
        let mut form = Form::new(prompt.to_owned());
        form.add_field(FormInputField::DirectoryName {
            prompt: prompt.to_string(),
            default_name,
            default: None,
            value: None,
        });
        if !self.get_form_input(&mut form) {
            return None;
        }
        form.get_field_with_name(prompt)
            .and_then(|f| f.try_value_string())
    }
}

pub struct InteractionHandlerTask {
    ctxt: *mut c_void,
    task: Option<
        unsafe extern "C" fn(
            taskCtxt: *mut c_void,
            progress: Option<
                unsafe extern "C" fn(progressCtxt: *mut c_void, cur: usize, max: usize) -> bool,
            >,
            progressCtxt: *mut c_void,
        ),
    >,
}

impl InteractionHandlerTask {
    pub fn task<P: FnMut(usize, usize) -> bool>(&mut self, progress: &mut P) {
        let Some(task) = self.task else {
            // Assuming a nullptr task mean nothing need to be done
            return;
        };

        let progress_ctxt = progress as *mut P as *mut c_void;
        ffi_wrap!("custom_interaction_run_progress_dialog", unsafe {
            task(
                self.ctxt,
                Some(cb_custom_interaction_handler_task::<P>),
                progress_ctxt,
            )
        })
    }
}

unsafe extern "C" fn cb_custom_interaction_handler_task<P: FnMut(usize, usize) -> bool>(
    ctxt: *mut c_void,
    cur: usize,
    max: usize,
) -> bool {
    let ctxt = ctxt as *mut P;
    (*ctxt)(cur, max)
}

unsafe extern "C" fn cb_show_plain_text_report<R: InteractionHandler>(
    ctxt: *mut c_void,
    view: *mut BNBinaryView,
    title: *const c_char,
    contents: *const c_char,
) {
    let ctxt = ctxt as *mut R;
    let title = raw_to_string(title).unwrap();
    let contents = raw_to_string(contents).unwrap();
    (*ctxt).show_plain_text_report(&BinaryView::from_raw(view), &title, &contents)
}

unsafe extern "C" fn cb_show_markdown_report<R: InteractionHandler>(
    ctxt: *mut c_void,
    view: *mut BNBinaryView,
    title: *const c_char,
    contents: *const c_char,
    plaintext: *const c_char,
) {
    let ctxt = ctxt as *mut R;
    let title = raw_to_string(title).unwrap();
    let contents = raw_to_string(contents).unwrap();
    let plaintext = raw_to_string(plaintext).unwrap();
    (*ctxt).show_markdown_report(&BinaryView::from_raw(view), &title, &contents, &plaintext)
}

unsafe extern "C" fn cb_show_html_report<R: InteractionHandler>(
    ctxt: *mut c_void,
    view: *mut BNBinaryView,
    title: *const c_char,
    contents: *const c_char,
    plaintext: *const c_char,
) {
    let ctxt = ctxt as *mut R;
    let title = raw_to_string(title).unwrap();
    let contents = raw_to_string(contents).unwrap();
    let plaintext = raw_to_string(plaintext).unwrap();
    (*ctxt).show_html_report(&BinaryView::from_raw(view), &title, &contents, &plaintext)
}

unsafe extern "C" fn cb_show_graph_report<R: InteractionHandler>(
    ctxt: *mut c_void,
    view: *mut BNBinaryView,
    title: *const c_char,
    graph: *mut BNFlowGraph,
) {
    let ctxt = ctxt as *mut R;
    let title = raw_to_string(title).unwrap();
    (*ctxt).show_graph_report(
        &BinaryView::from_raw(view),
        &title,
        &FlowGraph::from_raw(graph),
    )
}

unsafe extern "C" fn cb_show_report_collection<R: InteractionHandler>(
    ctxt: *mut c_void,
    title: *const c_char,
    report: *mut BNReportCollection,
) {
    let ctxt = ctxt as *mut R;
    let title = raw_to_string(title).unwrap();
    (*ctxt).show_report_collection(
        &title,
        &ReportCollection::from_raw(ptr::NonNull::new(report).unwrap()),
    )
}

unsafe extern "C" fn cb_get_text_line_input<R: InteractionHandler>(
    ctxt: *mut c_void,
    result_ffi: *mut *mut c_char,
    prompt: *const c_char,
    title: *const c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = raw_to_string(prompt).unwrap();
    let title = raw_to_string(title).unwrap();
    let result = (*ctxt).get_text_line_input(&prompt, &title);
    if let Some(result) = result {
        unsafe { *result_ffi = BnString::into_raw(BnString::new(result)) };
        true
    } else {
        unsafe { *result_ffi = ptr::null_mut() };
        false
    }
}

unsafe extern "C" fn cb_get_integer_input<R: InteractionHandler>(
    ctxt: *mut c_void,
    result_ffi: *mut i64,
    prompt: *const c_char,
    title: *const c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = raw_to_string(prompt).unwrap();
    let title = raw_to_string(title).unwrap();
    let result = (*ctxt).get_integer_input(&prompt, &title);
    if let Some(result) = result {
        unsafe { *result_ffi = result };
        true
    } else {
        unsafe { *result_ffi = 0 };
        false
    }
}

unsafe extern "C" fn cb_get_address_input<R: InteractionHandler>(
    ctxt: *mut c_void,
    result_ffi: *mut u64,
    prompt: *const c_char,
    title: *const c_char,
    view: *mut BNBinaryView,
    current_addr: u64,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = raw_to_string(prompt).unwrap();
    let title = raw_to_string(title).unwrap();
    let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
    let result = (*ctxt).get_address_input(&prompt, &title, view.as_ref(), current_addr);
    if let Some(result) = result {
        unsafe { *result_ffi = result };
        true
    } else {
        unsafe { *result_ffi = 0 };
        false
    }
}

unsafe extern "C" fn cb_get_choice_input<R: InteractionHandler>(
    ctxt: *mut c_void,
    result_ffi: *mut usize,
    prompt: *const c_char,
    title: *const c_char,
    choices: *mut *const c_char,
    count: usize,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = raw_to_string(prompt).unwrap();
    let title = raw_to_string(title).unwrap();
    let choices = unsafe { core::slice::from_raw_parts(choices, count) };
    // SAFETY: BnString and *const c_char are transparent
    let choices = unsafe { core::mem::transmute::<&[*const c_char], &[BnString]>(choices) };
    let choices: Vec<String> = choices
        .iter()
        .map(|x| x.to_string_lossy().to_string())
        .collect();
    let result = (*ctxt).get_choice_input(&prompt, &title, choices);
    if let Some(result) = result {
        unsafe { *result_ffi = result };
        true
    } else {
        unsafe { *result_ffi = 0 };
        false
    }
}

unsafe extern "C" fn cb_get_large_choice_input<R: InteractionHandler>(
    ctxt: *mut c_void,
    result_ffi: *mut usize,
    prompt: *const c_char,
    title: *const c_char,
    choices: *mut *const c_char,
    count: usize,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = raw_to_string(prompt).unwrap();
    let title = raw_to_string(title).unwrap();
    let choices = unsafe { core::slice::from_raw_parts(choices, count) };
    // SAFETY: BnString and *const c_char are transparent
    let choices = unsafe { core::mem::transmute::<&[*const c_char], &[BnString]>(choices) };
    let choices: Vec<String> = choices
        .iter()
        .map(|x| x.to_string_lossy().to_string())
        .collect();
    let result = (*ctxt).get_large_choice_input(&prompt, &title, choices);
    if let Some(result) = result {
        unsafe { *result_ffi = result };
        true
    } else {
        unsafe { *result_ffi = 0 };
        false
    }
}

unsafe extern "C" fn cb_get_open_file_name_input<R: InteractionHandler>(
    ctxt: *mut c_void,
    result_ffi: *mut *mut c_char,
    prompt: *const c_char,
    ext: *const c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = raw_to_string(prompt).unwrap();
    let ext = (!ext.is_null()).then(|| unsafe { CStr::from_ptr(ext) });
    let result =
        (*ctxt).get_open_file_name_input(&prompt, ext.map(|x| x.to_string_lossy().to_string()));
    if let Some(result) = result {
        unsafe { *result_ffi = BnString::into_raw(BnString::new(result)) };
        true
    } else {
        unsafe { *result_ffi = ptr::null_mut() };
        false
    }
}

unsafe extern "C" fn cb_get_save_file_name_input<R: InteractionHandler>(
    ctxt: *mut c_void,
    result_ffi: *mut *mut c_char,
    prompt: *const c_char,
    ext: *const c_char,
    default_name: *const c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = raw_to_string(prompt).unwrap();
    let ext = raw_to_string(ext);
    let default_name = raw_to_string(default_name);
    let result = (*ctxt).get_save_file_name_input(&prompt, ext, default_name);
    if let Some(result) = result {
        unsafe { *result_ffi = BnString::into_raw(BnString::new(result)) };
        true
    } else {
        unsafe { *result_ffi = ptr::null_mut() };
        false
    }
}

unsafe extern "C" fn cb_get_directory_name_input<R: InteractionHandler>(
    ctxt: *mut c_void,
    result_ffi: *mut *mut c_char,
    prompt: *const c_char,
    default_name: *const c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let prompt = raw_to_string(prompt).unwrap();
    let default_name = raw_to_string(default_name);
    let result = (*ctxt).get_directory_name_input(&prompt, default_name);
    if let Some(result) = result {
        unsafe { *result_ffi = BnString::into_raw(BnString::new(result)) };
        true
    } else {
        unsafe { *result_ffi = ptr::null_mut() };
        false
    }
}

unsafe extern "C" fn cb_get_form_input<R: InteractionHandler>(
    ctxt: *mut c_void,
    fields: *mut BNFormInputField,
    count: usize,
    title: *const c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let raw_fields = unsafe { core::slice::from_raw_parts_mut(fields, count) };
    let fields: Vec<_> = raw_fields
        .iter_mut()
        .map(|x| FormInputField::from_raw(x))
        .collect();
    let title = raw_to_string(title).unwrap();
    let mut form = Form::new_with_fields(title, fields);
    let results = (*ctxt).get_form_input(&mut form);
    // Update the fields with the new values. Freeing the old ones.
    raw_fields
        .iter_mut()
        .enumerate()
        .for_each(|(idx, raw_field)| {
            FormInputField::free_raw(*raw_field);
            *raw_field = form.fields[idx].into_raw();
        });
    results
}

unsafe extern "C" fn cb_show_message_box<R: InteractionHandler>(
    ctxt: *mut c_void,
    title: *const c_char,
    text: *const c_char,
    buttons: BNMessageBoxButtonSet,
    icon: BNMessageBoxIcon,
) -> BNMessageBoxButtonResult {
    let ctxt = ctxt as *mut R;
    let title = raw_to_string(title).unwrap();
    let text = raw_to_string(text).unwrap();
    (*ctxt).show_message_box(&title, &text, buttons, icon)
}

unsafe extern "C" fn cb_open_url<R: InteractionHandler>(
    ctxt: *mut c_void,
    url: *const c_char,
) -> bool {
    let ctxt = ctxt as *mut R;
    let url = raw_to_string(url).unwrap();
    (*ctxt).open_url(&url)
}

unsafe extern "C" fn cb_run_progress_dialog<R: InteractionHandler>(
    ctxt: *mut c_void,
    title: *const c_char,
    can_cancel: bool,
    task: Option<
        unsafe extern "C" fn(
            *mut c_void,
            Option<unsafe extern "C" fn(*mut c_void, usize, usize) -> bool>,
            *mut c_void,
        ),
    >,
    task_ctxt: *mut c_void,
) -> bool {
    let ctxt = ctxt as *mut R;
    let title = raw_to_string(title).unwrap();
    let task = InteractionHandlerTask {
        ctxt: task_ctxt,
        task,
    };
    (*ctxt).run_progress_dialog(&title, can_cancel, &task)
}
