use std::ffi::c_void;
use std::ptr::NonNull;

use binaryninjacore_sys::*;

use crate::disassembly::DisassemblyTextLine;
use crate::high_level_il::HighLevelILFunction;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{raw_to_string, BnString, IntoCStr};

/// Register a [`LineFormatter`] with the API.
pub fn register_line_formatter<C: LineFormatter>(name: &str, formatter: C) -> CoreLineFormatter {
    let custom = Box::leak(Box::new(formatter));
    let mut callbacks = BNCustomLineFormatter {
        context: custom as *mut C as *mut c_void,
        formatLines: Some(cb_format_lines::<C>),
        freeLines: Some(cb_free_lines),
    };
    let name = name.to_cstr();
    let handle = unsafe { BNRegisterLineFormatter(name.as_ptr(), &mut callbacks) };
    CoreLineFormatter::from_raw(NonNull::new(handle).unwrap())
}

pub trait LineFormatter: Sized {
    fn format_lines(
        &self,
        lines: &[DisassemblyTextLine],
        settings: &LineFormatterSettings,
    ) -> Vec<DisassemblyTextLine>;
}

#[repr(transparent)]
pub struct CoreLineFormatter {
    pub(crate) handle: NonNull<BNLineFormatter>,
}

impl CoreLineFormatter {
    pub fn from_raw(handle: NonNull<BNLineFormatter>) -> Self {
        Self { handle }
    }

    /// Get the default [`CoreLineFormatter`] if available, because the user might have disabled it.
    pub fn default_if_available() -> Option<Self> {
        Some(unsafe { Self::from_raw(NonNull::new(BNGetDefaultLineFormatter())?) })
    }

    pub fn all() -> Array<CoreLineFormatter> {
        let mut count = 0;
        let result = unsafe { BNGetLineFormatterList(&mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn from_name(name: &str) -> Option<CoreLineFormatter> {
        let name_raw = name.to_cstr();
        let result = unsafe { BNGetLineFormatterByName(name_raw.as_ptr()) };
        NonNull::new(result).map(Self::from_raw)
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetLineFormatterName(self.handle.as_ptr())) }
    }
}

impl CoreArrayProvider for CoreLineFormatter {
    type Raw = *mut BNLineFormatter;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CoreLineFormatter {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeLineFormatterList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // TODO: Because handle is a NonNull we should prob make Self::Raw that as well...
        let handle = NonNull::new(*raw).unwrap();
        CoreLineFormatter::from_raw(handle)
    }
}

#[derive(Clone, Debug)]
pub struct LineFormatterSettings {
    pub high_level_il: Option<Ref<HighLevelILFunction>>,
    pub desired_line_len: usize,
    pub min_content_len: usize,
    pub tab_width: usize,
    pub lang_name: String,
    pub comment_start: String,
    pub comment_end: String,
    pub annotation_start: String,
    pub annotation_end: String,
}

impl LineFormatterSettings {
    pub(crate) fn from_raw(value: &BNLineFormatterSettings) -> Self {
        Self {
            high_level_il: match value.highLevelIL.is_null() {
                false => Some(
                    unsafe { HighLevelILFunction::from_raw(value.highLevelIL, false) }.to_owned(),
                ),
                true => None,
            },
            desired_line_len: value.desiredLineLength,
            min_content_len: value.minimumContentLength,
            tab_width: value.tabWidth,
            lang_name: raw_to_string(value.languageName as *mut _).unwrap(),
            comment_start: raw_to_string(value.commentStartString as *mut _).unwrap(),
            comment_end: raw_to_string(value.commentEndString as *mut _).unwrap(),
            annotation_start: raw_to_string(value.annotationStartString as *mut _).unwrap(),
            annotation_end: raw_to_string(value.annotationEndString as *mut _).unwrap(),
        }
    }

    #[allow(unused)]
    pub(crate) fn from_owned_raw(value: BNLineFormatterSettings) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    #[allow(unused)]
    pub(crate) fn free_raw(value: BNLineFormatterSettings) {
        let _ = unsafe { HighLevelILFunction::ref_from_raw(value.highLevelIL, false) };
        let _ = unsafe { BnString::from_raw(value.languageName as *mut _) };
        let _ = unsafe { BnString::from_raw(value.commentStartString as *mut _) };
        let _ = unsafe { BnString::from_raw(value.commentEndString as *mut _) };
        let _ = unsafe { BnString::from_raw(value.annotationStartString as *mut _) };
        let _ = unsafe { BnString::from_raw(value.annotationEndString as *mut _) };
    }
}

unsafe extern "C" fn cb_format_lines<C: LineFormatter>(
    ctxt: *mut c_void,
    in_lines: *mut BNDisassemblyTextLine,
    in_count: usize,
    raw_settings: *const BNLineFormatterSettings,
    out_count: *mut usize,
) -> *mut BNDisassemblyTextLine {
    // NOTE dropped by line_formatter_free_lines_ffi
    let ctxt = ctxt as *mut C;
    let lines_slice = core::slice::from_raw_parts(in_lines, in_count);
    let lines: Vec<_> = lines_slice
        .iter()
        .map(DisassemblyTextLine::from_raw)
        .collect();
    let settings = LineFormatterSettings::from_raw(&*raw_settings);
    let result = (*ctxt).format_lines(&lines, &settings);
    *out_count = result.len();
    let result: Box<[BNDisassemblyTextLine]> = result
        .into_iter()
        .map(DisassemblyTextLine::into_raw)
        .collect();
    Box::leak(result).as_mut_ptr()
}

unsafe extern "C" fn cb_free_lines(
    _ctxt: *mut c_void,
    raw_lines: *mut BNDisassemblyTextLine,
    count: usize,
) {
    let lines: Box<[BNDisassemblyTextLine]> =
        Box::from_raw(core::slice::from_raw_parts_mut(raw_lines, count));
    for line in lines {
        DisassemblyTextLine::free_raw(line);
    }
}
