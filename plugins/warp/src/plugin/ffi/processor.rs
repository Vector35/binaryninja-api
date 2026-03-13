use crate::plugin::ffi::file::{BNWARPFile, RcWarpFile};
use crate::processor::{
    IncludedDataField, IncludedFunctionsField, ProcessingFileState, WarpFileProcessor,
    WarpFileProcessorEntry,
};
use binaryninja::binary_view::BinaryView;
use binaryninja::project::file::ProjectFile;
use binaryninja::project::Project;
use binaryninjacore_sys::{BNBinaryView, BNProject, BNProjectFile};
use std::ffi::{c_char, CStr, CString};
use std::mem::ManuallyDrop;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::Arc;
use warp::chunk::CompressionType;

pub type BNWARPProcessor = WarpFileProcessor;

#[repr(C)]
pub struct BNWARPProcessorState {
    cancelled: bool,
    unprocessed_files_count: usize,
    processed_files_count: usize,
    analyzing_files: *mut *mut c_char,
    analyzing_files_count: usize,
    processing_files: *mut *mut c_char,
    processing_files_count: usize,
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPNewProcessor(
    included_data: IncludedDataField,
    included_functions: IncludedFunctionsField,
    worker_count: usize,
) -> *mut BNWARPProcessor {
    let processor = WarpFileProcessor::new()
        .with_file_data(included_data)
        .with_included_functions(included_functions)
        .with_compression_type(CompressionType::Zstd)
        .with_entry_worker_count(worker_count);
    Box::into_raw(Box::new(processor))
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPProcessorAddPath(
    processor: *mut BNWARPProcessor,
    path: *const c_char,
) {
    let mut processor = ManuallyDrop::new(Box::from_raw(processor));
    let path_cstr = unsafe { CStr::from_ptr(path) };
    let path = PathBuf::from(path_cstr.to_str().unwrap());
    // TODO: Not thread safe.
    processor.add_entry(WarpFileProcessorEntry::Path(path));
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPProcessorAddProject(
    processor: *mut BNWARPProcessor,
    project: *mut BNProject,
) {
    let mut processor = ManuallyDrop::new(Box::from_raw(processor));
    let project = Project::from_raw(NonNull::new(project).unwrap());
    // TODO: Not thread safe.
    processor.add_entry(WarpFileProcessorEntry::Project(project.to_owned()));
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPProcessorAddProjectFile(
    processor: *mut BNWARPProcessor,
    project_file: *mut BNProjectFile,
) {
    let mut processor = ManuallyDrop::new(Box::from_raw(processor));
    let project_file = ProjectFile::from_raw(NonNull::new(project_file).unwrap());
    // TODO: Not thread safe.
    processor.add_entry(WarpFileProcessorEntry::ProjectFile(project_file.to_owned()));
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPProcessorAddBinaryView(
    processor: *mut BNWARPProcessor,
    view: *mut BNBinaryView,
) {
    let mut processor = ManuallyDrop::new(Box::from_raw(processor));
    let view = BinaryView::from_raw(view);
    // TODO: Not thread safe.
    processor.add_entry(WarpFileProcessorEntry::BinaryView(view.to_owned()));
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPProcessorStart(processor: *mut BNWARPProcessor) -> *mut BNWARPFile {
    let mut processor = ManuallyDrop::new(Box::from_raw(processor));
    // TODO: Not thread safe.
    match processor.process_entries() {
        Ok(file) => {
            let rc_file = RcWarpFile::from(file);
            Arc::into_raw(Arc::new(rc_file)) as *mut BNWARPFile
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPProcessorIsCancelled(processor: *mut BNWARPProcessor) -> bool {
    let processor = ManuallyDrop::new(Box::from_raw(processor));
    processor
        .state()
        .cancelled
        .load(std::sync::atomic::Ordering::Relaxed)
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPProcessorCancel(processor: *mut BNWARPProcessor) {
    let processor = ManuallyDrop::new(Box::from_raw(processor));
    processor
        .state()
        .cancelled
        .store(true, std::sync::atomic::Ordering::Relaxed)
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPProcessorGetState(
    processor: *mut BNWARPProcessor,
) -> BNWARPProcessorState {
    let processor = ManuallyDrop::new(Box::from_raw(processor));
    let processor_state = processor.state();

    let mut unprocessed_files_count = 0;
    let mut processed_files_count = 0;
    let mut analyzing_files = Vec::new();
    let mut processing_files = Vec::new();

    for file_state in &processor_state.files {
        match file_state.value() {
            ProcessingFileState::Unprocessed => unprocessed_files_count += 1,
            ProcessingFileState::Analyzing => analyzing_files.push(file_state.key().clone()),
            ProcessingFileState::Processing => processing_files.push(file_state.key().clone()),
            ProcessingFileState::Processed => processed_files_count += 1,
        }
    }

    let raw_analyzing_files: Box<[_]> = analyzing_files
        .into_iter()
        .map(|p| CString::new(p.to_str().unwrap()).unwrap().into_raw())
        .collect();
    let raw_analyzing_files_count = raw_analyzing_files.len();
    let raw_analyzing_files_ptr = Box::into_raw(raw_analyzing_files);

    let raw_processing_files: Box<[_]> = processing_files
        .into_iter()
        .map(|p| CString::new(p.to_str().unwrap()).unwrap().into_raw())
        .collect();
    let raw_processing_files_count = raw_processing_files.len();
    let raw_processing_files_ptr = Box::into_raw(raw_processing_files);

    BNWARPProcessorState {
        cancelled: processor_state
            .cancelled
            .load(std::sync::atomic::Ordering::Relaxed),
        unprocessed_files_count,
        processed_files_count,
        analyzing_files: raw_analyzing_files_ptr as *mut *mut c_char,
        analyzing_files_count: raw_analyzing_files_count,
        processing_files: raw_processing_files_ptr as *mut *mut c_char,
        processing_files_count: raw_processing_files_count,
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeProcessor(processor: *mut BNWARPProcessor) {
    let _ = Box::from_raw(processor);
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeProcessorState(state: BNWARPProcessorState) {
    let a_files_ptr =
        std::ptr::slice_from_raw_parts_mut(state.analyzing_files, state.analyzing_files_count);
    let a_files_boxed = unsafe { Box::from_raw(a_files_ptr) };
    for path in a_files_boxed.iter() {
        let _ = CString::from_raw(*path);
    }
    let p_files_ptr =
        std::ptr::slice_from_raw_parts_mut(state.processing_files, state.processing_files_count);
    let p_files_boxed = unsafe { Box::from_raw(p_files_ptr) };
    for path in p_files_boxed.iter() {
        let _ = CString::from_raw(*path);
    }
}
