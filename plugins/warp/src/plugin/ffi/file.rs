use std::ffi::c_char;
use std::sync::Arc;
use warp::WarpFile;

pub type BNWARPFile = WarpFile<'static>;

// TODO: At some point we may want to expose chunks directly. For now we will just enumerate all of them.
// pub type BNWARPChunk = warp::chunk::Chunk<'static>;

// TODO: From bytes as well.
#[no_mangle]
pub unsafe extern "C" fn BNWARPNewFileFromPath(path: *mut c_char) -> *mut BNWARPFile {
    let path_cstr = unsafe { std::ffi::CStr::from_ptr(path) };
    let Ok(path) = path_cstr.to_str() else {
        return std::ptr::null_mut();
    };
    let Ok(bytes) = std::fs::read(path) else {
        return std::ptr::null_mut();
    };
    let Some(file) = WarpFile::from_owned_bytes(bytes) else {
        return std::ptr::null_mut();
    };
    Arc::into_raw(Arc::new(file)) as *mut BNWARPFile
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPNewFileReference(file: *mut BNWARPFile) -> *mut BNWARPFile {
    Arc::increment_strong_count(file);
    file
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeFileReference(file: *mut BNWARPFile) {
    if file.is_null() {
        return;
    }
    Arc::decrement_strong_count(file);
}
