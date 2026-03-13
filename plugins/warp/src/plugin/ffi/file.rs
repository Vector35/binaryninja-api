use crate::plugin::ffi::{BNWARPFunction, BNWARPTarget, BNWARPType};
use binaryninja::data_buffer::DataBuffer;
use binaryninjacore_sys::BNDataBuffer;
use std::ffi::c_char;
use std::mem::ManuallyDrop;
use std::sync::Arc;
use warp::chunk::ChunkKind;
use warp::{WarpFile, WarpFileHeader};

/// A [`WarpFile`] wrapper that uses reference counting to manage its chunks lifetime.
///
/// Used primarily when passing to the C FFI so that chunks do not need to have a complicated lifetime.
pub struct RcWarpFile {
    pub header: WarpFileHeader,
    pub chunks: Vec<Arc<warp::chunk::Chunk<'static>>>,
}

impl From<WarpFile<'static>> for RcWarpFile {
    fn from(file: WarpFile<'static>) -> Self {
        let chunks = file.chunks.into_iter().map(|c| Arc::new(c)).collect();
        Self {
            header: file.header,
            chunks,
        }
    }
}

impl From<&RcWarpFile> for WarpFile<'static> {
    fn from(rc_file: &RcWarpFile) -> Self {
        let chunks = rc_file.chunks.iter().map(|c| (**c).clone()).collect();
        Self {
            header: rc_file.header.clone(),
            chunks,
        }
    }
}

pub type BNWARPFile = RcWarpFile;

pub type BNWARPChunk = warp::chunk::Chunk<'static>;

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
    let rc_file = RcWarpFile::from(file);
    Arc::into_raw(Arc::new(rc_file)) as *mut BNWARPFile
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFileGetChunks(
    file: *mut BNWARPFile,
    count: *mut usize,
) -> *mut *mut BNWARPChunk {
    let arc_file = ManuallyDrop::new(Arc::from_raw(file));
    *count = arc_file.chunks.len();
    let boxed_chunks: Box<[_]> = arc_file
        .chunks
        .iter()
        .map(|c| Arc::into_raw(c.clone()))
        .collect();
    Box::into_raw(boxed_chunks) as *mut *mut BNWARPChunk
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFileToDataBuffer(file: *mut BNWARPFile) -> *mut BNDataBuffer {
    let arc_file = ManuallyDrop::new(Arc::from_raw(file));
    let warp_file = WarpFile::from(arc_file.as_ref());
    let buffer = DataBuffer::new(&warp_file.to_bytes());
    buffer.into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPChunkGetTarget(chunk: *const BNWARPChunk) -> *mut BNWARPTarget {
    let chunk = unsafe { &*chunk };
    let chunk_target = chunk.header.target.clone();
    Arc::into_raw(Arc::new(chunk_target)) as *mut BNWARPTarget
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPChunkGetFunctions(
    chunk: *const BNWARPChunk,
    count: *mut usize,
) -> *mut *mut BNWARPFunction {
    let chunk = unsafe { &*chunk };
    match &chunk.kind {
        ChunkKind::Signature(sc) => {
            let boxed_funcs: Box<[_]> = sc
                .functions()
                .into_iter()
                .map(|f| Arc::into_raw(Arc::new(f.clone())))
                .collect();
            *count = boxed_funcs.len();
            Box::into_raw(boxed_funcs) as *mut *mut BNWARPFunction
        }
        ChunkKind::Type(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPChunkGetTypes(
    chunk: *const BNWARPChunk,
    count: *mut usize,
) -> *mut *mut BNWARPType {
    let chunk = unsafe { &*chunk };
    match &chunk.kind {
        ChunkKind::Signature(_) => std::ptr::null_mut(),
        ChunkKind::Type(tc) => {
            let boxed_types: Box<[_]> = tc
                .types()
                .into_iter()
                .map(|t| Arc::into_raw(Arc::new(t.ty.clone())))
                .collect();
            *count = boxed_types.len();
            Box::into_raw(boxed_types) as *mut *mut BNWARPType
        }
    }
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

#[no_mangle]
pub unsafe extern "C" fn BNWARPNewChunkReference(chunk: *mut BNWARPChunk) -> *mut BNWARPChunk {
    Arc::increment_strong_count(chunk);
    chunk
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeChunkReference(chunk: *mut BNWARPChunk) {
    if chunk.is_null() {
        return;
    }
    Arc::decrement_strong_count(chunk);
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeChunkList(chunks: *mut *mut BNWARPChunk, count: usize) {
    let chunks_ptr = std::ptr::slice_from_raw_parts_mut(chunks, count);
    let chunks = unsafe { Box::from_raw(chunks_ptr) };
    for chunk in chunks {
        // NOTE: The chunks themselves should also be arc.
        BNWARPFreeChunkReference(chunk);
    }
}
