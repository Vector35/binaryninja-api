use crate::cache::container::cached_containers;
use crate::container::SourcePath;
use crate::convert::{from_bn_type, to_bn_type};
use crate::plugin::ffi::{
    BNWARPContainer, BNWARPFunction, BNWARPFunctionGUID, BNWARPSource, BNWARPTarget, BNWARPTypeGUID,
};
use binaryninja::architecture::CoreArchitecture;
use binaryninja::binary_view::BinaryView;
use binaryninja::rc::Ref;
use binaryninja::string::BnString;
use binaryninja::types::Type;
use binaryninjacore_sys::{BNArchitecture, BNBinaryView, BNType};
use std::ffi::{c_char, CStr};
use std::mem::ManuallyDrop;
use std::sync::Arc;

#[no_mangle]
pub unsafe extern "C" fn BNWARPGetContainers(count: *mut usize) -> *mut *mut BNWARPContainer {
    // NOTE: Leak the arc pointers to be freed by BNWARPFreeContainerList
    let boxed_raw_containers: Box<[_]> =
        cached_containers().into_iter().map(Arc::into_raw).collect();
    *count = boxed_raw_containers.len();
    let leaked_raw_containers = Box::into_raw(boxed_raw_containers);
    leaked_raw_containers as *mut *mut BNWARPContainer
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerGetName(container: *mut BNWARPContainer) -> *const c_char {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(container) = arc_container.read() else {
        return std::ptr::null();
    };
    let name = container.to_string();
    // NOTE: Leak the container name to be freed by BNFreeString
    BnString::into_raw(name.into())
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerFetchFunctions(
    container: *mut BNWARPContainer,
    target: *mut BNWARPTarget,
    guids: *const BNWARPFunctionGUID,
    count: usize,
) {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(mut container) = arc_container.write() else {
        return;
    };

    let target = unsafe { ManuallyDrop::new(Arc::from_raw(target)) };

    let guids = unsafe { std::slice::from_raw_parts(guids, count) };

    if let Err(e) = container.fetch_functions(&target, guids) {
        log::error!("Failed to fetch functions: {}", e);
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerGetSources(
    container: *mut BNWARPContainer,
    count: *mut usize,
) -> *mut BNWARPSource {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(container) = arc_container.write() else {
        return std::ptr::null_mut();
    };

    // NOTE: Leak the sources to be freed by BNWARPFreeSourceList
    let boxed_sources: Box<[_]> = container.sources().unwrap_or_default().into_boxed_slice();
    *count = boxed_sources.len();
    Box::into_raw(boxed_sources) as *mut BNWARPSource
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerAddSource(
    container: *mut BNWARPContainer,
    source_path: *const c_char,
    result: *mut BNWARPSource,
) -> bool {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(mut container) = arc_container.write() else {
        return false;
    };

    let source_path_cstr = unsafe { CStr::from_ptr(source_path) };
    let source_path_str = source_path_cstr.to_str().unwrap();
    let source_path = SourcePath::new_with_str(source_path_str);

    match container.add_source(source_path) {
        Ok(source) => {
            // NOTE: Leak the source to be freed by BNFreeString
            *result = source;
            true
        }
        Err(_) => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerCommitSource(
    container: *mut BNWARPContainer,
    source: *const BNWARPSource,
) -> bool {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(mut container) = arc_container.write() else {
        return false;
    };

    let source = unsafe { *source };

    container
        .commit_source(&source)
        .is_ok_and(|committed| committed)
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerIsSourceUncommitted(
    container: *mut BNWARPContainer,
    source: *const BNWARPSource,
) -> bool {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(container) = arc_container.read() else {
        return false;
    };

    let source = unsafe { *source };

    container
        .is_source_uncommitted(&source)
        .is_ok_and(|uncommitted| uncommitted)
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerIsSourceWritable(
    container: *mut BNWARPContainer,
    source: *const BNWARPSource,
) -> bool {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(container) = arc_container.read() else {
        return false;
    };

    let source = unsafe { *source };

    container
        .is_source_writable(&source)
        .is_ok_and(|writable| writable)
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerGetSourcePath(
    container: *mut BNWARPContainer,
    source: *const BNWARPSource,
) -> *const c_char {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(container) = arc_container.read() else {
        return std::ptr::null();
    };

    let source = unsafe { *source };

    match container.source_path(&source) {
        Ok(path) => {
            let path = path.to_string();
            // NOTE: Leak the source path to be freed by BNFreeString
            BnString::into_raw(path.into())
        }
        Err(_) => std::ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerAddFunctions(
    container: *mut BNWARPContainer,
    target: *mut BNWARPTarget,
    source: *const BNWARPSource,
    functions: *mut *mut BNWARPFunction,
    count: usize,
) -> bool {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(mut container) = arc_container.write() else {
        return false;
    };

    let target = unsafe { ManuallyDrop::new(Arc::from_raw(target)) };

    let source = unsafe { *source };

    let functions_ptr = std::slice::from_raw_parts(functions, count);
    // TODO: We have to clone the objects here to make the type checker happy.
    // TODO: See about avoiding this later.
    let functions: Vec<_> = functions_ptr
        .iter()
        .map(|&f| unsafe { ManuallyDrop::new(Arc::from_raw(f)).as_ref().clone() })
        .collect();
    container
        .add_functions(&target, &source, &functions)
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerAddTypes(
    view: *mut BNBinaryView,
    container: *mut BNWARPContainer,
    source: *const BNWARPSource,
    types: *mut *mut BNType,
    count: usize,
) -> bool {
    let view = unsafe { BinaryView::from_raw(view) };

    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(mut container) = arc_container.write() else {
        return false;
    };

    let source = unsafe { *source };

    let types_ptr = std::slice::from_raw_parts(types, count);
    let types: Vec<_> = types_ptr
        .iter()
        .map(|&t| Type::from_raw(t))
        .map(|ty| from_bn_type(&view, &ty, 255))
        .collect();
    container.add_types(&source, &types).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerRemoveFunctions(
    container: *mut BNWARPContainer,
    target: *mut BNWARPTarget,
    source: *const BNWARPSource,
    functions: *mut *mut BNWARPFunction,
    count: usize,
) -> bool {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(mut container) = arc_container.write() else {
        return false;
    };

    let target = unsafe { ManuallyDrop::new(Arc::from_raw(target)) };

    let source = unsafe { *source };

    let functions_ptr = std::slice::from_raw_parts(functions, count);
    // TODO: We have to clone the objects here to make the type checker happy.
    // TODO: See about avoiding this later.
    let functions: Vec<_> = functions_ptr
        .iter()
        .map(|&f| unsafe { ManuallyDrop::new(Arc::from_raw(f)).as_ref().clone() })
        .collect();
    container
        .remove_functions(&target, &source, &functions)
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerRemoveTypes(
    container: *mut BNWARPContainer,
    source: *const BNWARPSource,
    guids: *mut BNWARPTypeGUID,
    count: usize,
) -> bool {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(mut container) = arc_container.write() else {
        return false;
    };

    let source = unsafe { *source };

    let guids = std::slice::from_raw_parts(guids, count);
    container.remove_types(&source, &guids).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerGetSourcesWithFunctionGUID(
    container: *mut BNWARPContainer,
    target: *mut BNWARPTarget,
    guid: *const BNWARPFunctionGUID,
    count: *mut usize,
) -> *mut BNWARPSource {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(container) = arc_container.read() else {
        return std::ptr::null_mut();
    };

    let target = unsafe { ManuallyDrop::new(Arc::from_raw(target)) };

    let guid = unsafe { *guid };

    // NOTE: Leak the sources to be freed by BNWARPFreeSourceList
    let boxed_sources: Box<[_]> = container
        .sources_with_function_guid(&target, &guid)
        .unwrap_or_default()
        .into_boxed_slice();
    *count = boxed_sources.len();
    Box::into_raw(boxed_sources) as *mut BNWARPSource
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerGetSourcesWithTypeGUID(
    container: *mut BNWARPContainer,
    guid: *const BNWARPTypeGUID,
    count: *mut usize,
) -> *mut BNWARPSource {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(container) = arc_container.read() else {
        return std::ptr::null_mut();
    };

    let guid = unsafe { *guid };

    // NOTE: Leak the sources to be freed by BNWARPFreeSourceList
    let boxed_sources: Box<[_]> = container
        .sources_with_type_guid(&guid)
        .unwrap_or_default()
        .into_boxed_slice();
    *count = boxed_sources.len();
    Box::into_raw(boxed_sources) as *mut BNWARPSource
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerGetFunctionsWithGUID(
    container: *mut BNWARPContainer,
    target: *mut BNWARPTarget,
    source: *const BNWARPSource,
    guid: *const BNWARPFunctionGUID,
    count: *mut usize,
) -> *mut *mut BNWARPFunction {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(container) = arc_container.read() else {
        return std::ptr::null_mut();
    };

    let source = unsafe { *source };

    let target = unsafe { ManuallyDrop::new(Arc::from_raw(target)) };

    let guid = unsafe { *guid };

    // NOTE: Leak the functions to be freed by BNWARPFreeFunctionList
    let raw_boxed_functions: Box<[_]> = container
        .functions_with_guid(&target, &source, &guid)
        .unwrap_or_default()
        .into_iter()
        .map(Arc::new)
        .map(Arc::into_raw)
        .collect();
    *count = raw_boxed_functions.len();
    Box::into_raw(raw_boxed_functions) as *mut *mut BNWARPFunction
}

// TODO: Swap arch to Target?
#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerGetTypeWithGUID(
    arch: *mut BNArchitecture,
    container: *mut BNWARPContainer,
    source: *const BNWARPSource,
    guid: *const BNWARPTypeGUID,
) -> *mut BNType {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(container) = arc_container.read() else {
        return std::ptr::null_mut();
    };

    // NOTE: to convert the type, we must have an architecture.
    let arch = CoreArchitecture::from_raw(arch);

    let source = unsafe { *source };

    let guid = unsafe { *guid };

    let Some(ty) = container.type_with_guid(&source, &guid).unwrap_or_default() else {
        return std::ptr::null_mut();
    };
    let function_type = to_bn_type(&arch, &ty);
    // NOTE: The type ref has been pre-incremented for the caller.
    unsafe { Ref::into_raw(function_type) }.handle
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPContainerGetTypeGUIDsWithName(
    container: *mut BNWARPContainer,
    source: *const BNWARPSource,
    name: *const c_char,
    count: *mut usize,
) -> *mut BNWARPTypeGUID {
    let arc_container = ManuallyDrop::new(Arc::from_raw(container));
    let Ok(container) = arc_container.read() else {
        return std::ptr::null_mut();
    };

    let source = unsafe { *source };

    let name_cstr = unsafe { CStr::from_ptr(name) };
    let name = name_cstr.to_str().unwrap();

    // NOTE: Leak the guids to be freed by BNWARPFreeTypeGUIDList
    let boxed_guids = container
        .type_guids_with_name(&source, name)
        .unwrap_or_default()
        .into_boxed_slice();
    *count = boxed_guids.len();
    Box::into_raw(boxed_guids) as *mut BNWARPTypeGUID
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPNewContainerReference(
    container: *mut BNWARPContainer,
) -> *mut BNWARPContainer {
    Arc::increment_strong_count(container);
    container
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeContainerReference(container: *mut BNWARPContainer) {
    if container.is_null() {
        return;
    }
    Arc::decrement_strong_count(container);
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeContainerList(
    containers: *mut *mut BNWARPContainer,
    count: usize,
) {
    let containers_ptr = std::ptr::slice_from_raw_parts_mut(containers, count);
    let containers = unsafe { Box::from_raw(containers_ptr) };
    for container in containers {
        BNWARPFreeContainerReference(container);
    }
}
