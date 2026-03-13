use crate::convert::{from_bn_type, to_bn_type};
use crate::plugin::ffi::BNWARPType;
use binaryninja::architecture::CoreArchitecture;
use binaryninja::binary_view::BinaryView;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::rc::Ref as BnRef;
use binaryninja::string::BnString;
use binaryninja::types::Type;
use binaryninjacore_sys::{BNArchitecture, BNType};
use std::ffi::c_char;
use std::mem::ManuallyDrop;
use std::sync::Arc;

#[no_mangle]
pub unsafe extern "C" fn BNWARPGetType(
    analysis_type: *mut BNType,
    confidence: u8,
) -> *mut BNWARPType {
    let analysis_type = Type::from_raw(analysis_type);
    // TODO: This will leak a bunch of memory, but we need to remove the view requirement anyways.
    let binary_view = BinaryView::from_data(&FileMetadata::new(), &[]);
    let ty = from_bn_type(&binary_view, &analysis_type, confidence);
    Arc::into_raw(Arc::new(ty)) as *mut BNWARPType
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPTypeGetName(ty: *mut BNWARPType) -> *mut c_char {
    let ty = ManuallyDrop::new(Arc::from_raw(ty));
    match ty.name.as_deref() {
        Some(name) => BnString::into_raw(BnString::new(name)),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPTypeGetConfidence(ty: *mut BNWARPType) -> u8 {
    let ty = ManuallyDrop::new(Arc::from_raw(ty));
    ty.confidence
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPTypeGetAnalysisType(
    arch: *mut BNArchitecture,
    ty: *mut BNWARPType,
) -> *mut BNType {
    let ty = ManuallyDrop::new(Arc::from_raw(ty));
    let analysis_ty = match arch.is_null() {
        true => to_bn_type::<CoreArchitecture>(None, &ty),
        false => to_bn_type(Some(CoreArchitecture::from_raw(arch)), &ty),
    };
    BnRef::into_raw(analysis_ty).handle
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPNewTypeReference(ty: *mut BNWARPType) -> *mut BNWARPType {
    Arc::increment_strong_count(ty);
    ty
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeTypeReference(ty: *mut BNWARPType) {
    if ty.is_null() {
        return;
    }
    Arc::decrement_strong_count(ty);
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeTypeList(types: *mut *mut BNWARPType, count: usize) {
    let types_ptr = std::ptr::slice_from_raw_parts_mut(types, count);
    let types = unsafe { Box::from_raw(types_ptr) };
    for ty in types {
        unsafe { BNWARPFreeTypeReference(ty) };
    }
}
