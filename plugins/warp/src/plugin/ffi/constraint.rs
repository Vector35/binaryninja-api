use crate::plugin::ffi::{BNWARPConstraintGUID, BNWarpConstraint};
use std::mem::ManuallyDrop;
use std::sync::Arc;
use warp::signature::constraint::UNRELATED_OFFSET;

#[no_mangle]
pub unsafe extern "C" fn BNWARPConstraintGetGUID(
    constraint: *mut BNWarpConstraint,
) -> BNWARPConstraintGUID {
    // We do not own constraint so we should not drop.
    let constraint = unsafe { ManuallyDrop::new(Arc::from_raw(constraint)) };
    constraint.guid
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPConstraintGetOffset(constraint: *mut BNWarpConstraint) -> i64 {
    // We do not own constraint so we should not drop.
    let constraint = unsafe { ManuallyDrop::new(Arc::from_raw(constraint)) };
    constraint.offset.unwrap_or(UNRELATED_OFFSET)
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPNewConstraintReference(
    constraint: *mut BNWarpConstraint,
) -> *mut BNWarpConstraint {
    Arc::increment_strong_count(constraint);
    constraint
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeConstraintReference(constraint: *mut BNWarpConstraint) {
    if constraint.is_null() {
        return;
    }
    Arc::decrement_strong_count(constraint);
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeConstraintList(
    constraints: *mut *mut BNWarpConstraint,
    count: usize,
) {
    let constraints_ptr = std::ptr::slice_from_raw_parts_mut(constraints, count);
    let constraints = unsafe { Box::from_raw(constraints_ptr) };
    for constraint in constraints {
        // NOTE: The constraints themselves should also be arc.
        BNWARPFreeConstraintReference(constraint);
    }
}
