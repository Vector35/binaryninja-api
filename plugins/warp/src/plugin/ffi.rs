mod container;
mod file;
mod function;

use binaryninjacore_sys::{
    BNBasicBlock, BNBinaryView, BNFunction, BNLowLevelILFunction, BNPlatform,
};
use std::ffi::c_char;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use binaryninja::basic_block::{BasicBlock, BasicBlockType};
use binaryninja::function::{Function, NativeBlock};

use crate::cache::cached_function_guid;
use crate::container::{Container, SourceId};
use crate::convert::platform_to_target;
use crate::plugin::workflow::run_matcher;
use crate::{
    basic_block_guid, is_blacklisted_instruction, is_computed_variant_instruction,
    is_variant_instruction, relocatable_regions,
};
use binaryninja::binary_view::BinaryView;
use binaryninja::low_level_il::function::{LowLevelILFunction, Mutable, NonSSA};
use binaryninja::low_level_il::instruction::LowLevelInstructionIndex;
use binaryninja::platform::Platform;
use binaryninja::string::BnString;
use warp::r#type::guid::TypeGUID;
use warp::signature::basic_block::BasicBlockGUID;
use warp::signature::constraint::{Constraint, ConstraintGUID, UNRELATED_OFFSET};
use warp::signature::function::FunctionGUID;

/// [`SourceId`] is marked transparent to the underlying `[u8; 16]`, safe to use directly in FFI.
pub type BNWARPSource = SourceId;

/// [`BasicBlockGUID`] is marked transparent to the underlying `[u8; 16]`, safe to use directly in FFI.
pub type BNWARPBasicBlockGUID = BasicBlockGUID;

/// [`ConstraintGUID`] is marked transparent to the underlying `[u8; 16]`, safe to use directly in FFI.
pub type BNWARPConstraintGUID = ConstraintGUID;

/// [`FunctionGUID`] is marked transparent to the underlying `[u8; 16]`, safe to use directly in FFI.
pub type BNWARPFunctionGUID = FunctionGUID;

/// [`TypeGUID`] is marked transparent to the underlying `[u8; 16]`, safe to use directly in FFI.
pub type BNWARPTypeGUID = TypeGUID;

pub type BNWARPTarget = warp::target::Target;
pub type BNWARPFunction = warp::signature::function::Function;
pub type BNWARPContainer = RwLock<Box<dyn Container>>;

// TODO: Some sort of callback for loading functions
// TODO: Be able to run matcher for a specific file
// TODO: Generate signatures for a file, return what?

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BNWARPConstraint {
    guid: BNWARPConstraintGUID,
    offset: i64,
}

impl From<BNWARPConstraint> for Constraint {
    fn from(constraint: BNWARPConstraint) -> Self {
        Constraint {
            guid: constraint.guid,
            offset: match constraint.offset {
                UNRELATED_OFFSET => None,
                _ => Some(constraint.offset),
            },
        }
    }
}

impl From<Constraint> for BNWARPConstraint {
    fn from(constraint: Constraint) -> Self {
        BNWARPConstraint {
            guid: constraint.guid,
            offset: constraint.offset.unwrap_or(UNRELATED_OFFSET),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPUUIDGetString(uuid: *const Uuid) -> *mut c_char {
    let uuid_str = (*uuid).to_string();
    // NOTE: Leak the uuid string to be freed by BNFreeString
    BnString::into_raw(uuid_str.into())
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPUUIDFromString(uuid_str: *mut c_char, uuid: *mut Uuid) -> bool {
    if let Ok(uuid_str) = std::ffi::CStr::from_ptr(uuid_str).to_str() {
        if let Some(parsed_uuid) = Uuid::parse_str(uuid_str).ok() {
            *uuid = parsed_uuid;
            return true;
        }
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPUUIDEqual(a: *const Uuid, b: *const Uuid) -> bool {
    (*a) == (*b)
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPRunMatcher(view: *mut BNBinaryView) {
    let view = BinaryView::from_raw(view);
    run_matcher(&view)
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPGetBasicBlockGUID(
    basic_block: *mut BNBasicBlock,
    result: *mut BNWARPBasicBlockGUID,
) -> bool {
    let basic_block = unsafe { BasicBlock::from_raw(basic_block, NativeBlock::new()) };
    if basic_block.block_type() != BasicBlockType::Native {
        return false;
    }
    let function = basic_block.function();
    match function.lifted_il() {
        Ok(lifted_il) => {
            let relocatable_regions = relocatable_regions(&function.view());
            *result = basic_block_guid(&relocatable_regions, &basic_block, &lifted_il);
            true
        }
        Err(_) => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPGetAnalysisFunctionGUID(
    analysis_function: *mut BNFunction,
    result: *mut BNWARPFunctionGUID,
) -> bool {
    let function = unsafe { Function::from_raw(analysis_function) };
    match cached_function_guid(&function, || function.lifted_il().ok()) {
        Some(guid) => {
            *result = guid;
            true
        }
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPIsLiftedInstructionVariant(
    analysis_function: *mut BNLowLevelILFunction,
    index: LowLevelInstructionIndex,
) -> bool {
    let lifted_il: LowLevelILFunction<Mutable, NonSSA> =
        unsafe { LowLevelILFunction::from_raw(analysis_function) };
    match lifted_il.instruction_from_index(index) {
        Some(instr) => {
            let Some(owner_function) = lifted_il.function() else {
                return false;
            };
            let relocatable_regions = relocatable_regions(&owner_function.view());
            is_variant_instruction(&relocatable_regions, &instr)
        }
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPIsLowLevelInstructionComputedVariant(
    analysis_function: *mut BNLowLevelILFunction,
    index: LowLevelInstructionIndex,
) -> bool {
    let llil: LowLevelILFunction<Mutable, NonSSA> =
        unsafe { LowLevelILFunction::from_raw(analysis_function) };
    match llil.instruction_from_index(index) {
        Some(instr) => {
            let Some(owner_function) = llil.function() else {
                return false;
            };
            let relocatable_regions = relocatable_regions(&owner_function.view());
            is_computed_variant_instruction(&relocatable_regions, &instr)
        }
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPIsLiftedInstructionBlacklisted(
    analysis_function: *mut BNLowLevelILFunction,
    index: LowLevelInstructionIndex,
) -> bool {
    let lifted_il: LowLevelILFunction<Mutable, NonSSA> =
        unsafe { LowLevelILFunction::from_raw(analysis_function) };
    match lifted_il.instruction_from_index(index) {
        Some(instr) => is_blacklisted_instruction(&instr),
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeUUIDList(uuids: *mut Uuid, count: usize) {
    let sources_ptr = std::ptr::slice_from_raw_parts_mut(uuids, count);
    let _ = unsafe { Box::from_raw(sources_ptr) };
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPGetTarget(platform: *mut BNPlatform) -> *mut BNWARPTarget {
    let platform = Platform::from_raw(platform);
    Arc::into_raw(Arc::new(platform_to_target(&platform))) as *mut BNWARPTarget
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPNewTargetReference(target: *mut BNWARPTarget) -> *mut BNWARPTarget {
    Arc::increment_strong_count(target);
    target
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeTargetReference(target: *mut BNWARPTarget) {
    if target.is_null() {
        return;
    }
    Arc::decrement_strong_count(target);
}
