use crate::build_function;
use crate::cache::{insert_cached_function_match, try_cached_function_match};
use crate::convert::{to_bn_symbol_at_address, to_bn_type};
use crate::plugin::ffi::{BNWARPConstraint, BNWARPFunction, BNWARPFunctionGUID};
use binaryninja::function::Function;
use binaryninja::rc::Ref;
use binaryninja::string::BnString;
use binaryninjacore_sys::{BNFunction, BNSymbol, BNType};
use std::ffi::c_char;
use std::mem::ManuallyDrop;
use std::sync::Arc;
use warp::signature::comment::FunctionComment;

#[repr(C)]
pub struct BNWarpFunctionComment {
    pub text: *mut c_char,
    pub offset: i64,
}

impl BNWarpFunctionComment {
    /// Leaks the text string to be freed with BNWARPFreeFunctionComment
    pub fn from_owned(value: &FunctionComment) -> Self {
        let text = BnString::into_raw(BnString::new(&value.text));
        Self {
            text,
            offset: value.offset,
        }
    }

    pub unsafe fn free_raw(value: &Self) {
        unsafe { BnString::free_raw(value.text) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPGetFunction(
    analysis_function: *mut BNFunction,
) -> *mut BNWARPFunction {
    let function = Function::from_raw(analysis_function);
    match build_function(&function, || function.lifted_il().ok(), false) {
        Some(function) => Arc::into_raw(Arc::new(function)) as *mut BNWARPFunction,
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPGetMatchedFunction(
    analysis_function: *mut BNFunction,
) -> *mut BNWARPFunction {
    let function = Function::from_raw(analysis_function);
    match try_cached_function_match(&function) {
        Some(matched_function) => {
            let arc_matched_function = Arc::new(matched_function);
            // NOTE: Freed by BNWARPFreeFunctionReference
            Arc::into_raw(arc_matched_function) as *mut BNWARPFunction
        }
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFunctionApply(
    function: *mut BNWARPFunction,
    analysis_function: *mut BNFunction,
) {
    let analysis_function = Function::from_raw(analysis_function);
    match function.is_null() {
        false => {
            // Set the matched function to `function`.
            let matched_function = ManuallyDrop::new(Arc::from_raw(function));
            insert_cached_function_match(
                &analysis_function,
                Some(matched_function.as_ref().clone()),
            )
        }
        true => {
            // We are removing the previous match.
            insert_cached_function_match(&analysis_function, None)
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFunctionGetGUID(
    function: *mut BNWARPFunction,
) -> BNWARPFunctionGUID {
    // We do not own function so we should not drop.
    let function = ManuallyDrop::new(Arc::from_raw(function));
    function.guid
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFunctionGetSymbol(
    function: *mut BNWARPFunction,
    analysis_function: *mut BNFunction,
) -> *mut BNSymbol {
    let analysis_function = Function::from_raw(analysis_function);
    // We do not own function so we should not drop.
    let function = ManuallyDrop::new(Arc::from_raw(function));
    let view = analysis_function.view();
    let address = analysis_function.symbol().address();
    let function_symbol = to_bn_symbol_at_address(&view, &function.symbol, address);
    // NOTE: The symbol ref has been pre-incremented for the caller.
    Ref::into_raw(function_symbol).handle
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFunctionGetSymbolName(function: *mut BNWARPFunction) -> *mut c_char {
    // We do not own function so we should not drop.
    let function = ManuallyDrop::new(Arc::from_raw(function));
    let bn_name = BnString::new(&function.symbol.name);
    // NOTE: The symbol name string to be freed by BNFreeString
    BnString::into_raw(bn_name)
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFunctionGetType(
    function: *mut BNWARPFunction,
    analysis_function: *mut BNFunction,
) -> *mut BNType {
    let analysis_function = Function::from_raw(analysis_function);
    // We do not own function so we should not drop.
    let function = ManuallyDrop::new(Arc::from_raw(function));
    match &function.ty {
        Some(func_ty) => {
            let arch = analysis_function.arch();
            let function_type = to_bn_type(Some(arch), func_ty);
            // NOTE: The type ref has been pre-incremented for the caller.
            unsafe { Ref::into_raw(function_type) }.handle
        }
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFunctionGetConstraints(
    function: *mut BNWARPFunction,
    count: *mut usize,
) -> *mut BNWARPConstraint {
    // We do not own function so we should not drop.
    let function = ManuallyDrop::new(Arc::from_raw(function));
    let raw_constraints: Box<[BNWARPConstraint]> = function
        .constraints
        .clone()
        .into_iter()
        .map(Into::into)
        .collect();
    *count = raw_constraints.len();
    let raw_constraints_ptr = Box::into_raw(raw_constraints);
    raw_constraints_ptr as *mut BNWARPConstraint
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFunctionGetComments(
    function: *mut BNWARPFunction,
    count: *mut usize,
) -> *mut BNWarpFunctionComment {
    // We do not own function so we should not drop.
    let function = ManuallyDrop::new(Arc::from_raw(function));
    let raw_comments: Box<[_]> = function
        .comments
        .iter()
        .map(BNWarpFunctionComment::from_owned)
        .collect();
    *count = raw_comments.len();
    let raw_comments_ptr = Box::into_raw(raw_comments);
    raw_comments_ptr as *mut BNWarpFunctionComment
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFunctionsEqual(
    function_a: *mut BNWARPFunction,
    function_b: *mut BNWARPFunction,
) -> bool {
    // We do not own function so we should not drop.
    let function_a = ManuallyDrop::new(Arc::from_raw(function_a));
    // We do not own function so we should not drop.
    let function_b = ManuallyDrop::new(Arc::from_raw(function_b));
    function_a.eq(&function_b)
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPNewFunctionReference(
    function: *mut BNWARPFunction,
) -> *mut BNWARPFunction {
    Arc::increment_strong_count(function);
    function
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeFunctionReference(function: *mut BNWARPFunction) {
    if function.is_null() {
        return;
    }
    Arc::decrement_strong_count(function);
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeFunctionList(functions: *mut *mut BNWARPFunction, count: usize) {
    let functions_ptr = std::ptr::slice_from_raw_parts_mut(functions, count);
    let functions = Box::from_raw(functions_ptr);
    for function in functions {
        // NOTE: The functions themselves should also be arc.
        BNWARPFreeFunctionReference(function);
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeFunctionCommentList(
    comments: *mut BNWarpFunctionComment,
    count: usize,
) {
    let comments_ptr = std::ptr::slice_from_raw_parts_mut(comments, count);
    let comments = Box::from_raw(comments_ptr);
    for comment in &comments {
        BNWarpFunctionComment::free_raw(comment)
    }
}

#[no_mangle]
pub unsafe extern "C" fn BNWARPFreeConstraintList(
    constraints: *mut BNWARPConstraint,
    count: usize,
) {
    let constraints_ptr = std::ptr::slice_from_raw_parts_mut(constraints, count);
    let _constraints = unsafe { Box::from_raw(constraints_ptr) };
}
