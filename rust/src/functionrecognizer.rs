use crate::{
    architecture::CoreArchitecture, binaryview::BinaryView, function::Function, llil, mlil,
};
use binaryninjacore_sys::*;
use std::os::raw::c_void;
use crate::rc::RefCountable;

pub trait FunctionRecognizer {
    fn recognize_low_level_il(
        &self,
        _bv: &BinaryView,
        _func: &Function,
        _llil: &llil::RegularFunction<CoreArchitecture>,
    ) -> bool {
        false
    }

    fn recognize_medium_level_il(
        &self,
        _bv: &BinaryView,
        _func: &Function,
        _mlil: &mlil::MediumLevelILFunction,
    ) -> bool {
        false
    }
}

fn create_function_recognizer_registration<R>(recognizer: R) -> BNFunctionRecognizer
where
    R: 'static + FunctionRecognizer + Send + Sync + Sized,
{
    #[repr(C)]
    struct FunctionRecognizerHandlerContext<R>
    where
        R: 'static + FunctionRecognizer + Send + Sync,
    {
        recognizer: R,
    }

    extern "C" fn cb_recognize_low_level_il<R>(
        ctxt: *mut c_void,
        bv: *mut BNBinaryView,
        func: *mut BNFunction,
        llil: *mut BNLowLevelILFunction,
    ) -> bool
    where
        R: 'static + FunctionRecognizer + Send + Sync,
    {
        let custom_handler = unsafe { &*(ctxt as *mut R) };
        let bv = unsafe { BinaryView::inc_ref(&BinaryView::from_raw(bv)) };
        let func = unsafe { Function::inc_ref(&Function::from_raw(func)) };
        let llil = unsafe { 
            llil::RegularFunction::inc_ref(&llil::RegularFunction::from_raw(func.arch(), llil))
        };
        custom_handler.recognize_low_level_il(&bv, &func, &llil)
    }

    extern "C" fn cb_recognize_medium_level_il<R>(
        ctxt: *mut c_void,
        bv: *mut BNBinaryView,
        func: *mut BNFunction,
        mlil: *mut BNMediumLevelILFunction,
    ) -> bool
    where
        R: 'static + FunctionRecognizer + Send + Sync,
    {
        let custom_handler = unsafe { &*(ctxt as *mut R) };
        let bv = unsafe { BinaryView::inc_ref(&BinaryView::from_raw(bv)) };
        let func = unsafe { Function::inc_ref(&Function::from_raw(func)) };
        let mlil = unsafe {
            mlil::MediumLevelILFunction::inc_ref(&mlil::MediumLevelILFunction::from_raw(mlil))
        };
        custom_handler.recognize_medium_level_il(&bv, &func, &mlil)
    }

    let recognizer = FunctionRecognizerHandlerContext { recognizer };
    let raw = Box::into_raw(Box::new(recognizer));
    BNFunctionRecognizer {
        context: raw as *mut _,
        recognizeLowLevelIL: Some(cb_recognize_low_level_il::<R>),
        recognizeMediumLevelIL: Some(cb_recognize_medium_level_il::<R>),
    }
}

pub fn register_global_function_recognizer<R>(recognizer: R)
where
    R: 'static + FunctionRecognizer + Send + Sync + Sized,
{
    let mut recognizer = create_function_recognizer_registration::<R>(recognizer);
    unsafe {
        BNRegisterGlobalFunctionRecognizer(&mut recognizer as *mut _);
    }
}

pub(crate) fn register_arch_function_recognizer<R>(arch: &CoreArchitecture, recognizer: R)
where
    R: 'static + FunctionRecognizer + Send + Sync + Sized,
{
    let mut recognizer = create_function_recognizer_registration::<R>(recognizer);
    unsafe {
        BNRegisterArchitectureFunctionRecognizer(
            arch.as_ref().handle,
            &mut recognizer as *mut _,
        );
    }
}
