use crate::architecture::Architecture;
use crate::{
    architecture::CoreArchitecture, binaryview::BinaryView, function::Function, llil, mlil,
};
use binaryninjacore_sys::*;
use std::os::raw::c_void;

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
        let bv = unsafe { BinaryView::from_raw(BNNewViewReference(bv)) };
        let arch = unsafe { BNGetFunctionArchitecture(func) };
        let func = unsafe { Function::from_raw(BNNewFunctionReference(func)) };
        if arch.is_null() {
            return false;
        }
        let arch = unsafe { CoreArchitecture::from_raw(arch) };
        let llil = unsafe { llil::RegularFunction::from_raw(arch, llil) };
        custom_handler.recognize_low_level_il(bv.as_ref(), func.as_ref(), &llil)
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
        let bv = unsafe { BinaryView::from_raw(BNNewViewReference(bv)) };
        let func = unsafe { Function::from_raw(BNNewFunctionReference(func)) };
        let mlil = unsafe { mlil::MediumLevelILFunction::ref_from_raw(mlil) };
        custom_handler.recognize_medium_level_il(bv.as_ref(), func.as_ref(), &mlil)
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
            arch.handle().as_ref().0,
            &mut recognizer as *mut _,
        );
    }
}
