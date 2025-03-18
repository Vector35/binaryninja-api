use crate::low_level_il::function::LowLevelILFunction;
use crate::low_level_il::RegularLowLevelILFunction;
use crate::medium_level_il::MediumLevelILFunction;
use crate::{architecture::CoreArchitecture, binary_view::BinaryView, function::Function};
use binaryninjacore_sys::*;
use std::os::raw::c_void;

pub trait FunctionRecognizer {
    fn recognize_low_level_il(
        &self,
        _bv: &BinaryView,
        _func: &Function,
        _llil: &RegularLowLevelILFunction<CoreArchitecture>,
    ) -> bool {
        false
    }

    fn recognize_medium_level_il(
        &self,
        _bv: &BinaryView,
        _func: &Function,
        _mlil: &MediumLevelILFunction,
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
        let context = unsafe { &*(ctxt as *mut FunctionRecognizerHandlerContext<R>) };
        let bv = unsafe { BinaryView::from_raw(bv).to_owned() };
        let func = unsafe { Function::from_raw(func).to_owned() };
        let llil = unsafe { LowLevelILFunction::from_raw(func.arch(), llil).to_owned() };
        context.recognizer.recognize_low_level_il(&bv, &func, &llil)
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
        let context = unsafe { &*(ctxt as *mut FunctionRecognizerHandlerContext<R>) };
        let bv = unsafe { BinaryView::from_raw(bv).to_owned() };
        let func = unsafe { Function::from_raw(func).to_owned() };
        let mlil = unsafe { MediumLevelILFunction::from_raw(mlil).to_owned() };
        context
            .recognizer
            .recognize_medium_level_il(&bv, &func, &mlil)
    }

    let recognizer = FunctionRecognizerHandlerContext { recognizer };
    // TODO: Currently we leak `recognizer`.
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
        BNRegisterGlobalFunctionRecognizer(&mut recognizer);
    }
}

pub(crate) fn register_arch_function_recognizer<R>(arch: &CoreArchitecture, recognizer: R)
where
    R: 'static + FunctionRecognizer + Send + Sync + Sized,
{
    let mut recognizer = create_function_recognizer_registration::<R>(recognizer);
    unsafe {
        BNRegisterArchitectureFunctionRecognizer(arch.handle, &mut recognizer);
    }
}
