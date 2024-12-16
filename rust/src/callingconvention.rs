// Copyright 2021-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Contains and provides information about different systems' calling conventions to analysis.

use std::borrow::Borrow;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::mem;
use std::os::raw::c_void;
use std::ptr;
use std::slice;

use binaryninjacore_sys::*;

use crate::architecture::{Architecture, ArchitectureExt, CoreArchitecture, Register};
use crate::rc::{
    CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable,
};
use crate::string::*;

// TODO
// force valid registers once Arch has _from_id methods
// CallingConvention impl
// dataflow callbacks

pub trait CallingConventionBase: Sync {
    type Arch: Architecture;

    fn caller_saved_registers(&self) -> Vec<<Self::Arch as Architecture>::Register>;
    fn callee_saved_registers(&self) -> Vec<<Self::Arch as Architecture>::Register>;
    fn int_arg_registers(&self) -> Vec<<Self::Arch as Architecture>::Register>;
    fn float_arg_registers(&self) -> Vec<<Self::Arch as Architecture>::Register>;

    fn arg_registers_shared_index(&self) -> bool;
    fn reserved_stack_space_for_arg_registers(&self) -> bool;
    fn stack_adjusted_on_return(&self) -> bool;
    fn is_eligible_for_heuristics(&self) -> bool;

    fn return_int_reg(&self) -> Option<<Self::Arch as Architecture>::Register>;
    fn return_hi_int_reg(&self) -> Option<<Self::Arch as Architecture>::Register>;
    fn return_float_reg(&self) -> Option<<Self::Arch as Architecture>::Register>;

    fn global_pointer_reg(&self) -> Option<<Self::Arch as Architecture>::Register>;

    fn implicitly_defined_registers(&self) -> Vec<<Self::Arch as Architecture>::Register>;
    fn are_argument_registers_used_for_var_args(&self) -> bool;
}

pub fn register_calling_convention<A, N, C>(arch: &A, name: N, cc: C) -> Ref<CallingConvention<A>>
where
    A: Architecture,
    N: BnStrCompatible,
    C: 'static + CallingConventionBase<Arch = A>,
{
    struct CustomCallingConventionContext<C>
    where
        C: CallingConventionBase,
    {
        raw_handle: *mut BNCallingConvention,
        cc: C,
    }

    extern "C" fn cb_free<C>(ctxt: *mut c_void)
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::free", unsafe {
            let _ctxt = Box::from_raw(ctxt as *mut CustomCallingConventionContext<C>);
        })
    }

    extern "C" fn cb_free_register_list(_ctxt: *mut c_void, regs: *mut u32, count: usize) {
        ffi_wrap!("CallingConvention::free_register_list", unsafe {
            if regs.is_null() {
                return;
            }
            
            let _regs = Box::from_raw(ptr::slice_from_raw_parts_mut(regs, count));
        })
    }

    extern "C" fn cb_caller_saved<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::caller_saved_registers", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let mut regs: Vec<_> = ctxt
                .cc
                .caller_saved_registers()
                .iter()
                .map(|r| r.id())
                .collect();

            // SAFETY: `count` is an out parameter
            *count = regs.len();
            let regs_ptr = regs.as_mut_ptr();
            mem::forget(regs);
            regs_ptr
        })
    }

    extern "C" fn cb_callee_saved<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::callee_saved_registers", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let mut regs: Vec<_> = ctxt
                .cc
                .callee_saved_registers()
                .iter()
                .map(|r| r.id())
                .collect();

            // SAFETY: `count` is an out parameter
            *count = regs.len();
            let regs_ptr = regs.as_mut_ptr();
            mem::forget(regs);
            regs_ptr
        })
    }

    extern "C" fn cb_int_args<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::int_arg_registers", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let mut regs: Vec<_> = ctxt.cc.int_arg_registers().iter().map(|r| r.id()).collect();

            // SAFETY: `count` is an out parameter
            *count = regs.len();
            let regs_ptr = regs.as_mut_ptr();
            mem::forget(regs);
            regs_ptr
        })
    }

    extern "C" fn cb_float_args<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::float_arg_registers", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let mut regs: Vec<_> = ctxt
                .cc
                .float_arg_registers()
                .iter()
                .map(|r| r.id())
                .collect();

            // SAFETY: `count` is an out parameter
            *count = regs.len();
            let regs_ptr = regs.as_mut_ptr();
            mem::forget(regs);
            regs_ptr
        })
    }

    extern "C" fn cb_arg_shared_index<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::arg_registers_shared_index", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);

            ctxt.cc.arg_registers_shared_index()
        })
    }

    extern "C" fn cb_stack_reserved_arg_regs<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConventionBase,
    {
        ffi_wrap!(
            "CallingConvention::reserved_stack_space_for_arg_registers",
            unsafe {
                let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);

                ctxt.cc.reserved_stack_space_for_arg_registers()
            }
        )
    }

    extern "C" fn cb_stack_adjusted_on_return<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::stack_adjusted_on_return", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);

            ctxt.cc.stack_adjusted_on_return()
        })
    }

    extern "C" fn cb_is_eligible_for_heuristics<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::is_eligible_for_heuristics", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);

            ctxt.cc.is_eligible_for_heuristics()
        })
    }

    extern "C" fn cb_return_int_reg<C>(ctxt: *mut c_void) -> u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::return_int_reg", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);

            match ctxt.cc.return_int_reg() {
                Some(r) => r.id(),
                _ => 0xffff_ffff,
            }
        })
    }

    extern "C" fn cb_return_hi_int_reg<C>(ctxt: *mut c_void) -> u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::return_hi_int_reg", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);

            match ctxt.cc.return_hi_int_reg() {
                Some(r) => r.id(),
                _ => 0xffff_ffff,
            }
        })
    }

    extern "C" fn cb_return_float_reg<C>(ctxt: *mut c_void) -> u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::return_float_reg", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);

            match ctxt.cc.return_float_reg() {
                Some(r) => r.id(),
                _ => 0xffff_ffff,
            }
        })
    }

    extern "C" fn cb_global_pointer_reg<C>(ctxt: *mut c_void) -> u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::global_pointer_reg", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);

            match ctxt.cc.global_pointer_reg() {
                Some(r) => r.id(),
                _ => 0xffff_ffff,
            }
        })
    }

    extern "C" fn cb_implicitly_defined_registers<C>(
        ctxt: *mut c_void,
        count: *mut usize,
    ) -> *mut u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::implicitly_defined_registers", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let mut regs: Vec<_> = ctxt
                .cc
                .implicitly_defined_registers()
                .iter()
                .map(|r| r.id())
                .collect();

            // SAFETY: `count` is an out parameter
            *count = regs.len();
            let regs_ptr = regs.as_mut_ptr();
            mem::forget(regs);
            regs_ptr
        })
    }

    #[allow(clippy::extra_unused_type_parameters)] // TODO : This is bad; need to finish this stub
    extern "C" fn cb_incoming_reg_value<C>(
        _ctxt: *mut c_void,
        _reg: u32,
        _func: *mut BNFunction,
        val: *mut BNRegisterValue,
    ) where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::incoming_reg_value", unsafe {
            //let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let val = &mut *val;

            val.state = BNRegisterValueType::EntryValue;
            val.value = _reg as i64;
        })
    }

    #[allow(clippy::extra_unused_type_parameters)] // TODO : This is bad; need to finish this stub
    extern "C" fn cb_incoming_flag_value<C>(
        _ctxt: *mut c_void,
        _flag: u32,
        _func: *mut BNFunction,
        val: *mut BNRegisterValue,
    ) where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::incoming_flag_value", unsafe {
            //let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let val = &mut *val;

            val.state = BNRegisterValueType::EntryValue;
            val.value = _flag as i64;
        })
    }

    extern "C" fn cb_incoming_var_for_param<C>(
        ctxt: *mut c_void,
        var: *const BNVariable,
        _func: *mut BNFunction,
        param: *mut BNVariable,
    ) where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::incoming_var_for_param", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            ptr::write(
                param,
                BNGetDefaultIncomingVariableForParameterVariable(ctxt.raw_handle, var),
            );
        })
    }

    extern "C" fn cb_incoming_param_for_var<C>(
        ctxt: *mut c_void,
        var: *const BNVariable,
        _func: *mut BNFunction,
        param: *mut BNVariable,
    ) where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::incoming_param_for_var", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            ptr::write(
                param,
                BNGetDefaultParameterVariableForIncomingVariable(ctxt.raw_handle, var),
            );
        })
    }

    extern "C" fn cb_are_argument_registers_used_for_var_args<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConventionBase,
    {
        ffi_wrap!(
            "CallingConvention::are_argument_registers_used_for_var_args",
            unsafe {
                let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);

                ctxt.cc.are_argument_registers_used_for_var_args()
            }
        )
    }

    let name = name.into_bytes_with_nul();
    let raw = Box::into_raw(Box::new(CustomCallingConventionContext {
        raw_handle: ptr::null_mut(),
        cc,
    }));
    let mut cc = BNCustomCallingConvention {
        context: raw as *mut _,

        freeObject: Some(cb_free::<C>),

        getCallerSavedRegisters: Some(cb_caller_saved::<C>),
        getCalleeSavedRegisters: Some(cb_callee_saved::<C>),
        getIntegerArgumentRegisters: Some(cb_int_args::<C>),
        getFloatArgumentRegisters: Some(cb_float_args::<C>),
        freeRegisterList: Some(cb_free_register_list),

        areArgumentRegistersSharedIndex: Some(cb_arg_shared_index::<C>),
        isStackReservedForArgumentRegisters: Some(cb_stack_reserved_arg_regs::<C>),
        isStackAdjustedOnReturn: Some(cb_stack_adjusted_on_return::<C>),
        isEligibleForHeuristics: Some(cb_is_eligible_for_heuristics::<C>),

        getIntegerReturnValueRegister: Some(cb_return_int_reg::<C>),
        getHighIntegerReturnValueRegister: Some(cb_return_hi_int_reg::<C>),
        getFloatReturnValueRegister: Some(cb_return_float_reg::<C>),
        getGlobalPointerRegister: Some(cb_global_pointer_reg::<C>),

        getImplicitlyDefinedRegisters: Some(cb_implicitly_defined_registers::<C>),
        getIncomingRegisterValue: Some(cb_incoming_reg_value::<C>),
        getIncomingFlagValue: Some(cb_incoming_flag_value::<C>),
        getIncomingVariableForParameterVariable: Some(cb_incoming_var_for_param::<C>),
        getParameterVariableForIncomingVariable: Some(cb_incoming_param_for_var::<C>),

        areArgumentRegistersUsedForVarArgs: Some(cb_are_argument_registers_used_for_var_args::<C>),
    };

    unsafe {
        let cc_name = name.as_ref().as_ptr() as *mut _;
        let result = BNCreateCallingConvention(arch.as_ref().0, cc_name, &mut cc);

        assert!(!result.is_null());

        (*raw).raw_handle = result;

        BNRegisterCallingConvention(arch.as_ref().0, result);

        Ref::new(CallingConvention {
            handle: result,
            arch_handle: arch.handle(),
            _arch: PhantomData,
        })
    }
}

pub struct CallingConvention<A: Architecture> {
    pub(crate) handle: *mut BNCallingConvention,
    pub(crate) arch_handle: A::Handle,
    _arch: PhantomData<*mut A>,
}

unsafe impl<A: Architecture> Send for CallingConvention<A> {}
unsafe impl<A: Architecture> Sync for CallingConvention<A> {}

impl<A: Architecture> CallingConvention<A> {
    pub(crate) unsafe fn ref_from_raw(
        handle: *mut BNCallingConvention,
        arch: A::Handle,
    ) -> Ref<Self> {
        Ref::new(CallingConvention {
            handle,
            arch_handle: arch,
            _arch: PhantomData,
        })
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetCallingConventionName(self.handle)) }
    }

    pub fn variables_for_parameters(
        &self,
        params: &[FunctionParameter],
        permitted_registers: Option<&[A::Register]>,
    ) -> Vec<Variable> {
        let mut bn_params: Vec<BNFunctionParameter> = vec![];
        let name_strings = params.iter().map(|parameter| &parameter.name);

        for (parameter, raw_name) in params.iter().zip(name_strings) {
            let location = match &parameter.location {
                Some(location) => location.raw(),
                None => unsafe { mem::zeroed() },
            };
            bn_params.push(BNFunctionParameter {
                name: BnString::new(raw_name).into_raw(),
                type_: parameter.t.contents.handle,
                typeConfidence: parameter.t.confidence,
                defaultLocation: parameter.location.is_none(),
                location,
            });
        }

        let mut count: usize = 0;
        let vars: *mut BNVariable = if let Some(permitted_args) = permitted_registers {
            let mut permitted_regs = vec![];
            for r in permitted_args {
                permitted_regs.push(r.id());
            }

            unsafe {
                BNGetVariablesForParameters(
                    self.handle,
                    bn_params.as_ptr(),
                    bn_params.len(),
                    permitted_regs.as_ptr(),
                    permitted_regs.len(),
                    &mut count,
                )
            }
        } else {
            unsafe {
                BNGetVariablesForParametersDefaultPermittedArgs(
                    self.handle,
                    bn_params.as_ptr(),
                    bn_params.len(),
                    &mut count,
                )
            }
        };

        let vars_slice = unsafe { slice::from_raw_parts(vars, count) };
        let mut result = vec![];
        for var in vars_slice {
            result.push(unsafe { Variable::from_raw(*var) });
        }

        unsafe { BNFreeVariableList(vars) };
        result
    }
}

impl<A: Architecture> Eq for CallingConvention<A> {}
impl<A: Architecture> PartialEq for CallingConvention<A> {
    fn eq(&self, rhs: &Self) -> bool {
        self.handle == rhs.handle
    }
}

use crate::types::{FunctionParameter, Variable};
use std::hash::{Hash, Hasher};

impl<A: Architecture> Hash for CallingConvention<A> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl<A: Architecture> CallingConventionBase for CallingConvention<A> {
    type Arch = A;

    fn caller_saved_registers(&self) -> Vec<A::Register> {
        unsafe {
            let mut count = 0;
            let regs = BNGetCallerSavedRegisters(self.handle, &mut count);
            let arch = self.arch_handle.borrow();

            let res = slice::from_raw_parts(regs, count)
                .iter()
                .map(|&r| {
                    arch.register_from_id(r)
                        .expect("bad reg id from CallingConvention")
                })
                .collect();

            BNFreeRegisterList(regs);

            res
        }
    }

    fn callee_saved_registers(&self) -> Vec<A::Register> {
        unsafe {
            let mut count = 0;
            let regs = BNGetCalleeSavedRegisters(self.handle, &mut count);
            let arch = self.arch_handle.borrow();

            let res = slice::from_raw_parts(regs, count)
                .iter()
                .map(|&r| {
                    arch.register_from_id(r)
                        .expect("bad reg id from CallingConvention")
                })
                .collect();

            BNFreeRegisterList(regs);

            res
        }
    }

    fn int_arg_registers(&self) -> Vec<A::Register> {
        unsafe {
            let mut count = 0;
            let regs = BNGetIntegerArgumentRegisters(self.handle, &mut count);
            let arch = self.arch_handle.borrow();

            let res = slice::from_raw_parts(regs, count)
                .iter()
                .map(|&r| {
                    arch.register_from_id(r)
                        .expect("bad reg id from CallingConvention")
                })
                .collect();

            BNFreeRegisterList(regs);

            res
        }
    }

    fn float_arg_registers(&self) -> Vec<A::Register> {
        unsafe {
            let mut count = 0;
            let regs = BNGetFloatArgumentRegisters(self.handle, &mut count);
            let arch = self.arch_handle.borrow();

            let res = slice::from_raw_parts(regs, count)
                .iter()
                .map(|&r| {
                    arch.register_from_id(r)
                        .expect("bad reg id from CallingConvention")
                })
                .collect();

            BNFreeRegisterList(regs);

            res
        }
    }

    fn arg_registers_shared_index(&self) -> bool {
        unsafe { BNAreArgumentRegistersSharedIndex(self.handle) }
    }

    fn reserved_stack_space_for_arg_registers(&self) -> bool {
        unsafe { BNIsStackReservedForArgumentRegisters(self.handle) }
    }

    fn stack_adjusted_on_return(&self) -> bool {
        unsafe { BNIsStackAdjustedOnReturn(self.handle) }
    }

    fn is_eligible_for_heuristics(&self) -> bool {
        false
    }

    fn return_int_reg(&self) -> Option<A::Register> {
        match unsafe { BNGetIntegerReturnValueRegister(self.handle) } {
            id if id < 0x8000_0000 => self.arch_handle.borrow().register_from_id(id),
            _ => None,
        }
    }

    fn return_hi_int_reg(&self) -> Option<A::Register> {
        match unsafe { BNGetHighIntegerReturnValueRegister(self.handle) } {
            id if id < 0x8000_0000 => self.arch_handle.borrow().register_from_id(id),
            _ => None,
        }
    }

    fn return_float_reg(&self) -> Option<A::Register> {
        match unsafe { BNGetFloatReturnValueRegister(self.handle) } {
            id if id < 0x8000_0000 => self.arch_handle.borrow().register_from_id(id),
            _ => None,
        }
    }

    fn global_pointer_reg(&self) -> Option<A::Register> {
        match unsafe { BNGetGlobalPointerRegister(self.handle) } {
            id if id < 0x8000_0000 => self.arch_handle.borrow().register_from_id(id),
            _ => None,
        }
    }

    fn implicitly_defined_registers(&self) -> Vec<A::Register> {
        Vec::new()
    }

    fn are_argument_registers_used_for_var_args(&self) -> bool {
        unsafe { BNAreArgumentRegistersUsedForVarArgs(self.handle) }
    }
}

impl<A: Architecture> ToOwned for CallingConvention<A> {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl<A: Architecture> RefCountable for CallingConvention<A> {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewCallingConventionReference(handle.handle),
            arch_handle: handle.arch_handle.clone(),
            _arch: PhantomData,
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeCallingConvention(handle.handle);
    }
}

impl<A: Architecture> CoreArrayProvider for CallingConvention<A> {
    type Raw = *mut BNCallingConvention;
    type Context = A::Handle;
    type Wrapped<'a> = Guard<'a, CallingConvention<A>>;
}

unsafe impl<A: Architecture> CoreArrayProviderInner for CallingConvention<A> {
    unsafe fn free(raw: *mut *mut BNCallingConvention, count: usize, _content: &Self::Context) {
        BNFreeCallingConventionList(raw, count);
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(
            CallingConvention {
                handle: *raw,
                arch_handle: context.clone(),
                _arch: Default::default(),
            },
            context,
        )
    }
}

impl Debug for CallingConvention<CoreArchitecture> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "<cc: {} arch: {}>", self.name(), self.arch_handle.name())
    }
}

pub struct ConventionBuilder<A: Architecture> {
    caller_saved_registers: Vec<A::Register>,
    callee_saved_registers: Vec<A::Register>,
    int_arg_registers: Vec<A::Register>,
    float_arg_registers: Vec<A::Register>,

    arg_registers_shared_index: bool,
    reserved_stack_space_for_arg_registers: bool,
    stack_adjusted_on_return: bool,
    is_eligible_for_heuristics: bool,

    return_int_reg: Option<A::Register>,
    return_hi_int_reg: Option<A::Register>,
    return_float_reg: Option<A::Register>,

    global_pointer_reg: Option<A::Register>,

    implicitly_defined_registers: Vec<A::Register>,

    are_argument_registers_used_for_var_args: bool,

    arch_handle: A::Handle,
    _arch: PhantomData<*const A>,
}

unsafe impl<A: Architecture> Send for ConventionBuilder<A> {}
unsafe impl<A: Architecture> Sync for ConventionBuilder<A> {}

macro_rules! bool_arg {
    ($name:ident) => {
        pub fn $name(mut self, val: bool) -> Self {
            self.$name = val;
            self
        }
    };
}

macro_rules! reg_list {
    ($name:ident) => {
        pub fn $name(mut self, regs: &[&str]) -> Self {
            {
                // FIXME NLL
                let arch = self.arch_handle.borrow();
                let arch_regs = regs.iter().filter_map(|&r| arch.register_by_name(r));

                self.$name = arch_regs.collect();
            }

            self
        }
    };
}

macro_rules! reg {
    ($name:ident) => {
        pub fn $name(mut self, reg: &str) -> Self {
            {
                // FIXME NLL
                let arch = self.arch_handle.borrow();
                self.$name = arch.register_by_name(reg);
            }

            self
        }
    };
}

impl<A: Architecture> ConventionBuilder<A> {
    pub fn new(arch: &A) -> Self {
        Self {
            caller_saved_registers: Vec::new(),
            callee_saved_registers: Vec::new(),
            int_arg_registers: Vec::new(),
            float_arg_registers: Vec::new(),

            arg_registers_shared_index: false,
            reserved_stack_space_for_arg_registers: false,
            stack_adjusted_on_return: false,
            is_eligible_for_heuristics: false,

            return_int_reg: None,
            return_hi_int_reg: None,
            return_float_reg: None,

            global_pointer_reg: None,

            implicitly_defined_registers: Vec::new(),

            are_argument_registers_used_for_var_args: false,

            arch_handle: arch.handle(),
            _arch: PhantomData,
        }
    }

    reg_list!(caller_saved_registers);
    reg_list!(callee_saved_registers);
    reg_list!(int_arg_registers);
    reg_list!(float_arg_registers);

    bool_arg!(arg_registers_shared_index);
    bool_arg!(reserved_stack_space_for_arg_registers);
    bool_arg!(stack_adjusted_on_return);
    bool_arg!(is_eligible_for_heuristics);

    reg!(return_int_reg);
    reg!(return_hi_int_reg);
    reg!(return_float_reg);

    reg!(global_pointer_reg);

    reg_list!(implicitly_defined_registers);

    bool_arg!(are_argument_registers_used_for_var_args);

    pub fn register(self, name: &str) -> Ref<CallingConvention<A>> {
        let arch = self.arch_handle.clone();

        register_calling_convention(arch.borrow(), name, self)
    }
}

impl<A: Architecture> CallingConventionBase for ConventionBuilder<A> {
    type Arch = A;

    fn caller_saved_registers(&self) -> Vec<A::Register> {
        self.caller_saved_registers.clone()
    }

    fn callee_saved_registers(&self) -> Vec<A::Register> {
        self.callee_saved_registers.clone()
    }

    fn int_arg_registers(&self) -> Vec<A::Register> {
        self.int_arg_registers.clone()
    }

    fn float_arg_registers(&self) -> Vec<A::Register> {
        self.float_arg_registers.clone()
    }

    fn arg_registers_shared_index(&self) -> bool {
        self.arg_registers_shared_index
    }

    fn reserved_stack_space_for_arg_registers(&self) -> bool {
        self.reserved_stack_space_for_arg_registers
    }

    fn stack_adjusted_on_return(&self) -> bool {
        self.stack_adjusted_on_return
    }

    fn is_eligible_for_heuristics(&self) -> bool {
        self.is_eligible_for_heuristics
    }

    fn return_int_reg(&self) -> Option<A::Register> {
        self.return_int_reg
    }

    fn return_hi_int_reg(&self) -> Option<A::Register> {
        self.return_hi_int_reg
    }

    fn return_float_reg(&self) -> Option<A::Register> {
        self.return_float_reg
    }

    fn global_pointer_reg(&self) -> Option<A::Register> {
        self.global_pointer_reg
    }

    fn implicitly_defined_registers(&self) -> Vec<A::Register> {
        self.implicitly_defined_registers.clone()
    }

    fn are_argument_registers_used_for_var_args(&self) -> bool {
        self.are_argument_registers_used_for_var_args
    }
}
