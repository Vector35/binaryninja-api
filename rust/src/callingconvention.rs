// Copyright 2021 Vector 35 Inc.
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

use std::borrow::Borrow;
use std::marker::PhantomData;
use std::mem;
use std::os::raw::c_void;
use std::ptr;
use std::slice;

use binaryninjacore_sys::*;

use crate::architecture::{Architecture, ArchitectureExt, Register};
use crate::rc::{Ref, RefCountable};
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

    fn alloc_register_list<I: Iterator<Item = u32> + ExactSizeIterator>(
        items: I,
        count: &mut usize,
    ) -> *mut u32 {
        let len = items.len();
        *count = len;

        if len == 0 {
            ptr::null_mut()
        } else {
            let mut res = Vec::with_capacity(len + 1);

            res.push(len as u32);

            for i in items {
                res.push(i.clone().into());
            }

            assert!(res.len() == len + 1);

            let raw = res.as_mut_ptr();
            mem::forget(res);

            unsafe { raw.offset(1) }
        }
    }

    extern "C" fn cb_free_register_list(_ctxt: *mut c_void, regs: *mut u32) {
        ffi_wrap!("CallingConvention::free_register_list", unsafe {
            if regs.is_null() {
                return;
            }

            let actual_start = regs.offset(-1);
            let len = *actual_start + 1;
            let _regs = Vec::from_raw_parts(actual_start, len as usize, len as usize);
        })
    }

    extern "C" fn cb_caller_saved<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::caller_saved_registers", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let regs = ctxt.cc.caller_saved_registers();

            alloc_register_list(regs.iter().map(|r| r.id()), &mut *count)
        })
    }

    extern "C" fn cb_callee_saved<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::callee_saved_registers", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let regs = ctxt.cc.callee_saved_registers();

            alloc_register_list(regs.iter().map(|r| r.id()), &mut *count)
        })
    }

    extern "C" fn cb_int_args<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::int_arg_registers", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let regs = ctxt.cc.int_arg_registers();

            alloc_register_list(regs.iter().map(|r| r.id()), &mut *count)
        })
    }

    extern "C" fn cb_float_args<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConventionBase,
    {
        ffi_wrap!("CallingConvention::float_arg_registers", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            let regs = ctxt.cc.float_arg_registers();

            alloc_register_list(regs.iter().map(|r| r.id()), &mut *count)
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
            let regs = ctxt.cc.implicitly_defined_registers();

            alloc_register_list(regs.iter().map(|r| r.id()), &mut *count)
        })
    }

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
        ffi_wrap!("CallingConvention::incoming_var_for_param", unsafe {
            let ctxt = &*(ctxt as *mut CustomCallingConventionContext<C>);
            ptr::write(
                param,
                BNGetDefaultParameterVariableForIncomingVariable(ctxt.raw_handle, var),
            );
        })
    }

    let name = name.as_bytes_with_nul();
    let raw = Box::into_raw(Box::new(CustomCallingConventionContext {
        raw_handle: ptr::null_mut(),
        cc: cc,
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
    pub(crate) unsafe fn from_raw(handle: *mut BNCallingConvention, arch: A::Handle) -> Self {
        CallingConvention {
            handle: handle,
            arch_handle: arch,
            _arch: PhantomData,
        }
    }
}

impl<A: Architecture> Eq for CallingConvention<A> {}
impl<A: Architecture> PartialEq for CallingConvention<A> {
    fn eq(&self, rhs: &Self) -> bool {
        self.handle == rhs.handle
    }
}

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
        Vec::new()
    }

    fn float_arg_registers(&self) -> Vec<A::Register> {
        Vec::new()
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
        self.caller_saved_registers.clone()
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
        self.return_int_reg.clone()
    }

    fn return_hi_int_reg(&self) -> Option<A::Register> {
        self.return_hi_int_reg.clone()
    }

    fn return_float_reg(&self) -> Option<A::Register> {
        self.return_float_reg.clone()
    }

    fn global_pointer_reg(&self) -> Option<A::Register> {
        self.global_pointer_reg.clone()
    }

    fn implicitly_defined_registers(&self) -> Vec<A::Register> {
        self.implicitly_defined_registers.clone()
    }
}
