// Copyright 2021-2026 Vector 35 Inc.
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

use binaryninjacore_sys::*;
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr;

use crate::architecture::{
    Architecture, ArchitectureExt, CoreArchitecture, FlagId, Register, RegisterId, RegisterStack,
    RegisterStackInfo,
};
use crate::binary_view::BinaryView;
use crate::ffi::{slice_from_raw_parts, INVALID_REGISTER};
use crate::function::Function;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::*;
use crate::types::{FunctionParameter, ReturnValue, Type, ValueLocation};
use crate::variable::{RegisterValue, RegisterValueType, Variable};

// TODO
// force valid registers once Arch has _from_id methods

/// Describes how parameters, return values, and the stack are handled when a function is called.
///
/// Implementors only need to provide the methods that describe their convention; every method that
/// computes a layout (parameter locations, return value location, and stack adjustments) has a
/// default implementation that delegates to the core's default behavior via the implementor's
/// associated [`CoreCallingConvention`]. A [`CallingConvention`] implementation must expose its
/// core handle through [`AsRef<CoreCallingConvention>`]; see [`register_calling_convention`] for
/// how the handle is provided to implementors.
pub trait CallingConvention: 'static + Sync + Sized + AsRef<CoreCallingConvention> {
    /// Gets the list of registers that are not preserved across a call
    /// (caller-saved / volatile registers).
    fn caller_saved_registers(&self) -> Vec<RegisterId>;

    /// Gets the list of registers that a callee must preserve across a call
    /// (callee-saved / non-volatile registers).
    fn callee_saved_registers(&self) -> Vec<RegisterId>;

    /// Gets the registers used to pass integer and pointer arguments, in the order they are used.
    fn int_arg_registers(&self) -> Vec<RegisterId>;

    /// Gets the registers used to pass floating point arguments, in the order they are used.
    fn float_arg_registers(&self) -> Vec<RegisterId>;

    /// Gets the set of registers that must be arguments for heuristic calling convention
    /// detection to consider this calling convention as a valid option.
    fn required_argument_registers(&self) -> Vec<RegisterId> {
        Vec::new()
    }

    /// Gets the set of registers that must be clobbered for heuristic calling convention
    /// detection to consider this calling convention as a valid option.
    fn required_clobbered_registers(&self) -> Vec<RegisterId> {
        Vec::new()
    }

    /// Whether the integer and floating point argument registers share a single argument index.
    ///
    /// When true, the Nth argument consumes the Nth slot of both the integer and float register
    /// lists regardless of its type. When false, integer and float arguments are assigned from
    /// their respective register lists independently.
    fn arg_registers_shared_index(&self) -> bool;

    /// Whether stack space is reserved by the caller for the register arguments (for example,
    /// the shadow/home space used by the Windows x64 calling convention).
    fn reserved_stack_space_for_arg_registers(&self) -> bool;

    /// Whether the callee adjusts the stack to remove the arguments before returning (as in
    /// stdcall), rather than leaving the caller to clean up the stack (as in cdecl).
    fn stack_adjusted_on_return(&self) -> bool;

    /// Whether this calling convention may be selected by heuristic calling convention detection.
    fn is_eligible_for_heuristics(&self) -> bool;

    /// Gets the register that holds the integer return value.
    fn return_int_reg(&self) -> Option<RegisterId>;

    /// Gets the register that holds the high part of an integer return value that is too large
    /// to fit in a single register.
    fn return_hi_int_reg(&self) -> Option<RegisterId>;

    /// Gets the register that holds the floating point return value.
    fn return_float_reg(&self) -> Option<RegisterId>;

    /// Deprecated. Use [`CallingConvention::global_pointer_regs`] instead.
    ///
    /// Gets the register that holds the global pointer, if the calling convention defines one.
    fn global_pointer_reg(&self) -> Option<RegisterId>;
    fn global_pointer_regs(&self) -> Vec<RegisterId> {
        self.global_pointer_reg().into_iter().collect()
    }

    /// Gets the registers that are implicitly given a known value on function entry by this
    /// calling convention.
    fn implicitly_defined_registers(&self) -> Vec<RegisterId>;

    /// Whether argument registers are used to pass variadic arguments.
    fn are_argument_registers_used_for_var_args(&self) -> bool;

    /// The known value of a register on entry to a function. The default implementation models the
    /// top of a register stack (such as the x87 floating point stack) as the constant zero and
    /// leaves all other registers undetermined.
    fn incoming_register_value(&self, reg: RegisterId, _func: Option<&Function>) -> RegisterValue {
        let arch = self.as_ref().arch_handle;
        if let Some(reg) = arch.register_from_id(reg) {
            if let Some(reg_stack) = arch.register_stack_for_register(reg) {
                if reg == reg_stack.info().stack_top_reg() {
                    return RegisterValue::new(RegisterValueType::ConstantValue, 0, 0, 0);
                }
            }
        }
        RegisterValue::new(RegisterValueType::UndeterminedValue, 0, 0, 0)
    }

    /// The known value of a flag on entry to a function. The default implementation leaves all
    /// flags undetermined.
    fn incoming_flag_value(&self, _flag: FlagId, _func: Option<&Function>) -> RegisterValue {
        RegisterValue::new(RegisterValueType::UndeterminedValue, 0, 0, 0)
    }

    /// The incoming variable used to pass the given parameter variable.
    fn incoming_variable_for_parameter_variable(
        &self,
        var: &Variable,
        _func: Option<&Function>,
    ) -> Variable {
        self.as_ref()
            .default_incoming_variable_for_parameter_variable(var)
    }

    /// The parameter variable corresponding to the given incoming variable.
    fn parameter_variable_for_incoming_variable(
        &self,
        var: &Variable,
        _func: Option<&Function>,
    ) -> Variable {
        self.as_ref()
            .default_parameter_variable_for_incoming_variable(var)
    }

    /// Whether a value of the given type can be returned in registers, as opposed to being
    /// returned indirectly through memory. The default implementation allows register returns
    /// for types that fit in a single register, have a size equal to two registers when
    /// [`CallingConvention::return_hi_int_reg`] is a valid register, or are a floating point
    /// type when [`CallingConvention::return_float_reg`] is a valid register.
    fn is_return_type_register_compatible(&self, _view: Option<&BinaryView>, ty: &Type) -> bool {
        self.as_ref().default_is_return_type_register_compatible(ty)
    }

    /// The location used to pass the hidden pointer argument for return values that are returned
    /// indirectly through memory. The default location is the first integer argument register,
    /// or the first stack slot if there are no integer argument registers.
    fn indirect_return_value_location(&self) -> Variable {
        self.as_ref().default_indirect_return_value_location()
    }

    /// The location in which the hidden indirect return value pointer is returned to the caller,
    /// for calling conventions that return it.
    fn returned_indirect_return_value_pointer(&self) -> Option<Variable> {
        None
    }

    /// Whether a value of the given type can be passed as an argument in registers. The default
    /// implementation allows register arguments for types that fit in a single register, or are
    /// a floating point type when [`CallingConvention::float_arg_registers`] has valid registers.
    fn is_argument_type_register_compatible(&self, _view: Option<&BinaryView>, ty: &Type) -> bool {
        self.as_ref()
            .default_is_argument_type_register_compatible(ty)
    }

    /// Whether an argument that cannot be passed in registers is passed indirectly by pointer, as
    /// opposed to being passed directly on the stack.
    fn is_non_register_argument_indirect(&self, _view: Option<&BinaryView>, _ty: &Type) -> bool {
        false
    }

    /// Whether arguments passed on the stack are aligned to their natural alignment. If false,
    /// arguments are aligned to the address size.
    fn are_stack_arguments_naturally_aligned(&self) -> bool {
        false
    }

    /// Whether arguments passed on the stack are pushed left-to-right, as opposed to the more
    /// common right-to-left order.
    fn are_stack_arguments_pushed_left_to_right(&self) -> bool {
        false
    }

    /// Computes the complete call layout (parameter locations, return value location, and stack
    /// adjustments) for a call with the given return value and parameters. The default
    /// implementation uses [`CallingConvention::return_value_location`],
    /// [`CallingConvention::parameter_locations`], [`CallingConvention::stack_adjustment_for_locations`],
    /// and [`CallingConvention::stack_adjustment_for_locations`] to compute the layout.
    ///
    /// It is recommended to only override this method if the calling convention behavior cannot be
    /// modeled with [`CallingConvention::return_value_location`] and/or
    /// [`CallingConvention::parameter_locations`].
    ///
    /// When calling this function to query the layout of a function, the return value and
    /// parameters should have their named type references dereferenced before passing them to
    /// this function. Calling the functions [`BinaryView::deref_return_value_named_type_references`]
    /// and [`BinaryView::deref_parameter_named_type_references`] will perform this dereferencing.
    fn call_layout(
        &self,
        view: Option<&BinaryView>,
        return_value: &ReturnValue,
        params: &[FunctionParameter],
        permitted_registers: Option<&[RegisterId]>,
    ) -> CallLayout {
        self.as_ref()
            .default_call_layout(view, return_value, params, permitted_registers)
    }

    /// Computes the location of the return value for the given return value type. The default
    /// implementation checks [`CallingConvention::is_return_type_register_compatible`] and places
    /// the return value in registers if it can, or uses an indirect return by pointer if not. If
    /// an indirect return is required, then [`CallingConvention::indirect_return_value_location`]
    /// and [`CallingConvention::returned_indirect_return_value_pointer`] are used to provide the
    /// location of the indirect return value.
    fn return_value_location(
        &self,
        view: Option<&BinaryView>,
        return_value: &ReturnValue,
    ) -> ValueLocation {
        self.as_ref()
            .default_return_value_location(view, return_value)
    }

    /// Computes the locations of the parameters for a call with the given return value and
    /// parameters. The default implementation uses [`CallingConvention::int_arg_registers`],
    /// [`CallingConvention::float_arg_registers`], [`CallingConvention::arg_registers_shared_index`],
    /// [`CallingConvention::reserved_stack_space_for_arg_registers`],
    /// [`CallingConvention::is_argument_type_register_compatible`],
    /// [`CallingConvention::is_non_register_argument_indirect`],
    /// [`CallingConvention::are_stack_arguments_naturally_aligned`], and
    /// [`CallingConvention::are_stack_arguments_pushed_left_to_right`] to compute the parameter
    /// layout.
    ///
    /// This function is usually sufficient unless the calling convention has unusual parameter
    /// passing behavior. Most calling conventions can be defined per-argument using the methods
    /// listed above.
    fn parameter_locations(
        &self,
        view: Option<&BinaryView>,
        return_value: Option<&ValueLocation>,
        params: &[FunctionParameter],
        permitted_registers: Option<&[RegisterId]>,
    ) -> Vec<ValueLocation> {
        self.as_ref()
            .default_parameter_locations(view, return_value, params, permitted_registers)
    }

    /// Computes the order in which the given parameter variables are passed. The default
    /// implementation first checks [`CallingConvention::arg_registers_shared_index`] to see if the
    /// parameter ordering is well defined. If the arguments do not share an index, it places all
    /// integer arguments before the floating point arguments. Arguments that are not passed in a
    /// normal location are placed last.
    fn parameter_ordering_for_variables(
        &self,
        _view: Option<&BinaryView>,
        params: &[(Variable, Ref<Type>)],
    ) -> Vec<Variable> {
        self.as_ref()
            .default_parameter_ordering_for_variables(params)
    }

    /// Computes the stack adjustment applied on return for a call with the given return value and
    /// parameter locations. The default implementation first checks
    /// [`CallingConvention::stack_adjusted_on_return`], and returns zero if that returns false.
    /// Otherwise, it checks the stack parameter locations and
    /// [`CallingConvention::are_stack_arguments_naturally_aligned`] to compute the stack
    /// adjustment necessary to cover all parameters.
    fn stack_adjustment_for_locations(
        &self,
        _view: Option<&BinaryView>,
        return_value: Option<&ValueLocation>,
        params: &[(ValueLocation, Ref<Type>)],
    ) -> i64 {
        self.as_ref()
            .default_stack_adjustment_for_locations(return_value, params)
    }

    /// Computes the per-register-stack adjustments (for architectures with register stacks, such
    /// as the x87 floating point stack) for a call with the given return value and parameter
    /// locations. The default implementation compares the register stack slots used by the
    /// parameters and the return value to compute the adjustments.
    fn register_stack_adjustments(
        &self,
        _view: Option<&BinaryView>,
        return_value: Option<&ValueLocation>,
        params: &[ValueLocation],
    ) -> BTreeMap<RegisterId, i32> {
        self.as_ref()
            .default_register_stack_adjustments(return_value, params)
    }
}

/// Registers a new calling convention with the given architecture.
///
/// The convention object is constructed by `func`, which is given the [`CoreCallingConvention`]
/// handle of the newly created convention. Implementors must store this handle and return it from
/// their [`AsRef<CoreCallingConvention>`] implementation so that the trait's layout methods can
/// delegate to the core's default behavior.
///
/// NOTE: This function should only be called within `CorePluginInit`.
pub fn register_calling_convention<A, C, F>(
    arch: &A,
    name: &str,
    func: F,
) -> Ref<CoreCallingConvention>
where
    A: Architecture,
    C: 'static + CallingConvention,
    F: FnOnce(CoreCallingConvention) -> C,
{
    #[repr(C)]
    struct CustomCallingConventionContext<C>
    where
        C: CallingConvention,
    {
        cc: MaybeUninit<C>,
    }

    unsafe fn from_ctxt<'a, C: CallingConvention>(ctxt: *mut c_void) -> &'a C {
        unsafe {
            (*(ctxt as *mut CustomCallingConventionContext<C>))
                .cc
                .assume_init_ref()
        }
    }

    unsafe fn register_list(regs: Vec<RegisterId>, count: *mut usize) -> *mut u32 {
        unsafe {
            let regs: Box<[u32]> = regs.iter().map(|r| r.0).collect();
            *count = regs.len();
            Box::leak(regs).as_mut_ptr()
        }
    }

    unsafe fn permitted_registers(
        has_permitted: bool,
        regs: *mut u32,
        count: usize,
    ) -> Option<Vec<RegisterId>> {
        if has_permitted {
            let regs = unsafe { slice_from_raw_parts(regs, count) };
            Some(regs.iter().copied().map(RegisterId::from).collect())
        } else {
            None
        }
    }

    extern "C" fn cb_free<C>(ctxt: *mut c_void)
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::free", unsafe {
            let mut ctxt = Box::from_raw(ctxt as *mut CustomCallingConventionContext<C>);
            ctxt.cc.assume_init_drop();
        })
    }

    extern "C" fn cb_free_register_list(_ctxt: *mut c_void, regs: *mut u32, count: usize) {
        ffi_wrap!("CallingConvention::free_register_list", unsafe {
            if regs.is_null() {
                return;
            }

            let regs_ptr = ptr::slice_from_raw_parts_mut(regs, count);
            let _regs = Box::from_raw(regs_ptr);
        })
    }

    extern "C" fn cb_caller_saved<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::caller_saved_registers", unsafe {
            register_list(from_ctxt::<C>(ctxt).caller_saved_registers(), count)
        })
    }

    extern "C" fn cb_callee_saved<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::callee_saved_registers", unsafe {
            register_list(from_ctxt::<C>(ctxt).callee_saved_registers(), count)
        })
    }

    extern "C" fn cb_int_args<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::int_arg_registers", unsafe {
            register_list(from_ctxt::<C>(ctxt).int_arg_registers(), count)
        })
    }

    extern "C" fn cb_float_args<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::float_arg_registers", unsafe {
            register_list(from_ctxt::<C>(ctxt).float_arg_registers(), count)
        })
    }

    extern "C" fn cb_required_argument_registers<C>(
        ctxt: *mut c_void,
        count: *mut usize,
    ) -> *mut u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::required_argument_registers", unsafe {
            register_list(from_ctxt::<C>(ctxt).required_argument_registers(), count)
        })
    }

    extern "C" fn cb_required_clobbered_registers<C>(
        ctxt: *mut c_void,
        count: *mut usize,
    ) -> *mut u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::required_clobbered_registers", unsafe {
            register_list(from_ctxt::<C>(ctxt).required_clobbered_registers(), count)
        })
    }

    extern "C" fn cb_arg_shared_index<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::arg_registers_shared_index", unsafe {
            from_ctxt::<C>(ctxt).arg_registers_shared_index()
        })
    }

    extern "C" fn cb_stack_reserved_arg_regs<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::reserved_stack_space_for_arg_registers",
            unsafe { from_ctxt::<C>(ctxt).reserved_stack_space_for_arg_registers() }
        )
    }

    extern "C" fn cb_stack_adjusted_on_return<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::stack_adjusted_on_return", unsafe {
            from_ctxt::<C>(ctxt).stack_adjusted_on_return()
        })
    }

    extern "C" fn cb_is_eligible_for_heuristics<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::is_eligible_for_heuristics", unsafe {
            from_ctxt::<C>(ctxt).is_eligible_for_heuristics()
        })
    }

    extern "C" fn cb_return_int_reg<C>(ctxt: *mut c_void) -> u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::return_int_reg", unsafe {
            from_ctxt::<C>(ctxt)
                .return_int_reg()
                .map(|r| r.0)
                .unwrap_or(INVALID_REGISTER)
        })
    }

    extern "C" fn cb_return_hi_int_reg<C>(ctxt: *mut c_void) -> u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::return_hi_int_reg", unsafe {
            from_ctxt::<C>(ctxt)
                .return_hi_int_reg()
                .map(|r| r.0)
                .unwrap_or(INVALID_REGISTER)
        })
    }

    extern "C" fn cb_return_float_reg<C>(ctxt: *mut c_void) -> u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::return_float_reg", unsafe {
            from_ctxt::<C>(ctxt)
                .return_float_reg()
                .map(|r| r.0)
                .unwrap_or(INVALID_REGISTER)
        })
    }

    extern "C" fn cb_global_pointer_regs<C>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::global_pointer_regs", unsafe {
            register_list(from_ctxt::<C>(ctxt).global_pointer_regs(), count)
        })
    }

    extern "C" fn cb_implicitly_defined_registers<C>(
        ctxt: *mut c_void,
        count: *mut usize,
    ) -> *mut u32
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::implicitly_defined_registers", unsafe {
            register_list(from_ctxt::<C>(ctxt).implicitly_defined_registers(), count)
        })
    }

    extern "C" fn cb_incoming_reg_value<C>(
        ctxt: *mut c_void,
        reg: u32,
        func: *mut BNFunction,
        val: *mut BNRegisterValue,
    ) where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::incoming_reg_value", unsafe {
            let func = (!func.is_null()).then(|| Function::from_raw(func));
            let value =
                from_ctxt::<C>(ctxt).incoming_register_value(RegisterId(reg), func.as_ref());
            ptr::write(val, value.into());
        })
    }

    extern "C" fn cb_incoming_flag_value<C>(
        ctxt: *mut c_void,
        flag: u32,
        func: *mut BNFunction,
        val: *mut BNRegisterValue,
    ) where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::incoming_flag_value", unsafe {
            let func = (!func.is_null()).then(|| Function::from_raw(func));
            let value = from_ctxt::<C>(ctxt).incoming_flag_value(FlagId(flag), func.as_ref());
            ptr::write(val, value.into());
        })
    }

    extern "C" fn cb_incoming_var_for_param<C>(
        ctxt: *mut c_void,
        var: *const BNVariable,
        func: *mut BNFunction,
        param: *mut BNVariable,
    ) where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::incoming_var_for_param", unsafe {
            let func = (!func.is_null()).then(|| Function::from_raw(func));
            let var = Variable::from(&*var);
            let result =
                from_ctxt::<C>(ctxt).incoming_variable_for_parameter_variable(&var, func.as_ref());
            ptr::write(param, result.into());
        })
    }

    extern "C" fn cb_incoming_param_for_var<C>(
        ctxt: *mut c_void,
        var: *const BNVariable,
        func: *mut BNFunction,
        param: *mut BNVariable,
    ) where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::incoming_param_for_var", unsafe {
            let func = (!func.is_null()).then(|| Function::from_raw(func));
            let var = Variable::from(&*var);
            let result =
                from_ctxt::<C>(ctxt).parameter_variable_for_incoming_variable(&var, func.as_ref());
            ptr::write(param, result.into());
        })
    }

    extern "C" fn cb_are_argument_registers_used_for_var_args<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::are_argument_registers_used_for_var_args",
            unsafe { from_ctxt::<C>(ctxt).are_argument_registers_used_for_var_args() }
        )
    }

    extern "C" fn cb_is_return_type_register_compatible<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        ty: *mut BNType,
    ) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::is_return_type_register_compatible",
            unsafe {
                let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
                let ty = (!ty.is_null()).then(|| Type::from_raw(ty));
                match ty.as_ref() {
                    Some(ty) => {
                        from_ctxt::<C>(ctxt).is_return_type_register_compatible(view.as_ref(), ty)
                    }
                    _ => false,
                }
            }
        )
    }

    extern "C" fn cb_indirect_return_value_location<C>(ctxt: *mut c_void, out_var: *mut BNVariable)
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::indirect_return_value_location",
            unsafe {
                ptr::write(
                    out_var,
                    from_ctxt::<C>(ctxt).indirect_return_value_location().into(),
                );
            }
        )
    }

    extern "C" fn cb_returned_indirect_return_value_pointer<C>(
        ctxt: *mut c_void,
        out_var: *mut BNVariable,
    ) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::returned_indirect_return_value_pointer",
            unsafe {
                match from_ctxt::<C>(ctxt).returned_indirect_return_value_pointer() {
                    Some(var) => {
                        ptr::write(out_var, var.into());
                        true
                    }
                    None => false,
                }
            }
        )
    }

    extern "C" fn cb_is_argument_type_register_compatible<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        ty: *mut BNType,
    ) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::is_argument_type_register_compatible",
            unsafe {
                let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
                let ty = (!ty.is_null()).then(|| Type::from_raw(ty));
                match ty.as_ref() {
                    Some(ty) => {
                        from_ctxt::<C>(ctxt).is_argument_type_register_compatible(view.as_ref(), ty)
                    }
                    _ => false,
                }
            }
        )
    }

    extern "C" fn cb_is_non_register_argument_indirect<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        ty: *mut BNType,
    ) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::is_non_register_argument_indirect",
            unsafe {
                let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
                let ty = (!ty.is_null()).then(|| Type::from_raw(ty));
                match ty.as_ref() {
                    Some(ty) => {
                        from_ctxt::<C>(ctxt).is_non_register_argument_indirect(view.as_ref(), ty)
                    }
                    _ => false,
                }
            }
        )
    }

    extern "C" fn cb_are_stack_arguments_naturally_aligned<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::are_stack_arguments_naturally_aligned",
            unsafe { from_ctxt::<C>(ctxt).are_stack_arguments_naturally_aligned() }
        )
    }

    extern "C" fn cb_are_stack_arguments_pushed_left_to_right<C>(ctxt: *mut c_void) -> bool
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::are_stack_arguments_pushed_left_to_right",
            unsafe { from_ctxt::<C>(ctxt).are_stack_arguments_pushed_left_to_right() }
        )
    }

    #[allow(clippy::too_many_arguments)]
    extern "C" fn cb_get_call_layout<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        return_value: *mut BNReturnValue,
        params: *mut BNFunctionParameter,
        param_count: usize,
        has_permitted_regs: bool,
        permitted_regs: *mut u32,
        permitted_reg_count: usize,
        result: *mut BNCallLayout,
    ) where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::get_call_layout", unsafe {
            let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
            let return_value = ReturnValue::from_raw(&*return_value);
            let params: Vec<FunctionParameter> = slice_from_raw_parts(params, param_count)
                .iter()
                .map(FunctionParameter::from_raw)
                .collect();
            let permitted =
                permitted_registers(has_permitted_regs, permitted_regs, permitted_reg_count);
            let layout = from_ctxt::<C>(ctxt).call_layout(
                view.as_ref(),
                &return_value,
                &params,
                permitted.as_deref(),
            );
            ptr::write(result, CallLayout::into_rust_raw(&layout));
        })
    }

    extern "C" fn cb_free_call_layout(_ctxt: *mut c_void, layout: *mut BNCallLayout) {
        ffi_wrap!("CallingConvention::free_call_layout", unsafe {
            CallLayout::free_rust_raw(&mut *layout);
        })
    }

    extern "C" fn cb_get_return_value_location<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        return_value: *mut BNReturnValue,
        out_location: *mut BNValueLocation,
    ) where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::get_return_value_location", unsafe {
            let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
            let return_value = ReturnValue::from_raw(&*return_value);
            let location = from_ctxt::<C>(ctxt).return_value_location(view.as_ref(), &return_value);
            ptr::write(out_location, ValueLocation::into_rust_raw(&location));
        })
    }

    extern "C" fn cb_free_value_location(_ctxt: *mut c_void, location: *mut BNValueLocation) {
        ffi_wrap!("CallingConvention::free_value_location", unsafe {
            ValueLocation::free_rust_raw(ptr::read(location));
        })
    }

    #[allow(clippy::too_many_arguments)]
    extern "C" fn cb_get_parameter_locations<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        return_value: *mut BNValueLocation,
        params: *mut BNFunctionParameter,
        param_count: usize,
        has_permitted_regs: bool,
        permitted_regs: *mut u32,
        permitted_reg_count: usize,
        out_count: *mut usize,
    ) -> *mut BNValueLocation
    where
        C: CallingConvention,
    {
        ffi_wrap!("CallingConvention::get_parameter_locations", unsafe {
            let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
            let return_value =
                (!return_value.is_null()).then(|| ValueLocation::from_raw(&*return_value));
            let params: Vec<FunctionParameter> = slice_from_raw_parts(params, param_count)
                .iter()
                .map(FunctionParameter::from_raw)
                .collect();
            let permitted =
                permitted_registers(has_permitted_regs, permitted_regs, permitted_reg_count);
            let locations = from_ctxt::<C>(ctxt).parameter_locations(
                view.as_ref(),
                return_value.as_ref(),
                &params,
                permitted.as_deref(),
            );
            let raw: Box<[BNValueLocation]> =
                locations.iter().map(ValueLocation::into_rust_raw).collect();
            *out_count = raw.len();
            Box::leak(raw).as_mut_ptr()
        })
    }

    extern "C" fn cb_free_parameter_locations(
        _ctxt: *mut c_void,
        locations: *mut BNValueLocation,
        count: usize,
    ) {
        ffi_wrap!("CallingConvention::free_parameter_locations", unsafe {
            if locations.is_null() {
                return;
            }
            let raw = Box::from_raw(ptr::slice_from_raw_parts_mut(locations, count));
            for loc in raw.into_vec() {
                ValueLocation::free_rust_raw(loc);
            }
        })
    }

    extern "C" fn cb_get_parameter_ordering_for_variables<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        vars: *mut BNVariable,
        types: *mut *mut BNType,
        param_count: usize,
        out_count: *mut usize,
    ) -> *mut BNVariable
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::get_parameter_ordering_for_variables",
            unsafe {
                let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
                let vars = slice_from_raw_parts(vars, param_count);
                let types = slice_from_raw_parts(types, param_count);
                let params: Option<Vec<(Variable, Ref<Type>)>> = vars
                    .iter()
                    .zip(types.iter())
                    .map(|(v, &ty)| {
                        (!ty.is_null()).then(|| {
                            (
                                Variable::from(v),
                                Type::ref_from_raw(BNNewTypeReference(ty)),
                            )
                        })
                    })
                    .collect();
                let ordering = if let Some(params) = params.as_deref() {
                    from_ctxt::<C>(ctxt).parameter_ordering_for_variables(view.as_ref(), params)
                } else {
                    Vec::new()
                };
                let raw: Box<[BNVariable]> =
                    ordering.iter().map(|v| BNVariable::from(*v)).collect();
                *out_count = raw.len();
                Box::leak(raw).as_mut_ptr()
            }
        )
    }

    extern "C" fn cb_free_variable_list(_ctxt: *mut c_void, vars: *mut BNVariable, count: usize) {
        ffi_wrap!("CallingConvention::free_variable_list", unsafe {
            if vars.is_null() {
                return;
            }
            let _vars = Box::from_raw(ptr::slice_from_raw_parts_mut(vars, count));
        })
    }

    extern "C" fn cb_get_stack_adjustment_for_locations<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        return_value: *mut BNValueLocation,
        locations: *mut BNValueLocation,
        types: *mut *mut BNType,
        param_count: usize,
    ) -> i64
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::get_stack_adjustment_for_locations",
            unsafe {
                let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
                let return_value =
                    (!return_value.is_null()).then(|| ValueLocation::from_raw(&*return_value));
                let locations = slice_from_raw_parts(locations, param_count);
                let types = slice_from_raw_parts(types, param_count);
                let params: Option<Vec<(ValueLocation, Ref<Type>)>> = locations
                    .iter()
                    .zip(types.iter())
                    .map(|(loc, &ty)| {
                        (!ty.is_null()).then(|| {
                            (
                                ValueLocation::from_raw(loc),
                                Type::ref_from_raw(BNNewTypeReference(ty)),
                            )
                        })
                    })
                    .collect();
                if let Some(params) = params.as_deref() {
                    from_ctxt::<C>(ctxt).stack_adjustment_for_locations(
                        view.as_ref(),
                        return_value.as_ref(),
                        params,
                    )
                } else {
                    0
                }
            }
        )
    }

    extern "C" fn cb_get_register_stack_adjustments<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        return_value: *mut BNValueLocation,
        params: *mut BNValueLocation,
        param_count: usize,
        out_regs: *mut *mut u32,
        out_adjust: *mut *mut i32,
    ) -> usize
    where
        C: CallingConvention,
    {
        ffi_wrap!(
            "CallingConvention::get_register_stack_adjustments",
            unsafe {
                let view = (!view.is_null()).then(|| BinaryView::from_raw(view));
                let return_value =
                    (!return_value.is_null()).then(|| ValueLocation::from_raw(&*return_value));
                let param_objs: Vec<ValueLocation> = slice_from_raw_parts(params, param_count)
                    .iter()
                    .map(ValueLocation::from_raw)
                    .collect();
                let adjustments = from_ctxt::<C>(ctxt).register_stack_adjustments(
                    view.as_ref(),
                    return_value.as_ref(),
                    &param_objs,
                );
                let regs: Box<[u32]> = adjustments.keys().map(|r| r.0).collect();
                let adjust: Box<[i32]> = adjustments.values().copied().collect();
                let count = regs.len();
                ptr::write(out_regs, Box::leak(regs).as_mut_ptr());
                ptr::write(out_adjust, Box::leak(adjust).as_mut_ptr());
                count
            }
        )
    }

    extern "C" fn cb_free_register_stack_adjustments(
        _ctxt: *mut c_void,
        regs: *mut u32,
        adjust: *mut i32,
        count: usize,
    ) {
        ffi_wrap!(
            "CallingConvention::free_register_stack_adjustments",
            unsafe {
                if !regs.is_null() {
                    let _ = Box::from_raw(ptr::slice_from_raw_parts_mut(regs, count));
                }
                if !adjust.is_null() {
                    let _ = Box::from_raw(ptr::slice_from_raw_parts_mut(adjust, count));
                }
            }
        )
    }

    let name = name.to_cstr();
    let raw = Box::into_raw(Box::new(CustomCallingConventionContext::<C> {
        cc: MaybeUninit::uninit(),
    }));
    let mut cc = BNCustomCallingConvention {
        context: raw as *mut _,

        freeObject: Some(cb_free::<C>),

        getCallerSavedRegisters: Some(cb_caller_saved::<C>),
        getCalleeSavedRegisters: Some(cb_callee_saved::<C>),
        getIntegerArgumentRegisters: Some(cb_int_args::<C>),
        getFloatArgumentRegisters: Some(cb_float_args::<C>),
        getRequiredArgumentRegisters: Some(cb_required_argument_registers::<C>),
        getRequiredClobberedRegisters: Some(cb_required_clobbered_registers::<C>),
        freeRegisterList: Some(cb_free_register_list),

        areArgumentRegistersSharedIndex: Some(cb_arg_shared_index::<C>),
        isStackReservedForArgumentRegisters: Some(cb_stack_reserved_arg_regs::<C>),
        isStackAdjustedOnReturn: Some(cb_stack_adjusted_on_return::<C>),
        isEligibleForHeuristics: Some(cb_is_eligible_for_heuristics::<C>),

        getIntegerReturnValueRegister: Some(cb_return_int_reg::<C>),
        getHighIntegerReturnValueRegister: Some(cb_return_hi_int_reg::<C>),
        getFloatReturnValueRegister: Some(cb_return_float_reg::<C>),
        getGlobalPointerRegisters: Some(cb_global_pointer_regs::<C>),

        getImplicitlyDefinedRegisters: Some(cb_implicitly_defined_registers::<C>),
        getIncomingRegisterValue: Some(cb_incoming_reg_value::<C>),
        getIncomingFlagValue: Some(cb_incoming_flag_value::<C>),
        getIncomingVariableForParameterVariable: Some(cb_incoming_var_for_param::<C>),
        getParameterVariableForIncomingVariable: Some(cb_incoming_param_for_var::<C>),

        areArgumentRegistersUsedForVarArgs: Some(cb_are_argument_registers_used_for_var_args::<C>),

        isReturnTypeRegisterCompatible: Some(cb_is_return_type_register_compatible::<C>),
        getIndirectReturnValueLocation: Some(cb_indirect_return_value_location::<C>),
        getReturnedIndirectReturnValuePointer: Some(cb_returned_indirect_return_value_pointer::<C>),
        isArgumentTypeRegisterCompatible: Some(cb_is_argument_type_register_compatible::<C>),
        isNonRegisterArgumentIndirect: Some(cb_is_non_register_argument_indirect::<C>),
        areStackArgumentsNaturallyAligned: Some(cb_are_stack_arguments_naturally_aligned::<C>),
        areStackArgumentsPushedLeftToRight: Some(cb_are_stack_arguments_pushed_left_to_right::<C>),

        getCallLayout: Some(cb_get_call_layout::<C>),
        freeCallLayout: Some(cb_free_call_layout),
        getReturnValueLocation: Some(cb_get_return_value_location::<C>),
        freeValueLocation: Some(cb_free_value_location),
        getParameterLocations: Some(cb_get_parameter_locations::<C>),
        freeParameterLocations: Some(cb_free_parameter_locations),
        getParameterOrderingForVariables: Some(cb_get_parameter_ordering_for_variables::<C>),
        freeVariableList: Some(cb_free_variable_list),
        getStackAdjustmentForLocations: Some(cb_get_stack_adjustment_for_locations::<C>),
        getRegisterStackAdjustments: Some(cb_get_register_stack_adjustments::<C>),
        freeRegisterStackAdjustments: Some(cb_free_register_stack_adjustments),
    };

    unsafe {
        let cc_name = name.as_ptr();
        let result = BNCreateCallingConvention(arch.as_ref().handle, cc_name, &mut cc);

        assert!(!result.is_null());

        let core = CoreCallingConvention::from_raw(result, arch.as_ref().handle());
        (*raw).cc.write(func(core));

        BNRegisterCallingConvention(arch.as_ref().handle, result);

        Ref::new(CoreCallingConvention {
            handle: result,
            arch_handle: arch.as_ref().handle(),
        })
    }
}

pub struct CoreCallingConvention {
    pub(crate) handle: *mut BNCallingConvention,
    pub(crate) arch_handle: CoreArchitecture,
}

impl CoreCallingConvention {
    pub(crate) unsafe fn from_raw(
        handle: *mut BNCallingConvention,
        arch: CoreArchitecture,
    ) -> Self {
        CoreCallingConvention {
            handle,
            arch_handle: arch,
        }
    }

    pub(crate) unsafe fn ref_from_raw(
        handle: *mut BNCallingConvention,
        arch: CoreArchitecture,
    ) -> Ref<Self> {
        unsafe {
            Ref::new(CoreCallingConvention {
                handle,
                arch_handle: arch,
            })
        }
    }

    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNGetCallingConventionName(self.handle)) }
    }

    pub fn arch(&self) -> CoreArchitecture {
        self.arch_handle
    }

    fn raw_permitted_args(permitted_registers: Option<&[RegisterId]>) -> Option<Vec<u32>> {
        permitted_registers.map(|regs| regs.iter().map(|r| r.0).collect())
    }

    pub fn default_incoming_variable_for_parameter_variable(&self, var: &Variable) -> Variable {
        let raw = BNVariable::from(var);
        Variable::from(unsafe {
            BNGetDefaultIncomingVariableForParameterVariable(self.handle, &raw)
        })
    }

    pub fn default_parameter_variable_for_incoming_variable(&self, var: &Variable) -> Variable {
        let raw = BNVariable::from(var);
        Variable::from(unsafe {
            BNGetDefaultParameterVariableForIncomingVariable(self.handle, &raw)
        })
    }

    pub fn default_is_return_type_register_compatible(&self, ty: &Type) -> bool {
        unsafe { BNDefaultIsReturnTypeRegisterCompatible(self.handle, ty.handle) }
    }

    pub fn default_indirect_return_value_location(&self) -> Variable {
        Variable::from(unsafe { BNGetDefaultIndirectReturnValueLocation(self.handle) })
    }

    pub fn default_is_argument_type_register_compatible(&self, ty: &Type) -> bool {
        unsafe { BNDefaultIsArgumentTypeRegisterCompatible(self.handle, ty.handle) }
    }

    pub fn default_call_layout(
        &self,
        view: Option<&BinaryView>,
        return_value: &ReturnValue,
        params: &[FunctionParameter],
        permitted_registers: Option<&[RegisterId]>,
    ) -> CallLayout {
        let raw_return_value = ReturnValue::into_rust_raw(return_value);
        let raw_params: Vec<BNFunctionParameter> = params
            .iter()
            .cloned()
            .map(FunctionParameter::into_raw)
            .collect();
        let raw_layout: BNCallLayout = match Self::raw_permitted_args(permitted_registers) {
            Some(permitted) => unsafe {
                BNGetDefaultCallLayout(
                    self.handle,
                    view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                    &raw_return_value,
                    raw_params.as_ptr(),
                    raw_params.len(),
                    permitted.as_ptr(),
                    permitted.len(),
                )
            },
            None => unsafe {
                BNGetDefaultCallLayoutDefaultPermittedArgs(
                    self.handle,
                    view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                    &raw_return_value,
                    raw_params.as_ptr(),
                    raw_params.len(),
                )
            },
        };

        ReturnValue::free_rust_raw(raw_return_value);
        for param in raw_params {
            FunctionParameter::free_raw(param);
        }
        CallLayout::from_owned_core_raw(raw_layout)
    }

    pub fn default_return_value_location(
        &self,
        view: Option<&BinaryView>,
        return_value: &ReturnValue,
    ) -> ValueLocation {
        let mut raw_return_value = ReturnValue::into_rust_raw(return_value);
        let mut raw_location = unsafe {
            BNGetDefaultReturnValueLocation(
                self.handle,
                view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                &mut raw_return_value,
            )
        };
        ReturnValue::free_rust_raw(raw_return_value);
        let result = ValueLocation::from_raw(&raw_location);
        unsafe {
            BNFreeValueLocation(&mut raw_location);
        }
        result
    }

    pub fn default_parameter_locations(
        &self,
        view: Option<&BinaryView>,
        return_value: Option<&ValueLocation>,
        params: &[FunctionParameter],
        permitted_registers: Option<&[RegisterId]>,
    ) -> Vec<ValueLocation> {
        let mut raw_return_value = return_value.map(ValueLocation::into_rust_raw);
        let return_value_ptr = raw_return_value
            .as_mut()
            .map(|r| r as *mut _)
            .unwrap_or(ptr::null_mut());
        let mut raw_params: Vec<BNFunctionParameter> = params
            .iter()
            .cloned()
            .map(FunctionParameter::into_raw)
            .collect();
        let mut count = 0;
        let locations_ptr = unsafe {
            match Self::raw_permitted_args(permitted_registers) {
                Some(permitted) => BNGetDefaultParameterLocations(
                    self.handle,
                    view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                    return_value_ptr,
                    raw_params.as_mut_ptr(),
                    raw_params.len(),
                    permitted.as_ptr(),
                    permitted.len(),
                    &mut count,
                ),
                None => BNGetDefaultParameterLocationsDefaultPermittedArgs(
                    self.handle,
                    view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                    return_value_ptr,
                    raw_params.as_mut_ptr(),
                    raw_params.len(),
                    &mut count,
                ),
            }
        };

        if let Some(raw_return_value) = raw_return_value {
            ValueLocation::free_rust_raw(raw_return_value);
        }
        for param in raw_params.drain(..) {
            FunctionParameter::free_raw(param);
        }

        let result = unsafe {
            slice_from_raw_parts(locations_ptr, count)
                .iter()
                .map(ValueLocation::from_raw)
                .collect()
        };
        unsafe {
            BNFreeValueLocationList(locations_ptr, count);
        }
        result
    }

    pub fn default_parameter_ordering_for_variables(
        &self,
        params: &[(Variable, Ref<Type>)],
    ) -> Vec<Variable> {
        let raw_vars: Vec<BNVariable> = params.iter().map(|(v, _)| BNVariable::from(*v)).collect();
        let mut raw_types: Vec<*const BNType> = params
            .iter()
            .map(|(_, t)| t.handle as *const BNType)
            .collect();
        let mut count = 0;
        let vars_ptr = unsafe {
            BNGetDefaultParameterOrderingForVariables(
                self.handle,
                raw_vars.as_ptr(),
                raw_types.as_mut_ptr(),
                params.len(),
                &mut count,
            )
        };
        let result = unsafe {
            slice_from_raw_parts(vars_ptr, count)
                .iter()
                .map(Variable::from)
                .collect()
        };
        unsafe {
            BNFreeVariableList(vars_ptr);
        }
        result
    }

    pub fn default_stack_adjustment_for_locations(
        &self,
        return_value: Option<&ValueLocation>,
        params: &[(ValueLocation, Ref<Type>)],
    ) -> i64 {
        let mut raw_return_value = return_value.map(ValueLocation::into_rust_raw);
        let return_value_ptr = raw_return_value
            .as_mut()
            .map(|r| r as *mut _)
            .unwrap_or(ptr::null_mut());
        let raw_locations: Vec<BNValueLocation> = params
            .iter()
            .map(|(loc, _)| ValueLocation::into_rust_raw(loc))
            .collect();
        let mut raw_types: Vec<*const BNType> = params
            .iter()
            .map(|(_, t)| t.handle as *const BNType)
            .collect();
        let result = unsafe {
            BNGetDefaultStackAdjustmentForLocations(
                self.handle,
                return_value_ptr,
                raw_locations.as_ptr(),
                raw_types.as_mut_ptr(),
                params.len(),
            )
        };
        if let Some(raw_return_value) = raw_return_value {
            ValueLocation::free_rust_raw(raw_return_value);
        }
        for loc in raw_locations {
            ValueLocation::free_rust_raw(loc);
        }
        result
    }

    pub fn default_register_stack_adjustments(
        &self,
        return_value: Option<&ValueLocation>,
        params: &[ValueLocation],
    ) -> BTreeMap<RegisterId, i32> {
        let mut raw_return_value = return_value.map(ValueLocation::into_rust_raw);
        let return_value_ptr = raw_return_value
            .as_mut()
            .map(|r| r as *mut _)
            .unwrap_or(ptr::null_mut());
        let mut raw_params: Vec<BNValueLocation> =
            params.iter().map(ValueLocation::into_rust_raw).collect();
        let mut regs: *mut u32 = ptr::null_mut();
        let mut adjust: *mut i32 = ptr::null_mut();
        let count = unsafe {
            BNGetCallingConventionDefaultRegisterStackAdjustments(
                self.handle,
                return_value_ptr,
                raw_params.as_mut_ptr(),
                raw_params.len(),
                &mut regs,
                &mut adjust,
            )
        };
        let regs_slice = unsafe { slice_from_raw_parts(regs, count) };
        let adjust_slice = unsafe { slice_from_raw_parts(adjust, count) };
        let result = regs_slice
            .iter()
            .zip(adjust_slice.iter())
            .map(|(r, a)| (RegisterId(*r), *a))
            .collect();
        if let Some(raw_return_value) = raw_return_value {
            ValueLocation::free_rust_raw(raw_return_value);
        }
        for param in raw_params {
            ValueLocation::free_rust_raw(param);
        }
        unsafe {
            BNFreeCallingConventionRegisterStackAdjustments(regs, adjust);
        }
        result
    }
}

unsafe impl Send for CoreCallingConvention {}
unsafe impl Sync for CoreCallingConvention {}

impl Eq for CoreCallingConvention {}
impl PartialEq for CoreCallingConvention {
    fn eq(&self, rhs: &Self) -> bool {
        self.handle == rhs.handle
    }
}

impl AsRef<CoreCallingConvention> for CoreCallingConvention {
    fn as_ref(&self) -> &CoreCallingConvention {
        self
    }
}

impl Debug for CoreCallingConvention {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreCallingConvention")
            .field("name", &self.name())
            .field("caller_saved_registers", &self.caller_saved_registers())
            .field("callee_saved_registers", &self.callee_saved_registers())
            .field("int_arg_registers", &self.int_arg_registers())
            .field("float_arg_registers", &self.float_arg_registers())
            .field(
                "required_argument_registers",
                &self.required_argument_registers(),
            )
            .field(
                "required_clobbered_registers",
                &self.required_clobbered_registers(),
            )
            .field(
                "arg_registers_shared_index",
                &self.arg_registers_shared_index(),
            )
            .field(
                "reserved_stack_space_for_arg_registers",
                &self.reserved_stack_space_for_arg_registers(),
            )
            .field("stack_adjusted_on_return", &self.stack_adjusted_on_return())
            .field(
                "is_eligible_for_heuristics",
                &self.is_eligible_for_heuristics(),
            )
            .field("return_int_reg", &self.return_int_reg())
            .field("return_hi_int_reg", &self.return_hi_int_reg())
            .field("return_float_reg", &self.return_float_reg())
            .field("global_pointer_reg", &self.global_pointer_reg())
            .field("global_pointer_regs", &self.global_pointer_regs())
            .field(
                "implicitly_defined_registers",
                &self.implicitly_defined_registers(),
            )
            .field(
                "are_argument_registers_used_for_var_args",
                &self.are_argument_registers_used_for_var_args(),
            )
            .finish()
    }
}

impl Hash for CoreCallingConvention {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl CallingConvention for CoreCallingConvention {
    fn caller_saved_registers(&self) -> Vec<RegisterId> {
        unsafe {
            let mut count = 0;
            let regs_ptr = BNGetCallerSavedRegisters(self.handle, &mut count);
            let regs: Vec<RegisterId> = std::slice::from_raw_parts(regs_ptr, count)
                .iter()
                .copied()
                .map(RegisterId::from)
                .collect();
            BNFreeRegisterList(regs_ptr);
            regs
        }
    }

    fn callee_saved_registers(&self) -> Vec<RegisterId> {
        unsafe {
            let mut count = 0;
            let regs_ptr = BNGetCalleeSavedRegisters(self.handle, &mut count);
            let regs: Vec<RegisterId> = std::slice::from_raw_parts(regs_ptr, count)
                .iter()
                .copied()
                .map(RegisterId::from)
                .collect();
            BNFreeRegisterList(regs_ptr);
            regs
        }
    }

    fn int_arg_registers(&self) -> Vec<RegisterId> {
        unsafe {
            let mut count = 0;
            let regs_ptr = BNGetIntegerArgumentRegisters(self.handle, &mut count);
            let regs: Vec<RegisterId> = std::slice::from_raw_parts(regs_ptr, count)
                .iter()
                .copied()
                .map(RegisterId::from)
                .collect();
            BNFreeRegisterList(regs_ptr);
            regs
        }
    }

    fn float_arg_registers(&self) -> Vec<RegisterId> {
        unsafe {
            let mut count = 0;
            let regs_ptr = BNGetFloatArgumentRegisters(self.handle, &mut count);
            let regs: Vec<RegisterId> = std::slice::from_raw_parts(regs_ptr, count)
                .iter()
                .copied()
                .map(RegisterId::from)
                .collect();
            BNFreeRegisterList(regs_ptr);
            regs
        }
    }

    fn required_argument_registers(&self) -> Vec<RegisterId> {
        unsafe {
            let mut count = 0;
            let regs_ptr = BNGetRequiredArgumentRegisters(self.handle, &mut count);
            let regs: Vec<RegisterId> = std::slice::from_raw_parts(regs_ptr, count)
                .iter()
                .copied()
                .map(RegisterId::from)
                .collect();
            BNFreeRegisterList(regs_ptr);
            regs
        }
    }

    fn required_clobbered_registers(&self) -> Vec<RegisterId> {
        unsafe {
            let mut count = 0;
            let regs_ptr = BNGetRequiredClobberedRegisters(self.handle, &mut count);
            let regs: Vec<RegisterId> = std::slice::from_raw_parts(regs_ptr, count)
                .iter()
                .copied()
                .map(RegisterId::from)
                .collect();
            BNFreeRegisterList(regs_ptr);
            regs
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
        unsafe { BNIsEligibleForHeuristics(self.handle) }
    }

    fn return_int_reg(&self) -> Option<RegisterId> {
        match unsafe { BNGetIntegerReturnValueRegister(self.handle) } {
            id if id < 0x8000_0000 => self
                .arch_handle
                .borrow()
                .register_from_id(RegisterId(id))
                .map(|r| r.id()),
            _ => None,
        }
    }

    fn return_hi_int_reg(&self) -> Option<RegisterId> {
        match unsafe { BNGetHighIntegerReturnValueRegister(self.handle) } {
            id if id < 0x8000_0000 => self
                .arch_handle
                .borrow()
                .register_from_id(RegisterId(id))
                .map(|r| r.id()),
            _ => None,
        }
    }

    fn return_float_reg(&self) -> Option<RegisterId> {
        match unsafe { BNGetFloatReturnValueRegister(self.handle) } {
            id if id < 0x8000_0000 => self
                .arch_handle
                .borrow()
                .register_from_id(RegisterId(id))
                .map(|r| r.id()),
            _ => None,
        }
    }

    /// Deprecated. Use [`CallingConvention::global_pointer_regs`] instead.
    fn global_pointer_reg(&self) -> Option<RegisterId> {
        self.global_pointer_regs().first().copied()
    }

    fn global_pointer_regs(&self) -> Vec<RegisterId> {
        unsafe {
            let mut count = 0;
            let regs_ptr = BNGetGlobalPointerRegisters(self.handle, &mut count);
            let regs: Vec<RegisterId> = std::slice::from_raw_parts(regs_ptr, count)
                .iter()
                .copied()
                .map(RegisterId::from)
                .collect();
            BNFreeRegisterList(regs_ptr);
            regs
        }
    }

    fn implicitly_defined_registers(&self) -> Vec<RegisterId> {
        unsafe {
            let mut count = 0;
            let regs_ptr = BNGetImplicitlyDefinedRegisters(self.handle, &mut count);
            let regs: Vec<RegisterId> = std::slice::from_raw_parts(regs_ptr, count)
                .iter()
                .copied()
                .map(RegisterId::from)
                .collect();
            BNFreeRegisterList(regs_ptr);
            regs
        }
    }

    fn are_argument_registers_used_for_var_args(&self) -> bool {
        unsafe { BNAreArgumentRegistersUsedForVarArgs(self.handle) }
    }

    fn incoming_register_value(&self, reg: RegisterId, func: Option<&Function>) -> RegisterValue {
        let func = func.map(|f| f.handle).unwrap_or(ptr::null_mut());
        RegisterValue::from(unsafe { BNGetIncomingRegisterValue(self.handle, reg.0, func) })
    }

    fn incoming_flag_value(&self, flag: FlagId, func: Option<&Function>) -> RegisterValue {
        let func = func.map(|f| f.handle).unwrap_or(ptr::null_mut());
        RegisterValue::from(unsafe { BNGetIncomingFlagValue(self.handle, flag.0, func) })
    }

    fn incoming_variable_for_parameter_variable(
        &self,
        var: &Variable,
        func: Option<&Function>,
    ) -> Variable {
        let raw = BNVariable::from(var);
        let func = func.map(|f| f.handle).unwrap_or(ptr::null_mut());
        Variable::from(unsafe {
            BNGetIncomingVariableForParameterVariable(self.handle, &raw, func)
        })
    }

    fn parameter_variable_for_incoming_variable(
        &self,
        var: &Variable,
        func: Option<&Function>,
    ) -> Variable {
        let raw = BNVariable::from(var);
        let func = func.map(|f| f.handle).unwrap_or(ptr::null_mut());
        Variable::from(unsafe {
            BNGetParameterVariableForIncomingVariable(self.handle, &raw, func)
        })
    }

    fn is_return_type_register_compatible(&self, view: Option<&BinaryView>, ty: &Type) -> bool {
        unsafe {
            BNIsReturnTypeRegisterCompatible(
                self.handle,
                view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                ty.handle,
            )
        }
    }

    fn indirect_return_value_location(&self) -> Variable {
        Variable::from(unsafe { BNGetIndirectReturnValueLocation(self.handle) })
    }

    fn returned_indirect_return_value_pointer(&self) -> Option<Variable> {
        let mut var = BNVariable::default();
        unsafe {
            BNGetReturnedIndirectReturnValuePointer(self.handle, &mut var)
                .then(|| Variable::from(var))
        }
    }

    fn is_argument_type_register_compatible(&self, view: Option<&BinaryView>, ty: &Type) -> bool {
        unsafe {
            BNIsArgumentTypeRegisterCompatible(
                self.handle,
                view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                ty.handle,
            )
        }
    }

    fn is_non_register_argument_indirect(&self, view: Option<&BinaryView>, ty: &Type) -> bool {
        unsafe {
            BNIsNonRegisterArgumentIndirect(
                self.handle,
                view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                ty.handle,
            )
        }
    }

    fn are_stack_arguments_naturally_aligned(&self) -> bool {
        unsafe { BNAreStackArgumentsNaturallyAligned(self.handle) }
    }

    fn are_stack_arguments_pushed_left_to_right(&self) -> bool {
        unsafe { BNAreStackArgumentsPushedLeftToRight(self.handle) }
    }

    fn call_layout(
        &self,
        view: Option<&BinaryView>,
        return_value: &ReturnValue,
        params: &[FunctionParameter],
        permitted_registers: Option<&[RegisterId]>,
    ) -> CallLayout {
        let raw_return_value = ReturnValue::into_rust_raw(return_value);
        let raw_params: Vec<BNFunctionParameter> = params
            .iter()
            .cloned()
            .map(FunctionParameter::into_raw)
            .collect();
        let raw_layout: BNCallLayout = if let Some(permitted_args) = permitted_registers {
            let permitted_regs = permitted_args.iter().map(|r| r.0).collect::<Vec<_>>();

            unsafe {
                BNGetCallLayout(
                    self.handle,
                    view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                    &raw_return_value,
                    raw_params.as_ptr(),
                    raw_params.len(),
                    permitted_regs.as_ptr(),
                    permitted_regs.len(),
                )
            }
        } else {
            unsafe {
                BNGetCallLayoutDefaultPermittedArgs(
                    self.handle,
                    view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                    &raw_return_value,
                    raw_params.as_ptr(),
                    raw_params.len(),
                )
            }
        };

        ReturnValue::free_rust_raw(raw_return_value);
        for param in raw_params {
            FunctionParameter::free_raw(param);
        }
        CallLayout::from_owned_core_raw(raw_layout)
    }

    fn return_value_location(
        &self,
        view: Option<&BinaryView>,
        return_value: &ReturnValue,
    ) -> ValueLocation {
        let mut raw_return_value = ReturnValue::into_rust_raw(return_value);
        let mut raw_location = unsafe {
            BNGetReturnValueLocation(
                self.handle,
                view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                &mut raw_return_value,
            )
        };
        ReturnValue::free_rust_raw(raw_return_value);
        let result = ValueLocation::from_raw(&raw_location);
        unsafe {
            BNFreeValueLocation(&mut raw_location);
        }
        result
    }

    fn parameter_locations(
        &self,
        view: Option<&BinaryView>,
        return_value: Option<&ValueLocation>,
        params: &[FunctionParameter],
        permitted_registers: Option<&[RegisterId]>,
    ) -> Vec<ValueLocation> {
        let mut raw_return_value = return_value.map(ValueLocation::into_rust_raw);
        let return_value_ptr = raw_return_value
            .as_mut()
            .map(|r| r as *mut _)
            .unwrap_or(ptr::null_mut());
        let mut raw_params: Vec<BNFunctionParameter> = params
            .iter()
            .cloned()
            .map(FunctionParameter::into_raw)
            .collect();
        let mut count = 0;
        let locations_ptr = unsafe {
            match Self::raw_permitted_args(permitted_registers) {
                Some(permitted) => BNGetParameterLocations(
                    self.handle,
                    view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                    return_value_ptr,
                    raw_params.as_mut_ptr(),
                    raw_params.len(),
                    permitted.as_ptr(),
                    permitted.len(),
                    &mut count,
                ),
                None => BNGetParameterLocationsDefaultPermittedArgs(
                    self.handle,
                    view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                    return_value_ptr,
                    raw_params.as_mut_ptr(),
                    raw_params.len(),
                    &mut count,
                ),
            }
        };

        if let Some(raw_return_value) = raw_return_value {
            ValueLocation::free_rust_raw(raw_return_value);
        }
        for param in raw_params {
            FunctionParameter::free_raw(param);
        }

        let result = unsafe {
            slice_from_raw_parts(locations_ptr, count)
                .iter()
                .map(ValueLocation::from_raw)
                .collect()
        };
        unsafe {
            BNFreeValueLocationList(locations_ptr, count);
        }
        result
    }

    fn parameter_ordering_for_variables(
        &self,
        view: Option<&BinaryView>,
        params: &[(Variable, Ref<Type>)],
    ) -> Vec<Variable> {
        let raw_vars: Vec<BNVariable> = params.iter().map(|(v, _)| BNVariable::from(*v)).collect();
        let mut raw_types: Vec<*const BNType> = params
            .iter()
            .map(|(_, t)| t.handle as *const BNType)
            .collect();
        let mut count = 0;
        let vars_ptr = unsafe {
            BNGetParameterOrderingForVariables(
                self.handle,
                view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                raw_vars.as_ptr(),
                raw_types.as_mut_ptr(),
                params.len(),
                &mut count,
            )
        };
        let result = unsafe {
            slice_from_raw_parts(vars_ptr, count)
                .iter()
                .map(Variable::from)
                .collect()
        };
        unsafe {
            BNFreeVariableList(vars_ptr);
        }
        result
    }

    fn stack_adjustment_for_locations(
        &self,
        view: Option<&BinaryView>,
        return_value: Option<&ValueLocation>,
        params: &[(ValueLocation, Ref<Type>)],
    ) -> i64 {
        let mut raw_return_value = return_value.map(ValueLocation::into_rust_raw);
        let return_value_ptr = raw_return_value
            .as_mut()
            .map(|r| r as *mut _)
            .unwrap_or(ptr::null_mut());
        let raw_locations: Vec<BNValueLocation> = params
            .iter()
            .map(|(loc, _)| ValueLocation::into_rust_raw(loc))
            .collect();
        let mut raw_types: Vec<*const BNType> = params
            .iter()
            .map(|(_, t)| t.handle as *const BNType)
            .collect();
        let result = unsafe {
            BNGetStackAdjustmentForLocations(
                self.handle,
                view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                return_value_ptr,
                raw_locations.as_ptr(),
                raw_types.as_mut_ptr(),
                params.len(),
            )
        };
        if let Some(raw_return_value) = raw_return_value {
            ValueLocation::free_rust_raw(raw_return_value);
        }
        for loc in raw_locations {
            ValueLocation::free_rust_raw(loc);
        }
        result
    }

    fn register_stack_adjustments(
        &self,
        view: Option<&BinaryView>,
        return_value: Option<&ValueLocation>,
        params: &[ValueLocation],
    ) -> BTreeMap<RegisterId, i32> {
        let mut raw_return_value = return_value.map(ValueLocation::into_rust_raw);
        let return_value_ptr = raw_return_value
            .as_mut()
            .map(|r| r as *mut _)
            .unwrap_or(ptr::null_mut());
        let mut raw_params: Vec<BNValueLocation> =
            params.iter().map(ValueLocation::into_rust_raw).collect();
        let mut regs: *mut u32 = ptr::null_mut();
        let mut adjust: *mut i32 = ptr::null_mut();
        let count = unsafe {
            BNGetCallingConventionRegisterStackAdjustments(
                self.handle,
                view.map(|view| view.handle).unwrap_or(ptr::null_mut()),
                return_value_ptr,
                raw_params.as_mut_ptr(),
                raw_params.len(),
                &mut regs,
                &mut adjust,
            )
        };
        let regs_slice = unsafe { slice_from_raw_parts(regs, count) };
        let adjust_slice = unsafe { slice_from_raw_parts(adjust, count) };
        let result = regs_slice
            .iter()
            .zip(adjust_slice.iter())
            .map(|(r, a)| (RegisterId(*r), *a))
            .collect();
        if let Some(raw_return_value) = raw_return_value {
            ValueLocation::free_rust_raw(raw_return_value);
        }
        for param in raw_params {
            ValueLocation::free_rust_raw(param);
        }
        unsafe {
            BNFreeCallingConventionRegisterStackAdjustments(regs, adjust);
        }
        result
    }
}

impl ToOwned for CoreCallingConvention {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for CoreCallingConvention {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        unsafe {
            Ref::new(Self {
                handle: BNNewCallingConventionReference(handle.handle),
                arch_handle: handle.arch_handle,
            })
        }
    }

    unsafe fn dec_ref(handle: &Self) {
        unsafe {
            BNFreeCallingConvention(handle.handle);
        }
    }
}

impl CoreArrayProvider for CoreCallingConvention {
    type Raw = *mut BNCallingConvention;
    type Context = CoreArchitecture;
    type Wrapped<'a> = Guard<'a, CoreCallingConvention>;
}

unsafe impl CoreArrayProviderInner for CoreCallingConvention {
    unsafe fn free(raw: *mut *mut BNCallingConvention, count: usize, _content: &Self::Context) {
        unsafe {
            BNFreeCallingConventionList(raw, count);
        }
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        unsafe {
            Guard::new(
                CoreCallingConvention {
                    handle: *raw,
                    arch_handle: *context,
                },
                context,
            )
        }
    }
}

/// A builder for a calling convention defined entirely by its register sets and flags.
///
/// Conventions built this way use the core's default behavior for parameter and return value
/// placement. Override the [`CallingConvention`] trait directly if you need custom layout logic.
pub struct ConventionBuilder<A: Architecture> {
    config: ConventionConfig,
    arch_handle: A::Handle,
    _arch: PhantomData<*const A>,
}

/// The plain-data portion of a [`ConventionBuilder`]. Moved to a [`RegisteredConvention`] when
/// registered.
struct ConventionConfig {
    caller_saved_registers: Vec<RegisterId>,
    callee_saved_registers: Vec<RegisterId>,
    int_arg_registers: Vec<RegisterId>,
    float_arg_registers: Vec<RegisterId>,
    required_argument_registers: Vec<RegisterId>,
    required_clobbered_registers: Vec<RegisterId>,

    arg_registers_shared_index: bool,
    reserved_stack_space_for_arg_registers: bool,
    stack_adjusted_on_return: bool,
    is_eligible_for_heuristics: bool,

    return_int_reg: Option<RegisterId>,
    return_hi_int_reg: Option<RegisterId>,
    return_float_reg: Option<RegisterId>,

    global_pointer_reg: Option<RegisterId>,
    global_pointer_regs: Vec<RegisterId>,

    implicitly_defined_registers: Vec<RegisterId>,

    are_argument_registers_used_for_var_args: bool,
    are_stack_arguments_naturally_aligned: bool,
    are_stack_arguments_pushed_left_to_right: bool,

    is_non_register_argument_indirect: bool,

    indirect_return_value_location: Option<Variable>,
    returned_indirect_return_value_pointer: Option<Variable>,
}

macro_rules! bool_arg {
    ($name:ident) => {
        pub fn $name(mut self, val: bool) -> Self {
            self.config.$name = val;
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
                let arch_regs = regs
                    .iter()
                    .filter_map(|&r| arch.register_by_name(r))
                    .map(|r| r.id());

                self.config.$name = arch_regs.collect();
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
                self.config.$name = arch.register_by_name(reg).map(|r| r.id());
            }

            self
        }
    };
}

impl<A: Architecture> ConventionBuilder<A> {
    pub fn new(arch: &A) -> Self {
        Self {
            config: ConventionConfig {
                caller_saved_registers: Vec::new(),
                callee_saved_registers: Vec::new(),
                int_arg_registers: Vec::new(),
                float_arg_registers: Vec::new(),
                required_argument_registers: Vec::new(),
                required_clobbered_registers: Vec::new(),

                arg_registers_shared_index: false,
                reserved_stack_space_for_arg_registers: false,
                stack_adjusted_on_return: false,
                is_eligible_for_heuristics: false,

                return_int_reg: None,
                return_hi_int_reg: None,
                return_float_reg: None,

                global_pointer_reg: None,
                global_pointer_regs: Vec::new(),

                implicitly_defined_registers: Vec::new(),

                are_argument_registers_used_for_var_args: false,
                are_stack_arguments_naturally_aligned: false,
                are_stack_arguments_pushed_left_to_right: false,

                is_non_register_argument_indirect: false,

                indirect_return_value_location: None,
                returned_indirect_return_value_pointer: None,
            },
            arch_handle: arch.handle(),
            _arch: PhantomData,
        }
    }

    reg_list!(caller_saved_registers);
    reg_list!(callee_saved_registers);
    reg_list!(int_arg_registers);
    reg_list!(float_arg_registers);
    reg_list!(required_argument_registers);
    reg_list!(required_clobbered_registers);

    bool_arg!(arg_registers_shared_index);
    bool_arg!(reserved_stack_space_for_arg_registers);
    bool_arg!(stack_adjusted_on_return);
    bool_arg!(is_eligible_for_heuristics);

    reg!(return_int_reg);
    reg!(return_hi_int_reg);
    reg!(return_float_reg);

    /// Deprecated. Use [`Self::global_pointer_regs`] instead.
    pub fn global_pointer_reg(mut self, reg: &str) -> Self {
        {
            // FIXME NLL
            let arch = self.arch_handle.borrow();
            self.config.global_pointer_reg = arch.register_by_name(reg).map(|r| r.id());
            self.config.global_pointer_regs = self.config.global_pointer_reg.into_iter().collect();
        }

        self
    }

    pub fn global_pointer_regs(mut self, regs: &[&str]) -> Self {
        {
            // FIXME NLL
            let arch = self.arch_handle.borrow();
            let arch_regs = regs
                .iter()
                .filter_map(|&r| arch.register_by_name(r))
                .map(|r| r.id());

            self.config.global_pointer_regs = arch_regs.collect();
            self.config.global_pointer_reg = self.config.global_pointer_regs.first().copied();
        }

        self
    }

    reg_list!(implicitly_defined_registers);

    bool_arg!(are_argument_registers_used_for_var_args);
    bool_arg!(are_stack_arguments_naturally_aligned);
    bool_arg!(are_stack_arguments_pushed_left_to_right);

    bool_arg!(is_non_register_argument_indirect);

    pub fn indirect_return_value_location(mut self, var: Variable) -> Self {
        self.config.indirect_return_value_location = Some(var);
        self
    }

    pub fn returned_indirect_return_value_pointer(mut self, var: Variable) -> Self {
        self.config.returned_indirect_return_value_pointer = Some(var);
        self
    }

    pub fn register(self, name: &str) -> Ref<CoreCallingConvention> {
        let arch = self.arch_handle.clone();
        register_calling_convention(arch.borrow(), name, move |core| RegisteredConvention {
            config: self.config,
            core,
        })
    }
}

/// A registered [`ConventionBuilder`], holding its configuration and core handle.
struct RegisteredConvention {
    config: ConventionConfig,
    core: CoreCallingConvention,
}

unsafe impl Send for RegisteredConvention {}
unsafe impl Sync for RegisteredConvention {}

impl AsRef<CoreCallingConvention> for RegisteredConvention {
    fn as_ref(&self) -> &CoreCallingConvention {
        &self.core
    }
}

impl CallingConvention for RegisteredConvention {
    fn caller_saved_registers(&self) -> Vec<RegisterId> {
        self.config.caller_saved_registers.clone()
    }

    fn callee_saved_registers(&self) -> Vec<RegisterId> {
        self.config.callee_saved_registers.clone()
    }

    fn int_arg_registers(&self) -> Vec<RegisterId> {
        self.config.int_arg_registers.clone()
    }

    fn float_arg_registers(&self) -> Vec<RegisterId> {
        self.config.float_arg_registers.clone()
    }

    fn required_argument_registers(&self) -> Vec<RegisterId> {
        self.config.required_argument_registers.clone()
    }

    fn required_clobbered_registers(&self) -> Vec<RegisterId> {
        self.config.required_clobbered_registers.clone()
    }

    fn arg_registers_shared_index(&self) -> bool {
        self.config.arg_registers_shared_index
    }

    fn reserved_stack_space_for_arg_registers(&self) -> bool {
        self.config.reserved_stack_space_for_arg_registers
    }

    fn stack_adjusted_on_return(&self) -> bool {
        self.config.stack_adjusted_on_return
    }

    fn is_eligible_for_heuristics(&self) -> bool {
        self.config.is_eligible_for_heuristics
    }

    fn return_int_reg(&self) -> Option<RegisterId> {
        self.config.return_int_reg
    }

    fn return_hi_int_reg(&self) -> Option<RegisterId> {
        self.config.return_hi_int_reg
    }

    fn return_float_reg(&self) -> Option<RegisterId> {
        self.config.return_float_reg
    }

    fn global_pointer_reg(&self) -> Option<RegisterId> {
        self.config
            .global_pointer_reg
            .or_else(|| self.config.global_pointer_regs.first().copied())
    }

    fn global_pointer_regs(&self) -> Vec<RegisterId> {
        if self.config.global_pointer_regs.is_empty() {
            self.config.global_pointer_reg.into_iter().collect()
        } else {
            self.config.global_pointer_regs.clone()
        }
    }

    fn implicitly_defined_registers(&self) -> Vec<RegisterId> {
        self.config.implicitly_defined_registers.clone()
    }

    fn are_argument_registers_used_for_var_args(&self) -> bool {
        self.config.are_argument_registers_used_for_var_args
    }

    fn are_stack_arguments_naturally_aligned(&self) -> bool {
        self.config.are_stack_arguments_naturally_aligned
    }

    fn are_stack_arguments_pushed_left_to_right(&self) -> bool {
        self.config.are_stack_arguments_pushed_left_to_right
    }

    fn is_non_register_argument_indirect(&self, _view: Option<&BinaryView>, _ty: &Type) -> bool {
        self.config.is_non_register_argument_indirect
    }

    fn indirect_return_value_location(&self) -> Variable {
        match self.config.indirect_return_value_location {
            Some(var) => var,
            None => self.as_ref().default_indirect_return_value_location(),
        }
    }

    fn returned_indirect_return_value_pointer(&self) -> Option<Variable> {
        self.config.returned_indirect_return_value_pointer
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallLayout {
    pub parameters: Vec<ValueLocation>,
    pub return_value: Option<ValueLocation>,
    pub stack_adjustment: i64,
    pub register_stack_adjustments: BTreeMap<RegisterId, i32>,
}

impl CallLayout {
    pub(crate) fn from_raw(value: &BNCallLayout) -> Self {
        let raw_params = unsafe { slice_from_raw_parts(value.parameters, value.parameterCount) };
        let parameters = raw_params.iter().map(ValueLocation::from_raw).collect();
        let return_value = if value.returnValueValid {
            Some(ValueLocation::from_raw(&value.returnValue))
        } else {
            None
        };
        let raw_regs = unsafe {
            slice_from_raw_parts(
                value.registerStackAdjustmentRegisters,
                value.registerStackAdjustmentCount,
            )
        };
        let raw_amounts = unsafe {
            slice_from_raw_parts(
                value.registerStackAdjustmentAmounts,
                value.registerStackAdjustmentCount,
            )
        };
        let mut register_stack_adjustments = BTreeMap::new();
        for i in 0..value.registerStackAdjustmentCount {
            register_stack_adjustments.insert(RegisterId(raw_regs[i]), raw_amounts[i]);
        }
        Self {
            parameters,
            return_value,
            stack_adjustment: value.stackAdjustment,
            register_stack_adjustments,
        }
    }

    /// Take ownership over an "owned" **core allocated** value. Do not call this for a rust allocated value.
    pub(crate) fn from_owned_core_raw(mut value: BNCallLayout) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_core_raw(&mut value);
        owned
    }

    /// Free a CORE ALLOCATED value. Do not use this with [Self::into_rust_raw] values.
    pub(crate) fn free_core_raw(value: &mut BNCallLayout) {
        unsafe { BNFreeCallLayout(value) }
    }

    /// Build a RUST ALLOCATED value. Free it only with [Self::free_rust_raw].
    pub(crate) fn into_rust_raw(value: &Self) -> BNCallLayout {
        let parameters: Box<[BNValueLocation]> = value
            .parameters
            .iter()
            .map(ValueLocation::into_rust_raw)
            .collect();
        let regs: Box<[u32]> = value
            .register_stack_adjustments
            .keys()
            .map(|r| r.0)
            .collect();
        let amounts: Box<[i32]> = value.register_stack_adjustments.values().copied().collect();
        let return_value =
            ValueLocation::into_rust_raw(value.return_value.as_ref().unwrap_or(&ValueLocation {
                components: Vec::new(),
                indirect: false,
                returned_pointer: None,
            }));
        BNCallLayout {
            parameterCount: parameters.len(),
            parameters: Box::leak(parameters).as_mut_ptr(),
            returnValueValid: value.return_value.is_some(),
            returnValue: return_value,
            stackAdjustment: value.stack_adjustment,
            registerStackAdjustmentCount: regs.len(),
            registerStackAdjustmentRegisters: Box::leak(regs).as_mut_ptr(),
            registerStackAdjustmentAmounts: Box::leak(amounts).as_mut_ptr(),
        }
    }

    /// Free a RUST ALLOCATED value. Do not use this with CORE ALLOCATED values.
    pub(crate) fn free_rust_raw(value: &mut BNCallLayout) {
        unsafe {
            let params = Box::from_raw(ptr::slice_from_raw_parts_mut(
                value.parameters,
                value.parameterCount,
            ));
            for loc in params.into_vec() {
                ValueLocation::free_rust_raw(loc);
            }
            ValueLocation::free_rust_raw(ptr::read(&value.returnValue));
            let _ = Box::from_raw(ptr::slice_from_raw_parts_mut(
                value.registerStackAdjustmentRegisters,
                value.registerStackAdjustmentCount,
            ));
            let _ = Box::from_raw(ptr::slice_from_raw_parts_mut(
                value.registerStackAdjustmentAmounts,
                value.registerStackAdjustmentCount,
            ));
        }
    }
}
