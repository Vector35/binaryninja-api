# Copyright (c) 2015-2026 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import traceback
import ctypes
from typing import Optional, Union, List, Dict, Tuple
from dataclasses import dataclass

# Binary Ninja components
from . import _binaryninjacore as core
from .log import log_error_for_exception
from . import variable
from . import function
from . import architecture
from . import types
from . import binaryview

FunctionOrILFunction = Union["binaryninja.function.Function", "binaryninja.lowlevelil.LowLevelILFunction",
                             "binaryninja.mediumlevelil.MediumLevelILFunction",
                             "binaryninja.highlevelil.HighLevelILFunction"]


@dataclass
class CallLayout:
	parameters: List['types.ValueLocation']
	return_value: Optional['types.ValueLocation']
	stack_adjustment: int
	reg_stack_adjustments: Dict['architecture.RegisterIndex', int]

	@staticmethod
	def _from_core_struct(struct: core.BNCallLayout, func: Optional['function.Function'] = None) -> 'CallLayout':
		params = []
		if func is None:
			arch = None
		else:
			arch = func.arch
		for i in range(struct.parameterCount):
			params.append(types.ValueLocation._from_core_struct(struct.parameters[i], arch))
		if struct.returnValueValid:
			return_value = types.ValueLocation._from_core_struct(struct.returnValue, arch)
		else:
			return_value = None
		stack_adjust = struct.stackAdjustment
		reg_stack_adjust = dict()
		for i in range(struct.registerStackAdjustmentCount):
			reg = architecture.RegisterIndex(struct.registerStackAdjustmentRegisters[i])
			reg_stack_adjust[reg] = struct.registerStackAdjustmentAmounts[i]
		return CallLayout(params, return_value, stack_adjust, reg_stack_adjust)

	def _to_core_struct(self):
		struct = core.BNCallLayout()
		struct.parameters = (core.BNValueLocation * len(self.parameters))()
		struct.parameterCount = len(self.parameters)
		for i in range(len(self.parameters)):
			struct.parameters[i] = self.parameters[i]._to_core_struct()
		if self.return_value is None:
			struct.returnValueValid = False
		else:
			struct.returnValue = self.return_value._to_core_struct()
			struct.returnValueValid = True
		struct.stackAdjustment = self.stack_adjustment
		struct.registerStackAdjustmentRegisters = (ctypes.c_uint * len(self.reg_stack_adjustments))()
		struct.registerStackAdjustmentAmounts = (ctypes.c_int * len(self.reg_stack_adjustments))()
		struct.registerStackAdjustmentCount = len(self.reg_stack_adjustments)
		for i, (reg, amount) in enumerate(self.reg_stack_adjustments.items()):
			struct.registerStackAdjustmentRegisters[i] = reg
			struct.registerStackAdjustmentAmounts[i] = amount
		return struct


class CallingConvention:
	"""
	``class CallingConvention`` describes how parameters, return values, and the stack are handled
	when a function is called. Subclasses of ``CallingConvention`` define the behavior of a calling
	convention by setting the class attributes below and, where necessary, overriding the methods.

	:cvar name: The name of this calling convention.
	:cvar caller_saved_regs: The list of registers that are not preserved across a call
		(caller-saved / volatile registers).
	:cvar callee_saved_regs: The list of registers that a callee must preserve across a call
		(callee-saved / non-volatile registers).
	:cvar int_arg_regs: The registers used to pass integer and pointer arguments, in the order
		they are used.
	:cvar float_arg_regs: The registers used to pass floating point arguments, in the order they
		are used.
	:cvar required_arg_regs: The set of registers that must be arguments for heuristic calling
		convention detection to consider this calling convention as a valid option.
	:cvar required_clobbered_regs: The set of registers that must be clobbered for heuristic
		calling convention detection to consider this calling convention as a valid option.
	:cvar arg_regs_share_index: Whether the integer and floating point argument registers share a
		single argument index. When ``True``, the Nth argument consumes the Nth slot of both the
		integer and float register lists regardless of its type. When ``False``, integer and float
		arguments are assigned from their respective register lists independently.
	:cvar arg_regs_for_varargs: Whether argument registers are used to pass variadic arguments.
	:cvar stack_reserved_for_arg_regs: Whether stack space is reserved by the caller for the
		register arguments (for example, the shadow/home space used by the Windows x64 calling
		convention).
	:cvar stack_adjusted_on_return: Whether the callee adjusts the stack to remove the arguments
		before returning (as in stdcall), rather than leaving the caller to clean up the stack (as
		in cdecl).
	:cvar eligible_for_heuristics: Whether this calling convention may be selected by heuristic
		calling convention detection.
	:cvar int_return_reg: The register that holds the integer return value.
	:cvar high_int_return_reg: The register that holds the high part of an integer return value
		that is too large to fit in a single register, or ``None`` if there is none.
	:cvar float_return_reg: The register that holds the floating point return value, or ``None``
		if there is none.
	:cvar global_pointer_reg: Deprecated. Use ``global_pointer_regs`` instead. The register
		that holds the global pointer, if the calling convention defines one, or ``None`` if
		there is none.
	:cvar global_pointer_regs: The registers that hold global pointers, if the calling
		convention defines any.
	:cvar implicitly_defined_regs: The registers that are implicitly given a known value on
		function entry by this calling convention.
	:cvar stack_args_naturally_aligned: Whether arguments passed on the stack are aligned to their
		natural alignment. If ``False``, arguments are aligned to the address size.
	:cvar stack_args_pushed_left_to_right: Whether arguments passed on the stack are pushed
		left-to-right, as opposed to the more common right-to-left order.
	"""
	name = None
	caller_saved_regs = []
	callee_saved_regs = []
	int_arg_regs = []
	float_arg_regs = []
	required_arg_regs = []
	required_clobbered_regs = []
	arg_regs_share_index = False
	arg_regs_for_varargs = True
	stack_reserved_for_arg_regs = False
	stack_adjusted_on_return = False
	eligible_for_heuristics = True
	int_return_reg = None
	high_int_return_reg = None
	float_return_reg = None
	global_pointer_reg = None
	global_pointer_regs = []
	implicitly_defined_regs = []
	stack_args_naturally_aligned = False
	stack_args_pushed_left_to_right = False

	_registered_calling_conventions = []
	_pending_value_locations = {}
	_pending_value_location_lists = {}
	_pending_variable_lists = {}
	_pending_reg_stack_adjustment_reg_lists = {}
	_pending_reg_stack_adjustment_amount_lists = {}

	def __init__(
	    self, arch: Optional['architecture.Architecture'] = None, name: Optional[str] = None, handle=None,
	    confidence: int = core.max_confidence
	):
		if handle is None:
			if arch is None or name is None:
				raise ValueError("Must specify either handle or architecture and name")
			self._arch = arch
			self._pending_reg_lists = {}
			self._cb = core.BNCustomCallingConvention()
			self._cb.context = 0
			self._cb.getCallerSavedRegisters = self._cb.getCallerSavedRegisters.__class__(self._get_caller_saved_regs)
			self._cb.getCalleeSavedRegisters = self._cb.getCalleeSavedRegisters.__class__(self._get_callee_saved_regs)
			self._cb.getIntegerArgumentRegisters = self._cb.getIntegerArgumentRegisters.__class__(
			    self._get_int_arg_regs
			)
			self._cb.getFloatArgumentRegisters = self._cb.getFloatArgumentRegisters.__class__(self._get_float_arg_regs)
			self._cb.getRequiredArgumentRegisters = self._cb.getRequiredArgumentRegisters.__class__(
				self._get_required_arg_regs
			)
			self._cb.getRequiredClobberedRegisters = self._cb.getRequiredClobberedRegisters.__class__(
				self._get_required_clobbered_regs
			)
			self._cb.freeRegisterList = self._cb.freeRegisterList.__class__(self._free_register_list)
			self._cb.areArgumentRegistersSharedIndex = self._cb.areArgumentRegistersSharedIndex.__class__(
			    self._arg_regs_share_index
			)
			self._cb.areArgumentRegistersUsedForVarArgs = self._cb.areArgumentRegistersUsedForVarArgs.__class__(
			    self._arg_regs_used_for_varargs
			)
			self._cb.isStackReservedForArgumentRegisters = self._cb.isStackReservedForArgumentRegisters.__class__(
			    self._stack_reserved_for_arg_regs
			)
			self._cb.isStackAdjustedOnReturn = self._cb.isStackAdjustedOnReturn.__class__(
			    self._stack_adjusted_on_return
			)
			self._cb.isEligibleForHeuristics = self._cb.isEligibleForHeuristics.__class__(self._eligible_for_heuristics)
			self._cb.getIntegerReturnValueRegister = self._cb.getIntegerReturnValueRegister.__class__(
			    self._get_int_return_reg
			)
			self._cb.getHighIntegerReturnValueRegister = self._cb.getHighIntegerReturnValueRegister.__class__(
			    self._get_high_int_return_reg
			)
			self._cb.getFloatReturnValueRegister = self._cb.getFloatReturnValueRegister.__class__(
			    self._get_float_return_reg
			)
			self._cb.getGlobalPointerRegisters = self._cb.getGlobalPointerRegisters.__class__(
			    self._get_global_pointer_regs
			)
			self._cb.getImplicitlyDefinedRegisters = self._cb.getImplicitlyDefinedRegisters.__class__(
			    self._get_implicitly_defined_regs
			)
			self._cb.getIncomingRegisterValue = self._cb.getIncomingRegisterValue.__class__(
			    self._get_incoming_reg_value
			)
			self._cb.getIncomingFlagValue = self._cb.getIncomingFlagValue.__class__(self._get_incoming_flag_value)
			self._cb.getIncomingVariableForParameterVariable = self._cb.getIncomingVariableForParameterVariable.__class__(
			    self._get_incoming_var_for_parameter_var
			)
			self._cb.getParameterVariableForIncomingVariable = self._cb.getParameterVariableForIncomingVariable.__class__(
			    self._get_parameter_var_for_incoming_var
			)
			self._cb.isReturnTypeRegisterCompatible = self._cb.isReturnTypeRegisterCompatible.__class__(
				self._is_return_type_reg_compatible
			)
			self._cb.getIndirectReturnValueLocation = self._cb.getIndirectReturnValueLocation.__class__(
				self._get_indirect_return_value_location
			)
			self._cb.getReturnedIndirectReturnValuePointer = self._cb.getReturnedIndirectReturnValuePointer.__class__(
				self._get_returned_indirect_return_value_pointer
			)
			self._cb.isArgumentTypeRegisterCompatible = self._cb.isArgumentTypeRegisterCompatible.__class__(
				self._is_arg_type_reg_compatible
			)
			self._cb.isNonRegisterArgumentIndirect = self._cb.isNonRegisterArgumentIndirect.__class__(
				self._is_non_reg_arg_indirect
			)
			self._cb.areStackArgumentsNaturallyAligned = self._cb.areStackArgumentsNaturallyAligned.__class__(
				self._are_stack_args_naturally_aligned
			)
			self._cb.areStackArgumentsPushedLeftToRight = self._cb.areStackArgumentsPushedLeftToRight.__class__(
				self._are_stack_args_pushed_left_to_right
			)
			self._cb.getCallLayout = self._cb.getCallLayout.__class__(self._get_call_layout)
			self._cb.freeCallLayout = self._cb.freeCallLayout.__class__(self._free_call_layout)
			self._cb.getReturnValueLocation = self._cb.getReturnValueLocation.__class__(self._get_return_value_location)
			self._cb.freeValueLocation = self._cb.freeValueLocation.__class__(self._free_value_location)
			self._cb.getParameterLocations = self._cb.getParameterLocations.__class__(self._get_parameter_locations)
			self._cb.freeParameterLocations = self._cb.freeParameterLocations.__class__(self._free_parameter_locations)
			self._cb.getParameterOrderingForVariables = self._cb.getParameterOrderingForVariables.__class__(
				self._get_parameter_ordering_for_variables
			)
			self._cb.freeVariableList = self._cb.freeVariableList.__class__(self._free_variable_list)
			self._cb.getStackAdjustmentForLocations = self._cb.getStackAdjustmentForLocations.__class__(
				self._get_stack_adjustment_for_locations
			)
			self._cb.getRegisterStackAdjustments = self._cb.getRegisterStackAdjustments.__class__(
				self._get_register_stack_adjustments
			)
			self._cb.freeRegisterStackAdjustments = self._cb.freeRegisterStackAdjustments.__class__(
				self._free_register_stack_adjustments
			)
			_handle = core.BNCreateCallingConvention(arch.handle, name, self._cb)
			self.__class__._registered_calling_conventions.append(self)
		else:
			_handle = handle
		assert _handle is not None
		self.handle = _handle
		self.confidence = confidence

	def __del__(self):
		if core is not None:
			core.BNFreeCallingConvention(self.handle)

	def __repr__(self):
		return f"<calling convention: {self.arch.name} {self.name}>"

	def __str__(self):
		return self.name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	def _get_caller_saved_regs(self, ctxt, count):
		try:
			regs = self.__class__.caller_saved_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_caller_saved_regs")
			count[0] = 0
			return None

	def _get_callee_saved_regs(self, ctxt, count):
		try:
			regs = self.__class__.callee_saved_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_callee_saved_regs")
			count[0] = 0
			return None

	def _get_int_arg_regs(self, ctxt, count):
		try:
			regs = self.__class__.int_arg_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_int_arg_regs")
			count[0] = 0
			return None

	def _get_float_arg_regs(self, ctxt, count):
		try:
			regs = self.__class__.float_arg_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_float_arg_regs")
			count[0] = 0
			return None

	def _get_required_arg_regs(self, ctxt, count):
		try:
			regs = self.__class__.required_arg_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_required_arg_regs")
			count[0] = 0
			return None

	def _get_required_clobbered_regs(self, ctxt, count):
		try:
			regs = self.__class__.required_clobbered_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_required_clobbered_regs")
			count[0] = 0
			return None

	def _free_register_list(self, ctxt, regs, count):
		try:
			buf = ctypes.cast(regs, ctypes.c_void_p)
			if buf.value not in self._pending_reg_lists:
				raise ValueError("freeing register list that wasn't allocated")
			del self._pending_reg_lists[buf.value]
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._free_register_list")

	def _arg_regs_share_index(self, ctxt):
		try:
			return self.__class__.arg_regs_share_index
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._arg_regs_share_index")
			return False

	def _arg_regs_used_for_varargs(self, ctxt):
		try:
			return self.__class__.arg_regs_for_varargs
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._arg_regs_used_for_varargs")
			return False

	def _stack_reserved_for_arg_regs(self, ctxt):
		try:
			return self.__class__.stack_reserved_for_arg_regs
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._stack_reserved_for_arg_regs")
			return False

	def _stack_adjusted_on_return(self, ctxt):
		try:
			return self.__class__.stack_adjusted_on_return
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._stack_adjusted_on_return")
			return False

	def _eligible_for_heuristics(self, ctxt):
		try:
			return self.__class__.eligible_for_heuristics
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._eligible_for_heuristics")
			return False

	def _get_int_return_reg(self, ctxt):
		if self.__class__.int_return_reg is None:
			return False
		assert isinstance(self.__class__.int_return_reg, str), "int_return_reg return reg must be a string"

		try:
			return self.arch.regs[self.__class__.int_return_reg].index
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_int_return_reg")
			return False

	def _get_high_int_return_reg(self, ctxt):
		try:
			if self.__class__.high_int_return_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.high_int_return_reg].index
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_high_int_return_reg")
			return False

	def _get_float_return_reg(self, ctxt):
		try:
			if self.__class__.float_return_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.float_return_reg].index
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_float_return_reg")
			return False

	def _get_global_pointer_reg(self, ctxt):
		try:
			if self.__class__.global_pointer_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.global_pointer_reg].index
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_global_pointer_reg")
			return False

	def _get_global_pointer_regs(self, ctxt, count):
		try:
			regs = self.__class__.global_pointer_regs
			if not regs and self.__class__.global_pointer_reg is not None:
				regs = [self.__class__.global_pointer_reg]
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_global_pointer_regs")
			count[0] = 0
			return None

	def _get_implicitly_defined_regs(self, ctxt, count):
		try:
			regs = self.__class__.implicitly_defined_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_implicitly_defined_regs")
			count[0] = 0
			return None

	def _get_incoming_reg_value(self, ctxt, reg, func, result):
		try:
			func_obj = function.Function(handle=core.BNNewFunctionReference(func))
			reg_name = self.arch.get_reg_name(reg)
			api_obj = self.perform_get_incoming_reg_value(reg_name, func_obj)._to_core_struct()
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_incoming_reg_value")
			api_obj = variable.Undetermined()._to_core_struct()
		result[0].state = api_obj.state
		result[0].value = api_obj.value

	def _get_incoming_flag_value(self, ctxt, flag, func, result):
		try:
			func_obj = function.Function(handle=core.BNNewFunctionReference(func))
			flag_name = self.arch.get_flag_name(flag)
			api_obj = self.perform_get_incoming_flag_value(flag_name, func_obj)._to_core_struct()
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_incoming_flag_value")
			api_obj = variable.Undetermined()._to_core_struct()
		result[0].state = api_obj.state
		result[0].value = api_obj.value

	def _get_incoming_var_for_parameter_var(self, ctxt, in_var, func, result):
		try:
			if func is None:
				func_obj = None
			else:
				func_obj = function.Function(handle=core.BNNewFunctionReference(func))
			in_var_obj = variable.CoreVariable.from_BNVariable(in_var[0])
			out_var = self.perform_get_incoming_var_for_parameter_var(in_var_obj, func_obj)
			result[0].type = out_var.source_type
			result[0].index = out_var.index
			result[0].storage = out_var.storage
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_incoming_var_for_parameter_var")
			result[0].type = in_var[0].type
			result[0].index = in_var[0].index
			result[0].storage = in_var[0].storage

	def _get_parameter_var_for_incoming_var(self, ctxt, in_var, func, result):
		try:
			if func is None:
				func_obj = None
			else:
				func_obj = function.Function(handle=core.BNNewFunctionReference(func))
			in_var_obj = variable.CoreVariable.from_BNVariable(in_var[0])
			out_var = self.perform_get_parameter_var_for_incoming_var(in_var_obj, func_obj)
			result[0].type = out_var.source_type
			result[0].index = out_var.index
			result[0].storage = out_var.storage
		except Exception:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_parameter_var_for_incoming_var")
			result[0].type = in_var[0].type
			result[0].index = in_var[0].index
			result[0].storage = in_var[0].storage

	def _is_return_type_reg_compatible(self, ctxt, view, type):
		try:
			if type:
				if view:
					view_obj = binaryview.BinaryView(handle=core.BNNewViewReference(view))
				else:
					view_obj = None
				type_obj = types.Type.create(handle=core.BNNewTypeReference(type))
				return self.is_return_type_reg_compatible(view_obj, type_obj)
			else:
				return False
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._is_return_type_reg_compatible")
			return False

	def _get_indirect_return_value_location(self, ctxt, out_var):
		try:
			out_var[0] = self.get_indirect_return_value_location().to_BNVariable()
		except:
			log_error_for_exception(
				"Unhandled Python exception in CallingConvention._get_indirect_return_value_location")

	def _get_returned_indirect_return_value_pointer(self, ctxt, out_var):
		try:
			result = self.get_returned_indirect_return_value_pointer()
			if result is None:
				return False
			out_var[0] = result.to_BNVariable()
			return True
		except:
			log_error_for_exception(
				"Unhandled Python exception in CallingConvention._get_returned_indirect_return_value_pointer")
			return False

	def _is_arg_type_reg_compatible(self, ctxt, view, type):
		try:
			if type:
				if view:
					view_obj = binaryview.BinaryView(handle=core.BNNewViewReference(view))
				else:
					view_obj = None
				type_obj = types.Type.create(handle=core.BNNewTypeReference(type))
				return self.is_arg_type_reg_compatible(view_obj, type_obj)
			else:
				return False
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._is_arg_type_reg_compatible")
			return False

	def _is_non_reg_arg_indirect(self, ctxt, view, type):
		try:
			if view:
				view_obj = binaryview.BinaryView(handle=core.BNNewViewReference(view))
			else:
				view_obj = None
			if type:
				type_obj = types.Type.create(handle=core.BNNewTypeReference(type))
				return self.is_non_reg_arg_indirect(view_obj, type_obj)
			else:
				return self.is_non_reg_arg_indirect(view_obj, None)
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._is_non_reg_arg_indirect")
			return False

	def _are_stack_args_naturally_aligned(self, ctxt):
		try:
			return self.__class__.stack_args_naturally_aligned
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._are_stack_args_naturally_aligned")
			return False

	def _are_stack_args_pushed_left_to_right(self, ctxt):
		try:
			return self.__class__.stack_args_pushed_left_to_right
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._are_stack_args_pushed_left_to_right")
			return False

	def _get_call_layout(
		self, ctxt, view, ret_value, params, param_count, has_permitted_regs, permitted_regs,
		permitted_reg_count, out_layout
	):
		try:
			if view:
				view_obj = binaryview.BinaryView(handle=core.BNNewViewReference(view))
			else:
				view_obj = None
			if ret_value:
				ret_value_obj = types.ReturnValue._from_core_struct(ret_value[0])
			else:
				ret_value_obj = None
			param_objs = []
			for i in range(param_count):
				param_objs.append(types.FunctionParameter._from_core_struct(params[i]))
			if has_permitted_regs:
				reg_objs = []
				for i in range(permitted_reg_count):
					reg_objs.append(architecture.RegisterIndex(permitted_regs[i]))
			else:
				reg_objs = None
			layout = self.get_call_layout(view_obj, ret_value_obj, param_objs, permitted_regs = reg_objs)

			result = layout._to_core_struct()

			param_ptr = ctypes.cast(result.parameters, ctypes.c_void_p)
			self._pending_value_location_lists[param_ptr.value] = (param_ptr.value, result.parameters)

			if result.returnValueValid:
				ret_ptr = ctypes.cast(result.returnValue.components, ctypes.c_void_p)
				self._pending_value_locations[ret_ptr.value] = (ret_ptr.value, result.returnValue)

			reg_ptr = ctypes.cast(result.registerStackAdjustmentRegisters, ctypes.c_void_p)
			self._pending_reg_stack_adjustment_reg_lists[reg_ptr.value] = (reg_ptr.value, result.registerStackAdjustmentRegisters)
			amount_ptr = ctypes.cast(result.registerStackAdjustmentAmounts, ctypes.c_void_p)
			self._pending_reg_stack_adjustment_amount_lists[amount_ptr.value] = (amount_ptr.value, result.registerStackAdjustmentAmounts)

			out_layout[0] = result
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_call_layout")
			result = core.BNCallLayout()
			result.parameterCount = 0
			result.returnValueValid = False
			result.stackAdjustment = 0
			result.registerStackAdjustmentCount = 0
			out_layout[0] = result

	def _free_call_layout(self, ctxt, layout_ptr):
		try:
			layout = layout_ptr[0]
			param_ptr = ctypes.cast(layout.parameters, ctypes.c_void_p)
			if param_ptr.value is not None:
				if param_ptr.value not in self._pending_value_location_lists:
					raise ValueError("freeing parameter location list that wasn't allocated")
				del self._pending_value_location_lists[param_ptr.value]

			if layout.returnValueValid:
				ret_ptr = ctypes.cast(layout.returnValue.components, ctypes.c_void_p)
				if ret_ptr.value is not None:
					if ret_ptr.value not in self._pending_value_locations:
						raise ValueError("freeing return value location that wasn't allocated")
					del self._pending_value_locations[ret_ptr.value]

			reg_ptr = ctypes.cast(layout.registerStackAdjustmentRegisters, ctypes.c_void_p)
			if reg_ptr.value is not None:
				if reg_ptr.value not in self._pending_reg_stack_adjustment_reg_lists:
					raise ValueError("freeing register list that wasn't allocated")
				del self._pending_reg_stack_adjustment_reg_lists[reg_ptr.value]

			amount_ptr = ctypes.cast(layout.registerStackAdjustmentAmounts, ctypes.c_void_p)
			if amount_ptr.value is not None:
				if amount_ptr.value not in self._pending_reg_stack_adjustment_amount_lists:
					raise ValueError("freeing adjustment list that wasn't allocated")
				del self._pending_reg_stack_adjustment_amount_lists[amount_ptr.value]
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._free_call_layout")

	def _get_return_value_location(self, ctxt, view, ret_value, out_location):
		try:
			if view:
				view_obj = binaryview.BinaryView(handle=core.BNNewViewReference(view))
			else:
				view_obj = None
			ret = types.ReturnValue._from_core_struct(ret_value[0])
			location = self.get_return_value_location(view_obj, ret)
			if location is None:
				location = types.ValueLocation([])
			result = location._to_core_struct()
			result_ptr = ctypes.cast(result.components, ctypes.c_void_p)
			self._pending_value_locations[result_ptr.value] = (result_ptr.value, result)
			out_location[0] = result
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_return_value_location")
			result = core.BNValueLocation()
			result.count = 0
			result.components = None
			out_location[0] = result

	def _free_value_location(self, ctxt, location_ptr):
		try:
			location = location_ptr[0]
			loc_ptr = ctypes.cast(location.components, ctypes.c_void_p)
			if loc_ptr.value is not None:
				if loc_ptr.value not in self._pending_value_locations:
					raise ValueError("freeing value location that wasn't allocated")
				del self._pending_value_locations[loc_ptr.value]
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._free_value_location")

	def _get_parameter_locations(
		self, ctxt, view, ret_value, params, param_count, has_permitted_regs, permitted_regs, permitted_reg_count,
		out_location_count
	):
		try:
			if view:
				view_obj = binaryview.BinaryView(handle=core.BNNewViewReference(view))
			else:
				view_obj = None
			if ret_value:
				ret_value_obj = types.ValueLocation._from_core_struct(ret_value[0])
			else:
				ret_value_obj = None
			param_objs = []
			for i in range(param_count):
				param_objs.append(types.FunctionParameter._from_core_struct(params[i]))
			if has_permitted_regs:
				reg_objs = []
				for i in range(permitted_reg_count):
					reg_objs.append(architecture.RegisterIndex(permitted_regs[i]))
			else:
				reg_objs = None
			locations = self.get_parameter_locations(view_obj, ret_value_obj, param_objs, permitted_regs = reg_objs)

			out_location_count[0] = len(locations)
			result = (core.BNValueLocation * len(locations))()
			for i, location in enumerate(locations):
				result[i] = location._to_core_struct()

			result_ptr = ctypes.cast(result, ctypes.c_void_p)
			self._pending_value_location_lists[result_ptr.value] = (result_ptr.value, result)

			return result_ptr.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_parameter_locations")
			out_location_count[0] = 0
			return None

	def _free_parameter_locations(self, ctxt, locations, count):
		try:
			location_ptr = ctypes.cast(locations, ctypes.c_void_p)
			if location_ptr.value is not None:
				if location_ptr.value not in self._pending_value_location_lists:
					raise ValueError("freeing parameter location list that wasn't allocated")
				del self._pending_value_location_lists[location_ptr.value]
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._free_parameter_locations")

	def _get_parameter_ordering_for_variables(self, ctxt, view, vars, type_list, param_count, out_count):
		try:
			if view:
				view_obj = binaryview.BinaryView(handle=core.BNNewViewReference(view))
			else:
				view_obj = None
			params = {}
			for i in range(param_count):
				var = variable.CoreVariable.from_BNVariable(vars[i])
				ty = types.Type.from_core_struct(type_list[i])
				params[var] = ty

			var_list = self.get_parameter_ordering_for_variables(view_obj, params)

			out_count[0] = len(var_list)
			result = (core.BNVariable * len(var_list))()
			for i, var in enumerate(var_list):
				result[i] = var.to_BNVariable()

			result_ptr = ctypes.cast(result, ctypes.c_void_p)
			self._pending_variable_lists[result_ptr.value] = (result_ptr.value, result)

			return result_ptr.value
		except:
			log_error_for_exception(
				"Unhandled Python exception in CallingConvention._get_parameter_ordering_for_variables")
			out_count[0] = 0
			return None

	def _free_variable_list(self, ctxt, vars, count):
		try:
			var_list_ptr = ctypes.cast(vars, ctypes.c_void_p)
			if var_list_ptr.value is not None:
				if var_list_ptr.value not in self._pending_variable_lists:
					raise ValueError("freeing variable list that wasn't allocated")
				del self._pending_variable_lists[var_list_ptr.value]
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._free_variable_list")

	def _get_stack_adjustment_for_locations(self, ctxt, view, ret_value, locations, type_list, param_count):
		try:
			if view:
				view_obj = binaryview.BinaryView(handle=core.BNNewViewReference(view))
			else:
				view_obj = None
			if ret_value:
				ret_value_obj = types.ValueLocation._from_core_struct(ret_value[0])
			else:
				ret_value_obj = None
			params = []
			for i in range(param_count):
				loc = types.ValueLocation._from_core_struct(locations[i])
				ty = types.Type.from_core_struct(type_list[i])
				params.append((loc, ty))
			return self.get_stack_adjustment_for_locations(view_obj, ret_value_obj, params)
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_stack_adjustment_for_locations")
			return 0

	def _get_register_stack_adjustments(self, ctxt, view, ret_value, params, param_count, out_regs, out_adjust):
		try:
			if view:
				view_obj = binaryview.BinaryView(handle=core.BNNewViewReference(view))
			else:
				view_obj = None
			if ret_value:
				ret_value_obj = types.ValueLocation._from_core_struct(ret_value[0])
			else:
				ret_value_obj = None
			param_objs = []
			for i in range(param_count):
				param_objs.append(types.ValueLocation._from_core_struct(params[i]))
			adjustment = self.get_register_stack_adjustments(view_obj, ret_value_obj, param_objs)

			regs = (ctypes.c_uint * len(adjustment))()
			adjust = (ctypes.c_int * len(adjustment))()
			for i, (reg, adj) in enumerate(adjustment.items()):
				regs[i] = int(reg)
				adjust[i] = adj

			reg_ptr = ctypes.cast(regs, ctypes.c_void_p)
			self._pending_reg_stack_adjustment_reg_lists[reg_ptr.value] = (reg_ptr.value, regs)
			adjust_ptr = ctypes.cast(adjust, ctypes.c_void_p)
			self._pending_reg_stack_adjustment_amount_lists[adjust_ptr.value] = (adjust_ptr.value, adjust)

			out_regs[0] = regs
			out_adjust[0] = adjust
			return len(adjustment)
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_register_stack_adjustments")
			out_regs[0] = None
			out_adjust[0] = None
			return 0

	def _free_register_stack_adjustments(self, ctxt, regs, adjust, count):
		try:
			reg_ptr = ctypes.cast(regs, ctypes.c_void_p)
			if reg_ptr.value is not None:
				if reg_ptr.value not in self._pending_reg_stack_adjustment_reg_lists:
					raise ValueError("freeing register list that wasn't allocated")
				del self._pending_reg_stack_adjustment_reg_lists[reg_ptr.value]
			adjust_ptr = ctypes.cast(adjust, ctypes.c_void_p)
			if adjust_ptr.value is not None:
				if adjust_ptr.value not in self._pending_reg_stack_adjustment_amount_lists:
					raise ValueError("freeing adjustment list that wasn't allocated")
				del self._pending_reg_stack_adjustment_amount_lists[adjust_ptr.value]
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._free_register_stack_adjustments")

	def perform_get_incoming_reg_value(
	    self, reg: 'architecture.RegisterName', func: 'function.Function'
	) -> 'variable.RegisterValue':
		"""Deprecated, override `get_incoming_reg_value` instead."""
		reg_stack = self.arch.get_reg_stack_for_reg(reg)
		if reg_stack is not None:
			if reg == self.arch.reg_stacks[reg_stack].stack_top_reg:
				return variable.ConstantRegisterValue(0)
		return variable.Undetermined()

	def perform_get_incoming_flag_value(
	    self, flag: 'architecture.FlagName', func: 'function.Function'
	) -> 'variable.RegisterValue':
		"""Deprecated, override `get_incoming_flag_value` instead."""
		return variable.Undetermined()

	def perform_get_incoming_var_for_parameter_var(
	    self, in_var: 'variable.CoreVariable', func: Optional['function.Function'] = None
	) -> 'variable.CoreVariable':
		"""Deprecated, override `get_incoming_var_for_parameter_var` instead."""
		out_var = core.BNGetDefaultIncomingVariableForParameterVariable(self.handle, in_var.to_BNVariable())
		return variable.CoreVariable.from_BNVariable(out_var)

	def perform_get_parameter_var_for_incoming_var(
	    self, in_var: 'variable.CoreVariable', func: Optional['function.Function'] = None
	) -> 'variable.CoreVariable':
		"""Deprecated, override `get_parameter_var_for_incoming_var` instead."""
		out_var = core.BNGetDefaultParameterVariableForIncomingVariable(self.handle, in_var.to_BNVariable())
		return variable.CoreVariable.from_BNVariable(out_var)

	def get_incoming_reg_value(
		self, reg: 'architecture.RegisterName', func: 'function.Function'
	) -> 'variable.RegisterValue':
		"""
		``get_incoming_reg_value`` gets the known value of a register on entry to a function.

		:param RegisterName reg: register to query
		:param Function func: function being analyzed
		:return: the incoming value of the register
		:rtype: RegisterValue
		"""
		return self.perform_get_incoming_reg_value(reg, func)

	def get_incoming_flag_value(
		self, reg: 'architecture.RegisterName', func: 'function.Function'
	) -> 'variable.RegisterValue':
		"""
		``get_incoming_flag_value`` gets the known value of a flag on entry to a function.

		:param reg: flag to query
		:param Function func: function being analyzed
		:return: the incoming value of the flag
		:rtype: RegisterValue
		"""
		return self.perform_get_incoming_flag_value(reg, func)

	def get_incoming_var_for_parameter_var(
		self, in_var: 'variable.CoreVariable', func: Optional['function.Function'] = None
	) -> 'variable.CoreVariable':
		"""
		``get_incoming_var_for_parameter_var`` gets the incoming variable that corresponds to the
		given parameter variable. This is the inverse of :py:meth:`get_parameter_var_for_incoming_var`.

		:param CoreVariable in_var: parameter variable
		:param Function func: function being analyzed
		:return: the incoming variable corresponding to the parameter variable
		:rtype: CoreVariable
		"""
		return self.perform_get_incoming_var_for_parameter_var(in_var, func)

	def get_parameter_var_for_incoming_var(
		self, in_var: 'variable.CoreVariable', func: Optional['function.Function'] = None
	) -> 'variable.CoreVariable':
		"""
		``get_parameter_var_for_incoming_var`` gets the parameter variable that corresponds to the
		given incoming variable. This is the inverse of :py:meth:`get_incoming_var_for_parameter_var`.

		:param CoreVariable in_var: incoming variable
		:param Function func: function being analyzed
		:return: the parameter variable corresponding to the incoming variable
		:rtype: CoreVariable
		"""
		return self.perform_get_incoming_var_for_parameter_var(in_var, func)

	def is_return_type_reg_compatible(self, view: Optional['binaryview.BinaryView'], type: 'types.Type') -> bool:
		"""
		``is_return_type_reg_compatible`` determines whether a value of the given type can be
		returned in registers, as opposed to being returned indirectly through memory.

		:param BinaryView view: binary view providing type information
		:param Type type: return type to check
		:return: whether the return type is register compatible
		:rtype: bool
		"""
		return self.default_is_return_type_reg_compatible(type)

	def is_non_reg_arg_indirect(self, view: Optional['binaryview.BinaryView'], type: Optional['types.Type']) -> bool:
		"""
		``is_non_reg_arg_indirect`` determines whether an argument that cannot be passed in
		registers is passed indirectly by pointer as opposed to being passed directly on the stack.

		:param BinaryView view: binary view providing type information
		:param Type type: argument type to check
		:return: whether the non-register argument is passed indirectly by pointer
		:rtype: bool
		"""
		return False

	def default_is_return_type_reg_compatible(self, type: 'types.Type') -> bool:
		"""
		``default_is_return_type_reg_compatible`` is the default implementation of
		:py:meth:`is_return_type_reg_compatible`. The default implementation allows register
		returns for types that fit in a single register, have a size equal to two registers when
		``high_int_return_reg`` is set, or are a floating point type when ``float_return_reg`` is set.

		:param Type type: return type to check
		:return: whether the return type is register compatible
		:rtype: bool
		"""
		return core.BNDefaultIsReturnTypeRegisterCompatible(self.handle, type.handle)

	def get_indirect_return_value_location(self) -> 'variable.CoreVariable':
		"""
		``get_indirect_return_value_location`` gets the location used to pass the hidden pointer
		argument for return values that are returned indirectly through memory.

		:return: the location of the indirect return value pointer
		:rtype: CoreVariable
		"""
		return self.get_default_indirect_return_value_location()

	def get_default_indirect_return_value_location(self) -> 'variable.CoreVariable':
		"""
		``get_default_indirect_return_value_location`` is the default implementation of
		:py:meth:`get_indirect_return_value_location`. The default location is the first integer
		argument register, or the first stack slot if there are no integer argument registers.

		:return: the location of the indirect return value pointer
		:rtype: CoreVariable
		"""
		result = core.BNGetDefaultIndirectReturnValueLocation(self.handle)
		return variable.CoreVariable.from_BNVariable(result)

	def get_returned_indirect_return_value_pointer(self) -> Optional['variable.CoreVariable']:
		"""
		``get_returned_indirect_return_value_pointer`` gets the location in which the hidden
		indirect return value pointer is returned to the caller, for calling conventions that
		return it.

		:return: the location the indirect return value pointer is returned in, or ``None`` if it is not returned
		:rtype: Optional[CoreVariable]
		"""
		return None

	def is_arg_type_reg_compatible(self, view: Optional['binaryview.BinaryView'], type: 'types.Type') -> bool:
		"""
		``is_arg_type_reg_compatible`` determines whether a value of the given type can be passed
		as an argument in registers.

		:param BinaryView view: binary view providing type information
		:param Type type: argument type to check
		:return: whether the argument type is register compatible
		:rtype: bool
		"""
		return self.default_is_arg_type_reg_compatible(type)

	def default_is_arg_type_reg_compatible(self, type: 'types.Type') -> bool:
		"""
		``default_is_arg_type_reg_compatible`` is the default implementation of
		:py:meth:`is_arg_type_reg_compatible`. The default implementation allows register arguments
		for types that fit in a single register, or are a floating point type when ``float_arg_regs``
		has valid registers.

		:param Type type: argument type to check
		:return: whether the argument type is register compatible
		:rtype: bool
		"""
		return core.BNDefaultIsArgumentTypeRegisterCompatible(self.handle, type.handle)

	def get_call_layout(
		self, view: Optional['binaryview.BinaryView'], return_value: Optional['types.ReturnValueOrType'],
		params: 'types.ParamsType', func: Optional['function.Function'] = None,
		permitted_regs: Optional[List['architecture.RegisterIndex']] = None
	) -> 'CallLayout':
		"""
		``get_call_layout`` computes the complete call layout (parameter locations, return value
		location, and stack adjustments) for a call with the given return value and parameters. It
		is recommended to only override this method if the calling convention behavior cannot be
		modeled with :py:meth:`get_return_value_location` and/or :py:meth:`get_parameter_locations`.

		The default implementation calls :py:meth:`get_default_call_layout`.

		When calling this method to query the layout of a function, the return value and parameters
		should have their named type references dereferenced before passing them to this method.
		Calling the methods :py:meth:`BinaryView.deref_return_value_named_type_references` and
		:py:meth:`BinaryView.deref_parameter_named_type_references` will perform this dereferencing.

		:param BinaryView view: binary view providing type information
		:param return_value: return value of the call
		:param params: parameters of the call
		:param Function func: function used to resolve the architecture of the resulting locations
		:param permitted_regs: optional set of register indices that argument passing is restricted \
		to; if not provided, the calling convention's default registers are used
		:return: the computed call layout
		:rtype: CallLayout
		"""
		return self.get_default_call_layout(view, return_value, params, func, permitted_regs)

	def get_default_call_layout(
		self, view: Optional['binaryview.BinaryView'], return_value: Optional['types.ReturnValueOrType'],
		params: 'types.ParamsType', func: Optional['function.Function'] = None,
		permitted_regs: Optional[List['architecture.RegisterIndex']] = None
	) -> 'CallLayout':
		"""
		``get_default_call_layout`` is the default implementation of :py:meth:`get_call_layout`. The
		default implementation uses :py:meth:`get_return_value_location`,
		:py:meth:`get_parameter_locations`, :py:meth:`get_stack_adjustment_for_locations`, and
		:py:meth:`get_register_stack_adjustments` to compute the layout.

		:param BinaryView view: binary view providing type information
		:param return_value: return value of the call
		:param params: parameters of the call
		:param Function func: function used to resolve the architecture of the resulting locations
		:param permitted_regs: optional set of register indices that argument passing is restricted \
		to; if not provided, the calling convention's default registers are used
		:return: the computed call layout
		:rtype: CallLayout
		"""
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		if return_value is None:
			ret = types.ReturnValue(types.Type.void())._to_core_struct()
		elif isinstance(return_value, types.ReturnValue):
			ret = return_value._to_core_struct()
		else:
			ret = types.ReturnValue(return_value)._to_core_struct()
		param_structs, type_list = types.FunctionBuilder._to_core_struct(params)
		if permitted_regs is None:
			layout = core.BNGetDefaultCallLayoutDefaultPermittedArgs(self.handle, view_obj, ret, param_structs, len(params))
		else:
			regs = (ctypes.c_uint * len(permitted_regs))()
			for i in range(len(permitted_regs)):
				regs[i] = int(permitted_regs[i])
			layout = core.BNGetDefaultCallLayout(self.handle, view_obj, ret, param_structs, len(params), regs,
				len(permitted_regs))
		result = CallLayout._from_core_struct(layout, func)
		core.BNFreeCallLayout(layout)
		return result

	def get_return_value_location(
		self, view: Optional['binaryview.BinaryView'], return_value: 'types.ReturnValueOrType'
	) -> Optional['types.ValueLocation']:
		"""
		``get_return_value_location`` computes the location of the return value for the given return
		value type and location structure.

		The default implementation calls :py:meth:`get_default_return_value_location`.

		:param BinaryView view: binary view providing type information
		:param return_value: return value to compute the location for
		:return: the location of the return value
		:rtype: Optional[ValueLocation]
		"""
		return self.get_default_return_value_location(view, return_value)

	def get_default_return_value_location(
		self, view: Optional['binaryview.BinaryView'], return_value: 'types.ReturnValueOrType'
	) -> Optional['types.ValueLocation']:
		"""
		``get_default_return_value_location`` is the default implementation of
		:py:meth:`get_return_value_location`. The default implementation checks
		:py:meth:`is_return_type_reg_compatible` and places the return value in registers if it
		can, or uses an indirect return by pointer if not. If an indirect return is required, then
		:py:meth:`get_indirect_return_value_location` and
		:py:meth:`get_returned_indirect_return_value_pointer` are used to provide the location of
		the indirect return value.

		:param BinaryView view: binary view providing type information
		:param return_value: return value to compute the location for
		:return: the location of the return value
		:rtype: Optional[ValueLocation]
		"""
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		if return_value is None:
			ret = types.ReturnValue(types.Type.void())._to_core_struct()
		elif isinstance(return_value, types.ReturnValue):
			ret = return_value._to_core_struct()
		else:
			ret = types.ReturnValue(return_value)._to_core_struct()
		location = core.BNGetDefaultReturnValueLocation(self.handle, view_obj, ret)
		if location.count == 0:
			result = None
		else:
			result = types.ValueLocation._from_core_struct(location)
		core.BNFreeValueLocation(location)
		return result

	def get_parameter_locations(
		self, view: Optional['binaryview.BinaryView'], return_value: Optional['types.ValueLocation'],
		params: 'types.ParamsType', arch: Optional['architecture.Architecture'] = None,
		permitted_regs: Optional[List['architecture.RegisterIndex']] = None
	) -> List['types.ValueLocation']:
		"""
		``get_parameter_locations`` computes the locations of the parameters for a call with the
		given return value and parameters.

		The default implementation calls :py:meth:`get_default_parameter_locations`.

		:param BinaryView view: binary view providing type information
		:param return_value: optional location of the return value, which may affect parameter \
		placement (for example, when an indirect return pointer consumes an argument register)
		:param params: parameters of the call
		:param Architecture arch: architecture used to resolve the resulting locations
		:param permitted_regs: optional set of register indices that argument passing is restricted \
		to; if not provided, the calling convention's default registers are used
		:return: the locations of the parameters, in order
		:rtype: List[ValueLocation]
		"""
		return self.get_default_parameter_locations(view, return_value, params, arch, permitted_regs)

	def get_default_parameter_locations(
		self, view: Optional['binaryview.BinaryView'], return_value: Optional['types.ValueLocation'],
		params: 'types.ParamsType', arch: Optional['architecture.Architecture'] = None,
		permitted_regs: Optional[List['architecture.RegisterIndex']] = None
	) -> List['types.ValueLocation']:
		"""
		``get_default_parameter_locations`` is the default implementation of
		:py:meth:`get_parameter_locations`. The default implementation uses ``int_arg_regs``,
		``float_arg_regs``, ``arg_regs_share_index``, ``stack_reserved_for_arg_regs``,
		:py:meth:`is_arg_type_reg_compatible`, :py:meth:`is_non_reg_arg_indirect`,
		``stack_args_naturally_aligned``, and ``stack_args_pushed_left_to_right`` to compute
		the parameter layout.

		This function is usually sufficient unless the calling convention has unusual parameter
		passing behavior. Most calling conventions can be defined per-argument using the attributes
		and methods listed above.

		:param BinaryView view: binary view providing type information
		:param return_value: optional location of the return value
		:param params: parameters of the call
		:param Architecture arch: architecture used to resolve the resulting locations
		:param permitted_regs: optional set of register indices that argument passing is restricted \
		to; if not provided, the calling convention's default registers are used
		:return: the locations of the parameters, in order
		:rtype: List[ValueLocation]
		"""
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		if return_value is None:
			ret = None
		else:
			ret = return_value._to_core_struct()
		param_structs, type_list = types.FunctionBuilder._to_core_struct(params)
		count = ctypes.c_ulonglong()
		if permitted_regs is None:
			locations = core.BNGetDefaultParameterLocationsDefaultPermittedArgs(self.handle, view_obj, ret, param_structs,
				len(params), count)
		else:
			regs = (ctypes.c_uint * len(permitted_regs))()
			for i in range(len(permitted_regs)):
				regs[i] = int(permitted_regs[i])
			locations = core.BNGetDefaultParameterLocations(self.handle, view_obj, ret, param_structs, len(params), regs,
				len(permitted_regs), count)
		result = []
		for i in range(count.value):
			result.append(types.ValueLocation._from_core_struct(locations[i], arch))
		core.BNFreeValueLocationList(locations, count.value)
		return result

	def get_parameter_ordering_for_variables(
		self, view: Optional['binaryview.BinaryView'], params: Dict['variable.CoreVariable', 'types.Type']
	) -> List['variable.CoreVariable']:
		"""
		``get_parameter_ordering_for_variables`` computes the order in which the given parameter
		variables are passed. Used by the heuristic calling convention detection to create a
		function type from a list of parameter variables.

		The default implementation calls :py:meth:`get_default_parameter_ordering_for_variables`.

		:param BinaryView view: binary view providing type information
		:param params: map of parameter variables to their types
		:return: the parameter variables in the order they are passed
		:rtype: List[CoreVariable]
		"""
		return self.get_default_parameter_ordering_for_variables(params)

	def get_default_parameter_ordering_for_variables(self, params: Dict['variable.CoreVariable', 'types.Type']) -> List['variable.CoreVariable']:
		"""
		``get_default_parameter_ordering_for_variables`` is the default implementation of
		:py:meth:`get_parameter_ordering_for_variables`. The default implementation first checks
		``arg_regs_share_index`` to see if the parameter ordering is well defined. If the arguments
		do not share an index, it places all integer arguments before the floating point arguments.
		Arguments that are not passed in a normal location are placed last.

		:param params: map of parameter variables to their types
		:return: the parameter variables in the order they are passed
		:rtype: List[CoreVariable]
		"""
		vars = (core.BNVariable * len(params))()
		types = (ctypes.POINTER(core.BNType) * len(params))()
		for (i, (var, ty)) in enumerate(params.items()):
			vars[i] = var.to_BNVariable()
			types[i] = ty.handle
			i += 1

		count = ctypes.c_ulonglong()
		var_list = core.BNGetDefaultParameterOrderingForVariables(self.handle, vars, types, len(params), count)

		result = []
		for i in range(count.value):
			result.append(variable.CoreVariable.from_BNVariable(var_list[i]))
		core.BNFreeVariableList(var_list)
		return result

	def get_stack_adjustment_for_locations(
		self, view: Optional['binaryview.BinaryView'], return_value: Optional['types.ValueLocation'],
		params: List[Tuple['types.ValueLocation', 'types.Type']]
	):
		"""
		``get_stack_adjustment_for_locations`` computes the stack adjustment applied on return for
		a call with the given return value and parameter locations.

		The default implementation calls :py:meth:`get_default_stack_adjustment_for_locations`.

		:param BinaryView view: binary view providing type information
		:param return_value: optional location of the return value
		:param params: list of ``(location, type)`` tuples for the parameters
		:return: the stack adjustment in bytes
		:rtype: int
		"""
		return self.get_default_stack_adjustment_for_locations(return_value, params)

	def get_default_stack_adjustment_for_locations(
		self, return_value: Optional['types.ValueLocation'],
		params: List[Tuple['types.ValueLocation', 'types.Type']]
	):
		"""
		``get_default_stack_adjustment_for_locations`` is the default implementation of
		:py:meth:`get_stack_adjustment_for_locations`. The default implementation first checks
		``stack_adjusted_on_return``, and returns zero if that is ``False``. Otherwise, it checks
		the stack parameter locations and ``stack_args_naturally_aligned`` to compute the stack
		adjustment necessary to cover all parameters.

		:param return_value: optional location of the return value
		:param params: list of ``(location, type)`` tuples for the parameters
		:return: the stack adjustment in bytes
		:rtype: int
		"""
		if return_value is None:
			ret = None
		else:
			ret = return_value._to_core_struct()
		locations = (core.BNValueLocation * len(params))()
		type_list = (ctypes.POINTER(core.BNType) * len(params))()
		for i, (loc, ty) in enumerate(params):
			locations[i] = loc._to_core_struct()
			type_list[i] = ty.handle
		return core.BNGetDefaultStackAdjustmentForLocations(self.handle, ret, locations, type_list, len(params))

	def get_register_stack_adjustments(
		self, view: Optional['binaryview.BinaryView'], return_value: Optional['types.ValueLocation'],
		params: List['types.ValueLocation']
	) -> Dict['architecture.RegisterIndex', int]:
		"""
		``get_register_stack_adjustments`` computes the per-register-stack adjustments (for
		architectures with register stacks, such as the x87 floating point stack) for a call with
		the given return value and parameter locations.

		The default implementation calls :py:meth:`get_default_register_stack_adjustments`.

		:param BinaryView view: binary view providing type information
		:param return_value: optional location of the return value
		:param params: locations of the parameters
		:return: a map from register stack index to its adjustment
		:rtype: Dict[RegisterIndex, int]
		"""
		return self.get_default_register_stack_adjustments(return_value, params)

	def get_default_register_stack_adjustments(
			self, return_value: Optional['types.ValueLocation'], params: List['types.ValueLocation']
	) -> Dict['architecture.RegisterIndex', int]:
		"""
		``get_default_register_stack_adjustments`` is the default implementation of
		:py:meth:`get_register_stack_adjustments`. The default implementation compares the register
		stack slots used by the parameters and the return value to compute the adjustments.

		:param return_value: optional location of the return value
		:param params: locations of the parameters
		:return: a map from register stack index to its adjustment
		:rtype: Dict[RegisterIndex, int]
		"""
		if return_value is None:
			ret = None
		else:
			ret = return_value._to_core_struct()
		locations = (core.BNValueLocation * len(params))()
		for i, loc in enumerate(params):
			locations[i] = loc._to_core_struct()
		out_regs = ctypes.POINTER(ctypes.c_uint)()
		out_adjust = ctypes.POINTER(ctypes.c_int)()
		count = core.BNGetCallingConventionDefaultRegisterStackAdjustments(self.handle, ret, locations, len(params),
			out_regs, out_adjust)

		result = {}
		for i in range(count):
			result[architecture.RegisterIndex(out_regs[i])] = out_adjust[i]

		core.BNFreeCallingConventionRegisterStackAdjustments(out_regs, out_adjust)
		return result

	def with_confidence(self, confidence: int) -> 'CallingConvention':
		return CallingConvention(
		    self.arch, handle=core.BNNewCallingConventionReference(self.handle), confidence=confidence
		)

	@property
	def arch(self) -> 'architecture.Architecture':
		"""
		The architecture this calling convention applies to.

		:getter: returns the architecture this calling convention applies to
		:setter: sets the architecture this calling convention applies to
		:type: Architecture
		"""
		return self._arch

	@arch.setter
	def arch(self, value: 'architecture.Architecture') -> None:
		self._arch = value


class CoreCallingConvention(CallingConvention):
	def __init__(self, handle, confidence: int = core.max_confidence):
		super().__init__(handle=handle, confidence=confidence)

		self.arch = architecture.CoreArchitecture._from_cache(core.BNGetCallingConventionArchitecture(handle))
		self.__dict__["name"] = core.BNGetCallingConventionName(handle)
		self.__dict__["arg_regs_share_index"] = core.BNAreArgumentRegistersSharedIndex(handle)
		self.__dict__["arg_regs_for_varargs"] = core.BNAreArgumentRegistersUsedForVarArgs(handle)
		self.__dict__["stack_reserved_for_arg_regs"] = core.BNIsStackReservedForArgumentRegisters(handle)
		self.__dict__["stack_adjusted_on_return"] = core.BNIsStackAdjustedOnReturn(handle)
		self.__dict__["eligible_for_heuristics"] = core.BNIsEligibleForHeuristics(handle)
		self.__dict__["stack_args_naturally_aligned"] = core.BNAreStackArgumentsNaturallyAligned(handle)
		self.__dict__["stack_args_pushed_left_to_right"] = core.BNAreStackArgumentsPushedLeftToRight(handle)

		count = ctypes.c_ulonglong()
		regs = core.BNGetCallerSavedRegisters(handle, count)
		assert regs is not None, "core.BNGetCallerSavedRegisters returned None"
		result = []
		arch = self.arch
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		self.__dict__["caller_saved_regs"] = result

		count = ctypes.c_ulonglong()
		regs = core.BNGetCalleeSavedRegisters(handle, count)
		assert regs is not None, "core.BNGetCalleeSavedRegisters returned None"
		result = []
		arch = self.arch
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		self.__dict__["callee_saved_regs"] = result

		count = ctypes.c_ulonglong()
		regs = core.BNGetIntegerArgumentRegisters(handle, count)
		assert regs is not None, "core.BNGetIntegerArgumentRegisters returned None"
		result = []
		arch = self.arch
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		self.__dict__["int_arg_regs"] = result

		count = ctypes.c_ulonglong()
		regs = core.BNGetFloatArgumentRegisters(handle, count)
		assert regs is not None, "core.BNGetFloatArgumentRegisters returned None"
		result = []
		arch = self.arch
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		self.__dict__["float_arg_regs"] = result

		count = ctypes.c_ulonglong()
		regs = core.BNGetRequiredArgumentRegisters(handle, count)
		assert regs is not None, "core.BNGetRequiredArgumentRegisters returned None"
		result = []
		arch = self.arch
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		self.__dict__["required_arg_regs"] = result

		count = ctypes.c_ulonglong()
		regs = core.BNGetRequiredClobberedRegisters(handle, count)
		assert regs is not None, "core.BNGetRequiredClobberedRegisters returned None"
		result = []
		arch = self.arch
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		self.__dict__["required_clobbered_regs"] = result

		reg = core.BNGetIntegerReturnValueRegister(handle)
		if reg == 0xffffffff:
			self.__dict__["int_return_reg"] = None
		else:
			self.__dict__["int_return_reg"] = self.arch.get_reg_name(reg)

		reg = core.BNGetHighIntegerReturnValueRegister(handle)
		if reg == 0xffffffff:
			self.__dict__["high_int_return_reg"] = None
		else:
			self.__dict__["high_int_return_reg"] = self.arch.get_reg_name(reg)

		reg = core.BNGetFloatReturnValueRegister(handle)
		if reg == 0xffffffff:
			self.__dict__["float_return_reg"] = None
		else:
			self.__dict__["float_return_reg"] = self.arch.get_reg_name(reg)

		count = ctypes.c_ulonglong()
		regs = core.BNGetGlobalPointerRegisters(handle, count)
		result = []
		arch = self.arch
		if regs is not None:
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs)
		self.__dict__["global_pointer_regs"] = result
		self.__dict__["global_pointer_reg"] = result[0] if result else None

		count = ctypes.c_ulonglong()
		regs = core.BNGetImplicitlyDefinedRegisters(handle, count)
		assert regs is not None, "core.BNGetImplicitlyDefinedRegisters returned None"
		result = []
		arch = self.arch
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		self.__dict__["implicitly_defined_regs"] = result

	def get_incoming_reg_value(
	    self, reg: 'architecture.RegisterType', func: 'function.Function'
	) -> 'variable.RegisterValue':
		reg_num = self.arch.get_reg_index(reg)
		func_handle = None
		if func is not None:
			func_handle = func.handle
		return variable.RegisterValue.from_BNRegisterValue(
		    core.BNGetIncomingRegisterValue(self.handle, reg_num, func_handle), self.arch
		)

	def get_incoming_flag_value(
	    self, flag: 'architecture.FlagType', func: 'function.Function'
	) -> 'variable.RegisterValue':
		flag_index = self.arch.get_flag_index(flag)
		func_handle = None
		if func is not None:
			func_handle = func.handle
		return variable.RegisterValue.from_BNRegisterValue(
		    core.BNGetIncomingFlagValue(self.handle, flag_index, func_handle), self.arch
		)

	def get_incoming_var_for_parameter_var(
	    self, in_var: 'variable.CoreVariable', func: FunctionOrILFunction = None
	) -> 'variable.Variable':
		in_buf = in_var.to_BNVariable()
		if func is None:
			func_obj = None
		else:
			func_obj = func.handle
		out_var = core.BNGetIncomingVariableForParameterVariable(self.handle, in_buf, func_obj)
		return variable.Variable.from_BNVariable(func, out_var)

	def get_parameter_var_for_incoming_var(
	    self, in_var: 'variable.CoreVariable', func: FunctionOrILFunction = None
	) -> 'variable.Variable':
		in_buf = in_var.to_BNVariable()
		if func is None:
			func_obj = None
		else:
			func_obj = func.handle
		out_var = core.BNGetParameterVariableForIncomingVariable(self.handle, in_buf, func_obj)
		return variable.Variable.from_BNVariable(func, out_var)

	def is_return_type_reg_compatible(self, view: Optional['binaryview.BinaryView'], type: 'types.Type') -> bool:
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		return core.BNIsReturnTypeRegisterCompatible(self.handle, view_obj, type.handle)

	def get_indirect_return_value_location(self) -> 'variable.CoreVariable':
		result = core.BNGetIndirectReturnValueLocation(self.handle)
		return variable.CoreVariable.from_BNVariable(result)

	def get_returned_indirect_return_value_pointer(self) -> Optional['variable.CoreVariable']:
		var = core.BNVariable()
		if core.BNGetReturnedIndirectReturnValuePointer(self.handle, var):
			return variable.CoreVariable.from_BNVariable(var)
		return None

	def is_arg_type_reg_compatible(self, view: Optional['binaryview.BinaryView'], type: 'types.Type') -> bool:
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		return core.BNIsArgumentTypeRegisterCompatible(self.handle, view_obj, type.handle)

	def is_non_reg_arg_indirect(self, view: Optional['binaryview.BinaryView'], type: Optional['types.Type']) -> bool:
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		if type is None:
			return core.BNIsNonRegisterArgumentIndirect(self.handle, view_obj, None)
		else:
			return core.BNIsNonRegisterArgumentIndirect(self.handle, view_obj, type.handle)

	def get_call_layout(
		self, view: Optional['binaryview.BinaryView'], return_value: Optional['types.ReturnValueOrType'],
		params: 'types.ParamsType', func: Optional['function.Function'] = None,
		permitted_regs: Optional[List['architecture.RegisterIndex']] = None
	) -> 'CallLayout':
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		if return_value is None:
			ret = types.ReturnValue(types.Type.void())._to_core_struct()
		elif isinstance(return_value, types.ReturnValue):
			ret = return_value._to_core_struct()
		else:
			ret = types.ReturnValue(return_value)._to_core_struct()
		param_structs, type_list = types.FunctionBuilder._to_core_struct(params)
		if permitted_regs is None:
			layout = core.BNGetCallLayoutDefaultPermittedArgs(self.handle, view_obj, ret, param_structs, len(params))
		else:
			regs = (ctypes.c_uint * len(permitted_regs))()
			for i in range(len(permitted_regs)):
				regs[i] = int(permitted_regs[i])
			layout = core.BNGetCallLayout(self.handle, view_obj, ret, param_structs, len(params), regs, len(permitted_regs))
		result = CallLayout._from_core_struct(layout, func)
		core.BNFreeCallLayout(layout)
		return result

	def get_return_value_location(
		self, view: Optional['binaryview.BinaryView'], return_value: 'types.ReturnValueOrType'
	) -> Optional['types.ValueLocation']:
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		if return_value is None:
			ret = types.ReturnValue(types.Type.void())._to_core_struct()
		elif isinstance(return_value, types.ReturnValue):
			ret = return_value._to_core_struct()
		else:
			ret = types.ReturnValue(return_value)._to_core_struct()
		location = core.BNGetReturnValueLocation(self.handle, view_obj, ret)
		if location.count == 0:
			result = None
		else:
			result = types.ValueLocation._from_core_struct(location)
		core.BNFreeValueLocation(location)
		return result

	def get_parameter_locations(
		self, view: Optional['binaryview.BinaryView'], return_value: Optional['types.ValueLocation'],
		params: 'types.ParamsType', arch: Optional['architecture.Architecture'] = None,
		permitted_regs: Optional[List['architecture.RegisterIndex']] = None
	) -> List['types.ValueLocation']:
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		if return_value is None:
			ret = None
		else:
			ret = return_value._to_core_struct()
		param_structs, type_list = types.FunctionBuilder._to_core_struct(params)
		count = ctypes.c_ulonglong()
		if permitted_regs is None:
			locations = core.BNGetParameterLocationsDefaultPermittedArgs(self.handle, view_obj, ret, param_structs,
				len(params), count)
		else:
			regs = (ctypes.c_uint * len(permitted_regs))()
			for i in range(len(permitted_regs)):
				regs[i] = int(permitted_regs[i])
			locations = core.BNGetParameterLocations(self.handle, view_obj, ret, param_structs, len(params), regs,
				len(permitted_regs), count)
		result = []
		for i in range(count.value):
			result.append(types.ValueLocation._from_core_struct(locations[i], arch))
		core.BNFreeValueLocationList(locations, count.value)
		return result

	def get_parameter_ordering_for_variables(
		self, view: Optional['binaryview.BinaryView'], params: Dict['variable.CoreVariable', 'types.Type']
	) -> List['variable.CoreVariable']:
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		vars = (core.BNVariable * len(params))()
		types = (ctypes.POINTER(core.BNType) * len(params))()
		for (i, (var, ty)) in enumerate(params.items()):
			vars[i] = var.to_BNVariable()
			types[i] = ty.handle
			i += 1

		count = ctypes.c_ulonglong()
		var_list = core.BNGetParameterOrderingForVariables(self.handle, view_obj, vars, types, len(params), count)

		result = []
		for i in range(count.value):
			result.append(variable.CoreVariable.from_BNVariable(var_list[i]))
		core.BNFreeVariableList(var_list)
		return result

	def get_stack_adjustment_for_locations(
		self, view: Optional['binaryview.BinaryView'], return_value: Optional['types.ValueLocation'],
		params: List[Tuple['types.ValueLocation', 'types.Type']]
	):
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		if return_value is None:
			ret = None
		else:
			ret = return_value._to_core_struct()
		locations = (core.BNValueLocation * len(params))()
		type_list = (ctypes.POINTER(core.BNType) * len(params))()
		for i, (loc, ty) in enumerate(params):
			locations[i] = loc._to_core_struct()
			type_list[i] = ty.handle
		return core.BNGetStackAdjustmentForLocations(self.handle, view_obj, ret, locations, type_list, len(params))

	def get_register_stack_adjustments(
		self, view: Optional['binaryview.BinaryView'], return_value: Optional['types.ValueLocation'],
		params: List['types.ValueLocation']
	) -> Dict['architecture.RegisterIndex', int]:
		if view is None:
			view_obj = None
		else:
			view_obj = view.handle
		if return_value is None:
			ret = None
		else:
			ret = return_value._to_core_struct()
		locations = (core.BNValueLocation * len(params))()
		for i, loc in enumerate(params):
			locations[i] = loc._to_core_struct()
		out_regs = ctypes.POINTER(ctypes.c_uint)()
		out_adjust = ctypes.POINTER(ctypes.c_int)()
		count = core.BNGetCallingConventionRegisterStackAdjustments(self.handle, view_obj, ret, locations, len(params),
			out_regs, out_adjust)

		result = {}
		for i in range(count):
			result[architecture.RegisterIndex(out_regs[i])] = out_adjust[i]

		core.BNFreeCallingConventionRegisterStackAdjustments(out_regs, out_adjust)
		return result
