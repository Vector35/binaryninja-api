# Copyright (c) 2015-2025 Vector 35 Inc
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

from typing import Optional, Union, Set
import traceback
import ctypes

# Binary Ninja components
from . import _binaryninjacore as core
from .log import log_error_for_exception
from . import variable
from . import function
from . import architecture

FunctionOrILFunction = Union["binaryninja.function.Function", "binaryninja.lowlevelil.LowLevelILFunction",
                             "binaryninja.mediumlevelil.MediumLevelILFunction",
                             "binaryninja.highlevelil.HighLevelILFunction"]

# Register list kinds
REGISTER_LIST_KIND_INTEGER_SEMANTICS = 0
REGISTER_LIST_KIND_FLOAT_SEMANTICS = 1
REGISTER_LIST_KIND_POINTER_SEMANTICS = 2


class CallingConvention:
	name = None
	caller_saved_regs = []
	callee_saved_regs = []
	int_arg_regs = []
	float_arg_regs = []
	arg_regs_share_index = False
	arg_regs_for_varargs = True
	stack_reserved_for_arg_regs = False
	stack_adjusted_on_return = False
	eligible_for_heuristics = True
	int_return_reg = None
	high_int_return_reg = None
	float_return_reg = None
	global_pointer_reg = None
	implicitly_defined_regs = []
	
	# New register list/class API attributes
	register_argument_classes = []
	register_argument_class_lists = {}
	register_argument_lists = []
	register_argument_list_regs = {}
	register_argument_list_kinds = {}

	_registered_calling_conventions = []

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
			self._cb.getGlobalPointerRegister = self._cb.getGlobalPointerRegister.__class__(
			    self._get_global_pointer_reg
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
			self._cb.getRegisterArgumentClasses = self._cb.getRegisterArgumentClasses.__class__(
			    self._get_register_argument_classes
			)
			self._cb.getRegisterArgumentClassLists = self._cb.getRegisterArgumentClassLists.__class__(
			    self._get_register_argument_class_lists
			)
			self._cb.getRegisterArgumentLists = self._cb.getRegisterArgumentLists.__class__(
			    self._get_register_argument_lists
			)
			self._cb.getRegisterArgumentListRegs = self._cb.getRegisterArgumentListRegs.__class__(
			    self._get_register_argument_list_regs
			)
			self._cb.getRegisterArgumentListKind = self._cb.getRegisterArgumentListKind.__class__(
			    self._get_register_argument_list_kind
			)
			self._cb.getVariablesForParameters = self._cb.getVariablesForParameters.__class__(
			    self._get_variables_for_parameters
			)
			self._cb.freeVariableList = self._cb.freeVariableList.__class__(self._free_variable_list)
			_handle = core.BNCreateCallingConvention(arch.handle, name, self._cb)
			self.__class__._registered_calling_conventions.append(self)
		else:
			_handle = handle
			self.arch = architecture.CoreArchitecture._from_cache(core.BNGetCallingConventionArchitecture(_handle))
			self.__dict__["name"] = core.BNGetCallingConventionName(_handle)
			self.__dict__["arg_regs_share_index"] = core.BNAreArgumentRegistersSharedIndex(_handle)
			self.__dict__["arg_regs_for_varargs"] = core.BNAreArgumentRegistersUsedForVarArgs(_handle)
			self.__dict__["stack_reserved_for_arg_regs"] = core.BNIsStackReservedForArgumentRegisters(_handle)
			self.__dict__["stack_adjusted_on_return"] = core.BNIsStackAdjustedOnReturn(_handle)
			self.__dict__["eligible_for_heuristics"] = core.BNIsEligibleForHeuristics(_handle)

			count = ctypes.c_ulonglong()
			regs = core.BNGetCallerSavedRegisters(_handle, count)
			assert regs is not None, "core.BNGetCallerSavedRegisters returned None"
			result = []
			arch = self.arch
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs)
			self.__dict__["caller_saved_regs"] = result

			count = ctypes.c_ulonglong()
			regs = core.BNGetCalleeSavedRegisters(_handle, count)
			assert regs is not None, "core.BNGetCalleeSavedRegisters returned None"
			result = []
			arch = self.arch
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs)
			self.__dict__["callee_saved_regs"] = result

			count = ctypes.c_ulonglong()
			regs = core.BNGetIntegerArgumentRegisters(_handle, count)
			assert regs is not None, "core.BNGetIntegerArgumentRegisters returned None"
			result = []
			arch = self.arch
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs)
			self.__dict__["int_arg_regs"] = result

			count = ctypes.c_ulonglong()
			regs = core.BNGetFloatArgumentRegisters(_handle, count)
			assert regs is not None, "core.BNGetFloatArgumentRegisters returned None"
			result = []
			arch = self.arch
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs)
			self.__dict__["float_arg_regs"] = result

			reg = core.BNGetIntegerReturnValueRegister(_handle)
			if reg == 0xffffffff:
				self.__dict__["int_return_reg"] = None
			else:
				self.__dict__["int_return_reg"] = self.arch.get_reg_name(reg)

			reg = core.BNGetHighIntegerReturnValueRegister(_handle)
			if reg == 0xffffffff:
				self.__dict__["high_int_return_reg"] = None
			else:
				self.__dict__["high_int_return_reg"] = self.arch.get_reg_name(reg)

			reg = core.BNGetFloatReturnValueRegister(_handle)
			if reg == 0xffffffff:
				self.__dict__["float_return_reg"] = None
			else:
				self.__dict__["float_return_reg"] = self.arch.get_reg_name(reg)

			reg = core.BNGetGlobalPointerRegister(_handle)
			if reg == 0xffffffff:
				self.__dict__["global_pointer_reg"] = None
			else:
				self.__dict__["global_pointer_reg"] = self.arch.get_reg_name(reg)

			count = ctypes.c_ulonglong()
			regs = core.BNGetImplicitlyDefinedRegisters(_handle, count)
			assert regs is not None, "core.BNGetImplicitlyDefinedRegisters returned None"
			result = []
			arch = self.arch
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs)
			self.__dict__["implicitly_defined_regs"] = result
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
		except:
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
		except:
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
		except:
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
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_float_arg_regs")
			count[0] = 0
			return None

	def _free_register_list(self, ctxt, regs, count):
		try:
			buf = ctypes.cast(regs, ctypes.c_void_p)
			if buf.value not in self._pending_reg_lists:
				raise ValueError("freeing register list that wasn't allocated")
			del self._pending_reg_lists[buf.value]
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._free_register_list")

	def _arg_regs_share_index(self, ctxt):
		try:
			return self.__class__.arg_regs_share_index
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._arg_regs_share_index")
			return False

	def _arg_regs_used_for_varargs(self, ctxt):
		try:
			return self.__class__.arg_regs_for_varargs
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._arg_regs_used_for_varargs")
			return False

	def _stack_reserved_for_arg_regs(self, ctxt):
		try:
			return self.__class__.stack_reserved_for_arg_regs
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._stack_reserved_for_arg_regs")
			return False

	def _stack_adjusted_on_return(self, ctxt):
		try:
			return self.__class__.stack_adjusted_on_return
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._stack_adjusted_on_return")
			return False

	def _eligible_for_heuristics(self, ctxt):
		try:
			return self.__class__.eligible_for_heuristics
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._eligible_for_heuristics")
			return False

	def _get_int_return_reg(self, ctxt):
		if self.__class__.int_return_reg is None:
			return False
		assert isinstance(self.__class__.int_return_reg, str), "int_return_reg return reg must be a string"

		try:
			return self.arch.regs[self.__class__.int_return_reg].index
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_int_return_reg")
			return False

	def _get_high_int_return_reg(self, ctxt):
		try:
			if self.__class__.high_int_return_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.high_int_return_reg].index
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_high_int_return_reg")
			return False

	def _get_float_return_reg(self, ctxt):
		try:
			if self.__class__.float_return_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.float_return_reg].index
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_float_return_reg")
			return False

	def _get_global_pointer_reg(self, ctxt):
		try:
			if self.__class__.global_pointer_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.global_pointer_reg].index
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_global_pointer_reg")
			return False

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
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_implicitly_defined_regs")
			count[0] = 0
			return None

	def _get_incoming_reg_value(self, ctxt, reg, func, result):
		try:
			func_obj = function.Function(handle=core.BNNewFunctionReference(func))
			reg_name = self.arch.get_reg_name(reg)
			api_obj = self.perform_get_incoming_reg_value(reg_name, func_obj)._to_core_struct()
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_incoming_reg_value")
			api_obj = variable.Undetermined()._to_core_struct()
		result[0].state = api_obj.state
		result[0].value = api_obj.value

	def _get_incoming_flag_value(self, ctxt, reg, func, result):
		try:
			func_obj = function.Function(handle=core.BNNewFunctionReference(func))
			reg_name = self.arch.get_reg_name(reg)
			api_obj = self.perform_get_incoming_flag_value(reg_name, func_obj)._to_core_struct()
		except:
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
		except:
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
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_parameter_var_for_incoming_var")
			result[0].type = in_var[0].type
			result[0].index = in_var[0].index
			result[0].storage = in_var[0].storage

	def _get_register_argument_classes(self, ctxt, count):
		try:
			classes = self.perform_get_register_argument_classes()
			count[0] = len(classes)
			class_buf = (ctypes.c_uint * len(classes))()
			for i in range(0, len(classes)):
				class_buf[i] = classes[i]
			result = ctypes.cast(class_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, class_buf)
			return result.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_register_argument_classes")
			count[0] = 0
			return None

	def _get_register_argument_class_lists(self, ctxt, class_id, count):
		try:
			lists = self.perform_get_register_argument_class_lists(class_id)
			count[0] = len(lists)
			list_buf = (ctypes.c_uint * len(lists))()
			for i in range(0, len(lists)):
				list_buf[i] = lists[i]
			result = ctypes.cast(list_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, list_buf)
			return result.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_register_argument_class_lists")
			count[0] = 0
			return None

	def _get_register_argument_lists(self, ctxt, count):
		try:
			lists = self.perform_get_register_argument_lists()
			count[0] = len(lists)
			list_buf = (ctypes.c_uint * len(lists))()
			for i in range(0, len(lists)):
				list_buf[i] = lists[i]
			result = ctypes.cast(list_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, list_buf)
			return result.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_register_argument_lists")
			count[0] = 0
			return None

	def _get_register_argument_list_regs(self, ctxt, reg_list_id, count):
		try:
			regs = self.perform_get_register_argument_list_regs(reg_list_id)
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				if isinstance(regs[i], str):
					reg_buf[i] = self.arch.regs[regs[i]].index
				else:
					reg_buf[i] = regs[i]
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_register_argument_list_regs")
			count[0] = 0
			return None

	def _get_register_argument_list_kind(self, ctxt, reg_list_id):
		try:
			return self.perform_get_register_argument_list_kind(reg_list_id)
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_register_argument_list_kind")
			return 0

	def _get_variables_for_parameters(self, ctxt, params, param_count, permitted_regs, permitted_reg_count, count):
		try:
			# Convert C parameters to Python
			param_list = []
			for i in range(param_count):
				param = params[i]
				param_name = param.name.decode('utf-8') if param.name else ""
				param_type = core.BNNewTypeReference(param.type)
				param_list.append((param_name, param_type))
			
			# Convert permitted registers
			permitted_reg_set = set()
			if permitted_regs and permitted_reg_count > 0:
				for i in range(permitted_reg_count):
					permitted_reg_set.add(permitted_regs[i])
			
			# Call the perform method
			variables = self.perform_get_variables_for_parameters(param_list, permitted_reg_set if permitted_reg_set else None)
			
			# If None returned, signal that core should handle it
			if variables is None:
				count[0] = 0
				return None
			
			# Convert result to C
			count[0] = len(variables)
			var_buf = (core.BNVariable * len(variables))()
			for i in range(len(variables)):
				var_buf[i].type = variables[i].source_type
				var_buf[i].index = variables[i].index
				var_buf[i].storage = variables[i].storage
			
			result = ctypes.cast(var_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, var_buf)
			return result.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_variables_for_parameters")
			count[0] = 0
			return None

	def _free_variable_list(self, ctxt, variables, count):
		try:
			buf = ctypes.cast(variables, ctypes.c_void_p)
			if buf.value in self._pending_reg_lists:
				del self._pending_reg_lists[buf.value]
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._free_variable_list")

	def perform_get_incoming_reg_value(
	    self, reg: 'architecture.RegisterName', func: 'function.Function'
	) -> 'variable.RegisterValue':
		reg_stack = self.arch.get_reg_stack_for_reg(reg)
		if reg_stack is not None:
			if reg == self.arch.reg_stacks[reg_stack].stack_top_reg:
				return variable.ConstantRegisterValue(0)
		return variable.Undetermined()

	def perform_get_incoming_flag_value(
	    self, reg: 'architecture.RegisterName', func: 'function.Function'
	) -> 'variable.RegisterValue':
		return variable.Undetermined()

	def perform_get_incoming_var_for_parameter_var(
	    self, in_var: 'variable.CoreVariable', func: Optional['function.Function'] = None
	) -> 'variable.CoreVariable':
		out_var = core.BNGetDefaultIncomingVariableForParameterVariable(self.handle, in_var.to_BNVariable())
		return variable.CoreVariable.from_BNVariable(out_var)

	def perform_get_parameter_var_for_incoming_var(
	    self, in_var: 'variable.CoreVariable', func: Optional['function.Function'] = None
	) -> 'variable.CoreVariable':
		out_var = core.BNGetDefaultParameterVariableForIncomingVariable(self.handle, in_var.to_BNVariable())
		return variable.CoreVariable.from_BNVariable(out_var)

	def perform_get_register_argument_classes(self):
		"""
		Override this method to provide custom register argument classes.
		Default implementation matches C++ CallingConvention::GetRegisterArgumentClasses
		"""
		if self.__class__.arg_regs_share_index:
			return [0]
		else:
			return [0, 1]

	def perform_get_register_argument_class_lists(self, class_id):
		"""
		Override this method to provide custom register argument class lists.
		Default implementation matches C++ CallingConvention::GetRegisterArgumentClassLists
		"""
		if self.__class__.arg_regs_share_index:
			return [0, 1]
		else:
			if class_id == 0:
				return [0]
			elif class_id == 1:
				return [1]
			else:
				return []

	def perform_get_register_argument_lists(self):
		"""
		Override this method to provide custom register argument lists.
		Default implementation matches C++ CallingConvention::GetRegisterArgumentLists
		"""
		result = []
		classes = self.perform_get_register_argument_classes()
		for class_id in classes:
			lists = self.perform_get_register_argument_class_lists(class_id)
			result.extend(lists)
		return result

	def perform_get_register_argument_list_regs(self, reg_list_id):
		"""
		Override this method to provide custom register argument list registers.
		Default implementation matches C++ CallingConvention::GetRegisterArgumentListRegs
		"""
		if reg_list_id == 0:
			return self.__class__.int_arg_regs[:]
		elif reg_list_id == 1:
			return self.__class__.float_arg_regs[:]
		else:
			return []

	def perform_get_register_argument_list_kind(self, reg_list_id):
		"""
		Override this method to provide custom register argument list kind.
		Default implementation matches C++ CallingConvention::GetRegisterArgumentListKind
		"""
		return 0 if reg_list_id == 0 else 1  # INTEGER_SEMANTICS : FLOAT_SEMANTICS

	def perform_get_variables_for_parameters(self, param_types, permitted_regs: Optional[Set[int]] = None):
		"""
		Override this method to provide custom parameter allocation logic.
		
		:param param_types: List of (name, type) tuples for parameters
		:param permitted_regs: Set of permitted register indices, or None for no restriction
		:return: List of Variable objects for parameter allocation
		"""
		# Default implementation: provide fallback parameter allocation logic
		# similar to C++ CallingConvention::GetVariablesForParameters
		
		int_args = self.__class__.int_arg_regs
		float_args = self.__class__.float_arg_regs
		shared_index = self.__class__.arg_regs_share_index
		
		result = []
		int_arg_iter = iter(int_args)
		float_arg_iter = iter(float_args)
		stack_offset = 0
		addr_size = self.arch.address_size
		
		# If there's a link register, start stack after it
		if self.arch.link_reg is not None:
			stack_offset = addr_size
		
		# Reserve stack space for argument registers if needed
		if self.__class__.stack_reserved_for_arg_regs:
			stack_offset += len(int_args) * addr_size
		
		for param_name, param_type in param_types:
			# Get parameter width - use a default if type info not available
			try:
				param_width = param_type.width if hasattr(param_type, 'width') else addr_size
			except:
				param_width = addr_size
			
			# Check if register is permitted
			def is_reg_permitted(reg_name):
				if permitted_regs is None:
					return True
				try:
					reg_index = self.arch.regs[reg_name].index
					return reg_index in permitted_regs
				except:
					return True
			
			allocated = False
			
			# Try to allocate in appropriate register type
			try:
				# For now, assume integer allocation (TODO: add float type detection)
				try:
					reg_name = next(int_arg_iter)
					if is_reg_permitted(reg_name):
						reg_index = self.arch.regs[reg_name].index
						result.append(variable.Variable(variable.RegisterVariableSourceType, 0, reg_index))
						allocated = True
						if shared_index:
							try:
								next(float_arg_iter)  # Advance float iterator too
							except StopIteration:
								pass
					else:
						# Register not permitted, spill to stack
						int_arg_iter = iter([])  # Empty the iterator
						if shared_index:
							float_arg_iter = iter([])
				except StopIteration:
					pass
			except:
				pass
			
			if not allocated:
				# Allocate on stack
				result.append(variable.Variable(variable.StackVariableSourceType, 0, stack_offset))
				
				# Align parameter width
				aligned_width = param_width
				if aligned_width < addr_size:
					aligned_width = addr_size
				elif aligned_width % addr_size != 0:
					aligned_width += addr_size - (aligned_width % addr_size)
				
				stack_offset += aligned_width
		
		return result

	def with_confidence(self, confidence: int) -> 'CallingConvention':
		return CallingConvention(
		    self.arch, handle=core.BNNewCallingConventionReference(self.handle), confidence=confidence
		)

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
	    self, flag: 'architecture.FlagIndex', func: 'function.Function'
	) -> 'variable.RegisterValue':
		reg_num = self.arch.get_flag_index(flag)
		func_handle = None
		if func is not None:
			func_handle = func.handle
		return variable.RegisterValue.from_BNRegisterValue(
		    core.BNGetIncomingFlagValue(self.handle, reg_num, func_handle), self.arch
		)

	def get_incoming_var_for_parameter_var(
	    self, in_var: 'variable.CoreVariable', func: FunctionOrILFunction
	) -> 'variable.Variable':
		in_buf = in_var.to_BNVariable()
		if func is None:
			func_obj = None
		else:
			func_obj = func.handle
		out_var = core.BNGetIncomingVariableForParameterVariable(self.handle, in_buf, func_obj)
		return variable.Variable.from_BNVariable(func, out_var)

	def get_parameter_var_for_incoming_var(
	    self, in_var: 'variable.CoreVariable', func: FunctionOrILFunction
	) -> 'variable.Variable':
		in_buf = in_var.to_BNVariable()
		if func is None:
			func_obj = None
		else:
			func_obj = func.handle
		out_var = core.BNGetParameterVariableForIncomingVariable(self.handle, in_buf, func_obj)
		return variable.Variable.from_BNVariable(func, out_var)

	def get_register_argument_classes(self):
		"""Get the register argument classes for this calling convention."""
		count = ctypes.c_ulonglong()
		classes = core.BNGetRegisterArgumentClasses(self.handle, count)
		result = []
		for i in range(count.value):
			result.append(classes[i])
		core.BNFreeRegisterList(classes)
		return result

	def get_register_argument_class_lists(self, class_id):
		"""Get the register lists for a specific class."""
		count = ctypes.c_ulonglong()
		lists = core.BNGetRegisterArgumentClassLists(self.handle, class_id, count)
		result = []
		for i in range(count.value):
			result.append(lists[i])
		core.BNFreeRegisterList(lists)
		return result

	def get_register_argument_lists(self):
		"""Get all register argument lists."""
		count = ctypes.c_ulonglong()
		lists = core.BNGetRegisterArgumentLists(self.handle, count)
		result = []
		for i in range(count.value):
			result.append(lists[i])
		core.BNFreeRegisterList(lists)
		return result

	def get_register_argument_list_regs(self, reg_list_id):
		"""Get the registers for a specific register list."""
		count = ctypes.c_ulonglong()
		regs = core.BNGetRegisterArgumentListRegs(self.handle, reg_list_id, count)
		result = []
		arch = self.arch
		for i in range(count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_register_argument_list_kind(self, reg_list_id):
		"""Get the kind (INTEGER_SEMANTICS or FLOAT_SEMANTICS) of a register list."""
		return core.BNGetRegisterArgumentListKind(self.handle, reg_list_id)

	def get_variables_for_parameters(self, param_types, permitted_regs: Optional[Set[int]] = None):
		"""Get variable allocations for the given parameter types."""
		# Convert Python parameters to BN parameters
		param_array = (core.BNFunctionParameter * len(param_types))()
		for i, (name, param_type) in enumerate(param_types):
			param_array[i].name = name.encode('utf-8')
			param_array[i].type = param_type.handle if hasattr(param_type, 'handle') else param_type
			param_array[i].typeConfidence = core.max_confidence
			param_array[i].defaultLocation = True
			param_array[i].location.type = 0  # RegisterVariableSourceType
			param_array[i].location.index = 0
			param_array[i].location.storage = 0

		# Convert permitted registers
		permitted_reg_array = None
		permitted_reg_count = 0
		if permitted_regs:
			permitted_reg_count = len(permitted_regs)
			permitted_reg_array = (ctypes.c_uint * len(permitted_regs))()
			for i, reg in enumerate(permitted_regs):
				if isinstance(reg, str):
					permitted_reg_array[i] = self.arch.regs[reg].index
				else:
					permitted_reg_array[i] = reg

		count = ctypes.c_ulonglong()
		variables = core.BNGetVariablesForParameters(
			self.handle, param_array, len(param_types), 
			permitted_reg_array, permitted_reg_count, count
		)
		
		result = []
		for i in range(count.value):
			result.append(variable.Variable.from_BNVariable(None, variables[i]))
		
		core.BNFreeVariableList(variables)
		return result

	@property
	def arch(self) -> 'architecture.Architecture':
		return self._arch

	@arch.setter
	def arch(self, value: 'architecture.Architecture') -> None:
		self._arch = value
