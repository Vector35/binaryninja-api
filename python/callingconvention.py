# Copyright (c) 2015-2020 Vector 35 Inc
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

# Binary Ninja components
import binaryninja
from binaryninja import _binaryninjacore as core
from binaryninja import log
from binaryninja.enums import VariableSourceType

# 2-3 compatibility
from binaryninja import range


class CallingConvention(object):
	name = None
	caller_saved_regs = []
	callee_saved_regs = []
	int_arg_regs = []
	float_arg_regs = []
	arg_regs_share_index = False
	stack_reserved_for_arg_regs = False
	stack_adjusted_on_return = False
	int_return_reg = None
	high_int_return_reg = None
	float_return_reg = None
	global_pointer_reg = None
	implicitly_defined_regs = []

	_registered_calling_conventions = []

	def __init__(self, arch=None, name=None, handle=None, confidence=binaryninja.types.max_confidence):
		if handle is None:
			if arch is None or name is None:
				self.handle = None
				raise ValueError("Must specify either handle or architecture and name")
			self._arch = arch
			self._pending_reg_lists = {}
			self._cb = core.BNCustomCallingConvention()
			self._cb.context = 0
			self._cb.getCallerSavedRegisters = self._cb.getCallerSavedRegisters.__class__(self._get_caller_saved_regs)
			self._cb.getCalleeSavedRegisters = self._cb.getCalleeSavedRegisters.__class__(self._get_callee_saved_regs)
			self._cb.getIntegerArgumentRegisters = self._cb.getIntegerArgumentRegisters.__class__(self._get_int_arg_regs)
			self._cb.getFloatArgumentRegisters = self._cb.getFloatArgumentRegisters.__class__(self._get_float_arg_regs)
			self._cb.freeRegisterList = self._cb.freeRegisterList.__class__(self._free_register_list)
			self._cb.areArgumentRegistersSharedIndex = self._cb.areArgumentRegistersSharedIndex.__class__(self._arg_regs_share_index)
			self._cb.isStackReservedForArgumentRegisters = self._cb.isStackReservedForArgumentRegisters.__class__(self._stack_reserved_for_arg_regs)
			self._cb.isStackAdjustedOnReturn = self._cb.isStackAdjustedOnReturn.__class__(self._stack_adjusted_on_return)
			self._cb.getIntegerReturnValueRegister = self._cb.getIntegerReturnValueRegister.__class__(self._get_int_return_reg)
			self._cb.getHighIntegerReturnValueRegister = self._cb.getHighIntegerReturnValueRegister.__class__(self._get_high_int_return_reg)
			self._cb.getFloatReturnValueRegister = self._cb.getFloatReturnValueRegister.__class__(self._get_float_return_reg)
			self._cb.getGlobalPointerRegister = self._cb.getGlobalPointerRegister.__class__(self._get_global_pointer_reg)
			self._cb.getImplicitlyDefinedRegisters = self._cb.getImplicitlyDefinedRegisters.__class__(self._get_implicitly_defined_regs)
			self._cb.getIncomingRegisterValue = self._cb.getIncomingRegisterValue.__class__(self._get_incoming_reg_value)
			self._cb.getIncomingFlagValue = self._cb.getIncomingFlagValue.__class__(self._get_incoming_flag_value)
			self._cb.getIncomingVariableForParameterVariable = self._cb.getIncomingVariableForParameterVariable.__class__(self._get_incoming_var_for_parameter_var)
			self._cb.getParameterVariableForIncomingVariable = self._cb.getParameterVariableForIncomingVariable.__class__(self._get_parameter_var_for_incoming_var)
			self.handle = core.BNCreateCallingConvention(arch.handle, name, self._cb)
			self.__class__._registered_calling_conventions.append(self)
		else:
			self.handle = handle
			self.arch = binaryninja.architecture.CoreArchitecture._from_cache(core.BNGetCallingConventionArchitecture(self.handle))
			self.__dict__["name"] = core.BNGetCallingConventionName(self.handle)
			self.__dict__["arg_regs_share_index"] = core.BNAreArgumentRegistersSharedIndex(self.handle)
			self.__dict__["stack_reserved_for_arg_regs"] = core.BNIsStackReservedForArgumentRegisters(self.handle)
			self.__dict__["stack_adjusted_on_return"] = core.BNIsStackAdjustedOnReturn(self.handle)

			count = ctypes.c_ulonglong()
			regs = core.BNGetCallerSavedRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["caller_saved_regs"] = result

			count = ctypes.c_ulonglong()
			regs = core.BNGetCalleeSavedRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["callee_saved_regs"] = result

			count = ctypes.c_ulonglong()
			regs = core.BNGetIntegerArgumentRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["int_arg_regs"] = result

			count = ctypes.c_ulonglong()
			regs = core.BNGetFloatArgumentRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["float_arg_regs"] = result

			reg = core.BNGetIntegerReturnValueRegister(self.handle)
			if reg == 0xffffffff:
				self.__dict__["int_return_reg"] = None
			else:
				self.__dict__["int_return_reg"] = self.arch.get_reg_name(reg)

			reg = core.BNGetHighIntegerReturnValueRegister(self.handle)
			if reg == 0xffffffff:
				self.__dict__["high_int_return_reg"] = None
			else:
				self.__dict__["high_int_return_reg"] = self.arch.get_reg_name(reg)

			reg = core.BNGetFloatReturnValueRegister(self.handle)
			if reg == 0xffffffff:
				self.__dict__["float_return_reg"] = None
			else:
				self.__dict__["float_return_reg"] = self.arch.get_reg_name(reg)

			reg = core.BNGetGlobalPointerRegister(self.handle)
			if reg == 0xffffffff:
				self.__dict__["global_pointer_reg"] = None
			else:
				self.__dict__["global_pointer_reg"] = self.arch.get_reg_name(reg)

			count = ctypes.c_ulonglong()
			regs = core.BNGetImplicitlyDefinedRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in range(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["implicitly_defined_regs"] = result

		self.confidence = confidence

	def __del__(self):
		if self.handle is not None:
			core.BNFreeCallingConvention(self.handle)

	def __repr__(self):
		return "<calling convention: %s %s>" % (self.arch.name, self.name)

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
			log.log_error(traceback.format_exc())
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
			log.log_error(traceback.format_exc())
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
			log.log_error(traceback.format_exc())
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
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _free_register_list(self, ctxt, regs):
		try:
			buf = ctypes.cast(regs, ctypes.c_void_p)
			if buf.value not in self._pending_reg_lists:
				raise ValueError("freeing register list that wasn't allocated")
			del self._pending_reg_lists[buf.value]
		except:
			log.log_error(traceback.format_exc())

	def _arg_regs_share_index(self, ctxt):
		try:
			return self.__class__.arg_regs_share_index
		except:
			log.log_error(traceback.format_exc())
			return False

	def _stack_reserved_for_arg_regs(self, ctxt):
		try:
			return self.__class__.stack_reserved_for_arg_regs
		except:
			log.log_error(traceback.format_exc())
			return False

	def _stack_adjusted_on_return(self, ctxt):
		try:
			return self.__class__.stack_adjusted_on_return
		except:
			log.log_error(traceback.format_exc())
			return False

	def _get_int_return_reg(self, ctxt):
		try:
			return self.arch.regs[self.__class__.int_return_reg].index
		except:
			log.log_error(traceback.format_exc())
			return False

	def _get_high_int_return_reg(self, ctxt):
		try:
			if self.__class__.high_int_return_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.high_int_return_reg].index
		except:
			log.log_error(traceback.format_exc())
			return False

	def _get_float_return_reg(self, ctxt):
		try:
			if self.__class__.float_return_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.float_int_return_reg].index
		except:
			log.log_error(traceback.format_exc())
			return False

	def _get_global_pointer_reg(self, ctxt):
		try:
			if self.__class__.global_pointer_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.global_pointer_reg].index
		except:
			log.log_error(traceback.format_exc())
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
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_incoming_reg_value(self, ctxt, reg, func, result):
		try:
			func_obj = binaryninja.function.Function(handle = core.BNNewFunctionReference(func))
			reg_name = self.arch.get_reg_name(reg)
			api_obj = self.perform_get_incoming_reg_value(reg_name, func_obj)._to_api_object()
		except:
			log.log_error(traceback.format_exc())
			api_obj = binaryninja.function.RegisterValue()._to_api_object()
		result[0].state = api_obj.state
		result[0].value = api_obj.value

	def _get_incoming_flag_value(self, ctxt, reg, func, result):
		try:
			func_obj = binaryninja.function.Function(handle = core.BNNewFunctionReference(func))
			reg_name = self.arch.get_reg_name(reg)
			api_obj = self.perform_get_incoming_flag_value(reg_name, func_obj)._to_api_object()
		except:
			log.log_error(traceback.format_exc())
			api_obj = binaryninja.function.RegisterValue()._to_api_object()
		result[0].state = api_obj.state
		result[0].value = api_obj.value

	def _get_incoming_var_for_parameter_var(self, ctxt, in_var, func, result):
		try:
			if func is None:
				func_obj = None
			else:
				func_obj = binaryninja.function.Function(handle = core.BNNewFunctionReference(func))
			in_var_obj = binaryninja.function.Variable(func_obj, in_var[0].type, in_var[0].index, in_var[0].storage)
			out_var = self.perform_get_incoming_var_for_parameter_var(in_var_obj, func_obj)
			result[0].type = out_var.source_type
			result[0].index = out_var.index
			result[0].storage = out_var.storage
		except:
			log.log_error(traceback.format_exc())
			result[0].type = in_var[0].type
			result[0].index = in_var[0].index
			result[0].storage = in_var[0].storage

	def _get_parameter_var_for_incoming_var(self, ctxt, in_var, func, result):
		try:
			if func is None:
				func_obj = None
			else:
				func_obj = binaryninja.function.Function(handle = core.BNNewFunctionReference(func))
			in_var_obj = binaryninja.function.Variable(func_obj, in_var[0].type, in_var[0].index, in_var[0].storage)
			out_var = self.perform_get_parameter_var_for_incoming_var(in_var_obj, func_obj)
			result[0].type = out_var.source_type
			result[0].index = out_var.index
			result[0].storage = out_var.storage
		except:
			log.log_error(traceback.format_exc())
			result[0].type = in_var[0].type
			result[0].index = in_var[0].index
			result[0].storage = in_var[0].storage

	def perform_get_incoming_reg_value(self, reg, func):
		reg_stack = self.arch.get_reg_stack_for_reg(reg)
		if reg_stack is not None:
			if reg == self.arch.reg_stacks[reg_stack].stack_top_reg:
				return binaryninja.function.RegisterValue.constant(0)
		return binaryninja.function.RegisterValue()

	def perform_get_incoming_flag_value(self, reg, func):
		return binaryninja.function.RegisterValue()

	def perform_get_incoming_var_for_parameter_var(self, in_var, func):
		in_buf = core.BNVariable()
		in_buf.type = in_var.source_type
		in_buf.index = in_var.index
		in_buf.storage = in_var.storage
		out_var = core.BNGetDefaultIncomingVariableForParameterVariable(self.handle, in_buf)
		name = None
		if (func is not None) and (out_var.type == VariableSourceType.RegisterVariableSourceType):
			name = func.arch.get_reg_name(out_var.storage)
		return binaryninja.function.Variable(func, out_var.type, out_var.index, out_var.storage, name)

	def perform_get_parameter_var_for_incoming_var(self, in_var, func):
		in_buf = core.BNVariable()
		in_buf.type = in_var.source_type
		in_buf.index = in_var.index
		in_buf.storage = in_var.storage
		out_var = core.BNGetDefaultParameterVariableForIncomingVariable(self.handle, in_buf)
		return binaryninja.function.Variable(func, out_var.type, out_var.index, out_var.storage)

	def with_confidence(self, confidence):
		return CallingConvention(self.arch, handle = core.BNNewCallingConventionReference(self.handle),
			confidence = confidence)

	def get_incoming_reg_value(self, reg, func):
		reg_num = self.arch.get_reg_index(reg)
		func_handle = None
		if func is not None:
			func_handle = func.handle
		return binaryninja.function.RegisterValue(self.arch, core.BNGetIncomingRegisterValue(self.handle, reg_num, func_handle))

	def get_incoming_flag_value(self, flag, func):
		reg_num = self.arch.get_flag_index(flag)
		func_handle = None
		if func is not None:
			func_handle = func.handle
		return binaryninja.function.RegisterValue(self.arch, core.BNGetIncomingFlagValue(self.handle, reg_num, func_handle))

	def get_incoming_var_for_parameter_var(self, in_var, func):
		in_buf = core.BNVariable()
		in_buf.type = in_var.source_type
		in_buf.index = in_var.index
		in_buf.storage = in_var.storage
		if func is None:
			func_obj = None
		else:
			func_obj = func.handle
		out_var = core.BNGetIncomingVariableForParameterVariable(self.handle, in_buf, func_obj)
		name = None
		if (func is not None) and (out_var.type == VariableSourceType.RegisterVariableSourceType):
			name = func.arch.get_reg_name(out_var.storage)
		return binaryninja.function.Variable(func, out_var.type, out_var.index, out_var.storage, name)

	def get_parameter_var_for_incoming_var(self, in_var, func):
		in_buf = core.BNVariable()
		in_buf.type = in_var.source_type
		in_buf.index = in_var.index
		in_buf.storage = in_var.storage
		if func is None:
			func_obj = None
		else:
			func_obj = func.handle
		out_var = core.BNGetParameterVariableForIncomingVariable(self.handle, in_buf, func_obj)
		return binaryninja.function.Variable(func, out_var.type, out_var.index, out_var.storage)

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value
