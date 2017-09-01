# Copyright (c) 2015-2017 Vector 35 LLC
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
import _binaryninjacore as core
import architecture
import log
import types
import function
import binaryview


class CallingConvention(object):
	name = None
	caller_saved_regs = []
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

	def __init__(self, arch=None, name=None, handle=None, confidence=types.max_confidence):
		if handle is None:
			if arch is None or name is None:
				raise ValueError("Must specify either handle or architecture and name")
			self.arch = arch
			self._pending_reg_lists = {}
			self._cb = core.BNCustomCallingConvention()
			self._cb.context = 0
			self._cb.getCallerSavedRegisters = self._cb.getCallerSavedRegisters.__class__(self._get_caller_saved_regs)
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
			self.handle = core.BNCreateCallingConvention(arch.handle, name, self._cb)
			self.__class__._registered_calling_conventions.append(self)
		else:
			self.handle = handle
			self.arch = architecture.Architecture(core.BNGetCallingConventionArchitecture(self.handle))
			self.__dict__["name"] = core.BNGetCallingConventionName(self.handle)
			self.__dict__["arg_regs_share_index"] = core.BNAreArgumentRegistersSharedIndex(self.handle)
			self.__dict__["stack_reserved_for_arg_regs"] = core.BNIsStackReservedForArgumentRegisters(self.handle)
			self.__dict__["stack_adjusted_on_return"] = core.BNIsStackAdjustedOnReturn(self.handle)

			count = ctypes.c_ulonglong()
			regs = core.BNGetCallerSavedRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in xrange(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["caller_saved_regs"] = result

			count = ctypes.c_ulonglong()
			regs = core.BNGetIntegerArgumentRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in xrange(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["int_arg_regs"] = result

			count = ctypes.c_ulonglong()
			regs = core.BNGetFloatArgumentRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in xrange(0, count.value):
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
			for i in xrange(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["implicitly_defined_regs"] = result

		self.confidence = confidence

	def __del__(self):
		core.BNFreeCallingConvention(self.handle)

	def __eq__(self, value):
		if not isinstance(value, CallingConvention):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, CallingConvention):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	def _get_caller_saved_regs(self, ctxt, count):
		try:
			regs = self.__class__.caller_saved_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in xrange(0, len(regs)):
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
			for i in xrange(0, len(regs)):
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
			for i in xrange(0, len(regs)):
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
			for i in xrange(0, len(regs)):
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
			func_obj = function.Function(binaryview.BinaryView(handle = core.BNGetFunctionData(func)),
				core.BNNewFunctionReference(func))
			reg_name = self.arch.get_reg_name(reg)
			api_obj = self.perform_get_incoming_reg_value(reg_name, func_obj)._to_api_object()
		except:
			log.log_error(traceback.format_exc())
			api_obj = function.RegisterValue()._to_api_object()
		result[0].state = api_obj.state
		result[0].value = api_obj.value

	def _get_incoming_flag_value(self, ctxt, reg, func, result):
		try:
			func_obj = function.Function(binaryview.BinaryView(handle = core.BNGetFunctionData(func)),
				core.BNNewFunctionReference(func))
			reg_name = self.arch.get_reg_name(reg)
			api_obj = self.perform_get_incoming_flag_value(reg_name, func_obj)._to_api_object()
		except:
			log.log_error(traceback.format_exc())
			api_obj = function.RegisterValue()._to_api_object()
		result[0].state = api_obj.state
		result[0].value = api_obj.value

	def __repr__(self):
		return "<calling convention: %s %s>" % (self.arch.name, self.name)

	def __str__(self):
		return self.name

	def perform_get_incoming_reg_value(self, reg, func):
		return function.RegisterValue()

	def perform_get_incoming_flag_value(self, reg, func):
		return function.RegisterValue()

	def with_confidence(self, confidence):
		return CallingConvention(self.arch, handle = core.BNNewCallingConventionReference(self.handle),
			confidence = confidence)

	def get_incoming_reg_value(self, reg, func):
		reg_num = self.arch.get_reg_index(reg)
		func_handle = None
		if func is not None:
			func_handle = func.handle
		return function.RegisterValue(self.arch, core.BNGetIncomingRegisterValue(self.handle, reg_num, func_handle))

	def get_incoming_flag_value(self, flag, func):
		reg_num = self.arch.get_flag_index(flag)
		func_handle = None
		if func is not None:
			func_handle = func.handle
		return function.RegisterValue(self.arch, core.BNGetIncomingFlagValue(self.handle, reg_num, func_handle))
