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

import threading
import traceback
import ctypes

# Binary Ninja components
import _binaryninjacore as core
from enums import (FunctionGraphType, BranchType, SymbolType, InstructionTextTokenType,
	HighlightStandardColor, HighlightColorStyle, RegisterValueType, ImplicitRegisterExtend,
	DisassemblyOption, IntegerDisplayType, InstructionTextTokenContext, VariableSourceType)
import architecture
import platform
import highlight
import associateddatastore
import types
import basicblock
import lowlevelil
import mediumlevelil
import binaryview
import log
import callingconvention


class LookupTableEntry(object):
	def __init__(self, from_values, to_value):
		self.from_values = from_values
		self.to_value = to_value

	def __repr__(self):
		return "[%s] -> %#x" % (', '.join(["%#x" % i for i in self.from_values]), self.to_value)


class RegisterValue(object):
	def __init__(self, arch = None, value = None, confidence = types.max_confidence):
		if value is None:
			self.type = RegisterValueType.UndeterminedValue
		else:
			self.type = RegisterValueType(value.state)
			self.is_constant = False
			if value.state == RegisterValueType.EntryValue:
				self.arch = arch
				if arch is not None:
					self.reg = arch.get_reg_name(value.value)
				else:
					self.reg = value.value
			elif (value.state == RegisterValueType.ConstantValue) or (value.state == RegisterValueType.ConstantPointerValue):
				self.value = value.value
				self.is_constant = True
			elif value.state == RegisterValueType.StackFrameOffset:
				self.offset = value.value
			elif value.state == RegisterValueType.ImportedAddressValue:
				self.value = value.value
		self.confidence = confidence

	def __repr__(self):
		if self.type == RegisterValueType.EntryValue:
			return "<entry %s>" % self.reg
		if self.type == RegisterValueType.ConstantValue:
			return "<const %#x>" % self.value
		if self.type == RegisterValueType.ConstantPointerValue:
			return "<const ptr %#x>" % self.value
		if self.type == RegisterValueType.StackFrameOffset:
			return "<stack frame offset %#x>" % self.offset
		if self.type == RegisterValueType.ReturnAddressValue:
			return "<return address>"
		if self.type == RegisterValueType.ImportedAddressValue:
			return "<imported address from entry %#x>" % self.value
		return "<undetermined>"

	def _to_api_object(self):
		result = core.BNRegisterValue()
		result.state = self.type
		result.value = 0
		if self.type == RegisterValueType.EntryValue:
			if self.arch is not None:
				result.value = self.arch.get_reg_index(self.reg)
			else:
				result.value = self.reg
		elif (self.type == RegisterValueType.ConstantValue) or (self.type == RegisterValueType.ConstantPointerValue):
			result.value = self.value
		elif self.type == RegisterValueType.StackFrameOffset:
			result.value = self.offset
		elif self.type == RegisterValueType.ImportedAddressValue:
			result.value = self.value
		return result


class ValueRange(object):
	def __init__(self, start, end, step):
		self.start = start
		self.end = end
		self.step = step

	def __repr__(self):
		if self.step == 1:
			return "<range: %#x to %#x>" % (self.start, self.end)
		return "<range: %#x to %#x, step %#x>" % (self.start, self.end, self.step)


class PossibleValueSet(object):
	def __init__(self, arch, value):
		self.type = RegisterValueType(value.state)
		if value.state == RegisterValueType.EntryValue:
			self.reg = arch.get_reg_name(value.value)
		elif value.state == RegisterValueType.ConstantValue:
			self.value = value.value
		elif value.state == RegisterValueType.StackFrameOffset:
			self.offset = value.value
		elif value.state == RegisterValueType.SignedRangeValue:
			self.offset = value.value
			self.ranges = []
			for i in xrange(0, value.count):
				start = value.ranges[i].start
				end = value.ranges[i].end
				step = value.ranges[i].step
				if start & (1 << 63):
					start |= ~((1 << 63) - 1)
				if end & (1 << 63):
					end |= ~((1 << 63) - 1)
				self.ranges.append(ValueRange(start, end, step))
		elif value.state == RegisterValueType.UnsignedRangeValue:
			self.offset = value.value
			self.ranges = []
			for i in xrange(0, value.count):
				start = value.ranges[i].start
				end = value.ranges[i].end
				step = value.ranges[i].step
				self.ranges.append(ValueRange(start, end, step))
		elif value.state == RegisterValueType.LookupTableValue:
			self.table = []
			self.mapping = {}
			for i in xrange(0, value.count):
				from_list = []
				for j in xrange(0, value.table[i].fromCount):
					from_list.append(value.table[i].fromValues[j])
					self.mapping[value.table[i].fromValues[j]] = value.table[i].toValue
				self.table.append(LookupTableEntry(from_list, value.table[i].toValue))
		elif (value.state == RegisterValueType.InSetOfValues) or (value.state == RegisterValueType.NotInSetOfValues):
			self.values = set()
			for i in xrange(0, value.count):
				self.values.add(value.valueSet[i])

	def __repr__(self):
		if self.type == RegisterValueType.EntryValue:
			return "<entry %s>" % self.reg
		if self.type == RegisterValueType.ConstantValue:
			return "<const %#x>" % self.value
		if self.type == RegisterValueType.StackFrameOffset:
			return "<stack frame offset %#x>" % self.offset
		if self.type == RegisterValueType.SignedRangeValue:
			return "<signed ranges: %s>" % repr(self.ranges)
		if self.type == RegisterValueType.UnsignedRangeValue:
			return "<unsigned ranges: %s>" % repr(self.ranges)
		if self.type == RegisterValueType.LookupTableValue:
			return "<table: %s>" % ', '.join([repr(i) for i in self.table])
		if self.type == RegisterValueType.InSetOfValues:
			return "<in %s>" % repr(self.values)
		if self.type == RegisterValueType.NotInSetOfValues:
			return "<not in %s>" % repr(self.values)
		if self.type == RegisterValueType.ReturnAddressValue:
			return "<return address>"
		return "<undetermined>"


class StackVariableReference(object):
	def __init__(self, src_operand, t, name, var, ref_ofs, size):
		self.source_operand = src_operand
		self.type = t
		self.name = name
		self.var = var
		self.referenced_offset = ref_ofs
		self.size = size
		if self.source_operand == 0xffffffff:
			self.source_operand = None

	def __repr__(self):
		if self.source_operand is None:
			if self.referenced_offset != self.var.storage:
				return "<ref to %s%+#x>" % (self.name, self.referenced_offset - self.var.storage)
			return "<ref to %s>" % self.name
		if self.referenced_offset != self.var.storage:
			return "<operand %d ref to %s%+#x>" % (self.source_operand, self.name, self.var.storage)
		return "<operand %d ref to %s>" % (self.source_operand, self.name)


class Variable(object):
	def __init__(self, func, source_type, index, storage, name = None, var_type = None):
		self.function = func
		self.source_type = VariableSourceType(source_type)
		self.index = index
		self.storage = storage

		var = core.BNVariable()
		var.type = source_type
		var.index = index
		var.storage = storage
		self.identifier = core.BNToVariableIdentifier(var)

		if name is None:
			name = core.BNGetVariableName(func.handle, var)
		if var_type is None:
			var_type_conf = core.BNGetVariableType(func.handle, var)
			if var_type_conf.type:
				var_type = types.Type(var_type_conf.type, platform = func.platform, confidence = var_type_conf.confidence)
			else:
				var_type = None

		self.name = name
		self.type = var_type

	@classmethod
	def from_identifier(self, func, identifier, name = None, var_type = None):
		var = core.BNFromVariableIdentifier(identifier)
		return Variable(func, VariableSourceType(var.type), var.index, var.storage, name, var_type)

	def __repr__(self):
		if self.type is None:
			return "<var %s>" % self.name
		return "<var %s %s%s>" % (self.type.get_string_before_name(), self.name, self.type.get_string_after_name())

	def __str__(self):
		return self.name

	def __eq__(self, other):
		return self.identifier == other.identifier

	def __hash__(self):
		return hash(self.identifier)


class ConstantReference(object):
	def __init__(self, val, size, ptr, intermediate):
		self.value = val
		self.size = size
		self.pointer = ptr
		self.intermediate = intermediate

	def __repr__(self):
		if self.pointer:
			return "<constant pointer %#x>" % self.value
		if self.size == 0:
			return "<constant %#x>" % self.value
		return "<constant %#x size %d>" % (self.value, self.size)


class IndirectBranchInfo(object):
	def __init__(self, source_arch, source_addr, dest_arch, dest_addr, auto_defined):
		self.source_arch = source_arch
		self.source_addr = source_addr
		self.dest_arch = dest_arch
		self.dest_addr = dest_addr
		self.auto_defined = auto_defined

	def __repr__(self):
		return "<branch %s:%#x -> %s:%#x>" % (self.source_arch.name, self.source_addr, self.dest_arch.name, self.dest_addr)


class ParameterVariables(object):
	def __init__(self, var_list, confidence = types.max_confidence):
		self.vars = var_list
		self.confidence = confidence

	def __repr__(self):
		return repr(self.vars)

	def __iter__(self):
		for var in self.vars:
			yield var

	def __getitem__(self, idx):
		return self.vars[idx]

	def __len__(self):
		return len(self.vars)

	def with_confidence(self, confidence):
		return ParameterVariables(list(self.vars), confidence = confidence)


class _FunctionAssociatedDataStore(associateddatastore._AssociatedDataStore):
	_defaults = {}


class Function(object):
	_associated_data = {}

	def __init__(self, view, handle):
		self._view = view
		self.handle = core.handle_of_type(handle, core.BNFunction)
		self._advanced_analysis_requests = 0

	def __del__(self):
		if self._advanced_analysis_requests > 0:
			core.BNReleaseAdvancedFunctionAnalysisDataMultiple(self.handle, self._advanced_analysis_requests)
		core.BNFreeFunction(self.handle)

	def __eq__(self, value):
		if not isinstance(value, Function):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, Function):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	def __hash__(self):
		return hash((self.start, self.arch.name, self.platform.name))

	@classmethod
	def _unregister(cls, func):
		handle = ctypes.cast(func, ctypes.c_void_p)
		if handle.value in cls._associated_data:
			del cls._associated_data[handle.value]

	@classmethod
	def set_default_session_data(cls, name, value):
		_FunctionAssociatedDataStore.set_default(name, value)

	@property
	def name(self):
		"""Symbol name for the function"""
		return self.symbol.name

	@name.setter
	def name(self, value):
		if value is None:
			if self.symbol is not None:
				self.view.undefine_user_symbol(self.symbol)
		else:
			symbol = types.Symbol(SymbolType.FunctionSymbol, self.start, value)
			self.view.define_user_symbol(symbol)

	@property
	def view(self):
		"""Function view (read-only)"""
		return self._view

	@property
	def arch(self):
		"""Function architecture (read-only)"""
		arch = core.BNGetFunctionArchitecture(self.handle)
		if arch is None:
			return None
		return architecture.Architecture(arch)

	@property
	def platform(self):
		"""Function platform (read-only)"""
		plat = core.BNGetFunctionPlatform(self.handle)
		if plat is None:
			return None
		return platform.Platform(None, handle = plat)

	@property
	def start(self):
		"""Function start (read-only)"""
		return core.BNGetFunctionStart(self.handle)

	@property
	def symbol(self):
		"""Function symbol(read-only)"""
		sym = core.BNGetFunctionSymbol(self.handle)
		if sym is None:
			return None
		return types.Symbol(None, None, None, handle = sym)

	@property
	def auto(self):
		"""Whether function was automatically discovered (read-only)"""
		return core.BNWasFunctionAutomaticallyDiscovered(self.handle)

	@property
	def can_return(self):
		"""Whether function can return"""
		result = core.BNCanFunctionReturn(self.handle)
		return types.BoolWithConfidence(result.value, confidence = result.confidence)

	@can_return.setter
	def can_return(self, value):
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if hasattr(value, 'confidence'):
			bc.confidence = value.confidence
		else:
			bc.confidence = types.max_confidence
		core.BNSetUserFunctionCanReturn(self.handle, bc)

	@property
	def explicitly_defined_type(self):
		"""Whether function has explicitly defined types (read-only)"""
		return core.BNFunctionHasExplicitlyDefinedType(self.handle)

	@property
	def needs_update(self):
		"""Whether the function has analysis that needs to be updated (read-only)"""
		return core.BNIsFunctionUpdateNeeded(self.handle)

	@property
	def basic_blocks(self):
		"""List of basic blocks (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionBasicBlockList(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(basicblock.BasicBlock(self._view, core.BNNewBasicBlockReference(blocks[i])))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def comments(self):
		"""Dict of comments (read-only)"""
		count = ctypes.c_ulonglong()
		addrs = core.BNGetCommentedAddresses(self.handle, count)
		result = {}
		for i in xrange(0, count.value):
			result[addrs[i]] = self.get_comment_at(addrs[i])
		core.BNFreeAddressList(addrs)
		return result

	@property
	def low_level_il(self):
		"""returns LowLevelILFunction used to represent Function low level IL (read-only)"""
		return lowlevelil.LowLevelILFunction(self.arch, core.BNGetFunctionLowLevelIL(self.handle), self)

	@property
	def lifted_il(self):
		"""returns LowLevelILFunction used to represent lifted IL (read-only)"""
		return lowlevelil.LowLevelILFunction(self.arch, core.BNGetFunctionLiftedIL(self.handle), self)

	@property
	def medium_level_il(self):
		"""Function medium level IL (read-only)"""
		return mediumlevelil.MediumLevelILFunction(self.arch, core.BNGetFunctionMediumLevelIL(self.handle), self)

	@property
	def function_type(self):
		"""Function type object"""
		return types.Type(core.BNGetFunctionType(self.handle), platform = self.platform)

	@function_type.setter
	def function_type(self, value):
		self.set_user_type(value)

	@property
	def stack_layout(self):
		"""List of function stack variables (read-only)"""
		count = ctypes.c_ulonglong()
		v = core.BNGetStackLayout(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(Variable(self, v[i].var.type, v[i].var.index, v[i].var.storage, v[i].name,
				types.Type(handle = core.BNNewTypeReference(v[i].type), platform = self.platform, confidence = v[i].typeConfidence)))
		result.sort(key = lambda x: x.identifier)
		core.BNFreeVariableList(v, count.value)
		return result

	@property
	def vars(self):
		"""List of function variables (read-only)"""
		count = ctypes.c_ulonglong()
		v = core.BNGetFunctionVariables(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(Variable(self, v[i].var.type, v[i].var.index, v[i].var.storage, v[i].name,
				types.Type(handle = core.BNNewTypeReference(v[i].type), platform = self.platform, confidence = v[i].typeConfidence)))
		result.sort(key = lambda x: x.identifier)
		core.BNFreeVariableList(v, count.value)
		return result

	@property
	def indirect_branches(self):
		"""List of indirect branches (read-only)"""
		count = ctypes.c_ulonglong()
		branches = core.BNGetIndirectBranches(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(IndirectBranchInfo(architecture.Architecture(branches[i].sourceArch), branches[i].sourceAddr, architecture.Architecture(branches[i].destArch), branches[i].destAddr, branches[i].autoDefined))
		core.BNFreeIndirectBranchList(branches)
		return result

	@property
	def session_data(self):
		"""Dictionary object where plugins can store arbitrary data associated with the function"""
		handle = ctypes.cast(self.handle, ctypes.c_void_p)
		if handle.value not in Function._associated_data:
			obj = _FunctionAssociatedDataStore()
			Function._associated_data[handle.value] = obj
			return obj
		else:
			return Function._associated_data[handle.value]

	@property
	def analysis_performance_info(self):
		count = ctypes.c_ulonglong()
		info = core.BNGetFunctionAnalysisPerformanceInfo(self.handle, count)
		result = {}
		for i in xrange(0, count.value):
			result[info[i].name] = info[i].seconds
		core.BNFreeAnalysisPerformanceInfo(info, count.value)
		return result

	@property
	def type_tokens(self):
		"""Text tokens for this function's prototype"""
		return self.get_type_tokens()[0].tokens

	@property
	def return_type(self):
		"""Return type of the function"""
		result = core.BNGetFunctionReturnType(self.handle)
		if not result.type:
			return None
		return types.Type(result.type, platform = self.platform, confidence = result.confidence)

	@return_type.setter
	def return_type(self, value):
		type_conf = core.BNTypeWithConfidence()
		if value is None:
			type_conf.type = None
			type_conf.confidence = 0
		else:
			type_conf.type = value.handle
			type_conf.confidence = value.confidence
		core.BNSetUserFunctionReturnType(self.handle, type_conf)

	@property
	def calling_convention(self):
		"""Calling convention used by the function"""
		result = core.BNGetFunctionCallingConvention(self.handle)
		if not result.convention:
			return None
		return callingconvention.CallingConvention(None, handle = result.convention, confidence = result.confidence)

	@calling_convention.setter
	def calling_convention(self, value):
		conv_conf = core.BNCallingConventionWithConfidence()
		if value is None:
			conv_conf.convention = None
			conv_conf.confidence = 0
		else:
			conv_conf.convention = value.handle
			conv_conf.confidence = value.confidence
		core.BNSetUserFunctionCallingConvention(self.handle, conv_conf)

	@property
	def parameter_vars(self):
		"""List of variables for the incoming function parameters"""
		result = core.BNGetFunctionParameterVariables(self.handle)
		var_list = []
		for i in xrange(0, result.count):
			var_list.append(Variable(self, result.vars[i].type, result.vars[i].index, result.vars[i].storage))
		confidence = result.confidence
		core.BNFreeParameterVariables(result)
		return ParameterVariables(var_list, confidence = confidence)

	@parameter_vars.setter
	def parameter_vars(self, value):
		if value is None:
			var_list = []
		else:
			var_list = list(value)
		var_conf = core.BNParameterVariablesWithConfidence()
		var_conf.vars = (core.BNVariable * len(var_list))()
		var_conf.count = len(var_list)
		for i in xrange(0, len(var_list)):
			var_conf.vars[i].type = var_list[i].source_type
			var_conf.vars[i].index = var_list[i].index
			var_conf.vars[i].storage = var_list[i].storage
		if value is None:
			var_conf.confidence = 0
		elif hasattr(value, 'confidence'):
			var_conf.confidence = value.confidence
		else:
			var_conf.confidence = types.max_confidence
		core.BNSetUserFunctionParameterVariables(self.handle, var_conf)

	@property
	def has_variable_arguments(self):
		"""Whether the function takes a variable number of arguments"""
		result = core.BNFunctionHasVariableArguments(self.handle)
		return types.BoolWithConfidence(result.value, confidence = result.confidence)

	@has_variable_arguments.setter
	def has_variable_arguments(self, value):
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if hasattr(value, 'confidence'):
			bc.confidence = value.confidence
		else:
			bc.confidence = types.max_confidence
		core.BNSetUserFunctionHasVariableArguments(self.handle, bc)

	@property
	def stack_adjustment(self):
		"""Number of bytes removed from the stack after return"""
		result = core.BNGetFunctionStackAdjustment(self.handle)
		return types.SizeWithConfidence(result.value, confidence = result.confidence)

	@stack_adjustment.setter
	def stack_adjustment(self, value):
		sc = core.BNSizeWithConfidence()
		sc.value = int(value)
		if hasattr(value, 'confidence'):
			sc.confidence = value.confidence
		else:
			sc.confidence = types.max_confidence
		core.BNSetUserFunctionStackAdjustment(self.handle, sc)

	@property
	def clobbered_regs(self):
		"""Registers that are modified by this function"""
		result = core.BNGetFunctionClobberedRegisters(self.handle)
		reg_set = []
		for i in xrange(0, result.count):
			reg_set.append(self.arch.get_reg_name(result.regs[i]))
		regs = types.RegisterSet(reg_set, confidence = result.confidence)
		core.BNFreeClobberedRegisters(result)
		return regs

	@clobbered_regs.setter
	def clobbered_regs(self, value):
		regs = core.BNRegisterSetWithConfidence()
		regs.regs = (ctypes.c_uint * len(value))()
		regs.count = len(value)
		for i in xrange(0, len(value)):
			regs.regs[i] = self.arch.get_reg_index(value[i])
		if hasattr(value, 'confidence'):
			regs.confidence = value.confidence
		else:
			regs.confidence = types.max_confidence
		core.BNSetUserFunctionClobberedRegisters(self.handle, regs)

	@property
	def global_pointer_value(self):
		"""Discovered value of the global pointer register, if the function uses one (read-only)"""
		result = core.BNGetFunctionGlobalPointerValue(self.handle)
		return RegisterValue(self.arch, result.value, confidence = result.confidence)

	@property
	def comment(self):
		"""Gets the comment for the current function"""
		return core.BNGetFunctionComment(self.handle)

	@comment.setter
	def comment(self, comment):
		"""Sets a comment for the current function"""
		return core.BNSetFunctionComment(self.handle, comment)

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionBasicBlockList(self.handle, count)
		try:
			for i in xrange(0, count.value):
				yield basicblock.BasicBlock(self._view, core.BNNewBasicBlockReference(blocks[i]))
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<func: %s@%#x>" % (arch.name, self.start)
		else:
			return "<func: %#x>" % self.start

	def mark_recent_use(self):
		core.BNMarkFunctionAsRecentlyUsed(self.handle)

	def get_comment_at(self, addr):
		return core.BNGetCommentForAddress(self.handle, addr)

	def set_comment(self, addr, comment):
		"""Deprecated use set_comment_at instead"""
		core.BNSetCommentForAddress(self.handle, addr, comment)

	def set_comment_at(self, addr, comment):
		"""
		``set_comment_at`` sets a comment for the current function at the address specified

		:param addr int: virtual address within the current function to apply the comment to
		:param comment str: string comment to apply
		:rtype: None
		:Example:

			>>> current_function.set_comment_at(here, "hi")

		"""
		core.BNSetCommentForAddress(self.handle, addr, comment)

	def get_low_level_il_at(self, addr, arch=None):
		"""
		``get_low_level_il_at`` gets the LowLevelILInstruction corresponding to the given virtual address

		:param int addr: virtual address of the function to be queried
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: LowLevelILInstruction
		:Example:

			>>> func = bv.functions[0]
			>>> func.get_low_level_il_at(func.start)
			<il: push(rbp)>
		"""
		if arch is None:
			arch = self.arch
		return self.low_level_il[core.BNGetLowLevelILForInstruction(self.handle, arch.handle, addr)]

	def get_low_level_il_exits_at(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		exits = core.BNGetLowLevelILExitsForInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(exits[i])
		core.BNFreeILInstructionList(exits)
		return result

	def get_reg_value_at(self, addr, reg, arch=None):
		"""
		``get_reg_value_at`` gets the value the provided string register address corresponding to the given virtual address

		:param int addr: virtual address of the instruction to query
		:param str reg: string value of native register to query
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: function.RegisterValue
		:Example:

			>>> func.get_reg_value_at(0x400dbe, 'rdi')
			<const 0x2>
		"""
		if arch is None:
			arch = self.arch
		reg = arch.get_reg_index(reg)
		value = core.BNGetRegisterValueAtInstruction(self.handle, arch.handle, addr, reg)
		result = RegisterValue(arch, value)
		return result

	def get_reg_value_after(self, addr, reg, arch=None):
		"""
		``get_reg_value_after`` gets the value instruction address corresponding to the given virtual address

		:param int addr: virtual address of the instruction to query
		:param str reg: string value of native register to query
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: function.RegisterValue
		:Example:

			>>> func.get_reg_value_after(0x400dbe, 'rdi')
			<undetermined>
		"""
		if arch is None:
			arch = self.arch
		reg = arch.get_reg_index(reg)
		value = core.BNGetRegisterValueAfterInstruction(self.handle, arch.handle, addr, reg)
		result = RegisterValue(arch, value)
		return result

	def get_stack_contents_at(self, addr, offset, size, arch=None):
		"""
		``get_stack_contents_at`` returns the RegisterValue for the item on the stack in the current function at the
		given virtual address ``addr``, stack offset ``offset`` and size of ``size``. Optionally specifying the architecture.

		:param int addr: virtual address of the instruction to query
		:param int offset: stack offset base of stack
		:param int size: size of memory to query
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: function.RegisterValue

		.. note:: Stack base is zero on entry into the function unless the architecture places the return address on the
		stack as in (x86/x86_64) where the stack base will start at address_size

		:Example:

			>>> func.get_stack_contents_at(0x400fad, -16, 4)
			<range: 0x8 to 0xffffffff>
		"""
		if arch is None:
			arch = self.arch
		value = core.BNGetStackContentsAtInstruction(self.handle, arch.handle, addr, offset, size)
		result = RegisterValue(arch, value)
		return result

	def get_stack_contents_after(self, addr, offset, size, arch=None):
		if arch is None:
			arch = self.arch
		value = core.BNGetStackContentsAfterInstruction(self.handle, arch.handle, addr, offset, size)
		result = RegisterValue(arch, value)
		return result

	def get_parameter_at(self, addr, func_type, i, arch=None):
		if arch is None:
			arch = self.arch
		if func_type is not None:
			func_type = func_type.handle
		value = core.BNGetParameterValueAtInstruction(self.handle, arch.handle, addr, func_type, i)
		result = RegisterValue(arch, value)
		return result

	def get_parameter_at_low_level_il_instruction(self, instr, func_type, i):
		if func_type is not None:
			func_type = func_type.handle
		value = core.BNGetParameterValueAtLowLevelILInstruction(self.handle, instr, func_type, i)
		result = RegisterValue(self.arch, value)
		return result

	def get_regs_read_by(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		regs = core.BNGetRegistersReadByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_regs_written_by(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		regs = core.BNGetRegistersWrittenByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_stack_vars_referenced_by(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		refs = core.BNGetStackVariablesReferencedByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			var_type = types.Type(core.BNNewTypeReference(refs[i].type), platform = self.platform, confidence = refs[i].typeConfidence)
			result.append(StackVariableReference(refs[i].sourceOperand, var_type,
				refs[i].name, Variable.from_identifier(self, refs[i].varIdentifier, refs[i].name, var_type),
				refs[i].referencedOffset, refs[i].size))
		core.BNFreeStackVariableReferenceList(refs, count.value)
		return result

	def get_constants_referenced_by(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		refs = core.BNGetConstantsReferencedByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(ConstantReference(refs[i].value, refs[i].size, refs[i].pointer, refs[i].intermediate))
		core.BNFreeConstantReferenceList(refs)
		return result

	def get_lifted_il_at(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		return self.lifted_il[core.BNGetLiftedILForInstruction(self.handle, arch.handle, addr)]

	def get_lifted_il_flag_uses_for_definition(self, i, flag):
		flag = self.arch.get_flag_index(flag)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILFlagUsesForDefinition(self.handle, i, flag, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_lifted_il_flag_definitions_for_use(self, i, flag):
		flag = self.arch.get_flag_index(flag)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILFlagDefinitionsForUse(self.handle, i, flag, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_flags_read_by_lifted_il_instruction(self, i):
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsReadByLiftedILInstruction(self.handle, i, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self.arch._flags_by_index[flags[i]])
		core.BNFreeRegisterList(flags)
		return result

	def get_flags_written_by_lifted_il_instruction(self, i):
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsWrittenByLiftedILInstruction(self.handle, i, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self.arch._flags_by_index[flags[i]])
		core.BNFreeRegisterList(flags)
		return result

	def create_graph(self):
		return FunctionGraph(self._view, core.BNCreateFunctionGraph(self.handle))

	def apply_imported_types(self, sym):
		core.BNApplyImportedTypes(self.handle, sym.handle)

	def apply_auto_discovered_type(self, func_type):
		core.BNApplyAutoDiscoveredFunctionType(self.handle, func_type.handle)

	def set_auto_indirect_branches(self, source, branches, source_arch=None):
		if source_arch is None:
			source_arch = self.arch
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in xrange(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNSetAutoIndirectBranches(self.handle, source_arch.handle, source, branch_list, len(branches))

	def set_user_indirect_branches(self, source, branches, source_arch=None):
		if source_arch is None:
			source_arch = self.arch
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in xrange(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNSetUserIndirectBranches(self.handle, source_arch.handle, source, branch_list, len(branches))

	def get_indirect_branches_at(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		branches = core.BNGetIndirectBranchesAt(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(IndirectBranchInfo(architecture.Architecture(branches[i].sourceArch), branches[i].sourceAddr, architecture.Architecture(branches[i].destArch), branches[i].destAddr, branches[i].autoDefined))
		core.BNFreeIndirectBranchList(branches)
		return result

	def get_block_annotations(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong(0)
		lines = core.BNGetFunctionBlockAnnotations(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			tokens = []
			for j in xrange(0, lines[i].count):
				token_type = InstructionTextTokenType(lines[i].tokens[j].type)
				text = lines[i].tokens[j].text
				value = lines[i].tokens[j].value
				size = lines[i].tokens[j].size
				operand = lines[i].tokens[j].operand
				context = lines[i].tokens[j].context
				confidence = lines[i].tokens[j].confidence
				address = lines[i].tokens[j].address
				tokens.append(InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
			result.append(tokens)
		core.BNFreeInstructionTextLines(lines, count.value)
		return result

	def set_auto_type(self, value):
		core.BNSetFunctionAutoType(self.handle, value.handle)

	def set_user_type(self, value):
		core.BNSetFunctionUserType(self.handle, value.handle)

	def set_auto_return_type(self, value):
		type_conf = core.BNTypeWithConfidence()
		if value is None:
			type_conf.type = None
			type_conf.confidence = 0
		else:
			type_conf.type = value.handle
			type_conf.confidence = value.confidence
		core.BNSetAutoFunctionReturnType(self.handle, type_conf)

	def set_auto_calling_convention(self, value):
		conv_conf = core.BNCallingConventionWithConfidence()
		if value is None:
			conv_conf.convention = None
			conv_conf.confidence = 0
		else:
			conv_conf.convention = value.handle
			conv_conf.confidence = value.confidence
		core.BNSetAutoFunctionCallingConvention(self.handle, conv_conf)

	def set_auto_parameter_vars(self, value):
		if value is None:
			var_list = []
		else:
			var_list = list(value)
		var_conf = core.BNParameterVariablesWithConfidence()
		var_conf.vars = (core.BNVariable * len(var_list))()
		var_conf.count = len(var_list)
		for i in xrange(0, len(var_list)):
			var_conf.vars[i].type = var_list[i].source_type
			var_conf.vars[i].index = var_list[i].index
			var_conf.vars[i].storage = var_list[i].storage
		if value is None:
			var_conf.confidence = 0
		elif hasattr(value, 'confidence'):
			var_conf.confidence = value.confidence
		else:
			var_conf.confidence = types.max_confidence
		core.BNSetAutoFunctionParameterVariables(self.handle, var_conf)

	def set_auto_has_variable_arguments(self, value):
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if hasattr(value, 'confidence'):
			bc.confidence = value.confidence
		else:
			bc.confidence = types.max_confidence
		core.BNSetAutoFunctionHasVariableArguments(self.handle, bc)

	def set_auto_can_return(self, value):
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if hasattr(value, 'confidence'):
			bc.confidence = value.confidence
		else:
			bc.confidence = types.max_confidence
		core.BNSetAutoFunctionCanReturn(self.handle, bc)

	def set_auto_stack_adjustment(self, value):
		sc = core.BNSizeWithConfidence()
		sc.value = int(value)
		if hasattr(value, 'confidence'):
			sc.confidence = value.confidence
		else:
			sc.confidence = types.max_confidence
		core.BNSetAutoFunctionStackAdjustment(self.handle, sc)

	def set_auto_clobbered_regs(self, value):
		regs = core.BNRegisterSetWithConfidence()
		regs.regs = (ctypes.c_uint * len(value))()
		regs.count = len(value)
		for i in xrange(0, len(value)):
			regs.regs[i] = self.arch.get_reg_index(value[i])
		if hasattr(value, 'confidence'):
			regs.confidence = value.confidence
		else:
			regs.confidence = types.max_confidence
		core.BNSetAutoFunctionClobberedRegisters(self.handle, regs)

	def get_int_display_type(self, instr_addr, value, operand, arch=None):
		if arch is None:
			arch = self.arch
		return IntegerDisplayType(core.BNGetIntegerConstantDisplayType(self.handle, arch.handle, instr_addr, value, operand))

	def set_int_display_type(self, instr_addr, value, operand, display_type, arch=None):
		"""

		:param int instr_addr:
		:param int value:
		:param int operand:
		:param enums.IntegerDisplayType display_type:
		:param Architecture arch: (optional)
		"""
		if arch is None:
			arch = self.arch
		if isinstance(display_type, str):
			display_type = IntegerDisplayType[display_type]
		core.BNSetIntegerConstantDisplayType(self.handle, arch.handle, instr_addr, value, operand, display_type)

	def reanalyze(self):
		"""
		``reanalyze`` causes this functions to be reanalyzed. This function does not wait for the analysis to finish.

		:rtype: None
		"""
		core.BNReanalyzeFunction(self.handle)

	def request_advanced_analysis_data(self):
		core.BNRequestAdvancedFunctionAnalysisData(self.handle)
		self._advanced_analysis_requests += 1

	def release_advanced_analysis_data(self):
		core.BNReleaseAdvancedFunctionAnalysisData(self.handle)
		self._advanced_analysis_requests -= 1

	def get_basic_block_at(self, addr, arch=None):
		"""
		``get_basic_block_at`` returns the BasicBlock of the optionally specified Architecture ``arch`` at the given
		address ``addr``.

		:param int addr: Address of the BasicBlock to retrieve.
		:param Architecture arch: (optional) Architecture of the basic block if different from the Function's self.arch
		:Example:
			>>> current_function.get_basic_block_at(current_function.start)
			<block: x86_64@0x100000f30-0x100000f50>
		"""
		if arch is None:
			arch = self.arch
		block = core.BNGetFunctionBasicBlockAtAddress(self.handle, arch.handle, addr)
		if not block:
			return None
		return basicblock.BasicBlock(self._view, handle = block)

	def get_instr_highlight(self, addr, arch=None):
		"""
		:Example:
			>>> current_function.set_user_instr_highlight(here, highlight.HighlightColor(red=0xff, blue=0xff, green=0))
			>>> current_function.get_instr_highlight(here)
			<color: #ff00ff>
		"""
		if arch is None:
			arch = self.arch
		color = core.BNGetInstructionHighlight(self.handle, arch.handle, addr)
		if color.style == HighlightColorStyle.StandardHighlightColor:
			return highlight.HighlightColor(color = color.color, alpha = color.alpha)
		elif color.style == HighlightColorStyle.MixedHighlightColor:
			return highlight.HighlightColor(color = color.color, mix_color = color.mixColor, mix = color.mix, alpha = color.alpha)
		elif color.style == HighlightColorStyle.CustomHighlightColor:
			return highlight.HighlightColor(red = color.r, green = color.g, blue = color.b, alpha = color.alpha)
		return highlight.HighlightColor(color = HighlightStandardColor.NoHighlightColor)

	def set_auto_instr_highlight(self, addr, color, arch=None):
		"""
		``set_auto_instr_highlight`` highlights the instruction at the specified address with the supplied color

		..warning:: Use only in analysis plugins. Do not use in regular plugins, as colors won't be saved to the database.

		:param int addr: virtual address of the instruction to be highlighted
		:param HighlightStandardColor or highlight.HighlightColor color: Color value to use for highlighting
		:param Architecture arch: (optional) Architecture of the instruction if different from self.arch
		"""
		if arch is None:
			arch = self.arch
		if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
			raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
		if isinstance(color, HighlightStandardColor):
			color = highlight.HighlightColor(color = color)
		core.BNSetAutoInstructionHighlight(self.handle, arch.handle, addr, color._get_core_struct())

	def set_user_instr_highlight(self, addr, color, arch=None):
		"""
		``set_user_instr_highlight`` highlights the instruction at the specified address with the supplied color

		:param int addr: virtual address of the instruction to be highlighted
		:param HighlightStandardColor or highlight.HighlightColor color: Color value to use for highlighting
		:param Architecture arch: (optional) Architecture of the instruction if different from self.arch
		:Example:

			>>> current_function.set_user_instr_highlight(here, HighlightStandardColor.BlueHighlightColor)
			>>> current_function.set_user_instr_highlight(here, highlight.HighlightColor(red=0xff, blue=0xff, green=0))
		"""
		if arch is None:
			arch = self.arch
		if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
			raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
		if isinstance(color, HighlightStandardColor):
			color = highlight.HighlightColor(color)
		core.BNSetUserInstructionHighlight(self.handle, arch.handle, addr, color._get_core_struct())

	def create_auto_stack_var(self, offset, var_type, name):
		tc = core.BNTypeWithConfidence()
		tc.type = var_type.handle
		tc.confidence = var_type.confidence
		core.BNCreateAutoStackVariable(self.handle, offset, tc, name)

	def create_user_stack_var(self, offset, var_type, name):
		tc = core.BNTypeWithConfidence()
		tc.type = var_type.handle
		tc.confidence = var_type.confidence
		core.BNCreateUserStackVariable(self.handle, offset, tc, name)

	def delete_auto_stack_var(self, offset):
		core.BNDeleteAutoStackVariable(self.handle, offset)

	def delete_user_stack_var(self, offset):
		core.BNDeleteUserStackVariable(self.handle, offset)

	def create_auto_var(self, var, var_type, name, ignore_disjoint_uses = False):
		var_data = core.BNVariable()
		var_data.type = var.source_type
		var_data.index = var.index
		var_data.storage = var.storage
		tc = core.BNTypeWithConfidence()
		tc.type = var_type.handle
		tc.confidence = var_type.confidence
		core.BNCreateAutoVariable(self.handle, var_data, tc, name, ignore_disjoint_uses)

	def create_user_var(self, var, var_type, name, ignore_disjoint_uses = False):
		var_data = core.BNVariable()
		var_data.type = var.source_type
		var_data.index = var.index
		var_data.storage = var.storage
		tc = core.BNTypeWithConfidence()
		tc.type = var_type.handle
		tc.confidence = var_type.confidence
		core.BNCreateUserVariable(self.handle, var_data, tc, name, ignore_disjoint_uses)

	def delete_auto_var(self, var):
		var_data = core.BNVariable()
		var_data.type = var.source_type
		var_data.index = var.index
		var_data.storage = var.storage
		core.BNDeleteAutoVariable(self.handle, var_data)

	def delete_user_var(self, var):
		var_data = core.BNVariable()
		var_data.type = var.source_type
		var_data.index = var.index
		var_data.storage = var.storage
		core.BNDeleteUserVariable(self.handle, var_data)

	def get_stack_var_at_frame_offset(self, offset, addr, arch=None):
		if arch is None:
			arch = self.arch
		found_var = core.BNVariableNameAndType()
		if not core.BNGetStackVariableAtFrameOffset(self.handle, arch.handle, addr, offset, found_var):
			return None
		result = Variable(self, found_var.var.type, found_var.var.index, found_var.var.storage,
			found_var.name, types.Type(handle = core.BNNewTypeReference(found_var.type), platform = self.platform,
			confidence = found_var.typeConfidence))
		core.BNFreeVariableNameAndType(found_var)
		return result

	def get_type_tokens(self, settings=None):
		if settings is not None:
			settings = settings.handle
		count = ctypes.c_ulonglong()
		lines = core.BNGetFunctionTypeTokens(self.handle, settings, count)
		result = []
		for i in xrange(0, count.value):
			addr = lines[i].addr
			tokens = []
			for j in xrange(0, lines[i].count):
				token_type = InstructionTextTokenType(lines[i].tokens[j].type)
				text = lines[i].tokens[j].text
				value = lines[i].tokens[j].value
				size = lines[i].tokens[j].size
				operand = lines[i].tokens[j].operand
				context = lines[i].tokens[j].context
				confidence = lines[i].tokens[j].confidence
				address = lines[i].tokens[j].address
				tokens.append(InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
			result.append(DisassemblyTextLine(addr, tokens))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	def get_reg_value_at_exit(self, reg):
		result = core.BNGetFunctionRegisterValueAtExit(self.handle, self.arch.get_reg_index(reg))
		return RegisterValue(self.arch, result.value, confidence = result.confidence)


class AdvancedFunctionAnalysisDataRequestor(object):
	def __init__(self, func = None):
		self._function = func
		if self._function is not None:
			self._function.request_advanced_analysis_data()

	def __del__(self):
		if self._function is not None:
			self._function.release_advanced_analysis_data()

	@property
	def function(self):
		return self._function

	@function.setter
	def function(self, func):
		if self._function is not None:
			self._function.release_advanced_analysis_data()
		self._function = func
		if self._function is not None:
			self._function.request_advanced_analysis_data()

	def close(self):
		if self._function is not None:
			self._function.release_advanced_analysis_data()
		self._function = None


class DisassemblyTextLine(object):
	def __init__(self, addr, tokens):
		self.address = addr
		self.tokens = tokens

	def __str__(self):
		result = ""
		for token in self.tokens:
			result += token.text
		return result

	def __repr__(self):
		return "<%#x: %s>" % (self.address, str(self))


class FunctionGraphEdge(object):
	def __init__(self, branch_type, source, target, points, back_edge):
		self.type = BranchType(branch_type)
		self.source = source
		self.target = target
		self.points = points
		self.back_edge = back_edge

	def __repr__(self):
		return "<%s: %s>" % (self.type.name, repr(self.target))


class FunctionGraphBlock(object):
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		core.BNFreeFunctionGraphBlock(self.handle)

	def __eq__(self, value):
		if not isinstance(value, FunctionGraphBlock):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, FunctionGraphBlock):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	@property
	def basic_block(self):
		"""Basic block associated with this part of the function graph (read-only)"""
		block = core.BNGetFunctionGraphBasicBlock(self.handle)
		func = core.BNGetBasicBlockFunction(block)
		if func is None:
			core.BNFreeBasicBlock(block)
			block = None
		else:
			block = basicblock.BasicBlock(binaryview.BinaryView(handle = core.BNGetFunctionData(func)), block)
			core.BNFreeFunction(func)
		return block

	@property
	def arch(self):
		"""Function graph block architecture (read-only)"""
		arch = core.BNGetFunctionGraphBlockArchitecture(self.handle)
		if arch is None:
			return None
		return architecture.Architecture(arch)

	@property
	def start(self):
		"""Function graph block start (read-only)"""
		return core.BNGetFunctionGraphBlockStart(self.handle)

	@property
	def end(self):
		"""Function graph block end (read-only)"""
		return core.BNGetFunctionGraphBlockEnd(self.handle)

	@property
	def x(self):
		"""Function graph block X (read-only)"""
		return core.BNGetFunctionGraphBlockX(self.handle)

	@property
	def y(self):
		"""Function graph block Y (read-only)"""
		return core.BNGetFunctionGraphBlockY(self.handle)

	@property
	def width(self):
		"""Function graph block width (read-only)"""
		return core.BNGetFunctionGraphBlockWidth(self.handle)

	@property
	def height(self):
		"""Function graph block height (read-only)"""
		return core.BNGetFunctionGraphBlockHeight(self.handle)

	@property
	def lines(self):
		"""Function graph block list of lines (read-only)"""
		count = ctypes.c_ulonglong()
		lines = core.BNGetFunctionGraphBlockLines(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			addr = lines[i].addr
			tokens = []
			for j in xrange(0, lines[i].count):
				token_type = InstructionTextTokenType(lines[i].tokens[j].type)
				text = lines[i].tokens[j].text
				value = lines[i].tokens[j].value
				size = lines[i].tokens[j].size
				operand = lines[i].tokens[j].operand
				context = lines[i].tokens[j].context
				confidence = lines[i].tokens[j].confidence
				address = lines[i].tokens[j].address
				tokens.append(InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
			result.append(DisassemblyTextLine(addr, tokens))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	@property
	def outgoing_edges(self):
		"""Function graph block list of outgoing edges (read-only)"""
		count = ctypes.c_ulonglong()
		edges = core.BNGetFunctionGraphBlockOutgoingEdges(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			branch_type = BranchType(edges[i].type)
			target = edges[i].target
			if target:
				func = core.BNGetBasicBlockFunction(target)
				if func is None:
					core.BNFreeBasicBlock(target)
					target = None
				else:
					target = basicblock.BasicBlock(binaryview.BinaryView(handle = core.BNGetFunctionData(func)),
						core.BNNewBasicBlockReference(target))
					core.BNFreeFunction(func)
			points = []
			for j in xrange(0, edges[i].pointCount):
				points.append((edges[i].points[j].x, edges[i].points[j].y))
			result.append(FunctionGraphEdge(branch_type, self, target, points, edges[i].backEdge))
		core.BNFreeFunctionGraphBlockOutgoingEdgeList(edges, count.value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<graph block: %s@%#x-%#x>" % (arch.name, self.start, self.end)
		else:
			return "<graph block: %#x-%#x>" % (self.start, self.end)

	def __iter__(self):
		count = ctypes.c_ulonglong()
		lines = core.BNGetFunctionGraphBlockLines(self.handle, count)
		try:
			for i in xrange(0, count.value):
				addr = lines[i].addr
				tokens = []
				for j in xrange(0, lines[i].count):
					token_type = InstructionTextTokenType(lines[i].tokens[j].type)
					text = lines[i].tokens[j].text
					value = lines[i].tokens[j].value
					size = lines[i].tokens[j].size
					operand = lines[i].tokens[j].operand
					context = lines[i].tokens[j].context
					confidence = lines[i].tokens[j].confidence
					address = lines[i].tokens[j].address
					tokens.append(InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
				yield DisassemblyTextLine(addr, tokens)
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)


class DisassemblySettings(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = core.BNCreateDisassemblySettings()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeDisassemblySettings(self.handle)

	@property
	def width(self):
		return core.BNGetDisassemblyWidth(self.handle)

	@width.setter
	def width(self, value):
		core.BNSetDisassemblyWidth(self.handle, value)

	@property
	def max_symbol_width(self):
		return core.BNGetDisassemblyMaximumSymbolWidth(self.handle)

	@max_symbol_width.setter
	def max_symbol_width(self, value):
		core.BNSetDisassemblyMaximumSymbolWidth(self.handle, value)

	def is_option_set(self, option):
		if isinstance(option, str):
			option = DisassemblyOption[option]
		return core.BNIsDisassemblySettingsOptionSet(self.handle, option)

	def set_option(self, option, state = True):
		if isinstance(option, str):
			option = DisassemblyOption[option]
		core.BNSetDisassemblySettingsOption(self.handle, option, state)


class FunctionGraph(object):
	def __init__(self, view, handle):
		self.view = view
		self.handle = handle
		self._on_complete = None
		self._cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._complete)

	def __del__(self):
		self.abort()
		core.BNFreeFunctionGraph(self.handle)

	def __eq__(self, value):
		if not isinstance(value, FunctionGraph):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, FunctionGraph):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	@property
	def function(self):
		"""Function for a function graph (read-only)"""
		func = core.BNGetFunctionForFunctionGraph(self.handle)
		if func is None:
			return None
		return Function(self.view, func)

	@property
	def complete(self):
		"""Whether function graph layout is complete (read-only)"""
		return core.BNIsFunctionGraphLayoutComplete(self.handle)

	@property
	def type(self):
		"""Function graph type (read-only)"""
		return FunctionGraphType(core.BNGetFunctionGraphType(self.handle))

	@property
	def blocks(self):
		"""List of basic blocks in function (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionGraphBlocks(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(FunctionGraphBlock(core.BNNewFunctionGraphBlockReference(blocks[i])))
		core.BNFreeFunctionGraphBlockList(blocks, count.value)
		return result

	@property
	def width(self):
		"""Function graph width (read-only)"""
		return core.BNGetFunctionGraphWidth(self.handle)

	@property
	def height(self):
		"""Function graph height (read-only)"""
		return core.BNGetFunctionGraphHeight(self.handle)

	@property
	def horizontal_block_margin(self):
		return core.BNGetHorizontalFunctionGraphBlockMargin(self.handle)

	@horizontal_block_margin.setter
	def horizontal_block_margin(self, value):
		core.BNSetFunctionGraphBlockMargins(self.handle, value, self.vertical_block_margin)

	@property
	def vertical_block_margin(self):
		return core.BNGetVerticalFunctionGraphBlockMargin(self.handle)

	@vertical_block_margin.setter
	def vertical_block_margin(self, value):
		core.BNSetFunctionGraphBlockMargins(self.handle, self.horizontal_block_margin, value)

	@property
	def settings(self):
		return DisassemblySettings(core.BNGetFunctionGraphSettings(self.handle))

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		return "<graph of %s>" % repr(self.function)

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionGraphBlocks(self.handle, count)
		try:
			for i in xrange(0, count.value):
				yield FunctionGraphBlock(core.BNNewFunctionGraphBlockReference(blocks[i]))
		finally:
			core.BNFreeFunctionGraphBlockList(blocks, count.value)

	def _complete(self, ctxt):
		try:
			if self._on_complete is not None:
				self._on_complete()
		except:
			log.log_error(traceback.format_exc())

	def layout(self, graph_type = FunctionGraphType.NormalFunctionGraph):
		if isinstance(graph_type, str):
			graph_type = FunctionGraphType[graph_type]
		core.BNStartFunctionGraphLayout(self.handle, graph_type)

	def _wait_complete(self):
		self._wait_cond.acquire()
		self._wait_cond.notify()
		self._wait_cond.release()

	def layout_and_wait(self, graph_type=FunctionGraphType.NormalFunctionGraph):
		self._wait_cond = threading.Condition()
		self.on_complete(self._wait_complete)
		self.layout(graph_type)

		self._wait_cond.acquire()
		while not self.complete:
			self._wait_cond.wait()
		self._wait_cond.release()

	def on_complete(self, callback):
		self._on_complete = callback
		core.BNSetFunctionGraphCompleteCallback(self.handle, None, self._cb)

	def abort(self):
		core.BNAbortFunctionGraph(self.handle)

	def get_blocks_in_region(self, left, top, right, bottom):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionGraphBlocksInRegion(self.handle, left, top, right, bottom, count)
		result = []
		for i in xrange(0, count.value):
			result.append(FunctionGraphBlock(core.BNNewFunctionGraphBlockReference(blocks[i])))
		core.BNFreeFunctionGraphBlockList(blocks, count.value)
		return result

	def is_option_set(self, option):
		if isinstance(option, str):
			option = DisassemblyOption[option]
		return core.BNIsFunctionGraphOptionSet(self.handle, option)

	def set_option(self, option, state = True):
		if isinstance(option, str):
			option = DisassemblyOption[option]
		core.BNSetFunctionGraphOption(self.handle, option, state)


class RegisterInfo(object):
	def __init__(self, full_width_reg, size, offset=0, extend=ImplicitRegisterExtend.NoExtend, index=None):
		self.full_width_reg = full_width_reg
		self.offset = offset
		self.size = size
		self.extend = extend
		self.index = index

	def __repr__(self):
		if self.extend == ImplicitRegisterExtend.ZeroExtendToFullWidth:
			extend = ", zero extend"
		elif self.extend == ImplicitRegisterExtend.SignExtendToFullWidth:
			extend = ", sign extend"
		else:
			extend = ""
		return "<reg: size %d, offset %d in %s%s>" % (self.size, self.offset, self.full_width_reg, extend)


class InstructionBranch(object):
	def __init__(self, branch_type, target = 0, arch = None):
		self.type = branch_type
		self.target = target
		self.arch = arch

	def __repr__(self):
		branch_type = self.type
		if self.arch is not None:
			return "<%s: %s@%#x>" % (branch_type.name, self.arch.name, self.target)
		return "<%s: %#x>" % (branch_type, self.target)


class InstructionInfo(object):
	def __init__(self):
		self.length = 0
		self.branch_delay = False
		self.branches = []

	def add_branch(self, branch_type, target = 0, arch = None):
		self.branches.append(InstructionBranch(branch_type, target, arch))

	def __repr__(self):
		branch_delay = ""
		if self.branch_delay:
			branch_delay = ", delay slot"
		return "<instr: %d bytes%s, %s>" % (self.length, branch_delay, repr(self.branches))


class InstructionTextToken(object):
	"""
	``class InstructionTextToken`` is used to tell the core about the various components in the disassembly views.

		========================== ============================================
		InstructionTextTokenType   Description
		========================== ============================================
		TextToken                  Text that doesn't fit into the other tokens
		InstructionToken           The instruction mnemonic
		OperandSeparatorToken      The comma or whatever else separates tokens
		RegisterToken              Registers
		IntegerToken               Integers
		PossibleAddressToken       Integers that are likely addresses
		BeginMemoryOperandToken    The start of memory operand
		EndMemoryOperandToken      The end of a memory operand
		FloatingPointToken         Floating point number
		AnnotationToken            **For internal use only**
		CodeRelativeAddressToken   **For internal use only**
		StackVariableTypeToken     **For internal use only**
		DataVariableTypeToken      **For internal use only**
		FunctionReturnTypeToken    **For internal use only**
		FunctionAttributeToken     **For internal use only**
		ArgumentTypeToken          **For internal use only**
		ArgumentNameToken          **For internal use only**
		HexDumpByteValueToken      **For internal use only**
		HexDumpSkippedByteToken    **For internal use only**
		HexDumpInvalidByteToken    **For internal use only**
		HexDumpTextToken           **For internal use only**
		OpcodeToken                **For internal use only**
		StringToken                **For internal use only**
		CharacterConstantToken     **For internal use only**
		CodeSymbolToken            **For internal use only**
		DataSymbolToken            **For internal use only**
		StackVariableToken         **For internal use only**
		ImportToken                **For internal use only**
		AddressDisplayToken        **For internal use only**
		========================== ============================================

	"""
	def __init__(self, token_type, text, value = 0, size = 0, operand = 0xffffffff,
		context = InstructionTextTokenContext.NoTokenContext, address = 0, confidence = types.max_confidence):
		self.type = InstructionTextTokenType(token_type)
		self.text = text
		self.value = value
		self.size = size
		self.operand = operand
		self.context = InstructionTextTokenContext(context)
		self.confidence = confidence
		self.address = address

	def __str__(self):
		return self.text

	def __repr__(self):
		return repr(self.text)
