# coding=utf-8
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

from __future__ import absolute_import
import threading
import traceback
import ctypes
import numbers

# Binary Ninja components
import binaryninja
from binaryninja import _binaryninjacore as core
from binaryninja import associateddatastore  # Required in the main scope due to being an argument for _FunctionAssociatedDataStore
from binaryninja import highlight
from binaryninja import log
from binaryninja import types
from binaryninja.enums import (AnalysisSkipReason, FunctionGraphType, BranchType, SymbolType, InstructionTextTokenType,
	HighlightStandardColor, HighlightColorStyle, RegisterValueType, ImplicitRegisterExtend,
	DisassemblyOption, IntegerDisplayType, InstructionTextTokenContext, VariableSourceType,
	FunctionAnalysisSkipOverride, MediumLevelILOperation)

# 2-3 compatibility
from binaryninja import range


class LookupTableEntry(object):
	def __init__(self, from_values, to_value):
		self._from_values = from_values
		self._to_value = to_value

	def __repr__(self):
		return "[%s] -> %#x" % (', '.join(["%#x" % i for i in self.from_values]), self.to_value)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._from_values, self._to_value) == (other._from_values, other._to_value)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._from_values, self._to_value))

	@property
	def from_values(self):
		""" """
		return self._from_values

	@from_values.setter
	def from_values(self, value):
		""" """
		self._from_values = value

	@property
	def to_value(self):
		""" """
		return self._to_value

	@to_value.setter
	def to_value(self, value):
		""" """
		self._to_value = value


class RegisterValue(object):
	def __init__(self, arch = None, value = None, confidence = types.max_confidence):
		self._is_constant = False
		self._value = None
		self._arch = None
		self._reg = None
		self._is_constant = False
		self._offset = None
		if value is None:
			self._type = RegisterValueType.UndeterminedValue
		else:
			self._type = RegisterValueType(value.state)
			if value.state == RegisterValueType.EntryValue:
				self._arch = arch
				if arch is not None:
					self._reg = arch.get_reg_name(value.value)
				else:
					self._reg = value.value
			elif (value.state == RegisterValueType.ConstantValue) or (value.state == RegisterValueType.ConstantPointerValue):
				self._value = value.value
				self._is_constant = True
			elif value.state == RegisterValueType.StackFrameOffset:
				self._offset = value.value
			elif value.state == RegisterValueType.ImportedAddressValue:
				self._value = value.value
		self._confidence = confidence

	def __repr__(self):
		if self._type == RegisterValueType.EntryValue:
			return "<entry %s>" % self._reg
		if self._type == RegisterValueType.ConstantValue:
			return "<const %#x>" % self._value
		if self._type == RegisterValueType.ConstantPointerValue:
			return "<const ptr %#x>" % self._value
		if self._type == RegisterValueType.StackFrameOffset:
			return "<stack frame offset %#x>" % self._offset
		if self._type == RegisterValueType.ReturnAddressValue:
			return "<return address>"
		if self._type == RegisterValueType.ImportedAddressValue:
			return "<imported address from entry %#x>" % self._value
		return "<undetermined>"

	def __hash__(self):
		if self._type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue, RegisterValueType.ImportedAddressValue, RegisterValueType.ReturnAddressValue]:
			return hash(self._value)
		elif self.type == RegisterValueType.EntryValue:
			return hash(self._reg)
		elif self._type == RegisterValueType.StackFrameOffset:
			return hash(self._offset)

	def __eq__(self, other):
		if self._type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue, RegisterValueType.ImportedAddressValue, RegisterValueType.ReturnAddressValue] and isinstance(other, numbers.Integral):
			return self._value == other
		elif self._type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue, RegisterValueType.ImportedAddressValue, RegisterValueType.ReturnAddressValue] and hasattr(other, 'type') and other.type == self._type:
			return self._value == other.value
		elif self._type == RegisterValueType.EntryValue and hasattr(other, "type") and other.type == self._type:
			return self._reg == other.reg
		elif self._type == RegisterValueType.StackFrameOffset and hasattr(other, 'type') and other.type == self._type:
			return self._offset == other.offset
		elif self._type == RegisterValueType.StackFrameOffset and isinstance(other, numbers.Integral):
			return self._offset == other
		return NotImplemented

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def _to_api_object(self):
		result = core.BNRegisterValue()
		result.type = self._type
		result._value = 0
		if self._type == RegisterValueType.EntryValue:
			if self._arch is not None:
				result._value = self._arch.get_reg_index(self._reg)
			else:
				result._value = self._reg
		elif (self._type == RegisterValueType.ConstantValue) or (self._type == RegisterValueType.ConstantPointerValue):
			result._value = self._value
		elif self._type == RegisterValueType.StackFrameOffset:
			result._value = self._offset
		elif self._type == RegisterValueType.ImportedAddressValue:
			result._value = self._value
		return result

	@classmethod
	def undetermined(self):
		return RegisterValue()

	@classmethod
	def entry_value(self, arch, reg):
		result = RegisterValue()
		result._type = RegisterValueType.EntryValue
		result._arch = arch
		result._reg = reg
		return result

	@classmethod
	def constant(self, value):
		result = RegisterValue()
		result._type = RegisterValueType.ConstantValue
		result._value = value
		result._is_constant = True
		return result

	@classmethod
	def constant_ptr(self, value):
		result = RegisterValue()
		result._type = RegisterValueType.ConstantPointerValue
		result._value = value
		result._is_constant = True
		return result

	@classmethod
	def stack_frame_offset(self, offset):
		result = RegisterValue()
		result._type = RegisterValueType.StackFrameOffset
		result._offset = offset
		return result

	@classmethod
	def imported_address(self, value):
		result = RegisterValue()
		result._type = RegisterValueType.ImportedAddressValue
		result._value = value
		return result

	@classmethod
	def return_address(self):
		result = RegisterValue()
		result._type = RegisterValueType.ReturnAddressValue
		return result

	@property
	def is_constant(self):
		"""Boolean for whether the RegisterValue is known to be constant (read-only)"""
		return self._is_constant

	@property
	def type(self):
		""":class:`~enums.RegisterValueType` (read-only)"""
		return self._type

	@property
	def arch(self):
		"""Architecture where it exists, None otherwise (read-only)"""
		return self._arch

	@property
	def reg(self):
		"""Register where the Architecture exists, None otherwise (read-only)"""
		return self._reg

	@property
	def value(self):
		"""Value where it exists, None otherwise (read-only)"""
		return self._value

	@property
	def offset(self):
		"""Offset where it exists, None otherwise (read-only)"""
		return self._offset

	@property
	def confidence(self):
		"""Confidence where it exists, None otherwise (read-only)"""
		return self._confidence


class ValueRange(object):
	def __init__(self, start, end, step):
		self._start = start
		self._end = end
		self._step = step

	def __repr__(self):
		if self.step == 1:
			return "<range: %#x to %#x>" % (self.start, self.end)
		return "<range: %#x to %#x, step %#x>" % (self.start, self.end, self.step)

	@property
	def start(self):
		""" """
		return self._start

	@start.setter
	def start(self, value):
		""" """
		self._start = value

	@property
	def end(self):
		""" """
		return self._end

	@end.setter
	def end(self, value):
		""" """
		self._end = value

	@property
	def step(self):
		""" """
		return self._step

	@step.setter
	def step(self, value):
		""" """
		self._step = value


class PossibleValueSet(object):
	def __init__(self, arch = None, value = None):
		if value is None:
			self._type = RegisterValueType.UndeterminedValue
			return
		self._type = RegisterValueType(value.state)
		if value.state == RegisterValueType.EntryValue:
			if arch is None:
				self._reg = value.value
			else:
				self._reg = arch.get_reg_name(value.value)
		elif value.state == RegisterValueType.ConstantValue:
			self._value = value.value
		elif value.state == RegisterValueType.ConstantPointerValue:
			self._value = value.value
		elif value.state == RegisterValueType.StackFrameOffset:
			self._offset = value.value
		elif value.state == RegisterValueType.SignedRangeValue:
			self._offset = value.value
			self._ranges = []
			for i in range(0, value.count):
				start = value.ranges[i].start
				end = value.ranges[i].end
				step = value.ranges[i].step
				if start & (1 << 63):
					start |= ~((1 << 63) - 1)
				if end & (1 << 63):
					end |= ~((1 << 63) - 1)
				self._ranges.append(ValueRange(start, end, step))
		elif value.state == RegisterValueType.UnsignedRangeValue:
			self._offset = value.value
			self._ranges = []
			for i in range(0, value.count):
				start = value.ranges[i].start
				end = value.ranges[i].end
				step = value.ranges[i].step
				self._ranges.append(ValueRange(start, end, step))
		elif value.state == RegisterValueType.LookupTableValue:
			self._table = []
			self._mapping = {}
			for i in range(0, value.count):
				from_list = []
				for j in range(0, value.table[i].fromCount):
					from_list.append(value.table[i].fromValues[j])
					self._mapping[value.table[i].fromValues[j]] = value.table[i].toValue
				self._table.append(LookupTableEntry(from_list, value.table[i].toValue))
		elif (value.state == RegisterValueType.InSetOfValues) or (value.state == RegisterValueType.NotInSetOfValues):
			self._values = set()
			for i in range(0, value.count):
				self._values.add(value.valueSet[i])

	def __repr__(self):
		if self._type == RegisterValueType.EntryValue:
			return "<entry %s>" % self.reg
		if self._type == RegisterValueType.ConstantValue:
			return "<const %#x>" % self.value
		if self._type == RegisterValueType.ConstantPointerValue:
			return "<const ptr %#x>" % self.value
		if self._type == RegisterValueType.StackFrameOffset:
			return "<stack frame offset %#x>" % self.offset
		if self._type == RegisterValueType.SignedRangeValue:
			return "<signed ranges: %s>" % repr(self.ranges)
		if self._type == RegisterValueType.UnsignedRangeValue:
			return "<unsigned ranges: %s>" % repr(self.ranges)
		if self._type == RegisterValueType.LookupTableValue:
			return "<table: %s>" % ', '.join([repr(i) for i in self.table])
		if self._type == RegisterValueType.InSetOfValues:
			return "<in set(%s)>" % '[{}]'.format(', '.join(hex(i) for i in sorted(self.values)))
		if self._type == RegisterValueType.NotInSetOfValues:
			return "<not in set(%s)>" % '[{}]'.format(', '.join(hex(i) for i in sorted(self.values)))
		if self._type == RegisterValueType.ReturnAddressValue:
			return "<return address>"
		return "<undetermined>"

	def __eq__(self, other):
		if self.type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantValue] and isinstance(other, numbers.Integral):
			return self.value == other
		if self.type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantValue] and hasattr(other, 'type') and other.type == self.type:
			return self.value == other.value
		else:
			return self == other

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	@property
	def type(self):
		""" """
		return self._type

	@type.setter
	def type(self, value):
		""" """
		self._type = value

	@property
	def reg(self):
		""" """
		return self._reg

	@reg.setter
	def reg(self, value):
		""" """
		self._reg = value

	@property
	def value(self):
		""" """
		return self._value

	@value.setter
	def value(self, value):
		""" """
		self._value = value

	@property
	def offset(self):
		""" """
		return self._offset

	@offset.setter
	def offset(self, value):
		""" """
		self._offset = value

	@property
	def ranges(self):
		""" """
		return self._ranges

	@ranges.setter
	def ranges(self, value):
		""" """
		self._ranges = value

	@property
	def table(self):
		""" """
		return self._table

	@table.setter
	def table(self, value):
		""" """
		self._table = value

	@property
	def mapping(self):
		""" """
		return self._mapping

	@mapping.setter
	def mapping(self, value):
		""" """
		self._mapping = value

	@property
	def values(self):
		""" """
		return self._values

	@values.setter
	def values(self, value):
		""" """
		self._values = value


class StackVariableReference(object):
	def __init__(self, src_operand, t, name, var, ref_ofs, size):
		self._source_operand = src_operand
		self._type = t
		self._name = name
		self._var = var
		self._referenced_offset = ref_ofs
		self._size = size
		if self._source_operand == 0xffffffff:
			self._source_operand = None

	def __repr__(self):
		if self._source_operand is None:
			if self._referenced_offset != self._var.storage:
				return "<ref to %s%+#x>" % (self._name, self._referenced_offset - self._var.storage)
			return "<ref to %s>" % self._name
		if self._referenced_offset != self._var.storage:
			return "<operand %d ref to %s%+#x>" % (self._source_operand, self._name, self._var.storage)
		return "<operand %d ref to %s>" % (self._source_operand, self._name)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._source_operand, self._type, self._name, self._var, self._referenced_offset, self._size) == \
			(other._source_operand, other._type, other._name, other._var, other._referenced_offset, other._size)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._source_operand, self._type, self._name, self._var, self._referenced_offset, self._size))

	@property
	def source_operand(self):
		""" """
		return self._source_operand

	@source_operand.setter
	def source_operand(self, value):
		self._source_operand = value

	@property
	def type(self):
		""" """
		return self._type

	@type.setter
	def type(self, value):
		self._type = value

	@property
	def name(self):
		""" """
		return self._name

	@name.setter
	def name(self, value):
		self._name = value

	@property
	def var(self):
		""" """
		return self._var

	@var.setter
	def var(self, value):
		self._var = value

	@property
	def referenced_offset(self):
		""" """
		return self._referenced_offset

	@referenced_offset.setter
	def referenced_offset(self, value):
		self._referenced_offset = value

	@property
	def size(self):
		""" """
		return self._size

	@size.setter
	def size(self, value):
		self._size = value


class Variable(object):
	def __init__(self, func, source_type, index, storage, name = None, var_type = None):
		self._function = func
		self._source_type = VariableSourceType(source_type)
		self._index = index
		self._storage = storage

		var = core.BNVariable()
		var.type = source_type
		var.index = index
		var.storage = storage
		self._identifier = core.BNToVariableIdentifier(var)

		if func is not None:
			if name is None:
				name = core.BNGetVariableName(func.handle, var)
			if var_type is None:
				var_type_conf = core.BNGetVariableType(func.handle, var)
				if var_type_conf.type:
					var_type = types.Type(var_type_conf.type, platform = func.platform, confidence = var_type_conf.confidence)
				else:
					var_type = None

		self._name = name
		self._type = var_type

	def __repr__(self):
		if self._type is None:
			return "<var %s>" % self.name
		return "<var %s %s%s>" % (self._type.get_string_before_name(), self.name, self._type.get_string_after_name())

	def __str__(self):
		return self.name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self.identifier, self.function) == (other.identifier, other.function)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self.identifier, self.function))

	@property
	def function(self):
		"""Function where the variable is defined"""
		return self._function

	@function.setter
	def function(self, value):
		self._function = value

	@property
	def source_type(self):
		""":class:`~enums.VariableSourceType`"""
		return self._source_type

	@source_type.setter
	def source_type(self, value):
		self._source_type = value

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value

	@property
	def storage(self):
		"""Stack offset for StackVariableSourceType, register index for RegisterVariableSourceType"""
		return self._storage

	@storage.setter
	def storage(self, value):
		self._storage = value

	@property
	def identifier(self):
		""" """
		return self._identifier

	@identifier.setter
	def identifier(self, value):
		self._identifier = value

	@property
	def name(self):
		"""Name of the variable"""
		return self._name

	@name.setter
	def name(self, value):
		self._name = value

	@property
	def type(self):
		""" """
		return self._type

	@type.setter
	def type(self, value):
		self._type = value

	@classmethod
	def from_identifier(self, func, identifier, name = None, var_type = None):
		var = core.BNFromVariableIdentifier(identifier)
		return Variable(func, VariableSourceType(var.type), var.index, var.storage, name, var_type)

class ConstantReference(object):
	def __init__(self, val, size, ptr, intermediate):
		self._value = val
		self._size = size
		self._pointer = ptr
		self._intermediate = intermediate

	def __repr__(self):
		if self.pointer:
			return "<constant pointer %#x>" % self.value
		if self.size == 0:
			return "<constant %#x>" % self.value
		return "<constant %#x size %d>" % (self.value, self.size)

	@property
	def value(self):
		""" """
		return self._value

	@value.setter
	def value(self, value):
		self._value = value

	@property
	def size(self):
		""" """
		return self._size

	@size.setter
	def size(self, value):
		self._size = value

	@property
	def pointer(self):
		""" """
		return self._pointer

	@pointer.setter
	def pointer(self, value):
		self._pointer = value

	@property
	def intermediate(self):
		""" """
		return self._intermediate

	@intermediate.setter
	def intermediate(self, value):
		self._intermediate = value



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
		self._vars = var_list
		self._confidence = confidence

	def __repr__(self):
		return repr(self._vars)

	def __len__(self):
		return len(self._vars)

	def __iter__(self):
		for var in self._vars:
			yield var

	def __getitem__(self, idx):
		return self._vars[idx]

	def with_confidence(self, confidence):
		return ParameterVariables(list(self._vars), confidence = confidence)

	@property
	def vars(self):
		""" """
		return self._vars

	@vars.setter
	def vars(self, value):
		self._vars = value

	@property
	def confidence(self):
		""" """
		return self._confidence

	@confidence.setter
	def confidence(self, value):
		self._confidence = value


class _FunctionAssociatedDataStore(associateddatastore._AssociatedDataStore):
	_defaults = {}


class Function(object):
	_associated_data = {}

	def __init__(self, view = None, handle = None):
		self._advanced_analysis_requests = 0
		if handle is None:
			self.handle = None
			raise NotImplementedError("creation of standalone 'Function' objects is not implemented")
		self.handle = core.handle_of_type(handle, core.BNFunction)
		if view is None:
			self._view = binaryninja.binaryview.BinaryView(handle = core.BNGetFunctionData(self.handle))
		else:
			self._view = view
		self._arch = None
		self._platform = None

	def __del__(self):
		if self.handle is not None:
			if self._advanced_analysis_requests > 0:
				core.BNReleaseAdvancedFunctionAnalysisDataMultiple(self.handle, self._advanced_analysis_requests)
			core.BNFreeFunction(self.handle)

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<func: %s@%#x>" % (arch.name, self.start)
		else:
			return "<func: %#x>" % self.start

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __lt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start < other.start

	def __gt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start > other.start

	def __le__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start <= other.start

	def __ge__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start >= other.start

	def __hash__(self):
		return hash((self.start, self.arch.name, self.platform.name))

	def __getitem__(self, i):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionBasicBlockList(self.handle, count)
		try:
			if i < 0:
				i = count.value + i
			if i < -len(self.basic_blocks) or i >= count.value:
				raise IndexError("index out of range")
			if i < 0:
				i = len(self.basic_blocks) + i
			block = binaryninja.basicblock.BasicBlock(core.BNNewBasicBlockReference(blocks[i]), self._view)
			return block
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionBasicBlockList(self.handle, count)
		try:
			for i in range(0, count.value):
				yield binaryninja.basicblock.BasicBlock(core.BNNewBasicBlockReference(blocks[i]), self._view)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def __str__(self):
		result = ""
		for token in self.type_tokens:
			result += token.text
		return result

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
		if self._arch:
			return self._arch
		else:
			arch = core.BNGetFunctionArchitecture(self.handle)
			if arch is None:
				return None
			self._arch = binaryninja.architecture.CoreArchitecture._from_cache(arch)
			return self._arch

	@property
	def platform(self):
		"""Function platform (read-only)"""
		if self._platform:
			return self._platform
		else:
			plat = core.BNGetFunctionPlatform(self.handle)
			if plat is None:
				return None
			self._platform = binaryninja.platform.Platform(handle = plat)
			return self._platform

	@property
	def start(self):
		"""Function start address (read-only)"""
		return core.BNGetFunctionStart(self.handle)

	@property
	def total_bytes(self):
		"""Total bytes of a function calculated by summing each basic_block. Because basic blocks can overlap and have gaps between them this may or may not be equivalent to a .size property."""
		return sum(map(len, self))

	@property
	def highest_address(self):
		"The highest virtual address contained in a function."""
		return max(self, key=lambda block:block.end).end - 1

	@property
	def lowest_address(self):
		"""The lowest virtual address contained in a function."""
		return min(self, key=lambda block:block.start).start

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
		for i in range(0, count.value):
			result.append(binaryninja.basicblock.BasicBlock(core.BNNewBasicBlockReference(blocks[i]), self._view))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def comments(self):
		"""Dict of comments (read-only)"""
		count = ctypes.c_ulonglong()
		addrs = core.BNGetCommentedAddresses(self.handle, count)
		result = {}
		for i in range(0, count.value):
			result[addrs[i]] = self.get_comment_at(addrs[i])
		core.BNFreeAddressList(addrs)
		return result

	def create_user_tag(self, type, data):
		return self.create_tag(type, data, True)

	def create_auto_tag(self, type, data):
		return self.create_tag(type, data, False)

	def create_tag(self, type, data, user=True):
		"""
		``create_tag`` creates a new Tag object but does not add it anywhere.
		Use :py:meth:`create_user_address_tag` or
		:py:meth:`create_user_function_tag` to create and add in one step.

		:param TagType type: The Tag Type for this Tag
		:param str data: Additional data for the Tag
		:return: The created Tag
		:rtype: Tag
		:Example:

			>>> tt = bv.tag_types["Crashes"]
			>>> tag = current_function.create_tag(tt, "Null pointer dereference", True)
			>>> current_function.add_user_address_tag(here, tag)
			>>>
		"""
		return self.view.create_tag(type, data, user)

	@property
	def address_tags(self):
		"""
		``address_tags`` gets a list of all address Tags in the function.
		Tags are returned as a list of (arch, address, Tag) tuples.

		:rtype: list((Architecture, int, Tag))
		"""
		count = ctypes.c_ulonglong()
		tags = core.BNGetAddressTagReferences(self.handle, count)
		result = []
		for i in range(0, count.value):
			arch = binaryninja.architecture.CoreArchitecture(tags[i].arch)
			tag = binaryninja.binaryview.Tag(core.BNNewTagReference(tags[i].tag))
			result.append((arch, tags[i].addr, tag))
		core.BNFreeTagReferences(tags, count.value)
		return result

	def get_address_tags_at(self, addr, arch=None):
		"""
		``get_address_tags_at`` gets a list of all Tags in the function at a given address.

		:param int addr: Address to get tags at
		:param Architecture arch: Architecture for the block in which the Tag is added (optional)
		:return: A list of Tags
		:rtype: list(Tag)
		"""
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		tags = core.BNGetAddressTags(self.handle, arch.handle, addr, count)
		result = []
		for i in range(0, count.value):
			result.append(binaryninja.binaryview.Tag(core.BNNewTagReference(tags[i])))
		core.BNFreeTagList(tags, count.value)
		return result

	def add_user_address_tag(self, addr, tag, arch=None):
		"""
		``add_user_address_tag`` adds an already-created Tag object at a given address.
		Since this adds a user tag, it will be added to the current undo buffer.

		:param int addr: Address at which to add the tag
		:param Tag tag: Tag object to be added
		:param Architecture arch: Architecture for the block in which the Tag is added (optional)
		:rtype: None
		"""
		if arch is None:
			arch = self.arch
		core.BNAddUserAddressTag(self.handle, arch.handle, addr, tag.handle)

	def create_user_address_tag(self, addr, type, data, unique=False, arch=None):
		"""
		``create_user_address_tag`` creates and adds a Tag object at a given
		address. Since this adds a user tag, it will be added to the current
		undo buffer. To create tags associated with an address that is not
		inside of a function, use :py:meth:`create_user_data_tag <binaryninja.binaryview.BinaryView.create_user_data_tag>`.

		:param int addr: Address at which to add the tag
		:param TagType type: Tag Type for the Tag that is created
		:param str data: Additional data for the Tag
		:param bool unique: If a tag already exists at this location with this data, don't add another
		:param Architecture arch: Architecture for the block in which the Tag is added (optional)
		:return: The created Tag
		:rtype: Tag
		"""
		if arch is None:
			arch = self.arch
		if unique:
			tags = self.get_address_tags_at(addr, arch)
			for tag in tags:
				if tag.type == type and tag.data == data:
					return

		tag = self.create_tag(type, data, True)
		core.BNAddUserAddressTag(self.handle, arch.handle, addr, tag.handle)
		return tag

	def remove_user_address_tag(self, addr, tag, arch=None):
		"""
		``remove_user_address_tag`` removes a Tag object at a given address.
		Since this removes a user tag, it will be added to the current undo buffer.

		:param int addr: Address at which to add the tag
		:param Tag tag: Tag object to be added
		:param Architecture arch: Architecture for the block in which the Tag is added (optional)
		:rtype: None
		"""
		if arch is None:
			arch = self.arch
		core.BNRemoveUserAddressTag(self.handle, arch.handle, addr, tag.handle)

	def add_auto_address_tag(self, addr, tag, arch=None):
		"""
		``add_auto_address_tag`` adds an already-created Tag object at a given address.

		:param int addr: Address at which to add the tag
		:param Tag tag: Tag object to be added
		:param Architecture arch: Architecture for the block in which the Tag is added (optional)
		:rtype: None
		"""
		if arch is None:
			arch = self.arch
		core.BNAddAutoAddressTag(self.handle, arch.handle, addr, tag.handle)

	def create_auto_address_tag(self, addr, type, data, unique=False, arch=None):
		"""
		``create_auto_address_tag`` creates and adds a Tag object at a given address.

		:param int addr: Address at which to add the tag
		:param TagType type: Tag Type for the Tag that is created
		:param str data: Additional data for the Tag
		:param bool unique: If a tag already exists at this location with this data, don't add another
		:param Architecture arch: Architecture for the block in which the Tag is added (optional)
		:return: The created Tag
		:rtype: Tag
		"""
		if arch is None:
			arch = self.arch
		if unique:
			tags = self.get_address_tags_at(addr, arch)
			for tag in tags:
				if tag.type == type and tag.data == data:
					return

		tag = self.create_tag(type, data, False)
		core.BNAddAutoAddressTag(self.handle, arch.handle, addr, tag.handle)
		return tag

	def remove_auto_address_tag(self, addr, tag, arch=None):
		"""
		``remove_auto_address_tag`` removes a Tag object at a given address.

		:param int addr: Address at which to add the tag
		:param Tag tag: Tag object to be added
		:param Architecture arch: Architecture for the block in which the Tag is added (optional)
		:rtype: None
		"""
		if arch is None:
			arch = self.arch
		core.BNRemoveAutoAddressTag(self.handle, arch.handle, addr, tag.handle)

	@property
	def function_tags(self):
		"""
		``function_tags`` gets a list of all function Tags for the function.

		:rtype: list(Tag)
		"""
		count = ctypes.c_ulonglong()
		tags = core.BNGetFunctionTags(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(binaryninja.binaryview.Tag(core.BNNewTagReference(tags[i])))
		core.BNFreeTagList(tags, count.value)
		return result

	def add_user_function_tag(self, tag):
		"""
		``add_user_function_tag`` adds an already-created Tag object as a function tag.
		Since this adds a user tag, it will be added to the current undo buffer.

		:param Tag tag: Tag object to be added
		:rtype: None
		"""
		core.BNAddUserFunctionTag(self.handle, tag.handle)

	def create_user_function_tag(self, type, data, unique=False):
		"""
		``add_user_function_tag`` creates and adds a Tag object as a function tag.
		Since this adds a user tag, it will be added to the current undo buffer.

		:param TagType type: Tag Type for the Tag that is created
		:param str data: Additional data for the Tag
		:param bool unique: If a tag already exists with this data, don't add another
		:return: The created Tag
		:rtype: Tag
		"""
		if unique:
			for tag in self.function_tags:
				if tag.type == type and tag.data == data:
					return

		tag = self.create_tag(type, data, True)
		core.BNAddUserFunctionTag(self.handle, tag.handle)
		return tag

	def remove_user_function_tag(self, tag):
		"""
		``remove_user_function_tag`` removes a Tag object as a function tag.
		Since this removes a user tag, it will be added to the current undo buffer.

		:param Tag tag: Tag object to be added
		:rtype: None
		"""
		core.BNRemoveUserFunctionTag(self.handle, tag.handle)

	def add_auto_function_tag(self, tag):
		"""
		``add_user_function_tag`` adds an already-created Tag object as a function tag.

		:param Tag tag: Tag object to be added
		:rtype: None
		"""
		core.BNAddAutoFunctionTag(self.handle, tag.handle)

	def create_auto_function_tag(self, type, data, unique=False):
		"""
		``add_user_function_tag`` creates and adds a Tag object as a function tag.

		:param TagType type: Tag Type for the Tag that is created
		:param str data: Additional data for the Tag
		:param bool unique: If a tag already exists with this data, don't add another
		:return: The created Tag
		:rtype: Tag
		"""
		if unique:
			for tag in self.function_tags:
				if tag.type == type and tag.data == data:
					return

		tag = self.create_tag(type, data, False)
		core.BNAddAutoFunctionTag(self.handle, tag.handle)
		return tag

	def remove_auto_function_tag(self, tag):
		"""
		``remove_user_function_tag`` removes a Tag object as a function tag.

		:param Tag tag: Tag object to be added
		:rtype: None
		"""
		core.BNRemoveAutoFunctionTag(self.handle, tag.handle)

	@property
	def low_level_il(self):
		"""Deprecated property provided for compatibility. Use llil instead."""
		return binaryninja.lowlevelil.LowLevelILFunction(self.arch, core.BNGetFunctionLowLevelIL(self.handle), self)

	@property
	def llil(self):
		"""returns LowLevelILFunction used to represent Function low level IL (read-only)"""
		return binaryninja.lowlevelil.LowLevelILFunction(self.arch, core.BNGetFunctionLowLevelIL(self.handle), self)

	@property
	def llil_if_available(self):
		"""returns LowLevelILFunction used to represent Function low level IL, or None if not loaded (read-only)"""
		result = core.BNGetFunctionLowLevelILIfAvailable(self.handle)
		if not result:
			return None
		return binaryninja.lowlevelil.LowLevelILFunction(self.arch, result, self)

	@property
	def lifted_il(self):
		"""returns LowLevelILFunction used to represent lifted IL (read-only)"""
		return binaryninja.lowlevelil.LowLevelILFunction(self.arch, core.BNGetFunctionLiftedIL(self.handle), self)

	@property
	def lifted_il_if_available(self):
		"""returns LowLevelILFunction used to represent lifted IL, or None if not loaded (read-only)"""
		result = core.BNGetFunctionLiftedILIfAvailable(self.handle)
		if not result:
			return None
		return binaryninja.lowlevelil.LowLevelILFunction(self.arch, result, self)

	@property
	def medium_level_il(self):
		"""Deprecated property provided for compatibility. Use mlil instead."""
		return binaryninja.mediumlevelil.MediumLevelILFunction(self.arch, core.BNGetFunctionMediumLevelIL(self.handle), self)

	@property
	def mlil(self):
		"""Function medium level IL (read-only)"""
		return binaryninja.mediumlevelil.MediumLevelILFunction(self.arch, core.BNGetFunctionMediumLevelIL(self.handle), self)

	@property
	def mlil_if_available(self):
		"""Function medium level IL, or None if not loaded (read-only)"""
		result = core.BNGetFunctionMediumLevelILIfAvailable(self.handle)
		if not result:
			return None
		return binaryninja.mediumlevelil.MediumLevelILFunction(self.arch, result, self)

	@property
	def high_level_il(self):
		"""Deprecated property provided for compatibility. Use hlil instead."""
		return binaryninja.highlevelil.HighLevelILFunction(self.arch, core.BNGetFunctionHighLevelIL(self.handle), self)

	@property
	def hlil(self):
		"""Function high level IL (read-only)"""
		return binaryninja.highlevelil.HighLevelILFunction(self.arch, core.BNGetFunctionHighLevelIL(self.handle), self)

	@property
	def hlil_if_available(self):
		"""Function high level IL, or None if not loaded (read-only)"""
		result = core.BNGetFunctionHighLevelILIfAvailable(self.handle)
		if not result:
			return None
		return binaryninja.highlevelil.HighLevelILFunction(self.arch, result, self)

	@property
	def function_type(self):
		"""Function type object, can be set with either a string representing the function prototype (`str(function)` shows examples) or a :py:class:`Type` object"""
		return types.Type(core.BNGetFunctionType(self.handle), platform = self.platform)

	@function_type.setter
	def function_type(self, value):
		if isinstance(value, str):
			(value, new_name) = self.view.parse_type_string(value)
			self.name = str(new_name)
		self.set_user_type(value)

	@property
	def stack_layout(self):
		"""List of function stack variables (read-only)"""
		count = ctypes.c_ulonglong()
		v = core.BNGetStackLayout(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(Variable(self, v[i].var.type, v[i].var.index, v[i].var.storage, v[i].name,
				types.Type(handle = core.BNNewTypeReference(v[i].type), platform = self.platform, confidence = v[i].typeConfidence)))
		result.sort(key = lambda x: x.identifier)
		core.BNFreeVariableNameAndTypeList(v, count.value)
		return result

	@property
	def vars(self):
		"""List of function variables (read-only)"""
		count = ctypes.c_ulonglong()
		v = core.BNGetFunctionVariables(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(Variable(self, v[i].var.type, v[i].var.index, v[i].var.storage, v[i].name,
				types.Type(handle = core.BNNewTypeReference(v[i].type), platform = self.platform, confidence = v[i].typeConfidence)))
		result.sort(key = lambda x: x.identifier)
		core.BNFreeVariableNameAndTypeList(v, count.value)
		return result

	@property
	def indirect_branches(self):
		"""List of indirect branches (read-only)"""
		count = ctypes.c_ulonglong()
		branches = core.BNGetIndirectBranches(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(IndirectBranchInfo(binaryninja.architecture.CoreArchitecture._from_cache(branches[i].sourceArch), branches[i].sourceAddr, binaryninja.architecture.CoreArchitecture._from_cache(branches[i].destArch), branches[i].destAddr, branches[i].autoDefined))
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
		for i in range(0, count.value):
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
	def return_regs(self):
		"""Registers that are used for the return value"""
		result = core.BNGetFunctionReturnRegisters(self.handle)
		reg_set = []
		for i in range(0, result.count):
			reg_set.append(self.arch.get_reg_name(result.regs[i]))
		regs = types.RegisterSet(reg_set, confidence = result.confidence)
		core.BNFreeRegisterSet(result)
		return regs

	@return_regs.setter
	def return_regs(self, value):
		regs = core.BNRegisterSetWithConfidence()
		regs.regs = (ctypes.c_uint * len(value))()
		regs.count = len(value)
		for i in range(0, len(value)):
			regs.regs[i] = self.arch.get_reg_index(value[i])
		if hasattr(value, 'confidence'):
			regs.confidence = value.confidence
		else:
			regs.confidence = types.max_confidence
		core.BNSetUserFunctionReturnRegisters(self.handle, regs)

	@property
	def calling_convention(self):
		"""Calling convention used by the function"""
		result = core.BNGetFunctionCallingConvention(self.handle)
		if not result.convention:
			return None
		return binaryninja.callingconvention.CallingConvention(None, handle = result.convention, confidence = result.confidence)

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
		for i in range(0, result.count):
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
		for i in range(0, len(var_list)):
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
		oc = core.BNOffsetWithConfidence()
		oc.value = int(value)
		if hasattr(value, 'confidence'):
			oc.confidence = value.confidence
		else:
			oc.confidence = types.max_confidence
		core.BNSetUserFunctionStackAdjustment(self.handle, oc)

	@property
	def reg_stack_adjustments(self):
		"""Number of entries removed from each register stack after return"""
		count = ctypes.c_ulonglong()
		adjust = core.BNGetFunctionRegisterStackAdjustments(self.handle, count)
		result = {}
		for i in range(0, count.value):
			name = self.arch.get_reg_stack_name(adjust[i].regStack)
			value = types.RegisterStackAdjustmentWithConfidence(adjust[i].adjustment,
				confidence = adjust[i].confidence)
			result[name] = value
		core.BNFreeRegisterStackAdjustments(adjust)
		return result

	@reg_stack_adjustments.setter
	def reg_stack_adjustments(self, value):
		adjust = (core.BNRegisterStackAdjustment * len(value))()
		i = 0
		for reg_stack in value.keys():
			adjust[i].regStack = self.arch.get_reg_stack_index(reg_stack)
			if isinstance(value[reg_stack], types.RegisterStackAdjustmentWithConfidence):
				adjust[i].adjustment = value[reg_stack].value
				adjust[i].confidence = value[reg_stack].confidence
			else:
				adjust[i].adjustment = value[reg_stack]
				adjust[i].confidence = types.max_confidence
			i += 1
		core.BNSetUserFunctionRegisterStackAdjustments(self.handle, adjust, len(value))

	@property
	def clobbered_regs(self):
		"""Registers that are modified by this function"""
		result = core.BNGetFunctionClobberedRegisters(self.handle)
		reg_set = []
		for i in range(0, result.count):
			reg_set.append(self.arch.get_reg_name(result.regs[i]))
		regs = types.RegisterSet(reg_set, confidence = result.confidence)
		core.BNFreeRegisterSet(result)
		return regs

	@clobbered_regs.setter
	def clobbered_regs(self, value):
		regs = core.BNRegisterSetWithConfidence()
		regs.regs = (ctypes.c_uint * len(value))()
		regs.count = len(value)
		for i in range(0, len(value)):
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

	@property
	def llil_basic_blocks(self):
		"""A generator of all LowLevelILBasicBlock objects in the current function"""
		for block in self.llil:
			yield block

	@property
	def mlil_basic_blocks(self):
		"""A generator of all MediumLevelILBasicBlock objects in the current function"""
		for block in self.mlil:
			yield block

	@property
	def instructions(self):
		"""A generator of instruction tokens and their start addresses for the current function"""
		for block in self.basic_blocks:
			start = block.start
			for i in block:
				yield (i[0], start)
				start += i[1]

	@property
	def llil_instructions(self):
		"""Deprecated method provided for compatibility. Use llil.instructions instead.  Was: A generator of llil instructions of the current function"""
		return self.llil.instructions

	@property
	def mlil_instructions(self):
		"""Deprecated method provided for compatibility. Use mlil.instructions instead.  Was: A generator of mlil instructions of the current function"""
		return self.mlil.instructions

	@property
	def too_large(self):
		"""Whether the function is too large to automatically perform analysis (read-only)"""
		return core.BNIsFunctionTooLarge(self.handle)

	@property
	def analysis_skipped(self):
		"""Whether automatic analysis was skipped for this function"""
		return core.BNIsFunctionAnalysisSkipped(self.handle)

	@property
	def analysis_skip_reason(self):
		"""Function analysis skip reason"""
		return AnalysisSkipReason(core.BNGetAnalysisSkipReason(self.handle))

	@analysis_skipped.setter
	def analysis_skipped(self, skip):
		if skip:
			core.BNSetFunctionAnalysisSkipOverride(self.handle, FunctionAnalysisSkipOverride.AlwaysSkipFunctionAnalysis)
		else:
			core.BNSetFunctionAnalysisSkipOverride(self.handle, FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis)

	@property
	def analysis_skip_override(self):
		"""Override for skipping of automatic analysis"""
		return FunctionAnalysisSkipOverride(core.BNGetFunctionAnalysisSkipOverride(self.handle))

	@analysis_skip_override.setter
	def analysis_skip_override(self, override):
		core.BNSetFunctionAnalysisSkipOverride(self.handle, override)

	@property
	def unresolved_stack_adjustment_graph(self):
		"""Flow graph of unresolved stack adjustments (read-only)"""
		graph = core.BNGetUnresolvedStackAdjustmentGraph(self.handle)
		if not graph:
			return None
		return binaryninja.flowgraph.CoreFlowGraph(graph)

	def mark_recent_use(self):
		core.BNMarkFunctionAsRecentlyUsed(self.handle)

	def get_comment_at(self, addr):
		return core.BNGetCommentForAddress(self.handle, addr)

	def set_comment(self, addr, comment):
		"""Deprecated method provided for compatibility. Use set_comment_at instead."""
		core.BNSetCommentForAddress(self.handle, addr, comment)

	def set_comment_at(self, addr, comment):
		"""
		``set_comment_at`` sets a comment for the current function at the address specified

		:param int addr: virtual address within the current function to apply the comment to
		:param str comment: string comment to apply
		:rtype: None
		:Example:

			>>> current_function.set_comment_at(here, "hi")

		"""
		core.BNSetCommentForAddress(self.handle, addr, comment)

	def add_user_code_ref(self, from_addr, to_addr, from_arch=None):
		"""
		``add_user_code_ref`` places a user-defined cross-reference from the instruction at
		the given address and architecture to the specified target address. If the specified
		source instruction is not contained within this function, no action is performed.
		To remove the reference, use :func:`remove_user_code_ref`.

		:param int from_addr: virtual address of the source instruction
		:param int to_addr: virtual address of the xref's destination.
		:param Architecture from_arch: (optional) architecture of the source instruction
		:rtype: None
		:Example:

			>>> current_function.add_user_code_ref(here, 0x400000)

		"""

		if from_arch is None:
			from_arch = self.arch

		core.BNAddUserCodeReference(self.handle, from_arch.handle, from_addr, to_addr)

	def remove_user_code_ref(self, from_addr, to_addr, from_arch=None):
		"""
		``remove_user_code_ref`` reomves a user-defined cross-reference.
		If the given address is not contained within this function, or if there is no
		such user-defined cross-reference, no action is performed.

		:param int from_addr: virtual address of the source instruction
		:param int to_addr: virtual address of the xref's destination.
		:param Architecture from_arch: (optional) architecture of the source instruction
		:rtype: None
		:Example:

			>>> current_function.remove_user_code_ref(here, 0x400000)

		"""

		if from_arch is None:
			from_arch = self.arch

		core.BNRemoveUserCodeReference(self.handle, from_arch.handle, from_addr, to_addr)

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

		idx = core.BNGetLowLevelILForInstruction(self.handle, arch.handle, addr)

		if idx == len(self.llil):
			return None

		return self.llil[idx]

	def get_low_level_il_exits_at(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		exits = core.BNGetLowLevelILExitsForInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in range(0, count.value):
			result.append(exits[i])
		core.BNFreeILInstructionList(exits)
		return result

	def get_reg_value_at(self, addr, reg, arch=None):
		"""
		``get_reg_value_at`` gets the value the provided string register address corresponding to the given virtual address

		:param int addr: virtual address of the instruction to query
		:param str reg: string value of native register to query
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: binaryninja.function.RegisterValue
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
		:rtype: binaryninja.function.RegisterValue
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
		:rtype: binaryninja.function.RegisterValue

		.. note:: Stack base is zero on entry into the function unless the architecture places the return address on the \
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
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_regs_written_by(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		regs = core.BNGetRegistersWrittenByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_stack_vars_referenced_by(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		refs = core.BNGetStackVariablesReferencedByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in range(0, count.value):
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
		for i in range(0, count.value):
			result.append(ConstantReference(refs[i].value, refs[i].size, refs[i].pointer, refs[i].intermediate))
		core.BNFreeConstantReferenceList(refs)
		return result

	def get_lifted_il_at(self, addr, arch=None):
		if arch is None:
			arch = self.arch

		idx = core.BNGetLiftedILForInstruction(self.handle, arch.handle, addr)

		if idx == len(self.lifted_il):
			return None

		return self.lifted_il[idx]

	def get_lifted_il_flag_uses_for_definition(self, i, flag):
		flag = self.arch.get_flag_index(flag)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILFlagUsesForDefinition(self.handle, i, flag, count)
		result = []
		for i in range(0, count.value):
			result.append(instrs[i])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_lifted_il_flag_definitions_for_use(self, i, flag):
		flag = self.arch.get_flag_index(flag)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILFlagDefinitionsForUse(self.handle, i, flag, count)
		result = []
		for i in range(0, count.value):
			result.append(instrs[i])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_flags_read_by_lifted_il_instruction(self, i):
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsReadByLiftedILInstruction(self.handle, i, count)
		result = []
		for i in range(0, count.value):
			result.append(self.arch._flags_by_index[flags[i]])
		core.BNFreeRegisterList(flags)
		return result

	def get_flags_written_by_lifted_il_instruction(self, i):
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsWrittenByLiftedILInstruction(self.handle, i, count)
		result = []
		for i in range(0, count.value):
			result.append(self.arch._flags_by_index[flags[i]])
		core.BNFreeRegisterList(flags)
		return result

	def create_graph(self, graph_type = FunctionGraphType.NormalFunctionGraph, settings = None):
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return binaryninja.flowgraph.CoreFlowGraph(core.BNCreateFunctionGraph(self.handle, graph_type, settings_obj))

	def apply_imported_types(self, sym):
		core.BNApplyImportedTypes(self.handle, sym.handle)

	def apply_auto_discovered_type(self, func_type):
		core.BNApplyAutoDiscoveredFunctionType(self.handle, func_type.handle)

	def set_auto_indirect_branches(self, source, branches, source_arch=None):
		if source_arch is None:
			source_arch = self.arch
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in range(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNSetAutoIndirectBranches(self.handle, source_arch.handle, source, branch_list, len(branches))

	def set_user_indirect_branches(self, source, branches, source_arch=None):
		if source_arch is None:
			source_arch = self.arch
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in range(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNSetUserIndirectBranches(self.handle, source_arch.handle, source, branch_list, len(branches))

	def get_indirect_branches_at(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		branches = core.BNGetIndirectBranchesAt(self.handle, arch.handle, addr, count)
		result = []
		for i in range(count.value):
			result.append(IndirectBranchInfo(binaryninja.architecture.CoreArchitecture._from_cache(branches[i].sourceArch), branches[i].sourceAddr, binaryninja.architecture.CoreArchitecture._from_cache(branches[i].destArch), branches[i].destAddr, branches[i].autoDefined))
		core.BNFreeIndirectBranchList(branches)
		return result

	def get_block_annotations(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong(0)
		lines = core.BNGetFunctionBlockAnnotations(self.handle, arch.handle, addr, count)
		result = []
		for i in range(count.value):
			result.append(InstructionTextToken.get_instruction_lines(lines[i].tokens, lines[i].count))
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

	def set_auto_return_regs(self, value):
		regs = core.BNRegisterSetWithConfidence()
		regs.regs = (ctypes.c_uint * len(value))()
		regs.count = len(value)
		for i in range(0, len(value)):
			regs.regs[i] = self.arch.get_reg_index(value[i])
		if hasattr(value, 'confidence'):
			regs.confidence = value.confidence
		else:
			regs.confidence = types.max_confidence
		core.BNSetAutoFunctionReturnRegisters(self.handle, regs)

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
		for i in range(0, len(var_list)):
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
		oc = core.BNOffsetWithConfidence()
		oc.value = int(value)
		if hasattr(value, 'confidence'):
			oc.confidence = value.confidence
		else:
			oc.confidence = types.max_confidence
		core.BNSetAutoFunctionStackAdjustment(self.handle, oc)

	def set_auto_reg_stack_adjustments(self, value):
		adjust = (core.BNRegisterStackAdjustment * len(value))()
		i = 0
		for reg_stack in value.keys():
			adjust[i].regStack = self.arch.get_reg_stack_index(reg_stack)
			if isinstance(value[reg_stack], types.RegisterStackAdjustmentWithConfidence):
				adjust[i].adjustment = value[reg_stack].value
				adjust[i].confidence = value[reg_stack].confidence
			else:
				adjust[i].adjustment = value[reg_stack]
				adjust[i].confidence = types.max_confidence
			i += 1
		core.BNSetAutoFunctionRegisterStackAdjustments(self.handle, adjust, len(value))

	def set_auto_clobbered_regs(self, value):
		regs = core.BNRegisterSetWithConfidence()
		regs.regs = (ctypes.c_uint * len(value))()
		regs.count = len(value)
		for i in range(0, len(value)):
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
		return binaryninja.basicblock.BasicBlock(block, self._view)

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
		for i in range(0, count.value):
			addr = lines[i].addr
			color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
			tokens = InstructionTextToken.get_instruction_lines(lines[i].tokens, lines[i].count)
			result.append(DisassemblyTextLine(tokens, addr, color = color))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	def get_reg_value_at_exit(self, reg):
		result = core.BNGetFunctionRegisterValueAtExit(self.handle, self.arch.get_reg_index(reg))
		return RegisterValue(self.arch, result.value, confidence = result.confidence)

	def set_auto_call_stack_adjustment(self, addr, adjust, arch=None):
		if arch is None:
			arch = self.arch
		if not isinstance(adjust, types.SizeWithConfidence):
			adjust = types.SizeWithConfidence(adjust)
		core.BNSetAutoCallStackAdjustment(self.handle, arch.handle, addr, adjust.value, adjust.confidence)

	def set_auto_call_reg_stack_adjustment(self, addr, adjust, arch=None):
		if arch is None:
			arch = self.arch
		adjust_buf = (core.BNRegisterStackAdjustment * len(adjust))()
		i = 0
		for reg_stack in adjust.keys():
			adjust_buf[i].regStack = arch.get_reg_stack_index(reg_stack)
			value = adjust[reg_stack]
			if not isinstance(value, types.RegisterStackAdjustmentWithConfidence):
				value = types.RegisterStackAdjustmentWithConfidence(value)
			adjust_buf[i].adjustment = value.value
			adjust_buf[i].confidence = value.confidence
			i += 1
		core.BNSetAutoCallRegisterStackAdjustment(self.handle, arch.handle, addr, adjust_buf, len(adjust))

	def set_auto_call_reg_stack_adjustment_for_reg_stack(self, addr, reg_stack, adjust, arch=None):
		if arch is None:
			arch = self.arch
		reg_stack = arch.get_reg_stack_index(reg_stack)
		if not isinstance(adjust, types.RegisterStackAdjustmentWithConfidence):
			adjust = types.RegisterStackAdjustmentWithConfidence(adjust)
		core.BNSetAutoCallRegisterStackAdjustmentForRegisterStack(self.handle, arch.handle, addr, reg_stack,
			adjust.value, adjust.confidence)

	def set_call_type_adjustment(self, addr, adjust_type, arch=None):
		if arch is None:
			arch = self.arch
		if adjust_type is None:
			tc = None
		else:
			tc = core.BNTypeWithConfidence()
			tc.type = adjust_type.handle
			tc.confidence = adjust_type.confidence
		core.BNSetUserCallTypeAdjustment(self.handle, arch.handle, addr, tc)

	def set_call_stack_adjustment(self, addr, adjust, arch=None):
		if arch is None:
			arch = self.arch
		if not isinstance(adjust, types.SizeWithConfidence):
			adjust = types.SizeWithConfidence(adjust)
		core.BNSetUserCallStackAdjustment(self.handle, arch.handle, addr, adjust.value, adjust.confidence)

	def set_call_reg_stack_adjustment(self, addr, adjust, arch=None):
		if arch is None:
			arch = self.arch
		adjust_buf = (core.BNRegisterStackAdjustment * len(adjust))()
		i = 0
		for reg_stack in adjust.keys():
			adjust_buf[i].regStack = arch.get_reg_stack_index(reg_stack)
			value = adjust[reg_stack]
			if not isinstance(value, types.RegisterStackAdjustmentWithConfidence):
				value = types.RegisterStackAdjustmentWithConfidence(value)
			adjust_buf[i].adjustment = value.value
			adjust_buf[i].confidence = value.confidence
			i += 1
		core.BNSetUserCallRegisterStackAdjustment(self.handle, arch.handle, addr, adjust_buf, len(adjust))

	def set_call_reg_stack_adjustment_for_reg_stack(self, addr, reg_stack, adjust, arch=None):
		if arch is None:
			arch = self.arch
		reg_stack = arch.get_reg_stack_index(reg_stack)
		if not isinstance(adjust, types.RegisterStackAdjustmentWithConfidence):
			adjust = types.RegisterStackAdjustmentWithConfidence(adjust)
		core.BNSetUserCallRegisterStackAdjustmentForRegisterStack(self.handle, arch.handle, addr, reg_stack,
			adjust.value, adjust.confidence)

	def get_call_type_adjustment(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		result = core.BNGetCallTypeAdjustment(self.handle, arch.handle, addr)
		if result.type:
			platform = self.platform
			return types.Type(result.type, platform = platform, confidence = result.confidence)
		return None

	def get_call_stack_adjustment(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		result = core.BNGetCallStackAdjustment(self.handle, arch.handle, addr)
		return types.SizeWithConfidence(result.value, confidence = result.confidence)

	def get_call_reg_stack_adjustment(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		adjust = core.BNGetCallRegisterStackAdjustment(self.handle, arch.handle, addr, count)
		result = {}
		for i in range(0, count.value):
			result[arch.get_reg_stack_name(adjust[i].regStack)] = types.RegisterStackAdjustmentWithConfidence(
				adjust[i].adjustment, confidence = adjust[i].confidence)
		core.BNFreeRegisterStackAdjustments(adjust)
		return result

	def get_call_reg_stack_adjustment_for_reg_stack(self, addr, reg_stack, arch=None):
		if arch is None:
			arch = self.arch
		reg_stack = arch.get_reg_stack_index(reg_stack)
		adjust = core.BNGetCallRegisterStackAdjustmentForRegisterStack(self.handle, arch.handle, addr, reg_stack)
		result = types.RegisterStackAdjustmentWithConfidence(adjust.adjustment, confidence = adjust.confidence)
		return result

	def is_call_instruction(self, addr, arch=None):
		if arch is None:
			arch = self.arch
		return core.BNIsCallInstruction(self.handle, arch.handle, addr)

	def request_debug_report(self, name):
		core.BNRequestFunctionDebugReport(self.handle, name)
		self.view.update_analysis()

	@property
	def call_sites(self):
		"""
		``call_sites`` returns a list of possible call sites.
		This includes ordinary calls, tail calls, and indirect jumps. Not all of the returned call sites
		may be true call sites; some may simply be unresolved indirect jumps.

		:return: List of References that represent the sources of possible calls in this function
		:rtype: list(ReferenceSource)
		"""
		count = ctypes.c_ulonglong(0)
		refs = core.BNGetFunctionCallSites(self.handle, count)
		result = []
		for i in range(0, count.value):
			if refs[i].func:
				func = binaryninja.function.Function(self, core.BNNewFunctionReference(refs[i].func))
			else:
				func = None
			if refs[i].arch:
				arch = binaryninja.architecture.CoreArchitecture._from_cache(refs[i].arch)
			else:
				arch = None
			addr = refs[i].addr
			result.append(binaryninja.architecture.ReferenceSource(func, arch, addr))
		core.BNFreeCodeReferences(refs, count.value)
		return result

	@property
	def callees(self):
		called = []
		for callee_addr in self.callee_addresses:
			func = self.view.get_function_at(callee_addr, self.platform)
			if func is not None:
				called.append(func)
		return called

	@property
	def callee_addresses(self):
		result = []
		for ref in self.call_sites:
			result.extend(self.view.get_callees(ref.address, ref.function, ref.arch))
		return result

	@property
	def callers(self):
		functions = []
		for ref in self.view.get_code_refs(self.start):
			if ref.function is not None:
				functions.append(ref.function)
		return functions


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
	def __init__(self, tokens, address = None, il_instr = None, color = None):
		self._address = address
		self._tokens = tokens
		self._il_instruction = il_instr
		if color is None:
			self._highlight = highlight.HighlightColor()
		else:
			if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
				raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
			if isinstance(color, HighlightStandardColor):
				color = highlight.HighlightColor(color)
			self._highlight = color

	def __str__(self):
		result = ""
		for token in self.tokens:
			result += token.text
		return result

	def __repr__(self):
		if self.address is None:
			return str(self)
		return "<%#x: %s>" % (self.address, str(self))

	@property
	def address(self):
		""" """
		return self._address

	@address.setter
	def address(self, value):
		self._address = value

	@property
	def tokens(self):
		""" """
		return self._tokens

	@tokens.setter
	def tokens(self, value):
		self._tokens = value

	@property
	def il_instruction(self):
		""" """
		return self._il_instruction

	@il_instruction.setter
	def il_instruction(self, value):
		self._il_instruction = value

	@property
	def highlight(self):
		""" """
		return self._highlight

	@highlight.setter
	def highlight(self, value):
		self._highlight = value


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


class RegisterInfo(object):
	def __init__(self, full_width_reg, size, offset=0, extend=ImplicitRegisterExtend.NoExtend, index=None):
		self._full_width_reg = full_width_reg
		self._offset = offset
		self._size = size
		self._extend = extend
		self._index = index

	def __repr__(self):
		if self._extend == ImplicitRegisterExtend.ZeroExtendToFullWidth:
			extend = ", zero extend"
		elif self._extend == ImplicitRegisterExtend.SignExtendToFullWidth:
			extend = ", sign extend"
		else:
			extend = ""
		return "<reg: size %d, offset %d in %s%s>" % (self._size, self._offset, self._full_width_reg, extend)

	@property
	def full_width_reg(self):
		""" """
		return self._full_width_reg

	@full_width_reg.setter
	def full_width_reg(self, value):
		self._full_width_reg = value

	@property
	def offset(self):
		""" """
		return self._offset

	@offset.setter
	def offset(self, value):
		self._offset = value

	@property
	def size(self):
		""" """
		return self._size

	@size.setter
	def size(self, value):
		self._size = value

	@property
	def extend(self):
		""" """
		return self._extend

	@extend.setter
	def extend(self, value):
		self._extend = value

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value


class RegisterStackInfo(object):
	def __init__(self, storage_regs, top_relative_regs, stack_top_reg, index=None):
		self._storage_regs = storage_regs
		self._top_relative_regs = top_relative_regs
		self._stack_top_reg = stack_top_reg
		self._index = index

	def __repr__(self):
		return "<reg stack: %d regs, stack top in %s>" % (len(self._storage_regs), self._stack_top_reg)

	@property
	def storage_regs(self):
		""" """
		return self._storage_regs

	@storage_regs.setter
	def storage_regs(self, value):
		self._storage_regs = value

	@property
	def top_relative_regs(self):
		""" """
		return self._top_relative_regs

	@top_relative_regs.setter
	def top_relative_regs(self, value):
		self._top_relative_regs = value

	@property
	def stack_top_reg(self):
		""" """
		return self._stack_top_reg

	@stack_top_reg.setter
	def stack_top_reg(self, value):
		self._stack_top_reg = value

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value


class IntrinsicInput(object):
	def __init__(self, type_obj, name=""):
		self._name = name
		self._type = type_obj

	def __repr__(self):
		if len(self._name) == 0:
			return "<input: %s>" % str(self._type)
		return "<input: %s %s>" % (str(self._type), self._name)

	@property
	def name(self):
		""" """
		return self._name

	@name.setter
	def name(self, value):
		self._name = value

	@property
	def type(self):
		""" """
		return self._type

	@type.setter
	def type(self, value):
		self._type = value


class IntrinsicInfo(object):
	def __init__(self, inputs, outputs, index=None):
		self._inputs = inputs
		self._outputs = outputs
		self._index = index

	def __repr__(self):
		return "<intrinsic: %s -> %s>" % (repr(self._inputs), repr(self._outputs))

	@property
	def inputs(self):
		""" """
		return self._inputs

	@inputs.setter
	def inputs(self, value):
		self._inputs = value

	@property
	def outputs(self):
		""" """
		return self._outputs

	@outputs.setter
	def outputs(self, value):
		self._outputs = value

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value


class InstructionBranch(object):
	def __init__(self, branch_type, target = 0, arch = None):
		self._type = branch_type
		self._target = target
		self._arch = arch

	def __repr__(self):
		branch_type = self._type
		if self._arch is not None:
			return "<%s: %s@%#x>" % (branch_type.name, self._arch.name, self._target)
		return "<%s: %#x>" % (branch_type, self._target)

	@property
	def type(self):
		""" """
		return self._type

	@type.setter
	def type(self, value):
		self._type = value

	@property
	def target(self):
		""" """
		return self._target

	@target.setter
	def target(self, value):
		self._target = value

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value


class InstructionInfo(object):
	def __init__(self):
		self.length = 0
		self.arch_transition_by_target_addr = False
		self.branch_delay = False
		self.branches = []

	def add_branch(self, branch_type, target = 0, arch = None):
		self._branches.append(InstructionBranch(branch_type, target, arch))

	def __len__(self):
		return self._length

	def __repr__(self):
		branch_delay = ""
		if self._branch_delay:
			branch_delay = ", delay slot"
		return "<instr: %d bytes%s, %s>" % (self._length, branch_delay, repr(self._branches))

	@property
	def length(self):
		""" """
		return self._length

	@length.setter
	def length(self, value):
		self._length = value

	@property
	def arch_transition_by_target_addr(self):
		""" """
		return self._arch_transition_by_target_addr

	@arch_transition_by_target_addr.setter
	def arch_transition_by_target_addr(self, value):
		self._arch_transition_by_target_addr = value

	@property
	def branch_delay(self):
		""" """
		return self._branch_delay

	@branch_delay.setter
	def branch_delay(self, value):
		self._branch_delay = value

	@property
	def branches(self):
		""" """
		return self._branches

	@branches.setter
	def branches(self, value):
		self._branches = value


class InstructionTextToken(object):
	"""
	``class InstructionTextToken`` is used to tell the core about the various components in the disassembly views.

	The below table is provided for ducmentation purposes but the complete list of TokenTypes is available at: :class:`!enums.InstructionTextTokenType`. Note that types marked as `Not emitted by architectures` are not intended to be used by Architectures during lifting. Rather, they are addded by the core during analysis or display. UI plugins, however, may make use of them as appropriate.
	
	Uses of tokens include plugins that parse the output of an architecture (though parsing IL is recommended), or additionally, applying color schemes appropriately.

		========================== ============================================
		InstructionTextTokenType   Description
		========================== ============================================
		AddressDisplayToken        **Not emitted by architectures**
		AnnotationToken            **Not emitted by architectures**
		ArgumentNameToken          **Not emitted by architectures**
		BeginMemoryOperandToken    The start of memory operand
		CharacterConstantToken     A printable character
		CodeRelativeAddressToken   **Not emitted by architectures**
		CodeSymbolToken            **Not emitted by architectures**
		DataSymbolToken            **Not emitted by architectures**
		EndMemoryOperandToken      The end of a memory operand
		ExternalSymbolToken        **Not emitted by architectures**
		FieldNameToken             **Not emitted by architectures**
		FloatingPointToken         Floating point number
		HexDumpByteValueToken      **Not emitted by architectures**
		HexDumpInvalidByteToken    **Not emitted by architectures**
		HexDumpSkippedByteToken    **Not emitted by architectures**
		HexDumpTextToken           **Not emitted by architectures**
		ImportToken                **Not emitted by architectures**
		IndirectImportToken        **Not emitted by architectures**
		InstructionToken           The instruction mnemonic
		IntegerToken               Integers
		KeywordToken               **Not emitted by architectures**
		LocalVariableToken         **Not emitted by architectures**
		NameSpaceSeparatorToken    **Not emitted by architectures**
		NameSpaceToken             **Not emitted by architectures**
		OpcodeToken                **Not emitted by architectures**
		OperandSeparatorToken      The comma or delimeter that separates tokens
		PossibleAddressToken       Integers that are likely addresses
		RegisterToken              Registers
		StringToken                **Not emitted by architectures**
		StructOffsetToken          **Not emitted by architectures**
		TagToken                   **Not emitted by architectures**
		TextToken                  Used for anything not of another type.
		TypeNameToken              **Not emitted by architectures**
		========================== ============================================

	"""
	def __init__(self, token_type, text, value = 0, size = 0, operand = 0xffffffff,
		context = InstructionTextTokenContext.NoTokenContext, address = 0, confidence = types.max_confidence, typeNames=[], width=0):
		self._type = InstructionTextTokenType(token_type)
		self._text = text
		self._value = value
		self._size = size
		self._operand = operand
		self._context = InstructionTextTokenContext(context)
		self._confidence = confidence
		self._address = address
		self._typeNames = typeNames
		self._width = width
		if width == 0:
			self._width = len(self._text)

	@classmethod
	def get_instruction_lines(cls, tokens, count=0):
		""" Helper method for converting between core.BNInstructionTextToken and InstructionTextToken lists """
		if isinstance(tokens, list):
			result = (core.BNInstructionTextToken * len(tokens))()
			for j in range(len(tokens)):
				result[j].type = tokens[j].type
				result[j].text = tokens[j].text
				result[j].width = tokens[j].width
				result[j].value = tokens[j].value
				result[j].size = tokens[j].size
				result[j].operand = tokens[j].operand
				result[j].context = tokens[j].context
				result[j].confidence = tokens[j].confidence
				result[j].address = tokens[j].address
				result[j].nameCount = len(tokens[j].typeNames)
				result[j].typeNames = (ctypes.c_char_p * len(tokens[j].typeNames))()
				for i in range(len(tokens[j].typeNames)):
					result[j].typeNames[i] = binaryninja.cstr(tokens[j].typeNames[i])
			return result

		result = []
		for j in range(count):
			token_type = InstructionTextTokenType(tokens[j].type)
			text = tokens[j].text
			if not isinstance(text, str):
				text = text.decode("charmap")
			width = tokens[j].width
			value = tokens[j].value
			size = tokens[j].size
			operand = tokens[j].operand
			context = tokens[j].context
			confidence = tokens[j].confidence
			address = tokens[j].address
			typeNames = []
			for i in range(tokens[j].namesCount):
				if not isinstance(tokens[j].typeNames[i], str):
					typeNames.append(tokens[j].typeNames[i].decode("charmap"))
				else:
					typeNames.append(tokens[j].typeNames[i])
			result.append(InstructionTextToken(token_type, text, value, size, operand, context, address, confidence, typeNames, width))
		return result

	def __str__(self):
		return self._text

	def __repr__(self):
		return repr(self._text)

	@property
	def type(self):
		""" """
		return self._type

	@type.setter
	def type(self, value):
		self._type = value

	@property
	def text(self):
		""" """
		return self._text

	@text.setter
	def text(self, value):
		self._text = value

	@property
	def value(self):
		""" """
		return self._value

	@value.setter
	def value(self, value):
		self._value = value

	@property
	def size(self):
		""" """
		return self._size

	@size.setter
	def size(self, value):
		self._size = value

	@property
	def operand(self):
		""" """
		return self._operand

	@operand.setter
	def operand(self, value):
		self._operand = value

	@property
	def context(self):
		""" """
		return self._context

	@context.setter
	def context(self, value):
		self._context = value

	@property
	def confidence(self):
		""" """
		return self._confidence

	@confidence.setter
	def confidence(self, value):
		self._confidence = value

	@property
	def address(self):
		""" """
		return self._address

	@address.setter
	def address(self, value):
		self._address = value

	@property
	def typeNames(self):
		""" """
		return self._typeNames

	@typeNames.setter
	def typeNames(self, value):
		self._typeNames = value

	@property
	def width(self):
		return self._width


class DisassemblyTextRenderer(object):
	def __init__(self, func = None, settings = None, handle = None):
		if handle is None:
			if func is None:
				raise ValueError("function required for disassembly")
			settings_obj = None
			if settings is not None:
				settings_obj = settings.handle
			if isinstance(func, Function):
				self.handle = core.BNCreateDisassemblyTextRenderer(func.handle, settings_obj)
			elif isinstance(func, binaryninja.lowlevelil.LowLevelILFunction):
				self.handle = core.BNCreateLowLevelILDisassemblyTextRenderer(func.handle, settings_obj)
			elif isinstance(func, binaryninja.mediumlevelil.MediumLevelILFunction):
				self.handle = core.BNCreateMediumLevelILDisassemblyTextRenderer(func.handle, settings_obj)
			elif isinstance(func, binaryninja.highlevelil.HighLevelILFunction):
				self.handle = core.BNCreateHighLevelILDisassemblyTextRenderer(func.handle, settings_obj)
			else:
				raise TypeError("invalid function object")
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeDisassemblyTextRenderer(self.handle)

	@property
	def function(self):
		return Function(handle = core.BNGetDisassemblyTextRendererFunction(self.handle))

	@property
	def il_function(self):
		llil = core.BNGetDisassemblyTextRendererLowLevelILFunction(self.handle)
		if llil:
			return binaryninja.lowlevelil.LowLevelILFunction(handle = llil)
		mlil = core.BNGetDisassemblyTextRendererMediumLevelILFunction(self.handle)
		if mlil:
			return binaryninja.mediumlevelil.MediumLevelILFunction(handle = mlil)
		hlil = core.BNGetDisassemblyTextRendererHighLevelILFunction(self.handle)
		if hlil:
			return binaryninja.highlevelil.HighLevelILFunction(handle = hlil)
		return None

	@property
	def basic_block(self):
		result = core.BNGetDisassemblyTextRendererBasicBlock(self.handle)
		if result:
			return binaryninja.basicblock.BasicBlock(handle = result)
		return None

	@basic_block.setter
	def basic_block(self, block):
		if block is not None:
			core.BNSetDisassemblyTextRendererBasicBlock(self.handle, block.handle)
		else:
			core.BNSetDisassemblyTextRendererBasicBlock(self.handle, None)

	@property
	def arch(self):
		return binaryninja.architecture.CoreArchitecture(handle = core.BNGetDisassemblyTextRendererArchitecture(self.handle))

	@arch.setter
	def arch(self, arch):
		core.BNSetDisassemblyTextRendererArchitecture(self.handle, arch.handle)

	@property
	def settings(self):
		return DisassemblySettings(handle = core.BNGetDisassemblyTextRendererSettings(self.handle))

	@settings.setter
	def settings(self, settings):
		if settings is not None:
			core.BNSetDisassemblyTextRendererSettings(self.handle, settings.handle)
		core.BNSetDisassemblyTextRendererSettings(self.handle, None)

	@property
	def il(self):
		return core.BNIsILDisassemblyTextRenderer(self.handle)

	@property
	def has_data_flow(self):
		return core.BNDisassemblyTextRendererHasDataFlow(self.handle)

	def get_instruction_annotations(self, addr):
		count = ctypes.c_ulonglong()
		tokens = core.BNGetDisassemblyTextRendererInstructionAnnotations(self.handle, addr, count)
		result = InstructionTextToken.get_instruction_lines(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	def get_instruction_text(self, addr):
		count = ctypes.c_ulonglong()
		length = ctypes.c_ulonglong()
		lines = ctypes.POINTER(core.BNDisassemblyTextLine)()
		if not core.BNGetDisassemblyTextRendererInstructionText(self.handle, addr, length, lines, count):
			return None, 0
		il_function = self.il_function
		result = []
		for i in range(0, count.value):
			addr = lines[i].addr
			if (lines[i].instrIndex != 0xffffffffffffffff) and (il_function is not None):
				il_instr = il_function[lines[i].instrIndex]
			else:
				il_instr = None
			color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
			tokens = InstructionTextToken.get_instruction_lines(lines[i].tokens, lines[i].count)
			result.append(DisassemblyTextLine(tokens, addr, il_instr, color))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return (result, length.value)

	def get_disassembly_text(self, addr):
		count = ctypes.c_ulonglong()
		length = ctypes.c_ulonglong()
		length.value = 0
		lines = ctypes.POINTER(core.BNDisassemblyTextLine)()
		ok = core.BNGetDisassemblyTextRendererLines(self.handle, addr, length, lines, count)
		if not ok:
			return None, 0
		il_function = self.il_function
		result = []
		for i in range(0, count.value):
			addr = lines[i].addr
			if (lines[i].instrIndex != 0xffffffffffffffff) and (il_function is not None):
				il_instr = il_function[lines[i].instrIndex]
			else:
				il_instr = None
			color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
			tokens = InstructionTextToken.get_instruction_lines(lines[i].tokens, lines[i].count)
			result.append(DisassemblyTextLine(tokens, addr, il_instr, color))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return (result, length.value)

	def post_process_lines(self, addr, length, in_lines, indent_spaces=""):
		if isinstance(in_lines, str):
			in_lines = in_lines.split('\n')
		line_buf = (core.BNDisassemblyTextLine * len(in_lines))()
		for i in range(0, len(in_lines)):
			line = in_lines[i]
			if isinstance(line, str):
				line = DisassemblyTextLine([InstructionTextToken(InstructionTextTokenType.TextToken, line)])
			if not isinstance(line, DisassemblyTextLine):
				line = DisassemblyTextLine(line)
			if line.address is None:
				if len(line.tokens) > 0:
					line_buf[i].addr = line.tokens[0].address
				else:
					line_buf[i].addr = 0
			else:
				line_buf[i].addr = line.address
			if line.il_instruction is not None:
				line_buf[i].instrIndex = line.il_instruction.instr_index
			else:
				line_buf[i].instrIndex = 0xffffffffffffffff
			color = line.highlight
			if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
				raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
			if isinstance(color, HighlightStandardColor):
				color = highlight.HighlightColor(color)
			line_buf[i].highlight = color._get_core_struct()
			line_buf[i].count = len(line.tokens)
			line_buf[i].tokens = InstructionTextToken.get_instruction_lines(line.tokens)
		count = ctypes.c_ulonglong()
		lines = ctypes.POINTER(core.BNDisassemblyTextLine)()
		lines = core.BNPostProcessDisassemblyTextRendererLines(self.handle, addr, length, line_buf, len(in_lines), count, indent_spaces)
		il_function = self.il_function
		result = []
		for i in range(0, count.value):
			addr = lines[i].addr
			if (lines[i].instrIndex != 0xffffffffffffffff) and (il_function is not None):
				il_instr = il_function[lines[i].instrIndex]
			else:
				il_instr = None
			color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
			tokens = InstructionTextToken.get_instruction_lines(lines[i].tokens, lines[i].count)
			result.append(DisassemblyTextLine(tokens, addr, il_instr, color))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	def reset_deduplicated_comments(self):
		core.BNResetDisassemblyTextRendererDeduplicatedComments(self.handle)

	def add_symbol_token(self, tokens, addr, size, operand = None):
		if operand is None:
			operand = 0xffffffff
		count = ctypes.c_ulonglong()
		new_tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		if not core.BNGetDisassemblyTextRendererSymbolTokens(self.handle, addr, size, operand, new_tokens, count):
			return False
		result = binaryninja.function.InstructionTextToken.get_instruction_lines(new_tokens, count.value)
		tokens += result
		core.BNFreeInstructionText(new_tokens, count.value)
		return True

	def add_stack_var_reference_tokens(self, tokens, ref):
		stack_ref = core.BNStackVariableReference()
		if ref.source_operand is None:
			stack_ref.sourceOperand = 0xffffffff
		else:
			stack_ref.sourceOperand = ref.source_operand
		if ref.type is None:
			stack_ref.type = None
			stack_ref.typeConfidence = 0
		else:
			stack_ref.type = ref.type.handle
			stack_ref.typeConfidence = ref.type.confidence
		stack_ref.name = ref.name
		stack_ref.varIdentifier = ref.var.identifier
		stack_ref.referencedOffset = ref.referenced_offset
		stack_ref.size = ref.size
		count = ctypes.c_ulonglong()
		new_tokens = core.BNGetDisassemblyTextRendererStackVariableReferenceTokens(self.handle, stack_ref, count)
		result = InstructionTextToken.get_instruction_lines(new_tokens, count.value)
		tokens += result
		core.BNFreeInstructionText(new_tokens, count.value)

	@classmethod
	def is_integer_token(self, token):
		return core.BNIsIntegerToken(token)

	def add_integer_token(self, tokens, int_token, addr, arch = None):
		if arch is not None:
			arch = arch.handle
		in_token_obj = InstructionTextToken.get_instruction_lines([int_token])
		count = ctypes.c_ulonglong()
		new_tokens = core.BNGetDisassemblyTextRendererIntegerTokens(self.handle, in_token_obj, arch, addr, count)
		result = InstructionTextToken.get_instruction_lines(new_tokens, count.value)
		tokens += result
		core.BNFreeInstructionText(new_tokens, count.value)

	def wrap_comment(self, lines, cur_line, comment, has_auto_annotations, leading_spaces = "  ", indent_spaces = ""):
		cur_line_obj = core.BNDisassemblyTextLine()
		cur_line_obj.addr = cur_line.address
		if cur_line.il_instruction is None:
			cur_line_obj.instrIndex = 0xffffffffffffffff
		else:
			cur_line_obj.instrIndex = cur_line.il_instruction.instr_index
		cur_line_obj.highlight = cur_line.highlight._get_core_struct()
		cur_line_obj.tokens = InstructionTextToken.get_instruction_lines(cur_line.tokens)
		cur_line_obj.count = len(cur_line.tokens)
		count = ctypes.c_ulonglong()
		new_lines = core.BNDisassemblyTextRendererWrapComment(self.handle, cur_line_obj, count, comment,
			has_auto_annotations, leading_spaces, indent_spaces)
		il_function = self.il_function
		for i in range(0, count.value):
			addr = new_lines[i].addr
			if (new_lines[i].instrIndex != 0xffffffffffffffff) and (il_function is not None):
				il_instr = il_function[new_lines[i].instrIndex]
			else:
				il_instr = None
			color = highlight.HighlightColor._from_core_struct(new_lines[i].highlight)
			tokens = InstructionTextToken.get_instruction_lines(new_lines[i].tokens, new_lines[i].count)
			lines.append(DisassemblyTextLine(tokens, addr, il_instr, color))
		core.BNFreeDisassemblyTextLines(new_lines, count.value)
