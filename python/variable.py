# coding=utf-8
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

import ctypes
from typing import Iterable, List, Generator, Optional, Union, Set, Dict, Tuple
from dataclasses import dataclass

import binaryninja
from . import _binaryninjacore as core
from . import databuffer
from . import decorators
from . import types
from .enums import RegisterValueType, VariableSourceType, DeadStoreElimination, FunctionGraphType, BuiltinType

FunctionOrILFunction = Union["binaryninja.function.Function", "binaryninja.lowlevelil.LowLevelILFunction",
                             "binaryninja.mediumlevelil.MediumLevelILFunction",
                             "binaryninja.highlevelil.HighLevelILFunction"]


@dataclass(frozen=True)
class LookupTableEntry:
	from_values: List[int]
	to_value: int
	type: RegisterValueType = RegisterValueType.LookupTableValue

	def __repr__(self):
		return f"[{', '.join([f'{i:#x}' for i in self.from_values])}] -> {self.to_value:#x}"

	def _to_core_struct(self) -> core.BNLookupTableEntry:
		result = core.BNLookupTableEntry()
		result.fromValues = (ctypes.c_longlong * len(self.from_values))()
		for i in range(len(self.from_values)):
			result.fromValues[i] = self.from_values[i]
		result.fromCount = len(self.from_values)
		result.toValue = self.to_value
		return result


@dataclass(frozen=True)
class RegisterValue:
	value: int
	offset: int
	type: RegisterValueType = RegisterValueType.UndeterminedValue
	confidence: int = core.max_confidence
	size: int = 0

	def _to_core_struct(self) -> core.BNRegisterValue:
		result = core.BNRegisterValue()
		result.state = self.type
		result.value = self.value
		result.offset = self.offset
		result.size = self.size
		return result

	def _to_core_struct_with_confidence(self):
		result = core.BNRegisterValueWithConfidence()
		result.value = self._to_core_struct()
		result.confidence = self.confidence
		return result

	def __bool__(self):
		return self.value != 0

	def __int__(self):
		return self.value

	def __eq__(self, other):
		if isinstance(other, int):
			return int(self) == other
		elif isinstance(other, bool):
			return bool(self) == other
		elif isinstance(other, self.__class__):
			return (self.type, self.offset, self.type,
			        self.confidence) == (other.type, other.offset, other.type, other.confidence)
		assert False, f"no comparison for types {repr(self)} and {repr(other)}"

	@classmethod
	def from_BNRegisterValue(
	    cls, reg_value: Union[core.BNRegisterValue, core.BNRegisterValueWithConfidence],
	    arch: Optional['binaryninja.architecture.Architecture'] = None
	) -> 'RegisterValue':
		confidence = core.max_confidence
		if isinstance(reg_value, core.BNRegisterValueWithConfidence):
			confidence = reg_value.confidence
			reg_value = reg_value.value
		if reg_value.state == RegisterValueType.EntryValue:
			reg = None
			if arch is not None:
				reg = arch.get_reg_name(binaryninja.architecture.RegisterIndex(reg_value.value))
			return EntryRegisterValue(reg_value.value, reg=reg, confidence=confidence)
		elif reg_value.state == RegisterValueType.ConstantValue:
			return ConstantRegisterValue(reg_value.value, confidence=confidence)
		elif reg_value.state == RegisterValueType.ConstantPointerValue:
			return ConstantPointerRegisterValue(reg_value.value, confidence=confidence)
		elif reg_value.state == RegisterValueType.StackFrameOffset:
			return StackFrameOffsetRegisterValue(reg_value.value, confidence=confidence)
		elif reg_value.state == RegisterValueType.ResultPointerValue:
			return ResultPointerRegisterValue(reg_value.value, confidence=confidence)
		elif reg_value.state == RegisterValueType.ParameterPointerValue:
			return ParameterPointerRegisterValue(reg_value.value, reg_value.offset, confidence=confidence)
		elif reg_value.state == RegisterValueType.ImportedAddressValue:
			return ImportedAddressRegisterValue(reg_value.value, confidence=confidence)
		elif reg_value.state == RegisterValueType.UndeterminedValue:
			return Undetermined()
		elif reg_value.state == RegisterValueType.ReturnAddressValue:
			return ReturnAddressRegisterValue(reg_value.value, confidence=confidence)
		elif reg_value.state == RegisterValueType.ExternalPointerValue:
			return ExternalPointerRegisterValue(reg_value.value, reg_value.offset, confidence=confidence)
		elif reg_value.state & RegisterValueType.ConstantDataValue == RegisterValueType.ConstantDataValue:
			return ConstantDataRegisterValue(reg_value.value, 0, RegisterValueType(reg_value.state), confidence=confidence, size=reg_value.size)
		assert False, f"RegisterValueType {reg_value.state} not handled"

	@classmethod
	def to_BNRegisterValue(cls, reg_value: 'RegisterValue') -> core.BNRegisterValue:
		return reg_value._to_core_struct()


@dataclass(frozen=True, eq=False)
class Undetermined(RegisterValue):
	value: int = 0
	offset: int = 0
	type: RegisterValueType = RegisterValueType.UndeterminedValue

	def __repr__(self):
		return "<undetermined>"


@dataclass(frozen=True, eq=False)
class ConstantRegisterValue(RegisterValue):
	offset: int = 0
	type: RegisterValueType = RegisterValueType.ConstantValue

	def __repr__(self):
		return f"<const {self.value:#x}>"


@dataclass(frozen=True, eq=False)
class ConstantPointerRegisterValue(RegisterValue):
	offset: int = 0
	type: RegisterValueType = RegisterValueType.ConstantPointerValue

	def __repr__(self):
		return f"<const ptr {self.value:#x}>"


@dataclass(frozen=True, eq=False)
class ImportedAddressRegisterValue(RegisterValue):
	offset: int = 0
	type: RegisterValueType = RegisterValueType.ImportedAddressValue

	def __repr__(self):
		return f"<imported address from entry {self.value:#x}>"


@dataclass(frozen=True, eq=False)
class ReturnAddressRegisterValue(RegisterValue):
	offset: int = 0
	type: RegisterValueType = RegisterValueType.ReturnAddressValue

	def __repr__(self):
		return "<return address>"


@dataclass(frozen=True, eq=False)
class EntryRegisterValue(RegisterValue):
	value: int = 0
	offset: int = 0
	type: RegisterValueType = RegisterValueType.EntryValue
	reg: Optional['binaryninja.architecture.RegisterName'] = None

	def __repr__(self):
		if self.reg is not None:
			return f"<entry {self.reg}>"
		return f"<entry {self.value}>"


@dataclass(frozen=True, eq=False)
class StackFrameOffsetRegisterValue(RegisterValue):
	offset: int = 0
	type: RegisterValueType = RegisterValueType.StackFrameOffset

	def __repr__(self):
		return f"<stack frame offset {self.value:#x}>"


@dataclass(frozen=True, eq=False)
class ResultPointerRegisterValue(RegisterValue):
	offset: int = 0
	type: RegisterValueType = RegisterValueType.ResultPointerValue

	def __repr__(self):
		return f"<result ptr offset {self.value:#x}>"

@dataclass(frozen=True, eq=False)
class ParameterPointerRegisterValue(RegisterValue):
	offset: int = 0
	type: RegisterValueType = RegisterValueType.ParameterPointerValue

	def __repr__(self):
		return f"<parameter {self.value} ptr offset {self.offset:#x}>"


@dataclass(frozen=True, eq=False)
class ExternalPointerRegisterValue(RegisterValue):
	type: RegisterValueType = RegisterValueType.ExternalPointerValue

	def __repr__(self):
		return f"<external {self.value:#x} + offset {self.offset:#x}>"


@dataclass(frozen=True, eq=False)
class ConstantDataRegisterValue(RegisterValue):

	def __repr__(self):
		if self.type == RegisterValueType.ConstantDataZeroExtendValue:
			return f"<const data {{zx.{self.size}({self.value:#x})}}>"
		if self.type == RegisterValueType.ConstantDataSignExtendValue:
			return f"<const data {{sx.{self.size}({self.value:#x})}}>"
		if self.type == RegisterValueType.ConstantDataAggregateValue:
			return f"<const data {{aggregate.{self.size}}} @ {self.value:#x}>"
		return f"<const data {{invalid}} {self.type} {self.value:#x}>"


@dataclass(frozen=True, eq=False)
class ConstantData(RegisterValue):
	function: '_function.Function' = None

	def __repr__(self):
		if self.type == RegisterValueType.ConstantDataZeroExtendValue:
			return f"<{self.__class__.__name__}: {{zx.{self.size}({self.value:#x})}}>"
		if self.type == RegisterValueType.ConstantDataSignExtendValue:
			return f"<{self.__class__.__name__}: {{sx.{self.size}({self.value:#x})}}>"
		if self.type == RegisterValueType.ConstantDataAggregateValue:
			return f"<{self.__class__.__name__}: {{aggregate.{self.size}}} @ {self.value:#x}>"
		return f"<{self.__class__.__name__}: {{invalid}} {self.type} {self.value:#x}>"

	@property
	def data(self) -> databuffer.DataBuffer:
		if self.function is None:
			raise ValueError(f"ConstantData requires a Function instance: {self.size}")
		return self.function.get_constant_data(self.type, self.value, self.size)

	@property
	def data_and_builtin(self) -> Tuple[databuffer.DataBuffer, BuiltinType]:
		if self.function is None:
			raise ValueError(f"ConstantData requires a Function instance: {self.size}")
		return self.function.get_constant_data_and_builtin(self.type, self.value, self.size)


@dataclass(frozen=True)
class ValueRange:
	start: int
	end: int
	step: int

	def __repr__(self):
		if self.step == 1:
			return f"<range: {self.start:#x} to {self.end:#x}>"
		return f"<range: {self.start:#x} to {self.end:#x}, step {self.step:#x}>"

	def __contains__(self, other):
		if not isinstance(other, int):
			return NotImplemented
		return other in range(self.start, self.end, self.step)


@decorators.passive
class PossibleValueSet:
	"""
	`class PossibleValueSet` PossibleValueSet is used to define possible values
	that a variable can take. It contains methods to instantiate different
	value sets such as Constant, Signed/Unsigned Ranges, etc.
	"""
	def __init__(
		self,
		arch: Optional['binaryninja.architecture.Architecture'] = None,
		value: Optional[core.BNPossibleValueSet] = None,
	):
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
		elif value.state == RegisterValueType.ResultPointerValue:
			self._offset = value.value
		elif value.state == RegisterValueType.ParameterPointerValue:
			self._value = value.value
			self._offset = value.offset
		elif value.state & RegisterValueType.ConstantDataValue == RegisterValueType.ConstantDataValue:
			self._value = value.value
			self._size = value.size
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
		self._count = value.count

	def __repr__(self):
		if self._type == RegisterValueType.EntryValue:
			return f"<entry {self.reg}>"
		if self._type == RegisterValueType.ConstantValue:
			return f"<const {self.value:#x}>"
		if self._type == RegisterValueType.ConstantPointerValue:
			return f"<const ptr {self.value:#x}>"
		if self._type == RegisterValueType.StackFrameOffset:
			return f"<stack frame offset {self._offset:#x}>"
		if self._type == RegisterValueType.ResultPointerValue:
			return f"<result ptr offset {self._offset:#x}>"
		if self._type == RegisterValueType.ParameterPointerValue:
			return f"<parameter {self._value} ptr offset {self._offset:#x}>"
		if self._type == RegisterValueType.ConstantDataZeroExtendValue:
			return f"<const data {{zx.{self._size}({self.value:#x})}}>"
		if self._type == RegisterValueType.ConstantDataSignExtendValue:
			return f"<const data {{sx.{self._size}({self.value:#x})}}>"
		if self._type == RegisterValueType.ConstantDataAggregateValue:
			return f"<const data {{aggregate.{self._size}}} @ {self.value:#x}>"
		if self._type == RegisterValueType.SignedRangeValue:
			return f"<signed ranges: {repr(self.ranges)}>"
		if self._type == RegisterValueType.UnsignedRangeValue:
			return f"<unsigned ranges: {repr(self.ranges)}>"
		if self._type == RegisterValueType.LookupTableValue:
			return f"<table: {', '.join([repr(i) for i in self.table])}>"
		if self._type == RegisterValueType.InSetOfValues:
			return f"<in set([{', '.join(hex(i) for i in sorted(self.values))}])>"
		if self._type == RegisterValueType.NotInSetOfValues:
			return f"<not in set([{', '.join(hex(i) for i in sorted(self.values))}])>"
		if self._type == RegisterValueType.ReturnAddressValue:
			return "<return address>"
		return "<undetermined>"

	def __contains__(self, other):
		if self.type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue
		                 ] and isinstance(other, int):
			return self.value == other
		if self.type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue
		                 ] and hasattr(other, "value"):
			return self.value == other.value
		if not isinstance(other, int):
			return NotImplemented
		#Initial implementation only checks numbers, no set logic
		if self.type in [RegisterValueType.StackFrameOffset, RegisterValueType.ResultPointerValue, RegisterValueType.ParameterPointerValue]:
			return NotImplemented
		if self.type in [RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue]:
			for rng in self.ranges:
				if other in rng:
					return True
			return False
		if self.type == RegisterValueType.InSetOfValues:
			return other in self.values
		if self.type == RegisterValueType.NotInSetOfValues:
			return other not in self.values
		return NotImplemented

	def __eq__(self, other):
		# Allow comparing some value types to an int
		if self.type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue
		                 ] and isinstance(other, int):
			return self.value == other

		# Otherwise just allow comparing to other PossibleValueSet instances
		if not isinstance(other, self.__class__):
			return NotImplemented

		# If the PVS type isn't the same, they're not equal
		if self.type != other.type:
			return False

		if self.type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue]:
			return self.value == other.value
		elif self.type == RegisterValueType.StackFrameOffset:
			return self.offset == other.offset
		elif self.type == RegisterValueType.ResultPointerValue:
			return self.offset == other.offset
		elif self.type == RegisterValueType.ParameterPointerValue:
			return self.value == other.value and self.offset == other.offset
		elif self.type & RegisterValueType.ConstantDataValue == RegisterValueType.ConstantDataValue:
			return self.value == other.value and self._size == other._size
		elif self.type in [RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue]:
			return self.ranges == other.ranges
		elif self.type in [RegisterValueType.InSetOfValues, RegisterValueType.NotInSetOfValues]:
			return self.values == other.values
		elif self.type == RegisterValueType.UndeterminedValue:
			return True # UndeterminedValue is always equal to itself
		elif self.type == RegisterValueType.LookupTableValue:
			return self.table == other.table and self.mapping == other.mapping
		return NotImplemented

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def _to_core_struct(self) -> core.BNPossibleValueSet:
		result = core.BNPossibleValueSet()
		result.state = RegisterValueType(self.type)
		if self.type == RegisterValueType.UndeterminedValue:
			return result
		elif self.type == RegisterValueType.ConstantValue:
			result.value = self.value
		elif self.type == RegisterValueType.ConstantPointerValue:
			result.value = self.value
		elif self.type == RegisterValueType.StackFrameOffset:
			result.offset = self.offset
		elif self.type == RegisterValueType.ResultPointerValue:
			result.value = self.offset
		elif self.type == RegisterValueType.ParameterPointerValue:
			result.value = self.value
			result.offset = self.offset
		elif self.type & RegisterValueType.ConstantDataValue == RegisterValueType.ConstantDataValue:
			result.value = self.value
			result.size = self.size
		elif self.type == RegisterValueType.SignedRangeValue:
			result.offset = self.value
			result.ranges = (core.BNValueRange * self.count)()
			for i in range(0, self.count):
				start = self.ranges[i].start
				end = self.ranges[i].end
				if start & (1 << 63):
					start |= ~((1 << 63) - 1)
				if end & (1 << 63):
					end |= ~((1 << 63) - 1)
				value_range = core.BNValueRange()
				value_range.start = start
				value_range.end = end
				value_range.step = self.ranges[i].step
				result.ranges[i] = value_range
			result.count = self.count
		elif self.type == RegisterValueType.UnsignedRangeValue:
			result.offset = self.value
			result.ranges = (core.BNValueRange * self.count)()
			for i in range(0, self.count):
				value_range = core.BNValueRange()
				value_range.start = self.ranges[i].start
				value_range.end = self.ranges[i].end
				value_range.step = self.ranges[i].step
				result.ranges[i] = value_range
			result.count = self.count
		elif self.type == RegisterValueType.LookupTableValue:
			result.table = (core.BNLookupTableEntry * self.count)()
			result.mapping = self.mapping
			for i in range(self.count):
				result.table[i] = self.table[i]._to_core_struct()
			result.count = self.count
		elif (self.type == RegisterValueType.InSetOfValues) or (self.type == RegisterValueType.NotInSetOfValues):
			values = (ctypes.c_longlong * self.count)()
			i = 0
			for value in self.values:
				values[i] = value
				i += 1
			int_ptr = ctypes.POINTER(ctypes.c_longlong)
			result.valueSet = ctypes.cast(values, int_ptr)
			result.count = self.count
		return result

	@property
	def type(self) -> RegisterValueType:
		return self._type

	@property
	def reg(self) -> 'binaryninja.architecture.RegisterName':
		return self._reg

	@property
	def value(self) -> int:
		return self._value

	@property
	def offset(self) -> int:
		return self._offset

	@property
	def size(self) -> int:
		return self._size

	@property
	def ranges(self) -> List[ValueRange]:
		return self._ranges

	@property
	def table(self) -> List[LookupTableEntry]:
		return self._table

	@property
	def mapping(self) -> Dict[int, int]:
		return self._mapping

	@property
	def values(self) -> Set[int]:
		return self._values

	@property
	def count(self) -> int:
		return self._count

	@staticmethod
	def undetermined() -> 'PossibleValueSet':
		"""
		Create a PossibleValueSet object of type UndeterminedValue.

		:return: PossibleValueSet object of type UndeterminedValue
		:rtype: PossibleValueSet
		"""
		return PossibleValueSet()

	@staticmethod
	def constant(value: int) -> 'PossibleValueSet':
		"""
		Create a constant valued PossibleValueSet object.

		:param int value: Integer value of the constant
		:rtype: PossibleValueSet
		"""
		result = PossibleValueSet()
		result._type = RegisterValueType.ConstantValue
		result._value = value
		return result

	@staticmethod
	def constant_ptr(value: int) -> 'PossibleValueSet':
		"""
		Create constant pointer valued PossibleValueSet object.

		:param int value: Integer value of the constant pointer
		:rtype: PossibleValueSet
		"""
		result = PossibleValueSet()
		result._type = RegisterValueType.ConstantPointerValue
		result._value = value
		return result

	@staticmethod
	def stack_frame_offset(offset: int) -> 'PossibleValueSet':
		"""
		Create a PossibleValueSet object for a stack frame offset.

		:param int offset: Integer value of the offset
		:rtype: PossibleValueSet
		"""
		result = PossibleValueSet()
		result._type = RegisterValueType.StackFrameOffset
		result._offset = offset
		return result

	@staticmethod
	def result_pointer(offset: int) -> 'PossibleValueSet':
		"""
		Create a PossibleValueSet object for a pointer to the return value when the return value
		is stored at an unknown location in memory. This is typically used for calling conventions
		that pass in a pointer to the storage location for the return value.

		:param int offset: Integer value of the offset
		:rtype: PossibleValueSet
		"""
		result = PossibleValueSet()
		result._type = RegisterValueType.ResultPointerValue
		result._value = offset
		return result

	@staticmethod
	def parameter_pointer(idx: int, offset: int) -> 'PossibleValueSet':
		"""
		Create a PossibleValueSet object for a pointer to a parameter when the parameter is
		stored at an unknown location in memory. This is typically used for calling conventions
		that pass in a pointer to the storage location for parameters (usually larger than
		can be held in a register).

		:param int idx: Index of the parameter
		:param int offset: Integer value of the offset
		:rtype: PossibleValueSet
		"""
		result = PossibleValueSet()
		result._type = RegisterValueType.ParameterPointerValue
		result._value = idx
		result._offset = offset
		return result

	@staticmethod
	def signed_range_value(ranges: List[ValueRange]) -> 'PossibleValueSet':
		"""
		Create a PossibleValueSet object for a signed range of values.

		:param list(ValueRange) ranges: List of ValueRanges
		:rtype: PossibleValueSet
		:Example:

			>>> v_1 = ValueRange(-5, -1, 1)
			>>> v_2 = ValueRange(7, 10, 1)
			>>> val = PossibleValueSet.signed_range_value([v_1, v_2])
			<signed ranges: [<range: -0x5 to -0x1>, <range: 0x7 to 0xa>]>
		"""
		result = PossibleValueSet()
		result._value = 0
		result._type = RegisterValueType.SignedRangeValue
		result._ranges = ranges
		result._count = len(ranges)
		return result

	@staticmethod
	def unsigned_range_value(ranges: List[ValueRange]) -> 'PossibleValueSet':
		"""
		Create a PossibleValueSet object for a unsigned signed range of values.

		:param list(ValueRange) ranges: List of ValueRanges
		:rtype: PossibleValueSet
		:Example:

			>>> v_1 = ValueRange(0, 5, 1)
			>>> v_2 = ValueRange(7, 10, 1)
			>>> val = PossibleValueSet.unsigned_range_value([v_1, v_2])
			<unsigned ranges: [<range: 0x0 to 0x5>, <range: 0x7 to 0xa>]>
		"""
		result = PossibleValueSet()
		result._value = 0
		result._type = RegisterValueType.UnsignedRangeValue
		result._ranges = ranges
		result._count = len(ranges)
		return result

	@staticmethod
	def in_set_of_values(values: Iterable[int]) -> 'PossibleValueSet':
		"""
		Create a PossibleValueSet object for a value in a set of values.

		:param Iterable[int] values: Iterable of integer values
		:rtype: PossibleValueSet
		"""
		result = PossibleValueSet()
		result._type = RegisterValueType.InSetOfValues
		result._values = set(values)
		result._count = len(values)
		return result

	@staticmethod
	def not_in_set_of_values(values: Iterable[int]) -> 'PossibleValueSet':
		"""
		Create a PossibleValueSet object for a value NOT in a set of values.

		:param Iterable[int] values: Iterable of integer values
		:rtype: PossibleValueSet
		"""
		result = PossibleValueSet()
		result._type = RegisterValueType.NotInSetOfValues
		result._values = set(values)
		result._count = len(values)
		return result

	@staticmethod
	def lookup_table_value(lookup_table: List[LookupTableEntry], mapping: Dict[int, int]) -> 'PossibleValueSet':
		"""
		Create a PossibleValueSet object for a value which is a member of a
		lookup table.

		:param list(LookupTableEntry) lookup_table: List of table entries
		:param dict of (int, int) mapping: Mapping used for resolution
		:rtype: PossibleValueSet
		"""
		result = PossibleValueSet()
		result._type = RegisterValueType.LookupTableValue
		result._table = lookup_table
		result._mapping = mapping
		result._count = len(lookup_table)
		return result

	def union(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Compute the union of two PossibleValueSets."""
		res = core.BNPossibleValueSetUnion(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def intersection(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Compute the intersection of two PossibleValueSets."""
		res = core.BNPossibleValueSetIntersection(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def add(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Add two PossibleValueSets."""
		res = core.BNPossibleValueSetAdd(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def subtract(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Subtract two PossibleValueSets."""
		res = core.BNPossibleValueSetSubtract(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def multiply(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Multiply two PossibleValueSets."""
		res = core.BNPossibleValueSetMultiply(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def signed_divide(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform signed division of two PossibleValueSets."""
		res = core.BNPossibleValueSetSignedDivide(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def unsigned_divide(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform unsigned division of two PossibleValueSets."""
		res = core.BNPossibleValueSetUnsignedDivide(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def signed_mod(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform signed modulo of two PossibleValueSets."""
		res = core.BNPossibleValueSetSignedMod(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def unsigned_mod(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform unsigned modulo of two PossibleValueSets."""
		res = core.BNPossibleValueSetUnsignedMod(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def and_(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform bitwise AND of two PossibleValueSets."""
		res = core.BNPossibleValueSetAnd(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def or_(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform bitwise OR of two PossibleValueSets."""
		res = core.BNPossibleValueSetOr(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def xor(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform bitwise XOR of two PossibleValueSets."""
		res = core.BNPossibleValueSetXor(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def shift_left(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform left shift of two PossibleValueSets."""
		res = core.BNPossibleValueSetShiftLeft(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def logical_shift_right(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform logical right shift of two PossibleValueSets."""
		res = core.BNPossibleValueSetLogicalShiftRight(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def arith_shift_right(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform arithmetic right shift of two PossibleValueSets."""
		res = core.BNPossibleValueSetArithShiftRight(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def rotate_left(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform left rotation of two PossibleValueSets."""
		res = core.BNPossibleValueSetRotateLeft(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def rotate_right(self, other: "PossibleValueSet", size: int) -> "PossibleValueSet":
		"""Perform right rotation of two PossibleValueSets."""
		res = core.BNPossibleValueSetRotateRight(ctypes.pointer(self._to_core_struct()), ctypes.pointer(other._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def negate(self, size: int) -> "PossibleValueSet":
		"""Negate a PossibleValueSet."""
		res = core.BNPossibleValueSetNegate(ctypes.pointer(self._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs

	def not_(self, size: int) -> "PossibleValueSet":
		"""Perform bitwise NOT of a PossibleValueSet."""
		res = core.BNPossibleValueSetNot(ctypes.pointer(self._to_core_struct()), size)
		pvs = PossibleValueSet(value=res)
		core.BNFreePossibleValueSet(ctypes.pointer(res))
		return pvs


@dataclass(frozen=True)
class StackVariableReference:
	_source_operand: Optional[int]
	type: 'binaryninja.types.Type'
	name: str
	var: 'Variable'
	referenced_offset: int
	size: int

	def __repr__(self):
		if self.source_operand is None:
			if self.referenced_offset != self.var.storage:
				return f"<ref to {self.name}{self.referenced_offset - self.var.storage:+#x}>"
			return f"<ref to {self.name}>"
		if self.referenced_offset != self.var.storage:
			return f"<operand {self.source_operand} ref to {self.var.storage}{self.var.storage:+#x}>"
		return f"<operand {self.source_operand} ref to {self.name}>"

	@property
	def source_operand(self):
		if self._source_operand == 0xffffffff:
			return None
		return self._source_operand


@dataclass(frozen=True, order=True)
class CoreVariable:
	"""
	``class CoreVariable`` is the base class for other variable types,
	such as :py:meth:`VariableNameAndType` and :py:meth:`Variable`

	:cvar index: Internal identifier
	:cvar storage: If this variable is a stack variable
		(`source_type == VariableSourceType.StackVariableSourceType`),
		then the storage location is the offset onto the stack that contains
		the first byte of this variable. Otherwise it's used as an internal identifier.
	"""
	_source_type: int
	index: int
	storage: int

	@property
	def identifier(self) -> int:
		"""A UID for a variable within a function."""
		return core.BNToVariableIdentifier(self.to_BNVariable())

	@property
	def source_type(self) -> VariableSourceType:
		"""Whether this variable was created based off of an underlying register, stack location, or flag."""
		return VariableSourceType(self._source_type)

	def to_BNVariable(self):
		v = core.BNVariable()
		v.type = self._source_type
		v.index = self.index
		v.storage = self.storage
		return v

	@classmethod
	def from_BNVariable(cls, var: core.BNVariable):
		return cls(var.type, var.index, var.storage)

	@classmethod
	def from_identifier(cls, identifier):
		var = core.BNFromVariableIdentifier(identifier)
		return cls(var.type, var.index, var.storage)

	@classmethod
	def reg(cls, reg: int):
		return cls(VariableSourceType.RegisterVariableSourceType, 0, int(reg))

	@classmethod
	def flag(cls, flag: int):
		return cls(VariableSourceType.FlagVariableSourceType, 0, int(flag))

	@classmethod
	def stack_offset(cls, offset: int):
		return cls(VariableSourceType.StackVariableSourceType, 0, int(offset))


@dataclass(frozen=True, order=True)
class VariableNameAndType(CoreVariable):
	"""
	``class VariableNameAndType`` is a lightweight wrapper around a
	variable and its name, useful for shuttling between APIs that require
	them both. While :py:meth:`Variable` has :py:meth:`Variable.name` and
	:py:meth:`Variable.type` fields, those require additional core calls
	each time you fetch them.

	:cvar name: The variable's name
	:cvar type: The variable's type
	"""
	name: str
	type: 'binaryninja.types.Type'

	@classmethod
	def from_identifier(cls, identifier, name, type):
		var = core.BNFromVariableIdentifier(identifier)
		return cls(var.type, var.index, var.storage, name, type)

	@classmethod
	def from_core_variable(cls, var, name, type):
		return cls(var.type, var.index, var.storage, name, type)


class ArchitectureVariable(CoreVariable):
	"""
	``class ArchitectureVariable`` is a wrapper around :py:meth:`CoreVariable` that
	is bound to an architecture (for register/flag naming) but not a function. This
	is typically used in calling conventions for specifying value locations. Calling
	conventions can be used outside functions to resolve type information, so only
	an architecture is required.
	"""
	def __init__(
		self, arch: 'binaryninja.architecture.Architecture', source_type: VariableSourceType, index: int,
		storage: int
	):
		super().__init__(int(source_type), index, storage)
		self._arch = arch

	@property
	def arch(self) -> 'binaryninja.architecture.Architecture':
		return self._arch

	@classmethod
	def reg(cls, arch: 'binaryninja.architecture.Architecture', reg: Union[str, int]):
		if isinstance(reg, str):
			if reg not in arch.regs:
				raise ValueError(f"Invalid register name: {reg}")
			reg = arch.regs[reg].index
		return cls(arch, VariableSourceType.RegisterVariableSourceType, 0, int(reg))

	@classmethod
	def flag(cls, arch: 'binaryninja.architecture.Architecture', flag: Union[str, int]):
		if isinstance(flag, str):
			flag = arch.get_flag_by_name(flag)
		return cls(arch, VariableSourceType.FlagVariableSourceType, 0, int(flag))

	@classmethod
	def stack_offset(cls, arch: 'binaryninja.architecture.Architecture', offset: int):
		return cls(arch, VariableSourceType.StackVariableSourceType, 0, int(offset))

	@property
	def name(self) -> str:
		if self.source_type == VariableSourceType.RegisterVariableSourceType:
			return str(self._arch.get_reg_name(binaryninja.architecture.RegisterIndex(self.storage)))
		if self.source_type == VariableSourceType.FlagVariableSourceType:
			return str(self._arch.get_flag_name(binaryninja.architecture.FlagIndex(self.storage)))
		return hex(self.storage)

	@classmethod
	def from_core_variable(cls, arch: 'binaryninja.architecture.Architecture', var: CoreVariable):
		return cls(arch, var.source_type, var.index, var.storage)

	@classmethod
	def from_BNVariable(cls, arch: 'binaryninja.architecture.Architecture', var: core.BNVariable):
		return cls(arch, var.type, var.index, var.storage)

	@classmethod
	def from_identifier(cls, arch: 'binaryninja.architecture.Architecture', identifier: int):
		var = core.BNFromVariableIdentifier(identifier)
		return cls(arch, VariableSourceType(var.type), var.index, var.storage)

	def _sort_key(self):
		if self._arch is None:
			arch_key = ""
		else:
			arch_key = self._arch.name
		return arch_key, self._source_type, self.index, self.storage

	def __repr__(self):
		if self.source_type == VariableSourceType.StackVariableSourceType:
			return f"<var @ stack offset {self.storage:#x}>"
		return f"<var @ {self.name}>"

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return super().__eq__(other) and (self._arch == other._arch)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __lt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._sort_key() < other._sort_key()

	def __gt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._sort_key() > other._sort_key()

	def __le__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._sort_key() <= other._sort_key()

	def __ge__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._sort_key() >= other._sort_key()

	def __hash__(self):
		return hash((self._arch, super().__hash__()))


class Variable(CoreVariable):
	"""
	``class Variable`` represents variables in Binary Ninja. Variables are resolved
	in medium level IL, so variables objects are only valid for MLIL and above.
	"""
	def __init__(self, func: FunctionOrILFunction, source_type: VariableSourceType, index: int, storage: int):
		super().__init__(int(source_type), index, storage)
		if isinstance(func, binaryninja.function.Function):
			self._function = func
			self._il_function = None
		else:
			self._function = func.source_function
			self._il_function = func

	@classmethod
	def from_variable_name_and_type(cls, func: FunctionOrILFunction, var: VariableNameAndType):
		return cls(func, VariableSourceType(var.type), var.index, var.storage)

	@classmethod
	def from_core_variable(cls, func: FunctionOrILFunction, var: CoreVariable):
		return cls(func, var.source_type, var.index, var.storage)

	@classmethod
	def from_BNVariable(cls, func: FunctionOrILFunction, var: core.BNVariable):
		return cls(func, var.type, var.index, var.storage)

	@classmethod
	def from_identifier(cls, func: FunctionOrILFunction, identifier: int):
		var = core.BNFromVariableIdentifier(identifier)
		return cls(func, VariableSourceType(var.type), var.index, var.storage)

	def __repr__(self):
		if self.type is not None:
			return f"<var {self.type.get_string_before_name()} {self.name}{self.type.get_string_after_name()}>"
		else:
			return f"<var {self.name}>"

	def __str__(self):
		return self.name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return super().__eq__(other) and (self._function == other._function)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __lt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return super().__lt__(other) and self._function < other._function

	def __gt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return super().__gt__(other) and self._function > other._function

	def __le__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return super().__le__(other) and self._function <= other._function

	def __ge__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return super().__ge__(other) and self._function >= other._function

	def __hash__(self):
		return hash((self._function, super().__hash__()))

	@property
	def core_variable(self) -> CoreVariable:
		"""Retrieve the underlying :py:meth:`CoreVariable` class"""
		return CoreVariable(self._source_type, self.index, self.storage)

	@property
	def var_name_and_type(self) -> VariableNameAndType:
		"""Convert to :py:meth:`VariableNameAndType` """
		return VariableNameAndType.from_core_variable(self, self.name, self.type)

	@property
	def name(self) -> str:
		"""Name of the variable, Settings this property is slow because it ensures that analysis has been updated. If you are renaming many variables, use :py:meth:`set_name_async`, then call :py:meth:`update_analysis` when complete."""
		return core.BNGetVariableNameOrDefault(self._function.handle, self.to_BNVariable())

	@name.setter
	def name(self, name: Optional[str]) -> None:
		self.set_name_async(name)
		self._function.view.update_analysis_and_wait()

	@property
	def last_seen_name(self) -> str:
		"""Name of the variable, or the name most recently assigned if the variable has since been removed (read-only). """
		return core.BNGetLastSeenVariableNameOrDefault(self._function.handle, self.to_BNVariable())

	@property
	def type(self) -> Optional['binaryninja.types.Type']:
		var_type_conf = core.BNGetVariableType(self._function.handle, self.to_BNVariable())
		if var_type_conf.type:
			return binaryninja.types.Type.create(var_type_conf.type, self._function.platform, var_type_conf.confidence)
		return None

	@type.setter
	def type(self, new_type: 'binaryninja.types.Type') -> None:
		self.set_type_async(new_type)
		self._function.view.update_analysis_and_wait()

	@property
	def ssa_versions(self) -> Generator[int, None, None]:
		"""Returns the SSA versions associated with this variable. Doesn't return anything for aliased variables."""
		if self._il_function is None:
			raise NotImplementedError("No IL function associated with variable")

		version_count = ctypes.c_ulonglong()
		if self._il_function.il_form in [
		    FunctionGraphType.MediumLevelILFunctionGraph, FunctionGraphType.MediumLevelILSSAFormFunctionGraph
		]:
			versions = core.BNGetMediumLevelILVariableSSAVersions(
			    self._il_function.handle, self.to_BNVariable(), version_count
			)
		elif self._il_function.il_form in [
		    FunctionGraphType.HighLevelILFunctionGraph, FunctionGraphType.HighLevelILSSAFormFunctionGraph
		]:
			versions = core.BNGetHighLevelILVariableSSAVersions(
			    self._il_function.handle, self.to_BNVariable(), version_count
			)
		else:
			raise NotImplementedError("Unsupported IL form")

		if versions is None:
			raise NotImplementedError("No SSA versions; is this an aliased variable?")

		try:
			for version_i in range(version_count.value):
				yield versions[version_i]
		finally:
			core.BNFreeILInstructionList(versions)

	@property
	def dead_store_elimination(self) -> DeadStoreElimination:
		"""returns the dead store elimination setting for this variable"""
		return DeadStoreElimination(
		    core.BNGetFunctionVariableDeadStoreElimination(self._function.handle, self.to_BNVariable())
		)

	@dead_store_elimination.setter
	def dead_store_elimination(self, value):
		core.BNSetFunctionVariableDeadStoreElimination(self._function.handle, self.to_BNVariable(), value)

	@property
	def is_parameter_variable(self) -> bool:
		"""returns whether this variable is a function parameter"""
		return self in self._function.parameter_vars

	@property
	def offset_to_next_variable(self) -> Optional[int]:
		"""returns number of bytes to the next variable on the stack"""
		if self.source_type != VariableSourceType.StackVariableSourceType:
			return None

		for i, var in enumerate(self._function.stack_layout):
			if var == self:
				if i+1 < len(self._function.stack_layout):
					return abs(self.storage - self._function.stack_layout[i+1].storage)
				else:
					return abs(self.storage)
		return None

	@property
	def function(self) -> 'binaryninja.function.Function':
		"""returns the source Function object which this variable belongs to"""
		return self._function

	@property
	def il_function(self) -> 'function.ILFunctionType':
		"""returns the IL Function object which this variable belongs to"""
		return self._il_function

	def set_name_async(self, name: Optional[str]) -> None:
		"""
		``set_name_async`` provides a way to asynchronously set the name of a variable. This method should be used
		when speed is of concern.
		"""
		if name is None:
			name = ""
		self._function.create_user_var(self, self.type, name)

	def set_type_async(self, new_type: 'binaryninja.types.Type') -> None:
		"""
		``set_type_async`` provides a way to asynchronously set the type of a variable. This method should be used
		when speed is of concern.
		"""
		self._function.create_user_var(self, new_type, self.name)

	def set_name_and_type_async(self, name: Optional[str], new_type: 'binaryninja.types.Type') -> None:
		"""
		``set_name_and_type_async`` provides a way to asynchronously set both the name and type of a variable. This method should be used
		when speed is of concern.
		"""
		self._function.create_user_var(self, new_type, name)


@dataclass(frozen=True)
class ConstantReference:
	value: int
	size: int
	pointer: bool
	intermediate: bool

	def __repr__(self):
		if self.pointer:
			return "<constant pointer %#x>" % self.value
		if self.size == 0:
			return "<constant %#x>" % self.value
		return "<constant %#x size %d>" % (self.value, self.size)


@dataclass(frozen=True)
class IndirectBranchInfo:
	source_arch: 'binaryninja.architecture.Architecture'
	source_addr: int
	dest_arch: 'binaryninja.architecture.Architecture'
	dest_addr: int
	auto_defined: bool

	def __repr__(self):
		return f"<branch {self.source_arch.name}:{self.source_addr:#x} -> {self.dest_arch.name}:{self.dest_addr:#x}>"


@decorators.passive
class ParameterVariables:
	def __init__(
	    self, var_list: List[Variable], confidence: int = core.max_confidence,
	    func: Optional['binaryninja.function.Function'] = None
	):
		self._vars = var_list
		self._confidence = confidence
		self._func = func

	def __repr__(self):
		return f"<ParameterVariables: {str(self._vars)}>"

	def __len__(self):
		return len(self._vars)

	def __iter__(self) -> Generator['Variable', None, None]:
		for var in self._vars:
			yield var

	def __eq__(self, other) -> bool:
		return (self._vars, self._confidence, self._func) == (other._vars, other._confidence, other._func)

	def __getitem__(self, idx) -> 'Variable':
		return self._vars[idx]

	def __setitem__(self, idx: int, value: 'Variable'):
		self._vars[idx] = value
		if self._func is not None:
			self._func.parameter_vars = self

	def with_confidence(self, confidence: int) -> 'ParameterVariables':
		return ParameterVariables(list(self._vars), confidence, self._func)

	@property
	def vars(self) -> List['Variable']:
		return self._vars

	@property
	def confidence(self) -> int:
		return self._confidence

	@property
	def function(self) -> Optional['binaryninja.function.Function']:
		return self._func


@decorators.passive
class ParameterLocations:
	def __init__(
		self, location_list: List['types.ValueLocation'], confidence: int = core.max_confidence,
		func: Optional['binaryninja.function.Function'] = None
	):
		self._locations = location_list
		self._confidence = confidence
		self._func = func

	def __repr__(self):
		return f"<ParameterLocations: {str(self._locations)}>"

	def __len__(self):
		return len(self._vars)

	def __iter__(self) -> Generator['types.ValueLocation', None, None]:
		for location in self._locations:
			yield location

	def __eq__(self, other) -> bool:
		return (self._locations, self._confidence, self._func) == (other._locations, other._confidence, other._func)

	def __getitem__(self, idx) -> 'types.ValueLocation':
		return self._locations[idx]

	def __setitem__(self, idx: int, value: 'types.ValueLocation'):
		self._locations[idx] = value
		if self._func is not None:
			self._func.parameter_locations = self

	def with_confidence(self, confidence: int) -> 'ParameterLocations':
		return ParameterLocations(list(self._locations), confidence, self._func)

	@property
	def locations(self) -> List['types.ValueLocation']:
		return self._locations

	@property
	def confidence(self) -> int:
		return self._confidence

	@property
	def function(self) -> Optional['binaryninja.function.Function']:
		return self._func


@dataclass(frozen=True, order=True)
class AddressRange:
	start: int  #  Inclusive starting address
	end: int  # Exclusive ending address

	def __repr__(self):
		return f"<{self.start:#x}-{self.end:#x}>"

	def __contains__(self, i: int):
		return self.start <= i < self.end
