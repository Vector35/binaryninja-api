# coding=utf-8
# Copyright (c) 2015-2024 Vector 35 Inc
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
import inspect
from typing import Generator, Optional, List, Tuple, Union, Mapping, Any, Dict, overload
from dataclasses import dataclass

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import (
	AnalysisSkipReason, FunctionGraphType, SymbolType, InstructionTextTokenType, HighlightStandardColor,
	HighlightColorStyle, DisassemblyOption, IntegerDisplayType, FunctionAnalysisSkipOverride, FunctionUpdateType,
	BuiltinType
)
from .exceptions import ILException

from . import associateddatastore  # Required in the main scope due to being an argument for _FunctionAssociatedDataStore
from . import types
from . import architecture
from . import lowlevelil
from . import mediumlevelil
from . import highlevelil
from . import binaryview
from . import basicblock
from . import databuffer
from . import variable
from . import flowgraph
from . import callingconvention
from . import workflow
from . import languagerepresentation
from . import deprecation
from . import __version__

# we define the following as such so the linter doesn't confuse 'highlight' the module with the
# property of the same name. There is probably some other work around but it eludes me.
from . import highlight as _highlight
from . import platform as _platform

# The following imports are for backward compatibility with API version < 3.0
# so old plugins which do 'from binaryninja.function import RegisterInfo' will still work
from .architecture import (
    RegisterInfo, RegisterStackInfo, IntrinsicInput, IntrinsicInfo, InstructionBranch, InstructionInfo,
    InstructionTextToken
)
from .variable import (
    Variable, LookupTableEntry, RegisterValue, ValueRange, PossibleValueSet, StackVariableReference, ConstantReference,
    IndirectBranchInfo, ParameterVariables, AddressRange
)
from . import decorators
from .enums import RegisterValueType
from . import component

ExpressionIndex = int
InstructionIndex = int
AnyFunctionType = Union['Function', 'lowlevelil.LowLevelILFunction', 'mediumlevelil.MediumLevelILFunction',
                        'highlevelil.HighLevelILFunction']
ILFunctionType = Union['lowlevelil.LowLevelILFunction', 'mediumlevelil.MediumLevelILFunction',
                       'highlevelil.HighLevelILFunction']
ILInstructionType = Union['lowlevelil.LowLevelILInstruction', 'mediumlevelil.MediumLevelILInstruction',
                          'highlevelil.HighLevelILInstruction']
StringOrType = Union[str, 'types.Type', 'types.TypeBuilder']
FunctionViewTypeOrName = Union['FunctionViewType', FunctionGraphType, str]


def _function_name_():
	return inspect.stack()[1][0].f_code.co_name


@dataclass(frozen=True)
class ArchAndAddr:
	arch: 'architecture.Architecture'
	addr: int

	def __repr__(self):
		return f"<archandaddr {self.arch} @ {self.addr:#x}>"


class _FunctionAssociatedDataStore(associateddatastore._AssociatedDataStore):
	_defaults = {}


class DisassemblySettings:
	def __init__(self, handle: Optional[core.BNDisassemblySettingsHandle] = None):
		if handle is None:
			self.handle = core.BNCreateDisassemblySettings()
		else:
			self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeDisassemblySettings(self.handle)

	@property
	def width(self) -> int:
		return core.BNGetDisassemblyWidth(self.handle)

	@width.setter
	def width(self, value: int) -> None:
		core.BNSetDisassemblyWidth(self.handle, value)

	@property
	def max_symbol_width(self) -> int:
		return core.BNGetDisassemblyMaximumSymbolWidth(self.handle)

	@max_symbol_width.setter
	def max_symbol_width(self, value: int) -> None:
		core.BNSetDisassemblyMaximumSymbolWidth(self.handle, value)

	def is_option_set(self, option: DisassemblyOption) -> bool:
		if isinstance(option, str):
			option = DisassemblyOption[option]
		return core.BNIsDisassemblySettingsOptionSet(self.handle, option)

	def set_option(self, option: DisassemblyOption, state: bool = True) -> None:
		if isinstance(option, str):
			option = DisassemblyOption[option]
		core.BNSetDisassemblySettingsOption(self.handle, option, state)

	@staticmethod
	def default_settings() -> 'DisassemblySettings':
		return DisassemblySettings(core.BNDefaultDisassemblySettings())

	@staticmethod
	def default_graph_settings() -> 'DisassemblySettings':
		return DisassemblySettings(core.BNDefaultGraphDisassemblySettings())

	@staticmethod
	def default_linear_settings() -> 'DisassemblySettings':
		return DisassemblySettings(core.BNDefaultLinearDisassemblySettings())


@dataclass
class ILReferenceSource:
	func: Optional['Function']
	arch: Optional['architecture.Architecture']
	address: int
	il_type: FunctionGraphType
	expr_id: ExpressionIndex

	@staticmethod
	def get_il_name(il_type: FunctionGraphType) -> str:
		if il_type == FunctionGraphType.NormalFunctionGraph:
			return 'disassembly'
		if il_type == FunctionGraphType.LowLevelILFunctionGraph:
			return 'llil'
		if il_type == FunctionGraphType.LiftedILFunctionGraph:
			return 'lifted_llil'
		if il_type == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			return 'llil_ssa'
		if il_type == FunctionGraphType.MediumLevelILFunctionGraph:
			return 'mlil'
		if il_type == FunctionGraphType.MediumLevelILSSAFormFunctionGraph:
			return 'mlil_ssa'
		if il_type == FunctionGraphType.MappedMediumLevelILFunctionGraph:
			return 'mapped_mlil'
		if il_type == FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph:
			return 'mapped_mlil_ssa'
		if il_type == FunctionGraphType.HighLevelILFunctionGraph:
			return 'hlil'
		if il_type == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
			return 'hlil_ssa'
		return ""

	def __repr__(self):
		if self.arch:
			return f"<ref: {self.arch}@{self.address:#x}, {self.get_il_name(self.il_type)}@{self.expr_id}>"
		else:
			return f"<ref: {self.address:#x}, {self.get_il_name(self.il_type)}@{self.expr_id}>"


@dataclass
class VariableReferenceSource:
	var: 'variable.Variable'
	src: ILReferenceSource

	def __repr__(self):
		return f"<var: {repr(self.var)}, src: {repr(self.src)}>"


@dataclass
class FunctionViewType:
	view_type: FunctionGraphType
	name: Optional[str]

	def __init__(self, view_type: FunctionViewTypeOrName):
		if isinstance(view_type, FunctionViewType):
			self.view_type = view_type.view_type
			self.name = view_type.name
		elif isinstance(view_type, FunctionGraphType):
			self.view_type = view_type
			self.name = None
		else:
			self.view_type = FunctionGraphType.HighLevelLanguageRepresentationFunctionGraph
			self.name = str(view_type)

	def __hash__(self):
		return hash((self.view_type, self.name))

	@staticmethod
	def _from_core_struct(view_type: core.BNFunctionViewType) -> 'FunctionViewType':
		if view_type.type == FunctionGraphType.HighLevelLanguageRepresentationFunctionGraph:
			if view_type.name is None:
				return FunctionViewType("Pseudo C")
			else:
				return FunctionViewType(view_type.name)
		else:
			return FunctionViewType(view_type.type)

	def _to_core_struct(self) -> core.BNFunctionViewType:
		result = core.BNFunctionViewType()
		result.type = self.view_type
		result.name = self.name
		return result


class BasicBlockList:
	def __init__(
	    self, function: Union['Function', 'lowlevelil.LowLevelILFunction', 'mediumlevelil.MediumLevelILFunction',
	                          'highlevelil.HighLevelILFunction']
	):
		self._count, self._blocks = function._basic_block_list()
		self._function = function
		self._n = 0

	def __repr__(self):
		return f"<BasicBlockList {len(self)} BasicBlocks: {list(self)}>"

	def __del__(self):
		if core is not None:
			core.BNFreeBasicBlockList(self._blocks, len(self))

	def __len__(self):
		return self._count.value

	def __iter__(self):
		return BasicBlockList(self._function)

	def __next__(self) -> 'basicblock.BasicBlock':
		if self._n >= len(self):
			raise StopIteration
		block = core.BNNewBasicBlockReference(self._blocks[self._n])
		assert block is not None, "core.BNNewBasicBlockReference returned None"
		self._n += 1
		return self._function._instantiate_block(block)

	@overload
	def __getitem__(self, i: int) -> 'basicblock.BasicBlock': ...

	@overload
	def __getitem__(self, i: slice) -> List['basicblock.BasicBlock']: ...

	def __getitem__(self, i: Union[int, slice]) -> Union['basicblock.BasicBlock', List['basicblock.BasicBlock']]:
		if isinstance(i, int):
			if i < 0:
				i = len(self) + i
			if i >= len(self):
				raise IndexError(f"Index {i} out of bounds for BasicBlockList of size {len(self)}")
			block = core.BNNewBasicBlockReference(self._blocks[i])
			assert block is not None, "core.BNNewBasicBlockReference returned None"
			return self._function._instantiate_block(block)
		elif isinstance(i, slice):
			result = []
			if i.start < 0 or i.start >= len(self) or i.stop < 0 or i.stop >= len(self):
				raise IndexError(f"Slice {i} out of bounds for FunctionList of size {len(self)}")

			for j in range(i.start, i.stop, i.step if i.step is not None else 1):
				block = core.BNNewBasicBlockReference(self._blocks[j])
				assert block is not None, "core.BNNewBasicBlockReference returned None"
				result.append(self._function._instantiate_block(block))
			return result
		raise ValueError("BasicBlockList.__getitem__ supports argument of type integer or slice only")


class LowLevelILBasicBlockList(BasicBlockList):
	def __repr__(self):
		return f"<LowLevelILBasicBlockList {len(self)} BasicBlocks: {list(self)}>"

	@overload
	def __getitem__(self, i: int) -> 'lowlevelil.LowLevelILBasicBlock': ...

	@overload
	def __getitem__(self, i: slice) -> List['lowlevelil.LowLevelILBasicBlock']: ...

	def __getitem__(
	    self, i: Union[int, slice]
	) -> Union['lowlevelil.LowLevelILBasicBlock', List['lowlevelil.LowLevelILBasicBlock']]:
		return BasicBlockList.__getitem__(self, i)  # type: ignore

	def __next__(self) -> 'lowlevelil.LowLevelILBasicBlock':
		return BasicBlockList.__next__(self)  # type: ignore


class MediumLevelILBasicBlockList(BasicBlockList):
	def __repr__(self):
		return f"<MediumLevelILBasicBlockList {len(self)} BasicBlocks: {list(self)}>"

	@overload
	def __getitem__(self, i: int) -> 'mediumlevelil.MediumLevelILBasicBlock': ...

	@overload
	def __getitem__(self, i: slice) -> List['mediumlevelil.MediumLevelILBasicBlock']: ...

	def __getitem__(
	    self, i: Union[int, slice]
	) -> Union['mediumlevelil.MediumLevelILBasicBlock', List['mediumlevelil.MediumLevelILBasicBlock']]:
		return BasicBlockList.__getitem__(self, i)  # type: ignore

	def __next__(self) -> 'mediumlevelil.MediumLevelILBasicBlock':
		return BasicBlockList.__next__(self)  # type: ignore


class HighLevelILBasicBlockList(BasicBlockList):
	def __repr__(self):
		return f"<HighLevelILBasicBlockList {len(self)} BasicBlocks: {list(self)}>"

	@overload
	def __getitem__(self, i: int) -> 'highlevelil.HighLevelILBasicBlock': ...

	@overload
	def __getitem__(self, i: slice) -> List['highlevelil.HighLevelILBasicBlock']: ...

	def __getitem__(
	    self, i: Union[int, slice]
	) -> Union['highlevelil.HighLevelILBasicBlock', List['highlevelil.HighLevelILBasicBlock']]:
		return BasicBlockList.__getitem__(self, i)  # type: ignore

	def __next__(self) -> 'highlevelil.HighLevelILBasicBlock':
		return BasicBlockList.__next__(self)  # type: ignore


class TagList:
	def __init__(self, function: 'Function'):
		self._count = ctypes.c_ulonglong()
		tags = core.BNGetAddressTagReferences(function.handle, self._count)
		assert tags is not None, "core.BNGetAddressTagReferences returned None"
		self._tags = tags
		self._function = function
		self._n = 0

	def __repr__(self):
		return f"<TagList {len(self)} Tags: {list(self)}>"

	def __del__(self):
		if core is not None:
			core.BNFreeTagReferences(self._tags, len(self))

	def __len__(self):
		return self._count.value

	def __iter__(self):
		return self

	def __next__(self) -> Tuple['architecture.Architecture', int, 'binaryview.Tag']:
		if self._n >= len(self):
			raise StopIteration
		core_tag = core.BNNewTagReference(self._tags[self._n].tag)
		arch = architecture.CoreArchitecture._from_cache(self._tags[self._n].arch)
		address = self._tags[self._n].addr
		assert core_tag is not None, "core.BNNewTagReference returned None"
		self._n += 1
		return arch, address, binaryview.Tag(core_tag)

	@overload
	def __getitem__(self, i: int) -> Tuple['architecture.Architecture', int, 'binaryview.Tag']: ...

	@overload
	def __getitem__(self, i: slice) -> List[Tuple['architecture.Architecture', int, 'binaryview.Tag']]: ...

	def __getitem__(
	    self, i: Union[int, slice]
	) -> Union[Tuple['architecture.Architecture', int, 'binaryview.Tag'], List[Tuple['architecture.Architecture', int, 'binaryview.Tag']]]:
		if isinstance(i, int):
			if i < 0:
				i = len(self) + i
			if i >= len(self):
				raise IndexError(f"Index {i} out of bounds for TagList of size {len(self)}")

			core_tag = core.BNNewTagReference(self._tags[i].tag)
			arch = architecture.CoreArchitecture._from_cache(self._tags[i].arch)
			assert core_tag is not None, "core.BNNewTagReference returned None"
			return arch, self._tags[i].addr, binaryview.Tag(core_tag)
		elif isinstance(i, slice):
			result = []
			if i.start < 0 or i.start >= len(self) or i.stop < 0 or i.stop >= len(self):
				raise IndexError(f"Slice {i} out of bounds for FunctionList of size {len(self)}")

			for j in range(i.start, i.stop, i.step if i.step is not None else 1):
				core_tag = core.BNNewTagReference(self._tags[j].tag)
				assert core_tag is not None, "core.BNNewTagReference returned None"
				arch = architecture.CoreArchitecture._from_cache(self._tags[j].arch)
				result.append((arch, self._tags[j].addr, binaryview.Tag(core_tag)))
			return result
		raise ValueError("TagList.__getitem__ supports argument of type integer or slice only")


class Function:
	_associated_data = {}
	"""
	The examples in the following code will use the following variables

		>>> from binaryninja import *
		>>> bv = load("/bin/ls")
		>>> current_function = bv.functions[0]
		>>> here = current_function.start
	"""
	def __init__(self, view: Optional['binaryview.BinaryView'] = None, handle: Optional[core.BNFunctionHandle] = None):
		self._advanced_analysis_requests = 0
		assert handle is not None, "creation of standalone 'Function' objects is not implemented"
		FunctionHandle = ctypes.POINTER(core.BNFunction)
		self.handle = ctypes.cast(handle, FunctionHandle)
		if view is None:
			self._view = binaryview.BinaryView(handle=core.BNGetFunctionData(self.handle))
		else:
			self._view = view
		self._arch = None
		self._platform = None

	def __del__(self):
		if core is not None and self.handle is not None:
			if self._advanced_analysis_requests > 0:
				core.BNReleaseAdvancedFunctionAnalysisDataMultiple(self.handle, self._advanced_analysis_requests)
			core.BNFreeFunction(self.handle)

	def __repr__(self):
		arch = self.arch
		if arch:
			return f"<func: {arch.name}@{self.start:#x}>"
		else:
			return f"<func: {self.start:#x}>"

	def __eq__(self, other: 'Function') -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other: 'Function') -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __lt__(self, other: 'Function') -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start < other.start

	def __gt__(self, other: 'Function') -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start > other.start

	def __le__(self, other: 'Function') -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start <= other.start

	def __ge__(self, other: 'Function') -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start >= other.start

	def __hash__(self):
		return hash((self.start, self.arch, self.platform))

	@overload
	def __getitem__(self, i: int) -> 'basicblock.BasicBlock': ...

	@overload
	def __getitem__(self, i: slice) -> List['basicblock.BasicBlock']: ...

	def __getitem__(self, i: Union[int, slice]) -> Union['basicblock.BasicBlock', List['basicblock.BasicBlock']]:
		return self.basic_blocks[i]

	def __iter__(self) -> Generator['basicblock.BasicBlock', None, None]:
		yield from self.basic_blocks

	def __str__(self):
		result = ""
		for token in self.type_tokens:
			result += token.text
		return result

	def __contains__(self, value: Union[basicblock.BasicBlock, int]):
		if isinstance(value, basicblock.BasicBlock):
			return value.function == self
		return self in [block.function for block in self.view.get_basic_blocks_at(int(value))]

	@classmethod
	def _unregister(cls, func: 'core.BNFunction') -> None:
		handle = ctypes.cast(func, ctypes.c_void_p)
		if handle.value in cls._associated_data:
			del cls._associated_data[handle.value]

	@staticmethod
	def set_default_session_data(name: str, value) -> None:
		_FunctionAssociatedDataStore.set_default(name, value)

	@property
	def name(self) -> str:
		"""Symbol name for the function"""
		return self.symbol.name

	@name.setter
	def name(self, value: Union[str, 'types.CoreSymbol']) -> None:  # type: ignore
		if value is None:
			if self.symbol is not None:
				self.view.undefine_user_symbol(self.symbol)
		elif isinstance(value, str):
			symbol = types.Symbol(SymbolType.FunctionSymbol, self.start, value)
			self.view.define_user_symbol(symbol)
		elif isinstance(value, types.Symbol):
			self.view.define_user_symbol(value)

	@property
	def view(self) -> 'binaryview.BinaryView':
		"""Function view (read-only)"""
		return self._view

	@property
	def arch(self) -> 'architecture.Architecture':
		"""Function architecture (read-only)"""
		if self._arch:
			return self._arch
		else:
			arch = core.BNGetFunctionArchitecture(self.handle)
			assert arch is not None, "core.BNGetFunctionArchitecture returned None"
			self._arch = architecture.CoreArchitecture._from_cache(arch)
			return self._arch

	@property
	def platform(self) -> Optional['_platform.Platform']:
		"""Function platform (read-only)"""
		if self._platform:
			return self._platform
		else:
			plat = core.BNGetFunctionPlatform(self.handle)
			if plat is None:
				return None
			self._platform = _platform.CorePlatform._from_cache(handle=plat)
			return self._platform

	@property
	def start(self) -> int:
		"""Function start address (read-only)"""
		return core.BNGetFunctionStart(self.handle)

	@property
	def total_bytes(self) -> int:
		"""
		Total bytes of a function calculated by summing each basic_block. Because basic blocks can overlap and
		have gaps between them this may or may not be equivalent to a .size property.
		"""
		return sum(map(len, self))

	@property
	def highest_address(self) -> int:
		"""The highest (largest) virtual address contained in a function."""
		return core.BNGetFunctionHighestAddress(self.handle)

	@property
	def lowest_address(self) -> int:
		"""The lowest (smallest) virtual address contained in a function."""
		return core.BNGetFunctionLowestAddress(self.handle)

	@property
	def address_ranges(self) -> List['variable.AddressRange']:
		"""All of the address ranges covered by a function"""
		count = ctypes.c_ulonglong(0)
		range_list = core.BNGetFunctionAddressRanges(self.handle, count)
		assert range_list is not None, "core.BNGetFunctionAddressRanges returned None"
		result = []
		for i in range(0, count.value):
			result.append(variable.AddressRange(range_list[i].start, range_list[i].end))
		core.BNFreeAddressRanges(range_list)
		return result

	@property
	def symbol(self) -> 'types.CoreSymbol':
		"""Function symbol(read-only)"""
		sym = core.BNGetFunctionSymbol(self.handle)
		assert sym is not None, "core.BNGetFunctionSymbol returned None"
		return types.CoreSymbol(sym)

	@property
	def auto(self) -> bool:
		"""
		Whether function was automatically discovered (read-only) as a result of some creation of a 'user' function.
		'user' functions may or may not have been created by a user through the or API. For instance the entry point
		into a function is always created a 'user' function. 'user' functions should be considered the root of auto
		analysis.
		"""
		return core.BNWasFunctionAutomaticallyDiscovered(self.handle)

	@property
	def has_user_annotations(self) -> bool:
		"""
		Whether the function has ever been 'user' modified
		"""
		return core.BNFunctionHasUserAnnotations(self.handle)

	@property
	def can_return(self) -> 'types.BoolWithConfidence':
		"""Whether function can return"""
		result = core.BNCanFunctionReturn(self.handle)
		return types.BoolWithConfidence(result.value, confidence=result.confidence)

	@can_return.setter
	def can_return(self, value: 'types.BoolWithConfidence') -> None:
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if hasattr(value, 'confidence'):
			bc.confidence = value.confidence
		else:
			bc.confidence = core.max_confidence
		core.BNSetUserFunctionCanReturn(self.handle, bc)

	@property
	def is_pure(self) -> 'types.BoolWithConfidence':
		"""Whether function is pure"""
		result = core.BNIsFunctionPure(self.handle)
		return types.BoolWithConfidence(result.value, confidence=result.confidence)

	@is_pure.setter
	def is_pure(self, value: 'types.BoolWithConfidence') -> None:
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if hasattr(value, 'confidence'):
			bc.confidence = value.confidence
		else:
			bc.confidence = core.max_confidence
		core.BNSetUserFunctionPure(self.handle, bc)

	@property
	def has_explicitly_defined_type(self) -> bool:
		"""Whether function has explicitly defined types (read-only)"""
		return core.BNFunctionHasExplicitlyDefinedType(self.handle)

	@property
	def needs_update(self) -> bool:
		"""Whether the function has analysis that needs to be updated (read-only)"""
		return core.BNIsFunctionUpdateNeeded(self.handle)

	def _basic_block_list(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionBasicBlockList(self.handle, count)
		assert blocks is not None, "core.BNGetFunctionBasicBlockList returned None"
		return count, blocks

	def _instantiate_block(self, handle):
		return basicblock.BasicBlock(handle, self.view)

	@property
	def basic_blocks(self) -> BasicBlockList:
		"""function.BasicBlockList of BasicBlocks in the current function (read-only)"""
		return BasicBlockList(self)

	@property
	def is_thunk(self) -> bool:
		"""Returns True if the function starts with a Tailcall (read-only)"""
		if self.llil_if_available is not None:
			return self.llil_if_available.is_thunk
		else:
			return False

	@property
	def comments(self) -> Dict[int, str]:
		"""Dict of comments (read-only)"""
		count = ctypes.c_ulonglong()
		addrs = core.BNGetCommentedAddresses(self.handle, count)
		assert addrs is not None, "core.BNGetCommentedAddresses returned None"
		try:
			result = {}
			for i in range(0, count.value):
				result[addrs[i]] = self.get_comment_at(addrs[i])
			return result
		finally:
			core.BNFreeAddressList(addrs)

	@property
	def tags(self) -> TagList:
		"""
		``tags`` gets a TagList of all Tags in the function (but not "function tags").
		Tags are returned as an iterable indexable object TagList of (arch, address, Tag) tuples.

		:rtype: TagList((Architecture, int, Tag))
		"""
		return TagList(self)

	def get_tags_at(self, addr: int, arch: Optional['architecture.Architecture'] = None, auto: Optional[bool] = None) -> List['binaryview.Tag']:
		"""
		``get_tags`` gets a list of Tags (but not function tags).

		:param int addr: Address to get tags from.
		:param bool auto: If None, gets all tags, if True, gets auto tags, if False, gets user tags
		:rtype: list((Architecture, int, Tag))
		"""
		if arch is None:
			assert self.arch is not None, "Can't call get_tags_at for function with no architecture specified"
			arch = self.arch
		count = ctypes.c_ulonglong()

		if auto is None:
			tags = core.BNGetAddressTags(self.handle, arch.handle, addr, count)
			assert tags is not None, "core.BNGetAddressTags returned None"
		elif auto:
			tags = core.BNGetAutoAddressTags(self.handle, arch.handle, addr, count)
			assert tags is not None, "core.BNGetAutoAddressTags returned None"
		else:
			tags = core.BNGetUserAddressTags(self.handle, arch.handle, addr, count)
			assert tags is not None, "core.BNGetUserAddressTags returned None"

		result = []
		try:
			for i in range(0, count.value):
				core_tag = core.BNNewTagReference(tags[i])
				assert core_tag is not None, "core.BNNewTagReference returned None"
				result.append(binaryview.Tag(core_tag))
			return result
		finally:
			core.BNFreeTagList(tags, count.value)

	def get_tags_in_range(
	    self, address_range: 'variable.AddressRange', arch: Optional['architecture.Architecture'] = None, auto: Optional[bool] = None
	) -> List[Tuple['architecture.Architecture', int, 'binaryview.Tag']]:
		"""
		``get_address_tags_in_range`` gets a list of all Tags in the function at a given address.
		Range is inclusive at the start, exclusive at the end.

		:param AddressRange address_range: Address range from which to get tags
		:param Architecture arch: Architecture for the block in which the Tag is located (optional)
		:param bool auto: If None, gets all tags, if True, gets auto tags, if False, gets user tags
		:return: A list of (arch, address, Tag) tuples
		:rtype: list((Architecture, int, Tag))
		"""
		if arch is None:
			assert self.arch is not None, "Can't call get_address_tags_in_range for function with no architecture specified"
			arch = self.arch
		count = ctypes.c_ulonglong()

		if auto is None:
			refs = core.BNGetAddressTagsInRange(self.handle, arch.handle, address_range.start, address_range.end, count)
			assert refs is not None, "core.BNGetAddressTagsInRange returned None"
		elif auto:
			refs = core.BNGetAutoAddressTagsInRange(self.handle, arch.handle, address_range.start, address_range.end, count)
			assert refs is not None, "core.BNGetAutoAddressTagsInRange returned None"
		else:
			refs = core.BNGetUserAddressTagsInRange(self.handle, arch.handle, address_range.start, address_range.end, count)
			assert refs is not None, "core.BNGetUserAddressTagsInRange returned None"

		try:
			result = []
			for i in range(0, count.value):
				tag_ref = core.BNNewTagReference(refs[i].tag)
				assert tag_ref is not None, "core.BNNewTagReference returned None"
				tag = binaryview.Tag(tag_ref)
				result.append((arch, refs[i].addr, tag))
			return result
		finally:
			core.BNFreeTagReferences(refs, count.value)

	def get_function_tags(self, auto: Optional[bool] = None, tag_type: Optional[str] = None) -> List['binaryview.Tag']:
		"""
		``get_function_tags`` gets a list of function Tags for the function.

		:param bool auto: If None, gets all tags, if True, gets auto tags, if False, gets user tags
		:param str tag_type: If None, gets all tags, otherwise only gets tags of the given type
		:rtype: list(Tag)
		"""
		count = ctypes.c_ulonglong()

		tags = []
		if tag_type is not None:
			tag_type = self.view.get_tag_type(tag_type)
			if tag_type is None:
				return []

			if auto is None:
				tags = core.BNGetFunctionTagsOfType(self.handle, tag_type.handle, count)
				assert tags is not None, "core.BNGetFunctionTagsOfType returned None"
			elif auto:
				tags = core.BNGetAutoFunctionTagsOfType(self.handle, tag_type.handle, count)
				assert tags is not None, "core.BNGetAutoFunctionTagsOfType returned None"
			else:
				tags = core.BNGetUserFunctionTagsOfType(self.handle, tag_type.handle, count)
				assert tags is not None, "core.BNGetUserFunctionTagsOfType returned None"
		else:
			if auto is None:
				tags = core.BNGetFunctionTags(self.handle, count)
				assert tags is not None, "core.BNGetFunctionTags returned None"
			elif auto:
				tags = core.BNGetAutoFunctionTags(self.handle, count)
				assert tags is not None, "core.BNGetAutoFunctionTags returned None"
			else:
				tags = core.BNGetUserFunctionTags(self.handle, count)
				assert tags is not None, "core.BNGetUserFunctionTags returned None"

		try:
			result = []
			for i in range(count.value):
				core_tag = core.BNNewTagReference(tags[i])
				assert core_tag is not None, "core.BNNewTagReference returned None"
				result.append(binaryview.Tag(core_tag))
			return result
		finally:
			core.BNFreeTagList(tags, count.value)

	def add_tag(
	    self, tag_type: str, data: str, addr: Optional[int] = None, auto: bool = False,
	    arch: Optional['architecture.Architecture'] = None
	):
		"""
		``add_tag`` creates and adds a :py:class:`Tag` object on either a function, or on
		an address inside of a function.

		"Function tags" appear at the top of a function and are a good way to label an
		entire function with some information. If you include an address when you call
		Function.add_tag, you'll create an "address tag". These are good for labeling
		specific instructions.

		For tagging arbitrary data, consider :py:func:`~binaryninja.binaryview.add_tag`.

		:param str tag_type_name: The name of the tag type for this Tag
		:param str data: additional data for the Tag
		:param int addr: address at which to add the tag
		:param bool user: Whether or not a user tag
		:Example:

			>>> current_function.add_tag("Important", "I think this is the main function")
			>>> current_function.add_tag("Crashes", "Nullpointer dereference", here)

		Warning: For performance reasons, this function does not ensure the address you
		have supplied is within the function's bounds.
		"""
		tag_type = self.view.get_tag_type(tag_type)
		if tag_type is None:
			return
		if arch is None:
			arch = self.arch

		# Create tag
		tag_handle = core.BNCreateTag(tag_type.handle, data)
		assert tag_handle is not None, "core.BNCreateTag returned None"
		tag = binaryview.Tag(tag_handle)
		core.BNAddTag(self.view.handle, tag.handle, auto)

		if auto:
			if addr is None:
				core.BNAddAutoFunctionTag(self.handle, tag.handle)
			else:
				core.BNAddAutoAddressTag(self.handle, arch.handle, addr, tag.handle)
		else:
			if addr is None:
				core.BNAddUserFunctionTag(self.handle, tag.handle)
			else:
				core.BNAddUserAddressTag(self.handle, arch.handle, addr, tag.handle)

	def remove_user_address_tag(
	    self, addr: int, tag: 'binaryview.Tag', arch: Optional['architecture.Architecture'] = None
	) -> None:
		"""
		``remove_user_address_tag`` removes a Tag object at a given address.
		Since this removes a user tag, it will be added to the current undo buffer.

		:param int addr: Address at which to remove the tag
		:param Tag tag: Tag object to be added
		:param Architecture arch: Architecture for the block in which the Tag is added (optional)
		:rtype: None
		"""
		if arch is None:
			arch = self.arch
		core.BNRemoveUserAddressTag(self.handle, arch.handle, addr, tag.handle)

	def remove_user_function_tag(self, tag: 'binaryview.Tag') -> None:
		"""
		``remove_user_function_tag`` removes a Tag object as a function tag.
		Since this removes a user tag, it will be added to the current undo buffer.

		:param Tag tag: Tag object to be added
		:rtype: None
		"""
		core.BNRemoveUserFunctionTag(self.handle, tag.handle)

	def remove_user_address_tags_of_type(self, addr: int, tag_type: str, arch=None):
		"""
		``remove_user_address_tags_of_type`` removes all tags at the given address of the given type.
		Since this removes user tags, it will be added to the current undo buffer.

		:param int addr: Address at which to remove the tag
		:param Tag tag_type: TagType object to match for removing
		:param Architecture arch: Architecture for the block in which the Tags is located (optional)
		:rtype: None
		"""
		if arch is None:
			arch = self.arch
		tag_type = self.view.get_tag_type(tag_type)
		if tag_type is not None:
			core.BNRemoveUserAddressTagsOfType(self.handle, arch.handle, addr, tag_type.handle)

	def remove_auto_address_tag(
	    self, addr: int, tag: 'binaryview.Tag', arch: Optional['architecture.Architecture'] = None
	) -> None:
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

	def remove_auto_address_tags_of_type(self, addr: int, tag_type: str, arch=None):
		"""
		``remove_auto_address_tags_of_type`` removes all tags at the given address of the given type.

		:param int addr: Address at which to remove the tags
		:param Tag tag_type: TagType object to match for removing
		:param Architecture arch: Architecture for the block in which the Tags is located (optional)
		:rtype: None
		"""
		if arch is None:
			arch = self.arch
		tag_type = self.view.get_tag_type(tag_type)
		if tag_type is not None:
			core.BNRemoveAutoAddressTagsOfType(self.handle, arch.handle, addr, tag_type.handle)

	def remove_user_function_tags_of_type(self, tag_type: str):
		"""
		``remove_user_function_tags_of_type`` removes all function Tag objects on a function of a given type
		Since this removes user tags, it will be added to the current undo buffer.

		:param TagType tag_type: TagType object to match for removing
		:rtype: None
		"""
		tag_type = self.view.get_tag_type(tag_type)
		if tag_type is not None:
			core.BNRemoveUserFunctionTagsOfType(self.handle, tag_type.handle)

	def remove_auto_function_tag(self, tag: 'binaryview.Tag') -> None:
		"""
		``remove_user_function_tag`` removes a Tag object as a function tag.

		:param Tag tag: Tag object to be added
		:rtype: None
		"""
		core.BNRemoveAutoFunctionTag(self.handle, tag.handle)

	def remove_auto_function_tags_of_type(self, tag_type: str):
		"""
		``remove_user_function_tags_of_type`` removes all function Tag objects on a function of a given type

		:param TagType tag_type: TagType object to match for removing
		:rtype: None
		"""
		tag_type = self.view.get_tag_type(tag_type)
		if tag_type is not None:
			core.BNRemoveAutoFunctionTagsOfType(self.handle, tag_type.handle)

	@property
	def low_level_il(self) -> 'lowlevelil.LowLevelILFunction':
		"""
		returns LowLevelILFunction used to represent Function low level IL (read-only)

		:raises ILException: if the low level IL could not be loaded
		:rtype: lowlevelil.LowLevelILFunction
		"""
		return self.llil

	@property
	def llil(self) -> 'lowlevelil.LowLevelILFunction':
		"""
		returns LowLevelILFunction used to represent Function low level IL (read-only)

		:raises ILException: if the low level IL could not be loaded
		:rtype: lowlevelil.LowLevelILFunction
		"""
		result = core.BNGetFunctionLowLevelIL(self.handle)
		if not result:
			raise ILException(f"Low level IL was not loaded for {self!r}")
		return lowlevelil.LowLevelILFunction(self.arch, result, self)

	@property
	def llil_if_available(self) -> Optional['lowlevelil.LowLevelILFunction']:
		"""returns LowLevelILFunction used to represent Function low level IL, or None if not loaded (read-only)"""
		result = core.BNGetFunctionLowLevelILIfAvailable(self.handle)
		if not result:
			return None
		return lowlevelil.LowLevelILFunction(self.arch, result, self)

	@property
	def lifted_il(self) -> 'lowlevelil.LowLevelILFunction':
		"""
		returns LowLevelILFunction used to represent Function lifted IL (read-only)

		:raises ILException: if the lifted IL could not be loaded
		:rtype: lowlevelil.LowLevelILFunction
		"""
		result = core.BNGetFunctionLiftedIL(self.handle)
		if not result:
			raise ILException(f"Lifted IL was not loaded for {self!r}")
		return lowlevelil.LowLevelILFunction(self.arch, result, self)

	@property
	def lifted_il_if_available(self) -> Optional['lowlevelil.LowLevelILFunction']:
		"""returns LowLevelILFunction used to represent lifted IL, or None if not loaded (read-only)"""
		result = core.BNGetFunctionLiftedILIfAvailable(self.handle)
		if not result:
			return None
		return lowlevelil.LowLevelILFunction(self.arch, result, self)

	@property
	def medium_level_il(self) -> 'mediumlevelil.MediumLevelILFunction':
		"""
		returns MediumLevelILFunction used to represent Function medium level IL (read-only)

		:raises ILException: if the medium level IL could not be loaded
		:rtype: mediumlevelil.MediumLevelILFunction
		"""
		return self.mlil

	@property
	def mlil(self) -> 'mediumlevelil.MediumLevelILFunction':
		"""
		returns MediumLevelILFunction used to represent Function medium level IL (read-only)

		:raises ILException: if the medium level IL could not be loaded
		:rtype: mediumlevelil.MediumLevelILFunction
		"""
		result = core.BNGetFunctionMediumLevelIL(self.handle)
		if not result:
			raise ILException(f"Medium level IL was not loaded for {self!r}")
		return mediumlevelil.MediumLevelILFunction(self.arch, result, self)

	@property
	def mlil_if_available(self) -> Optional['mediumlevelil.MediumLevelILFunction']:
		"""Function medium level IL, or None if not loaded (read-only)"""
		result = core.BNGetFunctionMediumLevelILIfAvailable(self.handle)
		if not result:
			return None
		return mediumlevelil.MediumLevelILFunction(self.arch, result, self)

	@property
	def mmlil(self) -> 'mediumlevelil.MediumLevelILFunction':
		"""
		returns MediumLevelILFunction used to represent Function mapped medium level IL (read-only)

		:raises ILException: if the mapped medium level IL could not be loaded
		:rtype: mediumlevelil.MediumLevelILFunction
		"""
		result = core.BNGetFunctionMappedMediumLevelIL(self.handle)
		if not result:
			raise ILException(f"Mapped medium level IL was not loaded for {self!r}")
		return mediumlevelil.MediumLevelILFunction(self.arch, result, self)

	@property
	def mapped_medium_level_il(self) -> 'mediumlevelil.MediumLevelILFunction':
		"""
		returns MediumLevelILFunction used to represent Function mapped medium level IL (read-only)

		:raises ILException: if the mapped medium level IL could not be loaded
		:rtype: mediumlevelil.MediumLevelILFunction
		"""
		return self.mmlil

	@property
	def mmlil_if_available(self) -> Optional['mediumlevelil.MediumLevelILFunction']:
		"""Function mapped medium level IL, or None if not loaded (read-only)"""
		result = core.BNGetFunctionMappedMediumLevelILIfAvailable(self.handle)
		if not result:
			return None
		return mediumlevelil.MediumLevelILFunction(self.arch, result, self)

	@property
	def high_level_il(self) -> 'highlevelil.HighLevelILFunction':
		"""
		returns HighLevelILFunction used to represent Function high level IL (read-only)

		:raises ILException: if the high level IL could not be loaded
		:rtype: highlevelil.HighLevelILFunction
		"""
		return self.hlil

	@property
	def hlil(self) -> 'highlevelil.HighLevelILFunction':
		"""
		returns HighLevelILFunction used to represent Function high level IL (read-only)

		:raises ILException: if the high level IL could not be loaded
		:rtype: highlevelil.HighLevelILFunction
		"""
		result = core.BNGetFunctionHighLevelIL(self.handle)
		if not result:
			raise ILException(f"High level IL was not loaded for {self!r}")
		return highlevelil.HighLevelILFunction(self.arch, result, self)

	@property
	def hlil_if_available(self) -> Optional['highlevelil.HighLevelILFunction']:
		"""Function high level IL, or None if not loaded (read-only)"""
		result = core.BNGetFunctionHighLevelILIfAvailable(self.handle)
		if not result:
			return None
		return highlevelil.HighLevelILFunction(self.arch, result, self)

	@property
	def pseudo_c(self) -> Optional['languagerepresentation.LanguageRepresentationFunction']:
		return self.language_representation("Pseudo C")

	@property
	def pseudo_c_if_available(self) -> Optional['languagerepresentation.LanguageRepresentationFunction']:
		return self.language_representation_if_available("Pseudo C")

	def language_representation(
			self, language: str
	) -> Optional['languagerepresentation.LanguageRepresentationFunction']:
		result = core.BNGetFunctionLanguageRepresentation(self.handle, language)
		if result is None:
			return None
		return languagerepresentation.LanguageRepresentationFunction(handle=result)

	def language_representation_if_available(
			self, language: str
	) -> Optional['languagerepresentation.LanguageRepresentationFunction']:
		result = core.BNGetFunctionLanguageRepresentationIfAvailable(self.handle, language)
		if result is None:
			return None
		return languagerepresentation.LanguageRepresentationFunction(handle=result)

	@property
	def type(self) -> 'types.FunctionType':
		"""
		Function type object, can be set with either a string representing the function prototype
		(`str(function)` shows examples) or a :py:class:`Type` object
		"""
		return types.FunctionType(core.BNGetFunctionType(self.handle), platform=self.platform)

	@type.setter
	def type(self, value: Union['types.FunctionType', str]) -> None:
		if isinstance(value, str):
			(parsed_value, new_name) = self.view.parse_type_string(value)
			self.name = str(new_name)
			self.set_user_type(parsed_value)
		else:
			self.set_user_type(value)

	@property
	def stack_layout(self) -> List['variable.Variable']:
		"""List of function stack variables (read-only)"""
		count = ctypes.c_ulonglong()
		v = core.BNGetStackLayout(self.handle, count)
		assert v is not None, "core.BNGetStackLayout returned None"
		try:
			return [variable.Variable.from_BNVariable(self, v[i].var) for i in range(count.value)]
		finally:
			core.BNFreeVariableNameAndTypeList(v, count.value)

	@property
	def core_var_stack_layout(self) -> List['variable.CoreVariable']:
		"""List of function stack variables (read-only)"""
		count = ctypes.c_ulonglong()
		v = core.BNGetStackLayout(self.handle, count)
		assert v is not None, "core.BNGetStackLayout returned None"
		try:
			return [variable.CoreVariable.from_BNVariable(v[i].var) for i in range(count.value)]
		finally:
			core.BNFreeVariableNameAndTypeList(v, count.value)

	@property
	def vars(self) -> List['variable.Variable']:
		"""List of function variables (read-only)"""
		count = ctypes.c_ulonglong()
		v = core.BNGetFunctionVariables(self.handle, count)
		assert v is not None, "core.BNGetFunctionVariables returned None"
		try:
			return [variable.Variable.from_BNVariable(self, v[i].var) for i in range(count.value)]
		finally:
			core.BNFreeVariableNameAndTypeList(v, count.value)

	@property
	def core_vars(self) -> List['variable.CoreVariable']:
		"""List of CoreVariable objects"""
		count = ctypes.c_ulonglong()
		v = core.BNGetFunctionVariables(self.handle, count)
		assert v is not None, "core.BNGetFunctionVariables returned None"
		try:
			return [variable.CoreVariable.from_BNVariable(v[i].var) for i in range(count.value)]
		finally:
			core.BNFreeVariableNameAndTypeList(v, count.value)

	def get_variable_by_name(self, name: str) -> Optional['variable.Variable']:
		"""Get a specific variable or None if it doesn't exist"""
		for v in self.vars:
			if v.name == name:
				return v
		return None

	@property
	def indirect_branches(self) -> List['variable.IndirectBranchInfo']:
		"""List of indirect branches (read-only)"""
		count = ctypes.c_ulonglong()
		branches = core.BNGetIndirectBranches(self.handle, count)
		assert branches is not None, "core.BNGetIndirectBranches returned None"
		result = []
		for i in range(0, count.value):
			result.append(
			    variable.IndirectBranchInfo(
			        architecture.CoreArchitecture._from_cache(branches[i].sourceArch), branches[i].sourceAddr,
			        architecture.CoreArchitecture._from_cache(branches[i].destArch), branches[i].destAddr,
			        branches[i].autoDefined
			    )
			)
		core.BNFreeIndirectBranchList(branches)
		return result

	@property
	def unresolved_indirect_branches(self) -> List[int]:
		"""List of unresolved indirect branches (read-only)"""
		count = ctypes.c_ulonglong()
		addrs = core.BNGetUnresolvedIndirectBranches(self.handle, count)
		assert addrs is not None, "core.BNGetUnresolvedIndirectBranches returned None"
		try:
			result = []
			for i in range(0, count.value):
				result.append(addrs[i])
			return result
		finally:
			core.BNFreeAddressList(addrs)

	@property
	def has_unresolved_indirect_branches(self) -> bool:
		"""Has unresolved indirect branches (read-only)"""
		return core.BNHasUnresolvedIndirectBranches(self.handle)

	@property
	def session_data(self) -> Any:
		"""Dictionary object where plugins can store arbitrary data associated with the function"""
		handle = ctypes.cast(self.handle, ctypes.c_void_p)  # type: ignore
		if handle.value not in Function._associated_data:
			obj = _FunctionAssociatedDataStore()
			Function._associated_data[handle.value] = obj
			return obj
		else:
			return Function._associated_data[handle.value]

	@property
	def analysis_performance_info(self) -> Dict[str, int]:
		count = ctypes.c_ulonglong()
		info = core.BNGetFunctionAnalysisPerformanceInfo(self.handle, count)
		assert info is not None, "core.BNGetFunctionAnalysisPerformanceInfo returned None"
		try:
			result = {}
			for i in range(0, count.value):
				result[info[i].name] = info[i].seconds
			return result
		finally:
			core.BNFreeAnalysisPerformanceInfo(info, count.value)

	@property
	def type_tokens(self) -> List['InstructionTextToken']:
		"""Text tokens for this function's prototype"""
		return self.get_type_tokens()[0].tokens

	@property
	def return_type(self) -> Optional['types.Type']:
		"""Return type of the function"""
		result = core.BNGetFunctionReturnType(self.handle)
		if not result.type:
			return None
		return types.Type.create(
		    result.type, platform=self.platform, confidence=result.confidence
		)

	@return_type.setter
	def return_type(self, value: Optional[StringOrType]) -> None:  # type: ignore
		type_conf = core.BNTypeWithConfidence()
		if value is None:
			type_conf.type = None
			type_conf.confidence = 0
		elif isinstance(value, str):
			(value, _) = self.view.parse_type_string(value)
			type_conf.type = value.handle
			type_conf.confidence = core.max_confidence
		else:
			type_conf.type = value.handle
			type_conf.confidence = value.confidence
		core.BNSetUserFunctionReturnType(self.handle, type_conf)

	@property
	def return_regs(self) -> 'types.RegisterSet':
		"""Registers that are used for the return value"""
		result = core.BNGetFunctionReturnRegisters(self.handle)
		assert result is not None, "core.BNGetFunctionReturnRegisters returned None"
		try:
			reg_set = []
			for i in range(result.count):
				reg_set.append(self.arch.get_reg_name(result.regs[i]))
			return types.RegisterSet(reg_set, confidence=result.confidence)
		finally:
			core.BNFreeRegisterSet(result)

	@return_regs.setter
	def return_regs(self, value: Union['types.RegisterSet', List['architecture.RegisterType']]) -> None:  # type: ignore
		regs = core.BNRegisterSetWithConfidence()
		regs.regs = (ctypes.c_uint * len(value))()
		regs.count = len(value)
		for i in range(0, len(value)):
			regs.regs[i] = self.arch.get_reg_index(value[i])
		if isinstance(value, types.RegisterSet):
			regs.confidence = value.confidence
		else:
			regs.confidence = core.max_confidence
		core.BNSetUserFunctionReturnRegisters(self.handle, regs)

	@property
	def calling_convention(self) -> Optional['callingconvention.CallingConvention']:
		"""Calling convention used by the function"""
		result = core.BNGetFunctionCallingConvention(self.handle)
		if not result.convention:
			return None
		return callingconvention.CallingConvention(None, handle=result.convention, confidence=result.confidence)

	@calling_convention.setter
	def calling_convention(self, value: Optional['callingconvention.CallingConvention']) -> None:
		conv_conf = core.BNCallingConventionWithConfidence()
		if value is None:
			conv_conf.convention = None
			conv_conf.confidence = 0
		else:
			conv_conf.convention = value.handle
			conv_conf.confidence = value.confidence
		core.BNSetUserFunctionCallingConvention(self.handle, conv_conf)

	@property
	def parameter_vars(self) -> 'variable.ParameterVariables':
		"""List of variables for the incoming function parameters"""
		result = core.BNGetFunctionParameterVariables(self.handle)
		var_list = []
		for i in range(0, result.count):
			var_list.append(variable.Variable.from_BNVariable(self, result.vars[i]))
		confidence = result.confidence
		core.BNFreeParameterVariables(result)
		return variable.ParameterVariables(var_list, confidence, self)

	@parameter_vars.setter
	def parameter_vars(
	    self, value: Optional[Union['variable.ParameterVariables', List['variable.Variable']]]
	) -> None:  # type: ignore
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
		elif isinstance(value, types.RegisterSet):
			var_conf.confidence = value.confidence
		else:
			var_conf.confidence = core.max_confidence
		core.BNSetUserFunctionParameterVariables(self.handle, var_conf)

	@property
	def has_variable_arguments(self) -> 'types.BoolWithConfidence':
		"""Whether the function takes a variable number of arguments"""
		result = core.BNFunctionHasVariableArguments(self.handle)
		return types.BoolWithConfidence(result.value, confidence=result.confidence)

	@has_variable_arguments.setter
	def has_variable_arguments(self, value: Union[bool, 'types.BoolWithConfidence']) -> None:  # type: ignore
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if isinstance(value, types.BoolWithConfidence):
			bc.confidence = value.confidence
		else:
			bc.confidence = core.max_confidence
		core.BNSetUserFunctionHasVariableArguments(self.handle, bc)

	@property
	def stack_adjustment(self) -> 'types.OffsetWithConfidence':
		"""Number of bytes removed from the stack after return"""
		result = core.BNGetFunctionStackAdjustment(self.handle)
		return types.OffsetWithConfidence(result.value, confidence=result.confidence)

	@stack_adjustment.setter
	def stack_adjustment(self, value: 'types.OffsetWithConfidence') -> None:
		oc = core.BNOffsetWithConfidence()
		oc.value = int(value)
		if hasattr(value, 'confidence'):
			oc.confidence = value.confidence
		else:
			oc.confidence = core.max_confidence
		core.BNSetUserFunctionStackAdjustment(self.handle, oc)

	@property
	def reg_stack_adjustments(
	    self
	) -> Dict['architecture.RegisterStackName', 'types.RegisterStackAdjustmentWithConfidence']:
		"""Number of entries removed from each register stack after return"""
		count = ctypes.c_ulonglong()
		adjust = core.BNGetFunctionRegisterStackAdjustments(self.handle, count)
		assert adjust is not None, "core.BNGetFunctionRegisterStackAdjustments returned None"
		try:
			result = {}
			for i in range(0, count.value):
				name = self.arch.get_reg_stack_name(adjust[i].regStack)
				value = types.RegisterStackAdjustmentWithConfidence(adjust[i].adjustment, confidence=adjust[i].confidence)
				result[name] = value
			return result
		finally:
			core.BNFreeRegisterStackAdjustments(adjust)

	@reg_stack_adjustments.setter
	def reg_stack_adjustments(
	    self, value: Mapping['architecture.RegisterStackName', Union[int,
	                                                                 'types.RegisterStackAdjustmentWithConfidence']]
	) -> None:  # type: ignore
		adjust = (core.BNRegisterStackAdjustment * len(value))()

		for i, reg_stack in enumerate(value.keys()):
			adjust[i].regStack = self.arch.get_reg_stack_index(reg_stack)
			entry = value[reg_stack]
			if isinstance(entry, types.RegisterStackAdjustmentWithConfidence):
				adjust[i].adjustment = entry.value
				adjust[i].confidence = entry.confidence
			else:
				adjust[i].adjustment = int(entry)
				adjust[i].confidence = core.max_confidence
		core.BNSetUserFunctionRegisterStackAdjustments(self.handle, adjust, len(value))

	@property
	def clobbered_regs(self) -> 'types.RegisterSet':
		"""Registers that are modified by this function"""
		result = core.BNGetFunctionClobberedRegisters(self.handle)

		reg_set = []
		for i in range(0, result.count):
			reg_set.append(self.arch.get_reg_name(result.regs[i]))
		regs = types.RegisterSet(reg_set, confidence=result.confidence)
		core.BNFreeRegisterSet(result)
		return regs

	@clobbered_regs.setter
	def clobbered_regs(
	    self, value: Union['types.RegisterSet', List['architecture.RegisterType']]
	) -> None:  # type: ignore
		regs = core.BNRegisterSetWithConfidence()

		regs.regs = (ctypes.c_uint * len(value))()
		regs.count = len(value)
		for i in range(0, len(value)):
			regs.regs[i] = self.arch.get_reg_index(value[i])
		if isinstance(value, types.RegisterSet):
			regs.confidence = value.confidence
		else:
			regs.confidence = core.max_confidence
		core.BNSetUserFunctionClobberedRegisters(self.handle, regs)

	@property
	def global_pointer_value(self) -> variable.RegisterValue:
		"""Discovered value of the global pointer register, if the function uses one (read-only)"""
		result = core.BNGetFunctionGlobalPointerValue(self.handle)
		return variable.RegisterValue.from_BNRegisterValue(result, self.arch)

	@property
	def uses_incoming_global_pointer(self) -> bool:
		"""Whether the function uses the incoming global pointer value"""
		return core.BNFunctionUsesIncomingGlobalPointer(self.handle)

	@property
	def comment(self) -> str:
		"""Gets the comment for the current function"""
		return core.BNGetFunctionComment(self.handle)

	@comment.setter
	def comment(self, comment: str) -> None:
		"""Sets a comment for the current function"""
		core.BNSetFunctionComment(self.handle, comment)

	@property
	def llil_basic_blocks(self) -> Generator['lowlevelil.LowLevelILBasicBlock', None, None]:
		"""A generator of all LowLevelILBasicBlock objects in the current function"""
		for block in self.llil:
			yield block

	@property
	def mlil_basic_blocks(self) -> Generator['mediumlevelil.MediumLevelILBasicBlock', None, None]:
		"""A generator of all MediumLevelILBasicBlock objects in the current function"""
		for block in self.mlil:
			yield block

	@property
	def instructions(self) -> Generator[Tuple[List['InstructionTextToken'], int], None, None]:
		"""A generator of instruction tokens and their start addresses for the current function"""
		for block in self.basic_blocks:
			start = block.start
			for i in block:
				yield i[0], start
				start += i[1]

	@property
	def too_large(self) -> bool:
		"""Whether the function is too large to automatically perform analysis (read-only)"""
		return core.BNIsFunctionTooLarge(self.handle)

	@property
	def analysis_skipped(self) -> bool:
		"""Whether automatic analysis was skipped for this function. Can be set to false to re-enable analysis."""
		return core.BNIsFunctionAnalysisSkipped(self.handle)

	@analysis_skipped.setter
	def analysis_skipped(self, skip: bool) -> None:
		if skip:
			core.BNSetFunctionAnalysisSkipOverride(self.handle, FunctionAnalysisSkipOverride.AlwaysSkipFunctionAnalysis)
		else:
			core.BNSetFunctionAnalysisSkipOverride(self.handle, FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis)

	@property
	def analysis_skip_reason(self) -> AnalysisSkipReason:
		"""Function analysis skip reason"""
		return AnalysisSkipReason(core.BNGetAnalysisSkipReason(self.handle))

	@property
	def analysis_skip_override(self) -> FunctionAnalysisSkipOverride:
		"""Override for skipping of automatic analysis"""
		return FunctionAnalysisSkipOverride(core.BNGetFunctionAnalysisSkipOverride(self.handle))

	@analysis_skip_override.setter
	def analysis_skip_override(self, override: FunctionAnalysisSkipOverride) -> None:
		core.BNSetFunctionAnalysisSkipOverride(self.handle, override)

	@property
	def unresolved_stack_adjustment_graph(self) -> Optional['flowgraph.CoreFlowGraph']:
		"""Flow graph of unresolved stack adjustments (read-only)"""
		graph = core.BNGetUnresolvedStackAdjustmentGraph(self.handle)
		if not graph:
			return None
		return flowgraph.CoreFlowGraph(graph)

	@property
	def merged_vars(self) -> Dict['variable.Variable', List['variable.Variable']]:
		"""
		Map of merged variables, organized by target variable (read-only). Use ``merge_vars`` and
		``unmerge_vars`` to update merged variables.
		"""
		count = ctypes.c_ulonglong()
		data = core.BNGetMergedVariables(self.handle, count)

		result = {}
		for i in range(count.value):
			target = Variable.from_BNVariable(self, data[i].target)
			sources = []
			for j in range(data[i].sourceCount):
				sources.append(Variable.from_BNVariable(self, data[i].sources[j]))
			result[target] = sources

		core.BNFreeMergedVariableList(data, count.value)
		return result

	@property
	def split_vars(self) -> List['variable.Variable']:
		"""
		Set of variables that have been split with ``split_var``. These variables correspond
		to those unique to each definition site and are obtained by using
		``MediumLevelILInstruction.get_split_var_for_definition`` at the definitions.
		"""
		count = ctypes.c_ulonglong()
		data = core.BNGetSplitVariables(self.handle, count)
		result = []
		for i in range(count.value):
			result.append(Variable.from_BNVariable(self, data[i]))
		core.BNFreeVariableList(data)
		return result

	@property
	def components(self):
		return self.view.get_function_parent_components(self)

	@property
	def inline_during_analysis(self) -> 'types.BoolWithConfidence':
		"""Whether the function's IL should be inlined into all callers' IL"""
		result = core.BNIsFunctionInlinedDuringAnalysis(self.handle)
		return types.BoolWithConfidence(result.value, confidence=result.confidence)

	@inline_during_analysis.setter
	def inline_during_analysis(self, value: Union[bool, 'types.BoolWithConfidence']):
		self.set_user_inline_during_analysis(value)

	def mark_recent_use(self) -> None:
		core.BNMarkFunctionAsRecentlyUsed(self.handle)

	def get_comment_at(self, addr: int) -> str:
		return core.BNGetCommentForAddress(self.handle, addr)

	def set_comment_at(self, addr: int, comment: str) -> None:
		"""
		``set_comment_at`` sets a comment for the current function at the address specified

		:param int addr: virtual address within the current function to apply the comment to
		:param str comment: string comment to apply
		:rtype: None
		:Example:

			>>> current_function.set_comment_at(here, "hi")

		"""
		core.BNSetCommentForAddress(self.handle, addr, comment)

	def add_user_code_ref(
	    self, from_addr: int, to_addr: int, arch: Optional['architecture.Architecture'] = None
	) -> None:
		"""
		``add_user_code_ref`` places a user-defined cross-reference from the instruction at
		the given address and architecture to the specified target address. If the specified
		source instruction is not contained within this function, no action is performed.
		To remove the reference, use :func:`remove_user_code_ref`.

		:param int from_addr: virtual address of the source instruction
		:param int to_addr: virtual address of the xref's destination.
		:param Architecture arch: (optional) architecture of the source instruction
		:rtype: None
		:Example:

			>>> current_function.add_user_code_ref(here, 0x400000)

		"""

		if arch is None:
			arch = self.arch

		core.BNAddUserCodeReference(self.handle, arch.handle, from_addr, to_addr)

	def remove_user_code_ref(
	    self, from_addr: int, to_addr: int, from_arch: Optional['architecture.Architecture'] = None
	) -> None:
		"""
		``remove_user_code_ref`` removes a user-defined cross-reference.
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

	def add_user_type_ref(
	    self, from_addr: int, name: 'types.QualifiedNameType', from_arch: Optional['architecture.Architecture'] = None
	) -> None:
		"""
		``add_user_type_ref`` places a user-defined type cross-reference from the instruction at
		the given address and architecture to the specified type. If the specified
		source instruction is not contained within this function, no action is performed.
		To remove the reference, use :func:`remove_user_type_ref`.

		:param int from_addr: virtual address of the source instruction
		:param QualifiedName name: name of the referenced type
		:param Architecture from_arch: (optional) architecture of the source instruction
		:rtype: None
		:Example:

			>>> current_function.add_user_code_ref(here, 'A')

		"""

		if from_arch is None:
			from_arch = self.arch

		_name = types.QualifiedName(name)._to_core_struct()
		core.BNAddUserTypeReference(self.handle, from_arch.handle, from_addr, _name)

	def remove_user_type_ref(
	    self, from_addr: int, name: 'types.QualifiedNameType', from_arch: Optional['architecture.Architecture'] = None
	) -> None:
		"""
		``remove_user_type_ref`` removes a user-defined type cross-reference.
		If the given address is not contained within this function, or if there is no
		such user-defined cross-reference, no action is performed.

		:param int from_addr: virtual address of the source instruction
		:param QualifiedName name: name of the referenced type
		:param Architecture from_arch: (optional) architecture of the source instruction
		:rtype: None
		:Example:

			>>> current_function.remove_user_type_ref(here, 'A')

		"""

		if from_arch is None:
			from_arch = self.arch

		_name = types.QualifiedName(name)._to_core_struct()
		core.BNRemoveUserTypeReference(self.handle, from_arch.handle, from_addr, _name)

	def add_user_type_field_ref(
	    self, from_addr: int, name: 'types.QualifiedNameType', offset: int,
	    from_arch: Optional['architecture.Architecture'] = None, size: int = 0
	) -> None:
		"""
		``add_user_type_field_ref`` places a user-defined type field cross-reference from the
		instruction at the given address and architecture to the specified type. If the specified
		source instruction is not contained within this function, no action is performed.
		To remove the reference, use :func:`remove_user_type_field_ref`.

		:param int from_addr: virtual address of the source instruction
		:param QualifiedName name: name of the referenced type
		:param int offset: offset of the field, relative to the type
		:param Architecture from_arch: (optional) architecture of the source instruction
		:param int size: (optional) the size of the access
		:rtype: None
		:Example:

			>>> current_function.add_user_type_field_ref(here, 'A', 0x8)

		"""

		if from_arch is None:
			from_arch = self.arch

		_name = types.QualifiedName(name)._to_core_struct()
		core.BNAddUserTypeFieldReference(self.handle, from_arch.handle, from_addr, _name, offset, size)

	def remove_user_type_field_ref(
	    self, from_addr: int, name: 'types.QualifiedNameType', offset: int,
	    from_arch: Optional['architecture.Architecture'] = None, size: int = 0
	) -> None:
		"""
		``remove_user_type_field_ref`` removes a user-defined type field cross-reference.
		If the given address is not contained within this function, or if there is no
		such user-defined cross-reference, no action is performed.

		:param int from_addr: virtual address of the source instruction
		:param QualifiedName name: name of the referenced type
		:param int offset: offset of the field, relative to the type
		:param Architecture from_arch: (optional) architecture of the source instruction
		:param int size: (optional) the size of the access
		:rtype: None
		:Example:

			>>> current_function.remove_user_type_field_ref(here, 'A', 0x8)

		"""

		if from_arch is None:
			from_arch = self.arch

		_name = types.QualifiedName(name)._to_core_struct()
		core.BNRemoveUserTypeFieldReference(self.handle, from_arch.handle, from_addr, _name, offset, size)

	def get_low_level_il_at(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> Optional['lowlevelil.LowLevelILInstruction']:
		"""
		``get_low_level_il_at`` gets the LowLevelILInstruction corresponding to the given virtual address

		:param int addr: virtual address of the function to be queried
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: LowLevelILInstruction
		:Example:

			>>> func = next(bv.functions)
			>>> func.get_low_level_il_at(func.start)
			<il: push(rbp)>
		"""
		if arch is None:
			arch = self.arch

		idx = core.BNGetLowLevelILForInstruction(self.handle, arch.handle, addr)

		llil = self.llil
		if idx == len(llil):
			return None

		return llil[idx]

	def get_llil_at(self, addr: int,
	                arch: Optional['architecture.Architecture'] = None) -> Optional['lowlevelil.LowLevelILInstruction']:
		"""
		``get_llil_at`` gets the LowLevelILInstruction corresponding to the given virtual address

		:param int addr: virtual address of the function to be queried
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: LowLevelILInstruction
		:Example:

			>>> func = next(bv.functions)
			>>> func.get_llil_at(func.start)
			<il: push(rbp)>
		"""
		return self.get_low_level_il_at(addr, arch)

	def get_llils_at(self, addr: int,
	                 arch: Optional['architecture.Architecture'] = None) -> List['lowlevelil.LowLevelILInstruction']:
		"""
		``get_llils_at`` gets the LowLevelILInstruction(s) corresponding to the given virtual address

		:param int addr: virtual address of the function to be queried
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: list(LowLevelILInstruction)
		:Example:

			>>> func = next(bv.functions)
			>>> func.get_llils_at(func.start)
			[<il: push(rbp)>]
		"""
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILInstructionsForAddress(self.handle, arch.handle, addr, count)
		assert instrs is not None, "core.BNGetLowLevelILInstructionsForAddress returned None"
		try:
			result = []
			for i in range(0, count.value):
				result.append(self.llil[instrs[i]])
			return result
		finally:
			core.BNFreeILInstructionList(instrs)

	def get_low_level_il_exits_at(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> List[int]:
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		exits = core.BNGetLowLevelILExitsForInstruction(self.handle, arch.handle, addr, count)
		assert exits is not None, "core.BNGetLowLevelILExitsForInstruction returned None"
		try:
			result = []
			for i in range(0, count.value):
				result.append(exits[i])
			return result
		finally:
			core.BNFreeILInstructionList(exits)

	def get_constant_data(self, state: RegisterValueType, value: int, size: int = 0) -> databuffer.DataBuffer:
		return databuffer.DataBuffer(handle=core.BNGetConstantData(self.handle, state, value, size, None))

	def get_constant_data_and_builtin(
			self, state: RegisterValueType, value: int, size: int = 0
	) -> Tuple[databuffer.DataBuffer, BuiltinType]:
		builtin = ctypes.c_int()
		db = databuffer.DataBuffer(
			handle=core.BNGetConstantData(self.handle, state, value, size, ctypes.byref(builtin)))
		return db, BuiltinType(builtin.value)

	def get_reg_value_at(
	    self, addr: int, reg: 'architecture.RegisterType', arch: Optional['architecture.Architecture'] = None
	) -> 'variable.RegisterValue':
		"""
		``get_reg_value_at`` gets the value the provided string register address corresponding to the given virtual address

		:param int addr: virtual address of the instruction to query
		:param str reg: string value of native register to query
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: variable.RegisterValue
		:Example:

			>>> current_function.get_reg_value_at(0x400dbe, 'rdi')
			<const 0x2>
		"""
		if arch is None:
			arch = self.arch
		reg = arch.get_reg_index(reg)
		value = core.BNGetRegisterValueAtInstruction(self.handle, arch.handle, addr, reg)
		result = variable.RegisterValue.from_BNRegisterValue(value, arch)
		return result

	def get_reg_value_after(
	    self, addr: int, reg: 'architecture.RegisterType', arch: Optional['architecture.Architecture'] = None
	) -> 'variable.RegisterValue':
		"""
		``get_reg_value_after`` gets the value instruction address corresponding to the given virtual address

		:param int addr: virtual address of the instruction to query
		:param str reg: string value of native register to query
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: variable.RegisterValue
		:Example:

			>>> current_function.get_reg_value_after(0x400dbe, 'rdi')
			<undetermined>
		"""
		if arch is None:
			arch = self.arch
		reg = arch.get_reg_index(reg)
		value = core.BNGetRegisterValueAfterInstruction(self.handle, arch.handle, addr, reg)
		result = variable.RegisterValue.from_BNRegisterValue(value, arch)
		return result

	def get_stack_contents_at(
	    self, addr: int, offset: int, size: int, arch: Optional['architecture.Architecture'] = None
	) -> 'variable.RegisterValue':
		"""
		``get_stack_contents_at`` returns the RegisterValue for the item on the stack in the current function at the
		given virtual address ``addr``, stack offset ``offset`` and size of ``size``. Optionally specifying the architecture.

		:param int addr: virtual address of the instruction to query
		:param int offset: stack offset base of stack
		:param int size: size of memory to query
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: variable.RegisterValue

		.. note:: Stack base is zero on entry into the function unless the architecture places the return address on the \
		stack as in (x86/x86_64) where the stack base will start at address_size

		:Example:

			>>> current_function.get_stack_contents_at(0x400fad, -16, 4)
			<range: 0x8 to 0xffffffff>
		"""
		if arch is None:
			arch = self.arch
		value = core.BNGetStackContentsAtInstruction(self.handle, arch.handle, addr, offset, size)
		result = variable.RegisterValue.from_BNRegisterValue(value, arch)
		return result

	def get_stack_contents_after(
	    self, addr: int, offset: int, size: int, arch: Optional['architecture.Architecture'] = None
	) -> 'variable.RegisterValue':
		if arch is None:
			arch = self.arch
		value = core.BNGetStackContentsAfterInstruction(self.handle, arch.handle, addr, offset, size)
		result = variable.RegisterValue.from_BNRegisterValue(value, arch)
		return result

	def get_parameter_at(
	    self, addr: int, func_type: Optional['types.Type'], i: int, arch: Optional['architecture.Architecture'] = None
	) -> 'variable.RegisterValue':
		if arch is None:
			arch = self.arch

		_func_type = None
		if func_type is not None:
			_func_type = func_type.handle
		value = core.BNGetParameterValueAtInstruction(self.handle, arch.handle, addr, _func_type, i)
		result = variable.RegisterValue.from_BNRegisterValue(value, arch)
		return result

	def get_parameter_at_low_level_il_instruction(
	    self, instr: 'lowlevelil.InstructionIndex', func_type: 'types.Type', i: int
	) -> 'variable.RegisterValue':
		_func_type = None
		if func_type is not None:
			_func_type = func_type.handle
		value = core.BNGetParameterValueAtLowLevelILInstruction(self.handle, instr, _func_type, i)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.arch)
		return result

	def get_regs_read_by(self, addr: int,
	                     arch: Optional['architecture.Architecture'] = None) -> List['architecture.RegisterName']:
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		regs = core.BNGetRegistersReadByInstruction(self.handle, arch.handle, addr, count)
		assert regs is not None, "core.BNGetRegistersReadByInstruction returned None"
		result = []
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_regs_written_by(self, addr: int,
	                        arch: Optional['architecture.Architecture'] = None) -> List['architecture.RegisterName']:
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		regs = core.BNGetRegistersWrittenByInstruction(self.handle, arch.handle, addr, count)
		assert regs is not None, "core.BNGetRegistersWrittenByInstruction returned None"
		result = []
		for i in range(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_stack_vars_referenced_by(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> List['variable.StackVariableReference']:
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		refs = core.BNGetStackVariablesReferencedByInstruction(self.handle, arch.handle, addr, count)
		assert refs is not None, "core.BNGetStackVariablesReferencedByInstruction returned None"
		result = []
		for i in range(0, count.value):
			var_type = types.Type.create(
			    core.BNNewTypeReference(refs[i].type), platform=self.platform, confidence=refs[i].typeConfidence
			)
			var = variable.Variable.from_identifier(self, refs[i].varIdentifier)
			result.append(
			    variable.StackVariableReference(
			        refs[i].sourceOperand, var_type, refs[i].name, var, refs[i].referencedOffset, refs[i].size
			    )
			)
		core.BNFreeStackVariableReferenceList(refs, count.value)
		return result

	def get_stack_vars_referenced_by_address_if_available(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> List['variable.StackVariableReference']:
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		refs = core.BNGetStackVariablesReferencedByInstructionIfAvailable(self.handle, arch.handle, addr, count)
		assert refs is not None, "core.BNGetStackVariablesReferencedByInstructionIfAvailable returned None"
		result = []
		for i in range(0, count.value):
			var_type = types.Type.create(
			    core.BNNewTypeReference(refs[i].type), platform=self.platform, confidence=refs[i].typeConfidence
			)
			var = variable.Variable.from_identifier(self, refs[i].varIdentifier)
			result.append(
			    variable.StackVariableReference(
			        refs[i].sourceOperand, var_type, refs[i].name, var, refs[i].referencedOffset, refs[i].size
			    )
			)
		core.BNFreeStackVariableReferenceList(refs, count.value)
		return result

	def get_lifted_il_at(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> Optional['lowlevelil.LowLevelILInstruction']:
		if arch is None:
			arch = self.arch

		idx = core.BNGetLiftedILForInstruction(self.handle, arch.handle, addr)

		if idx == len(self.lifted_il):
			return None

		return self.lifted_il[idx]

	def get_lifted_ils_at(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> List['lowlevelil.LowLevelILInstruction']:
		"""
		``get_lifted_ils_at`` gets the Lifted IL Instruction(s) corresponding to the given virtual address

		:param int addr: virtual address of the function to be queried
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: list(LowLevelILInstruction)
		:Example:
			>>> func = next(bv.functions)
			>>> func.get_lifted_ils_at(func.start)
			[<il: push(rbp)>]
		"""
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILInstructionsForAddress(self.handle, arch.handle, addr, count)
		assert instrs is not None, "core.BNGetLiftedILInstructionsForAddress returned None"
		result = []
		for i in range(0, count.value):
			result.append(self.lifted_il[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_constants_referenced_by(self, addr: int,
	                                arch: Optional['architecture.Architecture'] = None) -> List[variable.ConstantReference]:
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		refs = core.BNGetConstantsReferencedByInstruction(self.handle, arch.handle, addr, count)
		assert refs is not None, "core.BNGetConstantsReferencedByInstruction returned None"
		result = []
		for i in range(0, count.value):
			result.append(
			    variable.ConstantReference(refs[i].value, refs[i].size, refs[i].pointer, refs[i].intermediate)
			)
		core.BNFreeConstantReferenceList(refs)
		return result

	def get_constants_referenced_by_address_if_available(self, addr: int,
	                                arch: Optional['architecture.Architecture'] = None) -> List[variable.ConstantReference]:
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		refs = core.BNGetConstantsReferencedByInstructionIfAvailable(self.handle, arch.handle, addr, count)
		assert refs is not None, "core.BNGetConstantsReferencedByInstructionIfAvailable returned None"
		result = []
		for i in range(0, count.value):
			result.append(
			    variable.ConstantReference(refs[i].value, refs[i].size, refs[i].pointer, refs[i].intermediate)
			)
		core.BNFreeConstantReferenceList(refs)
		return result

	def get_lifted_il_flag_uses_for_definition(
	    self, i: 'lowlevelil.InstructionIndex', flag: 'architecture.FlagType'
	) -> List['lowlevelil.LowLevelILInstruction']:
		flag = self.arch.get_flag_index(flag)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILFlagUsesForDefinition(self.handle, i, flag, count)
		assert instrs is not None, "core.BNGetLiftedILFlagUsesForDefinition returned None"
		result = []
		for j in range(0, count.value):
			result.append(instrs[lowlevelil.InstructionIndex(j)])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_lifted_il_flag_definitions_for_use(self, i: 'lowlevelil.InstructionIndex',
	                                           flag: 'architecture.FlagType') -> List['lowlevelil.InstructionIndex']:
		flag = self.arch.get_flag_index(flag)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILFlagDefinitionsForUse(self.handle, i, flag, count)
		assert instrs is not None, "core.BNGetLiftedILFlagDefinitionsForUse returned None"
		result = []
		for j in range(0, count.value):
			result.append(instrs[lowlevelil.InstructionIndex(j)])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_flags_read_by_lifted_il_instruction(self,
	                                            i: 'lowlevelil.InstructionIndex') -> List['architecture.FlagName']:
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsReadByLiftedILInstruction(self.handle, i, count)
		assert flags is not None, "core.BNGetFlagsReadByLiftedILInstruction returned None"
		result = []
		for j in range(0, count.value):
			result.append(self.arch._flags_by_index[flags[j]])
		core.BNFreeRegisterList(flags)
		return result

	def get_flags_written_by_lifted_il_instruction(self,
	                                               i: 'lowlevelil.InstructionIndex') -> List['architecture.FlagName']:
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsWrittenByLiftedILInstruction(self.handle, i, count)
		assert flags is not None, "core.BNGetFlagsWrittenByLiftedILInstruction returned None"
		result = []
		for j in range(0, count.value):
			result.append(self.arch._flags_by_index[flags[j]])
		core.BNFreeRegisterList(flags)
		return result

	def create_graph(
	    self, graph_type: FunctionViewTypeOrName = FunctionGraphType.NormalFunctionGraph,
	    settings: Optional['DisassemblySettings'] = None
	) -> flowgraph.CoreFlowGraph:
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		graph_type = FunctionViewType(graph_type)._to_core_struct()
		return flowgraph.CoreFlowGraph(core.BNCreateFunctionGraph(self.handle, graph_type, settings_obj))

	def apply_imported_types(self, sym: 'types.CoreSymbol', type: Optional[StringOrType] = None) -> None:
		if isinstance(type, str):
			(type, _) = self.view.parse_type_string(type)
		core.BNApplyImportedTypes(self.handle, sym.handle, None if type is None else type.handle)

	def apply_auto_discovered_type(self, func_type: StringOrType) -> None:
		if isinstance(func_type, str):
			(func_type, _) = self.view.parse_type_string(func_type)
		core.BNApplyAutoDiscoveredFunctionType(self.handle, func_type.handle)

	def set_auto_indirect_branches(
	    self, source: int, branches: List[Tuple['architecture.Architecture', int]],
	    source_arch: Optional['architecture.Architecture'] = None
	) -> None:
		if source_arch is None:
			source_arch = self.arch
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in range(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNSetAutoIndirectBranches(self.handle, source_arch.handle, source, branch_list, len(branches))

	def set_user_indirect_branches(
	    self, source: int, branches: List[Tuple['architecture.Architecture', int]],
	    source_arch: Optional['architecture.Architecture'] = None
	) -> None:
		if source_arch is None:
			source_arch = self.arch
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in range(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNSetUserIndirectBranches(self.handle, source_arch.handle, source, branch_list, len(branches))

	def get_indirect_branches_at(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> List['variable.IndirectBranchInfo']:
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		branches = core.BNGetIndirectBranchesAt(self.handle, arch.handle, addr, count)
		try:
			assert branches is not None, "core.BNGetIndirectBranchesAt returned None"
			result = []
			for i in range(count.value):
				result.append(
				    variable.IndirectBranchInfo(
				        architecture.CoreArchitecture._from_cache(branches[i].sourceArch), branches[i].sourceAddr,
				        architecture.CoreArchitecture._from_cache(branches[i].destArch), branches[i].destAddr,
				        branches[i].autoDefined
				    )
				)
			return result
		finally:
			core.BNFreeIndirectBranchList(branches)

	def get_block_annotations(self, addr: int,
	                          arch: Optional['architecture.Architecture'] = None) -> List[List['InstructionTextToken']]:
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong(0)
		lines = core.BNGetFunctionBlockAnnotations(self.handle, arch.handle, addr, count)
		try:
			assert lines is not None, "core.BNGetFunctionBlockAnnotations returned None"
			result = []
			for i in range(count.value):
				result.append(InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count))
			return result
		finally:
			core.BNFreeInstructionTextLines(lines, count.value)

	def set_auto_type(self, value: StringOrType) -> None:
		if isinstance(value, str):
			(value, _) = self.view.parse_type_string(value)
		core.BNSetFunctionAutoType(self.handle, value.handle)

	def set_user_type(self, value: StringOrType) -> None:
		if isinstance(value, str):
			(value, _) = self.view.parse_type_string(value)
		core.BNSetFunctionUserType(self.handle, value.handle)

	@property
	def has_user_type(self) -> bool:
		"""True if the function has a user-defined type"""
		return core.BNFunctionHasUserType(self.handle)

	def set_auto_return_type(self, value: StringOrType) -> None:
		type_conf = core.BNTypeWithConfidence()
		if value is None:
			type_conf.type = None
			type_conf.confidence = 0
		elif isinstance(value, str):
			(value, _) = self.view.parse_type_string(value)
			type_conf.type = value
			type_conf.confidence = core.max_confidence
		else:
			type_conf.type = value.handle
			type_conf.confidence = value.confidence
		core.BNSetAutoFunctionReturnType(self.handle, type_conf)

	def set_auto_return_regs(self, value: Union['types.RegisterSet', List['architecture.RegisterType']]) -> None:
		regs = core.BNRegisterSetWithConfidence()
		regs.regs = (ctypes.c_uint * len(value))()
		regs.count = len(value)

		for i in range(0, len(value)):
			regs.regs[i] = self.arch.get_reg_index(value[i])
		if isinstance(value, types.RegisterSet):
			regs.confidence = value.confidence
		else:
			regs.confidence = core.max_confidence
		core.BNSetAutoFunctionReturnRegisters(self.handle, regs)

	def set_auto_calling_convention(self, value: 'callingconvention.CallingConvention') -> None:
		conv_conf = core.BNCallingConventionWithConfidence()
		if value is None:
			conv_conf.convention = None
			conv_conf.confidence = 0
		else:
			conv_conf.convention = value.handle
			conv_conf.confidence = value.confidence
		core.BNSetAutoFunctionCallingConvention(self.handle, conv_conf)

	def set_auto_parameter_vars(
	    self, value: Optional[Union[List['variable.Variable'], 'variable.Variable', 'variable.ParameterVariables']]
	) -> None:
		if value is None:
			var_list = []
		elif isinstance(value, variable.Variable):
			var_list = [value]
		elif isinstance(value, variable.ParameterVariables):
			var_list = value.vars
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
		elif isinstance(value, variable.ParameterVariables):
			var_conf.confidence = value.confidence
		else:
			var_conf.confidence = core.max_confidence
		core.BNSetAutoFunctionParameterVariables(self.handle, var_conf)

	def set_auto_has_variable_arguments(self, value: Union[bool, 'types.BoolWithConfidence']) -> None:
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if isinstance(value, types.BoolWithConfidence):
			bc.confidence = value.confidence
		else:
			bc.confidence = core.max_confidence
		core.BNSetAutoFunctionHasVariableArguments(self.handle, bc)

	def set_auto_can_return(self, value: Union[bool, 'types.BoolWithConfidence']) -> None:
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if isinstance(value, types.BoolWithConfidence):
			bc.confidence = value.confidence
		else:
			bc.confidence = core.max_confidence
		core.BNSetAutoFunctionCanReturn(self.handle, bc)

	def set_auto_pure(self, value: Union[bool, 'types.BoolWithConfidence']) -> None:
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if isinstance(value, types.BoolWithConfidence):
			bc.confidence = value.confidence
		else:
			bc.confidence = core.max_confidence
		core.BNSetAutoFunctionPure(self.handle, bc)

	def set_auto_stack_adjustment(self, value: Union[int, 'types.OffsetWithConfidence']) -> None:
		oc = core.BNOffsetWithConfidence()
		oc.value = int(value)
		if isinstance(value, types.OffsetWithConfidence):
			oc.confidence = value.confidence
		else:
			oc.confidence = core.max_confidence
		core.BNSetAutoFunctionStackAdjustment(self.handle, oc)

	def set_auto_reg_stack_adjustments(
	    self, value: Mapping['architecture.RegisterStackName', 'types.RegisterStackAdjustmentWithConfidence']
	):
		adjust = (core.BNRegisterStackAdjustment * len(value))()
		for i, reg_stack in enumerate(value.keys()):
			adjust[i].regStack = self.arch.get_reg_stack_index(reg_stack)
			if isinstance(value[reg_stack], types.RegisterStackAdjustmentWithConfidence):
				adjust[i].adjustment = value[reg_stack].value
				adjust[i].confidence = value[reg_stack].confidence
			else:
				adjust[i].adjustment = value[reg_stack]
				adjust[i].confidence = core.max_confidence
		core.BNSetAutoFunctionRegisterStackAdjustments(self.handle, adjust, len(value))

	def set_auto_clobbered_regs(self, value: List['architecture.RegisterType']) -> None:
		regs = core.BNRegisterSetWithConfidence()
		regs.regs = (ctypes.c_uint * len(value))()
		regs.count = len(value)

		for i in range(0, len(value)):
			regs.regs[i] = self.arch.get_reg_index(value[i])
		if isinstance(value, types.RegisterSet):
			regs.confidence = value.confidence
		else:
			regs.confidence = core.max_confidence
		core.BNSetAutoFunctionClobberedRegisters(self.handle, regs)

	def get_int_display_type(
	    self, instr_addr: int, value: int, operand: int, arch: Optional['architecture.Architecture'] = None
	) -> IntegerDisplayType:
		"""
		Get the current text display type for an integer token in the disassembly or IL views

		See also see :py:func:`get_int_display_type_and_typeid`

		:param int instr_addr: Address of the instruction or IL line containing the token
		:param int value: ``value`` field of the InstructionTextToken object for the token, usually the constant displayed
		:param int operand: Operand index of the token, defined as the number of OperandSeparatorTokens in the disassembly line before the token
		:param Architecture arch: (optional) Architecture of the instruction or IL line containing the token
		"""
		if arch is None:
			arch = self.arch
		return IntegerDisplayType(
		    core.BNGetIntegerConstantDisplayType(self.handle, arch.handle, instr_addr, value, operand)
		)

	def get_int_enum_display_typeid(self, instr_addr: int, value: int, operand: int,
									arch: Optional['architecture.Architecture'] = None) -> str:
		"""
		Get the current text display enum type for an integer token in the disassembly or IL views.

		See also see :py:func:`get_int_display_type_and_typeid`

		:param int instr_addr: Address of the instruction or IL line containing the token
		:param int value: ``value`` field of the InstructionTextToken object for the token, usually the constant displayed
		:param int operand: Operand index of the token, defined as the number of OperandSeparatorTokens in the disassembly line before the token
		:param Architecture arch: (optional) Architecture of the instruction or IL line containing the token
		:return: TypeID for the integer token
		"""
		if arch is None:
			arch = self.arch
		type_id = core.BNGetIntegerConstantDisplayTypeEnumerationType(self.handle, arch.handle, instr_addr, value, operand)
		return type_id

	def set_int_display_type(
	    self, instr_addr: int, value: int, operand: int, display_type: IntegerDisplayType,
	    arch: Optional['architecture.Architecture'] = None, enum_display_typeid = None
	) -> None:
		"""
		Change the text display type for an integer token in the disassembly or IL views

		:param int instr_addr: Address of the instruction or IL line containing the token
		:param int value: ``value`` field of the InstructionTextToken object for the token, usually the constant displayed
		:param int operand: Operand index of the token, defined as the number of OperandSeparatorTokens in the disassembly line before the token
		:param enums.IntegerDisplayType display_type: Desired display type
		:param Architecture arch: (optional) Architecture of the instruction or IL line containing the token
		:param str enum_display_typeid: (optional) Whenever passing EnumDisplayType to ``display_type``, passing a type ID here will specify the Enumeration display type. Must be a valid type ID and resolve to an enumeration type.
		"""
		if arch is None:
			arch = self.arch
		if isinstance(display_type, str):
			display_type = IntegerDisplayType[display_type]
		core.BNSetIntegerConstantDisplayType(self.handle, arch.handle, instr_addr, value, operand, display_type, enum_display_typeid)

	def get_int_display_type_and_typeid(self, instr_addr: int, value: int, operand: int,
										arch: Optional['architecture.Architecture'] = None) -> (IntegerDisplayType, str):
		"""
		Get the current text display type for an integer token in the disassembly or IL views

		:param int instr_addr: Address of the instruction or IL line containing the token
		:param int value: ``value`` field of the InstructionTextToken object for the token, usually the constant displayed
		:param int operand: Operand index of the token, defined as the number of OperandSeparatorTokens in the disassembly line before the token
		:param Architecture arch: (optional) Architecture of the instruction or IL line containing the token
		"""
		if arch is None:
			arch = self.arch
		display_type = core.BNGetIntegerConstantDisplayType(self.handle, arch.handle, instr_addr, value, operand)
		type_id = core.BNGetIntegerConstantDisplayTypeEnumerationType(self.handle, arch.handle, instr_addr, value, operand)
		return display_type, type_id

	def reanalyze(self, update_type: FunctionUpdateType = FunctionUpdateType.UserFunctionUpdate) -> None:
		"""
		``reanalyze`` causes this function to be reanalyzed. This function does not wait for the analysis to finish.

		:param enums.FunctionUpdateType update_type: (optional) Desired update type

		.. warning:: If analysis_skipped is True, using this API will not trigger re-analysis. Instead, set `analysis_skipped` to `False`.

		:rtype: None
		"""
		core.BNReanalyzeFunction(self.handle, update_type)

	def mark_updates_required(self, update_type: FunctionUpdateType = FunctionUpdateType.UserFunctionUpdate) -> None:
		"""
		``mark_updates_required`` indicates that this function needs to be reanalyzed during the next update cycle

		:param enums.FunctionUpdateType update_type: (optional) Desired update type

		:rtype: None
		"""
		core.BNMarkUpdatesRequired(self.handle, update_type)

	def mark_caller_updates_required(self, update_type: FunctionUpdateType = FunctionUpdateType.UserFunctionUpdate) -> None:
		"""
		``mark_caller_updates_required`` indicates that callers of this function need to be reanalyzed during the next update cycle

		:param enums.FunctionUpdateType update_type: (optional) Desired update type

		:rtype: None
		"""
		core.BNMarkCallerUpdatesRequired(self.handle, update_type)

	def request_advanced_analysis_data(self) -> None:
		core.BNRequestAdvancedFunctionAnalysisData(self.handle)
		self._advanced_analysis_requests += 1

	def release_advanced_analysis_data(self) -> None:
		core.BNReleaseAdvancedFunctionAnalysisData(self.handle)
		self._advanced_analysis_requests -= 1

	def get_basic_block_at(self, addr: int,
	                       arch: Optional['architecture.Architecture'] = None) -> Optional['basicblock.BasicBlock']:
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
		return basicblock.BasicBlock(block, self._view)

	def get_instr_highlight(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> '_highlight.HighlightColor':
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
			return _highlight.HighlightColor(color=color.color, alpha=color.alpha)
		elif color.style == HighlightColorStyle.MixedHighlightColor:
			return _highlight.HighlightColor(
			    color=color.color, mix_color=color.mixColor, mix=color.mix, alpha=color.alpha
			)
		elif color.style == HighlightColorStyle.CustomHighlightColor:
			return _highlight.HighlightColor(red=color.r, green=color.g, blue=color.b, alpha=color.alpha)
		return _highlight.HighlightColor(color=HighlightStandardColor.NoHighlightColor)

	def set_auto_instr_highlight(
	    self, addr: int, color: Union['_highlight.HighlightColor', HighlightStandardColor],
	    arch: Optional['architecture.Architecture'] = None
	):
		"""
		``set_auto_instr_highlight`` highlights the instruction at the specified address with the supplied color

		.. warning:: Use only in analysis plugins. Do not use in regular plugins, as colors won't be saved to the database.

		:param int addr: virtual address of the instruction to be highlighted
		:param HighlightStandardColor|highlight.HighlightColor color: Color value to use for highlighting
		:param Architecture arch: (optional) Architecture of the instruction if different from self.arch
		"""
		if arch is None:
			arch = self.arch
		if not isinstance(color, HighlightStandardColor) and not isinstance(color, _highlight.HighlightColor):
			raise ValueError("Specified color is not one of HighlightStandardColor, _highlight.HighlightColor")
		if isinstance(color, HighlightStandardColor):
			color = _highlight.HighlightColor(color=color)
		core.BNSetAutoInstructionHighlight(self.handle, arch.handle, addr, color._to_core_struct())

	def set_user_instr_highlight(
	    self, addr: int, color: Union['_highlight.HighlightColor', HighlightStandardColor],
	    arch: Optional['architecture.Architecture'] = None
	):
		"""
		``set_user_instr_highlight`` highlights the instruction at the specified address with the supplied color

		:param int addr: virtual address of the instruction to be highlighted
		:param HighlightStandardColor|highlight.HighlightColor color: Color value to use for highlighting
		:param Architecture arch: (optional) Architecture of the instruction if different from self.arch
		:Example:

			>>> current_function.set_user_instr_highlight(here, HighlightStandardColor.BlueHighlightColor)
			>>> current_function.set_user_instr_highlight(here, highlight.HighlightColor(red=0xff, blue=0xff, green=0))

		Warning: For performance reasons, this function does not ensure the address you have supplied is within the
		function's bounds.
		"""
		if arch is None:
			arch = self.arch
		if not isinstance(color, HighlightStandardColor) and not isinstance(color, _highlight.HighlightColor):
			raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
		if isinstance(color, HighlightStandardColor):
			color = _highlight.HighlightColor(color)
		core.BNSetUserInstructionHighlight(self.handle, arch.handle, addr, color._to_core_struct())

	def create_auto_stack_var(self, offset: int, var_type: StringOrType, name: str) -> None:
		if isinstance(var_type, str):
			(var_type, _) = self.view.parse_type_string(var_type)
		tc = var_type._to_core_struct()
		core.BNCreateAutoStackVariable(self.handle, offset, tc, name)

	def create_user_stack_var(self, offset: int, var_type: StringOrType, name: str) -> None:
		if isinstance(var_type, str):
			(var_type, _) = self.view.parse_type_string(var_type)
		tc = var_type._to_core_struct()
		core.BNCreateUserStackVariable(self.handle, offset, tc, name)

	def delete_auto_stack_var(self, offset: int) -> None:
		core.BNDeleteAutoStackVariable(self.handle, offset)

	def delete_user_stack_var(self, offset: int) -> None:
		core.BNDeleteUserStackVariable(self.handle, offset)

	def create_auto_var(
	    self, var: 'variable.Variable', var_type: StringOrType, name: str, ignore_disjoint_uses: bool = False
	) -> None:
		if isinstance(var_type, str):
			(var_type, _) = self.view.parse_type_string(var_type)
		tc = var_type._to_core_struct()
		core.BNCreateAutoVariable(self.handle, var.to_BNVariable(), tc, name, ignore_disjoint_uses)

	def create_user_var(
	    self, var: 'variable.Variable', var_type: StringOrType, name: str, ignore_disjoint_uses: bool = False
	) -> None:
		if isinstance(var_type, str):
			(var_type, _) = self.view.parse_type_string(var_type)
		tc = var_type._to_core_struct()
		core.BNCreateUserVariable(self.handle, var.to_BNVariable(), tc, name, ignore_disjoint_uses)

	def delete_user_var(self, var: 'variable.Variable') -> None:
		core.BNDeleteUserVariable(self.handle, var.to_BNVariable())

	def is_var_user_defined(self, var: 'variable.Variable') -> bool:
		return core.BNIsVariableUserDefined(self.handle, var.to_BNVariable())

	def get_stack_var_at_frame_offset(
	    self, offset: int, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> Optional['variable.Variable']:
		if arch is None:
			arch = self.arch
		found_var = core.BNVariableNameAndType()
		if not core.BNGetStackVariableAtFrameOffset(self.handle, arch.handle, addr, offset, found_var):
			return None
		result = variable.Variable.from_BNVariable(self, found_var.var)
		core.BNFreeVariableNameAndType(found_var)
		return result

	def get_stack_var_at_frame_offset_after_instruction(
	    self, offset: int, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> Optional['variable.Variable']:
		if arch is None:
			arch = self.arch
		found_var = core.BNVariableNameAndType()
		if not core.BNGetStackVariableAtFrameOffsetAfterInstruction(self.handle, arch.handle, addr, offset, found_var):
			return None
		result = variable.Variable.from_BNVariable(self, found_var.var)
		core.BNFreeVariableNameAndType(found_var)
		return result

	def get_type_tokens(self, settings: Optional['DisassemblySettings'] = None) -> List['DisassemblyTextLine']:
		_settings = None
		if settings is not None:
			_settings = settings.handle
		count = ctypes.c_ulonglong()
		lines = core.BNGetFunctionTypeTokens(self.handle, settings, count)
		assert lines is not None, "core.BNGetFunctionTypeTokens returned None"
		result = []
		for i in range(0, count.value):
			addr = lines[i].addr
			color = _highlight.HighlightColor._from_core_struct(lines[i].highlight)
			tokens = InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
			result.append(DisassemblyTextLine(tokens, addr, color=color))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	def get_reg_value_at_exit(self, reg: 'architecture.RegisterType') -> 'variable.RegisterValue':
		result = core.BNGetFunctionRegisterValueAtExit(self.handle, self.arch.get_reg_index(reg))
		return variable.RegisterValue.from_BNRegisterValue(result, self.arch)

	def set_auto_call_stack_adjustment(
	    self, addr: int, adjust: Union[int, 'types.OffsetWithConfidence'],
	    arch: Optional['architecture.Architecture'] = None
	) -> None:
		if arch is None:
			arch = self.arch
		if not isinstance(adjust, types.OffsetWithConfidence):
			adjust = types.OffsetWithConfidence(adjust)
		core.BNSetAutoCallStackAdjustment(self.handle, arch.handle, addr, adjust.value, adjust.confidence)

	def set_auto_call_reg_stack_adjustment(
	    self, addr: int, adjust: Mapping['architecture.RegisterStackName', int],
	    arch: Optional['architecture.Architecture'] = None
	) -> None:
		if arch is None:
			arch = self.arch
		adjust_buf = (core.BNRegisterStackAdjustment * len(adjust))()

		for i, reg_stack in enumerate(adjust.keys()):
			adjust_buf[i].regStack = arch.get_reg_stack_index(reg_stack)
			value = adjust[reg_stack]
			if not isinstance(value, types.RegisterStackAdjustmentWithConfidence):
				value = types.RegisterStackAdjustmentWithConfidence(value)
			adjust_buf[i].adjustment = value.value
			adjust_buf[i].confidence = value.confidence
		core.BNSetAutoCallRegisterStackAdjustment(self.handle, arch.handle, addr, adjust_buf, len(adjust))

	def set_auto_call_reg_stack_adjustment_for_reg_stack(
	    self, addr: int, reg_stack: 'architecture.RegisterStackType', adjust,
	    arch: Optional['architecture.Architecture'] = None
	) -> None:
		if arch is None:
			arch = self.arch
		reg_stack = arch.get_reg_stack_index(reg_stack)
		if not isinstance(adjust, types.RegisterStackAdjustmentWithConfidence):
			adjust = types.RegisterStackAdjustmentWithConfidence(adjust)
		core.BNSetAutoCallRegisterStackAdjustmentForRegisterStack(
		    self.handle, arch.handle, addr, reg_stack, adjust.value, adjust.confidence
		)

	def set_call_type_adjustment(
	    self, addr: int, adjust_type: Optional[StringOrType] = None, arch: Optional['architecture.Architecture'] = None
	) -> None:
		"""
		``set_call_type_adjustment`` sets or removes the call type override at a call site to the given type.

		:param int addr: virtual address of the call instruction to adjust
		:param str|types.Type|types.TypeBuilder adjust_type: (optional) overridden call type, or `None` to remove an existing adjustment
		:param Architecture arch: (optional) Architecture of the instruction if different from self.arch
		:Example:

			>>> # Change the current call site to no-return
			>>> target = bv.get_function_at(list(filter(lambda ref: ref.address == here, current_function.call_sites))[0].mlil.dest.value.value)
			>>> ft = target.type.mutable_copy()
			>>> ft.can_return = False
			>>> current_function.set_call_type_adjustment(here, ft)
		"""
		if arch is None:
			arch = self.arch

		if adjust_type is not None:
			if isinstance(adjust_type, str):
				(adjust_type, _) = self.view.parse_type_string(adjust_type)
				confidence = core.max_confidence
			else:
				confidence = adjust_type.confidence
			type_conf = core.BNTypeWithConfidence()
			type_conf.type = adjust_type.handle
			type_conf.confidence = confidence
		else:
			type_conf = None

		core.BNSetUserCallTypeAdjustment(self.handle, arch.handle, addr, type_conf)

	def set_call_stack_adjustment(
	    self, addr: int, adjust: Union[int, 'types.OffsetWithConfidence'],
	    arch: Optional['architecture.Architecture'] = None
	):
		if arch is None:
			arch = self.arch
		if not isinstance(adjust, types.OffsetWithConfidence):
			adjust = types.OffsetWithConfidence(adjust)
		core.BNSetUserCallStackAdjustment(self.handle, arch.handle, addr, adjust.value, adjust.confidence)

	def set_call_reg_stack_adjustment(
	    self, addr: int, adjust: Mapping['architecture.RegisterStackName',
	                                     Union[int, 'types.RegisterStackAdjustmentWithConfidence']],
	    arch: Optional['architecture.Architecture'] = None
	) -> None:
		if arch is None:
			arch = self.arch
		adjust_buf = (core.BNRegisterStackAdjustment * len(adjust))()

		for i, reg_stack in enumerate(adjust.keys()):
			adjust_buf[i].regStack = arch.get_reg_stack_index(reg_stack)
			value = adjust[reg_stack]
			if not isinstance(value, types.RegisterStackAdjustmentWithConfidence):
				value = types.RegisterStackAdjustmentWithConfidence(int(value))
			adjust_buf[i].adjustment = value.value
			adjust_buf[i].confidence = value.confidence
		core.BNSetUserCallRegisterStackAdjustment(self.handle, arch.handle, addr, adjust_buf, len(adjust))

	def set_call_reg_stack_adjustment_for_reg_stack(
	    self, addr: int, reg_stack: 'architecture.RegisterStackType',
	    adjust: Union[int,
	                  'types.RegisterStackAdjustmentWithConfidence'], arch: Optional['architecture.Architecture'] = None
	) -> None:
		if arch is None:
			arch = self.arch
		reg_stack = arch.get_reg_stack_index(reg_stack)
		if not isinstance(adjust, types.RegisterStackAdjustmentWithConfidence):
			adjust = types.RegisterStackAdjustmentWithConfidence(adjust)
		core.BNSetUserCallRegisterStackAdjustmentForRegisterStack(
		    self.handle, arch.handle, addr, reg_stack, adjust.value, adjust.confidence
		)

	def get_call_type_adjustment(self, addr: int,
	                             arch: Optional['architecture.Architecture'] = None) -> Optional['types.Type']:
		if arch is None:
			arch = self.arch
		result = core.BNGetCallTypeAdjustment(self.handle, arch.handle, addr)
		if not result.type:
			return None
		platform = self.platform
		return types.Type.create(result.type, platform=platform, confidence=result.confidence)

	def get_call_stack_adjustment(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> 'types.OffsetWithConfidence':
		if arch is None:
			arch = self.arch
		result = core.BNGetCallStackAdjustment(self.handle, arch.handle, addr)
		return types.OffsetWithConfidence(result.value, confidence=result.confidence)

	def get_call_reg_stack_adjustment(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> Dict['architecture.RegisterStackName', 'types.RegisterStackAdjustmentWithConfidence']:
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		adjust = core.BNGetCallRegisterStackAdjustment(self.handle, arch.handle, addr, count)
		assert adjust is not None, "core.BNGetCallRegisterStackAdjustment returned None"
		result = {}
		for i in range(0, count.value):
			result[arch.get_reg_stack_name(
			    adjust[i].regStack
			)] = types.RegisterStackAdjustmentWithConfidence(adjust[i].adjustment, confidence=adjust[i].confidence)
		core.BNFreeRegisterStackAdjustments(adjust)
		return result

	def get_call_reg_stack_adjustment_for_reg_stack(
	    self, addr: int, reg_stack: 'architecture.RegisterStackType', arch: Optional['architecture.Architecture'] = None
	) -> 'types.RegisterStackAdjustmentWithConfidence':
		if arch is None:
			arch = self.arch
		reg_stack = arch.get_reg_stack_index(reg_stack)
		adjust = core.BNGetCallRegisterStackAdjustmentForRegisterStack(self.handle, arch.handle, addr, reg_stack)
		result = types.RegisterStackAdjustmentWithConfidence(adjust.adjustment, confidence=adjust.confidence)
		return result

	def is_call_instruction(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> bool:
		if arch is None:
			arch = self.arch
		return core.BNIsCallInstruction(self.handle, arch.handle, addr)

	def set_user_var_value(self, var: 'variable.Variable', def_addr: int, value: 'variable.PossibleValueSet') -> None:
		"""
		`set_user_var_value` allows the user to specify a PossibleValueSet value for an MLIL variable at its \
		definition site.

		.. warning:: Setting the variable value, triggers a reanalysis of the function and allows the dataflow \
		to compute and propagate values which depend on the current variable. This implies that branch conditions \
		whose values can be determined statically will be computed, leading to potential branch elimination at \
		the HLIL layer.

		:param Variable var: Variable for which the value is to be set
		:param int def_addr: Address of the definition site of the variable
		:param PossibleValueSet value: Informed value of the variable
		:rtype: None

		:Example:

			>>> mlil_var = current_mlil[0].operands[0]
			>>> def_address = 0x40108d
			>>> var_value = PossibleValueSet.constant(5)
			>>> current_function.set_user_var_value(mlil_var, def_address, var_value)
		"""
		if var.index == 0:
			# Special case: function parameters have index 0 and are defined at the start of the function
			def_addr = self.start
		else:
			var_defs = self.mlil.get_var_definitions(var)
			if var_defs is None:
				raise ValueError("Could not get definition for Variable")
			found = False
			for site in var_defs:
				if site.address == def_addr:
					found = True
					break
			if not found:
				raise ValueError("No definition for Variable found at given address")
		def_site = core.BNArchitectureAndAddress()
		def_site.arch = self.arch.handle
		def_site.address = def_addr

		core.BNSetUserVariableValue(self.handle, var.to_BNVariable(), def_site, value._to_core_struct())

	def clear_user_var_value(self, var: 'variable.Variable', def_addr: int) -> None:
		"""
		Clears a previously defined user variable value.

		:param Variable var: Variable for which the value was informed
		:param int def_addr: Address of the definition site of the variable
		:rtype: None
		"""
		if var.index == 0:
			# Special case: function parameters have index 0 and are defined at the start of the function
			def_addr = self.start
		else:
			var_defs = self.mlil.get_var_definitions(var)
			if var_defs is None:
				raise ValueError("Could not get definition for Variable")

			found = False
			for site in var_defs:
				if site.address == def_addr:
					found = True
					break
			if not found:
				raise ValueError("No definition for Variable found at given address")
		def_site = core.BNArchitectureAndAddress()
		def_site.arch = self.arch.handle
		def_site.address = def_addr

		core.BNClearUserVariableValue(self.handle, var.to_BNVariable(), def_site)

	def get_all_user_var_values(
	    self
	) -> Dict['variable.Variable', Dict['ArchAndAddr', 'variable.PossibleValueSet']]:
		"""
		Returns a map of current defined user variable values.

		:returns: Map of user current defined user variable values and their definition sites.
		:type: dict of (Variable, dict of (ArchAndAddr, PossibleValueSet))
		"""
		count = ctypes.c_ulonglong(0)
		var_values = core.BNGetAllUserVariableValues(self.handle, count)
		assert var_values is not None, "core.BNGetAllUserVariableValues returned None"
		try:
			result = {}
			for i in range(count.value):
				var_val = var_values[i]
				var = variable.Variable.from_BNVariable(self, var_val.var)
				if var not in result:
					result[var] = {}
				def_site = ArchAndAddr(architecture.CoreArchitecture._from_cache(var_val.defSite.arch), var_val.defSite.address)
				result[var][def_site] = variable.PossibleValueSet(def_site.arch, var_val.value)
			return result
		finally:
			core.BNFreeUserVariableValues(var_values)

	def clear_all_user_var_values(self) -> None:
		"""
		Clear all user defined variable values.

		:rtype: None
		"""
		all_values = self.get_all_user_var_values()
		for var in all_values:
			for def_site in all_values[var]:
				self.clear_user_var_value(var, def_site.addr)

	def request_debug_report(self, name: str) -> None:
		"""
		``request_debug_report`` can generate internal debug reports for a variety of analysis.
		Current list of possible values include:

		- mlil_translator
		- stack_adjust_graph
		- high_level_il

		:param str name: Name of the debug report
		:rtype: None
		"""
		debug_report_alias = {
			"stack" : "stack_adjust_graph",
			"mlil" : "mlil_translator",
			"hlil" : "high_level_il"
		}

		if name in debug_report_alias:
			name = debug_report_alias[name]

		core.BNRequestFunctionDebugReport(self.handle, name)
		self.view.update_analysis()

	@property
	def call_sites(self) -> List['binaryview.ReferenceSource']:
		"""
		``call_sites`` returns a list of possible call sites contained in this function.
		This includes ordinary calls, tail calls, and indirect jumps. Not all of the returned call sites
		are necessarily true call sites; some may simply be unresolved indirect jumps, for example.

		:return: List of References that represent the sources of possible calls in this function
		:rtype: list(ReferenceSource)
		"""
		count = ctypes.c_ulonglong(0)
		refs = core.BNGetFunctionCallSites(self.handle, count)
		assert refs is not None, "core.BNGetFunctionCallSites returned None"
		result = []
		for i in range(0, count.value):
			if refs[i].func:
				func = Function(self.view, core.BNNewFunctionReference(refs[i].func))
			else:
				func = None
			if refs[i].arch:
				arch = architecture.CoreArchitecture._from_cache(refs[i].arch)
			else:
				arch = None
			addr = refs[i].addr
			result.append(binaryview.ReferenceSource(func, arch, addr))
		core.BNFreeCodeReferences(refs, count.value)
		return result

	@property
	def callees(self) -> List['Function']:
		"""
		``callees`` returns a list of functions that this function calls
		This does not include the address of those calls, rather just the function objects themselves. Use :py:meth:`call_sites` to identify the location of these calls.

		:return: List of Functions that this function calls
		:rtype: list(Function)
		"""
		called = []
		for callee_addr in self.callee_addresses:
			# a second argument to get_function_at() can filter callees whose platform matchers caller
			# good when two functions with different arch's start at same address (rare polyglot code)
			# bad for ARM/Thumb (common)
			func = self.view.get_function_at(callee_addr)
			if func is not None:
				called.append(func)
		return called

	@property
	def callee_addresses(self) -> List[int]:
		"""
		``callee_addressses`` returns a list of start addresses for functions that this function calls.
		Does not point to the actual address where the call occurs, just the start of the function that contains the reference.

		:return: List of start address for functions that this function calls
		:rtype: list(int)
		"""
		result = []
		for ref in self.call_sites:
			result.extend(self.view.get_callees(ref.address, ref.function, ref.arch))
		return result

	@property
	def callers(self) -> List['Function']:
		"""
		``callers`` returns a list of functions that call this function
		Does not point to the actual address where the call occurs, just the start of the function that contains the call.

		:return: List of Functions that call this function
		:rtype: list(Function)
		"""
		functions = []
		for ref in self.view.get_code_refs(self.start):
			if ref.function is not None:
				functions.append(ref.function)
		return functions

	@property
	def caller_sites(self) -> Generator['binaryview.ReferenceSource', None, None]:
		"""
		``caller_sites`` returns a list of ReferenceSource objects corresponding to the addresses
		in functions which reference this function

		:return: List of ReferenceSource objects of the call sites to this function
		:rtype: list(ReferenceSource)
		"""
		return self.view.get_code_refs(self.start)

	@property
	def workflow(self):
		handle = core.BNGetWorkflowForFunction(self.handle)
		if handle is None:
			return None
		return workflow.Workflow(handle=handle, object_handle=self.handle)

	@property
	def provenance(self):
		"""
		``provenance`` returns a string representing the provenance. This portion of the API is under development.
		Currently the provenance information is undocumented, not persistent, and not saved to a database.

		:return: string representation of the provenance
		:rtype: str
		"""
		return core.BNGetProvenanceString(self.handle)

	def get_mlil_var_refs(self, var: 'variable.Variable') -> List[ILReferenceSource]:
		"""
		``get_mlil_var_refs`` returns a list of ILReferenceSource objects (IL xrefs or cross-references)
		that reference the given variable. The variable is a local variable that can be either on the stack,
		in a register, or in a flag.
		This function is related to get_hlil_var_refs(), which returns variable references collected
		from HLIL. The two can be different in several cases, e.g., multiple variables in MLIL can be merged
		into a single variable in HLIL.

		:param Variable var: Variable for which to query the xref
		:return: List of IL References for the given variable
		:rtype: list(ILReferenceSource)
		:Example:

			>>> mlil_var = current_mlil[0].operands[0]
			>>> current_function.get_mlil_var_refs(mlil_var)
		"""
		count = ctypes.c_ulonglong(0)
		refs = core.BNGetMediumLevelILVariableReferences(self.handle, var.to_BNVariable(), count)
		assert refs is not None, "core.BNGetMediumLevelILVariableReferences returned None"
		result = []
		for i in range(0, count.value):
			if refs[i].func:
				func = Function(self.view, core.BNNewFunctionReference(refs[i].func))
			else:
				func = None
			if refs[i].arch:
				arch = architecture.CoreArchitecture._from_cache(refs[i].arch)
			else:
				arch = None

			result.append(ILReferenceSource(func, arch, refs[i].addr, refs[i].type, refs[i].exprId))
		core.BNFreeILReferences(refs, count.value)
		return result

	def get_mlil_var_refs_from(self, addr: int, length: Optional[int] = None,
	                           arch: Optional['architecture.Architecture'] = None) -> List[VariableReferenceSource]:
		"""
		``get_mlil_var_refs_from`` returns a list of variables referenced by code in the function ``func``,
		of the architecture ``arch``, and at the address ``addr``. If no function is specified, references from
		all functions and containing the address will be returned. If no architecture is specified, the
		architecture of the function will be used.
		This function is related to get_hlil_var_refs_from(), which returns variable references collected
		from HLIL. The two can be different in several cases, e.g., multiple variables in MLIL can be merged
		into a single variable in HLIL.

		:param int addr: virtual address to query for variable references
		:param int length: optional length of query
		:param Architecture arch: optional architecture of query
		:return: list of variable reference sources
		:rtype: list(VariableReferenceSource)
		"""
		result = []
		count = ctypes.c_ulonglong(0)

		if arch is None:
			arch = self.arch

		if length is None:
			refs = core.BNGetMediumLevelILVariableReferencesFrom(self.handle, arch.handle, addr, count)
			assert refs is not None, "core.BNGetMediumLevelILVariableReferencesFrom returned None"
		else:
			refs = core.BNGetMediumLevelILVariableReferencesInRange(self.handle, arch.handle, addr, length, count)
			assert refs is not None, "core.BNGetMediumLevelILVariableReferencesInRange returned None"
		for i in range(0, count.value):
			var = variable.Variable.from_BNVariable(self, refs[i].var)
			if refs[i].source.func:
				func = Function(self.view, core.BNNewFunctionReference(refs[i].source.func))
			else:
				func = None
			if refs[i].source.arch:
				_arch = architecture.CoreArchitecture._from_cache(refs[i].source.arch)
			else:
				_arch = arch

			src = ILReferenceSource(func, _arch, refs[i].source.addr, refs[i].source.type, refs[i].source.exprId)
			result.append(VariableReferenceSource(var, src))
		core.BNFreeVariableReferenceSourceList(refs, count.value)
		return result

	def get_hlil_var_refs(self, var: 'variable.Variable') -> List[ILReferenceSource]:
		"""
		``get_hlil_var_refs`` returns a list of ILReferenceSource objects (IL xrefs or cross-references)
		that reference the given variable. The variable is a local variable that can be either on the stack,
		in a register, or in a flag.

		:param Variable var: Variable for which to query the xref
		:return: List of IL References for the given variable
		:rtype: list(ILReferenceSource)
		:Example:

			>>> mlil_var = current_hlil[0].operands[0]
			>>> current_function.get_hlil_var_refs(mlil_var)
		"""
		count = ctypes.c_ulonglong(0)
		refs = core.BNGetHighLevelILVariableReferences(self.handle, var.to_BNVariable(), count)
		assert refs is not None, "core.BNGetHighLevelILVariableReferences returned None"
		result = []
		for i in range(0, count.value):
			if refs[i].func:
				func = Function(self.view, core.BNNewFunctionReference(refs[i].func))
			else:
				func = None
			if refs[i].arch:
				arch = architecture.CoreArchitecture._from_cache(refs[i].arch)
			else:
				arch = None
			result.append(ILReferenceSource(func, arch, refs[i].addr, refs[i].type, refs[i].exprId))
		core.BNFreeILReferences(refs, count.value)
		return result

	def get_hlil_var_refs_from(self, addr: int, length: Optional[int] = None,
	                           arch: Optional['architecture.Architecture'] = None) -> List[VariableReferenceSource]:
		"""
		``get_hlil_var_refs_from`` returns a list of variables referenced by code in the function ``func``,
		of the architecture ``arch``, and at the address ``addr``. If no function is specified, references from
		all functions and containing the address will be returned. If no architecture is specified, the
		architecture of the function will be used.

		:param int addr: virtual address to query for variable references
		:param int length: optional length of query
		:param Architecture arch: optional architecture of query
		:return: list of variables reference sources
		:rtype: list(VariableReferenceSource)
		"""
		result = []
		count = ctypes.c_ulonglong(0)
		if arch is None:
			arch = self.arch
		if length is None:
			refs = core.BNGetHighLevelILVariableReferencesFrom(self.handle, arch.handle, addr, count)
			assert refs is not None, "core.BNGetHighLevelILVariableReferencesFrom returned None"
		else:
			refs = core.BNGetHighLevelILVariableReferencesInRange(self.handle, arch.handle, addr, length, count)
			assert refs is not None, "core.BNGetHighLevelILVariableReferencesInRange returned None"
		for i in range(0, count.value):
			var = variable.Variable.from_BNVariable(self, refs[i].var)
			if refs[i].source.func:
				func = Function(self.view, core.BNNewFunctionReference(refs[i].source.func))
			else:
				func = None
			if refs[i].source.arch:
				_arch = architecture.CoreArchitecture._from_cache(refs[i].source.arch)
			else:
				_arch = arch

			src = ILReferenceSource(func, _arch, refs[i].source.addr, refs[i].source.type, refs[i].source.exprId)
			result.append(VariableReferenceSource(var, src))
		core.BNFreeVariableReferenceSourceList(refs, count.value)
		return result

	def get_instruction_containing_address(self, addr: int,
	                                       arch: Optional['architecture.Architecture'] = None) -> Optional[int]:
		if arch is None:
			arch = self.arch

		start = ctypes.c_ulonglong()
		if core.BNGetInstructionContainingAddress(self.handle, arch.handle, addr, start):
			return start.value
		return None

	def merge_vars(
	    self, target: 'variable.Variable', sources: Union[List['variable.Variable'], 'variable.Variable']
	) -> None:
		"""
		``merge_vars`` merges one or more variables in ``sources`` into the ``target`` variable. All
		variable accesses to the variables in ``sources`` will be rewritten to use ``target``.

		:param Variable target: target variable
		:param list(Variable) sources: list of source variables
		"""
		if isinstance(sources, variable.Variable):
			sources = [sources]
		source_list = (core.BNVariable * len(sources))()
		for i in range(0, len(sources)):
			source_list[i].type = sources[i].source_type
			source_list[i].index = sources[i].index
			source_list[i].storage = sources[i].storage
		core.BNMergeVariables(self.handle, target.to_BNVariable(), source_list, len(sources))

	def unmerge_vars(
	    self, target: 'variable.Variable', sources: Union[List['variable.Variable'], 'variable.Variable']
	) -> None:
		"""
		``unmerge_vars`` undoes variable merging performed with ``merge_vars``. The variables in
		``sources`` will no longer be merged into the ``target`` variable.

		:param Variable target: target variable
		:param list(Variable) sources: list of source variables
		"""
		if isinstance(sources, variable.Variable):
			sources = [sources]
		source_list = (core.BNVariable * len(sources))()
		for i in range(0, len(sources)):
			source_list[i].type = sources[i].source_type
			source_list[i].index = sources[i].index
			source_list[i].storage = sources[i].storage
		core.BNUnmergeVariables(self.handle, target.to_BNVariable(), source_list, len(sources))

	def split_var(self, var: 'variable.Variable') -> None:
		"""
		``split_var`` splits a variable at the definition site. The given ``var`` must be the
		variable unique to the definition and should be obtained by using
		``MediumLevelILInstruction.get_split_var_for_definition`` at the definition site.

		This function is not meant to split variables that have been previously merged. Use
		``unmerge_vars`` to split previously merged variables.

		.. warning:: Binary Ninja automatically splits all variables that the analysis determines \
		to be safely splittable. Splitting a variable manually with ``split_var`` can cause \
		IL and decompilation to be incorrect. There are some patterns where variables can be safely \
		split semantically but analysis cannot determine that it is safe. This function is provided \
		to allow variable splitting to be performed in these cases by plugins or by the user.

		:param Variable var: variable to split
		"""
		core.BNSplitVariable(self.handle, var.to_BNVariable())

	def unsplit_var(self, var: 'variable.Variable') -> None:
		"""
		``unsplit_var`` undoes variable splitting performed with ``split_var``. The given ``var``
		must be the variable unique to the definition and should be obtained by using
		``MediumLevelILInstruction.get_split_var_for_definition`` at the definition site.

		:param Variable var: variable to unsplit
		"""
		core.BNUnsplitVariable(self.handle, var.to_BNVariable())

	def set_auto_inline_during_analysis(self, value: Union[bool, 'types.BoolWithConfidence']):
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if isinstance(value, types.BoolWithConfidence):
			bc.confidence = value.confidence
		else:
			bc.confidence = core.max_confidence
		core.BNSetAutoFunctionInlinedDuringAnalysis(self.handle, bc)

	def set_user_inline_during_analysis(self, value: Union[bool, 'types.BoolWithConfidence']):
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if isinstance(value, types.BoolWithConfidence):
			bc.confidence = value.confidence
		else:
			bc.confidence = core.max_confidence
		core.BNSetUserFunctionInlinedDuringAnalysis(self.handle, bc)


class AdvancedFunctionAnalysisDataRequestor:
	def __init__(self, func: Optional['Function'] = None):
		self._function = func
		if self._function is not None:
			self._function.request_advanced_analysis_data()

	def __del__(self):
		if self._function is not None:
			self._function.release_advanced_analysis_data()

	@property
	def function(self) -> Optional['Function']:
		return self._function

	@function.setter
	def function(self, func: 'Function') -> None:
		if self._function is not None:
			self._function.release_advanced_analysis_data()
		self._function = func
		if self._function is not None:
			self._function.request_advanced_analysis_data()

	def close(self) -> None:
		if self._function is not None:
			self._function.release_advanced_analysis_data()
		self._function = None


@dataclass
class DisassemblyTextLineTypeInfo:
	parent_type: Optional['types.Type']
	field_index: int
	offset: int


@dataclass
class DisassemblyTextLine:
	tokens: List['InstructionTextToken']
	highlight: '_highlight.HighlightColor'
	address: Optional[int]
	il_instruction: Optional[ILInstructionType]
	tags: List['binaryview.Tag']
	type_info: Optional[DisassemblyTextLineTypeInfo]

	def __init__(
			self,
			tokens: List['InstructionTextToken'],
			address: Optional[int] = None,
			il_instr: Optional[ILInstructionType] = None,
			color: Optional[Union['_highlight.HighlightColor', HighlightStandardColor]] = None,
			tags: Optional[List['binaryview.Tag']] = None,
			type_info: Optional[DisassemblyTextLineTypeInfo] = None,
	):
		self.address = address
		self.tokens = tokens
		self.il_instruction = il_instr
		self.address = address
		if color is None:
			self.highlight = _highlight.HighlightColor()
		else:
			if not isinstance(color, HighlightStandardColor) and not isinstance(color, _highlight.HighlightColor):
				raise ValueError("Specified color is not one of HighlightStandardColor, _highlight.HighlightColor")
			if isinstance(color, HighlightStandardColor):
				self.highlight = _highlight.HighlightColor(color)
			else:
				self.highlight = color
		if tags is None:
			tags = []
		self.tags = tags
		self.type_info = type_info

	def __str__(self):
		return "".join(map(str, self.tokens))

	def __repr__(self):
		if self.address is None:
			return f"<disassemblyTextLine {self}>"
		return f"<disassemblyTextLine {self.address:#x}: {self}>"

	@property
	def total_width(self):
		return sum(token.width for token in self.tokens)

	def _find_address_and_indentation_tokens(self, callback):
		start_token = 0
		for i in range(len(self.tokens)):
			if self.tokens[i].type == InstructionTextTokenType.AddressSeparatorToken:
				start_token = i + 1
				break

		for token in self.tokens[:start_token]:
			callback(token)

		for token in self.tokens[start_token:]:
			if token.type in [InstructionTextTokenType.AddressDisplayToken,
							  InstructionTextTokenType.AddressSeparatorToken,
							  InstructionTextTokenType.CollapseStateIndicatorToken]:
				callback(token)
				continue
			if len(token.text) != 0 and not token.text.isspace():
				break
			callback(token)

	@property
	def address_and_indentation_width(self):
		result = 0

		def sum_width(token):
			nonlocal result
			result += token.width

		self._find_address_and_indentation_tokens(sum_width)
		return result

	@property
	def address_and_indentation_tokens(self):
		result = []

		def collect_tokens(token):
			nonlocal result
			result.append(token)

		self._find_address_and_indentation_tokens(collect_tokens)
		return result

	@classmethod
	def _from_core_struct(cls, struct: core.BNDisassemblyTextLine, il_func: Optional['ILFunctionType'] = None):
		il_instr = None
		if il_func is not None and struct.instrIndex < len(il_func):
			try:
				il_instr = il_func[struct.instrIndex]
			except:
				il_instr = None
		tokens = InstructionTextToken._from_core_struct(struct.tokens, struct.count)

		tags = []
		for i in range(struct.tagCount):
			tags.append(binaryview.Tag(handle=core.BNNewTagReference(struct.tags[i])))

		type_info = None
		if struct.typeInfo.hasTypeInfo:
			parent_type = None
			if struct.typeInfo.parentType:
				parent_type = types.Type.create(core.BNNewTypeReference(struct.typeInfo.parentType))
			type_info = DisassemblyTextLineTypeInfo(
				parent_type=parent_type,
				field_index=struct.typeInfo.fieldIndex,
				offset=struct.typeInfo.offset
			)

		return DisassemblyTextLine(
			tokens,
			struct.addr,
			il_instr,
			_highlight.HighlightColor._from_core_struct(struct.highlight),
			tags,
			type_info
		)

	def _to_core_struct(self) -> core.BNDisassemblyTextLine:
		result = core.BNDisassemblyTextLine()
		result.addr = self.address
		if self.il_instruction is not None:
			result.instrIndex = self.il_instruction.instr_index
		else:
			result.instrIndex = 0xffffffffffffffff
		result.tokens = InstructionTextToken._get_core_struct(self.tokens)
		result.count = len(self.tokens)
		result.highlight = self.highlight._to_core_struct()
		result.tagCount = len(self.tags)
		result.tags = (ctypes.POINTER(core.BNTag) * len(self.tags))()
		for i, tag in enumerate(self.tags):
			result.tags[i] = tag.handle
		if self.type_info is None:
			result.typeInfo.hasTypeInfo = False
		else:
			result.typeInfo.hasTypeInfo = True
			if self.type_info.parent_type is not None:
				result.typeInfo.parentType = self.type_info.parent_type.handle
			result.typeInfo.fieldIndex = self.type_info.field_index
			result.typeInfo.offset = self.type_info.offset
		return result


class DisassemblyTextRenderer:
	def __init__(
	    self, func: Optional[AnyFunctionType] = None, settings: Optional['DisassemblySettings'] = None,
	    handle: Optional[core.BNDisassemblySettings] = None
	):
		if handle is None:
			if func is None:
				raise ValueError("function required for disassembly")
			settings_obj = None
			if settings is not None:
				settings_obj = settings.handle
			if isinstance(func, Function):
				self.handle = core.BNCreateDisassemblyTextRenderer(func.handle, settings_obj)
			elif isinstance(func, lowlevelil.LowLevelILFunction):
				self.handle = core.BNCreateLowLevelILDisassemblyTextRenderer(func.handle, settings_obj)
			elif isinstance(func, mediumlevelil.MediumLevelILFunction):
				self.handle = core.BNCreateMediumLevelILDisassemblyTextRenderer(func.handle, settings_obj)
			elif isinstance(func, highlevelil.HighLevelILFunction):
				self.handle = core.BNCreateHighLevelILDisassemblyTextRenderer(func.handle, settings_obj)
			else:
				raise TypeError("invalid function object")
		else:
			self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeDisassemblyTextRenderer(self.handle)

	@property
	def function(self) -> 'Function':
		return Function(handle=core.BNGetDisassemblyTextRendererFunction(self.handle))

	@property
	def il_function(self) -> Optional[ILFunctionType]:
		llil = core.BNGetDisassemblyTextRendererLowLevelILFunction(self.handle)
		if llil:
			return lowlevelil.LowLevelILFunction(handle=llil)
		mlil = core.BNGetDisassemblyTextRendererMediumLevelILFunction(self.handle)
		if mlil:
			return mediumlevelil.MediumLevelILFunction(handle=mlil)
		hlil = core.BNGetDisassemblyTextRendererHighLevelILFunction(self.handle)
		if hlil:
			return highlevelil.HighLevelILFunction(handle=hlil)
		return None

	@property
	def basic_block(self) -> Optional['basicblock.BasicBlock']:
		result = core.BNGetDisassemblyTextRendererBasicBlock(self.handle)
		if result:
			return basicblock.BasicBlock._from_core_block(handle=result)
		return None

	@basic_block.setter
	def basic_block(self, block: Optional['basicblock.BasicBlock']) -> None:
		if block is not None:
			core.BNSetDisassemblyTextRendererBasicBlock(self.handle, block.handle)
		else:
			core.BNSetDisassemblyTextRendererBasicBlock(self.handle, None)

	@property
	def arch(self) -> 'architecture.Architecture':
		return architecture.CoreArchitecture._from_cache(
		    handle=core.BNGetDisassemblyTextRendererArchitecture(self.handle)
		)

	@arch.setter
	def arch(self, arch: 'architecture.Architecture') -> None:
		core.BNSetDisassemblyTextRendererArchitecture(self.handle, arch.handle)

	@property
	def settings(self) -> 'DisassemblySettings':
		return DisassemblySettings(handle=core.BNGetDisassemblyTextRendererSettings(self.handle))

	@settings.setter
	def settings(self, settings: Optional['DisassemblySettings']) -> None:
		if settings is not None:
			core.BNSetDisassemblyTextRendererSettings(self.handle, settings.handle)
		else:
			core.BNSetDisassemblyTextRendererSettings(self.handle, None)

	@property
	def il(self) -> bool:
		return core.BNIsILDisassemblyTextRenderer(self.handle)

	@property
	def has_data_flow(self) -> bool:
		return core.BNDisassemblyTextRendererHasDataFlow(self.handle)

	def get_instruction_annotations(self, addr: int) -> List['InstructionTextToken']:
		count = ctypes.c_ulonglong()
		tokens = core.BNGetDisassemblyTextRendererInstructionAnnotations(self.handle, addr, count)
		assert tokens is not None, "core.BNGetDisassemblyTextRendererInstructionAnnotations returned None"
		result = InstructionTextToken._from_core_struct(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	def get_instruction_text(self, addr: int) -> Generator[Tuple[Optional['DisassemblyTextLine'], int], None, None]:
		count = ctypes.c_ulonglong()
		length = ctypes.c_ulonglong()
		lines = ctypes.POINTER(core.BNDisassemblyTextLine)()
		if not core.BNGetDisassemblyTextRendererInstructionText(self.handle, addr, length, lines, count):
			yield None, 0
			return
		il_function = self.il_function
		try:
			for i in range(0, count.value):
				addr = lines[i].addr
				if (lines[i].instrIndex != 0xffffffffffffffff) and (il_function is not None):
					il_instr = il_function[lines[i].instrIndex]
				else:
					il_instr = None
				color = _highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				yield DisassemblyTextLine(tokens, addr, il_instr, color), length.value
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)

	def get_disassembly_text(self, addr: int) -> Generator[Tuple[Optional['DisassemblyTextLine'], int], None, None]:
		count = ctypes.c_ulonglong()
		length = ctypes.c_ulonglong()
		length.value = 0
		lines = ctypes.POINTER(core.BNDisassemblyTextLine)()
		ok = core.BNGetDisassemblyTextRendererLines(self.handle, addr, length, lines, count)
		if not ok:
			yield None, 0
			return
		il_function = self.il_function
		try:
			for i in range(0, count.value):
				addr = lines[i].addr
				if (lines[i].instrIndex != 0xffffffffffffffff) and (il_function is not None):
					il_instr = il_function[lines[i].instrIndex]
				else:
					il_instr = None
				color = _highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				yield DisassemblyTextLine(tokens, addr, il_instr, color), length.value
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)

	def post_process_lines(
	    self, addr: int, length: int, in_lines: Union[str, List[str], List['DisassemblyTextLine']],
	    indent_spaces: str = ''
	):
		if isinstance(in_lines, str):
			in_lines = in_lines.split('\n')
		line_buf = (core.BNDisassemblyTextLine * len(in_lines))()
		for i, line in enumerate(in_lines):
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
			if not isinstance(color, HighlightStandardColor) and not isinstance(color, _highlight.HighlightColor):
				raise ValueError("Specified color is not one of HighlightStandardColor, _highlight.HighlightColor")
			if isinstance(color, HighlightStandardColor):
				color = _highlight.HighlightColor(color)
			line_buf[i].highlight = color._to_core_struct()
			line_buf[i].count = len(line.tokens)
			line_buf[i].tokens = InstructionTextToken._get_core_struct(line.tokens)
		count = ctypes.c_ulonglong()
		lines = core.BNPostProcessDisassemblyTextRendererLines(
		    self.handle, addr, length, line_buf, len(in_lines), count, indent_spaces
		)
		assert lines is not None, "core.BNPostProcessDisassemblyTextRendererLines returned None"
		il_function = self.il_function
		try:
			for i in range(count.value):
				addr = lines[i].addr
				if (lines[i].instrIndex != 0xffffffffffffffff) and (il_function is not None):
					il_instr = il_function[lines[i].instrIndex]
				else:
					il_instr = None
				color = _highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				yield DisassemblyTextLine(tokens, addr, il_instr, color)
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)

	def reset_deduplicated_comments(self) -> None:
		core.BNResetDisassemblyTextRendererDeduplicatedComments(self.handle)

	def add_symbol_token(self, tokens: List['InstructionTextToken'], addr: int, size: int, operand: Optional[int] = None) -> bool:
		if operand is None:
			operand = 0xffffffff
		count = ctypes.c_ulonglong()
		new_tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		if not core.BNGetDisassemblyTextRendererSymbolTokens(self.handle, addr, size, operand, new_tokens, count):
			return False
		assert new_tokens is not None
		result = InstructionTextToken._from_core_struct(new_tokens, count.value)
		tokens += result
		core.BNFreeInstructionText(new_tokens, count.value)
		return True

	def add_stack_var_reference_tokens(
	    self, tokens: List['InstructionTextToken'], ref: 'variable.StackVariableReference'
	) -> None:
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
		assert new_tokens is not None
		result = InstructionTextToken._from_core_struct(new_tokens, count.value)
		tokens += result
		core.BNFreeInstructionText(new_tokens, count.value)

	@staticmethod
	def is_integer_token(token: 'InstructionTextToken') -> bool:
		return core.BNIsIntegerToken(token.type)

	def add_integer_token(
	    self, tokens: List['InstructionTextToken'], int_token: 'InstructionTextToken', addr: int,
	    arch: Optional['architecture.Architecture'] = None
	) -> None:
		if arch is not None:
			arch = arch.handle
		in_token_obj = InstructionTextToken._get_core_struct([int_token])
		count = ctypes.c_ulonglong()
		new_tokens = core.BNGetDisassemblyTextRendererIntegerTokens(self.handle, in_token_obj, arch, addr, count)
		assert new_tokens is not None
		result = InstructionTextToken._from_core_struct(new_tokens, count.value)
		tokens += result
		core.BNFreeInstructionText(new_tokens, count.value)

	def wrap_comment(
	    self, lines: List['DisassemblyTextLine'], cur_line: 'DisassemblyTextLine', comment: str,
	    has_auto_annotations: bool, leading_spaces: str = "  ", indent_spaces: str = ""
	) -> None:
		cur_line_obj = core.BNDisassemblyTextLine()
		cur_line_obj.addr = cur_line.address
		if cur_line.il_instruction is None:
			cur_line_obj.instrIndex = 0xffffffffffffffff
		else:
			cur_line_obj.instrIndex = cur_line.il_instruction.instr_index
		cur_line_obj.highlight = cur_line.highlight._to_core_struct()
		cur_line_obj.tokens = InstructionTextToken._get_core_struct(cur_line.tokens)
		cur_line_obj.count = len(cur_line.tokens)
		count = ctypes.c_ulonglong()
		new_lines = core.BNDisassemblyTextRendererWrapComment(
		    self.handle, cur_line_obj, count, comment, has_auto_annotations, leading_spaces, indent_spaces
		)
		assert new_lines is not None, "core.BNDisassemblyTextRendererWrapComment returned None"
		il_function = self.il_function
		for i in range(0, count.value):
			addr = new_lines[i].addr
			if (new_lines[i].instrIndex != 0xffffffffffffffff) and (il_function is not None):
				il_instr = il_function[new_lines[i].instrIndex]
			else:
				il_instr = None
			color = _highlight.HighlightColor._from_core_struct(new_lines[i].highlight)
			tokens = InstructionTextToken._from_core_struct(new_lines[i].tokens, new_lines[i].count)
			lines.append(DisassemblyTextLine(tokens, addr, il_instr, color))
		core.BNFreeDisassemblyTextLines(new_lines, count.value)
