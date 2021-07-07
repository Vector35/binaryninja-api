# Copyright (c) 2015-2021 Vector 35 Inc
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
from typing import Generator, List, Union, Mapping, Tuple, Optional
from dataclasses import dataclass, field
import uuid
from abc import ABC, abstractmethod

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import (StructureVariant, SymbolType, SymbolBinding, TypeClass,
	NamedTypeReferenceClass, ReferenceType, VariableSourceType, TypeReferenceType, MemberAccess, MemberScope)
from . import callingconvention
from . import function as _function
from . import variable
from . import architecture
from . import types
from . import binaryview
from . import platform as _platform
from . import log
from . import typelibrary

QualifiedNameType = Union[List[str], str, 'QualifiedName', List[bytes]]
BoolWithConfidenceType = Union[bool, 'BoolWithConfidence']
SizeWithConfidenceType = Union[int, 'SizeWithConfidence']
OffsetWithConfidenceType = Union[int, 'OffsetWithConfidence']
ParamsType = Union[List['Type'], List['FunctionParameter'], List[Tuple['Type', str]]]
MembersType = Union[List['StructureMember'], List[Tuple['Type', str]]]
EnumMembersType = Union[List[Tuple[str,int]], List[str], List['EnumerationMember']]
SomeType = Union['MutableType', 'Type']
TypeContainer = Union['binaryview.BinaryView', 'typelibrary.TypeLibrary']
# The following are needed to prevent the type checker from getting
# confused as we have member functions in `Type` named the same thing
_int = int
_bool = bool
MemberName = str
MemberIndex = int
MemberOffset = int

class TypeCreateException(ValueError):
	pass

class QualifiedName:
	def __init__(self, name:QualifiedNameType=[]):
		self._name:List[str] = []
		if isinstance(name, str):
			self._name = [name]
		elif isinstance(name, self.__class__):
			self._name = name._name
		elif isinstance(name, list):
			for i in name:
				if isinstance(i, bytes):
					self._name.append(i.decode("utf-8"))
				else:
					self._name.append(str(i))

	def __str__(self):
		return "::".join(self.name)

	def __repr__(self):
		return repr(str(self))

	def __len__(self):
		return len(self.name)

	def __eq__(self, other):
		if isinstance(other, str):
			return str(self) == other
		elif isinstance(other, list):
			return self.name == other
		elif isinstance(other, self.__class__):
			return self.name == other.name
		return NotImplemented

	def __ne__(self, other):
		if isinstance(other, str):
			return str(self) != other
		elif isinstance(other, list):
			return self.name != other
		elif isinstance(other, self.__class__):
			return self.name != other.name
		return NotImplemented

	def __lt__(self, other):
		if isinstance(other, self.__class__):
			return self.name < other.name
		return NotImplemented

	def __le__(self, other):
		if isinstance(other, self.__class__):
			return self.name <= other.name
		return NotImplemented

	def __gt__(self, other):
		if isinstance(other, self.__class__):
			return self.name > other.name
		return NotImplemented

	def __ge__(self, other):
		if isinstance(other, self.__class__):
			return self.name >= other.name
		return NotImplemented

	def __cmp__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented

		if self == other:
			return 0
		if self < other:
			return -1
		return 1

	def __hash__(self):
		return hash(str(self))

	def __getitem__(self, key):
		return self.name[key]

	def __iter__(self):
		return iter(self.name)

	def _get_core_struct(self):
		result = core.BNQualifiedName()
		name_list = (ctypes.c_char_p * len(self.name))()
		for i in range(0, len(self.name)):
			name_list[i] = self.name[i].encode("utf-8")
		result.name = name_list
		result.nameCount = len(self.name)
		return result

	@staticmethod
	def _from_core_struct(name):
		result = []
		for i in range(0, name.nameCount):
			result.append(name.name[i].decode("utf-8"))
		return QualifiedName(result)

	@property
	def name(self) -> List[str]:
		return self._name

	@name.setter
	def name(self, value:List[str]) -> None:
		self._name = value


@dataclass(frozen=True)
class TypeReferenceSource:
	name:QualifiedName
	offset:int
	ref_type:TypeReferenceType

	def __repr__(self):
		if self.ref_type == TypeReferenceType.DirectTypeReferenceType:
			s = 'direct'
		elif self.ref_type == TypeReferenceType.IndirectTypeReferenceType:
			s = 'indirect'
		else:
			s = 'unknown'
		return '<type %s, offset 0x%x, %s>' % (self.name, self.offset, s)


class NameSpace(QualifiedName):
	def __str__(self):
		return ":".join(self.name)

	def _get_core_struct(self):
		result = core.BNNameSpace()
		name_list = (ctypes.c_char_p * len(self.name))()
		for i in range(0, len(self.name)):
			name_list[i] = self.name[i].encode('charmap')
		result.name = name_list
		result.nameCount = len(self.name)
		return result

	@staticmethod
	def _from_core_struct(name):
		result = []
		for i in range(0, name.nameCount):
			result.append(name.name[i].decode("utf-8"))
		return NameSpace(result)


class Symbol:
	"""
	Symbols are defined as one of the following types:

		=========================== ==============================================================
		SymbolType                  Description
		=========================== ==============================================================
		FunctionSymbol              Symbol for function that exists in the current binary
		ImportAddressSymbol         Symbol defined in the Import Address Table
		ImportedFunctionSymbol      Symbol for a function that is not defined in the current binary
		DataSymbol                  Symbol for data in the current binary
		ImportedDataSymbol          Symbol for data that is not defined in the current binary
		ExternalSymbol              Symbols for data and code that reside outside the BinaryView
		LibraryFunctionSymbol       Symbols for external functions outside the library
		=========================== ==============================================================
	"""
	def __init__(self, sym_type, addr, short_name, full_name=None, raw_name=None, handle=None, binding=None, namespace=None, ordinal=0):
		if handle is not None:
			SymbolPointer = ctypes.POINTER(core.BNSymbol)
			_handle = ctypes.cast(handle, SymbolPointer)
		else:
			if isinstance(sym_type, str):
				sym_type = SymbolType[sym_type]
			if full_name is None:
				full_name = short_name
			if raw_name is None:
				raw_name = full_name
			if binding is None:
				binding = SymbolBinding.NoBinding
			if isinstance(namespace, str):
				namespace = NameSpace(namespace)
			if isinstance(namespace, NameSpace):
				namespace = namespace._get_core_struct()
			_handle = core.BNCreateSymbol(sym_type, short_name, full_name, raw_name, addr, binding, namespace, ordinal)
		assert _handle is not None
		self.handle = _handle

	def __del__(self):
		if core is not None:
			core.BNFreeSymbol(self.handle)

	def __repr__(self):
		return "<%s: \"%s\" @ %#x>" % (self.type, self.full_name, self.address)

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

	@property
	def type(self):
		"""Symbol type (read-only)"""
		return SymbolType(core.BNGetSymbolType(self.handle))

	@property
	def binding(self):
		"""Symbol binding (read-only)"""
		return SymbolBinding(core.BNGetSymbolBinding(self.handle))

	@property
	def namespace(self):
		"""Symbol namespace (read-only)"""
		ns = core.BNGetSymbolNameSpace(self.handle)
		result = NameSpace._from_core_struct(ns)
		core.BNFreeNameSpace(ns)
		return result

	@property
	def name(self):
		"""Symbol name (read-only)"""
		return core.BNGetSymbolRawName(self.handle)

	@property
	def short_name(self):
		"""Symbol short name (read-only)"""
		return core.BNGetSymbolShortName(self.handle)

	@property
	def full_name(self):
		"""Symbol full name (read-only)"""
		return core.BNGetSymbolFullName(self.handle)

	@property
	def raw_name(self):
		"""Symbol raw name (read-only)"""
		return core.BNGetSymbolRawName(self.handle)

	@property
	def address(self):
		"""Symbol address (read-only)"""
		return core.BNGetSymbolAddress(self.handle)

	@property
	def ordinal(self):
		"""Symbol ordinal (read-only)"""
		return core.BNGetSymbolOrdinal(self.handle)

	@property
	def auto(self):
		return core.BNIsSymbolAutoDefined(self.handle)


@dataclass
class FunctionParameter:
	type:SomeType
	name:str = ""
	location:Optional['variable.VariableNameAndType'] = None

	def __repr__(self):
		if (self.location is not None) and (self.location.name != self.name):
			return "%s %s%s @ %s" % (self.type.immutable_copy().get_string_before_name(), self.name, self.type.immutable_copy().get_string_after_name(), self.location.name)
		return "%s %s%s" % (self.type.immutable_copy().get_string_before_name(), self.name, self.type.immutable_copy().get_string_after_name())

	def immutable_copy(self) -> 'FunctionParameter':
		return FunctionParameter(self.type.immutable_copy(), self.name, self.location)

	def mutable_copy(self) -> 'FunctionParameter':
		return FunctionParameter(self.type.mutable_copy(), self.name, self.location)


@dataclass(frozen=True)
class OffsetWithConfidence:
	value:int
	confidence:int=core.max_confidence

	def __int__(self):
		return self.value

	def to_core_struct(self) -> core.BNOffsetWithConfidence:
		result = core.BNOffsetWithConfidence()
		result.value = self.value
		result.confidence = self.confidence
		return result

	@classmethod
	def from_core_struct(cls, core_struct:core.BNOffsetWithConfidence) -> 'OffsetWithConfidence':
		return cls(core_struct.value, core_struct.confidence)


@dataclass(frozen=True)
class BoolWithConfidence:
	value:bool
	confidence:int=core.max_confidence

	def __bool__(self):
		return self.value

	def to_core_struct(self) -> core.BNBoolWithConfidence:
		result = core.BNBoolWithConfidence()
		result.value = self.value
		result.confidence = self.confidence
		return result

	@classmethod
	def from_core_struct(cls, core_struct:core.BNBoolWithConfidence) -> 'BoolWithConfidence':
		return cls(core_struct.value, core_struct.confidence)


@dataclass(frozen=True)
class MemberAccessWithConfidence:
	value:MemberAccess
	confidence:int=core.max_confidence

	def to_core_struct(self) -> core.BNMemberAccessWithConfidence:
		result = core.BNMemberAccessWithConfidence()
		result.value = self.value
		result.confidence = self.confidence
		return result

	@classmethod
	def from_core_struct(cls, core_struct:core.BNMemberAccessWithConfidence) -> 'MemberAccessWithConfidence':
		return cls(core_struct.value, core_struct.confidence)


@dataclass(frozen=True)
class MemberScopeWithConfidence:
	value:MemberScope
	confidence:int=core.max_confidence

	def to_core_struct(self) -> core.BNMemberScopeWithConfidence:
		result = core.BNMemberScopeWithConfidence()
		result.value = self.value
		result.confidence = self.confidence
		return result

	@classmethod
	def from_core_struct(cls, core_struct:core.BNMemberScopeWithConfidence) -> 'MemberScopeWithConfidence':
		return cls(core_struct.value, core_struct.confidence)


@dataclass(frozen=True)
class SizeWithConfidence:
	value:int
	confidence:int=core.max_confidence

	def __int__(self):
		return self.value

	def to_core_struct(self) -> core.BNSizeWithConfidence:
		result = core.BNSizeWithConfidence()
		result.value = self.value
		result.confidence = self.confidence
		return result

	@classmethod
	def from_core_struct(cls, core_struct:core.BNSizeWithConfidence) -> 'SizeWithConfidence':
		return cls(core_struct.value, core_struct.confidence)


class _TypeBuilder:
	def __init__(self, handle, **kwargs):
		assert isinstance(handle.contents, core.BNTypeBuilder), "Attempting to create mutable Type"
		self.handle = handle
		core.BNTypeBuilderSetConst(self.handle, kwargs.get("const", BoolWithConfidence(False)).to_core_struct())
		core.BNTypeBuilderSetVolatile(self.handle, kwargs.get("volatile", BoolWithConfidence(False)).to_core_struct())
		core.BNSetFunctionTypeBuilderCanReturn(self.handle, kwargs.get("can_return", BoolWithConfidence(False).to_core_struct()))
		core.BNTypeBuilderSetMemberScope(self.handle, kwargs.get("member_scope", MemberScopeWithConfidence(MemberScope.NoScope).to_core_struct()))
		core.BNTypeBuilderSetMemberAccess(self.handle, kwargs.get("member_access", MemberAccessWithConfidence(MemberAccess.NoAccess).to_core_struct()))

	def finalize(self):
		type_handle = core.BNFinalizeTypeBuilder(self.handle)
		assert type_handle is not None, "core.BNFinalizeTypeBuilder returned None"
		return type_handle

	@property
	def const(self) -> BoolWithConfidence:
		"""Whether type is const (read/write)"""
		result = core.BNIsTypeBuilderConst(self.handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@const.setter
	def const(self, value:BoolWithConfidence) -> None:
		core.BNTypeBuilderSetConst(self.handle, value.to_core_struct())

	@property
	def volatile(self) -> BoolWithConfidence:
		"""Whether type is volatile (read/write)"""
		result = core.BNIsTypeBuilderVolatile(self.handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@volatile.setter
	def volatile(self, value:BoolWithConfidence) -> None:
		core.BNTypeBuilderSetVolatile(self.handle, value.to_core_struct())

	@property
	def can_return(self):
		core.BNFunctionTypeBuilderCanReturn(self.handle)

	@can_return.setter
	def can_return(self, value):
		core.BNSetFunctionTypeBuilderCanReturn(self.handle, value)

	@property
	def member_scope(self):
		core.BNTypeBuilderGetMemberScope(self.handle)

	@member_scope.setter
	def member_scope(self, value):
		core.BNTypeBuilderSetMemberScope(self.handle, value)

	@property
	def member_access(self):
		core.BNTypeBuilderGetMemberAccess(self.handle)

	@member_access.setter
	def member_access(self, value):
		core.BNTypeBuilderSetMemberAccess(self.handle, value)


class Type:
	"""
	``class Type`` allows you to interact with the Binary Ninja type system. Note that the ``repr`` and ``str``
	handlers respond differently on type objects.

	Other related functions that may be helpful include:

	:py:meth:`parse_type_string <binaryninja.binaryview.BinaryView.parse_type_string>`
	:py:meth:`parse_types_from_source <binaryninja.platform.Platform.parse_types_from_source>`
	:py:meth:`parse_types_from_source_file <binaryninja.platform.Platform.parse_types_from_source_file>`

	"""
	def __init__(self, handle, platform:'_platform.Platform'=None, confidence:int=core.max_confidence):
		assert isinstance(handle.contents, core.BNType), "Attempting to create mutable Type"
		self._handle = handle
		self._confidence = confidence
		self._platform = platform

	@classmethod
	def create(cls, handle, platform:'_platform.Platform'=None, confidence:int=core.max_confidence):
		type_class = TypeClass(core.BNGetTypeClass(handle))
		try:
			return Types[type_class](handle, platform, confidence)
		except TypeError:
			assert False, f"{str(type_class)}"

	def __del__(self):
		if core is not None:
			core.BNFreeType(self._handle)

	def __repr__(self):
		if self._confidence < core.max_confidence:
			return f"<type: {self}, {self._confidence * 100 // core.max_confidence}% confidence>"
		return f"<type: {self}>"

	def __str__(self):
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		return core.BNGetTypeString(self._handle, platform)
		name = None
		if isinstance(self, RegisteredNameType):
			name = self.registered_name
		if (name is not None) and (not isinstance(self, (StructureType, EnumerationType))):
			return self.get_string_before_name() + " " + str(name.name) + self.get_string_after_name()

	def __len__(self):
		return self.width

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return core.BNTypesEqual(self.handle, other.handle)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return core.BNTypesNotEqual(self.handle, other.handle)

	@property
	def handle(self):
		return self._handle

	@property
	def type_class(self) -> TypeClass:
		"""Type class (read-only)"""
		return TypeClass(core.BNGetTypeClass(self._handle))

	@property
	def width(self) -> int:
		"""Type width (read-only)"""
		return core.BNGetTypeWidth(self._handle)

	@property
	def alignment(self) -> int:
		"""Type alignment (read-only)"""
		return core.BNGetTypeAlignment(self._handle)

	@property
	def offset(self) -> int:
		"""Offset into structure (read-only)"""
		return core.BNGetTypeOffset(self._handle)

	@property
	def altname(self) -> str:
		"""Alternative name for the type object"""
		return core.BNGetTypeAlternateName(self._handle)

	def to_core_struct(self) -> core.BNTypeWithConfidence:
		type_conf = core.BNTypeWithConfidence()
		type_conf.type = self.handle
		type_conf.confidence = self.confidence
		return type_conf

	def get_string_before_name(self) -> str:
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		return core.BNGetTypeStringBeforeName(self._handle, platform)

	def get_string_after_name(self) -> str:
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		return core.BNGetTypeStringAfterName(self._handle, platform)

	@property
	def tokens(self) -> List['_function.InstructionTextToken']:
		"""Type string as a list of tokens (read-only)"""
		return self.get_tokens()

	def get_tokens(self, base_confidence = core.max_confidence) -> List['_function.InstructionTextToken']:
		count = ctypes.c_ulonglong()
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		tokens = core.BNGetTypeTokens(self._handle, platform, base_confidence, count)
		assert tokens is not None, "core.BNGetTypeTokens returned None"

		result = _function.InstructionTextToken._from_core_struct(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	def get_tokens_before_name(self, base_confidence = core.max_confidence) -> List['_function.InstructionTextToken']:
		count = ctypes.c_ulonglong()
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		tokens = core.BNGetTypeTokensBeforeName(self._handle, platform, base_confidence, count)
		assert tokens is not None, "core.BNGetTypeTokensBeforeName returned None"
		result = _function.InstructionTextToken._from_core_struct(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	def get_tokens_after_name(self, base_confidence = core.max_confidence) -> List['_function.InstructionTextToken']:
		count = ctypes.c_ulonglong()
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		tokens = core.BNGetTypeTokensAfterName(self._handle, platform, base_confidence, count)
		assert tokens is not None, "core.BNGetTypeTokensAfterName returned None"
		result = _function.InstructionTextToken._from_core_struct(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	def with_confidence(self, confidence) -> 'Type':
		return Type.create(handle = core.BNNewTypeReference(self.handle), platform = self._platform, confidence = confidence)

	@property
	def confidence(self) -> _int:
		return self._confidence

	@confidence.setter
	def confidence(self, value:_int) -> None:
		self._confidence = value

	@property
	def platform(self) -> Optional['_platform.Platform']:
		return self._platform

	@platform.setter
	def platform(self, value:'_platform.Platform') -> None:
		self._platform = value

	@abstractmethod
	def create_mutable(self):
		raise NotImplementedError("No implementation for create_mutable on base class Type")

	def mutable_copy(self) -> 'MutableType':
		return self.create_mutable()

	def get_builder(self, bv:'binaryview.BinaryView') -> 'MutableTypeBuilder':
		t = Types[self.type_class](self._handle).create_mutable()
		return MutableTypeBuilder(t, bv, self.name, self.platform, self._confidence)

	@staticmethod
	def builder(bv:'binaryview.BinaryView', name:Optional[QualifiedName]=None, id:Optional[str]=None,
		platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'MutableTypeBuilder':
		if name is None and id is None:
			raise TypeCreateException("Must specify either a name or id to create a builder object")
		if name is None:
			t = bv.get_type_by_id(id)
			if t is None:
				raise TypeCreateException("failed to look up type by id")
			registered_name = t.registered_name
			if registered_name is None:
				raise TypeCreateException("Registered name for type is None")
			name = registered_name.name
			if name is None:
				raise TypeCreateException("Name for registered name is None")
		else:
			t = bv.get_type_by_name(name)
			if t is None:
				raise TypeCreateException("failed to look up type by name")
		return MutableTypeBuilder(t, bv, name, platform, confidence)

	def with_replaced_structure(self, from_struct, to_struct):
		return Type.create(handle = core.BNTypeWithReplacedStructure(self._handle, from_struct.handle, to_struct.handle))

	def with_replaced_enumeration(self, from_enum, to_enum):
		return Type.create(handle = core.BNTypeWithReplacedEnumeration(self._handle, from_enum.handle, to_enum.handle))

	def with_replaced_named_type_reference(self, from_ref, to_ref):
		return Type.create(handle = core.BNTypeWithReplacedNamedTypeReference(self._handle, from_ref.handle, to_ref.handle))

	@staticmethod
	def void():
		return VoidType.create()

	@staticmethod
	def bool():
		return BoolType.create()

	@staticmethod
	def char():
		return Type.int(1, True)

	@staticmethod
	def int(width:_int, sign:BoolWithConfidenceType=BoolWithConfidence(True), altname:str="") -> 'IntegerType':
		"""
		``int`` class method for creating an int Type.
		:param int width: width of the integer in bytes
		:param bool sign: optional variable representing signedness
		:param str altname: alternate name for type
		"""
		return IntegerType.create(width, sign, altname)

	@staticmethod
	def float(width:_int, altname:str="") -> 'FloatType':
		"""
		``float`` class method for creating floating point Types.
		:param int width: width of the floating point number in bytes
		:param str altname: alternate name for type
		"""
		return FloatType.create(width, altname)

	@staticmethod
	def wide_char(width:_int, altname:str="") -> 'WideCharType':
		"""
		``wide_char`` class method for creating wide char Types.
		:param int width: width of the wide character in bytes
		:param str altname: alternate name for type
		"""
		return WideCharType.create(width=width, altname=altname)

	@staticmethod
	def structure_type(s:'Structure'):
		return s.immutable_copy()

	@staticmethod
	def named_type(named_type:'NamedTypeReference') -> 'NamedTypeReferenceType':
		return named_type.immutable_copy()

	@staticmethod
	def named_type_from_type(name:QualifiedName, type:'Type') -> 'NamedTypeReferenceType':
		return NamedTypeReferenceType.create_from_type(name, type)

	@staticmethod
	def named_type_from_type_and_id(type_id:str, name:QualifiedName, type:'Type') -> 'NamedTypeReferenceType':
		return NamedTypeReferenceType.create_from_type(name, type, type_id)

	def generate_named_type_reference(self, guid:str, name:QualifiedName):
		return NamedTypeReferenceType.create(NamedTypeReferenceClass.TypedefNamedTypeClass, guid, name)

	@staticmethod
	def named_type_from_registered_type(view:'binaryview.BinaryView', name:QualifiedName) -> 'NamedTypeReferenceType':
		return NamedTypeReferenceType.create_from_registered_type(view, name)

	@staticmethod
	def enumeration_type(arch, e:'Enumeration', width:_int=None, sign:_bool=False) -> 'EnumerationType':
		return EnumerationType.create(arch, e.members, e.width, e.sign)

	@staticmethod
	def pointer(type:'Type', arch:'architecture.Architecture'=None,
		const:BoolWithConfidenceType=BoolWithConfidence(False),
		volatile:BoolWithConfidenceType=BoolWithConfidence(False),
		ref_type:ReferenceType=ReferenceType.PointerReferenceType, width:_int=None) -> 'PointerType':

		if arch is not None:
			width = arch.address_size
		if width is None:
			raise TypeCreateException("Must specify either an architecture or a width to create a pointer")

		return PointerType.create_with_width(width, type, const, volatile, ref_type)

	@staticmethod
	def array(type:'Type', count:_int) -> 'ArrayType':
		return ArrayType.create(type, count)

	@staticmethod
	def function(ret:Optional['Type'], params:ParamsType=[], calling_convention:'callingconvention.CallingConvention'=None,
		variable_arguments:BoolWithConfidenceType=BoolWithConfidence(False),
		stack_adjust:OffsetWithConfidence=OffsetWithConfidence(0)) -> 'FunctionType':
		"""
		``function`` class method for creating an function Type.
		:param Type ret: return Type of the function
		:param params: list of parameter Types
		:type params: list(Type)
		:param CallingConvention calling_convention: optional argument for the function calling convention
		:param bool variable_arguments: optional boolean, true if the function has a variable number of arguments
		"""
		return FunctionType.create(ret, params, calling_convention, variable_arguments, stack_adjust)

	@staticmethod
	def from_core_struct(core_type:core.BNType):
		return Type.create(core.BNNewTypeReference(core_type))

	@staticmethod
	def structure(members:MembersType=[], packed:_bool=False, type:StructureVariant=StructureVariant.StructStructureType) -> 'StructureType':
		return StructureType.create(members, packed, type)

	@staticmethod
	def enumeration(arch:Optional['architecture.Architecture'], members:EnumMembersType=[],
		width:Optional[_int]=None, sign:BoolWithConfidenceType=BoolWithConfidence(False)) -> 'EnumerationType':
		return EnumerationType.create(arch, members, width, sign)

	@staticmethod
	def named_type_reference(name:QualifiedName, type:Optional['Type']=None, guid:Optional[str]=None):
		"""
		Deprecated property kept for backward compability.
		These operations can now be done directly on the Type object.
		"""
		return NamedTypeReferenceType.create_from_type(name, type, guid)

	@property
	@abstractmethod
	def name(self) -> QualifiedName:
		raise NotImplementedError("Name not implemented for this type")

	@staticmethod
	def generate_auto_type_id(source, name:str) -> str:
		_name = QualifiedName(name)._get_core_struct()
		return core.BNGenerateAutoTypeId(source, _name)

	@staticmethod
	def generate_auto_demangled_type_id(name:str) -> str:
		_name = QualifiedName(name)._get_core_struct()
		return core.BNGenerateAutoDemangledTypeId(_name)

	@staticmethod
	def get_auto_demangled_type_id_source() -> str:
		return core.BNGetAutoDemangledTypeIdSource()

	def immutable_copy(self) -> 'Type':
		return self


@dataclass(frozen=True)
class RegisterStackAdjustmentWithConfidence:
	value:int
	confidence:int=core.max_confidence

	def __int__(self):
		return self.value


class RegisteredNameType(Type):
	@property
	def registered_name(self) -> Optional['NamedTypeReferenceType']:
		"""Name of type registered to binary view, if any (read-only)"""
		# assert self.handle is not None, "RegisteredNameType.handle is None"
		# assert False, f"{str(self.type_class)}"
		ntr_handle = core.BNGetRegisteredTypeName(self.handle)
		if ntr_handle is None:
			return None
		# assert ntr_handle is not None, "core.BNGetRegisteredTypeName returned None"
		return NamedTypeReferenceType(self.handle, self.platform, self.confidence, ntr_handle)

	# @property
	# def name(self) -> Optional[QualifiedName]:
	# 	registered_name = self.registered_name
	# 	if registered_name is None:
	# 		return None
	# 	return registered_name.name


@dataclass
class MutableTypeBuilder:
	type:'MutableType'
	container:TypeContainer
	name:QualifiedName
	platform:Optional['_platform.Platform']
	confidence:int
	user:bool = True

	def __enter__(self):
		return self.type

	def __exit__(self, type, value, traceback):
		if isinstance(self.container, binaryview.BinaryView):
			if self.user:
				self.container.define_user_type(self.name, self.type.immutable_copy(self.platform, self.confidence))
			else:
				type_id = types.Type.generate_auto_type_id(str(uuid.uuid4()), str(self.name))
				self.container.define_type(type_id, self.name, self.type.immutable_copy(self.platform, self.confidence))
		else:
			self.container.add_named_type(self.name, self.type.immutable_copy())


@dataclass
class MutableType(ABC):
	@abstractmethod
	def immutable_copy(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> Type:
		return NotImplemented

	def builder(self, container:TypeContainer, name:'QualifiedName', user:bool=True, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> MutableTypeBuilder:
		return MutableTypeBuilder(self, container, name, platform, confidence, user)

	@abstractmethod
	def __len__(self):
		return NotImplemented

	def mutable_copy(self) -> 'MutableType':
		return self

@dataclass
class CVQualified(MutableType):
	const:BoolWithConfidence=BoolWithConfidence(False)
	volatile:BoolWithConfidence=BoolWithConfidence(False)


class CVQualifiedType(Type):
	@property
	def const(self):
		"""Whether type is const (read/write)"""
		result = core.BNIsTypeConst(self._handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@property
	def volatile(self):
		"""Whether type is volatile (read/write)"""
		result = core.BNIsTypeVolatile(self._handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@staticmethod
	def from_bools(const:BoolWithConfidenceType, volatile:BoolWithConfidenceType) -> Tuple[BoolWithConfidence, BoolWithConfidence]:
		_const = const
		if const is None:
			_const = BoolWithConfidence(False, confidence = 0)
		elif isinstance(const, bool):
			_const = BoolWithConfidence(const)
		if not isinstance(_const, BoolWithConfidence):
			raise ValueError(f"unhandled type {type(const)} for 'const' argument")

		_volatile = volatile
		if volatile is None:
			_volatile = BoolWithConfidence(False, confidence = 0)
		elif isinstance(volatile, bool):
			_volatile = BoolWithConfidence(volatile)
		if not isinstance(_volatile, BoolWithConfidence):
			raise ValueError(f"unhandled type {type(volatile)} for 'volatile' argument")

		return (_const, _volatile)


class PointerLike(CVQualifiedType):
	@property
	def target(self) -> Type:
		"""Target (read-only)"""
		result = core.BNGetChildType(self._handle)
		assert result is not None, "core.BNGetChildType returned None"
		return Type.create(core.BNNewTypeReference(result.type), self._platform, result.confidence)

@dataclass
class Void(MutableType):
	def immutable_copy(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'VoidType':
		return VoidType.create(platform, confidence)

	def __len__(self):
		return 0

class VoidType(Type):
	@classmethod
	def create(cls, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'VoidType':
		core_void = core.BNCreateVoidType()
		assert core_void is not None, "core.BNCreateVoidType returned None"
		return cls(core.BNNewTypeReference(core_void), platform, confidence)

	def create_mutable(self) -> 'Void':
		return Void()


@dataclass
class Integer(MutableType):
	width:int
	altname:str=""
	signed:BoolWithConfidence=BoolWithConfidence(True)

	def immutable_copy(self, **kwargs) -> 'IntegerType':
		return IntegerType.create(self.width, self.signed, self.altname, **self.__dict__)

	def __len__(self):
		return self.width


class IntegerType(CVQualifiedType):
	@classmethod
	def create(cls, width:int, sign:BoolWithConfidenceType=BoolWithConfidence(True), altname:str="", **kwargs) -> 'IntegerType':
		if isinstance(sign, BoolWithConfidence):
			_sign = sign.to_core_struct()
		elif isinstance(sign, bool):
			_sign = BoolWithConfidence(sign).to_core_struct()

		builder_handle = core.BNCreateIntegerTypeBuilder(width, _sign, altname, **kwargs)
		assert builder_handle is not None, "core.BNCreateIntegerTypeBuilder returned None"

		handle = _TypeBuilder(builder_handle, **kwargs).finalize()
		return cls(core.BNNewTypeReference(handle), **kwargs)

	def create_mutable(self) -> 'Integer':
		i = Integer(self.width, self.altname, self.signed)
		i.__dict__['const']__ = self.const
		i.__dict__['volatile']__ = self.volatile
		return i

	@property
	def signed(self) -> BoolWithConfidence:
		"""Whether type is signed (read-only)"""
		return BoolWithConfidence.from_core_struct(core.BNIsTypeSigned(self._handle))


@dataclass
class Bool(MutableType):
	def immutable_copy(self, platform:'_platform.Platform'=None,
		confidence:int=core.max_confidence) -> 'BoolType':
		return BoolType.create(platform, confidence)

	def __len__(self):
		return 1


class BoolType(Type):
	@classmethod
	def create(cls, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'BoolType':
		handle = core.BNCreateBoolType()
		assert handle is not None, "core.BNCreateBoolType returned None"
		return cls(core.BNNewTypeReference(handle), platform, confidence)

	def create_mutable(self) -> 'Bool':
		return Bool()

@dataclass
class Char(Integer):
	width:int=1
	altname:str=""
	sign:bool=True

	def as_char(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'CharType':
		return CharType.create(self.width, self.altname, self.sign, platform, confidence)


class CharType(IntegerType):
	@classmethod
	def create(cls, width:int=1, altname:str="char", sign:bool=True,
		platform:'_platform.Platform'=None, confidence:int=core.max_confidence, **kwargs) -> 'CharType':
		return cls(IntegerType.create(width, sign, altname, **kwargs).handle, platform, confidence)

	def create_mutable(self) -> 'Char':
		return Char(self.width, self.altname, self.signed, self.const, self.volatile)

	@property
	def signed(self) -> BoolWithConfidence:
		return BoolWithConfidence(False, core.max_confidence)


@dataclass
class Float(MutableType):
	width:int
	altname:str=""

	def immutable_copy(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'FloatType':
		return FloatType.create(self.width, self.altname, platform, confidence)

	def __len__(self):
		return self.width

class FloatType(Type):
	@classmethod
	def create(cls, width:int, altname:str="", platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'FloatType':
		"""
		``float`` class method for creating floating point Types.

		:param int width: width of the floating point number in bytes
		:param str altname: alternate name for type
		"""
		core_float = core.BNCreateFloatType(width, altname)
		assert core_float is not None, "core.BNCreateFloatType returned None"
		return cls(core.BNNewTypeReference(core_float), platform, confidence)

	def create_mutable(self) -> 'Float':
		return Float(self.width, self.altname)


@dataclass
class StructureMember:
	type:Union[Type, MutableType]
	name:str
	offset:int

	def __post_init__(self):
		self.type = self.type.mutable_copy()

	def __repr__(self):
		# TODO: Consider showing this differently if the type is mutable
		if len(self.name) == 0:
			return f"<member: {self.type.immutable_copy()}, offset {self.offset:#x}>"
		return f"<{self.type.immutable_copy().get_string_before_name()} {self.name}{self.type.immutable_copy().get_string_after_name()}" + \
			f", offset {self.offset:#x}>"
		# return f"<StructureMember: {self.type} {self.name}>"

	def __len__(self):
		return len(self.type)


class StructureType(RegisteredNameType):
	def __init__(self, handle, platform:'_platform.Platform'=None, confidence:int=core.max_confidence):
		assert handle is not None, "Attempted to create EnumerationType with handle which is None"
		super(StructureType, self).__init__(handle, platform, confidence)
		struct_handle = core.BNGetTypeStructure(handle)
		assert struct_handle is not None, "core.BNGetTypeStructure returned None"
		self.struct_handle = struct_handle

	@classmethod
	def create(cls, members:MembersType=[], packed:bool=False, variant:StructureVariant=StructureVariant.StructStructureType, 
		platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'StructureType':
		builder = core.BNCreateStructureBuilderWithOptions(variant, packed)
		assert builder is not None, "core.BNCreateStructureBuilder returned None"

		for member in members:
			if isinstance(member, Tuple):
				_type, _name = member
				core.BNAddStructureBuilderMember(builder, _type.immutable_copy().to_core_struct(), _name)
			elif isinstance(member, StructureMember):
				core.BNAddStructureBuilderMemberAtOffset(builder, member.type.immutable_copy().to_core_struct(),
					member.name, member.offset, False)
		core_struct = core.BNFinalizeStructureBuilder(builder)
		assert core_struct is not None, "core.BNFinalizeStructureBuilder returned None"
		core_type = core.BNCreateStructureType(core_struct)
		assert core_type is not None, "core.BNCreateStructureType returned None"
		return cls(core.BNNewTypeReference(core_type), platform, confidence)

	def create_mutable(self) -> 'Structure':
		return Structure(self.members, self.alignment, self.width, self.type, self.packed)

	@classmethod
	def from_core_struct(cls, structure:core.BNStructure) -> 'StructureType':
		return cls(core.BNNewTypeReference(core.BNCreateStructureType(structure)))

	def __del__(self):
		if core is not None:
			core.BNFreeStructure(self.struct_handle)

	# TODO: Commented to pass unit tests
	# def __repr__(self):
	# 	return f"<struct: {self.registered_name}>"

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		assert other.handle is not None
		return ctypes.addressof(self.struct_handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.struct_handle.contents))

	def __getitem__(self, name:str) -> StructureMember:
		member = None
		try:
			member = core.BNGetStructureMemberByName(self.struct_handle, name)
			if member is None:
				raise ValueError(f"Member {name} is not part of structure")
			return StructureMember(Type.create(core.BNNewTypeReference(member.contents.type), confidence=member.contents.typeConfidence),
					member.contents.name, member.contents.offset)
		finally:
			if member is not None:
				core.BNFreeStructureMember(member)

	def member_at_offset(self, offset:int) -> StructureMember:
		member = None
		try:
			member = core.BNGetStructureMemberAtOffset(self.struct_handle, offset, None)
			if member is None:
				raise ValueError(f"No member exists a offset {offset}")
			return StructureMember(Type.create(core.BNNewTypeReference(member.contents.type), confidence=member.contents.typeConfidence),
					member.contents.name, member.contents.offset)
		finally:
			core.BNFreeStructureMember(member)

	@property
	def members(self):
		"""Structure member list (read-only)"""
		count = ctypes.c_ulonglong()
		members = core.BNGetStructureMembers(self.struct_handle, count)
		assert members is not None, "core.BNGetStructureMembers returned None"
		try:
			result = []
			for i in range(0, count.value):
				result.append(StructureMember(Type.create(core.BNNewTypeReference(members[i].type), confidence=members[i].typeConfidence),
					members[i].name, members[i].offset))
		finally:
			core.BNFreeStructureMemberList(members, count.value)
		return result

	@property
	def width(self):
		"""Structure width"""
		return core.BNGetStructureWidth(self.struct_handle)

	@property
	def alignment(self):
		"""Structure alignment"""
		return core.BNGetStructureAlignment(self.struct_handle)

	@property
	def packed(self):
		return core.BNIsStructurePacked(self.struct_handle)

	@property
	def type(self) -> StructureVariant:
		return StructureVariant(core.BNGetStructureType(self.struct_handle))

	def with_replaced_structure(self, from_struct, to_struct) -> 'StructureType':
		return Type.create(core.BNStructureWithReplacedStructure(self.struct_handle, from_struct.handle, to_struct.handle))

	def with_replaced_enumeration(self, from_enum, to_enum) -> 'StructureType':
		return Type.create(core.BNStructureWithReplacedEnumeration(self.struct_handle, from_enum.handle, to_enum.handle))

	def with_replaced_named_type_reference(self, from_ref, to_ref) -> 'StructureType':
		return Type.create(core.BNStructureWithReplacedNamedTypeReference(self.struct_handle, from_ref.handle, to_ref.handle))

	def generate_named_type_reference(self, guid:str, name:QualifiedName):
		if self.type == StructureVariant.StructStructureType:
			ntr_type = NamedTypeReferenceClass.StructNamedTypeClass
		elif self.type == StructureVariant.UnionStructureType:
			ntr_type = NamedTypeReferenceClass.UnionNamedTypeClass
		else:
			ntr_type = NamedTypeReferenceClass.ClassNamedTypeClass
		return NamedTypeReferenceType.create(ntr_type, guid, name, self.alignment,
			self.width, self.platform, self.confidence)


@dataclass
class Structure(MutableType):
	members:List[StructureMember] = field(default_factory=list)
	_alignment:int=1
	_width:int=0
	type:StructureVariant=StructureVariant.StructStructureType
	_packed:bool=False

	def immutable_copy(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'StructureType':
		return StructureType.create(self.members, self.packed, self.type, platform, confidence)

	@property
	def packed(self) -> bool:
		return self._packed

	@packed.setter
	def packed(self, value:bool) -> None:
		self._packed = value

	@property
	def alignment(self) -> int:
		return self._alignment

	@alignment.setter
	def alignment(self, value:int) -> None:
		if value == 1:
			return
		if value < 1:
			raise ValueError("Can't set alignment to < 1")
		self._alignment = value

	@property
	def width(self) -> int:
		return self._width

	@width.setter
	def width(self, value:int) -> None:
		# if greater than the current width:
		#   expands the structure's size
		# if less than the current width:
		#   shrinks the structure's size removing any members which would exist outside the structure's bounds
		if value < 0:
			raise ValueError("Width of structure can not be negative")

		if value < self._width:
			amount = self._width - (self._width - value)
			self.clear_members(value, amount)
		self._width = value

	def __repr__(self):
		return f"<struct: size {self.width:#x}>"

	def __getitem__(self, name:str) -> Optional[StructureMember]:
		for member in self.members:
			if member.name == name:
				return member
		return None

	def __iter__(self) -> Generator[StructureMember, None, None]:
		for member in self.members:
			yield member

	def __len__(self) -> int:
		return self._width

	def member_at_offset(self, offset:int) -> Optional[StructureMember]:
		for member in self.members:
			if member.offset == offset:
				return member
		return None

	def index_by_name(self, name:MemberName) -> Optional[MemberIndex]:
		for i, member in enumerate(self.members):
			if member.name == name:
				return i
		return None

	def index_by_offset(self, offset:MemberOffset) -> Optional[MemberIndex]:
		for i, member in enumerate(self.members):
			if member.offset == offset:
				return i
		return None

	def index_from(self, index:Optional[MemberIndex]=None, name:Optional[MemberName]=None, offset:Optional[MemberOffset]=None) -> MemberIndex:
		if index is not None:
			if index >= len(self.members):
				raise IndexError("list index out of range")
		elif name is not None:
			index = self.index_by_name(name)
			if index is None:
				raise ValueError(f"StructureMember {name} doesn't exist")
		elif offset is not None:
			index = self.index_by_offset(offset)
			if index is None:
				raise ValueError(f"No StructureMember at offset exists")
		else:
			raise ValueError("One of the following must")

		return index

	def erase(self, index:MemberIndex=None, name:MemberName=None, offset:MemberOffset=None) -> None:
		# removes the specified item shrinking the total size of the structure and adjusting
		# the offset of any members with offsets greater than the offset of member[index].
		# In the case where there are multiple members which overlap the erased item they will be erased too
		# but the structure will only be shrunken by the specified member's width
		# raise exception if the index doesn't exist
		# raises exception if more not exactly one of index/name/offset are not None
		item = self.members[self.index_from(index, name, offset)]
		self.clear_members(item.offset, len(item))
		self.adjust_space(item.offset, -len(item))

	def clear(self, index:MemberIndex=None, name:MemberName=None, offset:MemberOffset=None) -> None:
		# clears the member at the index/member-name. No adjustment is made to other members or the structure's size
		# raise exception if the index doesn't exist
		del self.members[self.index_from(index, name, offset)]

	def clear_members(self, offset:MemberOffset, size:int) -> None:
		# clears members which overlap offset
		to_clear = []
		for i, member in enumerate(self.members):
			if member.offset >= offset and member.offset < offset + size:
				to_clear.append(i)
			elif member.offset < offset and member.offset + len(member) > offset:
				to_clear.append(i)
		for i in to_clear:
			self.clear(index=i)

	def replace_member(self, new_name:MemberName, type:SomeType, index:MemberIndex=None, old_name:MemberName=None, offset:MemberOffset=None) -> None:
		# replaces any members within the structure which overlap member[index]
		index = self.index_from(index, old_name, offset)
		item = self.members[index]
		self.clear_members(item.offset, len(item))
		self.members.insert(index, StructureMember(type, new_name, item.offset))

	def append(self, name:MemberName, type:SomeType) -> 'Structure':
		# appends a structure at the end of the structure growing the structure
		self.members.append(StructureMember(type.mutable_copy(), name, self._width))
		self._width += len(type)
		return self

	def add_member_at_offset(self, name:MemberName, type:SomeType, offset:MemberOffset) -> 'Structure':
		# Adds structure member to the given offset first clearing any members within the range offset-offset+len(type)
		self.clear_members(offset, len(type))
		self.members.append(StructureMember(type, name, offset))
		self.members = sorted(self.members, key=lambda m: m.offset)
		return self

	def adjust_space(self, offset:int, size:int) -> None:
		# adds or removes undefined space at the given offset and size
		# removes space and clears overlapping members if size is negative
		self.members = sorted(self.members, key=lambda m: m.offset)

		if size < -self._width:
			size = -self._width

		if size < 0:
			self.clear_members(offset, size)

		alignment = 0
		if size % self._alignment != 0:
			alignment = self._alignment - (abs(size) % self._alignment)

		new_members = []
		for member in self.members:
			if member.offset > offset:
				new_offset = member.offset + size + alignment
				new_members.append(StructureMember(member.type, member.name, new_offset))
		self.members = new_members
		self._width += size


class EnumerationType(RegisteredNameType, IntegerType):
	def __init__(self, handle, platform:'_platform.Platform'=None, confidence:int=core.max_confidence):
		assert handle is not None, "Attempted to create EnumerationType without handle"
		super(EnumerationType, self).__init__(handle, platform, confidence)
		enum_handle = core.BNGetTypeEnumeration(handle)
		assert enum_handle is not None, "core.BNGetTypeEnumeration returned None"
		self.enum_handle = enum_handle

	@classmethod
	def create(cls, arch:Optional['architecture.Architecture'], members:EnumMembersType=[], width:Optional[int]=None,
		sign:BoolWithConfidenceType=BoolWithConfidence(False), platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'EnumerationType':
		if width is None:
			if arch is None:
				raise ValueError("One of the following parameters must not be None: (arch, width)")
			width = arch.default_int_size
		if width == 0:
			raise ValueError("enumeration width must not be 0")

		builder = core.BNCreateEnumerationBuilder()
		assert builder is not None, "core.BNCreateEnumerationType returned None"
		for i, member in enumerate(members):
			value = i
			name = member
			if isinstance(member, Tuple):
				value, name = member
			elif isinstance(member, EnumerationMember):
				value = member.value
				name = member.name
			if value is None:
				core.BNAddEnumerationBuilderMember(builder, name)
			else:
				core.BNAddEnumerationBuilderMemberWithValue(builder, name, value)
		core_enum = core.BNFinalizeEnumerationBuilder(builder)
		assert core_enum is not None, "core.BNFinalizeEnumerationBuilder returned None"
		core_type = core.BNCreateEnumerationTypeOfWidth(core_enum, width, sign)
		assert core_type is not None, "core.BNCreateEnumerationTypeOfWidth returned None"
		return cls(core.BNNewTypeReference(core_type), platform, confidence)

	def create_mutable(self) -> 'Enumeration':
		return Enumeration(self.members, len(self), self.signed)

	def __del__(self):
		if core is not None:
			core.BNFreeEnumeration(self.enum_handle)

	# def __repr__(self):
	# 	return "<enum: %s>" % repr(self.members)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.enum_handle.contents) == ctypes.addressof(other.enum_handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.enum_handle.contents))

	@property
	def members(self):
		"""Enumeration member list (read-only)"""
		count = ctypes.c_ulonglong()
		members = core.BNGetEnumerationMembers(self.enum_handle, count)
		assert members is not None, "core.BNGetEnumerationMembers returned None"
		result = []
		for i in range(0, count.value):
			result.append(EnumerationMember(members[i].name, members[i].value))
		core.BNFreeEnumerationMemberList(members, count.value)
		return result

	def generate_named_type_reference(self, guid:str, name:QualifiedName):
		ntr_type = NamedTypeReferenceClass.EnumNamedTypeClass
		return NamedTypeReferenceType.create(ntr_type, guid, name,
			platform=self.platform, confidence=self.confidence)

@dataclass(frozen=True)
class EnumerationMember:
	name:str
	value:Optional[int]

	def __repr__(self):
		value = f"{self.value:#x}" if self.value is not None else "auto()"
		return f"<{self.name} = {value}>"


@dataclass
class Enumeration(MutableType):
	members:List[EnumerationMember] = field(default_factory=list)
	width:int=4
	sign:BoolWithConfidence=BoolWithConfidence(False)

	def __repr__(self):
		return "<enum: %s>" % repr(self.members)

	def __len__(self):
		return self.width

	def immutable_copy(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'EnumerationType':
		return EnumerationType.create(None, self.members, self.width, self.sign, platform, confidence)

	def append(self, name, value = None) -> 'Enumeration':
		self.members.append(EnumerationMember(name, value))
		return self

	def remove(self, i):
		del self.members[i]

	def replace(self, i, name, value):
		self.remove(i)
		self.members.insert(i, EnumerationMember(name, value))

	def __iter__(self) -> Generator[EnumerationMember, None, None]:
		for i, member in enumerate(self.members):
			if member.value is None:
				yield EnumerationMember(member.name, i)
			else:
				yield member

	def __getitem__(self, value:Union[str, int, slice]):
		if isinstance(value, str) and value in self.__dict__:
			return self.__dict__[value]

		if isinstance(value, str):
			for member in self.members:
				if member.name == value:
					return member
			return None
		elif isinstance(value, int):
			return self.members[value]
		elif isinstance(value, slice):  # not combined with the previous check due to pyright bug
			return self.members[value]
		else:
			raise ValueError(f"Incompatible type {type(value)} for __getitem__")

	def __setitem__(self, item, value):
		if isinstance(item, str):
			for i, member in enumerate(self.members):
				if member.name == item:
					self.members[i] = EnumerationMember(member.name, value)
		elif isinstance(item, int) and isinstance(value, EnumerationMember):
			self.members[item] = value
		raise ValueError(f"Incompatible type: {type(item)} for __setitem__")


@dataclass
class Pointer(MutableType):
	_target:Optional[SomeType] = None
	width:Optional[int] = None
	arch:Optional['architecture.Architecture'] = None
	const:BoolWithConfidenceType=BoolWithConfidence(False)
	volatile:BoolWithConfidenceType=BoolWithConfidence(False)
	ref_type:ReferenceType=ReferenceType.PointerReferenceType

	def __post_init__(self):
		if self._target is not None:
			self._target = self._target.mutable_copy()
		assert self.arch is not None or self.width is not None, f"Must specify either an architecture or a width {self.arch} : {self.width}"
		if self.arch is not None:
			self.width = self.arch.address_size

	def immutable_copy(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'PointerType':
		assert self._target is not None and self.width is not None, f"Target not set for Pointer(MutableType) {self._target}, {self.width}"
		return PointerType.create_with_width(self.width, self._target, self.const, self.volatile,
			self.ref_type, platform, confidence)

	@property
	def target(self) -> MutableType:
		assert isinstance(self._target, MutableType)
		return self._target

	@target.setter
	def target(self, value:SomeType): # type: ignore
		self._target = value.mutable_copy()

	def __len__(self):
		return self.width

class PointerType(PointerLike):
	@property
	def ref_type(self) -> ReferenceType:
		return core.BNTypeGetReferenceType(self._handle)

	@classmethod
	def create(cls, arch:'architecture.Architecture', type:SomeType, const:BoolWithConfidenceType=False,
		volatile:BoolWithConfidenceType=False, ref_type:ReferenceType=ReferenceType.PointerReferenceType,
		platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'PointerType':
		return cls.create_with_width(arch.address_size, type, const, volatile, ref_type, platform, confidence)

	@classmethod
	def create_with_width(cls, width:int, type:SomeType, const:BoolWithConfidenceType=False,
		volatile:BoolWithConfidenceType=False, ref_type:ReferenceType=None, platform:'_platform.Platform'=None,
		confidence:int=core.max_confidence) -> 'PointerType':
		_const, _volatile = CVQualifiedType.from_bools(const, volatile)
		type = type.immutable_copy()
		if ref_type is None:
			ref_type = ReferenceType.PointerReferenceType

		type_conf = type.to_core_struct()
		core_type = core.BNCreatePointerTypeOfWidth(width, type_conf, _const.to_core_struct(),
			_volatile.to_core_struct(), ref_type)
		assert core_type is not None, "core.BNCreatePointerTypeOfWidth returned None"
		return Type.create(core.BNNewTypeReference(core_type), platform, confidence)

	def create_mutable(self) -> 'Pointer':
		return Pointer(self.target, self.width, None, self.const, self.volatile, self.ref_type)


@dataclass
class Array(MutableType):
	count:int
	element_type:MutableType

	def __post_init__(self):
		self.element_type = self.element_type.mutable_copy()

	def immutable_copy(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'ArrayType':
		return ArrayType.create(self.element_type.immutable_copy(), self.count, platform, confidence)

	def __len__(self):
		return self.count * len(self.element_type)


class ArrayType(Type):
	@classmethod
	def create(cls, element_type:Type, count:int, platform:'_platform.Platform'=None, confidence:int=core.max_confidence):
		type_conf = element_type.to_core_struct()
		core_array = core.BNCreateArrayType(type_conf, count)
		assert core_array is not None, "core.BNCreateArrayType returned None"
		return cls(core.BNNewTypeReference(core_array))

	def create_mutable(self) -> 'Array':
		return Array(self.count, self.element_type.mutable_copy())

	@property
	def count(self):
		"""Type count (read-only)"""
		return core.BNGetTypeElementCount(self._handle)

	@property
	def element_type(self) -> Type:
		result = core.BNGetChildType(self._handle)
		assert result is not None, "core.BNGetChildType returned None"
		return Type.create(core.BNNewTypeReference(result.type), self._platform, result.confidence)


@dataclass
class Function(MutableType):
	_return_type:Optional[SomeType] = None
	parameters:List[FunctionParameter] = field(default_factory=list)
	calling_convention:Optional['callingconvention.CallingConvention'] = None
	variable_arguments:BoolWithConfidenceType = BoolWithConfidence(False)
	stack_adjustment:OffsetWithConfidence = OffsetWithConfidence(0)

	def __post_init__(self):
		if self._return_type is not None:
			self._return_type = self._return_type.mutable_copy()
		if len(self.parameters) > 0:
			self.parameters = [param.mutable_copy() for param in self.parameters]

	def immutable_copy(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'FunctionType':
		immutable_parameters = [param.immutable_copy() for param in self.parameters]
		if self._return_type is None:
			self._return_type = Type.void()
		return FunctionType.create(self._return_type.immutable_copy(), immutable_parameters, self.calling_convention,
			self.variable_arguments, self.stack_adjustment, platform, confidence)

	@property
	def return_type(self):
		return self._return_type

	@return_type.setter
	def return_type(self, value:SomeType):
		self._return_type = value.mutable_copy()

	def append(self, type:Union[SomeType, FunctionParameter], name:str=""):
		if isinstance(type, FunctionParameter):
			self.parameters.append(type.mutable_copy())
		else:
			self.parameters.append(FunctionParameter(type.mutable_copy(), name))

	def __len__(self):
		return 0

class FunctionType(Type):
	@classmethod
	def create(cls, ret:Optional[Type]=None, params:ParamsType=[],
		calling_convention:'callingconvention.CallingConvention'=None, variable_arguments:BoolWithConfidenceType=BoolWithConfidence(False),
		stack_adjust:OffsetWithConfidence=OffsetWithConfidence(0), platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'FunctionType':
		if ret is None:
			ret = VoidType.create()
		param_buf = (core.BNFunctionParameter * len(params))()
		for i in range(0, len(params)):
			param = params[i]
			core_param = param_buf[i]
			if isinstance(param, Type):
				core_param.name = ""
				core_param.type = param.handle
				core_param.typeConfidence = param.confidence
				core_param.defaultLocation = True
			elif isinstance(param, FunctionParameter):
				core_param.name = param.name
				core_param.type = param.type.immutable_copy().handle
				core_param.typeConfidence = param.type.immutable_copy().confidence
				if param.location is None:
					core_param.defaultLocation = True
				else:
					core_param.defaultLocation = False
					core_param.location.type = param.location.source_type
					core_param.location.index = param.location.index
					core_param.location.storage = param.location.storage
			elif isinstance(param, tuple):
				t, name = param
				core_param.name = name
				core_param.type = t.handle
				core_param.typeConfidence = t.confidence
				core_param.defaultLocation = True

		ret_conf = ret.to_core_struct()

		conv_conf = core.BNCallingConventionWithConfidence()
		if calling_convention is None:
			conv_conf.convention = None
			conv_conf.confidence = 0
		else:
			conv_conf.convention = calling_convention.handle
			conv_conf.confidence = calling_convention.confidence

		if isinstance(variable_arguments, bool):
			_variable_arguments = BoolWithConfidence(variable_arguments)
		elif isinstance(variable_arguments, BoolWithConfidence):
			_variable_arguments = variable_arguments
		elif variable_arguments is None:
			_variable_arguments = BoolWithConfidence(False)
		else:
			raise ValueError(f"variable_arguments parameter of unhandled type: {type(variable_arguments)}")

		if isinstance(stack_adjust, int):
			_stack_adjust = OffsetWithConfidence(stack_adjust)
		elif isinstance(stack_adjust, OffsetWithConfidence):
			_stack_adjust = stack_adjust
		elif stack_adjust is None:
			_stack_adjust = OffsetWithConfidence(0)
		else:
			raise ValueError(f"stack_adjust parameter of unhandled type: {type(variable_arguments)}")

		func_type = core.BNCreateFunctionType(ret_conf, conv_conf, param_buf, len(params),
			_variable_arguments.to_core_struct(), _stack_adjust.to_core_struct())
		return cls(core.BNNewTypeReference(func_type), platform, confidence)

	def create_mutable(self) -> 'Function':
		return Function(self.return_value.mutable_copy(), self.parameters, self.calling_convention, self.has_variable_arguments, self.stack_adjustment)

	@property
	def stack_adjustment(self) -> OffsetWithConfidence:
		"""Stack adjustment for function (read-only)"""
		result = core.BNGetTypeStackAdjustment(self._handle)
		return OffsetWithConfidence(result.value, confidence = result.confidence)

	@property
	def return_value(self) -> Type:
		"""Return value (read-only)"""
		result = core.BNGetChildType(self._handle)
		if result is None:
			return Type.void()
		return Type.create(core.BNNewTypeReference(result.type), platform = self._platform, confidence = result.confidence)

	@property
	def calling_convention(self) -> Optional[callingconvention.CallingConvention]:
		"""Calling convention (read-only)"""
		result = core.BNGetTypeCallingConvention(self._handle)
		if not result.convention:
			return None
		return callingconvention.CallingConvention(None, handle = result.convention, confidence = result.confidence)

	@property
	def parameters(self) -> List[FunctionParameter]:
		"""Type parameters list (read-only)"""
		count = ctypes.c_ulonglong()
		params = core.BNGetTypeParameters(self._handle, count)
		assert params is not None, "core.BNGetTypeParameters returned None"
		result = []
		for i in range(0, count.value):
			param_type = Type.create(core.BNNewTypeReference(params[i].type), platform = self._platform, confidence = params[i].typeConfidence)
			if params[i].defaultLocation:
				param_location = None
			else:
				name = params[i].name
				if (params[i].location.type == VariableSourceType.RegisterVariableSourceType) and (self._platform is not None):
					name = self._platform.arch.get_reg_name(params[i].location.storage)
				elif params[i].location.type == VariableSourceType.StackVariableSourceType:
					name = "arg_%x" % params[i].location.storage
				param_location = variable.VariableNameAndType(params[i].location.type, params[i].location.index,
					params[i].location.storage, name, param_type)
			result.append(FunctionParameter(param_type, params[i].name, param_location))
		core.BNFreeTypeParameterList(params, count.value)
		return result

	@property
	def has_variable_arguments(self) -> BoolWithConfidence:
		"""Whether type has variable arguments (read-only)"""
		result = core.BNTypeHasVariableArguments(self._handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@property
	def can_return(self) -> BoolWithConfidence:
		"""Whether type can return"""
		result = core.BNFunctionTypeCanReturn(self._handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)


# @dataclass
# class Value(MutableType):
# 	pass


# class ValueType(Type):
# 	pass


@dataclass
class NamedTypeReference(MutableType):
	name:QualifiedName
	id:str
	named_type_class:NamedTypeReferenceClass=NamedTypeReferenceClass.UnknownNamedTypeClass
	alignment:int = 0
	width:int = 0

	def __repr__(self):
		if self.named_type_class == NamedTypeReferenceClass.TypedefNamedTypeClass:
			return "<named type: typedef %s>" % str(self.name)
		if self.named_type_class == NamedTypeReferenceClass.StructNamedTypeClass:
			return "<named type: struct %s>" % str(self.name)
		if self.named_type_class == NamedTypeReferenceClass.UnionNamedTypeClass:
			return "<named type: union %s>" % str(self.name)
		if self.named_type_class == NamedTypeReferenceClass.EnumNamedTypeClass:
			return "<named type: enum %s>" % str(self.name)
		return "<named type: unknown >"

	def immutable_copy(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'NamedTypeReferenceType':
		return NamedTypeReferenceType.create(self.named_type_class, self.id, self.name, self.alignment, self.width,
			platform, confidence)

	def __len__(self):
		return self.width

class NamedTypeReferenceType(RegisteredNameType):
	def __init__(self, handle, platform:'_platform.Platform'=None, confidence:int=core.max_confidence, ntr_handle=None):
		assert handle is not None, "Attempting to create NamedTypeReferenceType handle which is None"
		super(NamedTypeReferenceType, self).__init__(handle, platform, confidence)
		if ntr_handle is None:
			ntr_handle = core.BNGetTypeNamedTypeReference(handle)
		assert ntr_handle is not None, "core.BNGetTypeNamedTypeReference returned None"
		self.ntr_handle = ntr_handle

	@classmethod
	def create(cls, named_type_class:NamedTypeReferenceClass, guid:Optional[str],
		name:QualifiedName, alignment:int=0, width:int=0, platform:'_platform.Platform'=None,
		confidence:int=core.max_confidence) -> 'NamedTypeReferenceType':
		_guid = guid
		if guid is None:
			_guid = str(uuid.uuid4())

		_name = QualifiedName(name)._get_core_struct()
		core_ntr = core.BNCreateNamedType(named_type_class, _guid, _name)
		assert core_ntr is not None, "core.BNCreateNamedType returned None"
		core_type = core.BNCreateNamedTypeReference(core_ntr, width, alignment)
		assert core_type is not None, "core.BNCreateNamedTypeReference returned None"
		return cls(core.BNNewTypeReference(core_type), platform, confidence)

	@classmethod
	def create_from_type(cls, name:QualifiedName, type:Optional[Type], guid:Optional[str]=None,
		platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'NamedTypeReferenceType':
		_guid = guid
		if _guid is None:
			_guid = str(uuid.uuid4())

		if type is None:
			return cls.create(NamedTypeReferenceClass.UnknownNamedTypeClass, _guid, name)
		else:
			return type.generate_named_type_reference(_guid, name)

	@classmethod
	def create_from_registered_type(cls, view:'binaryview.BinaryView', name:QualifiedName,
		platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'NamedTypeReferenceType':
		_name = QualifiedName(name)._get_core_struct()
		core_type = core.BNCreateNamedTypeReferenceFromType(view.handle, _name)
		assert core_type is not None, "core.BNCreateNamedTypeReferenceFromType returned None"
		return cls(core.BNNewTypeReference(core_type), platform, confidence)

	def create_mutable(self) -> 'NamedTypeReference':
		return NamedTypeReference(self.name, self.type_id, self.named_type_class, self.alignment, self.width)

	def __del__(self):
		if core is not None:
			core.BNFreeNamedTypeReference(self.ntr_handle)

	def __repr__(self):
		if self.named_type_class == NamedTypeReferenceClass.TypedefNamedTypeClass:
			return f"<named type: {self}>"
		if self.named_type_class == NamedTypeReferenceClass.StructNamedTypeClass:
			return f"<named type: {self}>"
		if self.named_type_class == NamedTypeReferenceClass.UnionNamedTypeClass:
			return f"<named type: {self}>"
		if self.named_type_class == NamedTypeReferenceClass.EnumNamedTypeClass:
			return f"<named type: {self}>"
		return "<named type: unknown >"

	def __str__(self):
		name = self.registered_name
		if name is None:
			name = ""
		else:
			name = " " + str(name.name)
		return f"{self.get_string_before_name()}{name}{self.get_string_after_name()}"

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		assert other.handle is not None
		return ctypes.addressof(self.ntr_handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.ntr_handle.contents))

	@property
	def named_type_class(self) -> NamedTypeReferenceClass:
		return NamedTypeReferenceClass(core.BNGetTypeReferenceClass(self.ntr_handle))

	@property
	def type_id(self) -> str:
		return core.BNGetTypeReferenceId(self.ntr_handle)

	@property
	def name(self) -> QualifiedName:
		name = core.BNGetTypeReferenceName(self.ntr_handle)
		result = QualifiedName._from_core_struct(name)
		core.BNFreeQualifiedName(name)
		return result

	@staticmethod
	def generate_auto_type_ref(type_class, source, name):
		type_id = RegisteredNameType.generate_auto_type_id(source, name)
		return NamedTypeReferenceType.create(type_class, type_id, name)

	@staticmethod
	def generate_auto_demangled_type_ref(type_class, name):
		type_id = RegisteredNameType.generate_auto_demangled_type_id(name)
		return NamedTypeReferenceType.create(type_class, type_id, name)

	def target(self, bv:'binaryview.BinaryView') -> Optional[Type]:
		return bv.get_type_by_id(self.type_id)


# class TypedefType(NamedTypeReferenceType):
# 	def __init__(self, handle, platform:'_platform.Platform'=None, confidence:int=core.max_confidence):
# 		super(TypedefType,).__init__(handle, platform, confidence)

# 	@classmethod
# 	def create(cls, guid:Optional[str],
# 		name:QualifiedName, alignment:int=None, width:int=None, platform:'_platform.Platform'=None,
# 		confidence:int=core.max_confidence) -> 'TypedefType'
# 		return cls(core_type, platform, confidence)


@dataclass
class WideChar(Integer):
	def immutable_copy(self, platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'WideCharType':
		return WideCharType.create(self.width, self.altname, platform, confidence)


class WideCharType(Type):
	@classmethod
	def create(cls, width:int, altname:str="", platform:'_platform.Platform'=None, confidence:int=core.max_confidence) -> 'WideCharType':
		"""
		``wide_char`` class method for creating wide char Types.

		:param int width: width of the wide character in bytes
		:param str altname: alternate name for type
		"""
		core_type = core.BNCreateWideCharType(width, altname)
		assert core_type is not None, "core.BNCreateWideCharType returned None"
		return cls(core.BNNewTypeReference(core_type), platform, confidence)

Types = {
	TypeClass.VoidTypeClass:VoidType,
	TypeClass.BoolTypeClass:BoolType,
	TypeClass.IntegerTypeClass:IntegerType,
	TypeClass.FloatTypeClass:FloatType,
	TypeClass.StructureTypeClass:StructureType,
	TypeClass.EnumerationTypeClass:EnumerationType,
	TypeClass.PointerTypeClass:PointerType,
	TypeClass.ArrayTypeClass:ArrayType,
	TypeClass.FunctionTypeClass:FunctionType,
	TypeClass.NamedTypeReferenceClass:NamedTypeReferenceType,
	TypeClass.WideCharTypeClass:WideCharType,
}

MutableTypes = {
	TypeClass.VoidTypeClass:Void,
	TypeClass.BoolTypeClass:Bool,
	TypeClass.IntegerTypeClass:Integer,
	TypeClass.FloatTypeClass:Float,
	TypeClass.StructureTypeClass:Structure,
	TypeClass.EnumerationTypeClass:Enumeration,
	TypeClass.PointerTypeClass:Pointer,
	TypeClass.ArrayTypeClass:Array,
	TypeClass.FunctionTypeClass:Function,
	TypeClass.NamedTypeReferenceClass:NamedTypeReference,
	TypeClass.WideCharTypeClass:WideChar,
}


@dataclass(frozen=True)
class RegisterSet:
	regs:List['architecture.RegisterName']
	confidence:int=core.max_confidence

	def __iter__(self) -> Generator['architecture.RegisterName', None, None]:
		for reg in self.regs:
			yield reg

	def __getitem__(self, idx):
		return self.regs[idx]

	def __len__(self):
		return len(self.regs)

	def with_confidence(self, confidence):
		return RegisterSet(list(self.regs), confidence=confidence)





@dataclass(frozen=True)
class TypeParserResult:
	types:Mapping[QualifiedName, Type]
	variables:Mapping[QualifiedName, Type]
	functions:Mapping[QualifiedName, Type]

	def __repr__(self):
		return f"<types: {self.types}, variables: {self.variables}, functions: {self.functions}>"


def preprocess_source(source:str, filename:str=None, include_dirs:List[str]=[]) -> Tuple[Optional[str], str]:
	"""
	``preprocess_source`` run the C preprocessor on the given source or source filename.

	:param str source: source to pre-process
	:param str filename: optional filename to pre-process
	:param include_dirs: list of string directories to use as include directories.
	:type include_dirs: list(str)
	:return: returns a tuple of (preprocessed_source, error_string)
	:rtype: tuple(str,str)
	:Example:

		>>> source = "#define TEN 10\\nint x[TEN];\\n"
		>>> preprocess_source(source)
		('#line 1 "input"\\n\\n#line 2 "input"\\n int x [ 10 ] ;\\n', '')
		>>>
	"""
	if filename is None:
		filename = "input"
	dir_buf = (ctypes.c_char_p * len(include_dirs))()
	for i in range(0, len(include_dirs)):
		dir_buf[i] = include_dirs[i].encode('charmap')
	output = ctypes.c_char_p()
	errors = ctypes.c_char_p()
	result = core.BNPreprocessSource(source, filename, output, errors, dir_buf, len(include_dirs))
	assert output.value is not None
	assert errors.value is not None
	output_str = output.value.decode('utf-8')
	error_str = errors.value.decode('utf-8')
	core.free_string(output)
	core.free_string(errors)
	if result:
		return (output_str, error_str)
	return (None, error_str)


@dataclass(frozen=True)
class TypeFieldReference:
	func:Optional['_function.Function']
	arch:Optional['architecture.Architecture']
	address:int
	size:int
	incomingType:Type

	def __repr__(self):
		if self.arch:
			return "<ref: %s@%#x, size: %#x>" % (self.arch.name, self.address, self.size)
		else:
			return "<ref: %#x, size: %#x>" % (self.address, self.size)