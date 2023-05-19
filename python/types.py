# Copyright (c) 2015-2023 Vector 35 Inc
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
import typing
from typing import Generator, List, Union, Tuple, Optional, Iterable, Dict, Generic, TypeVar
from dataclasses import dataclass
import uuid

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import (
    StructureVariant, SymbolType, SymbolBinding, TypeClass, NamedTypeReferenceClass, ReferenceType, VariableSourceType,
    TypeReferenceType, MemberAccess, MemberScope, TypeDefinitionLineType, TokenEscapingType,
    NameType
)
from . import callingconvention
from . import function as _function
from . import variable
from . import architecture
from . import binaryview
from . import platform as _platform
from . import typelibrary
from . import typeparser

QualifiedNameType = Union[Iterable[Union[str, bytes]], str, 'QualifiedName']
BoolWithConfidenceType = Union[bool, 'BoolWithConfidence']
OffsetWithConfidenceType = Union[int, 'OffsetWithConfidence']
ParamsType = Union[List['Type'], List['FunctionParameter'], List[Tuple[str, 'Type']]]
MembersType = Union[List['StructureMember'], List['Type'], List[Tuple['Type', str]]]
EnumMembersType = Union[List[Tuple[str, int]], List[str], List['EnumerationMember']]
SomeType = Union['TypeBuilder', 'Type']
TypeContainer = Union['binaryview.BinaryView', 'typelibrary.TypeLibrary']
NameSpaceType = Optional[Union[str, List[str], 'NameSpace']]
TypeParserResult = typeparser.TypeParserResult
# The following are needed to prevent the type checker from getting
# confused as we have member functions in `Type` named the same thing
_int = int
_bool = bool
MemberName = str
MemberIndex = int
MemberOffset = int

TB = TypeVar('TB', bound='TypeBuilder')

def convert_integer(value: ctypes.c_uint64, signed: bool, width: int) -> int:
	if width not in [1, 2, 4, 8]:
		raise ValueError("Width must be 1, 2, 4, or 8 bytes")
	func = {
		True: {
			1: ctypes.c_int8,
			2: ctypes.c_int16,
			4: ctypes.c_int32,
			8: ctypes.c_int64
		},
		False: {
			1: ctypes.c_uint8,
			2: ctypes.c_uint16,
			4: ctypes.c_uint32,
			8: ctypes.c_uint64
		}
	}
	return func[bool(signed)][width](value).value

class QualifiedName:
	def __init__(self, name: Optional[QualifiedNameType] = None):
		self._name: List[str] = []
		if isinstance(name, str):
			self._name = [name]
		elif isinstance(name, bytes):
			self._name = [name.decode("utf-8")]
		elif isinstance(name, self.__class__):
			self._name = name._name
		elif isinstance(name, (list, tuple)):
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

	def __hash__(self):
		return hash(str(self))

	def __getitem__(self, key):
		return self.name[key]

	def __iter__(self):
		return iter(self.name)

	def _to_core_struct(self) -> core.BNQualifiedName:
		result = core.BNQualifiedName()
		name_list = (ctypes.c_char_p * len(self.name))()
		for i in range(0, len(self.name)):
			name_list[i] = self.name[i].encode("utf-8")
		result.name = name_list
		result.nameCount = len(self.name)
		result.join = "::".encode("utf-8")
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
	def name(self, value: List[str]) -> None:
		self._name = value

	@staticmethod
	def escape(name: QualifiedNameType, escaping: TokenEscapingType) -> str:
		return core.BNEscapeTypeName(str(QualifiedName(name)), escaping)

	@staticmethod
	def unescape(name: QualifiedNameType, escaping: TokenEscapingType) -> str:
		return core.BNUnescapeTypeName(str(QualifiedName(name)), escaping)


@dataclass(frozen=True)
class TypeReferenceSource:
	name: QualifiedName
	offset: int
	ref_type: TypeReferenceType

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

	def _to_core_struct(self) -> core.BNNameSpace:
		result = core.BNNameSpace()
		name_list = (ctypes.c_char_p * len(self.name))()
		for i in range(0, len(self.name)):
			name_list[i] = self.name[i].encode('charmap')
		result.name = name_list
		result.nameCount = len(self.name)
		return result

	@staticmethod
	def _from_core_struct(name: core.BNNameSpace) -> 'NameSpace':
		result = []
		for i in range(0, name.nameCount):
			result.append(name.name[i].decode("utf-8"))
		return NameSpace(result)

	@staticmethod
	def get_core_struct(name: Optional[Union[str, List[str], 'NameSpace']]) -> Optional[core.BNNameSpace]:
		if name is None:
			return None
		if isinstance(name, NameSpace):
			return name._to_core_struct()
		else:
			return NameSpace(name)._to_core_struct()


@dataclass(frozen=True)
class TypeDefinitionLine:
	line_type: TypeDefinitionLineType
	tokens: List['_function.InstructionTextToken']
	type: 'Type'
	root_type: 'Type'
	root_type_name: str
	base_type: Optional['NamedTypeReferenceType']
	base_offset: int
	offset: int
	field_index: int

	def __str__(self):
		return "".join(map(str, self.tokens))

	def __repr__(self):
		return f"<typeDefinitionLine {self.type}: {self}>"

	@staticmethod
	def _from_core_struct(struct: core.BNTypeDefinitionLine, platform: Optional[_platform.Platform] = None):
		tokens = _function.InstructionTextToken._from_core_struct(struct.tokens, struct.count)
		type_ = Type.create(handle=core.BNNewTypeReference(struct.type), platform=platform)
		root_type = Type.create(handle=core.BNNewTypeReference(struct.rootType), platform=platform)
		root_type_name = core.pyNativeStr(struct.rootTypeName)
		if struct.baseType:
			const_conf = BoolWithConfidence.get_core_struct(False, 0)
			volatile_conf = BoolWithConfidence.get_core_struct(False, 0)
			handle = core.BNCreateNamedTypeReference(struct.baseType, 0, 1, const_conf, volatile_conf)
			base_type = NamedTypeReferenceType(handle, platform)
		else:
			base_type = None
		return TypeDefinitionLine(struct.lineType, tokens, type_, root_type, root_type_name, base_type,
								  struct.baseOffset, struct.offset, struct.fieldIndex)

	def _to_core_struct(self):
		struct = core.BNTypeDefinitionLine()
		struct.lineType = self.line_type
		struct.tokens = _function.InstructionTextToken._get_core_struct(self.tokens)
		struct.count = len(self.tokens)
		struct.type = core.BNNewTypeReference(self.type.handle)
		struct.rootType = core.BNNewTypeReference(self.root_type.handle)
		struct.rootTypeName = self.root_type_name
		if self.base_type is None:
			struct.baseType = None
		else:
			struct.baseType = core.BNNewNamedTypeReference(self.base_type.ntr_handle)
		struct.baseOffset = self.base_offset
		struct.offset = self.offset
		struct.fieldIndex = self.field_index
		return struct


class CoreSymbol:
	def __init__(self, handle: core.BNSymbolHandle):
		self._handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeSymbol(self._handle)

	def __repr__(self):
		try:
			return f"<{self.type.name}: \"{self.full_name}\" @ {self.address:#x}>"
		except UnicodeDecodeError:
			return f"<{self.type.name}: \"{self.raw_bytes}\" @ {self.address:#x}>"

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self._handle.contents) == ctypes.addressof(other._handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self._handle.contents))

	@property
	def type(self) -> SymbolType:
		"""Symbol type (read-only)"""
		return SymbolType(core.BNGetSymbolType(self._handle))

	@property
	def binding(self) -> SymbolBinding:
		"""Symbol binding (read-only)"""
		return SymbolBinding(core.BNGetSymbolBinding(self._handle))

	@property
	def namespace(self) -> 'NameSpace':
		"""Symbol namespace (read-only)"""
		ns = core.BNGetSymbolNameSpace(self._handle)
		result = NameSpace._from_core_struct(ns)
		core.BNFreeNameSpace(ns)
		return result

	@property
	def name(self) -> str:
		"""Symbol name (read-only)"""
		return core.BNGetSymbolRawName(self._handle)

	@property
	def short_name(self) -> str:
		"""Symbol short name (read-only)"""
		return core.BNGetSymbolShortName(self._handle)

	@property
	def full_name(self) -> str:
		"""Symbol full name (read-only)"""
		return core.BNGetSymbolFullName(self._handle)

	@property
	def raw_name(self) -> str:
		"""Symbol raw name (read-only)"""
		return core.BNGetSymbolRawName(self._handle)

	@property
	def raw_bytes(self) -> bytes:
		"""Bytes of the raw symbol (read-only)"""
		count = ctypes.c_ulonglong()
		result = core.BNGetSymbolRawBytes(self._handle, count)
		assert result is not None, "core.BNGetSymbolRawBytes returned None"
		buf = ctypes.create_string_buffer(count.value)
		ctypes.memmove(buf, result, count.value)
		core.BNFreeSymbolRawBytes(result)
		return buf.raw

	@property
	def address(self) -> int:
		"""Symbol address (read-only)"""
		return core.BNGetSymbolAddress(self._handle)

	@property
	def ordinal(self) -> int:
		"""Symbol ordinal (read-only)"""
		return core.BNGetSymbolOrdinal(self._handle)

	@property
	def auto(self) -> bool:
		"""Whether the symbol was auto-defined"""
		return core.BNIsSymbolAutoDefined(self._handle)

	@property
	def handle(self):
		return self._handle


class Symbol(CoreSymbol):
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
	def __init__(
	    self, sym_type, addr, short_name, full_name=None, raw_name=None, binding=None, namespace=None, ordinal=0
	):
		if isinstance(sym_type, str):
			sym_type = SymbolType[sym_type]
		if full_name is None:
			full_name = short_name
		if raw_name is None:
			raw_name = full_name
		if binding is None:
			binding = SymbolBinding.NoBinding
		_namespace = NameSpace.get_core_struct(namespace)
		_handle = core.BNCreateSymbol(sym_type, short_name, full_name, raw_name, addr, binding, _namespace, ordinal)
		assert _handle is not None, "core.BNCreateSymbol return None"
		super(Symbol, self).__init__(_handle)


@dataclass
class FunctionParameter:
	type: SomeType
	name: str = ""
	location: Optional['variable.VariableNameAndType'] = None

	def __repr__(self):
		if (self.location is not None) and (self.location.name != self.name):
			return f"{self.type.immutable_copy().get_string_before_name()} {self.name}{self.type.immutable_copy().get_string_after_name()} @ {self.location.name}"
		return f"{self.type.immutable_copy().get_string_before_name()} {self.name}{self.type.immutable_copy().get_string_after_name()}"

	def immutable_copy(self) -> 'FunctionParameter':
		return FunctionParameter(self.type.immutable_copy(), self.name, self.location)

	def mutable_copy(self) -> 'FunctionParameter':
		return FunctionParameter(self.type.mutable_copy(), self.name, self.location)


@dataclass(frozen=True)
class OffsetWithConfidence:
	value: int
	confidence: int = core.max_confidence

	def __int__(self):
		return self.value

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return self.value == int(other)
		else:
			return (self.value, self.confidence) == (other.value, other.confidence)

	def __ne__(self, other):
		return not (self == other)

	def __gt__(self, other):
		return self.value > int(other)

	def __le__(self, other):
		return self.value <= int(other)

	def __ge__(self, other):
		return self.value >= int(other)

	def __lt__(self, other):
		return self.value < int(other)

	def _to_core_struct(self) -> core.BNOffsetWithConfidence:
		result = core.BNOffsetWithConfidence()
		result.value = self.value
		result.confidence = self.confidence
		return result

	@classmethod
	def from_core_struct(cls, core_struct: core.BNOffsetWithConfidence) -> 'OffsetWithConfidence':
		return cls(core_struct.value, core_struct.confidence)

	@staticmethod
	def get_core_struct(value: OffsetWithConfidenceType, confidence: int = core.max_confidence) -> core.BNOffsetWithConfidence:
		if isinstance(value, OffsetWithConfidence):
			return value._to_core_struct()
		else:
			return OffsetWithConfidence(value, confidence)._to_core_struct()


@dataclass(frozen=True)
class BoolWithConfidence:
	value: bool
	confidence: int = core.max_confidence

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return self.value == bool(other)
		else:
			return (self.value, self.confidence) == (other.value, other.confidence)

	def __ne__(self, other):
		return not (self == other)

	def __bool__(self):
		return self.value

	def _to_core_struct(self) -> core.BNBoolWithConfidence:
		result = core.BNBoolWithConfidence()
		result.value = self.value
		result.confidence = self.confidence
		return result

	@classmethod
	def from_core_struct(cls, core_struct: core.BNBoolWithConfidence) -> 'BoolWithConfidence':
		return cls(core_struct.value, core_struct.confidence)

	@staticmethod
	def get_core_struct(value: Union[BoolWithConfidenceType, bool], confidence: int = core.max_confidence) -> core.BNBoolWithConfidence:
		if isinstance(value, BoolWithConfidence):
			return value._to_core_struct()
		else:
			return BoolWithConfidence(value, confidence)._to_core_struct()


@dataclass
class MutableTypeBuilder(Generic[TB]):
	type: TB
	container: TypeContainer
	name: QualifiedName
	platform: Optional['_platform.Platform']
	confidence: int
	user: bool = True

	def __enter__(self) -> TB:
		return self.type

	def __exit__(self, type, value, traceback):
		if isinstance(self.container, binaryview.BinaryView):
			if self.user:
				self.container.define_user_type(self.name, self.type.immutable_copy())
			else:
				type_id = Type.generate_auto_type_id(str(uuid.uuid4()), str(self.name))
				self.container.define_type(type_id, self.name, self.type.immutable_copy())
		else:
			self.container.add_named_type(self.name, self.type.immutable_copy())


class TypeBuilder:
	"""
	All TypeBuilder objects should not be instantiated directly but created via ``.create`` APIs.
	"""
	def __init__(
	    self, handle: core.BNTypeBuilderHandle, platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	):
		assert isinstance(handle, core.BNTypeBuilderHandle), "handle isn't an instance of BNTypeBuilderHandle"
		self._handle = handle
		self.platform = platform
		self.confidence = confidence

	def __del__(self):
		if core is not None:
			core.BNFreeTypeBuilder(self._handle)

	def __eq__(self, other: 'TypeBuilder') -> bool:
		if not isinstance(other, TypeBuilder):
			raise ValueError(f"Unable compare equality of TypeBuilder and {type(other)}")
		return self.immutable_copy() == other.immutable_copy()

	def __ne__(self, other: 'TypeBuilder') -> bool:
		return not self.__eq__(other)

	def __repr__(self):
		return f"<type: mutable:{self.type_class.name} '{self}'>"

	def __str__(self):
		return str(self.immutable_copy())

	@property
	def handle(self) -> core.BNTypeHandle:
		return self.immutable_copy().handle

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	def _to_core_struct(self) -> core.BNTypeWithConfidence:
		type_conf = core.BNTypeWithConfidence()
		type_conf.type = self.handle
		type_conf.confidence = self.confidence
		return type_conf

	def immutable_copy(self):
		Types = {
		    TypeClass.VoidTypeClass: VoidType, TypeClass.BoolTypeClass: BoolType,
		    TypeClass.IntegerTypeClass: IntegerType, TypeClass.FloatTypeClass: FloatType,
		    TypeClass.PointerTypeClass: PointerType, TypeClass.ArrayTypeClass: ArrayType,
		    TypeClass.FunctionTypeClass: FunctionType, TypeClass.WideCharTypeClass: WideCharType,
		    # TypeClass.StructureTypeClass:StructureType,
		    # TypeClass.EnumerationTypeClass:EnumerationType,
		    # TypeClass.NamedTypeReferenceClass:NamedTypeReferenceType,
		}
		return Types[self.type_class](self.finalized, self.platform, self.confidence)

	def mutable_copy(self) -> 'TypeBuilder':
		return self

	@classmethod
	def create(cls):
		_ = cls
		return NotImplemented

	@classmethod
	def builder(
	    cls: typing.Type[TB], container: TypeContainer, name: 'QualifiedName', user: bool = True, platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'MutableTypeBuilder[TB]':
		return MutableTypeBuilder(cls.create(), container, name, platform, confidence, user)

	@staticmethod
	def void() -> 'VoidBuilder':
		return VoidBuilder.create()

	@staticmethod
	def bool() -> 'BoolBuilder':
		return BoolBuilder.create()

	@staticmethod
	def char(alternate_name: str = "") -> 'CharBuilder':
		return CharBuilder.create(alternate_name)

	@staticmethod
	def int(
	    width: _int, sign: BoolWithConfidenceType = BoolWithConfidence(True), altname: str = ""
	) -> 'IntegerBuilder':
		"""
		``int`` class method for creating an int Type.

		:param int width: width of the integer in bytes
		:param bool sign: optional variable representing signedness
		:param str altname: alternate name for type
		"""
		return IntegerBuilder.create(width, sign, altname)

	@staticmethod
	def float(width: _int, altname: str = "") -> 'FloatBuilder':
		"""
		``float`` class method for creating floating point Types.

		:param int width: width of the floating point number in bytes
		:param str altname: alternate name for type
		"""
		return FloatBuilder.create(width, altname)

	@staticmethod
	def wide_char(width: _int, altname: str = "") -> 'WideCharBuilder':
		"""
		``wide_char`` class method for creating wide char Types.

		:param int width: width of the wide character in bytes
		:param str altname: alternate name for type
		"""
		return WideCharBuilder.create(width, altname)

	@staticmethod
	def named_type_from_type(
	    name: QualifiedNameType, type_class: Optional[NamedTypeReferenceClass] = None
	) -> 'NamedTypeReferenceBuilder':
		return NamedTypeReferenceBuilder.named_type_from_type(name, type_class)

	@staticmethod
	def named_type_from_type_and_id(
	    type_id: str, name: QualifiedNameType, type: Optional['Type'] = None
	) -> 'NamedTypeReferenceBuilder':
		return NamedTypeReferenceBuilder.named_type_from_type_and_id(type_id, name, type)

	@staticmethod
	def named_type_from_registered_type(
	    view: 'binaryview.BinaryView', name: QualifiedName
	) -> 'NamedTypeReferenceBuilder':
		return NamedTypeReferenceBuilder.named_type_from_registered_type(view, name)

	@staticmethod
	def pointer(
	    arch: 'architecture.Architecture', type: 'Type', const: BoolWithConfidenceType = BoolWithConfidence(False),
	    volatile: BoolWithConfidenceType = BoolWithConfidence(False),
	    ref_type: ReferenceType = ReferenceType.PointerReferenceType
	) -> 'PointerBuilder':
		return PointerBuilder.create(type, arch.address_size, arch, const, volatile, ref_type)

	@staticmethod
	def pointer_of_width(
	    width: _int, type: 'Type', const: BoolWithConfidenceType = BoolWithConfidence(False),
	    volatile: BoolWithConfidenceType = BoolWithConfidence(False),
	    ref_type: ReferenceType = ReferenceType.PointerReferenceType
	) -> 'PointerBuilder':
		return PointerBuilder.create(type, width, None, const, volatile, ref_type)

	@staticmethod
	def array(type: 'Type', count: _int) -> 'ArrayBuilder':
		return ArrayBuilder.create(type, count)

	@staticmethod
	def function(
	    ret: Optional['Type'] = None, params: Optional[ParamsType] = None,
	    calling_convention: Optional['callingconvention.CallingConvention'] = None,
	    variable_arguments: Optional[BoolWithConfidenceType] = None,
	    stack_adjust: Optional[OffsetWithConfidenceType] = None
	) -> 'FunctionBuilder':
		"""
		``function`` class method for creating a function Type.

		:param Type ret: return Type of the function
		:param params: list of parameter Types
		:type params: list(Type)
		:param CallingConvention calling_convention: optional argument for the function calling convention
		:param bool variable_arguments: optional boolean, true if the function has a variable number of arguments
		"""
		return FunctionBuilder.create(ret, calling_convention, params, variable_arguments, stack_adjust)

	@staticmethod
	def structure(
	    members: Optional[MembersType] = None, packed: _bool = False,
	    type: StructureVariant = StructureVariant.StructStructureType
	) -> 'StructureBuilder':
		return StructureBuilder.create(members, type=type, packed=packed)

	@staticmethod
	def union(members: Optional[MembersType] = None, packed: _bool = False) -> 'StructureBuilder':
		return StructureBuilder.create(members, type=StructureVariant.UnionStructureType, packed=packed)

	@staticmethod
	def class_type(members: Optional[MembersType] = None, packed: _bool = False) -> 'StructureBuilder':
		return StructureBuilder.create(members, type=StructureVariant.ClassStructureType, packed=packed)

	@staticmethod
	def enumeration(
	    arch: Optional['architecture.Architecture'] = None, members: Optional[EnumMembersType] = None,
	    width: Optional[_int] = None, sign: BoolWithConfidenceType = BoolWithConfidence(False)
	) -> 'EnumerationBuilder':
		return EnumerationBuilder.create(members, width, arch, sign)

	@staticmethod
	def named_type_reference(
	    type_class: NamedTypeReferenceClass, name: QualifiedName, type_id: Optional[str] = None, alignment: _int = 1,
	    width: _int = 0, const: BoolWithConfidenceType = BoolWithConfidence(False),
	    volatile: BoolWithConfidenceType = BoolWithConfidence(False)
	) -> 'NamedTypeReferenceBuilder':
		return NamedTypeReferenceBuilder.create(
		    type_class, type_id, name, width, alignment, None, core.max_confidence, const, volatile
		)

	@property
	def width(self) -> _int:
		return core.BNGetTypeBuilderWidth(self._handle)

	def __len__(self):
		return self.width

	@property
	def finalized(self):
		type_handle = core.BNFinalizeTypeBuilder(self._handle)
		assert type_handle is not None, "core.BNFinalizeTypeBuilder returned None"
		type_handle = core.BNNewTypeReference(type_handle)
		assert type_handle is not None, "core.BNNewTypeReference returned None"
		return type_handle

	@property
	def const(self) -> BoolWithConfidence:
		"""Whether type is const (read/write)"""
		result = core.BNIsTypeBuilderConst(self._handle)
		return BoolWithConfidence(result.value, confidence=result.confidence)

	@const.setter
	def const(
	    self, value: BoolWithConfidenceType
	) -> None: # We explicitly allow 'set' type to be different than 'get' type
		core.BNTypeBuilderSetConst(self._handle, BoolWithConfidence.get_core_struct(value))

	@property
	def volatile(self) -> BoolWithConfidence:
		"""Whether type is volatile (read/write)"""
		result = core.BNIsTypeBuilderVolatile(self._handle)
		return BoolWithConfidence(result.value, confidence=result.confidence)

	@volatile.setter
	def volatile(
	    self, value: BoolWithConfidenceType
	) -> None: # We explicitly allow 'set' type to be different than 'get' type
		core.BNTypeBuilderSetVolatile(self._handle, BoolWithConfidence.get_core_struct(value))

	@property
	def alignment(self) -> _int:
		return core.BNGetTypeBuilderAlignment(self._handle)

	@property
	def child(self) -> 'Type':
		type_conf = core.BNGetTypeBuilderChildType(self._handle)
		assert type_conf is not None, "core.BNGetTypeBuilderChildType returned None"
		return Type.create(type_conf.type, self.platform, type_conf.confidence)

	@child.setter
	def child(self, value: SomeType) -> None:
		core.BNTypeBuilderSetChildType(self._handle, value.immutable_copy()._to_core_struct())

	@property
	def alternate_name(self) -> Optional[str]:
		return core.BNGetTypeBuilderAlternateName(self._handle)

	@alternate_name.setter
	def alternate_name(self, name: str) -> None:
		core.BNTypeBuilderSetAlternateName(self._handle, name)

	@property
	def system_call_number(self) -> Optional[_int]:
		"""Gets/Sets the system call number for a FunctionType object if one exists otherwise None"""
		if not core.BNTypeBuilderIsSystemCall(self._handle):
			return None
		return core.BNTypeBuilderGetSystemCallNumber(self._handle)

	@system_call_number.setter
	def system_call_number(self, value: _int) -> None:
		core.BNTypeBuilderSetSystemCallNumber(self._handle, True, value)

	def clear_system_call(self) -> None:
		core.BNTypeBuilderSetSystemCallNumber(self._handle, False, 0)

	@property
	def type_class(self) -> TypeClass:
		return TypeClass(core.BNGetTypeBuilderClass(self._handle))

	@property
	def signed(self) -> BoolWithConfidence:
		return BoolWithConfidence.from_core_struct(core.BNIsTypeBuilderSigned(self._handle))

	@signed.setter
	def signed(self, value: BoolWithConfidenceType) -> None:
		_value = BoolWithConfidence.get_core_struct(value)
		core.BNTypeBuilderSetSigned(self._handle, _value)

	@property
	def children(self) -> List['TypeBuilder']:
		return []

class VoidBuilder(TypeBuilder):
	@classmethod
	def create(cls, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence) -> 'VoidBuilder':
		handle = core.BNCreateVoidTypeBuilder()
		assert handle is not None, "core.BNCreateVoidTypeBuilder returned None"
		return cls(handle, platform, confidence)


class BoolBuilder(TypeBuilder):
	@classmethod
	def create(cls, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence) -> 'BoolBuilder':
		handle = core.BNCreateBoolTypeBuilder()
		assert handle is not None, "core.BNCreateBoolTypeBuilder returned None"
		return cls(handle, platform, confidence)


class IntegerBuilder(TypeBuilder):
	@classmethod
	def create(
	    cls, width: int, sign: BoolWithConfidenceType = True, alternate_name: str = "",
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	) -> 'IntegerBuilder':
		_sign = BoolWithConfidence.get_core_struct(sign)
		handle = core.BNCreateIntegerTypeBuilder(width, _sign, alternate_name)
		assert handle is not None, "core.BNCreateIntegerTypeBuilder returned None"
		return cls(handle, platform, confidence)


class CharBuilder(IntegerBuilder):
	@classmethod
	def create(
	    cls, alternate_name: str = "", platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	) -> 'CharBuilder':
		handle = core.BNCreateIntegerTypeBuilder(1, BoolWithConfidence.get_core_struct(False), alternate_name)
		assert handle is not None, "BNCreateIntegerTypeBuilder returned None"
		return cls(handle, platform, confidence)


class FloatBuilder(TypeBuilder):
	@classmethod
	def create(
	    cls, width: int, alternate_name: str = "", platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'FloatBuilder':
		handle = core.BNCreateFloatTypeBuilder(width, alternate_name)
		assert handle is not None, "core.BNCreateFloatTypeBuilder returned None"
		return cls(handle, platform, confidence)


class WideCharBuilder(TypeBuilder):
	@classmethod
	def create(
	    cls, width: int, alternate_name: str = "", platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'WideCharBuilder':
		handle = core.BNCreateWideCharTypeBuilder(width, alternate_name)
		assert handle is not None, "core.BNCreateWideCharTypeBuilder returned None"
		return cls(handle, platform, confidence)


class PointerBuilder(TypeBuilder):
	@classmethod
	def create(
	    cls, type: 'Type', width: int = 4, arch: Optional['architecture.Architecture'] = None,
	    const: BoolWithConfidenceType = False, volatile: BoolWithConfidenceType = False,
	    ref_type: ReferenceType = ReferenceType.PointerReferenceType, platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'PointerBuilder':
		if width is not None:
			_width = width
		elif arch is not None:
			_width = arch.address_size
		else:
			raise ValueError("Must specify either a width or architecture when creating a pointer")

		_const = BoolWithConfidence.get_core_struct(const)
		_volatile = BoolWithConfidence.get_core_struct(volatile)
		handle = core.BNCreatePointerTypeBuilderOfWidth(_width, type._to_core_struct(), _const, _volatile, ref_type)
		assert handle is not None, "BNCreatePointerTypeBuilderOfWidth returned None"
		return cls(handle, platform, confidence)

	@property
	def target(self) -> 'TypeBuilder':
		return self.immutable_target.mutable_copy()

	@property
	def immutable_target(self) -> 'Type':
		return self.child

	@property
	def children(self) -> List[TypeBuilder]:
		return [self.target]

	@property
	def offset(self) -> int:
		return core.BNGetTypeBuilderOffset(self._handle)

	@offset.setter
	def offset(self, offset: int) -> None:
		core.BNSetTypeBuilderOffset(self._handle, offset)

	@property
	def origin(self) -> Optional[Tuple['QualifiedName', int]]:
		ntr_handle = core.BNGetTypeBuilderNamedTypeReference(self._handle)
		if ntr_handle is None:
			return None
		name = core.BNGetTypeReferenceName(ntr_handle)
		core.BNFreeNamedTypeReference(ntr_handle)
		if name is None:
			return None
		qn = QualifiedName._from_core_struct(name)
		core.BNFreeQualifiedName(name)
		return (qn, self.offset)

	@origin.setter
	def origin(self, origin: 'NamedTypeReferenceType'):
		core.BNSetTypeBuilderNamedTypeReference(self._handle, origin.ntr_handle)


class ArrayBuilder(TypeBuilder):
	@classmethod
	def create(
	    cls, type: SomeType, element_count: int, platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'ArrayBuilder':
		handle = core.BNCreateArrayTypeBuilder(type._to_core_struct(), element_count)
		assert handle is not None, "BNCreateArrayTypeBuilder returned None"
		return cls(handle, platform, confidence)

	@property
	def count(self) -> int:
		return core.BNGetTypeBuilderElementCount(self._handle)

	@property
	def element_type(self) -> TypeBuilder:
		return self.child.mutable_copy()

	@property
	def children(self) -> List[TypeBuilder]:
		return [self.element_type]

class FunctionBuilder(TypeBuilder):
	@classmethod
	def create(
	    cls, return_type: Optional[SomeType] = None,
	    calling_convention: Optional['callingconvention.CallingConvention'] = None, params: Optional[ParamsType] = None,
	    var_args: Optional[BoolWithConfidenceType] = None, stack_adjust: Optional[OffsetWithConfidenceType] = None,
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence,
	    can_return: Optional[BoolWithConfidence] = None, reg_stack_adjust: Optional[Dict['architecture.RegisterName', OffsetWithConfidenceType]] = None,
	    return_regs: Optional[Union['RegisterSet', List['architecture.RegisterType']]] = None,
	    name_type: 'NameType' = NameType.NoNameType
	) -> 'FunctionBuilder':
		param_buf = FunctionBuilder._to_core_struct(params)
		if return_type is None:
			ret_conf = Type.void()._to_core_struct()
		else:
			ret_conf = return_type._to_core_struct()

		conv_conf = core.BNCallingConventionWithConfidence()
		if calling_convention is None:
			conv_conf.convention = None
			conv_conf.confidence = 0
		else:
			conv_conf.convention = calling_convention.handle
			conv_conf.confidence = calling_convention.confidence

		if reg_stack_adjust is None:
			reg_stack_adjust = {}
		reg_stack_adjust_regs = (ctypes.c_uint32 * len(reg_stack_adjust))()
		reg_stack_adjust_values = (core.BNOffsetWithConfidence * len(reg_stack_adjust))()

		for i, (reg, adjust) in enumerate(reg_stack_adjust.items()):
			reg_stack_adjust_regs[i] = reg
			reg_stack_adjust_values[i].value = adjust.value
			reg_stack_adjust_values[i].confidence = adjust.confidence

		return_regs_set = core.BNRegisterSetWithConfidence()
		if return_regs is None or platform is None:
			return_regs_set.count = 0
			return_regs_set.confidence = 0
		else:
			return_regs_set.count = len(return_regs)
			return_regs_set.confidence = 255
			return_regs_set.regs = (ctypes.c_uint32 * len(return_regs))()

			for i, reg in enumerate(return_regs):
				return_regs_set[i] = platform.arch.get_reg_index(reg)

		if var_args is None:
			vararg_conf = BoolWithConfidence.get_core_struct(False, 0)
		else:
			vararg_conf = BoolWithConfidence.get_core_struct(var_args, core.max_confidence)

		if can_return is None:
			can_return_conf = BoolWithConfidence.get_core_struct(True, 0)
		else:
			can_return_conf = BoolWithConfidence.get_core_struct(can_return, core.max_confidence)

		if stack_adjust is None:
			stack_adjust_conf = OffsetWithConfidence.get_core_struct(0, 0)
		else:
			stack_adjust_conf = OffsetWithConfidence.get_core_struct(stack_adjust, core.max_confidence)
		if params is None:
			params = []
		handle = core.BNCreateFunctionTypeBuilder(
		    ret_conf, conv_conf, param_buf, len(params), vararg_conf, can_return_conf, stack_adjust_conf,
		    reg_stack_adjust_regs, reg_stack_adjust_values, len(reg_stack_adjust),
		    return_regs_set, name_type
		)
		assert handle is not None, "BNCreateFunctionTypeBuilder returned None"
		return cls(handle, platform, confidence)

	@property
	def immutable_return_value(self) -> 'Type':
		return self.child

	@property
	def return_value(self) -> TypeBuilder:
		return self.child.mutable_copy()

	@return_value.setter
	def return_value(self, value: SomeType) -> None:
		self.child = value

	def append(self, type: Union[SomeType, FunctionParameter], name: str = ""):
		if isinstance(type, FunctionParameter):
			self.parameters = [*self.parameters, type]
		else:
			self.parameters = [*self.parameters, FunctionParameter(type, name)]

	@property
	def calling_convention(self) -> 'callingconvention.CallingConvention':
		cc = core.BNGetTypeBuilderCallingConvention(self._handle)
		return callingconvention.CallingConvention(handle=core.BNNewCallingConventionReference(cc.convention))

	@property
	def can_return(self) -> BoolWithConfidence:
		return BoolWithConfidence.from_core_struct(core.BNFunctionTypeBuilderCanReturn(self._handle))

	@can_return.setter
	def can_return(self, value: BoolWithConfidenceType) -> None:
		core.BNSetFunctionTypeBuilderCanReturn(self._handle, BoolWithConfidence.get_core_struct(value))

	@property
	def stack_adjust(self) -> OffsetWithConfidence:
		return OffsetWithConfidence.from_core_struct(core.BNGetTypeBuilderStackAdjustment(self._handle))

	@property
	def stack_adjustment(self) -> OffsetWithConfidence:
		return OffsetWithConfidence.from_core_struct(core.BNGetTypeBuilderStackAdjustment(self._handle))

	@stack_adjustment.setter
	def stack_adjustment(self, value: OffsetWithConfidenceType) -> None:
		if isinstance(value, int):
			_value = OffsetWithConfidence(value)
		else:
			_value = value
		core.BNTypeBuilderSetStackAdjustment(self._handle, _value._to_core_struct())

	@property
	def parameters(self) -> List[FunctionParameter]:
		"""Type parameters list (read-only)"""
		count = ctypes.c_ulonglong()
		params = core.BNGetTypeBuilderParameters(self._handle, count)
		assert params is not None, "core.BNGetTypeBuilderParameters returned None"
		result = []
		for i in range(0, count.value):
			param_type = Type.create(
			    core.BNNewTypeReference(params[i].type), platform=self.platform, confidence=params[i].typeConfidence
			)
			if params[i].defaultLocation:
				param_location = None
			else:
				name = params[i].name
				if (params[i].location.type
				    == VariableSourceType.RegisterVariableSourceType) and (self.platform is not None):
					name = self.platform.arch.get_reg_name(params[i].location.storage)
				elif params[i].location.type == VariableSourceType.StackVariableSourceType:
					name = "arg_%x" % params[i].location.storage
				param_location = variable.VariableNameAndType(
				    params[i].location.type, params[i].location.index, params[i].location.storage, name, param_type
				)
			result.append(FunctionParameter(param_type, params[i].name, param_location))
		core.BNFreeTypeParameterList(params, count.value)
		return result

	@property
	def variable_arguments(self) -> BoolWithConfidence:
		return BoolWithConfidence.from_core_struct(core.BNTypeBuilderHasVariableArguments(self._handle))

	@staticmethod
	def _to_core_struct(params: Optional[ParamsType] = None):
		if params is None:
			params = []
		param_buf = (core.BNFunctionParameter * len(params))()
		for i, param in enumerate(params):
			core_param = param_buf[i]
			if isinstance(param, (Type, TypeBuilder)):
				assert param.handle is not None, "Attempting to construct function parameter without properly constructed type"
				core_param.name = ""
				core_param.type = param.handle
				core_param.typeConfidence = param.confidence
				core_param.defaultLocation = True
			elif isinstance(param, FunctionParameter):
				assert param.type is not None, "Attempting to construct function parameter without properly constructed type"
				core_param.name = param.name
				core_param.type = param.type.handle
				core_param.typeConfidence = param.type.confidence
				if param.location is None:
					core_param.defaultLocation = True
				else:
					core_param.defaultLocation = False
					core_param.location.type = param.location.source_type
					core_param.location.index = param.location.index
					core_param.location.storage = param.location.storage
			elif isinstance(param, tuple):
				name, _type = param
				if not isinstance(name, str) or not isinstance(_type, (Type, TypeBuilder)):
					raise ValueError(f"Conversion from unsupported function parameter type {type(param)}")
				core_param.name = name
				core_param.type = _type.handle
				core_param.typeConfidence = _type.confidence
				core_param.defaultLocation = True
			else:
				raise ValueError(f"Conversion from unsupported function parameter type {type(param)}")
		return param_buf

	@parameters.setter
	def parameters(self, params: List[FunctionParameter]) -> None:
		core.BNSetFunctionTypeBuilderParameters(self._handle, FunctionBuilder._to_core_struct(params), len(params))

	@property
	def children(self) -> List[TypeBuilder]:
		return [self.child.mutable_copy(), *[param.type.mutable_copy() for param in self.parameters]]

@dataclass
class StructureMember:
	type: 'Type'
	name: str
	offset: int
	access: MemberAccess = MemberAccess.NoAccess
	scope: MemberScope = MemberScope.NoScope

	def __repr__(self):
		if len(self.name) == 0:
			return f"<member: {self.type}, offset {self.offset:#x}>"
		return f"<{self.type.get_string_before_name()} {self.name}{self.type.get_string_after_name()}, offset {self.offset:#x}>"

	def __len__(self):
		return len(self.type)


@dataclass
class InheritedStructureMember:
	base: 'NamedTypeReferenceType'
	base_offset: int
	member: StructureMember
	member_index: int

	def __repr__(self):
		if self.base is None:
			return f"<member index {self.member_index}: {repr(self.member)}>"
		return f"<inherited from {self.base.name} @ {self.base_offset:#x} index {self.member_index}: {repr(self.member)}>"

	def __len__(self):
		return len(self.member.type)


@dataclass
class BaseStructure:
	type: 'NamedTypeReferenceType'
	offset: int
	width: int

	def __init__(self, type: Union['NamedTypeReferenceType', 'StructureType'], offset: int, width: int = 0):
		if isinstance(type, StructureType):
			self.type = type.registered_name
			self.offset = offset
			self.width = type.width
		else:
			self.type = type
			self.offset = offset
			self.width = width

	def __repr__(self):
		return f"<base: {repr(self.type)}, offset {self.offset:#x}, width: {self.width:#x}>"

	def _to_core_struct(self):
		result = core.BNBaseStructure()
		result.type = self.type.ntr_handle
		result.offset = self.offset
		result.width = self.width
		return result

	@staticmethod
	def _from_core_struct(core_obj: core.BNBaseStructure, platform: Optional['_platform.Platform'] = None):
		const_conf = BoolWithConfidence.get_core_struct(False, 0)
		volatile_conf = BoolWithConfidence.get_core_struct(False, 0)
		handle = core.BNCreateNamedTypeReference(core_obj.type, 0, 1, const_conf, volatile_conf)
		return BaseStructure(NamedTypeReferenceType(handle, platform), core_obj.offset, core_obj.width)


class StructureBuilder(TypeBuilder):
	def __init__(
	    self, handle: core.BNTypeBuilderHandle, builder_handle: core.BNStructureBuilderHandle,
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	):
		super(StructureBuilder, self).__init__(handle, platform, confidence)
		assert builder_handle is not None, "Can't instantiate Structure with builder_handle set to None"
		self.builder_handle = builder_handle

	@staticmethod
	def _add_members_to_builder(structure_builder_handle, members: Optional[MembersType]) -> None:
		if members is None:
			members = []
		for member in members:
			if isinstance(member, Tuple):
				_type, _name = member
				core.BNAddStructureBuilderMember(
				    structure_builder_handle, _type._to_core_struct(), _name, MemberAccess.NoAccess, MemberScope.NoScope
				)
			elif isinstance(member, StructureMember):
				core.BNAddStructureBuilderMemberAtOffset(
				    structure_builder_handle, member.type._to_core_struct(), member.name, member.offset, False,
				    member.access, member.scope
				)
			elif isinstance(member, (TypeBuilder, Type)):
				core.BNAddStructureBuilderMember(
				    structure_builder_handle, member._to_core_struct(), "", MemberAccess.NoAccess, MemberScope.NoScope
				)
			else:
				raise ValueError(f"Structure member type {member} not supported")

	def _add_members(self, members):
		StructureBuilder._add_members_to_builder(self.builder_handle, members)

	@classmethod
	def create(
	    cls, members: Optional[MembersType] = None, type: StructureVariant = StructureVariant.StructStructureType,
	    packed: bool = False, width: Optional[int] = None, platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'StructureBuilder':
		structure_builder_handle = core.BNCreateStructureBuilderWithOptions(type, packed)
		assert structure_builder_handle is not None, "core.BNCreateStructureBuilderWithOptions returned None"
		if width is not None:
			core.BNSetStructureBuilderWidth(structure_builder_handle, width)
		StructureBuilder._add_members_to_builder(structure_builder_handle, members)
		type_builder_handle = core.BNCreateStructureTypeBuilderWithBuilder(structure_builder_handle)
		assert type_builder_handle is not None, "core.BNCreateStructureTypeBuilderWithBuilder returned None"
		return cls(type_builder_handle, structure_builder_handle, platform, confidence)

	def immutable_copy(self) -> 'StructureType':
		assert self.builder_handle is not None
		structure_handle = core.BNFinalizeStructureBuilder(self.builder_handle)
		assert structure_handle is not None, "core.BNFinalizeStructureBuilder returned None"
		handle = core.BNCreateStructureType(structure_handle)
		assert handle is not None, "core.BNCreateStructureType returned None"
		return StructureType(handle, self.platform, self.confidence)

	@property
	def members(self) -> List[StructureMember]:
		"""Structure member list (read-only)"""
		count = ctypes.c_ulonglong()
		members = core.BNGetStructureBuilderMembers(self.builder_handle, count)
		assert members is not None, "core.BNGetStructureBuilderMembers returned None"
		try:
			result = []
			for i in range(0, count.value):
				t = Type.create(core.BNNewTypeReference(members[i].type), confidence=members[i].typeConfidence)
				result.append(
				    StructureMember(
				        t, members[i].name, members[i].offset, MemberAccess(members[i].access),
				        MemberScope(members[i].scope)
				    )
				)
			return result
		finally:
			core.BNFreeStructureMemberList(members, count.value)

	@members.setter
	def members(self, members: Optional[MembersType] = None) -> None:
		count = len(self.members)
		# remove members in reverse order
		for i in reversed(range(count)):
			self.remove(i)
		self._add_members(members)

	@property
	def base_structures(self) -> List[BaseStructure]:
		"""Base structure list. Offsets that are not defined by this structure will be filled
		    in by the fields of the base structure(s)."""
		count = ctypes.c_ulonglong()
		bases = core.BNGetBaseStructuresForStructureBuilder(self.builder_handle, count)
		try:
			result = []
			for i in range(0, count.value):
				result.append(BaseStructure._from_core_struct(bases[i], self.platform))
			return result
		finally:
			core.BNFreeBaseStructureList(bases, count.value)

	@base_structures.setter
	def base_structures(self, value: List[BaseStructure]) -> None:
		bases = (core.BNBaseStructure * len(value))()
		for i in range(0, len(value)):
			bases[i] = value[i]._to_core_struct()
		core.BNSetBaseStructuresForStructureBuilder(self.builder_handle, bases, len(value))

	@property
	def packed(self) -> bool:
		return core.BNIsStructureBuilderPacked(self.builder_handle)

	@packed.setter
	def packed(self, value: bool) -> None:
		core.BNSetStructureBuilderPacked(self.builder_handle, value)

	@property
	def alignment(self) -> int:
		return core.BNGetStructureBuilderAlignment(self.builder_handle)

	@alignment.setter
	def alignment(self, value: int) -> None:
		core.BNSetStructureBuilderAlignment(self.builder_handle, value)

	@property
	def width(self) -> int:
		return core.BNGetStructureBuilderWidth(self.builder_handle)

	@width.setter
	def width(self, value: int) -> None:
		core.BNSetStructureBuilderWidth(self.builder_handle, value)

	@property
	def pointer_offset(self) -> int:
		return core.BNGetStructureBuilderPointerOffset(self.builder_handle)

	@pointer_offset.setter
	def pointer_offset(self, value: int) -> None:
		core.BNSetStructureBuilderPointerOffset(self.builder_handle, value)

	@property
	def union(self) -> bool:
		return core.BNIsStructureBuilderUnion(self.builder_handle)

	@property
	def propagate_data_var_refs(self) -> bool:
		return core.BNStructureBuilderPropagatesDataVariableReferences(self.builder_handle)

	@propagate_data_var_refs.setter
	def propagate_data_var_refs(self, value: bool) -> None:
		core.BNSetStructureBuilderPropagatesDataVariableReferences(self.builder_handle, value)

	@property
	def type(self) -> StructureVariant:
		return StructureVariant(core.BNGetStructureBuilderType(self.builder_handle))

	@type.setter
	def type(self, value: StructureVariant) -> None:
		core.BNSetStructureBuilderType(self.builder_handle, value)

	def __getitem__(self, name: str) -> Optional[StructureMember]:
		member = core.BNGetStructureBuilderMemberByName(self.builder_handle, name)
		if member is None:
			return None
		try:
			return StructureMember(
			    Type(core.BNNewTypeReference(member.contents.type), confidence=member.contents.typeConfidence),
			    member.contents.name, member.contents.offset, MemberAccess(member.contents.access),
			    MemberScope(member.contents.scope)
			)
		finally:
			core.BNFreeStructureMember(member)

	def __iter__(self) -> Generator[StructureMember, None, None]:
		for member in self.members:
			yield member

	def __len__(self) -> int:
		return self.width

	def member_at_offset(self, offset: int) -> Optional[StructureMember]:
		for member in self.members:
			if member.offset == offset:
				return member
		return None

	def index_by_name(self, name: MemberName) -> Optional[MemberIndex]:
		for i, member in enumerate(self.members):
			if member.name == name:
				return i
		return None

	def index_by_offset(self, offset: MemberOffset) -> Optional[MemberIndex]:
		for i, member in enumerate(self.members):
			if member.offset == offset:
				return i
		return None

	def replace(self, index: int, type: SomeType, name: str = "", overwrite_existing: bool = True):
		core.BNReplaceStructureBuilderMember(
		    self.builder_handle, index, type._to_core_struct(), name, overwrite_existing
		)

	def remove(self, index: int):
		core.BNRemoveStructureBuilderMember(self.builder_handle, index)

	def insert(
	    self, offset: int, type: SomeType, name: str = "", overwrite_existing: bool = True,
	    access: MemberAccess = MemberAccess.NoAccess, scope: MemberScope = MemberScope.NoScope
	):
		core.BNAddStructureBuilderMemberAtOffset(
		    self.builder_handle, type._to_core_struct(), name, offset, overwrite_existing, access, scope
		)

	def append(
	    self, type: SomeType, name: MemberName = "", access: MemberAccess = MemberAccess.NoAccess,
	    scope: MemberScope = MemberScope.NoScope
	) -> 'StructureBuilder':
		# appends a member at the end of the structure growing the structure
		core.BNAddStructureBuilderMember(self.builder_handle, type._to_core_struct(), name, access, scope)
		return self

	def add_member_at_offset(
	    self, name: MemberName, type: SomeType, offset: MemberOffset, overwrite_existing: bool = True,
	    access: MemberAccess = MemberAccess.NoAccess, scope: MemberScope = MemberScope.NoScope
	) -> 'StructureBuilder':
		# Adds structure member to the given offset optionally clearing any members within the range offset-offset+len(type)
		core.BNAddStructureBuilderMemberAtOffset(
		    self.builder_handle, type._to_core_struct(), name, offset, overwrite_existing, access, scope
		)
		return self

	@property
	def children(self) -> List[TypeBuilder]:
		return [member.type.mutable_copy() for member in self.members]

@dataclass(frozen=True)
class EnumerationMember:
	name: str
	value: Optional[int] = None

	def __repr__(self):
		value = f"{self.value:#x}" if self.value is not None else "auto()"
		return f"<{self.name} = {value}>"

	def __int__(self) -> Optional[int]:
		return self.value


class EnumerationBuilder(TypeBuilder):
	def __init__(
	    self, handle: core.BNTypeBuilderHandle, enum_builder_handle: core.BNEnumerationBuilderHandle,
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	):
		super(EnumerationBuilder, self).__init__(handle, platform, confidence)
		assert isinstance(enum_builder_handle, core.BNEnumerationBuilderHandle)
		self.enum_builder_handle = enum_builder_handle

	@classmethod
	def create(
	    cls, members: Optional[EnumMembersType] = None, width: Optional[int] = None,
	    arch: Optional['architecture.Architecture'] = None, sign: BoolWithConfidenceType = False,
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	) -> 'EnumerationBuilder':

		if members is None:
			members = []

		if width is None or width == 0:
			_width = 4 if arch is None else arch.default_int_size
		else:
			_width = width

		_sign = BoolWithConfidence.get_core_struct(sign)

		enum_builder_handle = core.BNCreateEnumerationBuilder()
		assert enum_builder_handle is not None, "core.BNCreateEnumerationBuilder returned None"
		EnumerationBuilder._add_members(enum_builder_handle, members)
		type_builder_handle = core.BNCreateEnumerationTypeBuilderWithBuilder(None, enum_builder_handle, _width, _sign)
		assert type_builder_handle is not None, "core.BNCreateEnumerationTypeBuilderWithBuilder returned None"
		return cls(type_builder_handle, enum_builder_handle, platform, confidence)

	def immutable_copy(self) -> 'EnumerationType':
		enum_handle = core.BNFinalizeEnumerationBuilder(self.enum_builder_handle)
		assert enum_handle is not None, "core.BNFinalizeEnumerationBuilder returned None"
		_signed = BoolWithConfidence.get_core_struct(self.signed)
		handle = core.BNCreateEnumerationType(None, enum_handle, self.width, _signed)
		assert handle is not None, "core.BNCreateEnumerationType returned None"
		return EnumerationType(handle, self.platform, self.confidence)

	@property
	def members(self) -> List[EnumerationMember]:
		"""Enumeration member list (read-only)"""
		count = ctypes.c_ulonglong()
		members = core.BNGetEnumerationBuilderMembers(self.enum_builder_handle, count)
		assert members is not None, "core.BNGetEnumerationBuilderMembers returned None"
		result = []

		try:
			for i in range(count.value):
				value = convert_integer(members[i].value, self.signed, self.width)
				result.append(
				    EnumerationMember(members[i].name, value if not members[i].isDefault else None)
				)
			return result
		finally:
			core.BNFreeEnumerationMemberList(members, count.value)

	@members.setter
	def members(self, members: EnumMembersType) -> None:
		for i in reversed(range(len(self.members))):
			self.remove(i)
		EnumerationBuilder._add_members(self.enum_builder_handle, members)

	@staticmethod
	def _add_members(enum_builder_handle, members: EnumMembersType):
		for i, member in enumerate(members):
			value = None
			if isinstance(member, Tuple):
				name, value = member
			elif isinstance(member, EnumerationMember):
				name = member.name
				value = member.value
			else:
				if not isinstance(member, str):
					raise ValueError(f"Member type {member} not supported")
				name = member

			if value is None:
				core.BNAddEnumerationBuilderMember(enum_builder_handle, name)
			else:
				core.BNAddEnumerationBuilderMemberWithValue(enum_builder_handle, name, value)

	def append(self, name: str, value: Optional[int] = None) -> 'EnumerationBuilder':
		EnumerationBuilder._add_members(self.enum_builder_handle, [EnumerationMember(name, value)])
		return self

	def remove(self, i: int) -> 'EnumerationBuilder':
		core.BNRemoveEnumerationBuilderMember(self.enum_builder_handle, i)
		return self

	def replace(self, i: int, name: str, value: int) -> 'EnumerationBuilder':
		core.BNReplaceEnumerationBuilderMember(self.enum_builder_handle, i, name, value)
		return self

	def __iter__(self) -> Generator[EnumerationMember, None, None]:
		for member in self.members:
			yield member

	def __getitem__(self, value: Union[str, int, slice]):
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

	def __setitem__(self, item: Union[str, int], value: Union[Optional[int], EnumerationMember]):
		if isinstance(item, str):
			for i, member in enumerate(self.members):
				if member.name == item:
					self.replace(i, member.name, value)
		elif isinstance(item, int) and isinstance(value, EnumerationMember):
			self.replace(item, value.name, value.value)
		else:
			raise ValueError("Invalid type for Enumeration.__setitem__")


class NamedTypeReferenceBuilder(TypeBuilder):
	def __init__(
	    self, handle: core.BNTypeBuilderHandle, ntr_builder_handle: core.BNNamedTypeReferenceBuilderHandle,
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	):
		assert ntr_builder_handle is not None, "Failed to construct NameTypeReference"
		assert handle is not None, "Failed to construct NameTypeReference"
		assert isinstance(
		    ntr_builder_handle, core.BNNamedTypeReferenceBuilderHandle
		), "Failed to construct NameTypeReference"
		super(NamedTypeReferenceBuilder, self).__init__(handle, platform, confidence)
		self.ntr_builder_handle = ntr_builder_handle

	@classmethod
	def create(
	    cls, type_class: NamedTypeReferenceClass = NamedTypeReferenceClass.UnknownNamedTypeClass,
	    type_id: Optional[str] = None, name: QualifiedNameType = "", width: int = 0, align: int = 1,
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence,
	    const: BoolWithConfidenceType = False, volatile: BoolWithConfidenceType = False
	) -> 'NamedTypeReferenceBuilder':
		ntr_builder_handle = core.BNCreateNamedTypeBuilder(type_class, type_id, QualifiedName(name)._to_core_struct())
		assert ntr_builder_handle is not None, "core.BNCreateNamedTypeBuilder returned None"

		_const = BoolWithConfidence.get_core_struct(const)
		_volatile = BoolWithConfidence.get_core_struct(volatile)
		type_builder_handle = core.BNCreateNamedTypeReferenceBuilderWithBuilder(
		    ntr_builder_handle, width, align, _const, _volatile
		)
		assert type_builder_handle is not None, "core.BNCreateNamedTypeReferenceBuilderWithBuilder returned None"
		return cls(type_builder_handle, ntr_builder_handle, platform, confidence)

	def immutable_copy(self) -> 'NamedTypeReferenceType':
		ntr_handle = core.BNFinalizeNamedTypeReferenceBuilder(self.ntr_builder_handle)
		assert ntr_handle is not None, "core.BNFinalizeEnumerationBuilder returned None"

		_const = BoolWithConfidence.get_core_struct(self.const)
		_volatile = BoolWithConfidence.get_core_struct(self.volatile)

		handle = core.BNCreateNamedTypeReference(ntr_handle, self.width, self.alignment, _const, _volatile)
		assert handle is not None, "core.BNCreateEnumerationType returned None"
		return NamedTypeReferenceType(handle, self.platform, self.confidence)

	@property
	def name(self) -> QualifiedName:
		return QualifiedName._from_core_struct(core.BNGetTypeReferenceBuilderName(self.ntr_builder_handle))

	@property
	def id(self) -> str:
		return core.BNGetTypeReferenceBuilderId(self.ntr_builder_handle)

	@property
	def type_id(self) -> str:
		return core.BNGetTypeReferenceBuilderId(self.ntr_builder_handle)

	@property
	def named_type_class(self) -> NamedTypeReferenceClass:
		return NamedTypeReferenceClass(core.BNGetTypeReferenceBuilderClass(self.ntr_builder_handle))

	@staticmethod
	def named_type(
	    named_type: 'NamedTypeReferenceBuilder', width: int = 0, align: int = 1,
	    const: BoolWithConfidenceType = BoolWithConfidence(False),
	    volatile: BoolWithConfidenceType = BoolWithConfidence(False)
	) -> 'NamedTypeReferenceBuilder':
		return NamedTypeReferenceBuilder.create(
		    named_type.named_type_class, named_type.id, named_type.name, width, align, None, core.max_confidence, const,
		    volatile
		)

	@staticmethod
	def named_type_from_type_and_id(
	    type_id: str, name: QualifiedNameType, type: Optional['Type'] = None
	) -> 'NamedTypeReferenceBuilder':
		if type is None:
			return NamedTypeReferenceBuilder.create(NamedTypeReferenceClass.UnknownNamedTypeClass, type_id, name)
		elif type.type_class == TypeClass.StructureTypeClass:
			if type.type == StructureVariant.StructStructureType:
				return NamedTypeReferenceBuilder.create(NamedTypeReferenceClass.StructNamedTypeClass, type_id, name)
			elif type.type == StructureVariant.UnionStructureType:
				return NamedTypeReferenceBuilder.create(NamedTypeReferenceClass.UnionNamedTypeClass, type_id, name)
			else:
				return NamedTypeReferenceBuilder.create(NamedTypeReferenceClass.ClassNamedTypeClass, type_id, name)
		elif type.type_class == TypeClass.EnumerationTypeClass:
			return NamedTypeReferenceBuilder.create(NamedTypeReferenceClass.EnumNamedTypeClass, type_id, name)
		else:
			return NamedTypeReferenceBuilder.create(NamedTypeReferenceClass.TypedefNamedTypeClass, type_id, name)

	@staticmethod
	def named_type_from_type(
	    name: QualifiedNameType, type_class: Optional[NamedTypeReferenceClass] = None
	) -> 'NamedTypeReferenceBuilder':
		if type_class is None:
			return NamedTypeReferenceBuilder.create(
			    NamedTypeReferenceClass.UnknownNamedTypeClass, str(uuid.uuid4()), name
			)
		else:
			return NamedTypeReferenceBuilder.create(type_class, str(uuid.uuid4()), name)

	@staticmethod
	def named_type_from_registered_type(
	    view: 'binaryview.BinaryView', name: QualifiedNameType
	) -> 'NamedTypeReferenceBuilder':
		type = view.get_type_by_name(name)
		if type is None:
			raise ValueError(f"Unable to find type named {name}")
		return NamedTypeReferenceBuilder.named_type_from_type_and_id(type_id=str(uuid.uuid4()), name=name, type=type)

	def __repr__(self):
		if self.named_type_class == NamedTypeReferenceClass.TypedefNamedTypeClass:
			return f"<type: mutable:{self.type_class.name} 'typedef {self.name}'>"
		elif self.named_type_class == NamedTypeReferenceClass.StructNamedTypeClass:
			return f"<type: mutable:{self.type_class.name} 'struct {self.name}'>"
		elif self.named_type_class == NamedTypeReferenceClass.UnionNamedTypeClass:
			return f"<type: mutable:{self.type_class.name} 'union {self.name}'>"
		elif self.named_type_class == NamedTypeReferenceClass.ClassNamedTypeClass:
			return f"<type: mutable:{self.type_class.name} 'class {self.name}'>"
		elif self.named_type_class == NamedTypeReferenceClass.EnumNamedTypeClass:
			return f"<type: mutable:{self.type_class.name} 'enum {self.name}'>"
		else:
			return f"<type: mutable:{self.type_class.name} 'unknown'>"


class Type:
	"""
	``class Type`` allows you to interact with the Binary Ninja type system. Note that the ``repr`` and ``str``
	handlers respond differently on type objects.

	Other related functions that may be helpful include:

	:py:meth:`parse_type_string <binaryview.BinaryView.parse_type_string>`
	:py:meth:`parse_types_from_source <platform.Platform.parse_types_from_source>`
	:py:meth:`parse_types_from_source_file <platform.Platform.parse_types_from_source_file>`

	"""
	def __init__(self, handle, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence):
		assert isinstance(handle.contents, core.BNType), "Attempting to create mutable Type"
		self._handle = handle
		self._confidence = confidence
		self._platform = platform
		self._type_class = None
		self._width = None
		self._alignment = None
		self._offset = None

	@classmethod
	def create(
	    cls, handle=core.BNTypeHandle, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	) -> 'Type':
		assert handle is not None, "Passed a handle which is None"
		assert isinstance(handle, core.BNTypeHandle)
		type_class = TypeClass(core.BNGetTypeClass(handle))
		return Types[type_class](handle, platform, confidence)

	def __del__(self):
		if core is not None:
			core.BNFreeType(self._handle)

	def __repr__(self):
		if self._confidence < core.max_confidence:
			return f"<type: immutable:{self.type_class.name} '{self}', {self._confidence * 100 // core.max_confidence}% confidence>"
		return f"<type: immutable:{self.type_class.name} '{self}'>"

	def __str__(self):
		return self.get_string()

	def __len__(self):
		return self.width

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return core.BNTypesEqual(self._handle, other._handle)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return core.BNTypesNotEqual(self._handle, other._handle)

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	@property
	def handle(self):
		return self._handle

	@property
	def type_class(self) -> TypeClass:
		"""Type class (read-only)"""
		if self._type_class is None:
			self._type_class = TypeClass(core.BNGetTypeClass(self._handle))
		return self._type_class

	@property
	def width(self) -> int:
		"""Type width (read-only)"""
		if self._width is None:
			self._width = core.BNGetTypeWidth(self._handle)
		return self._width

	@property
	def alignment(self) -> int:
		"""Type alignment (read-only)"""
		if self._alignment is None:
			self._alignment = core.BNGetTypeAlignment(self._handle)
		return self._alignment

	@property
	def offset(self) -> int:
		"""Offset into structure (read-only)"""
		if self._offset is None:
			self._offset = core.BNGetTypeOffset(self._handle)
		return self._offset

	@property
	def altname(self) -> str:
		"""Alternative name for the type object"""
		return core.BNGetTypeAlternateName(self._handle)

	def _to_core_struct(self) -> core.BNTypeWithConfidence:
		type_conf = core.BNTypeWithConfidence()
		type_conf.type = self._handle
		type_conf.confidence = self.confidence
		return type_conf

	def get_string(
		self, escaping: TokenEscapingType = TokenEscapingType.NoTokenEscapingType
	) -> str:
		"""
		Get string representation for this type

		:param TokenEscapingType escaping: How to escape non-parsable strings in types
		:return: String for type
		:rtype: str
		:Example:
			>>> Type.array(Type.int(4), 10).get_string()
			'int32_t[0xa]'
		"""
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		return core.BNGetTypeString(self._handle, platform, escaping)

	def get_string_before_name(
		self, escaping: TokenEscapingType = TokenEscapingType.NoTokenEscapingType
	) -> str:
		"""
		Get the string to be printed before this type's name in a representation of it

		:param TokenEscapingType escaping: How to escape non-parsable strings in types
		:return: String for type representation before the name
		:rtype: str
		:Example:
			>>> Type.array(Type.int(4), 10).get_string()
			'int32_t[0xa]'
			>>> Type.array(Type.int(4), 10).get_string_before_name()
			'int32_t'
		"""
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		return core.BNGetTypeStringBeforeName(self._handle, platform, escaping)

	def get_string_after_name(
		self, escaping: TokenEscapingType = TokenEscapingType.NoTokenEscapingType
	) -> str:
		"""
		Get the string to be printed after this type's name in a representation

		:param TokenEscapingType escaping: How to escape non-parsable strings in types
		:return: String for type representation after the name
		:rtype: str
		:Example:
			>>> Type.array(Type.int(4), 10).get_string()
			'int32_t[0xa]'
			>>> Type.array(Type.int(4), 10).get_string_after_name()
			'[0xa]'
		"""
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		return core.BNGetTypeStringAfterName(self._handle, platform, escaping)

	@property
	def tokens(self) -> List['_function.InstructionTextToken']:
		"""Type string as a list of tokens (read-only)"""
		return self.get_tokens()

	def get_tokens(
		self, base_confidence=core.max_confidence,
		escaping: TokenEscapingType = TokenEscapingType.NoTokenEscapingType
	) -> List['_function.InstructionTextToken']:
		"""
		Get a list of tokens for the definition of a type

		:param int base_confidence: Confidence of this type
		:param TokenEscapingType escaping: How to escape non-parsable strings in types
		:return: List of tokens
		:rtype: List[_function.InstructionTextToken]
		:Example:
			>>> Type.array(Type.int(4), 10).get_string()
			'int32_t[0xa]'
			>>> Type.array(Type.int(4), 10).get_tokens()
			['int32_t', ' ', '[', '0xa', ']']
		"""
		count = ctypes.c_ulonglong()
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		tokens = core.BNGetTypeTokens(self._handle, platform, base_confidence, escaping, count)
		assert tokens is not None, "core.BNGetTypeTokens returned None"

		result = _function.InstructionTextToken._from_core_struct(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	def get_tokens_before_name(
		self, base_confidence=core.max_confidence,
		escaping: TokenEscapingType = TokenEscapingType.NoTokenEscapingType
	) -> List['_function.InstructionTextToken']:
		"""
		Get a list of tokens for the definition of a type that are placed before the type name

		:param int base_confidence: Confidence of this type
		:param TokenEscapingType escaping: How to escape non-parsable strings in types
		:return: List of tokens
		:rtype: List[_function.InstructionTextToken]
		:Example:
			>>> Type.array(Type.int(4), 10).get_string()
			'int32_t[0xa]'
			>>> Type.array(Type.int(4), 10).get_tokens_before_name()
			['int32_t']
		"""
		count = ctypes.c_ulonglong()
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		tokens = core.BNGetTypeTokensBeforeName(self._handle, platform, base_confidence, escaping, count)
		assert tokens is not None, "core.BNGetTypeTokensBeforeName returned None"
		result = _function.InstructionTextToken._from_core_struct(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	@property
	def children(self) -> List['Type']:
		return []

	def get_tokens_after_name(
		self, base_confidence=core.max_confidence,
		escaping: TokenEscapingType = TokenEscapingType.NoTokenEscapingType
	) -> List['_function.InstructionTextToken']:
		"""
		Get a list of tokens for the definition of a type that are placed after the type name

		:param int base_confidence: Confidence of this type
		:param TokenEscapingType escaping: How to escape non-parsable strings in types
		:return: List of tokens
		:rtype: List[_function.InstructionTextToken]
		:Example:
			>>> Type.array(Type.int(4), 10).get_string()
			'int32_t[0xa]'
			>>> Type.array(Type.int(4), 10).get_tokens_after_name()
			['[', '0xa', ']']
		"""
		count = ctypes.c_ulonglong()
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		tokens = core.BNGetTypeTokensAfterName(self._handle, platform, base_confidence, escaping, count)
		assert tokens is not None, "core.BNGetTypeTokensAfterName returned None"
		result = _function.InstructionTextToken._from_core_struct(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	def get_lines(
		self, bv: 'binaryview.BinaryView', name: str, line_width: int = 80, collapsed: bool = False,
		escaping: TokenEscapingType = TokenEscapingType.NoTokenEscapingType
	) -> List['TypeDefinitionLine']:
		"""
		Get a list of :py:class:`TypeDefinitionLine` structures for representing a Type in a structured form.
		This structure uses the same logic as Types View and will expand structures and enumerations
		unless `collapsed` is set.

		:param BinaryView bv: BinaryView object owning this Type
		:param str name: Displayed name of the Type
		:param int line_width: Maximum width of lines (in characters)
		:param bool collapsed: If the type should be collapsed, and not show fields/members
		:param TokenEscapingType escaping: How to escape non-parsable strings in types
		:return: Returns a list of :py:class:`TypeDefinitionLine` structures
		:rtype: :py:class:`TypeDefinitionLine`
		"""
		count = ctypes.c_ulonglong()
		core_lines = core.BNGetTypeLines(self._handle, bv.handle, name, line_width, collapsed, escaping, count)
		assert core_lines is not None, "core.BNGetTypeLines returned None"
		lines = []
		for i in range(count.value):
			lines.append(TypeDefinitionLine._from_core_struct(core_lines[i]))
		core.BNFreeTypeDefinitionLineList(core_lines, count.value)
		return lines

	def with_confidence(self, confidence: int) -> 'Type':
		return Type.create(handle=core.BNNewTypeReference(self._handle), platform=self._platform, confidence=confidence)

	@property
	def confidence(self) -> _int:
		return self._confidence

	@confidence.setter
	def confidence(self, value: _int) -> None:
		self._confidence = value

	@property
	def platform(self) -> Optional['_platform.Platform']:
		return self._platform

	@platform.setter
	def platform(self, value: '_platform.Platform') -> None:
		self._platform = value

	def mutable_copy(self) -> 'TypeBuilder':
		TypeBuilders: Dict[TypeClass, typing.Type[TypeBuilder]] = {
		    TypeClass.VoidTypeClass: VoidBuilder, TypeClass.BoolTypeClass: BoolBuilder,
		    TypeClass.IntegerTypeClass: IntegerBuilder, TypeClass.FloatTypeClass: FloatBuilder,
		    TypeClass.PointerTypeClass: PointerBuilder, TypeClass.ArrayTypeClass: ArrayBuilder,
		    TypeClass.FunctionTypeClass: FunctionBuilder, TypeClass.WideCharTypeClass: WideCharBuilder,
		    # TypeClass.StructureTypeClass:Structure,
		    # TypeClass.EnumerationTypeClass:Enumeration,
		    # TypeClass.NamedTypeReferenceClass:NamedTypeReference,
		}
		builder_handle = core.BNCreateTypeBuilderFromType(self._handle)
		assert builder_handle is not None, "core.BNCreateTypeBuilderFromType returned None"
		return TypeBuilders[self.type_class](builder_handle, self.platform, self.confidence)

	def immutable_copy(self) -> 'Type':
		return self

	def get_builder(self, bv: 'binaryview.BinaryView') -> 'MutableTypeBuilder':
		return MutableTypeBuilder(self.mutable_copy(), bv, self.registered_name, self.platform, self._confidence)

	@staticmethod
	def builder(
	    bv: 'binaryview.BinaryView', name: Optional[QualifiedName] = None, id: Optional[str] = None,
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	) -> 'MutableTypeBuilder':
		type = None
		if name is None and id is None:
			raise ValueError("Must specify either a name or id to create a builder object")
		if name is None and id is not None:
			type = bv.get_type_by_id(id)
			if type is None:
				raise ValueError("failed to look up type by id")
			registered_name = type.registered_name
			if registered_name is None:
				raise ValueError("Registered name for type is None")
			name = registered_name.name
			if name is None:
				raise ValueError("Name for registered name is None")
		elif name is not None:
			type = bv.get_type_by_name(name)
			if type is None:
				raise ValueError("failed to look up type by name")
		assert type is not None
		assert name is not None
		return MutableTypeBuilder(type.mutable_copy(), bv, name, platform, confidence)

	def with_replaced_structure(self, from_struct, to_struct):
		handle = core.BNTypeWithReplacedStructure(self._handle, from_struct.handle, to_struct.handle)
		return Type.create(handle)

	def with_replaced_enumeration(self, from_enum, to_enum):
		handle = core.BNTypeWithReplacedEnumeration(self._handle, from_enum.handle, to_enum.handle)
		return Type.create(handle)

	def with_replaced_named_type_reference(self, from_ref, to_ref):
		return Type.create(
		    handle=core.BNTypeWithReplacedNamedTypeReference(self._handle, from_ref.handle, to_ref.handle)
		)

	@staticmethod
	def void() -> 'VoidType':
		return VoidType.create()

	@staticmethod
	def bool() -> 'BoolType':
		return BoolType.create()

	@staticmethod
	def char(alternate_name: str = "") -> 'CharType':
		return CharType.create(alternate_name)

	@staticmethod
	def int(width: _int, sign: BoolWithConfidenceType = True, alternate_name: str = "") -> 'IntegerType':
		"""
		``int`` class method for creating an int Type.

		:param int width: width of the integer in bytes
		:param bool sign: optional variable representing signedness
		:param str alternate_name: alternate name for type
		"""
		return IntegerType.create(width, sign, alternate_name)

	@staticmethod
	def float(width: _int, alternate_name: str = "") -> 'FloatType':
		"""
		``float`` class method for creating floating point Types.

		:param int width: width of the floating point number in bytes
		:param str alternate_name: alternate name for type
		"""
		return FloatType.create(width, alternate_name)

	@staticmethod
	def wide_char(width: _int, alternate_name: str = "") -> 'WideCharType':
		"""
		``wide_char`` class method for creating wide char Types.

		:param int width: width of the wide character in bytes
		:param str alternate_name: alternate name for type
		"""
		return WideCharType.create(width=width, alternate_name=alternate_name)

	@staticmethod
	def structure_type(structure: 'StructureBuilder') -> 'StructureType':
		result = structure.immutable_copy()
		assert isinstance(result, StructureType)
		return result

	@staticmethod
	def named_type(named_type: 'NamedTypeReferenceBuilder') -> 'NamedTypeReferenceType':
		result = named_type.immutable_copy()
		assert isinstance(result, NamedTypeReferenceType)
		return result

	@staticmethod
	def named_type_from_type(name: QualifiedNameType, type: 'Type') -> 'NamedTypeReferenceType':
		return NamedTypeReferenceType.create_from_type(name, type)

	@staticmethod
	def named_type_from_type_and_id(
	    type_id: str, name: QualifiedNameType, type: Optional['Type'] = None
	) -> 'NamedTypeReferenceType':
		return NamedTypeReferenceType.create_from_type(name, type, type_id)

	@staticmethod
	def generate_named_type_reference(guid: str, name: QualifiedNameType) -> 'NamedTypeReferenceType':
		return NamedTypeReferenceType.create(NamedTypeReferenceClass.TypedefNamedTypeClass, guid, name)

	@staticmethod
	def named_type_from_registered_type(view: 'binaryview.BinaryView', name: QualifiedNameType) -> 'NamedTypeReferenceType':
		return NamedTypeReferenceType.create_from_registered_type(view, name)

	@staticmethod
	def enumeration_type(
	    arch, enum: 'EnumerationBuilder', width: _int = None, sign: _bool = False
	) -> 'EnumerationType':
		return EnumerationType.create(enum.members, enum.width, arch, enum.signed)

	@staticmethod
	def pointer(
	    arch: 'architecture.Architecture', type: 'Type', const: BoolWithConfidenceType = BoolWithConfidence(False),
	    volatile: BoolWithConfidenceType = BoolWithConfidence(False),
	    ref_type: ReferenceType = ReferenceType.PointerReferenceType, width: _int = None
	) -> 'PointerType':

		if arch is None and width is None:
			raise ValueError("Must specify either an architecture or a width to create a pointer")

		_width = width if width is not None else arch.address_size
		return PointerType.create_with_width(_width, type, const, volatile, ref_type)

	@staticmethod
	def pointer_of_width(
	    width: _int, type: 'Type', const: BoolWithConfidenceType = False, volatile: BoolWithConfidenceType = False,
	    ref_type: ReferenceType = ReferenceType.PointerReferenceType
	) -> 'PointerType':
		return PointerType.create_with_width(width, type, const, volatile, ref_type)

	@staticmethod
	def array(type: 'Type', count: _int) -> 'ArrayType':
		return ArrayType.create(type, count)

	@staticmethod
	def function(
	    ret: Optional['Type'] = None, params: Optional[ParamsType] = None,
	    calling_convention: Optional['callingconvention.CallingConvention'] = None,
	    variable_arguments: BoolWithConfidenceType = False,
	    stack_adjust: OffsetWithConfidence = OffsetWithConfidence(0)
	) -> 'FunctionType':
		"""
		``function`` class method for creating a function Type.

		:param Type ret: return Type of the function
		:param params: list of parameter Types
		:type params: list(Type)
		:param CallingConvention calling_convention: optional argument for the function calling convention
		:param bool variable_arguments: optional boolean, true if the function has a variable number of arguments
		"""
		return FunctionType.create(ret, params, calling_convention, variable_arguments, stack_adjust)

	@staticmethod
	def from_core_struct(core_type: core.BNType):
		return Type.create(core.BNNewTypeReference(core_type))

	@staticmethod
	def structure(
	    members: Optional[MembersType] = None, packed: _bool = False,
	    type: StructureVariant = StructureVariant.StructStructureType
	) -> 'StructureType':
		return StructureType.create(members, packed, type)

	@staticmethod
	def union(members: Optional[MembersType] = None, packed: _bool = False) -> 'StructureType':
		return StructureType.create(members, type=StructureVariant.UnionStructureType, packed=packed)

	@staticmethod
	def class_type(members: Optional[MembersType] = None, packed: _bool = False) -> 'StructureType':
		return StructureType.create(members, type=StructureVariant.ClassStructureType, packed=packed)

	@staticmethod
	def enumeration(
	    arch: Optional['architecture.Architecture'] = None, members: Optional[EnumMembersType] = None,
	    width: Optional[_int] = None, sign: BoolWithConfidenceType = False
	) -> 'EnumerationType':
		if members is None:
			members = []
		return EnumerationType.create(members, width, arch, sign)

	@staticmethod
	def named_type_reference(
	    type_class: NamedTypeReferenceClass, name: QualifiedNameType, type_id: Optional[str] = None, alignment: _int = 1,
	    width: _int = 0, const: BoolWithConfidenceType = BoolWithConfidence(False),
	    volatile: BoolWithConfidenceType = BoolWithConfidence(False)
	):
		return NamedTypeReferenceType.create(
		    type_class, type_id, name, alignment, width, None, core.max_confidence, const, volatile
		)

	@property
	def name(self) -> QualifiedName:
		raise NotImplementedError("Name not implemented for this type")

	@staticmethod
	def generate_auto_type_id(source: str, name: QualifiedNameType) -> str:
		_name = QualifiedName(name)._to_core_struct()
		return core.BNGenerateAutoTypeId(source, _name)

	@staticmethod
	def generate_auto_demangled_type_id(name: QualifiedNameType) -> str:
		_name = QualifiedName(name)._to_core_struct()
		return core.BNGenerateAutoDemangledTypeId(_name)

	@staticmethod
	def get_auto_demangled_type_id_source() -> str:
		return core.BNGetAutoDemangledTypeIdSource()

	@property
	def registered_name(self) -> Optional['NamedTypeReferenceType']:
		"""Name of type registered to binary view, if any (read-only)"""
		ntr_handle = core.BNGetRegisteredTypeName(self._handle)
		if ntr_handle is None:
			return None
		return NamedTypeReferenceType.create_from_handle(ntr_handle, self.alignment, self.width,
			self.platform, self.confidence, self.const, self.volatile)

	@property
	def const(self):
		"""Whether type is const (read/write)"""
		result = core.BNIsTypeConst(self._handle)
		return BoolWithConfidence(result.value, confidence=result.confidence)

	@property
	def volatile(self):
		"""Whether type is volatile (read/write)"""
		result = core.BNIsTypeVolatile(self._handle)
		return BoolWithConfidence(result.value, confidence=result.confidence)

	@property
	def system_call_number(self) -> Optional[_int]:
		"""Returns the system call number for a FunctionType object if one exists otherwise None"""
		if not core.BNTypeIsSystemCall(self._handle):
			return None
		return core.BNTypeGetSystemCallNumber(self._handle)


@dataclass(frozen=True)
class RegisterStackAdjustmentWithConfidence:
	value: int
	confidence: int = core.max_confidence

	def __int__(self):
		return self.value


class VoidType(Type):
	@classmethod
	def create(cls, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence) -> 'VoidType':
		core_void = core.BNCreateVoidType()
		assert core_void is not None, "core.BNCreateVoidType returned None"
		return cls(core_void, platform, confidence)


class BoolType(Type):
	@classmethod
	def create(cls, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence) -> 'BoolType':
		handle = core.BNCreateBoolType()
		assert handle is not None, "core.BNCreateBoolType returned None"
		return cls(handle, platform, confidence)


class IntegerType(Type):
	def __init__(self, handle, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence):
		super(IntegerType, self).__init__(handle, platform, confidence)

	@classmethod
	def create(
	    cls, width: int, sign: BoolWithConfidenceType = True, alternate_name: str = "",
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	) -> 'IntegerType':
		_sign = BoolWithConfidence.get_core_struct(sign)
		handle = core.BNCreateIntegerType(width, _sign, alternate_name)
		assert handle is not None, "core.BNCreateIntegerType returned None"
		return cls(handle, platform, confidence)

	@property
	def signed(self) -> BoolWithConfidence:
		"""Whether type is signed (read-only)"""
		return BoolWithConfidence.from_core_struct(core.BNIsTypeSigned(self._handle))


class CharType(IntegerType):
	@classmethod
	def create(
	    cls, altname: str = "char", platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	) -> 'CharType':
		result = IntegerType.create(1, True, altname)
		return cls(core.BNNewTypeReference(result.handle), platform, confidence)


class FloatType(Type):
	@classmethod
	def create(
	    cls, width: int, altname: str = "", platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	) -> 'FloatType':
		"""
		``float`` class method for creating floating point Types.

		:param int width: width of the floating point number in bytes
		:param str altname: alternate name for type
		"""
		core_float = core.BNCreateFloatType(width, altname)
		assert core_float is not None, "core.BNCreateFloatType returned None"
		return cls(core_float, platform, confidence)


class StructureType(Type):
	def __init__(self, handle, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence):
		assert handle is not None, "Attempted to create EnumerationType with handle which is None"
		super(StructureType, self).__init__(handle, platform, confidence)
		struct_handle = core.BNGetTypeStructure(handle)
		assert struct_handle is not None, "core.BNGetTypeStructure returned None"
		self.struct_handle = struct_handle

	@classmethod
	def create(
	    cls, members: Optional[MembersType] = None, packed: bool = False,
	    type: StructureVariant = StructureVariant.StructStructureType, platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'StructureType':
		builder = core.BNCreateStructureBuilderWithOptions(type, packed)
		assert builder is not None, "core.BNCreateStructureBuilder returned None"
		StructureBuilder._add_members_to_builder(builder, members)
		core_struct = core.BNFinalizeStructureBuilder(builder)
		assert core_struct is not None, "core.BNFinalizeStructureBuilder returned None"
		core_type = core.BNCreateStructureType(core_struct)
		assert core_type is not None, "core.BNCreateStructureType returned None"
		return cls(core_type, platform, confidence)

	def mutable_copy(self) -> 'StructureBuilder':
		type_builder_handle = core.BNCreateTypeBuilderFromType(self._handle)
		assert type_builder_handle is not None, "core.BNCreateTypeBuilderFromType returned None"
		structure_handle = core.BNGetTypeStructure(self._handle)
		assert structure_handle is not None, "core.BNGetTypeStructure returned None"
		structure_builder_handle = core.BNCreateStructureBuilderFromStructure(structure_handle)
		assert structure_builder_handle is not None, "core.BNCreateStructureBuilderFromStructure returned None"
		return StructureBuilder(type_builder_handle, structure_builder_handle, self.platform, self.confidence)

	@classmethod
	def from_core_struct(cls, structure: core.BNStructure) -> 'StructureType':
		return cls(core.BNNewTypeReference(core.BNCreateStructureType(structure)))

	def __del__(self):
		if core is not None:
			core.BNFreeStructure(self.struct_handle)

	def __hash__(self):
		return hash(ctypes.addressof(self.struct_handle.contents))

	def __getitem__(self, name: str) -> StructureMember:
		member = None
		try:
			member = core.BNGetStructureMemberByName(self.struct_handle, name)
			if member is None:
				raise ValueError(f"Member {name} is not part of structure")
			return StructureMember(
			    Type.create(core.BNNewTypeReference(member.contents.type), confidence=member.contents.typeConfidence),
			    member.contents.name, member.contents.offset, MemberAccess(member.contents.access),
			    MemberScope(member.contents.scope)
			)
		finally:
			if member is not None:
				core.BNFreeStructureMember(member)

	def member_at_offset(self, offset: int) -> StructureMember:
		member = None
		try:
			member = core.BNGetStructureMemberAtOffset(self.struct_handle, offset, None)
			if member is None:
				raise ValueError(f"No member exists a offset {offset}")
			return StructureMember(
			    Type.create(core.BNNewTypeReference(member.contents.type), confidence=member.contents.typeConfidence),
			    member.contents.name, member.contents.offset, MemberAccess(member.contents.access),
			    MemberScope(member.contents.scope)
			)
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
				result.append(
				    StructureMember(
				        Type.create(core.BNNewTypeReference(members[i].type), confidence=members[i].typeConfidence),
				        members[i].name, members[i].offset, MemberAccess(members[i].access),
				        MemberScope(members[i].scope)
				    )
				)
		finally:
			core.BNFreeStructureMemberList(members, count.value)
		return result

	@property
	def base_structures(self) -> List[BaseStructure]:
		"""Base structure list (read-only). Offsets that are not defined by this structure will be filled
		    in by the fields of the base structure(s)."""
		count = ctypes.c_ulonglong()
		bases = core.BNGetBaseStructuresForStructure(self.struct_handle, count)
		try:
			result = []
			for i in range(0, count.value):
				result.append(BaseStructure._from_core_struct(bases[i], self.platform))
			return result
		finally:
			core.BNFreeBaseStructureList(bases, count.value)

	@property
	def width(self):
		"""Structure width"""
		return core.BNGetStructureWidth(self.struct_handle)

	@property
	def pointer_offset(self):
		"""
		Structure pointer offset. Pointers to this structure will implicitly
		have this offset subtracted from the pointer to arrive at the start of the structure.
		Effectively, the pointer offset becomes the new start of the structure, and fields
		before it are accessed using negative offsets from the pointer.
		"""
		return core.BNGetStructurePointerOffset(self.struct_handle)

	@property
	def alignment(self):
		"""Structure alignment"""
		return core.BNGetStructureAlignment(self.struct_handle)

	@property
	def packed(self):
		return core.BNIsStructurePacked(self.struct_handle)

	@property
	def propagate_data_var_refs(self) -> bool:
		"""Whether structure field references propagate the references to data variable field values"""
		return core.BNStructurePropagatesDataVariableReferences(self.struct_handle)

	@property
	def type(self) -> StructureVariant:
		return StructureVariant(core.BNGetStructureType(self.struct_handle))

	def members_including_inherited(self, view: 'binaryview.BinaryView') -> List[InheritedStructureMember]:
		"""Returns structure member list, including those inherited by base structures"""
		count = ctypes.c_ulonglong()
		members = core.BNGetStructureMembersIncludingInherited(self.struct_handle, view.handle, count)
		assert members is not None, "core.BNGetInheritedStructureMembers returned None"
		try:
			result = []
			for i in range(0, count.value):
				if members[i].base:
					const_conf = BoolWithConfidence.get_core_struct(False, 0)
					volatile_conf = BoolWithConfidence.get_core_struct(False, 0)
					handle = core.BNCreateNamedTypeReference(members[i].base, 0, 1, const_conf, volatile_conf)
					base_type = NamedTypeReferenceType(handle, self.platform)
				else:
					base_type = None
				result.append(
				    InheritedStructureMember(
						base_type,
						members[i].baseOffset,
				        StructureMember(
							Type.create(core.BNNewTypeReference(members[i].member.type), confidence=members[i].member.typeConfidence),
							members[i].member.name, members[i].member.offset, MemberAccess(members[i].member.access),
							MemberScope(members[i].member.scope)
						),
						members[i].memberIndex
				    )
				)
		finally:
			core.BNFreeInheritedStructureMemberList(members, count.value)
		return result

	def with_replaced_structure(self, from_struct, to_struct) -> 'StructureType':
		return StructureType(
		    core.BNStructureWithReplacedStructure(self.struct_handle, from_struct.handle, to_struct.handle)
		)

	def with_replaced_enumeration(self, from_enum, to_enum) -> 'StructureType':
		return StructureType(
		    core.BNStructureWithReplacedEnumeration(self.struct_handle, from_enum.handle, to_enum.handle)
		)

	def with_replaced_named_type_reference(self, from_ref, to_ref) -> 'StructureType':
		return StructureType(
		    core.BNStructureWithReplacedNamedTypeReference(self.struct_handle, from_ref.handle, to_ref.handle)
		)

	def generate_named_type_reference(self, guid: str, name: QualifiedNameType):
		if self.type == StructureVariant.StructStructureType:
			ntr_type = NamedTypeReferenceClass.StructNamedTypeClass
		elif self.type == StructureVariant.UnionStructureType:
			ntr_type = NamedTypeReferenceClass.UnionNamedTypeClass
		else:
			ntr_type = NamedTypeReferenceClass.ClassNamedTypeClass
		return NamedTypeReferenceType.create(
		    ntr_type, guid, name, self.alignment, self.width, self.platform, self.confidence
		)

	@property
	def children(self) -> List[Type]:
		return [member.type for member in self.members]


class EnumerationType(IntegerType):
	def __init__(self, handle, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence):
		assert handle is not None, "Attempted to create EnumerationType without handle"
		super(EnumerationType, self).__init__(handle, platform, confidence)
		enum_handle = core.BNGetTypeEnumeration(handle)
		core.BNNewEnumerationReference(enum_handle)
		assert enum_handle is not None, "core.BNGetTypeEnumeration returned None"
		self.enum_handle = enum_handle

	def __del__(self):
		if core is not None:
			core.BNFreeEnumeration(self.enum_handle)

	def __hash__(self):
		return hash(ctypes.addressof(self.enum_handle.contents))

	@property
	def members(self):
		"""Enumeration member list (read-only)"""
		count = ctypes.c_ulonglong()
		members = core.BNGetEnumerationMembers(self.enum_handle, count)
		assert members is not None, "core.BNGetEnumerationMembers returned None"
		try:
			result = []
			for i in range(0, count.value):
				value = convert_integer(members[i].value, self.signed, self.width)
				result.append(EnumerationMember(members[i].name, value if not members[i].isDefault else None))
			return result
		finally:
			core.BNFreeEnumerationMemberList(members, count.value)

	@classmethod
	def create(
	    cls, members: EnumMembersType, width: Optional[int] = None,
	    arch: Optional['architecture.Architecture'] = None, sign: BoolWithConfidenceType = False,
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	) -> 'EnumerationType':
		if width is not None:
			_width = width
		elif arch is not None:
			_width = arch.address_size
		else:
			raise ValueError("One of the following parameters must not be None: (arch, width)")

		if width == 0:
			raise ValueError("enumeration width must not be 0")

		builder = core.BNCreateEnumerationBuilder()
		assert builder is not None, "core.BNCreateEnumerationType returned None"
		EnumerationBuilder._add_members(builder, members)
		core_enum = core.BNFinalizeEnumerationBuilder(builder)
		assert core_enum is not None, "core.BNFinalizeEnumerationBuilder returned None"
		core.BNFreeEnumerationBuilder(builder)

		core_type = core.BNCreateEnumerationTypeOfWidth(core_enum, _width, BoolWithConfidence.get_core_struct(sign))
		assert core_type is not None, "core.BNCreateEnumerationTypeOfWidth returned None"
		return cls(core_type, platform, confidence)

	def mutable_copy(self) -> 'EnumerationBuilder':
		type_builder_handle = core.BNCreateTypeBuilderFromType(self._handle)
		assert type_builder_handle is not None, "core.BNCreateTypeBuilderFromType returned None"
		enumeration_handle = core.BNGetTypeEnumeration(self._handle)
		assert enumeration_handle is not None, "core.BNGetTypeEnumeration returned None"
		enumeration_builder_handle = core.BNCreateEnumerationBuilderFromEnumeration(enumeration_handle)
		assert enumeration_builder_handle is not None, "core.BNCreateEnumerationBuilderFromEnumeration returned None"
		return EnumerationBuilder(type_builder_handle, enumeration_builder_handle, self.platform, self.confidence)

	def generate_named_type_reference(self, guid: str, name: QualifiedNameType):
		ntr_type = NamedTypeReferenceClass.EnumNamedTypeClass
		return NamedTypeReferenceType.create(ntr_type, guid, name, platform=self.platform, confidence=self.confidence)


class PointerType(Type):
	@property
	def ref_type(self) -> ReferenceType:
		return ReferenceType(core.BNTypeGetReferenceType(self._handle))

	@classmethod
	def create(
	    cls, arch: 'architecture.Architecture', type: SomeType, const: BoolWithConfidenceType = False,
	    volatile: BoolWithConfidenceType = False, ref_type: ReferenceType = ReferenceType.PointerReferenceType,
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence
	) -> 'PointerType':
		return cls.create_with_width(arch.address_size, type, const, volatile, ref_type, platform, confidence)

	@staticmethod
	def from_bools(const: BoolWithConfidenceType,
	               volatile: BoolWithConfidenceType) -> Tuple[BoolWithConfidence, BoolWithConfidence]:
		_const = const
		if const is None:
			_const = BoolWithConfidence(False, confidence=0)
		elif isinstance(const, bool):
			_const = BoolWithConfidence(const)
		if not isinstance(_const, BoolWithConfidence):
			raise ValueError(f"unhandled type {type(const)} for 'const' argument")

		_volatile = volatile
		if volatile is None:
			_volatile = BoolWithConfidence(False, confidence=0)
		elif isinstance(volatile, bool):
			_volatile = BoolWithConfidence(volatile)
		if not isinstance(_volatile, BoolWithConfidence):
			raise ValueError(f"unhandled type {type(volatile)} for 'volatile' argument")

		return (_const, _volatile)

	@classmethod
	def create_with_width(
	    cls, width: int, type: SomeType, const: BoolWithConfidenceType = False,
	    volatile: BoolWithConfidenceType = False, ref_type: Optional[ReferenceType] = None, platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'PointerType':
		_const, _volatile = PointerType.from_bools(const, volatile)
		type = type.immutable_copy()
		if ref_type is None:
			ref_type = ReferenceType.PointerReferenceType
		type_conf = type._to_core_struct()
		core_type = core.BNCreatePointerTypeOfWidth(
		    width, type_conf, _const._to_core_struct(), _volatile._to_core_struct(), ref_type
		)
		assert core_type is not None, "core.BNCreatePointerTypeOfWidth returned None"
		return cls(core_type, platform, confidence)

	def origin(self, bv: Optional['binaryview.BinaryView']) -> Optional[Tuple['QualifiedName', int]]:
		ntr_handle = core.BNGetTypeNamedTypeReference(self._handle)
		if ntr_handle is None:
			return None
		name = core.BNGetTypeReferenceName(ntr_handle)
		core.BNFreeNamedTypeReference(ntr_handle)
		if name is None:
			return None
		qn = QualifiedName._from_core_struct(name)
		core.BNFreeQualifiedName(name)
		return (qn, self.offset)

	@property
	def target(self) -> Type:
		"""Target (read-only)"""
		result = core.BNGetChildType(self._handle)
		assert result is not None, "core.BNGetChildType returned None"
		return Type.create(result.type, self._platform, result.confidence)

	@property
	def children(self) -> List[Type]:
		return [self.target]


class ArrayType(Type):
	@classmethod
	def create(
	    cls, element_type: Type, count: int, platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'ArrayType':
		type_conf = element_type._to_core_struct()
		core_array = core.BNCreateArrayType(type_conf, count)
		assert core_array is not None, "core.BNCreateArrayType returned None"
		return cls(core_array)

	@property
	def count(self):
		"""Type count (read-only)"""
		return core.BNGetTypeElementCount(self._handle)

	@property
	def element_type(self) -> Type:
		result = core.BNGetChildType(self._handle)
		assert result is not None, "core.BNGetChildType returned None"
		return Type.create(result.type, self._platform, result.confidence)

	@property
	def children(self) -> List[Type]:
		return [self.element_type]


class FunctionType(Type):
	@classmethod
	def create(
	    cls, ret: Optional[Type] = None, params: Optional[ParamsType] = None,
	    calling_convention: Optional['callingconvention.CallingConvention'] = None,
	    variable_arguments: BoolWithConfidenceType = BoolWithConfidence(False),
	    stack_adjust: OffsetWithConfidence = OffsetWithConfidence(0), platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence,
	    can_return: Union[BoolWithConfidence, bool] = True, reg_stack_adjust: Optional[Dict['architecture.RegisterName', OffsetWithConfidenceType]] = None,
	    return_regs: Optional[Union['RegisterSet', List['architecture.RegisterType']]] = None,
	    name_type: 'NameType' = NameType.NoNameType
	) -> 'FunctionType':
		if ret is None:
			ret = VoidType.create()
		if params is None:
			params = []
		param_buf = FunctionBuilder._to_core_struct(params)
		ret_conf = ret._to_core_struct()
		conv_conf = core.BNCallingConventionWithConfidence()
		if calling_convention is None:
			conv_conf.convention = None
			conv_conf.confidence = 0
		else:
			conv_conf.convention = calling_convention.handle
			conv_conf.confidence = calling_convention.confidence

		if variable_arguments is None:
			_variable_arguments = BoolWithConfidence.get_core_struct(False, 0)
		else:
			_variable_arguments = BoolWithConfidence.get_core_struct(variable_arguments, core.max_confidence)

		if stack_adjust is None:
			_stack_adjust = OffsetWithConfidence.get_core_struct(0, 0)
		else:
			_stack_adjust = OffsetWithConfidence.get_core_struct(stack_adjust, core.max_confidence)


		if reg_stack_adjust is None:
			reg_stack_adjust = {}
		reg_stack_adjust_regs = (ctypes.c_uint32 * len(reg_stack_adjust))()
		reg_stack_adjust_values = (core.BNOffsetWithConfidence * len(reg_stack_adjust))()

		for i, (reg, adjust) in enumerate(reg_stack_adjust.items()):
			reg_stack_adjust_regs[i] = reg
			reg_stack_adjust_values[i].value = adjust.value
			reg_stack_adjust_values[i].confidence = adjust.confidence

		return_regs_set = core.BNRegisterSetWithConfidence()
		if return_regs is None or platform is None:
			return_regs_set.count = 0
			return_regs_set.confidence = 0
		else:
			return_regs_set.count = len(return_regs)
			return_regs_set.confidence = 255
			return_regs_set.regs = (ctypes.c_uint32 * len(return_regs))()

			for i, reg in enumerate(return_regs):
				return_regs_set[i] = platform.arch.get_reg_index(reg)

		_can_return = BoolWithConfidence.get_core_struct(can_return)
		if params is None:
			params = []
		func_type = core.BNCreateFunctionType(
			ret_conf, conv_conf, param_buf, len(params), _variable_arguments, _can_return, _stack_adjust,
			reg_stack_adjust_regs, reg_stack_adjust_values, len(reg_stack_adjust),
			return_regs_set, name_type
		)

		assert func_type is not None, f"core.BNCreateFunctionType returned None {ret_conf} {conv_conf} {param_buf} {_variable_arguments} {_stack_adjust}"
		return cls(func_type, platform, confidence)

	@property
	def stack_adjustment(self) -> OffsetWithConfidence:
		"""Stack adjustment for function (read-only)"""
		result = core.BNGetTypeStackAdjustment(self._handle)
		return OffsetWithConfidence(result.value, confidence=result.confidence)

	@property
	def return_value(self) -> Type:
		"""Return value (read-only)"""
		result = core.BNGetChildType(self._handle)
		if result is None:
			return Type.void()
		return Type.create(result.type, platform=self._platform, confidence=result.confidence)

	@property
	def calling_convention(self) -> Optional[callingconvention.CallingConvention]:
		"""Calling convention (read-only)"""
		result = core.BNGetTypeCallingConvention(self._handle)
		if not result.convention:
			return None
		return callingconvention.CallingConvention(None, handle=result.convention, confidence=result.confidence)

	@property
	def parameters(self) -> List[FunctionParameter]:
		"""Type parameters list (read-only)"""
		count = ctypes.c_ulonglong()
		params = core.BNGetTypeParameters(self._handle, count)
		assert params is not None, "core.BNGetTypeParameters returned None"
		result = []
		for i in range(0, count.value):
			param_type = Type.create(
			    core.BNNewTypeReference(params[i].type), platform=self._platform, confidence=params[i].typeConfidence
			)
			if params[i].defaultLocation:
				param_location = None
			else:
				name = params[i].name
				if (params[i].location.type
				    == VariableSourceType.RegisterVariableSourceType) and (self._platform is not None):
					name = self._platform.arch.get_reg_name(params[i].location.storage)
				elif params[i].location.type == VariableSourceType.StackVariableSourceType:
					name = "arg_%x" % params[i].location.storage
				param_location = variable.VariableNameAndType(
				    params[i].location.type, params[i].location.index, params[i].location.storage, name, param_type
				)
			result.append(FunctionParameter(param_type, params[i].name, param_location))
		core.BNFreeTypeParameterList(params, count.value)
		return result

	@property
	def has_variable_arguments(self) -> BoolWithConfidence:
		"""Whether type has variable arguments (read-only)"""
		result = core.BNTypeHasVariableArguments(self._handle)
		return BoolWithConfidence(result.value, confidence=result.confidence)

	@property
	def can_return(self) -> BoolWithConfidence:
		"""Whether type can return"""
		result = core.BNFunctionTypeCanReturn(self._handle)
		return BoolWithConfidence(result.value, confidence=result.confidence)

	@property
	def children(self) -> List[Type]:
		return [self.return_value, *[param.type for param in self.parameters]]


class NamedTypeReferenceType(Type):
	def __init__(
	    self, handle, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence, ntr_handle=None
	):
		assert handle is not None, "Attempting to create NamedTypeReferenceType handle which is None"
		super(NamedTypeReferenceType, self).__init__(handle, platform, confidence)
		if ntr_handle is None:
			ntr_handle = core.BNGetTypeNamedTypeReference(handle)
		assert ntr_handle is not None, "core.BNGetTypeNamedTypeReference returned None"
		self.ntr_handle = ntr_handle

	def mutable_copy(self):
		type_builder_handle = core.BNCreateTypeBuilderFromType(self._handle)
		assert type_builder_handle is not None, "core.BNCreateTypeBuilderFromType returned None"
		ntr_builder_handle = core.BNCreateNamedTypeBuilder(
		    self.named_type_class, self.type_id, self.name._to_core_struct()
		)
		assert ntr_builder_handle is not None, "core.BNCreateNamedTypeBuilder returned None"
		return NamedTypeReferenceBuilder(type_builder_handle, ntr_builder_handle, self.platform, self.confidence)

	@classmethod
	def create(
	    cls, named_type_class: NamedTypeReferenceClass, guid: Optional[str], name: QualifiedNameType, alignment: int = 0,
	    width: int = 0, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence,
	    const: BoolWithConfidenceType = False, volatile: BoolWithConfidenceType = False
	) -> 'NamedTypeReferenceType':
		_guid = guid
		if guid is None:
			_guid = str(uuid.uuid4())

		_name = QualifiedName(name)._to_core_struct()
		core_ntr = core.BNCreateNamedType(named_type_class, _guid, _name)
		assert core_ntr is not None, "core.BNCreateNamedType returned None"

		_const = BoolWithConfidence.get_core_struct(const)
		_volatile = BoolWithConfidence.get_core_struct(volatile)
		core_type = core.BNCreateNamedTypeReference(core_ntr, width, alignment, _const, _volatile)
		assert core_type is not None, "core.BNCreateNamedTypeReference returned None"
		return cls(core_type, platform, confidence)

	@classmethod
	def create_from_handle(cls, ntr_handle, alignment: int = 0,
	    width: int = 0, platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence,
	    const: BoolWithConfidenceType = False, volatile: BoolWithConfidenceType = False
	):
		"""Create a NamedTypeReferenceType from a BNNamedTypeReference handle"""
		assert ntr_handle is not None, "Attempting to create NamedTypeReferenceType from None handle"
		_const = BoolWithConfidence.get_core_struct(const)
		_volatile = BoolWithConfidence.get_core_struct(volatile)
		core_type = core.BNCreateNamedTypeReference(ntr_handle, width, alignment, _const, _volatile)
		assert core_type is not None, "core.BNCreateNamedTypeReference returned None"
		return cls(core_type, platform, confidence)

	@classmethod
	def create_from_type(
	    cls, name: QualifiedNameType, type: Optional[Type], guid: Optional[str] = None,
	    platform: Optional['_platform.Platform'] = None, confidence: int = core.max_confidence,
	    const: BoolWithConfidenceType = False, volatile: BoolWithConfidenceType = False
	) -> 'NamedTypeReferenceType':
		_guid = guid
		if _guid is None:
			_guid = str(uuid.uuid4())

		if type is None:
			return cls.create(NamedTypeReferenceClass.UnknownNamedTypeClass, _guid, name, 0, 0, platform, confidence)
		else:
			return NamedTypeReferenceType.create(NamedTypeReferenceClass.TypedefNamedTypeClass, _guid, name, type.alignment, type.width, platform, confidence, const, volatile)

	@classmethod
	def create_from_registered_type(
	    cls, view: 'binaryview.BinaryView', name: QualifiedNameType, platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'NamedTypeReferenceType':
		_name = QualifiedName(name)._to_core_struct()
		core_type = core.BNCreateNamedTypeReferenceFromType(view.handle, _name)
		assert core_type is not None, "core.BNCreateNamedTypeReferenceFromType returned None"
		return cls(core_type, platform, confidence)

	def __del__(self):
		if core is not None:
			core.BNFreeNamedTypeReference(self.ntr_handle)

	def __repr__(self):
		if self.named_type_class == NamedTypeReferenceClass.TypedefNamedTypeClass:
			return f"<type: immutable:NamedTypeReferenceClass 'typedef {self.name}'>"
		elif self.named_type_class == NamedTypeReferenceClass.StructNamedTypeClass:
			return f"<type: immutable:NamedTypeReferenceClass 'struct {self.name}'>"
		elif self.named_type_class == NamedTypeReferenceClass.UnionNamedTypeClass:
			return f"<type: immutable:NamedTypeReferenceClass 'union {self.name}'>"
		elif self.named_type_class == NamedTypeReferenceClass.ClassNamedTypeClass:
			return f"<type: immutable:NamedTypeReferenceClass 'class {self.name}'>"
		elif self.named_type_class == NamedTypeReferenceClass.EnumNamedTypeClass:
			return f"<type: immutable:NamedTypeReferenceClass 'enum {self.name}'>"
		else:
			return f"<type: immutable:NamedTypeReferenceClass 'unknown'>"

	def __str__(self):
		name = self.registered_name
		if name is None:
			name = ""
		else:
			name = " " + str(name.name)
		return f"{self.get_string_before_name()}{name}{self.get_string_after_name()}"

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
	def generate_auto_type_ref(type_class: NamedTypeReferenceClass, source: str, name: QualifiedNameType):
		type_id = Type.generate_auto_type_id(source, name)
		return NamedTypeReferenceType.create(type_class, type_id, name)

	@staticmethod
	def generate_auto_demangled_type_ref(type_class: NamedTypeReferenceClass, name: QualifiedNameType):
		type_id = Type.generate_auto_demangled_type_id(name)
		return NamedTypeReferenceType.create(type_class, type_id, name)

	def _target_helper(self, bv: 'binaryview.BinaryView', type_ids=None) -> Optional[Type]:
		t = bv.get_type_by_id(self.type_id)
		if t is None:
			return None
		if type_ids is None:
			type_ids = set()
		if isinstance(t, NamedTypeReferenceType):
			if t.type_id in type_ids:
				raise TypeError("Can't get target for recursively defined type")
			type_ids.add(t)
			return t._target_helper(bv, type_ids)
		else:
			return t

	def target(self, bv: 'binaryview.BinaryView') -> Optional[Type]:
		"""Returns the type pointed to by the current type

		:param bv: The BinaryView in which this type is defined.
		:type bv: binaryview.BinaryView
		:return: The type this NamedTypeReference is referencing
		:rtype: Optional[Type]
		"""
		return self._target_helper(bv)


class WideCharType(Type):
	@classmethod
	def create(
	    cls, width: int, alternate_name: str = "", platform: Optional['_platform.Platform'] = None,
	    confidence: int = core.max_confidence
	) -> 'WideCharType':
		"""
		``wide_char`` class method for creating wide char Types.

		:param int width: width of the wide character in bytes
		:param str alternate_name: alternate name for type
		"""
		core_type = core.BNCreateWideCharType(width, alternate_name)
		assert core_type is not None, "core.BNCreateWideCharType returned None"
		return cls(core_type, platform, confidence)


Types = {
    TypeClass.VoidTypeClass: VoidType, TypeClass.BoolTypeClass: BoolType, TypeClass.IntegerTypeClass: IntegerType,
    TypeClass.FloatTypeClass: FloatType, TypeClass.StructureTypeClass: StructureType,
    TypeClass.EnumerationTypeClass: EnumerationType, TypeClass.PointerTypeClass: PointerType,
    TypeClass.ArrayTypeClass: ArrayType, TypeClass.FunctionTypeClass: FunctionType,
    TypeClass.NamedTypeReferenceClass: NamedTypeReferenceType, TypeClass.WideCharTypeClass: WideCharType,
}


@dataclass(frozen=True)
class RegisterSet:
	regs: List['architecture.RegisterName']
	confidence: int = core.max_confidence

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
class TypeFieldReference:
	func: Optional['_function.Function']
	arch: Optional['architecture.Architecture']
	address: int
	size: int
	incomingType: Optional[Type]

	def __repr__(self):
		if self.arch:
			return f"<ref: {self.arch.name}@{self.address:#x}, size: {self.size:#x}, type: {self.incomingType}>"
		else:
			return f"<ref: {self.address:#x}, size: {self.size:#x}, type: {self.incomingType}>"
