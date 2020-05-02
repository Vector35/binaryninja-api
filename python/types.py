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
max_confidence = 255

import ctypes

# Binary Ninja components
import binaryninja
from binaryninja import _binaryninjacore as core
from binaryninja.enums import SymbolType, SymbolBinding, TypeClass, NamedTypeReferenceClass, InstructionTextTokenType, StructureType, ReferenceType, VariableSourceType

# 2-3 compatibility
from binaryninja import range
from binaryninja import pyNativeStr


class QualifiedName(object):
	def __init__(self, name = []):
		if isinstance(name, str):
			self._name = [name]
			self._byte_name = [name.encode('charmap')]
		elif isinstance(name, self.__class__):
			self._name = name.name
			self._byte_name = [n.encode('charmap') for n in name.name]
		else:
			self._name = [pyNativeStr(i) for i in name]
			self._byte_name = name

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
			name_list[i] = self.name[i].encode('charmap')
		result.name = name_list
		result.nameCount = len(self.name)
		return result

	@classmethod
	def _from_core_struct(cls, name):
		result = []
		for i in range(0, name.nameCount):
			result.append(name.name[i])
		return QualifiedName(result)

	@property
	def name(self):
		""" """
		return self._name

	@name.setter
	def name(self, value):
		self._name = value

	@property
	def byte_name(self):
		""" """
		return self._byte_name

	@byte_name.setter
	def byte_name(self, value):
		self._byte_name = value


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

	@classmethod
	def _from_core_struct(cls, name):
		result = []
		for i in range(0, name.nameCount):
			result.append(name.name[i])
		return NameSpace(result)


class Symbol(object):
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
			self.handle = core.handle_of_type(handle, core.BNSymbol)
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
			self.handle = core.BNCreateSymbol(sym_type, short_name, full_name, raw_name, addr, binding, namespace, ordinal)

	def __del__(self):
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

	@property
	def aliases(self):
		"""
		List of aliases tied to this symbol.
		Aliases are the names of any other symbols that also happen to be at the same address.
		"""
		result = []
		count = ctypes.c_ulonglong(0)
		aliases = core.BNGetSymbolAliases(self.handle, count)
		for i in range(count.value):
			result.append(aliases[i])
		core.BNFreeStringList(aliases, count)
		return result


class FunctionParameter(object):
	def __init__(self, param_type, name = "", location = None):
		self._type = param_type
		self._name = name
		self._location = location

	def __repr__(self):
		if (self._location is not None) and (self._location.name != self._name):
			return "%s %s%s @ %s" % (self._type.get_string_before_name(), self._name, self._type.get_string_after_name(), self._location.name)
		return "%s %s%s" % (self._type.get_string_before_name(), self._name, self._type.get_string_after_name())

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
	def location(self):
		""" """
		return self._location

	@location.setter
	def location(self, value):
		self._location = value


class Type(object):
	"""
	``class Type`` allows you to interact with the Binary Ninja type system. Note that the ``repr`` and ``str``
	handlers respond differently on type objects.

	Other related functions that may be helpful include:

	:py:meth:`parse_type_string <binaryninja.binaryview.BinaryView.parse_type_string>`
	:py:meth:`parse_types_from_source <binaryninja.platform.Platform.parse_types_from_source>`
	:py:meth:`parse_types_from_source_file <binaryninja.platform.Platform.parse_types_from_source_file>`

	"""
	def __init__(self, handle, platform = None, confidence = max_confidence):
		self._handle = handle
		self._mutable = isinstance(handle.contents, core.BNTypeBuilder)
		self._confidence = confidence
		self._platform = platform

	def __del__(self):
		if self._mutable:
			core.BNFreeTypeBuilder(self._handle)
		else:
			core.BNFreeType(self._handle)

	def __repr__(self):
		if self._confidence < max_confidence:
			return "<type: %s, %d%% confidence>" % (str(self), (self._confidence * 100) // max_confidence)
		return "<type: %s>" % str(self)

	def __str__(self):
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		if self._mutable:
			return core.BNGetTypeBuilderString(self._handle, platform)
		name = self.registered_name
		if (name is not None) and (self.type_class != TypeClass.StructureTypeClass) and (self.type_class != TypeClass.EnumerationTypeClass):
			return self.get_string_before_name() + " " + str(name.name) + self.get_string_after_name()
		return core.BNGetTypeString(self._handle, platform)

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
		if self._mutable:
			# First use of a mutable Type makes it immutable
			finalized = core.BNFinalizeTypeBuilder(self._handle)
			core.BNFreeTypeBuilder(self._handle)
			self._handle = finalized
			self._mutable = False
		return self._handle

	@property
	def type_class(self):
		"""Type class (read-only)"""
		if self._mutable:
			return TypeClass(core.BNGetTypeBuilderClass(self._handle))
		return TypeClass(core.BNGetTypeClass(self._handle))

	@property
	def width(self):
		"""Type width (read-only)"""
		if self._mutable:
			return core.BNGetTypeBuilderWidth(self._handle)
		return core.BNGetTypeWidth(self._handle)

	@property
	def alignment(self):
		"""Type alignment (read-only)"""
		if self._mutable:
			return core.BNGetTypeBuilderAlignment(self._handle)
		return core.BNGetTypeAlignment(self._handle)

	@property
	def signed(self):
		"""Wether type is signed (read-only)"""
		if self._mutable:
			result = core.BNIsTypeBuilderSigned(self._handle)
		else:
			result = core.BNIsTypeSigned(self._handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@property
	def const(self):
		"""Whether type is const (read/write)"""
		if self._mutable:
			result = core.BNIsTypeBuilderConst(self._handle)
		else:
			result = core.BNIsTypeConst(self._handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@const.setter
	def const(self, value):
		if not self._mutable:
			raise AttributeError("Finalized Type object is immutable, use mutable_copy()")
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if hasattr(value, 'confidence'):
			bc.confidence = value.confidence
		else:
			bc.confidence = max_confidence
		core.BNTypeBuilderSetConst(self._handle, bc)

	@property
	def volatile(self):
		"""Whether type is volatile (read/write)"""
		if self._mutable:
			result = core.BNIsTypeBuilderVolatile(self._handle)
		else:
			result = core.BNIsTypeVolatile(self._handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@volatile.setter
	def volatile(self, value):
		if not self._mutable:
			raise AttributeError("Finalized Type object is immutable, use mutable_copy()")
		bc = core.BNBoolWithConfidence()
		bc.value = bool(value)
		if hasattr(value, 'confidence'):
			bc.confidence = value.confidence
		else:
			bc.confidence = max_confidence
		core.BNTypeBuilderSetVolatile(self._handle, bc)

	@property
	def floating_point(self):
		"""Whether type is floating point (read-only)"""
		if self._mutable:
			return core.BNIsTypeBuilderFloatingPoint(self._handle)
		return core.BNIsTypeFloatingPoint(self._handle)

	@property
	def target(self):
		"""Target (read-only)"""
		if self._mutable:
			result = core.BNGetTypeBuilderChildType(self._handle)
		else:
			result = core.BNGetChildType(self._handle)
		if not result.type:
			return None
		return Type(result.type, platform = self._platform, confidence = result.confidence)

	@property
	def element_type(self):
		"""Target (read-only)"""
		if self._mutable:
			result = core.BNGetTypeBuilderChildType(self._handle)
		else:
			result = core.BNGetChildType(self._handle)
		if not result.type:
			return None
		return Type(result.type, platform = self._platform, confidence = result.confidence)

	@property
	def return_value(self):
		"""Return value (read-only)"""
		if self._mutable:
			result = core.BNGetTypeBuilderChildType(self._handle)
		else:
			result = core.BNGetChildType(self._handle)
		if not result.type:
			return None
		return Type(result.type, platform = self._platform, confidence = result.confidence)

	@property
	def calling_convention(self):
		"""Calling convention (read-only)"""
		if self._mutable:
			result = core.BNGetTypeBuilderCallingConvention(self._handle)
		else:
			result = core.BNGetTypeCallingConvention(self._handle)
		if not result.convention:
			return None
		return binaryninja.callingconvention.CallingConvention(None, handle = result.convention, confidence = result.confidence)

	@property
	def parameters(self):
		"""Type parameters list (read-only)"""
		count = ctypes.c_ulonglong()
		if self._mutable:
			params = core.BNGetTypeBuilderParameters(self._handle, count)
		else:
			params = core.BNGetTypeParameters(self._handle, count)
		result = []
		for i in range(0, count.value):
			param_type = Type(core.BNNewTypeReference(params[i].type), platform = self._platform, confidence = params[i].typeConfidence)
			if params[i].defaultLocation:
				param_location = None
			else:
				name = params[i].name
				if (params[i].location.type == VariableSourceType.RegisterVariableSourceType) and (self._platform is not None):
					name = self._platform.arch.get_reg_name(params[i].location.storage)
				elif params[i].location.type == VariableSourceType.StackVariableSourceType:
					name = "arg_%x" % params[i].location.storage
				param_location = binaryninja.function.Variable(None, params[i].location.type, params[i].location.index,
					params[i].location.storage, name, param_type)
			result.append(FunctionParameter(param_type, params[i].name, param_location))
		core.BNFreeTypeParameterList(params, count.value)
		return result

	@property
	def has_variable_arguments(self):
		"""Whether type has variable arguments (read-only)"""
		if self._mutable:
			result = core.BNTypeBuilderHasVariableArguments(self._handle)
		else:
			result = core.BNTypeHasVariableArguments(self._handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@property
	def can_return(self):
		"""Whether type can return (read-only)"""
		if self._mutable:
			result = core.BNFunctionTypeBuilderCanReturn(self._handle)
		else:
			result = core.BNFunctionTypeCanReturn(self._handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@property
	def structure(self):
		"""Structure of the type (read-only)"""
		if self._mutable:
			result = core.BNGetTypeBuilderStructure(self._handle)
		else:
			result = core.BNGetTypeStructure(self._handle)
		if result is None:
			return None
		return Structure(result)

	@property
	def enumeration(self):
		"""Type enumeration (read-only)"""
		if self._mutable:
			result = core.BNGetTypeBuilderEnumeration(self._handle)
		else:
			result = core.BNGetTypeEnumeration(self._handle)
		if result is None:
			return None
		return Enumeration(result)

	@property
	def named_type_reference(self):
		"""Reference to a named type (read-only)"""
		if self._mutable:
			result = core.BNGetTypeBuilderNamedTypeReference(self._handle)
		else:
			result = core.BNGetTypeNamedTypeReference(self._handle)
		if result is None:
			return None
		return NamedTypeReference(handle = result)

	@property
	def count(self):
		"""Type count (read-only)"""
		if self._mutable:
			return core.BNGetTypeBuilderElementCount(self._handle)
		return core.BNGetTypeElementCount(self._handle)

	@property
	def offset(self):
		"""Offset into structure (read-only)"""
		if self._mutable:
			return core.BNGetTypeBuilderOffset(self._handle)
		return core.BNGetTypeOffset(self._handle)

	@property
	def stack_adjustment(self):
		"""Stack adjustment for function (read-only)"""
		if self._mutable:
			result = core.BNGetTypeBuilderStackAdjustment(self._handle)
		else:
			result = core.BNGetTypeStackAdjustment(self._handle)
		return SizeWithConfidence(result.value, confidence = result.confidence)

	@property
	def registered_name(self):
		"""Name of type registered to binary view, if any (read-only)"""
		if self._mutable:
			return None
		name = core.BNGetRegisteredTypeName(self._handle)
		if not name:
			return None
		return NamedTypeReference(handle = name)

	def get_string_before_name(self):
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		if self._mutable:
			return core.BNGetTypeBuilderStringBeforeName(self._handle, platform)
		return core.BNGetTypeStringBeforeName(self._handle, platform)

	def get_string_after_name(self):
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		if self._mutable:
			return core.BNGetTypeBuilderStringAfterName(self._handle, platform)
		return core.BNGetTypeStringAfterName(self._handle, platform)

	@property
	def tokens(self):
		"""Type string as a list of tokens (read-only)"""
		return self.get_tokens()

	def get_tokens(self, base_confidence = max_confidence):
		count = ctypes.c_ulonglong()
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		if self._mutable:
			tokens = core.BNGetTypeBuilderTokens(self._handle, platform, base_confidence, count)
		else:
			tokens = core.BNGetTypeTokens(self._handle, platform, base_confidence, count)
		result = binaryninja.function.InstructionTextToken.get_instruction_lines(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	def get_tokens_before_name(self, base_confidence = max_confidence):
		count = ctypes.c_ulonglong()
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		if self._mutable:
			tokens = core.BNGetTypeBuilderTokensBeforeName(self._handle, platform, base_confidence, count)
		else:
			tokens = core.BNGetTypeTokensBeforeName(self._handle, platform, base_confidence, count)
		result = binaryninja.function.InstructionTextToken.get_instruction_lines(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	def get_tokens_after_name(self, base_confidence = max_confidence):
		count = ctypes.c_ulonglong()
		platform = None
		if self._platform is not None:
			platform = self._platform.handle
		if self._mutable:
			tokens = core.BNGetTypeBuilderTokensAfterName(self._handle, platform, base_confidence, count)
		else:
			tokens = core.BNGetTypeTokensAfterName(self._handle, platform, base_confidence, count)
		result = binaryninja.function.InstructionTextToken.get_instruction_lines(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	@classmethod
	def void(cls):
		return Type(core.BNCreateVoidTypeBuilder())

	@classmethod
	def bool(self):
		return Type(core.BNCreateBoolTypeBuilder())

	@classmethod
	def char(self):
		return Type.int(1, True)

	@classmethod
	def int(self, width, sign = None, altname=""):
		"""
		``int`` class method for creating an int Type.

		:param int width: width of the integer in bytes
		:param bool sign: optional variable representing signedness
		:param str altname: alternate name for type
		"""
		if sign is None:
			sign = BoolWithConfidence(True, confidence = 0)
		elif not isinstance(sign, BoolWithConfidence):
			sign = BoolWithConfidence(sign)

		sign_conf = core.BNBoolWithConfidence()
		sign_conf.value = sign.value
		sign_conf.confidence = sign.confidence

		return Type(core.BNCreateIntegerTypeBuilder(width, sign_conf, altname))

	@classmethod
	def float(self, width, altname=""):
		"""
		``float`` class method for creating an floating point Types.

		:param int width: width of the floating point number in bytes
		:param str altname: alternate name for type
		"""
		return Type(core.BNCreateFloatTypeBuilder(width, altname))

	@classmethod
	def structure_type(self, structure_type):
		return Type(core.BNCreateStructureTypeBuilder(structure_type.handle))

	@classmethod
	def named_type(self, named_type, width = 0, align = 1):
		return Type(core.BNCreateNamedTypeReferenceBuilder(named_type.handle, width, align))

	@classmethod
	def named_type_from_type_and_id(self, type_id, name, t):
		name = QualifiedName(name)._get_core_struct()
		if t is not None:
			t = t.handle
		return Type(core.BNCreateNamedTypeReferenceBuilderFromTypeAndId(type_id, name, t))

	@classmethod
	def named_type_from_type(self, name, t):
		name = QualifiedName(name)._get_core_struct()
		if t is not None:
			t = t.handle
		return Type(core.BNCreateNamedTypeReferenceBuilderFromTypeAndId("", name, t))

	@classmethod
	def named_type_from_registered_type(self, view, name):
		name = QualifiedName(name)._get_core_struct()
		return Type(core.BNCreateNamedTypeReferenceBuilderFromType(view.handle, name))

	@classmethod
	def enumeration_type(self, arch, e, width=None, sign=False):
		if width is None:
			width = arch.default_int_size
		return Type(core.BNCreateEnumerationTypeBuilder(arch.handle, e.handle, width, sign))

	@classmethod
	def pointer(self, arch, t, const=None, volatile=None, ref_type=None):
		if const is None:
			const = BoolWithConfidence(False, confidence = 0)
		elif not isinstance(const, BoolWithConfidence):
			const = BoolWithConfidence(const)

		if volatile is None:
			volatile = BoolWithConfidence(False, confidence = 0)
		elif not isinstance(volatile, BoolWithConfidence):
			volatile = BoolWithConfidence(volatile)

		if ref_type is None:
			ref_type = ReferenceType.PointerReferenceType

		type_conf = core.BNTypeWithConfidence()
		type_conf.type = t.handle
		type_conf.confidence = t.confidence

		const_conf = core.BNBoolWithConfidence()
		const_conf.value = const.value
		const_conf.confidence = const.confidence

		volatile_conf = core.BNBoolWithConfidence()
		volatile_conf.value = volatile.value
		volatile_conf.confidence = volatile.confidence

		return Type(core.BNCreatePointerTypeBuilder(arch.handle, type_conf, const_conf, volatile_conf, ref_type))

	@classmethod
	def array(self, t, count):
		type_conf = core.BNTypeWithConfidence()
		type_conf.type = t.handle
		type_conf.confidence = t.confidence
		return Type(core.BNCreateArrayTypeBuilder(type_conf, count))

	@classmethod
	def function(self, ret, params, calling_convention=None, variable_arguments=None, stack_adjust=None):
		"""
		``function`` class method for creating an function Type.

		:param Type ret: return Type of the function
		:param params: list of parameter Types
		:type params: list(Type)
		:param CallingConvention calling_convention: optional argument for the function calling convention
		:param bool variable_arguments: optional boolean, true if the function has a variable number of arguments
		"""
		param_buf = (core.BNFunctionParameter * len(params))()
		for i in range(0, len(params)):
			if isinstance(params[i], Type):
				param_buf[i].name = ""
				param_buf[i].type = params[i].handle
				param_buf[i].typeConfidence = params[i].confidence
				param_buf[i].defaultLocation = True
			elif isinstance(params[i], FunctionParameter):
				param_buf[i].name = params[i].name
				param_buf[i].type = params[i].type.handle
				param_buf[i].typeConfidence = params[i].type.confidence
				if params[i].location is None:
					param_buf[i].defaultLocation = True
				else:
					param_buf[i].defaultLocation = False
					param_buf[i].location.type = params[i].location.source_type
					param_buf[i].location.index = params[i].location.index
					param_buf[i].location.storage = params[i].location.storage
			else:
				param_buf[i].name = params[i][1]
				param_buf[i].type = params[i][0].handle
				param_buf[i].typeConfidence = params[i][0].confidence
				param_buf[i].defaultLocation = True

		ret_conf = core.BNTypeWithConfidence()
		ret_conf.type = ret.handle
		ret_conf.confidence = ret.confidence

		conv_conf = core.BNCallingConventionWithConfidence()
		if calling_convention is None:
			conv_conf.convention = None
			conv_conf.confidence = 0
		else:
			conv_conf.convention = calling_convention.handle
			conv_conf.confidence = calling_convention.confidence

		if variable_arguments is None:
			variable_arguments = BoolWithConfidence(False, confidence = 0)
		elif not isinstance(variable_arguments, BoolWithConfidence):
			variable_arguments = BoolWithConfidence(variable_arguments)

		vararg_conf = core.BNBoolWithConfidence()
		vararg_conf.value = variable_arguments.value
		vararg_conf.confidence = variable_arguments.confidence

		if stack_adjust is None:
			stack_adjust = SizeWithConfidence(0, confidence = 0)
		elif not isinstance(stack_adjust, SizeWithConfidence):
			stack_adjust = SizeWithConfidence(stack_adjust)

		stack_adjust_conf = core.BNOffsetWithConfidence()
		stack_adjust_conf.value = stack_adjust.value
		stack_adjust_conf.confidence = stack_adjust.confidence

		return Type(core.BNCreateFunctionTypeBuilder(ret_conf, conv_conf, param_buf, len(params),
			vararg_conf, stack_adjust_conf))

	@classmethod
	def generate_auto_type_id(self, source, name):
		name = QualifiedName(name)._get_core_struct()
		return core.BNGenerateAutoTypeId(source, name)

	@classmethod
	def generate_auto_demangled_type_id(self, name):
		name = QualifiedName(name)._get_core_struct()
		return core.BNGenerateAutoDemangledTypeId(name)

	@classmethod
	def get_auto_demangled_type_id_source(self):
		return core.BNGetAutoDemangledTypeIdSource()

	def with_confidence(self, confidence):
		return Type(handle = core.BNNewTypeReference(self._handle), platform = self._platform, confidence = confidence)

	@property
	def confidence(self):
		""" """
		return self._confidence

	@confidence.setter
	def confidence(self, value):
		self._confidence = value

	@property
	def platform(self):
		""" """
		return self._platform

	@platform.setter
	def platform(self, value):
		self._platform = value

	def mutable_copy(self):
		if self._mutable:
			return Type(core.BNDuplicateTypeBuilder(self._handle), confidence = self._confidence)
		return Type(core.BNCreateTypeBuilderFromType(self._handle), confidence = self._confidence)

	def with_replaced_structure(self, from_struct, to_struct):
		return Type(handle = core.BNTypeWithReplacedStructure(self._handle, from_struct.handle, to_struct.handle))

	def with_replaced_enumeration(self, from_enum, to_enum):
		return Type(handle = core.BNTypeWithReplacedEnumeration(self._handle, from_enum.handle, to_enum.handle))

	def with_replaced_named_type_reference(self, from_ref, to_ref):
		return Type(handle = core.BNTypeWithReplacedNamedTypeReference(self._handle, from_ref.handle, to_ref.handle))


class BoolWithConfidence(object):
	def __init__(self, value, confidence = max_confidence):
		self._value = value
		self._confidence = confidence

	def __str__(self):
		return str(self._value)

	def __repr__(self):
		return repr(self._value)

	def __bool__(self):
		return self._value

	def __nonzero__(self):
		return self._value

	@property
	def value(self):
		""" """
		return self._value

	@value.setter
	def value(self, value):
		self._value = value

	@property
	def confidence(self):
		""" """
		return self._confidence

	@confidence.setter
	def confidence(self, value):
		self._confidence = value


class SizeWithConfidence(object):
	def __init__(self, value, confidence = max_confidence):
		self._value = value
		self._confidence = confidence

	def __str__(self):
		return str(self._value)

	def __repr__(self):
		return repr(self._value)

	def __int__(self):
		return self._value

	@property
	def value(self):
		""" """
		return self._value

	@value.setter
	def value(self, value):
		self._value = value

	@property
	def confidence(self):
		""" """
		return self._confidence

	@confidence.setter
	def confidence(self, value):
		self._confidence = value


class RegisterStackAdjustmentWithConfidence(object):
	def __init__(self, value, confidence = max_confidence):
		self._value = value
		self._confidence = confidence

	def __str__(self):
		return str(self._value)

	def __repr__(self):
		return repr(self._value)

	def __int__(self):
		return self._value

	@property
	def value(self):
		""" """
		return self._value

	@value.setter
	def value(self, value):
		self._value = value

	@property
	def confidence(self):
		""" """
		return self._confidence

	@confidence.setter
	def confidence(self, value):
		self._confidence = value


class RegisterSet(object):
	def __init__(self, reg_list, confidence = max_confidence):
		self._regs = reg_list
		self._confidence = confidence

	def __repr__(self):
		return repr(self._regs)

	def __iter__(self):
		for reg in self._regs:
			yield reg

	def __getitem__(self, idx):
		return self._regs[idx]

	def __len__(self):
		return len(self._regs)

	def with_confidence(self, confidence):
		return RegisterSet(list(self._regs), confidence = confidence)

	@property
	def regs(self):
		""" """
		return self._regs

	@regs.setter
	def regs(self, value):
		self._regs = value

	@property
	def confidence(self):
		""" """
		return self._confidence

	@confidence.setter
	def confidence(self, value):
		self._confidence = value


class ReferenceTypeWithConfidence(object):
	def __init__(self, value, confidence = max_confidence):
		self._value = value
		self._confidence = confidence

	def __str__(self):
		return str(self._value)

	def __repr__(self):
		return repr(self._value)

	@property
	def value(self):
		""" """
		return self._value

	@value.setter
	def value(self, value):
		self._value = value

	@property
	def confidence(self):
		""" """
		return self._confidence

	@confidence.setter
	def confidence(self, value):
		self._confidence = value


class NamedTypeReference(object):
	def __init__(self, type_class = NamedTypeReferenceClass.UnknownNamedTypeClass, type_id = None, name = None, handle = None):
		if handle is None:
			if name is not None:
				name = QualifiedName(name)._get_core_struct()
			self.handle = core.BNCreateNamedType(type_class, type_id, name)
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeNamedTypeReference(self.handle)

	def __repr__(self):
		if self.type_class == NamedTypeReferenceClass.TypedefNamedTypeClass:
			return "<named type: typedef %s>" % str(self.name)
		if self.type_class == NamedTypeReferenceClass.StructNamedTypeClass:
			return "<named type: struct %s>" % str(self.name)
		if self.type_class == NamedTypeReferenceClass.UnionNamedTypeClass:
			return "<named type: union %s>" % str(self.name)
		if self.type_class == NamedTypeReferenceClass.EnumNamedTypeClass:
			return "<named type: enum %s>" % str(self.name)
		return "<named type: unknown %s>" % str(self.name)

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
	def type_class(self):
		return NamedTypeReferenceClass(core.BNGetTypeReferenceClass(self.handle))

	@property
	def type_id(self):
		return core.BNGetTypeReferenceId(self.handle)

	@property
	def name(self):
		name = core.BNGetTypeReferenceName(self.handle)
		result = QualifiedName._from_core_struct(name)
		core.BNFreeQualifiedName(name)
		return result

	@classmethod
	def generate_auto_type_ref(self, type_class, source, name):
		type_id = Type.generate_auto_type_id(source, name)
		return NamedTypeReference(type_class, type_id, name)

	@classmethod
	def generate_auto_demangled_type_ref(self, type_class, name):
		type_id = Type.generate_auto_demangled_type_id(name)
		return NamedTypeReference(type_class, type_id, name)


class StructureMember(object):
	def __init__(self, t, name, offset):
		self._type = t
		self._name = name
		self._offset = offset

	def __repr__(self):
		if len(self._name) == 0:
			return "<member: %s, offset %#x>" % (str(self._type), self._offset)
		return "<%s %s%s, offset %#x>" % (self._type.get_string_before_name(), self._name,
							 self._type.get_string_after_name(), self._offset)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._type, self._name, self._offset) == (other._type, other._name, other._offset)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __lt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._offset < other._offset

	def __gt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._offset > other._offset

	def __le__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._offset <= other._offset

	def __ge__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._offset >= other._offset

	def __hash__(self):
		return hash((self._type, self._name, self._offset))

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
	def offset(self):
		""" """
		return self._offset

	@offset.setter
	def offset(self, value):
		self._offset = value


class Structure(object):
	def __init__(self, handle=None):
		if handle is None:
			self._handle = core.BNCreateStructureBuilder()
			self._mutable = True
		else:
			self._handle = handle
			self._mutable = isinstance(handle.contents, core.BNStructureBuilder)

	def __del__(self):
		if self._mutable:
			core.BNFreeStructureBuilder(self._handle)
		else:
			core.BNFreeStructure(self._handle)

	def __repr__(self):
		return "<struct: size %#x>" % self.width

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self._handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self._handle.contents))

	def __getitem__(self, name):
		try:
			if self._mutable:
				member = core.BNGetStructureBuilderMemberByName(self._handle, name)
			else:
				member = core.BNGetStructureMemberByName(self._handle, name)
			return StructureMember(Type(core.BNNewTypeReference(member.contents.type), confidence=member.contents.typeConfidence),
					member.contents.name, member.contents.offset)
		finally:
			core.BNFreeStructureMember(member)

	def member_at_offset(self, offset):
		try:
			if self._mutable:
				member = core.BNGetStructureBuilderMemberAtOffset(self._handle, offset, None)
			else:
				member = core.BNGetStructureMemberAtOffset(self._handle, offset, None)
			return StructureMember(Type(core.BNNewTypeReference(member.contents.type), confidence=member.contents.typeConfidence),
					member.contents.name, member.contents.offset)
		finally:
			core.BNFreeStructureMember(member)

	@property
	def handle(self):
		if self._mutable:
			# First use of a mutable Structure makes it immutable
			finalized = core.BNFinalizeStructureBuilder(self._handle)
			core.BNFreeStructureBuilder(self._handle)
			self._handle = finalized
			self._mutable = False
		return self._handle

	@property
	def members(self):
		"""Structure member list (read-only)"""
		count = ctypes.c_ulonglong()
		if self._mutable:
			members = core.BNGetStructureBuilderMembers(self._handle, count)
		else:
			members = core.BNGetStructureMembers(self._handle, count)
		try:
			result = []
			for i in range(0, count.value):
				result.append(StructureMember(Type(core.BNNewTypeReference(members[i].type), confidence=members[i].typeConfidence),
					members[i].name, members[i].offset))
		finally:
			core.BNFreeStructureMemberList(members, count.value)
		return result

	@property
	def width(self):
		"""Structure width"""
		if self._mutable:
			return core.BNGetStructureBuilderWidth(self._handle)
		return core.BNGetStructureWidth(self._handle)

	@width.setter
	def width(self, new_width):
		if not self._mutable:
			raise AttributeError("Finalized Structure object is immutable, use mutable_copy()")
		core.BNSetStructureBuilderWidth(self._handle, new_width)

	@property
	def alignment(self):
		"""Structure alignment"""
		if self._mutable:
			return core.BNGetStructureBuilderAlignment(self._handle)
		return core.BNGetStructureAlignment(self._handle)

	@alignment.setter
	def alignment(self, align):
		if not self._mutable:
			raise AttributeError("Finalized Structure object is immutable, use mutable_copy()")
		core.BNSetStructureBuilderAlignment(self._handle, align)

	@property
	def packed(self):
		if self._mutable:
			return core.BNIsStructureBuilderPacked(self._handle)
		return core.BNIsStructurePacked(self._handle)

	@packed.setter
	def packed(self, value):
		if not self._mutable:
			raise AttributeError("Finalized Structure object is immutable, use mutable_copy()")
		core.BNSetStructureBuilderPacked(self._handle, value)

	@property
	def union(self):
		if self._mutable:
			return core.BNIsStructureBuilderUnion(self._handle)
		return core.BNIsStructureUnion(self._handle)

	@property
	def type(self):
		if self._mutable:
			return StructureType(core.BNGetStructureBuilderType(self._handle))
		return StructureType(core.BNGetStructureType(self._handle))

	@type.setter
	def type(self, value):
		if not self._mutable:
			raise AttributeError("Finalized Structure object is immutable, use mutable_copy()")
		core.BNSetStructureBuilderType(self._handle, value)

	def append(self, t, name = ""):
		if not self._mutable:
			raise AttributeError("Finalized Structure object is immutable, use mutable_copy()")
		tc = core.BNTypeWithConfidence()
		tc.type = t.handle
		tc.confidence = t.confidence
		core.BNAddStructureBuilderMember(self._handle, tc, name)

	def insert(self, offset, t, name = ""):
		if not self._mutable:
			raise AttributeError("Finalized Structure object is immutable, use mutable_copy()")
		tc = core.BNTypeWithConfidence()
		tc.type = t.handle
		tc.confidence = t.confidence
		core.BNAddStructureBuilderMemberAtOffset(self._handle, tc, name, offset)

	def remove(self, i):
		if not self._mutable:
			raise AttributeError("Finalized Structure object is immutable, use mutable_copy()")
		core.BNRemoveStructureBuilderMember(self._handle, i)

	def replace(self, i, t, name = ""):
		if not self._mutable:
			raise AttributeError("Finalized Structure object is immutable, use mutable_copy()")
		tc = core.BNTypeWithConfidence()
		tc.type = t.handle
		tc.confidence = t.confidence
		core.BNReplaceStructureBuilderMember(self._handle, i, tc, name)

	def mutable_copy(self):
		if self._mutable:
			return Structure(core.BNDuplicateStructureBuilder(self._handle))
		return Structure(core.BNCreateStructureBuilderFromStructure(self._handle))

	def with_replaced_structure(self, from_struct, to_struct):
		return Structure(core.BNStructureWithReplacedStructure(self._handle, from_struct.handle, to_struct.handle))

	def with_replaced_enumeration(self, from_enum, to_enum):
		return Structure(core.BNStructureWithReplacedEnumeration(self._handle, from_enum.handle, to_enum.handle))

	def with_replaced_named_type_reference(self, from_ref, to_ref):
		return Structure(core.BNStructureWithReplacedNamedTypeReference(self._handle, from_ref.handle, to_ref.handle))


class EnumerationMember(object):
	def __init__(self, name, value, default):
		self.name = name
		self.value = value
		self.default = default

	def __repr__(self):
		return "<%s = %#x>" % (self.name, self.value)

	@property
	def value(self):
		""" """
		return self._value

	@value.setter
	def value(self, value):
		self._value = value

	@property
	def name(self):
		""" """
		return self._name

	@name.setter
	def name(self, value):
		self._name = value

	@property
	def default(self):
		""" """
		return self._default

	@default.setter
	def default(self, value):
		self._default = value


class Enumeration(object):
	def __init__(self, handle=None):
		if handle is None:
			self._handle = core.BNCreateEnumerationBuilder()
			self._mutable = True
		else:
			self._handle = handle
			self._mutable = isinstance(handle.contents, core.BNEnumerationBuilder)

	def __del__(self):
		if self._mutable:
			core.BNFreeEnumerationBuilder(self._handle)
		else:
			core.BNFreeEnumeration(self._handle)

	def __repr__(self):
		return "<enum: %s>" % repr(self.members)

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
	def handle(self):
		if self._mutable:
			# First use of a mutable Enumeration makes it immutable
			finalized = core.BNFinalizeEnumerationBuilder(self._handle)
			core.BNFreeEnumerationBuilder(self._handle)
			self._handle = finalized
			self._mutable = False
		return self._handle

	@property
	def members(self):
		"""Enumeration member list (read-only)"""
		count = ctypes.c_ulonglong()
		if self._mutable:
			members = core.BNGetEnumerationBuilderMembers(self._handle, count)
		else:
			members = core.BNGetEnumerationMembers(self._handle, count)
		result = []
		for i in range(0, count.value):
			result.append(EnumerationMember(members[i].name, members[i].value, members[i].isDefault))
		core.BNFreeEnumerationMemberList(members, count.value)
		return result

	def append(self, name, value = None):
		if not self._mutable:
			raise AttributeError("Finalized Enumeration object is immutable, use mutable_copy()")
		if value is None:
			core.BNAddEnumerationBuilderMember(self._handle, name)
		else:
			core.BNAddEnumerationBuilderMemberWithValue(self._handle, name, value)

	def remove(self, i):
		if not self._mutable:
			raise AttributeError("Finalized Enumeration object is immutable, use mutable_copy()")
		core.BNRemoveEnumerationBuilderMember(self._handle, i)

	def replace(self, i, name, value):
		if not self._mutable:
			raise AttributeError("Finalized Enumeration object is immutable, use mutable_copy()")
		core.BNReplaceEnumerationBuilderMember(self._handle, i, name, value)

	def mutable_copy(self):
		if self._mutable:
			return Enumeration(core.BNDuplicateEnumerationBuilder(self._handle))
		return Enumeration(core.BNCreateEnumerationBuilderFromEnumeration(self._handle))


class TypeParserResult(object):
	def __init__(self, types, variables, functions):
		self._types = types
		self._variables = variables
		self._functions = functions

	def __repr__(self):
		return "<types: %s, variables: %s, functions: %s>" % (self._types, self._variables, self._functions)

	@property
	def types(self):
		""" """
		return self._types

	@types.setter
	def types(self, value):
		self._types = value

	@property
	def variables(self):
		""" """
		return self._variables

	@variables.setter
	def variables(self, value):
		self._variables = value

	@property
	def functions(self):
		""" """
		return self._functions

	@functions.setter
	def functions(self, value):
		self._functions = value


def preprocess_source(source, filename=None, include_dirs=[]):
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
	output_str = output.value
	error_str = errors.value
	core.BNFreeString(ctypes.cast(output, ctypes.POINTER(ctypes.c_byte)))
	core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
	if result:
		return (output_str, error_str)
	return (None, error_str)
