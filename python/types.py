# Copyright (c) 2015-2016 Vector 35 LLC
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

# Binary Ninja components
import _binaryninjacore as core
from enums import SymbolType, TypeClass, NamedTypeReferenceClass
import callingconvention


class QualifiedName(object):
	def __init__(self, name = []):
		if isinstance(name, str):
			self.name = [name]
		elif isinstance(name, QualifiedName):
			self.name = name.name
		else:
			self.name = name

	def __str__(self):
		return "::".join(self.name)

	def __repr__(self):
		return repr(str(self))

	def __len__(self):
		return len(self.name)

	def __hash__(self):
		return hash(str(self))

	def __eq__(self, other):
		if isinstance(other, str):
			return str(self) == other
		elif isinstance(other, list):
			return self.name == other
		elif isinstance(other, QualifiedName):
			return self.name == other.name
		return False

	def __ne__(self, other):
		return not (self == other)

	def __lt__(self, other):
		if isinstance(other, QualifiedName):
			return self.name < other.name
		return False

	def __le__(self, other):
		if isinstance(other, QualifiedName):
			return self.name <= other.name
		return False

	def __gt__(self, other):
		if isinstance(other, QualifiedName):
			return self.name > other.name
		return False

	def __ge__(self, other):
		if isinstance(other, QualifiedName):
			return self.name >= other.name
		return False

	def __cmp__(self, other):
		if self == other:
			return 0
		if self < other:
			return -1
		return 1

	def __getitem__(self, key):
		return self.name[key]

	def __iter__(self):
		return iter(self.name)

	def _get_core_struct(self):
		result = core.BNQualifiedName()
		name_list = (ctypes.c_char_p * len(self.name))()
		for i in xrange(0, len(self.name)):
			name_list[i] = self.name[i]
		result.name = name_list
		result.nameCount = len(self.name)
		return result

	@classmethod
	def _from_core_struct(cls, name):
		result = []
		for i in xrange(0, name.nameCount):
			result.append(name.name[i])
		return QualifiedName(result)


class Symbol(object):
	"""
	Symbols are defined as one of the following types:

		=========================== ==============================================================
		SymbolType                  Description
		=========================== ==============================================================
		FunctionSymbol              Symbol for Function that exists in the current binary
		ImportAddressSymbol         Symbol defined in the Import Address Table
		ImportedFunctionSymbol      Symbol for Function that is not defined in the current binary
		DataSymbol                  Symbol for Data in the current binary
		ImportedDataSymbol          Symbol for Data that is not defined in the current binary
		=========================== ==============================================================
	"""
	def __init__(self, sym_type, addr, short_name, full_name = None, raw_name = None, handle = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNSymbol)
		else:
			if isinstance(sym_type, str):
				sym_type = SymbolType[sym_type]
			if full_name is None:
				full_name = short_name
			if raw_name is None:
				raw_name = full_name
			self.handle = core.BNCreateSymbol(sym_type, short_name, full_name, raw_name, addr)

	def __del__(self):
		core.BNFreeSymbol(self.handle)

	@property
	def type(self):
		"""Symbol type (read-only)"""
		return SymbolType(core.BNGetSymbolType(self.handle))

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
	def auto(self):
		return core.BNIsSymbolAutoDefined(self.handle)

	@auto.setter
	def auto(self, value):
		core.BNSetSymbolAutoDefined(self.handle, value)

	def __repr__(self):
		return "<%s: \"%s\" @ %#x>" % (self.type, self.full_name, self.address)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class Type(object):
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		core.BNFreeType(self.handle)

	@property
	def type_class(self):
		"""Type class (read-only)"""
		return TypeClass(core.BNGetTypeClass(self.handle))

	@property
	def width(self):
		"""Type width (read-only)"""
		return core.BNGetTypeWidth(self.handle)

	@property
	def alignment(self):
		"""Type alignment (read-only)"""
		return core.BNGetTypeAlignment(self.handle)

	@property
	def signed(self):
		"""Wether type is signed (read-only)"""
		return core.BNIsTypeSigned(self.handle)

	@property
	def const(self):
		"""Whether type is const (read-only)"""
		return core.BNIsTypeConst(self.handle)

	@property
	def modified(self):
		"""Whether type is modified (read-only)"""
		return core.BNIsTypeFloatingPoint(self.handle)

	@property
	def target(self):
		"""Target (read-only)"""
		result = core.BNGetChildType(self.handle)
		if result is None:
			return None
		return Type(result)

	@property
	def element_type(self):
		"""Target (read-only)"""
		result = core.BNGetChildType(self.handle)
		if result is None:
			return None
		return Type(result)

	@property
	def return_value(self):
		"""Return value (read-only)"""
		result = core.BNGetChildType(self.handle)
		if result is None:
			return None
		return Type(result)

	@property
	def calling_convention(self):
		"""Calling convention (read-only)"""
		result = core.BNGetTypeCallingConvention(self.handle)
		if result is None:
			return None
		return callingconvention.CallingConvention(None, result)

	@property
	def parameters(self):
		"""Type parameters list (read-only)"""
		count = ctypes.c_ulonglong()
		params = core.BNGetTypeParameters(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append((Type(core.BNNewTypeReference(params[i].type)), params[i].name))
		core.BNFreeTypeParameterList(params, count.value)
		return result

	@property
	def has_variable_arguments(self):
		"""Whether type has variable arguments (read-only)"""
		return core.BNTypeHasVariableArguments(self.handle)

	@property
	def can_return(self):
		"""Whether type can return (read-only)"""
		return core.BNFunctionTypeCanReturn(self.handle)

	@property
	def structure(self):
		"""Structure of the type (read-only)"""
		result = core.BNGetTypeStructure(self.handle)
		if result is None:
			return None
		return Structure(result)

	@property
	def enumeration(self):
		"""Type enumeration (read-only)"""
		result = core.BNGetTypeEnumeration(self.handle)
		if result is None:
			return None
		return Enumeration(result)

 	@property
	def named_type_reference(self):
		"""Reference to a named type (read-only)"""
		result = core.BNGetTypeNamedTypeReference(self.handle)
		if result is None:
			return None
		return NamedTypeReference(result)

	@property
	def count(self):
		"""Type count (read-only)"""
		return core.BNGetTypeElementCount(self.handle)

	def __str__(self):
		return core.BNGetTypeString(self.handle)

	def __repr__(self):
		return "<type: %s>" % str(self)

	def get_string_before_name(self):
		return core.BNGetTypeStringBeforeName(self.handle)

	def get_string_after_name(self):
		return core.BNGetTypeStringAfterName(self.handle)

	@classmethod
	def void(cls):
		return Type(core.BNCreateVoidType())

	@classmethod
	def bool(self):
		return Type(core.BNCreateBoolType())

	@classmethod
	def int(self, width, sign = True, altname=""):
		return Type(core.BNCreateIntegerType(width, sign, altname))

	@classmethod
	def float(self, width):
		return Type(core.BNCreateFloatType(width))

	@classmethod
	def structure_type(self, structure_type):
		return Type(core.BNCreateStructureType(structure_type.handle))

	@classmethod
	def named_type(self, named_type, width = 0, align = 1):
		return Type(core.BNCreateNamedTypeReference(named_type.handle, width, align))

	@classmethod
	def named_type_from_type(self, name, t):
		name = QualifiedName(name)._get_core_struct()
		if t is not None:
			t = t.handle
		return Type(core.BNCreateNamedTypeReferenceFromType(name, t))

	@classmethod
	def enumeration_type(self, arch, e, width=None):
		if width is None:
			width = arch.default_int_size
		return Type(core.BNCreateEnumerationType(e.handle, width))

	@classmethod
	def pointer(self, arch, t, const=False):
		return Type(core.BNCreatePointerType(arch.handle, t.handle, const))

	@classmethod
	def array(self, t, count):
		return Type(core.BNCreateArrayType(t.handle, count))

	@classmethod
	def function(self, ret, params, calling_convention=None, variable_arguments=False):
		param_buf = (core.BNNameAndType * len(params))()
		for i in xrange(0, len(params)):
			if isinstance(params[i], Type):
				param_buf[i].name = ""
				param_buf[i].type = params[i].handle
			else:
				param_buf[i].name = params[i][1]
				param_buf[i].type = params[i][0]
		if calling_convention is not None:
			calling_convention = calling_convention.handle
		return Type(core.BNCreateFunctionType(ret.handle, calling_convention, param_buf, len(params),
			  variable_arguments))

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class NamedTypeReference(object):
	def __init__(self, type_class = NamedTypeReferenceClass.UnknownNamedTypeClass, name = None, handle = None):
		if handle is None:
			self.handle = core.BNCreateNamedType()
			core.BNSetTypeReferenceClass(self.handle, type_class)
			if name is not None:
				name = QualifiedName(name)._get_core_struct()
				core.BNSetTypeReferenceName(self.handle, name)
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeNamedTypeReference(self.handle)

	@property
	def type_class(self):
		return core.BNGetTypeReferenceClass(self.handle)

	@type_class.setter
	def type_class(self, value):
		core.BNSetTypeReferenceClass(self.handle, value)

	@property
	def name(self):
		count = ctypes.c_ulonglong()
		name = core.BNGetTypeReferenceName(self.handle, count)
		result = QualifiedName._from_core_struct(name)
		core.BNFreeQualifiedName(name)
		return result

	@name.setter
	def name(self, value):
		value = QualifiedName(value)._get_core_struct()
		core.BNSetTypeReferenceName(self.handle, value)

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


class StructureMember(object):
	def __init__(self, t, name, offset):
		self.type = t
		self.name = name
		self.offset = offset

	def __repr__(self):
		if len(self.name) == 0:
			return "<member: %s, offset %#x>" % (str(self.type), self.offset)
		return "<%s %s%s, offset %#x>" % (self.type.get_string_before_name(), self.name,
							 self.type.get_string_after_name(), self.offset)


class Structure(object):
	def __init__(self, handle=None):
		if handle is None:
			self.handle = core.BNCreateStructure()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeStructure(self.handle)

	@property
	def members(self):
		"""Structure member list (read-only)"""
		count = ctypes.c_ulonglong()
		members = core.BNGetStructureMembers(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(StructureMember(Type(core.BNNewTypeReference(members[i].type)),
				members[i].name, members[i].offset))
		core.BNFreeStructureMemberList(members, count.value)
		return result

	@property
	def width(self):
		"""Structure width"""
		return core.BNGetStructureWidth(self.handle)

	@width.setter
	def width(self, new_width):
		core.BNSetStructureWidth(self.handle, new_width)

	@property
	def alignment(self):
		"""Structure alignment"""
		return core.BNGetStructureAlignment(self.handle)

	@alignment.setter
	def alignment(self, align):
		core.BNSetStructureAlignment(self.handle, align)

	@property
	def packed(self):
		return core.BNIsStructurePacked(self.handle)

	@packed.setter
	def packed(self, value):
		core.BNSetStructurePacked(self.handle, value)

	@property
	def union(self):
		return core.BNIsStructureUnion(self.handle)

	@union.setter
	def union(self, value):
		core.BNSetStructureUnion(self.handle, value)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		return "<struct: size %#x>" % self.width

	def append(self, t, name = ""):
		core.BNAddStructureMember(self.handle, t.handle, name)

	def insert(self, offset, t, name = ""):
		core.BNAddStructureMemberAtOffset(self.handle, t.handle, name, offset)

	def remove(self, i):
		core.BNRemoveStructureMember(self.handle, i)


class EnumerationMember(object):
	def __init__(self, name, value, default):
		self.name = name
		self.value = value
		self.default = default

	def __repr__(self):
		return "<%s = %#x>" % (self.name, self.value)


class Enumeration(object):
	def __init__(self, handle=None):
		if handle is None:
			self.handle = core.BNCreateEnumeration()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeEnumeration(self.handle)

	@property
	def members(self):
		"""Enumeration member list (read-only)"""
		count = ctypes.c_ulonglong()
		members = core.BNGetEnumerationMembers(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(EnumerationMember(members[i].name, members[i].value, members[i].isDefault))
		core.BNFreeEnumerationMemberList(members, count.value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		return "<enum: %s>" % repr(self.members)

	def append(self, name, value = None):
		if value is None:
			core.BNAddEnumerationMember(self.handle, name)
		else:
			core.BNAddEnumerationMemberWithValue(self.handle, name, value)


class TypeParserResult(object):
	def __init__(self, types, variables, functions):
		self.types = types
		self.variables = variables
		self.functions = functions

	def __repr__(self):
		return "{types: %s, variables: %s, functions: %s}" % (self.types, self.variables, self.functions)


def preprocess_source(source, filename=None, include_dirs=[]):
	"""
	``preprocess_source`` run the C preprocessor on the given source or source filename.

	:param str source: source to preprocess
	:param str filename: optional filename to preprocess
	:param list(str) include_dirs: list of string directorires to use as include directories.
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
	for i in xrange(0, len(include_dirs)):
		dir_buf[i] = str(include_dirs[i])
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
