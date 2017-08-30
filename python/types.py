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

max_confidence = 255

import ctypes

# Binary Ninja components
import _binaryninjacore as core
from enums import SymbolType, TypeClass, NamedTypeReferenceClass, InstructionTextTokenType, StructureType, ReferenceType, VariableSourceType
import callingconvention
import function


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

	def __eq__(self, value):
		if not isinstance(value, Symbol):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, Symbol):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

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


class FunctionParameter(object):
	def __init__(self, param_type, name = "", location = None):
		self.type = param_type
		self.name = name
		self.location = location

	def __repr__(self):
		if (self.location is not None) and (self.location.name != self.name):
			return "%s %s%s @ %s" % (self.type.get_string_before_name(), self.name, self.type.get_string_after_name(), self.location.name)
		return "%s %s%s" % (self.type.get_string_before_name(), self.name, self.type.get_string_after_name())


class Type(object):
	def __init__(self, handle, platform = None, confidence = max_confidence):
		self.handle = handle
		self.confidence = confidence
		self.platform = platform

	def __del__(self):
		core.BNFreeType(self.handle)

	def __eq__(self, value):
		if not isinstance(value, Type):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, Type):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

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
		result = core.BNIsTypeSigned(self.handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@property
	def const(self):
		"""Whether type is const (read-only)"""
		result = core.BNIsTypeConst(self.handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@property
	def modified(self):
		"""Whether type is modified (read-only)"""
		return core.BNIsTypeFloatingPoint(self.handle)

	@property
	def target(self):
		"""Target (read-only)"""
		result = core.BNGetChildType(self.handle)
		if not result.type:
			return None
		return Type(result.type, platform = self.platform, confidence = result.confidence)

	@property
	def element_type(self):
		"""Target (read-only)"""
		result = core.BNGetChildType(self.handle)
		if not result.type:
			return None
		return Type(result.type, platform = self.platform, confidence = result.confidence)

	@property
	def return_value(self):
		"""Return value (read-only)"""
		result = core.BNGetChildType(self.handle)
		if not result.type:
			return None
		return Type(result.type, platform = self.platform, confidence = result.confidence)

	@property
	def calling_convention(self):
		"""Calling convention (read-only)"""
		result = core.BNGetTypeCallingConvention(self.handle)
		if not result.convention:
			return None
		return callingconvention.CallingConvention(None, handle = result.convention, confidence = result.confidence)

	@property
	def parameters(self):
		"""Type parameters list (read-only)"""
		count = ctypes.c_ulonglong()
		params = core.BNGetTypeParameters(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			param_type = Type(core.BNNewTypeReference(params[i].type), platform = self.platform, confidence = params[i].typeConfidence)
			if params[i].defaultLocation:
				param_location = None
			else:
				name = params[i].name
				if (params[i].location.type == VariableSourceType.RegisterVariableSourceType) and (self.platform is not None):
					name = self.platform.arch.get_reg_name(params[i].location.storage)
				elif params[i].location.type == VariableSourceType.StackVariableSourceType:
					name = "arg_%x" % params[i].location.storage
				param_location = function.Variable(None, params[i].location.type, params[i].location.index,
					params[i].location.storage, name, param_type)
			result.append(FunctionParameter(param_type, params[i].name, param_location))
		core.BNFreeTypeParameterList(params, count.value)
		return result

	@property
	def has_variable_arguments(self):
		"""Whether type has variable arguments (read-only)"""
		result = core.BNTypeHasVariableArguments(self.handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

	@property
	def can_return(self):
		"""Whether type can return (read-only)"""
		result = core.BNFunctionTypeCanReturn(self.handle)
		return BoolWithConfidence(result.value, confidence = result.confidence)

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
		return NamedTypeReference(handle = result)

	@property
	def count(self):
		"""Type count (read-only)"""
		return core.BNGetTypeElementCount(self.handle)

	@property
	def offset(self):
		"""Offset into structure (read-only)"""
		return core.BNGetTypeOffset(self.handle)

	@property
	def stack_adjustment(self):
		"""Stack adjustment for function (read-only)"""
		result = core.BNGetTypeStackAdjustment(self.handle)
		return SizeWithConfidence(result.value, confidence = result.confidence)

	def __str__(self):
		platform = None
		if self.platform is not None:
			platform = self.platform.handle
		return core.BNGetTypeString(self.handle, platform)

	def __repr__(self):
		if self.confidence < max_confidence:
			return "<type: %s, %d%% confidence>" % (str(self), (self.confidence * 100) / max_confidence)
		return "<type: %s>" % str(self)

	def get_string_before_name(self):
		platform = None
		if self.platform is not None:
			platform = self.platform.handle
		return core.BNGetTypeStringBeforeName(self.handle, platform)

	def get_string_after_name(self):
		platform = None
		if self.platform is not None:
			platform = self.platform.handle
		return core.BNGetTypeStringAfterName(self.handle, platform)

	@property
	def tokens(self):
		"""Type string as a list of tokens (read-only)"""
		return self.get_tokens()

	def get_tokens(self, base_confidence = max_confidence):
		count = ctypes.c_ulonglong()
		platform = None
		if self.platform is not None:
			platform = self.platform.handle
		tokens = core.BNGetTypeTokens(self.handle, platform, base_confidence, count)
		result = []
		for i in xrange(0, count.value):
			token_type = InstructionTextTokenType(tokens[i].type)
			text = tokens[i].text
			value = tokens[i].value
			size = tokens[i].size
			operand = tokens[i].operand
			context = tokens[i].context
			confidence = tokens[i].confidence
			address = tokens[i].address
			result.append(function.InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
		core.BNFreeTokenList(tokens, count.value)
		return result

	def get_tokens_before_name(self, base_confidence = max_confidence):
		count = ctypes.c_ulonglong()
		platform = None
		if self.platform is not None:
			platform = self.platform.handle
		tokens = core.BNGetTypeTokensBeforeName(self.handle, platform, base_confidence, count)
		result = []
		for i in xrange(0, count.value):
			token_type = InstructionTextTokenType(tokens[i].type)
			text = tokens[i].text
			value = tokens[i].value
			size = tokens[i].size
			operand = tokens[i].operand
			context = tokens[i].context
			confidence = tokens[i].confidence
			address = tokens[i].address
			result.append(function.InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
		core.BNFreeTokenList(tokens, count.value)
		return result

	def get_tokens_after_name(self, base_confidence = max_confidence):
		count = ctypes.c_ulonglong()
		platform = None
		if self.platform is not None:
			platform = self.platform.handle
		tokens = core.BNGetTypeTokensAfterName(self.handle, platform, base_confidence, count)
		result = []
		for i in xrange(0, count.value):
			token_type = InstructionTextTokenType(tokens[i].type)
			text = tokens[i].text
			value = tokens[i].value
			size = tokens[i].size
			operand = tokens[i].operand
			context = tokens[i].context
			confidence = tokens[i].confidence
			address = tokens[i].address
			result.append(function.InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
		core.BNFreeTokenList(tokens, count.value)
		return result

	@classmethod
	def void(cls):
		return Type(core.BNCreateVoidType())

	@classmethod
	def bool(self):
		return Type(core.BNCreateBoolType())

	@classmethod
	def int(self, width, sign = None, altname=""):
		"""
		``int`` class method for creating an int Type.

		:param int width: width of the integer in bytes
		:param bool sign: optional variable representing signedness
		"""
		if sign is None:
			sign = BoolWithConfidence(True, confidence = 0)
		elif not isinstance(sign, BoolWithConfidence):
			sign = BoolWithConfidence(sign)

		sign_conf = core.BNBoolWithConfidence()
		sign_conf.value = sign.value
		sign_conf.confidence = sign.confidence

		return Type(core.BNCreateIntegerType(width, sign_conf, altname))

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
	def named_type_from_type_and_id(self, type_id, name, t):
		name = QualifiedName(name)._get_core_struct()
		if t is not None:
			t = t.handle
		return Type(core.BNCreateNamedTypeReferenceFromTypeAndId(type_id, name, t))

	@classmethod
	def named_type_from_type(self, name, t):
		name = QualifiedName(name)._get_core_struct()
		if t is not None:
			t = t.handle
		return Type(core.BNCreateNamedTypeReferenceFromTypeAndId("", name, t))

	@classmethod
	def named_type_from_registered_type(self, view, name):
		name = QualifiedName(name)._get_core_struct()
		return Type(core.BNCreateNamedTypeReferenceFromType(view.handle, name))

	@classmethod
	def enumeration_type(self, arch, e, width=None):
		if width is None:
			width = arch.default_int_size
		return Type(core.BNCreateEnumerationType(e.handle, width))

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

		return Type(core.BNCreatePointerType(arch.handle, type_conf, const_conf, volatile_conf, ref_type))

	@classmethod
	def array(self, t, count):
		type_conf = core.BNTypeWithConfidence()
		type_conf.type = t.handle
		type_conf.confidence = t.confidence
		return Type(core.BNCreateArrayType(type_conf, count))

	@classmethod
	def function(self, ret, params, calling_convention=None, variable_arguments=None, stack_adjust=None):
		"""
		``function`` class method for creating an function Type.

		:param Type ret: width of the integer in bytes
		:param list(Type) params: list of parameter Types
		:param CallingConvention calling_convention: optional argument for function calling convention
		:param bool variable_arguments: optional argument for functions that have a variable number of arguments
		"""
		param_buf = (core.BNFunctionParameter * len(params))()
		for i in xrange(0, len(params)):
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
					param_buf[i].location.type = params[i].location.type
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

		stack_adjust_conf = core.BNSizeWithConfidence()
		stack_adjust_conf.value = stack_adjust.value
		stack_adjust_conf.confidence = stack_adjust.confidence

		return Type(core.BNCreateFunctionType(ret_conf, conv_conf, param_buf, len(params),
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
	def get_auto_demanged_type_id_source(self):
		return core.BNGetAutoDemangledTypeIdSource()

	def with_confidence(self, confidence):
		return Type(handle = core.BNNewTypeReference(self.handle), platform = self.platform, confidence = confidence)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class BoolWithConfidence(object):
	def __init__(self, value, confidence = max_confidence):
		self.value = value
		self.confidence = confidence

	def __str__(self):
		return str(self.value)

	def __repr__(self):
		return repr(self.value)

	def __bool__(self):
		return self.value

	def __nonzero__(self):
		return self.value


class SizeWithConfidence(object):
	def __init__(self, value, confidence = max_confidence):
		self.value = value
		self.confidence = confidence

	def __str__(self):
		return str(self.value)

	def __repr__(self):
		return repr(self.value)

	def __int__(self):
		return self.value


class RegisterSet(object):
	def __init__(self, reg_list, confidence = max_confidence):
		self.regs = reg_list
		self.confidence = confidence

	def __repr__(self):
		return repr(self.regs)

	def __iter__(self):
		for reg in self.regs:
			yield reg

	def __getitem__(self, idx):
		return self.regs[idx]

	def __len__(self):
		return len(self.regs)

	def with_confidence(self, confidence):
		return RegisterSet(list(self.regs), confidence = confidence)


class ReferenceTypeWithConfidence(object):
	def __init__(self, value, confidence = max_confidence):
		self.value = value
		self.confidence = confidence

	def __str__(self):
		return str(self.value)

	def __repr__(self):
		return repr(self.value)


class NamedTypeReference(object):
	def __init__(self, type_class = NamedTypeReferenceClass.UnknownNamedTypeClass, type_id = None, name = None, handle = None):
		if handle is None:
			self.handle = core.BNCreateNamedType()
			core.BNSetTypeReferenceClass(self.handle, type_class)
			if type_id is not None:
				core.BNSetTypeReferenceId(self.handle, type_id)
			if name is not None:
				name = QualifiedName(name)._get_core_struct()
				core.BNSetTypeReferenceName(self.handle, name)
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeNamedTypeReference(self.handle)

	def __eq__(self, value):
		if not isinstance(value, NamedTypeReference):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, NamedTypeReference):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	@property
	def type_class(self):
		return NamedTypeReferenceClass(core.BNGetTypeReferenceClass(self.handle))

	@type_class.setter
	def type_class(self, value):
		core.BNSetTypeReferenceClass(self.handle, value)

	@property
	def type_id(self):
		return core.BNGetTypeReferenceId(self.handle)

	@type_id.setter
	def type_id(self, value):
		core.BNSetTypeReferenceId(self.handle, value)

	@property
	def name(self):
		name = core.BNGetTypeReferenceName(self.handle)
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

	def __eq__(self, value):
		if not isinstance(value, Structure):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, Structure):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	@property
	def members(self):
		"""Structure member list (read-only)"""
		count = ctypes.c_ulonglong()
		members = core.BNGetStructureMembers(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(StructureMember(Type(core.BNNewTypeReference(members[i].type), confidence = members[i].typeConfidence),
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

	@property
	def type(self):
		return StructureType(core.BNGetStructureType(self.handle))

	@type.setter
	def type(self, value):
		core.BNSetStructureType(self.handle, value)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		return "<struct: size %#x>" % self.width

	def append(self, t, name = ""):
		tc = core.BNTypeWithConfidence()
		tc.type = t.handle
		tc.confidence = t.confidence
		core.BNAddStructureMember(self.handle, tc, name)

	def insert(self, offset, t, name = ""):
		tc = core.BNTypeWithConfidence()
		tc.type = t.handle
		tc.confidence = t.confidence
		core.BNAddStructureMemberAtOffset(self.handle, tc, name, offset)

	def remove(self, i):
		core.BNRemoveStructureMember(self.handle, i)

	def replace(self, i, t, name = ""):
		tc = core.BNTypeWithConfidence()
		tc.type = t.handle
		tc.confidence = t.confidence
		core.BNReplaceStructureMember(self.handle, i, tc, name)


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

	def __eq__(self, value):
		if not isinstance(value, Enumeration):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, Enumeration):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

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

	def remove(self, i):
		core.BNRemoveEnumerationMember(self.handle, i)

	def replace(self, i, name, value):
		core.BNReplaceEnumerationMember(self.handle, i, name, value)


class TypeParserResult(object):
	def __init__(self, types, variables, functions):
		self.types = types
		self.variables = variables
		self.functions = functions

	def __repr__(self):
		return "<types: %s, variables: %s, functions: %s>" % (self.types, self.variables, self.functions)


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
