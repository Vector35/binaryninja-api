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
import dataclasses
from json import dumps
from typing import List, Tuple, Optional

import sys
import traceback

# Binary Ninja Components
import binaryninja
import binaryninja._binaryninjacore as core

from .settings import Settings
from . import platform as _platform
from . import types
from . import function as _function
from . import binaryview
from .log import log_error
from .enums import TokenEscapingType


def to_bytes(field):
	if type(field) == bytes:
		return field
	if type(field) == str:
		return field.encode()
	return str(field).encode()


class _TypePrinterMetaclass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetTypePrinterList(count)
		try:
			for i in range(0, count.value):
				yield CoreTypePrinter(types[i])
		finally:
			core.BNFreeTypePrinterList(types)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		handle = core.BNGetTypePrinterByName(str(value))
		if handle is None:
			raise KeyError(f"'{value}' is not a valid TypePrinter")
		return CoreTypePrinter(handle)

	@property
	def default(self):
		name = binaryninja.Settings().get_string("analysis.types.printerName")
		return CoreTypePrinter[name]


class TypePrinter(metaclass=_TypePrinterMetaclass):
	"""
	Class for turning Type objects into strings and tokens.
	"""

	name = None
	_registered_printers = []
	_cached_tokens = None
	_cached_string = None
	_cached_error = None

	def __init__(self, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNTypePrinter)
			self.__dict__["name"] = core.BNGetTypePrinterName(handle)

	def register(self):
		assert self.__class__.name is not None

		self._cb = core.BNTypePrinterCallbacks()
		self._cb.context = 0
		self._cb.getTypeTokens = self._cb.getTypeTokens.__class__(self._get_type_tokens)
		self._cb.getTypeTokensBeforeName = self._cb.getTypeTokensBeforeName.__class__(self._get_type_tokens_before_name)
		self._cb.getTypeTokensAfterName = self._cb.getTypeTokensAfterName.__class__(self._get_type_tokens_after_name)
		self._cb.getTypeString = self._cb.getTypeString.__class__(self._get_type_string)
		self._cb.getTypeStringBeforeName = self._cb.getTypeStringBeforeName.__class__(self._get_type_string_before_name)
		self._cb.getTypeStringAfterName = self._cb.getTypeStringAfterName.__class__(self._get_type_string_after_name)
		self._cb.getTypeLines = self._cb.getTypeLines.__class__(self._get_type_lines)
		self._cb.printAllTypes = self._cb.printAllTypes.__class__(self._print_all_types)
		self._cb.freeTokens = self._cb.freeTokens.__class__(self._free_tokens)
		self._cb.freeString = self._cb.freeString.__class__(self._free_string)
		self._cb.freeLines = self._cb.freeLines.__class__(self._free_lines)
		self.handle = core.BNRegisterTypePrinter(self.__class__.name, self._cb)
		self.__class__._registered_printers.append(self)

	def __str__(self):
		return f'<TypePrinter: {self.name}>'

	def __repr__(self):
		return f'<TypePrinter: {self.name}>'

	def _get_type_tokens(self, ctxt, type, platform, name, base_confidence, escaping, result, result_count):
		try:
			platform_py = None
			if platform:
				platform_py = _platform.Platform(handle=core.BNNewPlatformReference(platform))
			result_py = self.get_type_tokens(
				types.Type(handle=core.BNNewTypeReference(type)), platform_py,
				types.QualifiedName._from_core_struct(name.contents), base_confidence, escaping)

			TypePrinter._cached_tokens = _function.InstructionTextToken._get_core_struct(result_py)
			result[0] = TypePrinter._cached_tokens
			result_count[0] = len(result_py)

			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _get_type_tokens_before_name(self, ctxt, type, platform, base_confidence, parent_type, escaping, result, result_count):
		try:
			platform_py = None
			if platform:
				platform_py = _platform.Platform(handle=core.BNNewPlatformReference(platform))
			parent_type_py = None
			if parent_type:
				parent_type_py = types.Type(handle=core.BNNewTypeReference(parent_type))
			result_py = self.get_type_tokens_before_name(
				types.Type(handle=core.BNNewTypeReference(type)), platform_py,
				base_confidence, parent_type_py, escaping)

			TypePrinter._cached_tokens = _function.InstructionTextToken._get_core_struct(result_py)
			result[0] = TypePrinter._cached_tokens
			result_count[0] = len(result_py)

			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _get_type_tokens_after_name(self, ctxt, type, platform, base_confidence, parent_type, escaping, result, result_count):
		try:
			platform_py = None
			if platform:
				platform_py = _platform.Platform(handle=core.BNNewPlatformReference(platform))
			parent_type_py = None
			if parent_type:
				parent_type_py = types.Type(handle=core.BNNewTypeReference(parent_type))
			result_py = self.get_type_tokens_after_name(
				types.Type(handle=core.BNNewTypeReference(type)), platform_py,
				base_confidence, parent_type_py, escaping)

			TypePrinter._cached_tokens = _function.InstructionTextToken._get_core_struct(result_py)
			result[0] = TypePrinter._cached_tokens
			result_count[0] = len(result_py)

			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _get_type_string(self, ctxt, type, platform, name, escaping, result):
		try:
			platform_py = None
			if platform:
				platform_py = _platform.Platform(handle=core.BNNewPlatformReference(platform))
			result_py = self.get_type_string(
				types.Type(handle=core.BNNewTypeReference(type)), platform_py,
				types.QualifiedName._from_core_struct(name.contents), escaping)

			TypePrinter._cached_string = core.cstr(result_py)
			result[0] = TypePrinter._cached_string
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _get_type_string_before_name(self, ctxt, type, platform, escaping, result):
		try:
			platform_py = None
			if platform:
				platform_py = _platform.Platform(handle=core.BNNewPlatformReference(platform))
			result_py = self.get_type_string_before_name(
				types.Type(handle=core.BNNewTypeReference(type)), platform_py,
				escaping)

			TypePrinter._cached_string = core.cstr(result_py)
			result[0] = TypePrinter._cached_string
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _get_type_string_after_name(self, ctxt, type, platform, escaping, result):
		try:
			platform_py = None
			if platform:
				platform_py = _platform.Platform(handle=core.BNNewPlatformReference(platform))
			result_py = self.get_type_string_after_name(
				types.Type(handle=core.BNNewTypeReference(type)), platform_py,
				escaping)

			TypePrinter._cached_string = core.cstr(result_py)
			result[0] = TypePrinter._cached_string
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _get_type_lines(self, ctxt, type, data, name, line_width, collapsed, escaping, result, result_count):
		try:
			result_py = self.get_type_lines(
				types.Type(handle=core.BNNewTypeReference(type)),
				binaryview.BinaryView(handle=core.BNNewViewReference(data)),
				types.QualifiedName._from_core_struct(name.contents),
				line_width, collapsed, escaping)

			TypePrinter._cached_lines = (core.BNTypeDefinitionLine * len(result_py))()
			for (i, line) in enumerate(result_py):
				TypePrinter._cached_lines[i] = line._to_core_struct()
			result[0] = TypePrinter._cached_lines
			result_count[0] = len(result_py)

			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _print_all_types(self, ctxt, names, types_, type_count, data, line_width, escaping, result):
		try:
			types_py = []
			for i in range(type_count):
				types_py.append((
					types.QualifiedName._from_core_struct(names[i]),
					types.Type(handle=core.BNNewTypeReference(types_[i]))
				))

			result_py = self.print_all_types(
				types_py,
				binaryview.BinaryView(handle=core.BNNewViewReference(data)),
				line_width, escaping)

			TypePrinter._cached_string = core.cstr(result_py)
			result[0] = TypePrinter._cached_string
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _free_tokens(self, ctxt, tokens, count):
		try:
			TypePrinter._cached_tokens = None
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _free_string(self, ctxt, string):
		try:
			TypePrinter._cached_string = None
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _free_lines(self, ctxt, lines, count):
		try:
			for line in TypePrinter._cached_lines:
				core.BNFreeType(line.type)
				core.BNFreeType(line.rootType)
			TypePrinter._cached_lines = None
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _default_print_all_types(self, types_: List[Tuple[types.QualifiedNameType, types.Type]], data: binaryview.BinaryView, line_width = 80, escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> str:
		cpp_names = (core.BNQualifiedName * len(types_))()
		cpp_types = (ctypes.POINTER(core.BNType) * len(types_))()

		i = 0
		for (name, type) in types_:
			cpp_names[i] = types.QualifiedName(name)._to_core_struct()
			cpp_types[i] = type.handle
			i += 1

		result = ctypes.c_char_p()
		core.BNTypePrinterDefaultPrintAllTypes(self.handle, cpp_names, cpp_types, len(types_), data.handle, line_width, ctypes.c_int(escaping), result)
		return core.pyNativeStr(result.value)

	def get_type_tokens(self, type: types.Type, platform: Optional[_platform.Platform] = None, name: types.QualifiedNameType = "", base_confidence: int = core.max_confidence, escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> List[_function.InstructionTextToken]:
		"""
		Generate a single-line text representation of a type

		:param type: Type to print
		:param platform: Platform responsible for this type
		:param name: Name of the type
		:param base_confidence: Confidence to use for tokens created for this type
		:param escaping: Style of escaping literals which may not be parsable
		:return: List of text tokens representing the type
		"""
		raise NotImplementedError()

	def get_type_tokens_before_name(self, type: types.Type, platform: Optional[_platform.Platform] = None, base_confidence: int = core.max_confidence, parent_type: Optional[types.Type] = None, escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> List[_function.InstructionTextToken]:
		"""
		In a single-line text representation of a type, generate the tokens that should
		be printed before the type's name.

		:param type: Type to print
		:param platform: Platform responsible for this type
		:param base_confidence: Confidence to use for tokens created for this type
		:param parent_type: Type of the parent of this type, or None
		:param escaping: Style of escaping literals which may not be parsable
		:return: List of text tokens representing the type
		"""
		raise NotImplementedError()

	def get_type_tokens_after_name(self, type: types.Type, platform: Optional[_platform.Platform] = None, base_confidence: int = core.max_confidence, parent_type: Optional[types.Type] = None, escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> List[_function.InstructionTextToken]:
		"""
		In a single-line text representation of a type, generate the tokens that should
		be printed after the type's name.

		:param type: Type to print
		:param platform: Platform responsible for this type
		:param base_confidence: Confidence to use for tokens created for this type
		:param parent_type: Type of the parent of this type, or None
		:param escaping: Style of escaping literals which may not be parsable
		:return: List of text tokens representing the type
		"""
		raise NotImplementedError()

	def get_type_string(self, type: types.Type, platform: Optional[_platform.Platform] = None, name: types.QualifiedNameType = "", escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> str:
		"""
		Generate a single-line text representation of a type

		:param type: Type to print
		:param platform: Platform responsible for this type
		:param name: Name of the type
		:param escaping: Style of escaping literals which may not be parsable
		:return: String representing the type
		"""
		raise NotImplementedError()

	def get_type_string_before_name(self, type: types.Type, platform: Optional[_platform.Platform] = None, escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> str:
		"""
		In a single-line text representation of a type, generate the string that should
		be printed before the type's name.

		:param type: Type to print
		:param platform: Platform responsible for this type
		:param escaping: Style of escaping literals which may not be parsable
		:return: String representing the type
		"""
		raise NotImplementedError()

	def get_type_string_after_name(self, type: types.Type, platform: Optional[_platform.Platform] = None, escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> str:
		"""
		In a single-line text representation of a type, generate the string that should
		be printed after the type's name.

		:param type: Type to print
		:param platform: Platform responsible for this type
		:param escaping: Style of escaping literals which may not be parsable
		:return: String representing the type
		"""
		raise NotImplementedError()

	def get_type_lines(self, type: types.Type, data: binaryview.BinaryView, name: types.QualifiedNameType, line_width = 80, collapsed = False, escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> List[types.TypeDefinitionLine]:
		"""
		Generate a multi-line representation of a type

		:param type: Type to print
		:param data: Binary View in which the type is defined
		:param name: Name of the type
		:param line_width: Maximum width of lines, in characters
		:param collapsed: Whether to collapse structure/enum blocks
		:param escaping: Style of escaping literals which may not be parsable
		:return: List of type definition lines
		"""
		raise NotImplementedError()

	def print_all_types(self, types: List[Tuple[types.QualifiedNameType, types.Type]], data: binaryview.BinaryView, line_width = 80, escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> str:
		"""
		Print all types to a single big string, including headers, sections, etc

		:param types: All types to print
		:param data: Binary View in which all the types are defined
		:param line_width: Maximum width of lines, in characters
		:param escaping: Style of escaping literals which may not be parsable
		:return: All the types in a string
		"""
		return self._default_print_all_types(types, data, line_width, escaping)


class CoreTypePrinter(TypePrinter):

	def get_type_tokens(self, type: types.Type, platform: Optional[_platform.Platform] = None,
						name: types.QualifiedNameType = "", base_confidence: int = core.max_confidence,
						escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> List[
		_function.InstructionTextToken]:
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		count = ctypes.c_ulonglong()
		name_cpp = name._to_core_struct()
		result_cpp = ctypes.POINTER(core.BNInstructionTextToken)()
		if not core.BNGetTypePrinterTypeTokens(self.handle, type.handle, None if platform is None else platform.handle, name_cpp, base_confidence, ctypes.c_int(escaping), result_cpp, count):
			raise RuntimeError("BNGetTypePrinterTypeTokens returned False")

		result = _function.InstructionTextToken._from_core_struct(result_cpp, count.value)
		core.BNFreeInstructionText(result_cpp.contents, count.value)
		return result

	def get_type_tokens_before_name(self, type: types.Type, platform: Optional[_platform.Platform] = None,
									base_confidence: int = core.max_confidence, parent_type: Optional[types.Type] = None,
									escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> List[
		_function.InstructionTextToken]:
		count = ctypes.c_ulonglong()
		result_cpp = ctypes.POINTER(core.BNInstructionTextToken)()
		parent_type_cpp = None
		if parent_type is not None:
			parent_type_cpp = parent_type.handle
		if not core.BNGetTypePrinterTypeTokensBeforeName(self.handle, type.handle, None if platform is None else platform.handle, base_confidence, parent_type_cpp, ctypes.c_int(escaping), result_cpp, count):
			raise RuntimeError("BNGetTypePrinterTypeTokensBeforeName returned False")

		result = _function.InstructionTextToken._from_core_struct(result_cpp, count.value)
		core.BNFreeInstructionText(result_cpp.contents, count.value)
		return result

	def get_type_tokens_after_name(self, type: types.Type, platform: Optional[_platform.Platform] = None,
								   base_confidence: int = core.max_confidence, parent_type: Optional[types.Type] = None,
								   escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> List[
		_function.InstructionTextToken]:
		count = ctypes.c_ulonglong()
		result_cpp = ctypes.POINTER(core.BNInstructionTextToken)()
		parent_type_cpp = None
		if parent_type is not None:
			parent_type_cpp = parent_type.handle
		if not core.BNGetTypePrinterTypeTokensAfterName(self.handle, type.handle, None if platform is None else platform.handle, base_confidence, parent_type_cpp, ctypes.c_int(escaping), result_cpp, count):
			raise RuntimeError("BNGetTypePrinterTypeTokensAfterName returned False")

		result = _function.InstructionTextToken._from_core_struct(result_cpp, count.value)
		core.BNFreeInstructionText(result_cpp.contents, count.value)
		return result

	def get_type_string(self, type: types.Type, platform: Optional[_platform.Platform] = None,
						name: types.QualifiedNameType = "",
						escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> str:
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		result_cpp = ctypes.c_char_p()
		if not core.BNGetTypePrinterTypeString(self.handle, type.handle, None if platform is None else platform.handle, name._to_core_struct(), ctypes.c_int(escaping), result_cpp):
			raise RuntimeError("BNGetTypePrinterTypeString returned False")

		result = core.pyNativeStr(result_cpp.value)
		core.free_string(result_cpp)
		return result

	def get_type_string_before_name(self, type: types.Type, platform: Optional[_platform.Platform] = None,
									escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> str:
		result_cpp = ctypes.c_char_p()
		if not core.BNGetTypePrinterTypeStringBeforeName(self.handle, type.handle, None if platform is None else platform.handle, ctypes.c_int(escaping), result_cpp):
			raise RuntimeError("BNGetTypePrinterTypeStringBeforeName returned False")

		result = core.pyNativeStr(result_cpp.value)
		core.free_string(result_cpp)
		return result

	def get_type_string_after_name(self, type: types.Type, platform: Optional[_platform.Platform] = None,
								   escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> str:
		result_cpp = ctypes.c_char_p()
		if not core.BNGetTypePrinterTypeStringAfterName(self.handle, type.handle, None if platform is None else platform.handle, ctypes.c_int(escaping), result_cpp):
			raise RuntimeError("BNGetTypePrinterTypeStringAfterName returned False")

		result = core.pyNativeStr(result_cpp.value)
		core.free_string(result_cpp)
		return result

	def get_type_lines(self, type: types.Type, data: binaryview.BinaryView,
					   name: types.QualifiedNameType, line_width = 80, collapsed = False,
					   escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType
					   ) -> List[types.TypeDefinitionLine]:
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		count = ctypes.c_ulonglong()
		core_lines = ctypes.POINTER(core.BNTypeDefinitionLine)()
		if not core.BNGetTypePrinterTypeLines(self.handle, type.handle, data.handle, name._to_core_struct(), line_width, collapsed, ctypes.c_int(escaping), core_lines, count):
			raise RuntimeError("BNGetTypePrinterTypeLines returned False")
		lines = []
		for i in range(count.value):
			tokens = _function.InstructionTextToken._from_core_struct(core_lines[i].tokens, core_lines[i].count)
			type_ = types.Type.create(handle=core.BNNewTypeReference(core_lines[i].type), platform=data.platform)
			root_type = types.Type.create(handle=core.BNNewTypeReference(core_lines[i].rootType), platform=data.platform)
			root_type_name = core.pyNativeStr(core_lines[i].rootTypeName)
			if core_lines[i].baseType:
				const_conf = types.BoolWithConfidence.get_core_struct(False, 0)
				volatile_conf = types.BoolWithConfidence.get_core_struct(False, 0)
				handle = core.BNCreateNamedTypeReference(core_lines[i].baseType, 0, 1, const_conf, volatile_conf)
				base_type = types.NamedTypeReferenceType(handle, data.platform)
			else:
				base_type = None
			line = types.TypeDefinitionLine(core_lines[i].lineType, tokens, type_, root_type, root_type_name, base_type,
									  core_lines[i].baseOffset, core_lines[i].offset, core_lines[i].fieldIndex)
			lines.append(line)
		core.BNFreeTypeDefinitionLineList(core_lines, count.value)
		return lines

	def print_all_types(self, types_: List[Tuple[types.QualifiedNameType, types.Type]], data: binaryview.BinaryView, line_width = 80, escaping: TokenEscapingType = TokenEscapingType.BackticksTokenEscapingType) -> str:
		cpp_names = (core.BNQualifiedName * len(types_))()
		cpp_types = (ctypes.POINTER(core.BNType) * len(types_))()

		i = 0
		for (name, type) in types_:
			cpp_names[i] = types.QualifiedName(name)._to_core_struct()
			cpp_types[i] = type.handle
			i += 1

		result = ctypes.c_char_p()
		core.BNTypePrinterPrintAllTypes(self.handle, cpp_names, cpp_types, len(types_), data.handle, line_width, ctypes.c_int(escaping), result)
		return core.pyNativeStr(result.value)
