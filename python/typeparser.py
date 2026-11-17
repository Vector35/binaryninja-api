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

import abc
import ctypes
import dataclasses
from json import dumps
from typing import List, Tuple, Optional, Dict, Any

import sys
import traceback

# Binary Ninja Components
import binaryninja
import binaryninja._binaryninjacore as core

from .settings import Settings
from . import binaryview
from . import platform
from . import typecontainer
from . import types
from . import deprecation
from .log import log_error_for_exception
from .enums import TypeParserErrorSeverity, TypeParserOption


@dataclasses.dataclass(frozen=True)
class QualifiedNameTypeAndId:
	name: 'types.QualifiedNameType'
	id: str
	type: 'types.Type'

	@classmethod
	def _from_core_struct(cls, struct: core.BNQualifiedNameTypeAndId) -> 'QualifiedNameTypeAndId':
		name = types.QualifiedName._from_core_struct(struct.name)
		type = types.Type.create(handle=core.BNNewTypeReference(struct.type))
		return QualifiedNameTypeAndId(name, struct.id, type)

	def _to_core_struct(self) -> core.BNQualifiedNameTypeAndId:
		result = core.BNQualifiedNameTypeAndId()
		result.name = types.QualifiedName(self.name)._to_core_struct()
		result.type = core.BNNewTypeReference(self.type.handle)
		result.id = self.id
		return result


@dataclasses.dataclass(frozen=True)
class TypeParserError:
	severity: TypeParserErrorSeverity
	message: str
	file_name: str
	line: int
	column: int

	def __str__(self):
		text = ""
		if self.severity == TypeParserErrorSeverity.ErrorSeverity \
				or self.severity == TypeParserErrorSeverity.FatalSeverity:
			text += "error: "
		if self.severity == TypeParserErrorSeverity.WarningSeverity:
			text += "warning: "
		if self.severity == TypeParserErrorSeverity.NoteSeverity:
			text += "note: "
		if self.severity == TypeParserErrorSeverity.RemarkSeverity:
			text += "remark: "
		if self.severity == TypeParserErrorSeverity.IgnoredSeverity:
			text += "ignored: "

		if self.file_name == "":
			text += f"<unknown>: {self.message}\n"
		else:
			text += f"{self.file_name}: {self.line}:{self.column} {self.message}\n"
		return text

	@classmethod
	def _from_core_struct(cls, struct: core.BNTypeParserError) -> 'TypeParserError':
		return TypeParserError(struct.severity, struct.message, struct.fileName, struct.line, struct.column)

	def _to_core_struct(self) -> core.BNTypeParserError:
		result = core.BNTypeParserError()
		result.severity = self.severity
		result.message = self.message
		result.fileName = self.file_name
		result.line = self.line
		result.column = self.column
		return result


@dataclasses.dataclass(frozen=True)
class ParsedType:
	name: 'types.QualifiedNameType'
	type: 'types.Type'
	is_user: bool

	@classmethod
	def _from_core_struct(cls, struct: core.BNParsedType) -> 'ParsedType':
		name = types.QualifiedName._from_core_struct(struct.name)
		type = types.Type.create(handle=core.BNNewTypeReference(struct.type))
		return ParsedType(name, type, struct.isUser)

	def _to_core_struct(self) -> core.BNParsedType:
		result = core.BNParsedType()
		result.name = types.QualifiedName(self.name)._to_core_struct()
		result.type = core.BNNewTypeReference(self.type.handle)
		result.isUser = self.is_user
		return result


@dataclasses.dataclass(frozen=True)
class BasicTypeParserResult:
	types: Dict['types.QualifiedName', 'types.Type']
	variables: Dict['types.QualifiedName', 'types.Type']
	functions: Dict['types.QualifiedName', 'types.Type']

	def __repr__(self):
		return f"<types: {self.types}, variables: {self.variables}, functions: {self.functions}>"


@dataclasses.dataclass(frozen=True)
class TypeParserResult:
	types: List[ParsedType]
	variables: List[ParsedType]
	functions: List[ParsedType]

	def __repr__(self):
		return f"<types: {self.types}, variables: {self.variables}, functions: {self.functions}>"

	@classmethod
	def _from_core_struct(cls, struct: core.BNTypeParserResult) -> 'TypeParserResult':
		types = []
		variables = []
		functions = []
		for i in range(struct.typeCount):
			types.append(ParsedType._from_core_struct(struct.types[i]))
		for i in range(struct.variableCount):
			variables.append(ParsedType._from_core_struct(struct.variables[i]))
		for i in range(struct.functionCount):
			functions.append(ParsedType._from_core_struct(struct.functions[i]))
		return TypeParserResult(types, variables, functions)

	def _to_core_struct(self) -> core.BNTypeParserResult:
		result = core.BNTypeParserResult()
		result.typeCount = len(self.types)
		result.variableCount = len(self.variables)
		result.functionCount = len(self.functions)
		result.types = (core.BNParsedType * len(self.types))()
		result.variables = (core.BNParsedType * len(self.variables))()
		result.functions = (core.BNParsedType * len(self.functions))()

		for (i, type) in enumerate(self.types):
			result.types[i] = type._to_core_struct()
		for (i, variable) in enumerate(self.variables):
			result.variables[i] = variable._to_core_struct()
		for (i, function) in enumerate(self.functions):
			result.functions[i] = function._to_core_struct()

		return result

	@staticmethod
	def _free_core_struct(struct: core.BNTypeParserResult) -> None:
		"""
		Release the type references that `_to_core_struct` took
		"""
		for i in range(struct.typeCount):
			core.BNFreeType(struct.types[i].type)
		for i in range(struct.variableCount):
			core.BNFreeType(struct.variables[i].type)
		for i in range(struct.functionCount):
			core.BNFreeType(struct.functions[i].type)


def to_bytes(field):
	if type(field) == bytes:
		return field
	if type(field) == str:
		return field.encode()
	return str(field).encode()


class _TypeParserMetaclass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetTypeParserList(count)
		try:
			for i in range(0, count.value):
				yield CoreTypeParser(types[i])
		finally:
			core.BNFreeTypeParserList(types)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		handle = core.BNGetTypeParserByName(str(value))
		if handle is None:
			raise KeyError(f"'{value}' is not a valid TypeParser")
		return CoreTypeParser(handle)

	def __contains__(cls: '_TypeParserMetaclass', name: object) -> bool:
		if not isinstance(name, str):
			return False
		try:
			cls[name]
			return True
		except KeyError:
			return False

	def get(cls: '_TypeParserMetaclass', name: str, default: Any = None) -> Optional['TypeParser']:
		try:
			return cls[name]
		except KeyError:
			if default is not None:
				return default
			return None

	@property
	def default(self):
		"""
		Get the default parser as specified by the user's settings
		:return: Default parser
		"""
		return CoreTypeParser(core.BNGetDefaultTypeParser())


class TypeParser(metaclass=_TypeParserMetaclass):
	name = None
	_registered_parsers = []

	def __init__(self, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNTypeParser)
			self.__dict__["name"] = core.BNGetTypeParserName(handle)

	def register(self):
		"""
		Register a custom parser with the API
		"""
		assert self.__class__.name is not None

		# Holds each result returned to core until core frees it, keyed by the address core passes to the
		# free callback.
		self._pending_results = {}

		self._cb = core.BNTypeParserCallbacks()
		self._cb.context = 0
		self._cb.getOptionText = self._cb.getOptionText.__class__(self._get_option_text)
		self._cb.preprocessSource = self._cb.preprocessSource.__class__(self._preprocess_source)
		self._cb.parseTypesFromSource = self._cb.parseTypesFromSource.__class__(self._parse_types_from_source)
		self._cb.parseTypeString = self._cb.parseTypeString.__class__(self._parse_type_string)
		# The generated `freeString` type converts the string to `bytes`, which loses the address
		# that identifies it.
		self._free_string_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)(self._free_string)
		self._cb.freeString = ctypes.cast(self._free_string_cb, self._cb.freeString.__class__)
		self._cb.freeResult = self._cb.freeResult.__class__(self._free_result)
		self._cb.freeErrorList = self._cb.freeErrorList.__class__(self._free_error_list)
		self.handle = core.BNRegisterTypeParser(self.__class__.name, self._cb)
		self.__class__._registered_parsers.append(self)

	def __str__(self):
		return f'<TypeParser: {self.name}>'

	def __repr__(self):
		return f'<TypeParser: {self.name}>'

	def _return_string(self, value: str) -> ctypes.c_char_p:
		buffer = ctypes.create_string_buffer(core.cstr(value))
		self._pending_results[ctypes.addressof(buffer)] = buffer
		return ctypes.cast(buffer, ctypes.c_char_p)

	def _return_errors(self, errors_py: List['TypeParserError']) -> 'ctypes.Array[core.BNTypeParserError]':
		errors_out = (core.BNTypeParserError * len(errors_py))()
		for i in range(len(errors_py)):
			errors_out[i] = errors_py[i]._to_core_struct()
		self._pending_results[ctypes.addressof(errors_out)] = errors_out
		return errors_out

	def _get_option_text(self, ctxt, option, value, result) -> bool:
		try:
			value_py = core.pyNativeStr(value)
			result_py = self.get_option_text(TypeParserOption(option), value_py)
			if result_py is None:
				return False
			result[0] = self._return_string(result_py)
			return True
		except Exception:
			log_error_for_exception("Unhandled Python exception in TypeParser._get_option_text")
			return False

	def _preprocess_source(
			self, ctxt, source, fileName, platform_, existingTypes,
			options, optionCount, includeDirs, includeDirCount,
			output, errors, errorCount
	) -> bool:
		try:
			source_py = core.pyNativeStr(source)
			file_name_py = core.pyNativeStr(fileName)
			platform_py = platform.CorePlatform._from_cache(handle=core.BNNewPlatformReference(platform_))

			existing_types_py = None
			if existingTypes:
				existing_types_py = typecontainer.TypeContainer(handle=core.BNDuplicateTypeContainer(existingTypes))

			options_py = []
			for i in range(optionCount):
				options_py.append(core.pyNativeStr(options[i]))

			include_dirs_py = []
			for i in range(includeDirCount):
				include_dirs_py.append(core.pyNativeStr(includeDirs[i]))

			(output_py, errors_py) = self.preprocess_source(
				source_py, file_name_py, platform_py, existing_types_py, options_py,
				include_dirs_py)

			if errors is not None:
				errors[0] = self._return_errors(errors_py)
			if errorCount is not None:
				errorCount[0] = len(errors_py)

			# Core frees the output only on success, so return it after everything that can raise.
			if output_py is not None and output is not None:
				output[0] = self._return_string(output_py)

			return output_py is not None
		except Exception:
			errorCount[0] = 0
			log_error_for_exception("Unhandled Python exception in TypeParser._preprocess_source")
			return False

	def _parse_types_from_source(
			self, ctxt, source, fileName, platform_, existingTypes,
			options, optionCount, includeDirs, includeDirCount, autoTypeSource,
			result, errors, errorCount
	) -> bool:
		try:
			source_py = core.pyNativeStr(source)
			file_name_py = core.pyNativeStr(fileName)
			platform_py = platform.CorePlatform._from_cache(handle=core.BNNewPlatformReference(platform_))

			existing_types_py = None
			if existingTypes:
				existing_types_py = typecontainer.TypeContainer(handle=core.BNDuplicateTypeContainer(existingTypes))

			options_py = []
			for i in range(optionCount):
				options_py.append(core.pyNativeStr(options[i]))

			include_dirs_py = []
			for i in range(includeDirCount):
				include_dirs_py.append(core.pyNativeStr(includeDirs[i]))

			auto_type_source = core.pyNativeStr(autoTypeSource) or ""

			(result_py, errors_py) = self.parse_types_from_source(
				source_py, file_name_py, platform_py, existing_types_py, options_py,
				include_dirs_py, auto_type_source)

			if errors is not None:
				errors[0] = self._return_errors(errors_py)
			if errorCount is not None:
				errorCount[0] = len(errors_py)

			# Core frees the result only on success, so return it after everything that can raise.
			if result_py is not None and result is not None:
				result_struct = result_py._to_core_struct()
				self._pending_results[ctypes.addressof(result.contents)] = result_struct
				result[0] = result_struct

			return result_py is not None
		except Exception:
			errorCount[0] = 0
			log_error_for_exception("Unhandled Python exception in TypeParser._parse_types_from_source")
			return False

	def _parse_type_string(
			self, ctxt, source, platform_, existingTypes,
			result, errors, errorCount
	) -> bool:
		try:
			source_py = core.pyNativeStr(source)
			platform_py = platform.CorePlatform._from_cache(handle=core.BNNewPlatformReference(platform_))

			existing_types_py = None
			if existingTypes:
				existing_types_py = typecontainer.TypeContainer(handle=core.BNDuplicateTypeContainer(existingTypes))

			(result_py, errors_py) = self.parse_type_string(
				source_py, platform_py, existing_types_py)

			if errors is not None:
				errors[0] = self._return_errors(errors_py)
			if errorCount is not None:
				errorCount[0] = len(errors_py)

			if result_py is not None and result is not None:
				result[0].name = types.QualifiedName(result_py[0])._to_core_struct()
				result[0].type = core.BNNewTypeReference(result_py[1].handle)

			return result_py is not None
		except Exception:
			errorCount[0] = 0
			log_error_for_exception("Unhandled Python exception in TypeParser._parse_type_string")
			return False

	def _free_string(
			self, ctxt, string
	) -> None:
		try:
			self._pending_results.pop(string)
		except Exception:
			log_error_for_exception("Unhandled Python exception in TypeParser._free_string")

	def _free_result(
			self, ctxt, result
	) -> None:
		try:
			TypeParserResult._free_core_struct(self._pending_results.pop(ctypes.addressof(result.contents)))
		except Exception:
			log_error_for_exception("Unhandled Python exception in TypeParser._free_result")

	def _free_error_list(
			self, ctxt, errors, errorCount
	) -> None:
		try:
			if not errors:
				# The error list is null when the callback raised before returning one.
				return

			self._pending_results.pop(ctypes.cast(errors, ctypes.c_void_p).value)
		except Exception:
			log_error_for_exception("Unhandled Python exception in TypeParser._free_error_list")

	def get_option_text(self, option: TypeParserOption, value: str) -> Optional[str]:
		"""
		Get the string representation of an option for passing to parse_type_*

		:param option: Option type
		:param value: Option value
		:return: A string representing the option if the parser supports it, otherwise None
		"""
		return None

	def preprocess_source(
			self, source: str, file_name: str, platform: 'platform.Platform',
			existing_types: Optional['types.TypeContainerType'] = None,
			options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None
	) -> Tuple[Optional[str], List[TypeParserError]]:
		"""
		Preprocess a block of source, returning the source that would be parsed

		:param source: Source code to process
		:param file_name: Name of the file containing the source (does not need to exist on disk)
		:param platform: Platform to assume the source is relevant to
		:param existing_types: Optional collection of all existing types to use for parsing context
		:param options: Optional string arguments to pass as options, e.g. command line arguments
		:param include_dirs: Optional list of directories to include in the header search path
		:return: A tuple of (preproccessed source, errors), where the preproccessed source
		         is None if there was a fatal error.
		"""
		raise NotImplementedError("Not implemented")

	def parse_types_from_source(
			self, source: str, file_name: str, platform: 'platform.Platform',
			existing_types: Optional['types.TypeContainerType'] = None,
			options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None,
			auto_type_source: str = ""
	) -> Tuple[Optional[TypeParserResult], List[TypeParserError]]:
		"""
		Parse an entire block of source into types, variables, and functions

		:param source: Source code to parse
		:param file_name: Name of the file containing the source (optional: exists on disk)
		:param platform: Platform to assume the types are relevant to
		:param existing_types: Optional container of all existing types to use for parsing context
		:param options: Optional string arguments to pass as options, e.g. command line arguments
		:param include_dirs: Optional list of directories to include in the header search path
		:param auto_type_source: Optional source of types if used for automatically generated types
		:return: A tuple of (result, errors) where the result is None if there was a fatal error
		"""
		raise NotImplementedError("Not implemented")

	def parse_type_string(
			self, source: str, platform: 'platform.Platform',
			existing_types: Optional['types.TypeContainerType'] = None
	) -> Tuple[Optional[Tuple['types.QualifiedNameType', 'types.Type']], List[TypeParserError]]:
		"""
		Parse a single type and name from a string containing their definition.

		:param source: Source code to parse
		:param platform: Platform to assume the types are relevant to
		:param existing_types: Optional container of all existing types to use for parsing context
		:return: A tuple of (result, errors) where result is a tuple of (type, name) or
		         None of there was a fatal error.
		"""
		raise NotImplementedError("Not implemented")


class CoreTypeParser(TypeParser):

	def get_option_text(self, option: TypeParserOption, value: str) -> Optional[str]:
		result_cpp = ctypes.c_char_p()
		if not core.BNGetTypeParserOptionText(self.handle, option, value, result_cpp):
			return None
		result = core.pyNativeStr(result_cpp.value)
		core.free_string(result_cpp)
		return result

	def preprocess_source(
			self, source: str, file_name: str, platform: 'platform.Platform',
			existing_types: Optional['types.TypeContainerType'] = None,
			options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None
	) -> Tuple[Optional[str], List[TypeParserError]]:
		if options is None:
			options = []
		if include_dirs is None:
			include_dirs = []

		existing_types_cpp = None
		if existing_types is not None:
			if isinstance(existing_types, (binaryview.BinaryView,)):
				existing_types_cpp = existing_types.type_container
			elif isinstance(existing_types, (typecontainer.TypeContainer,)):
				existing_types_cpp = existing_types
			else:
				assert False, "Unexpected type container type"

		options_cpp = (ctypes.c_char_p * len(options))()
		for (i, s) in enumerate(options):
			options_cpp[i] = core.cstr(s)

		include_dirs_cpp = (ctypes.c_char_p * len(include_dirs))()
		for (i, s) in enumerate(include_dirs):
			include_dirs_cpp[i] = core.cstr(s)

		output_cpp = ctypes.c_char_p()
		errors_cpp = ctypes.POINTER(core.BNTypeParserError)()
		error_count = ctypes.c_size_t()

		success = core.BNTypeParserPreprocessSource(
			self.handle, source, file_name, platform.handle,
			existing_types_cpp.handle if existing_types_cpp is not None else None,
			options_cpp, len(options), include_dirs_cpp, len(include_dirs),
			output_cpp, errors_cpp, error_count
		)

		if success:
			output = core.pyNativeStr(output_cpp.value)
			core.free_string(output_cpp)
		else:
			output = None

		errors = []
		for i in range(error_count.value):
			errors.append(TypeParserError._from_core_struct(errors_cpp[i]))
		core.BNFreeTypeParserErrors(errors_cpp, error_count.value)

		return output, errors

	def parse_types_from_source(
			self, source: str, file_name: str, platform: 'platform.Platform',
			existing_types: Optional['types.TypeContainerType'] = None,
			options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None,
			auto_type_source: str = ""
	) -> Tuple[Optional[TypeParserResult], List[TypeParserError]]:
		if options is None:
			options = []
		if include_dirs is None:
			include_dirs = []

		existing_types_cpp = None
		if existing_types is not None:
			if isinstance(existing_types, (binaryview.BinaryView,)):
				existing_types_cpp = existing_types.type_container
			elif isinstance(existing_types, (typecontainer.TypeContainer,)):
				existing_types_cpp = existing_types
			else:
				assert False, "Unexpected type container type"

		options_cpp = (ctypes.c_char_p * len(options))()
		for (i, s) in enumerate(options):
			options_cpp[i] = core.cstr(s)

		include_dirs_cpp = (ctypes.c_char_p * len(include_dirs))()
		for (i, s) in enumerate(include_dirs):
			include_dirs_cpp[i] = core.cstr(s)

		result_cpp = core.BNTypeParserResult()
		errors_cpp = ctypes.POINTER(core.BNTypeParserError)()
		error_count = ctypes.c_size_t()

		success = core.BNTypeParserParseTypesFromSource(
			self.handle, source, file_name, platform.handle,
			existing_types_cpp.handle if existing_types_cpp is not None else None,
			options_cpp, len(options), include_dirs_cpp, len(include_dirs),
			auto_type_source, result_cpp, errors_cpp, error_count
		)

		if success:
			result = TypeParserResult._from_core_struct(result_cpp)
		else:
			result = None
		core.BNFreeTypeParserResult(result_cpp)

		errors = []
		for i in range(error_count.value):
			errors.append(TypeParserError._from_core_struct(errors_cpp[i]))
		core.BNFreeTypeParserErrors(errors_cpp, error_count.value)

		return result, errors


	def parse_type_string(
			self, source: str, platform: 'platform.Platform',
			existing_types: Optional['types.TypeContainerType'] = None
	) -> Tuple[Optional[Tuple['types.QualifiedNameType', 'types.Type']], List[TypeParserError]]:

		existing_types_cpp = None
		if existing_types is not None:
			if isinstance(existing_types, (binaryview.BinaryView,)):
				existing_types_cpp = existing_types.type_container
			elif isinstance(existing_types, (typecontainer.TypeContainer,)):
				existing_types_cpp = existing_types
			else:
				assert False, "Unexpected type container type"

		result_cpp = core.BNQualifiedNameAndType()
		errors_cpp = ctypes.POINTER(core.BNTypeParserError)()
		error_count = ctypes.c_size_t()

		success = core.BNTypeParserParseTypeString(
			self.handle, source, platform.handle,
			existing_types_cpp.handle if existing_types_cpp is not None else None,
			result_cpp, errors_cpp, error_count
		)

		if success:
			result = (
				types.QualifiedName._from_core_struct(result_cpp.name),
				types.Type.create(handle=core.BNNewTypeReference(result_cpp.type))
			)
		else:
			result = None
		core.BNFreeQualifiedNameAndType(result_cpp)

		errors = []
		for i in range(error_count.value):
			errors.append(TypeParserError._from_core_struct(errors_cpp[i]))
		core.BNFreeTypeParserErrors(errors_cpp, error_count.value)

		return result, errors
