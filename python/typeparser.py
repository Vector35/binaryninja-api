# Copyright (c) 2015-2022 Vector 35 Inc
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
from typing import List, Tuple, Optional, Dict

import sys
import traceback

# Binary Ninja Components
import binaryninja
import binaryninja._binaryninjacore as core

from .settings import Settings
from . import platform
from . import types
from .log import log_error
from .enums import TypeParserErrorSeverity


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

	@property
	def default(self):
		name = binaryninja.Settings().get_string("analysis.types.parserName")
		return CoreTypeParser[name]


class TypeParser(metaclass=_TypeParserMetaclass):
	name = None
	_registered_parsers = []
	_cached_string = None
	_cached_result = None
	_cached_error = None

	def __init__(self, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNTypeParser)
			self.__dict__["name"] = core.BNGetTypeParserName(handle)

	def register(self):
		assert self.__class__.name is not None

		self._cb = core.BNTypeParserCallbacks()
		self._cb.context = 0
		self._cb.preprocessSource = self._cb.preprocessSource.__class__(self._preprocess_source)
		self._cb.parseTypesFromSource = self._cb.parseTypesFromSource.__class__(self._parse_types_from_source)
		self._cb.parseTypeString = self._cb.parseTypeString.__class__(self._parse_type_string)
		self._cb.freeString = self._cb.freeString.__class__(self._free_string)
		self._cb.freeResult = self._cb.freeResult.__class__(self._free_result)
		self._cb.freeErrorList = self._cb.freeErrorList.__class__(self._free_error_list)
		self.handle = core.BNRegisterTypeParser(self.__class__.name, self._cb)
		self.__class__._registered_parsers.append(self)

	def __str__(self):
		return f'<TypeParser: {self.name}>'

	def __repr__(self):
		return f'<TypeParser: {self.name}>'

	def _preprocess_source(
			self, ctxt, source, fileName, platform_, existingTypes, existingTypeCount,
			options, optionCount, includeDirs, includeDirCount,
			output, errors, errorCount
	) -> bool:
		try:
			source_py = core.pyNativeStr(source)
			file_name_py = core.pyNativeStr(fileName)
			platform_py = platform.Platform(handle=core.BNNewPlatformReference(platform_))

			existing_types_py = []
			for i in range(existingTypeCount):
				existing_types_py.append(QualifiedNameTypeAndId._from_core_struct(existingTypes[i]))

			options_py = []
			for i in range(optionCount):
				options_py.append(core.pyNativeStr(options[i]))

			include_dirs_py = []
			for i in range(includeDirCount):
				include_dirs_py.append(core.pyNativeStr(includeDirs[i]))

			(output_py, errors_py) = self.preprocess_source(
				source_py, file_name_py, platform_py, existing_types_py, options_py,
				include_dirs_py)

			if output_py is not None and output is not None:
				TypeParser._cached_string = core.cstr(output_py)
				output[0] = TypeParser._cached_string
			if errorCount is not None:
				errorCount[0] = len(errors_py)
			if errors is not None:
				errors_out = (core.BNTypeParserError * len(errors_py))()
				for i in range(len(errors_py)):
					errors_out[i] = errors_py[i]._to_core_struct()
				TypeParser._cached_error = errors_out
				errors[0] = errors_out

			return output_py is not None
		except:
			errorCount[0] = 0
			log_error(traceback.format_exc())
			return False

	def _parse_types_from_source(
			self, ctxt, source, fileName, platform_, existingTypes, existingTypeCount,
			options, optionCount, includeDirs, includeDirCount, autoTypeSource,
			result, errors, errorCount
	) -> bool:
		try:
			source_py = core.pyNativeStr(source)
			file_name_py = core.pyNativeStr(fileName)
			platform_py = platform.Platform(handle=core.BNNewPlatformReference(platform_))

			existing_types_py = []
			for i in range(existingTypeCount):
				existing_types_py.append(QualifiedNameTypeAndId._from_core_struct(existingTypes[i]))

			options_py = []
			for i in range(optionCount):
				options_py.append(core.pyNativeStr(options[i]))

			include_dirs_py = []
			for i in range(includeDirCount):
				include_dirs_py.append(core.pyNativeStr(includeDirs[i]))

			auto_type_source = core.pyNativeStr(autoTypeSource)

			(result_py, errors_py) = self.parse_types_from_source(
				source_py, file_name_py, platform_py, existing_types_py, options_py,
				include_dirs_py, auto_type_source)

			if result_py is not None and result is not None:
				result_struct = result_py._to_core_struct()
				TypeParser._cached_result = result_struct
				result[0] = result_struct

			if errorCount is not None:
				errorCount[0] = len(errors_py)
			if errors is not None:
				errors_out = (core.BNTypeParserError * len(errors_py))()
				for i in range(len(errors_py)):
					errors_out[i] = errors_py[i]._to_core_struct()
				TypeParser._cached_error = errors_out
				errors[0] = errors_out

			return result_py is not None
		except:
			result[0].typeCount = 0
			result[0].variableCount = 0
			result[0].functionCount = 0
			errorCount[0] = 0
			log_error(traceback.format_exc())
			return False

	def _parse_type_string(
			self, ctxt, source, platform_, existingTypes, existingTypeCount,
			result, errors, errorCount
	) -> bool:
		try:
			source_py = core.pyNativeStr(source)
			platform_py = platform.Platform(handle=core.BNNewPlatformReference(platform_))

			existing_types_py = []
			for i in range(existingTypeCount):
				existing_types_py.append(QualifiedNameTypeAndId._from_core_struct(existingTypes[i]))

			(result_py, errors_py) = self.parse_type_string(
				source_py, platform_py, existing_types_py)

			if result_py is not None and result is not None:
				result[0].name = types.QualifiedName(result_py[0])._to_core_struct()
				result[0].type = core.BNNewTypeReference(result_py[1].handle)

			if errorCount is not None:
				errorCount[0] = len(errors_py)
			if errors is not None:
				errors_out = (core.BNTypeParserError * len(errors_py))()
				for i in range(len(errors_py)):
					errors_out[i] = errors_py[i]._to_core_struct()
				TypeParser._cached_error = errors_out
				errors[0] = errors_out

			return result_py is not None
		except:
			errorCount[0] = 0
			log_error(traceback.format_exc())
			return False

	def _free_string(
			self, ctxt, string
	) -> bool:
		try:
			TypeParser._cached_string = None
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _free_result(
			self, ctxt, result
	) -> bool:
		try:
			if TypeParser._cached_result is not None:
				for i in range(TypeParser._cached_result.typeCount):
					core.BNFreeType(TypeParser._cached_result.types[i].type)
				for i in range(TypeParser._cached_result.variableCount):
					core.BNFreeType(TypeParser._cached_result.variables[i].type)
				for i in range(TypeParser._cached_result.functionCount):
					core.BNFreeType(TypeParser._cached_result.functions[i].type)
			TypeParser._cached_result = None
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _free_error_list(
			self, ctxt, errors, errorCount
	) -> bool:
		try:
			TypeParser._cached_error = None
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def preprocess_source(
			self, source: str, file_name: str, platform: 'platform.Platform',
			existing_types: Optional[List[QualifiedNameTypeAndId]] = None,
			options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None
	) -> Tuple[Optional[str], List[TypeParserError]]:
		raise NotImplementedError("Not implemented")

	def parse_types_from_source(
			self, source: str, file_name: str, platform: 'platform.Platform',
			existing_types: Optional[List[QualifiedNameTypeAndId]] = None,
			options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None,
			auto_type_source: str = ""
	) -> Tuple[Optional[TypeParserResult], List[TypeParserError]]:
		raise NotImplementedError("Not implemented")

	def parse_type_string(
			self, source: str, platform: 'platform.Platform',
			existing_types: Optional[List[QualifiedNameTypeAndId]] = None
	) -> Tuple[Optional[Tuple['types.QualifiedNameType', 'types.Type']], List[TypeParserError]]:
		raise NotImplementedError("Not implemented")


class CoreTypeParser(TypeParser):

	def preprocess_source(
			self, source: str, file_name: str, platform: 'platform.Platform',
			existing_types: Optional[List[QualifiedNameTypeAndId]] = None,
			options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None
	) -> Tuple[Optional[str], List[TypeParserError]]:
		if existing_types is None:
			existing_types = []
		if options is None:
			options = []
		if include_dirs is None:
			include_dirs = []

		existing_types_cpp = (core.BNQualifiedNameTypeAndId * len(existing_types))()
		for (i, qnatid) in enumerate(existing_types):
			existing_types_cpp[i] = qnatid._to_core_struct()

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
			existing_types_cpp, len(existing_types), options_cpp, len(options),
			include_dirs_cpp, len(include_dirs),
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
			existing_types: Optional[List[QualifiedNameTypeAndId]] = None,
			options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None,
			auto_type_source: str = ""
	) -> Tuple[Optional[TypeParserResult], List[TypeParserError]]:
		if existing_types is None:
			existing_types = []
		if options is None:
			options = []
		if include_dirs is None:
			include_dirs = []

		existing_types_cpp = (core.BNQualifiedNameTypeAndId * len(existing_types))()
		for (i, qnatid) in enumerate(existing_types):
			existing_types_cpp[i] = qnatid._to_core_struct()

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
			existing_types_cpp, len(existing_types), options_cpp, len(options),
			include_dirs_cpp, len(include_dirs), auto_type_source,
			result_cpp, errors_cpp, error_count
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
			existing_types: Optional[List[QualifiedNameTypeAndId]] = None
	) -> Tuple[Optional[Tuple['types.QualifiedNameType', 'types.Type']], List[TypeParserError]]:
		if existing_types is None:
			existing_types = []
		existing_types_cpp = (core.BNQualifiedNameTypeAndId * len(existing_types))()
		for (i, qnatid) in enumerate(existing_types):
			existing_types_cpp[i] = qnatid._to_core_struct()

		result_cpp = core.BNQualifiedNameAndType()
		errors_cpp = ctypes.POINTER(core.BNTypeParserError)()
		error_count = ctypes.c_size_t()

		success = core.BNTypeParserParseTypeString(
			self.handle, source, platform.handle,
			existing_types_cpp, len(existing_types),
			result_cpp, errors_cpp, error_count
		)

		if success:
			result = (
				types.QualifiedName._from_core_struct(result_cpp.name),
				types.Type.create(handle=core.BNNewTypeReference(result_cpp.type))
			)
			core.BNFreeQualifiedNameAndType(result_cpp)
		else:
			result = None

		errors = []
		for i in range(error_count.value):
			errors.append(TypeParserError._from_core_struct(errors_cpp[i]))
		core.BNFreeTypeParserErrors(errors_cpp, error_count.value)

		return result, errors


def preprocess_source(source: str, filename: str = None,
					  include_dirs: Optional[List[str]] = None) -> Tuple[Optional[str], str]:
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
	if include_dirs is None:
		include_dirs = []
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
		return output_str, error_str
	return None, error_str
