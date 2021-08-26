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
from typing import Optional, List, Iterator, Callable, Tuple
import traceback
from dataclasses import dataclass

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import callingconvention
from . import platform
from . import types as _types
from . import log
from . import binaryview
from . import filemetadata


_debug_info_parsers = {}


class _DebugInfoParserMetaClass(type):
	@property
	def list(self) -> List["DebugInfoParser"]:
		"""List all debug-info parsers (read-only)"""
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		parsers = core.BNGetDebugInfoParsers(count)
		assert parsers is not None, "core.BNGetDebugInfoParsers returned None"
		result = []
		for i in range(0, count.value):
			parser = core.BNNewDebugInfoParserReference(parsers[i])
			assert parser is not None, "core.BNNewDebugInfoParserReference returned None"
			result.append(DebugInfoParser(parser))
		core.BNFreeDebugInfoParserList(parsers, count.value)
		return result

	def __iter__(self) -> Iterator["DebugInfoParser"]:
		"""Generator of all debug-info parsers"""
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		parsers = core.BNGetDebugInfoParsers(count)
		assert parsers is not None, "core.BNGetDebugInfoParsers returned None"
		try:
			for i in range(0, count.value):
				parser = core.BNNewDebugInfoParserReference(parsers[i])
				assert parser is not None, "core.BNNewDebugInfoParserReference returned None"
				yield DebugInfoParser(parser)
		finally:
			core.BNFreeDebugInfoParserList(parsers, count.value)

	def __getitem__(cls, value: str) -> 'DebugInfoParser':
		"""Returns debug info parser of the given name, if it exists"""
		binaryninja._init_plugins()
		parser = core.BNGetDebugInfoParserByName(str(value))
		if parser is None:
			raise KeyError(f"'{str(value)}' is not a valid debug-info parser")
		parser_ref = core.BNNewDebugInfoParserReference(parser)
		assert parser_ref is not None, "core.BNNewDebugInfoParserReference returned None"
		return DebugInfoParser(parser_ref)

	@staticmethod
	def get_parsers_for_view(view: 'binaryview.BinaryView') -> List['DebugInfoParser']:
		"""Returns a list of debug-info parsers that are valid for the provided binary view"""
		binaryninja._init_plugins()

		count = ctypes.c_ulonglong()
		parsers = core.BNGetDebugInfoParsersForView(view.handle, count)
		assert parsers is not None, "core.BNGetDebugInfoParsersForView returned None"
		result = []
		try:
			for i in range(0, count.value):
				parser_ref = core.BNNewDebugInfoParserReference(parsers[i])
				assert parser_ref is not None, "core.BNNewDebugInfoParserReference returned None"
				result.append(DebugInfoParser(parser_ref))
		finally:
			core.BNFreeDebugInfoParserList(parsers, count.value)
		return result

	@staticmethod
	def _is_valid(view: core.BNBinaryView, callback: Callable[['binaryview.BinaryView'], bool]) -> bool:
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			return callback(view_obj)
		except:
			log.log_error(traceback.format_exc())
			return False

	@staticmethod
	def _parse_info(debug_info: core.BNDebugInfo, view: core.BNBinaryView, callback: Callable[["DebugInfo", 'binaryview.BinaryView'], None]) -> None:
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			parser_ref = core.BNNewDebugInfoReference(debug_info)
			assert parser_ref is not None, "core.BNNewDebugInfoReference returned None"
			callback(DebugInfo(parser_ref), view_obj)
		except:
			log.log_error(traceback.format_exc())

	@classmethod
	def register(cls, name: str, is_valid: Callable[['binaryview.BinaryView'], bool], parse_info: Callable[["DebugInfo", 'binaryview.BinaryView'], None]) -> "DebugInfoParser":
		"""Registers a DebugInfoParser. See ``debuginfo.DebugInfoParser`` for more details."""
		binaryninja._init_plugins()

		is_valid_cb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView))(lambda ctxt, view: cls._is_valid(view, is_valid))
		parse_info_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNDebugInfo), ctypes.POINTER(core.BNBinaryView))(lambda ctxt, debug_info, view: cls._parse_info(debug_info, view, parse_info))

		# Don't let our callbacks get garbage collected
		global _debug_info_parsers
		_debug_info_parsers[len(_debug_info_parsers)] = (is_valid_cb, parse_info_cb)
		parser = core.BNRegisterDebugInfoParser(name, is_valid_cb, parse_info_cb, None)
		assert parser is not None, "core.BNRegisterDebugInfoParser is not None"
		parser_ref = core.BNNewDebugInfoParserReference(parser)
		assert parser_ref is not None, "core.BNNewDebugInfoParserReference returned None"
		return DebugInfoParser(parser_ref)


class DebugInfoParser(object, metaclass=_DebugInfoParserMetaClass):
	"""
	``DebugInfoParser``s represent the registered parsers and providers of debug information to Binary Ninja.

	The debug information is used by Binary Ninja as ground-truth information about the attributes of functions,
	types, and variables that Binary Ninja's analysis pipeline would otherwise work to deduce. By providing
	debug info, Binary Ninja's output can be generated quicker, more accurately, and more completely.

	A DebugInfoParser consists of:
		1. A name
		2. An ``is_valid`` function which takes a BV and returns a bool
		3. A ``parse`` function which takes a ``DebugInfo`` object and uses the member functions ``add_type``, ``add_function``, and ``add_data_variable`` to populate all the info it can.
	And finally calling ``bn.debuginfo.DebugInfoParser.register`` to register it with the core.

	Here's a minimal, complete example boilerplate-plugin:
	```
	import binaryninja as bn

	def is_valid(bv: bn.binaryview.BinaryView) -> bool:
		return bv.view_type == "Raw"

	def parse_info(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView) -> None:
		debug_info.add_type("name", bn.types.Type.int(4, True))
		debug_info.add_data_variable(0x1234, bn.types.Type.int(4, True), "name")

		function_info = bn.debuginfo.DebugFunctionInfo(0xdead1337, "short_name", "full_name", "raw_name", bn.types.Type.int(4, False), [])
		debug_info.add_function(function_info)

	bn.debuginfo.DebugInfoParser.register("debug info parser", is_valid, parse_info)
	```

	``DebugInfo`` can then be automatically applied to valid binary views (via the "Parse and Apply Debug Info" setting), or manually fetched/applied as bellow:
	```
	valid_parsers = bn.debuginfo.DebugInfoParser.get_parsers_for_view(bv)
	parser = valid_parsers[0]
	debug_info = parser.parse_debug_info(bv)
	bv.apply_debug_info(debug_info)
	```

	Multiple debug-info parsers can manually contribute debug info for a binary view by simply calling ``parse_debug_info`` with the
	``DebugInfo`` object just returned. This is automatic when opening a binary view with multiple valid debug info parsers. If you
	wish to set the debug info for a binary view without applying it as well, you can call ``'binaryview.BinaryView'.set_debug_info``.
	"""
	def __init__(self, handle: core.BNDebugInfoParser) -> None:
		self.handle = core.handle_of_type(handle, core.BNDebugInfoParser)

	def __del__(self) -> None:
		core.BNFreeDebugInfoParserReference(self.handle)

	def __repr__(self) -> str:
		return f"<debug-info parser: '{self.name}'>"

	def __eq__(self, other: "DebugInfoParser") -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other: "DebugInfoParser") -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self) -> int:
		return hash(ctypes.addressof(self.handle.contents))

	@property
	def name(self) -> str:
		"""Debug-info parser's name (read-only)"""
		return core.BNGetDebugInfoParserName(self.handle)

	def is_valid_for_view(self, view: 'binaryview.BinaryView') -> bool:
		"""Returns whether this debug-info parser is valid for the provided binary view"""
		return core.BNIsDebugInfoParserValidForView(self.handle, view.handle)

	def parse_debug_info(self, view: 'binaryview.BinaryView', debug_info: Optional["DebugInfo"] = None) -> "DebugInfo":
		"""Returns a ``DebugInfo`` object populated with debug info by this debug-info parser. Only provide a ``DebugInfo`` object if you wish to append to the existing debug info"""
		if isinstance(debug_info, DebugInfo):
			parser = core.BNParseDebugInfo(self.handle, view.handle, debug_info.handle)
			assert parser is not None, "core.BNParseDebugInfo returned None"
			parser_ref = core.BNNewDebugInfoReference(parser)
			assert parser_ref is not None, "core.BNNewDebugInfoReference returned None"
			return DebugInfo(parser_ref)
		else:
			parser = core.BNParseDebugInfo(self.handle, view.handle, None)
			assert parser is not None, "core.BNParseDebugInfo returned None"
			return DebugInfo(parser)


@dataclass(frozen=True)
class DebugFunctionInfo(object):
	"""
	``DebugFunctionInfo`` collates ground-truth function-external attributes for use in BinaryNinja's internal analysis.

	When contributing function info, provide only what you know - BinaryNinja will figure out everything else that it can, as it usually does.

	Functions will not be created if an address is not provided, but will be able to be queried from debug info for later user analysis.
	"""
	short_name:Optional[str]
	full_name:Optional[str]
	raw_name:Optional[str]
	address:Optional[int]
	return_type:Optional[_types.Type]
	parameters:Optional[List[Tuple[str, _types.Type]]]
	variable_parameters:Optional[bool]
	calling_convention:Optional[callingconvention.CallingConvention]
	platform:Optional[platform.Platform]

	def __repr__(self) -> str:
		suffix = f"@{self.address:#x}>" if self.address != 0 else ">"
		if self.short_name is not None:
			return f"<debug-info function: {self.short_name}{suffix}"
		elif self.full_name is not None:
			return f"<debug-info function: {self.full_name}{suffix}"
		elif self.raw_name is not None:
			return f"<debug-info function: {self.raw_name}{suffix}"
		else:
			return f"<debug-info function{suffix}"


class DebugInfo(object):
	"""
	``class DebugInfo`` provides an interface to both provide and query debug info. The DebugInfo object is used
	internally by the binary view to which it is applied to determine the attributes of functions, types, and variables
	that would otherwise be costly to deduce.

	DebugInfo objects themselves are independent of binary views; their data can be sourced from any arbitrary binary
	views and be applied to any other arbitrary binary view. A DebugInfo object can also contain debug info from multiple
	DebugInfoParsers. This makes it possible to gather debug info that may be distributed across several different
	formats and files.

	DebugInfo cannot be instantiated by the user, instead get it from either the binary view (see ``'binaryview.BinaryView'.debug_info``)
	or a debug-info parser (see ``debuginfo.DebugInfoParser.parse_debug_info``).

	.. note:: Please note that calling one of ``add_*`` functions will not work outside of a debuginfo plugin.
	"""
	def __init__(self, handle: core.BNDebugInfo) -> None:
		self.handle = core.handle_of_type(handle, core.BNDebugInfo)

	def __del__(self) -> None:
		core.BNFreeDebugInfoReference(self.handle)

	def types_from_parser(self, name: Optional[str] = None) -> Iterator[Tuple[str, _types.Type]]:
		"""Returns a generator of all types provided by a named DebugInfoParser"""
		count = ctypes.c_ulonglong(0)
		name_and_types = core.BNGetDebugTypes(self.handle, name, count)
		assert name_and_types is not None, "core.BNGetDebugTypes returned None"
		try:
			for i in range(0, count.value):
				yield (name_and_types[i].name, _types.Type(core.BNNewTypeReference(name_and_types[i].type)))
		finally:
			core.BNFreeDebugTypes(name_and_types, count.value)

	@property
	def types(self) -> Iterator[Tuple[str, _types.Type]]:
		"""A generator of all types provided by DebugInfoParsers"""
		return self.types_from_parser()

	def functions_from_parser(self, name: Optional[str] = None) -> Iterator[DebugFunctionInfo]:
		"""Returns a generator of all functions provided by a named DebugInfoParser"""
		count = ctypes.c_ulonglong(0)
		functions = core.BNGetDebugFunctions(self.handle, name, count)
		assert functions is not None, "core.BNGetDebugFunctions returned None"
		try:
			for i in range(0, count.value):

				parameters: List[Tuple[str, _types.Type]] = []
				for j in range(functions[i].parameterCount):
					parameters.append((functions[i].parameterNames[j], _types.Type(core.BNNewTypeReference(functions[i].parameterTypes[j]))))

				if functions[i].returnType:
					return_type = _types.Type(core.BNNewTypeReference(functions[i].returnType))
				else:
					return_type = None

				if functions[i].callingConvention:
					calling_convention = callingconvention.CallingConvention(handle=core.BNNewCallingConventionReference(functions[i].callingConvention))
				else:
					calling_convention = None

				if functions[i].platform:
					func_platform = platform.Platform(handle=core.BNNewPlatformReference(functions[i].platform))
				else:
					func_platform = None

				yield DebugFunctionInfo(
					functions[i].address,
					functions[i].shortName,
					functions[i].fullName,
					functions[i].rawName,
					return_type,
					parameters,
					functions[i].variableParameters,
					calling_convention,
					func_platform
				)
		finally:
			core.BNFreeDebugFunctions(functions, count.value)

	@property
	def functions(self) -> Iterator[DebugFunctionInfo]:
		"""A generator of all functions provided by DebugInfoParsers"""
		return self.functions_from_parser()

	def data_variables_from_parser(self, name: Optional[str] = None) -> Iterator['binaryview.DataVariableAndName']:
		"""Returns a generator of all data variables provided by a named DebugInfoParser"""
		count = ctypes.c_ulonglong(0)
		data_variables = core.BNGetDebugDataVariables(self.handle, name, count)
		assert data_variables is not None, "core.BNGetDebugDataVariables returned None"
		try:
			for i in range(0, count.value):
				yield binaryview.DataVariableAndName(
					data_variables[i].address,
					_types.Type(core.BNNewTypeReference(data_variables[i].type), confidence=data_variables[i].typeConfidence),
					data_variables[i].name,
					data_variables[i].autoDiscovered)
		finally:
			core.BNFreeDataVariablesAndName(data_variables, count.value)

	@property
	def data_variables(self) -> Iterator['binaryview.DataVariableAndName']:
		"""A generator of all data variables provided by DebugInfoParsers"""
		return self.data_variables_from_parser()

	def add_type(self, name: str, new_type:'_types.Type') -> bool:
		"""Adds a type scoped under the current parser's name to the debug info"""
		if isinstance(new_type, _types.Type):
			return core.BNAddDebugType(self.handle, name, new_type.handle)
		return NotImplemented

	def add_function(self, new_func: DebugFunctionInfo) -> bool:
		"""Adds a function scoped under the current parser's name to the debug info"""
		if not isinstance(new_func, DebugFunctionInfo):
			return NotImplemented

		parameter_count = 0
		if new_func.parameters is not None:
			parameter_count = len(new_func.parameters)

		func_info = core.BNDebugFunctionInfo()

		if new_func.return_type is None:
			func_info.returnType = None
		elif isinstance(new_func.return_type, _types.Type):
			func_info.returnType = new_func.return_type.handle
		else:
			return NotImplemented

		if new_func.calling_convention is None:
			func_info.callingConvention = None
		elif isinstance(new_func.calling_convention, callingconvention.CallingConvention):
			func_info.callingConvention = new_func.calling_convention.handle
		else:
			return NotImplemented

		if new_func.platform is None:
			func_info.platform = None
		elif isinstance(new_func.platform, platform.Platform):
			func_info.platform = new_func.platform.handle
		else:
			return NotImplemented

		func_info.shortName = new_func.short_name
		func_info.fullName = new_func.full_name
		func_info.rawName = new_func.raw_name
		func_info.address = new_func.address
		func_info.variableParameters = new_func.variable_parameters

		if parameter_count == 0:
			func_info.parameterNames = None
			func_info.parameterTypes = None
			func_info.parameterCount = parameter_count
		else:
			func_info.parameterNames = (ctypes.c_char_p * parameter_count)(*map(lambda pair: binaryninja.cstr(pair[0]), new_func.parameters))  # type: ignore
			func_info.parameterTypes = (ctypes.POINTER(core.BNType) * parameter_count)(*map(lambda pair: pair[1].handle, new_func.parameters))  # type: ignore
			func_info.parameterCount = parameter_count

		return core.BNAddDebugFunction(self.handle, func_info)

	def add_data_variable(self, address: int, new_type: '_types.Type', name: Optional[str] = None) -> bool:
		"""Adds a data variable scoped under the current parser's name to the debug info"""
		if isinstance(address, int) and isinstance(new_type, _types.Type):
			return core.BNAddDebugDataVariable(self.handle, address, new_type.handle, name)
		return NotImplemented
