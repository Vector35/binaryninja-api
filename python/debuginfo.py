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
from typing import Optional, List, Iterator, Callable, Tuple
import traceback
from dataclasses import dataclass

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import platform as _platform
from . import types as _types
from .log import log_error
from . import binaryview
from . import filemetadata
from . import typecontainer

_debug_info_parsers = {}
ProgressFuncType = Callable[[int, int], bool]


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
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			return callback(view_obj)
		except:
			log_error(traceback.format_exc())
			return False

	@staticmethod
	def _parse_info(
	    debug_info: core.BNDebugInfo, view: core.BNBinaryView, debug_view: core.BNBinaryView, progress: ProgressFuncType,
	    callback: Callable[["DebugInfo", 'binaryview.BinaryView', 'binaryview.BinaryView', ProgressFuncType], bool],
	) -> bool:
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			debug_file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(debug_view))
			debug_view_obj = binaryview.BinaryView(file_metadata=debug_file_metadata, handle=core.BNNewViewReference(debug_view))
			parser_ref = core.BNNewDebugInfoReference(debug_info)
			assert parser_ref is not None, "core.BNNewDebugInfoReference returned None"
			return callback(DebugInfo(parser_ref), view_obj, debug_view_obj, progress)
		except:
			log_error(traceback.format_exc())
			return False

	@classmethod
	def register(
	    cls, name: str, is_valid: Callable[['binaryview.BinaryView'], bool],
	    parse_info: Callable[["DebugInfo", 'binaryview.BinaryView', 'binaryview.BinaryView', ProgressFuncType], bool]
	) -> "DebugInfoParser":
		"""Registers a DebugInfoParser. See ``debuginfo.DebugInfoParser`` for more details."""
		binaryninja._init_plugins()

		is_valid_cb = ctypes.CFUNCTYPE(
		  ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView)
		)(lambda ctxt, view: cls._is_valid(view, is_valid))

		parse_info_cb = ctypes.CFUNCTYPE(
		  ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNDebugInfo), ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNBinaryView),
		  ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t), ctypes.c_void_p,
		)(lambda ctxt, debug_info, view, debug_view, progress, progress_ctxt: cls._parse_info(debug_info, view, debug_view, lambda cur, max: progress(progress_ctxt, cur, max), parse_info))

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
	:py:class:`DebugInfoParser` represents the registered parsers and providers of debug information for Binary Ninja.

	The debug information is used by Binary Ninja as ground-truth information about the attributes of functions,
	types, and variables that Binary Ninja's analysis pipeline would otherwise work to deduce. By providing
	debug info, Binary Ninja's output can be generated quicker, more accurately, and more completely.

	A DebugInfoParser consists of:

	1. A name
	2. An ``is_valid`` function which takes a :py:class:`binaryview.BinaryView` and returns a bool.
	3. A ``parse`` function which takes a :py:class:`DebugInfo` object and uses the member functions :py:meth:`DebugInfo.add_type`, :py:meth:`DebugInfo.add_function`, and :py:meth:`DebugInfo.add_data_variable` to populate all the info it can.

	And finally calling :py:meth:`DebugInfoParser.register` to register it with the core.

	A working example::

		import binaryninja as bn

		def is_valid(bv: bn.binaryview.BinaryView) -> bool:
			return bv.view_type == "Raw"

		def parse_info(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, debug_file: bn.binaryview.BinaryView, progress: Callable[[int, int], bool]) -> None:
			debug_info.add_type("name", bn.types.Type.int(4, True))
			debug_info.add_data_variable(0x1234, bn.types.Type.int(4, True), "name")
			function_info = bn.debuginfo.DebugFunctionInfo(0xadd6355, "short_name", "full_name", "raw_name", bn.types.Type.function(bn.types.Type.int(4, False), None), components=["some", "namespaces"])
			debug_info.add_function(function_info)

		bn.debuginfo.DebugInfoParser.register("debug info parser", is_valid, parse_info)

	:py:class:`DebugInfo` will then be automatically applied to binary views that contain debug information (via the setting `analysis.debugInfo.internal`), binary views that provide valid external debug info files (`analysis.debugInfo.external`), or manually fetched/applied as below::

		valid_parsers = bn.debuginfo.DebugInfoParser.get_parsers_for_view(bv)
		parser = valid_parsers[0]
		debug_info = parser.parse_debug_info(bv, bv)  # See docs for why BV is here twice
		bv.apply_debug_info(debug_info)

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

	def parse_debug_info(self, view: 'binaryview.BinaryView', debug_view: 'binaryview.BinaryView', debug_info: Optional["DebugInfo"] = None, progress: ProgressFuncType = None) -> Optional["DebugInfo"]:
		"""
		Returns a ``DebugInfo`` object populated with debug info by this debug-info parser. Only provide a ``DebugInfo`` object if you wish to append to the existing debug info.

		Some debug file formats need both the original :py:class:`binaryview.BinaryView` (the binary being analyzed/having debug information applied to it) in addition to the :py:class:`binaryview.BinaryView` of the file containing the debug information.
		For formats where you can get all the information you need from a single file, calls to ``parse_debug_info`` are required to provide that file for both arguments.
		For formats where you can get all the information you need from a single file, implementations of `parse` should only read from the second `debug_file` parameter and ignore the former.
		"""
		if progress is None:
			progress = lambda cur, max: True
		progress_c = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t)(lambda ctxt, cur, max: progress(cur, max))

		if isinstance(debug_info, DebugInfo):
			parser = core.BNParseDebugInfo(self.handle, view.handle, debug_view.handle, debug_info.handle, progress_c, None)
			if parser is None:
				return None
			parser_ref = core.BNNewDebugInfoReference(parser)
			assert parser_ref is not None, "core.BNNewDebugInfoReference returned None"
			return DebugInfo(parser_ref)
		else:
			parser = core.BNParseDebugInfo(self.handle, view.handle, debug_view.handle, None, progress_c, None)
			if parser is None:
				return None
			return DebugInfo(parser)


@dataclass(frozen=True)
class DebugFunctionInfo(object):
	"""
	``DebugFunctionInfo`` collates ground-truth function attributes for use in BinaryNinja's analysis.

	When contributing function info, provide only what you know - BinaryNinja will figure out everything else that it can.

	Functions will not be created if an address is not provided, but are able to be queried by the user from  `bv.debug_info` for later analysis.
	"""
	address: Optional[int] = None
	short_name: Optional[str] = None
	full_name: Optional[str] = None
	raw_name: Optional[str] = None
	function_type: Optional[_types.Type] = None
	platform: Optional['_platform.Platform'] = None
	components: Optional[List[str]] = None

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

	DebugInfo cannot be instantiated by the user, instead you must get it from either the binary view (see ``'binaryview.BinaryView'.debug_info``)
	or a debug-info parser (see ``debuginfo.DebugInfoParser.parse_debug_info``).

	.. note:: Please note that calling one of ``add_*`` functions will not work outside of a debuginfo plugin.
	"""
	def __init__(self, handle: core.BNDebugInfo) -> None:
		self.handle = core.handle_of_type(handle, core.BNDebugInfo)

	def __del__(self) -> None:
		core.BNFreeDebugInfoReference(self.handle)

	@property
	def parsers(self) -> Iterator[str]:
		count = ctypes.c_ulonglong()
		parsers = core.BNGetDebugParserNames(self.handle, count)
		try:
			assert parsers is not None, "core.BNGetDebugParserNames returned None"
			for i in range(0, count.value):
				yield parsers[i].decode("utf-8")
		finally:
			core.BNFreeStringList(parsers, count.value)

	def get_type_container(self, parser_name: str) -> 'typecontainer.TypeContainer':
		"""
		Type Container for all types in the DebugInfo that resulted from the parse of
		the given parser.

		:param parser_name: Name of parser
		:return: Type Container for types from that parser
		"""
		return typecontainer.TypeContainer(core.BNGetDebugInfoTypeContainer(self.handle, parser_name))

	def types_from_parser(self, name: Optional[str] = None) -> Iterator[Tuple[str, _types.Type]]:
		"""Returns a generator of all types provided by a named DebugInfoParser"""
		count = ctypes.c_ulonglong(0)
		name_and_types = core.BNGetDebugTypes(self.handle, name, count)
		try:
			assert name_and_types is not None, "core.BNGetDebugTypes returned None"
			for i in range(0, count.value):
				yield (name_and_types[i].name, _types.Type.create(core.BNNewTypeReference(name_and_types[i].type)))
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
		try:
			assert functions is not None, "core.BNGetDebugFunctions returned None"
			for i in range(0, count.value):
				function = functions[i]

				if function.type:
					function_type = _types.Type.create(core.BNNewTypeReference(function.type))
				else:
					function_type = None

				if function.platform:
					func_platform = _platform.CorePlatform._from_cache(handle=core.BNNewPlatformReference(function.platform))
				else:
					func_platform = None

				components = []
				for c in range(0, function.componentN):
					components.append(function.components[c])

				yield DebugFunctionInfo(
				    function.address, function.shortName, function.fullName, function.rawName,
				    function_type, func_platform, components
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
		try:
			assert data_variables is not None, "core.BNGetDebugDataVariables returned None"
			for i in range(0, count.value):
				yield binaryview.DataVariableAndName(
				    data_variables[i].address,
				    _types.Type.create(
				        core.BNNewTypeReference(data_variables[i].type), confidence=data_variables[i].typeConfidence
				    ), data_variables[i].name, data_variables[i].autoDiscovered
				)
		finally:
			core.BNFreeDataVariablesAndName(data_variables, count.value)

	@property
	def data_variables(self) -> Iterator['binaryview.DataVariableAndName']:
		"""A generator of all data variables provided by DebugInfoParsers"""
		return self.data_variables_from_parser()

	def get_type_by_name(self, parser_name: str, name: str) -> Optional[_types.Type]:
		result = core.BNGetDebugTypeByName(self.handle, parser_name, name)
		if result is not None:
			return _types.Type.create(result)
		return None

	def get_data_variable_by_name(self, parser_name: str, name: str) -> Optional[Tuple[int, _types.Type]]:
		name_and_var = core.BNDataVariableAndName()
		if not core.BNGetDebugDataVariableByName(self.handle, parser_name, name, name_and_var):
			return None
		result = (name_and_var.address, _types.Type.create(core.BNNewTypeReference(name_and_var.type)))
		core.BNFreeDataVariableAndName(name_and_var)
		return result

	def get_data_variable_by_address(self, parser_name: str, address: int) -> Optional[Tuple[str, _types.Type]]:
		name_and_var = core.BNDataVariableAndName()
		if not core.BNGetDebugDataVariableByAddress(self.handle, parser_name, address, name_and_var):
			return None
		result = (str(name_and_var.name), _types.Type.create(core.BNNewTypeReference(name_and_var.type)))
		core.BNFreeDataVariableAndName(name_and_var)
		return result

	def get_types_by_name(self, name: str) -> List[Tuple[str, _types.Type]]:
		""" The first element in the Tuple returned in the list is the name of the debug info parser the type came from """
		count = ctypes.c_ulonglong()
		names_and_types = core.BNGetDebugTypesByName(self.handle, name, count)
		try:
			result = []
			for i in range(count.value):
				assert names_and_types is not None, "core.BNGetDebugTypesByName returned None"
				result.append((names_and_types[i].name, _types.Type.create(core.BNNewTypeReference(names_and_types[i].type))))
			return result
		finally:
			core.BNFreeNameAndTypeList(names_and_types, count.value)

	def get_data_variables_by_name(self, name: str) -> List[Tuple[str, _types.Type]]:
		"""	The values in the tuples returned in the list is (DebugInfoParserName, address, type) """
		count = ctypes.c_ulonglong()
		variables_and_name = core.BNGetDebugDataVariablesByName(self.handle, name, count)
		try:
			result = []
			for i in range(count.value):
				assert variables_and_name is not None, "core.BNGetDebugDataVariablesByName returned None"
				result.append((
					variables_and_name[i].name, variables_and_name[i].address,
					_types.Type.create(core.BNNewTypeReference(variables_and_name[i].type))
				))
			return result
		finally:
			core.BNFreeDataVariablesAndName(variables_and_name, count.value)

	def get_data_variables_by_address(self, address: int) -> List[Tuple[str, _types.Type]]:
		"""	The values in the tuples returned in the list is (DebugInfoParserName, TypeName, type) """
		count = ctypes.c_ulonglong()
		variables_and_name = core.BNGetDebugDataVariablesByAddress(self.handle, address, count)
		try:
			result = []
			for i in range(count.value):
				assert variables_and_name is not None, "core.BNGetDebugDataVariablesByAddress returned None"
				result.append((
					variables_and_name[i].parser, variables_and_name[i].name,
					_types.Type.create(core.BNNewTypeReference(variables_and_name[i].type))
				))
			return result
		finally:
			core.BNFreeDataVariableAndNameAndDebugParserList(variables_and_name, count.value)

	def remove_parser_info(self, parser_name: str):
		return core.BNRemoveDebugParserInfo(self.handle, parser_name)

	def remove_parser_types(self, parser_name: str):
		return core.BNRemoveDebugParserTypes(self.handle, parser_name)

	def remove_parser_functions(self, parser_name: str):
		return core.BNRemoveDebugParserFunctions(self.handle, parser_name)

	def remove_parser_data_variables(self, parser_name: str):
		return core.BNRemoveDebugParserDataVariables(self.handle, parser_name)

	def remove_type_by_name(self, parser_name: str, name: str):
		return core.BNRemoveDebugTypeByName(self.handle, parser_name, name)

	def remove_function_by_index(self, parser_name: str, index: int):
		return core.BNRemoveDebugFunctionByIndex(self.handle, parser_name, index)

	def remove_data_variable_by_address(self, parser_name: str, address: int):
		return core.BNRemoveDebugDataVariableByAddress(self.handle, parser_name, address)

	def add_type(self, name: str, new_type: '_types.Type', components: Optional[List[str]] = None) -> bool:
		"""Adds a type scoped under the current parser's name to the debug info. While you're able to provide a list of components a type should live in, this is currently unused."""
		if components is None:
			components = []
		component_list = (ctypes.c_char_p * len(components))()
		for i in range(0, len(components)):
			component_list[i] = str(components[i]).encode('charmap')

		if isinstance(new_type, _types.Type):
			return core.BNAddDebugType(self.handle, name, new_type.handle, component_list, len(components))
		return NotImplemented

	def add_function(self, new_func: DebugFunctionInfo) -> bool:
		"""Adds a function scoped under the current parser's name to the debug info"""
		if not isinstance(new_func, DebugFunctionInfo):
			return NotImplemented

		func_info = core.BNDebugFunctionInfo()

		if new_func.function_type is None:
			func_info.type = None
		elif isinstance(new_func.function_type, _types.Type):
			func_info.type = new_func.function_type.handle
		else:
			return NotImplemented

		if new_func.platform is None:
			func_info.platform = None
		elif isinstance(new_func.platform, _platform.Platform):
			func_info.platform = new_func.platform.handle
		else:
			return NotImplemented

		if new_func.components is None:
			components = []
		elif isinstance(new_func.components, list):
			components = new_func.components
		else:
			return NotImplemented
		component_list = (ctypes.c_char_p * len(components))()
		for c in range(0, len(components)):
			component_list[c] = str(components[c]).encode('charmap')
		func_info.components = component_list
		func_info.componentN = len(components)

		func_info.shortName = new_func.short_name
		func_info.fullName = new_func.full_name
		func_info.rawName = new_func.raw_name
		func_info.address = new_func.address

		return core.BNAddDebugFunction(self.handle, func_info)

	def add_data_variable(self, address: int, new_type: '_types.Type', name: Optional[str] = None, components: Optional[List[str]] = None) -> bool:
		"""Adds a data variable scoped under the current parser's name to the debug info. Optionally, you can provide a path of component names under which that data variable should appear in the symbols sidebar."""
		if components is None:
			components = []
		component_list = (ctypes.c_char_p * len(components))()
		for i in range(0, len(components)):
			component_list[i] = str(components[i]).encode('charmap')

		if isinstance(address, int) and isinstance(new_type, _types.Type):
			return core.BNAddDebugDataVariable(self.handle, address, new_type.handle, name, component_list, len(components))
		return NotImplemented
