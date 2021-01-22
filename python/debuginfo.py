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


# TODO : Documentation

import ctypes
from typing import Optional, List, Iterator, Callable, Tuple
import traceback

# Binary Ninja components
import binaryninja
from binaryninja import _binaryninjacore as core
from binaryninja import types
from binaryninja import log


_debug_info_parsers = {}


class _DebugInfoParserMetaClass(type):
	@property
	def list(self) -> List["DebugInfoParser"]:
		"""List all debug-info parsers (read-only)"""
		binaryninja._init_plugins()  # TODO : Is this needed?
		count = ctypes.c_ulonglong()
		parsers = core.BNGetDebugInfoParsers(count)
		result = []
		for i in range(0, count.value):
			result.append(DebugInfoParser(parsers[i]))
		core.BNFreeDebugInfoParserList(parsers, count.value)
		return result

	# TODO : Convert in to a "real" iterator
	def __iter__(self) -> Iterator["DebugInfoParser"]:
		binaryninja._init_plugins()  # TODO : Is this needed?
		count = ctypes.c_ulonglong()
		parsers = core.BNGetDebugInfoParsers(count)
		try:
			for i in range(0, count.value):
				yield DebugInfoParser(parsers[i])
		finally:
			core.BNFreeDebugInfoParserList(parsers, count.value)

	def __getitem__(cls, value: str) -> "DebugInfoParser":
		binaryninja._init_plugins()  # TODO : Is this needed?
		parser = core.BNGetDebugInfoParserByName(str(value))
		if parser is None:
			raise KeyError(f"'{str(value)}' is not a valid debug-info parser")
		return DebugInfoParser(parser)

	def _is_valid(cls, view: core.BNBinaryView, callback: Callable[[binaryninja.BinaryView], bool]) -> bool:
		try:
			file_metadata = binaryninja.filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryninja.binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			return callback(view_obj)
		except:
			log.log_error(traceback.format_exc())

	def _parse_info(cls, debug_info: core.BNDebugInfo, view: core.BNBinaryView, callback: Callable[["DebugInfo", binaryninja.BinaryView], None]) -> None:
		try:
			file_metadata = binaryninja.filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryninja.binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			callback(DebugInfo(debug_info), view_obj)
		except:
			log.log_error(traceback.format_exc())

	def register(cls, name: str, is_valid: Callable[[binaryninja.BinaryView], bool], parse_info: Callable[["DebugInfo", binaryninja.BinaryView], None]) -> "DebugInfoParser":
		binaryninja._init_plugins()  # TODO : Is this needed?

		is_valid_cb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView))(lambda ctxt, view: cls._is_valid(view, is_valid))
		parse_info_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNDebugInfo), ctypes.POINTER(core.BNBinaryView))(lambda ctxt, debug_info, view: cls._parse_info(debug_info, view, parse_info))

		# Don't let our callbacks get garbage collected
		global _debug_info_parsers
		_debug_info_parsers[len(_debug_info_parsers)] = (is_valid_cb, parse_info_cb)

		return DebugInfoParser(core.BNRegisterDebugInfoParser(name, is_valid_cb, parse_info_cb, None))


class DebugInfoParser(object, metaclass=_DebugInfoParserMetaClass):
	def __init__(self, handle: core.BNDebugInfoParser) -> None:
		self.handle = core.handle_of_type(handle, core.BNDebugInfoParser)

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
		"""debug-info parsers name (read-only)"""
		return core.BNGetDebugInfoParserName(self.handle)

	def is_valid_for_view(self, view: binaryninja.BinaryView) -> bool:
		return core.BNIsDebugInfoParserValidForView(self.handle, view.handle)


class DebugFunctionInfo(object):
	def __init__(self, short_name: str, full_name: str, raw_name: str, address: int, return_type: Optional[types.Type], parameters: List[Tuple[str, types.Type]]) -> None:
		self._short_name = short_name
		self._full_name = full_name
		self._raw_name = raw_name
		self._address = address

		if return_type is None:
			self._return_type = types.Type.void()
		else:
			self._return_type = return_type

		self._parameters = parameters

	def __repr__(self) -> str:
		return f"<debug-info function: {self._short_name}>"

	@property
	def short_name(self) -> str:
		""" """
		return self._short_name

	@property
	def full_name(self) -> str:
		""" """
		return self._full_name

	@property
	def raw_name(self) -> str:
		""" """
		return self._raw_name

	@property
	def address(self) -> int:
		""" """
		return self._address

	@property
	def return_type(self) -> int:
		""" """
		return self._return_type

	@property
	def parameters(self) -> List[Tuple[str, types.Type]]:
		""" """
		return self._parameters


class DebugInfo(object):
	# TODO : Look at the BinaryView documentation and make this equally as nice
	def __init__(self, handle: core.BNDebugInfo) -> None:
		self.handle = core.handle_of_type(handle, core.BNDebugInfo)

	# TODO : Return the type that was added instead of whether or not the type was added (type wasn't previously added)?
	def add_type(self, name: str, new_type: types.Type) -> bool:
		if isinstance(new_type, types.Type):
			return core.BNAddDebugType(self.handle, name, new_type.handle)
		return NotImplemented

	def add_function(self, new_func: DebugFunctionInfo) -> bool:
		if not isinstance(new_func, DebugFunctionInfo):
			return NotImplemented

		parameter_count = len(new_func.parameters)

		func_info = core.BNDebugFunctionInfo()

		if new_func.return_type is None:
			func_info.returnType = None
		elif isinstance(new_func.return_type, types.Type):
			func_info.returnType = new_func.return_type.handle
		else:
			return NotImplemented

		func_info.shortName = new_func.short_name
		func_info.fullName = new_func.full_name
		func_info.rawName = new_func.raw_name
		func_info.address = new_func.address
		func_info.parameterNames = (ctypes.c_char_p * parameter_count)(*map(lambda pair: binaryninja.cstr(pair[0]), new_func.parameters))
		func_info.parameterTypes = (ctypes.POINTER(core.BNType) * parameter_count)(*map(lambda pair: pair[1].handle, new_func.parameters))
		func_info.parameterCount = parameter_count

		return core.BNAddDebugFunction(self.handle, func_info)
