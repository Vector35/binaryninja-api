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
from typing import Optional, Mapping, Callable, List, Tuple

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import types as ty_
from . import platform
from . import typeparser
from . import enums


ProgressFuncType = Callable[[int, int], bool]


class TypeContainer:
	def __init__(self, handle: core.BNTypeContainerHandle):
		binaryninja._init_plugins()
		self.handle: core.BNTypeContainerHandle = core.handle_of_type(handle, core.BNTypeContainer)

	def __del__(self):
		if core is not None:
			core.BNFreeTypeContainer(self.handle)

	def __repr__(self):
		return f"<type container {self.name}>"

	@property
	def id(self) -> str:
		return core.BNTypeContainerGetId(self.handle)

	@property
	def name(self) -> str:
		return core.BNTypeContainerGetName(self.handle)

	@property
	def container_type(self) -> 'enums.TypeContainerType':
		return core.BNTypeContainerGetType(self.handle)

	@property
	def mutable(self) -> bool:
		return core.BNTypeContainerIsMutable(self.handle)

	@property
	def platform(self) -> 'platform.Platform':
		handle = core.BNTypeContainerGetPlatform(self.handle)
		assert handle is not None
		return platform.Platform(handle=handle)

	def add_types(self, types: Mapping['ty_.QualifiedNameType', 'ty_.Type'], progress_func: Optional[ProgressFuncType] = None) -> Optional[Mapping['ty_.QualifiedName', str]]:
		api_names = (core.BNQualifiedName * len(types))()
		api_types = (ctypes.POINTER(core.BNType) * len(types))()
		for (i, (key, value)) in enumerate(types.items()):
			api_names[i] = ty_.QualifiedName(key)._to_core_struct()
			api_types[i] = value.handle

		if progress_func:
			progress_func_obj = ctypes.CFUNCTYPE(
				ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: progress_func(cur, total))
		else:
			progress_func_obj = ctypes.CFUNCTYPE(
				ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: True)

		result_names = ctypes.POINTER(core.BNQualifiedName)()
		result_ids = ctypes.POINTER(ctypes.c_char_p)()
		result_count = ctypes.c_size_t(0)

		if not core.BNTypeContainerAddTypes(self.handle, api_names, api_types, len(types), progress_func_obj, None, result_names, result_ids, result_count):
			return None

		result = {}
		for i in range(result_count.value):
			name = ty_.QualifiedName._from_core_struct(result_names[i])
			id = core.pyNativeStr(result_ids[i])
			result[name] = id

		core.BNFreeTypeNameList(result_names, result_count.value)
		core.BNFreeStringList(result_ids, result_count.value)
		return result

	def rename_type(self, type_id: str, new_name: 'ty_.QualifiedNameType') -> bool:
		return core.BNTypeContainerRenameType(self.handle, type_id, ty_.QualifiedName(new_name)._to_core_struct())

	def delete_type(self, type_id: str) -> bool:
		return core.BNTypeContainerDeleteType(self.handle, type_id)

	def get_type_id(self, type_name: 'ty_.QualifiedNameType') -> Optional[str]:
		result = ctypes.c_char_p()
		if not core.BNTypeContainerGetTypeId(self.handle, ty_.QualifiedName(type_name)._to_core_struct(), result):
			return None
		return core.pyNativeStr(result.value)

	def get_type_name(self, type_id: str) -> Optional['ty_.QualifiedName']:
		api_result = core.BNQualifiedName()
		if not core.BNTypeContainerGetTypeName(self.handle, type_id, api_result):
			return None
		result = ty_.QualifiedName._from_core_struct(api_result)
		core.BNFreeQualifiedName(api_result)
		return result

	def get_type_by_id(self, type_id: str) -> Optional['ty_.Type']:
		result = ctypes.POINTER(core.BNType)()
		if not core.BNTypeContainerGetTypeById(self.handle, type_id, result):
			return None
		return ty_.Type(handle=result)

	@property
	def types(self) -> Optional[Mapping[str, Tuple['ty_.QualifiedName', 'ty_.Type']]]:
		result_names = ctypes.POINTER(core.BNQualifiedName)()
		result_ids = ctypes.POINTER(ctypes.c_char_p)()
		result_types = ctypes.POINTER(ctypes.POINTER(core.BNType))()
		result_count = ctypes.c_size_t(0)

		if not core.BNTypeContainerGetTypes(self.handle, result_ids, result_names, result_types, result_count):
			return None

		result = {}
		for i in range(result_count.value):
			name = ty_.QualifiedName._from_core_struct(result_names[i])
			id = core.pyNativeStr(result_ids[i])
			type = ty_.Type(handle=core.BNNewTypeReference(result_types[i]))
			result[id] = (name, type)

		core.BNFreeTypeNameList(result_names, result_count.value)
		core.BNFreeStringList(result_ids, result_count.value)
		core.BNFreeTypeList(result_types, result_count.value)
		return result

	def get_type_by_name(self, type_name: 'ty_.QualifiedNameType') -> Optional['ty_.Type']:
		result = ctypes.POINTER(core.BNType)()
		if not core.BNTypeContainerGetTypeByName(self.handle, ty_.QualifiedName(type_name)._to_core_struct(), result):
			return None
		return ty_.Type(handle=result)

	@property
	def type_ids(self) -> Optional[List[str]]:
		result_ids = ctypes.POINTER(ctypes.c_char_p)()
		result_count = ctypes.c_size_t(0)
		if not core.BNTypeContainerGetTypeIds(self.handle, result_ids, result_count):
			return None

		result = []
		for i in range(result_count.value):
			id = core.pyNativeStr(result_ids[i])
			result.append(id)

		core.BNFreeStringList(result_ids, result_count.value)
		return result

	@property
	def type_names(self) -> Optional[List['ty_.QualifiedName']]:
		result_names = ctypes.POINTER(core.BNQualifiedName)()
		result_count = ctypes.c_size_t(0)
		if not core.BNTypeContainerGetTypeNames(self.handle, result_names, result_count):
			return None

		result = []
		for i in range(result_count.value):
			name = ty_.QualifiedName._from_core_struct(result_names[i])
			result.append(name)

		core.BNFreeTypeNameList(result_names, result_count.value)
		return result

	@property
	def type_names_and_ids(self) -> Optional[Mapping[str, 'ty_.QualifiedName']]:
		result_names = ctypes.POINTER(core.BNQualifiedName)()
		result_ids = ctypes.POINTER(ctypes.c_char_p)()
		result_count = ctypes.c_size_t(0)
		if not core.BNTypeContainerGetTypeNamesAndIds(self.handle, result_ids, result_names, result_count):
			return None

		result = {}
		for i in range(result_count.value):
			name = ty_.QualifiedName._from_core_struct(result_names[i])
			id = core.pyNativeStr(result_ids[i])
			result[id] = name

		core.BNFreeTypeNameList(result_names, result_count.value)
		core.BNFreeStringList(result_ids, result_count.value)
		return result

	def parse_types_from_source(self, source: str, file_name: str, platform: 'platform.Platform',
			options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None,
			auto_type_source: str = ""
	) -> Tuple[Optional['typeparser.TypeParserResult'], List['typeparser.TypeParserError']]:
		if options is None:
			options = []
		if include_dirs is None:
			include_dirs = []

		options_cpp = (ctypes.c_char_p * len(options))()
		for (i, s) in enumerate(options):
			options_cpp[i] = core.cstr(s)

		include_dirs_cpp = (ctypes.c_char_p * len(include_dirs))()
		for (i, s) in enumerate(include_dirs):
			include_dirs_cpp[i] = core.cstr(s)

		result_cpp = core.BNTypeParserResult()
		errors_cpp = ctypes.POINTER(core.BNTypeParserError)()
		error_count = ctypes.c_size_t()

		success = core.BNTypeContainerParseTypesFromSource(
			self.handle, source, file_name, platform.handle,
			options_cpp, len(options),
			include_dirs_cpp, len(include_dirs), auto_type_source,
			result_cpp, errors_cpp, error_count
		)

		if success:
			result = typeparser.TypeParserResult._from_core_struct(result_cpp)
		else:
			result = None
		core.BNFreeTypeParserResult(result_cpp)

		errors = []
		for i in range(error_count.value):
			errors.append(typeparser.TypeParserError._from_core_struct(errors_cpp[i]))
		core.BNFreeTypeParserErrors(errors_cpp, error_count.value)

		return result, errors


