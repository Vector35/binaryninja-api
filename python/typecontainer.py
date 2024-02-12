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
from typing import Optional, Mapping, Callable, List, Tuple

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import types as _types
from . import platform
from . import typeparser
from . import enums


ProgressFuncType = Callable[[int, int], bool]


class TypeContainer:
	"""
	A ``TypeContainer`` is a generic interface to access various Binary Ninja models
	that contain types. Types are stored with both a unique id and a unique name.
	"""
	def __init__(self, handle: core.BNTypeContainerHandle):
		"""
		Construct a Type Container, internal use only
		:param handle: Handle pointer
		"""
		binaryninja._init_plugins()
		self.handle: core.BNTypeContainerHandle = core.handle_of_type(handle, core.BNTypeContainer)

	def __del__(self):
		if core is not None:
			core.BNFreeTypeContainer(self.handle)

	def __repr__(self):
		return f"<type container {self.name}>"

	@property
	def id(self) -> str:
		"""
		Get an id string for the Type Container. This will be unique within a given
		analysis session, but may not be globally unique.
		:return: Identifier string
		"""
		return core.BNTypeContainerGetId(self.handle)

	@property
	def name(self) -> str:
		"""
		Get a user-friendly name for the Type Container.
		:return: Display name
		"""
		return core.BNTypeContainerGetName(self.handle)

	@property
	def container_type(self) -> 'enums.TypeContainerType':
		"""
		Get the type of underlying model the Type Container is accessing.
		:return: Container type enum
		"""
		return core.BNTypeContainerGetType(self.handle)

	@property
	def mutable(self) -> bool:
		"""
		Test if the Type Container supports mutable operations (add, rename, delete)
		:return: True if mutable
		"""
		return core.BNTypeContainerIsMutable(self.handle)

	@property
	def platform(self) -> 'platform.Platform':
		"""
		Get the Platform object associated with this Type Container. All Type Containers
		have exactly one associated Platform (as opposed to, e.g. Type Libraries).
		:return: Associated Platform object
		"""
		handle = core.BNTypeContainerGetPlatform(self.handle)
		assert handle is not None
		return platform.Platform(handle=handle)

	def add_types(self, types: Mapping['_types.QualifiedNameType', '_types.Type'], progress_func: Optional[ProgressFuncType] = None) -> Optional[Mapping['_types.QualifiedName', str]]:
		"""
		Add or update types to a Type Container. If the Type Container already contains
		a type with the same name as a type being added, the existing type will be
		replaced with the definition given to this function, and references will be
		updated in the source model.

		An optional progress callback is included because adding many types can be a slow operation.

		:param types: Dict from name -> definition of new types to add
		:param progress_func: Optional function to call for progress updates
		:return: Dict from name -> id of type in Type Container for all added types if successful,
		         None otherwise.
		"""
		api_names = (core.BNQualifiedName * len(types))()
		api_types = (ctypes.POINTER(core.BNType) * len(types))()
		for (i, (key, value)) in enumerate(types.items()):
			api_names[i] = _types.QualifiedName(key)._to_core_struct()
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
			name = _types.QualifiedName._from_core_struct(result_names[i])
			id = core.pyNativeStr(result_ids[i])
			result[name] = id

		core.BNFreeTypeNameList(result_names, result_count.value)
		core.BNFreeStringList(result_ids, result_count.value)
		return result

	def rename_type(self, type_id: str, new_name: '_types.QualifiedNameType') -> bool:
		"""
		Rename a type in the Type Container. All references to this type will be updated
		(by id) to use the new name.
		:param type_id: Id of type to update
		:param new_name: New name for the type
		:return: True if successful
		"""
		return core.BNTypeContainerRenameType(self.handle, type_id, _types.QualifiedName(new_name)._to_core_struct())

	def delete_type(self, type_id: str) -> bool:
		"""
		Delete a type in the Type Container. Behavior of references to this type is
		not specified and you may end up with broken references if any still exist.
		:param type_id: Id of type to delete
		:return: True if successful
		"""
		return core.BNTypeContainerDeleteType(self.handle, type_id)

	def get_type_id(self, type_name: '_types.QualifiedNameType') -> Optional[str]:
		"""
		Get the unique id of the type in the Type Container with the given name.
		If no type with that name exists, returns None.
		:param type_name: Name of type
		:return: Type id, if exists, else, None
		"""
		result = ctypes.c_char_p()
		if not core.BNTypeContainerGetTypeId(self.handle, _types.QualifiedName(type_name)._to_core_struct(), result):
			return None
		return core.pyNativeStr(result.value)

	def get_type_name(self, type_id: str) -> Optional['_types.QualifiedName']:
		"""
		Get the unique name of the type in the Type Container with the given id.
		If no type with that id exists, returns None.
		:param type_id: Id of type
		:return: Type name, if exists, else, None
		"""
		api_result = core.BNQualifiedName()
		if not core.BNTypeContainerGetTypeName(self.handle, type_id, api_result):
			return None
		result = _types.QualifiedName._from_core_struct(api_result)
		core.BNFreeQualifiedName(api_result)
		return result

	def get_type_by_id(self, type_id: str) -> Optional['_types.Type']:
		"""
		Get the definition of the type in the Type Container with the given id.
		If no type with that id exists, returns None.
		:param type_id: Id of type
		:return: Type object, if exists, else, None
		"""
		result = ctypes.POINTER(core.BNType)()
		if not core.BNTypeContainerGetTypeById(self.handle, type_id, result):
			return None
		return _types.Type.create(handle=result)

	@property
	def types(self) -> Optional[Mapping[str, Tuple['_types.QualifiedName', '_types.Type']]]:
		"""
		Get a mapping of all types in a Type Container.
		:return: All types in a dict of type id -> (type name, type definition)
		"""
		result_names = ctypes.POINTER(core.BNQualifiedName)()
		result_ids = ctypes.POINTER(ctypes.c_char_p)()
		result_types = ctypes.POINTER(ctypes.POINTER(core.BNType))()
		result_count = ctypes.c_size_t(0)

		if not core.BNTypeContainerGetTypes(self.handle, result_ids, result_names, result_types, result_count):
			return None

		result = {}
		for i in range(result_count.value):
			name = _types.QualifiedName._from_core_struct(result_names[i])
			id = core.pyNativeStr(result_ids[i])
			ref_handle = core.BNNewTypeReference(result_types[i])
			assert ref_handle is not None
			type = _types.Type.create(handle=ref_handle)
			result[id] = (name, type)

		core.BNFreeTypeNameList(result_names, result_count.value)
		core.BNFreeStringList(result_ids, result_count.value)
		core.BNFreeTypeList(result_types, result_count.value)
		return result

	def get_type_by_name(self, type_name: '_types.QualifiedNameType') -> Optional['_types.Type']:
		"""
		Get the definition of the type in the Type Container with the given name.
		If no type with that name exists, returns None.
		:param type_name: Name of type
		:return: Type object, if exists, else, None
		"""
		result = ctypes.POINTER(core.BNType)()
		if not core.BNTypeContainerGetTypeByName(self.handle, _types.QualifiedName(type_name)._to_core_struct(), result):
			return None
		return _types.Type.create(handle=result)

	@property
	def type_ids(self) -> Optional[List[str]]:
		"""
		Get all type ids in a Type Container.
		:return: List of all type ids
		"""
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
	def type_names(self) -> Optional[List['_types.QualifiedName']]:
		"""
		Get all type names in a Type Container.
		:return: List of all type names
		"""
		result_names = ctypes.POINTER(core.BNQualifiedName)()
		result_count = ctypes.c_size_t(0)
		if not core.BNTypeContainerGetTypeNames(self.handle, result_names, result_count):
			return None

		result = []
		for i in range(result_count.value):
			name = _types.QualifiedName._from_core_struct(result_names[i])
			result.append(name)

		core.BNFreeTypeNameList(result_names, result_count.value)
		return result

	@property
	def type_names_and_ids(self) -> Optional[Mapping[str, '_types.QualifiedName']]:
		"""
		Get a mapping of all type ids and type names in a Type Container.
		:return: Dict of type id -> type name
		"""
		result_names = ctypes.POINTER(core.BNQualifiedName)()
		result_ids = ctypes.POINTER(ctypes.c_char_p)()
		result_count = ctypes.c_size_t(0)
		if not core.BNTypeContainerGetTypeNamesAndIds(self.handle, result_ids, result_names, result_count):
			return None

		result = {}
		for i in range(result_count.value):
			name = _types.QualifiedName._from_core_struct(result_names[i])
			id = core.pyNativeStr(result_ids[i])
			result[id] = name

		core.BNFreeTypeNameList(result_names, result_count.value)
		core.BNFreeStringList(result_ids, result_count.value)
		return result

	def parse_types_from_source(self, source: str, file_name: str,
			options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None,
			auto_type_source: str = ""
	) -> Tuple[Optional['typeparser.TypeParserResult'], List['typeparser.TypeParserError']]:
		"""
		Parse an entire block of source into types, variables, and functions, with
		knowledge of the types in the Type Container.

		:param source: Source code to parse
		:param file_name: Name of the file containing the source (optional: exists on disk)
		:param options: Optional string arguments to pass as options, e.g. command line arguments
		:param include_dirs: Optional list of directories to include in the header search path
		:param auto_type_source: Optional source of types if used for automatically generated types
		:return: A tuple of (result, errors) where the result is None if there was a fatal error
		"""
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
			self.handle, source, file_name,
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


