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

import ctypes
from typing import Any, Optional, List, Dict, Union
import uuid

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import types
from . import metadata
from . import platform
from . import architecture
from . import typecontainer


class ImportLibrary:
	def __init__(self, handle: core.BNImportLibraryHandle):
		binaryninja._init_plugins()
		self.handle: core.BNImportLibraryHandle = core.handle_of_type(handle, core.BNImportLibrary)

	def __del__(self):
		if core is not None:
			core.BNFreeImportLibrary(self.handle)

	def __repr__(self):
		return f"<importlib '{self.name}':{self.arch.name}>"

	@staticmethod
	def new(arch: 'architecture.Architecture', name:str) -> 'ImportLibrary':
		"""
		Creates an empty import library object with a random GUID and
		the provided name.

		:param Architecture arch:
		:param str name:
		:rtype: ImportLibrary
		"""
		return ImportLibrary(core.BNNewImportLibrary(arch.handle, name))

	@staticmethod
	def load_from_file(path: str) -> Optional['ImportLibrary']:
		"""
		Loads a finalized import library instance from file

		:param str path:
		:rtype: ImportLibrary
		"""
		binaryninja._init_plugins()
		handle: Optional[core.BNImportLibraryHandle] = core.BNLoadImportLibraryFromFile(path)
		if handle is None:
			return None
		return ImportLibrary(handle)

	def write_to_file(self, path: str) -> None:
		"""
		Saves a finalized import library instance to file

		:param str path:
		:rtype: None
		:raises: OSError if saving the file fails
		"""
		if not core.BNWriteImportLibraryToFile(self.handle, path):
			raise OSError(f"Failed to write import library to '{path}'")

	def decompress_to_file(self, path: str) -> None:
		"""
		Decompresses the import library file to a file on disk.

		:param str path:
		:rtype: bool
		:raises: OSError if saving the file fails
		"""
		if not core.BNImportLibraryDecompressToFile(self.handle, path):
			raise OSError(f"Failed to decompress import library to '{path}'")

	@staticmethod
	def from_name(arch: architecture.Architecture, name: str):
		"""
		`from_name` looks up the first import library found with a matching name. Keep
		in mind that names are not necessarily unique.

		:param Architecture arch:
		:param str name:
		:rtype: ImportLibrary
		"""
		handle: Optional[core.BNImportLibraryHandle] = core.BNLookupImportLibraryByName(arch.handle, name)
		if handle is None:
			return None
		return ImportLibrary(handle)

	@staticmethod
	def from_guid(arch: architecture.Architecture, guid: str):
		"""
		`from_guid` attempts to grab an import library associated with the provided
		Architecture and GUID pair

		:param Architecture arch:
		:param str guid:
		:rtype: ImportLibrary
		"""
		handle: Optional[core.BNImportLibraryHandle] = core.BNLookupImportLibraryByGuid(arch.handle, guid)
		if handle is None:
			return None
		return ImportLibrary(handle)

	@property
	def arch(self) -> 'architecture.Architecture':
		"""The Architecture this import library is associated with"""
		arch: Optional[core.BNArchitectureHandle] = core.BNGetImportLibraryArchitecture(self.handle)
		assert arch is not None, "core.BNGetImportLibraryArchitecture returned None"
		return architecture.CoreArchitecture._from_cache(handle=arch)

	@property
	def name(self) -> Optional[str]:
		"""The primary name associated with this import library"""
		return core.BNGetImportLibraryName(self.handle)

	@name.setter
	def name(self, value:str):
		"""Sets the name of an import library instance that has not been finalized"""
		core.BNSetImportLibraryName(self.handle, value)

	def duplicate(self) -> 'ImportLibrary':
		"""
		Creates a new import library instance with a random GUID and the same data as the current instance.

		:rtype: ImportLibrary
		"""
		return ImportLibrary(core.BNDuplicateImportLibrary(self.handle))

	@property
	def dependency_name(self) -> Optional[str]:
		"""
		The `dependency_name` of a library is the name used to record dependencies across
		import libraries. This allows, for example, a library with the name "musl_libc" to have
		dependencies on it recorded as "libc_generic", allowing an import library to be used across
		multiple platforms where each has a specific libc that also provides the name "libc_generic"
		as an `alternate_name`.
		"""
		return core.BNGetImportLibraryDependencyName(self.handle)

	@dependency_name.setter
	def dependency_name(self, value: str) -> None:
		"""Sets the dependency name of an import library instance that has not been finalized"""
		core.BNSetImportLibraryDependencyName(self.handle, value)

	@property
	def guid(self) -> Optional[str]:
		"""Returns the GUID associated with the import library"""
		return core.BNGetImportLibraryGuid(self.handle)

	@guid.setter
	def guid(self, value: str) -> None:
		"""Sets the GUID of an import library instance that has not been finalized"""
		core.BNSetImportLibraryGuid(self.handle, value)

	@property
	def alternate_names(self) -> List[str]:
		"""
		A list of extra names that will be considered a match by ``Platform.get_import_libraries_by_name``
		"""
		count = ctypes.c_ulonglong(0)
		result:List[str] = []
		names = core.BNGetImportLibraryAlternateNames(self.handle, count)
		assert names is not None, "core.BNGetImportLibraryAlternateNames returned None"
		try:
			for i in range(count.value):
				result.append(names[i].decode("utf-8"))
			return result
		finally:
			core.BNFreeStringList(names, count.value)

	def add_alternate_name(self, name: str) -> None:
		"""Adds an extra name to this import library used during library lookups and dependency resolution"""
		if not isinstance(name, str):
			raise ValueError(f"Expected name to be str, got {type(name)}")
		core.BNAddImportLibraryAlternateName(self.handle, name)

	def remove_alternate_name(self, name: str) -> None:
		"""Removes an extra name from this import library instance that has not been finalized"""
		if not isinstance(name, str):
			raise ValueError(f"Expected name to be str, got {type(name)}")
		core.BNRemoveImportLibraryAlternateName(self.handle, name)

	@property
	def platform_names(self) -> List[str]:
		"""
		Returns a list of all platform names that this import library will register with during platform
		type registration.

		This returns strings, not Platform objects, as import libraries can be distributed with support for
		Platforms that may not be present.
		"""
		count = ctypes.c_ulonglong(0)
		result = []
		platforms = core.BNGetImportLibraryPlatforms(self.handle, count)
		assert platforms is not None, "core.BNGetImportLibraryPlatforms returned None"
		try:
			for i in range(0, count.value):
				result.append(platforms[i].decode("utf-8"))
			return result
		finally:
			core.BNFreeStringList(platforms, count.value)

	def add_platform(self, plat: platform.Platform) -> None:
		"""
		Associate a platform with an import library instance that has not been finalized.

		This will cause the library to be searchable by ``Platform.get_import_libraries_by_name``
		when loaded.

		This does not have side affects until finalization of the import library.
		"""
		if not isinstance(plat, platform.Platform):
			raise ValueError("plat must be a Platform object")
		core.BNAddImportLibraryPlatform(self.handle, plat.handle)

	def clear_platforms(self) -> None:
		"""Clears the list of platforms associated with an import library instance that has not been finalized"""
		core.BNClearImportLibraryPlatforms(self.handle)

	def finalize(self) -> bool:
		"""
		Flags a newly created import library instance as finalized and makes it available for Platform and Architecture
		import library searches

		:rtype: True if the import library was successfully finalized, False otherwise
		"""
		return core.BNFinalizeImportLibrary(self.handle)

	def register(self) -> None:
		"""
		Make a created or loaded Import Library available for Platforms to use when loading binaries.
		"""
		core.BNRegisterImportLibrary(self.handle)

	def query_metadata(self, key: str) -> 'metadata.MetadataValueType':
		"""
		`query_metadata` retrieves a metadata associated with the given key stored in the import library

		.. note:: As of Binary Ninja 5.3 this API now raises KeyError on failure. \
			Please use `get_metadata` for a non-raising version of the API.

		:param string key: key to query
		:rtype: metadata associated with the key
		:Example:

			>>> lib.store_metadata("ordinals", {"9": "htons"})
			>>> lib.query_metadata("ordinals")["9"]
			"htons"
		"""
		md_handle = core.BNImportLibraryQueryMetadata(self.handle, key)
		if md_handle is None:
			raise KeyError(key)
		return metadata.Metadata(handle=md_handle).value

	def get_metadata(self, key: str, default: Any = None) -> 'metadata.MetadataValueType | Any':
		"""
		`get_metadata` retrieves a metadata value associated with the given key stored in the current BinaryView.

		This method behaves like `dict.get()`:

		- If the key exists, its metadata value is returned.
		- If the key does not exist and `default` is not provided, `None` is returned.
		- If the key does not exist and `default` is provided, `default` is returned.

		:param str key: key to query
		:param default: value to return if the key does not exist (defaults to None)
		:rtype: metadata associated with the key or the default value
		:Example:

			>>> tl.store_metadata("integer", 1337)
			>>> tl.get_metadata("integer")
			1337L
			>>> tl.get_metadata("missing")
			None
			>>> tl.get_metadata("missing", 42)
			42
		"""
		md_handle = core.BNImportLibraryQueryMetadata(self.handle, key)
		if md_handle is None:
			return default
		return metadata.Metadata(handle=md_handle).value

	def store_metadata(self, key: str, md: metadata.Metadata) -> None:
		"""
		`store_metadata` stores an object for the given key in the current import library. Objects stored using
		`store_metadata` can be retrieved from any reference to the library. Objects stored are not arbitrary python
		objects! The values stored must be able to be held in a Metadata object. See :py:class:`Metadata`
		for more information. Python objects could obviously be serialized using pickle but this intentionally
		a task left to the user since there is the potential security issues.

		This is primarily intended as a way to store Platform specific information relevant to BinaryView implementations;
		for example the PE BinaryViewType uses import library metadata to retrieve ordinal information, when available.

		:param string key: key value to associate the Metadata object with
		:param Varies md: object to store.
		:rtype: None
		:Example:

			>>> lib.store_metadata("ordinals", {"9": "htons"})
			>>> lib.query_metadata("ordinals")["9"]
			"htons"
		"""
		if not isinstance(md, metadata.Metadata):
			md = metadata.Metadata(md)
		core.BNImportLibraryStoreMetadata(self.handle, key, md.handle)

	def remove_metadata(self, key: str) -> None:
		"""
		`remove_metadata` removes the metadata associated with key from the current import library.

		:param string key: key associated with metadata
		:rtype: None
		:Example:

			>>> lib.store_metadata("integer", 1337)
			>>> lib.remove_metadata("integer")
		"""
		core.BNImportLibraryRemoveMetadata(self.handle, key)

	@property
	def metadata(self) -> Dict[str, 'metadata.MetadataValueType']:
		"""
		`metadata` retrieves the metadata associated with the current import library.

		:rtype: Metadata object
		:Example:

			>>> lib.store_metadata("integer", 1337)
			>>> lib.metadata["integer"]
			1337
		"""
		md_handle = core.BNImportLibraryGetMetadata(self.handle)
		assert md_handle is not None, "core.BNImportLibraryGetMetadata returned None"
		value = metadata.Metadata(handle=md_handle).value
		assert isinstance(value, dict), "core.BNImportLibraryGetMetadata returned non-dict"
		return value

	@property
	def type_container(self) -> 'typecontainer.TypeContainer':
		"""
		Type Container for all TYPES within the Import Library. Objects are not included.
		The Type Container's Platform will be the first platform associated with the Import Library.
		:return: Import Library Type Container
		"""
		return typecontainer.TypeContainer(core.BNGetImportLibraryTypeContainer(self.handle))

	def add_named_object(self, name: Union[types.QualifiedName, str], type: 'types.Type') -> None:
		"""
		`add_named_object` directly inserts a named object into the import library's object store.
		This is not done recursively, so care should be taken that types referring to other types
		through NamedTypeReferences are already appropriately prepared.

		To add types and objects from an existing BinaryView, it is recommended to use
		:py:meth:`export_object_to_library <binaryview.BinaryView.export_object_to_library>`, which will automatically pull in
		all referenced types and record additional dependencies as needed.

		:param QualifiedName name:
		:param Type t:
		:rtype: None
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		type = type.immutable_copy()
		if not isinstance(type, types.Type):
			raise ValueError("type must be a Type")
		core.BNAddImportLibraryNamedObject(self.handle, name._to_core_struct(), type.handle)

	def remove_named_object(self, name: Union[types.QualifiedName, str]) -> None:
		"""
		`remove_named_object` removes a named object from the import library's object store.
		This does not remove any types that are referenced by the object, only the object itself.
		
		:param QualifiedName name:
		:rtype: None
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		core.BNRemoveImportLibraryNamedObject(self.handle, name._to_core_struct())

	def add_named_type(self, name: 'types.QualifiedNameType', type: 'types.Type') -> None:
		"""
		`add_named_type` directly inserts a named object into the import library's object store.
		This is not done recursively, so care should be taken that types referring to other types
		through NamedTypeReferences are already appropriately prepared.

		To add types and objects from an existing BinaryView, it is recommended to use
		:py:meth:`export_type_to_library <binaryview.BinaryView.export_type_to_library>`, which will automatically pull in
		all referenced types and record additional dependencies as needed.

		:param QualifiedName name:
		:param Type t:
		:rtype: None
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		type = type.immutable_copy()
		if not isinstance(type, types.Type):
			raise ValueError("parameter type must be a Type")
		core.BNAddImportLibraryNamedType(self.handle, name._to_core_struct(), type.handle)

	def remove_named_type(self, name: Union[types.QualifiedName, str]) -> None:
		"""
		`remove_named_type` removes a named type from the import library's type store.
		This does not remove any objects that reference the type, only the type itself.
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		core.BNRemoveImportLibraryNamedType(self.handle, name._to_core_struct())

	def add_type_source(self, name: Union[types.QualifiedName, str], source: str) -> None:
		"""
		Manually flag NamedTypeReferences to the given QualifiedName as originating from another source
		ImportLibrary with the given dependency name.

		.. warning:: Use this api with extreme caution.
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		core.BNAddImportLibraryNamedTypeSource(self.handle, types.QualifiedName(name)._to_core_struct(), source)

	def get_named_object(self, name: Union[types.QualifiedName, str]) -> Optional[types.Type]:
		"""
		`get_named_object` direct extracts a reference to a contained object -- when
		attempting to extract types from a library into a BinaryView, consider using
		:py:meth:`import_object_from_library <binaryview.BinaryView.import_object_from_library>` instead.

		:param QualifiedName name:
		:rtype: Type
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		t = core.BNGetImportLibraryNamedObject(self.handle, name._to_core_struct())
		if t is None:
			return None
		return types.Type.create(t)

	def get_named_type(self, name: Union[str, types.QualifiedName]) -> Optional[types.Type]:
		"""
		`get_named_type` direct extracts a reference to a contained type -- when
		attempting to extract types from a library into a BinaryView, consider using
		:py:meth:`import_type_from_library <binaryview.BinaryView.import_type_from_library>` instead.

		:param QualifiedName name:
		:rtype: Type
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		t = core.BNGetImportLibraryNamedType(self.handle, name._to_core_struct())
		if t is None:
			return None
		return types.Type.create(t)

	@property
	def named_objects(self) -> Dict[types.QualifiedName, types.Type]:
		"""
		A dict containing all named objects (functions, exported variables) provided by an import library (read-only)
		"""
		count = ctypes.c_ulonglong(0)
		result = {}
		named_types = core.BNGetImportLibraryNamedObjects(self.handle, count)
		assert named_types is not None, "core.BNGetImportLibraryNamedObjects returned None"
		try:
			for i in range(0, count.value):
				name = types.QualifiedName._from_core_struct(named_types[i].name)
				result[name] = types.Type.create(core.BNNewTypeReference(named_types[i].type))
			return result
		finally:
			core.BNFreeQualifiedNameAndTypeArray(named_types, count.value)

	@property
	def named_types(self) -> Dict[types.QualifiedName, types.Type]:
		"""
		A dict containing all named types provided by an import library (read-only)
		"""
		count = ctypes.c_ulonglong(0)
		result = {}
		named_types = core.BNGetImportLibraryNamedTypes(self.handle, count)
		assert named_types is not None, "core.BNGetImportLibraryNamedTypes returned None"
		try:
			for i in range(0, count.value):
				name = types.QualifiedName._from_core_struct(named_types[i].name)
				result[name] = types.Type.create(core.BNNewTypeReference(named_types[i].type))
			return result
		finally:
			core.BNFreeQualifiedNameAndTypeArray(named_types, count.value)
