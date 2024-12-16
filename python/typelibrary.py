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
from typing import Optional, List, Dict, Union
import uuid

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import types
from . import metadata
from . import platform
from . import architecture
from . import typecontainer


class TypeLibrary:
	def __init__(self, handle: core.BNTypeLibraryHandle):
		binaryninja._init_plugins()
		self.handle: core.BNTypeLibraryHandle = core.handle_of_type(handle, core.BNTypeLibrary)

	def __del__(self):
		if core is not None:
			core.BNFreeTypeLibrary(self.handle)

	def __repr__(self):
		return f"<typelib '{self.name}':{self.arch.name}>"

	@staticmethod
	def new(arch: 'architecture.Architecture', name:str) -> 'TypeLibrary':
		"""
		Creates an empty type library object with a random GUID and
		the provided name.

		:param Architecture arch:
		:param str name:
		:rtype: TypeLibrary
		"""
		return TypeLibrary(core.BNNewTypeLibrary(arch.handle, name))

	@staticmethod
	def decompress_to_file(path: str, output: str) -> bool:
		"""
		Decompresses a type library file to a file on disk.

		:param str path:
		:param str output:
		:rtype: bool
		"""
		return core.BNTypeLibraryDecompressToFile(path, output)

	@staticmethod
	def load_from_file(path: str) -> Optional['TypeLibrary']:
		"""
		Loads a finalized type library instance from file

		:param str path:
		:rtype: TypeLibrary
		"""
		binaryninja._init_plugins()
		handle: Optional[core.BNTypeLibraryHandle] = core.BNLoadTypeLibraryFromFile(path)
		if handle is None:
			return None
		return TypeLibrary(handle)

	def write_to_file(self, path: str) -> None:
		"""
		Saves a finalized type library instance to file

		:param str path:
		:rtype: None
		:raises: OSError if saving the file fails
		"""
		if not core.BNWriteTypeLibraryToFile(self.handle, path):
			raise OSError(f"Failed to write type library to '{path}'")

	@staticmethod
	def from_name(arch: architecture.Architecture, name: str):
		"""
		`from_name` looks up the first type library found with a matching name. Keep
		in mind that names are not necessarily unique.

		:param Architecture arch:
		:param str name:
		:rtype: TypeLibrary
		"""
		handle: Optional[core.BNTypeLibraryHandle] = core.BNLookupTypeLibraryByName(arch.handle, name)
		if handle is None:
			return None
		return TypeLibrary(handle)

	@staticmethod
	def from_guid(arch: architecture.Architecture, guid: str):
		"""
		`from_guid` attempts to grab a type library associated with the provided
		Architecture and GUID pair

		:param Architecture arch:
		:param str guid:
		:rtype: TypeLibrary
		"""
		handle: Optional[core.BNTypeLibraryHandle] = core.BNLookupTypeLibraryByGuid(arch.handle, guid)
		if handle is None:
			return None
		return TypeLibrary(handle)

	@property
	def arch(self) -> 'architecture.Architecture':
		"""The Architecture this type library is associated with"""
		arch: Optional[core.BNArchitectureHandle] = core.BNGetTypeLibraryArchitecture(self.handle)
		assert arch is not None, "core.BNGetTypeLibraryArchitecture returned None"
		return architecture.CoreArchitecture._from_cache(handle=arch)

	@property
	def name(self) -> Optional[str]:
		"""The primary name associated with this type library"""
		return core.BNGetTypeLibraryName(self.handle)

	@name.setter
	def name(self, value:str):
		"""Sets the name of a type library instance that has not been finalized"""
		core.BNSetTypeLibraryName(self.handle, value)

	@property
	def dependency_name(self) -> Optional[str]:
		"""
		The `dependency_name` of a library is the name used to record dependencies across
		type libraries. This allows, for example, a library with the name "musl_libc" to have
		dependencies on it recorded as "libc_generic", allowing a type library to be used across
		multiple platforms where each has a specific libc that also provides the name "libc_generic"
		as an `alternate_name`.
		"""
		return core.BNGetTypeLibraryDependencyName(self.handle)

	@dependency_name.setter
	def dependency_name(self, value: str) -> None:
		"""Sets the dependency name of a type library instance that has not been finalized"""
		core.BNSetTypeLibraryDependencyName(self.handle, value)

	@property
	def guid(self) -> Optional[str]:
		"""Returns the GUID associated with the type library"""
		return core.BNGetTypeLibraryGuid(self.handle)

	@guid.setter
	def guid(self, value: str) -> None:
		"""Sets the GUID of a type library instance that has not been finalized"""
		core.BNSetTypeLibraryGuid(self.handle, value)

	@property
	def alternate_names(self) -> List[str]:
		"""
		A list of extra names that will be considered a match by ``Platform.get_type_libraries_by_name``
		"""
		count = ctypes.c_ulonglong(0)
		result:List[str] = []
		names = core.BNGetTypeLibraryAlternateNames(self.handle, count)
		assert names is not None, "core.BNGetTypeLibraryAlternateNames returned None"
		try:
			for i in range(count.value):
				result.append(names[i].decode("utf-8"))
			return result
		finally:
			core.BNFreeStringList(names, count.value)

	def add_alternate_name(self, name: str) -> None:
		"""Adds an extra name to this type library used during library lookups and dependency resolution"""
		if not isinstance(name, str):
			raise ValueError(f"Expected name to be str, got {type(name)}")
		core.BNAddTypeLibraryAlternateName(self.handle, name)

	@property
	def platform_names(self) -> List[str]:
		"""
		Returns a list of all platform names that this type library will register with during platform
		type registration.

		This returns strings, not Platform objects, as type libraries can be distributed with support for
		Platforms that may not be present.
		"""
		count = ctypes.c_ulonglong(0)
		result = []
		platforms = core.BNGetTypeLibraryPlatforms(self.handle, count)
		assert platforms is not None, "core.BNGetTypeLibraryPlatforms returned None"
		try:
			for i in range(0, count.value):
				result.append(platforms[i].decode("utf-8"))
			return result
		finally:
			core.BNFreeStringList(platforms, count.value)

	def add_platform(self, plat: platform.Platform) -> None:
		"""
		Associate a platform with a type library instance that has not been finalized.

		This will cause the library to be searchable by ``Platform.get_type_libraries_by_name``
		when loaded.

		This does not have side affects until finalization of the type library.
		"""
		if not isinstance(plat, platform.Platform):
			raise ValueError("plat must be a Platform object")
		core.BNAddTypeLibraryPlatform(self.handle, plat.handle)

	def clear_platforms(self) -> None:
		"""Clears the list of platforms associated with a type library instance that has not been finalized"""
		core.BNClearTypeLibraryPlatforms(self.handle)

	def finalize(self) -> bool:
		"""
		Flags a newly created type library instance as finalized and makes it available for Platform and Architecture
		type library searches

		:rtype: True if the type library was successfully finalized, False otherwise
		"""
		return core.BNFinalizeTypeLibrary(self.handle)

	def query_metadata(self, key: str) -> Optional['metadata.MetadataValueType']:
		"""
		`query_metadata` retrieves a metadata associated with the given key stored in the type library

		:param string key: key to query
		:rtype: metadata associated with the key
		:Example:

			>>> lib.store_metadata("ordinals", {"9": "htons"})
			>>> lib.query_metadata("ordinals")["9"]
			"htons"
		"""
		md_handle = core.BNTypeLibraryQueryMetadata(self.handle, key)
		if md_handle is None:
			return None
		return metadata.Metadata(handle=md_handle).value

	def store_metadata(self, key: str, md: metadata.Metadata) -> None:
		"""
		`store_metadata` stores an object for the given key in the current type library. Objects stored using
		`store_metadata` can be retrieved from any reference to the library. Objects stored are not arbitrary python
		objects! The values stored must be able to be held in a Metadata object. See :py:class:`Metadata`
		for more information. Python objects could obviously be serialized using pickle but this intentionally
		a task left to the user since there is the potential security issues.

		This is primarily intended as a way to store Platform specific information relevant to BinaryView implementations;
		for example the PE BinaryViewType uses type library metadata to retrieve ordinal information, when available.

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
		core.BNTypeLibraryStoreMetadata(self.handle, key, md.handle)

	def remove_metadata(self, key: str) -> None:
		"""
		`remove_metadata` removes the metadata associated with key from the current type library.

		:param string key: key associated with metadata
		:rtype: None
		:Example:

			>>> lib.store_metadata("integer", 1337)
			>>> lib.remove_metadata("integer")
		"""
		core.BNTypeLibraryRemoveMetadata(self.handle, key)

	@property
	def metadata(self) -> Dict[str, 'metadata.MetadataValueType']:
		"""
		`metadata` retrieves the metadata associated with the current type library.

		:rtype: Metadata object
		:Example:

			>>> lib.store_metadata("integer", 1337)
			>>> lib.metadata["integer"]
			1337
		"""
		md_handle = core.BNTypeLibraryGetMetadata(self.handle)
		assert md_handle is not None, "core.BNTypeLibraryGetMetadata returned None"
		value = metadata.Metadata(handle=md_handle).value
		assert isinstance(value, dict), "core.BNTypeLibraryGetMetadata returned non-dict"
		return value

	@property
	def type_container(self) -> 'typecontainer.TypeContainer':
		"""
		Type Container for all TYPES within the Type Library. Objects are not included.
		The Type Container's Platform will be the first platform associated with the Type Library.
		:return: Type Library Type Container
		"""
		return typecontainer.TypeContainer(core.BNGetTypeLibraryTypeContainer(self.handle))

	def add_named_object(self, name: 'types.QualifiedName', type: 'types.Type') -> None:
		"""
		`add_named_object` directly inserts a named object into the type library's object store.
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
		core.BNAddTypeLibraryNamedObject(self.handle, name._to_core_struct(), type.handle)

	def add_named_type(self, name: 'types.QualifiedNameType', type: 'types.Type') -> None:
		"""
		`add_named_type` directly inserts a named object into the type library's object store.
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
		core.BNAddTypeLibraryNamedType(self.handle, name._to_core_struct(), type.handle)

	def add_type_source(self, name: types.QualifiedName, source: str) -> None:
		"""
		Manually flag NamedTypeReferences to the given QualifiedName as originating from another source
		TypeLibrary with the given dependency name.

		.. warning:: Use this api with extreme caution.
		"""
		core.BNAddTypeLibraryNamedTypeSource(self.handle, types.QualifiedName(name)._to_core_struct(), source)

	def get_named_object(self, name: Union[types.QualifiedName, str]) -> Optional[types.Type]:
		"""
		`get_named_object` direct extracts a reference to a contained object -- when
		attempting to extract types from a library into a BinaryView, consider using
		:py:meth:`import_library_object <binaryview.BinaryView.import_library_object>` instead.

		:param QualifiedName name:
		:rtype: Type
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		t = core.BNGetTypeLibraryNamedObject(self.handle, name._to_core_struct())
		if t is None:
			return None
		return types.Type.create(t)

	def get_named_type(self, name: Union[str, types.QualifiedName]) -> Optional[types.Type]:
		"""
		`get_named_type` direct extracts a reference to a contained type -- when
		attempting to extract types from a library into a BinaryView, consider using
		:py:meth:`import_library_type <binaryview.BinaryView.import_library_type>` instead.

		:param QualifiedName name:
		:rtype: Type
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		t = core.BNGetTypeLibraryNamedType(self.handle, name._to_core_struct())
		if t is None:
			return None
		return types.Type.create(t)

	@property
	def named_objects(self) -> Dict[types.QualifiedName, types.Type]:
		"""
		A dict containing all named objects (functions, exported variables) provided by a type library (read-only)
		"""
		count = ctypes.c_ulonglong(0)
		result = {}
		named_types = core.BNGetTypeLibraryNamedObjects(self.handle, count)
		assert named_types is not None, "core.BNGetTypeLibraryNamedObjects returned None"
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
		A dict containing all named types provided by a type library (read-only)
		"""
		count = ctypes.c_ulonglong(0)
		result = {}
		named_types = core.BNGetTypeLibraryNamedTypes(self.handle, count)
		assert named_types is not None, "core.BNGetTypeLibraryNamedTypes returned None"
		try:
			for i in range(0, count.value):
				name = types.QualifiedName._from_core_struct(named_types[i].name)
				result[name] = types.Type.create(core.BNNewTypeReference(named_types[i].type))
			return result
		finally:
			core.BNFreeQualifiedNameAndTypeArray(named_types, count.value)
