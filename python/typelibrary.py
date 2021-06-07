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
from typing import Optional

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import types
from . import metadata
from . import platform
from . import architecture


class TypeLibrary(object):
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNTypeLibrary)

	def __del__(self):
		core.BNFreeTypeLibrary(self.handle)

	def __repr__(self):
		return "<typelib '{}':{}>".format(self.name, self.arch.name)

	@staticmethod
	def new(arch, name):
		"""
		Creates an empty type library object with a random GUID and
		the provided name.

		:param Architecture arch:
		:param str name:
		:rtype: TypeLibrary
		"""
		handle = core.BNNewTypeLibrary(arch.handle, name)
		return TypeLibrary(handle)

	@staticmethod
	def load_from_file(path):
		"""
		Loads a finalized type library instance from file

		:param str path:
		:rtype: TypeLibrary
		"""
		handle = core.BNLoadTypeLibraryFromFile(path)
		if handle is None:
			return None
		return TypeLibrary(handle)

	def write_to_file(self, path):
		"""
		Saves a finalized type library instance to file

		:param str path:
		:rtype: None
		"""
		core.BNWriteTypeLibraryToFile(self.handle, path)

	@staticmethod
	def from_name(arch, name):
		"""
		`from_name` looks up the first type library found with a matching name. Keep
		in mind that names are not necessarily unique.

		:param Architecture arch:
		:param str name:
		:rtype: TypeLibrary
		"""
		handle = core.BNLookupTypeLibraryByName(arch.handle, name)
		if handle is None:
			return None
		return TypeLibrary(handle)

	@staticmethod
	def from_guid(arch, guid):
		"""
		`from_guid` attempts to grab a type library associated with the provided
		Architecture and GUID pair

		:param Architecture arch:
		:param str guid:
		:rtype: TypeLibrary
		"""
		handle = core.BNLookupTypeLibraryByGuid(arch.handle, guid)
		if handle is None:
			return None
		return TypeLibrary(handle)

	@property
	def arch(self) -> 'architecture.Architecture':
		"""The Architecture this type library is associated with"""
		arch = core.BNGetTypeLibraryArchitecture(self.handle)
		assert arch is not None, "core.BNGetTypeLibraryArchitecture returned None"
		return architecture.CoreArchitecture._from_cache(handle=arch)

	@property
	def name(self):
		"""The primary name associated with this type library"""
		name = core.BNGetTypeLibraryName(self.handle)
		return name

	@name.setter
	def name(self, value):
		"""Sets the name of a type library instance that has not been finalized"""
		core.BNSetTypeLibraryName(self.handle, value)

	@property
	def dependency_name(self):
		"""
		The `dependency_name` of a library is the name used to record dependencies across
		type libraries. This allows, for example, a library with the name "musl_libc" to have
		dependencies on it recorded as "libc_generic", allowing a type library to be used across
		multiple platforms where each has a specific libc that also provides the name "libc_generic"
		as an `alternate_name`.
		"""
		return core.BNGetTypeLibraryDependencyName(self.handle)

	@dependency_name.setter
	def dependency_name(self, value):
		"""Sets the dependency name of a type library instance that has not been finalized"""
		core.BNSetTypeLibraryDependencyName(self.handle, value)

	@property
	def guid(self):
		"""Returns the GUID associated with the type library"""
		return core.BNGetTypeLibraryGuid(self.handle)

	@guid.setter
	def guid(self, value):
		"""Sets the GUID of a type library instance that has not been finalized"""
		core.BNSetTypeLibraryGuid(self.handle, value)

	@property
	def alternate_names(self):
		"""
		A list of extra names that will be considered a match by ``Platform.get_type_libraries_by_name``
		"""
		count = ctypes.c_ulonglong(0)
		result = []
		names = core.BNGetTypeLibraryAlternateNames(self.handle, count)
		assert names is not None, "core.BNGetTypeLibraryAlternateNames returned None"
		for i in range(0, count.value):
			result.append(names[i])
		core.BNFreeStringList(names, count.value)
		return result

	def add_alternate_name(self, name):
		"""Adds an extra name to this type library used during library lookups and dependency resolution"""
		core.BNAddTypeLibraryAlternateName(self.handle, name)

	@property
	def platform_names(self):
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
		for i in range(0, count.value):
			result.append(platforms[i])
		core.BNFreeStringList(platforms, count.value)
		return result

	def add_platform(self, plat):
		"""
		Associate a platform with a type library instance that has not been finalized.

		This will cause the library to be searchable by ``Platform.get_type_libraries_by_name``
		when loaded.

		This does not have side affects until finalization of the type library.
		"""
		if not isinstance(plat, platform.Platform):
			raise ValueError("plat must be a Platform object")
		core.BNAddTypeLibraryPlatform(self.handle, plat.handle)

	def clear_platforms(self):
		"""Clears the list of platforms associated with a type library instance that has not been finalized"""
		core.BNClearTypeLibraryPlatforms(self.handle)

	def finalize(self):
		"""
		Flags a newly created type library instance as finalized and makes it available for Platform and Architecture
		type library searches
		"""
		core.BNFinalizeTypeLibrary(self.handle)

	def query_metadata(self, key):
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

	def store_metadata(self, key, md):
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

	def remove_metadata(self, key):
		"""
		`remove_metadata` removes the metadata associated with key from the current type library.

		:param string key: key associated with metadata
		:rtype: None
		:Example:

			>>> lib.store_metadata("integer", 1337)
			>>> lib.remove_metadata("integer")
		"""
		core.BNTypeLibraryRemoveMetadata(self.handle, key)

	def add_named_object(self, name, t):
		"""
		`add_named_object` directly inserts a named object into the type library's object store.
		This is not done recursively, so care should be taken that types referring to other types
		through NamedTypeReferences are already appropriately prepared.

		To add types and objects from an existing BinaryView, it is recommended to use
		:py:meth:`export_object_to_library <binaryninja.binaryview.BinaryView.export_object_to_library>`, which will automatically pull in
		all referenced types and record additional dependencies as needed.

		:param QualifiedName name:
		:param Type t:
		:rtype: None
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		if not isinstance(t, types.Type):
			raise ValueError("t must be a Type")
		core.BNAddTypeLibraryNamedObject(self.handle, name._get_core_struct(), t.handle)

	def add_named_type(self, name, t):
		"""
		`add_named_type` directly inserts a named object into the type library's object store.
		This is not done recursively, so care should be taken that types referring to other types
		through NamedTypeReferences are already appropriately prepared.

		To add types and objects from an existing BinaryView, it is recommended to use
		:py:meth:`export_type_to_library <binaryninja.binaryview.BinaryView.export_type_to_library>`, which will automatically pull in
		all referenced types and record additional dependencies as needed.

		:param QualifiedName name:
		:param Type t:
		:rtype: None
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		if not isinstance(t, types.Type):
			raise ValueError("t must be a Type")
		core.BNAddTypeLibraryNamedType(self.handle, name._get_core_struct(), t.handle)

	def get_named_object(self, name):
		"""
		`get_named_object` direct extracts a reference to a contained object -- when
		attempting to extract types from a library into a BinaryView, consider using
		:py:meth:`import_library_object <binaryninja.binaryview.BinaryView.import_library_object>` instead.

		:param QualifiedName name:
		:rtype: Type
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		t = core.BNGetTypeLibraryNamedObject(self.handle, name._get_core_struct())
		if t is None:
			return None
		return types.Type(t)

	def get_named_type(self, name):
		"""
		`get_named_type` direct extracts a reference to a contained type -- when
		attempting to extract types from a library into a BinaryView, consider using
		:py:meth:`import_library_type <binaryninja.binaryview.BinaryView.import_library_type>` instead.

		:param QualifiedName name:
		:rtype: Type
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		t = core.BNGetTypeLibraryNamedType(self.handle, name._get_core_struct())
		if t is None:
			return None
		return types.Type(t)

	@property
	def named_objects(self):
		"""
		A dict containing all named objects (functions, exported variables) provided by a type library (read-only)
		"""
		count = ctypes.c_ulonglong(0)
		result = {}
		named_types = core.BNGetTypeLibraryNamedObjects(self.handle, count)
		assert named_types is not None, "core.BNGetTypeLibraryNamedObjects returned None"
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(named_types[i].name)
			result[name] = types.Type(core.BNNewTypeReference(named_types[i].type))
		core.BNFreeQualifiedNameAndTypeArray(named_types, count.value)
		return result

	@property
	def named_types(self):
		"""
		A dict containing all named types provided by a type library (read-only)
		"""
		count = ctypes.c_ulonglong(0)
		result = {}
		named_types = core.BNGetTypeLibraryNamedTypes(self.handle, count)
		assert named_types is not None, "core.BNGetTypeLibraryNamedTypes returned None"
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(named_types[i].name)
			result[name] = types.Type(core.BNNewTypeReference(named_types[i].type))
		core.BNFreeQualifiedNameAndTypeArray(named_types, count.value)
		return result

