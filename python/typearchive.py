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
import traceback
from typing import Optional, List, Dict, Union, Tuple

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import types as _types
from . import log
from . import metadata
from . import databuffer
from . import platform
from . import architecture
from . import binaryview


class TypeArchive:
	def __init__(self, handle: core.BNTypeArchiveHandle):
		binaryninja._init_plugins()
		self.handle: core.BNTypeArchiveHandle = core.handle_of_type(handle, core.BNTypeArchive)
		self._notifications = {}

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	def __del__(self):
		if core is not None:
			core.BNFreeTypeArchiveReference(self.handle)

	def __repr__(self):
		return f"<type archive '{self.path}'>"

	def __eq__(self, other):
		if not isinstance(other, TypeArchive):
			return False
		return self.id == other.id

	@staticmethod
	def open(path: str) -> Optional['TypeArchive']:
		"""
		Open the Type Archive at the given path, if it exists.
		:param path: Path to Type Archive file
		:return: Type Archive, or None if it could not be loaded.
		"""
		handle = core.BNOpenTypeArchive(path)
		if handle is None:
			return None
		return TypeArchive(handle=handle)

	@staticmethod
	def create(path: str, platform: 'platform.Platform') -> Optional['TypeArchive']:
		"""
		Create a Type Archive at the given path.
		:param path: Path to Type Archive file
		:param platform: Relevant platform for types in the archive
		:return: Type Archive, or None if it could not be created.
		"""
		handle = core.BNCreateTypeArchive(path, platform.handle)
		if handle is None:
			return None
		return TypeArchive(handle=handle)

	@staticmethod
	def lookup_by_id(id: str) -> Optional['TypeArchive']:
		"""
		Get a reference to the Type Archive with the known id, if one exists.
		:param id: Type Archive id
		:return: Type archive, or None if it could not be found.
		"""
		handle = core.BNLookupTypeArchiveById(id)
		if handle is None:
			return None
		return TypeArchive(handle=handle)

	@property
	def path(self) -> Optional[str]:
		"""
		Get the path to the Type Archive's file
		:return: File path
		"""
		return core.BNGetTypeArchivePath(self.handle)

	@property
	def id(self) -> Optional[str]:
		"""
		Get the guid for a Type Archive
		:return: Guid string
		"""
		return core.BNGetTypeArchiveId(self.handle)

	@property
	def platform(self) -> 'platform.Platform':
		"""
		Get the associated Platform for a Type Archive
		:return: Platform object
		"""
		handle = core.BNGetTypeArchivePlatform(self.handle)
		assert handle is not None
		return platform.Platform(handle=handle)

	@property
	def current_snapshot_id(self) -> str:
		"""
		Get the id of the current snapshot in the type archive
		:return: Snapshot id
		"""
		result = core.BNGetTypeArchiveCurrentSnapshotId(self.handle)
		if result is None:
			raise RuntimeError("BNGetTypeArchiveCurrentSnapshotId")
		return result

	@current_snapshot_id.setter
	def current_snapshot_id(self, value: str):
		"""
		Revert the type archive's current snapshot to the given snapshot
		:param value: Snapshot id
		"""
		core.BNSetTypeArchiveCurrentSnapshot(self.handle, value)

	@property
	def all_snapshot_ids(self) -> List[str]:
		"""
		Get a list of every snapshot's id
		:return: All ids (including the empty first snapshot)
		"""
		count = ctypes.c_ulonglong(0)
		ids = core.BNGetTypeArchiveAllSnapshotIds(self.handle, count)
		if ids is None:
			raise RuntimeError("BNGetTypeArchiveAllSnapshotIds")
		result = []
		try:
			for i in range(0, count.value):
				result.append(core.pyNativeStr(ids[i]))
			return result
		finally:
			core.BNFreeStringList(ids, count.value)

	def get_snapshot_parent_ids(self, snapshot: str) -> Optional[List[str]]:
		"""
		Get the ids of the parents to the given snapshot
		:param snapshot: Child snapshot id
		:return: Parent snapshot ids, or empty list if the snapshot is a root
		"""
		count = ctypes.c_size_t(0)
		ids = core.BNGetTypeArchiveSnapshotParentIds(self.handle, snapshot, count)
		if ids is None:
			raise RuntimeError("BNGetTypeArchiveSnapshotParentIds")
		result = []
		try:
			for i in range(0, count.value):
				result.append(core.pyNativeStr(ids[i]))
			return result
		finally:
			core.BNFreeStringList(ids, count.value)

	def get_snapshot_child_ids(self, snapshot: str) -> Optional[List[str]]:
		"""
		Get the ids of the children to the given snapshot
		:param snapshot: Parent snapshot id
		:return: Child snapshot ids, or empty list if the snapshot is a root
		"""
		count = ctypes.c_size_t(0)
		ids = core.BNGetTypeArchiveSnapshotChildIds(self.handle, snapshot, count)
		if ids is None:
			raise RuntimeError("BNGetTypeArchiveSnapshotChildIds")
		result = []
		try:
			for i in range(0, count.value):
				result.append(core.pyNativeStr(ids[i]))
			return result
		finally:
			core.BNFreeStringList(ids, count.value)

	def add_type(self, name: '_types.QualifiedNameType', type: '_types.Type') -> None:
		"""
		Add named types to the type archive. Type must have all dependant named types added
		prior to being added, or this function will fail.
		If the type already exists, it will be overwritten.
		:param name: Name of new type
		:param type: Definition of new type
		"""
		self.add_types([(name, type)])

	def add_types(self, new_types: List[Tuple['_types.QualifiedNameType', '_types.Type']]) -> None:
		"""
		Add named types to the type archive. Types must have all dependant named
		types prior to being added, or this function will fail.
		Types already existing with any added names will be overwritten.
		:param new_types: Names and definitions of new types
		"""
		api_types = (core.BNQualifiedNameAndType * len(new_types))()
		i = 0
		for (name, type) in new_types:
			if not isinstance(name, _types.QualifiedName):
				name = _types.QualifiedName(name)
			type = type.immutable_copy()
			if not isinstance(type, _types.Type):
				raise ValueError("parameter type must be a Type")
			api_types[i].name = name._to_core_struct()
			api_types[i].type = type.handle
			i += 1

		if not core.BNAddTypeArchiveTypes(self.handle, api_types, len(new_types)):
			raise RuntimeError("BNAddTypeArchiveTypes")

	def rename_type(self, old_name: '_types.QualifiedNameType', new_name: '_types.QualifiedNameType') -> None:
		"""
		Change the name of an existing type in the type archive.
		:param old_name: Old type name in archive
		:param new_name: New type name
		"""
		id = self.get_type_id(old_name)
		return self.rename_type_by_id(id, new_name)

	def rename_type_by_id(self, id: str, new_name: '_types.QualifiedNameType') -> None:
		"""
		Change the name of an existing type in the type archive.
		:param id: Old id of type in archive
		:param new_name: New type name
		"""
		if not isinstance(new_name, _types.QualifiedName):
			new_name = _types.QualifiedName(new_name)
		if not core.BNRenameTypeArchiveType(self.handle, id, new_name._to_core_struct()):
			raise RuntimeError("BNRenameTypeArchiveType")

	def delete_type(self, name: '_types.QualifiedNameType') -> None:
		"""
		Delete an existing type in the type archive.
		:param name: Type name
		"""
		id = self.get_type_id(name)
		if id is None:
			raise RuntimeError(f"Unknown type {name}")
		self.delete_type_by_id(id)

	def delete_type_by_id(self, id: str) -> None:
		"""
		Delete an existing type in the type archive.
		:param id: Type id
		"""
		if not core.BNDeleteTypeArchiveType(self.handle, id):
			raise RuntimeError("BNDeleteTypeArchiveType")

	def get_type_by_name(self, name: '_types.QualifiedNameType', snapshot: Optional[str] = None) -> Optional[_types.Type]:
		"""
		Retrieve a stored type in the archive
		:param name: Type name
		:param snapshot: Snapshot id to search for types, or None to search the latest snapshot
		:return: Type, if it exists. Otherwise None
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		if not isinstance(name, _types.QualifiedName):
			name = _types.QualifiedName(name)
		t = core.BNGetTypeArchiveTypeByName(self.handle, name._to_core_struct(), snapshot)
		if t is None:
			return None
		return _types.Type.create(t)

	def get_type_by_id(self, id: str, snapshot: Optional[str] = None) -> Optional[_types.Type]:
		"""
		Retrieve a stored type in the archive by id
		:param id: Type id
		:param snapshot: Snapshot id to search for types, or None to search the latest snapshot
		:return: Type, if it exists. Otherwise None
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		assert id is not None
		t = core.BNGetTypeArchiveTypeById(self.handle, id, snapshot)
		if t is None:
			return None
		return _types.Type.create(t)

	def get_type_name_by_id(self, id: str, snapshot: Optional[str] = None) -> Optional['_types.QualifiedName']:
		"""
		Retrieve a type's name by its id
		:param id: Type id
		:param snapshot: Snapshot id to search for types, or None to search the latest snapshot
		:return: Type name, if it exists. Otherwise None
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		assert id is not None
		name = core.BNGetTypeArchiveTypeName(self.handle, id, snapshot)
		if name is None:
			return None
		qname = _types.QualifiedName._from_core_struct(name)
		if len(qname.name) == 0:
			return None
		return qname

	def get_type_id(self, name: '_types.QualifiedNameType', snapshot: Optional[str] = None) -> Optional[str]:
		"""
		Retrieve a type's id by its name
		:param name: Type name
		:param snapshot: Snapshot id to search for types, or None to search the latest snapshot
		:return: Type id, if it exists. Otherwise None
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		if not isinstance(name, _types.QualifiedName):
			name = _types.QualifiedName(name)
		t = core.BNGetTypeArchiveTypeId(self.handle, name._to_core_struct(), snapshot)
		if t is None:
			return None
		if t == "":
			return None
		return t

	@property
	def types(self) -> Dict[_types.QualifiedName, _types.Type]:
		"""
		Retrieve all stored types in the archive at the current snapshot
		:return: Map of all types, by name
		"""
		return self.get_types()

	@property
	def types_and_ids(self) -> Dict[str, Tuple[_types.QualifiedName, _types.Type]]:
		"""
		Retrieve all stored types in the archive at the current snapshot
		:return: Map of type id to type name and definition
		"""
		return self.get_types_and_ids()

	def get_types(self, snapshot: Optional[str] = None) -> Dict[_types.QualifiedName, _types.Type]:
		"""
		Retrieve all stored types in the archive at a snapshot
		:param snapshot: Snapshot id to search for types, or None to search the latest snapshot
		:return: Map of all types, by name
		"""
		result = {}
		for id, (name, type) in self.get_types_and_ids(snapshot).items():
			result[name] = type
		return result

	def get_types_and_ids(self, snapshot: Optional[str] = None) -> Dict[str, Tuple[_types.QualifiedName, _types.Type]]:
		"""
		Retrieve all stored types in the archive at a snapshot
		:param snapshot: Snapshot id to search for types, or None to search the latest snapshot
		:return: Map of type id to type name and definition
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		count = ctypes.c_ulonglong(0)
		result = {}
		named_types = core.BNGetTypeArchiveTypes(self.handle, snapshot, count)
		assert named_types is not None, "core.BNGetTypeArchiveTypes returned None"
		try:
			for i in range(0, count.value):
				name = _types.QualifiedName._from_core_struct(named_types[i].name)
				id = core.pyNativeStr(named_types[i].id)
				result[id] = (name, _types.Type.create(core.BNNewTypeReference(named_types[i].type)))
			return result
		finally:
			core.BNFreeTypeIdList(named_types, count.value)

	@property
	def type_ids(self) -> List[str]:
		"""
		Get a list of all types' ids in the archive at the current snapshot
		:return: All type ids
		"""
		return self.get_type_ids()

	def get_type_ids(self, snapshot: Optional[str] = None) -> List[str]:
		"""
		Get a list of all types' ids in the archive at a snapshot
		:param snapshot: Snapshot id to search for types, or None to search the latest snapshot
		:return: All type ids
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		count = ctypes.c_ulonglong(0)
		result = []
		ids = core.BNGetTypeArchiveTypeIds(self.handle, snapshot, count)
		assert ids is not None, "core.BNGetTypeArchiveTypeIds returned None"
		try:
			for i in range(count.value):
				result.append(core.pyNativeStr(ids[i]))
			return result
		finally:
			core.BNFreeStringList(ids, count.value)

	@property
	def type_names(self) -> List['_types.QualifiedName']:
		"""
		Get a list of all types' names in the archive at the current snapshot
		:return: All type names
		"""
		return self.get_type_names()

	def get_type_names(self, snapshot: Optional[str] = None) -> List['_types.QualifiedName']:
		"""
		Get a list of all types' names in the archive at a snapshot
		:param snapshot: Snapshot id to search for types, or None to search the latest snapshot
		:return: All type names
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		count = ctypes.c_ulonglong(0)
		result = []
		names = core.BNGetTypeArchiveTypeNames(self.handle, snapshot, count)
		assert names is not None, "core.BNGetTypeArchiveTypeNames returned None"
		try:
			for i in range(count.value):
				result.append(_types.QualifiedName._from_core_struct(names[i]))
			return result
		finally:
			core.BNFreeQualifiedNameArray(names, count.value)

	@property
	def type_names_and_ids(self) -> Dict[str, '_types.QualifiedName']:
		"""
		Get a list of all types' names and ids in the archive at the current snapshot
		:return: Mapping of all type ids to names
		"""
		return self.get_type_names_and_ids()

	def get_type_names_and_ids(self, snapshot: Optional[str] = None) -> Dict[str, '_types.QualifiedName']:
		"""
		Get a list of all types' names and ids in the archive at a current snapshot
		:param snapshot: Snapshot id to search for types, or None to search the latest snapshot
		:return: Mapping of all type ids to names
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		names = ctypes.POINTER(core.BNQualifiedName)()
		ids = ctypes.POINTER(ctypes.c_char_p)()
		count = ctypes.c_ulonglong(0)
		result = {}
		if not core.BNGetTypeArchiveTypeNamesAndIds(self.handle, snapshot, names, ids, count):
			raise RuntimeError("core.BNGetTypeArchiveTypeNamesAndIds returned False")
		try:
			for i in range(count.value):
				id = core.pyNativeStr(ids[i])
				name = _types.QualifiedName._from_core_struct(names[i])
				result[id] = name
			return result
		finally:
			core.BNFreeQualifiedNameArray(names, count.value)

	def get_outgoing_direct_references(self, id: str, snapshot: Optional[str] = None) -> List[str]:
		"""
		Get all types a given type references directly
		:param id: Source type id
		:param snapshot: Snapshot id to search for types, or empty string to search the latest snapshot
		:return: Target type ids
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		assert id is not None
		count = ctypes.c_size_t(0)
		ids = core.BNGetTypeArchiveOutgoingDirectTypeReferences(self.handle, id, snapshot, count)
		if ids is None:
			raise RuntimeError("BNGetTypeArchiveOutgoingDirectTypeReferences")
		result = []
		try:
			for i in range(0, count.value):
				result.append(core.pyNativeStr(ids[i]))
			return result
		finally:
			core.BNFreeStringList(ids, count.value)

	def get_outgoing_recursive_references(self, id: str, snapshot: Optional[str] = None) -> List[str]:
		"""
		Get all types a given type references, and any types that the referenced types reference
		:param id: Source type id
		:param snapshot: Snapshot id to search for types, or empty string to search the latest snapshot
		:return: Target type ids
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		assert id is not None
		count = ctypes.c_size_t(0)
		ids = core.BNGetTypeArchiveOutgoingRecursiveTypeReferences(self.handle, id, snapshot, count)
		if ids is None:
			raise RuntimeError("BNGetTypeArchiveOutgoingRecursiveTypeReferences")
		result = []
		try:
			for i in range(0, count.value):
				result.append(core.pyNativeStr(ids[i]))
			return result
		finally:
			core.BNFreeStringList(ids, count.value)

	def get_incoming_direct_references(self, id: str, snapshot: Optional[str] = None) -> List[str]:
		"""
		Get all types that reference a given type
		:param id: Target type id
		:param snapshot: Snapshot id to search for types, or empty string to search the latest snapshot
		:return: Source type ids
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		assert id is not None
		count = ctypes.c_size_t(0)
		ids = core.BNGetTypeArchiveIncomingDirectTypeReferences(self.handle, id, snapshot, count)
		if ids is None:
			raise RuntimeError("BNGetTypeArchiveIncomingDirectTypeReferences")
		result = []
		try:
			for i in range(0, count.value):
				result.append(core.pyNativeStr(ids[i]))
			return result
		finally:
			core.BNFreeStringList(ids, count.value)

	def get_incoming_recursive_references(self, id: str, snapshot: Optional[str] = None) -> List[str]:
		"""
		Get all types that reference a given type, and all types that reference them, recursively
		:param id: Target type id
		:param snapshot: Snapshot id to search for types, or empty string to search the latest snapshot
		:return: Source type ids
		"""
		if snapshot is None:
			snapshot = self.current_snapshot_id
		assert id is not None
		count = ctypes.c_size_t(0)
		ids = core.BNGetTypeArchiveIncomingRecursiveTypeReferences(self.handle, id, snapshot, count)
		if ids is None:
			raise RuntimeError("BNGetTypeArchiveIncomingRecursiveTypeReferences")
		result = []
		try:
			for i in range(0, count.value):
				result.append(core.pyNativeStr(ids[i]))
			return result
		finally:
			core.BNFreeStringList(ids, count.value)

	def query_metadata(self, key: str) -> Optional['metadata.MetadataValueType']:
		"""
		Look up a metadata entry in the archive
		:param string key: key to query
		:rtype: Metadata associated with the key, if it exists. Otherwise, None
		:Example:

			>>> ta: TypeArchive
			>>> ta.store_metadata("ordinals", {"9": "htons"})
			>>> ta.query_metadata("ordinals")["9"]
			"htons"
		"""
		md_handle = core.BNTypeArchiveQueryMetadata(self.handle, key)
		if md_handle is None:
			return None
		return metadata.Metadata(handle=md_handle).value

	def store_metadata(self, key: str, md: 'metadata.MetadataValueType') -> None:
		"""
		Store a key/value pair in the archive's metadata storage
		:param string key: key value to associate the Metadata object with
		:param Varies md: object to store.
		:Example:

			>>> ta: TypeArchive
			>>> ta.store_metadata("ordinals", {"9": "htons"})
			>>> ta.query_metadata("ordinals")["9"]
			"htons"
		"""
		if not isinstance(md, metadata.Metadata):
			md = metadata.Metadata(md)
		if not core.BNTypeArchiveStoreMetadata(self.handle, key, md.handle):
			raise RuntimeError("BNTypeArchiveStoreMetadata")

	def remove_metadata(self, key: str) -> None:
		"""
		Delete a given metadata entry in the archive
		:param string key: key associated with metadata
		:Example:

			>>> ta: TypeArchive
			>>> ta.store_metadata("integer", 1337)
			>>> ta.remove_metadata("integer")
		"""
		core.BNTypeArchiveRemoveMetadata(self.handle, key)

	def serialize_snapshot(self, snapshot: str) -> 'databuffer.DataBuffer':
		"""
		Turn a given snapshot into a data stream
		:param snapshot: Snapshot id
		:return: Buffer containing serialized snapshot data
		"""
		result = core.BNTypeArchiveSerializeSnapshot(self.handle, snapshot)
		if not result:
			raise RuntimeError("BNTypeArchiveDeserializeSnapshot")
		return databuffer.DataBuffer(handle=result)

	def deserialize_snapshot(self, data: 'databuffer.DataBufferInputType') -> str:
		"""
		Take a serialized snapshot data stream and create a new snapshot from it
		:param data: Snapshot data
		:return: String of created snapshot id
		"""
		buffer = databuffer.DataBuffer(data)
		result = core.BNTypeArchiveDeserializeSnapshot(self.handle, buffer.handle)
		if not result:
			raise RuntimeError("BNTypeArchiveDeserializeSnapshot")
		return result

	def register_notification(self, notify: 'TypeArchiveNotification') -> None:
		"""
		Register a notification listener
		:param notify: Object to receive notifications
		"""
		cb = TypeArchiveNotificationCallbacks(self, notify)
		cb._register()
		self._notifications[notify] = cb

	def unregister_notification(self, notify: 'TypeArchiveNotification') -> None:
		"""
		Unregister a notification listener
		:param notify: Object to no longer receive notifications
		"""
		if notify in self._notifications:
			self._notifications[notify]._unregister()
			del self._notifications[notify]


class TypeArchiveNotification:
	def __init__(self):
		pass

	def view_attached(self, archive: 'TypeArchive', view: 'binaryview.BinaryView') -> None:
		"""
		Called when a new view attaches to the type archive.
		:param archive: Source Type archive
		:param view: View attaching the archive
		"""
		pass

	def view_detached(self, archive: 'TypeArchive', view: 'binaryview.BinaryView') -> None:
		"""
		Called when a view that has previously attached the archive detaches it
		:param archive: Source Type archive
		:param view: View detaching the archive
		"""
		pass

	def type_added(self, archive: 'TypeArchive', id: str, definition: '_types.Type') -> None:
		"""
		Called when a type is added to the archive
		:param archive: Source Type archive
		:param id: Id of type added
		:param definition: Definition of type
		"""
		pass

	def type_updated(self, archive: 'TypeArchive', id: str, old_definition: '_types.Type', new_definition: '_types.Type') -> None:
		"""
		Called when a type in the archive is updated to a new definition
		:param archive: Source Type archive
		:param id: Id of type
		:param old_definition: Previous definition
		:param new_definition: Current definition
		"""
		pass

	def type_renamed(self, archive: 'TypeArchive', id: str, old_name: '_types.QualifiedName', new_name: '_types.QualifiedName') -> None:
		"""
		Called when a type in the archive is renamed
		:param archive: Source Type archive
		:param id: Type id
		:param old_name: Previous name
		:param new_name: Current name
		"""
		pass

	def type_deleted(self, archive: 'TypeArchive', id: str, definition: '_types.Type') -> None:
		"""
		Called when a type in the archive is deleted from the archive
		:param archive: Source Type archive
		:param id: Id of type deleted
		:param definition: Definition of type deleted
		"""
		pass


class TypeArchiveNotificationCallbacks:
	def __init__(self, archive: 'TypeArchive', notify: 'TypeArchiveNotification'):
		self._archive = archive
		self._notify = notify
		self._cb = core.BNTypeArchiveNotification()
		self._cb.context = 0
		self._cb.typeAdded = self._cb.typeAdded.__class__(self._type_added)
		self._cb.typeUpdated = self._cb.typeUpdated.__class__(self._type_updated)
		self._cb.typeRenamed = self._cb.typeRenamed.__class__(self._type_renamed)
		self._cb.typeDeleted = self._cb.typeDeleted.__class__(self._type_deleted)

	def _register(self) -> None:
		core.BNRegisterTypeArchiveNotification(self._archive.handle, self._cb)

	def _unregister(self) -> None:
		core.BNUnregisterTypeArchiveNotification(self._archive.handle, self._cb)

	def _view_attached(self, ctxt, archive: ctypes.POINTER(core.BNTypeArchive), view: ctypes.POINTER(core.BNBinaryView)) -> None:
		try:
			self._notify.view_attached(self._archive, binaryview.BinaryView(handle=core.BNNewViewReference(view)))
		except:
			log.log_error(traceback.format_exc())

	def _view_detached(self, ctxt, archive: ctypes.POINTER(core.BNTypeArchive), view: ctypes.POINTER(core.BNBinaryView)) -> None:
		try:
			self._notify.view_detached(self._archive, binaryview.BinaryView(handle=core.BNNewViewReference(view)))
		except:
			log.log_error(traceback.format_exc())

	def _type_added(self, ctxt, archive: ctypes.POINTER(core.BNTypeArchive), id: ctypes.c_char_p, definition: ctypes.POINTER(core.BNType)) -> None:
		try:
			self._notify.type_added(self._archive, core.pyNativeStr(id), _types.Type.create(handle=core.BNNewTypeReference(definition)))
		except:
			log.log_error(traceback.format_exc())

	def _type_updated(self, ctxt, archive: ctypes.POINTER(core.BNTypeArchive), id: ctypes.c_char_p, old_definition: ctypes.POINTER(core.BNType), new_definition: ctypes.POINTER(core.BNType)) -> None:
		try:
			self._notify.type_updated(self._archive, core.pyNativeStr(id), _types.Type.create(handle=core.BNNewTypeReference(old_definition)), _types.Type.create(handle=core.BNNewTypeReference(new_definition)))
		except:
			log.log_error(traceback.format_exc())

	def _type_renamed(self, ctxt, archive: ctypes.POINTER(core.BNTypeArchive), id: ctypes.c_char_p, old_name: ctypes.POINTER(core.BNQualifiedName), new_name: ctypes.POINTER(core.BNQualifiedName)) -> None:
		try:
			self._notify.type_renamed(self._archive, core.pyNativeStr(id), _types.QualifiedName._from_core_struct(old_name.contents), _types.QualifiedName._from_core_struct(new_name.contents))
		except:
			log.log_error(traceback.format_exc())

	def _type_deleted(self, ctxt, archive: ctypes.POINTER(core.BNTypeArchive), id: ctypes.c_char_p, definition: ctypes.POINTER(core.BNType)) -> None:
		try:
			self._notify.type_deleted(self._archive, core.pyNativeStr(id), _types.Type.create(handle=core.BNNewTypeReference(definition)))
		except:
			log.log_error(traceback.format_exc())

	@property
	def archive(self) -> 'TypeArchive':
		return self._archive

	@property
	def notify(self) -> 'TypeArchiveNotification':
		return self._notify
