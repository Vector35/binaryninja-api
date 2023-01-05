# coding=utf-8
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
from typing import List, Optional, Dict, Callable

import binaryninja
from . import _binaryninjacore as core
from . import databuffer
from . import filemetadata


class KeyValueStore:
	"""
    ``class KeyValueStore`` maintains access to the raw data stored in Snapshots and various
    other Database-related structures.
    """
	def __init__(self, buffer: Optional[databuffer.DataBuffer] = None, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNKeyValueStore)
		else:
			if buffer is None:
				_handle = core.BNCreateKeyValueStore()
			else:
				_handle = core.BNCreateKeyValueStoreFromDataBuffer(buffer.handle)
			assert _handle is not None
			self.handle = _handle

	def __del__(self):
		core.BNFreeKeyValueStore(self.handle)

	def __getitem__(self, item: str) -> databuffer.DataBuffer:
		return self.get_value(item)

	def __setitem__(self, key: str, value: databuffer.DataBuffer):
		return self.set_value(key, value)

	@property
	def keys(self):
		"""Get a list of all keys stored in the kvs (read-only)"""
		count = ctypes.c_ulonglong(0)
		value = core.BNGetKeyValueStoreKeys(self.handle, count)
		assert value is not None

		result = []
		try:
			for i in range(0, count.value):
				result.append(value[i])
			return result
		finally:
			core.BNFreeStringList(value, count)

	def get_value(self, key: str) -> databuffer.DataBuffer:
		"""Get the value for a single key"""
		handle = core.BNGetKeyValueStoreBuffer(self.handle, key)
		assert handle is not None
		return databuffer.DataBuffer(handle=handle)

	def set_value(self, key: str, value: databuffer.DataBuffer):
		"""Set the value for a single key"""
		core.BNSetKeyValueStoreBuffer(self.handle, key, value.handle)

	@property
	def serialized_data(self) -> databuffer.DataBuffer:
		"""Get the stored representation of the kvs (read-only)"""
		handle = core.BNGetKeyValueStoreSerializedData(self.handle)
		assert handle is not None
		return databuffer.DataBuffer(handle=handle)

	def begin_namespace(self, name: str):
		"""Begin storing new keys into a namespace"""
		core.BNBeginKeyValueStoreNamespace(self.handle, name)

	def end_namespace(self):
		"""End storing new keys into a namespace"""
		core.BNEndKeyValueStoreNamespace(self.handle)

	@property
	def empty(self) -> bool:
		"""If the kvs is empty (read-only)"""
		return core.BNIsKeyValueStoreEmpty(self.handle)

	@property
	def value_size(self) -> bool:
		"""Number of values in the kvs (read-only)"""
		return core.BNGetKeyValueStoreValueSize(self.handle)

	@property
	def data_size(self) -> bool:
		"""Length of serialized data (read-only)"""
		return core.BNGetKeyValueStoreDataSize(self.handle)

	@property
	def value_storage_size(self) -> bool:
		"""Size of all data in storage (read-only)"""
		return core.BNGetKeyValueStoreValueStorageSize(self.handle)

	@property
	def namespace_size(self) -> bool:
		"""Number of namespaces pushed with begin_namespace (read-only)"""
		return core.BNGetKeyValueStoreNamespaceSize(self.handle)


class Snapshot:
	"""
    ``class Snapshot`` is a model of an individual database snapshot, created on save.
    """
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNSnapshot)

	def __del__(self):
		core.BNFreeSnapshot(self.handle)

	@property
	def database(self) -> 'Database':
		"""Get the owning database (read-only)"""
		return Database(handle=core.BNGetSnapshotDatabase(self.handle))

	@property
	def id(self) -> int:
		"""Get the numerical id (read-only)"""
		return core.BNGetSnapshotId(self.handle)

	@property
	def name(self) -> str:
		"""Get the displayed snapshot name"""
		return core.BNGetSnapshotName(self.handle)

	@name.setter
	def name(self, value: str) -> None:
		"""Set the displayed snapshot name"""
		core.BNSetSnapshotName(self.handle, value)

	@property
	def is_auto_save(self) -> bool:
		"""If the snapshot was the result of an auto-save (read-only)"""
		return core.BNIsSnapshotAutoSave(self.handle)

	@property
	def has_contents(self) -> bool:
		"""If the snapshot has contents, and has not been trimmed (read-only)"""
		return core.BNSnapshotHasContents(self.handle)

	@property
	def has_undo(self) -> bool:
		"""If the snapshot has undo data (read-only)"""
		return core.BNSnapshotHasUndo(self.handle)

	@property
	def first_parent(self) -> Optional['Snapshot']:
		"""Get the first parent of the snapshot, or None if it has no parents (read-only)"""
		handle = core.BNGetSnapshotFirstParent(self.handle)
		if handle is None:
			return None
		return Snapshot(handle=handle)

	@property
	def parents(self) -> List['Snapshot']:
		"""Get a list of all parent snapshots of the snapshot (read-only)"""
		count = ctypes.c_ulonglong(0)
		parents = core.BNGetSnapshotParents(self.handle, count)

		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewSnapshotReference(parents[i])
				result.append(Snapshot(handle=handle))
			return result
		finally:
			core.BNFreeSnapshotList(parents, count)

	@property
	def children(self) -> List['Snapshot']:
		"""Get a list of all child snapshots of the snapshot (read-only)"""
		count = ctypes.c_ulonglong(0)
		children = core.BNGetSnapshotChildren(self.handle, count)

		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewSnapshotReference(children[i])
				result.append(Snapshot(handle=handle))
			return result
		finally:
			core.BNFreeSnapshotList(children, count)

	@property
	def file_contents(self) -> databuffer.DataBuffer:
		"""Get a buffer of the raw data at the time of the snapshot (read-only)"""
		assert self.has_contents
		handle = core.BNGetSnapshotFileContents(self.handle)
		assert handle is not None
		return databuffer.DataBuffer(handle=handle)

	@property
	def file_contents_hash(self) -> databuffer.DataBuffer:
		"""Get a hash of the data at the time of the snapshot (read-only)"""
		assert self.has_contents
		handle = core.BNGetSnapshotFileContentsHash(self.handle)
		assert handle is not None
		return databuffer.DataBuffer(handle=handle)

	@property
	def undo_entries(self):
		"""Get a list of undo entries at the time of the snapshot (read-only)"""
		assert self.has_undo
		raise NotImplementedError("GetUndoEntries is not implemented in python")

	@property
	def data(self) -> KeyValueStore:
		"""Get the backing kvs data with snapshot fields (read-only)"""
		assert self.has_contents
		handle = core.BNReadSnapshotData(self.handle)
		assert handle is not None
		return KeyValueStore(handle=handle)

	def has_ancestor(self, other: 'Snapshot') -> bool:
		"""Determine if this snapshot has another as an ancestor"""
		return core.BNSnapshotHasAncestor(self.handle, other.handle)


class Database:
	"""
    ``class Database`` provides lower level access to raw snapshot data used to construct analysis data
    """
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNDatabase)

	def __del__(self):
		core.BNFreeDatabase(self.handle)

	def __getitem__(self, item: int) -> Optional[Snapshot]:
		return self.get_snapshot(item)

	def get_snapshot(self, id: int) -> Optional[Snapshot]:
		"""Get a snapshot by its id, or None if no snapshot with that id exists"""
		snap = core.BNGetDatabaseSnapshot(self.handle, id)
		if snap is None:
			return None
		return Snapshot(handle=snap)

	@property
	def snapshots(self) -> List[Snapshot]:
		"""Get a list of all snapshots in the database (read-only)"""
		count = ctypes.c_ulonglong(0)
		snapshots = core.BNGetDatabaseSnapshots(self.handle, count)
		assert snapshots is not None

		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewSnapshotReference(snapshots[i])
				result.append(Snapshot(handle=handle))
			return result
		finally:
			core.BNFreeSnapshotList(snapshots, count)

	@property
	def current_snapshot(self) -> Optional[Snapshot]:
		"""Get the current snapshot"""
		snap = core.BNGetDatabaseCurrentSnapshot(self.handle)
		if snap is None:
			return None
		return Snapshot(handle=snap)

	@current_snapshot.setter
	def current_snapshot(self, value: Snapshot):
		core.BNSetDatabaseCurrentSnapshot(self.handle, value.id)

	def trim_snapshot(self, id: int):
		"""
		Trim a snapshot's contents in the database by id, but leave the parent/child
		hierarchy intact. Future references to this snapshot will return False for has_contents
		"""
		if not core.BNRemoveDatabaseSnapshot(self.handle, id):
			raise RuntimeError("BNRemoveDatabaseSnapshot returned False")

	def remove_snapshot(self, id: int):
		"""
		Remove a snapshot in the database by id, deleting its contents and references.
		Attempting to remove a snapshot with children will raise an exception.
		"""
		if not core.BNRemoveDatabaseSnapshot(self.handle, id):
			raise RuntimeError("BNRemoveDatabaseSnapshot returned False")

	@property
	def global_keys(self) -> List[str]:
		"""Get a list of keys for all globals in the database (read-only)"""
		count = ctypes.c_ulonglong(0)
		value = core.BNGetDatabaseGlobalKeys(self.handle, count)
		assert value is not None

		result = []
		try:
			for i in range(0, count.value):
				result.append(value[i])
			return result
		finally:
			core.BNFreeStringList(value, count)

	@property
	def globals(self) -> Dict[str, str]:
		"""Get a dictionary of all globals (read-only)"""
		count = ctypes.c_ulonglong(0)
		value = core.BNGetDatabaseGlobalKeys(self.handle, count)
		assert value is not None

		result = {}
		try:
			for i in range(0, count.value):
				key = value[i]
				result[key] = self.read_global(key)
			return result
		finally:
			core.BNFreeStringList(value, count)

	def read_global(self, key: str) -> str:
		"""Get a specific global by key"""
		value = core.BNReadDatabaseGlobal(self.handle, key)
		assert value is not None
		return value

	def write_global(self, key: str, value: str):
		"""Write a global into the database"""
		core.BNWriteDatabaseGlobal(self.handle, key, value)

	def read_global_data(self, key: str) -> databuffer.DataBuffer:
		"""Get a specific global by key, as a binary buffer"""
		handle = core.BNReadDatabaseGlobalData(self.handle, key)
		assert handle is not None
		return databuffer.DataBuffer(handle=handle)

	def write_global_data(self, key: str, value: databuffer.DataBuffer):
		"""Write a binary buffer into a global in the database"""
		core.BNWriteDatabaseGlobalData(self.handle, key, value.handle)

	@property
	def file(self) -> 'filemetadata.FileMetadata':
		"""Get the owning FileMetadata (read-only)"""
		handle = core.BNGetDatabaseFile(self.handle)
		assert handle is not None
		return filemetadata.FileMetadata(handle=handle)

	@property
	def analysis_cache(self) -> KeyValueStore:
		"""Get the backing analysis cache kvs (read-only)"""
		handle = core.BNReadDatabaseAnalysisCache(self.handle)
		assert handle is not None
		return KeyValueStore(handle=handle)
