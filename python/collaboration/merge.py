import abc
import ctypes
import json
import sys
import traceback
from typing import Dict, Optional

from .. import _binaryninjacore as core
from ..enums import MergeConflictDataType
from ..database import KeyValueStore
from . import util

from ..database import Database, Snapshot
from ..filemetadata import FileMetadata

OptionalStringDict = Optional[Dict[str, object]]


class MergeConflict:
	"""
	Structure representing an individual merge conflict
	"""
	def __init__(self, handle: core.BNAnalysisMergeConflictHandle):
		"""
		FFI constructor

		:param handle: FFI handle for internal use
		"""
		self._handle = ctypes.cast(handle, core.BNAnalysisMergeConflictHandle)

	def __del__(self):
		core.BNFreeAnalysisMergeConflict(self._handle)

	@property
	def database(self) -> Database:
		"""
		Database backing all snapshots in the merge conflict

		:return: Database object
		"""
		result = core.BNAnalysisMergeConflictGetDatabase(self._handle)
		return Database(handle=ctypes.cast(result, ctypes.POINTER(core.BNDatabase)))

	@property
	def base_snapshot(self) -> Optional[Snapshot]:
		"""
		Snapshot which is the parent of the two being merged

		:return: Snapshot object
		"""
		result = core.BNAnalysisMergeConflictGetBaseSnapshot(self._handle)
		if result is None:
			return None
		return Snapshot(handle=ctypes.cast(result, ctypes.POINTER(core.BNSnapshot)))

	@property
	def first_snapshot(self) -> Optional[Snapshot]:
		"""
		First snapshot being merged

		:return: Snapshot object
		"""
		result = core.BNAnalysisMergeConflictGetFirstSnapshot(self._handle)
		if result is None:
			return None
		return Snapshot(handle=ctypes.cast(result, ctypes.POINTER(core.BNSnapshot)))

	@property
	def second_snapshot(self) -> Optional[Snapshot]:
		"""
		Second snapshot being merged

		:return: Snapshot object
		"""
		result = core.BNAnalysisMergeConflictGetSecondSnapshot(self._handle)
		if result is None:
			return None
		return Snapshot(handle=ctypes.cast(result, ctypes.POINTER(core.BNSnapshot)))

	@property
	def base_file(self) -> Optional[FileMetadata]:
		"""
		FileMetadata with contents of file for base snapshot
		This function is slow! Only use it if you really need it.

		:return: FileMetadata object
		"""
		result = core.BNAnalysisMergeConflictGetBaseFile(self._handle)
		if result is None:
			return None
		lazy = util.LazyT(handle=result)
		file = FileMetadata(handle=ctypes.cast(lazy.get(ctypes.POINTER(core.BNFileMetadata)), ctypes.POINTER(core.BNFileMetadata)))
		core.BNCollaborationFreeLazyT(result)
		return file

	@property
	def first_file(self) -> Optional[FileMetadata]:
		"""
		FileMetadata with contents of file for first snapshot
		This function is slow! Only use it if you really need it.

		:return: FileMetadata object
		"""
		result = core.BNAnalysisMergeConflictGetFirstFile(self._handle)
		if result is None:
			return None
		lazy = util.LazyT(handle=result)
		file = FileMetadata(handle=ctypes.cast(lazy.get(ctypes.POINTER(core.BNFileMetadata)), ctypes.POINTER(core.BNFileMetadata)))
		core.BNCollaborationFreeLazyT(result)
		return file

	@property
	def second_file(self) -> Optional[FileMetadata]:
		"""
		FileMetadata with contents of file for second snapshot
		This function is slow! Only use it if you really need it.

		:return: FileMetadata object
		"""
		result = core.BNAnalysisMergeConflictGetSecondFile(self._handle)
		if result is None:
			return None
		lazy = util.LazyT(handle=result)
		file = FileMetadata(handle=ctypes.cast(lazy.get(ctypes.POINTER(core.BNFileMetadata)), ctypes.POINTER(core.BNFileMetadata)))
		core.BNCollaborationFreeLazyT(result)
		return file

	@property
	def base(self) -> OptionalStringDict:
		"""
		Json object for conflicting data in the base snapshot

		:return: Python dictionary from parsed json
		"""
		result = core.BNAnalysisMergeConflictGetBase(self._handle)
		if result is None:
			return None
		return json.loads(result)

	@property
	def first(self) -> OptionalStringDict:
		"""
		Json object for conflicting data in the first snapshot

		:return: Python dictionary from parsed json
		"""
		result = core.BNAnalysisMergeConflictGetFirst(self._handle)
		if result is None:
			return None
		return json.loads(result)

	@property
	def second(self) -> OptionalStringDict:
		"""
		Json object for conflicting data in the second snapshot

		:return: Python dictionary from parsed json
		"""
		result = core.BNAnalysisMergeConflictGetSecond(self._handle)
		if result is None:
			return None
		return json.loads(result)

	@property
	def data_type(self) -> 'MergeConflictDataType':
		"""
		Type of data in the conflict, Text/Json/Binary

		:return: Conflict data type
		"""
		return MergeConflictDataType(core.BNAnalysisMergeConflictGetDataType(self._handle))

	@property
	def type(self) -> str:
		"""
		String representing the type name of the data, not the same as data_type.
		This is like "typeName" or "tag" depending on what object the conflict represents.

		:return: Type name
		"""
		return core.BNAnalysisMergeConflictGetType(self._handle)

	@property
	def key(self) -> str:
		"""
		Lookup key for the merge conflict, ideally a tree path that contains the name of the conflict
		and all the recursive children leading up to this conflict.

		:return: Key name
		"""
		return core.BNAnalysisMergeConflictGetKey(self._handle)

	def success(self, value: OptionalStringDict) -> bool:
		"""
		Call this when you've resolved the conflict to save the result

		:param value: Resolved value
		:return: True if successful
		"""
		if value is None:
			printed = None
		else:
			printed = json.dumps(value)
		return core.BNAnalysisMergeConflictSuccess(self._handle, printed)

	def get_path_item(self, path_key: str) -> Optional[object]:
		"""
		Get item in the merge conflict's path for a given key.

		:param path_key: Key for path item
		:return: Path item, or an None if not found
		"""
		value = core.BNAnalysisMergeConflictGetPathItem(self._handle, path_key)
		if value is None:
			return None
		return ctypes.py_object(value)


class ConflictHandler:
	"""
	Helper class that resolves conflicts
	"""
	def _handle(self, ctxt: ctypes.c_void_p, keys: ctypes.POINTER(ctypes.c_char_p), conflicts: ctypes.POINTER(core.BNAnalysisMergeConflictHandle), count: ctypes.c_ulonglong) -> bool:
		try:
			py_conflicts = {}
			for i in range(count.value):
				py_conflicts[core.pyNativeStr(keys[i])] = MergeConflict(handle=conflicts[i])
			return self.handle(py_conflicts)
		except:
			traceback.print_exc(file=sys.stderr)
			return False

	@abc.abstractmethod
	def handle(self, conflicts: Dict[str, MergeConflict]) -> bool:
		"""
		Handle any merge conflicts by calling their success() function with a merged value

		:param conflicts: Map of conflict id to conflict structure
		:return: True if all conflicts were successfully merged
		"""
		raise NotImplementedError("Not implemented")


class ConflictSplitter:
	"""
	Helper class that takes one merge conflict and splits it into multiple conflicts
	Eg takes conflicts for View/symbols and splits to one conflict per symbol
	"""

	def __init__(self, handle=None):
		if handle is not None:
			self._handle = handle

	def register(self):
		self._cb = core.BNAnalysisMergeConflictSplitterCallbacks()
		self._cb.context = 0
		self._cb.getName = self._cb.getName.__class__(self._get_name)
		self._cb.reset = self._cb.reset.__class__(self._reset)
		self._cb.finished = self._cb.finished.__class__(self._finished)
		self._cb.canSplit = self._cb.canSplit.__class__(self._can_split)
		self._cb.split = self._cb.split.__class__(self._split)
		self._cb.freeName = self._cb.freeName.__class__(self._free_name)
		self._cb.freeKeyList = self._cb.freeKeyList.__class__(self._free_key_list)
		self._cb.freeConflictList = self._cb.freeConflictList.__class__(self._free_conflict_list)
		self._handle = core.BNRegisterAnalysisMergeConflictSplitter(self._cb)
		self._split_keys = None
		self._split_conflicts = None


	def _get_name(self, ctxt: ctypes.c_void_p) -> ctypes.c_char_p:
		try:
			return core.BNAllocString(core.cstr(self.name))
		except:
			# Not sure why your get_name() would throw but let's handle it anyway
			traceback.print_exc(file=sys.stderr)
			return core.BNAllocString(core.cstr(type(self).__name__))

	def _reset(self, ctxt: ctypes.c_void_p):
		try:
			self.reset()
		except:
			traceback.print_exc(file=sys.stderr)

	def _finished(self, ctxt: ctypes.c_void_p):
		try:
			self.finished()
		except:
			traceback.print_exc(file=sys.stderr)

	def _can_split(self, ctxt: ctypes.c_void_p, key: ctypes.c_char_p, conflict: core.BNAnalysisMergeConflictHandle) -> bool:
		try:
			py_conflict = MergeConflict(handle=conflict)
			return self.can_split(core.pyNativeStr(key), py_conflict)
		except:
			traceback.print_exc(file=sys.stderr)
			return False

	def _split(
		self,
		ctxt: ctypes.c_void_p,
		original_key: ctypes.c_char_p,
		original_conflict: core.BNAnalysisMergeConflictHandle,
		result_kvs: core.BNKeyValueStoreHandle,
		new_keys: ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p)),
		new_conflicts: ctypes.POINTER(core.BNAnalysisMergeConflictHandle),
		new_count: ctypes.POINTER(ctypes.c_size_t)
	) -> bool:
		try:
			py_original_conflict = MergeConflict(handle=original_conflict)
			py_result_kvs = KeyValueStore(handle=ctypes.cast(result_kvs, core.BNKeyValueStoreHandle))
			result = self.split(core.pyNativeStr(original_key), py_original_conflict, py_result_kvs)

			if result is None:
				return False

			new_count[0] = ctypes.c_size_t(len(result))
			new_keys[0] = (ctypes.c_char_p * len(result))()
			new_conflicts[0] = (core.BNAnalysisMergeConflictHandle * len(result))()

			self._split_keys = []
			self._split_conflicts = []

			for (i, (key, conflict)) in enumerate(result):
				self._split_keys.append(key)
				self._split_conflicts.append(conflict)

				new_keys[0][i] = core.cstr(self._split_keys[-1])
				new_conflicts[0][i] = self._split_conflicts[-1]._handle

			return True
		except:
			traceback.print_exc(file=sys.stderr)
			return False

	def _free_name(self, ctxt: ctypes.c_void_p, name: ctypes.c_char_p):
		core.BNFreeString(name)

	def _free_key_list(self, ctxt: ctypes.c_void_p, key_list: ctypes.POINTER(ctypes.c_char_p), count: ctypes.c_size_t):
		del self._split_keys

	def _free_conflict_list(self, ctxt: ctypes.c_void_p, conflict_list: core.BNAnalysisMergeConflictHandle, count: ctypes.c_size_t):
		del self._split_conflicts

	@property
	def name(self):
		"""
		Get a friendly name for the splitter

		:return: Name of the splitter
		"""
		return self.get_name()

	def get_name(self) -> str:
		"""
		Get a friendly name for the splitter

		:return: Name of the splitter
		"""
		return type(self).__name__

	def reset(self):
		"""
		Reset any internal state the splitter may hold during the merge
		"""
		return

	def finished(self):
		"""
		Clean up any internal state after the merge operation has finished
		"""
		return

	@abc.abstractmethod
	def can_split(self, key: str, conflict: MergeConflict) -> bool:
		"""
		Test if the splitter applies to a given conflict (by key).

		:param key: Key of the conflicting field
		:param conflict: Conflict data
		:return: True if this splitter should be used on the conflict
		"""
		raise NotImplementedError("Not implemented")

	@abc.abstractmethod
	def split(self, key: str, conflict: MergeConflict, result: KeyValueStore) -> Optional[Dict[str, MergeConflict]]:
		"""
		Split a field conflict into any number of alternate conflicts.
		Note: Returned conflicts will also be checked for splitting, beware infinite loops!
		If this function raises, it will be treated as returning None

		:param key: Original conflicting field's key
		:param conflict: Original conflict data
		:param result: Kvs structure containing the result of all splits. You should use the original conflict's
		               success() function in most cases unless you specifically want to write a new key to this.
		:return: A collection of conflicts into which the original conflict was split, or None if
		         this splitter cannot handle the conflict
		"""
		raise NotImplementedError("Not implemented")
