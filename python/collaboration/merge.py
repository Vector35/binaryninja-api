import abc
import ctypes
import json
import sys
import traceback
from typing import Dict, Optional

from .. import _binaryninjacore as core
from ..enums import MergeConflictDataType
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
