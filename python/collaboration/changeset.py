
import ctypes
from typing import List

from .. import _binaryninjacore as core
from ..database import Database
from . import file, user, util


class Changeset:
	"""
	Class representing a collection of snapshots in a local database
	"""
	def __init__(self, handle: core.BNCollaborationChangesetHandle):
		"""
			:param handle: FFI handle for internal use
		"""
		self._handle = ctypes.cast(handle, core.BNCollaborationChangesetHandle)

	def __del__(self):
		if core is not None:
			core.BNFreeCollaborationChangeset(self._handle)

	@property
	def database(self) -> 'Database':
		"""
		Owning database for snapshots

		:return: Database object
		"""
		value = core.BNCollaborationChangesetGetDatabase(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		result = Database(handle=value)
		return result

	@property
	def file(self) -> 'file.RemoteFile':
		"""
		Relevant remote File object

		:return: File object
		"""
		value = core.BNCollaborationChangesetGetFile(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return file.RemoteFile(handle=value)

	@property
	def snapshot_ids(self) -> List[int]:
		"""
		List of snapshot ids in the database

		:return: Snapshot id list
		"""
		count = ctypes.c_size_t()
		snapshot_ids = core.BNCollaborationChangesetGetSnapshotIds(self._handle, count)
		if snapshot_ids is None:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(snapshot_ids[i])
		core.BNCollaborationFreeSnapshotIdList(snapshot_ids, count.value)
		return result

	@property
	def author(self) -> 'user.User':
		"""
		Relevant remote author User

		:return: Author User
		"""
		value = core.BNCollaborationChangesetGetAuthor(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return user.User(handle=value)

	@property
	def name(self) -> str:
		"""
		Changeset name

		:return: Name string
		"""
		return core.BNCollaborationChangesetGetName(self._handle)

	@name.setter
	def name(self, name: str):
		"""
		Set the name of the changeset, e.g. in a name changeset function.

		:param name: New changeset name
		"""
		core.BNCollaborationChangesetSetName(self._handle, name)
