import ctypes
import datetime
from typing import List, Optional

from .. import _binaryninjacore as core
from ..binaryview import BinaryView
from ..database import Snapshot
from . import databasesync, file, project, remote, util

class CollabSnapshot:
	"""
	Class representing a remote Snapshot
	"""
	def __init__(self, handle: core.BNCollaborationSnapshotHandle):
		self._handle = ctypes.cast(handle, core.BNCollaborationSnapshotHandle)

	def __del__(self):
		if core is not None:
			core.BNFreeCollaborationSnapshot(self._handle)

	def __eq__(self, other):
		if not isinstance(other, CollabSnapshot):
			return False
		return other.id == self.id

	def __str__(self):
		return f'<snapshot: {self.name} @ {self.remote.name}.{self.project.name}.{self.file.name}>'

	def __repr__(self):
		return f'<snapshot: {self.name} @ {self.remote.name}.{self.project.name}.{self.file.name}>'

	@staticmethod
	def get_for_local_snapshot(snapshot: 'Snapshot') -> Optional['CollabSnapshot']:
		"""
		Get the remote snapshot associated with a local snapshot (if it exists)

		:param snap: Local snapshot
		:return: Remote snapshot if it exists, or None if not
		:raises RuntimeError: If there was an error
		"""
		return databasesync.get_remote_snapshot_for_local(snapshot)

	@property
	def file(self) -> 'file.RemoteFile':
		"""
		Owning File

		:return: File object
		"""
		value = core.BNCollaborationSnapshotGetFile(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return file.RemoteFile(handle=value)

	@property
	def project(self) -> 'project.RemoteProject':
		"""
		Owning Project

		:return: Project object
		"""
		value = core.BNCollaborationSnapshotGetProject(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return project.RemoteProject(handle=value)

	@property
	def remote(self) -> 'remote.Remote':
		"""
		Owning Remote

		:return: Remote object
		"""
		value = core.BNCollaborationSnapshotGetRemote(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return remote.Remote(handle=value)

	@property
	def url(self) -> str:
		"""
		Web api endpoint url

		:return:
		"""
		return core.BNCollaborationSnapshotGetUrl(self._handle)

	@property
	def id(self) -> str:
		"""
		Unique id

		:return: Id string
		"""
		return core.BNCollaborationSnapshotGetId(self._handle)

	@property
	def name(self) -> str:
		"""
		Name of snapshot

		:return: Name string
		"""
		return core.BNCollaborationSnapshotGetName(self._handle)

	@property
	def title(self) -> str:
		"""
		Get the title of a snapshot: the first line of its name

		:return: Snapshot title as described
		"""
		return core.BNCollaborationSnapshotGetTitle(self._handle)

	@property
	def description(self) -> str:
		"""
		Get the description of a snapshot: the lines of its name after the first line

		:return: Snapshot description as described
		"""
		return core.BNCollaborationSnapshotGetDescription(self._handle)

	@property
	def author(self) -> str:
		"""
		Get the user id of the author of a snapshot

		:return: Snapshot author user id
		"""
		return core.BNCollaborationSnapshotGetAuthor(self._handle)

	@property
	def author_username(self) -> str:
		"""
		Get the username of the author of a snapshot, if possible (vs author which is user id)

		:return: Snapshot author username
		"""
		return core.BNCollaborationSnapshotGetAuthorUsername(self._handle)

	@property
	def created(self) -> datetime.datetime:
		"""
		Created date of Snapshot

		:return: Created date
		"""
		return datetime.datetime.utcfromtimestamp(core.BNCollaborationSnapshotGetCreated(self._handle))

	@property
	def last_modified(self) -> datetime.datetime:
		"""
		Date of last modification to the snapshot

		:return: Last modified date
		"""
		return datetime.datetime.utcfromtimestamp(core.BNCollaborationSnapshotGetLastModified(self._handle))

	@property
	def hash(self) -> str:
		"""
		Hash of snapshot data (analysis and markup, etc)
		No specific hash algorithm is guaranteed

		:return: Hash string
		"""
		return core.BNCollaborationSnapshotGetHash(self._handle)

	@property
	def snapshot_file_hash(self) -> str:
		"""
		Hash of file contents in snapshot
		No specific hash algorithm is guaranteed

		:return: Hash string
		"""
		return core.BNCollaborationSnapshotGetSnapshotFileHash(self._handle)

	@property
	def has_pulled_undo_entires(self) -> bool:
		"""
		If the snapshot has pulled undo entries yet

		:return: True if they have been pulled
		"""
		return core.BNCollaborationSnapshotHasPulledUndoEntries(self._handle)

	@property
	def is_finalized(self) -> bool:
		"""
		If the snapshot has been finalized on the server and is no longer editable

		:return: True if finalized
		"""
		return core.BNCollaborationSnapshotIsFinalized(self._handle)

	@property
	def parent_ids(self) -> List[str]:
		"""
		List of ids of all remote parent Snapshots

		:return: List of id strings
		:raises: RuntimeError if there was an error
		"""
		count = ctypes.c_size_t()
		value = core.BNCollaborationSnapshotGetParentIds(self._handle, count)
		if not value:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(value[i])
		return result

	@property
	def child_ids(self) -> List[str]:
		"""
		List of ids of all remote child Snapshots

		:return: List of id strings
		:raises: RuntimeError if there was an error
		"""
		count = ctypes.c_size_t()
		value = core.BNCollaborationSnapshotGetChildIds(self._handle, count)
		if not value:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(value[i])
		return result

	@property
	def parents(self) -> List['CollabSnapshot']:
		"""
		List of all parent Snapshot objects

		:return: List of Snapshot objects
		:raises: RuntimeError if there was an error
		"""
		count = ctypes.c_size_t()
		value = core.BNCollaborationSnapshotGetParents(self._handle, count)
		if not value:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(CollabSnapshot(handle=value[i]))
		return result

	@property
	def children(self) -> List['CollabSnapshot']:
		"""
		List of all child Snapshot objects

		:return: List of Snapshot objects
		:raises: RuntimeError if there was an error
		"""
		count = ctypes.c_size_t()
		value = core.BNCollaborationSnapshotGetChildren(self._handle, count)
		if not value:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(CollabSnapshot(handle=value[i]))
		return result

	@property
	def undo_entries(self) -> List['UndoEntry']:
		"""
		Get the list of undo entries stored in this snapshot.

		.. note:: If undo entries have not been pulled, they will be pulled upon calling this.

		:return: List of UndoEntry objects
		:raises: RuntimeError if there was an error pulling undo entries
		"""
		if not self.has_pulled_undo_entires:
			self.pull_undo_entries()

		count = ctypes.c_size_t()
		value = core.BNCollaborationSnapshotGetUndoEntries(self._handle, count)
		if not value:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(UndoEntry(handle=value[i]))
		return result

	def get_undo_entry_by_id(self, id: int) -> Optional['UndoEntry']:
		"""
		Get a specific Undo Entry in the Snapshot by its id

		.. note:: If undo entries have not been pulled, they will be pulled upon calling this.

		:param id: Id of Undo Entry
		:return: UndoEntry object, if one with that id exists. Else, None
		:raises: RuntimeError if there was an error pulling undo entries
		"""
		if not self.has_pulled_undo_entires:
			self.pull_undo_entries()

		value = core.BNCollaborationSnapshotGetUndoEntryById(self._handle, id)
		if value is None:
			return None
		return UndoEntry(value)

	def pull_undo_entries(self, progress: 'util.ProgressFuncType' = util.nop):
		"""
		Pull the list of Undo Entries from the Remote.

		:param progress: Function to call for progress updates
		:raises: RuntimeError if there was an error pulling undo entries
		"""
		if not core.BNCollaborationSnapshotPullUndoEntries(self._handle, util.wrap_progress(progress), None):
			raise RuntimeError(util._last_error())

	def create_undo_entry(self, parent: Optional[int], data: str) -> 'UndoEntry':
		"""
		Create a new Undo Entry in this snapshot.

		:param parent: Id of parent Undo Entry
		:param data: Undo Entry contents
		:return: Created Undo Entry
		:raises: RuntimeError if there was an error
		"""
		value = core.BNCollaborationSnapshotCreateUndoEntry(self._handle, parent is not None, parent if parent is not None else 0, data)
		if value is None:
			raise RuntimeError(util._last_error())
		return UndoEntry(value)

	def finalize(self):
		"""
		Mark a snapshot as Finalized, committing it to the Remote, preventing future updates,
		and allowing snapshots to be children of it.

		:raises: RuntimeError if there was an error
		"""
		if not core.BNCollaborationSnapshotFinalize(self._handle):
			raise RuntimeError(util._last_error())

	def download_snapshot_file(self, progress: 'util.ProgressFuncType' = util.nop) -> bytes:
		"""
		Download the contents of the file in the Snapshot.

		:param progress: Function to call for progress updates. Cancels if the function returns False.
		:return: File contents data
		:raises: RuntimeError if there was an error or the operation was cancelled
		"""
		data = ctypes.POINTER(ctypes.c_uint8)()
		size = ctypes.c_size_t()
		if not core.BNCollaborationSnapshotDownloadSnapshotFile(self._handle, util.wrap_progress(progress), None, data, size):
			raise RuntimeError(util._last_error())
		return bytes(ctypes.cast(data, ctypes.POINTER(ctypes.c_uint8 * size.value)).contents)

	def download(self, progress: 'util.ProgressFuncType' = util.nop) -> bytes:
		"""
		Download the snapshot fields blob, compatible with KeyValueStore.

		:param progress: Function to call for progress updates. Cancels if the function returns False.
		:return: Snapshot contents data
		:raises: RuntimeError if there was an error or the operation was cancelled
		"""
		data = ctypes.POINTER(ctypes.c_uint8)()
		size = ctypes.c_size_t()
		if not core.BNCollaborationSnapshotDownload(self._handle, util.wrap_progress(progress), None, data, size):
			raise RuntimeError(util._last_error())
		return bytes(ctypes.cast(data, ctypes.POINTER(ctypes.c_uint8 * size.value)).contents)

	def download_analysis_cache(self, progress: 'util.ProgressFuncType' = util.nop) -> bytes:
		"""
		Download the analysis cache fields blob, compatible with KeyValueStore.

		:param progress: Function to call for progress updates. Cancels if the function returns False.
		:return: Snapshot analysis cache data
		:raises: RuntimeError if there was an error or the operation was cancelled
		"""
		data = ctypes.POINTER(ctypes.c_uint8)()
		size = ctypes.c_size_t()
		if not core.BNCollaborationSnapshotDownloadAnalysisCache(self._handle, util.wrap_progress(progress), None, data, size):
			raise RuntimeError(util._last_error())
		return bytes(ctypes.cast(data, ctypes.POINTER(ctypes.c_uint8 * size.value)).contents)

	def get_local_snapshot(self, bv: 'BinaryView') -> Optional['Snapshot']:
		"""
		Get the local snapshot associated with a remote snapshot (if it exists)

		:param bv: BinaryView with database to search
		:return: Local snapshot, if one exists. Else, None
		:raises: RuntimeError if there was an error
		"""
		if not bv.file.has_database:
			return None
		db = bv.file.database
		if db is None:
			return None
		return databasesync.get_local_snapshot_for_remote(self, db)


class UndoEntry:
	"""
	Class representing a remote undo entry
	"""
	def __init__(self, handle: core.BNCollaborationUndoEntryHandle):
		self._handle = ctypes.cast(handle, core.BNCollaborationUndoEntryHandle)

	def __del__(self):
		if core is not None:
			core.BNFreeCollaborationUndoEntry(self._handle)

	def __eq__(self, other):
		if not isinstance(other, UndoEntry):
			return False
		return other.id == self.id

	@property
	def snapshot(self) -> 'CollabSnapshot':
		"""
		Owning Snapshot

		:return: Snapshot object
		"""
		value = core.BNCollaborationUndoEntryGetSnapshot(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return CollabSnapshot(handle=value)

	@property
	def file(self) -> 'file.RemoteFile':
		"""
		Owning File

		:return: File object
		"""
		value = core.BNCollaborationUndoEntryGetFile(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return file.RemoteFile(handle=value)

	@property
	def project(self) -> 'project.RemoteProject':
		"""
		Owning Project

		:return: Project object
		"""
		value = core.BNCollaborationUndoEntryGetProject(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return project.RemoteProject(handle=value)

	@property
	def remote(self) -> 'remote.Remote':
		"""
		Owning Remote

		:return: Remote object
		"""
		value = core.BNCollaborationUndoEntryGetRemote(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return remote.Remote(handle=value)

	@property
	def url(self) -> str:
		"""
		Web api endpoint url

		:return: URL String
		"""
		return core.BNCollaborationUndoEntryGetUrl(self._handle)

	@property
	def id(self) -> int:
		"""
		Unique id

		:return: Id number
		"""
		return core.BNCollaborationUndoEntryGetId(self._handle)

	@property
	def parent_id(self) -> Optional[int]:
		"""
		Id of parent undo entry

		:return: Parent id number, if there is one, None otherwise
		"""
		id = ctypes.c_uint64()
		if not core.BNCollaborationUndoEntryGetParentId(self._handle, id):
			return None
		return id.value

	@property
	def data(self) -> str:
		"""
		Undo entry contents data

		:return: Data string
		"""
		data = ctypes.c_char_p()
		if not core.BNCollaborationUndoEntryGetData(self._handle, data):
			raise RuntimeError(util._last_error())
		return str(core.pyNativeStr(data.value))

	@property
	def parent(self) -> Optional['UndoEntry']:
		"""
		Parent Undo Entry object

		:return: Undo Entry object, if there is one, None otherwise
		"""
		value = core.BNCollaborationUndoEntryGetParent(self._handle)
		if value is None:
			return None
		return UndoEntry(handle=value)
