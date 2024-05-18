import ctypes
import datetime
from typing import List, Optional, Union

from .. import _binaryninjacore as core
from .. import enums
from . import databasesync
from . import folder as _folder
from . import project, remote, snapshot, util


from ..binaryview import BinaryView
from ..database import Database
from ..filemetadata import FileMetadata
from ..project import ProjectFile


class RemoteFile:
	"""
	Class representing a remote project file. It controls the various
	snapshots and raw file contents associated with the analysis.
	"""
	def __init__(self, handle: core.BNRemoteFileHandle):
		self._handle = ctypes.cast(handle, core.BNRemoteFileHandle)

	def __del__(self):
		if core is not None:
			core.BNFreeRemoteFile(self._handle)

	def __eq__(self, other):
		if not isinstance(other, RemoteFile):
			return False
		return other.id == self.id

	def __str__(self):
		path = self.name
		parent = self.folder
		while parent is not None:
			path = parent.name + '/' + path
			parent = parent.parent
		return f'<file: {self.remote.name}/{self.project.name}/{path}>'

	def __repr__(self):
		path = self.name
		parent = self.folder
		while parent is not None:
			path = parent.name + '/' + path
			parent = parent.parent
		return f'<file: {self.remote.name}/{self.project.name}/{path}>'

	@staticmethod
	def get_for_local_database(database: 'Database') -> Optional['RemoteFile']:
		"""
		Look up the remote File for a local database, or None if there is no matching
		remote File found.
		See :func:`get_for_bv` to load from a BinaryView.

		:param database: Local database
		:return: Remote File object
		:rtype: File or None
		"""
		remote = databasesync.get_remote_for_local_database(database)
		if remote is None:
			return None
		if not remote.has_pulled_projects:
			remote.pull_projects()
		project = databasesync.get_remote_project_for_local_database(database)
		if project is None:
			return None
		if not project.has_pulled_files:
			project.pull_files()
		return databasesync.get_remote_file_for_local_database(database)

	@staticmethod
	def get_for_bv(bv: 'BinaryView') -> Optional['RemoteFile']:
		"""
		Look up the remote File for a local BinaryView, or None if there is no matching
		remote File found.

		:param bv: Local BinaryView
		:return: Remote File object
		:rtype: File or None
		"""
		if not bv.file.has_database:
			return None
		return RemoteFile.get_for_local_database(bv.file.database)

	@property
	def core_file(self) -> 'ProjectFile':
		core_handle = core.BNRemoteFileGetCoreFile(self._handle)
		if core_handle is None:
			raise RuntimeError(util._last_error())
		return ProjectFile(handle=ctypes.cast(core_handle, ctypes.POINTER(core.BNProjectFile)))

	@property
	def project(self) -> 'project.RemoteProject':
		"""
		Owning Project

		:return: Project object
		"""
		value = core.BNRemoteFileGetProject(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return project.RemoteProject(handle=value)

	@property
	def remote(self) -> 'remote.Remote':
		"""
		Owning Remote

		:return: Remote object
		"""
		value = core.BNRemoteFileGetRemote(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return remote.Remote(handle=value)

	@property
	def folder(self) -> Optional['_folder.RemoteFolder']:
		"""
		Parent folder, if one exists. None if this is in the root of the project.

		:return: Folder object or None
		"""
		if not self.project.has_pulled_folders:
			self.project.pull_folders()
		value = core.BNRemoteFileGetFolder(self._handle)
		if value is None:
			return None
		return _folder.RemoteFolder(handle=value)

	@folder.setter
	def folder(self, folder: Optional['_folder.RemoteFolder']):
		"""
		Set the parent folder of a file.

		:param folder: New parent folder, or None to move file to the root of the project.
		"""
		folder_handle = folder._handle if folder is not None else None
		if not core.BNRemoteFileSetFolder(self._handle, folder_handle):
			raise RuntimeError(util._last_error())

	@property
	def url(self) -> str:
		"""
		Web api endpoint URL

		:return: URL string
		"""
		return core.BNRemoteFileGetUrl(self._handle)

	@property
	def chat_log_url(self) -> str:
		"""
		Chat log api endpoint URL

		:return: URL string
		"""
		return core.BNRemoteFileGetChatLogUrl(self._handle)

	@property
	def id(self) -> str:
		"""
		Unique id

		:return: Id string
		"""
		return core.BNRemoteFileGetId(self._handle)

	@property
	def type(self) -> enums.RemoteFileType:
		"""
		File Type
		All files share the same properties, but files with different types may make different
		uses of those properties, or not use some of them at all.

		:return: Type of file on server (enum)
		"""
		return enums.RemoteFileType(core.BNRemoteFileGetType(self._handle))

	@property
	def created(self) -> datetime.datetime:
		"""
		Created date of the file

		:return: Date object
		"""
		return datetime.datetime.utcfromtimestamp(core.BNRemoteFileGetCreated(self._handle))

	@property
	def last_modified(self) -> datetime.datetime:
		"""
		Last modified date of the file

		:return: Date object
		"""
		return datetime.datetime.utcfromtimestamp(core.BNRemoteFileGetLastModified(self._handle))

	@property
	def last_snapshot(self) -> datetime.datetime:
		"""
		Date of last snapshot in the file

		:return: Date object
		"""
		return datetime.datetime.utcfromtimestamp(core.BNRemoteFileGetLastSnapshot(self._handle))

	@property
	def last_snapshot_by(self) -> str:
		"""
		Username of user who pushed the last snapshot in the file

		:return: Username string
		"""
		return core.BNRemoteFileGetLastSnapshotBy(self._handle)

	@property
	def hash(self) -> str:
		"""
		Hash of file contents (no algorithm guaranteed)

		:return: Hash string
		"""
		return core.BNRemoteFileGetHash(self._handle)

	@property
	def name(self) -> str:
		"""
		Displayed name of file

		:return: Name string
		"""
		return core.BNRemoteFileGetName(self._handle)

	@name.setter
	def name(self, value: str):
		"""
		Set the display name of the file. You will need to push the file to update the remote version.

		:param value: New name
		"""
		if not core.BNRemoteFileSetName(self._handle, value):
			raise RuntimeError(util._last_error())

	@property
	def description(self) -> str:
		"""
		Description of the file

		:return: Description string
		"""
		return core.BNRemoteFileGetDescription(self._handle)

	@description.setter
	def description(self, value: str):
		"""
		Set the description of the file. You will need to push the file to update the remote version.

		:param description: New description
		"""
		if not core.BNRemoteFileSetDescription(self._handle, value):
			raise RuntimeError(util._last_error())

	@property
	def size(self) -> int:
		"""
		Size of raw content of file, in bytes

		:return: Size in bytes
		"""
		return core.BNRemoteFileGetSize(self._handle)

	@property
	def default_path(self) -> str:
		"""
		Get the default filepath for a remote File. This is based off the Setting for
		collaboration.directory, the file's id, the file's project's id, and the file's
		remote's id.

		:return: Default file path
		:rtype: str
		"""
		return databasesync.default_file_path(self)

	@property
	def has_pulled_snapshots(self) -> bool:
		"""
		If the file has pulled the snapshots yet

		:return: True if they have been pulled
		"""
		return core.BNRemoteFileHasPulledSnapshots(self._handle)

	@property
	def snapshots(self) -> List['snapshot.CollabSnapshot']:
		"""
		Get the list of snapshots in this file.

		.. note:: If snapshots have not been pulled, they will be pulled upon calling this.

		:return: List of Snapshot objects
		:raises: RuntimeError if there was an error pulling snapshots
		"""
		if not self.has_pulled_snapshots:
			self.pull_snapshots()

		count = ctypes.c_size_t()
		value = core.BNRemoteFileGetSnapshots(self._handle, count)
		if value is None:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(snapshot.CollabSnapshot(value[i]))
		return result

	def get_snapshot_by_id(self, id: str) -> Optional['snapshot.CollabSnapshot']:
		"""
		Get a specific Snapshot in the File by its id

		.. note:: If snapshots have not been pulled, they will be pulled upon calling this.

		:param id: Id of Snapshot
		:return: Snapshot object, if one with that id exists. Else, None
		:raises: RuntimeError if there was an error pulling snapshots
		"""
		if not self.has_pulled_snapshots:
			self.pull_snapshots()

		value = core.BNRemoteFileGetSnapshotById(self._handle, id)
		if value is None:
			return None
		return snapshot.CollabSnapshot(value)

	def pull_snapshots(self, progress: 'util.ProgressFuncType' = util.nop):
		"""
		Pull the list of Snapshots from the Remote.

		:param progress: Function to call for progress updates
		:raises: RuntimeError if there was an error pulling snapshots
		"""
		if not core.BNRemoteFilePullSnapshots(self._handle, util.wrap_progress(progress), None):
			raise RuntimeError(util._last_error())

	def create_snapshot(self, name: str, contents: bytes, analysis_cache_contents: bytes, file: bytes, parent_ids: List[str], progress: 'util.ProgressFuncType' = util.nop) -> 'snapshot.CollabSnapshot':
		"""
		Create a new snapshot on the remote (and pull it)

		:param name: Snapshot name
		:param contents: Snapshot contents
		:param analysis_cache_contents: Contents of analysis cache of snapshot
		:param file: New file contents (if contents changed)
		:param parent_ids: List of ids of parent snapshots (or empty if this is a root snapshot)
		:param progress: Function to call on progress updates
		:return: Reference to the created snapshot
		:raises: RuntimeError if there was an error
		"""
		array = (ctypes.c_char_p * len(parent_ids))()
		for i in range(len(parent_ids)):
			array[i] = parent_ids[i]

		value = core.BNRemoteFileCreateSnapshot(self._handle, name, contents, len(contents), analysis_cache_contents, len(analysis_cache_contents), file, len(file), array, len(parent_ids), util.wrap_progress(progress), None)
		if value is None:
			raise RuntimeError(util._last_error())
		return snapshot.CollabSnapshot(value)

	def delete_snapshot(self, snapshot: 'snapshot.CollabSnapshot'):
		"""
		Delete a snapshot from the remote

		:param snapshot: Snapshot to delete
		:raises: RuntimeError if there was an error
		"""
		if not core.BNRemoteFileDeleteSnapshot(self._handle, snapshot._handle):
			raise RuntimeError(util._last_error())

	def download(self, progress: 'util.ProgressFuncType' = util.nop) -> bytes:
		"""
		Download the contents of a remote file

		:param progress: Function to call on progress updates
		:return: Contents of the file
		:raises: RuntimeError if there was an error
		"""
		data = (ctypes.POINTER(ctypes.c_ubyte))()
		size = ctypes.c_size_t()
		value = core.BNRemoteFileDownload(self._handle, util.wrap_progress(progress), None, data, size)
		if not value:
			raise RuntimeError(util._last_error())
		return bytes(ctypes.cast(data, ctypes.POINTER(ctypes.c_uint8 * size.value)).contents)

	def download_to_bndb(self, path: Optional[str] = None, progress: 'util.ProgressFuncType' = util.nop) -> FileMetadata:
		"""
		Download a remote file and save it to a bndb at the given path.
		This calls databasesync.download_file and self.sync to fully prepare the bndb.

		:param path: Path to new bndb to create
		:param progress: Function to call on progress updates
		:return: Constructed FileMetadata object
		:raises: RuntimeError if there was an error
		"""
		if path is None:
			path = self.default_path
		file = databasesync.download_file(self, path, util.split_progress(progress, 0, [0.5, 0.5]))
		self.sync(
			file.database, lambda conflicts: False, util.split_progress(progress, 1, [0.5, 0.5]))
		return file

	def sync(self, bv_or_db: Union['BinaryView', 'Database'], conflict_handler: 'util.ConflictHandlerType', progress: 'util.ProgressFuncType' = util.nop, name_changeset: 'util.NameChangesetFuncType' = util.nop):
		"""
		Completely sync a file, pushing/pulling/merging/applying changes

		:param bv_or_db: Binary view or database to sync with
		:param conflict_handler: Function to call to resolve snapshot conflicts
		:param name_changeset: Function to call for naming a pushed changeset, if necessary
		:param progress: Function to call for progress updates
		:raises RuntimeError: If there was an error (or the operation was cancelled)
		"""
		if isinstance(bv_or_db, BinaryView):
			if not bv_or_db.file.has_database:
				raise RuntimeError("Cannot sync non-database view")
			db = bv_or_db.file.database
		else:
			db = bv_or_db
		databasesync.sync_database(db, self, conflict_handler, progress, name_changeset)

	def pull(self, bv_or_db: Union['BinaryView', 'Database'], conflict_handler: 'util.ConflictHandlerType', progress: 'util.ProgressFuncType' = util.nop, name_changeset: 'util.NameChangesetFuncType' = util.nop):
		"""
		Pull updated snapshots from the remote. Merge local changes with remote changes and
		potentially create a new snapshot for unsaved changes, named via name_changeset.

		:param bv_or_db: Binary view or database to sync with
		:param conflict_handler: Function to call to resolve snapshot conflicts
		:param name_changeset: Function to call for naming a pushed changeset, if necessary
		:param progress: Function to call for progress updates
		:raises RuntimeError: If there was an error (or the operation was cancelled)
		"""
		if isinstance(bv_or_db, BinaryView):
			if not bv_or_db.file.has_database:
				raise RuntimeError("Cannot pull non-database view")
			db = bv_or_db.file.database
		else:
			db = bv_or_db
		databasesync.pull_database(db, self, conflict_handler, progress, name_changeset)

	def push(self, bv_or_db: Union['BinaryView', 'Database'], progress: 'util.ProgressFuncType' = util.nop):
		"""
		Push locally added snapshots to the remote

		:param bv_or_db: Binary view or database to sync with
		:param progress: Function to call for progress updates
		:raises RuntimeError: If there was an error (or the operation was cancelled)
		"""
		if isinstance(bv_or_db, BinaryView):
			if not bv_or_db.file.has_database:
				raise RuntimeError("Cannot pull non-database view")
			db = bv_or_db.file.database
		else:
			db = bv_or_db
		databasesync.push_database(db, self, progress)
