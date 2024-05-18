import ctypes
from typing import Optional

from .. import _binaryninjacore as core
from . import file, folder, merge, project, remote, snapshot, util

from ..database import Database, Snapshot
from ..filemetadata import FileMetadata

"""
Database syncing and choreography between BN api and remote
"""


def default_project_path(project_: 'project.RemoteProject') -> str:
	"""
	Get the default directory path for a remote Project. This is based off the Setting for
	collaboration.directory, the project's id, and the project's remote's id.

	:param project_: Remote Project
	:return: Default project path
	:raises RuntimeError: If there was an error
	"""
	value = core.BNCollaborationDefaultProjectPath(project_._handle)
	if value is None:
		raise RuntimeError(util._last_error())
	return value


def default_file_path(file_: 'file.RemoteFile') -> str:
	"""
	Get the default filepath for a remote File. This is based off the Setting for
	collaboration.directory, the file's id, the file's project's id, and the file's
	remote's id.

	:param file_: Remote File
	:return: Default file path
	:raises RuntimeError: If there was an error
	"""
	value = core.BNCollaborationDefaultFilePath(file_._handle)
	if value is None:
		raise RuntimeError(util._last_error())
	return value


def download_file(file_: 'file.RemoteFile', db_path: str, progress: 'util.ProgressFuncType' = util.nop) -> 'FileMetadata':
	"""
	Download a file from its remote, saving all snapshots to a database in the
	specified location. Returns a FileContext for opening the file later.

	:param file_: Remote File to download and open
	:param db_path: File path for saved database
	:param progress: Function to call for progress updates
	:return: FileContext for opening
	:raises RuntimeError: If there was an error
	"""
	value = core.BNCollaborationDownloadFile(file_._handle, db_path, util.wrap_progress(progress), None)
	if value is None:
		raise RuntimeError(util._last_error())
	return FileMetadata(handle=ctypes.cast(value, core.BNFileMetadataHandle))


def upload_database(metadata: 'FileMetadata', project: 'project.RemoteProject', parent_folder: Optional['folder.RemoteFolder'] = None, progress: 'util.ProgressFuncType' = util.nop, name_changeset: 'util.NameChangesetFuncType' = util.nop) -> 'file.RemoteFile':
	"""
	Upload a file, with database, to the remote under the given project

	:param metadata: Local file with database
	:param project: Remote project under which to place the new file
	:param progress: Function to call for progress updates
	:param name_changeset: Function to call for naming a pushed changeset, if necessary
	:param parent_folder: Optional parent folder in which to place this file
	:return: Remote File created
	:raises RuntimeError: If there was an error
	"""
	folder_handle = parent_folder._handle if parent_folder is not None else None
	value = core.BNCollaborationUploadDatabase(ctypes.cast(metadata.handle, core.BNFileMetadataHandle), project._handle, folder_handle, util.wrap_progress(progress), None, util.wrap_name_changeset(name_changeset), None)
	if value is None:
		raise RuntimeError(util._last_error())
	return file.RemoteFile(handle=value)


def is_collaboration_database(database: Database) -> bool:
	"""
	Test if a database is valid for use in collaboration

	:param database: Database to test
	:return: True if valid
	"""
	return core.BNCollaborationIsCollaborationDatabase(ctypes.cast(database.handle, core.BNDatabaseHandle))


def get_remote_for_local_database(database: Database) -> Optional['remote.Remote']:
	"""
	Get the Remote for a Database

	:param database: BN database, potentially with collaboration metadata
	:return: Remote from one of the connected remotes, or None if not found
	:raises RuntimeError: If there was an error
	"""
	value = core.BNRemoteHandle()
	if not core.BNCollaborationGetRemoteForLocalDatabase(ctypes.cast(database.handle, core.BNDatabaseHandle), value):
		raise RuntimeError(util._last_error())
	if not value:
		return None
	return remote.Remote(handle=value)


def get_remote_project_for_local_database(database: Database) -> Optional['project.RemoteProject']:
	"""
	Get the Remote Project for a Database

	:param database: BN database, potentially with collaboration metadata
	:return: Remote project from one of the connected remotes, or None if not found
	         or if projects are not pulled
	:raises RuntimeError: If there was an error
	"""
	value = core.BNRemoteProjectHandle()
	if not core.BNCollaborationGetRemoteProjectForLocalDatabase(ctypes.cast(database.handle, core.BNDatabaseHandle), value):
		raise RuntimeError(util._last_error())
	if not value:
		return None
	return project.RemoteProject(handle=value)


def get_remote_file_for_local_database(database: Database) -> Optional['file.RemoteFile']:
	"""
	Get the Remote File for a Database

	:param database: BN database, potentially with collaboration metadata
	:return: Remote file from one of the connected remotes, or None if not found
	         or if files are not pulled
	:raises RuntimeError: If there was an error
	"""
	value = core.BNRemoteFileHandle()
	if not core.BNCollaborationGetRemoteFileForLocalDatabase(ctypes.cast(database.handle, core.BNDatabaseHandle), value):
		raise RuntimeError(util._last_error())
	if not value:
		return None
	return file.RemoteFile(handle=value)


def assign_snapshot_map(local_snapshot: Snapshot, remote_snapshot: snapshot.CollabSnapshot):
	"""
	Add a snapshot to the id map in a database

	:param local_snapshot: Local snapshot, will use this snapshot's database
	:param remote_snapshot: Remote snapshot
	:raises RuntimeError: If there was an error
	"""
	if not core.BNCollaborationAssignSnapshotMap(ctypes.cast(local_snapshot.handle, core.BNSnapshotHandle), remote_snapshot._handle):
		raise RuntimeError(util._last_error())


def get_remote_snapshot_for_local(snap: Snapshot) -> Optional['snapshot.CollabSnapshot']:
	"""
	Get the remote snapshot associated with a local snapshot (if it exists)

	:param snap: Local snapshot
	:return: Remote snapshot if it exists, or None if not
	:raises RuntimeError: If there was an error
	"""
	value = core.BNCollaborationSnapshotHandle()
	if not core.BNCollaborationGetRemoteSnapshotFromLocal(ctypes.cast(snap.handle, core.BNSnapshotHandle), value):
		raise RuntimeError(util._last_error())
	if not value:
		return None
	return snapshot.CollabSnapshot(handle=value)


def get_local_snapshot_for_remote(snapshot: snapshot.CollabSnapshot, database: Database) -> Optional['Snapshot']:
	"""
	Get the local snapshot associated with a remote snapshot (if it exists)

	:param snapshot: Remote snapshot
	:param database: Local database to search
	:return: Snapshot reference if it exists, or None reference if not
	:raises RuntimeError: If there was an error
	"""
	value = core.BNSnapshotHandle()
	if not core.BNCollaborationGetLocalSnapshotFromRemote(snapshot._handle, ctypes.cast(database.handle, core.BNSnapshotHandle), value):
		raise RuntimeError(util._last_error())
	if not value:
		return None
	return Snapshot(handle=ctypes.cast(value, ctypes.POINTER(core.BNSnapshot)))


def sync_database(database: Database, file_: 'file.RemoteFile', conflict_handler: 'util.ConflictHandlerType', progress: 'util.ProgressFuncType' = util.nop, name_changeset: 'util.NameChangesetFuncType' = util.nop):
	"""
	Completely sync a database, pushing/pulling/merging/applying changes

	:param database: Database to sync
	:param file_: File to sync with
	:param conflict_handler: Function to call to resolve snapshot conflicts
	:param progress: Function to call for progress updates
	:param name_changeset: Function to call for naming a pushed changeset, if necessary
	:raises RuntimeError: If there was an error (or the operation was cancelled)
	"""

	if not core.BNCollaborationSyncDatabase(ctypes.cast(database.handle, core.BNDatabaseHandle), file_._handle, util.wrap_conflict_handler(conflict_handler), None, util.wrap_progress(progress), None, util.wrap_name_changeset(name_changeset), None):
		raise RuntimeError(util._last_error())


def pull_database(database: Database, file_: 'file.RemoteFile', conflict_handler: 'util.ConflictHandlerType', progress: 'util.ProgressFuncType' = util.nop, name_changeset: 'util.NameChangesetFuncType' = util.nop):
	"""
	Pull updated snapshots from the remote. Merge local changes with remote changes and
	potentially create a new snapshot for unsaved changes, named via name_changeset.

	:param database: Database to pull
	:param file_: Remote File to pull to
	:param conflict_handler: Function to call to resolve snapshot conflicts
	:param progress: Function to call for progress updates
	:param name_changeset: Function to call for naming a pushed changeset, if necessary
	:raises RuntimeError: If there was an error (or the operation was cancelled)
	"""
	count = ctypes.c_ulonglong()
	if not core.BNCollaborationPullDatabase(ctypes.cast(database.handle, core.BNDatabaseHandle), file_._handle, count, util.wrap_conflict_handler(conflict_handler), None, util.wrap_progress(progress), None, util.wrap_name_changeset(name_changeset), None):
		raise RuntimeError(util._last_error())


def merge_database(database: Database, conflict_handler: 'util.ConflictHandlerType', progress: 'util.ProgressFuncType' = util.nop):
	"""
	Merge all leaf snapshots in a database down to a single leaf snapshot.

	:param database: Database to merge
	:param conflict_handler: Function to call for progress updates
	:param progress: Function to call to resolve snapshot conflicts
	:raises RuntimeError: If there was an error (or the operation was cancelled)
	"""
	if not core.BNCollaborationMergeDatabase(ctypes.cast(database.handle, core.BNDatabaseHandle), util.wrap_conflict_handler(conflict_handler), None, util.wrap_progress(progress), None):
		raise RuntimeError(util._last_error())


def push_database(database: Database, file_: 'file.RemoteFile', progress: 'util.ProgressFuncType' = util.nop):
	"""
	Push locally added snapshots to the remote

	:param database: Database to push
	:param file_: Remote File to push to
	:param progress: Function to call for progress updates
	:raises RuntimeError: If there was an error (or the operation was cancelled)
	"""
	count = ctypes.c_ulonglong()
	if not core.BNCollaborationPushDatabase(ctypes.cast(database.handle, core.BNDatabaseHandle), file_._handle, count, util.wrap_progress(progress), None):
		raise RuntimeError(util._last_error())


def dump_database(database: Database):
	"""
	Print debug information about a database to stdout

	:param database: Database to dump
	:raises RuntimeError: If there was an error
	"""
	if not core.BNCollaborationDumpDatabase(ctypes.cast(database.handle, core.BNDatabaseHandle)):
		raise RuntimeError(util._last_error())


def ignore_snapshot(database: Database, snapshot: Snapshot):
	"""
	Ignore a snapshot from database syncing operations

	:param database: Parent database
	:param snapshot: Snapshot to ignore
	:raises RuntimeError: If there was an error
	"""
	if not core.BNCollaborationIgnoreSnapshot(ctypes.cast(database.handle, core.BNDatabaseHandle), ctypes.cast(snapshot.handle, core.BNSnapshotHandle)):
		raise RuntimeError(util._last_error())


def is_snapshot_ignored(database: Database, snapshot: Snapshot) -> bool:
	"""
	Test if a snapshot is ignored from the database

	:param database: Parent database
	:param snapshot: Snapshot to test
	:return: True if snapshot should be ignored
	:raises RuntimeError: If there was an error
	"""
	return core.BNCollaborationIsSnapshotIgnored(ctypes.cast(database.handle, core.BNDatabaseHandle), ctypes.cast(snapshot.handle, core.BNSnapshotHandle))


def get_snapshot_author(database: Database, snapshot: Snapshot) -> Optional[str]:
	"""
	Get the remote author of a local snapshot

	:param database: Parent database
	:param snapshot: Snapshot to query
	:return: Remote author, or None if one could not be determined
	:raises RuntimeError: If there was an error
	"""
	value = ctypes.POINTER(ctypes.c_char_p)()
	if not core.BNCollaborationGetSnapshotAuthor(ctypes.cast(database.handle, core.BNDatabaseHandle), ctypes.cast(snapshot.handle, core.BNSnapshotHandle), value):
		raise RuntimeError(util._last_error())
	if value is None:
		return None
	return core.pyNativeStr(value)


def set_snapshot_author(database: Database, snapshot: Snapshot, author: str):
	"""
	Set the remote author of a local snapshot (does not upload)

	:param database: Parent database
	:param snapshot: Snapshot to edit
	:param author: Target author
	:raises RuntimeError: If there was an error
	"""
	if not core.BNCollaborationSetSnapshotAuthor(ctypes.cast(database.handle, core.BNDatabaseHandle), ctypes.cast(snapshot.handle, core.BNSnapshotHandle), author):
		raise RuntimeError(util._last_error())

