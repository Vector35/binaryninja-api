import ctypes
import datetime
import tempfile
from os import PathLike
from pathlib import Path
from typing import Dict, List, Optional, Union

from .. import _binaryninjacore as core
from .. import enums, load, log_info
from ..binaryview import BinaryView, ProgressFuncType
from ..database import Database
from ..filemetadata import FileMetadata
from ..project import Project
from . import databasesync, file, folder, permission, remote, util


def _nop(*args, **kwargs):
	"""
	Function that just returns True, used as default for callbacks

	:return: True
	"""
	return True


class RemoteProject:
	"""
	Class representing a remote project
	"""
	def __init__(self, handle: core.BNRemoteProjectHandle):
		self._handle = ctypes.cast(handle, core.BNRemoteProjectHandle)

	def __del__(self):
		if self._handle is not None:
			core.BNFreeRemoteProject(self._handle)

	def __eq__(self, other):
		if not isinstance(other, RemoteProject):
			return False
		return other.id == self.id

	def __str__(self):
		return f'<project: {self.remote.name}/{self.name}>'

	def __repr__(self):
		return f'<project: {self.remote.name}/{self.name}>'

	@property
	def is_open(self) -> bool:
		"""
		Determine if the project is open (it needs to be opened before you can access its files)

		:return: True if open
		"""
		return core.BNRemoteProjectIsOpen(self._handle)

	def open(self, progress: ProgressFuncType = _nop) -> bool:
		"""
		Open the project, allowing various file and folder based apis to work, as well as
		connecting a core Project (see :py:func:`core_project`).

		:param progress: Function to call for progress updates
		:raises: RuntimeError if there was an error opening the Project
		"""
		if self.is_open:
			return True
		return core.BNRemoteProjectOpen(self._handle, util.wrap_progress(progress), None)

	def close(self):
		"""
		Close the project and stop all background operations (e.g. file uploads)
		"""
		core.BNRemoteProjectClose(self._handle)

	@staticmethod
	def get_for_local_database(database: 'Database') -> Optional['RemoteProject']:
		"""
		Get the Remote Project for a Database

		:param database: BN database, potentially with collaboration metadata
		:return: Remote project from one of the connected remotes, or None if not found
		         or if projects are not pulled
		:raises RuntimeError: If there was an error
		"""
		remote = databasesync.get_remote_for_local_database(database)
		if remote is None:
			return None
		if not remote.has_pulled_projects:
			remote.pull_projects()
		return databasesync.get_remote_project_for_local_database(database)

	@staticmethod
	def get_for_bv(bv: 'BinaryView') -> Optional['RemoteProject']:
		"""
		Get the Remote Project for a BinaryView

		:param bv: BinaryView, potentially with collaboration metadata
		:return: Remote project from one of the connected remotes, or None if not found
		         or if projects are not pulled
		:raises RuntimeError: If there was an error
		"""
		if not bv.file.has_database:
			return None
		db = bv.file.database
		if db is None:
			return None
		return RemoteProject.get_for_local_database(db)

	@property
	def core_project(self) -> 'Project':
		"""
		Get the core :py:class:`binaryninja.Project` object for this Remote Project.

		.. note:: If the project has not been opened, it will be opened upon calling this.

		:return: Project instance
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		core_handle = core.BNRemoteProjectGetCoreProject(self._handle)
		if core_handle is None:
			raise RuntimeError(util._last_error())
		return Project(handle=ctypes.cast(core_handle, ctypes.POINTER(core.BNProject)))

	@property
	def remote(self) -> 'remote.Remote':
		"""
		Owning Remote

		:return: Remote object
		"""
		value = core.BNRemoteProjectGetRemote(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return remote.Remote(handle=value)

	@property
	def url(self):
		"""
		Web api endpoint URL

		:return: URL string
		"""
		return core.BNRemoteProjectGetUrl(self._handle)

	@property
	def id(self):
		"""
		Unique id

		:return: Id string
		"""
		return core.BNRemoteProjectGetId(self._handle)

	@property
	def created(self) -> datetime.datetime:
		"""
		Created date of the project

		:return: Date object
		"""
		return datetime.datetime.utcfromtimestamp(core.BNRemoteProjectGetCreated(self._handle))

	@property
	def last_modified(self) -> datetime.datetime:
		"""
		Last modified date of the project

		:return: Date object
		"""
		return datetime.datetime.utcfromtimestamp(core.BNRemoteProjectGetLastModified(self._handle))

	@property
	def name(self):
		"""
		Displayed name of project

		:return: Name string
		"""
		return core.BNRemoteProjectGetName(self._handle)

	@property
	def description(self):
		"""
		Description of the project

		:return: Description string
		"""
		return core.BNRemoteProjectGetDescription(self._handle)

	@name.setter
	def name(self, value):
		"""
		Set the display name of the project. You will need to push the project to update the remote version.

		:param value: New name
		"""
		if not core.BNRemoteProjectSetName(self._handle, value):
			raise RuntimeError(util._last_error())

	@description.setter
	def description(self, value):
		"""
		Set the description of the project. You will need to push the project to update the remote version.

		:param description: New description
		"""
		if not core.BNRemoteProjectSetDescription(self._handle, value):
			raise RuntimeError(util._last_error())

	@property
	def received_file_count(self) -> int:
			"""
			Get the number of files in a project (without needing to pull them first)

			:return: Number of files
			"""
			return core.BNRemoteProjectGetReceivedFileCount(self._handle)

	@property
	def received_folder_count(self) -> int:
			"""
			Get the number of folders in a project (without needing to pull them first)

			:return: Number of folders
			"""
			return core.BNRemoteProjectGetReceivedFolderCount(self._handle)

	@property
	def default_path(self) -> str:
		"""
		Get the default directory path for a remote Project. This is based off the Setting for
		collaboration.directory, the project's id, and the project's remote's id.

		:return: Default project path
		:rtype: str
		"""
		return databasesync.default_project_path(self)

	@property
	def has_pulled_files(self):
		"""
		If the project has pulled the files yet

		:return: True if they have been pulled
		"""
		return core.BNRemoteProjectHasPulledFiles(self._handle)

	@property
	def has_pulled_folders(self):
		"""
		If the project has pulled the folders yet

		:return: True if they have been pulled
		"""
		return core.BNRemoteProjectHasPulledFolders(self._handle)

	@property
	def has_pulled_group_permissions(self):
		"""
		If the project has pulled the group permissions yet

		:return: True if they have been pulled
		"""
		return core.BNRemoteProjectHasPulledGroupPermissions(self._handle)

	@property
	def has_pulled_user_permissions(self):
		"""
		If the project has pulled the user permissions yet

		:return: True if they have been pulled
		"""
		return core.BNRemoteProjectHasPulledUserPermissions(self._handle)

	@property
	def is_admin(self):
		"""
		If the currently logged in user is an administrator of the project (and can edit
		permissions and such for the project).

		:return: True if the user is an admin
		"""
		return core.BNRemoteProjectIsAdmin(self._handle)

	@property
	def files(self) -> List['file.RemoteFile']:
		"""
		Get the list of files in this project.

		.. note:: If the project has not been opened, it will be opened upon calling this.

		.. note:: If folders have not been pulled, they will be pulled upon calling this.

		.. note:: If files have not been pulled, they will be pulled upon calling this.

		:return: List of File objects
		:raises: RuntimeError if there was an error pulling files
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if not self.has_pulled_files:
			self.pull_files()

		count = ctypes.c_size_t()
		value = core.BNRemoteProjectGetFiles(self._handle, count)
		if value is None:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(file.RemoteFile(value[i]))
		return result

	def get_file_by_id(self, id: str) -> Optional['file.RemoteFile']:
		"""
		Get a specific File in the Project by its id

		.. note:: If the project has not been opened, it will be opened upon calling this.

		.. note:: If files have not been pulled, they will be pulled upon calling this.

		:param id: Id of File
		:return: File object, if one with that id exists. Else, None
		:raises: RuntimeError if there was an error pulling files
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if not self.has_pulled_files:
			self.pull_files()

		value = core.BNRemoteProjectGetFileById(self._handle, id)
		if value is None:
			return None
		return file.RemoteFile(value)

	def get_file_by_name(self, name: str) -> Optional['file.RemoteFile']:
		"""
		Get a specific File in the Project by its name

		.. note:: If the project has not been opened, it will be opened upon calling this.

		.. note:: If files have not been pulled, they will be pulled upon calling this.

		:param name: Name of File
		:return: File object, if one with that name exists. Else, None
		:raises: RuntimeError if there was an error pulling files
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if not self.has_pulled_files:
			self.pull_files()

		value = core.BNRemoteProjectGetFileByName(self._handle, name)
		if value is None:
			return None
		return file.RemoteFile(value)

	def pull_files(self, progress: 'util.ProgressFuncType' = util.nop):
		"""
		Pull the list of files from the Remote.

		.. note:: If the project has not been opened, it will be opened upon calling this.

		.. note:: If folders have not been pulled, they will be pulled upon calling this.

		:param progress: Function to call for progress updates
		:raises: RuntimeError if there was an error pulling files
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if not self.has_pulled_folders:
			self.pull_folders()

		if not core.BNRemoteProjectPullFiles(self._handle, util.wrap_progress(progress), None):
			raise RuntimeError(util._last_error())

	def create_file(self, filename: str, contents: bytes, name: str, description: str, parent_folder: Optional['folder.RemoteFolder'] = None,
		file_type: enums.RemoteFileType = enums.RemoteFileType.BinaryViewAnalysisFileType, progress: 'util.ProgressFuncType' = util.nop) -> 'file.RemoteFile':
		"""
		Create a new file on the remote (and pull it)

		.. note:: If the project has not been opened, it will be opened upon calling this.

		:param filename: File name
		:param contents: File contents
		:param name: Displayed file name
		:param description: File description
		:param parent_folder: Folder that will contain the file
		:param file_type: Type of File to create
		:param progress: Function to call on upload progress updates
		:return: Reference to the created file
		:raises: RuntimeError if there was an error
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		folder_handle = parent_folder._handle if parent_folder is not None else None
		value = core.BNRemoteProjectCreateFile(self._handle, filename, contents, len(contents), name, description, folder_handle, file_type.value, util.wrap_progress(progress), None)
		if value is None:
			raise RuntimeError(util._last_error())
		return file.RemoteFile(value)

	def push_file(self, file: 'file.RemoteFile', extra_fields: Optional[Dict[str, str]] = None):
		"""
		Push an updated File object to the Remote

		.. note:: If the project has not been opened, it will be opened upon calling this.

		:param file: File object which has been updated
		:param extra_fields: Extra HTTP fields to send with the update
		:raises: RuntimeError if there was an error
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if extra_fields is None:
			extra_fields = {}
		extra_field_keys = (ctypes.c_char_p * len(extra_fields))()
		extra_field_values = (ctypes.c_char_p * len(extra_fields))()
		for (i, (key, value)) in enumerate(extra_fields.items()):
			extra_field_keys[i] = core.cstr(key)
			extra_field_values[i] = core.cstr(value)
		if not core.BNRemoteProjectPushFile(self._handle, file._handle, extra_field_keys, extra_field_values, len(extra_fields)):
			raise RuntimeError(util._last_error())

	def delete_file(self, file: 'file.RemoteFile'):
		"""
		Delete a file from the remote

		.. note:: If the project has not been opened, it will be opened upon calling this.

		:param file: File to delete
		:raises: RuntimeError if there was an error
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if not core.BNRemoteProjectDeleteFile(self._handle, file._handle):
			raise RuntimeError(util._last_error())

	@property
	def folders(self) -> List['folder.RemoteFolder']:
		"""
		Get the list of folders in this project.

		.. note:: If the project has not been opened, it will be opened upon calling this.

		.. note:: If folders have not been pulled, they will be pulled upon calling this.

		:return: List of Folder objects
		:raises: RuntimeError if there was an error pulling folders
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if not self.has_pulled_folders:
			self.pull_folders()

		count = ctypes.c_size_t()
		value = core.BNRemoteProjectGetFolders(self._handle, count)
		if value is None:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(folder.RemoteFolder(value[i]))
		return result

	def get_folder_by_id(self, id: str) -> Optional['folder.RemoteFolder']:
		"""
		Get a specific Folder in the Project by its id

		.. note:: If the project has not been opened, it will be opened upon calling this.

		.. note:: If folders have not been pulled, they will be pulled upon calling this.

		:param id: Id of Folder
		:return: Folder object, if one with that id exists. Else, None
		:raises: RuntimeError if there was an error pulling folders
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if not self.has_pulled_folders:
			self.pull_folders()

		value = core.BNRemoteProjectGetFolderById(self._handle, id)
		if value is None:
			return None
		return folder.RemoteFolder(value)

	def pull_folders(self, progress: 'util.ProgressFuncType' = util.nop):
		"""
		Pull the list of folders from the Remote.

		.. note:: If the project has not been opened, it will be opened upon calling this.

		:param progress: Function to call for progress updates
		:raises: RuntimeError if there was an error pulling folders
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if not core.BNRemoteProjectPullFolders(self._handle, util.wrap_progress(progress), None):
			raise RuntimeError(util._last_error())

	def create_folder(self, name: str, description: str, parent: Optional['folder.RemoteFolder'] = None, progress: 'util.ProgressFuncType' = util.nop) -> 'folder.RemoteFolder':
		"""
		Create a new folder on the remote (and pull it)

		.. note:: If the project has not been opened, it will be opened upon calling this.

		:param name: Displayed folder name
		:param description: Folder description
		:param parent: Parent folder (optional)
		:param progress: Function to call on upload progress updates
		:return: Reference to the created folder
		:raises: RuntimeError if there was an error pulling folders
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		parent_handle = parent._handle if parent is not None else None
		value = core.BNRemoteProjectCreateFolder(self._handle, name, description, parent_handle, util.wrap_progress(progress), None)
		if value is None:
			raise RuntimeError(util._last_error())
		return folder.RemoteFolder(value)

	def push_folder(self, folder: 'folder.RemoteFolder', extra_fields: Optional[Dict[str, str]] = None):
		"""
		Push an updated Folder object to the Remote

		.. note:: If the project has not been opened, it will be opened upon calling this.

		:param folder: Folder object which has been updated
		:param extra_fields: Extra HTTP fields to send with the update
		:raises: RuntimeError if there was an error
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if extra_fields is None:
			extra_fields = {}
		extra_field_keys = (ctypes.c_char_p * len(extra_fields))()
		extra_field_values = (ctypes.c_char_p * len(extra_fields))()
		for (i, (key, value)) in enumerate(extra_fields.items()):
			extra_field_keys[i] = core.cstr(key)
			extra_field_values[i] = core.cstr(value)
		if not core.BNRemoteProjectPushFolder(self._handle, folder._handle, extra_field_keys, extra_field_values, len(extra_fields)):
			raise RuntimeError(util._last_error())

	def delete_folder(self, folder: 'folder.RemoteFolder'):
		"""
		Delete a folder from the remote

		.. note:: If the project has not been opened, it will be opened upon calling this.

		:param folder: Folder to delete
		:raises: RuntimeError if there was an error
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if not core.BNRemoteProjectDeleteFolder(self._handle, folder._handle):
			raise RuntimeError(util._last_error())

	@property
	def group_permissions(self) -> List['permission.Permission']:
		"""
		Get the list of group permissions in this project.

		.. note:: If group permissions have not been pulled, they will be pulled upon calling this.

		:return: List of Permission objects
		:raises: RuntimeError if there was an error pulling group permissions
		"""
		if not self.has_pulled_group_permissions:
			self.pull_group_permissions()

		count = ctypes.c_size_t()
		value = core.BNRemoteProjectGetGroupPermissions(self._handle, count)
		if value is None:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(permission.Permission(value[i]))
		return result

	@property
	def user_permissions(self) -> List['permission.Permission']:
		"""
		Get the list of user permissions in this project.

		.. note:: If user permissions have not been pulled, they will be pulled upon calling this.

		:return: List of Permission objects
		:raises: RuntimeError if there was an error pulling user permissions
		"""
		if not self.has_pulled_user_permissions:
			self.pull_user_permissions()

		count = ctypes.c_size_t()
		value = core.BNRemoteProjectGetUserPermissions(self._handle, count)
		if value is None:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(permission.Permission(value[i]))
		return result

	def get_permission_by_id(self, id: str) -> Optional['permission.Permission']:
		"""
		Get a specific permission in the Project by its id

		.. note:: If group or user permissions have not been pulled, they will be pulled upon calling this.

		:param id: Id of Permission
		:return: Permission object, if one with that id exists. Else, None
		:raises: RuntimeError if there was an error pulling permissions
		"""
		if not self.has_pulled_user_permissions:
			self.pull_user_permissions()
		if not self.has_pulled_group_permissions:
			self.pull_group_permissions()

		value = core.BNRemoteProjectGetPermissionById(self._handle, id)
		if value is None:
			return None
		return permission.Permission(value)

	def pull_group_permissions(self, progress: 'util.ProgressFuncType' = util.nop):
		"""
		Pull the list of group permissions from the Remote.

		:param progress: Function to call for progress updates
		:raises: RuntimeError if there was an error pulling permissions
		"""
		if not core.BNRemoteProjectPullGroupPermissions(self._handle, util.wrap_progress(progress), None):
			raise RuntimeError(util._last_error())

	def pull_user_permissions(self, progress: 'util.ProgressFuncType' = util.nop):
		"""
		Pull the list of user permissions from the Remote.

		:param progress: Function to call for progress updates
		:raises: RuntimeError if there was an error pulling permissions
		"""
		if not core.BNRemoteProjectPullUserPermissions(self._handle, util.wrap_progress(progress), None):
			raise RuntimeError(util._last_error())

	def create_group_permission(self, group_id: int, level: enums.CollaborationPermissionLevel, progress: 'util.ProgressFuncType' = util.nop) -> 'permission.Permission':
		"""
		Create a new group permission on the remote (and pull it)

		:param group_id: Group id
		:param level: Permission level
		:param progress: Function to call on upload progress updates
		:return: Reference to the created permission
		:raises: RuntimeError if there was an error pulling permissions
		"""
		value = core.BNRemoteProjectCreateGroupPermission(self._handle, group_id, level, util.wrap_progress(progress), None)
		if value is None:
			raise RuntimeError(util._last_error())
		return permission.Permission(value)

	def create_user_permission(self, user_id: str, level: enums.CollaborationPermissionLevel, progress: 'util.ProgressFuncType' = util.nop) -> 'permission.Permission':
		"""
		Create a new user permission on the remote (and pull it)

		:param user_id: User id
		:param level: Permission level
		:param progress: Function to call on upload progress updates
		:return: Reference to the created permission
		:raises: RuntimeError if there was an error pulling permissions
		"""
		value = core.BNRemoteProjectCreateUserPermission(self._handle, user_id, level, util.wrap_progress(progress), None)
		if value is None:
			raise RuntimeError(util._last_error())
		return permission.Permission(value)

	def push_permission(self, permission: 'permission.Permission', extra_fields: Optional[Dict[str, str]] = None):
		"""
		Push project permissions to the remote

		:param permission: Permission object which has been updated
		:param extra_fields: Extra HTTP fields to send with the update
		:raises: RuntimeError if there was an error
		"""
		if extra_fields is None:
			extra_fields = {}
		extra_field_keys = (ctypes.c_char_p * len(extra_fields))()
		extra_field_values = (ctypes.c_char_p * len(extra_fields))()
		for (i, (key, value)) in enumerate(extra_fields.items()):
			extra_field_keys[i] = core.cstr(key)
			extra_field_values[i] = core.cstr(value)
		if not core.BNRemoteProjectPushPermission(self._handle, permission._handle, extra_field_keys, extra_field_values, len(extra_fields)):
			raise RuntimeError(util._last_error())

	def delete_permission(self, permission: 'permission.Permission'):
		"""
		Delete a permission from the remote

		:param permission: Permission to delete
		:raises: RuntimeError if there was an error
		"""
		if not core.BNRemoteProjectDeletePermission(self._handle, permission._handle):
			raise RuntimeError(util._last_error())

	def can_user_view(self, username: str) -> bool:
		"""
		Determine if a user is in any of the view/edit/admin groups

		:param username: Username of user to check
		:return: True if they are in any of those groups
		:raises: RuntimeError if there was an error
		"""
		return core.BNRemoteProjectCanUserView(self._handle, username)

	def can_user_edit(self, username: str) -> bool:
		"""
		Determine if a user is in any of the edit/admin groups

		:param username: Username of user to check
		:return: True if they are in any of those groups
		:raises: RuntimeError if there was an error
		"""
		return core.BNRemoteProjectCanUserEdit(self._handle, username)

	def can_user_admin(self, username: str) -> bool:
		"""
		Determine if a user is in the admin group

		:param username: Username of user to check
		:return: True if they are in any of those groups
		:raises: RuntimeError if there was an error
		"""
		return core.BNRemoteProjectCanUserAdmin(self._handle, username)

	def upload_new_file(
			self,
			target: Union[str, PathLike, 'BinaryView', 'FileMetadata'],
			parent_folder: Optional['folder.RemoteFolder'] = None,
			progress: 'util.ProgressFuncType' = util.nop,
			open_view_options = None) -> 'file.RemoteFile':
		"""
		Upload a file to the project, creating a new File and pulling it

		.. note:: If the project has not been opened, it will be opened upon calling this.

		:param target: Path to file on disk or BinaryView/FileMetadata object of
		               already-opened file
		:param parent_folder: Parent folder to place the uploaded file in
		:param progress: Function to call for progress updates
		:return: Created File object
		:raises: RuntimeError if there was an error
		"""
		if not self.open():
			raise RuntimeError("Failed to open project")

		if isinstance(target, FileMetadata):
			if target.has_database:
				return databasesync.upload_database(target, self, parent_folder=parent_folder, progress=progress)
			else:
				target = target.raw

		if isinstance(target, BinaryView):
			maybe_bv = target
			target = maybe_bv.file.original_filename
		else:
			# Convert PathLike to string
			if isinstance(target, (Path,)):
				target = target.resolve()

			target = str(target)

			# Argument is a path, try opening it:
			try:
				if open_view_options is None:
					open_view_options = {}
				maybe_bv = load(
					target, progress_func=util.split_progress(progress, 0, [0.25, 0.75]), **open_view_options)
			except Exception as e:
				raise RuntimeError("Could not upload view: " + str(e))

		with tempfile.TemporaryDirectory() as temp_dir:
			with maybe_bv as bv:
				# Can't open, can't upload
				if not bv:
					raise RuntimeError("Could not open file at path for uploading")

				# If it is backed by a database, just upload that
				metadata = bv.file
				if metadata.has_database:
					uploaded = databasesync.upload_database(
						metadata, self, parent_folder=parent_folder, progress=util.split_progress(progress, 1, [0.25, 0.75]))
					return uploaded

				# Ported from remotebrowser.cpp (original comments):
				# TODO: This is not efficient at all!
				# No db exists, so create one before uploading so we always have a root snapshot
				# on the server
				# - Load file into memory
				# - Make temp path for temp database
				# - Make temp database with file
				# - UploadDatabase copies the temp database and makes its own
				# - Delete temp database
				# - Now you don't have an empty remote file
				db_path = Path(temp_dir) / Path(target).name
				log_info(f'Saving temporary database at {db_path}')
				# Save bndb first to create database
				if not metadata.create_database(
						str(db_path), util.split_progress(progress, 1, [0.25, 0.25, 0.25, 0.25])):
					raise RuntimeError("Could not save database for temporary path")

				if not metadata.save_auto_snapshot(
						util.split_progress(progress, 2, [0.25, 0.25, 0.25, 0.25])):
					raise RuntimeError("Could not create initial snapshot for upload")

				metadata.filename = str(db_path)
				uploaded = databasesync.upload_database(
					metadata, self, parent_folder=parent_folder, progress=util.split_progress(progress, 3, [0.25, 0.25, 0.25, 0.25]))
				return uploaded
