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

from contextlib import contextmanager
from os import PathLike
from typing import Callable, List, Optional, Union

from . import _binaryninjacore as core
from .exceptions import ProjectException
from .metadata import Metadata, MetadataValueType


ProgressFuncType = Callable[[int, int], bool]
AsPath = Union[PathLike, str]

#TODO: notifications

def _nop(*args, **kwargs):
	"""
	Function that just returns True, used as default for callbacks

	:return: True
	"""
	return True


def _wrap_progress(progress_func: ProgressFuncType):
	"""
	Wraps a progress function in a ctypes function for passing to the FFI

	:param progress_func: Python progress function
	:return: Wrapped ctypes function
	"""
	return ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
		lambda ctxt, cur, total: progress_func(cur, total))


class ProjectFile:
	"""
	Class representing a file in a project
	"""
	def __init__(self, handle: core.BNProjectFileHandle):
		self._handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeProjectFile(self._handle)

	def __repr__(self) -> str:
		path = self.name
		parent = self.folder
		while parent is not None:
			path = parent.name + '/' + path
			parent = parent.parent
		return f'<ProjectFile: {self.project.name}/{path}>'

	def __str__(self) -> str:
		path = self.name
		parent = self.folder
		while parent is not None:
			path = parent.name + '/' + path
			parent = parent.parent
		return f'<ProjectFile: {self.project.name}/{path}>'

	@property
	def project(self):
		"""
		Get the project that owns this file

		:return: Project that owns this file
		"""
		proj_handle = core.BNProjectFileGetProject(self._handle)

		if proj_handle is None:
			raise ProjectException("Failed to get project for file")

		return Project(handle=proj_handle)

	@property
	def path_on_disk(self) -> str:
		"""
		Get the path on disk to this file's contents

		:return: Path on disk as a string
		"""
		return core.BNProjectFileGetPathOnDisk(self._handle) # type: ignore

	@property
	def exists_on_disk(self) -> bool:
		"""
		Check if this file's contents exist on disk

		:return: True if this file's contents exist on disk, False otherwise
		"""
		return core.BNProjectFileExistsOnDisk(self._handle)

	@property
	def id(self) -> str:
		"""
		Get the unique id of this file

		:return: Unique identifier of this file
		"""
		return core.BNProjectFileGetId(self._handle) # type: ignore

	@property
	def name(self) -> str:
		"""
		Get the name of this file

		:return: Name of this file
		"""
		return core.BNProjectFileGetName(self._handle) # type: ignore

	@name.setter
	def name(self, new_name: str):
		"""
		Set the name of this file

		:param new_name: Desired name
		"""
		return core.BNProjectFileSetName(self._handle, new_name)

	@property
	def description(self) -> str:
		"""
		Get the description of this file

		:return: Description of this file
		"""
		return core.BNProjectFileGetDescription(self._handle) # type: ignore

	@description.setter
	def description(self, new_description: str):
		"""
		Set the description of this file

		:param new_description: Desired description
		"""
		return core.BNProjectFileSetDescription(self._handle, new_description)

	@property
	def folder(self) -> Optional['ProjectFolder']:
		"""
		Get the folder that contains this file

		:return: Folder that contains this file, or None
		"""
		folder_handle = core.BNProjectFileGetFolder(self._handle)
		if folder_handle is None:
			return None
		return ProjectFolder(handle=folder_handle)

	@folder.setter
	def folder(self, new_folder: Optional['ProjectFolder']):
		"""
		Set the folder that contains this file

		:param new_parent: The folder that will contain this file, or None
		"""
		folder_handle = None if new_folder is None else new_folder._handle
		core.BNProjectFileSetFolder(self._handle, folder_handle)

	def export(self, dest: AsPath) -> bool:
		"""
		Export this file to disk

		:param dest: Destination path for the exported contents
		:return: True if the export succeeded, False otherwise
		"""
		return core.BNProjectFileExport(self._handle, str(dest))


class ProjectFolder:
	"""
	Class representing a folder in a project
	"""
	def __init__(self, handle: core.BNProjectFolderHandle):
		self._handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeProjectFolder(self._handle)

	def __repr__(self) -> str:
		path = self.name
		parent = self.parent
		while parent is not None:
			path = parent.name + '/' + path
			parent = parent.parent
		return f'<ProjectFolder: {self.project.name}/{path}>'

	def __str__(self) -> str:
		path = self.name
		parent = self.parent
		while parent is not None:
			path = parent.name + '/' + path
			parent = parent.parent
		return f'<ProjectFolder: {self.project.name}/{path}>'

	@property
	def project(self):
		"""
		Get the project that owns this folder

		:return: Project that owns this folder
		"""
		proj_handle = core.BNProjectFolderGetProject(self._handle)

		if proj_handle is None:
			raise ProjectException("Failed to get project for folder")

		return Project(handle=proj_handle)

	@property
	def id(self) -> str:
		"""
		Get the unique id of this folder

		:return: Unique identifier of this folder
		"""
		return core.BNProjectFolderGetId(self._handle) # type: ignore

	@property
	def name(self) -> str:
		"""
		Get the name of this folder

		:return: Name of this folder
		"""
		return core.BNProjectFolderGetName(self._handle) # type: ignore

	@name.setter
	def name(self, new_name: str):
		"""
		Set the name of this folder

		:param new_name: Desired name
		"""
		return core.BNProjectFolderSetName(self._handle, new_name)

	@property
	def description(self) -> str:
		"""
		Get the description of this folder

		:return: Description of this folder
		"""
		return core.BNProjectFolderGetDescription(self._handle) # type: ignore

	@description.setter
	def description(self, new_description: str):
		"""
		Set the description of this folder

		:param new_description: Desired description
		"""
		return core.BNProjectFolderSetDescription(self._handle, new_description)

	@property
	def parent(self) -> Optional['ProjectFolder']:
		"""
		Get the parent folder of this folder

		:return: Folder that contains this folder, or None if it is a root folder
		"""
		folder_handle = core.BNProjectFolderGetParent(self._handle)
		if folder_handle is None:
			return None
		return ProjectFolder(handle=folder_handle)

	@parent.setter
	def parent(self, new_parent: Optional['ProjectFolder']):
		"""
		Set the parent folder of this folder

		:param new_parent: The folder that will contain this folder, or None
		"""
		parent_handle = None if new_parent is None else new_parent._handle
		core.BNProjectFolderSetParent(self._handle, parent_handle)

	def export(self, dest: AsPath, progress_func: ProgressFuncType = _nop) -> bool:
		"""
		Recursively export this folder to disk

		:param dest: Destination path for the exported contents
		:param progress_func: Progress function that will be called as contents are exporting
		:return: True if the export succeeded, False otherwise
		"""
		return core.BNProjectFolderExport(self._handle, str(dest), None, _wrap_progress(progress_func))


class Project:
	"""
	Class representing a project
	"""
	def __init__(self, handle: core.BNProjectHandle):
		self._handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeProject(self._handle)

	def __repr__(self) -> str:
		return f'<Project: {self.name}>'

	def __str__(self) -> str:
		return f'<Project: {self.name}>'

	@staticmethod
	def open_project(path: AsPath) -> 'Project':
		"""
		Open an existing project

		:param path: Path to the project directory (.bnpr) or project metadata file (.bnpm)
		:return: Opened project
		:raises ProjectException: If there was an error opening the project
		"""
		project_handle = core.BNOpenProject(str(path))
		if project_handle is None:
			raise ProjectException("Failed to open project")
		return Project(handle=project_handle)

	@staticmethod
	def create_project(path: AsPath, name: str) -> 'Project':
		"""
		Create a new project

		:param path: Path to the project directory (.bnpr)
		:param name: Name of the new project
		:return: Opened project
		:raises ProjectException: If there was an error creating the project
		"""
		project_handle = core.BNCreateProject(str(path), name)
		if project_handle is None:
			raise ProjectException("Failed to create project")
		return Project(handle=project_handle)

	def open(self) -> bool:
		"""
		Open a closed project

		:return: True if the project is now open, False otherwise
		"""
		return core.BNProjectOpen(self._handle)

	def close(self) -> bool:
		"""
		Close an opened project

		:return: True if the project is now closed, False otherwise
		"""
		return core.BNProjectClose(self._handle)

	@property
	def id(self) -> str:
		"""
		Get the unique id of this project

		:return: Unique identifier of project
		"""
		return core.BNProjectGetId(self._handle) # type: ignore

	@property
	def is_open(self) -> bool:
		"""
		Check if the project is currently open

		:return: True if the project is currently open, False otherwise
		"""
		return core.BNProjectIsOpen(self._handle)

	@property
	def path(self) -> str:
		"""
		Get the path of the project

		:return: Path of the project's .bnpr directory
		"""
		return core.BNProjectGetPath(self._handle) # type: ignore

	@property
	def name(self) -> str:
		"""
		Get the name of the project

		:return: Name of the project
		"""
		return core.BNProjectGetName(self._handle) # type: ignore

	@name.setter
	def name(self, new_name: str):
		"""
		Set the name of the project

		:param new_name: Desired name
		"""
		core.BNProjectSetName(self._handle, new_name)

	@property
	def description(self) -> str:
		"""
		Get the description of the project

		:return: Description of the project
		"""
		return core.BNProjectGetDescription(self._handle) # type: ignore

	@description.setter
	def description(self, new_description: str):
		"""
		Set the description of the project

		:param new_description: Desired description
		"""
		core.BNProjectSetDescription(self._handle, new_description)

	def query_metadata(self, key: str) -> MetadataValueType:
		"""
		Retrieves metadata stored under a key from the project

		:param str key: Key to query
		"""
		md_handle = core.BNProjectQueryMetadata(self._handle, key)
		if md_handle is None:
			raise KeyError(key)
		return Metadata(handle=md_handle).value

	def store_metadata(self, key: str, value: MetadataValueType):
		"""
		Stores metadata within the project

		:param str key: Key under which to store the Metadata object
		:param Varies value: Object to store
		"""
		_val = value
		if not isinstance(_val, Metadata):
			_val = Metadata(_val)
		core.BNProjectStoreMetadata(self._handle, key, _val.handle)

	def remove_metadata(self, key: str):
		"""
		Removes the metadata associated with this key from the project

		:param str key: Key associated with the metadata object to remove
		"""
		core.BNProjectRemoveMetadata(self._handle, key)

	def create_folder_from_path(self, path: Union[PathLike, str], parent: Optional[ProjectFolder] = None, description: str = "", progress_func: ProgressFuncType = _nop) -> ProjectFolder:
		"""
		Recursively create files and folders in the project from a path on disk

		:param path: Path to folder on disk
		:param parent: Parent folder in the project that will contain the new contents
		:param description: Description for created root folder
		:param progress_func: Progress function that will be called
		:return: Created root folder
		"""
		parent_handle = parent._handle if parent is not None else None
		folder_handle = core.BNProjectCreateFolderFromPath(
			project=self._handle,
			path=str(path),
			parent=parent_handle,
			description=description,
			ctxt=None,
			progress=_wrap_progress(progress_func)
		)

		if folder_handle is None:
			raise ProjectException("Failed to create folder")

		return ProjectFolder(handle=folder_handle)

	def create_folder(self, parent: Optional[ProjectFolder], name: str, description: str = "") -> ProjectFolder:
		"""
		Recursively create files and folders in the project from a path on disk

		:param parent: Parent folder in the project that will contain the new folder
		:param name: Name for the created folder
		:param description: Description for created folder
		:return: Created folder
		"""
		parent_handle = parent._handle if parent is not None else None
		folder_handle = core.BNProjectCreateFolder(
			project=self._handle,
			parent=parent_handle,
			name=name,
			description=description,
		)

		if folder_handle is None:
			raise ProjectException("Failed to create folder")

		return ProjectFolder(handle=folder_handle)

	@property
	def folders(self) -> List[ProjectFolder]:
		"""
		Get a list of folders in the project

		:return: List of folders in the project
		"""
		count = ctypes.c_size_t()
		value = core.BNProjectGetFolders(self._handle, count)
		if value is None:
			raise ProjectException("Failed to get list of project folders")
		result = []
		try:
			for i in range(count.value):
				folder_handle = core.BNNewProjectFolderReference(value[i])
				if folder_handle is None:
					raise ProjectException("core.BNNewProjectFolderReference returned None")
				result.append(ProjectFolder(folder_handle))
			return result
		finally:
			core.BNFreeProjectFolderList(value, count.value)

	def get_folder_by_id(self, id: str) -> Optional[ProjectFolder]:
		"""
		Retrieve a folder in the project by unique id

		:param id: Unique identifier for a folder
		:return: Folder with the requested id or None
		"""
		handle = core.BNProjectGetFolderById(self._handle, id)
		if handle is None:
			return None
		folder = ProjectFolder(handle)
		return folder

	def delete_folder(self, folder: ProjectFolder, progress_func: ProgressFuncType = _nop) -> bool:
		"""
		Recursively delete a folder from the project

		:param folder: Folder to delete recursively
		:param progress_func: Progress function that will be called as objects get deleted
		:return: True if the folder was deleted, False otherwise
		"""
		return core.BNProjectDeleteFolder(self._handle, folder._handle, None, _wrap_progress(progress_func))

	def create_file_from_path(self, path: AsPath, folder: Optional[ProjectFile], name: str, description: str = "", progress_func: ProgressFuncType = _nop) -> ProjectFile:
		"""
		Create a file in the project from a path on disk

		:param path: Path on disk
		:param folder: Folder to place the created file in
		:param name: Name to assign to the created file
		:param description: Description to assign to the created file
		:param progress_func: Progress function that will be called as the file is being added
		"""
		folder_handle = folder._handle if folder is not None else None
		file_handle = core.BNProjectCreateFileFromPath(
			project=self._handle,
			path=str(path),
			folder=folder_handle,
			name=name,
			description=description,
			ctxt=None,
			progress=_wrap_progress(progress_func)
		)

		if file_handle is None:
			raise ProjectException("Failed to create file")

		return ProjectFile(handle=file_handle)

	def create_file(self, contents: bytes, folder: Optional[ProjectFile], name: str, description: str = "", progress_func: ProgressFuncType = _nop) -> ProjectFile:
		"""
		Create a file in the project

		:param contents: Bytes of the file that will be created
		:param folder: Folder to place the created file in
		:param name: Name to assign to the created file
		:param description: Description to assign to the created file
		:param progress_func: Progress function that will be called as the file is being added
		"""
		folder_handle = folder._handle if folder is not None else None
		buf = (ctypes.c_ubyte * len(contents))()
		ctypes.memmove(buf, contents, len(contents))
		file_handle = core.BNProjectCreateFile(
			project=self._handle,
			contents=buf,
			contentsSize=len(contents),
			folder=folder_handle,
			name=name,
			description=description,
			ctxt=None,
			progress=_wrap_progress(progress_func)
		)

		if file_handle is None:
			raise ProjectException("Failed to create file")

		return ProjectFile(handle=file_handle)

	@property
	def files(self) -> List[ProjectFile]:
		"""
		Get a list of files in the project

		:return: List of files in the project
		"""
		count = ctypes.c_size_t()
		value = core.BNProjectGetFiles(self._handle, count)
		if value is None:
			raise ProjectException("Failed to get list of project files")
		result = []
		try:
			for i in range(count.value):
				file_handle = core.BNNewProjectFileReference(value[i])
				if file_handle is None:
					raise ProjectException("core.BNNewProjectFileReference returned None")
				result.append(ProjectFile(file_handle))
			return result
		finally:
			core.BNFreeProjectFileList(value, count.value)

	def get_file_by_id(self, id: str) -> Optional[ProjectFile]:
		"""
		Retrieve a file in the project by unique id

		:param id: Unique identifier for a file
		:return: File with the requested id or None
		"""
		handle = core.BNProjectGetFileById(self._handle, id)
		if handle is None:
			return None
		file = ProjectFile(handle)
		return file

	def delete_file(self, file: ProjectFile) -> bool:
		"""
		Delete a file from the project

		:param file: File to delete
		:return: True if the file was deleted, False otherwise
		"""
		return core.BNProjectDeleteFile(self._handle, file._handle)

	@contextmanager
	def bulk_operation(self):
		"""
		A context manager to speed up bulk project operations.
		Project modifications are synced to disk in chunks,
		and the project on disk vs in memory may not agree on state
		if an exception occurs while a bulk operation is happening.

		:Example:
			>>> from pathlib import Path
			>>> with project.bulk_operation():
			... 	for i in Path('/bin/').iterdir():
			... 		if i.is_file() and not i.is_symlink():
			... 			project.create_file_from_path(i, None, i.name)
		"""
		core.BNProjectBeginBulkOperation(self._handle)
		yield
		core.BNProjectEndBulkOperation(self._handle)
