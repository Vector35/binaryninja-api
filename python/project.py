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

from contextlib import contextmanager
from os import PathLike
from typing import Callable, List, Optional, Union

from . import _binaryninjacore as core
from .exceptions import ProjectException
from .metadata import Metadata, MetadataValueType


ProgressFuncType = Callable[[int, int], bool]
AsPath = Union[PathLike, str]

#TODO: notifications

def nop(*args, **kwargs):
	"""
	Function that just returns True, used as default for callbacks

	:return: True
	"""
	return True


def wrap_progress(progress_func: ProgressFuncType):
	"""
	Wraps a progress function in a ctypes function for passing to the FFI

	:param progress_func: Python progress function
	:return: Wrapped ctypes function
	"""
	return ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
		lambda ctxt, cur, total: progress_func(cur, total))


class ProjectFile:
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
		proj_handle = core.BNProjectFileGetProject(self._handle)

		if proj_handle is None:
			raise ProjectException("Failed to get project for file")

		return Project(handle=proj_handle)

	@property
	def path_on_disk(self) -> str:
		return core.BNProjectFileGetPathOnDisk(self._handle) # type: ignore

	@property
	def exists_on_disk(self) -> bool:
		return core.BNProjectFileExistsOnDisk(self._handle)

	@property
	def id(self) -> str:
		return core.BNProjectFileGetId(self._handle) # type: ignore

	@property
	def name(self) -> str:
		return core.BNProjectFileGetName(self._handle) # type: ignore

	@name.setter
	def name(self, new_name: str):
		return core.BNProjectFileSetName(self._handle, new_name)

	@property
	def description(self) -> str:
		return core.BNProjectFileGetDescription(self._handle) # type: ignore

	@description.setter
	def description(self, new_description: str):
		return core.BNProjectFileSetDescription(self._handle, new_description)

	@property
	def folder(self) -> Optional['ProjectFolder']:
		folder_handle = core.BNProjectFileGetFolder(self._handle)
		if folder_handle is None:
			return None
		return ProjectFolder(handle=folder_handle)

	@folder.setter
	def folder(self, new_folder: Optional['ProjectFolder']):
		folder_handle = None if new_folder is None else new_folder._handle
		core.BNProjectFileSetFolder(self._handle, folder_handle)

	def export(self, dest: AsPath) -> bool:
		return core.BNProjectFileExport(self._handle, str(dest))


class ProjectFolder:
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
		proj_handle = core.BNProjectFolderGetProject(self._handle)

		if proj_handle is None:
			raise ProjectException("Failed to get project for folder")

		return Project(handle=proj_handle)

	@property
	def id(self) -> str:
		return core.BNProjectFolderGetId(self._handle) # type: ignore

	@property
	def name(self) -> str:
		return core.BNProjectFolderGetName(self._handle) # type: ignore

	@name.setter
	def name(self, new_name: str):
		return core.BNProjectFolderSetName(self._handle, new_name)

	@property
	def description(self) -> str:
		return core.BNProjectFolderGetDescription(self._handle) # type: ignore

	@description.setter
	def description(self, new_description: str):
		return core.BNProjectFolderSetDescription(self._handle, new_description)

	@property
	def parent(self) -> Optional['ProjectFolder']:
		folder_handle = core.BNProjectFolderGetParent(self._handle)
		if folder_handle is None:
			return None
		return ProjectFolder(handle=folder_handle)

	@parent.setter
	def parent(self, new_parent: Optional['ProjectFolder']):
		parent_handle = None if new_parent is None else new_parent._handle
		core.BNProjectFolderSetParent(self._handle, parent_handle)

	def export(self, dest: AsPath, progress_func: ProgressFuncType = nop) -> bool:
		return core.BNProjectFolderExport(self._handle, str(dest), None, wrap_progress(progress_func))


class Project:
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
		project_handle = core.BNOpenProject(str(path))
		if project_handle is None:
			raise ProjectException("Failed to open project")
		return Project(handle=project_handle)

	@staticmethod
	def create_project(path: AsPath, name: str) -> 'Project':
		project_handle = core.BNCreateProject(str(path), name)
		if project_handle is None:
			raise ProjectException("Failed to create project")
		return Project(handle=project_handle)

	def open(self) -> bool:
		return core.BNProjectOpen(self._handle)

	def close(self) -> bool:
		return core.BNProjectClose(self._handle)

	@property
	def id(self) -> str:
		return core.BNProjectGetId(self._handle) # type: ignore

	@property
	def is_open(self) -> bool:
		return core.BNProjectIsOpen(self._handle)

	@property
	def path(self) -> str:
		return core.BNProjectGetPath(self._handle) # type: ignore

	@property
	def name(self) -> str:
		return core.BNProjectGetName(self._handle) # type: ignore

	@name.setter
	def name(self, new_name: str):
		core.BNProjectSetName(self._handle, new_name)

	@property
	def description(self) -> str:
		return core.BNProjectGetDescription(self._handle) # type: ignore

	@description.setter
	def description(self, new_description: str):
		core.BNProjectSetDescription(self._handle, new_description)

	def query_metadata(self, key: str) -> MetadataValueType:
		md_handle = core.BNProjectQueryMetadata(self._handle, key)
		if md_handle is None:
			raise KeyError(key)
		return Metadata(handle=md_handle).value

	def store_metadata(self, key: str, value: MetadataValueType):
		_val = value
		if not isinstance(_val, Metadata):
			_val = Metadata(_val)
		core.BNProjectStoreMetadata(self._handle, key, _val.handle)

	def remove_metadata(self, key: str):
		core.BNProjectRemoveMetadata(self._handle, key)

	def create_folder_from_path(self, path: Union[PathLike, str], parent: Optional[ProjectFolder] = None, description: str = "", progress_func: ProgressFuncType = nop) -> ProjectFolder:
		parent_handle = parent._handle if parent is not None else None
		folder_handle = core.BNProjectCreateFolderFromPath(
			project=self._handle,
			path=str(path),
			parent=parent_handle,
			description=description,
			ctxt=None,
			progress=wrap_progress(progress_func)
		)

		if folder_handle is None:
			raise ProjectException("Failed to create folder")

		return ProjectFolder(handle=folder_handle)

	def create_folder(self, parent: Optional[ProjectFolder], name: str, description: str = "") -> ProjectFolder:
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
		handle = core.BNProjectGetFolderById(self._handle, id)
		if handle is None:
			return None
		folder = ProjectFolder(handle)
		return folder

	def push_folder(self, folder: ProjectFolder):
		core.BNProjectPushFolder(self._handle, folder._handle)

	def delete_folder(self, folder: ProjectFolder, progress_func: ProgressFuncType = nop):
		core.BNProjectDeleteFolder(self._handle, folder._handle, None, wrap_progress(progress_func))

	def create_file_from_path(self, path: AsPath, folder: Optional[ProjectFile], name: str, description: str = "", progress_func: ProgressFuncType = nop) -> ProjectFile:
		folder_handle = folder._handle if folder is not None else None
		file_handle = core.BNProjectCreateFileFromPath(
			project=self._handle,
			path=str(path),
			folder=folder_handle,
			name=name,
			description=description,
			ctxt=None,
			progress=wrap_progress(progress_func)
		)

		if file_handle is None:
			raise ProjectException("Failed to create file")

		return ProjectFile(handle=file_handle)

	def create_file(self, contents: bytes, folder: Optional[ProjectFile], name: str, description: str = "", progress_func: ProgressFuncType = nop) -> ProjectFile:
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
			progress=wrap_progress(progress_func)
		)

		if file_handle is None:
			raise ProjectException("Failed to create file")

		return ProjectFile(handle=file_handle)

	@property
	def files(self) -> List[ProjectFile]:
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
		handle = core.BNProjectGetFileById(self._handle, id)
		if handle is None:
			return None
		file = ProjectFile(handle)
		return file

	def push_file(self, file: ProjectFile):
		core.BNProjectPushFile(self._handle, file._handle)

	def delete_file(self, file: ProjectFile):
		core.BNProjectDeleteFile(self._handle, file._handle)

	@contextmanager
	def bulk_operation(self):
		core.BNProjectBeginBulkOperation(self._handle)
		yield
		core.BNProjectEndBulkOperation(self._handle)
