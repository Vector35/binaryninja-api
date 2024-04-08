
import ctypes
from typing import Optional

from .. import _binaryninjacore as core
from .. import project as core_project
from . import project, remote, util


class RemoteFolder:
	"""
	Class representing a remote folder in a project.
	"""
	def __init__(self, handle: core.BNRemoteFolderHandle):
		self._handle = ctypes.cast(handle, core.BNRemoteFolderHandle)

	def __del__(self):
		if core is not None:
			core.BNFreeRemoteFolder(self._handle)

	def __eq__(self, other):
		if not isinstance(other, RemoteFolder):
			return False
		return self.id == other.id

	def __repr__(self):
		path = self.name
		parent = self.parent
		while parent is not None:
			path = parent.name + '/' + path
			parent = parent.parent
		return f'<folder: {self.remote.name}/{self.project.name}/{path}>'

	def __str__(self):
		path = self.name
		parent = self.parent
		while parent is not None:
			path = parent.name + '/' + path
			parent = parent.parent
		return f'<folder: {self.remote.name}/{self.project.name}/{path}>'

	@property
	def core_folder(self) -> 'core_project.ProjectFolder':
		core_handle = core.BNRemoteFolderGetCoreFolder(self._handle)
		if core_handle is None:
			raise RuntimeError(util._last_error())
		return core_project.ProjectFolder(handle=ctypes.cast(core_handle, ctypes.POINTER(core.BNProjectFolder)))

	@property
	def project(self) -> 'project.RemoteProject':
		"""
		Owning Project.

		:return: Project object
		"""
		value = core.BNRemoteFolderGetProject(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return project.RemoteProject(handle=value)

	@property
	def remote(self) -> 'remote.Remote':
		"""
		Owning Remote

		:return: Remote object
		"""
		value = core.BNRemoteFolderGetRemote(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return remote.Remote(handle=value)

	@property
	def parent(self) -> Optional['RemoteFolder']:
		"""
		Parent folder, if one exists. None if this is in the root of a project.

		:return: Parent folder object or None
		"""
		if not self.project.has_pulled_folders:
			self.project.pull_folders()
		parent = ctypes.POINTER(core.BNRemoteFolder)()
		if not core.BNRemoteFolderGetParent(self._handle, parent):
			raise RuntimeError(util._last_error())
		if not parent:
			return None
		return RemoteFolder(handle=parent)

	@parent.setter
	def parent(self, parent: Optional['RemoteFolder']):
		"""
		Set the parent folder. You will need to push the folder to update the remote version.

		:param parent: New parent folder
		:raises RuntimeError: If there was an error
		"""
		if not core.BNRemoteFolderSetParent(self._handle, parent._handle if parent is not None else None):
			raise RuntimeError(util._last_error())

	@property
	def url(self) -> str:
		"""
		Web api endpoint URL

		:return: URL string
		"""
		return core.BNRemoteFolderGetUrl(self._handle)

	@property
	def id(self) -> str:
		"""
		Unique id

		:return: Id string
		"""
		return core.BNRemoteFolderGetId(self._handle)

	@property
	def parent_id(self) -> Optional[str]:
		"""
		Unique id of parent folder, if there is a parent. None, otherwise

		:return: Id string or None
		"""
		parent_id = ctypes.c_char_p()
		if not core.BNRemoteFolderGetParentId(self._handle, parent_id):
			return None
		return core.pyNativeStr(parent_id.value)

	@property
	def name(self) -> str:
		"""
		Displayed name of folder

		:return: Name string
		"""
		return core.BNRemoteFolderGetName(self._handle)

	@name.setter
	def name(self, name: str):
		"""
		Set the display name of the folder. You will need to push the folder to update the remote version.

		:param name: New name
		"""
		core.BNRemoteFolderSetName(self._handle, name)

	@property
	def description(self) -> str:
		"""
		Description of the folder

		:return: Description string
		"""
		return core.BNRemoteFolderGetDescription(self._handle)

	@description.setter
	def description(self, description: str):
		"""
		Set the description of the folder. You will need to push the folder to update the remote version.

		:param description: New description
		"""
		core.BNRemoteFolderSetDescription(self._handle, description)
