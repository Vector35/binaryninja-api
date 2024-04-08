import ctypes
from typing import Optional

from .. import _binaryninjacore as core
from . import project, remote, util
from ..enums import CollaborationPermissionLevel


class Permission:
	"""
	Class representing a permission grant for a user or group on a project.
	"""
	def __init__(self, handle: core.BNCollaborationPermissionHandle):
		self._handle = ctypes.cast(handle, core.BNCollaborationPermissionHandle)

	def __del__(self):
		if core is not None:
			core.BNFreeCollaborationPermission(self._handle)

	def __eq__(self, other):
		if not isinstance(other, Permission):
			return False
		return other.id == self.id

	@property
	def remote(self) -> 'remote.Remote':
		"""
		Owning Remote

		:return: Remote object
		"""
		value = core.BNCollaborationPermissionGetRemote(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return remote.Remote(handle=value)

	@property
	def project(self) -> 'project.RemoteProject':
		"""
		Owning Project

		:return: Project object
		"""
		value = core.BNCollaborationPermissionGetProject(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return project.RemoteProject(handle=value)

	@property
	def url(self) -> str:
		"""
		Web api endpoint url

		:return: URL string
		"""
		return core.BNCollaborationPermissionGetUrl(self._handle)

	@property
	def id(self) -> str:
		"""
		Unique id

		:return: Id string
		"""
		return core.BNCollaborationPermissionGetId(self._handle)

	@property
	def level(self) -> CollaborationPermissionLevel:
		"""
		Level of permission

		:return: Permission level
		"""
		return CollaborationPermissionLevel(core.BNCollaborationPermissionGetLevel(self._handle))

	@level.setter
	def level(self, value: CollaborationPermissionLevel):
		"""
		Change the level of the permission
		You will need to push the group to update the Remote.

		:param value: New value
		"""
		core.BNCollaborationPermissionSetLevel(self._handle, value)

	@property
	def group_id(self) -> Optional[int]:
		"""
		Id of affected group

		:return: Group id, if this is a group permission. Else, None
		"""
		result = core.BNCollaborationPermissionGetGroupId(self._handle)
		if result == 0:
			return None
		return result

	@property
	def group_name(self) -> Optional[str]:
		"""
		Name of affected group

		:return: Group name, if this is a group permission. Else, None
		"""
		result = core.BNCollaborationPermissionGetGroupName(self._handle)
		if result == "":
			return None
		return result

	@property
	def user_id(self) -> Optional[str]:
		"""
		Id of affected user

		:return: User id, if this is a user permission. Else, None
		"""
		result = core.BNCollaborationPermissionGetUserId(self._handle)
		if result == "":
			return None
		return result

	@property
	def username(self) -> Optional[str]:
		"""
		Name of affected user

		:return: User name, if this is a user permission. Else, None
		"""
		result = core.BNCollaborationPermissionGetUsername(self._handle)
		if result == "":
			return None
		return result

	@property
	def can_view(self) -> bool:
		"""
		If the permission grants the affect user/group the ability to read files in the project

		:return: True if permission granted
		"""
		return core.BNCollaborationPermissionCanView(self._handle)

	@property
	def can_edit(self) -> bool:
		"""
		If the permission grants the affect user/group the ability to edit files in the project

		:return: True if permission granted
		"""
		return core.BNCollaborationPermissionCanEdit(self._handle)

	@property
	def can_admin(self) -> bool:
		"""
		If the permission grants the affect user/group the ability to administer the project

		:return: True if permission granted
		"""
		return core.BNCollaborationPermissionCanAdmin(self._handle)
