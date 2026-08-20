import ctypes
from typing import List, Tuple

from .. import _binaryninjacore as core
from . import remote, user, util


class Group:
	"""
	Class representing a remote Group
	"""
	def __init__(self, handle: core.BNCollaborationGroupHandle):
		self._handle = ctypes.cast(handle, core.BNCollaborationGroupHandle)

	def __del__(self):
		core.BNFreeCollaborationGroup(self._handle)

	def __eq__(self, other):
		if not isinstance(other, Group):
			return False
		return self.id == other.id

	@property
	def remote(self) -> 'remote.Remote':
		"""
		Owning Remote

		:return: Remote object
		"""
		value = core.BNCollaborationGroupGetRemote(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return remote.Remote(handle=value)

	@property
	def url(self) -> str:
		"""
		Web api endpoint url

		:return: URL string
		"""
		return core.BNCollaborationGroupGetUrl(self._handle)

	@property
	def id(self) -> int:
		"""
		Unique id

		:return: Id number
		"""
		return core.BNCollaborationGroupGetId(self._handle)

	@property
	def name(self) -> str:
		"""
		Group name

		:return: Name string
		"""
		return core.BNCollaborationGroupGetName(self._handle)

	@name.setter
	def name(self, name: str):
		"""
		Set group name
		You will need to push the group to update the Remote.

		:param name: New group name
		"""
		core.BNCollaborationGroupSetName(self._handle, name)

	@property
	def users(self) -> List[user.User]:
		"""
		Get list of users in the group

		:return: List of users
		"""
		count = ctypes.c_size_t()
		result = core.BNCollaborationGroupGetUsers(self._handle, count)
		if not result:
			raise RuntimeError(util._last_error())
		out = []
		for i in range(count.value):
			out.append(user.User(result[i]))
		return out

	@users.setter
	def users(self, users: List[user.User]):
		"""
		Set the list of users in a group.
		You will need to push the group to update the Remote.

		:param users: New group members
		"""
		array = ctypes.POINTER(core.BNCollaborationUserHandle)()
		for i in range(len(users)):
			array[i] = users[i]._handle
		if not core.BNCollaborationGroupSetUsers(self._handle, array, len(users)):
			raise RuntimeError(util._last_error())

	def contains_user(self, user: user.User) -> bool:
		"""
		Test if a group contains a user

		:param user: User to check membership of
		:return: If the group contains the user
		"""
		return core.BNCollaborationGroupContainsUser(self._handle, user._handle)
