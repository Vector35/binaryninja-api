import ctypes
from typing import List, Tuple

from .. import _binaryninjacore as core
from . import remote, util


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
	def users(self) -> List[Tuple[str, str]]:
		"""
		Get list of users in the group

		:return: List of (userid, username) pairs
		"""
		count = ctypes.c_size_t()
		user_ids = ctypes.POINTER(ctypes.c_char_p)()
		usernames = ctypes.POINTER(ctypes.c_char_p)()
		if not core.BNCollaborationGroupGetUsers(self._handle, user_ids, usernames, count):
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append((core.pyNativeStr(user_ids[i]), core.pyNativeStr(usernames[i])))
		core.BNFreeStringList(user_ids, count.value)
		core.BNFreeStringList(usernames, count.value)
		return result

	@users.setter
	def users(self, usernames: List[str]):
		"""
		Set the list of users in a group by their usernames.
		You will need to push the group to update the Remote.

		:param usernames: Usernames of new group members
		"""
		array = (ctypes.c_char_p * len(usernames))()
		for i in range(len(usernames)):
			array[i] = core.cstr(usernames[i])
		if not core.BNCollaborationGroupSetUsernames(self._handle, array, len(usernames)):
			raise RuntimeError(util._last_error())

	def contains_user(self, username: str) -> bool:
		"""
		Test if a group has a user with the given username

		:param username: Username of user to check membership
		:return: If the user is in the group
		"""
		return core.BNCollaborationGroupContainsUser(self._handle, username)
