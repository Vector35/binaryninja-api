import ctypes
from .. import _binaryninjacore as core
from . import remote, util


class User:
	"""
	Class representing a remote User
	"""
	def __init__(self, handle: core.BNCollaborationUserHandle):
		self._handle = ctypes.cast(handle, core.BNCollaborationUserHandle)

	def __del__(self):
		if core is not None:
			core.BNFreeCollaborationUser(self._handle)

	def __eq__(self, other):
		if not isinstance(other, User):
			return False
		return self.id == other.id

	@property
	def remote(self) -> 'remote.Remote':
		"""
		Owning Remote

		:return: Remote object
		"""
		value = core.BNCollaborationUserGetRemote(self._handle)
		if value is None:
			raise RuntimeError(util._last_error())
		return remote.Remote(handle=value)

	@property
	def url(self) -> str:
		"""
		Web api endpoint URL

		:return: URL string
		"""
		return core.BNCollaborationUserGetUrl(self._handle)

	@property
	def id(self) -> str:
		"""
		Unique id

		:return: Id string
		"""
		return core.BNCollaborationUserGetId(self._handle)

	@property
	def username(self) -> str:
		"""
		User's login username

		:return: Username string
		"""
		return core.BNCollaborationUserGetUsername(self._handle)

	@username.setter
	def username(self, value: str):
		"""
		Set user's username. You will need to push the user to update the Remote

		:param value: New username
		:raises RuntimeError: If there was an error
		"""
		if not core.BNCollaborationUserSetUsername(self._handle, value):
			raise RuntimeError(util._last_error())

	@property
	def email(self) -> str:
		"""
		User's email address

		:return: Email string
		"""
		return core.BNCollaborationUserGetEmail(self._handle)

	@email.setter
	def email(self, value: str):
		"""
		Set user's email. You will need to push the user to update the Remote

		:param value: New email address
		:raises RuntimeError: If there was an error
		"""
		if not core.BNCollaborationUserSetEmail(self._handle, value):
			raise RuntimeError(util._last_error())

	@property
	def last_login(self) -> str:
		"""
		String representing the last date the user logged in

		:return: Last login string
		"""
		return core.BNCollaborationUserGetLastLogin(self._handle)

	@property
	def is_active(self) -> bool:
		"""
		If the user account is active and can log in

		:return: If account is active
		"""
		return core.BNCollaborationUserIsActive(self._handle)

	@is_active.setter
	def is_active(self, value: bool):
		"""
		Enable/disable a user account. You will need to push the user to update the Remote

		:param value: New active value
		:raises RuntimeError: If there was an error
		"""
		if not core.BNCollaborationUserSetIsActive(self._handle, value):
			raise RuntimeError(util._last_error())
