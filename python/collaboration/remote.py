import ctypes
import json
from typing import Dict, List, Optional, Tuple

import binaryninja
import binaryninja.enterprise as enterprise

from .. import _binaryninjacore as core
from . import databasesync, group, project, user, util


class Remote:
	"""
	Class representing a connection to a Collaboration server
	"""
	def __init__(self, handle: core.BNRemoteHandle):
		"""
		Create a Remote object (but don't connect to it yet)

		:param name: Identifier for remote
		:param address: Base address (HTTPS) for all api requests
		:param handle: FFI handle for internal use
		:raises: RuntimeError if there was an error
		"""

		self._handle = ctypes.cast(handle, core.BNRemoteHandle)

	def __del__(self):
		if core is not None:
			core.BNFreeRemote(self._handle)

	def __eq__(self, other):
		if not isinstance(other, Remote):
			return False
		if not self.has_loaded_metadata or not other.has_loaded_metadata:
			# Don't pull metadata if we haven't yet
			return self.address == other.address
		return other.unique_id == self.unique_id

	def __str__(self):
		return f'<remote: {self.name}>'

	def __repr__(self):
		return f'<remote: {self.name}>'

	@staticmethod
	def get_for_local_database(database: 'binaryninja.Database') -> Optional['Remote']:
		"""
		Get the Remote for a Database

		:param database: BN database, potentially with collaboration metadata
		:return: Remote from one of the connected remotes, or None if not found
		:rtype: Optional[Remote]
		:raises RuntimeError: If there was an error
		"""
		return databasesync.get_remote_for_local_database(database)

	@staticmethod
	def get_for_bv(bv: 'binaryninja.BinaryView') -> Optional['Remote']:
		"""
		Get the Remote for a Binary View

		:param bv: Binary view, potentially with collaboration metadata
		:return: Remote from one of the connected remotes, or None if not found
		:raises RuntimeError: If there was an error
		"""
		if not bv.file.has_database:
			return None
		db = bv.file.database
		if db is None:
			return None
		return databasesync.get_remote_for_local_database(db)

	@property
	def has_loaded_metadata(self):
		"""
		If the remote has pulled metadata like its id, etc

		:return: True if it has been pulled
		"""
		return core.BNRemoteHasLoadedMetadata(self._handle)

	@property
	def unique_id(self) -> str:
		"""
		Unique id. If metadata has not been pulled, it will be pulled upon calling this.

		:return: Id string
		:raises RuntimeError: If there was an error pulling metadata.
		"""
		if not self.has_loaded_metadata:
			self.load_metadata()
		return core.BNRemoteGetUniqueId(self._handle)

	@property
	def name(self) -> str:
		"""
		Assigned name of the Remote

		:return: Name string
		"""
		return core.BNRemoteGetName(self._handle)

	@property
	def address(self) -> str:
		"""
		Base address of the Remote

		:return: URL string
		"""
		return core.BNRemoteGetAddress(self._handle)

	@property
	def is_connected(self) -> bool:
		"""
		If the Remote is connected (has `Remote.connect` been called)

		:return: True if connected
		"""
		return core.BNRemoteIsConnected(self._handle)

	@property
	def username(self) -> str:
		"""
		Username used to connect to the remote

		:return: Username string
		"""
		return core.BNRemoteGetUsername(self._handle)

	@property
	def token(self) -> str:
		"""
		Token used to connect to the remote

		:return: Token string
		"""
		return core.BNRemoteGetToken(self._handle)

	@property
	def server_version(self) -> int:
		"""
		Version of software running on the server. If metadata has not been pulled, it will
		be pulled upon calling this.

		:return: Server version number
		:raises RuntimeError: If there was an error
		"""
		if not self.has_loaded_metadata:
			self.load_metadata()
		return core.BNRemoteGetServerVersion(self._handle)

	@property
	def server_build_id(self) -> str:
		"""
		Build id of software running on the server. If metadata has not been pulled, it will
		be pulled upon calling this.

		:return: Server build id string
		:raises RuntimeError: If there was an error
		"""
		if not self.has_loaded_metadata:
			self.load_metadata()
		return core.BNRemoteGetServerBuildId(self._handle)

	@property
	def auth_backends(self) -> List[Tuple[str, str]]:
		"""
		List of supported authentication backends on the server.
		If metadata has not been pulled, it will be pulled upon calling this.

		:return: List of Backend id <=> backend display name tuples
		:raises RuntimeError: If there was an error
		"""
		if not self.has_loaded_metadata:
			self.load_metadata()
		backend_ids = ctypes.POINTER(ctypes.c_char_p)()
		backend_names = ctypes.POINTER(ctypes.c_char_p)()
		count = ctypes.c_size_t()
		if not core.BNRemoteGetAuthBackends(self._handle, backend_ids, backend_names, count):
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append((core.pyNativeStr(backend_ids[i]), core.pyNativeStr(backend_names[i])))
		core.BNFreeStringList(backend_ids, count.value)
		core.BNFreeStringList(backend_names, count.value)
		return result

	@property
	def is_admin(self) -> bool:
		"""
		If the currently connected user is an administrator.

		.. note:: If users have not been pulled, they will attempt to be pulled upon calling this.

		:return: True if the user is an administrator
		"""

		# This is the test by which the api knows it is an admin
		if not self.has_pulled_users:
			self.pull_users()

		return core.BNRemoteIsAdmin(self._handle)

	@property
	def is_enterprise(self) -> bool:
		"""
		If this remote is the same as the Enterprise License server

		:return: True if the same
		"""
		if not self.has_loaded_metadata:
			self.load_metadata()
		return core.BNRemoteIsEnterprise(self._handle)

	def load_metadata(self):
		"""
		Load metadata from the Remote, including unique id and versions

		:raises RuntimeError: If there was an error
		"""
		if not core.BNRemoteLoadMetadata(self._handle):
			raise RuntimeError(util._last_error())

	def request_authentication_token(self, username: str, password: str) -> Optional[str]:
		"""
		Request an authentication token using a username and password.

		:param username: Username to authenticate with
		:param password: Password of user
		:return: Authentication token string, or None if there was an error
		"""
		return core.BNRemoteRequestAuthenticationToken(self._handle, username, password)

	def connect(self, username: Optional[str] = None, token: Optional[str] = None):
		"""
		Connect to a Remote, loading metadata and optionally acquiring a token.

		.. note:: If no username or token are provided, they will be looked up from the keychain, \
		likely saved there by Enterprise authentication.

		:param username: Optional username to connect with
		:param token: Optional token to authenticate with
		:raises RuntimeError: If the connection fails
		"""
		if not self.has_loaded_metadata:
			self.load_metadata()
		if username is None:
			# Try logging in with defaults
			if self.is_enterprise:
				username = enterprise.username()
				token = enterprise.token()
			else:
				# Load from default secrets provider
				secrets = binaryninja.SecretsProvider[
					binaryninja.Settings().get_string("enterprise.secretsProvider")]
				if not secrets.has_data(self.address):
					raise RuntimeError("No username and token provided, and none found "
									   "in the default keychain.")
				creds = json.loads(secrets.get_data(self.address))
				username = creds['username']
				token = creds['token']
		if username is None or token is None:
			raise RuntimeError("Cannot connect without a username or token")

		if not core.BNRemoteConnect(self._handle, username, token):
			raise RuntimeError(util._last_error())

	def disconnect(self):
		"""
		Disconnect from the remote

		:raises RuntimeError: If there was somehow an error
		"""
		if not core.BNRemoteDisconnect(self._handle):
			raise RuntimeError(util._last_error())

	@property
	def has_pulled_projects(self) -> bool:
		"""
		If the project has pulled the projects yet

		:return: True if they have been pulled
		"""
		return core.BNRemoteHasPulledProjects(self._handle)

	@property
	def has_pulled_groups(self) -> bool:
		"""
		If the project has pulled the groups yet

		:return: True if they have been pulled
		"""
		return core.BNRemoteHasPulledGroups(self._handle)

	@property
	def has_pulled_users(self) -> bool:
		"""
		If the project has pulled the users yet

		:return: True if they have been pulled
		"""
		return core.BNRemoteHasPulledUsers(self._handle)

	@property
	def projects(self) -> List['project.RemoteProject']:
		"""
		Get the list of projects in this project.

		.. note:: If projects have not been pulled, they will be pulled upon calling this.

		:return: List of Project objects
		:raises: RuntimeError if there was an error pulling projects
		"""
		if not self.has_pulled_projects:
			self.pull_projects()

		count = ctypes.c_size_t()
		value = core.BNRemoteGetProjects(self._handle, count)
		if value is None:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(project.RemoteProject(value[i]))
		return result

	def get_project_by_id(self, id: str) -> Optional['project.RemoteProject']:
		"""
		Get a specific project in the Remote by its id

		.. note:: If projects have not been pulled, they will be pulled upon calling this.

		:param id: Id of Project
		:return: Project object, if one with that id exists. Else, None
		:raises: RuntimeError if there was an error pulling projects
		"""
		if not self.has_pulled_projects:
			self.pull_projects()

		value = core.BNRemoteGetProjectById(self._handle, id)
		if value is None:
			return None
		return project.RemoteProject(value)

	def get_project_by_name(self, name: str) -> Optional['project.RemoteProject']:
		"""
		Get a specific project in the Remote by its name

		.. note:: If projects have not been pulled, they will be pulled upon calling this.

		:param name: Name of Project
		:return: Project object, if one with that name exists. Else, None
		:raises: RuntimeError if there was an error pulling projects
		"""
		if not self.has_pulled_projects:
			self.pull_projects()

		value = core.BNRemoteGetProjectByName(self._handle, name)
		if value is None:
			return None
		return project.RemoteProject(value)

	def pull_projects(self, progress: 'util.ProgressFuncType' = util.nop):
		"""
		Pull the list of projects from the Remote.

		:param progress: Function to call for progress updates
		:raises: RuntimeError if there was an error pulling projects
		"""
		if not core.BNRemotePullProjects(self._handle, util.wrap_progress(progress), None):
			raise RuntimeError(util._last_error())

	def create_project(self, name: str, description: str) -> 'project.RemoteProject':
		"""
		Create a new project on the remote (and pull it)

		:param name: Project name
		:param description: Project description
		:return: Reference to the created project
		:raises: RuntimeError if there was an error
		"""
		value = core.BNRemoteCreateProject(self._handle, name, description)
		if value is None:
			raise RuntimeError(util._last_error())
		return project.RemoteProject(value)

	def push_project(self, project: 'project.RemoteProject', extra_fields: Optional[Dict[str, str]] = None):
		"""
		Push an updated Project object to the Remote

		:param project: Project object which has been updated
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
		if not core.BNRemotePushProject(self._handle, project._handle, extra_field_keys, extra_field_values, len(extra_fields)):
			raise RuntimeError(util._last_error())

	def delete_project(self, project: 'project.RemoteProject'):
		"""
		Delete a project from the remote

		:param project: Project to delete
		:raises: RuntimeError if there was an error
		"""
		if not core.BNRemoteDeleteProject(self._handle, project._handle):
			raise RuntimeError(util._last_error())

	@property
	def groups(self) -> List['group.Group']:
		"""
		Get the list of groups in this project.

		.. note:: If groups have not been pulled, they will be pulled upon calling this.

		.. note:: This function is only available to accounts with admin status on the Remote

		:return: List of Group objects
		:raises: RuntimeError if there was an error pulling groups
		"""
		if not self.has_pulled_groups:
			self.pull_groups()

		count = ctypes.c_size_t()
		value = core.BNRemoteGetGroups(self._handle, count)
		if value is None:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(group.Group(value[i]))
		return result

	def get_group_by_id(self, id: int) -> Optional['group.Group']:
		"""
		Get a specific group in the Remote by its id

		.. note:: If groups have not been pulled, they will be pulled upon calling this.

		.. note:: This function is only available to accounts with admin status on the Remote

		:param id: Id of Group
		:return: Group object, if one with that id exists. Else, None
		:raises: RuntimeError if there was an error pulling groups
		"""
		if not self.has_pulled_groups:
			self.pull_groups()

		value = core.BNRemoteGetGroupById(self._handle, id)
		if value is None:
			return None
		return group.Group(value)

	def get_group_by_name(self, name: str) -> Optional['group.Group']:
		"""
		Get a specific group in the Remote by its name

		.. note:: If groups have not been pulled, they will be pulled upon calling this.

		.. note:: This function is only available to accounts with admin status on the Remote

		:param name: Name of Group
		:return: Group object, if one with that name exists. Else, None
		:raises: RuntimeError if there was an error pulling groups
		"""
		if not self.has_pulled_groups:
			self.pull_groups()

		value = core.BNRemoteGetGroupByName(self._handle, name)
		if value is None:
			return None
		return group.Group(value)

	def search_groups(self, prefix: str) -> List[Tuple[int, str]]:
		"""
		Search for groups in the Remote with a given prefix

		:param prefix: Prefix of name for groups
		:return: List of group id <=> group name pairs
		:raises: RuntimeError if there was an error
		"""
		count = ctypes.c_size_t()
		group_ids = ctypes.POINTER(ctypes.c_uint64)()
		group_names = ctypes.POINTER(ctypes.c_char_p)()
		if not core.BNRemoteSearchGroups(self._handle, prefix, group_ids, group_names, count):
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append((group_ids[i], core.pyNativeStr(group_names[i])))
		core.BNCollaborationFreeIdList(group_ids, count.value)
		core.BNFreeStringList(group_names, count.value)
		return result

	def pull_groups(self, progress: 'util.ProgressFuncType' = util.nop):
		"""
		Pull the list of groups from the Remote.

		.. note:: This function is only available to accounts with admin status on the Remote

		:param progress: Function to call for progress updates
		:raises: RuntimeError if there was an error pulling groups
		"""
		if not core.BNRemotePullGroups(self._handle, util.wrap_progress(progress), None):
			raise RuntimeError(util._last_error())

	def create_group(self, name: str, usernames: List[str]) -> 'group.Group':
		"""
		Create a new group on the remote (and pull it)

		.. note:: This function is only available to accounts with admin status on the Remote

		:param name: Group name
		:param usernames: List of usernames of users in the group
		:return: Reference to the created group
		:raises: RuntimeError if there was an error
		"""
		c_usernames = (ctypes.c_char_p * len(usernames))()
		for (i, username) in enumerate(usernames):
			c_usernames[i] = core.cstr(username)

		value = core.BNRemoteCreateGroup(self._handle, name, c_usernames, len(usernames))
		if value is None:
			raise RuntimeError(util._last_error())
		return group.Group(value)

	def push_group(self, group: 'group.Group', extra_fields: Optional[Dict[str, str]] = None):
		"""
		Push an updated Group object to the Remote

		.. note:: This function is only available to accounts with admin status on the Remote

		:param group: Group object which has been updated
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
		if not core.BNRemotePushGroup(self._handle, group._handle, extra_field_keys, extra_field_values, len(extra_fields)):
			raise RuntimeError(util._last_error())

	def delete_group(self, group: 'group.Group'):
		"""
		Delete a group from the remote

		.. note:: This function is only available to accounts with admin status on the Remote

		:param group: Group to delete
		:raises: RuntimeError if there was an error
		"""
		if not core.BNRemoteDeleteGroup(self._handle, group._handle):
			raise RuntimeError(util._last_error())

	@property
	def users(self) -> List['user.User']:
		"""
		Get the list of users in this project.

		.. note:: If users have not been pulled, they will be pulled upon calling this.

		.. note:: This function is only available to accounts with admin status on the Remote

		:return: List of User objects
		:raises: RuntimeError if there was an error pulling users
		"""
		if not self.has_pulled_users:
			self.pull_users()
		count = ctypes.c_size_t()
		value = core.BNRemoteGetUsers(self._handle, count)
		if value is None:
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append(user.User(value[i]))
		return result

	def get_user_by_id(self, id: str) -> Optional['user.User']:
		"""
		Get a specific user in the Remote by their id

		.. note:: If users have not been pulled, they will be pulled upon calling this.

		.. note:: This function is only available to accounts with admin status on the Remote

		:param id: Id of User
		:return: User object, if one with that id exists. Else, None
		:raises: RuntimeError if there was an error pulling users
		"""
		if not self.has_pulled_users:
			self.pull_users()
		value = core.BNRemoteGetUserById(self._handle, id)
		if value is None:
			return None
		return user.User(value)

	def get_user_by_username(self, username: str) -> Optional['user.User']:
		"""
		Get a specific user in the Remote by their username

		.. note:: If users have not been pulled, they will be pulled upon calling this.

		.. note:: This function is only available to accounts with admin status on the Remote

		:param username: Username of User
		:return: User object, if one with that name exists. Else, None
		:raises: RuntimeError if there was an error pulling users
		"""
		if not self.has_pulled_users:
			self.pull_users()
		value = core.BNRemoteGetUserByUsername(self._handle, username)
		if value is None:
			return None
		return user.User(value)

	@property
	def current_user(self) -> Optional['user.User']:
		"""
		Get the user object for the currently connected user (only if you are an admin)

		.. note:: If users have not been pulled, they will be pulled upon calling this.

		.. note:: This function is only available to accounts with admin status on the Remote

		:return: User object
		:raises: RuntimeError if there was an error pulling users
		"""
		if not self.has_pulled_users:
			self.pull_users()
		value = core.BNRemoteGetCurrentUser(self._handle)
		if value is None:
			return None
		return user.User(value)

	def search_users(self, prefix: str) -> List[Tuple[str, str]]:
		"""
		Search for users in the Remote with a given prefix

		:param prefix: Prefix of name for users
		:return: List of user id <=> user name pairs
		:raises: RuntimeError if there was an error
		"""
		count = ctypes.c_size_t()
		user_ids = ctypes.POINTER(ctypes.c_char_p)()
		usernames = ctypes.POINTER(ctypes.c_char_p)()
		if not core.BNRemoteSearchUsers(self._handle, prefix, user_ids, usernames, count):
			raise RuntimeError(util._last_error())
		result = []
		for i in range(count.value):
			result.append((core.pyNativeStr(user_ids[i]), core.pyNativeStr(usernames[i])))
		core.BNFreeStringList(user_ids, count.value)
		core.BNFreeStringList(usernames, count.value)
		return result

	def pull_users(self, progress: 'util.ProgressFuncType' = util.nop):
		"""
		Pull the list of users from the Remote.

		.. note:: This function is only available to accounts with admin status on the Remote. \
		Non-admin accounts attempting to call this function will pull an empty list of users.

		:param progress: Function to call for progress updates
		:raises: RuntimeError if there was an error pulling users
		"""
		if not core.BNRemotePullUsers(self._handle, util.wrap_progress(progress), None):
			raise RuntimeError(util._last_error())

	def create_user(self, username: str, email: str, is_active: bool, password: str, group_ids: List[int], user_permission_ids: List[int]) -> 'user.User':
		"""
		Create a new user on the remote (and pull it)

		.. note:: This function is only available to accounts with admin status on the Remote

		:param username: User username
		:param email: User email
		:param is_active: If the user is enabled
		:param password: User password
		:param group_ids: List of group ids for the user
		:param user_permission_ids: List of permission ids for the user
		:return: Reference to the created user
		:raises: RuntimeError if there was an error
		"""
		group_ids_array = (ctypes.c_uint64 * len(group_ids))()
		for i in range(len(group_ids)):
			group_ids_array[i] = group_ids[i]

		user_permission_ids_array = (ctypes.c_uint64 * len(group_ids))()
		for i in range(len(user_permission_ids)):
			user_permission_ids_array[i] = user_permission_ids[i]

		value = core.BNRemoteCreateUser(self._handle, username, email, is_active, password, group_ids_array, len(group_ids), user_permission_ids_array, len(user_permission_ids))
		if value is None:
			raise RuntimeError(util._last_error())
		return user.User(value)

	def push_user(self, user: 'user.User', extra_fields: Optional[Dict[str, str]] = None):
		"""
		Push an updated User object to the Remote

		.. note:: This function is only available to accounts with admin status on the Remote

		:param group: User object which has been updated
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
		if not core.BNRemotePushUser(self._handle, user._handle, extra_field_keys, extra_field_values, len(extra_fields)):
			raise RuntimeError(util._last_error())
