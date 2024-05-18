import binaryninja

from .changeset import *
from .databasesync import *
from .file import *
from .folder import *
from .group import *
from .project import *
from .remote import *
from .snapshot import *
from .user import *
from .util import _last_error

"""
Collaboration Remote API
Python wrappers around C++ wrappers around the various REST apis exposed by the collaboration server.
Many methods throw RuntimeError, as documented.

None of these classes are thread-safe. Python's GIL probably helps with this but if you are
doing heavily multi-threaded work with these you may want the C++ api.
"""


def active_remote() -> Optional['Remote']:
	"""
	Get the single actively connected Remote (for ux simplification)

	:return: Active Remote, if one is set. None, otherwise.
	"""
	binaryninja._init_plugins()
	value = core.BNCollaborationGetActiveRemote()
	if value is None:
		return None
	result = Remote(handle=value)
	return result


def set_active_remote(remote: Optional['Remote']):
	"""
	Set the single actively connected Remote

	:param remote: New active Remote, or None to clear it.
	"""
	binaryninja._init_plugins()
	if remote is not None:
		core.BNCollaborationSetActiveRemote(remote._handle)
	else:
		core.BNCollaborationSetActiveRemote(None)


def known_remotes() -> List['Remote']:
	"""
	List of known/connected Remotes

	:return: All known remotes
	"""
	binaryninja._init_plugins()
	count = ctypes.c_size_t()
	value = core.BNCollaborationGetRemotes(count)
	result = []
	for i in range(count.value):
		result.append(Remote(handle=value[i]))
	return result


def enterprise_remote() -> Optional['Remote']:
	"""
	Get whichever known Remote has the same address as the Enterprise license server

	:return: Relevant known Remote, or None if one is not found
	"""
	for remote in known_remotes():
		if remote.is_enterprise:
			return remote
	return None


def add_known_remote(remote: 'Remote') -> None:
	"""
	Add a Remote to the list of known remotes (saved to Settings)

	:param remote: New Remote to add
	"""
	binaryninja._init_plugins()
	core.BNCollaborationAddRemote(remote._handle)


def remove_known_remote(remote: 'Remote') -> None:
	"""
	Remove a Remote from the list of known remotes (saved to Settings)

	:param remote: Remote to remove
	"""
	binaryninja._init_plugins()
	core.BNCollaborationRemoveRemote(remote._handle)


def get_remote_by_id(id: str) -> Optional['Remote']:
	"""
	Get Remote by unique id

	:param id: Unique id of the Remote
	:return: Remote, if known, else None
	"""
	binaryninja._init_plugins()
	value = core.BNCollaborationGetRemoteById(id)
	if value is None:
		return None
	result = Remote(handle=value)
	return result


def get_remote_by_address(address: str) -> Optional['Remote']:
	"""
	Get Remote by address

	:param address: Base address of remote api
	:return: Remote, if found, else None
	"""
	binaryninja._init_plugins()
	value = core.BNCollaborationGetRemoteByAddress(address)
	if value is None:
		return None
	result = Remote(handle=value)
	return result


def get_remote_by_name(name: str) -> Optional['Remote']:
	"""
	Get Remote by name

	:param name: Name of Remote
	:return: Remote, if found, else None
	"""
	binaryninja._init_plugins()
	value = core.BNCollaborationGetRemoteByName(name)
	if value is None:
		return None
	result = Remote(handle=value)
	return result


def load_remotes():
	"""
	Load the list of known Remotes from local Settings

	:raises RuntimeError: If there was an error
	"""
	binaryninja._init_plugins()
	if not core.BNCollaborationLoadRemotes():
		raise RuntimeError(_last_error())


def save_remotes():
	"""
	Save the list of known Remotes to local Settings

	:raises RuntimeError: If there was an error
	"""
	binaryninja._init_plugins()
	if not core.BNCollaborationSaveRemotes():
		raise RuntimeError(_last_error())

