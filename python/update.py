# Copyright (c) 2015-2021 Vector 35 Inc
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

import traceback
import ctypes

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from .enums import UpdateResult
from . import log



class _UpdateChannelMetaClass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		channels = core.BNGetUpdateChannels(count, errors)
		assert channels is not None, "core.BNGetUpdateChannels returned None"
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		try:
			for i in range(0, count.value):
				yield UpdateChannel(channels[i].name, channels[i].description, channels[i].latestVersion)
		finally:
			core.BNFreeUpdateChannelList(channels, count.value)

	def __getitem__(cls, name):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		channels = core.BNGetUpdateChannels(count, errors)
		assert channels is not None, "core.BNGetUpdateChannels returned None"
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		result = None
		for i in range(0, count.value):
			if channels[i].name == str(name):
				result = UpdateChannel(channels[i].name, channels[i].description, channels[i].latestVersion)
				break
		core.BNFreeUpdateChannelList(channels, count.value)
		if result is None:
			raise KeyError("'%s' is not a valid channel" % str(name))
		return result


class UpdateProgressCallback(object):
	def __init__(self, func):
		self.cb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(self.callback)
		self.func = func

	def callback(self, ctxt, progress, total):
		try:
			if self.func is not None:
				return self.func(progress, total)
			return True
		except:
			log.log_error(traceback.format_exc())

	@property
	def active(cls):
		return core.BNGetActiveUpdateChannel()

	@active.setter
	def active(cls, value:str) -> None:
		return core.BNSetActiveUpdateChannel(value)

class UpdateChannel(metaclass=_UpdateChannelMetaClass):
	def __init__(self, name, desc, ver):
		self._name = name
		self._description = desc
		self._latest_version_num = ver

	@property
	def versions(self):
		"""List of versions (read-only)"""
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		versions = core.BNGetUpdateChannelVersions(self._name, count, errors)
		assert versions is not None, "core.BNGetUpdateChannelVersions returned None"
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		result = []
		for i in range(0, count.value):
			result.append(UpdateVersion(self, versions[i].version, versions[i].notes, versions[i].time))
		core.BNFreeUpdateChannelVersionList(versions, count.value)
		return result

	@property
	def latest_version(self):
		"""Latest version (read-only)"""
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		versions = core.BNGetUpdateChannelVersions(self._name, count, errors)
		assert versions is not None, "core.BNGetUpdateChannelVersions returned None"
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		result = None
		for i in range(0, count.value):
			if versions[i].version == self._latest_version_num:
				result = UpdateVersion(self, versions[i].version, versions[i].notes, versions[i].time)
				break
		core.BNFreeUpdateChannelVersionList(versions, count.value)
		return result

	@property
	def updates_available(self):
		"""Whether updates are available (read-only)"""
		errors = ctypes.c_char_p()
		result = core.BNAreUpdatesAvailable(self._name, None, None, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		return "<channel: %s>" % self._name

	def __str__(self):
		return self._name

	def update_to_latest(self, progress = None):
		cb = UpdateProgressCallback(progress)
		errors = ctypes.c_char_p()
		result = core.BNUpdateToLatestVersion(self._name, errors, cb.cb, None)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		return UpdateResult(result)

	@property
	def name(self):
		return self._name

	@name.setter
	def name(self, value):
		self._name = value

	@property
	def description(self):
		return self._description

	@description.setter
	def description(self, value):
		self._description = value

	@property
	def latest_version_num(self):
		return self._latest_version_num

	@latest_version_num.setter
	def latest_version_num(self, value):
		self._latest_version_num = value


class UpdateVersion(object):
	def __init__(self, channel, ver, notes, t):
		self._channel = channel
		self._version = ver
		self._notes = notes
		self._time = t

	def __repr__(self):
		return "<version: %s>" % self._version

	def __str__(self):
		return self._version

	def update(self, progress = None):
		cb = UpdateProgressCallback(progress)
		errors = ctypes.c_char_p()
		result = core.BNUpdateToVersion(self._channel.name, self._version, errors, cb.cb, None)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		return UpdateResult(result)

	@property
	def channel(self):
		return self._channel

	@channel.setter
	def channel(self, value):
		self._channel = value

	@property
	def version(self):
		return self._version

	@version.setter
	def version(self, value):
		self._version = value

	@property
	def notes(self):
		return self._notes

	@notes.setter
	def notes(self, value):
		self._notes = value

	@property
	def time(self):
		return self._time

	@time.setter
	def time(self, value):
		self._time = value


def are_auto_updates_enabled():
	"""
	``are_auto_updates_enabled`` queries if auto updates are enabled.

	:return: boolean True if auto updates are enabled. False if they are disabled.
	:rtype: bool
	"""
	return core.BNAreAutoUpdatesEnabled()


def set_auto_updates_enabled(enabled):
	"""
	``set_auto_updates_enabled`` sets auto update enabled status.

	:param bool enabled: True to enable update, False to disable updates.
	:rtype: None
	"""
	core.BNSetAutoUpdatesEnabled(enabled)


def get_time_since_last_update_check():
	"""
	``get_time_since_last_update_check`` returns the time stamp for the last time updates were checked.

	:return: time stamp for last update check
	:rtype: int
	"""
	return core.BNGetTimeSinceLastUpdateCheck()


def is_update_installation_pending():
	"""
	``is_update_installation_pending`` whether an update has been downloaded and is waiting installation

	:return: boolean True if an update is pending, false if no update is pending
	:rtype: bool
	"""
	return core.BNIsUpdateInstallationPending()


def install_pending_update():
	"""
	``install_pending_update`` installs any pending updates

	:rtype: None
	"""
	errors = ctypes.c_char_p()
	core.BNInstallPendingUpdate(errors)
	if errors:
		error_str = errors.value
		core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
		raise IOError(error_str)


def updates_checked():
	core.BNUpdatesChecked()
