# Copyright (c) 2015-2017 Vector 35 LLC
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
import _binaryninjacore as core
from enums import UpdateResult
import startup
import log


class _UpdateChannelMetaClass(type):
	@property
	def list(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		channels = core.BNGetUpdateChannels(count, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		result = []
		for i in xrange(0, count.value):
			result.append(UpdateChannel(channels[i].name, channels[i].description, channels[i].latestVersion))
		core.BNFreeUpdateChannelList(channels, count.value)
		return result

	@property
	def active(self):
		return core.BNGetActiveUpdateChannel()

	@active.setter
	def active(self, value):
		return core.BNSetActiveUpdateChannel(value)

	def __iter__(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		channels = core.BNGetUpdateChannels(count, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		try:
			for i in xrange(0, count.value):
				yield UpdateChannel(channels[i].name, channels[i].description, channels[i].latestVersion)
		finally:
			core.BNFreeUpdateChannelList(channels, count.value)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __getitem__(cls, name):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		channels = core.BNGetUpdateChannels(count, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		result = None
		for i in xrange(0, count.value):
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


class UpdateChannel(object):
	__metaclass__ = _UpdateChannelMetaClass

	def __init__(self, name, desc, ver):
		self.name = name
		self.description = desc
		self.latest_version_num = ver

	@property
	def versions(self):
		"""List of versions (read-only)"""
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		versions = core.BNGetUpdateChannelVersions(self.name, count, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		result = []
		for i in xrange(0, count.value):
			result.append(UpdateVersion(self, versions[i].version, versions[i].notes, versions[i].time))
		core.BNFreeUpdateChannelVersionList(versions, count.value)
		return result

	@property
	def latest_version(self):
		"""Latest version (read-only)"""
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		versions = core.BNGetUpdateChannelVersions(self.name, count, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		result = None
		for i in xrange(0, count.value):
			if versions[i].version == self.latest_version_num:
				result = UpdateVersion(self, versions[i].version, versions[i].notes, versions[i].time)
				break
		core.BNFreeUpdateChannelVersionList(versions, count.value)
		return result

	@property
	def updates_available(self):
		"""Whether updates are available (read-only)"""
		errors = ctypes.c_char_p()
		result = core.BNAreUpdatesAvailable(self.name, errors)
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
		return "<channel: %s>" % self.name

	def __str__(self):
		return self.name

	def update_to_latest(self, progress = None):
		cb = UpdateProgressCallback(progress)
		errors = ctypes.c_char_p()
		result = core.BNUpdateToLatestVersion(self.name, errors, cb.cb, None)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		return UpdateResult(result)


class UpdateVersion(object):
	def __init__(self, channel, ver, notes, t):
		self.channel = channel
		self.version = ver
		self.notes = notes
		self.time = t

	def __repr__(self):
		return "<version: %s>" % self.version

	def __str__(self):
		return self.version

	def update(self, progress = None):
		cb = UpdateProgressCallback(progress)
		errors = ctypes.c_char_p()
		result = core.BNUpdateToVersion(self.channel.name, self.version, errors, cb.cb, None)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError(error_str)
		return UpdateResult(result)


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

	:param bool enabled: True to enable update, Flase to disable updates.
	:rtype: None
	"""
	core.BNSetAutoUpdatesEnabled(enabled)


def get_time_since_last_update_check():
	"""
	``get_time_since_last_update_check`` returns the time stamp for the last time updates were checked.

	:return: time stacmp for last update check
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
