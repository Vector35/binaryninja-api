# Copyright (c) 2015-2016 Vector 35 LLC
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

#Binary Ninja components
import _binaryninjacore as core
import startup
import architecture

class _PlatformMetaClass(type):
	@property
	def list(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformList(count)
		result = []
		for i in xrange(0, count.value):
			result.append(Platform(None, core.BNNewPlatformReference(platforms[i])))
		core.BNFreePlatformList(platforms, count.value)
		return result

	@property
	def os_list(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformOSList(count)
		result = []
		for i in xrange(0, count.value):
			result.append(str(platforms[i]))
		core.BNFreePlatformOSList(platforms, count.value)
		return result

	def __iter__(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformList(count)
		try:
			for i in xrange(0, count.value):
				yield Platform(None, core.BNNewPlatformReference(platforms[i]))
		finally:
			core.BNFreePlatformList(platforms, count.value)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __getitem__(cls, value):
		startup._init_plugins()
		platform = core.BNGetPlatformByName(str(value))
		if platform is None:
			raise KeyError, "'%s' is not a valid platform" % str(value)
		return Platform(None, platform)

	def get_list(cls, os = None, arch = None):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		if os is None:
			platforms = core.BNGetPlatformList(count)
		elif arch is None:
			platforms = core.BNGetPlatformListByOS(os)
		else:
			platforms = core.BNGetPlatformListByArchitecture(os, arch.handle)
		result = []
		for i in xrange(0, count.value):
			result.append(Platform(None, core.BNNewPlatformReference(platforms[i])))
		core.BNFreePlatformList(platforms, count.value)
		return result

class Platform(object):
	"""
	``class Platform`` contains all information releated to the execution environment of the binary, mainly the
	calling conventions used.
	"""
	__metaclass__ = _PlatformMetaClass
	name = None

	def __init__(self, arch, handle = None):
		if handle is None:
			self.arch = arch
			self.handle = core.BNCreatePlatform(arch.handle, self.__class__.name)
		else:
			self.handle = handle
			self.__dict__["name"] = core.BNGetPlatformName(self.handle)
			self.arch = architecture.Architecture(core.BNGetPlatformArchitecture(self.handle))

	def __del__(self):
		core.BNFreePlatform(self.handle)

	@property
	def default_calling_convention(self):
		"""
		Default calling convention.

		:getter: returns a CallingConvention object for the default calling convention.
		:setter: sets the default calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformDefaultCallingConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@default_calling_convention.setter
	def default_calling_convention(self, value):
		core.BNRegisterPlatformDefaultCallingConvention(self.handle, value.handle)

	@property
	def cdecl_calling_convention(self):
		"""
		Cdecl calling convention.

		:getter: returns a CallingConvention object for the cdecl calling convention.
		:setter sets the cdecl calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformCdeclCallingConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@cdecl_calling_convention.setter
	def cdecl_calling_convention(self, value):
		core.BNRegisterPlatformCdeclCallingConvention(self.handle, value.handle)

	@property
	def stdcall_calling_convention(self):
		"""
		Stdcall calling convention.

		:getter: returns a CallingConvention object for the stdcall calling convention.
		:setter sets the stdcall calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformStdcallCallingConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@stdcall_calling_convention.setter
	def stdcall_calling_convention(self, value):
		core.BNRegisterPlatformStdcallCallingConvention(self.handle, value.handle)

	@property
	def fastcall_calling_convention(self):
		"""
		Fastcall calling convention.

		:getter: returns a CallingConvention object for the fastcall calling convention.
		:setter sets the fastcall calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformFastcallCallingConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@fastcall_calling_convention.setter
	def fastcall_calling_convention(self, value):
		core.BNRegisterPlatformFastcallCallingConvention(self.handle, value.handle)

	@property
	def system_call_convention(self):
		"""
		System call convention.

		:getter: returns a CallingConvention object for the system call convention.
		:setter sets the system call convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformSystemCallConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@system_call_convention.setter
	def system_call_convention(self, value):
		core.BNSetPlatformSystemCallConvention(self.handle, value.handle)

	@property
	def calling_conventions(self):
		"""
		List of platform CallingConvention objects (read-only)

		:getter: returns the list of supported CallingConvention objects
		:type: list(CallingConvention)
		"""
		count = ctypes.c_ulonglong()
		cc = core.BNGetPlatformCallingConventions(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(CallingConvention(None, core.BNNewCallingConventionReference(cc[i])))
		core.BNFreeCallingConventionList(cc, count.value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __repr__(self):
		return "<platform: %s>" % self.name

	def __str__(self):
		return self.name

	def register(self, os):
		"""
		``register`` registers the platform for given OS name.

		:param str os: OS name to register
		:rtype: None
		"""
		core.BNRegisterPlatform(os, self.handle)

	def register_calling_convention(self, cc):
		"""
		``register_calling_convention`` register a new calling convention.

		:param CallingConvention cc: a CallingConvention object to register
		:rtype: None
		"""
		core.BNRegisterPlatformCallingConvention(self.handle, cc.handle)

	def get_related_platform(self, arch):
		result = core.BNGetRelatedPlatform(self.handle, arch.handle)
		if not result:
			return None
		return Platform(None, handle = result)

	def add_related_platform(self, arch, platform):
		core.BNAddRelatedPlatform(self.handle, arch.handle, platform.handle)
