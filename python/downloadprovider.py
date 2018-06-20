# Copyright (c) 2015-2018 Vector 35 LLC
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


import abc
import code
import ctypes
import sys
import traceback

try:
	from urllib.parse import urlparse, urlencode
	from urllib.request import urlopen, Request, build_opener, install_opener, ProxyHandler
	from urllib.error import HTTPError, URLError
except ImportError:
	from urlparse import urlparse
	from urllib import urlencode
	from urllib2 import urlopen, Request, build_opener, install_opener, ProxyHandler, HTTPError, URLError

# Binary Ninja Components
import _binaryninjacore as core
from binaryninja.setting import Setting
import startup
import log


class DownloadInstance(object):
	def __init__(self, provider, handle = None):
		if handle is None:
			self._cb = core.BNDownloadInstanceCallbacks()
			self._cb.context = 0
			self._cb.destroyInstance = self._cb.destroyInstance.__class__(self._destroy_instance)
			self._cb.performRequest = self._cb.performRequest.__class__(self._perform_request)
			self.handle = core.BNInitDownloadInstance(provider.handle, self._cb)
		else:
			self.handle = core.handle_of_type(handle, core.BNDownloadInstance)
		self._outputCallbacks = None

	def __del__(self):
		core.BNFreeDownloadInstance(self.handle)

	def _destroy_instance(self, ctxt):
		try:
			self.perform_destroy_instance()
		except:
			log.log_error(traceback.format_exc())

	def _perform_request(self, ctxt, url):
		try:
			return self.perform_request(ctxt, url)
		except:
			log.log_error(traceback.format_exc())
			return -1

	@abc.abstractmethod
	def perform_destroy_instance(self):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_request(self, ctxt, url):
		raise NotImplementedError

	def perform_request(self, url, callbacks):
		return core.BNPerformDownloadRequest(self.handle, url, callbacks)


class _DownloadProviderMetaclass(type):
	@property
	def list(self):
		"""List all DownloadProvider types (read-only)"""
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetDownloadProviderList(count)
		result = []
		for i in xrange(0, count.value):
			result.append(DownloadProvider(types[i]))
		core.BNFreeDownloadProviderList(types)
		return result

	def __iter__(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetDownloadProviderList(count)
		try:
			for i in xrange(0, count.value):
				yield DownloadProvider(types[i])
		finally:
			core.BNFreeDownloadProviderList(types)

	def __getitem__(self, value):
		startup._init_plugins()
		provider = core.BNGetDownloadProviderByName(str(value))
		if provider is None:
			raise KeyError("'%s' is not a valid download provider" % str(value))
		return DownloadProvider(provider)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class DownloadProvider(object):
	__metaclass__ = _DownloadProviderMetaclass
	name = None
	instance_class = None
	_registered_providers = []

	def __init__(self, handle = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNDownloadProvider)
			self.__dict__["name"] = core.BNGetDownloadProviderName(handle)

	def register(self):
		self._cb = core.BNDownloadProviderCallbacks()
		self._cb.context = 0
		self._cb.createInstance = self._cb.createInstance.__class__(self._create_instance)
		self.handle = core.BNRegisterDownloadProvider(self.__class__.name, self._cb)
		self.__class__._registered_providers.append(self)

	def _create_instance(self, ctxt):
		try:
			result = self.__class__.instance_class(self)
			if result is None:
				return None
			return ctypes.cast(core.BNNewDownloadInstanceReference(result.handle), ctypes.c_void_p).value
		except:
			log.log_error(traceback.format_exc())
			return None

	def create_instance(self):
		result = core.BNCreateDownloadProviderInstance(self.handle)
		if result is None:
			return None
		return DownloadInstance(self, handle = result)


class PythonDownloadInstance(DownloadInstance):
	def __init__(self, provider):
		super(PythonDownloadInstance, self).__init__(provider)

	@abc.abstractmethod
	def perform_destroy_instance(self):
		pass

	@abc.abstractmethod
	def perform_request(self, ctxt, url):
		try:
			proxy_setting = Setting('download-client').get_string('https-proxy')
			if proxy_setting:
				opener = build_opener(ProxyHandler({'https': proxy_setting}))
				install_opener(opener)

			r = urlopen(url)
			total_size = int(r.headers.get('content-length', 0))
			bytes_sent = 0
			while True:
				data = r.read(4096)
				if not data:
					break
				raw_bytes = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
				bytes_wrote = core.BNWriteDataForDownloadInstance(self.handle, raw_bytes, len(raw_bytes))
				if bytes_wrote != len(raw_bytes):
					core.BNSetErrorForDownloadInstance(self.handle, "Bytes written mismatch!")
					return -1
				bytes_sent = bytes_sent + bytes_wrote
				continue_download = core.BNNotifyProgressForDownloadInstance(self.handle, bytes_sent, total_size)
				if continue_download is False:
					core.BNSetErrorForDownloadInstance(self.handle, "Download aborted!")
					return -1

			if not bytes_sent:
				core.BNSetErrorForDownloadInstance(self.handle, "Received no data!")
				return -1

		except URLError as e:
			core.BNSetErrorForDownloadInstance(self.handle, e.__class__.__name__)
			return -1
		except:
			core.BNSetErrorForDownloadInstance(self.handle, "Unknown Exception!")
			log.log_error(traceback.format_exc())
			return -1

		return 0


class PythonDownloadProvider(DownloadProvider):
	name = "DefaultDownloadProvider"
	instance_class = PythonDownloadInstance


PythonDownloadProvider().register()
