# Copyright (c) 2015-2019 Vector 35 Inc
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
import ctypes
import sys
import traceback

# Binary Ninja Components
import binaryninja._binaryninjacore as core

import binaryninja
from binaryninja.settings import Settings
from binaryninja import with_metaclass
from binaryninja import startup
from binaryninja import log

# 2-3 compatibility
from binaryninja import pyNativeStr
from binaryninja import range


class DownloadInstance(object):
	_registered_instances = []
	def __init__(self, provider, handle = None):
		if handle is None:
			self._cb = core.BNDownloadInstanceCallbacks()
			self._cb.context = 0
			self._cb.destroyInstance = self._cb.destroyInstance.__class__(self._destroy_instance)
			self._cb.performRequest = self._cb.performRequest.__class__(self._perform_request)
			self.handle = core.BNInitDownloadInstance(provider.handle, self._cb)
			self.__class__._registered_instances.append(self)
		else:
			self.handle = core.handle_of_type(handle, core.BNDownloadInstance)
		self._must_free = handle is not None

	def __del__(self):
		if self._must_free:
			core.BNFreeDownloadInstance(self.handle)

	def _destroy_instance(self, ctxt):
		try:
			if self in self.__class__._registered_instances:
				self.__class__._registered_instances.remove(self)
			self.perform_destroy_instance()
		except:
			log.log_error(traceback.format_exc())

	def _perform_request(self, ctxt, url):
		try:
			return self.perform_request(url)
		except:
			log.log_error(traceback.format_exc())
			return -1

	@abc.abstractmethod
	def perform_destroy_instance(self):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_request(self, ctxt, url):
		raise NotImplementedError


class _DownloadProviderMetaclass(type):
	@property
	def list(self):
		"""List all DownloadProvider types (read-only)"""
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetDownloadProviderList(count)
		result = []
		for i in range(0, count.value):
			result.append(DownloadProvider(types[i]))
		core.BNFreeDownloadProviderList(types)
		return result

	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetDownloadProviderList(count)
		try:
			for i in range(0, count.value):
				yield DownloadProvider(types[i])
		finally:
			core.BNFreeDownloadProviderList(types)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		provider = core.BNGetDownloadProviderByName(str(value))
		if provider is None:
			raise KeyError("'%s' is not a valid download provider" % str(value))
		return DownloadProvider(provider)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class DownloadProvider(with_metaclass(_DownloadProviderMetaclass, object)):
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


if (sys.platform != "win32") and (sys.version_info >= (2, 7, 9)):
	try:
		from urllib.request import urlopen, build_opener, install_opener, ProxyHandler
		from urllib.error import URLError
	except ImportError:
		from urllib2 import urlopen, build_opener, install_opener, ProxyHandler, URLError

	class PythonDownloadInstance(DownloadInstance):
		def __init__(self, provider):
			super(PythonDownloadInstance, self).__init__(provider)

		def perform_destroy_instance(self):
			pass

		def perform_request(self, url):
			try:
				proxy_setting = Settings().get_string('downloadClient.httpsProxy')
				if proxy_setting:
					opener = build_opener(ProxyHandler({'https': proxy_setting}))
					install_opener(opener)

				r = urlopen(pyNativeStr(url))
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
		name = "PythonDownloadProvider"
		instance_class = PythonDownloadInstance

	PythonDownloadProvider().register()
else:
	try:
		import requests
		if sys.platform != "win32":
			from requests import pyopenssl
		class PythonDownloadInstance(DownloadInstance):
			def __init__(self, provider):
				super(PythonDownloadInstance, self).__init__(provider)

			def perform_destroy_instance(self):
				pass

			def perform_request(self, url):
				try:
					proxy_setting = Settings().get_string('downloadClient.httpsProxy')
					if proxy_setting:
						proxies = {"https": proxy_setting}
					else:
						proxies = None

					r = requests.get(pyNativeStr(url), proxies=proxies)
					if not r.ok:
						core.BNSetErrorForDownloadInstance(self.handle, "Received error from server")
						return -1
					data = r.content
					if len(data) == 0:
						core.BNSetErrorForDownloadInstance(self.handle, "No data received from server!")
						return -1
					raw_bytes = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
					bytes_wrote = core.BNWriteDataForDownloadInstance(self.handle, raw_bytes, len(raw_bytes))
					if bytes_wrote != len(raw_bytes):
						core.BNSetErrorForDownloadInstance(self.handle, "Bytes written mismatch!")
						return -1
					continue_download = core.BNNotifyProgressForDownloadInstance(self.handle, bytes_wrote, bytes_wrote)
					if continue_download is False:
						core.BNSetErrorForDownloadInstance(self.handle, "Download aborted!")
						return -1
				except requests.RequestException as e:
					core.BNSetErrorForDownloadInstance(self.handle, e.__class__.__name__)
					return -1
				except:
					core.BNSetErrorForDownloadInstance(self.handle, "Unknown Exception!")
					log.log_error(traceback.format_exc())
					return -1

				return 0

		class PythonDownloadProvider(DownloadProvider):
			name = "PythonDownloadProvider"
			instance_class = PythonDownloadInstance

		PythonDownloadProvider().register()
	except ImportError:
		if sys.platform == "win32":
			log.log_error("The pip requests package is required for network connectivity!")
			log.log_error("Please install the requests package into the selected Python environment:")
			log.log_error("  python -m pip install requests")
		else:
			log.log_error("On Python versions below 2.7.9, the pip requests[security] package is required for network connectivity!")
			log.log_error("On an Ubuntu 14.04 install, the following three commands are sufficient to enable networking for the current user:")
			log.log_error("  sudo apt install python-pip")
			log.log_error("  python -m pip install pip --upgrade --user")
			log.log_error("  python -m pip install requests[security] --upgrade --user")

