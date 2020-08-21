# Copyright (c) 2015-2020 Vector 35 Inc
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
from json import loads, dumps
import sys
import traceback

if sys.version_info >= (3, 0, 0):
	from urllib.parse import urlencode
else:
	from urllib import urlencode

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


def to_bytes(field):
	if type(field) == bytes:
		return field
	if type(field) == str:
		return field.encode()
	return str(field).encode()


class DownloadInstance(object):
	_registered_instances = []
	_response = b""
	_data = b""

	class Response:
		def __init__(self, status_code, headers, content):
			self.status_code = status_code
			self.headers = headers
			self.content = content

	def __init__(self, provider, handle = None):
		if handle is None:
			self._cb = core.BNDownloadInstanceCallbacks()
			self._cb.context = 0
			self._cb.destroyInstance = self._cb.destroyInstance.__class__(self._destroy_instance)
			self._cb.performRequest = self._cb.performRequest.__class__(self._perform_request)
			self._cb.performCustomRequest = self._cb.performCustomRequest.__class__(self._perform_custom_request)
			self._cb.freeResponse = self._cb.freeResponse.__class__(self._free_response)
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

	def _perform_custom_request(self, ctxt, method, url, header_count, header_keys, header_values, response):
		# Cast response to an array of length 1 so ctypes can write to the pointer
		# out_response = ((BNDownloadInstanceResponse*)[1])response
		out_response = (ctypes.POINTER(core.BNDownloadInstanceResponse) * 1).from_address(ctypes.addressof(response.contents))
		try:
			# Extract headers
			keys_ptr = ctypes.cast(header_keys, ctypes.POINTER(ctypes.c_char_p))
			values_ptr = ctypes.cast(header_values, ctypes.POINTER(ctypes.c_char_p))
			header_key_array = (ctypes.c_char_p * header_count).from_address(ctypes.addressof(keys_ptr.contents))
			header_value_array = (ctypes.c_char_p * header_count).from_address(ctypes.addressof(values_ptr.contents))
			headers = {}
			for i in range(header_count):
				headers[header_key_array[i]] = header_value_array[i]

			# Read all data
			data = b''
			while True:
				read_buffer = ctypes.create_string_buffer(0x1000)
				read_len = core.BNReadDataForDownloadInstance(self.handle, ctypes.cast(read_buffer, ctypes.POINTER(ctypes.c_uint8)), 0x1000)
				if read_len == 0:
					break
				data += read_buffer[:read_len]

			py_response = self.perform_custom_request(method, url, headers, data)
			if py_response is not None:
				# Assign to an instance variable so the memory stays live until the request is done
				self.bn_response = core.BNDownloadInstanceResponse()
				self.bn_response.statusCode = py_response.status_code
				self.bn_response.headerCount = len(py_response.headers)
				self.bn_response.headerKeys = (ctypes.c_char_p * len(py_response.headers))()
				self.bn_response.headerValues = (ctypes.c_char_p * len(py_response.headers))()
				for i, (key, value) in enumerate(py_response.headers.items()):
					self.bn_response.headerKeys[i] = core.BNAllocString(pyNativeStr(key))
					self.bn_response.headerValues[i] = core.BNAllocString(pyNativeStr(value))

				out_response[0] = ctypes.pointer(self.bn_response)
			else:
				out_response[0] = None
			return 0 if py_response is not None else -1
		except:
			out_response[0] = None
			log.log_error(traceback.format_exc())
			return -1

	def _free_response(self, ctxt, response):
		del self.bn_response

	@abc.abstractmethod
	def perform_destroy_instance(self):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_request(self, url):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_custom_request(self, method, url, headers, data):
		raise NotImplementedError

	def _read_callback(self, data, len_, ctxt):
		try:
			bytes_len = len_
			if bytes_len > len(self._data):
				bytes_len = len(self._data)

			c = ctypes.cast(data, ctypes.POINTER(ctypes.c_char))
			writeable_data = (ctypes.c_char * len_).from_address(ctypes.addressof(c.contents))
			writeable_data[:bytes_len] = self._data[:bytes_len]
			self._data = self._data[bytes_len:]

			return bytes_len
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _write_callback(self, data, len, ctxt):
		try:
			str_bytes = ctypes.string_at(data, len)
			self._response = self._response + str_bytes
			return len
		except:
			log.log_error(traceback.format_exc())
			return 0

	def get_response(self, url):
		callbacks = core.BNDownloadInstanceOutputCallbacks()
		callbacks.writeCallback = callbacks.writeCallback.__class__(self._write_callback)
		callbacks.writeContext = 0
		callbacks.progressContext = 0
		self._response = b""
		result = core.BNPerformDownloadRequest(self.handle, url, callbacks)
		return (result, self._response)

	def request(self, method, url, headers=None, data=None, json=None):
		if headers is None:
			headers = {}
		if data is None and json is None:
			data = b''
		elif data is None and json is not None:
			data = to_bytes(dumps(json))
			if "Content-Type" not in headers:
				headers["Content-Type"] = "application/json"
		elif data is not None and json is None:
			if type(data) == dict:
				# Urlencode data as a form body
				data = to_bytes(urlencode(data))
				if "Content-Type" not in headers:
					headers["Content-Type"] = "application/x-www-form-urlencoded"
			else:
				assert(type(data) == bytes)

		self._data = data
		if len(data) > 0 and "Content-Length" not in headers:
			headers["Content-Length"] = len(data)
		if "Content-Type" not in headers:
			headers["Content-Type"] = "application/octet-stream"

		callbacks = core.BNDownloadInstanceInputOutputCallbacks()
		callbacks.readCallback = callbacks.readCallback.__class__(self._read_callback)
		callbacks.writeCallback = callbacks.writeCallback.__class__(self._write_callback)
		callbacks.readContext = 0
		callbacks.writeContext = 0
		callbacks.progressContext = 0
		self._response = b""
		header_keys = (ctypes.c_char_p * len(headers))()
		header_values = (ctypes.c_char_p * len(headers))()
		for (i, item) in enumerate(headers.items()):
			key, value = item
			header_keys[i] = to_bytes(key)
			header_values[i] = to_bytes(value)

		response = ctypes.POINTER(core.BNDownloadInstanceResponse)()
		result = core.BNPerformCustomRequest(self.handle, method, url, len(headers), header_keys, header_values, response, callbacks)

		if result != 0:
			return None

		response_headers = {}
		for i in range(response.contents.headerCount):
			response_headers[response.contents.headerKeys[i]] = response.contents.headerValues[i]

		return DownloadInstance.Response(response.contents.statusCode, response_headers, self._response)

	def get(self, url, headers=None):
		return self.request("GET", url, headers)

	def post(self, url, headers=None, data=None, json=None):
		return self.request("POST", url, headers, data, json)

	def put(self, url, headers=None, data=None, json=None):
		return self.request("POST", url, headers, data, json)

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


_loaded = False

try:
	import requests
	if sys.platform != "win32":
		try:
			from requests import pyopenssl
		except:
			pass
	elif core.BNIsUIEnabled():
		try:
			# since requests will use urllib behind the scenes, which will use
			# the openssl statically linked into _ssl.pyd, the first connection made
			# will attempt to walk the entire process heap on windows using Heap32First
			# and Heap32Next, which is O(n^2) in heap allocations. by doing this now,
			# earlier and before threads are started, hopefully we dodge some of the impact.
			# this should also help with some issues where when Heap32First fails to walk the
			# heap and causes an exception, and because openssl 1.0.2q's RAND_poll implementation
			# wraps this all in a __try block and silently eats said exception, when the windows
			# segment heap is explicitly turned on this leaves the heap in a locked state resulting
			# in process deadlock as other threads attempt to allocate or free memory.
			#
			# as an additional *delightful* addendum, it turns out that when the windows segment
			# heap is manually flipped on, Heap32First/Heap32Next being called while another
			# thread is interacting with the allocator can deadlock (or outright crash) the entire
			# process.
			#
			# considering that this can be reproduced in a 60 line C file that mallocs/frees in a loop
			# while another thread just runs the toolhelp example code from msdn, this is probably
			# a windows bug. if it's not, then it's an openssl bug. ugh.
			#
			# radioactive superfund site workaround follows:
			# RAND_status should cause the broken openssl code to run before too many threads are
			# started in the UI case. this drastically reduces the repro rate in the interim. it still
			# happens occasionally; threads spawned by the intel graphics drivers seem to still get hit here,
			# but only ~1/2 the time. on machines i've interacted with personally, this drops repro rate to 0%.
			#
			# TODO FIXME remove asap when windows patch/hotfix (hopefully) gets released
			import _ssl
			_ssl.RAND_status()
		except:
			pass

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

		def perform_custom_request(self, method, url, headers, data):
			try:
				proxy_setting = Settings().get_string('downloadClient.httpsProxy')
				if proxy_setting:
					proxies = {"https": proxy_setting}
				else:
					proxies = None

				r = requests.request(pyNativeStr(method), pyNativeStr(url), headers=headers, data=data, proxies=proxies)
				response = r.content
				if len(response) == 0:
					core.BNSetErrorForDownloadInstance(self.handle, "No data received from server!")
					return None
				raw_bytes = (ctypes.c_ubyte * len(response)).from_buffer_copy(response)
				bytes_wrote = core.BNWriteDataForDownloadInstance(self.handle, raw_bytes, len(raw_bytes))
				if bytes_wrote != len(raw_bytes):
					core.BNSetErrorForDownloadInstance(self.handle, "Bytes written mismatch!")
					return None
				continue_download = core.BNNotifyProgressForDownloadInstance(self.handle, bytes_wrote, bytes_wrote)
				if continue_download is False:
					core.BNSetErrorForDownloadInstance(self.handle, "Download aborted!")
					return None

				return DownloadInstance.Response(r.status_code, r.headers, None)
			except requests.RequestException as e:
				core.BNSetErrorForDownloadInstance(self.handle, e.__class__.__name__)
				return None
			except:
				core.BNSetErrorForDownloadInstance(self.handle, "Unknown Exception!")
				log.log_error(traceback.format_exc())
				return None

	class PythonDownloadProvider(DownloadProvider):
		name = "PythonDownloadProvider"
		instance_class = PythonDownloadInstance

	PythonDownloadProvider().register()
	_loaded = True
except ImportError:
	pass

if not _loaded and (sys.platform != "win32") and (sys.version_info >= (2, 7, 9)):
	try:
		try:
			from urllib.request import urlopen, build_opener, install_opener, ProxyHandler, Request
			from urllib.error import URLError, HTTPError
		except ImportError:
			from urllib2 import urlopen, build_opener, install_opener, ProxyHandler, URLError, HTTPError, Request

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
					log.log_error(str(e))
					return -1
				except:
					core.BNSetErrorForDownloadInstance(self.handle, "Unknown Exception!")
					log.log_error(traceback.format_exc())
					return -1

				return 0

			class CustomRequest(Request):
				"""
				urllib2 (python2) does not have a parameter for custom request methods
				So this is a shim class to deal with that
				"""

				def __init__(self, *args, **kwargs):
					if "method" in kwargs:
						self._method = kwargs["method"]
						# Need to remove from kwargs or python2 will complain about the unused arg
						del kwargs["method"]
					else:
						self._method = None

					Request.__init__(self, *args, **kwargs)

				def get_method(self, *args, **kwargs):
					if self._method is not None:
						return self._method
					return Request.get_method(self, *args, **kwargs)

			def perform_custom_request(self, method, url, headers, data):
				result = None
				try:
					proxy_setting = Settings().get_string('downloadClient.httpsProxy')
					if proxy_setting:
						opener = build_opener(ProxyHandler({'https': proxy_setting}))
						install_opener(opener)

					if b"Content-Length" in headers:
						del headers[b"Content-Length"]

					req = PythonDownloadInstance.CustomRequest(pyNativeStr(url), data=data, headers=headers, method=pyNativeStr(method))
					result = urlopen(req)
				except HTTPError as he:
					result = he
				except URLError as e:
					core.BNSetErrorForDownloadInstance(self.handle, e.__class__.__name__)
					log.log_error(str(e))
					return None
				except:
					core.BNSetErrorForDownloadInstance(self.handle, "Unknown Exception!")
					log.log_error(traceback.format_exc())
					return None

				total_size = int(result.headers.get('content-length', 0))
				bytes_sent = 0
				while True:
					data = result.read(4096)
					if not data:
						break
					raw_bytes = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
					bytes_wrote = core.BNWriteDataForDownloadInstance(self.handle, raw_bytes, len(raw_bytes))
					if bytes_wrote != len(raw_bytes):
						core.BNSetErrorForDownloadInstance(self.handle, "Bytes written mismatch!")
						return None
					bytes_sent = bytes_sent + bytes_wrote
					continue_download = core.BNNotifyProgressForDownloadInstance(self.handle, bytes_sent, total_size)
					if continue_download is False:
						core.BNSetErrorForDownloadInstance(self.handle, "Download aborted!")
						return None

				if not bytes_sent:
					core.BNSetErrorForDownloadInstance(self.handle, "Received no data!")
					return None

				return DownloadInstance.Response(result.getcode(), result.headers, None)

		class PythonDownloadProvider(DownloadProvider):
			name = "PythonDownloadProvider"
			instance_class = PythonDownloadInstance

		PythonDownloadProvider().register()
		_loaded = True
	except ImportError:
		pass

if not _loaded:
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
