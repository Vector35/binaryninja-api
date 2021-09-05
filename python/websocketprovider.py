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
from .log import log_error



def nop(*args, **kwargs):
	pass


def to_bytes(field):
	if type(field) == bytes:
		return field
	if type(field) == str:
		return field.encode()
	return str(field).encode()


class WebsocketClient(object):
	_registered_clients = []

	def __init__(self, provider, handle = None):
		if handle is None:
			self._cb = core.BNWebsocketClientCallbacks()
			self._cb.context = 0
			self._cb.destroyClient = self._cb.destroyClient.__class__(self._destroy_client)
			self._cb.connect = self._cb.connect.__class__(self._connect)
			self._cb.write = self._cb.write.__class__(self._write)
			self._cb.disconnect = self._cb.disconnect.__class__(self._disconnect)
			self.handle = core.BNInitWebsocketClient(provider.handle, self._cb)
			self.__class__._registered_clients.append(self)
		else:
			self.handle = core.handle_of_type(handle, core.BNWebsocketClient)
		self._must_free = handle is not None
		self.on_connected = nop
		self.on_disconnected = nop
		self.on_error = nop
		self.on_data = nop
		self._connected = False

	def __del__(self):
		if self._must_free:
			core.BNFreeWebsocketClient(self.handle)

	def _destroy_client(self, ctxt):
		try:
			if self in self.__class__._registered_clients:
				self.__class__._registered_clients.remove(self)
			self.perform_destroy_client()
		except:
			log_error(traceback.format_exc())

	def _connect(self, ctxt, host, header_count, header_keys, header_values):
		# Extract headers
		keys_ptr = ctypes.cast(header_keys, ctypes.POINTER(ctypes.c_char_p))
		values_ptr = ctypes.cast(header_values, ctypes.POINTER(ctypes.c_char_p))
		header_key_array = (ctypes.c_char_p * header_count).from_address(ctypes.addressof(keys_ptr.contents))
		header_value_array = (ctypes.c_char_p * header_count).from_address(ctypes.addressof(values_ptr.contents))
		headers = {}
		for i in range(header_count):
			headers[header_key_array[i]] = header_value_array[i]

		return self.perform_connect(host, headers)

	def _write(self, data, len, ctxt):
		try:
			data_bytes = (ctypes.c_char * len).from_buffer(data)
			self.perform_write(data_bytes)
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _disconnect(self, ctxt):
		return self.perform_disconnect()

	def _connected_callback(self, ctxt):
		self.on_connected()
		return True

	def _disconnected_callback(self, ctxt):
		self.on_disconnected()

	def _error_callback(self, msg, ctxt):
		self.on_error(msg)

	def _read_callback(self, data, len, ctxt):
		c = ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte))
		data_bytes = (ctypes.c_ubyte * len).from_address(ctypes.addressof(c.contents))
		self.on_data(bytes(data_bytes))
		return True

	@abc.abstractmethod
	def perform_connect(self, host, headers):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_destroy_client(self):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_write(self, data):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_disconnect(self):
		raise NotImplementedError

	def connect(self, url, headers=None, on_connected=nop, on_disconnected=nop, on_error=nop, on_data=nop):
		"""
		Connect to a given url, asynchronously. The connection will be run in a separate thread managed by the websocket provider.
		Client callbacks are set according to whichever on_ callback parameters you pass.

		Callbacks will be called **on the thread of the connection**, so be sure to execute_on_main_thread any long-running
		or gui operations in the callbacks.

		If the connection succeeds, on_connected will be called. On normal termination, on_disconnected will be called.
		If the connection succeeds, but later fails, on_disconnected will not be called, and on_error will be called instead.
		If the connection fails, neither on_connected nor on_disconnected will be called, and on_error will be called instead.

		If on_connected or on_data return false, the connection will be aborted.

		:param str url: full url with scheme, domain, optionally port, and path
		:param dict headers: dictionary of string header keys to string header values
		:param function() -> bool on_connected: function to call when connection succeeds
		:param function() -> void on_disconnected: function to call when connection is closed normally
		:param function(str) -> void on_error: function to call when connection is closed with an error
		:param function(bytes) -> bool on_data: function to call when data is read from the websocket
		:return: if the connection has started, but not necessarily if it succeeded
		:rtype: bool
		"""
		if self._connected:
			raise RuntimeError("Cannot use connect() twice on the same WebsocketClient")

		self._connected = True

		header_keys = (ctypes.c_char_p * len(headers))()
		header_values = (ctypes.c_char_p * len(headers))()
		for (i, item) in enumerate(headers.items()):
			key, value = item
			header_keys[i] = to_bytes(key)
			header_values[i] = to_bytes(value)

		# Store this so the callbacks are not GC'd
		self.io_callbacks = core.BNWebsocketClientOutputCallbacks()
		self.io_callbacks.context = 0
		self.io_callbacks.connectedCallback = self.io_callbacks.connectedCallback.__class__(self._connected_callback)
		self.io_callbacks.disconnectedCallback = self.io_callbacks.disconnectedCallback.__class__(self._disconnected_callback)
		self.io_callbacks.errorCallback = self.io_callbacks.errorCallback.__class__(self._error_callback)
		self.io_callbacks.readCallback = self.io_callbacks.readCallback.__class__(self._read_callback)

		self.on_connected = on_connected
		self.on_disconnected = on_disconnected
		self.on_error = on_error
		self.on_data = on_data

		return core.BNConnectWebsocketClient(self.handle, url, len(headers), header_keys, header_values, self.io_callbacks)

	def write(self, data):
		"""
		Send some data to the websocket

		:param bytes data: data to write
		:return: true if successful
		:rtype: bool
		"""
		return core.BNWriteWebsocketClientData(self.handle, (ctypes.c_ubyte * len(data)).from_buffer_copy(data), len(data))

	def disconnect(self):
		"""
		Disconnect the websocket

		:return: true if successful
		:rtype: bool
		"""
		return core.BNDisconnectWebsocketClient(self.handle)

class _WebsocketProviderMetaclass(type):
	@property
	def list(self):
		"""List all WebsocketProvider types (read-only)"""
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetWebsocketProviderList(count)
		result = []
		for i in range(0, count.value):
			result.append(WebsocketProvider(types[i]))
		core.BNFreeWebsocketProviderList(types)
		return result

	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetWebsocketProviderList(count)
		try:
			for i in range(0, count.value):
				yield WebsocketProvider(types[i])
		finally:
			core.BNFreeWebsocketProviderList(types)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		provider = core.BNGetWebsocketProviderByName(str(value))
		if provider is None:
			raise KeyError("'%s' is not a valid websocket provider" % str(value))
		return WebsocketProvider(provider)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class WebsocketProvider(metaclass=_WebsocketProviderMetaclass):
	name = None
	instance_class = None
	_registered_providers = []

	def __init__(self, handle = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNWebsocketProvider)
			self.__dict__["name"] = core.BNGetWebsocketProviderName(handle)

	def register(self):
		self._cb = core.BNWebsocketProviderCallbacks()
		self._cb.context = 0
		self._cb.createInstance = self._cb.createInstance.__class__(self._create_instance)
		self.handle = core.BNRegisterWebsocketProvider(self.__class__.name, self._cb)
		self.__class__._registered_providers.append(self)

	def _create_instance(self, ctxt):
		try:
			assert self.__class__.instance_class is not None, "instance_class can not be None"
			result = self.__class__.instance_class(self)
			if result is None:
				return None
			return ctypes.cast(core.BNNewWebsocketClientReference(result.handle), ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	def create_instance(self):
		result = core.BNCreateWebsocketProviderClient(self.handle)
		if result is None:
			return None
		return WebsocketClient(self, handle=result)
