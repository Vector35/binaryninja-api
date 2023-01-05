# Copyright (c) 2015-2023 Vector 35 Inc
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
from json import dumps
import sys
import traceback
from urllib.parse import urlencode

# Binary Ninja Components
import binaryninja
import binaryninja._binaryninjacore as core
from . import settings
from .log import log_error


def to_bytes(field):
	if type(field) == bytes:
		return field
	if type(field) == str:
		return field.encode()
	return str(field).encode()


class _SecretsProviderMetaclass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetSecretsProviderList(count)
		try:
			for i in range(0, count.value):
				yield SecretsProvider(types[i])
		finally:
			core.BNFreeSecretsProviderList(types)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		provider = core.BNGetSecretsProviderByName(str(value))
		if provider is None:
			raise KeyError(f"'{value}' is not a valid secrets provider")
		return SecretsProvider(provider)


class SecretsProvider(metaclass=_SecretsProviderMetaclass):
	name = None
	instance_class = None
	_registered_providers = []

	def __init__(self, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNSecretsProvider)
			self.__dict__["name"] = core.BNGetSecretsProviderName(handle)

	def register(self):
		self._cb = core.BNSecretsProviderCallbacks()
		self._cb.context = 0
		self._cb.hasData = self._cb.hasData.__class__(self._has_data)
		self._cb.getData = self._cb.getData.__class__(self._get_data)
		self._cb.storeData = self._cb.storeData.__class__(self._store_data)
		self._cb.deleteData = self._cb.deleteData.__class__(self._delete_data)
		self.handle = core.BNRegisterSecretsProvider(self.__class__.name, self._cb)
		self.__class__._registered_providers.append(self)

	def _has_data(self, ctxt, key: str) -> bool:
		try:
			return self.perform_has_data(key)
		except:
			log_error(traceback.format_exc())
			return False

	def _get_data(self, ctxt, key: str):
		try:
			data = self.perform_get_data(key)
			return core.BNAllocString(data)
		except:
			log_error(traceback.format_exc())
			return None

	def _store_data(self, ctxt, key: str, data: str) -> bool:
		try:
			return self.perform_store_data(key, data)
		except:
			log_error(traceback.format_exc())
			return False

	def _delete_data(self, ctxt, key: str) -> bool:
		try:
			return self.perform_delete_data(key)
		except:
			log_error(traceback.format_exc())
			return False

	def perform_has_data(self, key: str) -> bool:
		raise NotImplementedError("Not implemented")

	def perform_get_data(self, key: str) -> str:
		raise NotImplementedError("Not implemented")

	def perform_store_data(self, key: str, data: str) -> bool:
		raise NotImplementedError("Not implemented")

	def perform_delete_data(self, key: str) -> bool:
		raise NotImplementedError("Not implemented")

	def has_data(self, key: str) -> bool:
		return core.BNSecretsProviderHasData(self.handle, key)

	def get_data(self, key: str) -> str:
		return core.BNGetSecretsProviderData(self.handle, key)

	def store_data(self, key: str, data: str) -> bool:
		return core.BNStoreSecretsProviderData(self.handle, key, data)

	def delete_data(self, key: str) -> bool:
		return core.BNDeleteSecretsProviderData(self.handle, key)
