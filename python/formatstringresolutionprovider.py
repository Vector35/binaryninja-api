# Copyright (c) 2015-2026 Vector 35 Inc
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
from typing import Any, List, Optional

import binaryninja
import binaryninja._binaryninjacore as core
from . import platform as _platform
from . import types as _types
from .log import log_error_for_exception


class _FormatStringResolutionProviderMetaclass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		providers = core.BNGetFormatStringResolutionProviderList(count)
		try:
			for i in range(count.value):
				yield FormatStringResolutionProvider(providers[i])
		finally:
			core.BNFreeFormatStringResolutionProviderList(providers)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		provider = core.BNGetFormatStringResolutionProviderByName(str(value))
		if provider is None:
			raise KeyError(f"'{value}' is not a valid format string resolution provider")
		return FormatStringResolutionProvider(provider)

	def __contains__(cls: '_FormatStringResolutionProviderMetaclass', name: object) -> bool:
		if not isinstance(name, str):
			return False
		try:
			cls[name]
			return True
		except KeyError:
			return False

	def get(
		cls: '_FormatStringResolutionProviderMetaclass', name: str, default: Any = None
	) -> Optional['FormatStringResolutionProvider']:
		try:
			return cls[name]
		except KeyError:
			if default is not None:
				return default
			return None


class FormatStringResolutionProvider(metaclass=_FormatStringResolutionProviderMetaclass):
	"""
	``FormatStringResolutionProvider`` resolves the variadic argument types described by a format string.

	To implement a provider, subclass this class, set :py:attr:`name`, implement
	:py:meth:`perform_is_valid`, and call :py:meth:`register`. The confidence attached to each returned
	:py:class:`Type` is preserved when the result crosses the core API boundary.
	"""
	name = None
	_registered_providers = []

	def __init__(self, handle=None):
		self._pending_type_lists = {}
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNFormatStringResolutionProvider)
			self.__dict__["name"] = core.BNGetFormatStringResolutionProviderName(handle)

	def __repr__(self):
		return f"<FormatStringResolutionProvider: {self.name}>"

	def register(self):
		"""Register this provider with the Binary Ninja core."""
		if self.__class__.name is None:
			raise ValueError("name is missing")
		if hasattr(self, "handle"):
			raise ValueError("provider is already registered")

		self._cb = core.BNFormatStringResolutionProviderCallbacks()
		self._cb.context = 0
		self._cb.isValid = self._cb.isValid.__class__(self._is_valid)
		self._cb.freeTypeList = self._cb.freeTypeList.__class__(self._free_type_list)
		self.handle = core.BNRegisterFormatStringResolutionProvider(self.__class__.name, self._cb)
		assert self.handle is not None, "core.BNRegisterFormatStringResolutionProvider returned None"
		self.__class__._registered_providers.append(self)

	def _is_valid(self, ctxt, format_string, platform, types, count) -> bool:
		types[0] = None
		count[0] = 0
		try:
			platform_obj = None
			if platform:
				platform_obj = _platform.CorePlatform._from_cache(
					core.BNNewPlatformReference(platform))

			result = self.perform_is_valid(core.pyNativeStr(format_string), platform_obj)
			if result is None:
				return False

			resolved_types = list(result)
			for resolved_type in resolved_types:
				if not isinstance(resolved_type, _types.Type):
					raise TypeError("perform_is_valid must return Type objects")

			count[0] = len(resolved_types)
			if not resolved_types:
				return True

			output_buf = (core.BNTypeWithConfidence * len(resolved_types))()
			created_count = 0
			try:
				for i, resolved_type in enumerate(resolved_types):
					output_buf[i].type = core.BNNewTypeReference(resolved_type.handle)
					output_buf[i].confidence = resolved_type.confidence
					created_count += 1
			except Exception:
				for i in range(created_count):
					core.BNFreeType(output_buf[i].type)
				raise

			output_ptr = ctypes.cast(output_buf, ctypes.POINTER(core.BNTypeWithConfidence))
			key = ctypes.cast(output_ptr, ctypes.c_void_p).value
			self._pending_type_lists[key] = (output_ptr, output_buf, len(resolved_types))
			types[0] = output_ptr
			return True
		except Exception:
			types[0] = None
			count[0] = 0
			log_error_for_exception("Unhandled Python exception in FormatStringResolutionProvider._is_valid")
			return False

	def _free_type_list(self, ctxt, type_list, count):
		try:
			key = ctypes.cast(type_list, ctypes.c_void_p).value
			if key not in self._pending_type_lists:
				raise ValueError("freeing type list that wasn't allocated")
			_, output_buf, output_count = self._pending_type_lists.pop(key)
			for i in range(output_count):
				core.BNFreeType(output_buf[i].type)
		except Exception:
			log_error_for_exception("Unhandled Python exception in FormatStringResolutionProvider._free_type_list")

	def perform_is_valid(
		self, format_string: str, platform: Optional['_platform.Platform']
	) -> Optional[List['_types.Type']]:
		"""
		Resolve the argument types described by ``format_string`` for ``platform``.

		Return ``None`` when the format is invalid, an empty list for a valid format with no arguments,
		or a list of :py:class:`Type` objects for a valid format. Override this method in custom providers.
		"""
		raise NotImplementedError("Not implemented")

	def is_valid(
		self, format_string: str, platform: Optional['_platform.Platform']
	) -> Optional[List['_types.Type']]:
		"""
		Resolve the argument types described by ``format_string`` for ``platform``.

		The returned type objects carry the confidence supplied by the provider. ``None`` denotes an invalid
		format; an empty list denotes a valid format that consumes no arguments.
		"""
		if not isinstance(format_string, str):
			raise TypeError("format_string must be a string")
		if platform is not None and not isinstance(platform, _platform.Platform):
			raise TypeError("platform must be a Platform or None")
		if not hasattr(self, "handle"):
			raise ValueError("provider is not registered")

		type_list = ctypes.POINTER(core.BNTypeWithConfidence)()
		count = ctypes.c_ulonglong()
		valid = core.BNFormatStringResolutionProviderIsValid(
			self.handle, format_string, platform.handle if platform is not None else None, type_list, count)
		if not valid:
			if type_list:
				core.BNFreeTypeWithConfidenceList(type_list, count.value)
			return None

		try:
			return [
				_types.Type.create(
					core.BNNewTypeReference(type_list[i].type), platform=platform,
					confidence=type_list[i].confidence)
				for i in range(count.value)
			]
		finally:
			core.BNFreeTypeWithConfidenceList(type_list, count.value)
