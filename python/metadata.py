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

import ctypes
from typing import Union, Optional, List, Tuple

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import MetadataType

MetadataValueType = Union['Metadata', int, bool, str, bytes, float, List['MetadataValueType'], Tuple['MetadataValueType'], dict]


class Metadata:
	def __init__(
	    self, value: Optional[MetadataValueType] = None, signed: Optional[bool] = None, raw: Optional[bool] = None,
	    handle: Optional[core.BNMetadata] = None
	):
		"""
		The 'raw' parameter is no longer needed it was a work around for a python 2 limitation.
		To pass raw data into this api simply use a `bytes` object
		"""
		if handle is not None:
			self.handle = handle
		elif isinstance(value, bool):
			self.handle = core.BNCreateMetadataBooleanData(value)
		elif isinstance(value, int):
			if signed:
				self.handle = core.BNCreateMetadataSignedIntegerData(value)
			else:
				self.handle = core.BNCreateMetadataUnsignedIntegerData(value)
		elif isinstance(value, str):
			self.handle = core.BNCreateMetadataStringData(value)
		elif isinstance(value, bytes):
			buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
			self.handle = core.BNCreateMetadataRawData(buffer, len(value))
		elif isinstance(value, float):
			self.handle = core.BNCreateMetadataDoubleData(value)
		elif isinstance(value, (list, tuple)):
			self.handle = core.BNCreateMetadataOfType(MetadataType.ArrayDataType)
			for elm in value:
				md = Metadata(elm, signed, raw)
				core.BNMetadataArrayAppend(self.handle, md.handle)
		elif isinstance(value, dict):
			self.handle = core.BNCreateMetadataOfType(MetadataType.KeyValueDataType)
			for elm in value:
				md = Metadata(value[elm], signed, raw)
				core.BNMetadataSetValueForKey(self.handle, str(elm), md.handle)
		else:
			raise ValueError(f"{type(value)} doesn't contain type of: int, bool, str, float, list, dict")

	def __len__(self):
		if self.is_array or self.is_dict or self.is_string or self.is_bytes:
			return core.BNMetadataSize(self.handle)
		raise TypeError("Metadata object doesn't support len()")

	def __eq__(self, other):
		if isinstance(other, int) and self.is_integer:
			return int(self) == other
		elif isinstance(other, str) and self.is_string:
			return str(self) == other
		elif isinstance(other, bytes) and self.is_bytes:
			return bytes(self) == other
		elif isinstance(other, float) and self.is_float:
			return float(self) == other
		elif isinstance(other, bool) and self.is_boolean:
			return bool(self) == other
		elif self.is_array and ((isinstance(other, Metadata) and other.is_array) or isinstance(other, list)):
			if len(self) != len(other):
				return False
			for a, b in zip(self, other):
				if a != b:
					return False
			return True
		elif self.is_dict and ((isinstance(other, Metadata) and other.is_dict) or isinstance(other, dict)):
			if len(self) != len(other):
				return False
			for a, b in zip(self, other):
				if a != b or self[a] != other[b]:
					return False
			return True
		elif isinstance(other, Metadata) and self.is_integer and other.is_integer:
			return int(self) == int(other)
		elif isinstance(other, Metadata) and self.is_string and other.is_string:
			return str(self) == str(other)
		elif isinstance(other, Metadata) and self.is_bytes and other.is_bytes:
			return bytes(self) == bytes(other)
		elif isinstance(other, Metadata) and self.is_float and other.is_float:
			return float(self) == float(other)
		elif isinstance(other, Metadata) and self.is_boolean and other.is_boolean:
			return bool(self) == bool(other)
		return NotImplemented

	def __ne__(self, other):
		return not self.__eq__(other)

	def __iter__(self):
		if self.is_array:
			for i in range(core.BNMetadataSize(self.handle)):
				yield Metadata(handle=core.BNMetadataGetForIndex(self.handle, i)).value
		elif self.is_dict:
			result = core.BNMetadataGetValueStore(self.handle)
			assert result is not None, "core.BNMetadataGetValueStore returned None"
			try:
				for i in range(result.contents.size):
					if isinstance(result.contents.keys[i], bytes):
						yield result.contents.keys[i].decode("utf-8")
					else:
						yield result.contents.keys[i]
			finally:
				core.BNFreeMetadataValueStore(result)
		else:
			raise TypeError("Metadata object doesn't support iteration")

	def __getitem__(self, value):
		if self.is_array:
			if not isinstance(value, int):
				raise ValueError("Metadata object only supports integers for indexing")
			if value >= len(self):
				raise IndexError("Index value out of range")
			return Metadata(handle=core.BNMetadataGetForIndex(self.handle, value)).value
		if self.is_dict:
			if not isinstance(value, str):
				raise ValueError("Metadata object only supports strings for indexing")
			handle = core.BNMetadataGetForKey(self.handle, value)
			if handle is None:
				raise KeyError(value)
			return Metadata(handle=handle).value

		raise NotImplementedError("Metadata object doesn't support indexing")

	def __str__(self):
		if self.is_string:
			return str(core.BNMetadataGetString(self.handle))
		raise ValueError("Metadata object not a string")

	def __bool__(self):
		if self.is_boolean:
			return bool(core.BNMetadataGetBoolean(self.handle))
		raise ValueError("Metadata object not a boolean")

	def __bytes__(self):
		try:
			length = ctypes.c_ulonglong()
			length.value = 0
			native_list = core.BNMetadataGetRaw(self.handle, ctypes.byref(length))
			assert native_list is not None, "core.BNMetadataGetRaw returned None"
			return ctypes.string_at(native_list, length.value)
		finally:
			core.BNFreeMetadataRaw(native_list)

	def __int__(self):
		if self.is_signed_integer:
			return core.BNMetadataGetSignedInteger(self.handle)
		if self.is_unsigned_integer:
			return core.BNMetadataGetUnsignedInteger(self.handle)

		raise ValueError("Metadata object not of integer type")

	def __float__(self):
		if not self.is_float:
			raise ValueError("Metadata object is not float type")
		return core.BNMetadataGetDouble(self.handle)

	def __nonzero__(self):
		if not self.is_boolean:
			raise ValueError("Metadata object is not boolean type")
		return core.BNMetadataGetBoolean(self.handle)

	@property
	def value(self):
		if self.is_integer:
			return int(self)
		elif self.is_string:
			return str(self)
		elif self.is_bytes:
			return bytes(self)
		elif self.is_float:
			return float(self)
		elif self.is_boolean:
			return bool(self)
		elif self.is_array:
			return list(self)
		elif self.is_dict:
			return self.get_dict()
		raise TypeError()

	def get_dict(self):
		if not self.is_dict:
			raise TypeError()
		result = {}
		for key in self:
			result[key] = self[key]
		return result

	@property
	def type(self):
		return MetadataType(core.BNMetadataGetType(self.handle))

	@property
	def is_integer(self):
		return self.is_signed_integer or self.is_unsigned_integer

	@property
	def is_signed_integer(self):
		return core.BNMetadataIsSignedInteger(self.handle)

	@property
	def is_unsigned_integer(self):
		return core.BNMetadataIsUnsignedInteger(self.handle)

	@property
	def is_float(self):
		return core.BNMetadataIsDouble(self.handle)

	@property
	def is_boolean(self):
		return core.BNMetadataIsBoolean(self.handle)

	@property
	def is_string(self):
		return core.BNMetadataIsString(self.handle)

	@property
	def is_raw(self):
		"""deprecated in favor of `is_bytes`"""
		return core.BNMetadataIsRaw(self.handle)

	@property
	def is_bytes(self):
		return core.BNMetadataIsRaw(self.handle)

	@property
	def is_array(self):
		return core.BNMetadataIsArray(self.handle)

	@property
	def is_dict(self):
		return core.BNMetadataIsKeyValueStore(self.handle)

	def remove(self, key_or_index):
		if isinstance(key_or_index, str) and self.is_dict:
			core.BNMetadataRemoveKey(self.handle, key_or_index)
		elif isinstance(key_or_index, int) and self.is_array:
			core.BNMetadataRemoveIndex(self.handle, key_or_index)
		else:
			raise TypeError("remove only valid for dict and array objects")
