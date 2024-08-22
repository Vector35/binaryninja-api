# Copyright (c) 2015-2024 Vector 35 Inc
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
from typing import Optional, Union

# Binary Ninja components
from . import _binaryninjacore as core

DataBufferInputType = Union[str, bytes, 'DataBuffer', int]


class DataBuffer:
	def __init__(self, contents: Union[str, bytes, 'DataBuffer', int] = b"", handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNDataBuffer)
		elif isinstance(contents, int):
			self.handle = core.BNCreateDataBuffer(None, contents)
		elif isinstance(contents, DataBuffer):
			self.handle = core.BNDuplicateDataBuffer(contents.handle)
		elif isinstance(contents, str):
			self.handle = core.BNCreateDataBuffer(contents.encode("utf-8"), len(contents.encode("utf-8")))
		elif isinstance(contents, bytes):
			self.handle = core.BNCreateDataBuffer(contents, len(contents))
		elif isinstance(contents, bytearray):
			b = bytes(contents)
			self.handle = core.BNCreateDataBuffer(b, len(b))
		else:
			raise TypeError(f"type {type(contents)} not convertable to DataBuffer")


	def __del__(self):
		if core is not None:
			core.BNFreeDataBuffer(self.handle)

	def __len__(self):
		return int(core.BNGetDataBufferLength(self.handle))

	def __getitem__(self, i) -> bytes:
		if isinstance(i, tuple):
			result = bytes()
			for s in i:
				result += self.__getitem__(s)
			return result
		elif isinstance(i, slice):
			if i.step is not None:
				i = i.indices(len(self))
				start = i[0]
				stop = i[1]
				if stop <= start:
					return b""
				buf = ctypes.create_string_buffer(stop - start)
				data = core.BNGetDataBufferContentsAt(self.handle, start)
				assert data is not None, "core.BNGetDataBufferContentsAt returned None"
				ctypes.memmove(buf, data, stop - start)
				return buf.raw
			else:
				return bytes(self)[i]
		elif i < 0:
			if i >= -len(self):
				return core.BNGetDataBufferByte(self.handle, int(len(self) + i)).to_bytes(1, "little")
			raise IndexError("index out of range")
		elif i < len(self):
			return core.BNGetDataBufferByte(self.handle, int(i)).to_bytes(1, "little")
		else:
			raise IndexError("index out of range")

	def __setitem__(self, i, value):
		if isinstance(i, slice):
			if i.step is not None:
				raise IndexError("step not supported on assignment")
			i = i.indices(len(self))
			start = i[0]
			stop = i[1]
			if stop < start:
				stop = start
			if len(value) != (stop - start):
				data = bytes(self)
				data = data[0:start] + value + data[stop:]
				core.BNSetDataBufferContents(self.handle, data, len(data))
			else:
				value = str(value)
				buf = ctypes.create_string_buffer(len(value))
				data = core.BNGetDataBufferContentsAt(self.handle, start)
				assert data is not None, "core.BNGetDataBufferContentsAt returned None"
				ctypes.memmove(data, buf, len(value))
		elif i < 0:
			if i >= -len(self):
				if len(value) != 1:
					raise ValueError("expected single byte for assignment")
				value = str(value)
				buf = ctypes.create_string_buffer(len(value))
				data = core.BNGetDataBufferContentsAt(self.handle, int(len(self) + i))
				assert data is not None, "core.BNGetDataBufferContentsAt returned None"
				ctypes.memmove(data, buf, 1)
			else:
				raise IndexError("index out of range")
		elif i < len(self):
			if len(value) != 1:
				raise ValueError("expected single byte for assignment")
			value = str(value)
			buf = ctypes.create_string_buffer(len(value))
			data = core.BNGetDataBufferContentsAt(self.handle, int(i))
			assert data is not None, "core.BNGetDataBufferContentsAt returned None"
			ctypes.memmove(data, buf, 1)
		else:
			raise IndexError("index out of range")

	def __str__(self):
		buf = ctypes.create_string_buffer(len(self))
		data = core.BNGetDataBufferContents(self.handle)
		assert data is not None, "core.BNGetDataBufferContents returned None"
		ctypes.memmove(buf, data, len(self))
		return buf.raw.decode('utf8')

	def __bytes__(self):
		buf = ctypes.create_string_buffer(len(self))
		data = core.BNGetDataBufferContents(self.handle)
		assert data is not None, "core.BNGetDataBufferContents returned None"
		ctypes.memmove(buf, data, len(self))
		return buf.raw

	def __eq__(self, other: 'DataBuffer') -> bool:
		# Not cryptographically secure
		if len(self) != len(other):
			return False
		return bytes(self) == bytes(other)

	def escape(self, null_terminates=False, escape_printable=False) -> str:
		return core.BNDataBufferToEscapedString(self.handle, null_terminates, escape_printable)

	def unescape(self) -> 'DataBuffer':
		return DataBuffer(handle=core.BNDecodeEscapedString(str(self)))

	def base64_encode(self) -> str:
		return core.BNDataBufferToBase64(self.handle)

	def base64_decode(self) -> 'DataBuffer':
		return DataBuffer(handle=core.BNDecodeBase64(str(self)))

	def zlib_compress(self) -> Optional['DataBuffer']:
		buf = core.BNZlibCompress(self.handle)
		if buf is None:
			return None
		return DataBuffer(handle=buf)

	def zlib_decompress(self) -> Optional['DataBuffer']:
		buf = core.BNZlibDecompress(self.handle)
		if buf is None:
			return None
		return DataBuffer(handle=buf)


def escape_string(text: bytes) -> str:
	return DataBuffer(text).escape()


def unescape_string(text: bytes) -> 'DataBuffer':
	return DataBuffer(text).unescape()
