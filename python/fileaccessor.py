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

import traceback
import ctypes

# Binary Ninja components
from . import _binaryninjacore as core
from . import log

class FileAccessor:
	def __init__(self):
		self._cb = core.BNFileAccessor()
		self._cb.context = 0
		self._cb.getLength = self._cb.getLength.__class__(self._get_length)
		self._cb.read = self._cb.read.__class__(self._read)
		self._cb.write = self._cb.write.__class__(self._write)

	def get_length(self):
		return NotImplemented

	def read(self, offset, length):
		return NotImplemented

	def write(self, offset:int, data:bytes):
		return NotImplemented

	def __len__(self):
		return self.get_length()

	def _get_length(self, ctxt):
		try:
			return self.get_length()
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _read(self, ctxt, dest, offset, length):
		try:
			data = self.read(offset, length)
			if data is None:
				return 0
			if len(data) > length:
				data = data[0:length]
			ctypes.memmove(dest, data, len(data))
			return len(data)
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _write(self, ctxt, offset, src, length):
		try:
			data = ctypes.create_string_buffer(length)
			ctypes.memmove(data, src, length)
			return self.write(offset, data.raw)
		except:
			log.log_error(traceback.format_exc())
			return 0


class CoreFileAccessor(FileAccessor):
	def __init__(self, accessor):
		self._cb.context = accessor.context
		self._cb.getLength = accessor.getLength
		self._cb.read = accessor.read
		self._cb.write = accessor.write

	def get_length(self):
		return self._cb.getLength(self._cb.context)

	def read(self, offset, length):
		data = ctypes.create_string_buffer(length)
		length = self._cb.read(self._cb.context, data, offset, length)
		return data.raw[0:length]

	def write(self, offset, value):
		value = str(value)
		data = ctypes.create_string_buffer(len(value))
		return self._cb.write(self._cb.context, offset, data, len(value))
