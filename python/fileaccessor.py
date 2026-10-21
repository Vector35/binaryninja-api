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

import traceback
import ctypes
from typing import Tuple, Union

# Binary Ninja components
from . import _binaryninjacore as core
from .log import log_error_for_exception
from .enums import MemoryReadStatus


class FileAccessor:
	def __init__(self):
		self._cb = core.BNFileAccessor()
		self._cb.context = 0
		self._cb.getLength = self._cb.getLength.__class__(self._get_length)
		self._cb.read = self._cb.read.__class__(self._read)
		self._cb.write = self._cb.write.__class__(self._write)

	def get_length(self):
		raise NotImplementedError

	def read(self, offset, length):
		raise NotImplementedError

	def write(self, offset: int, data: bytes):
		raise NotImplementedError

	def __len__(self):
		return self.get_length()

	def _get_length(self, ctxt):
		try:
			return self.get_length()
		except Exception:
			log_error_for_exception("Unhandled Python exception in FileAccessor._get_length")
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
		except Exception:
			log_error_for_exception("Unhandled Python exception in FileAccessor._read")
			return 0

	def _write(self, ctxt, offset, src, length):
		try:
			data = ctypes.create_string_buffer(length)
			ctypes.memmove(data, src, length)
			return self.write(offset, data.raw)
		except Exception:
			log_error_for_exception("Unhandled Python exception in FileAccessor._write")
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


class MemoryRegionAccessor:
	"""
	``class MemoryRegionAccessor`` backs a remote memory region and describes its contents span by span. Unlike a
	:py:class:`FileAccessor`, it can report that it has no bytes for a span, so that a region added with
	``fallthrough=True`` shows the regions beneath it there, or that a span is inaccessible.

	Pass an instance to :py:meth:`~binaryninja.binaryview.MemoryMap.add_memory_region`. The memory map then owns it,
	keeps it alive and releases it once no snapshot of the map references the region any longer. An accessor can
	back only one region. Callbacks run with the view's lock held and must not read from or write to the same view.
	"""
	_live_instances = {}  # accessors owned by the core, kept alive until it frees them

	def __init__(self):
		self._cb = core.BNMemoryRegionAccessor()
		self._cb.version = 1  # BN_MEMORY_REGION_ACCESSOR_VERSION
		self._cb.context = 0
		self._cb.getLength = self._cb.getLength.__class__(self._get_length)
		self._cb.read = self._cb.read.__class__(self._read)
		self._cb.write = self._cb.write.__class__(self._write)
		self._cb.freeObject = self._cb.freeObject.__class__(self._free_object)

	def get_length(self) -> int:
		raise NotImplementedError

	def read(self, offset: int, length: int) -> Tuple[MemoryReadStatus, Union[bytes, int]]:
		"""
		Describe the single span starting at ``offset`` (an absolute address), at most ``length`` bytes long.

		:return: ``(MemoryReadStatus.MemoryReadAvailable, data)`` with the bytes of an available span, or
			``(MemoryReadStatus.MemoryReadTransparent, count)`` / ``(MemoryReadStatus.MemoryReadInaccessible, count)``
			for a span of ``count`` bytes that the region has no bytes for or that cannot be read
		"""
		raise NotImplementedError

	def write(self, offset: int, data: bytes) -> int:
		return 0

	def _take_ownership(self) -> core.BNMemoryRegionAccessor:
		if id(self) in MemoryRegionAccessor._live_instances:
			raise ValueError("A MemoryRegionAccessor can only back one memory region")
		MemoryRegionAccessor._live_instances[id(self)] = self
		return self._cb

	def _get_length(self, ctxt):
		try:
			return self.get_length()
		except Exception:
			log_error_for_exception("Unhandled Python exception in MemoryRegionAccessor._get_length")
			return 0

	def _read(self, ctxt, dest, offset, length, status):
		try:
			result_status, result = self.read(offset, length)
			if result_status == MemoryReadStatus.MemoryReadAvailable:
				data = result[0:length]
				ctypes.memmove(dest, data, len(data))
				count = len(data)
			else:
				count = result
			status[0] = int(result_status)
			return count
		except Exception:
			log_error_for_exception("Unhandled Python exception in MemoryRegionAccessor._read")
			status[0] = int(MemoryReadStatus.MemoryReadInaccessible)
			return 0

	def _write(self, ctxt, offset, src, length):
		try:
			data = ctypes.create_string_buffer(length)
			ctypes.memmove(data, src, length)
			return self.write(offset, data.raw)
		except Exception:
			log_error_for_exception("Unhandled Python exception in MemoryRegionAccessor._write")
			return 0

	def _free_object(self, ctxt):
		MemoryRegionAccessor._live_instances.pop(id(self), None)
