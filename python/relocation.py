# coding=utf-8
# Copyright (c) 2015-2025 Vector 35 Inc
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
from typing import List, Optional

from dataclasses import dataclass

from . import _binaryninjacore as core
from . import filemetadata
from . import binaryview
from . import architecture
from . import enums
from . import lowlevelil
from .log import log_error_for_exception
from . import types

@dataclass
class RelocationInfo:
	type: enums.RelocationType
	pc_relative: bool
	base_relative: bool
	base: int
	size: int
	truncate_size: int
	native_type: int
	addend: int
	has_sign: bool
	implicit_addend: bool
	external: bool
	symbol_index: int
	section_index: int
	address: int
	target: int
	data_relocation: bool

	@classmethod
	def _from_core_struct(cls, info: core.BNRelocationInfo):
		return RelocationInfo(
			type=enums.RelocationType(info.type),
			pc_relative=info.pcRelative,
			base_relative=info.baseRelative,
			base=info.base,
			size=info.size,
			truncate_size=info.truncateSize,
			native_type=info.nativeType,
			addend=info.addend,
			has_sign=info.hasSign,
			implicit_addend=info.implicitAddend,
			external=info.external,
			symbol_index=info.symbolIndex,
			section_index=info.sectionIndex,
			address=info.address,
			target=info.target,
			data_relocation=info.dataRelocation,
		)

	def _to_core_struct(self):
		result = core.BNRelocationInfo()
		result.type = int(self.type)
		result.pcRelative = self.pc_relative
		result.baseRelative = self.base_relative
		result.base = self.base
		result.size = self.size
		result.truncateSize = self.truncate_size
		result.nativeType = self.native_type
		result.addend = self.addend
		result.hasSign = self.has_sign
		result.implicitAddend = self.implicit_addend
		result.external = self.external
		result.symbolIndex = self.symbol_index
		result.sectionIndex = self.section_index
		result.address = self.address
		result.target = self.target
		result.dataRelocation = self.data_relocation
		return result

class Relocation:
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeRelocation(self.handle)

	def __repr__(self):
		if self.symbol is None:
			return f"<Relocation: {self.target:#x}>"
		try:
			return f"<Relocation: \"{self.symbol.full_name}\" @ {self.target:#x}>"
		except UnicodeDecodeError:
			return f"<Relocation: \"{self.symbol.raw_bytes}\" @ {self.target:#x}>"

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	@property
	def info(self) -> RelocationInfo:
		return RelocationInfo._from_core_struct(core.BNRelocationGetInfo(self.handle))

	@property
	def arch(self) -> Optional['architecture.Architecture']:
		"""The architecture associated with the :py:class:`Relocation` (read/write)"""
		core_arch = core.BNRelocationGetArchitecture(self.handle)
		return architecture.CoreArchitecture._from_cache(handle=core_arch)

	@property
	def target(self) -> int:
		"""Where the reloc needs to point to"""
		return core.BNRelocationGetTarget(self.handle)

	@property
	def reloc(self) -> int:
		"""The actual pointer that needs to be relocated"""
		return core.BNRelocationGetReloc(self.handle)

	@property
	def symbol(self) -> Optional['types.CoreSymbol']:
		core_symbol = core.BNRelocationGetSymbol(self.handle)
		if core_symbol is None:
			return None
		return types.CoreSymbol(core_symbol)

class RelocationHandler:
	def __init__(self, handle=None):
		if handle is None:
			self._cb = core.BNCustomRelocationHandler()
			self._cb.context = 0
			self._cb.freeObject = self._cb.freeObject.__class__(self._free_object)
			self._cb.getRelocationInfo = self._cb.getRelocationInfo.__class__(self._get_relocation_info)
			self._cb.applyRelocation = self._cb.applyRelocation.__class__(self._apply_relocation)
			self._cb.getOperandForExternalRelocation = self._cb.getOperandForExternalRelocation.__class__(self._get_operand_for_external_relocation)
			self.handle = core.BNCreateRelocationHandler(self._cb)
		else:
			self.handle = handle

	def _free_object(self, ctxt):
		try:
			self.perform_free_object(ctxt)
		except:
			log_error_for_exception("Unhandled Python exception in RelocationHandler._free_object")

	def _get_relocation_info(self, ctxt, view, arch, result, resultCount):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			arch = architecture.CoreArchitecture._from_cache(arch)

			pyresult: List[RelocationInfo] = []
			for i in range(resultCount):
				pyresult.append(
					RelocationInfo._from_core_struct(result[i]),
				)

			if not self.perform_get_relocation_info(view, arch, result):
				return False

			for i in range(resultCount):
				result[i] = pyresult[i]._to_core_struct()

			return True
		except:
			log_error_for_exception("Unhandled Python exception in RelocationHandler._get_relocation_info")
			return False

	def _apply_relocation(self, ctxt, view, arch, reloc, dest, length):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			arch = architecture.CoreArchitecture._from_cache(arch)
			reloc = Relocation(reloc)

			result = self.perform_apply_relocation(view, arch, reloc, length)
			if result is None or len(result) < length:
				return False

			for i in range(length):
				dest[i] = result[i]

			return True
		except:
			log_error_for_exception("Unhandled Python exception in RelocationHandler._apply_relocation")
			return False

	def _get_operand_for_external_relocation(self, data, addr, length, il, reloc):
		try:
			il = lowlevelil.LowLevelILFunction(None, core.BNNewLowLevelILFunctionReference(il))
			reloc = Relocation(reloc)
			data = bytes((ctypes.c_byte * length).from_address(data))
			result = self.get_operand_for_external_relocation(data, addr, il, reloc)

			if result is None: # TODO: cleaner DX?
				return 0xffffffff
			elif result is True:
				return 0xfffffffd
			elif result is False:
				return 0xfffffffe
			else:
				return result
		except:
			log_error_for_exception("Unhandled Python exception in RelocationHandler._get_operand_for_external_relocation")
			return 0xffffffff

	def perform_free_object(self, ctxt):
		pass

	def perform_get_relocation_info(self, view: 'binaryview.BinaryView', arch: 'architecture.Architecture', result: List[RelocationInfo]) -> bool:
		return True

	def perform_apply_relocation(self, view: 'binaryview.BinaryView', arch: 'architecture.Architecture', reloc: Relocation, length: int) -> Optional[bytes]:
		dest = (ctypes.c_byte * length)()
		if not core.BNRelocationHandlerDefaultApplyRelocation(
			self.handle,
			arch.handle,
			reloc.handle,
			dest,
		):
			return None

		return bytes(dest)

	def perform_get_operand_for_external_relocation(self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction, reloc: Relocation) -> bool | Optional['lowlevelil.ExpressionIndex']:
		return True

	def get_relocation_info(self, view: 'binaryview.BinaryView', arch: 'architecture.Architecture', result: List[RelocationInfo]) -> bool:
		_result = (core.BNRelocationInfo * len(result))()
		for i, res in enumerate(result):
			_result[i] = res._to_core_struct()

		if not core.BNRelocationHandlerGetRelocationInfo(
			self.handle,
			view.handle,
			arch.handle,
			_result
		):
			return False

		for i, res in enumerate(_result):
			result[i] = RelocationInfo._from_core_struct(res)

		return True

	def apply_relocation(self, view: 'binaryview.BinaryView', arch: 'architecture.Architecture', reloc: Relocation, length: int) -> Optional[bytes]:
		dest = (ctypes.c_ubyte * length)()
		if not core.BNRelocationHandlerApplyRelocation(
			self.handle,
			view.handle,
			arch.handle,
			reloc.handle,
			dest,
			length
		):
			return None

		return bytes(dest)

	def get_operand_for_external_relocation(self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction, reloc: Relocation) -> bool | Optional['lowlevelil.ExpressionIndex']:
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		result = core.BNRelocationHandlerGetOperandForExternalRelocation(
			self.handle,
			buf,
			len(data),
			il.handle,
			reloc.handle,
		)

		if result == 0xffffffff:
			return None
		elif result == 0xfffffffd:
			return True
		elif result == 0xfffffffe:
			return False
		else:
			return result
