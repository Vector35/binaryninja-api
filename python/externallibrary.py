# coding=utf-8
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

from typing import Optional

from . import _binaryninjacore as core
from . import project
from . import types


class ExternalLibrary:
	def __init__(self, handle: core.BNExternalLibrary):
		self._handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeExternalLibrary(self._handle)

	def __repr__(self) -> str:
		return f'<ExternalLibrary: {self.name}>'

	def __str__(self) -> str:
		return f'<ExternalLibrary: {self.name}>'

	@property
	def name(self) -> str:
		return core.BNExternalLibraryGetName(self._handle) # type: ignore

	@property
	def backing_file(self) -> Optional[project.ProjectFile]:
		handle = core.BNExternalLibraryGetBackingFile(self._handle)
		if handle is None:
			return None
		return project.ProjectFile(handle)

	@backing_file.setter
	def backing_file(self, new_file: Optional[project.ProjectFile]):
		new_file_handle = None
		if new_file is not None:
			new_file_handle = new_file._handle
		core.BNExternalLibrarySetBackingFile(self._handle, new_file_handle)


class ExternalLocation:
	def __init__(self, handle: core.BNExternalLocation):
		self._handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeExternalLocation(self._handle)

	def __repr__(self) -> str:
		return f'<ExternalLocation: {self.internal_symbol}>'

	def __str__(self) -> str:
		return f'<ExternalLocation: {self.internal_symbol}>'

	@property
	def internal_symbol(self) -> 'types.CoreSymbol':
		sym = core.BNExternalLocationGetInternalSymbol(self._handle)
		assert sym is not None, "core.BNExternalLocationGetInternalSymbol returned None"
		return types.CoreSymbol(sym)

	@property
	def has_address(self) -> bool:
		return core.BNExternalLocationHasAddress(self._handle)

	@property
	def has_symbol(self) -> bool:
		return core.BNExternalLocationHasSymbol(self._handle)

	@property
	def address(self) -> Optional[int]:
		if not self.has_address:
			return None
		return core.BNExternalLocationGetAddress(self._handle)

	@address.setter
	def address(self, new_address: Optional[int]):
		c_addr = None
		if new_address is not None:
			c_addr = ctypes.c_ulonglong(new_address)
		return core.BNExternalLocationSetAddress(self._handle, c_addr)

	@property
	def symbol(self) -> Optional[str]:
		if not self.has_symbol:
			return None
		return core.BNExternalLocationGetSymbol(self._handle)

	@symbol.setter
	def symbol(self, new_symbol: Optional[str]):
		return core.BNExternalLocationSetSymbol(self._handle, new_symbol)

	@property
	def library(self) -> Optional[ExternalLibrary]:
		handle = core.BNExternalLocationGetExternalLibrary(self._handle)
		if handle is None:
			return None
		return ExternalLibrary(handle)

	@library.setter
	def library(self, new_library: Optional[ExternalLibrary]):
		lib_handle = new_library._handle if new_library is not None else None
		return core.BNExternalLocationSetExternalLibrary(self._handle, lib_handle)
