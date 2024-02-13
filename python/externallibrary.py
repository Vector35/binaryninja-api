# coding=utf-8
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

from typing import Optional

from . import _binaryninjacore as core
from . import project
from . import types


class ExternalLibrary:
	"""
	An ExternalLibrary is an abstraction for a library that is optionally backed by a ProjectFile.
	"""
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
		"""
		Get the name of this external library

		:return: The name of this external library
		"""
		return core.BNExternalLibraryGetName(self._handle) # type: ignore

	@property
	def backing_file(self) -> Optional[project.ProjectFile]:
		"""
		Get the file backing this external library

		:return: The file backing this external library or None
		"""
		handle = core.BNExternalLibraryGetBackingFile(self._handle)
		if handle is None:
			return None
		return project.ProjectFile(handle)

	@backing_file.setter
	def backing_file(self, new_file: Optional[project.ProjectFile]):
		"""
		Set the file backing this external library

		:param new_file: The file that will back this external library
		"""
		new_file_handle = None
		if new_file is not None:
			new_file_handle = new_file._handle
		core.BNExternalLibrarySetBackingFile(self._handle, new_file_handle)


class ExternalLocation:
	"""
	An ExternalLocation is an association from a source symbol in a binary view to a target symbol and/or address in an ExternalLibrary.
	"""
	def __init__(self, handle: core.BNExternalLocation):
		self._handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeExternalLocation(self._handle)

	def __repr__(self) -> str:
		return f'<ExternalLocation: {self.source_symbol}>'

	def __str__(self) -> str:
		return f'<ExternalLocation: {self.source_symbol}>'

	@property
	def source_symbol(self) -> 'types.CoreSymbol':
		"""
		Get the source symbol for this ExternalLocation

		:return: The source symbol for this ExternalLocation
		"""
		sym = core.BNExternalLocationGetSourceSymbol(self._handle)
		assert sym is not None, "core.BNExternalLocationGetSourceSymbol returned None"
		return types.CoreSymbol(sym)

	@property
	def has_target_address(self) -> bool:
		"""
		Check if this ExternalLocation has a target address

		:return: True is this ExternalLocation has a target address, False otherwise
		"""
		return core.BNExternalLocationHasTargetAddress(self._handle)

	@property
	def has_target_symbol(self) -> bool:
		"""
		Check if this ExternalLocation has a target symbol

		:return: True is this ExternalLocation has a target symbol, False otherwise
		"""
		return core.BNExternalLocationHasTargetSymbol(self._handle)

	@property
	def target_address(self) -> Optional[int]:
		"""
		Get the address pointed to by this ExternalLocation

		:return: The address pointed to by this ExternalLocation if one exists, None otherwise
		"""
		if not self.has_target_address:
			return None
		return core.BNExternalLocationGetTargetAddress(self._handle)

	@target_address.setter
	def target_address(self, new_address: Optional[int]) -> bool:
		"""
		Set the address pointed to by this ExternalLocation.
		ExternalLocations must have a valid target address and/or symbol set.

		:param new_address: The address that this ExternalLocation will point to
		:return: True if the address was set, False otherwise
		"""
		c_addr = None
		if new_address is not None:
			c_addr = ctypes.c_ulonglong(new_address)
		return core.BNExternalLocationSetTargetAddress(self._handle, c_addr)

	@property
	def target_symbol(self) -> Optional[str]:
		"""
		Get the symbol pointed to by this ExternalLocation

		:return: The symbol pointed to by this ExternalLocation if one exists, None otherwise
		"""
		if not self.has_target_symbol:
			return None
		return core.BNExternalLocationGetTargetSymbol(self._handle)

	@target_symbol.setter
	def target_symbol(self, new_symbol: Optional[str]) -> bool:
		"""
		Set the symbol pointed to by this ExternalLocation.
		ExternalLocations must have a valid target address and/or symbol set.

		:param new_symbol: The raw symbol that this ExternalLocation will point to
		:return: True if the symbol was set, False otherwise
		"""
		return core.BNExternalLocationSetTargetSymbol(self._handle, new_symbol)

	@property
	def library(self) -> Optional[ExternalLibrary]:
		"""
		Get the ExternalLibrary that this ExternalLocation targets

		:return: The ExternalLibrary pointed in to by this ExternalLocation if one exists, None otherwise
		"""
		handle = core.BNExternalLocationGetExternalLibrary(self._handle)
		if handle is None:
			return None
		return ExternalLibrary(handle)

	@library.setter
	def library(self, new_library: Optional[ExternalLibrary]):
		"""
		Set the ExternalLibrary that this ExternalLocation targets

		:param new_library: The ExternalLibrary that this ExternalLocation will pointed in to
		"""
		lib_handle = new_library._handle if new_library is not None else None
		return core.BNExternalLocationSetExternalLibrary(self._handle, lib_handle)
