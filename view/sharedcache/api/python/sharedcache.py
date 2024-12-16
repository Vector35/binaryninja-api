import os
import ctypes
import dataclasses
import traceback

import binaryninja
from binaryninja._binaryninjacore import BNFreeStringList, BNAllocString, BNFreeString

from . import _sharedcachecore as sccore
from .sharedcache_enums import *


@dataclasses.dataclass
class DSCMemoryMapping:
	name: str
	vmAddress: int
	size: int

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<DSCMemoryMapping '{self.name}': {self.vmAddress:x}+{self.size:x}>"


@dataclasses.dataclass
class LoadedRegion:
	name: str
	headerAddress: int
	mappings: list[DSCMemoryMapping]

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<LoadedRegion {self.name} @ {self.headerAddress:x}>"


@dataclasses.dataclass
class DSCBackingCacheMapping:
	vmAddress: int
	size: int
	fileOffset: int

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<DSCBackingCacheMapping {self.vmAddress:x}+{self.size:x} @ {self.fileOffset:x}"


@dataclasses.dataclass
class DSCBackingCache:
	path: str
	isPrimary: bool
	mappings: list[DSCBackingCacheMapping]

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<DSCBackingCache {self.path} {'Primary' if self.isPrimary else 'Secondary'} | {len(self.mappings)} mappings>"


@dataclasses.dataclass
class DSCImageMemoryMapping:
	filePath: str
	name: str
	vmAddress: int
	size: int
	loaded: bool
	rawViewOffset: int

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<DSCImageMemoryMapping '{self.name}' {os.path.basename(self.filePath)} raw<{self.rawViewOffset:x}>: {self.vmAddress:x}+{self.size:x}>"


@dataclasses.dataclass
class DSCImage:
	name: str
	headerAddress: int
	mappings: list[DSCImageMemoryMapping]

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<DSCImage {self.name} @ {self.headerAddress:x}>"


@dataclasses.dataclass
class DSCSymbol:
	name: str
	image: str
	address: int

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<DSCSymbol {self.name} @ {self.address:x} ({self.image}>"


class SharedCache:
	def __init__(self, view):
		self.handle = sccore.BNGetSharedCache(view.handle)

	def load_image_with_install_name(self, installName):
		return sccore.BNDSCViewLoadImageWithInstallName(self.handle, installName)

	def load_section_at_address(self, addr):
		return sccore.BNDSCViewLoadSectionAtAddress(self.handle, addr)

	def load_image_containing_address(self, addr):
		return sccore.BNDSCViewLoadImageContainingAddress(self.handle, addr)

	@property
	def caches(self):
		count = ctypes.c_ulonglong()
		value = sccore.BNDSCViewGetBackingCaches(self.handle, count)
		if value is None:
			return []

		result = []
		for i in range(count.value):
			mappings = []
			for j in range(value[i].mappingCount):
				mapping = DSCBackingCacheMapping(
					value[i].mappings[j].vmAddress,
					value[i].mappings[j].size,
					value[i].mappings[j].fileOffset
				)
				mappings.append(mapping)
			result.append(DSCBackingCache(
				value[i].path,
				value[i].isPrimary,
				mappings
			))

		sccore.BNDSCViewFreeBackingCaches(value, count)
		return result

	@property
	def images(self):
		count = ctypes.c_ulonglong()
		value = sccore.BNDSCViewGetAllImages(self.handle, count)
		if value is None:
			return []

		result = []
		for i in range(count.value):
			mappings = []
			for j in range(value[i].mappingCount):
				mapping = DSCImageMemoryMapping(
					value[i].mappings[j].filePath,
					value[i].mappings[j].name,
					value[i].mappings[j].vmAddress,
					value[i].mappings[j].size,
					value[i].mappings[j].loaded,
					value[i].mappings[j].rawViewOffset
				)
				mappings.append(mapping)
			result.append(DSCImage(
				value[i].name,
				value[i].headerAddress,
				mappings
			))

		sccore.BNDSCViewFreeAllImages(value, count)
		return result

	@property
	def loaded_regions(self):
		"""
		Get all loaded regions in the shared cache

		The internal logic for loading images treats a region as 'loaded' whenever
		that region has been mapped into memory, and, if it's located within an image, header information has been applied to that region.

		Individual segments within an image can be loaded independently of the image itself.

		Only once all regions of an image are loaded will the header processor refuse to run on that region.
		:return:
		"""
		count = ctypes.c_ulonglong()
		value = sccore.BNDSCViewGetLoadedRegions(self.handle, count)
		if value is None:
			return []

		result = []
		for i in range(count.value):
			mapping = DSCMemoryMapping(
				value[i].name,
				value[i].vmAddress,
				value[i].size,
			)
			result.append(mapping)
		sccore.BNDSCViewFreeLoadedRegions(value, count)
		return result

	def load_all_symbols_and_wait(self):
		count = ctypes.c_ulonglong()
		value = sccore.BNDSCViewLoadAllSymbolsAndWait(self.handle, count)
		if value is None:
			return []
		result = []
		for i in range(count.value):
			sym = DSCSymbol(
				value[i].name,
				value[i].image,
				value[i].address
			)
			result.append(sym)

		sccore.BNDSCViewFreeSymbols(value, count)
		return result

	@property
	def image_names(self):
		count = ctypes.c_ulonglong()
		value = sccore.BNDSCViewGetInstallNames(self.handle, count)
		if value is None:
			return []

		result = []
		for i in range(count.value):
			result.append(value[i].decode('utf-8'))

		BNFreeStringList(value, count)
		return result

	@property
	def state(self):
		return DSCViewState(sccore.BNDSCViewGetState(self.handle))

	def get_name_for_address(self, address):
		name = sccore.BNDSCViewGetNameForAddress(self.handle, address)
		if name is None:
			return ""
		result = name
		return result

	def get_image_name_for_address(self, address):
		name = sccore.BNDSCViewGetImageNameForAddress(self.handle, address)
		if name is None:
			return ""
		result = name
		return result

	def find_symbol_at_addr_and_apply_to_addr(self, symbolAddress, targetAddress, triggerReanalysis) -> None:
		sccore.BNDSCFindSymbolAtAddressAndApplyToAddress(self.handle, symbolAddress, targetAddress, triggerReanalysis)
