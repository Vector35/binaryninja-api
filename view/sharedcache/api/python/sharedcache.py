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
	cacheType: BackingCacheType
	mappings: list[DSCBackingCacheMapping]

	def __str__(self):
		return repr(self)

	def __repr__(self):
		cache_type_str = 'Unknown'
		if self.cacheType == BackingCacheType.BackingCacheTypePrimary:
			cache_type_str = 'Primary'
		elif self.cacheType == BackingCacheType.BackingCacheTypeSecondary:
			cache_type_str = 'Secondary'
		elif self.cacheType == BackingCacheType.BackingCacheTypeSymbols:
			cache_type_str = 'Symbols'
		return f"<DSCBackingCache {self.path} {cache_type_str} | {len(self.mappings)} mappings>"


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
	"""
	SharedCache is the primary class for interacting with the shared cache processor and DSCView metadata.

	You can create a SharedCache object from a BinaryView object by calling `SharedCache(bv)`, where `bv` is the BinaryView.

	By default `bv` in the console will return the instance of the BinaryView that is currently open, \
		so in the UI, you can use `dsc = SharedCache(bv)` to create a SharedCache object in the scripting console.

	Methods and attributes in this class have documentation which can be viewed by typing `SharedCache.method_or_attribute_name?` in the console.
	"""
	def __init__(self, view):
		self.handle = sccore.BNGetSharedCache(view.handle)

	def load_image_with_install_name(self, install_name, skip_loading_objective_c = False) -> bool:
		"""
		Locate an image with the provided install name and load it into the shared cache view

		:param install_name: Install name of the image
		:param skip_loading_objective_c: Whether to skip process Objective-C information for this image. Default false.
		:return:
		"""
		return sccore.BNDSCViewLoadImageWithInstallName(self.handle, install_name, skip_loading_objective_c)

	def load_section_at_address(self, addr) -> bool:
		"""
		Load a singular section at the provided address into the shared cache view.

		This will partial-load the image, only mapping the requested segment containing this section.

		Image info will still be processed, but will only be applied to mapped regions.

		:param addr: Address within the section
		:return:
		"""
		return sccore.BNDSCViewLoadSectionAtAddress(self.handle, addr)

	def load_image_containing_address(self, addr, skip_loading_objective_c = False) -> bool:
		"""
		Load the image containing the provided address into the shared cache view.

		:param addr: Address within the image to load
		:param skip_loading_objective_c: Whether to skip processing Objective-C information for this image. Default false.
		:return:
		"""
		return sccore.BNDSCViewLoadImageContainingAddress(self.handle, addr, skip_loading_objective_c)

	def process_objc_sections_for_image_with_install_name(self, install_name) -> bool:
		"""
		Process Objective-C information for the image with the provided install name.

		:param install_name: Install name of the image
		:return:
		"""
		return sccore.BNDSCViewProcessObjCSectionsForImageWithInstallName(self.handle, install_name, False)

	def process_all_objc_sections(self) -> bool:
		"""
		Process Objective-C information for all images in the shared cache view.

		:return:
		"""
		return sccore.BNDSCViewProcessAllObjCSections(self.handle)

	@property
	def caches(self) -> list[DSCBackingCache]:
		"""
		Get all backing caches in the shared cache.
		:return:
		"""
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
				value[i].cacheType,
				mappings
			))

		sccore.BNDSCViewFreeBackingCaches(value, count)
		return result

	@property
	def images(self) -> list[DSCImage]:
		"""
		Get all images in the shared cache
		:return:
		"""
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
	def loaded_regions(self) -> list[LoadedRegion]:
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

	def load_all_symbols_and_wait(self) -> list[DSCSymbol]:
		"""
		Load all symbols in the shared cache. This will block on the current thread waiting for processing to finish.

		While all functions in this API are synchronous, this function can be particularly slow due to the large number
			of symbols in the shared cache. "and_wait" is appended to the function name to indicate that this function
			will block until processing is complete, and for performant applications, you should consider calling this
			function in a separate thread and waiting on its return. An example of this is provided in the shared cache
			triage view.

		This may take several seconds if this is the first time this function is called. Subsequent calls will be faster.

		In UI-based API usage, it is likely that the triage view will have already performed this operation, and calls
			to this function will be much faster.

		:return: A list of all symbols in the shared cache
		"""
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
	def image_names(self) -> list[str]:
		"""
		Get all image names in the shared cache
		:return:
		"""
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
	def state(self) -> DSCViewState:
		"""
		Get the current image state of the shared cache view. Useful for checking if images have been loaded yet or not.
		:return:
		"""
		return DSCViewState(sccore.BNDSCViewGetState(self.handle))

	def get_name_for_address(self, address) -> str:
		"""
		Get the "name" for the provided address. Specifically, the name of the memory region this address lies in.

		If this lies within an image segment, this will be in the format image_name + "::" + segment_name.

		It may also be the name of a branch pool or other non-image region.

		This is the API call utilized on the first dynamic entry in the right-click context menu.

		:param address: address to check
		:return:
		"""
		name = sccore.BNDSCViewGetNameForAddress(self.handle, address)
		if name is None:
			return ""
		result = name
		return result

	def get_image_name_for_address(self, address) -> str:
		"""
		Return the install name for the image containing the provided address.

		If the address is not within an image, this will return an empty string.

		This is the API call used in the second dynamic entry in the right-click context menu.

		:param address: address to check
		:return:
		"""
		name = sccore.BNDSCViewGetImageNameForAddress(self.handle, address)
		if name is None:
			return ""
		result = name
		return result

	def find_symbol_at_addr_and_apply_to_addr(self, symbol_address, target_address, trigger_reanalysis) -> None:
		"""
		This is primarily a function utilized for automated backwards symbol propagation for stubs in the workflow, however
			it is passed through here as well in the event you need to use it to do something similar, or want to create
			your own version of the workflow.

		This is currently a blocking function.

		This will check the cache for a symbol located at symbol_address, and apply it to target_address, appending a
			`j_` to the front of the symbol name copy at `target_address`.

		It will additionally backwards-propagate type information that was specifically applied via TypeLibrary to the stub.

		This includes calling conventions and can be seen in stubs pointing to objc_release_x[register] functions.

		This check will not run if:
		- The symbol address and target address are the same
		- The target address has already been given a name by this function

		:param symbol_address: Symbol address to check
		:param target_address: Target address to apply symbol name and type to
		:param trigger_reanalysis: Whether to reanalyze the function at target_address if the function already existed.
		:return: None
		"""
		sccore.BNDSCFindSymbolAtAddressAndApplyToAddress(self.handle, symbol_address, target_address, trigger_reanalysis)
