import os
import ctypes
import dataclasses
import traceback

import binaryninja
from binaryninja._binaryninjacore import BNFreeStringList, BNAllocString, BNFreeString

from . import _kernelcachecore as kccore
from .kernelcache_enums import *


@dataclasses.dataclass
class KCImageMemoryMapping:
	name: str
	vmAddress: int
	rawViewOffset: int
	size: int

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return (f"<KCImageMemoryMapping '{self.name}' {self.vmAddress:x}+{self.size:x} "
				f"raw<{self.rawViewOffset:x}>>")


@dataclasses.dataclass
class KCImage:
	name: str
	headerFileAddress: int
	mappings: list[KCImageMemoryMapping]

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<KCImage {self.name} @ {self.headerFileAddress:x}>"


@dataclasses.dataclass
class KCSymbol:
	name: str
	image: str
	address: int

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<KCSymbol {self.name} @ {self.address:x} ({self.image})>"


@dataclasses.dataclass
class KernelCacheMachOHeader:
	header: str

	@classmethod
	def LoadFromString(cls, s: str):
		return cls(header=s)

	def __repr__(self):
		return f"<KernelCacheMachOHeader {self.header!r}>"


class KernelCache:
	def __init__(self, view):
		# Create a KernelCache object from a BinaryView.
		self.handle = kccore.BNGetKernelCache(view.handle)

	@staticmethod
	def get_load_progress(view) -> int:
		"""
		Returns the current load progress.
		Note: In the C++ FFI this function takes the BinaryView's file session ID.
		"""
		return KCViewLoadProgress(kccore.BNKCViewGetLoadProgress(view.file.session_id))

	@staticmethod
	def fast_get_image_count(view) -> int:
		"""
		Quickly returns the number of images in the kernel cache.
		"""
		return kccore.BNKCViewFastGetImageCount(view.handle)

	def load_image_with_install_name(self, install_name: str) -> bool:
		"""
		Load a kernel cache image by its install name.
		"""
		return kccore.BNKCViewLoadImageWithInstallName(self.handle, install_name)

	def load_image_containing_address(self, addr: int) -> bool:
		"""
		Load the image that contains the given address.
		"""
		return kccore.BNKCViewLoadImageContainingAddress(self.handle, addr)

	@property
	def image_names(self) -> list[str]:
		"""
		Return a list of available kernel cache image install names.
		"""
		count = ctypes.c_ulonglong()
		value = kccore.BNKCViewGetInstallNames(self.handle, count)
		if value is None:
			return []
		result = []
		for i in range(count.value):
			result.append(value[i].decode('utf-8'))
		BNFreeStringList(value, count)
		return result

	@property
	def images(self) -> list[KCImage]:
		"""
		Return all kernel cache images.
		"""
		count = ctypes.c_ulonglong()
		value = kccore.BNKCViewGetAllImages(self.handle, count)
		if value is None:
			return []
		result = []
		for i in range(count.value):
			mappings = []
			for j in range(value[i].mappingCount):
				mapping = KCImageMemoryMapping(
					name=value[i].mappings[j].name,
					vmAddress=value[i].mappings[j].vmAddress,
					rawViewOffset=value[i].mappings[j].rawViewOffset,
					size=value[i].mappings[j].size,
				)
				mappings.append(mapping)
			result.append(KCImage(
				name=value[i].name,
				headerFileAddress=value[i].headerFileAddress,
				mappings=mappings
			))
		kccore.BNKCViewFreeAllImages(value, count)
		return result

	@property
	def loaded_images(self) -> list[KCImage]:
		"""
		Return the kernel cache images that are currently loaded.
		"""
		count = ctypes.c_ulonglong()
		images = kccore.BNKCViewGetLoadedImages(self.handle, count)
		if images is None:
			return []
		result = []
		for i in range(count.value):
			mappings = []
			for j in range(images[i].mappingCount):
				mapping = KCImageMemoryMapping(
					name=images[i].mappings[j].name,
					vmAddress=images[i].mappings[j].vmAddress,
					rawViewOffset=images[i].mappings[j].rawViewOffset,
					size=images[i].mappings[j].size,
				)
				mappings.append(mapping)
			result.append(KCImage(
				name=images[i].name,
				headerFileAddress=images[i].headerFileAddress,
				mappings=mappings
			))
		kccore.BNKCViewFreeAllImages(images, count)
		return result

	def load_all_symbols_and_wait(self) -> list[KCSymbol]:
		"""
		Load all symbols from the kernel cache and wait for completion.
		"""
		count = ctypes.c_ulonglong()
		value = kccore.BNKCViewLoadAllSymbolsAndWait(self.handle, count)
		if value is None:
			return []
		result = []
		for i in range(count.value):
			sym = KCSymbol(
				name=value[i].name,
				image=value[i].image,
				address=value[i].address
			)
			result.append(sym)
		kccore.BNKCViewFreeSymbols(value, count)
		return result

	def get_name_for_address(self, address: int) -> str:
		"""
		Return the symbol name for a given address.
		"""
		name = kccore.BNKCViewGetNameForAddress(self.handle, address)
		if name is None:
			return ""
		return name

	def get_image_name_for_address(self, address: int) -> str:
		"""
		Return the image name for a given address.
		"""
		name = kccore.BNKCViewGetImageNameForAddress(self.handle, address)
		if name is None:
			return ""
		return name

	def get_macho_header_for_image(self, name: str):
		"""
		Return a KernelCacheMachOHeader for the image with the given install name.
		"""
		s = BNAllocString(name)
		outputStr = kccore.BNKCViewGetImageHeaderForName(self.handle, s)
		if outputStr is None:
			return None
		output = outputStr
		BNFreeString(outputStr)
		if output == "":
			return None
		return KernelCacheMachOHeader.LoadFromString(output)

	def get_macho_header_for_address(self, address: int):
		"""
		Return a KernelCacheMachOHeader for the image containing the given address.
		"""
		outputStr = kccore.BNKCViewGetImageHeaderForAddress(self.handle, address)
		if outputStr is None:
			return None
		output = outputStr
		BNFreeString(outputStr)
		if output == "":
			return None
		return KernelCacheMachOHeader.LoadFromString(output)

	@property
	def state(self):
		"""
		Return the current state of the kernel cache.
		"""
		return KCViewState(kccore.BNKCViewGetState(self.handle))
