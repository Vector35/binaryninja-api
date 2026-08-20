import ctypes
import dataclasses
from typing import Optional

import binaryninja
from binaryninja import BinaryView
from binaryninja._binaryninjacore import BNFreeStringList, BNAllocString, BNFreeString

from . import _kernelcachecore as kccore
from .kernelcache_enums import *

@dataclasses.dataclass
class CacheImage:
	name: str
	header_virtual_address: int
	header_file_address: int

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<CacheImage '{self.name}': 0x{self.header_virtual_address:x} (@0x{self.header_file_address:x})>"

@dataclasses.dataclass
class CacheSymbol:
	symbol_type: kccore.SymbolTypeEnum
	address: int
	name: str

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<CacheSymbol '{self.name}': 0x{self.address:x}>"

def image_from_api(image: kccore.BNKernelCacheImage) -> CacheImage:
	return CacheImage(
		name=image.name,
		header_file_address=image.headerFileAddress,
		header_virtual_address=image.headerVirtualAddress
	)

def image_to_api(image: CacheImage) -> kccore.BNKernelCacheImage:
	return kccore.BNKernelCacheImage(
		_name=BNAllocString(image.name),
		headerFileAddress=image.header_file_address,
		headerVirtualAddress=image.header_virtual_address,
	)

def symbol_from_api(symbol: kccore.BNKernelCacheSymbol) -> CacheSymbol:
	return CacheSymbol(
		symbol_type=symbol.symbolType,
		address=symbol.address,
		name=symbol.name
	)

def symbol_to_api(symbol: CacheSymbol) -> kccore.BNKernelCacheSymbol:
	return kccore.BNKernelCacheSymbol(
		symbolType=symbol.symbol_type,
		address=symbol.address,
		_name=BNAllocString(symbol.name)
	)

class KernelCacheController:
	def __init__(self, view: BinaryView):
		"""
		Retrieve the shared cache controller for a given view.
		Call `is_valid` to check if the controller is valid.
		"""
		self.handle = kccore.BNGetKernelCacheController(view.handle)

	def __del__(self):
		if self.handle is not None:
			kccore.BNFreeKernelCacheControllerReference(self.handle)

	def __str__(self):
		return repr(self)

	def __repr__(self):
		return f"<KernelCacheController: {len(self.images)} images>"

	def is_valid(self) -> bool:
		return self.handle is not None

	def apply_image(self, view: BinaryView, image: CacheImage) -> bool:
		api_image: kccore.BNKernelCacheImage = image_to_api(image)
		result = kccore.BNKernelCacheControllerApplyImage(self.handle, view.handle, api_image)
		kccore.BNKernelCacheFreeImage(api_image)
		return result

	def is_image_loaded(self, image: CacheImage) -> bool:
		api_image: kccore.BNKernelCacheImage = image_to_api(image)
		result = kccore.BNKernelCacheControllerIsImageLoaded(self.handle, api_image)
		kccore.BNKernelCacheFreeImage(api_image)
		return result

	def get_image_at(self, address: int) -> Optional[CacheImage]:
		api_image = kccore.BNKernelCacheImage()
		if not kccore.BNKernelCacheControllerGetImageAt(self.handle, address, api_image):
			return None
		image = image_from_api(api_image)
		kccore.BNKernelCacheFreeImage(api_image)
		return image

	def get_image_containing(self, address: int) -> Optional[CacheImage]:
		api_image = kccore.BNKernelCacheImage()
		if not kccore.BNKernelCacheControllerGetImageContaining(self.handle, address, api_image):
			return None
		image = image_from_api(api_image)
		kccore.BNKernelCacheFreeImage(api_image)
		return image

	def get_image_with_name(self, name: str) -> Optional[CacheImage]:
		api_image = kccore.BNKernelCacheImage()
		if not kccore.BNKernelCacheControllerGetImageWithName(self.handle, name, api_image):
			return None
		image = image_from_api(api_image)
		kccore.BNKernelCacheFreeImage(api_image)
		return image

	def get_image_dependencies(self, image: CacheImage) -> [str]:
		"""
		Returns a list of image names that this image depends on.
		"""
		count = ctypes.c_ulonglong()
		api_image: kccore.BNKernelCacheImage = image_to_api(image)
		value = kccore.BNKernelCacheControllerGetImageDependencies(self.handle, api_image, count)
		kccore.BNKernelCacheFreeImage(api_image)
		if value is None:
			return []
		result = []
		for i in range(count.value):
			result.append(value[i].decode("utf-8"))
		BNFreeStringList(value, count)
		return result

	def get_symbol_at(self, address: int) -> Optional[CacheSymbol]:
		api_symbol = kccore.BNKernelCacheSymbol()
		if not kccore.BNKernelCacheControllerGetSymbolAt(self.handle, address, api_symbol):
			return None
		symbol = symbol_from_api(api_symbol)
		kccore.BNKernelCacheFreeSymbol(api_symbol)
		return symbol

	def get_symbol_with_name(self, name: str) -> Optional[CacheSymbol]:
		api_symbol = kccore.BNKernelCacheSymbol()
		if not kccore.BNKernelCacheControllerGetSymbolWithName(self.handle, name, api_symbol):
			return None
		symbol = symbol_from_api(api_symbol)
		kccore.BNKernelCacheFreeSymbol(api_symbol)
		return symbol

	@property
	def images(self) -> [CacheImage]:
		count = ctypes.c_ulonglong()
		value = kccore.BNKernelCacheControllerGetImages(self.handle, count)
		if value is None:
			return []
		result = []
		for i in range(count.value):
			result.append(image_from_api(value[i]))
		kccore.BNKernelCacheFreeImageList(value, count)
		return result

	@property
	def loaded_images(self) -> [CacheImage]:
		"""
		Get a list of images that are currently loaded in the view.
		"""
		count = ctypes.c_ulonglong()
		value = kccore.BNKernelCacheControllerGetLoadedImages(self.handle, count)
		if value is None:
			return []
		result = []
		for i in range(count.value):
			result.append(image_from_api(value[i]))
		kccore.BNKernelCacheFreeImageList(value, count)
		return result

	@property
	def symbols(self) -> [CacheSymbol]:
		count = ctypes.c_ulonglong()
		value = kccore.BNKernelCacheControllerGetSymbols(self.handle, count)
		if value is None:
			return []
		result = []
		for i in range(count.value):
			result.append(symbol_from_api(value[i]))
		kccore.BNKernelCacheFreeSymbolList(value, count)
		return result


def _get_kernel_cache(instance: binaryninja.PythonScriptingInstance):
	if instance.interpreter.active_view is None:
		return None
	controller = KernelCacheController(instance.interpreter.active_view)
	if not controller.is_valid():
		return None
	return controller


binaryninja.PythonScriptingProvider.register_magic_variable(
	"kc",
	_get_kernel_cache
)

binaryninja.PythonScriptingProvider.register_magic_variable(
	"kernel_cache",
	_get_kernel_cache
)
