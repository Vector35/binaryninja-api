import binaryninja
import ctypes, os

from typing import Optional
from . import sharedcache_enums
# Load core module
import platform
core = None
core_platform = platform.system()

from binaryninja import Settings
if Settings().get_bool("corePlugins.view.sharedCache"):
    from binaryninja._binaryninjacore import BNGetBundledPluginDirectory
    if core_platform == "Darwin":
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libsharedcache.dylib"))

    elif core_platform == "Linux":
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libsharedcache.so"))

    elif (core_platform == "Windows") or (core_platform.find("CYGWIN_NT") == 0):
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "sharedcache.dll"))
    else:
        raise Exception("OS not supported")
else:
    from binaryninja._binaryninjacore import BNGetUserPluginDirectory
    if core_platform == "Darwin":
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libsharedcache.dylib"))

    elif core_platform == "Linux":
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libsharedcache.so"))

    elif (core_platform == "Windows") or (core_platform.find("CYGWIN_NT") == 0):
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "sharedcache.dll"))
    else:
        raise Exception("OS not supported")

def cstr(var) -> Optional[ctypes.c_char_p]:
    if var is None:
        return None
    if isinstance(var, bytes):
        return var
    return var.encode("utf-8")

def pyNativeStr(arg):
    if isinstance(arg, str):
        return arg
    else:
        return arg.decode('utf8')

def free_string(value:ctypes.c_char_p) -> None:
    BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))

# Type definitions
from binaryninja._binaryninjacore import BNBinaryView, BNBinaryViewHandle
SegmentFlagEnum = ctypes.c_int
class BNSharedCacheController(ctypes.Structure):
	pass
BNSharedCacheControllerHandle = ctypes.POINTER(BNSharedCacheController)
class BNSharedCacheEntry(ctypes.Structure):
	@property
	def path(self):
		return pyNativeStr(self._path)
	@path.setter
	def path(self, value):
		self._path = cstr(value)
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
BNSharedCacheEntryHandle = ctypes.POINTER(BNSharedCacheEntry)
SharedCacheEntryTypeEnum = ctypes.c_int
class BNSharedCacheImage(ctypes.Structure):
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
BNSharedCacheImageHandle = ctypes.POINTER(BNSharedCacheImage)
class BNSharedCacheMappingInfo(ctypes.Structure):
	pass
BNSharedCacheMappingInfoHandle = ctypes.POINTER(BNSharedCacheMappingInfo)
class BNSharedCacheRegion(ctypes.Structure):
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
BNSharedCacheRegionHandle = ctypes.POINTER(BNSharedCacheRegion)
SharedCacheRegionTypeEnum = ctypes.c_int
class BNSharedCacheSymbol(ctypes.Structure):
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
BNSharedCacheSymbolHandle = ctypes.POINTER(BNSharedCacheSymbol)
SymbolTypeEnum = ctypes.c_int

# Structure definitions
BNSharedCacheEntry._fields_ = [
		("_path", ctypes.c_char_p),
		("_name", ctypes.c_char_p),
		("entryType", SharedCacheEntryTypeEnum),
		("mappingCount", ctypes.c_ulonglong),
		("mappings", ctypes.POINTER(BNSharedCacheMappingInfo)),
	]
BNSharedCacheImage._fields_ = [
		("_name", ctypes.c_char_p),
		("headerAddress", ctypes.c_ulonglong),
		("regionStartCount", ctypes.c_ulonglong),
		("regionStarts", ctypes.POINTER(ctypes.c_ulonglong)),
	]
BNSharedCacheMappingInfo._fields_ = [
		("vmAddress", ctypes.c_ulonglong),
		("size", ctypes.c_ulonglong),
		("fileOffset", ctypes.c_ulonglong),
	]
BNSharedCacheRegion._fields_ = [
		("regionType", SharedCacheRegionTypeEnum),
		("_name", ctypes.c_char_p),
		("vmAddress", ctypes.c_ulonglong),
		("size", ctypes.c_ulonglong),
		("imageStart", ctypes.c_ulonglong),
		("flags", SegmentFlagEnum),
	]
BNSharedCacheSymbol._fields_ = [
		("symbolType", SymbolTypeEnum),
		("address", ctypes.c_ulonglong),
		("_name", ctypes.c_char_p),
	]

# Function definitions
# -------------------------------------------------------
# _BNFreeSharedCacheControllerReference

_BNFreeSharedCacheControllerReference = core.BNFreeSharedCacheControllerReference
_BNFreeSharedCacheControllerReference.restype = None
_BNFreeSharedCacheControllerReference.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
	]


# noinspection PyPep8Naming
def BNFreeSharedCacheControllerReference(
		controller: ctypes.POINTER(BNSharedCacheController)
		) -> None:
	return _BNFreeSharedCacheControllerReference(controller)


# -------------------------------------------------------
# _BNGetSharedCacheController

_BNGetSharedCacheController = core.BNGetSharedCacheController
_BNGetSharedCacheController.restype = ctypes.POINTER(BNSharedCacheController)
_BNGetSharedCacheController.argtypes = [
		ctypes.POINTER(BNBinaryView),
	]


# noinspection PyPep8Naming
def BNGetSharedCacheController(
		data: ctypes.POINTER(BNBinaryView)
		) -> Optional[ctypes.POINTER(BNSharedCacheController)]:
	result = _BNGetSharedCacheController(data)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNNewSharedCacheControllerReference

_BNNewSharedCacheControllerReference = core.BNNewSharedCacheControllerReference
_BNNewSharedCacheControllerReference.restype = ctypes.POINTER(BNSharedCacheController)
_BNNewSharedCacheControllerReference.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
	]


# noinspection PyPep8Naming
def BNNewSharedCacheControllerReference(
		controller: ctypes.POINTER(BNSharedCacheController)
		) -> Optional[ctypes.POINTER(BNSharedCacheController)]:
	result = _BNNewSharedCacheControllerReference(controller)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNSharedCacheAllocRegionList

_BNSharedCacheAllocRegionList = core.BNSharedCacheAllocRegionList
_BNSharedCacheAllocRegionList.restype = ctypes.POINTER(ctypes.c_ulonglong)
_BNSharedCacheAllocRegionList.argtypes = [
		ctypes.POINTER(ctypes.c_ulonglong),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNSharedCacheAllocRegionList(
		list: ctypes.POINTER(ctypes.c_ulonglong), 
		count: int
		) -> Optional[ctypes.POINTER(ctypes.c_ulonglong)]:
	result = _BNSharedCacheAllocRegionList(list, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNSharedCacheControllerApplyImage

_BNSharedCacheControllerApplyImage = core.BNSharedCacheControllerApplyImage
_BNSharedCacheControllerApplyImage.restype = ctypes.c_bool
_BNSharedCacheControllerApplyImage.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(BNBinaryView),
		ctypes.POINTER(BNSharedCacheImage),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerApplyImage(
		controller: ctypes.POINTER(BNSharedCacheController), 
		view: ctypes.POINTER(BNBinaryView), 
		image: ctypes.POINTER(BNSharedCacheImage)
		) -> bool:
	return _BNSharedCacheControllerApplyImage(controller, view, image)


# -------------------------------------------------------
# _BNSharedCacheControllerApplyRegion

_BNSharedCacheControllerApplyRegion = core.BNSharedCacheControllerApplyRegion
_BNSharedCacheControllerApplyRegion.restype = ctypes.c_bool
_BNSharedCacheControllerApplyRegion.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(BNBinaryView),
		ctypes.POINTER(BNSharedCacheRegion),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerApplyRegion(
		controller: ctypes.POINTER(BNSharedCacheController), 
		view: ctypes.POINTER(BNBinaryView), 
		region: ctypes.POINTER(BNSharedCacheRegion)
		) -> bool:
	return _BNSharedCacheControllerApplyRegion(controller, view, region)


# -------------------------------------------------------
# _BNSharedCacheControllerGetEntries

_BNSharedCacheControllerGetEntries = core.BNSharedCacheControllerGetEntries
_BNSharedCacheControllerGetEntries.restype = ctypes.POINTER(BNSharedCacheEntry)
_BNSharedCacheControllerGetEntries.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetEntries(
		controller: ctypes.POINTER(BNSharedCacheController), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNSharedCacheEntry)]:
	result = _BNSharedCacheControllerGetEntries(controller, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNSharedCacheControllerGetImageAt

_BNSharedCacheControllerGetImageAt = core.BNSharedCacheControllerGetImageAt
_BNSharedCacheControllerGetImageAt.restype = ctypes.c_bool
_BNSharedCacheControllerGetImageAt.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.c_ulonglong,
		ctypes.POINTER(BNSharedCacheImage),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetImageAt(
		controller: ctypes.POINTER(BNSharedCacheController), 
		address: int, 
		image: ctypes.POINTER(BNSharedCacheImage)
		) -> bool:
	return _BNSharedCacheControllerGetImageAt(controller, address, image)


# -------------------------------------------------------
# _BNSharedCacheControllerGetImageContaining

_BNSharedCacheControllerGetImageContaining = core.BNSharedCacheControllerGetImageContaining
_BNSharedCacheControllerGetImageContaining.restype = ctypes.c_bool
_BNSharedCacheControllerGetImageContaining.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.c_ulonglong,
		ctypes.POINTER(BNSharedCacheImage),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetImageContaining(
		controller: ctypes.POINTER(BNSharedCacheController), 
		address: int, 
		image: ctypes.POINTER(BNSharedCacheImage)
		) -> bool:
	return _BNSharedCacheControllerGetImageContaining(controller, address, image)


# -------------------------------------------------------
# _BNSharedCacheControllerGetImageDependencies

_BNSharedCacheControllerGetImageDependencies = core.BNSharedCacheControllerGetImageDependencies
_BNSharedCacheControllerGetImageDependencies.restype = ctypes.POINTER(ctypes.c_char_p)
_BNSharedCacheControllerGetImageDependencies.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(BNSharedCacheImage),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetImageDependencies(
		controller: ctypes.POINTER(BNSharedCacheController), 
		image: ctypes.POINTER(BNSharedCacheImage), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(ctypes.c_char_p)]:
	result = _BNSharedCacheControllerGetImageDependencies(controller, image, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNSharedCacheControllerGetImageWithName

_BNSharedCacheControllerGetImageWithName = core.BNSharedCacheControllerGetImageWithName
_BNSharedCacheControllerGetImageWithName.restype = ctypes.c_bool
_BNSharedCacheControllerGetImageWithName.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.c_char_p,
		ctypes.POINTER(BNSharedCacheImage),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetImageWithName(
		controller: ctypes.POINTER(BNSharedCacheController), 
		name: Optional[str], 
		image: ctypes.POINTER(BNSharedCacheImage)
		) -> bool:
	return _BNSharedCacheControllerGetImageWithName(controller, cstr(name), image)


# -------------------------------------------------------
# _BNSharedCacheControllerGetImages

_BNSharedCacheControllerGetImages = core.BNSharedCacheControllerGetImages
_BNSharedCacheControllerGetImages.restype = ctypes.POINTER(BNSharedCacheImage)
_BNSharedCacheControllerGetImages.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetImages(
		controller: ctypes.POINTER(BNSharedCacheController), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNSharedCacheImage)]:
	result = _BNSharedCacheControllerGetImages(controller, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNSharedCacheControllerGetLoadedImages

_BNSharedCacheControllerGetLoadedImages = core.BNSharedCacheControllerGetLoadedImages
_BNSharedCacheControllerGetLoadedImages.restype = ctypes.POINTER(BNSharedCacheImage)
_BNSharedCacheControllerGetLoadedImages.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetLoadedImages(
		controller: ctypes.POINTER(BNSharedCacheController), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNSharedCacheImage)]:
	result = _BNSharedCacheControllerGetLoadedImages(controller, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNSharedCacheControllerGetLoadedRegions

_BNSharedCacheControllerGetLoadedRegions = core.BNSharedCacheControllerGetLoadedRegions
_BNSharedCacheControllerGetLoadedRegions.restype = ctypes.POINTER(BNSharedCacheRegion)
_BNSharedCacheControllerGetLoadedRegions.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetLoadedRegions(
		controller: ctypes.POINTER(BNSharedCacheController), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNSharedCacheRegion)]:
	result = _BNSharedCacheControllerGetLoadedRegions(controller, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNSharedCacheControllerGetRegionAt

_BNSharedCacheControllerGetRegionAt = core.BNSharedCacheControllerGetRegionAt
_BNSharedCacheControllerGetRegionAt.restype = ctypes.c_bool
_BNSharedCacheControllerGetRegionAt.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.c_ulonglong,
		ctypes.POINTER(BNSharedCacheRegion),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetRegionAt(
		controller: ctypes.POINTER(BNSharedCacheController), 
		address: int, 
		outRegion: ctypes.POINTER(BNSharedCacheRegion)
		) -> bool:
	return _BNSharedCacheControllerGetRegionAt(controller, address, outRegion)


# -------------------------------------------------------
# _BNSharedCacheControllerGetRegionContaining

_BNSharedCacheControllerGetRegionContaining = core.BNSharedCacheControllerGetRegionContaining
_BNSharedCacheControllerGetRegionContaining.restype = ctypes.c_bool
_BNSharedCacheControllerGetRegionContaining.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.c_ulonglong,
		ctypes.POINTER(BNSharedCacheRegion),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetRegionContaining(
		controller: ctypes.POINTER(BNSharedCacheController), 
		address: int, 
		region: ctypes.POINTER(BNSharedCacheRegion)
		) -> bool:
	return _BNSharedCacheControllerGetRegionContaining(controller, address, region)


# -------------------------------------------------------
# _BNSharedCacheControllerGetRegions

_BNSharedCacheControllerGetRegions = core.BNSharedCacheControllerGetRegions
_BNSharedCacheControllerGetRegions.restype = ctypes.POINTER(BNSharedCacheRegion)
_BNSharedCacheControllerGetRegions.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetRegions(
		controller: ctypes.POINTER(BNSharedCacheController), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNSharedCacheRegion)]:
	result = _BNSharedCacheControllerGetRegions(controller, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNSharedCacheControllerGetSymbolAt

_BNSharedCacheControllerGetSymbolAt = core.BNSharedCacheControllerGetSymbolAt
_BNSharedCacheControllerGetSymbolAt.restype = ctypes.c_bool
_BNSharedCacheControllerGetSymbolAt.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.c_ulonglong,
		ctypes.POINTER(BNSharedCacheSymbol),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetSymbolAt(
		controller: ctypes.POINTER(BNSharedCacheController), 
		address: int, 
		symbol: ctypes.POINTER(BNSharedCacheSymbol)
		) -> bool:
	return _BNSharedCacheControllerGetSymbolAt(controller, address, symbol)


# -------------------------------------------------------
# _BNSharedCacheControllerGetSymbolWithName

_BNSharedCacheControllerGetSymbolWithName = core.BNSharedCacheControllerGetSymbolWithName
_BNSharedCacheControllerGetSymbolWithName.restype = ctypes.c_bool
_BNSharedCacheControllerGetSymbolWithName.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.c_char_p,
		ctypes.POINTER(BNSharedCacheSymbol),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetSymbolWithName(
		controller: ctypes.POINTER(BNSharedCacheController), 
		name: Optional[str], 
		symbol: ctypes.POINTER(BNSharedCacheSymbol)
		) -> bool:
	return _BNSharedCacheControllerGetSymbolWithName(controller, cstr(name), symbol)


# -------------------------------------------------------
# _BNSharedCacheControllerGetSymbols

_BNSharedCacheControllerGetSymbols = core.BNSharedCacheControllerGetSymbols
_BNSharedCacheControllerGetSymbols.restype = ctypes.POINTER(BNSharedCacheSymbol)
_BNSharedCacheControllerGetSymbols.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerGetSymbols(
		controller: ctypes.POINTER(BNSharedCacheController), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNSharedCacheSymbol)]:
	result = _BNSharedCacheControllerGetSymbols(controller, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNSharedCacheControllerIsImageLoaded

_BNSharedCacheControllerIsImageLoaded = core.BNSharedCacheControllerIsImageLoaded
_BNSharedCacheControllerIsImageLoaded.restype = ctypes.c_bool
_BNSharedCacheControllerIsImageLoaded.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(BNSharedCacheImage),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerIsImageLoaded(
		controller: ctypes.POINTER(BNSharedCacheController), 
		image: ctypes.POINTER(BNSharedCacheImage)
		) -> bool:
	return _BNSharedCacheControllerIsImageLoaded(controller, image)


# -------------------------------------------------------
# _BNSharedCacheControllerIsRegionLoaded

_BNSharedCacheControllerIsRegionLoaded = core.BNSharedCacheControllerIsRegionLoaded
_BNSharedCacheControllerIsRegionLoaded.restype = ctypes.c_bool
_BNSharedCacheControllerIsRegionLoaded.argtypes = [
		ctypes.POINTER(BNSharedCacheController),
		ctypes.POINTER(BNSharedCacheRegion),
	]


# noinspection PyPep8Naming
def BNSharedCacheControllerIsRegionLoaded(
		controller: ctypes.POINTER(BNSharedCacheController), 
		region: ctypes.POINTER(BNSharedCacheRegion)
		) -> bool:
	return _BNSharedCacheControllerIsRegionLoaded(controller, region)


# -------------------------------------------------------
# _BNSharedCacheFreeEntry

_BNSharedCacheFreeEntry = core.BNSharedCacheFreeEntry
_BNSharedCacheFreeEntry.restype = None
_BNSharedCacheFreeEntry.argtypes = [
		BNSharedCacheEntry,
	]


# noinspection PyPep8Naming
def BNSharedCacheFreeEntry(
		entry: BNSharedCacheEntry
		) -> None:
	return _BNSharedCacheFreeEntry(entry)


# -------------------------------------------------------
# _BNSharedCacheFreeEntryList

_BNSharedCacheFreeEntryList = core.BNSharedCacheFreeEntryList
_BNSharedCacheFreeEntryList.restype = None
_BNSharedCacheFreeEntryList.argtypes = [
		ctypes.POINTER(BNSharedCacheEntry),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNSharedCacheFreeEntryList(
		entries: ctypes.POINTER(BNSharedCacheEntry), 
		count: int
		) -> None:
	return _BNSharedCacheFreeEntryList(entries, count)


# -------------------------------------------------------
# _BNSharedCacheFreeImage

_BNSharedCacheFreeImage = core.BNSharedCacheFreeImage
_BNSharedCacheFreeImage.restype = None
_BNSharedCacheFreeImage.argtypes = [
		BNSharedCacheImage,
	]


# noinspection PyPep8Naming
def BNSharedCacheFreeImage(
		image: BNSharedCacheImage
		) -> None:
	return _BNSharedCacheFreeImage(image)


# -------------------------------------------------------
# _BNSharedCacheFreeImageList

_BNSharedCacheFreeImageList = core.BNSharedCacheFreeImageList
_BNSharedCacheFreeImageList.restype = None
_BNSharedCacheFreeImageList.argtypes = [
		ctypes.POINTER(BNSharedCacheImage),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNSharedCacheFreeImageList(
		images: ctypes.POINTER(BNSharedCacheImage), 
		count: int
		) -> None:
	return _BNSharedCacheFreeImageList(images, count)


# -------------------------------------------------------
# _BNSharedCacheFreeRegion

_BNSharedCacheFreeRegion = core.BNSharedCacheFreeRegion
_BNSharedCacheFreeRegion.restype = None
_BNSharedCacheFreeRegion.argtypes = [
		BNSharedCacheRegion,
	]


# noinspection PyPep8Naming
def BNSharedCacheFreeRegion(
		region: BNSharedCacheRegion
		) -> None:
	return _BNSharedCacheFreeRegion(region)


# -------------------------------------------------------
# _BNSharedCacheFreeRegionList

_BNSharedCacheFreeRegionList = core.BNSharedCacheFreeRegionList
_BNSharedCacheFreeRegionList.restype = None
_BNSharedCacheFreeRegionList.argtypes = [
		ctypes.POINTER(BNSharedCacheRegion),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNSharedCacheFreeRegionList(
		regions: ctypes.POINTER(BNSharedCacheRegion), 
		count: int
		) -> None:
	return _BNSharedCacheFreeRegionList(regions, count)


# -------------------------------------------------------
# _BNSharedCacheFreeSymbol

_BNSharedCacheFreeSymbol = core.BNSharedCacheFreeSymbol
_BNSharedCacheFreeSymbol.restype = None
_BNSharedCacheFreeSymbol.argtypes = [
		BNSharedCacheSymbol,
	]


# noinspection PyPep8Naming
def BNSharedCacheFreeSymbol(
		symbol: BNSharedCacheSymbol
		) -> None:
	return _BNSharedCacheFreeSymbol(symbol)


# -------------------------------------------------------
# _BNSharedCacheFreeSymbolList

_BNSharedCacheFreeSymbolList = core.BNSharedCacheFreeSymbolList
_BNSharedCacheFreeSymbolList.restype = None
_BNSharedCacheFreeSymbolList.argtypes = [
		ctypes.POINTER(BNSharedCacheSymbol),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNSharedCacheFreeSymbolList(
		symbols: ctypes.POINTER(BNSharedCacheSymbol), 
		count: int
		) -> None:
	return _BNSharedCacheFreeSymbolList(symbols, count)



# Helper functions
def handle_of_type(value, handle_type):
	if isinstance(value, ctypes.POINTER(handle_type)) or isinstance(value, ctypes.c_void_p):
		return ctypes.cast(value, ctypes.POINTER(handle_type))
	raise ValueError('expected pointer to %s' % str(handle_type))
