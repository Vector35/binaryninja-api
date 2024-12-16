import binaryninja
import ctypes, os

from typing import Optional
from . import sharedcache_enums
# Load core module
import platform
core = None
core_platform = platform.system()

# By the time the debugger is loaded, binaryninja has not fully initialized.
# So we cannot call binaryninja.bundled_plugin_path()
from binaryninja._binaryninjacore import BNGetBundledPluginDirectory, BNFreeString
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
class BNDSCBackingCache(ctypes.Structure):
	@property
	def path(self):
		return pyNativeStr(self._path)
	@path.setter
	def path(self, value):
		self._path = cstr(value)
BNDSCBackingCacheHandle = ctypes.POINTER(BNDSCBackingCache)
class BNDSCBackingCacheMapping(ctypes.Structure):
	pass
BNDSCBackingCacheMappingHandle = ctypes.POINTER(BNDSCBackingCacheMapping)
class BNDSCImage(ctypes.Structure):
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
BNDSCImageHandle = ctypes.POINTER(BNDSCImage)
class BNDSCImageMemoryMapping(ctypes.Structure):
	@property
	def filePath(self):
		return pyNativeStr(self._filePath)
	@filePath.setter
	def filePath(self, value):
		self._filePath = cstr(value)
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
BNDSCImageMemoryMappingHandle = ctypes.POINTER(BNDSCImageMemoryMapping)
class BNDSCMappedMemoryRegion(ctypes.Structure):
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
BNDSCMappedMemoryRegionHandle = ctypes.POINTER(BNDSCMappedMemoryRegion)
class BNDSCMemoryUsageInfo(ctypes.Structure):
	pass
BNDSCMemoryUsageInfoHandle = ctypes.POINTER(BNDSCMemoryUsageInfo)
class BNDSCSymbolRep(ctypes.Structure):
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
	@property
	def image(self):
		return pyNativeStr(self._image)
	@image.setter
	def image(self, value):
		self._image = cstr(value)
BNDSCSymbolRepHandle = ctypes.POINTER(BNDSCSymbolRep)
DSCViewLoadProgressEnum = ctypes.c_int
DSCViewStateEnum = ctypes.c_int
class BNSharedCache(ctypes.Structure):
	pass
BNSharedCacheHandle = ctypes.POINTER(BNSharedCache)

# Structure definitions
BNDSCBackingCache._fields_ = [
		("_path", ctypes.c_char_p),
		("isPrimary", ctypes.c_bool),
		("mappings", ctypes.POINTER(BNDSCBackingCacheMapping)),
		("mappingCount", ctypes.c_ulonglong),
	]
BNDSCBackingCacheMapping._fields_ = [
		("vmAddress", ctypes.c_ulonglong),
		("size", ctypes.c_ulonglong),
		("fileOffset", ctypes.c_ulonglong),
	]
BNDSCImage._fields_ = [
		("_name", ctypes.c_char_p),
		("headerAddress", ctypes.c_ulonglong),
		("mappings", ctypes.POINTER(BNDSCImageMemoryMapping)),
		("mappingCount", ctypes.c_ulonglong),
	]
BNDSCImageMemoryMapping._fields_ = [
		("_filePath", ctypes.c_char_p),
		("_name", ctypes.c_char_p),
		("vmAddress", ctypes.c_ulonglong),
		("size", ctypes.c_ulonglong),
		("loaded", ctypes.c_bool),
		("rawViewOffset", ctypes.c_ulonglong),
	]
BNDSCMappedMemoryRegion._fields_ = [
		("vmAddress", ctypes.c_ulonglong),
		("size", ctypes.c_ulonglong),
		("_name", ctypes.c_char_p),
	]
BNDSCMemoryUsageInfo._fields_ = [
		("sharedCacheRefs", ctypes.c_ulonglong),
		("mmapRefs", ctypes.c_ulonglong),
	]
BNDSCSymbolRep._fields_ = [
		("address", ctypes.c_ulonglong),
		("_name", ctypes.c_char_p),
		("_image", ctypes.c_char_p),
	]

# Function definitions
# -------------------------------------------------------
# _BNDSCFindSymbolAtAddressAndApplyToAddress

_BNDSCFindSymbolAtAddressAndApplyToAddress = core.BNDSCFindSymbolAtAddressAndApplyToAddress
_BNDSCFindSymbolAtAddressAndApplyToAddress.restype = None
_BNDSCFindSymbolAtAddressAndApplyToAddress.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.c_ulonglong,
		ctypes.c_ulonglong,
		ctypes.c_bool,
	]


# noinspection PyPep8Naming
def BNDSCFindSymbolAtAddressAndApplyToAddress(
		cache: ctypes.POINTER(BNSharedCache), 
		symbolLocation: int, 
		targetLocation: int, 
		triggerReanalysis: bool
		) -> None:
	return _BNDSCFindSymbolAtAddressAndApplyToAddress(cache, symbolLocation, targetLocation, triggerReanalysis)


# -------------------------------------------------------
# _BNDSCViewFastGetBackingCacheCount

_BNDSCViewFastGetBackingCacheCount = core.BNDSCViewFastGetBackingCacheCount
_BNDSCViewFastGetBackingCacheCount.restype = ctypes.c_ulonglong
_BNDSCViewFastGetBackingCacheCount.argtypes = [
		ctypes.POINTER(BNBinaryView),
	]


# noinspection PyPep8Naming
def BNDSCViewFastGetBackingCacheCount(
		view: ctypes.POINTER(BNBinaryView)
		) -> int:
	return _BNDSCViewFastGetBackingCacheCount(view)


# -------------------------------------------------------
# _BNDSCViewFreeAllImages

_BNDSCViewFreeAllImages = core.BNDSCViewFreeAllImages
_BNDSCViewFreeAllImages.restype = None
_BNDSCViewFreeAllImages.argtypes = [
		ctypes.POINTER(BNDSCImage),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNDSCViewFreeAllImages(
		images: ctypes.POINTER(BNDSCImage), 
		count: int
		) -> None:
	return _BNDSCViewFreeAllImages(images, count)


# -------------------------------------------------------
# _BNDSCViewFreeBackingCaches

_BNDSCViewFreeBackingCaches = core.BNDSCViewFreeBackingCaches
_BNDSCViewFreeBackingCaches.restype = None
_BNDSCViewFreeBackingCaches.argtypes = [
		ctypes.POINTER(BNDSCBackingCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNDSCViewFreeBackingCaches(
		caches: ctypes.POINTER(BNDSCBackingCache), 
		count: int
		) -> None:
	return _BNDSCViewFreeBackingCaches(caches, count)


# -------------------------------------------------------
# _BNDSCViewFreeLoadedRegions

_BNDSCViewFreeLoadedRegions = core.BNDSCViewFreeLoadedRegions
_BNDSCViewFreeLoadedRegions.restype = None
_BNDSCViewFreeLoadedRegions.argtypes = [
		ctypes.POINTER(BNDSCMappedMemoryRegion),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNDSCViewFreeLoadedRegions(
		images: ctypes.POINTER(BNDSCMappedMemoryRegion), 
		count: int
		) -> None:
	return _BNDSCViewFreeLoadedRegions(images, count)


# -------------------------------------------------------
# _BNDSCViewFreeSymbols

_BNDSCViewFreeSymbols = core.BNDSCViewFreeSymbols
_BNDSCViewFreeSymbols.restype = None
_BNDSCViewFreeSymbols.argtypes = [
		ctypes.POINTER(BNDSCSymbolRep),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNDSCViewFreeSymbols(
		symbols: ctypes.POINTER(BNDSCSymbolRep), 
		count: int
		) -> None:
	return _BNDSCViewFreeSymbols(symbols, count)


# -------------------------------------------------------
# _BNDSCViewGetAllImages

_BNDSCViewGetAllImages = core.BNDSCViewGetAllImages
_BNDSCViewGetAllImages.restype = ctypes.POINTER(BNDSCImage)
_BNDSCViewGetAllImages.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNDSCViewGetAllImages(
		cache: ctypes.POINTER(BNSharedCache), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNDSCImage)]:
	result = _BNDSCViewGetAllImages(cache, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNDSCViewGetBackingCaches

_BNDSCViewGetBackingCaches = core.BNDSCViewGetBackingCaches
_BNDSCViewGetBackingCaches.restype = ctypes.POINTER(BNDSCBackingCache)
_BNDSCViewGetBackingCaches.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNDSCViewGetBackingCaches(
		cache: ctypes.POINTER(BNSharedCache), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNDSCBackingCache)]:
	result = _BNDSCViewGetBackingCaches(cache, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNDSCViewGetImageHeaderForAddress

_BNDSCViewGetImageHeaderForAddress = core.BNDSCViewGetImageHeaderForAddress
_BNDSCViewGetImageHeaderForAddress.restype = ctypes.POINTER(ctypes.c_byte)
_BNDSCViewGetImageHeaderForAddress.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNDSCViewGetImageHeaderForAddress(
		cache: ctypes.POINTER(BNSharedCache), 
		address: int
		) -> Optional[Optional[str]]:
	result = _BNDSCViewGetImageHeaderForAddress(cache, address)
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNDSCViewGetImageHeaderForName

_BNDSCViewGetImageHeaderForName = core.BNDSCViewGetImageHeaderForName
_BNDSCViewGetImageHeaderForName.restype = ctypes.POINTER(ctypes.c_byte)
_BNDSCViewGetImageHeaderForName.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.c_char_p,
	]


# noinspection PyPep8Naming
def BNDSCViewGetImageHeaderForName(
		cache: ctypes.POINTER(BNSharedCache), 
		name: Optional[str]
		) -> Optional[Optional[str]]:
	result = _BNDSCViewGetImageHeaderForName(cache, cstr(name))
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNDSCViewGetImageNameForAddress

_BNDSCViewGetImageNameForAddress = core.BNDSCViewGetImageNameForAddress
_BNDSCViewGetImageNameForAddress.restype = ctypes.POINTER(ctypes.c_byte)
_BNDSCViewGetImageNameForAddress.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNDSCViewGetImageNameForAddress(
		cache: ctypes.POINTER(BNSharedCache), 
		address: int
		) -> Optional[Optional[str]]:
	result = _BNDSCViewGetImageNameForAddress(cache, address)
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNDSCViewGetInstallNames

_BNDSCViewGetInstallNames = core.BNDSCViewGetInstallNames
_BNDSCViewGetInstallNames.restype = ctypes.POINTER(ctypes.c_char_p)
_BNDSCViewGetInstallNames.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNDSCViewGetInstallNames(
		cache: ctypes.POINTER(BNSharedCache), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(ctypes.c_char_p)]:
	result = _BNDSCViewGetInstallNames(cache, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNDSCViewGetLoadProgress

_BNDSCViewGetLoadProgress = core.BNDSCViewGetLoadProgress
_BNDSCViewGetLoadProgress.restype = DSCViewLoadProgressEnum
_BNDSCViewGetLoadProgress.argtypes = [
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNDSCViewGetLoadProgress(
		sessionID: int
		) -> DSCViewLoadProgressEnum:
	return _BNDSCViewGetLoadProgress(sessionID)


# -------------------------------------------------------
# _BNDSCViewGetLoadedRegions

_BNDSCViewGetLoadedRegions = core.BNDSCViewGetLoadedRegions
_BNDSCViewGetLoadedRegions.restype = ctypes.POINTER(BNDSCMappedMemoryRegion)
_BNDSCViewGetLoadedRegions.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNDSCViewGetLoadedRegions(
		cache: ctypes.POINTER(BNSharedCache), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNDSCMappedMemoryRegion)]:
	result = _BNDSCViewGetLoadedRegions(cache, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNDSCViewGetMemoryUsageInfo

_BNDSCViewGetMemoryUsageInfo = core.BNDSCViewGetMemoryUsageInfo
_BNDSCViewGetMemoryUsageInfo.restype = BNDSCMemoryUsageInfo
_BNDSCViewGetMemoryUsageInfo.argtypes = [
	]


# noinspection PyPep8Naming
def BNDSCViewGetMemoryUsageInfo(
		) -> BNDSCMemoryUsageInfo:
	return _BNDSCViewGetMemoryUsageInfo()


# -------------------------------------------------------
# _BNDSCViewGetNameForAddress

_BNDSCViewGetNameForAddress = core.BNDSCViewGetNameForAddress
_BNDSCViewGetNameForAddress.restype = ctypes.POINTER(ctypes.c_byte)
_BNDSCViewGetNameForAddress.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNDSCViewGetNameForAddress(
		cache: ctypes.POINTER(BNSharedCache), 
		address: int
		) -> Optional[Optional[str]]:
	result = _BNDSCViewGetNameForAddress(cache, address)
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNDSCViewGetState

_BNDSCViewGetState = core.BNDSCViewGetState
_BNDSCViewGetState.restype = DSCViewStateEnum
_BNDSCViewGetState.argtypes = [
		ctypes.POINTER(BNSharedCache),
	]


# noinspection PyPep8Naming
def BNDSCViewGetState(
		cache: ctypes.POINTER(BNSharedCache)
		) -> DSCViewStateEnum:
	return _BNDSCViewGetState(cache)


# -------------------------------------------------------
# _BNDSCViewLoadAllSymbolsAndWait

_BNDSCViewLoadAllSymbolsAndWait = core.BNDSCViewLoadAllSymbolsAndWait
_BNDSCViewLoadAllSymbolsAndWait.restype = ctypes.POINTER(BNDSCSymbolRep)
_BNDSCViewLoadAllSymbolsAndWait.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNDSCViewLoadAllSymbolsAndWait(
		cache: ctypes.POINTER(BNSharedCache), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNDSCSymbolRep)]:
	result = _BNDSCViewLoadAllSymbolsAndWait(cache, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNDSCViewLoadImageContainingAddress

_BNDSCViewLoadImageContainingAddress = core.BNDSCViewLoadImageContainingAddress
_BNDSCViewLoadImageContainingAddress.restype = ctypes.c_bool
_BNDSCViewLoadImageContainingAddress.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNDSCViewLoadImageContainingAddress(
		cache: ctypes.POINTER(BNSharedCache), 
		address: int
		) -> bool:
	return _BNDSCViewLoadImageContainingAddress(cache, address)


# -------------------------------------------------------
# _BNDSCViewLoadImageWithInstallName

_BNDSCViewLoadImageWithInstallName = core.BNDSCViewLoadImageWithInstallName
_BNDSCViewLoadImageWithInstallName.restype = ctypes.c_bool
_BNDSCViewLoadImageWithInstallName.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.c_char_p,
	]


# noinspection PyPep8Naming
def BNDSCViewLoadImageWithInstallName(
		cache: ctypes.POINTER(BNSharedCache), 
		name: Optional[str]
		) -> bool:
	return _BNDSCViewLoadImageWithInstallName(cache, cstr(name))


# -------------------------------------------------------
# _BNDSCViewLoadSectionAtAddress

_BNDSCViewLoadSectionAtAddress = core.BNDSCViewLoadSectionAtAddress
_BNDSCViewLoadSectionAtAddress.restype = ctypes.c_bool
_BNDSCViewLoadSectionAtAddress.argtypes = [
		ctypes.POINTER(BNSharedCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNDSCViewLoadSectionAtAddress(
		cache: ctypes.POINTER(BNSharedCache), 
		name: int
		) -> bool:
	return _BNDSCViewLoadSectionAtAddress(cache, name)


# -------------------------------------------------------
# _BNFreeSharedCacheReference

_BNFreeSharedCacheReference = core.BNFreeSharedCacheReference
_BNFreeSharedCacheReference.restype = None
_BNFreeSharedCacheReference.argtypes = [
		ctypes.POINTER(BNSharedCache),
	]


# noinspection PyPep8Naming
def BNFreeSharedCacheReference(
		cache: ctypes.POINTER(BNSharedCache)
		) -> None:
	return _BNFreeSharedCacheReference(cache)


# -------------------------------------------------------
# _BNGetSharedCache

_BNGetSharedCache = core.BNGetSharedCache
_BNGetSharedCache.restype = ctypes.POINTER(BNSharedCache)
_BNGetSharedCache.argtypes = [
		ctypes.POINTER(BNBinaryView),
	]


# noinspection PyPep8Naming
def BNGetSharedCache(
		data: ctypes.POINTER(BNBinaryView)
		) -> Optional[ctypes.POINTER(BNSharedCache)]:
	result = _BNGetSharedCache(data)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNNewSharedCacheReference

_BNNewSharedCacheReference = core.BNNewSharedCacheReference
_BNNewSharedCacheReference.restype = ctypes.POINTER(BNSharedCache)
_BNNewSharedCacheReference.argtypes = [
		ctypes.POINTER(BNSharedCache),
	]


# noinspection PyPep8Naming
def BNNewSharedCacheReference(
		cache: ctypes.POINTER(BNSharedCache)
		) -> Optional[ctypes.POINTER(BNSharedCache)]:
	result = _BNNewSharedCacheReference(cache)
	if not result:
		return None
	return result



# Helper functions
def handle_of_type(value, handle_type):
	if isinstance(value, ctypes.POINTER(handle_type)) or isinstance(value, ctypes.c_void_p):
		return ctypes.cast(value, ctypes.POINTER(handle_type))
	raise ValueError('expected pointer to %s' % str(handle_type))
