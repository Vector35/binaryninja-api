import binaryninja
import ctypes, os

from typing import Optional
from . import kernelcache_enums
# Load core module
import platform
core = None
core_platform = platform.system()

from binaryninja import Settings
if Settings().get_bool("corePlugins.view.kernelCache"):
    from binaryninja._binaryninjacore import BNGetBundledPluginDirectory
    if core_platform == "Darwin":
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libkernelcache.dylib"))

    elif core_platform == "Linux":
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libkernelcache.so"))

    elif (core_platform == "Windows") or (core_platform.find("CYGWIN_NT") == 0):
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "kernelcache.dll"))
    else:
        raise Exception("OS not supported")
else:
    from binaryninja._binaryninjacore import BNGetUserPluginDirectory
    if core_platform == "Darwin":
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libkernelcache.dylib"))

    elif core_platform == "Linux":
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libkernelcache.so"))

    elif (core_platform == "Windows") or (core_platform.find("CYGWIN_NT") == 0):
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "kernelcache.dll"))
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
class BNKCImage(ctypes.Structure):
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
BNKCImageHandle = ctypes.POINTER(BNKCImage)
class BNKCImageMemoryMapping(ctypes.Structure):
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
BNKCImageMemoryMappingHandle = ctypes.POINTER(BNKCImageMemoryMapping)
class BNKCMappedMemoryRegion(ctypes.Structure):
	@property
	def name(self):
		return pyNativeStr(self._name)
	@name.setter
	def name(self, value):
		self._name = cstr(value)
BNKCMappedMemoryRegionHandle = ctypes.POINTER(BNKCMappedMemoryRegion)
class BNKCMemoryUsageInfo(ctypes.Structure):
	pass
BNKCMemoryUsageInfoHandle = ctypes.POINTER(BNKCMemoryUsageInfo)
class BNKCSymbolRep(ctypes.Structure):
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
BNKCSymbolRepHandle = ctypes.POINTER(BNKCSymbolRep)
KCViewLoadProgressEnum = ctypes.c_int
KCViewStateEnum = ctypes.c_int
class BNKernelCache(ctypes.Structure):
	pass
BNKernelCacheHandle = ctypes.POINTER(BNKernelCache)

# Structure definitions
BNKCImage._fields_ = [
		("_name", ctypes.c_char_p),
		("headerFileAddress", ctypes.c_ulonglong),
		("mappings", ctypes.POINTER(BNKCImageMemoryMapping)),
		("mappingCount", ctypes.c_ulonglong),
	]
BNKCImageMemoryMapping._fields_ = [
		("_name", ctypes.c_char_p),
		("vmAddress", ctypes.c_ulonglong),
		("size", ctypes.c_ulonglong),
		("loaded", ctypes.c_bool),
		("rawViewOffset", ctypes.c_ulonglong),
	]
BNKCMappedMemoryRegion._fields_ = [
		("vmAddress", ctypes.c_ulonglong),
		("size", ctypes.c_ulonglong),
		("_name", ctypes.c_char_p),
	]
BNKCMemoryUsageInfo._fields_ = [
		("sharedCacheRefs", ctypes.c_ulonglong),
		("mmapRefs", ctypes.c_ulonglong),
	]
BNKCSymbolRep._fields_ = [
		("address", ctypes.c_ulonglong),
		("_name", ctypes.c_char_p),
		("_image", ctypes.c_char_p),
	]

# Function definitions
# -------------------------------------------------------
# _BNFreeKernelCacheReference

_BNFreeKernelCacheReference = core.BNFreeKernelCacheReference
_BNFreeKernelCacheReference.restype = None
_BNFreeKernelCacheReference.argtypes = [
		ctypes.POINTER(BNKernelCache),
	]


# noinspection PyPep8Naming
def BNFreeKernelCacheReference(
		cache: ctypes.POINTER(BNKernelCache)
		) -> None:
	return _BNFreeKernelCacheReference(cache)


# -------------------------------------------------------
# _BNGetKernelCache

_BNGetKernelCache = core.BNGetKernelCache
_BNGetKernelCache.restype = ctypes.POINTER(BNKernelCache)
_BNGetKernelCache.argtypes = [
		ctypes.POINTER(BNBinaryView),
	]


# noinspection PyPep8Naming
def BNGetKernelCache(
		data: ctypes.POINTER(BNBinaryView)
		) -> Optional[ctypes.POINTER(BNKernelCache)]:
	result = _BNGetKernelCache(data)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNKCViewFastGetImageCount

_BNKCViewFastGetImageCount = core.BNKCViewFastGetImageCount
_BNKCViewFastGetImageCount.restype = ctypes.c_ulonglong
_BNKCViewFastGetImageCount.argtypes = [
		ctypes.POINTER(BNBinaryView),
	]


# noinspection PyPep8Naming
def BNKCViewFastGetImageCount(
		view: ctypes.POINTER(BNBinaryView)
		) -> int:
	return _BNKCViewFastGetImageCount(view)


# -------------------------------------------------------
# _BNKCViewFreeAllImages

_BNKCViewFreeAllImages = core.BNKCViewFreeAllImages
_BNKCViewFreeAllImages.restype = None
_BNKCViewFreeAllImages.argtypes = [
		ctypes.POINTER(BNKCImage),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNKCViewFreeAllImages(
		images: ctypes.POINTER(BNKCImage), 
		count: int
		) -> None:
	return _BNKCViewFreeAllImages(images, count)


# -------------------------------------------------------
# _BNKCViewFreeLoadedImages

_BNKCViewFreeLoadedImages = core.BNKCViewFreeLoadedImages
_BNKCViewFreeLoadedImages.restype = None
_BNKCViewFreeLoadedImages.argtypes = [
		ctypes.POINTER(BNKCImage),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNKCViewFreeLoadedImages(
		images: ctypes.POINTER(BNKCImage), 
		count: int
		) -> None:
	return _BNKCViewFreeLoadedImages(images, count)


# -------------------------------------------------------
# _BNKCViewFreeSymbols

_BNKCViewFreeSymbols = core.BNKCViewFreeSymbols
_BNKCViewFreeSymbols.restype = None
_BNKCViewFreeSymbols.argtypes = [
		ctypes.POINTER(BNKCSymbolRep),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNKCViewFreeSymbols(
		symbols: ctypes.POINTER(BNKCSymbolRep), 
		count: int
		) -> None:
	return _BNKCViewFreeSymbols(symbols, count)


# -------------------------------------------------------
# _BNKCViewGetAllImages

_BNKCViewGetAllImages = core.BNKCViewGetAllImages
_BNKCViewGetAllImages.restype = ctypes.POINTER(BNKCImage)
_BNKCViewGetAllImages.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNKCViewGetAllImages(
		cache: ctypes.POINTER(BNKernelCache), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNKCImage)]:
	result = _BNKCViewGetAllImages(cache, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNKCViewGetImageHeaderForAddress

_BNKCViewGetImageHeaderForAddress = core.BNKCViewGetImageHeaderForAddress
_BNKCViewGetImageHeaderForAddress.restype = ctypes.POINTER(ctypes.c_byte)
_BNKCViewGetImageHeaderForAddress.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNKCViewGetImageHeaderForAddress(
		cache: ctypes.POINTER(BNKernelCache), 
		address: int
		) -> Optional[Optional[str]]:
	result = _BNKCViewGetImageHeaderForAddress(cache, address)
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNKCViewGetImageHeaderForName

_BNKCViewGetImageHeaderForName = core.BNKCViewGetImageHeaderForName
_BNKCViewGetImageHeaderForName.restype = ctypes.POINTER(ctypes.c_byte)
_BNKCViewGetImageHeaderForName.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.c_char_p,
	]


# noinspection PyPep8Naming
def BNKCViewGetImageHeaderForName(
		cache: ctypes.POINTER(BNKernelCache), 
		name: Optional[str]
		) -> Optional[Optional[str]]:
	result = _BNKCViewGetImageHeaderForName(cache, cstr(name))
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNKCViewGetImageNameForAddress

_BNKCViewGetImageNameForAddress = core.BNKCViewGetImageNameForAddress
_BNKCViewGetImageNameForAddress.restype = ctypes.POINTER(ctypes.c_byte)
_BNKCViewGetImageNameForAddress.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNKCViewGetImageNameForAddress(
		cache: ctypes.POINTER(BNKernelCache), 
		address: int
		) -> Optional[Optional[str]]:
	result = _BNKCViewGetImageNameForAddress(cache, address)
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNKCViewGetInstallNames

_BNKCViewGetInstallNames = core.BNKCViewGetInstallNames
_BNKCViewGetInstallNames.restype = ctypes.POINTER(ctypes.c_char_p)
_BNKCViewGetInstallNames.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNKCViewGetInstallNames(
		cache: ctypes.POINTER(BNKernelCache), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(ctypes.c_char_p)]:
	result = _BNKCViewGetInstallNames(cache, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNKCViewGetLoadProgress

_BNKCViewGetLoadProgress = core.BNKCViewGetLoadProgress
_BNKCViewGetLoadProgress.restype = KCViewLoadProgressEnum
_BNKCViewGetLoadProgress.argtypes = [
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNKCViewGetLoadProgress(
		sessionID: int
		) -> KCViewLoadProgressEnum:
	return _BNKCViewGetLoadProgress(sessionID)


# -------------------------------------------------------
# _BNKCViewGetLoadedImages

_BNKCViewGetLoadedImages = core.BNKCViewGetLoadedImages
_BNKCViewGetLoadedImages.restype = ctypes.POINTER(BNKCImage)
_BNKCViewGetLoadedImages.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNKCViewGetLoadedImages(
		cache: ctypes.POINTER(BNKernelCache), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNKCImage)]:
	result = _BNKCViewGetLoadedImages(cache, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNKCViewGetNameForAddress

_BNKCViewGetNameForAddress = core.BNKCViewGetNameForAddress
_BNKCViewGetNameForAddress.restype = ctypes.POINTER(ctypes.c_byte)
_BNKCViewGetNameForAddress.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNKCViewGetNameForAddress(
		cache: ctypes.POINTER(BNKernelCache), 
		address: int
		) -> Optional[Optional[str]]:
	result = _BNKCViewGetNameForAddress(cache, address)
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNKCViewGetState

_BNKCViewGetState = core.BNKCViewGetState
_BNKCViewGetState.restype = KCViewStateEnum
_BNKCViewGetState.argtypes = [
		ctypes.POINTER(BNKernelCache),
	]


# noinspection PyPep8Naming
def BNKCViewGetState(
		cache: ctypes.POINTER(BNKernelCache)
		) -> KCViewStateEnum:
	return _BNKCViewGetState(cache)


# -------------------------------------------------------
# _BNKCViewIsImageLoaded

_BNKCViewIsImageLoaded = core.BNKCViewIsImageLoaded
_BNKCViewIsImageLoaded.restype = ctypes.c_bool
_BNKCViewIsImageLoaded.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNKCViewIsImageLoaded(
		cache: ctypes.POINTER(BNKernelCache), 
		address: int
		) -> bool:
	return _BNKCViewIsImageLoaded(cache, address)


# -------------------------------------------------------
# _BNKCViewLoadAllSymbolsAndWait

_BNKCViewLoadAllSymbolsAndWait = core.BNKCViewLoadAllSymbolsAndWait
_BNKCViewLoadAllSymbolsAndWait.restype = ctypes.POINTER(BNKCSymbolRep)
_BNKCViewLoadAllSymbolsAndWait.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNKCViewLoadAllSymbolsAndWait(
		cache: ctypes.POINTER(BNKernelCache), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNKCSymbolRep)]:
	result = _BNKCViewLoadAllSymbolsAndWait(cache, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNKCViewLoadImageContainingAddress

_BNKCViewLoadImageContainingAddress = core.BNKCViewLoadImageContainingAddress
_BNKCViewLoadImageContainingAddress.restype = ctypes.c_bool
_BNKCViewLoadImageContainingAddress.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNKCViewLoadImageContainingAddress(
		cache: ctypes.POINTER(BNKernelCache), 
		address: int
		) -> bool:
	return _BNKCViewLoadImageContainingAddress(cache, address)


# -------------------------------------------------------
# _BNKCViewLoadImageWithInstallName

_BNKCViewLoadImageWithInstallName = core.BNKCViewLoadImageWithInstallName
_BNKCViewLoadImageWithInstallName.restype = ctypes.c_bool
_BNKCViewLoadImageWithInstallName.argtypes = [
		ctypes.POINTER(BNKernelCache),
		ctypes.c_char_p,
	]


# noinspection PyPep8Naming
def BNKCViewLoadImageWithInstallName(
		cache: ctypes.POINTER(BNKernelCache), 
		name: Optional[str]
		) -> bool:
	return _BNKCViewLoadImageWithInstallName(cache, cstr(name))


# -------------------------------------------------------
# _BNNewKernelCacheReference

_BNNewKernelCacheReference = core.BNNewKernelCacheReference
_BNNewKernelCacheReference.restype = ctypes.POINTER(BNKernelCache)
_BNNewKernelCacheReference.argtypes = [
		ctypes.POINTER(BNKernelCache),
	]


# noinspection PyPep8Naming
def BNNewKernelCacheReference(
		cache: ctypes.POINTER(BNKernelCache)
		) -> Optional[ctypes.POINTER(BNKernelCache)]:
	result = _BNNewKernelCacheReference(cache)
	if not result:
		return None
	return result



# Helper functions
def handle_of_type(value, handle_type):
	if isinstance(value, ctypes.POINTER(handle_type)) or isinstance(value, ctypes.c_void_p):
		return ctypes.cast(value, ctypes.POINTER(handle_type))
	raise ValueError('expected pointer to %s' % str(handle_type))
