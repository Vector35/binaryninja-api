import ctypes
import dataclasses
from typing import Optional

import binaryninja
from binaryninja import BinaryView
from binaryninja._binaryninjacore import BNFreeStringList, BNAllocString, BNFreeString

from . import _sharedcachecore as sccore
from .sharedcache_enums import *

@dataclasses.dataclass
class CacheRegion:
    region_type: SharedCacheRegionType
    name: str
    start: int
    size: int
    image_start: int
    # TODO: Might want to make this use the BN segment flag enum?
    flags: sccore.SegmentFlagEnum

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"<CacheRegion '{self.name}': 0x{self.start:x} + {self.size:x}>"

@dataclasses.dataclass
class CacheImage:
    name: str
    header_address: int
    region_starts: [int]

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"<CacheImage '{self.name}': 0x{self.header_address:x}>"

@dataclasses.dataclass
class CacheSymbol:
    symbol_type: sccore.SymbolTypeEnum
    address: int
    name: str

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"<CacheSymbol '{self.name}': 0x{self.address:x}>"

def region_from_api(region: sccore.BNSharedCacheRegion) -> CacheRegion:
    return CacheRegion(
        region_type=SharedCacheRegionType(region.regionType),
        name=region.name,
        start=region.vmAddress,
        size=region.size,
        image_start=region.imageStart,
        flags=region.flags
    )

def region_to_api(region: CacheRegion) -> sccore.BNSharedCacheRegion:
    return sccore.BNSharedCacheRegion(
        regionType=region.region_type,
        _name=BNAllocString(region.name),
        vmAddress=region.start,
        size=region.size,
        imageStart=region.image_start,
        flags=region.flags
    )

def image_from_api(image: sccore.BNSharedCacheImage) -> CacheImage:
    region_starts = []
    for i in range(image.regionStartCount):
        region_starts.append(image.regionStarts[i])
    return CacheImage(
        name=image.name,
        header_address=image.headerAddress,
        region_starts=region_starts
    )

def image_to_api(image: CacheImage) -> sccore.BNSharedCacheImage:
    region_start_array = (ctypes.c_ulonglong * len(image.region_starts))()
    for i, region_start in enumerate(image.region_starts):
        region_start_array[i] = region_start
    core_region_starts = sccore.BNSharedCacheAllocRegionList(region_start_array, len(region_start_array))
    return sccore.BNSharedCacheImage(
        _name=BNAllocString(image.name),
        headerAddress=image.header_address,
        regionStartCount=len(region_start_array),
        regionStarts=core_region_starts
    )

def symbol_from_api(symbol: sccore.BNSharedCacheSymbol) -> CacheSymbol:
    return CacheSymbol(
        symbol_type=symbol.symbolType,
        address=symbol.address,
        name=symbol.name
    )

def symbol_to_api(symbol: CacheSymbol) -> sccore.BNSharedCacheSymbol:
    return sccore.BNSharedCacheSymbol(
        symbolType=symbol.symbol_type,
        address=symbol.address,
        _name=BNAllocString(symbol.name)
    )

class SharedCacheController:
    def __init__(self, view: BinaryView):
        """
        Retrieve the shared cache controller for a given view.
        Call `is_valid` to check if the controller is valid.
        """
        self.handle = sccore.BNGetSharedCacheController(view.handle)

    def __del__(self):
        if self.handle is not None:
            sccore.BNFreeSharedCacheControllerReference(self.handle)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"<SharedCacheController: {len(self.images)} images, {len(self.regions)} regions>"

    def is_valid(self) -> bool:
        return self.handle is not None

    def apply_region(self, view: BinaryView, region: CacheRegion) -> bool:
        api_region: sccore.BNSharedCacheRegion = region_to_api(region)
        result = sccore.BNSharedCacheControllerApplyRegion(self.handle, view.handle, api_region)
        sccore.BNSharedCacheFreeRegion(api_region)
        return result

    def apply_image(self, view: BinaryView, image: CacheImage) -> bool:
        api_image: sccore.BNSharedCacheImage = image_to_api(image)
        result = sccore.BNSharedCacheControllerApplyImage(self.handle, view.handle, api_image)
        sccore.BNSharedCacheFreeImage(api_image)
        return result

    def is_region_loaded(self, region: CacheRegion) -> bool:
        api_region: sccore.BNSharedCacheRegion = region_to_api(region)
        result = sccore.BNSharedCacheControllerIsRegionLoaded(self.handle, api_region)
        sccore.BNSharedCacheFreeRegion(api_region)
        return result

    def is_image_loaded(self, image: CacheImage) -> bool:
        api_image: sccore.BNSharedCacheImage = image_to_api(image)
        result = sccore.BNSharedCacheControllerIsImageLoaded(self.handle, api_image)
        sccore.BNSharedCacheFreeImage(api_image)
        return result

    def get_region_at(self, address: int) -> Optional[CacheRegion]:
        api_region = sccore.BNSharedCacheRegion()
        if not sccore.BNSharedCacheControllerGetRegionAt(self.handle, address, api_region):
            return None
        region = region_from_api(api_region)
        sccore.BNSharedCacheFreeRegion(api_region)
        return region

    def get_region_containing(self, address: int) -> Optional[CacheRegion]:
        api_region = sccore.BNSharedCacheRegion()
        if not sccore.BNSharedCacheControllerGetRegionContaining(self.handle, address, api_region):
            return None
        region = region_from_api(api_region)
        sccore.BNSharedCacheFreeRegion(api_region)
        return region

    def get_image_at(self, address: int) -> Optional[CacheImage]:
        api_image = sccore.BNSharedCacheImage()
        if not sccore.BNSharedCacheControllerGetImageAt(self.handle, address, api_image):
            return None
        image = image_from_api(api_image)
        sccore.BNSharedCacheFreeImage(api_image)
        return image

    def get_image_containing(self, address: int) -> Optional[CacheImage]:
        api_image = sccore.BNSharedCacheImage()
        if not sccore.BNSharedCacheControllerGetImageContaining(self.handle, address, api_image):
            return None
        image = image_from_api(api_image)
        sccore.BNSharedCacheFreeImage(api_image)
        return image

    def get_image_with_name(self, name: str) -> Optional[CacheImage]:
        api_image = sccore.BNSharedCacheImage()
        if not sccore.BNSharedCacheControllerGetImageWithName(self.handle, name, api_image):
            return None
        image = image_from_api(api_image)
        sccore.BNSharedCacheFreeImage(api_image)
        return image

    def get_image_dependencies(self, image: CacheImage) -> [str]:
        """
        Returns a list of image names that this image depends on.
        """
        count = ctypes.c_ulonglong()
        api_image: sccore.BNSharedCacheImage = image_to_api(image)
        value = sccore.BNSharedCacheControllerGetImageDependencies(self.handle, api_image, count)
        sccore.BNSharedCacheFreeImage(api_image)
        if value is None:
            return []
        result = []
        for i in range(count.value):
            result.append(value[i].decode("utf-8"))
        BNFreeStringList(value, count)
        return result

    def get_symbol_at(self, address: int) -> Optional[CacheSymbol]:
        api_symbol = sccore.BNSharedCacheSymbol()
        if not sccore.BNSharedCacheControllerGetSymbolAt(self.handle, address, api_symbol):
            return None
        symbol = symbol_from_api(api_symbol)
        sccore.BNSharedCacheFreeSymbol(api_symbol)
        return symbol

    def get_symbol_with_name(self, name: str) -> Optional[CacheSymbol]:
        api_symbol = sccore.BNSharedCacheSymbol()
        if not sccore.BNSharedCacheControllerGetSymbolWithName(self.handle, name, api_symbol):
            return None
        symbol = symbol_from_api(api_symbol)
        sccore.BNSharedCacheFreeSymbol(api_symbol)
        return symbol

    @property
    def regions(self) -> [CacheRegion]:
        count = ctypes.c_ulonglong()
        value = sccore.BNSharedCacheControllerGetRegions(self.handle, count)
        if value is None:
            return []
        result = []
        for i in range(count.value):
            result.append(region_from_api(value[i]))
        sccore.BNSharedCacheFreeRegionList(value, count)
        return result

    @property
    def loaded_regions(self) -> [CacheRegion]:
        """
        Get a list of regions that are currently loaded in the view.
        """
        count = ctypes.c_ulonglong()
        value = sccore.BNSharedCacheControllerGetLoadedRegions(self.handle, count)
        if value is None:
            return []
        result = []
        for i in range(count.value):
            result.append(region_from_api(value[i]))
        sccore.BNSharedCacheFreeRegionList(value, count)
        return result

    @property
    def images(self) -> [CacheImage]:
        count = ctypes.c_ulonglong()
        value = sccore.BNSharedCacheControllerGetImages(self.handle, count)
        if value is None:
            return []
        result = []
        for i in range(count.value):
            result.append(image_from_api(value[i]))
        sccore.BNSharedCacheFreeImageList(value, count)
        return result

    @property
    def loaded_images(self) -> [CacheImage]:
        """
        Get a list of images that are currently loaded in the view.
        """
        count = ctypes.c_ulonglong()
        value = sccore.BNSharedCacheControllerGetLoadedImages(self.handle, count)
        if value is None:
            return []
        result = []
        for i in range(count.value):
            result.append(image_from_api(value[i]))
        sccore.BNSharedCacheFreeImageList(value, count)
        return result

    @property
    def symbols(self) -> [CacheSymbol]:
        count = ctypes.c_ulonglong()
        value = sccore.BNSharedCacheControllerGetSymbols(self.handle, count)
        if value is None:
            return []
        result = []
        for i in range(count.value):
            result.append(symbol_from_api(value[i]))
        sccore.BNSharedCacheFreeSymbolList(value, count)
        return result


def _get_shared_cache(instance: binaryninja.PythonScriptingInstance):
    if instance.interpreter.active_view is None:
        return None
    controller = SharedCacheController(instance.interpreter.active_view)
    if not controller.is_valid():
        return None
    return controller


binaryninja.PythonScriptingProvider.register_magic_variable(
	"dsc",
    _get_shared_cache
)

binaryninja.PythonScriptingProvider.register_magic_variable(
    "shared_cache",
    _get_shared_cache
)
