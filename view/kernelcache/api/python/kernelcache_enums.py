import enum
from binaryninja.enums import SegmentFlag
from binaryninja.enums import SymbolType


class KernelCacheEntryType(enum.IntEnum):
	KernelCacheEntryTypePrimary = 0
	KernelCacheEntryTypeSecondary = 1
	KernelCacheEntryTypeSymbols = 2
	KernelCacheEntryTypeDyldData = 3
	KernelCacheEntryTypeStub = 4


class KernelCacheRegionType(enum.IntEnum):
	KernelCacheRegionTypeImage = 0
	KernelCacheRegionTypeStubIsland = 1
	KernelCacheRegionTypeDyldData = 2
	KernelCacheRegionTypeNonImage = 3
