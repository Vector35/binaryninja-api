import enum
from binaryninja.enums import SegmentFlag
from binaryninja.enums import StringType
from binaryninja.enums import SymbolBinding
from binaryninja.enums import SymbolType


class SharedCacheEntryType(enum.IntEnum):
	SharedCacheEntryTypePrimary = 0
	SharedCacheEntryTypeSecondary = 1
	SharedCacheEntryTypeSymbols = 2
	SharedCacheEntryTypeDyldData = 3
	SharedCacheEntryTypeStub = 4


class SharedCacheRegionType(enum.IntEnum):
	SharedCacheRegionTypeImage = 0
	SharedCacheRegionTypeStubIsland = 1
	SharedCacheRegionTypeDyldData = 2
	SharedCacheRegionTypeNonImage = 3
