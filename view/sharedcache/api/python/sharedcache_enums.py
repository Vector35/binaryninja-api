import enum


class SegmentFlag(enum.IntEnum):
	SegmentExecutable = 1
	SegmentWritable = 2
	SegmentReadable = 4
	SegmentContainsData = 8
	SegmentContainsCode = 16
	SegmentDenyWrite = 32
	SegmentDenyExecute = 64


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


class SymbolType(enum.IntEnum):
	FunctionSymbol = 0
	ImportAddressSymbol = 1
	ImportedFunctionSymbol = 2
	DataSymbol = 3
	ImportedDataSymbol = 4
	ExternalSymbol = 5
	LibraryFunctionSymbol = 6
	SymbolicFunctionSymbol = 7
	LocalLabelSymbol = 8
