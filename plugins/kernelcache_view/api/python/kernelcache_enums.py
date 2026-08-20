import enum


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


class SegmentFlag(enum.IntEnum):
	SegmentExecutable = 1
	SegmentWritable = 2
	SegmentReadable = 4
	SegmentContainsData = 8
	SegmentContainsCode = 16
	SegmentDenyWrite = 32
	SegmentDenyExecute = 64


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
