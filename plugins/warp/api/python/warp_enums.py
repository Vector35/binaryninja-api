import enum


class WARPContainerSearchItemKind(enum.IntEnum):
	WARPContainerSearchItemKindSource = 0
	WARPContainerSearchItemKindFunction = 1
	WARPContainerSearchItemKindType = 2
	WARPContainerSearchItemKindSymbol = 3


class WARPProcessorIncludedData(enum.IntEnum):
	WARPProcessorIncludedDataSymbols = 0
	WARPProcessorIncludedDataSignatures = 1
	WARPProcessorIncludedDataTypes = 2
	WARPProcessorIncludedDataAll = 3


class WARPProcessorIncludedFunctions(enum.IntEnum):
	WARPProcessorIncludedFunctionsSelected = 0
	WARPProcessorIncludedFunctionsAnnotated = 1
	WARPProcessorIncludedFunctionsAll = 2
