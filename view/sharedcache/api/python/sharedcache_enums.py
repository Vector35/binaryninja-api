import enum


class BackingCacheType(enum.IntEnum):
	BackingCacheTypePrimary = 0
	BackingCacheTypeSecondary = 1
	BackingCacheTypeSymbols = 2


class DSCViewLoadProgress(enum.IntEnum):
	LoadProgressNotStarted = 0
	LoadProgressLoadingCaches = 1
	LoadProgressLoadingImages = 2
	LoadProgressFinished = 3


class DSCViewState(enum.IntEnum):
	Unloaded = 0
	Loaded = 1
	LoadedWithImages = 2
