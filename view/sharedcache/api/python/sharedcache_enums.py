import enum


class DSCViewLoadProgress(enum.IntEnum):
	LoadProgressNotStarted = 0
	LoadProgressLoadingCaches = 1
	LoadProgressLoadingImages = 2
	LoadProgressFinished = 3


class DSCViewState(enum.IntEnum):
	Unloaded = 0
	Loaded = 1
	LoadedWithImages = 2
