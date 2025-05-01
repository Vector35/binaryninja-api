import enum


class KCViewLoadProgress(enum.IntEnum):
	LoadProgressNotStarted = 0
	LoadProgressLoadingCaches = 1
	LoadProgressLoadingImages = 2
	LoadProgressFinished = 3


class KCViewState(enum.IntEnum):
	Unloaded = 0
	Loaded = 1
	LoadedWithImages = 2
