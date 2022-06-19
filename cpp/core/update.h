#pragma once

#include "core/binaryninja_defs.h"

extern "C" {
	enum BNUpdateResult
	{
		UpdateFailed = 0,
		UpdateSuccess = 1,
		AlreadyUpToDate = 2,
		UpdateAvailable = 3
	};

	struct BNUpdateChannel
	{
		char* name;
		char* description;
		char* latestVersion;
	};

	struct BNUpdateVersion
	{
		char* version;
		char* notes;
		uint64_t time;
	};

	// Updates
	BINARYNINJACOREAPI BNUpdateChannel* BNGetUpdateChannels(size_t* count, char** errors);
	BINARYNINJACOREAPI void BNFreeUpdateChannelList(BNUpdateChannel* list, size_t count);
	BINARYNINJACOREAPI BNUpdateVersion* BNGetUpdateChannelVersions(const char* channel, size_t* count, char** errors);
	BINARYNINJACOREAPI void BNFreeUpdateChannelVersionList(BNUpdateVersion* list, size_t count);

	BINARYNINJACOREAPI bool BNAreUpdatesAvailable(
	    const char* channel, uint64_t* expireTime, uint64_t* serverTime, char** errors);

	BINARYNINJACOREAPI BNUpdateResult BNUpdateToVersion(const char* channel, const char* version, char** errors,
	    bool (*progress)(void* ctxt, uint64_t progress, uint64_t total), void* context);
	BINARYNINJACOREAPI BNUpdateResult BNUpdateToLatestVersion(const char* channel, char** errors,
	    bool (*progress)(void* ctxt, uint64_t progress, uint64_t total), void* context);

	BINARYNINJACOREAPI bool BNAreAutoUpdatesEnabled(void);
	BINARYNINJACOREAPI void BNSetAutoUpdatesEnabled(bool enabled);
	BINARYNINJACOREAPI uint64_t BNGetTimeSinceLastUpdateCheck(void);
	BINARYNINJACOREAPI void BNUpdatesChecked(void);

	BINARYNINJACOREAPI char* BNGetActiveUpdateChannel(void);
	BINARYNINJACOREAPI void BNSetActiveUpdateChannel(const char* channel);

	BINARYNINJACOREAPI bool BNIsUpdateInstallationPending(void);
	BINARYNINJACOREAPI void BNInstallPendingUpdate(char** errors);
}