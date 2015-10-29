#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


namespace BinaryNinja
{
	struct UpdateProgress
	{
		function<void(uint64_t progress, uint64_t total)> func;

		static void UpdateCallback(void* ctxt, uint64_t progress, uint64_t total)
		{
			UpdateProgress* self = (UpdateProgress*)ctxt;
			self->func(progress, total);
		}
	};
}


vector<UpdateChannel> UpdateChannel::GetList()
{
	size_t count;
	char* errors;
	BNUpdateChannel* channels = BNGetUpdateChannels(&count, &errors);

	if (errors)
	{
		string errorStr = errors;
		BNFreeString(errors);
		throw UpdateException(errorStr);
	}

	vector<UpdateChannel> result;
	for (size_t i = 0; i < count; i++)
	{
		UpdateChannel channel;
		channel.name = channels[i].name;
		channel.description = channels[i].description;
		channel.latestVersion = channels[i].latestVersion;
		result.push_back(channel);
	}

	BNFreeUpdateChannelList(channels, count);
	return result;
}


bool UpdateChannel::AreUpdatesAvailable()
{
	char* errors;
	bool result = BNAreUpdatesAvailable(name.c_str(), &errors);

	if (errors)
	{
		string errorStr = errors;
		BNFreeString(errors);
		throw UpdateException(errorStr);
	}

	return result;
}


BNUpdateResult UpdateChannel::UpdateToVersion(const string& version)
{
	return UpdateToVersion(version, [](uint64_t, uint64_t){});
}


BNUpdateResult UpdateChannel::UpdateToVersion(const string& version,
                                              const function<void(uint64_t progress, uint64_t total)>& progress)
{
	UpdateProgress up;
	up.func = progress;

	char* errors;
	BNUpdateResult result = BNUpdateToVersion(name.c_str(), version.c_str(), &errors,
	                                          UpdateProgress::UpdateCallback, &up);

	if (errors)
	{
		string errorStr = errors;
		BNFreeString(errors);
		throw UpdateException(errorStr);
	}

	return result;
}


BNUpdateResult UpdateChannel::UpdateToLatestVersion()
{
	return UpdateToLatestVersion([](uint64_t, uint64_t){});
}


BNUpdateResult UpdateChannel::UpdateToLatestVersion(const function<void(uint64_t progress, uint64_t total)>& progress)
{
	UpdateProgress up;
	up.func = progress;

	char* errors;
	BNUpdateResult result = BNUpdateToLatestVersion(name.c_str(), &errors, UpdateProgress::UpdateCallback, &up);

	if (errors)
	{
		string errorStr = errors;
		BNFreeString(errors);
		throw UpdateException(errorStr);
	}

	return result;
}


vector<UpdateVersion> UpdateVersion::GetChannelVersions(const string& channel)
{
	size_t count;
	char* errors;
	BNUpdateVersion* versions = BNGetUpdateChannelVersions(channel.c_str(), &count, &errors);

	if (errors)
	{
		string errorStr = errors;
		BNFreeString(errors);
		throw UpdateException(errorStr);
	}

	vector<UpdateVersion> result;
	for (size_t i = 0; i < count; i++)
	{
		UpdateVersion version;
		version.version = versions[i].version;
		version.notes = versions[i].notes;
		version.time = (time_t)versions[i].time;
		result.push_back(version);
	}

	BNFreeUpdateChannelVersionList(versions, count);
	return result;
}


bool BinaryNinja::AreAutoUpdatesEnabled()
{
	return BNAreAutoUpdatesEnabled();
}


void BinaryNinja::SetAutoUpdatesEnabled(bool enabled)
{
	BNSetAutoUpdatesEnabled(enabled);
}


uint64_t BinaryNinja::GetTimeSinceLastUpdateCheck()
{
	return BNGetTimeSinceLastUpdateCheck();
}


void BinaryNinja::UpdatesChecked()
{
	BNUpdatesChecked();
}


string BinaryNinja::GetActiveUpdateChannel()
{
	char* channel = BNGetActiveUpdateChannel();
	string result = channel;
	BNFreeString(channel);
	return result;
}


void BinaryNinja::SetActiveUpdateChannel(const string& channel)
{
	BNSetActiveUpdateChannel(channel.c_str());
}
