// Copyright (c) 2015-2022 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


namespace BinaryNinja
{
	struct UpdateProgress
	{
		function<bool(uint64_t progress, uint64_t total)> func;

		static bool UpdateCallback(void* ctxt, uint64_t progress, uint64_t total)
		{
			UpdateProgress* self = (UpdateProgress*)ctxt;
			return self->func(progress, total);
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
	result.reserve(count);
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


bool UpdateChannel::AreUpdatesAvailable(uint64_t* expireTime, uint64_t* serverTime)
{
	char* errors;
	bool result = BNAreUpdatesAvailable(name.c_str(), expireTime, serverTime, &errors);

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
	return UpdateToVersion(version, [](uint64_t, uint64_t){ return true; });
}


BNUpdateResult UpdateChannel::UpdateToVersion(const string& version,
                                              const function<bool(uint64_t progress, uint64_t total)>& progress)
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
	return UpdateToLatestVersion([](uint64_t, uint64_t){ return true; });
}


BNUpdateResult UpdateChannel::UpdateToLatestVersion(const function<bool(uint64_t progress, uint64_t total)>& progress)
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
	result.reserve(count);
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
