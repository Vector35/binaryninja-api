#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


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
