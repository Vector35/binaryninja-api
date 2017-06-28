#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


bool Setting::GetBool(const std::string& pluginName, const std::string& name, bool defaultValue)
{
	return BNSettingGetBool(pluginName.c_str(), name.c_str(), defaultValue);
}

uint64_t Setting::GetInteger(const std::string& pluginName, const std::string& name, uint64_t defaultValue)
{
	return BNSettingGetInteger(pluginName.c_str(), name.c_str(), defaultValue);
}

std::string Setting::GetString(const std::string& pluginName, const std::string& name, const std::string& defaultValue)
{
	return BNSettingGetString(pluginName.c_str(), name.c_str(), defaultValue.c_str());
}

double Setting::GetDouble(const std::string& pluginName, const std::string& name, double defaultValue)
{
	return BNSettingGetDouble(pluginName.c_str(), name.c_str(), defaultValue);
}

std::vector<uint64_t> Setting::GetIntegerList(const std::string& pluginName,
	const std::string& name,
	const std::vector<uint64_t>& defaultValue)
{
	uint64_t* buffer = new uint64_t[defaultValue.size()];
	memcpy(&buffer[0], &defaultValue[0], sizeof(uint64_t) * defaultValue.size());
	size_t size = defaultValue.size();
	uint64_t* outBuffer = BNSettingGetIntegerList(pluginName.c_str(), name.c_str(), buffer, &size);
	delete[] buffer;

	vector<uint64_t> out(outBuffer, outBuffer + size);
	BNFreeSettingIntegerList(buffer);
	return out;
}

std::vector<std::string> Setting::GetStringList(const std::string& pluginName,
	const std::string& name,
	const std::vector<std::string>& defaultValue)
{
	char** buffer = new char*[defaultValue.size()];
	for (size_t i = 0; i < defaultValue.size(); i++)
		buffer[i] = BNAllocString(defaultValue[i].c_str());
	size_t size = defaultValue.size();
	char** outBuffer = (char**)BNSettingGetStringList(pluginName.c_str(), name.c_str(), (const char**)buffer, &size);

	vector<string> result;
	for (size_t i = 0; i < size; i++)
		result.push_back(string(outBuffer[i]));

	for (size_t i = 0; i < defaultValue.size(); i++)
		BNFreeString(buffer[i]);
	delete[] buffer;
	BNFreeStringList(outBuffer, size);
	return result;
}


bool Setting::IsPresent(const std::string& pluginName, const std::string& name)
{
	return BNSettingIsPresent(pluginName.c_str(), name.c_str());
}

bool Setting::IsBool(const std::string& pluginName, const std::string& name)
{
	return BNSettingIsBool(pluginName.c_str(), name.c_str());
}

bool Setting::IsInteger(const std::string& pluginName, const std::string& name)
{
	return BNSettingIsInteger(pluginName.c_str(), name.c_str());
}

bool Setting::IsString(const std::string& pluginName, const std::string& name)
{
	return BNSettingIsString(pluginName.c_str(), name.c_str());
}

bool Setting::IsIntegerList(const std::string& pluginName, const std::string& name)
{
	return BNSettingIsIntegerList(pluginName.c_str(), name.c_str());
}

bool Setting::IsStringList(const std::string& pluginName, const std::string& name)
{
	return BNSettingIsStringList(pluginName.c_str(), name.c_str());
}

bool Setting::IsDouble(const std::string& pluginName, const std::string& name)
{
	return BNSettingIsDouble(pluginName.c_str(), name.c_str());
}
