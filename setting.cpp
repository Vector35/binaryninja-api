#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


bool Setting::ProcessMainSettingsFile()
{
	return BNProcessMainSettingsFile();
}

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

std::vector<uint64_t> Setting::GetIntegerList(const std::string& pluginName, const std::string& name, const std::vector<uint64_t>& defaultValue)
{
	uint64_t* buffer = new uint64_t[defaultValue.size()];
	memcpy(&buffer[0], &defaultValue[0], sizeof(uint64_t) * defaultValue.size());
	size_t size = defaultValue.size();
	uint64_t* outBuffer = BNSettingGetIntegerList(pluginName.c_str(), name.c_str(), buffer, &size);
	if (buffer == outBuffer)
		return defaultValue;

	vector<uint64_t> out(buffer, buffer + size);
	delete[] buffer;
	return out;
}

std::vector<std::string> Setting::GetStringList(const std::string& pluginName, const std::string& name, const std::vector<std::string>& defaultValue)
{
	char** buffer = new char*[defaultValue.size()];
	for (size_t i = 0; i < defaultValue.size(); i++)
		buffer[i] = BNAllocString(defaultValue[i].c_str());
	size_t size = defaultValue.size();
	const char** outBuffer = BNSettingGetStringList(pluginName.c_str(), name.c_str(), (const char**)buffer, &size);
	if (buffer == outBuffer)
		return defaultValue;

	vector<string> out;
	for (size_t i = 0; i < size; i++)
		out.push_back(string(outBuffer[i]));
	for (size_t i = 0; i < defaultValue.size(); i++)
		BNFreeString(buffer[i]);
	delete[] buffer;
	return out;
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



bool CoreSetting::GetBool(const std::string& name, bool defaultValue)
{
	return BNSettingGetBool("core", name.c_str(), defaultValue);
}
uint64_t CoreSetting::GetInteger(const std::string& name, uint64_t defaultValue)
{
	return BNSettingGetInteger("core", name.c_str(), defaultValue);
}
std::string CoreSetting::GetString(const std::string& name, const std::string& defaultValue)
{
	return Setting::GetString("core", name.c_str(), defaultValue);
}
double CoreSetting::GetDouble(const std::string& name, double defaultValue)
{
	return BNSettingGetDouble("core", name.c_str(), defaultValue);
}
std::vector<uint64_t> CoreSetting::GetIntegerList(const std::string& name, const std::vector<uint64_t>& defaultValue)
{
	return Setting::GetIntegerList("core", name.c_str(), defaultValue);
}
std::vector<std::string> CoreSetting::GetStringList(const std::string& name, const std::vector<std::string>& defaultValue)
{
	return Setting::GetStringList("core", name.c_str(), defaultValue);
}

bool CoreSetting::IsPresent(const std::string& name)
{
	return BNSettingIsPresent("core", name.c_str());
}

bool CoreSetting::IsBool(const std::string& name)
{
	return BNSettingIsBool("core", name.c_str());
}

bool CoreSetting::IsInteger(const std::string& name)
{
	return BNSettingIsInteger("core", name.c_str());
}

bool CoreSetting::IsString(const std::string& name)
{
	return BNSettingIsString("core", name.c_str());
}

bool CoreSetting::IsIntegerList(const std::string& name)
{
	return BNSettingIsIntegerList("core", name.c_str());
}

bool CoreSetting::IsStringList(const std::string& name)
{
	return BNSettingIsStringList("core", name.c_str());
}

bool CoreSetting::IsDouble(const std::string& name)
{
	return BNSettingIsDouble("core", name.c_str());
}

