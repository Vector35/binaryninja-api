#include "binaryninjaapi.h"
#include "json/json.h"
#include <string.h>

using namespace BinaryNinja;
using namespace std;


Settings::Settings(BNSettings* settings)
{
	m_object = BNNewSettingsReference(settings);
}


Settings::Settings(const std::string& instanceId) : m_instanceId(instanceId)
{
	m_object = BNCreateSettings(m_instanceId.c_str());
}


Ref<Settings> Settings::Instance(const std::string& instanceId)
{
	static Ref<Settings> defaultInstance = new Settings("default");
	if (!instanceId.size() || (instanceId == "default"))
		return defaultInstance;
	else
		return new Settings(instanceId);
}


bool Settings::RegisterGroup(const string& group, const string& title)
{
	return BNSettingsRegisterGroup(m_object, group.c_str(), title.c_str());
}


bool Settings::RegisterSetting(const string& key, const string& properties)
{
	return BNSettingsRegisterSetting(m_object, key.c_str(), properties.c_str());
}


bool Settings::Contains(const string& key)
{
	return BNSettingsContains(m_object, key.c_str());
}


template<> vector<string> Settings::QueryProperty<vector<string>>(const string& key, const string& property)
{
	size_t size = 0;
	char** outBuffer = (char**)BNSettingsQueryPropertyStringList(m_object, key.c_str(), property.c_str(), &size);

	vector<string> result;
	result.reserve(size);
	for (size_t i = 0; i < size; i++)
		result.emplace_back(outBuffer[i]);

	BNFreeStringList(outBuffer, size);
	return result;
}


bool Settings::UpdateProperty(const std::string& key, const std::string& property)
{
	return BNSettingsUpdateProperty(m_object, key.c_str(), property.c_str());
}


bool Settings::UpdateProperty(const std::string& key, const std::string& property, bool value)
{
	return BNSettingsUpdateBoolProperty(m_object, key.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& key, const std::string& property, double value)
{
	return BNSettingsUpdateDoubleProperty(m_object, key.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& key, const std::string& property, int value)
{
	return BNSettingsUpdateInt64Property(m_object, key.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& key, const std::string& property, int64_t value)
{
	return BNSettingsUpdateInt64Property(m_object, key.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& key, const std::string& property, uint64_t value)
{
	return BNSettingsUpdateUInt64Property(m_object, key.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& key, const std::string& property, const char* value)
{
	return BNSettingsUpdateStringProperty(m_object, key.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& key, const std::string& property, const std::string& value)
{
	return BNSettingsUpdateStringProperty(m_object, key.c_str(), property.c_str(), value.c_str());
}


bool Settings::UpdateProperty(const std::string& key, const std::string& property, const std::vector<std::string>& value)
{
	char** buffer = new char*[value.size()];
	if (!buffer)
		return false;

	for (size_t i = 0; i < value.size(); i++)
		buffer[i] = BNAllocString(value[i].c_str());

	bool result = BNSettingsUpdateStringListProperty(m_object, key.c_str(), property.c_str(), (const char**)buffer, value.size());
	BNFreeStringList(buffer, value.size());
	return result;
}


bool Settings::DeserializeSchema(const string& schema, BNSettingsScope scope, bool merge)
{
	return BNSettingsDeserializeSchema(m_object, schema.c_str(), scope, merge);
}


string Settings::SerializeSchema()
{
	char* schemaStr = BNSettingsSerializeSchema(m_object);
	string schema(schemaStr);
	BNFreeString(schemaStr);
	return schema;
}


bool Settings::DeserializeSettings(const string& contents, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNDeserializeSettings(m_object, contents.c_str(), view ? view->GetObject() : nullptr, scope);
}


string Settings::SerializeSettings(Ref<BinaryView> view, BNSettingsScope scope)
{
	char* settingsStr = BNSerializeSettings(m_object, view ? view->GetObject() : nullptr, scope);
	string settings(settingsStr);
	BNFreeString(settingsStr);
	return settings;
}


bool Settings::CopyValuesFrom(Ref<Settings> source, BNSettingsScope scope)
{
	return BNSettingsCopyValuesFrom(m_object, source->GetObject(), scope);
}


bool Settings::Reset(const string& key, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsReset(m_object, key.c_str(), view ? view->GetObject() : nullptr, scope);
}


bool Settings::ResetAll(Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsResetAll(m_object, view ? view->GetObject() : nullptr, scope);
}


template<> bool Settings::Get<bool>(const string& key, Ref<BinaryView> view, BNSettingsScope* scope)
{
	return BNSettingsGetBool(m_object, key.c_str(), view ? view->GetObject() : nullptr, scope);
}


template<> double Settings::Get<double>(const string& key, Ref<BinaryView> view, BNSettingsScope* scope)
{
	return BNSettingsGetDouble(m_object, key.c_str(), view ? view->GetObject() : nullptr, scope);
}


template<> int64_t Settings::Get<int64_t>(const string& key, Ref<BinaryView> view, BNSettingsScope* scope)
{
	return BNSettingsGetInt64(m_object, key.c_str(), view ? view->GetObject() : nullptr, scope);
}


template<> uint64_t Settings::Get<uint64_t>(const string& key, Ref<BinaryView> view, BNSettingsScope* scope)
{
	return BNSettingsGetUInt64(m_object, key.c_str(), view ? view->GetObject() : nullptr, scope);
}


template<> string Settings::Get<string>(const string& key, Ref<BinaryView> view, BNSettingsScope* scope)
{
	char* tmpStr = BNSettingsGetString(m_object, key.c_str(), view ? view->GetObject() : nullptr, scope);
	string result(tmpStr);
	BNFreeString(tmpStr);
	return result;
}


template<> vector<string> Settings::Get<vector<string>>(const string& key, Ref<BinaryView> view, BNSettingsScope* scope)
{
	size_t size = 0;
	char** outBuffer = (char**)BNSettingsGetStringList(m_object, key.c_str(), view ? view->GetObject() : nullptr, scope, &size);

	vector<string> result;
	result.reserve(size);
	for (size_t i = 0; i < size; i++)
		result.emplace_back(outBuffer[i]);

	BNFreeStringList(outBuffer, size);
	return result;
}


bool Settings::Set(const string& key, bool value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetBool(m_object, view ? view->GetObject() : nullptr, scope, key.c_str(), value);
}


bool Settings::Set(const string& key, double value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetDouble(m_object, view ? view->GetObject() : nullptr, scope, key.c_str(), value);
}


bool Settings::Set(const string& key, int value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetInt64(m_object, view ? view->GetObject() : nullptr, scope, key.c_str(), value);
}


bool Settings::Set(const string& key, int64_t value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetInt64(m_object, view ? view->GetObject() : nullptr, scope, key.c_str(), value);
}


bool Settings::Set(const string& key, uint64_t value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetUInt64(m_object, view ? view->GetObject() : nullptr, scope, key.c_str(), value);
}


bool Settings::Set(const string& key, const char* value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetString(m_object, view ? view->GetObject() : nullptr, scope, key.c_str(), value);
}


bool Settings::Set(const string& key, const string& value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetString(m_object, view ? view->GetObject() : nullptr, scope, key.c_str(), value.c_str());
}


bool Settings::Set(const string& key, const vector<string>& value, Ref<BinaryView> view, BNSettingsScope scope)
{
	char** buffer = new char*[value.size()];
	if (!buffer)
		return false;

	for (size_t i = 0; i < value.size(); i++)
		buffer[i] = BNAllocString(value[i].c_str());

	bool result = BNSettingsSetStringList(m_object, view ? view->GetObject() : nullptr, scope, key.c_str(), (const char**)buffer, value.size());
	BNFreeStringList(buffer, value.size());
	return result;
}
