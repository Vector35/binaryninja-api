#include "binaryninjaapi.h"
#include "json/json.h"
#include <string.h>

using namespace BinaryNinja;
using namespace std;


bool Settings::RegisterGroup(const string& group, const string& title)
{
	return BNSettingsRegisterGroup(m_registry.c_str(), group.c_str(), title.c_str());
}


bool Settings::RegisterSetting(const string& id, const string& properties)
{
	return BNSettingsRegisterSetting(m_registry.c_str(), id.c_str(), properties.c_str());
}


bool Settings::UpdateProperty(const std::string& id, const std::string& property)
{
	return BNSettingsUpdateProperty(m_registry.c_str(), id.c_str(), property.c_str());
}


bool Settings::UpdateProperty(const std::string& id, const std::string& property, bool value)
{
	return BNSettingsUpdateBoolProperty(m_registry.c_str(), id.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& id, const std::string& property, double value)
{
	return BNSettingsUpdateDoubleProperty(m_registry.c_str(), id.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& id, const std::string& property, int value)
{
	return BNSettingsUpdateInt64Property(m_registry.c_str(), id.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& id, const std::string& property, int64_t value)
{
	return BNSettingsUpdateInt64Property(m_registry.c_str(), id.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& id, const std::string& property, uint64_t value)
{
	return BNSettingsUpdateUInt64Property(m_registry.c_str(), id.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& id, const std::string& property, const char* value)
{
	return BNSettingsUpdateStringProperty(m_registry.c_str(), id.c_str(), property.c_str(), value);
}


bool Settings::UpdateProperty(const std::string& id, const std::string& property, const std::string& value)
{
	return BNSettingsUpdateStringProperty(m_registry.c_str(), id.c_str(), property.c_str(), value.c_str());
}


bool Settings::UpdateProperty(const std::string& id, const std::string& property, const std::vector<std::string>& value)
{
	char** buffer = new char*[value.size()];
	if (!buffer)
		return false;

	for (size_t i = 0; i < value.size(); i++)
		buffer[i] = BNAllocString(value[i].c_str());

	bool result = BNSettingsUpdateStringListProperty(m_registry.c_str(), id.c_str(), property.c_str(), (const char**)buffer, value.size());
	BNFreeStringList(buffer, value.size());
	return result;
}


string Settings::GetSchema()
{
	char* schemaStr = BNSettingsGetSchema(m_registry.c_str());
	string schema(schemaStr);
	BNFreeString(schemaStr);
	return schema;
}


bool Settings::DeserializeSettings(const string& contents, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNDeserializeSettings(m_registry.c_str(), contents.c_str(), view ? view->GetObject() : nullptr, scope);
}


string Settings::SerializeSettings(Ref<BinaryView> view, BNSettingsScope scope)
{
	char* settingsStr = BNSerializeSettings(m_registry.c_str(), view ? view->GetObject() : nullptr, scope);
	string settings(settingsStr);
	BNFreeString(settingsStr);
	return settings;
}


bool Settings::Reset(const string& id, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsReset(m_registry.c_str(), id.c_str(), view ? view->GetObject() : nullptr, scope);
}


bool Settings::ResetAll(Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsResetAll(m_registry.c_str(), view ? view->GetObject() : nullptr, scope);
}


template<> bool Settings::Get<bool>(const string& id, Ref<BinaryView> view, BNSettingsScope* scope)
{
	return BNSettingsGetBool(m_registry.c_str(), id.c_str(), view ? view->GetObject() : nullptr, scope);
}


template<> double Settings::Get<double>(const string& id, Ref<BinaryView> view, BNSettingsScope* scope)
{
	return BNSettingsGetDouble(m_registry.c_str(), id.c_str(), view ? view->GetObject() : nullptr, scope);
}


template<> int64_t Settings::Get<int64_t>(const string& id, Ref<BinaryView> view, BNSettingsScope* scope)
{
	return BNSettingsGetInt64(m_registry.c_str(), id.c_str(), view ? view->GetObject() : nullptr, scope);
}


template<> uint64_t Settings::Get<uint64_t>(const string& id, Ref<BinaryView> view, BNSettingsScope* scope)
{
	return BNSettingsGetUInt64(m_registry.c_str(), id.c_str(), view ? view->GetObject() : nullptr, scope);
}


template<> string Settings::Get<string>(const string& id, Ref<BinaryView> view, BNSettingsScope* scope)
{
	char* tmpStr = BNSettingsGetString(m_registry.c_str(), id.c_str(), view ? view->GetObject() : nullptr, scope);
	string result(tmpStr);
	BNFreeString(tmpStr);
	return result;
}


template<> vector<string> Settings::Get<vector<string>>(const string& id, Ref<BinaryView> view, BNSettingsScope* scope)
{
	size_t size = 0;
	char** outBuffer = (char**)BNSettingsGetStringList(m_registry.c_str(), id.c_str(), view ? view->GetObject() : nullptr, scope, &size);

	vector<string> result;
	result.reserve(size);
	for (size_t i = 0; i < size; i++)
		result.emplace_back(outBuffer[i]);

	BNFreeStringList(outBuffer, size);
	return result;
}


bool Settings::Set(const string& id, bool value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetBool(m_registry.c_str(), view ? view->GetObject() : nullptr, scope, id.c_str(), value);
}


bool Settings::Set(const string& id, double value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetDouble(m_registry.c_str(), view ? view->GetObject() : nullptr, scope, id.c_str(), value);
}


bool Settings::Set(const string& id, int value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetInt64(m_registry.c_str(), view ? view->GetObject() : nullptr, scope, id.c_str(), value);
}


bool Settings::Set(const string& id, int64_t value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetInt64(m_registry.c_str(), view ? view->GetObject() : nullptr, scope, id.c_str(), value);
}


bool Settings::Set(const string& id, uint64_t value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetUInt64(m_registry.c_str(), view ? view->GetObject() : nullptr, scope, id.c_str(), value);
}


bool Settings::Set(const string& id, const char* value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetString(m_registry.c_str(), view ? view->GetObject() : nullptr, scope, id.c_str(), value);
}


bool Settings::Set(const string& id, const string& value, Ref<BinaryView> view, BNSettingsScope scope)
{
	return BNSettingsSetString(m_registry.c_str(), view ? view->GetObject() : nullptr, scope, id.c_str(), value.c_str());
}


bool Settings::Set(const string& id, const vector<string>& value, Ref<BinaryView> view, BNSettingsScope scope)
{
	char** buffer = new char*[value.size()];
	if (!buffer)
		return false;

	for (size_t i = 0; i < value.size(); i++)
		buffer[i] = BNAllocString(value[i].c_str());

	bool result = BNSettingsSetStringList(m_registry.c_str(), view ? view->GetObject() : nullptr, scope, id.c_str(), (const char**)buffer, value.size());
	BNFreeStringList(buffer, value.size());
	return result;
}
