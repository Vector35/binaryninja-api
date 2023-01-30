#include "binaryninjaapi.h"

using namespace std;
using namespace BinaryNinja;

Metadata::Metadata(BNMetadata* metadata)
{
	m_object = metadata;
}

Metadata::Metadata(bool data)
{
	m_object = BNCreateMetadataBooleanData(data);
}

Metadata::Metadata(const string& data)
{
	m_object = BNCreateMetadataStringData(data.c_str());
}

Metadata::Metadata(uint64_t data)
{
	m_object = BNCreateMetadataUnsignedIntegerData(data);
}

Metadata::Metadata(int64_t data)
{
	m_object = BNCreateMetadataSignedIntegerData(data);
}

Metadata::Metadata(double data)
{
	m_object = BNCreateMetadataDoubleData(data);
}

Metadata::Metadata(MetadataType type)
{
	m_object = BNCreateMetadataOfType(type);
}

Metadata::Metadata(const vector<uint8_t>& data)
{
	auto input = new uint8_t[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		input[i] = data[i];

	m_object = BNCreateMetadataRawData(input, data.size());
	delete[] input;
}

Metadata::Metadata(const std::vector<Ref<Metadata>>& data)
{
	BNMetadata** dataList = new BNMetadata*[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		dataList[i] = data[i]->m_object;

	m_object = BNCreateMetadataArray(dataList, data.size());
}

Metadata::Metadata(const std::map<std::string, Ref<Metadata>>& data)
{
	char** keys = new char*[data.size()];
	BNMetadata** values = new BNMetadata*[data.size()];

	size_t i = 0;
	for (auto& elm : data)
	{
		keys[i] = BNAllocString(elm.first.c_str());
		values[i++] = elm.second->m_object;
	}
	m_object = BNCreateMetadataValueStore((const char**)keys, values, data.size());
	for (size_t j = 0; j < data.size(); j++)
		BNFreeString(keys[j]);
	delete[] keys;
	delete[] values;
}

Metadata::Metadata(const std::vector<bool>& data)
{
	auto* list = new bool[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		list[i] = data[i];

	m_object = BNCreateMetadataBooleanListData(list, data.size());
	delete[] list;
}

Metadata::Metadata(const std::vector<uint64_t>& data)
{
	auto* list = new uint64_t[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		list[i] = data[i];

	m_object = BNCreateMetadataUnsignedIntegerListData(list, data.size());
	delete[] list;
}

Metadata::Metadata(const std::vector<int64_t>& data)
{
	auto* list = new int64_t[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		list[i] = data[i];

	m_object = BNCreateMetadataSignedIntegerListData(list, data.size());
	delete[] list;
}

Metadata::Metadata(const std::vector<double>& data)
{
	auto* list = new double[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		list[i] = data[i];

	m_object = BNCreateMetadataDoubleListData(list, data.size());
	delete[] list;
}

Metadata::Metadata(const std::vector<std::string>& data)
{
	auto* list = new const char*[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		list[i] = data[i].c_str();

	m_object = BNCreateMetadataStringListData(list, data.size());
	delete[] list;
}

bool Metadata::operator==(const Metadata& rhs)
{
	return BNMetadataIsEqual(m_object, rhs.m_object);
}

Ref<Metadata> Metadata::operator[](const std::string& key)
{
	auto result = BNMetadataGetForKey(m_object, key.c_str());
	if (!result)
		return nullptr;
	return new Metadata(result);
}

Ref<Metadata> Metadata::operator[](size_t idx)
{
	auto result = BNMetadataGetForIndex(m_object, idx);
	if (!result)
		return nullptr;
	return new Metadata(result);
}

Ref<Metadata> Metadata::Get(const std::string& key)
{
	auto result = BNMetadataGetForKey(m_object, key.c_str());
	if (!result)
		return nullptr;
	return new Metadata(result);
}

Ref<Metadata> Metadata::Get(size_t index)
{
	auto result = BNMetadataGetForIndex(m_object, index);
	if (!result)
		return nullptr;
	return new Metadata(result);
}

bool Metadata::SetValueForKey(const string& key, Ref<Metadata> data)
{
	return BNMetadataSetValueForKey(m_object, key.c_str(), data->m_object);
}

void Metadata::RemoveKey(const string& key)
{
	return BNMetadataRemoveKey(m_object, key.c_str());
}

MetadataType Metadata::GetType() const
{
	return BNMetadataGetType(m_object);
}

bool Metadata::GetBoolean() const
{
	return BNMetadataGetBoolean(m_object);
}

string Metadata::GetString() const
{
	char* str = BNMetadataGetString(m_object);
	string result = string(str);
	BNFreeString(str);
	return result;
}

uint64_t Metadata::GetUnsignedInteger() const
{
	return BNMetadataGetUnsignedInteger(m_object);
}

int64_t Metadata::GetSignedInteger() const
{
	return BNMetadataGetSignedInteger(m_object);
}

double Metadata::GetDouble() const
{
	return BNMetadataGetDouble(m_object);
}

std::vector<bool> Metadata::GetBooleanList() const
{
	size_t size;
	auto list = BNMetadataGetBooleanList(m_object, &size);

	std::vector<bool> result;
	result.reserve(size);

	for (size_t i = 0; i < size; i++)
	{
		result.push_back(list[i]);
	}

	BNFreeMetadataBooleanList(list, size);
	return result;
}

std::vector<uint64_t> Metadata::GetUnsignedIntegerList() const
{
	size_t size;
	auto list = BNMetadataGetUnsignedIntegerList(m_object, &size);

	std::vector<uint64_t> result;
	result.reserve(size);

	for (size_t i = 0; i < size; i++)
	{
		result.push_back(list[i]);
	}

	BNFreeMetadataUnsignedIntegerList(list, size);
	return result;
}

std::vector<int64_t> Metadata::GetSignedIntegerList() const
{
	size_t size;
	auto list = BNMetadataGetSignedIntegerList(m_object, &size);

	std::vector<int64_t> result;
	result.reserve(size);

	for (size_t i = 0; i < size; i++)
	{
		result.push_back(list[i]);
	}

	BNFreeMetadataSignedIntegerList(list, size);
	return result;
}

std::vector<std::string> Metadata::GetStringList() const
{
	size_t size;
	auto list = BNMetadataGetStringList(m_object, &size);

	std::vector<std::string> result;
	result.reserve(size);

	for (size_t i = 0; i < size; i++)
	{
		result.push_back(list[i]);
	}

	BNFreeMetadataStringList(list, size);
	return result;
}

std::vector<double> Metadata::GetDoubleList() const
{
	size_t size;
	auto list = BNMetadataGetDoubleList(m_object, &size);

	std::vector<double> result;
	result.reserve(size);

	for (size_t i = 0; i < size; i++)
	{
		result.push_back(list[i]);
	}

	BNFreeMetadataDoubleList(list, size);
	return result;
}

vector<uint8_t> Metadata::GetRaw() const
{
	size_t outSize;
	uint8_t* outList = BNMetadataGetRaw(m_object, &outSize);
	vector<uint8_t> result(outList, outList + outSize);
	BNFreeMetadataRaw(outList);
	return result;
}

vector<Ref<Metadata>> Metadata::GetArray()
{
	size_t size = 0;
	BNMetadata** data = BNMetadataGetArray(m_object, &size);
	vector<Ref<Metadata>> result;
	result.reserve(size);
	for (size_t i = 0; i < size; i++)
		result.push_back(new Metadata(data[i]));
	BNFreeMetadataArray(data);
	return result;
}

map<string, Ref<Metadata>> Metadata::GetKeyValueStore()
{
	BNMetadataValueStore* data = BNMetadataGetValueStore(m_object);
	map<string, Ref<Metadata>> result;
	for (size_t i = 0; i < data->size; i++)
	{
		result[data->keys[i]] = new Metadata(data->values[i]);
	}
	return result;
}

bool Metadata::Append(Ref<Metadata> data)
{
	return BNMetadataArrayAppend(m_object, data->m_object);
}

void Metadata::RemoveIndex(size_t index)
{
	BNMetadataRemoveIndex(m_object, index);
}

size_t Metadata::Size() const
{
	return BNMetadataSize(m_object);
}

bool Metadata::IsBoolean() const
{
	return BNMetadataIsBoolean(m_object);
}

bool Metadata::IsString() const
{
	return BNMetadataIsString(m_object);
}

bool Metadata::IsUnsignedInteger() const
{
	return BNMetadataIsUnsignedInteger(m_object);
}

bool Metadata::IsSignedInteger() const
{
	return BNMetadataIsSignedInteger(m_object);
}

bool Metadata::IsDouble() const
{
	return BNMetadataIsDouble(m_object);
}

bool Metadata::IsBooleanList() const
{
	return BNMetadataIsBooleanList(m_object);
}

bool Metadata::IsStringList() const
{
	return BNMetadataIsStringList(m_object);
}

bool Metadata::IsUnsignedIntegerList() const
{
	return BNMetadataIsUnsignedIntegerList(m_object);
}

bool Metadata::IsSignedIntegerList() const
{
	return BNMetadataIsSignedIntegerList(m_object);
}

bool Metadata::IsDoubleList() const
{
	return BNMetadataIsDoubleList(m_object);
}

bool Metadata::IsRaw() const
{
	return BNMetadataIsRaw(m_object);
}

bool Metadata::IsArray() const
{
	return BNMetadataIsArray(m_object);
}

bool Metadata::IsKeyValueStore() const
{
	return BNMetadataIsKeyValueStore(m_object);
}
