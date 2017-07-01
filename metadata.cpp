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

Metadata::Metadata(const vector<bool>& data)
{
	auto input = new bool[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		input[i] = data[i];

	m_object = BNCreateMetadataBooleanListData(input, data.size());
	delete[] input;
}

Metadata::Metadata(const vector<string>& data)
{
	char** input = new char*[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		input[i] = BNAllocString(data[i].c_str());

	m_object = BNCreateMetadataStringListData((const char**)input, data.size());

	for (size_t i = 0; i < data.size(); i++)
		BNFreeString(input[i]);
	delete[] input;
}

Metadata::Metadata(const vector<uint64_t>& data)
{
	auto input = new uint64_t[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		input[i] = data[i];

	m_object = BNCreateMetadataUnsignedIntegerListData(input, data.size());
	delete[] input;
}

Metadata::Metadata(const vector<int64_t>& data)
{
	auto input = new int64_t[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		input[i] = data[i];

	m_object = BNCreateMetadataSignedIntegerListData(input, data.size());
	delete[] input;
}

Metadata::Metadata(const vector<double>& data)
{
	auto input = new double[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		input[i] = data[i];

	m_object = BNCreateMetadataDoubleListData(input, data.size());
	delete[] input;
}

Metadata::Metadata(const vector<uint8_t>& data)
{
	auto input = new uint8_t[data.size()];
	for (size_t i = 0; i < data.size(); i++)
		input[i] = data[i];

	m_object = BNCreateMetadataRawData(input, data.size());
	delete[] input;
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
	return BNMetadataGetString(m_object);
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

vector<bool> Metadata::GetBooleanList() const
{
	size_t outSize;
	bool* outList = BNMetadataGetBooleanList(m_object, &outSize);
	vector<bool> result(outList, outList + outSize);
	BNFreeMetadataBooleanList(outList);
	return result;
}

vector<string> Metadata::GetStringList() const
{
	size_t outSize;
	char** outList = BNMetadataGetStringList(m_object, &outSize);
	vector<string> result;
	for (size_t i = 0; i < outSize; i++)
		result.push_back(string(outList[i]));
	BNFreeMetadataStringList(outList, outSize);
	return result;
}

vector<uint64_t> Metadata::GetUnsignedIntegerList() const
{
	size_t outSize;
	uint64_t* outList = BNMetadataGetUnsignedIntegerList(m_object, &outSize);
	vector<uint64_t> result(outList, outList + outSize);
	BNFreeMetadataUnsignedIntegerList(outList);
	return result;
}

vector<int64_t> Metadata::GetSignedIntegerList() const
{
	size_t outSize;
	int64_t* outList = BNMetadataGetSignedIntegerList(m_object, &outSize);
	vector<int64_t> result(outList, outList + outSize);
	BNFreeMetadataSignedIntegerList(outList);
	return result;
}

vector<double> Metadata::GetDoubleList() const
{
	size_t outSize;
	double* outList = BNMetadataGetDoubleList(m_object, &outSize);
	vector<double> result(outList, outList + outSize);
	BNFreeMetadataDoubleList(outList);
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
