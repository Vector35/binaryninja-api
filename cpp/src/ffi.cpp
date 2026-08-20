
#include "ffi.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


char BN_API_PTR* BinaryNinja::AllocApiString(const char* string)
{
	return strdup(string);
}


void BinaryNinja::AllocApiString(const char* string, char BN_API_PTR** output)
{
	*output = AllocApiString(string);
}


char BN_API_PTR* BinaryNinja::AllocApiString(const string& string)
{
	return AllocApiString(string.c_str());
}


void BinaryNinja::AllocApiString(const string& string, char BN_API_PTR** output)
{
	AllocApiString(string.c_str(), output);
}


char BN_API_PTR* BN_API_PTR* BinaryNinja::AllocApiStringList(const char* const* stringList, size_t count)
{
	char BN_API_PTR* BN_API_PTR* result = new char*[count];
	for (size_t i = 0; i < count; i++)
	{
		result[i] = AllocApiString(stringList[i]);
	}
	return result;
}


void BinaryNinja::AllocApiStringList(const char* const* stringList, size_t count, char BN_API_PTR* BN_API_PTR** output)
{
	*output = AllocApiStringList(stringList, count);
}


char BN_API_PTR* BN_API_PTR* BinaryNinja::AllocApiStringList(const vector<string>& stringList, size_t* count)
{
	*count = stringList.size();
	vector<const char*> intermediate;
	intermediate.reserve(*count);
	for (const auto& string: stringList)
	{
		intermediate.push_back(string.c_str());
	}
	return AllocApiStringList(intermediate.data(), *count);
}


void BinaryNinja::AllocApiStringList(const vector<string>& stringList, char BN_API_PTR* BN_API_PTR** output, size_t* count)
{
	*count = stringList.size();
	vector<const char*> intermediate;
	intermediate.reserve(*count);
	for (const auto& string: stringList)
	{
		intermediate.push_back(string.c_str());
	}
	AllocApiStringList(intermediate.data(), *count, output);
}


char BN_API_PTR* BN_API_PTR* BinaryNinja::AllocApiStringList(const set<string>& stringList, size_t* count)
{
	*count = stringList.size();
	vector<const char*> intermediate;
	intermediate.reserve(*count);
	for (const auto& string: stringList)
	{
		intermediate.push_back(string.c_str());
	}
	return AllocApiStringList(intermediate.data(), *count);
}


void BinaryNinja::AllocApiStringList(const set<string>& stringList, char BN_API_PTR* BN_API_PTR** output, size_t* count)
{
	*count = stringList.size();
	vector<const char*> intermediate;
	intermediate.reserve(*count);
	for (const auto& string: stringList)
	{
		intermediate.push_back(string.c_str());
	}
	AllocApiStringList(intermediate.data(), *count, output);
}


char BN_API_PTR* BN_API_PTR* BinaryNinja::AllocApiStringList(const unordered_set<string>& stringList, size_t* count)
{
	*count = stringList.size();
	vector<const char*> intermediate;
	intermediate.reserve(*count);
	for (const auto& string: stringList)
	{
		intermediate.push_back(string.c_str());
	}
	return AllocApiStringList(intermediate.data(), *count);
}


void BinaryNinja::AllocApiStringList(const unordered_set<string>& stringList, char BN_API_PTR* BN_API_PTR** output, size_t* count)
{
	*count = stringList.size();
	vector<const char*> intermediate;
	intermediate.reserve(*count);
	for (const auto& string: stringList)
	{
		intermediate.push_back(string.c_str());
	}
	AllocApiStringList(intermediate.data(), *count, output);
}


void BinaryNinja::AllocApiStringPairList(const vector<pair<string, string>>& stringPairList, char BN_API_PTR* BN_API_PTR** outputKeys, char BN_API_PTR* BN_API_PTR** outputValues, size_t* count)
{
	*count = stringPairList.size();
	vector<const char*> intermediateKeys;
	vector<const char*> intermediateValues;
	intermediateKeys.reserve(*count);
	intermediateValues.reserve(*count);
	for (const auto& pair: stringPairList)
	{
		intermediateKeys.push_back(pair.first.c_str());
		intermediateValues.push_back(pair.second.c_str());
	}
	AllocApiStringList(intermediateKeys.data(), *count, outputKeys);
	AllocApiStringList(intermediateValues.data(), *count, outputValues);
}


void BinaryNinja::AllocApiStringPairList(const map<string, string>& stringPairList, char BN_API_PTR* BN_API_PTR** outputKeys, char BN_API_PTR* BN_API_PTR** outputValues, size_t* count)
{
	*count = stringPairList.size();
	vector<const char*> intermediateKeys;
	vector<const char*> intermediateValues;
	intermediateKeys.reserve(*count);
	intermediateValues.reserve(*count);
	for (const auto& pair: stringPairList)
	{
		intermediateKeys.push_back(pair.first.c_str());
		intermediateValues.push_back(pair.second.c_str());
	}
	AllocApiStringList(intermediateKeys.data(), *count, outputKeys);
	AllocApiStringList(intermediateValues.data(), *count, outputValues);
}


void BinaryNinja::AllocApiStringPairList(const unordered_map<string, string>& stringPairList, char BN_API_PTR* BN_API_PTR** outputKeys, char BN_API_PTR* BN_API_PTR** outputValues, size_t* count)
{
	*count = stringPairList.size();
	vector<const char*> intermediateKeys;
	vector<const char*> intermediateValues;
	intermediateKeys.reserve(*count);
	intermediateValues.reserve(*count);
	for (const auto& pair: stringPairList)
	{
		intermediateKeys.push_back(pair.first.c_str());
		intermediateValues.push_back(pair.second.c_str());
	}
	AllocApiStringList(intermediateKeys.data(), *count, outputKeys);
	AllocApiStringList(intermediateValues.data(), *count, outputValues);
}


string BinaryNinja::ParseString(const char* string)
{
	return string;
}


vector<string> BinaryNinja::ParseStringList(const char* const* stringList, size_t count)
{
	vector<string> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i ++)
	{
		result.push_back(stringList[i]);
	}
	return result;
}


set<string> BinaryNinja::ParseStringSet(const char* const* stringList, size_t count)
{
	set<string> result;
	for (size_t i = 0; i < count; i ++)
	{
		result.insert(stringList[i]);
	}
	return result;
}


unordered_set<string> BinaryNinja::ParseStringUnorderedSet(const char* const* stringList, size_t count)
{
	unordered_set<string> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i ++)
	{
		result.insert(stringList[i]);
	}
	return result;
}


vector<pair<string, string>> BinaryNinja::ParseStringPairList(const char* const* keys, const char* const* values, size_t count)
{
	vector<pair<string, string>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i ++)
	{
		result.push_back({keys[i], values[i]});
	}
	return result;
}


map<string, string> BinaryNinja::ParseStringMap(const char* const* keys, const char* const* values, size_t count)
{
	map<string, string> result;
	for (size_t i = 0; i < count; i ++)
	{
		result.insert({keys[i], values[i]});
	}
	return result;
}


unordered_map<string, string> BinaryNinja::ParseStringUnorderedMap(const char* const* keys, const char* const* values, size_t count)
{
	unordered_map<string, string> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i ++)
	{
		result.insert({keys[i], values[i]});
	}
	return result;
}


void BinaryNinja::FreeApiString(char BN_API_PTR* string)
{
	// Allocated with strdup()
	free(string);
}


void BinaryNinja::FreeApiStringList(char BN_API_PTR* BN_API_PTR* stringList, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		FreeApiString(stringList[i]);
	}
	delete[] stringList;
}


void BinaryNinja::FreeApiStringPairList(char BN_API_PTR* BN_API_PTR* keys, char BN_API_PTR* BN_API_PTR* values, size_t count)
{
	FreeApiStringList(keys, count);
	FreeApiStringList(values, count);
}


void BinaryNinja::FreeCoreString(char BN_CORE_PTR* string)
{
	BNFreeString(string);
}


void BinaryNinja::FreeCoreStringList(char BN_CORE_PTR* BN_CORE_PTR* stringList, size_t count)
{
	BNFreeStringList(stringList, count);
}


void BinaryNinja::FreeCoreStringPairList(char BN_CORE_PTR* BN_CORE_PTR* keys, char BN_CORE_PTR* BN_CORE_PTR* values, size_t count)
{
	FreeCoreStringList(keys, count);
	FreeCoreStringList(values, count);
}
