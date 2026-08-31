
#include "ffi.h"

#include "binaryninjacore.h"

#include <stdlib.h>
#include <string.h>

using namespace BinaryNinja;
using namespace std;


char BN_API_PTR* BinaryNinja::AllocApiString(std::string_view string)
{
	char* result = static_cast<char*>(malloc(string.size() + 1));
	memcpy(result, string.data(), string.size());
	result[string.size()] = '\0';
	return result;
}


void BinaryNinja::AllocApiString(std::string_view string, char BN_API_PTR** output)
{
	*output = AllocApiString(string);
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


string BinaryNinja::ParseString(const char* string)
{
	return string;
}


vector<string> BinaryNinja::ParseStringList(const char* const* stringList, size_t count)
{
	return bn::base::capi::ParseList<vector<string>>(stringList, count);
}


set<string> BinaryNinja::ParseStringSet(const char* const* stringList, size_t count)
{
	return bn::base::capi::ParseList<set<string>>(stringList, count);
}


unordered_set<string> BinaryNinja::ParseStringUnorderedSet(const char* const* stringList, size_t count)
{
	return bn::base::capi::ParseList<unordered_set<string>>(stringList, count);
}


vector<pair<string, string>> BinaryNinja::ParseStringPairList(const char* const* keys, const char* const* values, size_t count)
{
	return bn::base::capi::ParsePairList<vector<pair<string, string>>>(keys, values, count);
}


map<string, string> BinaryNinja::ParseStringMap(const char* const* keys, const char* const* values, size_t count)
{
	return bn::base::capi::ParsePairList<map<string, string>>(keys, values, count);
}


unordered_map<string, string> BinaryNinja::ParseStringUnorderedMap(const char* const* keys, const char* const* values, size_t count)
{
	return bn::base::capi::ParsePairList<unordered_map<string, string>>(keys, values, count);
}


void BinaryNinja::FreeApiString(char BN_API_PTR* string)
{
	// Allocated with malloc()
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
