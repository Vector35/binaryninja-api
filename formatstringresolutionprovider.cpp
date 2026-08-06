// Copyright (c) 2015-2026 Vector 35 Inc
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


FormatStringResolutionProvider::FormatStringResolutionProvider(const string& name) : m_nameForRegister(name) {}


FormatStringResolutionProvider::FormatStringResolutionProvider(BNFormatStringResolutionProvider* provider)
{
	m_object = provider;
}


bool FormatStringResolutionProvider::IsValidCallback(
	void* ctxt, const char* format, BNPlatform* platform,
	BNTypeWithConfidence** types, size_t* count)
{
	FormatStringResolutionProvider* provider = (FormatStringResolutionProvider*)ctxt;
	Ref<Platform> resolvedPlatform;
	if (platform)
		resolvedPlatform = new CorePlatform(BNNewPlatformReference(platform));
	auto result = provider->IsValid(format, resolvedPlatform);
	if (!result.has_value())
	{
		*types = nullptr;
		*count = 0;
		return false;
	}

	*count = result->size();
	if (result->empty())
	{
		*types = nullptr;
		return true;
	}

	*types = new BNTypeWithConfidence[result->size()];
	for (size_t i = 0; i < result->size(); i++)
	{
		(*types)[i].type = BNNewTypeReference((*result)[i].GetValue()->GetObject());
		(*types)[i].confidence = (*result)[i].GetConfidence();
	}
	return true;
}


void FormatStringResolutionProvider::FreeTypeListCallback(
	void*, BNTypeWithConfidence* types, size_t count)
{
	for (size_t i = 0; i < count; i++)
		BNFreeType(types[i].type);
	delete[] types;
}


string FormatStringResolutionProvider::GetName() const
{
	char* name = BNGetFormatStringResolutionProviderName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


vector<Ref<FormatStringResolutionProvider>> FormatStringResolutionProvider::GetList()
{
	size_t count;
	BNFormatStringResolutionProvider** list = BNGetFormatStringResolutionProviderList(&count);
	vector<Ref<FormatStringResolutionProvider>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreFormatStringResolutionProvider(list[i]));
	BNFreeFormatStringResolutionProviderList(list);
	return result;
}


Ref<FormatStringResolutionProvider> FormatStringResolutionProvider::GetByName(const string& name)
{
	BNFormatStringResolutionProvider* result = BNGetFormatStringResolutionProviderByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreFormatStringResolutionProvider(result);
}


void FormatStringResolutionProvider::Register(FormatStringResolutionProvider* provider)
{
	BNFormatStringResolutionProviderCallbacks callbacks;
	callbacks.context = provider;
	callbacks.isValid = IsValidCallback;
	callbacks.freeTypeList = FreeTypeListCallback;
	provider->AddRefForRegistration();
	provider->m_object = BNRegisterFormatStringResolutionProvider(provider->m_nameForRegister.c_str(), &callbacks);
}


CoreFormatStringResolutionProvider::CoreFormatStringResolutionProvider(BNFormatStringResolutionProvider* provider) :
	FormatStringResolutionProvider(provider)
{}


optional<vector<Confidence<Ref<Type>>>> CoreFormatStringResolutionProvider::IsValid(
	const string& format, Platform* platform)
{
	BNTypeWithConfidence* types = nullptr;
	size_t count = 0;
	if (!BNFormatStringResolutionProviderIsValid(
		m_object, format.c_str(), platform ? platform->GetObject() : nullptr, &types, &count))
		return nullopt;

	vector<Confidence<Ref<Type>>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.emplace_back(
			new Type(BNNewTypeReference(types[i].type)), types[i].confidence);
	}
	BNFreeTypeWithConfidenceList(types, count);
	return result;
}
