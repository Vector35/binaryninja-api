// Copyright (c) 2015-2022 Vector 35 Inc
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

#include "secretsprovider.hpp"
#include <string>
#include <optional>

using namespace BinaryNinja;

SecretsProvider::SecretsProvider(const std::string& name) : m_nameForRegister(name) {}


SecretsProvider::SecretsProvider(BNSecretsProvider* provider)
{
	m_object = provider;
}


bool SecretsProvider::HasDataCallback(void* ctxt, const char* key)
{
	SecretsProvider* provider = (SecretsProvider*)ctxt;
	return provider->HasData(key);
}


char* SecretsProvider::GetDataCallback(void* ctxt, const char* key)
{
	SecretsProvider* provider = (SecretsProvider*)ctxt;
	std::optional<std::string> data = provider->GetData(key);
	if (!data.has_value())
		return nullptr;
	char* value = BNAllocString(data->c_str());
	memset(data->data(), 0, data->size());
	return value;
}


bool SecretsProvider::StoreDataCallback(void* ctxt, const char* key, const char* data)
{
	SecretsProvider* provider = (SecretsProvider*)ctxt;
	std::string value = data;
	bool result = provider->StoreData(key, value);
	memset(value.data(), 0, value.size());
	return result;
}


bool SecretsProvider::DeleteDataCallback(void* ctxt, const char* key)
{
	SecretsProvider* provider = (SecretsProvider*)ctxt;
	return provider->DeleteData(key);
}


std::vector<Ref<SecretsProvider>> SecretsProvider::GetList()
{
	size_t count;
	BNSecretsProvider** list = BNGetSecretsProviderList(&count);
	std::vector<Ref<SecretsProvider>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreSecretsProvider(list[i]));
	BNFreeSecretsProviderList(list);
	return result;
}


Ref<SecretsProvider> SecretsProvider::GetByName(const std::string& name)
{
	BNSecretsProvider* result = BNGetSecretsProviderByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreSecretsProvider(result);
}


void SecretsProvider::Register(SecretsProvider* provider)
{
	BNSecretsProviderCallbacks cb;
	cb.context = provider;
	cb.hasData = HasDataCallback;
	cb.getData = GetDataCallback;
	cb.storeData = StoreDataCallback;
	cb.deleteData = DeleteDataCallback;
	provider->m_object = BNRegisterSecretsProvider(provider->m_nameForRegister.c_str(), &cb);
}


CoreSecretsProvider::CoreSecretsProvider(BNSecretsProvider* provider) : SecretsProvider(provider) {}


bool CoreSecretsProvider::HasData(const std::string& key)
{
	return BNSecretsProviderHasData(m_object, key.c_str());
}


std::optional<std::string> CoreSecretsProvider::GetData(const std::string& key)
{
	char* data = BNGetSecretsProviderData(m_object, key.c_str());
	if (data == nullptr)
		return std::optional<std::string>();

	std::string value = data;
	memset(data, 0, strlen(data));
	BNFreeString(data);
	return value;
}


bool CoreSecretsProvider::StoreData(const std::string& key, const std::string& data)
{
	return BNStoreSecretsProviderData(m_object, key.c_str(), data.c_str());
}


bool CoreSecretsProvider::DeleteData(const std::string& key)
{
	return BNDeleteSecretsProviderData(m_object, key.c_str());
}
