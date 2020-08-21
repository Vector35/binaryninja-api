#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


DownloadInstance::DownloadInstance(DownloadProvider* provider)
{
	BNDownloadInstanceCallbacks cb;
	cb.context = this;
	cb.destroyInstance = DestroyInstanceCallback;
	cb.performRequest = PerformRequestCallback;
	cb.performCustomRequest = PerformCustomRequestCallback;
	cb.freeResponse = PerformFreeResponse;
	AddRefForRegistration();
	m_object = BNInitDownloadInstance(provider->GetObject(), &cb);
}


DownloadInstance::DownloadInstance(BNDownloadInstance* instance)
{
	m_object = instance;
}


void DownloadInstance::DestroyInstanceCallback(void* ctxt)
{
	DownloadInstance* instance = (DownloadInstance*)ctxt;
	instance->DestroyInstance();
}


int DownloadInstance::PerformRequestCallback(void* ctxt, const char* url)
{
	DownloadInstance* instance = (DownloadInstance*)ctxt;
	return instance->PerformRequest(url);
}


int DownloadInstance::PerformCustomRequestCallback(void* ctxt, const char* method, const char* url, uint64_t headerCount, const char* const* headerKeys, const char* const* headerValues, BNDownloadInstanceResponse** response)
{
	DownloadInstance* instance = (DownloadInstance*)ctxt;
	unordered_map<string, string> headers;
	for (uint64_t i = 0; i < headerCount; i ++)
	{
		headers[headerKeys[i]] = headerValues[i];
	}

	Response apiResponse;
	int status = instance->PerformCustomRequest(method, url, headers, apiResponse);

	char** keys = new char*[apiResponse.headers.size()];
	char** values = new char*[apiResponse.headers.size()];

	uint64_t i = 0;
	for (const auto& pair : apiResponse.headers)
	{
		keys[i] = BNAllocString(pair.first.c_str());
		values[i] = BNAllocString(pair.second.c_str());
		i ++;
	}

	*response = new BNDownloadInstanceResponse;
	(*response)->statusCode = apiResponse.statusCode;
	(*response)->headerCount = apiResponse.headers.size();
	(*response)->headerKeys = keys;
	(*response)->headerValues = values;

	return status;
}


void DownloadInstance::PerformFreeResponse(void* ctxt, BNDownloadInstanceResponse* response)
{
	for (uint64_t i = 0; i < response->headerCount; i ++)
	{
		BNFreeString(response->headerKeys[i]);
		BNFreeString(response->headerValues[i]);
	}

	delete [] response->headerKeys;
	delete [] response->headerValues;

	delete response;
}


uint64_t DownloadInstance::ReadDataCallback(uint8_t* data, uint64_t len)
{
	return BNReadDataForDownloadInstance(m_object, data, len);
}


uint64_t DownloadInstance::WriteDataCallback(uint8_t* data, uint64_t len)
{
	return BNWriteDataForDownloadInstance(m_object, data, len);
}


bool DownloadInstance::NotifyProgressCallback(uint64_t progress, uint64_t total)
{
	return BNNotifyProgressForDownloadInstance(m_object, progress, total);
}


void DownloadInstance::SetError(const string& error)
{
	BNSetErrorForDownloadInstance(m_object, error.c_str());
}


string DownloadInstance::GetError() const
{
	char* str = BNGetErrorForDownloadInstance(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


int DownloadInstance::PerformRequest(const string& url, BNDownloadInstanceOutputCallbacks* callbacks)
{
	return BNPerformDownloadRequest(m_object, url.c_str(), callbacks);
}


int DownloadInstance::PerformCustomRequest(const string& method, const string& url, const std::unordered_map<std::string, std::string>& headers, Response& response, BNDownloadInstanceInputOutputCallbacks* callbacks)
{
	const char** headerKeys = new const char*[headers.size()];
	const char** headerValues = new const char*[headers.size()];

	uint64_t i = 0;
	for (auto it = headers.begin(); it != headers.end(); ++it)
	{
		headerKeys[i] = it->first.c_str();
		headerValues[i] = it->second.c_str();
		i ++;
	}

	BNDownloadInstanceResponse* bnResponse;

	int result = BNPerformCustomRequest(m_object, method.c_str(), url.c_str(), headers.size(), headerKeys, headerValues, &bnResponse, callbacks);

	response.statusCode = bnResponse->statusCode;
	for (uint64_t i = 0; i < bnResponse->headerCount; i ++)
	{
		response.headers[bnResponse->headerKeys[i]] = bnResponse->headerValues[i];
	}

	BNFreeDownloadInstanceResponse(bnResponse);

	delete [] headerKeys;
	delete [] headerValues;

	return result;
}


void DownloadInstance::DestroyInstance()
{
	ReleaseForRegistration();
}


CoreDownloadInstance::CoreDownloadInstance(BNDownloadInstance* instance): DownloadInstance(instance)
{
}


int CoreDownloadInstance::PerformRequest(const std::string& url)
{
	(void)url;
	return -1;
}


int CoreDownloadInstance::PerformCustomRequest(const std::string& method, const std::string& url, const std::unordered_map<std::string, std::string>& headers, Response& response)
{
	(void)method;
	(void)url;
	(void)headers;
	response.statusCode = -1;
	return -1;
}


DownloadProvider::DownloadProvider(const string& name): m_nameForRegister(name)
{
}


DownloadProvider::DownloadProvider(BNDownloadProvider* provider)
{
	m_object = provider;
}


BNDownloadInstance* DownloadProvider::CreateInstanceCallback(void* ctxt)
{
	DownloadProvider* provider = (DownloadProvider*)ctxt;
	Ref<DownloadInstance> instance = provider->CreateNewInstance();
	return instance ? BNNewDownloadInstanceReference(instance->GetObject()) : nullptr;
}


vector<Ref<DownloadProvider>> DownloadProvider::GetList()
{
	size_t count;
	BNDownloadProvider** list = BNGetDownloadProviderList(&count);
	vector<Ref<DownloadProvider>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreDownloadProvider(list[i]));
	BNFreeDownloadProviderList(list);
	return result;
}


Ref<DownloadProvider> DownloadProvider::GetByName(const string& name)
{
	BNDownloadProvider* result = BNGetDownloadProviderByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreDownloadProvider(result);
}


void DownloadProvider::Register(DownloadProvider* provider)
{
	BNDownloadProviderCallbacks cb;
	cb.context = provider;
	cb.createInstance = CreateInstanceCallback;
	provider->m_object = BNRegisterDownloadProvider(provider->m_nameForRegister.c_str(), &cb);
}


CoreDownloadProvider::CoreDownloadProvider(BNDownloadProvider* provider): DownloadProvider(provider)
{
}


Ref<DownloadInstance> CoreDownloadProvider::CreateNewInstance()
{
	BNDownloadInstance* result = BNCreateDownloadProviderInstance(m_object);
	if (!result)
		return nullptr;
	return new CoreDownloadInstance(result);
}
