#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


DownloadInstance::DownloadInstance(DownloadProvider* provider)
{
	BNDownloadInstanceCallbacks cb;
	cb.context = this;
	cb.destroyInstance = DestroyInstanceCallback;
	cb.performRequest = PerformRequestCallback;
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
