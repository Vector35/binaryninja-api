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

#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


WebsocketClient::WebsocketClient(WebsocketProvider* provider)
{
	BNWebsocketClientCallbacks cb;
	cb.context = this;
	cb.destroyClient = DestroyClientCallback;
	cb.connect = ConnectCallback;
	cb.write = WriteCallback;
	cb.disconnect = DisconnectCallback;
	AddRefForRegistration();
	m_object = BNInitWebsocketClient(provider->GetObject(), &cb);
}


WebsocketClient::WebsocketClient(BNWebsocketClient* client)
{
	m_object = client;
}


void WebsocketClient::DestroyClientCallback(void* ctxt)
{
	WebsocketClient* client = (WebsocketClient*)ctxt;
	client->DestroyClient();
}


bool WebsocketClient::ConnectCallback(
    void* ctxt, const char* host, uint64_t headerCount, const char* const* headerKeys, const char* const* headerValues)
{
	unordered_map<string, string> headers;
	for (uint64_t i = 0; i < headerCount; i++)
	{
		headers[headerKeys[i]] = headerValues[i];
	}

	WebsocketClient* client = (WebsocketClient*)ctxt;
	return client->Connect(host, headers);
}


bool WebsocketClient::DisconnectCallback(void* ctxt)
{
	WebsocketClient* client = (WebsocketClient*)ctxt;
	return client->Disconnect();
}


void WebsocketClient::ErrorCallback(const char* msg, void* ctxt)
{
	WebsocketClient* client = (WebsocketClient*)ctxt;
	BNNotifyWebsocketClientError(client->m_object, msg);
}


bool WebsocketClient::WriteCallback(const uint8_t* data, uint64_t len, void* ctxt)
{
	WebsocketClient* client = (WebsocketClient*)ctxt;
	return client->Write(vector<uint8_t>(data, data + len));
}


bool WebsocketClient::ReadData(uint8_t* data, uint64_t len)
{
	return BNNotifyWebsocketClientReadData(m_object, data, len);
}


bool WebsocketClient::Connect(const std::string& host, const std::unordered_map<std::string, std::string>& headers,
    BNWebsocketClientOutputCallbacks* callbacks)
{
	const char** headerKeys = new const char*[headers.size()];
	const char** headerValues = new const char*[headers.size()];

	uint64_t i = 0;
	for (auto it = headers.begin(); it != headers.end(); ++it)
	{
		headerKeys[i] = it->first.c_str();
		headerValues[i] = it->second.c_str();
		i++;
	}

	bool result = BNConnectWebsocketClient(m_object, host.c_str(), headers.size(), headerKeys, headerValues, callbacks);

	delete[] headerKeys;
	delete[] headerValues;

	return result;
}


void WebsocketClient::DestroyClient()
{
	ReleaseForRegistration();
}


CoreWebsocketClient::CoreWebsocketClient(BNWebsocketClient* client) : WebsocketClient(client) {}


bool CoreWebsocketClient::Connect(const std::string& host, const std::unordered_map<std::string, std::string>& headers)
{
	(void)host;
	(void)headers;
	return false;
}


bool CoreWebsocketClient::Write(const std::vector<uint8_t>& data)
{
	return BNWriteWebsocketClientData(m_object, data.data(), data.size());
}


bool CoreWebsocketClient::Disconnect()
{
	return BNDisconnectWebsocketClient(m_object);
}


WebsocketProvider::WebsocketProvider(const string& name) : m_nameForRegister(name) {}


WebsocketProvider::WebsocketProvider(BNWebsocketProvider* provider)
{
	m_object = provider;
}


BNWebsocketClient* WebsocketProvider::CreateClientCallback(void* ctxt)
{
	WebsocketProvider* provider = (WebsocketProvider*)ctxt;
	Ref<WebsocketClient> client = provider->CreateNewClient();
	return client ? BNNewWebsocketClientReference(client->GetObject()) : nullptr;
}


vector<Ref<WebsocketProvider>> WebsocketProvider::GetList()
{
	size_t count;
	BNWebsocketProvider** list = BNGetWebsocketProviderList(&count);
	vector<Ref<WebsocketProvider>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreWebsocketProvider(list[i]));
	BNFreeWebsocketProviderList(list);
	return result;
}


Ref<WebsocketProvider> WebsocketProvider::GetByName(const string& name)
{
	BNWebsocketProvider* result = BNGetWebsocketProviderByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreWebsocketProvider(result);
}


void WebsocketProvider::Register(WebsocketProvider* provider)
{
	BNWebsocketProviderCallbacks cb;
	cb.context = provider;
	cb.createClient = CreateClientCallback;
	provider->m_object = BNRegisterWebsocketProvider(provider->m_nameForRegister.c_str(), &cb);
}


CoreWebsocketProvider::CoreWebsocketProvider(BNWebsocketProvider* provider) : WebsocketProvider(provider) {}


Ref<WebsocketClient> CoreWebsocketProvider::CreateNewClient()
{
	BNWebsocketClient* result = BNCreateWebsocketProviderClient(m_object);

	if (!result)
		return nullptr;
	return new CoreWebsocketClient(result);
}
