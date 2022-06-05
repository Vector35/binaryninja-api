#pragma once

#include "binaryninja_defs.h"

extern "C" {
	struct BNWebsocketProvider;
	struct BNWebsocketClient;

	struct BNWebsocketClientOutputCallbacks
	{
		void* context;
		bool (*connectedCallback)(void* ctxt);
		void (*disconnectedCallback)(void* ctxt);
		void (*errorCallback)(const char* msg, void* ctxt);
		bool (*readCallback)(uint8_t* data, uint64_t len, void* ctxt);
	};

	struct BNWebsocketClientCallbacks
	{
		void* context;
		void (*destroyClient)(void* ctxt);
		bool (*connect)(void* ctxt, const char* host, uint64_t headerCount, const char* const* headerKeys,
			const char* const* headerValues);
		bool (*write)(const uint8_t* data, uint64_t len, void* ctxt);
		bool (*disconnect)(void* ctxt);
	};

	struct BNWebsocketProviderCallbacks
	{
		void* context;
		BNWebsocketClient* (*createClient)(void* ctxt);
	};

	// Websocket providers
	BINARYNINJACOREAPI BNWebsocketProvider* BNRegisterWebsocketProvider(
		const char* name, BNWebsocketProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNWebsocketProvider** BNGetWebsocketProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeWebsocketProviderList(BNWebsocketProvider** providers);
	BINARYNINJACOREAPI BNWebsocketProvider* BNGetWebsocketProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetWebsocketProviderName(BNWebsocketProvider* provider);
	BINARYNINJACOREAPI BNWebsocketClient* BNCreateWebsocketProviderClient(BNWebsocketProvider* provider);

	BINARYNINJACOREAPI BNWebsocketClient* BNInitWebsocketClient(
		BNWebsocketProvider* provider, BNWebsocketClientCallbacks* callbacks);
	BINARYNINJACOREAPI BNWebsocketClient* BNNewWebsocketClientReference(BNWebsocketClient* client);
	BINARYNINJACOREAPI void BNFreeWebsocketClient(BNWebsocketClient* client);
	BINARYNINJACOREAPI bool BNConnectWebsocketClient(BNWebsocketClient* client, const char* url, uint64_t headerCount,
		const char* const* headerKeys, const char* const* headerValues, BNWebsocketClientOutputCallbacks* callbacks);
	BINARYNINJACOREAPI bool BNNotifyWebsocketClientConnect(BNWebsocketClient* client);
	BINARYNINJACOREAPI void BNNotifyWebsocketClientDisconnect(BNWebsocketClient* client);
	BINARYNINJACOREAPI void BNNotifyWebsocketClientError(BNWebsocketClient* client, const char* msg);
	BINARYNINJACOREAPI bool BNNotifyWebsocketClientReadData(BNWebsocketClient* client, uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI uint64_t BNWriteWebsocketClientData(
		BNWebsocketClient* client, const uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI bool BNDisconnectWebsocketClient(BNWebsocketClient* client);
}