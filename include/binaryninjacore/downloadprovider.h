#pragma once

#include "binaryninja_defs.h"

extern "C" {
	struct BNDownloadInstance;
	struct BNDownloadProvider;

	struct BNDownloadInstanceResponse
	{
		uint16_t statusCode;
		uint64_t headerCount;
		char** headerKeys;
		char** headerValues;
	};

	struct BNDownloadInstanceInputOutputCallbacks
	{
		int64_t (*readCallback)(uint8_t* data, uint64_t len, void* ctxt);
		void* readContext;
		uint64_t (*writeCallback)(uint8_t* data, uint64_t len, void* ctxt);
		void* writeContext;
		bool (*progressCallback)(void* ctxt, uint64_t progress, uint64_t total);
		void* progressContext;
	};

	struct BNDownloadInstanceOutputCallbacks
	{
		uint64_t (*writeCallback)(uint8_t* data, uint64_t len, void* ctxt);
		void* writeContext;
		bool (*progressCallback)(void* ctxt, uint64_t progress, uint64_t total);
		void* progressContext;
	};

	struct BNDownloadInstanceCallbacks
	{
		void* context;
		void (*destroyInstance)(void* ctxt);
		int (*performRequest)(void* ctxt, const char* url);
		int (*performCustomRequest)(void* ctxt, const char* method, const char* url, uint64_t headerCount,
			const char* const* headerKeys, const char* const* headerValues, BNDownloadInstanceResponse** response);
		void (*freeResponse)(void* ctxt, BNDownloadInstanceResponse* response);
	};

	struct BNDownloadProviderCallbacks
	{
		void* context;
		BNDownloadInstance* (*createInstance)(void* ctxt);
	};

	// Download providers
	BINARYNINJACOREAPI BNDownloadProvider* BNRegisterDownloadProvider(
		const char* name, BNDownloadProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNDownloadProvider** BNGetDownloadProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeDownloadProviderList(BNDownloadProvider** providers);
	BINARYNINJACOREAPI BNDownloadProvider* BNGetDownloadProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetDownloadProviderName(BNDownloadProvider* provider);
	BINARYNINJACOREAPI BNDownloadInstance* BNCreateDownloadProviderInstance(BNDownloadProvider* provider);

	BINARYNINJACOREAPI BNDownloadInstance* BNInitDownloadInstance(
		BNDownloadProvider* provider, BNDownloadInstanceCallbacks* callbacks);
	BINARYNINJACOREAPI BNDownloadInstance* BNNewDownloadInstanceReference(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNFreeDownloadInstance(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNFreeDownloadInstanceResponse(BNDownloadInstanceResponse* response);
	BINARYNINJACOREAPI int BNPerformDownloadRequest(
		BNDownloadInstance* instance, const char* url, BNDownloadInstanceOutputCallbacks* callbacks);
	BINARYNINJACOREAPI int BNPerformCustomRequest(BNDownloadInstance* instance, const char* method, const char* url,
		uint64_t headerCount, const char* const* headerKeys, const char* const* headerValues,
		BNDownloadInstanceResponse** response, BNDownloadInstanceInputOutputCallbacks* callbacks);
	BINARYNINJACOREAPI int64_t BNReadDataForDownloadInstance(BNDownloadInstance* instance, uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI uint64_t BNWriteDataForDownloadInstance(
		BNDownloadInstance* instance, uint8_t* data, uint64_t len);
	BINARYNINJACOREAPI bool BNNotifyProgressForDownloadInstance(
		BNDownloadInstance* instance, uint64_t progress, uint64_t total);
	BINARYNINJACOREAPI char* BNGetErrorForDownloadInstance(BNDownloadInstance* instance);
	BINARYNINJACOREAPI void BNSetErrorForDownloadInstance(BNDownloadInstance* instance, const char* error);

}