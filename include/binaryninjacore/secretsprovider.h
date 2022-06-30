#pragma once

#include "binaryninja_defs.h"

extern "C" {
	struct BNSecretsProvider;
	struct BNSecretsProviderCallbacks
	{
		void* context;
		bool (*hasData)(void* ctxt, const char* key);
		char* (*getData)(void* ctxt, const char* key);
		bool (*storeData)(void* ctxt, const char* key, const char* data);
		bool (*deleteData)(void* ctxt, const char* key);
	};

	// Secrets providers
	BINARYNINJACOREAPI BNSecretsProvider* BNRegisterSecretsProvider(
		const char* name, BNSecretsProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNSecretsProvider** BNGetSecretsProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeSecretsProviderList(BNSecretsProvider** providers);
	BINARYNINJACOREAPI BNSecretsProvider* BNGetSecretsProviderByName(const char* name);

	BINARYNINJACOREAPI char* BNGetSecretsProviderName(BNSecretsProvider* provider);

	BINARYNINJACOREAPI bool BNSecretsProviderHasData(BNSecretsProvider* provider, const char* key);
	BINARYNINJACOREAPI char* BNGetSecretsProviderData(BNSecretsProvider* provider, const char* key);
	BINARYNINJACOREAPI bool BNStoreSecretsProviderData(BNSecretsProvider* provider, const char* key, const char* data);
	BINARYNINJACOREAPI bool BNDeleteSecretsProviderData(BNSecretsProvider* provider, const char* key);

}