#pragma once
#include "binaryninja_defs.h"

extern "C" {
	struct BNBasicBlock;
	struct BNBinaryView;
	struct BNFunction;
	struct BNScriptingInstance;
	struct BNScriptingProvider;

	enum BNScriptingProviderInputReadyState
	{
		NotReadyForInput,
		ReadyForScriptExecution,
		ReadyForScriptProgramInput
	};

	enum BNScriptingProviderExecuteResult
	{
		InvalidScriptInput,
		IncompleteScriptInput,
		SuccessfulScriptExecution,
		ScriptExecutionCancelled
	};


	struct BNScriptingInstanceCallbacks
	{
		void* context;
		void (*destroyInstance)(void* ctxt);
		void (*externalRefTaken)(void* ctxt);
		void (*externalRefReleased)(void* ctxt);
		BNScriptingProviderExecuteResult (*executeScriptInput)(void* ctxt, const char* input);
		void (*cancelScriptInput)(void* ctxt);
		void (*setCurrentBinaryView)(void* ctxt, BNBinaryView* view);
		void (*setCurrentFunction)(void* ctxt, BNFunction* func);
		void (*setCurrentBasicBlock)(void* ctxt, BNBasicBlock* block);
		void (*setCurrentAddress)(void* ctxt, uint64_t addr);
		void (*setCurrentSelection)(void* ctxt, uint64_t begin, uint64_t end);
		char* (*completeInput)(void* ctxt, const char* text, uint64_t state);
		void (*stop)(void* ctxt);
	};

	struct BNScriptingProviderCallbacks
	{
		void* context;
		BNScriptingInstance* (*createInstance)(void* ctxt);
		bool (*loadModule)(void* ctxt, const char* repoPath, const char* pluginPath, bool force);
		bool (*installModules)(void* ctxt, const char* modules);
	};

	struct BNScriptingOutputListener
	{
		void* context;
		void (*output)(void* ctxt, const char* text);
		void (*error)(void* ctxt, const char* text);
		void (*inputReadyStateChanged)(void* ctxt, BNScriptingProviderInputReadyState state);
	};

	// Scripting providers
	BINARYNINJACOREAPI BNScriptingProvider* BNRegisterScriptingProvider(
		const char* name, const char* apiName, BNScriptingProviderCallbacks* callbacks);
	BINARYNINJACOREAPI BNScriptingProvider** BNGetScriptingProviderList(size_t* count);
	BINARYNINJACOREAPI void BNFreeScriptingProviderList(BNScriptingProvider** providers);
	BINARYNINJACOREAPI BNScriptingProvider* BNGetScriptingProviderByName(const char* name);
	BINARYNINJACOREAPI BNScriptingProvider* BNGetScriptingProviderByAPIName(const char* name);

	BINARYNINJACOREAPI char* BNGetScriptingProviderName(BNScriptingProvider* provider);
	BINARYNINJACOREAPI char* BNGetScriptingProviderAPIName(BNScriptingProvider* provider);
	BINARYNINJACOREAPI BNScriptingInstance* BNCreateScriptingProviderInstance(BNScriptingProvider* provider);
	BINARYNINJACOREAPI bool BNLoadScriptingProviderModule(
		BNScriptingProvider* provider, const char* repository, const char* module, bool force);
	BINARYNINJACOREAPI bool BNInstallScriptingProviderModules(BNScriptingProvider* provider, const char* modules);

	BINARYNINJACOREAPI BNScriptingInstance* BNInitScriptingInstance(
		BNScriptingProvider* provider, BNScriptingInstanceCallbacks* callbacks);
	BINARYNINJACOREAPI BNScriptingInstance* BNNewScriptingInstanceReference(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNFreeScriptingInstance(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNNotifyOutputForScriptingInstance(BNScriptingInstance* instance, const char* text);
	BINARYNINJACOREAPI void BNNotifyErrorForScriptingInstance(BNScriptingInstance* instance, const char* text);
	BINARYNINJACOREAPI void BNNotifyInputReadyStateForScriptingInstance(
		BNScriptingInstance* instance, BNScriptingProviderInputReadyState state);

	BINARYNINJACOREAPI void BNRegisterScriptingInstanceOutputListener(
		BNScriptingInstance* instance, BNScriptingOutputListener* callbacks);
	BINARYNINJACOREAPI void BNUnregisterScriptingInstanceOutputListener(
		BNScriptingInstance* instance, BNScriptingOutputListener* callbacks);

	BINARYNINJACOREAPI const char* BNGetScriptingInstanceDelimiters(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNSetScriptingInstanceDelimiters(BNScriptingInstance* instance, const char* delimiters);

	BINARYNINJACOREAPI BNScriptingProviderInputReadyState BNGetScriptingInstanceInputReadyState(
		BNScriptingInstance* instance);
	BINARYNINJACOREAPI BNScriptingProviderExecuteResult BNExecuteScriptInput(
		BNScriptingInstance* instance, const char* input);
	BINARYNINJACOREAPI void BNCancelScriptInput(BNScriptingInstance* instance);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentBinaryView(BNScriptingInstance* instance, BNBinaryView* view);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentFunction(BNScriptingInstance* instance, BNFunction* func);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentBasicBlock(BNScriptingInstance* instance, BNBasicBlock* block);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentAddress(BNScriptingInstance* instance, uint64_t addr);
	BINARYNINJACOREAPI void BNSetScriptingInstanceCurrentSelection(
		BNScriptingInstance* instance, uint64_t begin, uint64_t end);
	BINARYNINJACOREAPI char* BNScriptingInstanceCompleteInput(
		BNScriptingInstance* instance, const char* text, uint64_t state);
	BINARYNINJACOREAPI void BNStopScriptingInstance(BNScriptingInstance* instance);
}