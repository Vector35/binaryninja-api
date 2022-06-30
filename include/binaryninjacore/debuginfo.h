#pragma once
#include "binaryninja_defs.h"

extern "C" {
	struct BNDebugInfoParser;
	struct BNDebugInfo;
	struct BNBinaryView;
	struct BNNameAndType;
	struct BNCallingConvention;
	struct BNPlatform;
	struct BNType;
	struct BNDataVariableAndName;

	struct BNDebugFunctionInfo
	{
		char* shortName;
		char* fullName;
		char* rawName;
		uint64_t address;
		BNType* returnType;
		char** parameterNames;
		BNType** parameterTypes;
		size_t parameterCount;
		bool variableParameters;
		BNCallingConvention* callingConvention;
		BNPlatform* platform;
	};

	BINARYNINJACOREAPI BNDebugInfoParser* BNRegisterDebugInfoParser(const char* name,
		bool (*isValid)(void*, BNBinaryView*), void (*parseInfo)(void*, BNDebugInfo*, BNBinaryView*), void* context);
	BINARYNINJACOREAPI void BNUnregisterDebugInfoParser(const char* rawName);
	BINARYNINJACOREAPI BNDebugInfoParser* BNGetDebugInfoParserByName(const char* name);
	BINARYNINJACOREAPI BNDebugInfoParser** BNGetDebugInfoParsers(size_t* count);
	BINARYNINJACOREAPI BNDebugInfoParser** BNGetDebugInfoParsersForView(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI char* BNGetDebugInfoParserName(BNDebugInfoParser* parser);
	BINARYNINJACOREAPI bool BNIsDebugInfoParserValidForView(BNDebugInfoParser* parser, BNBinaryView* view);
	BINARYNINJACOREAPI BNDebugInfo* BNParseDebugInfo(
		BNDebugInfoParser* parser, BNBinaryView* view, BNDebugInfo* existingDebugInfo);
	BINARYNINJACOREAPI BNDebugInfoParser* BNNewDebugInfoParserReference(BNDebugInfoParser* parser);
	BINARYNINJACOREAPI void BNFreeDebugInfoParserReference(BNDebugInfoParser* parser);
	BINARYNINJACOREAPI void BNFreeDebugInfoParserList(BNDebugInfoParser** parsers, size_t count);

	BINARYNINJACOREAPI BNDebugInfo* BNNewDebugInfoReference(BNDebugInfo* debugInfo);
	BINARYNINJACOREAPI void BNFreeDebugInfoReference(BNDebugInfo* debugInfo);
	BINARYNINJACOREAPI bool BNAddDebugType(
		BNDebugInfo* const debugInfo, const char* const name, const BNType* const type);
	BINARYNINJACOREAPI BNNameAndType* BNGetDebugTypes(
		BNDebugInfo* const debugInfo, const char* const name, size_t* count);
	BINARYNINJACOREAPI void BNFreeDebugTypes(BNNameAndType* types, size_t count);
	BINARYNINJACOREAPI bool BNAddDebugFunction(BNDebugInfo* const debugInfo, BNDebugFunctionInfo* func);
	BINARYNINJACOREAPI BNDebugFunctionInfo* BNGetDebugFunctions(
		BNDebugInfo* const debugInfo, const char* const name, size_t* count);
	BINARYNINJACOREAPI void BNFreeDebugFunctions(BNDebugFunctionInfo* functions, size_t count);
	BINARYNINJACOREAPI bool BNAddDebugDataVariable(
		BNDebugInfo* const debugInfo, uint64_t address, const BNType* const type, const char* name);
	// DebugInfo
	BINARYNINJACOREAPI BNDataVariableAndName* BNGetDebugDataVariables(
	    BNDebugInfo* const debugInfo, const char* const name, size_t* count);
	BINARYNINJACOREAPI void BNFreeDataVariablesAndName(BNDataVariableAndName* vars, size_t count);
}