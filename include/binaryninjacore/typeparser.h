#pragma once
#include "binaryninja_defs.h"
#include "qualifiedname.h"

extern "C" {
	struct BNPlatform;

	enum BNTypeParserErrorSeverity
	{
		IgnoredSeverity = 0,
		NoteSeverity = 1,
		RemarkSeverity = 2,
		WarningSeverity = 3,
		ErrorSeverity = 4,
		FatalSeverity = 5,
	};

	struct BNTypeParserError
	{
		BNTypeParserErrorSeverity severity;
		char* message;
		char* fileName;
		uint64_t line;
		uint64_t column;
	};

	struct BNType;

	struct BNParsedType
	{
		BNQualifiedName name;
		BNType* type;
		bool isUser;
	};

	struct BNTypeParserResult
	{
		BNParsedType* types;
		BNParsedType* variables;
		BNParsedType* functions;
		size_t typeCount, variableCount, functionCount;
	};

	struct BNQualifiedNameTypeAndId
	{
		BNQualifiedName name;
		char* id;
		BNType* type;
	};


	struct BNQualifiedNameList
	{
		BNQualifiedName* names;
		size_t count;
	};

	struct BNQualifiedNameAndType
	{
		BNQualifiedName name;
		BNType* type;
	};

	struct BNTypeParserCallbacks
	{
		void* context;
		bool (*preprocessSource)(void* ctxt,
			const char* source, const char* fileName, BNPlatform* platform,
			const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
			const char* const* options, size_t optionCount,
			const char* const* includeDirs, size_t includeDirCount,
			char** output, BNTypeParserError** errors, size_t* errorCount
		);
		bool (*parseTypesFromSource)(void* ctxt,
			const char* source, const char* fileName, BNPlatform* platform,
			const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
			const char* const* options, size_t optionCount,
			const char* const* includeDirs, size_t includeDirCount,
			const char* autoTypeSource, BNTypeParserResult* result,
			BNTypeParserError** errors, size_t* errorCount
		);
		bool (*parseTypeString)(void* ctxt,
			const char* source, BNPlatform* platform,
			const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
			BNQualifiedNameAndType* result,
			BNTypeParserError** errors, size_t* errorCount
		);
		void (*freeString)(void* ctxt, char* string);
		void (*freeResult)(void* ctxt, BNTypeParserResult* result);
		void (*freeErrorList)(void* ctxt, BNTypeParserError* errors, size_t errorCount);
	};

		// Source code processing
	BINARYNINJACOREAPI bool BNPreprocessSource(const char* source, const char* fileName, char** output, char** errors,
	    const char** includeDirs, size_t includeDirCount);
	BINARYNINJACOREAPI bool BNParseTypesFromSource(BNPlatform* platform, const char* source, const char* fileName,
	    BNTypeParserResult* result, char** errors, const char** includeDirs, size_t includeDirCount,
	    const char* autoTypeSource);
	BINARYNINJACOREAPI bool BNParseTypesFromSourceFile(BNPlatform* platform, const char* fileName,
	    BNTypeParserResult* result, char** errors, const char** includeDirs, size_t includeDirCount,
	    const char* autoTypeSource);

	struct BNTypeParser;
	BINARYNINJACOREAPI BNTypeParser* BNRegisterTypeParser(
		const char* name, BNTypeParserCallbacks* callbacks);
	BINARYNINJACOREAPI BNTypeParser** BNGetTypeParserList(size_t* count);
	BINARYNINJACOREAPI void BNFreeTypeParserList(BNTypeParser** parsers);
	BINARYNINJACOREAPI BNTypeParser* BNGetTypeParserByName(const char* name);

	BINARYNINJACOREAPI char* BNGetTypeParserName(BNTypeParser* parser);

	BINARYNINJACOREAPI bool BNTypeParserPreprocessSource(BNTypeParser* parser,
	    const char* source, const char* fileName, BNPlatform* platform,
	    const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
	    const char* const* options, size_t optionCount,
	    const char* const* includeDirs, size_t includeDirCount,
	    char** output, BNTypeParserError** errors, size_t* errorCount
	);
	BINARYNINJACOREAPI bool BNTypeParserParseTypesFromSource(BNTypeParser* parser,
	    const char* source, const char* fileName, BNPlatform* platform,
	    const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
	    const char* const* options, size_t optionCount,
	    const char* const* includeDirs, size_t includeDirCount,
	    const char* autoTypeSource, BNTypeParserResult* result,
	    BNTypeParserError** errors, size_t* errorCount
	);
	BINARYNINJACOREAPI bool BNTypeParserParseTypeString(BNTypeParser* parser,
	    const char* source, BNPlatform* platform,
	    const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
	    BNQualifiedNameAndType* result,
	    BNTypeParserError** errors, size_t* errorCount
	);

	struct BNBinaryView;
	BINARYNINJACOREAPI bool BNParseTypeString(BNBinaryView* view, const char* text, BNQualifiedNameAndType* result,
	    char** errors, BNQualifiedNameList* typesAllowRedefinition);
	BINARYNINJACOREAPI bool BNParseTypesString(BNBinaryView* view, const char* text, const char* const* options, size_t optionCount,
		const char* const* includeDirs, size_t includeDirCount, BNTypeParserResult* result, char** errors,
		BNQualifiedNameList* typesAllowRedefinition);

	BINARYNINJACOREAPI void BNFreeTypeParserResult(BNTypeParserResult* result);
	BINARYNINJACOREAPI void BNFreeTypeParserErrors(BNTypeParserError* errors, size_t count);

	BINARYNINJACOREAPI void BNFreeQualifiedNameAndType(BNQualifiedNameAndType* obj);
	BINARYNINJACOREAPI void BNFreeQualifiedNameAndTypeArray(BNQualifiedNameAndType* obj, size_t count);
}