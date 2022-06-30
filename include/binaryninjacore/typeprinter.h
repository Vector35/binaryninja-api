#pragma once
#include "binaryninja_defs.h"
#include "qualifiedname.h"
#include "type.h"

extern "C" {
    struct BNTypePrinter;

	struct BNTypePrinterCallbacks
	{
		void* context;
		bool (*getTypeTokens)(void* ctxt, BNType* type, BNPlatform* platform,
			BNQualifiedName* name, uint8_t baseConfidence, BNTokenEscapingType escaping,
			BNInstructionTextToken** result, size_t* resultCount);
		bool (*getTypeTokensBeforeName)(void* ctxt, BNType* type,
			BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
			BNTokenEscapingType escaping, BNInstructionTextToken** result,
			size_t* resultCount);
		bool (*getTypeTokensAfterName)(void* ctxt, BNType* type,
			BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
			BNTokenEscapingType escaping, BNInstructionTextToken** result,
			size_t* resultCount);
		bool (*getTypeString)(void* ctxt, BNType* type, BNPlatform* platform,
			BNQualifiedName* name, BNTokenEscapingType escaping, char** result);
		bool (*getTypeStringBeforeName)(void* ctxt, BNType* type,
			BNPlatform* platform, BNTokenEscapingType escaping, char** result);
		bool (*getTypeStringAfterName)(void* ctxt, BNType* type,
			BNPlatform* platform, BNTokenEscapingType escaping, char** result);
		bool (*getTypeLines)(void* ctxt, BNType* type, BNBinaryView* data,
			BNQualifiedName* name, int lineWidth, bool collapsed,
			BNTokenEscapingType escaping, BNTypeDefinitionLine** result, size_t* resultCount);
		void (*freeTokens)(void* ctxt, BNInstructionTextToken* tokens, size_t count);
		void (*freeString)(void* ctxt, char* string);
		void (*freeLines)(void* ctxt, BNTypeDefinitionLine* lines, size_t count);
	};

	BINARYNINJACOREAPI BNTypePrinter* BNRegisterTypePrinter(
		const char* name, BNTypePrinterCallbacks* callbacks);
	BINARYNINJACOREAPI BNTypePrinter** BNGetTypePrinterList(size_t* count);
	BINARYNINJACOREAPI void BNFreeTypePrinterList(BNTypePrinter** printers);
	BINARYNINJACOREAPI BNTypePrinter* BNGetTypePrinterByName(const char* name);

	BINARYNINJACOREAPI char* BNGetTypePrinterName(BNTypePrinter* printer);

	BINARYNINJACOREAPI bool BNGetTypePrinterTypeTokens(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, BNQualifiedName* name,
		uint8_t baseConfidence, BNTokenEscapingType escaping,
		BNInstructionTextToken** result, size_t* resultCount);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeTokensBeforeName(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
		BNTokenEscapingType escaping, BNInstructionTextToken** result,
		size_t* resultCount);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeTokensAfterName(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
		BNTokenEscapingType escaping, BNInstructionTextToken** result,
		size_t* resultCount);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeString(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, BNQualifiedName* name,
		BNTokenEscapingType escaping, char** result);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeStringBeforeName(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, BNTokenEscapingType escaping, char** result);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeStringAfterName(BNTypePrinter* printer,
		BNType* type, BNPlatform* platform, BNTokenEscapingType escaping, char** result);
	BINARYNINJACOREAPI bool BNGetTypePrinterTypeLines(BNTypePrinter* printer,
		BNType* type, BNBinaryView* data,
		BNQualifiedName* name, int lineWidth, bool collapsed,
		BNTokenEscapingType escaping, BNTypeDefinitionLine** result, size_t* resultCount);
}