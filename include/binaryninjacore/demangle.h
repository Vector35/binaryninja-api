#pragma once

#include "binaryninja_defs.h"

extern "C" {
	struct BNArchitecture;
	struct BNType;
	struct BNBinaryView;

	// Demangler
	BINARYNINJACOREAPI bool BNDemangleMS(BNArchitecture* arch, const char* mangledName, BNType** outType,
		char*** outVarName, size_t* outVarNameElements, const bool simplify);
	BINARYNINJACOREAPI bool BNDemangleMSWithOptions(BNArchitecture* arch, const char* mangledName, BNType** outType,
		char*** outVarName, size_t* outVarNameElements, const BNBinaryView* const view);

	BINARYNINJACOREAPI bool BNIsGNU3MangledString(const char* mangledName);
	BINARYNINJACOREAPI bool BNDemangleGNU3(BNArchitecture* arch, const char* mangledName, BNType** outType,
		char*** outVarName, size_t* outVarNameElements, const bool simplify);
	BINARYNINJACOREAPI bool BNDemangleGNU3WithOptions(BNArchitecture* arch, const char* mangledName, BNType** outType,
		char*** outVarName, size_t* outVarNameElements, const BNBinaryView* const view);
	BINARYNINJACOREAPI void BNFreeDemangledName(char*** name, size_t nameElements);

	BINARYNINJACOREAPI void BNRustFreeString(const char* const);
	BINARYNINJACOREAPI void BNRustFreeStringArray(const char** const, uint64_t);
	BINARYNINJACOREAPI char** BNRustSimplifyStrToFQN(const char* const, bool);
	BINARYNINJACOREAPI char* BNRustSimplifyStrToStr(const char* const);
}