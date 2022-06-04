#pragma once
#include "binaryninja_defs.h"

extern "C" {
	struct BNArchitecture;
	struct BNFunction;
	struct BNLanguageRepresentationFunction;

	// Language Representation
	BINARYNINJACOREAPI BNLanguageRepresentationFunction* BNCreateLanguageRepresentationFunction(
	    BNArchitecture* arch, BNFunction* func);
	BINARYNINJACOREAPI BNLanguageRepresentationFunction* BNNewLanguageRepresentationFunctionReference(
	    BNLanguageRepresentationFunction* func);
	BINARYNINJACOREAPI void BNFreeLanguageRepresentationFunction(BNLanguageRepresentationFunction* func);
	BINARYNINJACOREAPI BNFunction* BNGetLanguageRepresentationOwnerFunction(BNLanguageRepresentationFunction* func);

}