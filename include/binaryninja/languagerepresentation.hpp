#pragma once
#include "binaryninjacore/languagerepresentation.h"
#include "refcount.hpp"

namespace BinaryNinja {
	class Architecture;
	class Function;

	class LanguageRepresentationFunction :
	    public CoreRefCountObject<BNLanguageRepresentationFunction, BNNewLanguageRepresentationFunctionReference,
	        BNFreeLanguageRepresentationFunction>
	{
	  public:
		LanguageRepresentationFunction(Architecture* arch, Function* func = nullptr);
		LanguageRepresentationFunction(BNLanguageRepresentationFunction* func);
	};
}