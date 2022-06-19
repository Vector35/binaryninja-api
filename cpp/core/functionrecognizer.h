#pragma once
#include "core/binaryninja_defs.h"

extern "C" {
	struct BNBinaryView;
	struct BNFunction;
	struct BNLowLevelILFunction;
	struct BNMediumLevelILFunction;

	struct BNFunctionRecognizer
	{
		void* context;
		bool (*recognizeLowLevelIL)(void* ctxt, BNBinaryView* data, BNFunction* func, BNLowLevelILFunction* il);
		bool (*recognizeMediumLevelIL)(void* ctxt, BNBinaryView* data, BNFunction* func, BNMediumLevelILFunction* il);
	};

	BINARYNINJACOREAPI void BNRegisterGlobalFunctionRecognizer(BNFunctionRecognizer* rec);

}