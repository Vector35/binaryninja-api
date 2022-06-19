#pragma once
#include "core/binaryninja_defs.h"

extern "C" {
	struct BNAnalysisContext;
	struct BNLowLevelILFunction;
	struct BNMediumLevelILFunction;
	struct BNHighLevelILFunction;
	struct BNFunction;
	struct BNBasicBlock;
    struct BNActivity;

	// Analysis Context
	BINARYNINJACOREAPI BNAnalysisContext* BNCreateAnalysisContext(void);
	BINARYNINJACOREAPI BNAnalysisContext* BNNewAnalysisContextReference(BNAnalysisContext* analysisContext);
	BINARYNINJACOREAPI void BNFreeAnalysisContext(BNAnalysisContext* analysisContext);
	BINARYNINJACOREAPI BNFunction* BNAnalysisContextGetFunction(BNAnalysisContext* analysisContext);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNAnalysisContextGetLowLevelILFunction(BNAnalysisContext* analysisContext);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNAnalysisContextGetMediumLevelILFunction(
		BNAnalysisContext* analysisContext);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNAnalysisContextGetHighLevelILFunction(
		BNAnalysisContext* analysisContext);

	BINARYNINJACOREAPI void BNSetBasicBlockList(
		BNAnalysisContext* analysisContext, BNBasicBlock** basicBlocks, size_t count);
	BINARYNINJACOREAPI void BNSetLiftedILFunction(BNAnalysisContext* analysisContext, BNLowLevelILFunction* liftedIL);
	BINARYNINJACOREAPI void BNSetLowLevelILFunction(
		BNAnalysisContext* analysisContext, BNLowLevelILFunction* lowLevelIL);
	BINARYNINJACOREAPI void BNSetMediumLevelILFunction(
		BNAnalysisContext* analysisContext, BNMediumLevelILFunction* mediumLevelIL);
	BINARYNINJACOREAPI void BNSetHighLevelILFunction(
		BNAnalysisContext* analysisContext, BNHighLevelILFunction* highLevelIL);
	BINARYNINJACOREAPI bool BNAnalysisContextInform(BNAnalysisContext* analysisContext, const char* request);

	// Activity
	BINARYNINJACOREAPI BNActivity* BNCreateActivity(
	    const char* name, void* ctxt, void (*action)(void*, BNAnalysisContext*));
	BINARYNINJACOREAPI BNActivity* BNNewActivityReference(BNActivity* activity);
	BINARYNINJACOREAPI void BNFreeActivity(BNActivity* activity);

	BINARYNINJACOREAPI char* BNActivityGetName(BNActivity* activity);
}