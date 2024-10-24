
#include "binaryninjaapi.h"

using namespace BinaryNinja;


#ifndef SHAREDCACHE_SHAREDCACHEWORKFLOW_H
#define SHAREDCACHE_SHAREDCACHEWORKFLOW_H


class SharedCacheWorkflow
{
public:
	static void ProcessOffImageCall(Ref<AnalysisContext> ctx, Ref<Function> func, Ref<MediumLevelILFunction> il, const MediumLevelILInstruction instr, ExprId exprIndex, bool applySymbolIfFoundToCurrentFunction = false);
	static void FixupStubs(Ref<AnalysisContext> ctx);
	static void Register();
};

#ifdef __cplusplus
extern "C" {
#endif
	void RegisterSharedCacheWorkflow();
#ifdef __cplusplus
}
#endif

#endif //SHAREDCACHE_SHAREDCACHEWORKFLOW_H
