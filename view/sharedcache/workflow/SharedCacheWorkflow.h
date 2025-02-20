#ifndef SHAREDCACHE_SHAREDCACHEWORKFLOW_H
#define SHAREDCACHE_SHAREDCACHEWORKFLOW_H

#include "binaryninjaapi.h"
#include "view/sharedcache/api/sharedcacheapi.h"

class SharedCacheWorkflow
{
public:
	static void ProcessOffImageCall(Ref<AnalysisContext> ctx, Ref<SharedCacheAPI::SharedCache> cache, Ref<Function> func, Ref<MediumLevelILFunction> il, const MediumLevelILInstruction instr, bool applySymbolIfFoundToCurrentFunction = false);
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
