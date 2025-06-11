#include <binaryninjaapi.h>
#include "KCView.h"
#include "KernelCache.h"

#ifdef __cplusplus
extern "C" {
#endif
	// extern void RegisterSharedCacheWorkflow();
#ifdef __cplusplus
}
#endif

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		InitKernelcache();
		// RegisterSharedCacheWorkflow();
		return true;
	}
}