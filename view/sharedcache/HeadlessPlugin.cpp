#include <binaryninjaapi.h>
#include "DSCView.h"
#include "SharedCache.h"

#ifdef __cplusplus
extern "C" {
#endif
	extern void RegisterSharedCacheWorkflow();
#ifdef __cplusplus
}
#endif

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		InitDSCViewType();
		RegisterSharedCacheWorkflow();
		return true;
	}
}