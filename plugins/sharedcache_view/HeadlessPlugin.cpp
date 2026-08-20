#include <binaryninjaapi.h>
#include "SharedCacheView.h"

#ifdef __cplusplus
extern "C"
{
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
		SharedCacheViewType::Register();
		RegisterSharedCacheWorkflow();
		return true;
	}
}