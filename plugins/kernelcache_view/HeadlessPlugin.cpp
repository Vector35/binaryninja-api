#include <binaryninjaapi.h>
#include "KernelCacheView.h"
#include "transformers/KernelCacheTransforms.h"
#include "workflow/KernelCacheWorkflow.h"

#ifdef __cplusplus
extern "C" {
#endif
#ifdef __cplusplus
}
#endif

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		KernelCacheViewType::Register();
		RegisterTransformers();
		RegisterKernelCacheWorkflow();
		return true;
	}
}