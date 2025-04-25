#include "binaryninjaapi.h"
#include "binaryninjacore.h"

using namespace BinaryNinja;

extern "C" {
	BN_DECLARE_CORE_ABI_VERSION
	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		return BNArchitectureSetDefaultAnalyzeBasicBlocksCallback((void *)Architecture::DefaultAnalyzeBasicBlocksCallback);
	}
}
