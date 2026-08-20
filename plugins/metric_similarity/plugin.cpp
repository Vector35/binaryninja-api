#include <binaryninjaapi.h>

#include "resolver.h"

using namespace BinaryNinja;

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_EDITION
	bool MetricSimilarityPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		SimilaritySessionResolverType::Register(new MetricResolverType());
		return true;
	}
}
