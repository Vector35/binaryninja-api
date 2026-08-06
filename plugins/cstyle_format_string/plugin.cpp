#include "cstyleformatstringresolutionprovider.h"

using namespace BinaryNinja;

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_EDITION
	bool CStyleFormatStringPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		RegisterCStyleFormatStringResolutionProvider();
		return true;
	}
}
