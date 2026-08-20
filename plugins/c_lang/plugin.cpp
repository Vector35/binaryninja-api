#include "binaryninjaapi.h"
#include "pseudoc.h"
#include "pseudoobjc.h"

using namespace BinaryNinja;

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_EDITION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}
#endif

#ifdef DEMO_EDITION
	bool PseudoCPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		LanguageRepresentationFunctionType* type = new PseudoCFunctionType();
		LanguageRepresentationFunctionType::Register(type);

		type = new PseudoObjCFunctionType();
		LanguageRepresentationFunctionType::Register(type);
		return true;
	}
}
