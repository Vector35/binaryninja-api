#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


class DecreeX86Platform: public Platform
{
public:
	DecreeX86Platform(Architecture* arch): Platform(arch, "decree-x86")
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("cdecl");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
		}

		cc = arch->GetCallingConventionByName("regparm");
		if (cc)
			RegisterFastcallCallingConvention(cc);

		cc = arch->GetCallingConventionByName("stdcall");
		if (cc)
			RegisterStdcallCallingConvention(cc);

		cc = arch->GetCallingConventionByName("linux-syscall");
		if (cc)
			SetSystemCallConvention(cc);
	}
};


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_EDITION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("arch_x86");
		AddOptionalPluginDependency("view_elf");
	}
#endif

#ifdef DEMO_EDITION
	bool DecreePluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		Ref<Architecture> x86 = Architecture::GetByName("x86");
		if (x86)
		{
			Ref<Platform> platform;

			platform = new DecreeX86Platform(x86);
			Platform::Register("decree", platform);
			BinaryViewType::RegisterPlatform("ELF", 'C', x86, platform);
		}

		return true;
	}
}
