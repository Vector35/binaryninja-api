#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


class MacX86Platform: public Platform
{
public:
	MacX86Platform(Architecture* arch): Platform(arch, "mac-x86")
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
	}
};


class MacX64Platform: public Platform
{
public:
	MacX64Platform(Architecture* arch): Platform(arch, "mac-x86_64")
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("sysv");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}
	}
};


class MacArmv7Platform: public Platform
{
public:
	MacArmv7Platform(Architecture* arch, const std::string& name): Platform(arch, name)
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("cdecl");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}
	}
};


class MacArm64Platform: public Platform
{
public:
	MacArm64Platform(Architecture* arch): Platform(arch, "mac-aarch64")
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("apple-arm64");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}
	}
};


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_VERSION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("arch_x86");
		AddOptionalPluginDependency("arch_armv7");
		AddOptionalPluginDependency("arch_arm64");
		AddOptionalPluginDependency("view_macho");
	}
#endif

#ifdef DEMO_VERSION
	bool MacPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		Ref<Architecture> x86 = Architecture::GetByName("x86");
		if (x86)
		{
			Ref<Platform> platform;

			platform = new MacX86Platform(x86);
			Platform::Register("mac", platform);
			BinaryViewType::RegisterPlatform("Mach-O", 0, x86, platform);
		}

		Ref<Architecture> x64 = Architecture::GetByName("x86_64");
		if (x64)
		{
			Ref<Platform> platform;

			platform = new MacX64Platform(x64);
			Platform::Register("mac", platform);
			BinaryViewType::RegisterPlatform("Mach-O", 0, x64, platform);
		}

		Ref<Architecture> armv7 = Architecture::GetByName("armv7");
		Ref<Architecture> thumb2 = Architecture::GetByName("thumb2");
		if (armv7 && thumb2)
		{
			Ref<Platform> armPlatform, thumbPlatform;

			armPlatform = new MacArmv7Platform(armv7, "mac-armv7");
			thumbPlatform = new MacArmv7Platform(thumb2, "mac-thumb2");
			armPlatform->AddRelatedPlatform(thumb2, thumbPlatform);
			thumbPlatform->AddRelatedPlatform(armv7, armPlatform);
			Platform::Register("mac", armPlatform);
			Platform::Register("mac", thumbPlatform);
			BinaryViewType::RegisterPlatform("Mach-O", 0, armv7, armPlatform);
		}

		Ref<Architecture> arm64 = Architecture::GetByName("aarch64");
		if (arm64)
		{
			Ref<Platform> platform;

			platform = new MacArm64Platform(arm64);
			Platform::Register("mac", platform);
			BinaryViewType::RegisterPlatform("Mach-O", 9, arm64, platform);
			BinaryViewType::RegisterPlatform("Mach-O", 0, arm64, platform);
		}

		return true;
	}
}
