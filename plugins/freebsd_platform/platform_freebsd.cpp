#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


class FreeBSDX86Platform: public Platform
{
public:
	FreeBSDX86Platform(Architecture* arch): Platform(arch, "freebsd-x86")
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


class FreeBSDX64Platform: public Platform
{
public:
	FreeBSDX64Platform(Architecture* arch): Platform(arch, "freebsd-x86_64")
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


class FreeBSDArmv7Platform: public Platform
{
public:
	FreeBSDArmv7Platform(Architecture* arch, const std::string& name): Platform(arch, name)
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


class FreeBSDArm64Platform: public Platform
{
public:
	FreeBSDArm64Platform(Architecture* arch): Platform(arch, "freebsd-aarch64")
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


class FreeBSDPpcPlatform: public Platform
{
public:
	FreeBSDPpcPlatform(Architecture* arch, const std::string& name): Platform(arch, name)
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("svr4");
		if (cc)
			RegisterDefaultCallingConvention(cc);
	}
};


class FreeBSDRiscVPlatform: public Platform
{
public:
	FreeBSDRiscVPlatform(Architecture* arch, const std::string& name): Platform(arch, name)
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("default");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}

		cc = arch->GetCallingConventionByName("syscall");
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
		AddOptionalPluginDependency("arch_armv7");
		AddOptionalPluginDependency("arch_arm64");
		AddOptionalPluginDependency("arch_powerpc");
		AddOptionalPluginDependency("arch_riscv");
		AddOptionalPluginDependency("view_elf");
	}
#endif

#ifdef DEMO_EDITION
	bool FreeBSDPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		Ref<Architecture> x86 = Architecture::GetByName("x86");
		if (x86)
		{
			Ref<Platform> platform;

			platform = new FreeBSDX86Platform(x86);
			Platform::Register("freebsd", platform);
			BinaryViewType::RegisterPlatform("ELF", 9, platform);
		}

		Ref<Architecture> x64 = Architecture::GetByName("x86_64");
		if (x64)
		{
			Ref<Platform> platform;

			platform = new FreeBSDX64Platform(x64);
			Platform::Register("freebsd", platform);
			BinaryViewType::RegisterPlatform("ELF", 9, platform);
		}

		Ref<Architecture> armv7 = Architecture::GetByName("armv7");
		Ref<Architecture> thumb2 = Architecture::GetByName("thumb2");
		if (armv7 && thumb2)
		{
			Ref<Platform> armPlatform, thumbPlatform;

			armPlatform = new FreeBSDArmv7Platform(armv7, "freebsd-armv7");
			thumbPlatform = new FreeBSDArmv7Platform(thumb2, "freebsd-thumb2");
			armPlatform->AddRelatedPlatform(thumb2, thumbPlatform);
			thumbPlatform->AddRelatedPlatform(armv7, armPlatform);
			Platform::Register("freebsd", armPlatform);
			Platform::Register("freebsd", thumbPlatform);
			BinaryViewType::RegisterPlatform("ELF", 9, armPlatform);
		}

		Ref<Architecture> arm64 = Architecture::GetByName("aarch64");
		if (arm64)
		{
			Ref<Platform> platform;

			platform = new FreeBSDArm64Platform(arm64);
			Platform::Register("freebsd", platform);
			BinaryViewType::RegisterPlatform("ELF", 9, platform);
		}

		Ref<Architecture> ppc = Architecture::GetByName("ppc");
		if (ppc)
		{
			Ref<Platform> platform;

			platform = new FreeBSDPpcPlatform(ppc, "freebsd-ppc32");
			Platform::Register("freebsd", platform);
			BinaryViewType::RegisterPlatform("ELF", 9, platform);
		}

		Ref<Architecture> ppc64 = Architecture::GetByName("ppc64");
		if (ppc64)
		{
			Ref<Platform> platform;

			platform = new FreeBSDPpcPlatform(ppc64, "freebsd-ppc64");
			Platform::Register("freebsd", platform);
			BinaryViewType::RegisterPlatform("ELF", 9, platform);
		}

		Ref<Architecture> ppc64le = Architecture::GetByName("ppc64_le");
		if (ppc64le)
		{
			Ref<Platform> platform;

			platform = new FreeBSDPpcPlatform(ppc64le, "freebsd-ppc64_le");
			Platform::Register("freebsd", platform);
			BinaryViewType::RegisterPlatform("ELF", 9, platform);
		}

		Ref<Architecture> rv64 = Architecture::GetByName("rv64gc");
		if (rv64)
		{
			Ref<Platform> platform;

			platform = new FreeBSDRiscVPlatform(rv64, "freebsd-rv64gc");
			Platform::Register("freebsd", platform);
			BinaryViewType::RegisterPlatform("ELF", 9, platform);
		}

		return true;
	}
}
