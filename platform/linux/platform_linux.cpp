#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


class LinuxX86Platform: public Platform
{
public:
	LinuxX86Platform(Architecture* arch): Platform(arch, "linux-x86")
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
			RegisterCallingConvention(cc);

		cc = arch->GetCallingConventionByName("stdcall");
		if (cc)
			RegisterStdcallCallingConvention(cc);

		cc = arch->GetCallingConventionByName("linux-syscall");
		if (cc)
			SetSystemCallConvention(cc);
	}

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}
};

class LinuxPpc32Platform: public Platform
{
public:
	LinuxPpc32Platform(Architecture* arch, const std::string& name): Platform(arch, name)
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("svr4");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
		}

		cc = arch->GetCallingConventionByName("linux-syscall");
		if (cc)
			SetSystemCallConvention(cc);
	}
};

class LinuxPpc64Platform: public Platform
{
public:
	LinuxPpc64Platform(Architecture* arch, const std::string& name): Platform(arch, name)
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("svr4");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
		}

		cc = arch->GetCallingConventionByName("linux-syscall");
		if (cc)
			SetSystemCallConvention(cc);
	}
};

class LinuxX64Platform: public Platform
{
public:
	LinuxX64Platform(Architecture* arch): Platform(arch, "linux-x86_64")
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

		cc = arch->GetCallingConventionByName("linux-syscall");
		if (cc)
			SetSystemCallConvention(cc);
	}

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}
};


class LinuxArmv7Platform: public Platform
{
public:
	LinuxArmv7Platform(Architecture* arch, const std::string& name): Platform(arch, name)
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

		cc = arch->GetCallingConventionByName("linux-syscall");
		if (cc)
			SetSystemCallConvention(cc);
	}
};


class LinuxArm64Platform: public Platform
{
public:
	LinuxArm64Platform(Architecture* arch): Platform(arch, "linux-aarch64")
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

		cc = arch->GetCallingConventionByName("linux-syscall");
		if (cc)
			SetSystemCallConvention(cc);
	}

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}
};


class LinuxMipsPlatform: public Platform
{
public:
	LinuxMipsPlatform(Architecture* arch, const std::string& name): Platform(arch, name)
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("o32");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}

		cc = arch->GetCallingConventionByName("linux-syscall");
		if (cc)
			SetSystemCallConvention(cc);
	}

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}
};

class LinuxMips64Platform: public Platform
{
public:
	LinuxMips64Platform(Architecture* arch, const std::string& name): Platform(arch, name)
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("n64");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}

		cc = arch->GetCallingConventionByName("linux-syscall");
		if (cc)
			SetSystemCallConvention(cc);
	}
};


class LinuxRiscVPlatform : public Platform
{
public:
	LinuxRiscVPlatform(Architecture* arch, const std::string& name) : Platform(arch, name)
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
		AddOptionalPluginDependency("arch_mips");
		AddOptionalPluginDependency("arch_ppc");
		AddOptionalPluginDependency("arch_riscv");
		AddOptionalPluginDependency("arch_msp430");
		AddOptionalPluginDependency("view_elf");
	}
#endif

#ifdef DEMO_EDITION
	bool LinuxPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		Ref<Architecture> x86 = Architecture::GetByName("x86");
		if (x86)
		{
			Ref<Platform> platform;

			platform = new LinuxX86Platform(x86);
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, x86, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, x86, platform);
		}

		Ref<Architecture> x64 = Architecture::GetByName("x86_64");
		if (x64)
		{
			Ref<Platform> platform;

			platform = new LinuxX64Platform(x64);
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, x64, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, x64, platform);
		}

		Ref<Architecture> armv7 = Architecture::GetByName("armv7");
		Ref<Architecture> armv7eb = Architecture::GetByName("armv7eb");
		Ref<Architecture> thumb2 = Architecture::GetByName("thumb2");
		Ref<Architecture> thumb2eb = Architecture::GetByName("thumb2eb");
		if (armv7 && armv7eb && thumb2 && thumb2eb)
		{
			Ref<Platform> armPlatform, armebPlatform, thumbPlatform, thumbebPlatform;

			armPlatform = new LinuxArmv7Platform(armv7, "linux-armv7");
			armebPlatform = new LinuxArmv7Platform(armv7eb, "linux-armv7eb");
			thumbPlatform = new LinuxArmv7Platform(thumb2, "linux-thumb2");
			thumbebPlatform = new LinuxArmv7Platform(thumb2eb, "linux-thumb2eb");
			armPlatform->AddRelatedPlatform(thumb2, thumbPlatform);
			armebPlatform->AddRelatedPlatform(thumb2eb, thumbebPlatform);
			thumbPlatform->AddRelatedPlatform(armv7, armPlatform);
			thumbebPlatform->AddRelatedPlatform(armv7eb, armebPlatform);
			Platform::Register("linux", armPlatform);
			Platform::Register("linux", thumbPlatform);
			Platform::Register("linux", armebPlatform);
			Platform::Register("linux", thumbebPlatform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, armv7, armPlatform);
			BinaryViewType::RegisterPlatform("ELF", 3, armv7, armPlatform);
			BinaryViewType::RegisterPlatform("ELF", 0, armv7eb, armebPlatform);
			BinaryViewType::RegisterPlatform("ELF", 3, armv7eb, armebPlatform);
		}

		Ref<Architecture> arm64 = Architecture::GetByName("aarch64");
		if (arm64)
		{
			Ref<Platform> platform;

			platform = new LinuxArm64Platform(arm64);
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, arm64, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, arm64, platform);
		}

		Ref<Architecture> ppc = Architecture::GetByName("ppc");
		Ref<Architecture> ppcle = Architecture::GetByName("ppc_le");
		if (ppc && ppcle)
		{
			Ref<Platform> platform;
			Ref<Platform> platformle;

			platform = new LinuxPpc32Platform(ppc, "linux-ppc32");
			platformle = new LinuxPpc32Platform(ppcle, "linux-ppc32_le");
			Platform::Register("linux", platform);
			Platform::Register("linux", platformle);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, ppc, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, ppc, platform);
			BinaryViewType::RegisterPlatform("ELF", 0, ppcle, platformle);
			BinaryViewType::RegisterPlatform("ELF", 3, ppcle, platformle);
		}

		Ref<Architecture> ppc64 = Architecture::GetByName("ppc64");
		Ref<Architecture> ppc64le = Architecture::GetByName("ppc64_le");
		if (ppc64 && ppc64le)
		{
			Ref<Platform> platform;
			Ref<Platform> platformle;

			platform = new LinuxPpc64Platform(ppc64, "linux-ppc64");
			platformle = new LinuxPpc64Platform(ppc64le, "linux-ppc64_le");
			Platform::Register("linux", platform);
			Platform::Register("linux", platformle);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, ppc64, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, ppc64, platform);
			BinaryViewType::RegisterPlatform("ELF", 0, ppc64le, platformle);
			BinaryViewType::RegisterPlatform("ELF", 3, ppc64le, platformle);
		}

		Ref<Architecture> mipsel = Architecture::GetByName("mipsel32");
		Ref<Architecture> mipseb = Architecture::GetByName("mips32");
		Ref<Architecture> mips64eb = Architecture::GetByName("mips64");
		Ref<Architecture> cnmips64eb = Architecture::GetByName("cavium-mips64");
		if (mipsel && mipseb && mips64eb && cnmips64eb)
		{
			Ref<Platform> platformLE, platformBE, platformBE64, platformBE64cn;

			platformLE = new LinuxMipsPlatform(mipsel, "linux-mipsel");
			platformBE = new LinuxMipsPlatform(mipseb, "linux-mips");
			platformBE64 = new LinuxMips64Platform(mips64eb, "linux-mips64");
			platformBE64cn = new LinuxMips64Platform(cnmips64eb, "linux-cnmips64");
			Platform::Register("linux", platformLE);
			Platform::Register("linux", platformBE);
			Platform::Register("linux", platformBE64);
			Platform::Register("linux", platformBE64cn);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, mipsel, platformLE);
			BinaryViewType::RegisterPlatform("ELF", 0, mipseb, platformBE);
			BinaryViewType::RegisterPlatform("ELF", 0, mips64eb, platformBE64);
			BinaryViewType::RegisterPlatform("ELF", 0, cnmips64eb, platformBE64cn);
			BinaryViewType::RegisterPlatform("ELF", 3, mipsel, platformLE);
			BinaryViewType::RegisterPlatform("ELF", 3, mipseb, platformBE);
			BinaryViewType::RegisterPlatform("ELF", 3, mips64eb, platformBE64);
			BinaryViewType::RegisterPlatform("ELF", 3, cnmips64eb, platformBE64cn);
		}

		Ref<Architecture> rv32 = Architecture::GetByName("rv32gc");
		if (rv32)
		{
			Ref<Platform> platform;

			platform = new LinuxRiscVPlatform(rv32, "linux-rv32gc");
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, rv32, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, rv32, platform);
		}

		Ref<Architecture> rv64 = Architecture::GetByName("rv64gc");
		if (rv64)
		{
			Ref<Platform> platform;

			platform = new LinuxRiscVPlatform(rv64, "linux-rv64gc");
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, rv64, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, rv64, platform);
		}

		return true;
	}
}
