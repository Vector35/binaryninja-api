#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

Ref<Platform> g_linuxX32;
#define EM_X86_64 62 // AMD x86-64 architecture

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


class LinuxX32Platform: public Platform
{
	public:
	LinuxX32Platform(Architecture* arch): Platform(arch, "linux-x32")
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

	virtual size_t GetAddressSize() const override
	{
		return 4;
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> fileClass = metadata->Get("EI_CLASS");

		if (!fileClass || !fileClass->IsUnsignedInteger())
			return nullptr;

		Ref<Metadata> machine = metadata->Get("e_machine");
		if (!machine || !machine->IsUnsignedInteger())
			return nullptr;

		if (fileClass->GetUnsignedInteger() == 1 && machine->GetUnsignedInteger() == EM_X86_64)
			return g_linuxX32;

		return nullptr;
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

#ifdef ULTIMATE_EDITION
class LinuxCSkyV1Platform : public Platform
{
public:
	LinuxCSkyV1Platform(Architecture* arch, const std::string& name) : Platform(arch, name)
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

class LinuxCSkyV2Platform : public Platform
{
public:
	LinuxCSkyV2Platform(Architecture* arch, const std::string& name) : Platform(arch, name)
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
#endif


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
#ifdef ULTIMATE_EDITION
		AddOptionalPluginDependency("arch_csky");
#endif
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
			BinaryViewType::RegisterPlatform("ELF", 0, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, platform);
		}

		Ref<Architecture> x64 = Architecture::GetByName("x86_64");
		if (x64)
		{
			Ref<Platform> x64Platform = new LinuxX64Platform(x64);
			g_linuxX32 = new LinuxX32Platform(x64);

			Platform::Register("linux", x64Platform);
			Platform::Register("linux", g_linuxX32);

			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, x64, x64Platform);
			BinaryViewType::RegisterPlatform("ELF", 3, x64, x64Platform);


			Ref<BinaryViewType> elf = BinaryViewType::GetByName("ELF");
			if (elf)
				elf->RegisterPlatformRecognizer(EM_X86_64, LittleEndian, LinuxX32Platform::Recognize);
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
			BinaryViewType::RegisterPlatform("ELF", 0, armPlatform);
			BinaryViewType::RegisterPlatform("ELF", 3, armPlatform);
			BinaryViewType::RegisterPlatform("ELF", 0, armebPlatform);
			BinaryViewType::RegisterPlatform("ELF", 3, armebPlatform);
		}

		Ref<Architecture> arm64 = Architecture::GetByName("aarch64");
		if (arm64)
		{
			Ref<Platform> platform;

			platform = new LinuxArm64Platform(arm64);
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, platform);
		}

		Ref<Architecture> ppc = Architecture::GetByName("ppc");
		Ref<Architecture> ppcvle = Architecture::GetByName("ppcvle");
		Ref<Architecture> ppcLE = Architecture::GetByName("ppc_le");
		// TODO: VLEPEM says that VLE always uses big-endian instruction
		//       encoding, but doesn't say anything about data
		//       endianness, so in theory little-endian PPC should be
		//       possible?
		if (ppc && ppcvle && ppcLE)
		{
			Ref<Platform> ppcPlatform;
			Ref<Platform> ppcvlePlatform;
			Ref<Platform> ppcLEPlatform;

			ppcPlatform = new LinuxPpc32Platform(ppc, "linux-ppc32");
			ppcvlePlatform = new LinuxPpc32Platform(ppcvle, "linux-ppcvle32");
			ppcLEPlatform = new LinuxPpc32Platform(ppcLE, "linux-ppc32_le");

			Platform::Register("linux", ppcPlatform);
			Platform::Register("linux", ppcvlePlatform);
			Platform::Register("linux", ppcLEPlatform);

			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0,ppcPlatform);
			BinaryViewType::RegisterPlatform("ELF", 3,ppcPlatform);
			BinaryViewType::RegisterPlatform("ELF", 0,ppcvlePlatform);
			BinaryViewType::RegisterPlatform("ELF", 3,ppcvlePlatform);
			BinaryViewType::RegisterPlatform("ELF", 0,ppcLEPlatform);
			BinaryViewType::RegisterPlatform("ELF", 3,ppcLEPlatform);
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
			BinaryViewType::RegisterPlatform("ELF", 0, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, platform);
			BinaryViewType::RegisterPlatform("ELF", 0, platformle);
			BinaryViewType::RegisterPlatform("ELF", 3, platformle);
		}

		Ref<Architecture> mipsel = Architecture::GetByName("mipsel32");
		Ref<Architecture> mipseb = Architecture::GetByName("mips32");
		Ref<Architecture> mips3el = Architecture::GetByName("mipsel3");
		Ref<Architecture> mips3eb = Architecture::GetByName("mips3");
		Ref<Architecture> mips64eb = Architecture::GetByName("mips64");
		Ref<Architecture> cnmips64eb = Architecture::GetByName("cavium-mips64");
		if (mipsel && mipseb && mips64eb && cnmips64eb && mips3el && mips3eb)
		{
			Ref<Platform> platformLE, platformBE, platformBE64, platformBE64cn, platform3LE, platform3BE;

			platformLE = new LinuxMipsPlatform(mipsel, "linux-mipsel");
			platformBE = new LinuxMipsPlatform(mipseb, "linux-mips");
			platform3LE = new LinuxMipsPlatform(mips3el, "linux-mipsel3");
			platform3BE = new LinuxMipsPlatform(mips3eb, "linux-mips3");
			platformBE64 = new LinuxMips64Platform(mips64eb, "linux-mips64");
			platformBE64cn = new LinuxMips64Platform(cnmips64eb, "linux-cnmips64");
			Platform::Register("linux", platformLE);
			Platform::Register("linux", platformBE);
			Platform::Register("linux", platform3LE);
			Platform::Register("linux", platform3BE);
			Platform::Register("linux", platformBE64);
			Platform::Register("linux", platformBE64cn);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, platformLE);
			BinaryViewType::RegisterPlatform("ELF", 0, platformBE);
			BinaryViewType::RegisterPlatform("ELF", 0, platform3LE);
			BinaryViewType::RegisterPlatform("ELF", 0, platform3BE);
			BinaryViewType::RegisterPlatform("ELF", 0, platformBE64);
			BinaryViewType::RegisterPlatform("ELF", 0, platformBE64cn);
			BinaryViewType::RegisterPlatform("ELF", 3, platformLE);
			BinaryViewType::RegisterPlatform("ELF", 3, platformBE);
			BinaryViewType::RegisterPlatform("ELF", 3, platform3LE);
			BinaryViewType::RegisterPlatform("ELF", 3, platform3BE);
			BinaryViewType::RegisterPlatform("ELF", 3, platformBE64);
			BinaryViewType::RegisterPlatform("ELF", 3, platformBE64cn);
		}

		Ref<Architecture> rv32 = Architecture::GetByName("rv32gc");
		if (rv32)
		{
			Ref<Platform> platform;

			platform = new LinuxRiscVPlatform(rv32, "linux-rv32gc");
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, platform);
		}

		Ref<Architecture> rv64 = Architecture::GetByName("rv64gc");
		if (rv64)
		{
			Ref<Platform> platform;

			platform = new LinuxRiscVPlatform(rv64, "linux-rv64gc");
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, platform);
		}

#ifdef ULTIMATE_EDITION
		Ref<Architecture> mcore_le = Architecture::GetByName("mcore_le");
		if (mcore_le)
		{
			Ref<Platform> platform;

			platform = new LinuxCSkyV1Platform(mcore_le, "linux-mcore_le");
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, platform);
		}

		Ref<Architecture> mcore_be = Architecture::GetByName("mcore_be");
		if (mcore_be)
		{
			Ref<Platform> platform;

			platform = new LinuxCSkyV1Platform(mcore_be, "linux-mcore_be");
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, platform);
		}

		Ref<Architecture> cskyv1 = Architecture::GetByName("csky_le_v1");
		if (cskyv1)
		{
			Ref<Platform> platform;

			platform = new LinuxCSkyV1Platform(cskyv1, "linux-csky_le_v1");
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, platform);
		}

		Ref<Architecture> cskyv2 = Architecture::GetByName("csky_le");
		if (cskyv2)
		{
			Ref<Platform> platform;

			platform = new LinuxCSkyV2Platform(cskyv2, "linux-csky_le");
			Platform::Register("linux", platform);
			// Linux binaries sometimes have an OS identifier of zero, even though 3 is the correct one
			BinaryViewType::RegisterPlatform("ELF", 0, platform);
			BinaryViewType::RegisterPlatform("ELF", 3, platform);
		}
#endif

		return true;
	}
}
