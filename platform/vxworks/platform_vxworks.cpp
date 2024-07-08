#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

Ref<Platform> g_vxWorksX86, g_vxWorksX64, g_vxWorksArm, g_vxWorksArm64, g_vxWorksThumb;
Ref<Platform> g_vxWorksMips32, g_vxWorksMips64, g_vxWorksPpc32, g_vxWorksPpc64;
Ref<Platform> g_vxWorksRiscV32, g_vxWorksRiscv64;


class VxWorksIntelPlatform : public Platform
{
public:
    VxWorksIntelPlatform(Architecture* arch, const std::string& name) : Platform(arch, name)
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

class VxWorksArmPlatform : public Platform
{
public:
    VxWorksArmPlatform(Architecture* arch, const std::string& name) : Platform(arch, name)
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

class VxWorksMipsPlatform : public Platform
{
public:
    VxWorksMipsPlatform(Architecture* arch, const std::string& name) : Platform(arch, name)
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
    }
};

class VxWorksPpcPlatform : public Platform
{
public:
	VxWorksPpcPlatform(Architecture* arch, const std::string& name): Platform(arch, name)
	{
		Ref<CallingConvention> cc;
		cc = arch->GetCallingConventionByName("svr4");
		if (cc)
			RegisterDefaultCallingConvention(cc);
	}
};

class VxWorksRiscVPlatform : public Platform
{
public:
    VxWorksRiscVPlatform(Architecture* arch, const std::string& name): Platform(arch, name)
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
		AddOptionalPluginDependency("arch_mips");
		AddOptionalPluginDependency("arch_ppc");
		AddOptionalPluginDependency("arch_riscv");
	}
#endif

#ifdef DEMO_VERSION
    bool VxWorksPluginInit()
#else
    BINARYNINJAPLUGIN bool CorePluginInit()
#endif
    {
        Ref<BinaryViewType> vx = BinaryViewType::GetByName("VxWorks");
        if (!vx)
            return true;

        Ref<Architecture> x86 = Architecture::GetByName("x86");
        Ref<Architecture> x64 = Architecture::GetByName("x86_64");
        if (x86 && x64)
        {
            g_vxWorksX86 = new VxWorksIntelPlatform(x86, "vxworks-x86");
            Platform::Register("vxworks", g_vxWorksX86);
			BinaryViewType::RegisterDefaultPlatform("VxWorks", x86, g_vxWorksX86);
            g_vxWorksX64 = new VxWorksIntelPlatform(x64, "vxworks-x86_64");
            Platform::Register("vxworks", g_vxWorksX64);
			BinaryViewType::RegisterDefaultPlatform("VxWorks", x64, g_vxWorksX64);
        }

        Ref<Architecture> armv7 = Architecture::GetByName("armv7");
        Ref<Architecture> thumb2 = Architecture::GetByName("thumb2");
        Ref<Architecture> arm64 = Architecture::GetByName("aarch64");
        if (armv7 && thumb2)
        {
            g_vxWorksArm = new VxWorksArmPlatform(armv7, "vxworks-armv7");
            Platform::Register("vxworks", g_vxWorksArm);
			BinaryViewType::RegisterDefaultPlatform("VxWorks", armv7, g_vxWorksArm);
            g_vxWorksThumb = new VxWorksArmPlatform(thumb2, "vxworks-thumb2");
            Platform::Register("vxworks", g_vxWorksThumb);
			BinaryViewType::RegisterDefaultPlatform("VxWorks", thumb2, g_vxWorksThumb);
            g_vxWorksArm64 = new VxWorksArmPlatform(arm64, "vxworks-aarch64");
            Platform::Register("vxworks", g_vxWorksArm64);
            BinaryViewType::RegisterDefaultPlatform("VxWorks", arm64, g_vxWorksArm64);
        }

		Ref<Architecture> mips32 = Architecture::GetByName("mips32");
        Ref<Architecture> mips64 = Architecture::GetByName("mips64");
		if (mips64 && mips32)
		{
            g_vxWorksMips32 = new VxWorksMipsPlatform(mips32, "vxworks-mips32");
            Platform::Register("vxworks", g_vxWorksMips32);
			BinaryViewType::RegisterDefaultPlatform("VxWorks", mips32, g_vxWorksMips32);
            g_vxWorksMips64 = new VxWorksMipsPlatform(mips64, "vxworks-mips64");
            Platform::Register("vxworks", g_vxWorksMips64);
			BinaryViewType::RegisterDefaultPlatform("VxWorks", mips64, g_vxWorksMips64);
        }

        Ref<Architecture> ppc32 = Architecture::GetByName("ppc");
        Ref<Architecture> ppc64 = Architecture::GetByName("ppc64");
        if (ppc32 && ppc64)
        {
            g_vxWorksPpc32 = new VxWorksPpcPlatform(ppc32, "vxworks-ppc32");
            Platform::Register("vxworks", g_vxWorksPpc32);
			BinaryViewType::RegisterDefaultPlatform("VxWorks", ppc32, g_vxWorksPpc32);
            g_vxWorksPpc64 = new VxWorksPpcPlatform(ppc64, "vxworks-ppc64");
            Platform::Register("vxworks", g_vxWorksPpc64);
			BinaryViewType::RegisterDefaultPlatform("VxWorks", ppc64, g_vxWorksPpc64);
        }

        Ref<Architecture> riscv32 = Architecture::GetByName("rv32gc");
        Ref<Architecture> riscv64 = Architecture::GetByName("rv64gc");
        if (riscv32 && riscv64)
        {
            g_vxWorksRiscV32 = new VxWorksRiscVPlatform(riscv32, "vxworks-rv32gc");
            Platform::Register("vxworks", g_vxWorksRiscV32);
			BinaryViewType::RegisterDefaultPlatform("VxWorks", riscv32, g_vxWorksRiscV32);
            g_vxWorksRiscv64 = new VxWorksRiscVPlatform(riscv64, "vxworks-rv64gc");
            Platform::Register("vxworks", g_vxWorksRiscv64);
			BinaryViewType::RegisterDefaultPlatform("VxWorks", riscv64, g_vxWorksRiscv64);
        }

        return true;
    }
}