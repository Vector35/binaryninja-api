#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


Ref<Platform> g_windowsKernelX86, g_windowsKernelX64, g_windowsKernelArm64;


class WindowsKernelX86Platform : public Platform
{
public:
	WindowsKernelX86Platform(Architecture* arch) : Platform(arch, "windows-kernel-x86")
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("cdecl");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
		}

		cc = arch->GetCallingConventionByName("fastcall");
		if (cc)
			RegisterFastcallCallingConvention(cc);

		cc = arch->GetCallingConventionByName("stdcall");
		if (cc)
			RegisterStdcallCallingConvention(cc);

		cc = arch->GetCallingConventionByName("thiscall");
		if (cc)
			RegisterCallingConvention(cc);

		// Linux-style register convention is commonly used by Borland compilers
		cc = arch->GetCallingConventionByName("regparm");
		if (cc)
			RegisterCallingConvention(cc);
	}

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> subsystem = metadata->Get("Subsystem");
		if (!subsystem || !subsystem->IsUnsignedInteger())
			return nullptr;
		if (subsystem->GetUnsignedInteger() == 1)  // IMAGE_SUBSYSTEM_NATIVE
			return g_windowsKernelX86;
		return nullptr;
	}
};


class WindowsKernelX64Platform : public Platform
{
public:
	WindowsKernelX64Platform(Architecture* arch) : Platform(arch, "windows-kernel-x86_64")
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("win64");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}

		// Linux-style calling convention is sometimes used internally by WindowsKernel applications
		cc = arch->GetCallingConventionByName("sysv");
		RegisterCallingConvention(cc);
	}

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> subsystem = metadata->Get("Subsystem");
		if (!subsystem || !subsystem->IsUnsignedInteger())
			return nullptr;
		if (subsystem->GetUnsignedInteger() == 1)  // IMAGE_SUBSYSTEM_NATIVE
			return g_windowsKernelX64;
		return nullptr;
	}
};



class WindowsKernelArm64Platform : public Platform
{
public:
	WindowsKernelArm64Platform(Architecture* arch) : Platform(arch, "windows-kernel-windows-aarch64")
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

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> subsystem = metadata->Get("Subsystem");
		if (!subsystem || !subsystem->IsUnsignedInteger())
			return nullptr;
		if (subsystem->GetUnsignedInteger() == 1)  // IMAGE_SUBSYSTEM_NATIVE
			return g_windowsKernelArm64;
		return nullptr;
	}
};


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_EDITION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("arch_x86");
		AddOptionalPluginDependency("arch_arm64");
		AddOptionalPluginDependency("view_pe");
	}
#endif

#ifdef DEMO_EDITION
	bool WindowsKernelPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		Ref<BinaryViewType> pe = BinaryViewType::GetByName("PE");
		if (pe)
		{
			Ref<Architecture> x86 = Architecture::GetByName("x86");
			if (x86)
			{
				g_windowsKernelX86 = new WindowsKernelX86Platform(x86);
				Platform::Register("windows-kernel", g_windowsKernelX86);
				pe->RegisterPlatformRecognizer(0x14c, LittleEndian, WindowsKernelX86Platform::Recognize);
			}

			Ref<Architecture> x64 = Architecture::GetByName("x86_64");
			if (x64)
			{
				g_windowsKernelX64 = new WindowsKernelX64Platform(x64);
				Platform::Register("windows-kernel", g_windowsKernelX64);
				pe->RegisterPlatformRecognizer(0x8664, LittleEndian, WindowsKernelX64Platform::Recognize);
			}

			Ref<Architecture> arm64 = Architecture::GetByName("aarch64");
			if (arm64)
			{
				g_windowsKernelArm64 = new WindowsKernelArm64Platform(arm64);
				Platform::Register("windows-kernel", g_windowsKernelArm64);
				pe->RegisterPlatformRecognizer(0xaa64, LittleEndian, WindowsKernelArm64Platform::Recognize);
			}
		}

		return true;
	}
}
