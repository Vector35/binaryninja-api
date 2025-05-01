#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


Ref<Platform> g_efiX86, g_efiX64, g_efiArm, g_efiThumb, g_efiArm64;
Ref<Platform> g_efiX86Windows, g_efiX64Windows, g_efiArm64Windows;


class EFIX86Platform : public Platform
{
public:
	EFIX86Platform(Architecture* arch) : Platform(arch, "efi-x86")
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

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> subsystem = metadata->Get("Subsystem");
		if (!subsystem || !subsystem->IsUnsignedInteger())
			return nullptr;
		if (subsystem->GetUnsignedInteger() >= 10 && subsystem->GetUnsignedInteger() <= 13)
			return g_efiX86;
		return nullptr;
	}
};


class EFIX86WindowsPlatform : public Platform
{
public:
	EFIX86WindowsPlatform(Architecture* arch) : Platform(arch, "efi-windows-x86")
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

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> subsystem = metadata->Get("Subsystem");
		if (!subsystem || !subsystem->IsUnsignedInteger())
			return nullptr;
		if (subsystem->GetUnsignedInteger() == 0x10)  // IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION
			return g_efiX86Windows;
		return nullptr;
	}
};


class EFIX64Platform : public Platform
{
public:
	EFIX64Platform(Architecture* arch) : Platform(arch, "efi-x86_64")
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
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> subsystem = metadata->Get("Subsystem");
		if (!subsystem || !subsystem->IsUnsignedInteger())
			return nullptr;
		if (subsystem->GetUnsignedInteger() >= 10 && subsystem->GetUnsignedInteger() <= 13)
			return g_efiX64;
		return nullptr;
	}
};


class EFIX64WindowsPlatform : public Platform
{
public:
	EFIX64WindowsPlatform(Architecture* arch) : Platform(arch, "efi-windows-x86_64")
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
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> subsystem = metadata->Get("Subsystem");
		if (!subsystem || !subsystem->IsUnsignedInteger())
			return nullptr;
		if (subsystem->GetUnsignedInteger() == 0x10)  // IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION
			return g_efiX64Windows;
		return nullptr;
	}
};


class EFIArmv7Platform : public Platform
{
public:
	EFIArmv7Platform(Architecture* arch, const std::string& name) : Platform(arch, name)
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

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> subsystem = metadata->Get("Subsystem");
		if (!subsystem || !subsystem->IsUnsignedInteger())
			return nullptr;
		if (subsystem->GetUnsignedInteger() >= 10 && subsystem->GetUnsignedInteger() <= 13)
			return g_efiArm;
		return nullptr;
	}
};


class EFIArm64Platform : public Platform
{
public:
	EFIArm64Platform(Architecture* arch) : Platform(arch, "efi-aarch64")
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

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> subsystem = metadata->Get("Subsystem");
		if (!subsystem || !subsystem->IsUnsignedInteger())
			return nullptr;
		if (subsystem->GetUnsignedInteger() >= 10 && subsystem->GetUnsignedInteger() <= 13)
			return g_efiArm64;
		return nullptr;
	}
};


class EFIArm64WindowsPlatform : public Platform
{
public:
	EFIArm64WindowsPlatform(Architecture* arch) : Platform(arch, "efi-windows-aarch64")
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

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		Ref<Metadata> subsystem = metadata->Get("Subsystem");
		if (!subsystem || !subsystem->IsUnsignedInteger())
			return nullptr;
		if (subsystem->GetUnsignedInteger() == 0x10)  // IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION
			return g_efiArm64Windows;
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
		AddOptionalPluginDependency("arch_armv7");
		AddOptionalPluginDependency("arch_arm64");
		AddOptionalPluginDependency("view_pe");
	}
#endif

#ifdef DEMO_EDITION
	bool EFIPluginInit()
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
				g_efiX86 = new EFIX86Platform(x86);
				Platform::Register("efi", g_efiX86);
				pe->RegisterPlatformRecognizer(0x14c, LittleEndian, EFIX86Platform::Recognize);

				g_efiX86Windows = new EFIX86WindowsPlatform(x86);
				Platform::Register("efi", g_efiX86Windows);
				pe->RegisterPlatformRecognizer(0x14c, LittleEndian, EFIX86WindowsPlatform::Recognize);
			}

			Ref<Architecture> x64 = Architecture::GetByName("x86_64");
			if (x64)
			{
				g_efiX64 = new EFIX64Platform(x64);
				Platform::Register("efi", g_efiX64);
				pe->RegisterPlatformRecognizer(0x8664, LittleEndian, EFIX64Platform::Recognize);

				g_efiX64Windows = new EFIX64WindowsPlatform(x64);
				Platform::Register("efi", g_efiX64Windows);
				pe->RegisterPlatformRecognizer(0x8664, LittleEndian, EFIX64WindowsPlatform::Recognize);
			}

			Ref<Architecture> armv7 = Architecture::GetByName("armv7");
			Ref<Architecture> thumb2 = Architecture::GetByName("thumb2");
			if (armv7 && thumb2)
			{
				g_efiArm = new EFIArmv7Platform(armv7, "efi-armv7");
				g_efiThumb = new EFIArmv7Platform(thumb2, "efi-thumb2");
				g_efiArm->AddRelatedPlatform(thumb2, g_efiThumb);
				g_efiThumb->AddRelatedPlatform(armv7, g_efiArm);
				Platform::Register("efi", g_efiArm);
				Platform::Register("efi", g_efiThumb);
				pe->RegisterPlatformRecognizer(0x1c0, LittleEndian, EFIArmv7Platform::Recognize);
				pe->RegisterPlatformRecognizer(0x1c2, LittleEndian, EFIArmv7Platform::Recognize);
				pe->RegisterPlatformRecognizer(0x1c4, LittleEndian, EFIArmv7Platform::Recognize);
			}

			Ref<Architecture> arm64 = Architecture::GetByName("aarch64");
			if (arm64)
			{
				g_efiArm64 = new EFIArm64Platform(arm64);
				Platform::Register("efi", g_efiArm64);
				pe->RegisterPlatformRecognizer(0xaa64, LittleEndian, EFIArm64Platform::Recognize);

				g_efiArm64Windows = new EFIArm64WindowsPlatform(arm64);
				Platform::Register("efi", g_efiArm64Windows);
				pe->RegisterPlatformRecognizer(0xaa64, LittleEndian, EFIArm64WindowsPlatform::Recognize);
			}
		}

		return true;
	}
}
