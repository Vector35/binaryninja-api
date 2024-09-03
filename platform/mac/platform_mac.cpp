#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


Ref<Platform> g_macX86, g_macX64, g_macArmv7, g_macThumb2, g_macArm64;
Ref<Platform> g_iosArmv7, g_iosThumb2, g_iosArm64;


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

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		auto machoPlatform = metadata->Get("machoplatform");
		if (!machoPlatform || !machoPlatform->IsUnsignedInteger())
			return nullptr;
		if (machoPlatform->GetUnsignedInteger() != 2)
			return g_macX86;

		return nullptr;
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

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		auto machoPlatform = metadata->Get("machoplatform");
		if (!machoPlatform || !machoPlatform->IsUnsignedInteger())
			return nullptr;
		if (machoPlatform->GetUnsignedInteger() != 2)
			return g_macX64;

		return nullptr;
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

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		bool shouldRecognizeOnIOS = false;
		if (view->GetFile()->IsBackedByDatabase())
		{
			if (auto database = view->GetFile()->GetDatabase())
			{
				if (database->HasGlobal("original_version") && database->ReadGlobal("original_version").asInt64() < 6)
					shouldRecognizeOnIOS = true;
			}
		}
		auto machoPlatform = metadata->Get("machoplatform");
		if (!machoPlatform || !machoPlatform->IsUnsignedInteger())
			return nullptr;
		if (machoPlatform->GetUnsignedInteger() != 2 || shouldRecognizeOnIOS)
			return g_macArmv7;

		return nullptr;
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

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		bool shouldRecognizeOnIOS = false;
		if (view->GetFile()->IsBackedByDatabase())
		{
			if (auto database = view->GetFile()->GetDatabase())
			{
				if (database->HasGlobal("original_version") && database->ReadGlobal("original_version").asInt64() < 6)
					shouldRecognizeOnIOS = true;
			}
		}
		auto machoPlatform = metadata->Get("machoplatform");
		if (!machoPlatform || !machoPlatform->IsUnsignedInteger())
			return nullptr;
		if (machoPlatform->GetUnsignedInteger() != 2 || shouldRecognizeOnIOS)
			return g_macArm64;

		return nullptr;
	}
};


class IOSArmv7Platform: public Platform
{
public:
	IOSArmv7Platform(Architecture* arch, const std::string& name): Platform(arch, name)
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
		auto machoPlatform = metadata->Get("machoplatform");
		if (machoPlatform->GetUnsignedInteger() != 2)
			return nullptr;
		if (!machoPlatform || !machoPlatform->IsUnsignedInteger())
			return nullptr;
		if (view->GetFile()->IsBackedByDatabase())
		{
			if (auto database = view->GetFile()->GetDatabase())
			{
				if (database->HasGlobal("original_version") && database->ReadGlobal("original_version").asInt64() < 6)
				{
					LogError("%s", "iOS database was saved with mac platform. Unable to upgrade. For iOS typelibs to"
						" function properly, this binary must be reopened.");
					return nullptr;
				}
			}
		}
		return g_iosArmv7;
	}
};

class IOSArm64Platform: public Platform
{
public:
	IOSArm64Platform(Architecture* arch): Platform(arch, "ios-aarch64")
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

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}

	static Ref<Platform> Recognize(BinaryView* view, Metadata* metadata)
	{
		auto machoPlatform = metadata->Get("machoplatform");
		if (!machoPlatform || !machoPlatform->IsUnsignedInteger())
			return nullptr;
		if (machoPlatform->GetUnsignedInteger() != 2)
			return nullptr;
		if (view->GetFile()->IsBackedByDatabase())
		{
			if (auto database = view->GetFile()->GetDatabase())
			{
				if (database->HasGlobal("original_version") && database->ReadGlobal("original_version").asInt64() < 6)
				{
					LogError("%s", "iOS database was saved with mac platform. Unable to upgrade. For iOS typelibs to"
						" function properly, this binary must be reopened.");
					return nullptr;
				}
			}
		}
		return g_iosArm64;
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
		AddOptionalPluginDependency("view_macho");
	}
#endif

#ifdef DEMO_EDITION
	bool MacPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		auto viewType = BinaryViewType::GetByName("Mach-O");
		Ref<Architecture> x86 = Architecture::GetByName("x86");
		if (x86)
		{
			g_macX86 = new MacX86Platform(x86);
			Platform::Register("mac", g_macX86);
			viewType->RegisterPlatformRecognizer(7, LittleEndian, MacX86Platform::Recognize);
		}

		Ref<Architecture> x64 = Architecture::GetByName("x86_64");
		if (x64)
		{
			g_macX64 = new MacX64Platform(x64);
			Platform::Register("mac", g_macX64);
			viewType->RegisterPlatformRecognizer(0x01000007, LittleEndian, MacX64Platform::Recognize);
		}

		Ref<Architecture> armv7 = Architecture::GetByName("armv7");
		Ref<Architecture> thumb2 = Architecture::GetByName("thumb2");
		if (armv7 && thumb2)
		{
			g_macArmv7 = new MacArmv7Platform(armv7, "mac-armv7");
			g_macThumb2 = new MacArmv7Platform(thumb2, "mac-thumb2");
			g_iosArmv7 = new IOSArmv7Platform(armv7, "ios-armv7");
			g_iosThumb2 = new IOSArmv7Platform(thumb2, "ios-thumb2");
			g_macArmv7->AddRelatedPlatform(thumb2, g_macThumb2);
			g_macThumb2->AddRelatedPlatform(armv7, g_macArmv7);
			g_iosArmv7->AddRelatedPlatform(thumb2, g_iosThumb2);
			g_iosThumb2->AddRelatedPlatform(armv7, g_iosArmv7);
			Platform::Register("mac", g_macArmv7);
			Platform::Register("ios", g_iosArmv7);
			Platform::Register("mac", g_macThumb2);
			Platform::Register("ios", g_iosThumb2);
			viewType->RegisterPlatformRecognizer(0xc, LittleEndian, MacArmv7Platform::Recognize);
			viewType->RegisterPlatformRecognizer(0xc, LittleEndian, IOSArmv7Platform::Recognize);
		}

		Ref<Architecture> arm64 = Architecture::GetByName("aarch64");
		if (arm64)
		{
			g_macArm64 = new MacArm64Platform(arm64);
			g_iosArm64 = new IOSArm64Platform(arm64);
			Platform::Register("mac", g_macArm64);
			Platform::Register("ios", g_iosArm64);
			viewType->RegisterPlatformRecognizer(0, LittleEndian, MacArm64Platform::Recognize);
			viewType->RegisterPlatformRecognizer(0x0100000c, LittleEndian, MacArm64Platform::Recognize);
			viewType->RegisterPlatformRecognizer(0x0200000c, LittleEndian, MacArm64Platform::Recognize);
			viewType->RegisterPlatformRecognizer(0, LittleEndian, IOSArm64Platform::Recognize);
			viewType->RegisterPlatformRecognizer(0x0100000c, LittleEndian, IOSArm64Platform::Recognize);
		}

		return true;
	}
}
