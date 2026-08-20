#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


Ref<Platform> g_macKernelX86, g_macKernelX64, g_macKernelArmv7, g_macKernelThumb2, g_macKernelArm64;
Ref<Platform> g_iosKernelArmv7, g_iosKernelThumb2, g_iosKernelArm64;


class MacKernelX86Platform: public Platform
{
public:
	MacKernelX86Platform(Architecture* arch): Platform(arch, "mac-kernel-x86")
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
			return g_macKernelX86;

		return nullptr;
	}
};


class MacKernelX64Platform: public Platform
{
public:
	MacKernelX64Platform(Architecture* arch): Platform(arch, "mac-kernel-x86_64")
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
			return g_macKernelX64;

		return nullptr;
	}
};


class MacKernelArmv7Platform: public Platform
{
public:
	MacKernelArmv7Platform(Architecture* arch, const std::string& name): Platform(arch, name)
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
			return g_macKernelArmv7;

		return nullptr;
	}
};


class MacKernelArm64Platform: public Platform
{
public:
	MacKernelArm64Platform(Architecture* arch): Platform(arch, "mac-kernel-aarch64")
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
			return g_macKernelArm64;

		return nullptr;
	}
};


class IOSKernelArmv7Platform: public Platform
{
public:
	IOSKernelArmv7Platform(Architecture* arch, const std::string& name): Platform(arch, name)
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
		return g_iosKernelArmv7;
	}
};

class IOSKernelArm64Platform: public Platform
{
public:
	IOSKernelArm64Platform(Architecture* arch): Platform(arch, "ios-kernel-aarch64")
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
		return g_iosKernelArm64;
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
		AddOptionalPluginDependency("sharedcache");
	}
#endif

#ifdef DEMO_EDITION
	bool MacKernelPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		Ref<BinaryViewType> viewType = BinaryViewType::GetByName("KCView");
		Ref<Architecture> x86 = Architecture::GetByName("x86");
		if (x86)
		{
			g_macKernelX86 = new MacKernelX86Platform(x86);
			Platform::Register("mac-kernel", g_macKernelX86);
			if (viewType)
				viewType->RegisterPlatformRecognizer(7, LittleEndian, MacKernelX86Platform::Recognize);
		}

		Ref<Architecture> x64 = Architecture::GetByName("x86_64");
		if (x64)
		{
			g_macKernelX64 = new MacKernelX64Platform(x64);
			Platform::Register("mac-kernel", g_macKernelX64);
			if (viewType)
				viewType->RegisterPlatformRecognizer(0x01000007, LittleEndian, MacKernelX64Platform::Recognize);
		}

		Ref<Architecture> armv7 = Architecture::GetByName("armv7");
		Ref<Architecture> thumb2 = Architecture::GetByName("thumb2");
		if (armv7 && thumb2)
		{
			g_macKernelArmv7 = new MacKernelArmv7Platform(armv7, "mac-kernel-armv7");
			g_macKernelThumb2 = new MacKernelArmv7Platform(thumb2, "mac-kernel-thumb2");
			g_iosKernelArmv7 = new IOSKernelArmv7Platform(armv7, "ios-kernel-armv7");
			g_iosKernelThumb2 = new IOSKernelArmv7Platform(thumb2, "ios-kernel-thumb2");
			g_macKernelArmv7->AddRelatedPlatform(thumb2, g_macKernelThumb2);
			g_macKernelThumb2->AddRelatedPlatform(armv7, g_macKernelArmv7);
			g_iosKernelArmv7->AddRelatedPlatform(thumb2, g_iosKernelThumb2);
			g_iosKernelThumb2->AddRelatedPlatform(armv7, g_iosKernelArmv7);
			Platform::Register("mac-kernel", g_macKernelArmv7);
			Platform::Register("ios-kernel", g_iosKernelArmv7);
			Platform::Register("mac-kernel", g_macKernelThumb2);
			Platform::Register("ios-kernel", g_iosKernelThumb2);
			if (viewType)
			{
				viewType->RegisterPlatformRecognizer(0xc, LittleEndian, MacKernelArmv7Platform::Recognize);
				viewType->RegisterPlatformRecognizer(0xc, LittleEndian, IOSKernelArmv7Platform::Recognize);
			}
		}

		Ref<Architecture> arm64 = Architecture::GetByName("aarch64");
		if (arm64)
		{
			g_macKernelArm64 = new MacKernelArm64Platform(arm64);
			g_iosKernelArm64 = new IOSKernelArm64Platform(arm64);
			Platform::Register("mac-kernel", g_macKernelArm64);
			Platform::Register("ios-kernel", g_iosKernelArm64);
			if (viewType)
			{
				viewType->RegisterPlatformRecognizer(0, LittleEndian, MacKernelArm64Platform::Recognize);
				viewType->RegisterPlatformRecognizer(0x0100000c, LittleEndian, MacKernelArm64Platform::Recognize);
				viewType->RegisterPlatformRecognizer(0x0200000c, LittleEndian, MacKernelArm64Platform::Recognize);
				viewType->RegisterPlatformRecognizer(0, LittleEndian, IOSKernelArm64Platform::Recognize);
				viewType->RegisterPlatformRecognizer(0x0100000c, LittleEndian, IOSKernelArm64Platform::Recognize);
			}
		}

		return true;
	}
}
