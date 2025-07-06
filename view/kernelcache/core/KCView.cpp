//
// Created by kat on 5/23/23.
//

/*
 *
 * */

#include "KCView.h"
#include "macho/types.h"
#include "KernelCache.h"

[[maybe_unused]] KCViewType* g_kcViewType;


#define COMPRESSION_DEBUG 1

using namespace BinaryNinja;


KCView::KCView(const std::string& typeName, BinaryView* data, bool parseOnly) :
	BinaryView(typeName, data->GetFile(), data), m_parseOnly(parseOnly)
{
	CreateLogger("KernelCache");
}

KCView::~KCView()
{
}

enum KCPlatform {
	KCPlatformMacOS = 1,
	KCPlatformiOS = 2,
	KCPlatformTVOS = 3,
	KCPlatformWatchOS = 4,
	KCPlatformBridgeOS = 5,			// T1/T2 APL1023/T8012, this is your touchbar/touchid in intel macs. Similar to watchOS.
	// KCPlatformMacCatalyst = 6,
	KCPlatformiOSSimulator = 7,
	KCPlatformTVOSSimulator = 8,
	KCPlatformWatchOSSimulator = 9,
	KCPlatformVisionOS = 11,			// Apple Vision Pro
	KCPlatformVisionOSSimulator = 12	// Apple Vision Pro Simulator
};

bool KCView::Init()
{
	BinaryReader reader(GetParentView());
	reader.Seek(0x4);
	uint32_t cpuType = reader.Read32();
	reader.Seek(0x10);
	uint64_t ncmds = reader.Read32();
	uint64_t sizeofcmds = reader.Read32();

	// get __TEXT seg offset
	uint64_t textSegOffset = 0;
	uint64_t anyFilesetHeaderFileOffset = 0;
	uint64_t offset = 0x20;
	for (uint64_t i = 0; i < ncmds; i++)
	{
		reader.Seek(offset);
		uint64_t cmd = reader.Read32();
		uint64_t cmdsize = reader.Read32();
		if (textSegOffset == 0 && cmd == LC_SEGMENT_64)
		{
			uint64_t segname = reader.Read64();
			reader.Read64();
			uint64_t vmaddr = reader.Read64();
			if (segname == 0x545845545f5f) // __TEXT
			{
				textSegOffset = vmaddr;
			}
		}

		if (anyFilesetHeaderFileOffset == 0 && cmd == LC_FILESET_ENTRY)
		{
			reader.SeekRelative(8);
			anyFilesetHeaderFileOffset = reader.Read64();
		}

		offset += cmdsize;
		if (textSegOffset && anyFilesetHeaderFileOffset)
			break;
	}

	Ref<Platform> platform;
	Ref<Architecture> architecture;

	if (anyFilesetHeaderFileOffset)
	{
		reader.Seek(anyFilesetHeaderFileOffset);
		reader.SeekRelative(0x10);

		uint64_t ncmdsFH = reader.Read32();

		reader.Seek(anyFilesetHeaderFileOffset + 0x20);
		offset = anyFilesetHeaderFileOffset + 0x20;
		bool foundBuildVersion = false;
		for (uint64_t i = 0; i < ncmdsFH; i++)
		{
			reader.Seek(offset);
			uint64_t cmd = reader.Read32();
			uint64_t cmdsize = reader.Read32();
			if (cmd == LC_BUILD_VERSION)
			{
				uint32_t platformID = reader.Read32();
				std::map<std::string, Ref<Metadata>> metadataMap = {
					{"machoplatform", new Metadata((uint64_t) platformID)},
				};
				Ref<Metadata> metadata = new Metadata(metadataMap);
				Ref<Platform> plat = g_kcViewType->RecognizePlatform(cpuType, GetDefaultEndianness(), this, metadata);
				SetDefaultArchitecture(plat->GetArchitecture());
				SetDefaultPlatform(plat);
				foundBuildVersion = true;
			}
			offset += cmdsize;
		}
		if (!foundBuildVersion)
		{
			LogError("Failed to find LC_BUILD_VERSION in subheader");
			SetDefaultArchitecture(Architecture::GetByName("aarch64"));
			SetDefaultPlatform(Platform::GetByName("macos-kernel-aarch64"));
		}
	}
	else
	{
		LogError("MH_FILESET had no subheaders");
		return false;
	}

	if (textSegOffset == 0)
	{
		LogError("Failed to find __TEXT segment");
		return false;
	}

	MachO::CreateHeaderTypes(this);

	std::vector<KernelCacheCore::MemoryRegion> regionsMappedIntoMemory;
	if (auto metadata = KernelCacheCore::KernelCacheMetadata::LoadFromView(GetParentView()))
	{
		for (const auto& image : metadata->LoadedImages())
		{
			auto header = KernelCacheCore::KernelCache::LoadHeaderForAddress(this, image.headerFileLocation, image.installName);
			if (!header)
			{
				LogError("Failed to load header for image %s", image.installName.c_str());
				return false;
			}
			if (!KernelCacheCore::KernelCache::InitializeSegmentsForHeader(this, *header, image))
			{
				LogError("Failed to initialize segments for image %s", image.installName.c_str());
				return false;
			}
			KernelCacheCore::KernelCache::InitializeHeader(this, *header);
		}
	}

	// Technically the header is executable, but there shouldn't reasonably be code in the header.
	AddAutoSegment(textSegOffset, sizeofcmds + 0x20, 0, sizeofcmds + 0x20, SegmentReadable);
	AddAutoSection("kernelcache_header", textSegOffset, sizeofcmds + 0x20, ReadOnlyDataSectionSemantics);

	if (m_parseOnly)
		return true;
	
	DefineDataVariable(textSegOffset, Type::NamedType(this, QualifiedName("mach_header_64")));
	DefineAutoSymbol(
		new Symbol(DataSymbol, "kernelcache_header", textSegOffset, LocalBinding));
	
	MachO::ApplyHeaderTypes(this, nullptr, reader, "kernelcache", textSegOffset + sizeof(mach_header_64), ncmds);

	return true;
}


KCViewType::KCViewType() : BinaryViewType(KC_VIEW_NAME, KC_VIEW_NAME)
{
}

BinaryNinja::Ref<BinaryNinja::BinaryView> KCViewType::Create(BinaryNinja::BinaryView* data)
{
	uint32_t magic;
	data->Read(&magic, data->GetStart(), 4);
	if (magic != MH_CIGAM_64 && magic != MH_MAGIC_64) // FIXME 32 bit
	{
		uint32_t im4pMagic;
		data->Read(&im4pMagic, data->GetStart() + 0x8, 4);
		if (im4pMagic == 0x50344d49) // P4MI
		{
			auto img4 = Transform::GetByName("IMG4-Unencrypted");

			DataBuffer img4Payload;
			img4->Decode(data->ReadBuffer(data->GetStart(), data->GetLength()), img4Payload);

			DataBuffer machOPayload;
			uint32_t magic = ((uint32_t*)img4Payload.GetData())[0];
			if (magic == FAT_MAGIC_64 || magic == MH_MAGIC_64 || magic == MH_MAGIC
				|| magic == MH_CIGAM_64 || magic == MH_CIGAM )
			{
				machOPayload = img4Payload;
			}
			else if (strncmp((char*)img4Payload.GetData(), "bvx2", 4) == 0)
			{
				auto lzfse = Transform::GetByName("LZFSE");
				if (lzfse)
					lzfse->Decode(img4Payload, machOPayload);
			}
			else
			{
#ifdef COMPRESSION_DEBUG
				LogError("Unknown compression type in IMG4 Payload, writing img4 payload to RAW view for debug purposes.");
				LogError("KernelCache parsing will now fail to proceed.");
				data->WriteBuffer(0, img4Payload);
				return new KCView(KC_VIEW_NAME, data, false);
#else
				LogError("Unknown compression type in IMG4 Payload, unable to proceed.");
				LogError("You can manually extract the kernelcache using `kerneldec`,`ipsw`, or other tools.")
				return nullptr;
#endif
			}

			if (machOPayload.GetLength() == 0)
			{
#ifdef COMPRESSION_DEBUG
				LogError("Failed to perform extraction on IMG4 Payload, writing img4 payload to RAW view for debug purposes.");
				LogError("KernelCache parsing will now fail to proceed.");
				data->WriteBuffer(0, img4Payload);
				return new KCView(KC_VIEW_NAME, data, false);
#else
				return nullptr;
#endif
			}

			uint32_t machoMagic = ((uint32_t*)machOPayload.GetData())[0];
			if (machoMagic == FAT_MAGIC_64)
			{
				DataBuffer output = machOPayload.GetSlice(0x1c, machOPayload.GetLength()-0x1c);
				data->WriteBuffer(0, output);
			}
			else if (machoMagic == MH_MAGIC_64 || machoMagic == MH_MAGIC || machoMagic == MH_CIGAM_64 || machoMagic == MH_CIGAM)
			{
				data->WriteBuffer(0, machOPayload);
			}
			else
			{
#ifdef COMPRESSION_DEBUG
				LogError("Unknown Mach-O magic in IMG4 Payload, writing img4 payload to RAW view for debug purposes.");
				LogError("KernelCache parsing will now fail to proceed.");
				data->WriteBuffer(0, machOPayload);
				return new KCView(KC_VIEW_NAME, data, false);
#else
				return nullptr;
#endif
			}

			return new KCView(KC_VIEW_NAME, data, false);
		}

		return nullptr;
	}

	return new KCView(KC_VIEW_NAME, data, false);
}


Ref<Settings> KCViewType::GetLoadSettingsForData(BinaryView* data)
{
	Ref<BinaryView> viewRef = Parse(data);
	if (!viewRef || !viewRef->Init())
	{
		LogWarn("Failed to initialize view of type '%s'. Generating default load settings.", GetName().c_str());
		viewRef = data;
	}

	Ref<Settings> settings = GetDefaultLoadSettingsForData(viewRef);

	// specify default load settings that can be overridden
	std::vector<std::string> overrides = {"loader.imageBase", "loader.platform"};
	settings->UpdateProperty("loader.imageBase", "message", "Note: File indicates image is not relocatable.");

	for (const auto& override : overrides)
	{
		if (settings->Contains(override))
			settings->UpdateProperty(override, "readOnly", false);
	}

	// Merge existing load settings if they exist. This allows for the selection of a specific object file from a Mach-O
	// Universal file. The 'Universal' BinaryViewType generates a schema with 'loader.universal.architectures'. This
	// schema contains an appropriate 'Mach-O' load schema for selecting a specific object file. The embedded schema
	// contains 'loader.macho.universalImageOffset'.
	Ref<Settings> loadSettings = viewRef->GetLoadSettings(GetName());
	if (loadSettings && !loadSettings->IsEmpty())
		settings->DeserializeSchema(loadSettings->SerializeSchema());

	return settings;
}


BinaryNinja::Ref<BinaryNinja::BinaryView> KCViewType::Parse(BinaryNinja::BinaryView* data)
{
	uint32_t magic;
	data->Read(&magic, data->GetStart(), 4);
	if (magic != MH_CIGAM_64 && magic != MH_MAGIC_64) // FIXME 32 bit
	{
		uint32_t im4pMagic;
		data->Read(&im4pMagic, data->GetStart() + 0x8, 4);
		if (im4pMagic == 0x50344d49) // P4MI
		{
			auto img4 = Transform::GetByName("IMG4-Unencrypted");
			auto lzfse = Transform::GetByName("LZFSE");

			DataBuffer img4Payload;
			img4->Decode(data->ReadBuffer(data->GetStart(), data->GetLength()), img4Payload);
			DataBuffer machOPayload;
			lzfse->Decode(img4Payload, machOPayload);

			uint32_t magic = ((uint32_t*)machOPayload.GetData())[0];
			auto id = data->BeginUndoActions();
			if (magic == FAT_MAGIC_64)
			{
				DataBuffer output = machOPayload.GetSlice(0x1c, machOPayload.GetLength()-0x1c);
				data->WriteBuffer(0, output);
			}
			else
			{
				data->WriteBuffer(0, machOPayload);
			}
			data->ForgetUndoActions(id);
			return new KCView(KC_VIEW_NAME, data, true);
		}

		return nullptr;
	}

	return new KCView(KC_VIEW_NAME, data, true);
}

bool KCViewType::IsTypeValidForData(BinaryNinja::BinaryView* data)
{
	if (!data)
		return false;

	uint32_t magic;
	data->Read(&magic, data->GetStart(), 4);

	if (magic != MH_CIGAM_64 && magic != MH_MAGIC_64) // FIXME 32 bit
	{
		uint32_t im4pMagic;
		data->Read(&im4pMagic, data->GetStart() + 0x8, 4);
		if (im4pMagic == 0x50344d49) // P4MI
		{
			auto img4 = Transform::GetByName("IMG4-Unencrypted");
			auto lzfse = Transform::GetByName("LZFSE");

			DataBuffer img4Payload;
			img4->Decode(data->ReadBuffer(data->GetStart(), data->GetLength()), img4Payload);
			DataBuffer machOPayload;
			lzfse->Decode(img4Payload, machOPayload);

			uint32_t magic = ((uint32_t*)machOPayload.GetData())[0];
			if (magic == FAT_MAGIC_64 || magic == MH_CIGAM_64 || magic == MH_MAGIC_64)
				return true;

			return false;
		}

		return false;
	}

	uint32_t fileType;
	data->Read(&fileType, data->GetStart() + 0xc, 4);
	if (fileType != MH_FILESET)
	{
		return false;
	}

	return true;
}

extern "C" {
	void InitKCViewType()
	{
		static KCViewType type;
		BinaryViewType::Register(&type);
		g_kcViewType = &type;
	}
}

