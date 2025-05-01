//
// Created by kat on 5/19/23.
//

#include "binaryninjaapi.h"

/* ---
 * This is the primary image loader logic for Kernelcaches.
 * */

#include "KernelCache.h"
#include <filesystem>
#include <utility>
#include <fcntl.h>
#include <memory>
#include <chrono>
#include <thread>


using namespace BinaryNinja;
using namespace KernelCacheCore;

namespace KernelCacheCore {
	
		

#ifdef _MSC_VER

int count_trailing_zeros(uint64_t value) {
	unsigned long index; // 32-bit long on Windows
	if (_BitScanForward64(&index, value)) {
		return index;
	} else {
		return 64; // If the value is 0, return 64.
	}
}
#else
int count_trailing_zeros(uint64_t value) {
	return value == 0 ? 64 : __builtin_ctzll(value);
}
#endif

// State that does not change after `PerformInitialLoad`.
struct KernelCache::CacheInfo :
	public MetadataSerializable<KernelCache::CacheInfo, std::optional<KernelCache::CacheInfo>>
{
	// std::unordered_map<uint64_t, KernelCacheMachOHeader> headers;
	std::vector<KernelCacheImage> images;
	std::unordered_map<std::string, uint64_t> imageStarts;

	KernelCacheFormat cacheFormat = FilesetCacheFormat;

#ifndef NDEBUG
	void Verify() const;
#endif

	uint64_t BaseAddress() const;

	void Store(SerializationContext&) const;
	static std::optional<KernelCache::CacheInfo> Load(DeserializationContext&);
};

struct State : public MetadataSerializable<State>
{
	std::unordered_map<uint64_t, KernelCacheImage> loadedImages;
	// Store only. Loading is done via `ModifiedState`.
	void Store(SerializationContext&, std::optional<KCViewState> viewState) const;
};

struct KernelCache::ModifiedState : public State, public MetadataSerializable<KernelCache::ModifiedState>
{
	std::optional<KCViewState> viewState;

	using Base = MetadataSerializable<KernelCache::ModifiedState>;
	using Base::AsMetadata;
	using Base::LoadFromString;

	void Store(SerializationContext&) const;
	static KernelCache::ModifiedState Load(DeserializationContext&);
	static KernelCache::ModifiedState LoadAll(BinaryNinja::BinaryView*, const CacheInfo&);

	void Merge(KernelCache::ModifiedState&& other);
};

struct KernelCache::ViewSpecificState
{
	std::mutex typeLibraryMutex;
	std::unordered_map<std::string, Ref<TypeLibrary>> typeLibraries;

	std::mutex viewOperationsThatInfluenceMetadataMutex;

	std::atomic<BNKCViewLoadProgress> progress;

	std::mutex cacheInfoMutex;
	std::shared_ptr<const KernelCache::CacheInfo> cacheInfo;

	std::mutex stateMutex;
	struct State state;

	std::atomic<KCViewState> viewState;
	uint64_t savedModifications = 0;
};

namespace {

	std::shared_ptr<KernelCache::ViewSpecificState> ViewSpecificStateForId(
		uint64_t viewIdentifier, bool insertIfNeeded = true)
	{
		static std::mutex viewSpecificStateMutex;
		static std::unordered_map<uint64_t, std::weak_ptr<KernelCache::ViewSpecificState>> viewSpecificState;

		std::lock_guard lock(viewSpecificStateMutex);

		if (auto it = viewSpecificState.find(viewIdentifier); it != viewSpecificState.end())
		{
			if (auto statePtr = it->second.lock())
				return statePtr;
		}

		if (!insertIfNeeded)
			return nullptr;

		auto statePtr = std::make_shared<KernelCache::ViewSpecificState>();
		viewSpecificState[viewIdentifier] = statePtr;

		// Prune entries for any views that are no longer in use.
		for (auto it = viewSpecificState.begin(); it != viewSpecificState.end();)
		{
			if (it->second.expired())
				it = viewSpecificState.erase(it);
			else
				++it;
		}

		return statePtr;
	}

	std::shared_ptr<KernelCache::ViewSpecificState> ViewSpecificStateForView(Ref<BinaryNinja::BinaryView> view)
	{
		return ViewSpecificStateForId(view->GetFile()->GetSessionId());
	}

	std::string base_name(std::string const& path)
	{
		return path.substr(path.find_last_of("/\\") + 1);
	}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
	static int64_t readSLEB128(DataBuffer& buffer, size_t length, size_t& offset)
	{
		uint8_t cur;
		int64_t value = 0;
		size_t shift = 0;
		while (offset < length)
		{
			cur = buffer[offset++];
			value |= (cur & 0x7f) << shift;
			shift += 7;
			if ((cur & 0x80) == 0)
				break;
		}
		value = (value << (64 - shift)) >> (64 - shift);
		return value;
	}
#pragma clang diagnostic pop


	static uint64_t readLEB128(DataBuffer& p, size_t end, size_t& offset)
	{
		uint64_t result = 0;
		int bit = 0;
		do
		{
			if (offset >= end)
				return -1;

			uint64_t slice = p[offset] & 0x7f;

			if (bit > 63)
				return -1;
			else
			{
				result |= (slice << bit);
				bit += 7;
			}
		} while (p[offset++] & 0x80);
		return result;
	}


	uint64_t readValidULEB128(DataBuffer& buffer, size_t& cursor)
	{
		uint64_t value = readLEB128(buffer, buffer.GetLength(), cursor);
		if ((int64_t)value == -1)
			throw ReadException();
		return value;
	}

} // namespace

void KernelCache::PerformInitialLoad(std::lock_guard<std::mutex>& lock)
{
	bool is64 = m_kcView->GetAddressSize() == 8;

	m_logger->LogInfo("Performing initial load of Kernel Cache");

    m_viewSpecificState->progress = LoadProgressLoadingCaches;

	CacheInfo initialState;
	initialState.cacheFormat = FilesetCacheFormat;

	m_viewSpecificState->progress = LoadProgressLoadingImages;

	// We have set up enough metadata to map VM now.
	// Iterate load comands:
	BinaryReader reader(m_kcView->GetParentView());

	uint32_t magic = reader.Read32();
	if (magic != MH_CIGAM_64 && magic != MH_MAGIC_64) // FIXME 32 bit
	{
		m_logger->LogError("Invalid magic number in KernelCache");
		return;
	}
	uint32_t cpuType = reader.Read32();
	reader.SeekRelative(4);
	uint32_t fileType = reader.Read32();
	if (fileType != MH_FILESET)
	{
		m_logger->LogError("Invalid file type in KernelCache");
		return;
	}
	uint32_t ncmds = reader.Read32();
	reader.SeekRelative(8);
	if ((cpuType & MachOABIMask) != MachOABI64)
	{
		m_logger->LogError("Invalid ABI in KernelCache. 32 bit not yet supported.");
		return;
	}
	if (is64)
		reader.SeekRelative(4);

	uint64_t off = reader.GetOffset();

	while (ncmds--)
	{
		reader.Seek(off);
		uint32_t cmd = reader.Read32();
		uint32_t cmdsize = reader.Read32();
		if (cmd == LC_FILESET_ENTRY)
		{
			// uint64_t vmAddr =reader.Read64();
			reader.SeekRelative(m_kcView->GetAddressSize());
			uint64_t fileOff = reader.Read64();
			uint32_t entryID = reader.Read32();
			reader.Seek(entryID + off);
			std::string installName = reader.ReadCString(0x1000);
			initialState.imageStarts[installName] = fileOff;
		}
		off += cmdsize;
	}

	for (const auto& start : initialState.imageStarts)
	{
		try {
			auto imageHeader = KernelCache::LoadHeaderForAddress(m_kcView, start.second, start.first);
			if (imageHeader)
			{
				KernelCacheImage image;
				image.installName = start.first;
				image.headerFileLocation = start.second;
				for (const auto& segment : imageHeader->segments)
				{
					char segName[17];
					memcpy(segName, segment.segname, 16);
					segName[16] = 0;
					MemoryRegion sectionRegion;
					sectionRegion.prettyName = imageHeader.value().identifierPrefix + "::" + std::string(segName);
					sectionRegion.start = segment.vmaddr;
					sectionRegion.size = segment.vmsize;
					sectionRegion.fileOffset = segment.fileoff;
					uint32_t flags = 0;
					if (segment.initprot & MACHO_VM_PROT_READ)
						flags |= SegmentReadable;
					if (segment.initprot & MACHO_VM_PROT_WRITE)
						flags |= SegmentWritable;
					if (segment.initprot & MACHO_VM_PROT_EXECUTE)
						flags |= SegmentExecutable;
					if (((segment.initprot & MACHO_VM_PROT_WRITE) == 0) &&
						((segment.maxprot & MACHO_VM_PROT_WRITE) == 0))
						flags |= SegmentDenyWrite;
					if (((segment.initprot & MACHO_VM_PROT_EXECUTE) == 0) &&
						((segment.maxprot & MACHO_VM_PROT_EXECUTE) == 0))
						flags |= SegmentDenyExecute;

					// if we're positive we have an entry point for some reason, force the segment
					// executable. this helps with kernel images.
					for (auto &entryPoint : imageHeader->m_entryPoints)
						if (segment.vmaddr <= entryPoint && (entryPoint < (segment.vmaddr + segment.filesize)))
							flags |= SegmentExecutable;

					sectionRegion.flags = (BNSegmentFlag)flags;
					image.regions.push_back(sectionRegion);
				}
				initialState.images.push_back(image);
			}
			else
			{
				m_logger->LogError("Failed to load Mach-O header for %s", start.first.c_str());
			}
		}
		catch (std::exception& ex)
		{
			m_logger->LogError("Failed to load Mach-O header for %s: %s", start.first.c_str(), ex.what());
		}
	}

	m_cacheInfo = std::make_shared<CacheInfo>(std::move(initialState));
	m_modifiedState->viewState = KCViewStateLoaded;
	SaveCacheInfoToKCView(lock);
	SaveModifiedStateToKCView(lock);

	m_logger->LogDebug("Finished initial load of KernelCache");

	m_viewSpecificState->progress = LoadProgressFinished;
}

void KernelCache::DeserializeFromRawView(std::lock_guard<std::mutex>& lock)
{
	std::lock_guard cacheInfoLock(m_viewSpecificState->cacheInfoMutex);
	if (m_viewSpecificState->cacheInfo)
	{
		m_cacheInfo = m_viewSpecificState->cacheInfo;
		m_modifiedState = std::make_unique<ModifiedState>();
		m_metadataValid = true;
		return;
	}

	if (KernelCacheMetadata::ViewHasMetadata(m_kcView))
	{
		auto metadata = KernelCacheMetadata::LoadFromView(m_kcView);
		if (!metadata)
		{
			m_metadataValid = false;
			m_logger->LogError("Failed to deserialize Shared Cache metadata");
			return;
		}

		m_viewSpecificState->viewState = metadata->state->viewState.value_or(KCViewStateUnloaded);
		m_viewSpecificState->state = std::move(*metadata->state);
		m_viewSpecificState->cacheInfo = std::move(metadata->cacheInfo);

		m_cacheInfo = m_viewSpecificState->cacheInfo;
		m_modifiedState = std::make_unique<ModifiedState>();
		m_metadataValid = true;
		return;
	}

	m_cacheInfo = nullptr;
	m_modifiedState = std::make_unique<ModifiedState>();
	m_modifiedState->viewState = KCViewStateUnloaded;
	m_metadataValid = true;
}


std::string to_hex_string(uint64_t value)
{
	std::stringstream ss;
	ss << std::hex << value;
	return ss.str();
}


KernelCache::KernelCache(BinaryNinja::Ref<BinaryNinja::BinaryView> kcView) : m_kcView(kcView),
	m_viewSpecificState(ViewSpecificStateForView(kcView))
{
	std::lock_guard lock(m_mutex);
	m_logger = LogRegistry::GetLogger("KernelCache", kcView->GetFile()->GetSessionId());
	if (kcView->GetTypeName() != KC_VIEW_NAME)
	{
		// Unreachable?
		m_logger->LogError("Attempted to create KernelCache object from non-KernelCache view");
		return;
	}

	INIT_KERNELCACHE_API_OBJECT()
	DeserializeFromRawView(lock);
	if (!m_metadataValid)
		return;

	if (m_modifiedState->viewState.value_or(m_viewSpecificState->viewState) != KCViewStateUnloaded)
	{
		m_viewSpecificState->progress = LoadProgressFinished;
		return;
	}

	std::unique_lock viewOperationsLock(m_viewSpecificState->viewOperationsThatInfluenceMetadataMutex);

	try {
		PerformInitialLoad(lock);
	}
	catch (...)
	{
		m_logger->LogError("Failed to perform initial load of KernelCache");
	}
}

KernelCache::~KernelCache() {
}

KernelCache* KernelCache::GetFromKCView(BinaryNinja::Ref<BinaryNinja::BinaryView> kcView)
{
	if (kcView->GetTypeName() != KC_VIEW_NAME)
		return nullptr;
	try {
		return new KernelCache(kcView);
	}
	catch (...)
	{
		return nullptr;
	}
}


uint64_t KernelCache::FastGetImageCount(BinaryNinja::Ref<BinaryNinja::BinaryView> kcView)
{
	if (!kcView->GetParentView())
		return 0;
	auto reader = BinaryReader(kcView->GetParentView());
	uint32_t magic = reader.Read32();
	if (magic != MH_CIGAM_64 && magic != MH_MAGIC_64) // FIXME 32 bit
	{
		return 0;
	}
	reader.Seek(0xc);
	uint32_t fileType = reader.Read32();
	if (fileType != MH_FILESET)
	{
		return 0;
	}
	uint32_t ncmds = reader.Read32();

	uint64_t imageCount = 0;

	uint64_t off = 0x20; // FIXME 32 bit
	while (ncmds--)
	{
		reader.Seek(off);
		uint32_t cmd = reader.Read32();
		uint32_t cmdsize = reader.Read32();
		if (cmd == LC_FILESET_ENTRY)
		{
			imageCount++;
		}
		off += cmdsize;
	}

	return imageCount;
}


const std::unordered_map<std::string, uint64_t>& KernelCache::AllImageStarts() const
{
	return m_cacheInfo->imageStarts;
}


const std::unordered_map<uint64_t, KernelCacheMachOHeader> KernelCache::AllImageHeaders() const
{
	std::unordered_map<uint64_t, KernelCacheMachOHeader> headers;
	for (const auto& start : m_cacheInfo->imageStarts)
	{
		auto header = LoadHeaderForAddress(m_kcView, start.second, start.first);
		if (header)
		{
			headers[start.second] = *header;
		}
	}
	return headers;
}


KCViewState KernelCache::ViewState() const
{
	return m_viewSpecificState->viewState;
}

std::optional<uint64_t> KernelCache::GetImageStart(std::string installName)
{
	for (const auto& [name, start] : m_cacheInfo->imageStarts)
	{
		if (name == installName)
		{
			return start;
		}
	}
	return {};
}

std::optional<KernelCacheMachOHeader> KernelCache::HeaderForVMAddress(uint64_t address)
{
	for (const auto& img : m_cacheInfo->images)
	{
		for (const auto& region : img.regions)
		{
			if (region.start <= address && region.start + region.size > address)
			{
				return LoadHeaderForAddress(m_kcView, img.headerFileLocation, img.installName);
			}
		}
	}
	return {};
}

std::optional<KernelCacheMachOHeader> KernelCache::HeaderForFileAddress(uint64_t address)
{
	for (const auto& img : m_cacheInfo->images)
	{
		for (const auto& region : img.regions)
		{
			if (region.fileOffset <= address && region.fileOffset + region.size > address)
			{
				return LoadHeaderForAddress(m_kcView, img.headerFileLocation, img.installName);
			}
		}
	}
	return {};
}

std::string KernelCache::NameForAddress(uint64_t address)
{
	if (auto header = HeaderForVMAddress(address))
	{
		for (const auto& section : header->sections)
		{
			if (section.addr <= address && section.addr + section.size > address)
			{
				char sectionName[17];
				strncpy(sectionName, section.sectname, 16);
				sectionName[16] = '\0';
				return header->identifierPrefix + "::" + sectionName;
			}
		}
	}
	return "";
}

std::string KernelCache::ImageNameForAddress(uint64_t address)
{
	if (auto header = HeaderForVMAddress(address))
	{
		return header->identifierPrefix;
	}
	return "";
}

bool KernelCache::LoadImageContainingAddress(uint64_t address)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return LoadImageContainingAddress(lock, address);
}

bool KernelCache::LoadImageContainingAddress(std::lock_guard<std::mutex>& lock, uint64_t address)
{
	for (const auto& img : m_cacheInfo->images)
	{
		for (const auto& region : img.regions)
		{
			if (region.start <= address && region.start + region.size > address)
			{
				return LoadImageWithInstallName(lock, img.installName);
			}
		}
	}
	return false;
}


bool KernelCache::LoadImageWithInstallName(std::string installName)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return LoadImageWithInstallName(lock, installName);
}


bool KernelCache::LoadImageWithInstallName(std::lock_guard<std::mutex>& lock, std::string installName)
{
	auto settings = m_kcView->GetLoadSettings(KC_VIEW_NAME);

	std::lock_guard viewSpecificStateLock(m_viewSpecificState->viewOperationsThatInfluenceMetadataMutex);

	m_logger->LogInfo("Loading image %s", installName.c_str());
	const KernelCacheImage* targetImage = nullptr;

	// FIXME at some point the logic func should be one with targetImage passed, and an installName wrapper can be added.
	// 		In many use cases of this function we already have our target image.
	for (auto& cacheImage : m_cacheInfo->images)
	{
		if (cacheImage.installName == installName)
		{
			targetImage = &cacheImage;
			break;
		}
	}
	if (!targetImage)
		return false;

	const auto header = LoadHeaderForAddress(m_kcView, targetImage->headerFileLocation, targetImage->installName);
	if (!header)
		return false;

	m_modifiedState->viewState = KCViewStateLoadedWithImages;

	InitializeSegmentsForHeader(m_kcView, *header, *targetImage);

	// Optimize relocations we just added en masse.
	m_kcView->FinalizeNewSegments();

	// FIXME Load TypeLibrary here when we have those for the kernel.

	m_modifiedState->loadedImages[targetImage->headerFileLocation] = *targetImage;

	SaveModifiedStateToKCView(lock);

	auto h = KernelCache::LoadHeaderForAddress(m_kcView, targetImage->headerFileLocation, installName);
	if (!h.has_value())
	{
		return false;
	}

	KernelCache::InitializeHeader(m_kcView, *h);

	m_kcView->AddAnalysisOption("linearsweep");
	m_kcView->UpdateAnalysis();

	return true;
}

std::optional<KernelCacheMachOHeader> KernelCache::LoadHeaderForAddress(Ref<BinaryView> view, uint64_t address, std::string installName)
{
	KernelCacheMachOHeader header;

	header.installName = installName;
	header.identifierPrefix = base_name(installName);

	std::string errorMsg;
	// address is a Raw file offset
	BinaryReader reader(view->GetParentView());
	reader.Seek(address);

	header.ident.magic = reader.Read32();

	BNEndianness endianness;
	if (header.ident.magic == MH_MAGIC || header.ident.magic == MH_MAGIC_64)
		endianness = LittleEndian;
	else if (header.ident.magic == MH_CIGAM || header.ident.magic == MH_CIGAM_64)
		endianness = BigEndian;
	else
	{
		return {};
	}

	reader.SetEndianness(endianness);
	header.ident.cputype = reader.Read32();
	header.ident.cpusubtype = reader.Read32();
	header.ident.filetype = reader.Read32();
	header.ident.ncmds = reader.Read32();
	header.ident.sizeofcmds = reader.Read32();
	header.ident.flags = reader.Read32();
	if ((header.ident.cputype & MachOABIMask) == MachOABI64)  // address size == 8
	{
		header.ident.reserved = reader.Read32();
	}
	header.loadCommandOffset = reader.GetOffset();

	// Parse segment commands
	try
	{
		for (size_t i = 0; i < header.ident.ncmds; i++)
		{
			// BNLogInfo("of 0x%llx", reader.GetOffset());
			load_command load;
			segment_command_64 segment64;
			section_64 sect;
			memset(&sect, 0, sizeof(sect));
			size_t curOffset = reader.GetOffset();
			load.cmd = reader.Read32();
			load.cmdsize = reader.Read32();
			size_t nextOffset = curOffset + load.cmdsize;
			if (load.cmdsize < sizeof(load_command))
				return {};

			switch (load.cmd)
			{
			case LC_MAIN:
			{
				uint64_t entryPoint = reader.Read64();
				header.entryPoints.push_back({entryPoint, true});
				(void)reader.Read64();	// Stack start
				break;
			}
			case LC_SEGMENT:  // map the 32bit version to 64 bits
				segment64.cmd = LC_SEGMENT_64;
				reader.Read(&segment64.segname, 16);
				segment64.vmaddr = reader.Read32();
				segment64.vmsize = reader.Read32();
				segment64.fileoff = reader.Read32();
				segment64.filesize = reader.Read32();
				segment64.maxprot = reader.Read32();
				segment64.initprot = reader.Read32();
				segment64.nsects = reader.Read32();
				segment64.flags = reader.Read32();
				if (strncmp(segment64.segname, "__TEXT\0", 7) == 0)
				{
					header.relocationBase = segment64.vmaddr;
					header.textBase = segment64.vmaddr;
					header.textBaseFileOffset = segment64.fileoff;
				}
				for (size_t j = 0; j < segment64.nsects; j++)
				{
					reader.Read(&sect.sectname, 16);
					reader.Read(&sect.segname, 16);
					sect.addr = reader.Read32();
					sect.size = reader.Read32();
					sect.offset = reader.Read32();
					sect.align = reader.Read32();
					sect.reloff = reader.Read32();
					sect.nreloc = reader.Read32();
					sect.flags = reader.Read32();
					sect.reserved1 = reader.Read32();
					sect.reserved2 = reader.Read32();
					// if the segment isn't mapped into virtual memory don't add the corresponding sections.
					if (segment64.vmsize > 0)
					{
						header.sections.push_back(sect);
					}
					if (!strncmp(sect.sectname, "__mod_init_func", 15))
						header.moduleInitSections.push_back(sect);
					if (!strncmp(sect.sectname, "__mod_term_func", 15))
						header.moduleTermSections.push_back(sect);
					if ((sect.flags & (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						== (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						header.symbolStubSections.push_back(sect);
					if ((sect.flags & S_NON_LAZY_SYMBOL_POINTERS) == S_NON_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
					if ((sect.flags & S_LAZY_SYMBOL_POINTERS) == S_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
				}
				header.segments.push_back(segment64);
				break;
			case LC_SEGMENT_64:
				segment64.cmd = LC_SEGMENT_64;
				reader.Read(&segment64.segname, 16);
				segment64.vmaddr = reader.Read64();
				segment64.vmsize = reader.Read64();
				segment64.fileoff = reader.Read64();
				segment64.filesize = reader.Read64();
				segment64.maxprot = reader.Read32();
				segment64.initprot = reader.Read32();
				segment64.nsects = reader.Read32();
				segment64.flags = reader.Read32();
				if (strncmp(segment64.segname, "__LINKEDIT", 10) == 0)
				{
					header.linkeditSegment = segment64;
					header.linkeditPresent = true;
				}
				if (strncmp(segment64.segname, "__TEXT\0", 7) == 0)
				{
					header.relocationBase = segment64.vmaddr;
					header.textBase = segment64.vmaddr;
					header.textBaseFileOffset = segment64.fileoff;
				}
				for (size_t j = 0; j < segment64.nsects; j++)
				{
					reader.Read(&sect.sectname, 16);
					reader.Read(&sect.segname, 16);
					sect.addr = reader.Read64();
					sect.size = reader.Read64();
					sect.offset = reader.Read32();
					sect.align = reader.Read32();
					sect.reloff = reader.Read32();
					sect.nreloc = reader.Read32();
					sect.flags = reader.Read32();
					sect.reserved1 = reader.Read32();
					sect.reserved2 = reader.Read32();
					sect.reserved3 = reader.Read32();
					// if the segment isn't mapped into virtual memory don't add the corresponding sections.
					if (segment64.vmsize > 0)
					{
						header.sections.push_back(sect);
					}

					if (!strncmp(sect.sectname, "__mod_init_func", 15))
						header.moduleInitSections.push_back(sect);
					if ((sect.flags & (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						== (S_ATTR_SELF_MODIFYING_CODE | S_SYMBOL_STUBS))
						header.symbolStubSections.push_back(sect);
					if ((sect.flags & S_NON_LAZY_SYMBOL_POINTERS) == S_NON_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
					if ((sect.flags & S_LAZY_SYMBOL_POINTERS) == S_LAZY_SYMBOL_POINTERS)
						header.symbolPointerSections.push_back(sect);
				}
				header.segments.push_back(segment64);
				break;
			case LC_ROUTINES:  // map the 32bit version to 64bits
				header.routines64.cmd = LC_ROUTINES_64;
				header.routines64.init_address = reader.Read32();
				header.routines64.init_module = reader.Read32();
				header.routines64.reserved1 = reader.Read32();
				header.routines64.reserved2 = reader.Read32();
				header.routines64.reserved3 = reader.Read32();
				header.routines64.reserved4 = reader.Read32();
				header.routines64.reserved5 = reader.Read32();
				header.routines64.reserved6 = reader.Read32();
				header.routinesPresent = true;
				break;
			case LC_ROUTINES_64:
				header.routines64.cmd = LC_ROUTINES_64;
				header.routines64.init_address = reader.Read64();
				header.routines64.init_module = reader.Read64();
				header.routines64.reserved1 = reader.Read64();
				header.routines64.reserved2 = reader.Read64();
				header.routines64.reserved3 = reader.Read64();
				header.routines64.reserved4 = reader.Read64();
				header.routines64.reserved5 = reader.Read64();
				header.routines64.reserved6 = reader.Read64();
				header.routinesPresent = true;
				break;
			case LC_FUNCTION_STARTS:
				header.functionStarts.funcoff = reader.Read32();
				header.functionStarts.funcsize = reader.Read32();
				header.functionStartsPresent = true;
				break;
			case LC_SYMTAB:
				header.symtab.symoff = reader.Read32();
				header.symtab.nsyms = reader.Read32();
				header.symtab.stroff = reader.Read32();
				header.symtab.strsize = reader.Read32();
				break;
			case LC_DYSYMTAB:
				header.dysymtab.ilocalsym = reader.Read32();
				header.dysymtab.nlocalsym = reader.Read32();
				header.dysymtab.iextdefsym = reader.Read32();
				header.dysymtab.nextdefsym = reader.Read32();
				header.dysymtab.iundefsym = reader.Read32();
				header.dysymtab.nundefsym = reader.Read32();
				header.dysymtab.tocoff = reader.Read32();
				header.dysymtab.ntoc = reader.Read32();
				header.dysymtab.modtaboff = reader.Read32();
				header.dysymtab.nmodtab = reader.Read32();
				header.dysymtab.extrefsymoff = reader.Read32();
				header.dysymtab.nextrefsyms = reader.Read32();
				header.dysymtab.indirectsymoff = reader.Read32();
				header.dysymtab.nindirectsyms = reader.Read32();
				header.dysymtab.extreloff = reader.Read32();
				header.dysymtab.nextrel = reader.Read32();
				header.dysymtab.locreloff = reader.Read32();
				header.dysymtab.nlocrel = reader.Read32();
				header.dysymPresent = true;
				break;
			case LC_DYLD_CHAINED_FIXUPS:
				header.chainedFixups.dataoff = reader.Read32();
				header.chainedFixups.datasize = reader.Read32();
				header.chainedFixupsPresent = true;
				break;
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
				header.dyldInfo.rebase_off = reader.Read32();
				header.dyldInfo.rebase_size = reader.Read32();
				header.dyldInfo.bind_off = reader.Read32();
				header.dyldInfo.bind_size = reader.Read32();
				header.dyldInfo.weak_bind_off = reader.Read32();
				header.dyldInfo.weak_bind_size = reader.Read32();
				header.dyldInfo.lazy_bind_off = reader.Read32();
				header.dyldInfo.lazy_bind_size = reader.Read32();
				header.dyldInfo.export_off = reader.Read32();
				header.dyldInfo.export_size = reader.Read32();
				header.exportTrie.dataoff = header.dyldInfo.export_off;
				header.exportTrie.datasize = header.dyldInfo.export_size;
				header.exportTriePresent = true;
				header.dyldInfoPresent = true;
				break;
			case LC_DYLD_EXPORTS_TRIE:
				header.exportTrie.dataoff = reader.Read32();
				header.exportTrie.datasize = reader.Read32();
				header.exportTriePresent = true;
				break;
			case LC_THREAD:
			case LC_UNIXTHREAD:
				/*while (reader.GetOffset() < nextOffset)
				{

					thread_command thread;
					thread.flavor = reader.Read32();
					thread.count = reader.Read32();
					switch (m_archId)
					{
						case MachOx64:
							m_logger->LogDebug("x86_64 Thread state\n");
							if (thread.flavor != X86_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statex64, sizeof(thread.statex64));
							header.entryPoints.push_back({thread.statex64.rip, false});
							break;
						case MachOx86:
							m_logger->LogDebug("x86 Thread state\n");
							if (thread.flavor != X86_THREAD_STATE32)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statex86, sizeof(thread.statex86));
							header.entryPoints.push_back({thread.statex86.eip, false});
							break;
						case MachOArm:
							m_logger->LogDebug("Arm Thread state\n");
							if (thread.flavor != _ARM_THREAD_STATE)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//This wont be big endian so we can just read the whole thing
							reader.Read(&thread.statearmv7, sizeof(thread.statearmv7));
							header.entryPoints.push_back({thread.statearmv7.r15, false});
							break;
						case MachOAarch64:
						case MachOAarch6432:
							m_logger->LogDebug("Aarch64 Thread state\n");
							if (thread.flavor != _ARM_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							reader.Read(&thread.stateaarch64, sizeof(thread.stateaarch64));
							header.entryPoints.push_back({thread.stateaarch64.pc, false});
							break;
						case MachOPPC:
							m_logger->LogDebug("PPC Thread state\n");
							if (thread.flavor != PPC_THREAD_STATE)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							//Read individual entries for endian reasons
							header.entryPoints.push_back({reader.Read32(), false});
							(void)reader.Read32();
							(void)reader.Read32();
							//Read the rest of the structure
							(void)reader.Read(&thread.stateppc.r1, sizeof(thread.stateppc) - (3 * 4));
							break;
						case MachOPPC64:
							m_logger->LogDebug("PPC64 Thread state\n");
							if (thread.flavor != PPC_THREAD_STATE64)
							{
								reader.SeekRelative(thread.count * sizeof(uint32_t));
								break;
							}
							header.entryPoints.push_back({reader.Read64(), false});
							(void)reader.Read64();
							(void)reader.Read64(); // Stack start
							(void)reader.Read(&thread.stateppc64.r1, sizeof(thread.stateppc64) - (3 * 8));
							break;
						default:
							m_logger->LogError("Unknown archid: %x", m_archId);
					}

				}*/
				break;
			case LC_LOAD_DYLIB:
			{
				uint32_t offset = reader.Read32();
				if (offset < nextOffset)
				{
					reader.Seek(curOffset + offset);
					std::string libname = reader.ReadCString(reader.GetOffset());
					header.dylibs.push_back(libname);
				}
			}
			break;
			case LC_BUILD_VERSION:
			{
				// m_logger->LogDebug("LC_BUILD_VERSION:");
				header.buildVersion.platform = reader.Read32();
				header.buildVersion.minos = reader.Read32();
				header.buildVersion.sdk = reader.Read32();
				header.buildVersion.ntools = reader.Read32();
				// m_logger->LogDebug("Platform: %s", BuildPlatformToString(header.buildVersion.platform).c_str());
				// m_logger->LogDebug("MinOS: %s", BuildToolVersionToString(header.buildVersion.minos).c_str());
				// m_logger->LogDebug("SDK: %s", BuildToolVersionToString(header.buildVersion.sdk).c_str());
				for (uint32_t j = 0; (i < header.buildVersion.ntools) && (j < 10); j++)
				{
					uint32_t tool = reader.Read32();
					uint32_t version = reader.Read32();
					header.buildToolVersions.push_back({tool, version});
					// m_logger->LogDebug("Build Tool: %s: %s", BuildToolToString(tool).c_str(),
					// BuildToolVersionToString(version).c_str());
				}
				break;
			}
			case LC_FILESET_ENTRY:
			{
				throw ReadException();
			}
			default:
				// m_logger->LogDebug("Unhandled command: %s : %" PRIu32 "\n", CommandToString(load.cmd).c_str(),
				// load.cmdsize);
				break;
			}
			if (reader.GetOffset() != nextOffset)
			{
				// m_logger->LogDebug("Didn't parse load command: %s fully %" PRIx64 ":%" PRIxPTR,
				// CommandToString(load.cmd).c_str(), reader.GetOffset(), nextOffset);
			}
			reader.Seek(nextOffset);
		}

		for (auto& section : header.sections)
		{
			char sectionName[17];
			memcpy(sectionName, section.sectname, sizeof(section.sectname));
			sectionName[16] = 0;
			char segmentName[17];
			memcpy(segmentName, section.segname, sizeof(section.segname));
			segmentName[16] = 0;
			if (header.identifierPrefix.empty())
				header.sectionNames.push_back(sectionName);
			else
				header.sectionNames.push_back(header.identifierPrefix + "::" + segmentName + ":" + sectionName);
		}
	}
	catch (ReadException&)
	{
		return {};
	}

	return header;
}

bool KernelCache::InitializeSegmentsForHeader(Ref<BinaryView> view, const KernelCacheMachOHeader& header, const KernelCacheImage& targetImage)
{
	// FIXME this uselessly loads chained fixups if an image is already loaded.
	auto logger = LogRegistry::GetLogger("KernelCache", view->GetFile()->GetSessionId());

	bool hasRegionsToLoad = false;

	auto reader = BinaryReader(view->GetParentView());

	reader.Seek(0x10);
	uint32_t ncmds = reader.Read32();
	uint64_t off = 0x20; // FIXME 32 bit

	uint64_t kernelBaseAddress = 0;

	uint32_t chainedFixupDataOff = 0;
	uint32_t chainedFixupDataSize = 0;

	while (ncmds--)
	{
		reader.Seek(off);
		uint32_t cmd = reader.Read32();
		uint32_t cmdsize = reader.Read32();
		if (cmd == LC_SEGMENT_64)
		{
			segment_command_64 segment {};
			reader.Read(&segment.segname, 16);
			if (strncmp(segment.segname, "__TEXT\0", 7) == 0)
			{
				kernelBaseAddress = reader.Read64();
			}
		}
		if (cmd == LC_DYLD_CHAINED_FIXUPS)
		{
			chainedFixupDataOff = reader.Read32();
			chainedFixupDataSize = reader.Read32();
		}
		off += cmdsize;
	}

	BNRelocationInfo reloc;
	memset(&reloc, 0, sizeof(BNRelocationInfo));
	reloc.type = StandardRelocationType;
	reloc.size = 8;
	reloc.nativeType = BINARYNINJA_MANUAL_RELOCATION;
	logger->LogDebug("Processing Chained Fixups");

	std::vector<std::pair<uint64_t, uint64_t>> relocations;
	if (chainedFixupDataOff && chainedFixupDataSize)
	{
		BinaryReader parentReader(view->GetParentView());

		try {
			dyld_chained_fixups_header fixupsHeader {};
			uint64_t fixupHeaderAddress = chainedFixupDataOff;
			parentReader.Seek(fixupHeaderAddress);
			fixupsHeader.fixups_version = parentReader.Read32();
			fixupsHeader.starts_offset = parentReader.Read32();
			fixupsHeader.imports_offset = parentReader.Read32();
			fixupsHeader.symbols_offset = parentReader.Read32();
			fixupsHeader.imports_count = parentReader.Read32();
			fixupsHeader.imports_format = parentReader.Read32();
			fixupsHeader.symbols_format = parentReader.Read32();

			logger->LogDebug("Chained Fixups: Header @ %llx // Fixups version %lx", fixupHeaderAddress, fixupsHeader.fixups_version);

			if (fixupsHeader.fixups_version > 0)
			{
				logger->LogError("Chained Fixup parsing failed. Unknown Fixups Version");
				throw ReadException();
			}

			uint64_t fixupStartsAddress = fixupHeaderAddress + fixupsHeader.starts_offset;
			parentReader.Seek(fixupStartsAddress);
			dyld_chained_starts_in_image segs {};
			segs.seg_count = parentReader.Read32();
			std::vector<uint32_t> segInfoOffsets {};
			for (size_t i = 0; i < segs.seg_count; i++)
			{
				segInfoOffsets.push_back(parentReader.Read32());
			}
			for (auto offset : segInfoOffsets)
			{
				if (!offset)
					continue;

				dyld_chained_starts_in_segment starts {};
				uint64_t startsAddr = fixupStartsAddress + offset;
				parentReader.Seek(startsAddr);
				starts.size = parentReader.Read32();
				starts.page_size = parentReader.Read16();
				starts.pointer_format = parentReader.Read16();
				starts.segment_offset = parentReader.Read64();
				starts.max_valid_pointer = parentReader.Read32();
				starts.page_count = parentReader.Read16();

				uint8_t strideSize;
				ChainedFixupPointerGeneric format;

				// Firmware formats will require digging up whatever place they're being used and reversing it.
				// They are not handled by dyld.
				switch (starts.pointer_format) {
				case DYLD_CHAINED_PTR_ARM64E:
				case DYLD_CHAINED_PTR_ARM64E_USERLAND:
				case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
					strideSize = 8;
					format = GenericArm64eFixupFormat;
					break;
				case DYLD_CHAINED_PTR_ARM64E_KERNEL:
					strideSize = 4;
					format = GenericArm64eFixupFormat;
					break;
				// case DYLD_CHAINED_PTR_ARM64E_FIRMWARE: Unsupported.
				case DYLD_CHAINED_PTR_64:
				case DYLD_CHAINED_PTR_64_OFFSET:
					strideSize = 4;
					format = Generic64FixupFormat;
					break;
				case DYLD_CHAINED_PTR_32:
				case DYLD_CHAINED_PTR_32_CACHE:
					strideSize = 4;
					format = Generic32FixupFormat;
					break;
				case DYLD_CHAINED_PTR_32_FIRMWARE:
					strideSize = 4;
					format = Firmware32FixupFormat;
					break;
				case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
					strideSize = 4;
					format = Kernel64Format;
					break;
				case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
					strideSize = 1;
					format = Kernel64Format;
					break;
				default:
				{
					logger->LogError("Chained Fixups: Unknown or unsupported pointer format %d, "
						"unable to process chains for segment at @llx", starts.pointer_format, starts.segment_offset);
					continue;
				}
				}

				uint16_t fmt = starts.pointer_format;
				logger->LogDebug("Chained Fixups: Segment start @ %llx, fmt %d", starts.segment_offset, fmt);

				uint64_t pageStartsTableStartAddress = parentReader.GetOffset();
				std::vector<std::vector<uint16_t>> pageStartOffsets {};
				for (size_t i = 0; i < starts.page_count; i++)
				{
					// On armv7, Chained pointers here can have multiple starts.
					// And if so, there's another table *overlapping* the table we're currently reading.
					// dyld handles this through 'overflow indexing'
					// This is technically supported on other archs however is not (currently) used.
					parentReader.Seek(pageStartsTableStartAddress + (sizeof(uint16_t) * i));
					uint16_t start = parentReader.Read16();
					if ((start & DYLD_CHAINED_PTR_START_MULTI) && (start != DYLD_CHAINED_PTR_START_NONE))
					{
						uint64_t overflowIndex = start & ~DYLD_CHAINED_PTR_START_MULTI;
						std::vector<uint16_t> pageStartSubStarts;
						parentReader.Seek(pageStartsTableStartAddress + (overflowIndex * sizeof(uint16_t)));
						bool done = false;
						while (!done)
						{
							uint16_t subPageStart = parentReader.Read16();
							if ((subPageStart & DYLD_CHAINED_PTR_START_LAST) == 0)
							{
								pageStartSubStarts.push_back(subPageStart);
							}
							else
							{
								pageStartSubStarts.push_back(subPageStart & ~DYLD_CHAINED_PTR_START_LAST);
								done = true;
							}
						}
						pageStartOffsets.push_back(pageStartSubStarts);
					}
					else
					{
						pageStartOffsets.push_back({start});
					}
				}

				int i = -1;
				for (auto pageStarts : pageStartOffsets)
				{
					i++;
					uint64_t pageAddress = starts.segment_offset + (i * starts.page_size);
					for (uint16_t start : pageStarts)
					{
						if (start == DYLD_CHAINED_PTR_START_NONE)
							continue;

						uint64_t chainEntryAddress = pageAddress + start;

						bool fixupsDone = false;

						while (!fixupsDone)
						{
							ChainedFixupPointer pointer;
							parentReader.Seek(chainEntryAddress);
							if (format == Generic32FixupFormat || format == Firmware32FixupFormat)
								pointer.raw32 = (uint32_t)(uintptr_t)parentReader.Read32();
							else
								pointer.raw64 = (uintptr_t)parentReader.Read64();

							bool bind = false;
							uint64_t nextEntryStrideCount;

							switch (format)
							{
							case Generic32FixupFormat:
								bind = pointer.generic32.bind.bind;
								nextEntryStrideCount = pointer.generic32.rebase.next;
								break;
							case Generic64FixupFormat:
								bind = pointer.generic64.bind.bind;
								nextEntryStrideCount = pointer.generic64.rebase.next;
								break;
							case GenericArm64eFixupFormat:
								bind = pointer.arm64e.bind.bind;
								nextEntryStrideCount = pointer.arm64e.rebase.next;
								break;
							case Firmware32FixupFormat:
								nextEntryStrideCount = pointer.firmware32.next;
								bind = false;
								break;
							case Kernel64Format:
								nextEntryStrideCount = pointer.kernel64.next;
								bind = false;
							}

							logger->LogTrace("Chained Fixups: @ 0x%llx ( 0x%llx ) - %d 0x%llx", chainEntryAddress,
								kernelBaseAddress + (chainEntryAddress),
								bind, nextEntryStrideCount);

							if (!bind)
							{
								uint64_t entryOffset;
								switch (starts.pointer_format)
								{
								case DYLD_CHAINED_PTR_ARM64E:
								case DYLD_CHAINED_PTR_ARM64E_KERNEL:
								case DYLD_CHAINED_PTR_ARM64E_USERLAND:
								case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
								{
									if (pointer.arm64e.bind.auth)
										entryOffset = pointer.arm64e.authRebase.target;
									else
										entryOffset = pointer.arm64e.rebase.target;

									if ( starts.pointer_format != DYLD_CHAINED_PTR_ARM64E || pointer.arm64e.bind.auth)
										entryOffset += kernelBaseAddress;

									break;
								}
								case DYLD_CHAINED_PTR_64:
									entryOffset = pointer.generic64.rebase.target;
									break;
								case DYLD_CHAINED_PTR_64_OFFSET:
									entryOffset = pointer.generic64.rebase.target + kernelBaseAddress;
									break;
								// We expect only cases past this point will be applicable in this context.
								case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
								case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
									entryOffset = pointer.kernel64.target + kernelBaseAddress;
									break;
								case DYLD_CHAINED_PTR_32:
								case DYLD_CHAINED_PTR_32_CACHE:
									entryOffset = pointer.generic32.rebase.target;
									break;
								case DYLD_CHAINED_PTR_32_FIRMWARE:
									entryOffset = pointer.firmware32.target;
									break;
								}

								// logger->LogInfo("Chained Fixups: Pointer at 0x%llx -> 0x%llx", view->GetStart() + chainEntryAddress, entryOffset);

								relocations.emplace_back(kernelBaseAddress + chainEntryAddress, entryOffset);
							}

							chainEntryAddress += (nextEntryStrideCount * strideSize);

							if (chainEntryAddress > pageAddress + starts.page_size)
							{
								// Something is seriously wrong here. likely malformed binary, or our parsing failed elsewhere.
								// This will log the pointer in mapped memory.
								logger->LogError("Chained Fixups: Pointer at 0x%llx left page",
									kernelBaseAddress + ((chainEntryAddress - (nextEntryStrideCount * strideSize))));
								fixupsDone = true;
							}

							if (nextEntryStrideCount == 0)
								fixupsDone = true;
						}
					}
				}
			}
		}
		catch (ReadException&)
		{
			logger->LogError("Chained Fixup parsing failed");
		}
	}

	// Critical that we sort these as this optimization allows us to save a lot of time on image loading when we
	// need to apply relocations later. Now is the best time, since we aren't going to find more relocs now.
	std::sort(relocations.begin(), relocations.end(),
		[](const std::pair<uint64_t, uint64_t>& a, const std::pair<uint64_t, uint64_t>& b) {
			return a.first < b.first;
		});

	for (auto& region : targetImage.regions)
	{
		if (view->IsValidOffset(region.start))
		{
			logger->LogDebug("Skipping region %s as it is already loaded.", region.prettyName.c_str());
			continue;
		}

		hasRegionsToLoad = true;

		// Considerations at this point in processing:
		// * View is already finalized
		// * view (shown to user) has only one segment, at the kernel start address
		// * All of our relevant data is contained in the Raw view.
		view->AddAutoSegment(region.start, region.size, region.fileOffset, region.size, region.flags);

		auto begin = std::lower_bound(relocations.begin(), relocations.end(), region.start,
			[](const std::pair<uint64_t, uint64_t>& reloc, uint64_t addr) {
				return reloc.first < addr;
			});

		auto arch = view->GetDefaultArchitecture();
		// Process relocations until the VM address is beyond our region
		for (auto it = begin; it != relocations.end() && it->first < region.start + region.size; ++it) {
			reloc.address = it->first;
			view->DefineRelocation(arch, reloc, it->second, reloc.address);
		}
	}

	if (!hasRegionsToLoad)
	{
		logger->LogWarn("No regions to load for image %s", header.installName.c_str());
		return false;
	}

	return true;
}

void KernelCache::InitializeHeader(Ref<BinaryView> view, KernelCacheMachOHeader header)
{
	Ref<Settings> settings = view->GetLoadSettings(KC_VIEW_NAME);
	bool applyFunctionStarts = true; // FIXME

	view->AddAutoSection(header.identifierPrefix + "::__macho_header", header.textBase, header.ident.sizeofcmds + sizeof(mach_header_64), ReadOnlyDataSectionSemantics);

	for (size_t i = 0; i < header.sections.size(); i++)
	{
		if (!header.sections[i].size)
			continue;

		std::string type;
		BNSectionSemantics semantics = DefaultSectionSemantics;
		switch (header.sections[i].flags & 0xff)
		{
		case S_REGULAR:
			if (header.sections[i].flags & S_ATTR_PURE_INSTRUCTIONS)
			{
				type = "PURE_CODE";
				semantics = ReadOnlyCodeSectionSemantics;
			}
			else if (header.sections[i].flags & S_ATTR_SOME_INSTRUCTIONS)
			{
				type = "CODE";
				semantics = ReadOnlyCodeSectionSemantics;
			}
			else
			{
				type = "REGULAR";
			}
			break;
		case S_ZEROFILL:
			type = "ZEROFILL";
			semantics = ReadWriteDataSectionSemantics;
			break;
		case S_CSTRING_LITERALS:
			type = "CSTRING_LITERALS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_4BYTE_LITERALS:
			type = "4BYTE_LITERALS";
			break;
		case S_8BYTE_LITERALS:
			type = "8BYTE_LITERALS";
			break;
		case S_LITERAL_POINTERS:
			type = "LITERAL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_NON_LAZY_SYMBOL_POINTERS:
			type = "NON_LAZY_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_LAZY_SYMBOL_POINTERS:
			type = "LAZY_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_SYMBOL_STUBS:
			type = "SYMBOL_STUBS";
			semantics = ReadOnlyCodeSectionSemantics;
			break;
		case S_MOD_INIT_FUNC_POINTERS:
			type = "MOD_INIT_FUNC_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_MOD_TERM_FUNC_POINTERS:
			type = "MOD_TERM_FUNC_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_COALESCED:
			type = "COALESCED";
			break;
		case S_GB_ZEROFILL:
			type = "GB_ZEROFILL";
			semantics = ReadWriteDataSectionSemantics;
			break;
		case S_INTERPOSING:
			type = "INTERPOSING";
			break;
		case S_16BYTE_LITERALS:
			type = "16BYTE_LITERALS";
			break;
		case S_DTRACE_DOF:
			type = "DTRACE_DOF";
			break;
		case S_LAZY_DYLIB_SYMBOL_POINTERS:
			type = "LAZY_DYLIB_SYMBOL_POINTERS";
			semantics = ReadOnlyDataSectionSemantics;
			break;
		case S_THREAD_LOCAL_REGULAR:
			type = "THREAD_LOCAL_REGULAR";
			break;
		case S_THREAD_LOCAL_ZEROFILL:
			type = "THREAD_LOCAL_ZEROFILL";
			break;
		case S_THREAD_LOCAL_VARIABLES:
			type = "THREAD_LOCAL_VARIABLES";
			break;
		case S_THREAD_LOCAL_VARIABLE_POINTERS:
			type = "THREAD_LOCAL_VARIABLE_POINTERS";
			break;
		case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS:
			type = "THREAD_LOCAL_INIT_FUNCTION_POINTERS";
			break;
		default:
			type = "UNKNOWN";
			break;
		}
		if (i >= header.sectionNames.size())
			break;
		if (strncmp(header.sections[i].sectname, "__text", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadOnlyCodeSectionSemantics;
		if (strncmp(header.sections[i].sectname, "__const", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;
		if (strncmp(header.sections[i].sectname, "__data", sizeof(header.sections[i].sectname)) == 0)
			semantics = ReadWriteDataSectionSemantics;
		if (strncmp(header.sections[i].segname, "__DATA_CONST", sizeof(header.sections[i].segname)) == 0)
			semantics = ReadOnlyDataSectionSemantics;

		view->AddAutoSection(header.sectionNames[i], header.sections[i].addr, header.sections[i].size, semantics,
			type, header.sections[i].align);
	}

	auto typeLib = view->GetTypeLibrary(header.installName);

	BinaryReader virtualReader(view->GetParentView());

	view->DefineDataVariable(header.textBase, Type::NamedType(view, QualifiedName("mach_header_64")));
	view->DefineAutoSymbol(
		new Symbol(DataSymbol, "__macho_header::" + header.identifierPrefix, header.textBase, LocalBinding));

	try
	{
		virtualReader.Seek(header.textBaseFileOffset + sizeof(mach_header_64));
		size_t sectionNum = 0;
		uint64_t curVirtualOffset = header.textBase + sizeof(mach_header_64);
		uint64_t curFileOffset = header.textBaseFileOffset + sizeof(mach_header_64);
		for (size_t i = 0; i < header.ident.ncmds; i++)
		{
			load_command load;
			curFileOffset = virtualReader.GetOffset();
			load.cmd = virtualReader.Read32();
			load.cmdsize = virtualReader.Read32();
			uint64_t nextOffset = curFileOffset + load.cmdsize;
			switch (load.cmd)
			{
			case LC_SEGMENT:
			{
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("segment_command")));
				virtualReader.SeekRelative(5 * 8);
				size_t numSections = virtualReader.Read32();
				virtualReader.SeekRelative(4);
				for (size_t j = 0; j < numSections; j++)
				{
					view->DefineDataVariable(
						virtualReader.GetOffset(), Type::NamedType(view, QualifiedName("section")));
					view->DefineAutoSymbol(new Symbol(DataSymbol,
						"__macho_section::" + header.identifierPrefix + "_[" + std::to_string(sectionNum++) + "]",
						virtualReader.GetOffset(), LocalBinding));
					virtualReader.SeekRelative((8 * 8) + 4);
				}
				break;
			}
			case LC_SEGMENT_64:
			{
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("segment_command_64")));
				virtualReader.SeekRelative(7 * 8);
				size_t numSections = virtualReader.Read32();
				virtualReader.SeekRelative(4);
				for (size_t j = 0; j < numSections; j++)
				{
					view->DefineDataVariable(
						virtualReader.GetOffset(), Type::NamedType(view, QualifiedName("section_64")));
					view->DefineAutoSymbol(new Symbol(DataSymbol,
						"__macho_section_64::" + header.identifierPrefix + "_[" + std::to_string(sectionNum++) + "]",
						virtualReader.GetOffset(), LocalBinding));
					virtualReader.SeekRelative(10 * 8);
				}
				break;
			}
			case LC_SYMTAB:
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("symtab")));
				break;
			case LC_DYSYMTAB:
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("dysymtab")));
				break;
			case LC_UUID:
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("uuid")));
				break;
			case LC_ID_DYLIB:
			case LC_LOAD_DYLIB:
			case LC_REEXPORT_DYLIB:
			case LC_LOAD_WEAK_DYLIB:
			case LC_LOAD_UPWARD_DYLIB:
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("dylib_command")));
				if (load.cmdsize - 24 <= 150)
					view->DefineDataVariable(
						curVirtualOffset + 24, Type::ArrayType(Type::IntegerType(1, true), load.cmdsize - 24));
				break;
			case LC_CODE_SIGNATURE:
			case LC_SEGMENT_SPLIT_INFO:
			case LC_FUNCTION_STARTS:
			case LC_DATA_IN_CODE:
			case LC_DYLIB_CODE_SIGN_DRS:
			case LC_DYLD_EXPORTS_TRIE:
			case LC_DYLD_CHAINED_FIXUPS:
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("linkedit_data")));
				break;
			case LC_ENCRYPTION_INFO:
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("encryption_info")));
				break;
			case LC_VERSION_MIN_MACOSX:
			case LC_VERSION_MIN_IPHONEOS:
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("version_min")));
				break;
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("dyld_info")));
				break;
			default:
				view->DefineDataVariable(curVirtualOffset, Type::NamedType(view, QualifiedName("load_command")));
				break;
			}

			view->DefineAutoSymbol(new Symbol(DataSymbol,
				"__macho_load_command::" + header.identifierPrefix + "_[" + std::to_string(i) + "]", curVirtualOffset,
				LocalBinding));
			curVirtualOffset += (nextOffset - curFileOffset);
			virtualReader.Seek(nextOffset);
		}
	}
	catch (ReadException&)
	{
		LogError("Error when applying Mach-O header types at %" PRIx64, header.textBase);
	}

	if (applyFunctionStarts && header.functionStartsPresent && header.linkeditPresent)
	{
		size_t i = 0;
		uint64_t curfunc = header.textBase;
		uint64_t curOffset;

		auto funcStarts = view->GetParentView()->ReadBuffer(header.functionStarts.funcoff, header.functionStarts.funcsize);

		while (i < header.functionStarts.funcsize)
		{
			curOffset = readLEB128(funcStarts, header.functionStarts.funcsize, i);
			curfunc += curOffset;
			// LogError("0x%llx, 0x%llx", header.textBase, curOffset);
			if (curOffset == 0)
				continue;
			uint64_t target = curfunc;
			Ref<Platform> targetPlatform = view->GetDefaultPlatform();
			view->AddFunctionForAnalysis(targetPlatform, target);
		}
	}

	view->BeginBulkModifySymbols();
	ParseSymbolTable(view, header);

	BinaryReader reader(view);

	size_t modInitFuncCnt = 0;
	for (const auto& moduleInitSection : header.moduleInitSections)
	{
		// The mod_init section contains a list of function pointers called at initialization
		// if we don't have a defined entrypoint then use the first one in the list as the entrypoint
		size_t i = 0;
		reader.Seek(moduleInitSection.addr);
		for (; i < (moduleInitSection.size / view->GetAddressSize()); i++)
		{
			uint64_t target = (view->GetAddressSize() == 4) ? reader.Read32() : reader.Read64();
			if (!view->IsValidOffset(target))
				continue;
			Ref<Platform> targetPlatform = view->GetDefaultPlatform()->GetAssociatedPlatformByAddress(target);
			auto name = header.identifierPrefix + "_init_func_" + std::to_string(modInitFuncCnt++);
			view->AddEntryPointForAnalysis(targetPlatform, target);
			auto symbol = new Symbol(FunctionSymbol, name, target, GlobalBinding);
			view->DefineAutoSymbol(symbol);
		}
	}

	view->EndBulkModifySymbols();
}


std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>> KernelCache::ParseSymbolTable(Ref<BinaryView> view, KernelCacheMachOHeader header, bool defineSymbolsInView)
{
	if (header.symtab.symoff != 0 && header.linkeditPresent)
	{
		// Mach-O View symtab processing with
		// a ton of stuff cut out so it can work
		// auto symtab = reader->ReadBuffer(header.symtab.symoff, header.symtab.nsyms * sizeof(nlist_64));
		auto strtab = view->GetParentView()->ReadBuffer(header.symtab.stroff, header.symtab.strsize);
		nlist_64 sym;
		memset(&sym, 0, sizeof(sym));
		std::vector<std::pair<uint64_t, std::pair<BNSymbolType, std::string>>> symbolInfos;
		for (size_t i = 0; i < header.symtab.nsyms; i++)
		{
			view->GetParentView()->Read(&sym, header.symtab.symoff + i * sizeof(nlist_64), sizeof(nlist_64));
			if (sym.n_strx >= header.symtab.strsize || ((sym.n_type & N_TYPE) == N_INDR))
				continue;

			std::string symbol((char*)strtab.GetDataAt(sym.n_strx));
			// BNLogError("%s: 0x%llx", symbol.c_str(), sym.n_value);
			if (symbol == "<redacted>")
				continue;

			BNSymbolType type = DataSymbol;
			uint32_t flags;
			if ((sym.n_type & N_TYPE) == N_SECT && sym.n_sect > 0 && (size_t)(sym.n_sect - 1) < header.sections.size())
			{}
			else if ((sym.n_type & N_TYPE) == N_ABS)
			{}
			else if ((sym.n_type & 0x1))
			{
				type = ExternalSymbol;
			}
			else
				continue;

			for (auto s : header.sections)
			{
				if (s.addr < sym.n_value)
				{
					if (s.addr + s.size > sym.n_value)
					{
						flags = s.flags;
					}
				}
			}

			if (type != ExternalSymbol)
			{
				if ((flags & S_ATTR_PURE_INSTRUCTIONS) == S_ATTR_PURE_INSTRUCTIONS
					|| (flags & S_ATTR_SOME_INSTRUCTIONS) == S_ATTR_SOME_INSTRUCTIONS)
					type = FunctionSymbol;
				else
					type = DataSymbol;
			}
			if ((sym.n_desc & N_ARM_THUMB_DEF) == N_ARM_THUMB_DEF)
				sym.n_value++;

			std::string rawName = symbol;
			std::string shortName = symbol;
			std::string fullName = symbol;
			Ref<Type> typeRef = nullptr;

			if (view->GetDefaultArchitecture())
			{
				QualifiedName demangledName;
				Ref<Type> demangledType;
				bool simplify = Settings::Instance()->Get<bool>("analysis.types.templateSimplifier", view);
				if (DemangleGeneric(view->GetDefaultArchitecture(), rawName, demangledType, demangledName, view, simplify))
				{
					shortName = demangledName.GetString();
					fullName = shortName;
					if (demangledType)
						fullName += demangledType->GetStringAfterName();
					if (!typeRef && !view->GetDefaultPlatform()->GetFunctionByName(rawName))
						typeRef = demangledType;
				}
				else
				{
					LogDebug("Failed to demangle name: '%s'\n", rawName.c_str());
				}
			}

			if (defineSymbolsInView)
			{
				auto symbolObj = new Symbol(type, shortName, fullName, rawName, sym.n_value, GlobalBinding);

				if (typeRef)
					view->DefineAutoSymbolAndVariableOrFunction(view->GetDefaultPlatform(), symbolObj, typeRef);
				else
				{
					view->DefineAutoSymbol(symbolObj);
					if (type == FunctionSymbol)
					{
						Ref<Platform> targetPlatform = view->GetDefaultPlatform();
						view->AddFunctionForAnalysis(targetPlatform, sym.n_value);
					}
				}
			}
			symbolInfos.push_back({sym.n_value, {type, fullName}});
		}
		return symbolInfos;
	}
	return {};
}


struct ExportNode
{
	std::string text;
	uint64_t offset;
	uint64_t flags;
};


void KernelCache::ReadExportNode(Ref<BinaryView> view, std::vector<Ref<Symbol>>& symbolList, KernelCacheMachOHeader& header, DataBuffer& buffer, uint64_t textBase,
	const std::string& currentText, size_t cursor, uint32_t endGuard)
{

	if (cursor > endGuard)
		throw ReadException();

	uint64_t terminalSize = readValidULEB128(buffer, cursor);
	uint64_t childOffset = cursor + terminalSize;
	if (terminalSize != 0) {
		uint64_t imageOffset = 0;
		uint64_t flags = readValidULEB128(buffer, cursor);
		if (!(flags & EXPORT_SYMBOL_FLAGS_REEXPORT))
		{
			imageOffset = readValidULEB128(buffer, cursor);
			// auto symbolType = view->GetAnalysisFunctionsForAddress(textBase + imageOffset).size() ? FunctionSymbol : DataSymbol;
			{
				if (!currentText.empty() && textBase + imageOffset)
				{
					uint32_t sectionFlags;
					BNSymbolType type;
					for (auto s : header.sections)
					{
						if (s.addr < textBase + imageOffset)
						{
							if (s.addr + s.size > textBase + imageOffset)
							{
								sectionFlags = s.flags;
							}
						}
					}
					if ((sectionFlags & S_ATTR_PURE_INSTRUCTIONS) == S_ATTR_PURE_INSTRUCTIONS
						|| (sectionFlags & S_ATTR_SOME_INSTRUCTIONS) == S_ATTR_SOME_INSTRUCTIONS)
						type = FunctionSymbol;
					else
						type = DataSymbol;

#if EXPORT_TRIE_DEBUG
						// BNLogInfo("export: %s -> 0x%llx", n.text.c_str(), image.baseAddress + n.offset);
#endif
					auto sym = new Symbol(type, currentText, textBase + imageOffset);
					symbolList.push_back(sym);
				}
			}
		}
	}
	cursor = childOffset;
	uint8_t childCount = buffer[cursor];
	cursor++;
	if (cursor > endGuard)
		throw ReadException();
	for (uint8_t i = 0; i < childCount; ++i)
	{
		std::string childText;
		while (buffer[cursor] != 0 & cursor <= endGuard)
			childText.push_back(buffer[cursor++]);
		cursor++;
		if (cursor > endGuard)
			throw ReadException();
		auto next = readValidULEB128(buffer, cursor);
		if (next == 0)
			throw ReadException();
		ReadExportNode(view, symbolList, header, buffer, textBase, currentText + childText, next, endGuard);
	}
}


std::vector<Ref<Symbol>> KernelCache::ParseExportTrie(Ref<BinaryView> view, KernelCacheMachOHeader header)
{
	if (!header.exportTriePresent || !header.exportTrie.dataoff || !header.exportTrie.datasize)
		return {};

	std::vector<Ref<Symbol>> symbols;
	try
	{
		std::vector<ExportNode> nodes;

		DataBuffer buffer = view->GetParentView()->ReadBuffer(header.exportTrie.dataoff, header.exportTrie.datasize);
		ReadExportNode(view, symbols, header, buffer, header.textBase, "", 0, header.exportTrie.datasize);
	}
	catch (std::exception& e)
	{
		BNLogError("Failed to load Export Trie");
	}
	return symbols;
}

std::vector<std::string> KernelCache::GetAvailableImages()
{
	std::vector<std::string> installNames;
	for (const auto& img : m_cacheInfo->images)
	{
		installNames.push_back(img.installName);
	}
	return installNames;
}


std::vector<KernelCacheImage> KernelCache::GetLoadedImages()
{
	std::lock_guard lock(m_viewSpecificState->stateMutex);
	std::vector<KernelCacheImage> images;
	for (const auto& [fileStart, image] : m_viewSpecificState->state.loadedImages)
	{
		images.push_back(image);
	}
	return images;
}


bool KernelCache::IsImageLoaded(uint64_t address)
{
	std::lock_guard lock(m_viewSpecificState->stateMutex);
	return m_viewSpecificState->state.loadedImages.find(address)!= m_viewSpecificState->state.loadedImages.end();
}


std::vector<std::pair<uint64_t, std::pair<std::string, std::string>>> KernelCache::LoadAllSymbolsAndWait()
{
	std::vector<std::pair<uint64_t, std::pair<std::string, std::string>>> symbols;
	for (const auto& img : m_cacheInfo->images)
	{
		auto header = HeaderForFileAddress(img.headerFileLocation);
		if (header)
		{
			auto newSymbolList = ParseSymbolTable(m_kcView, *header, false);
			for (const auto& symbol : newSymbolList)
			{
				if (symbol.first != 0)
					symbols.push_back({symbol.first, {header->installName, symbol.second.second}});
			}
		}
	}
	return symbols;
}


std::string KernelCache::SerializedImageHeaderForVMAddress(uint64_t address)
{
	auto header = HeaderForVMAddress(address);
	if (header)
	{
		return header->AsString();
	}
	return "";
}


std::string KernelCache::SerializedImageHeaderForName(std::string name)
{
	if (auto it = m_cacheInfo->imageStarts.find(name); it != m_cacheInfo->imageStarts.end())
	{
		if (auto header = HeaderForFileAddress(it->second))
		{
			return header->AsString();
		}
	}
	return "";
}



bool KernelCache::SaveCacheInfoToKCView(std::lock_guard<std::mutex>&)
{
	if (!m_cacheInfo)
		return false;

	// The initial load should only populate `m_cacheInfo` and should not modify any state.
	assert(m_modifiedState->loadedImages.size() == 0);

	auto data = m_cacheInfo->AsMetadata();
	m_kcView->StoreMetadata(KernelCacheMetadata::Tag, data);
	m_kcView->GetParentView()->StoreMetadata(KernelCacheMetadata::Tag, data);

	{
		std::lock_guard lock(m_viewSpecificState->cacheInfoMutex);
		if (m_cacheInfo && !m_viewSpecificState->cacheInfo)
			m_viewSpecificState->cacheInfo = m_cacheInfo;
		else if (m_cacheInfo != m_viewSpecificState->cacheInfo)
			abort();
	}

	m_metadataValid = true;
	return true;
}


bool KernelCache::SaveModifiedStateToKCView(std::lock_guard<std::mutex>&)
{
	if (!m_kcView)
		return false;
	
	{
		std::lock_guard lock(m_viewSpecificState->stateMutex);

		uint64_t modificationNumber = m_viewSpecificState->savedModifications++;
		if (modificationNumber == 0)
		{
			// The cached state in the view-specific state has not yet been saved.
			// For the initial load of a shared cache this will be empty, but if
			// the shared cache has been loaded from a database then this will
			// contain the full state that was saved.
			std::string metadataKey = KernelCacheMetadata::ModifiedStateTagPrefix + std::to_string(modificationNumber);
			auto data = m_viewSpecificState->state.AsMetadata(m_viewSpecificState->viewState);

			m_kcView->StoreMetadata(metadataKey, data);
			m_kcView->GetParentView()->StoreMetadata(metadataKey, data);
			modificationNumber = m_viewSpecificState->savedModifications++;
		}

		std::string metadataKey = KernelCacheMetadata::ModifiedStateTagPrefix + std::to_string(modificationNumber);
		auto data = m_modifiedState->AsMetadata();

		m_kcView->StoreMetadata(metadataKey, data);
		m_kcView->GetParentView()->StoreMetadata(metadataKey, data);

		Ref<Metadata> count = new Metadata(m_viewSpecificState->savedModifications);
		m_kcView->StoreMetadata(KernelCacheMetadata::ModifiedStateCountTag, count);
		m_kcView->GetParentView()->StoreMetadata(KernelCacheMetadata::ModifiedStateCountTag, count);

		m_viewSpecificState->state.loadedImages.merge(m_modifiedState->loadedImages);
		// `merge` will move a node to the target map if the corresponding key does not yet exist.
		// If we've redundantly loaded images, we may be left with symbols in the source maps.
		m_modifiedState->loadedImages.clear();

		// Clean up any metadata entries past the current modification number.
		// These can happen after being loaded from a database as all modifications are
		// merged into a single state object and the modification count is reset to zero.
		for (size_t i = modificationNumber + 1; i < std::numeric_limits<size_t>::max(); ++i)
		{
			std::string modifiedStateMetadataKey = KernelCacheMetadata::ModifiedStateTagPrefix + std::to_string(i);
			bool done = true;
			if (m_kcView->QueryMetadata(modifiedStateMetadataKey))
			{
				done = false;
				m_kcView->RemoveMetadata(modifiedStateMetadataKey);
			}
			if (m_kcView->GetParentView()->QueryMetadata(modifiedStateMetadataKey))
			{
				done = false;
				m_kcView->GetParentView()->RemoveMetadata(modifiedStateMetadataKey);
			}
			if (done)
				break;
		}
	}

	if (m_modifiedState->viewState)
	{
		m_viewSpecificState->viewState = m_modifiedState->viewState.value();
		m_modifiedState->viewState = std::nullopt;
	}

	m_metadataValid = true;

	return true;
}


const std::string KernelCacheMetadata::Tag = "KERNELCACHE-KernelCacheData";
const std::string KernelCacheMetadata::CacheInfoTag = "KERNELCACHE-CacheInfo";
const std::string KernelCacheMetadata::ModifiedStateTagPrefix = "KERNELCACHE-ModifiedState-";
const std::string KernelCacheMetadata::ModifiedStateCountTag = "KERNELCACHE-ModifiedState-Count";

KernelCacheMetadata::~KernelCacheMetadata() = default;
KernelCacheMetadata::KernelCacheMetadata(KernelCacheMetadata&&) = default;
KernelCacheMetadata& KernelCacheMetadata::operator=(KernelCacheMetadata&&) = default;

KernelCacheMetadata::KernelCacheMetadata(KernelCache::CacheInfo cacheInfo, KernelCache::ModifiedState state) :
	cacheInfo(std::make_unique<KernelCache::CacheInfo>(std::move(cacheInfo))),
	state(std::make_unique<KernelCache::ModifiedState>(std::move(state)))
{}


// static
bool KernelCacheMetadata::ViewHasMetadata(BinaryView* view)
{
	return view->QueryMetadata(Tag);
}

// static
std::optional<KernelCacheMetadata> KernelCacheMetadata::LoadFromView(BinaryView* view)
{
	Ref<Metadata> viewMetadata = view->QueryMetadata(Tag);
	if (!viewMetadata)
		return std::nullopt;

	auto cacheInfo = KernelCache::CacheInfo::LoadFromString(viewMetadata->GetString());
	if (!cacheInfo)
		return std::nullopt;

	auto modifiedState = KernelCache::ModifiedState::LoadAll(view, *cacheInfo);
	return KernelCacheMetadata(std::move(*cacheInfo), std::move(modifiedState));
}

std::string KernelCacheMetadata::InstallNameForImageBaseAddress(uint64_t baseAddress) const
{
	auto it = std::find_if(cacheInfo->imageStarts.begin(), cacheInfo->imageStarts.end(), [=](auto& pair) {
		return pair.second == baseAddress;
	});

	if (it == cacheInfo->imageStarts.end())
		return "";

	return it->first;
}

std::vector<KernelCacheImage> KernelCacheMetadata::LoadedImages()
{
	std::vector<KernelCacheImage> images;
	for (const auto& image : state->loadedImages)
	{
		images.push_back(image.second);
	}
	return images;
}

}

extern "C"
{
	BNKernelCache* BNGetKernelCache(BNBinaryView* data)
	{
		if (!data)
			return nullptr;

		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		if (auto cache = KernelCache::GetFromKCView(view))
		{
			cache->AddAPIRef();
			return cache->GetAPIObject();
		}

		return nullptr;
	}

	BNKernelCache* BNNewKernelCacheReference(BNKernelCache* cache)
	{
		if (!cache->object)
			return nullptr;

		cache->object->AddAPIRef();
		return cache;
	}

	void BNFreeKernelCacheReference(BNKernelCache* cache)
	{
		if (!cache->object)
			return;

		cache->object->ReleaseAPIRef();
	}

	bool BNKCViewLoadImageWithInstallName(BNKernelCache* cache, char* name)
	{
		std::string imageName = std::string(name);
		// FIXME !!!!!!!! BNFreeString(name);

		if (cache->object)
			return cache->object->LoadImageWithInstallName(imageName);

		return false;
	}

	bool BNKCViewLoadImageContainingAddress(BNKernelCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			return cache->object->LoadImageContainingAddress(address);
		}

		return false;
	}

	bool BNKCViewIsImageLoaded(BNKernelCache* cache, uint64_t address)
	{
		if (cache->object)
			return cache->object->IsImageLoaded(address);

		return false;
	}

	char** BNKCViewGetInstallNames(BNKernelCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto value = cache->object->GetAvailableImages();
			*count = value.size();

			std::vector<const char*> cstrings;
			for (size_t i = 0; i < value.size(); i++)
			{
				cstrings.push_back(value[i].c_str());
			}
			return BNAllocStringList(cstrings.data(), cstrings.size());
		}
		*count = 0;
		return nullptr;
	}

	BNKCSymbolRep* BNKCViewLoadAllSymbolsAndWait(BNKernelCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto value = cache->object->LoadAllSymbolsAndWait();
			*count = value.size();

			BNKCSymbolRep* symbols = (BNKCSymbolRep*)malloc(sizeof(BNKCSymbolRep) * value.size());
			for (size_t i = 0; i < value.size(); i++)
			{
				symbols[i].address = value[i].first;
				symbols[i].name = BNAllocString(value[i].second.second.c_str());
				symbols[i].image = BNAllocString(value[i].second.first.c_str());
			}
			return symbols;
		}
		*count = 0;
		return nullptr;
	}

	void BNKCViewFreeSymbols(BNKCSymbolRep* symbols, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			BNFreeString(symbols[i].name);
			BNFreeString(symbols[i].image);
		}
		delete symbols;
	}

	char* BNKCViewGetNameForAddress(BNKernelCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			return BNAllocString(cache->object->NameForAddress(address).c_str());
		}

		return nullptr;
	}

	char* BNKCViewGetImageNameForAddress(BNKernelCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			return BNAllocString(cache->object->ImageNameForAddress(address).c_str());
		}

		return nullptr;
	}

	uint64_t BNKCViewLoadedImageCount(BNKernelCache* cache)
	{
		// FIXME?
		return 0;
	}

	BNKCViewState BNKCViewGetState(BNKernelCache* cache)
	{
		if (cache->object)
		{
			return (BNKCViewState)cache->object->ViewState();
		}

		return BNKCViewState::Unloaded;
	}

	void BNKCViewFreeLoadedRegions(BNKCMappedMemoryRegion* images, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			BNFreeString(images[i].name);
		}
		delete images;
	}

	BNKCImage* BNKCViewGetAllImages(BNKernelCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto viewImageHeaders = cache->object->AllImageHeaders();
			*count = viewImageHeaders.size();
			BNKCImage* images = (BNKCImage*)malloc(sizeof(BNKCImage) * viewImageHeaders.size());
			size_t i = 0;
			for (const auto& [baseAddress, header] : viewImageHeaders)
			{
				images[i].name = BNAllocString(header.installName.c_str());
				images[i].headerFileAddress = baseAddress;
				images[i].mappingCount = header.sections.size();
				images[i].mappings = (BNKCImageMemoryMapping*)malloc(sizeof(BNKCImageMemoryMapping) * header.sections.size());
				for (size_t j = 0; j < header.sections.size(); j++)
				{
					images[i].mappings[j].rawViewOffset = header.sections[j].offset;
					images[i].mappings[j].vmAddress = header.sections[j].addr;
					images[i].mappings[j].size = header.sections[j].size;
					images[i].mappings[j].name = BNAllocString(header.sectionNames[j].c_str());
				}
				i++;
			}
			return images;
		}
		*count = 0;
		return nullptr;
	}

	void BNKCViewFreeAllImages(BNKCImage* images, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			for (size_t j = 0; j < images[i].mappingCount; j++)
			{
				BNFreeString(images[i].mappings[j].name);
			}
			delete[] images[i].mappings;
			BNFreeString(images[i].name);
		}
		delete[] images;
	}

	char* BNKCViewGetImageHeaderForAddress(BNKernelCache* cache, uint64_t address)
	{
		if (cache->object)
		{
			auto header = cache->object->SerializedImageHeaderForVMAddress(address);
			return BNAllocString(header.c_str());
		}

		return nullptr;
	}

	char* BNKCViewGetImageHeaderForName(BNKernelCache* cache, char* name)
	{
		std::string imageName = std::string(name);
		BNFreeString(name);
		if (cache->object)
		{
			auto header = cache->object->SerializedImageHeaderForName(imageName);
			return BNAllocString(header.c_str());
		}

		return nullptr;
	}

	BNKCViewLoadProgress BNKCViewGetLoadProgress(uint64_t sessionID)
	{
		if (auto viewSpecificState = ViewSpecificStateForId(sessionID, false))
			return viewSpecificState->progress;
		
		return LoadProgressNotStarted;
	}

	uint64_t BNKCViewFastGetImageCount(BNBinaryView* data)
	{
		Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
		if (view)
			return KernelCache::FastGetImageCount(view);
		return 0;
	}

	BNKCImage* BNKCViewGetLoadedImages(BNKernelCache* cache, size_t* count)
	{
		if (cache->object)
		{
			auto images = cache->object->GetLoadedImages();
			*count = images.size();
			BNKCImage* bnImages = new BNKCImage[images.size()];
			for (size_t i = 0; i < images.size(); i++)
			{
				bnImages[i].name = BNAllocString(images[i].installName.c_str());
				bnImages[i].headerFileAddress = images[i].headerFileLocation;
				bnImages[i].mappingCount = images[i].regions.size();
				bnImages[i].mappings = new BNKCImageMemoryMapping[images[i].regions.size()];
				for (size_t j = 0; j < images[i].regions.size(); j++)
				{
					bnImages[i].mappings[j].rawViewOffset = images[i].regions[j].fileOffset;
					bnImages[i].mappings[j].vmAddress = images[i].regions[j].start;
					bnImages[i].mappings[j].size = images[i].regions[j].size;
					bnImages[i].mappings[j].name = BNAllocString(images[i].regions[j].prettyName.c_str());
				}
			}
			return bnImages;
		}
		*count = 0;
		return nullptr;
	}

	void BNKCViewFreeLoadedImages(BNKCImage* images, size_t count)
	{
		for (size_t i = 0; i < count; i++)
		{
			for (size_t j = 0; j < images[i].mappingCount; j++)
			{
				BNFreeString(images[i].mappings[j].name);
			}
			delete[] images[i].mappings;
			BNFreeString(images[i].name);
		}
		delete[] images;
	}
}
#ifdef __cplusplus
extern "C" {
#endif

	void RegisterTransformers();

#ifdef __cplusplus
}
#endif

void InitKernelcache()
{
	InitKCViewType();
	RegisterTransformers();
}

namespace KernelCacheCore {

void Deserialize(
	DeserializationContext& context, std::string_view name, std::optional<std::pair<uint64_t, uint64_t>>& value)
{
	if (!context.doc.HasMember(name.data()))
	{
		value = std::nullopt;
		return;
	}

	auto array = context.doc[name.data()].GetArray();
	value = {array[0].GetUint64(), array[1].GetUint64()};
}

void Serialize(SerializationContext& context, const Ref<Symbol>& value)
{
	context.writer.StartArray();
	Serialize(context, value->GetRawNameRef());
	Serialize(context, value->GetAddress());
	Serialize(context, value->GetType());
	context.writer.EndArray();
}

void Serialize(SerializationContext& context, const std::shared_ptr<std::unordered_map<uint64_t, Ref<Symbol>>>& value)
{
	context.writer.StartArray();
	for (const auto& [_, symbol] : *value)
	{
		Serialize(context, symbol);
	}
	context.writer.EndArray();
}

void Serialize(SerializationContext& context, const std::shared_ptr<std::vector<Ref<Symbol>>>& value)
{
	Serialize(context, *value);
}

void Deserialize(DeserializationContext& context, std::string_view name,
	std::unordered_map<uint64_t, std::shared_ptr<std::unordered_map<uint64_t, Ref<Symbol>>>>& value)
{
	auto array = context.doc[name.data()].GetArray();
	for (auto& pair : array)
	{
		auto symbols_array = pair[1].GetArray();
		std::unordered_map<uint64_t, Ref<Symbol>> symbols;
		for (auto& symbol_value : symbols_array)
		{
			auto symbol_array = symbol_value.GetArray();
			std::string symbolName = symbol_array[0].GetString();
			uint64_t address = symbol_array[1].GetUint64();
			BNSymbolType type = (BNSymbolType)symbol_array[2].GetUint();
			symbols.insert({address, new Symbol(type, symbolName, address)});
		}
		value[pair[0].GetUint64()] = std::make_shared<std::unordered_map<uint64_t, Ref<Symbol>>>(std::move(symbols));
	}
}

void Deserialize(DeserializationContext& context, std::string_view name,
	std::unordered_map<uint64_t, std::shared_ptr<std::vector<Ref<Symbol>>>>& value)
{
	auto array = context.doc[name.data()].GetArray();
	for (auto& pair : array)
	{
		auto symbols_array = pair[1].GetArray();
		std::vector<Ref<Symbol>> symbols;
		symbols.reserve(symbols_array.Size());
		for (auto& symbol_value : symbols_array)
		{
			auto symbol_array = symbol_value.GetArray();
			std::string symbolName = symbol_array[0].GetString();
			uint64_t address = symbol_array[1].GetUint64();
			BNSymbolType type = (BNSymbolType)symbol_array[2].GetUint();
			symbols.push_back(new Symbol(type, symbolName, address));
		}
		value[pair[0].GetUint64()] = std::make_shared<std::vector<Ref<Symbol>>>(std::move(symbols));
	}
}

void Deserialize(DeserializationContext& context, std::string_view name, std::optional<KCViewState>& viewState)
{
	auto& value = context.doc[name.data()];
	if (value.IsNull())
		viewState = std::nullopt;
	else
		viewState = (KCViewState)value.GetUint();
}


void Serialize(SerializationContext& context, const std::vector<MemoryRegion>& value)
{
	context.writer.StartArray();
	for (const auto& region : value)
	{
		context.writer.StartArray();
		Serialize(context, region.prettyName);
		Serialize(context, region.start);
		Serialize(context, region.size);
		Serialize(context, region.fileOffset);
		Serialize(context, (uint64_t)region.flags);
		Serialize(context, (uint8_t)region.type);
		context.writer.EndArray();
	}
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::vector<MemoryRegion>& value)
{
	auto array = context.doc[name.data()].GetArray();
	value.reserve(array.Size());
	for (auto& region : array)
	{
		auto region_array = region.GetArray();
		MemoryRegion newRegion;
		newRegion.prettyName = region_array[0].GetString();
		newRegion.start = region_array[1].GetUint64();
		newRegion.size = region_array[2].GetUint64();
		newRegion.fileOffset = region_array[3].GetUint64();
		newRegion.flags = (BNSegmentFlag)region_array[4].GetUint64();
		newRegion.type = (MemoryRegion::Type)region_array[5].GetUint();
		value.push_back(newRegion);
	}
}

void Serialize(SerializationContext& context, const std::vector<KernelCacheImage>& value)
{
	context.writer.StartArray();
	for (const auto& image : value)
	{
		Serialize(context, image);
	}
	context.writer.EndArray();
}


void Deserialize(DeserializationContext& context, std::string_view name, std::vector<KernelCacheImage>& value)
{
	auto array = context.doc[name.data()].GetArray();
	value.reserve(array.Size());
	for (auto& image : array)
	{
		KernelCacheImage img = KernelCacheImage::LoadFromValue(image);
		value.push_back(img);
	}
}


void Serialize(SerializationContext& context, const std::vector<std::pair<uint64_t, uint64_t>>& value)
{
	context.writer.StartArray();
	for (const auto& pair : value)
	{
		context.writer.StartArray();
		Serialize(context, pair.first);
		Serialize(context, pair.second);
		context.writer.EndArray();
	}
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::vector<std::pair<uint64_t, uint64_t>>& value)
{
	auto array = context.doc[name.data()].GetArray();
	value.reserve(array.Size());
	for (auto& pair : array)
	{
		auto pair_array = pair.GetArray();
		value.push_back({pair_array[0].GetUint64(), pair_array[1].GetUint64()});
	}
}

void Serialize(SerializationContext& context, const std::unordered_map<uint64_t, KernelCacheMachOHeader>& value)
{
	context.writer.StartArray();
	for (const auto& pair : value)
	{
		context.writer.StartArray();
		Serialize(context, pair.first);
		Serialize(context, pair.second);
		context.writer.EndArray();
	}
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<uint64_t, KernelCacheMachOHeader>& value)
{
	auto array = context.doc[name.data()].GetArray();
	for (auto& pair : array)
	{
		auto pair_array = pair.GetArray();
		uint64_t key = pair_array[0].GetUint64();
		KernelCacheMachOHeader header = KernelCacheMachOHeader::LoadFromValue(pair_array[1]);
		value[key] = header;
	}
}


void Serialize(SerializationContext& context, const std::unordered_map<uint64_t, KernelCacheImage> value)
{
	context.writer.StartArray();
	for (const auto& pair : value)
	{
		context.writer.StartArray();
		Serialize(context, pair.first);
		Serialize(context, pair.second);
		context.writer.EndArray();
	}
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<uint64_t, KernelCacheImage>& value)
{
	auto array = context.doc[name.data()].GetArray();
	for (auto& pair : array)
	{
		auto pair_array = pair.GetArray();
		uint64_t key = pair_array[0].GetUint64();
		KernelCacheImage image = KernelCacheImage::LoadFromValue(pair_array[1]);
		value[key] = image;
	}
}


void KernelCache::CacheInfo::Store(SerializationContext& context) const
{
	Serialize(context, "metadataVersion", METADATA_VERSION);

	MSS(images);
	MSS(imageStarts);
	MSS_CAST(cacheFormat, uint8_t);
}

// static
std::optional<KernelCache::CacheInfo> KernelCache::CacheInfo::Load(DeserializationContext& context)
{
	if (!context.doc.HasMember("metadataVersion"))
	{
		LogError("Shared Cache metadata version missing");
		return std::nullopt;
	}

	if (context.doc["metadataVersion"].GetUint() != METADATA_VERSION)
	{
		LogError("Shared Cache metadata version mismatch");
		return std::nullopt;
	}

	CacheInfo cacheInfo;
	cacheInfo.MSL(images);
	cacheInfo.MSL(imageStarts);
	cacheInfo.MSL_CAST(cacheFormat, uint8_t, KernelCacheFormat);
	return cacheInfo;
}
void State::Store(SerializationContext& context, std::optional<KCViewState> viewState) const
{
	MSS(loadedImages);
	MSS(viewState);
}

void KernelCache::ModifiedState::Store(SerializationContext& context) const
{
	State::Store(context, viewState);
}

KernelCache::ModifiedState KernelCache::ModifiedState::Load(DeserializationContext& context)
{
	KernelCache::ModifiedState state;
	state.MSL(loadedImages);
	state.MSL(viewState);
	return state;
}

KernelCache::ModifiedState KernelCache::ModifiedState::LoadAll(BinaryNinja::BinaryView *dscView, const CacheInfo& cacheInfo)
{
	uint64_t stateCount = dscView->GetUIntMetadata(KernelCacheMetadata::ModifiedStateCountTag);
	KernelCache::ModifiedState state;
	for (uint64_t i = 0; i < stateCount; ++i)
	{
		std::string key = KernelCacheMetadata::ModifiedStateTagPrefix + std::to_string(i);
		std::string serialized = dscView->GetStringMetadata(key);
		auto thisState = KernelCache::ModifiedState::LoadFromString(serialized);
		state.Merge(std::move(thisState));
	}
	return state;
}

void KernelCache::ModifiedState::Merge(KernelCache::ModifiedState&& newer)
{
	loadedImages.merge(newer.loadedImages);

	if (newer.viewState)
		viewState = newer.viewState;
}

void KernelCacheImage::Store(SerializationContext& context) const
{
	MSS(installName);
	MSS(headerFileLocation);
	MSS(regions);
}

// static
KernelCacheImage KernelCacheImage::Load(DeserializationContext& context)
{
	KernelCacheImage cacheImage;
	cacheImage.MSL(installName);
	cacheImage.MSL(headerFileLocation);
	cacheImage.MSL(regions);
	return cacheImage;
}


}  // namespace KernelCacheCore
