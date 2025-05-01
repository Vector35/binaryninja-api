#pragma once

#include <vector>
#include <Dyld.h>

#include "binaryninjaapi.h"
#include "MachO.h"
#include "VirtualMemory.h"

struct CacheSymbol
{
	BNSymbolType type;
	uint64_t address;
	std::string name;

	CacheSymbol() = default;
	CacheSymbol(BNSymbolType type, uint64_t address, std::string name) :
		type(type), address(address), name(std::move(name))
	{}
	~CacheSymbol() = default;

	CacheSymbol(const CacheSymbol& other) = default;
	CacheSymbol& operator=(const CacheSymbol& other) = default;

	CacheSymbol(CacheSymbol&& other) noexcept = default;
	CacheSymbol& operator=(CacheSymbol&& other) noexcept = default;

	std::pair<std::string, BinaryNinja::Ref<BinaryNinja::Type>> DemangledName(BinaryNinja::BinaryView& view) const;

	// NOTE: you should really only call this when adding the symbol to the view.
	std::pair<BinaryNinja::Ref<BinaryNinja::Symbol>, BinaryNinja::Ref<BinaryNinja::Type>> GetBNSymbolAndType(BinaryNinja::BinaryView& view) const;
};

enum class CacheRegionType
{
	Image,
	StubIsland,
	DyldData,
	NonImage,
};

struct CacheRegion
{
	CacheRegionType type;
	std::string name;
	uint64_t start;
	uint64_t size;
	// Associate this region with this image, this makes it easier to identify what image owns this region.
	std::optional<uint64_t> imageStart;
	BNSegmentFlag flags;

	CacheRegion() = default;
	~CacheRegion() = default;

	CacheRegion(const CacheRegion& other) = default;
	CacheRegion& operator=(const CacheRegion& other) = default;

	CacheRegion(CacheRegion&& other) noexcept = default;
	CacheRegion& operator=(CacheRegion&& other) noexcept = default;

	AddressRange AsAddressRange() const { return {start, start + size}; }

	BNSectionSemantics SectionSemanticsForRegion() const
	{
		if ((flags & SegmentExecutable) && (flags & SegmentDenyWrite))
			return ReadOnlyCodeSectionSemantics;

		if (flags & SegmentExecutable)
			return DefaultSectionSemantics;

		if (flags & SegmentDenyWrite)
			return ReadOnlyDataSectionSemantics;

		return ReadWriteDataSectionSemantics;
	}
};

// Represents a single image and its associated memory regions.
struct CacheImage
{
	uint64_t headerAddress;
	std::string path;
	// A list to the start of memory regions associated with the image.
	// This lets us load all regions for a given image easily.
	std::vector<uint64_t> regionStarts;
	std::shared_ptr<SharedCacheMachOHeader> header;

	CacheImage() = default;
	~CacheImage() = default;

	CacheImage(const CacheImage& other) = default;
	CacheImage& operator=(const CacheImage& other) = default;

	CacheImage(CacheImage&& other) noexcept = default;
	CacheImage& operator=(CacheImage&& other) noexcept = default;

	// Get the file name from the path.
	std::string GetName() const { return BaseFileName(path); }

	// Get the names of the dependencies.
	std::vector<std::string> GetDependencies() const;
};

enum class CacheEntryType
{
	Primary,
	Secondary,
	// A special entry that holds symbols for other cache entries.
	Symbols,
	// If the type is marked as this then all mappings will be marked as such.
	DyldData,
	// A single stub mapping file.
	Stub,
};

// Describes a single files cache information
class CacheEntry
{
	CacheEntryType m_type;
	std::string m_filePath;
	std::string m_fileName;
	dyld_cache_header m_header {};
	// Mappings tell us _where_ to map the regions within the flat address space.
	// Without this we wouldn't know where the entry is supposed to exist in the address space.
	std::vector<dyld_cache_mapping_info> m_mappings {};
	// Mapping of image path to image info, used within ProcessImagesAndRegions to add them to the cache.
	// Also used to retrieve the image dependencies.
	std::vector<std::pair<std::string, dyld_cache_image_info>> m_images {};

public:
	CacheEntry(std::string filePath, std::string fileName, CacheEntryType type, dyld_cache_header header,
		std::vector<dyld_cache_mapping_info>&& mappings, std::vector<std::pair<std::string, dyld_cache_image_info>>&& images);

	CacheEntry() = default;
	CacheEntry(const CacheEntry&) = default;

	CacheEntry(CacheEntry&&) = default;
	CacheEntry& operator=(CacheEntry&&) = default;

	// Construct a cache entry from the file on disk.
	static CacheEntry FromFile(const std::string& filePath, const std::string& fileName, CacheEntryType type);

	WeakFileAccessor GetAccessor() const;

	// Get the headers virtual address.
	// This is useful if you need to read relative to the start of the entry file.
	std::optional<uint64_t> GetHeaderAddress() const;

	// Get the mapped address for a given file offset.
	// Ex. passing 0x0 will retrieve the mapped address for the start of the file (i.e. the header)
	std::optional<uint64_t> GetMappedAddress(uint64_t fileOffset) const;

	CacheEntryType GetType() const { return m_type; }
	// Ex. "/myuser/mypath/dyld_shared_cache_arm64e"
	const std::string& GetFilePath() const { return m_filePath; }
	// Ex. "dyld_shared_cache_arm64e"
	const std::string GetFileName() const { return m_fileName; }
	const dyld_cache_header& GetHeader() const { return m_header; }
	const std::vector<dyld_cache_mapping_info>& GetMappings() const { return m_mappings; }
	const std::vector<std::pair<std::string, dyld_cache_image_info>>& GetImages() const { return m_images; }
};

// The ID for a given CacheEntry, use this instead of passing a pointer around to avoid complexity :V
typedef uint32_t CacheEntryId;

// The C in DSC.
// This represents the entire cache, all regions and images are visible from here.
// This is the dump for all the information, and what the workflow activities and the UI want.
// Creating this is expensive, both in actual processing and just copying, so we only generate this
// once every time the database is open.
class SharedCache
{
	// Calculated within `AddEntry`, this indicates where the shared cache image is based at.
	uint64_t m_baseAddress = 0;
	// The shared cache can own the virtual memory, this is fine...
	std::shared_ptr<VirtualMemory> m_vm;
	std::vector<CacheEntry> m_entries {};
	// This information is used in tandem with the cache images to load memory regions into the binary view.
	AddressRangeMap<CacheRegion> m_regions {};
	// Describes the images of the cache.
	std::unordered_map<uint64_t, CacheImage> m_images {};
	// All the external symbols for this cache. Both mapped and unmapped (not in the view).
	std::unordered_map<uint64_t, CacheSymbol> m_symbols {};
	// Quickly lookup a symbol by name, populated by `FinalizeSymbols`.
	// `m_namedSymbols` is modified in a worker thread spawned by view init so we must not get a symbol until its populated.
	std::unordered_map<std::string, uint64_t> m_namedSymbols {};
	// Used to guard `m_namedSymbols` as it's accessed on multiple threads.
	// NOTE: Wrapped in unique_ptr to keep SharedCache movable.
	std::unique_ptr<std::shared_mutex> m_namedSymMutex;

	bool ProcessEntryImage(const std::string& path, const dyld_cache_image_info& info);

	// Add a region known not to overlap with another, otherwise use AddRegion.
	// returns whether the region was inserted.
	bool AddNonOverlappingRegion(CacheRegion region);

public:
	SharedCache() = default;
	explicit SharedCache(uint64_t addressSize);

	SharedCache(const SharedCache &) = delete;
	SharedCache &operator=(const SharedCache &) = delete;

	SharedCache(SharedCache &&) noexcept = default;
	SharedCache &operator=(SharedCache &&) noexcept = default;

	uint64_t GetBaseAddress() const { return m_baseAddress; }
	std::shared_ptr<VirtualMemory> GetVirtualMemory() const { return m_vm; }
	const std::vector<CacheEntry>& GetEntries() const { return m_entries; }
	const AddressRangeMap<CacheRegion>& GetRegions() const { return m_regions; }
	const std::unordered_map<uint64_t, CacheImage>& GetImages() const { return m_images; }
	const std::unordered_map<uint64_t, CacheSymbol>& GetSymbols() const { return m_symbols; }

	void AddImage(CacheImage&& image);

	// Add a region that may overlap with another.
	void AddRegion(CacheRegion&& region);

	void AddSymbol(CacheSymbol symbol);

	void AddSymbols(std::vector<CacheSymbol>&& symbols);

	// Adds the cache entry and populates the virtual memory using the mapping information.
	// After being added the entry is read only, there is nothing that can modify it.
	void AddEntry(CacheEntry entry);

	void ProcessEntryImages(const CacheEntry& entry);

	void ProcessEntryRegions(const CacheEntry& entry);

	void ProcessEntrySlideInfo(const CacheEntry& entry) const;

	// Construct the named symbols lookup map for use with `GetSymbolWithName`.
	void ProcessSymbols();

	std::optional<CacheEntry> GetEntryContaining(uint64_t address) const;

	std::optional<CacheEntry> GetEntryWithImage(const CacheImage& image) const;

	std::optional<CacheRegion> GetRegionAt(uint64_t address) const;

	std::optional<CacheRegion> GetRegionContaining(uint64_t address) const;

	std::optional<CacheImage> GetImageAt(uint64_t address) const;

	std::optional<CacheImage> GetImageContaining(uint64_t address) const;

	// TODO: Rename to GetImageWithPath and then make another one for the image name.
	std::optional<CacheImage> GetImageWithName(const std::string& name) const;

	std::optional<CacheSymbol> GetSymbolAt(uint64_t address) const;

	std::optional<CacheSymbol> GetSymbolWithName(const std::string& name);
};
