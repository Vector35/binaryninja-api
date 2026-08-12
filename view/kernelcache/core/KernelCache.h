#pragma once

#include <vector>

#include "binaryninjaapi.h"
#include "MachO.h"

#include <mutex>
#include <shared_mutex>
#include "Utility.h"

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

	// NOTE: you should really only call this when adding the symbol to the view.
	std::pair<BinaryNinja::Ref<BinaryNinja::Symbol>, BinaryNinja::Ref<BinaryNinja::Type>>
		GetBNSymbolAndType(const BinaryNinja::DemanglerConfig& config) const;
};

struct CacheRegion
{
	// type is always image
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
	uint64_t headerFileAddress;
	uint64_t headerVirtualAddress;
	std::string path;
	// A list to the start of memory regions associated with the image.
	// This lets us load all regions for a given image easily.
	std::vector<CacheRegion> regions;
	std::shared_ptr<KernelCacheMachOHeader> header;

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

// The C in KC.
// This represents the entire cache, all regions and images are visible from here.
// This is the dump for all the information, and what the workflow activities and the UI want.
// Creating this is expensive, both in actual processing and just copying, so we only generate this
// once every time the database is open.
class KernelCache
{
	// Calculated within `AddEntry`, this indicates where the shared cache image is based at.
	uint64_t m_baseAddress = 0;

	std::vector<std::pair<uint64_t, uint64_t>> m_relocations {};

	std::unordered_map<uint64_t, CacheImage> m_images {};
	// All the external symbols for this cache. Both mapped and unmapped (not in the view).
	std::unordered_map<uint64_t, CacheSymbol> m_symbols {};
	// Quickly lookup a symbol by name, populated by `FinalizeSymbols`.
	// `m_namedSymbols` is modified in a worker thread spawned by view init so we must not get a symbol until its populated.
	std::unordered_map<std::string, uint64_t> m_namedSymbols {};
	// Used to guard `m_namedSymbols` as it's accessed on multiple threads.
	// NOTE: Wrapped in unique_ptr to keep KernelCache movable.
	std::unique_ptr<std::shared_mutex> m_namedSymMutex;

public:

	bool ProcessEntryImage(BinaryNinja::Ref<BinaryNinja::BinaryView> bv, const std::string& path, const BinaryNinja::fileset_entry_command& info);
	KernelCache() = default;
	explicit KernelCache(uint64_t addressSize);

	KernelCache(const KernelCache &) = delete;
	KernelCache &operator=(const KernelCache &) = delete;

	KernelCache(KernelCache &&) noexcept = default;
	KernelCache &operator=(KernelCache &&) noexcept = default;

	uint64_t GetBaseAddress() const { return m_baseAddress; }
	const std::unordered_map<uint64_t, CacheImage>& GetImages() const { return m_images; }
	const std::unordered_map<uint64_t, CacheSymbol>& GetSymbols() const { return m_symbols; }

	void AddImage(CacheImage&& image);

	void AddSymbol(CacheSymbol symbol);

	void AddSymbols(std::vector<CacheSymbol>&& symbols);

	// Construct the named symbols lookup map for use with `GetSymbolWithName`.
	void ProcessSymbols();

	void ProcessRelocations(BinaryNinja::Ref<BinaryNinja::BinaryView> view, BinaryNinja::linkedit_data_command chained_fixup_command);

	const std::vector<std::pair<uint64_t, uint64_t>>& GetRelocations() const { return m_relocations; }

	std::optional<CacheImage> GetImageAt(uint64_t address) const;

	std::optional<CacheImage> GetImageContaining(uint64_t address) const;

	// TODO: Rename to GetImageWithPath and then make another one for the image name.
	std::optional<CacheImage> GetImageWithName(const std::string& name) const;

	std::optional<CacheSymbol> GetSymbolAt(uint64_t address) const;

	std::optional<CacheSymbol> GetSymbolWithName(const std::string& name);
};
