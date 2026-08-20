#pragma once

#include "machoview.h"

#include <functional>
#include <stdint.h>
#include <string_view>
#include <vector>

namespace BinaryNinja
{
	
enum class FixupType : uint8_t
{
	Bind,
	Rebase,
};

enum class AuthKeyType : uint8_t
{
	IA,
	IB,
	DA,
	DB,
	None,
};

struct FixupInfo
{
	union
	{
		struct
		{
			uint32_t ordinal = 0;
			int32_t addend = 0;
		} bind;
		struct
		{
			uint64_t target = 0;
		} rebase;
	};
	FixupType type : 1;
	bool isAuthenticated : 1 = false;
	AuthKeyType authKeyType : 3 = AuthKeyType::None;
	bool usesAddressDiversity : 1 = false;
	uint16_t addressDiversity = 0;
	uint16_t next = 0;
};

struct ImportEntry
{
	std::string_view name;
	uint64_t addend;
	int32_t libraryOrdinal;
	bool weakImport = false;
};

class ChainedFixupProcessor
{
public:
	ChainedFixupProcessor(Ref<BinaryView> raw, Ref<Logger> logger, uint64_t machOStartOffset, uint64_t preferredLoadAddress,
		const linkedit_data_command& chainedFixupCommand, std::unordered_map<uint64_t, uint64_t> segmentVMAddrToFileOffset)
		: m_raw(std::move(raw))
		, m_logger(std::move(logger))
		, m_machOStartOffset(machOStartOffset)
		, m_fixupsStartOffset(OffsetInRaw(chainedFixupCommand.dataoff))
		, m_fixupsSize(chainedFixupCommand.datasize)
		, m_preferredLoadAddress(preferredLoadAddress)
		, m_segmentVMAddrToFileOffset(std::move(segmentVMAddrToFileOffset))
	{}

	std::vector<ImportEntry> ProcessImports() const;

	// Calls the provided handler for each fixup found. `offset` is relative to `machOStartOffset`.
	//
	// Note that `FixupInfo` references data owned by this object and so should not be used outside
	// of the handler function.
	void ProcessFixups(std::function<void(uint64_t offset, const FixupInfo&)> fixupHandler) const;

private:
	dyld_chained_fixups_header ReadHeader(BinaryReader&) const;

	void ProcessChainedFixups(const dyld_chained_fixups_header&, BinaryReader&) const;
	void ProcessChainsInSegment(const dyld_chained_starts_in_segment&, BinaryReader&) const;

	// Returns a vector of pairs of (page index, offset in page) representing the start of each fixup chain.
	std::vector<std::pair<uint64_t, uint16_t>> ReadChainStartsInSegment(const dyld_chained_starts_in_segment&, BinaryReader&) const;

	uint64_t OffsetInRaw(uint64_t offset) const { return m_machOStartOffset + offset; }
	uint64_t OffsetInFixups(uint64_t offset) const { return m_fixupsStartOffset + offset; }

	Ref<BinaryView> m_raw;
	Ref<Logger> m_logger;

	// Offset to the start of the Mach-O file within the BinaryView.
	// This will be non-zero for Mach-O files within a universal binary.
	uint64_t m_machOStartOffset;

	// Offset to the start of the chained fixups data within the BinaryView.
	uint64_t m_fixupsStartOffset;

	// Total size of the chained fixups data.
	uint64_t m_fixupsSize;

	// The preferred load address of the __TEXT segment. Used for translating
	// address-based fixups into offset-based fixups.
	uint64_t m_preferredLoadAddress;

	std::unordered_map<uint64_t, uint64_t> m_segmentVMAddrToFileOffset;

	mutable std::function<void(uint64_t offset, const FixupInfo&)> m_fixupHandler;
	mutable std::vector<char> m_symbolData;
};

} // namespace BinaryNinja
