#include "chained_fixups.h"

#include "view/macho/machoview.h"
#include <span>

// If enabled, prints detailed information in the same format as `dyld_info -fixup_chain_details`
// to allow comparing behavior.
// #define DEBUG_PRINT_DYLD_INFO 1

#if DEBUG_PRINT_DYLD_INFO
namespace BinaryNinja {
std::string format_as(const FixupInfo& fixup);
}

template <>
struct fmt::formatter<BinaryNinja::AuthKeyType> : fmt::formatter<std::string>
{
	template <typename FormatContext>
	auto format(const BinaryNinja::AuthKeyType& type, FormatContext& ctx) const
	{
		using BinaryNinja::AuthKeyType;
		std::string_view name = "Unknown";
		switch (type)
		{
			case AuthKeyType::IA: name = "IA"; break;
			case AuthKeyType::IB: name = "IB"; break;
			case AuthKeyType::DA: name = "DA"; break;
			case AuthKeyType::DB: name = "DB"; break;
			case AuthKeyType::None: name = "None"; break;
		}
		return fmt::formatter<std::string>::format(name, ctx);
	}
};
#endif

namespace BinaryNinja {

namespace {

FixupInfo BindFixup(uint32_t ordinal, int32_t addend, uint16_t next)
{
	return FixupInfo{ .bind = { ordinal, addend }, .type = FixupType::Bind, .next = next };
}

FixupInfo RebaseFixup(uint64_t target, uint16_t next)
{
	return FixupInfo{ .rebase = { target }, .type = FixupType::Rebase, .next = next };
}

FixupInfo AuthBindFixup(uint32_t ordinal,
	AuthKeyType keyType, bool usesAddressDiversity, uint16_t addressDiversity, uint16_t next)
{
	return FixupInfo{
		.bind = { ordinal, 0 }, .type = FixupType::Bind, .isAuthenticated = true,
		.authKeyType = keyType, .usesAddressDiversity = usesAddressDiversity,
		.addressDiversity = addressDiversity, .next = next
	};
}

FixupInfo AuthRebaseFixup(uint64_t target,
	AuthKeyType keyType, bool usesAddressDiversity, uint16_t addressDiversity, uint16_t next)
{
	return FixupInfo{
		.rebase = { target }, .type = FixupType::Rebase, .isAuthenticated = true,
		.authKeyType = keyType, .usesAddressDiversity = usesAddressDiversity,
		.addressDiversity = addressDiversity, .next = next
	};
}

FixupInfo ConvertFromAddressToOffset(FixupInfo fixup, uint64_t preferredLoadAddress)
{
	if (fixup.type == FixupType::Rebase)
		fixup.rebase.target -= preferredLoadAddress;

	return fixup;
}

uint64_t Stride(int pointerFormat)
{
	switch (pointerFormat)
	{
		case DYLD_CHAINED_PTR_ARM64E:
		case DYLD_CHAINED_PTR_ARM64E_USERLAND:
		case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
		case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
			return 8;

		case DYLD_CHAINED_PTR_32_CACHE:
		case DYLD_CHAINED_PTR_32_FIRMWARE:
		case DYLD_CHAINED_PTR_32:
		case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
		case DYLD_CHAINED_PTR_64_OFFSET:
		case DYLD_CHAINED_PTR_64:
		case DYLD_CHAINED_PTR_ARM64E_KERNEL:
		case DYLD_CHAINED_PTR_ARM64E_SEGMENTED:
			return 4;

		case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			return 1;

		default:
			return 0;
	}
}

bool IsOffsetBased(int pointerFormat)
{
	switch (pointerFormat)
	{
		case DYLD_CHAINED_PTR_ARM64E_USERLAND:
		case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
		case DYLD_CHAINED_PTR_ARM64E_KERNEL:
		case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
		case DYLD_CHAINED_PTR_64_OFFSET:
		case DYLD_CHAINED_PTR_32_CACHE:
		case DYLD_CHAINED_PTR_32:
		case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
		case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			return true;

		case DYLD_CHAINED_PTR_ARM64E:
		case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		case DYLD_CHAINED_PTR_ARM64E_SEGMENTED:
		case DYLD_CHAINED_PTR_64:
		case DYLD_CHAINED_PTR_32_FIRMWARE:
			return false;
	}
	return false;
}

// DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND, DYLD_CHAINED_PTR_ARM64E_FIRMWARE,
// DYLD_CHAINED_PTR_ARM64E_KERNEL, DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE
FixupInfo ParseFixup(Arm64e ptr)
{
	if (ptr.bind.bind)
	{
		if (!ptr.bind.auth)
			return BindFixup(ptr.bind.ordinal, ptr.bind.addend, ptr.bind.next);

		return AuthBindFixup(ptr.authBind.ordinal,
			(AuthKeyType)ptr.authBind.key, ptr.authBind.addrDiv,
			ptr.authBind.diversity, ptr.authBind.next);
	}

	if (!ptr.rebase.auth) {
		// TODO: Handle high8.
		return RebaseFixup(ptr.rebase.target, ptr.rebase.next);
	}

	return AuthRebaseFixup(ptr.authRebase.target, (AuthKeyType)ptr.authRebase.key,
	ptr.authRebase.addrDiv, ptr.authRebase.diversity, ptr.authRebase.next);
}

// DYLD_CHAINED_PTR_ARM64E_USERLAND24
FixupInfo ParseFixup24(Arm64e ptr)
{
	// DYLD_CHAINED_PTR_ARM64E_USERLAND24 has special handling for binds only.
	if (ptr.bind24.bind) {
		if (!ptr.bind24.auth)
			return BindFixup(ptr.bind24.ordinal, 0, ptr.bind24.next);

		return AuthBindFixup(ptr.authBind24.ordinal,
			(AuthKeyType)ptr.authBind24.key, ptr.authBind24.addrDiv,
			ptr.authBind24.diversity, ptr.authBind24.next);
	}

	// For rebases it is interpreted as if it were DYLD_CHAINED_PTR_ARM64E.
	return ParseFixup(ptr);
}

// DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET
FixupInfo ParseFixup(Generic64 ptr)
{
	if (ptr.bind.bind)
		return BindFixup(ptr.bind.ordinal, ptr.bind.addend, ptr.bind.next);

	// TODO: Handle high8.
	return RebaseFixup(ptr.rebase.target, ptr.rebase.next);
}

// DYLD_CHAINED_PTR_32, DYLD_CHAINED_PTR_32_FIRMWARE
FixupInfo ParseFixup(Generic32 ptr)
{
	if (ptr.bind.bind)
		return BindFixup(ptr.bind.ordinal, ptr.bind.addend, ptr.bind.next);

	return RebaseFixup(ptr.rebase.target, ptr.rebase.next);
}

// DYLD_CHAINED_PTR_32_CACHE
FixupInfo ParseFixup(dyld_chained_ptr_32_cache_rebase ptr)
{
	return RebaseFixup(ptr.target, ptr.next);
}

// Returns a function that will read a single chained fixup of the given format
// from the provided BinaryReader, returning the raw value and the parsed FixupInfo.
auto FixupReaderForFormat(int format) -> std::pair<uint64_t, FixupInfo>(*)(BinaryReader&)
{
	switch (format)
	{
		case DYLD_CHAINED_PTR_ARM64E:
		case DYLD_CHAINED_PTR_ARM64E_USERLAND:
		case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		case DYLD_CHAINED_PTR_ARM64E_KERNEL:
		case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
			return +[](BinaryReader& reader) -> std::pair<uint64_t, FixupInfo> {
				uint64_t raw = reader.Read64();
				return {raw, ParseFixup(ChainedFixupPointer{ .raw64 = raw }.arm64e) };
			};
		case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
			return +[](BinaryReader& reader) -> std::pair<uint64_t, FixupInfo> {
				uint64_t raw = reader.Read64();
				return {raw, ParseFixup24(ChainedFixupPointer{ .raw64 = raw }.arm64e) };
			};
		case DYLD_CHAINED_PTR_64:
		case DYLD_CHAINED_PTR_64_OFFSET:
			return +[](BinaryReader& reader) -> std::pair<uint64_t, FixupInfo> {
				uint64_t raw = reader.Read64();
				return {raw, ParseFixup(ChainedFixupPointer{ .raw64 = raw }.generic64) };
			};
		case DYLD_CHAINED_PTR_32:
		case DYLD_CHAINED_PTR_32_FIRMWARE:
			return +[](BinaryReader& reader) -> std::pair<uint64_t, FixupInfo> {
				uint32_t raw = reader.Read32();
				return {static_cast<uint64_t>(raw), ParseFixup(ChainedFixupPointer{ .raw32 = raw }.generic32) };
			};
		case DYLD_CHAINED_PTR_32_CACHE:
			return +[](BinaryReader& reader) -> std::pair<uint64_t, FixupInfo> {
				uint32_t raw = reader.Read32();
				return {static_cast<uint64_t>(raw), ParseFixup(ChainedFixupPointer{ .raw32 = raw }.cache32)};
			};
		case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
		case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
		case DYLD_CHAINED_PTR_ARM64E_SEGMENTED:
			// These formats are not yet supported.
			return nullptr;
	}
	throw std::invalid_argument("Unknown chained pointer format: " + std::to_string(format));
}

ImportEntry ReadChainedImport32(BinaryReader& reader, std::span<const char> symbolData)
{
	dyld_chained_import import;
	reader.Read(&import, sizeof(import));
	std::string_view view;
	if (symbolData.size() > import.name_offset) {
		view = std::string_view(&symbolData[import.name_offset]);
	} else {
		view = std::string_view();
	}
	return {
		view,
		0,
		import.lib_ordinal > 0xF0 ? static_cast<int8_t>(import.lib_ordinal) : static_cast<int32_t>(import.lib_ordinal),
		(bool)import.weak_import,
	};
}

ImportEntry ReadChainedImportAddend32(BinaryReader& reader, std::span<const char> symbolData)
{
	dyld_chained_import_addend import;
	reader.Read(&import, sizeof(import));
	return {
		std::string_view(&symbolData[import.name_offset]),
		static_cast<uint32_t>(import.addend),
		import.lib_ordinal > 0xF0 ? static_cast<int8_t>(import.lib_ordinal) : static_cast<int32_t>(import.lib_ordinal),
		(bool)import.weak_import,
	};
}

ImportEntry ReadChainedImportAddend64(BinaryReader& reader, std::span<const char> symbolData)
{
	dyld_chained_import_addend64 import;
	reader.Read(&import, sizeof(import));
	return {
		std::string_view(&symbolData[import.name_offset]),
		import.addend,
		import.lib_ordinal > 0xFFF0 ? static_cast<int16_t>(import.lib_ordinal) : static_cast<int32_t>(import.lib_ordinal),
		(bool)import.weak_import,
	};
}

// Returns a function that will read a single chained import of the given format
// from the provided BinaryReader, returning the parsed ImportEntry.
auto ChainedImportReaderForFormat(int format)
{
	switch (format)
	{
		case DYLD_CHAINED_IMPORT:
			return ReadChainedImport32;
		case DYLD_CHAINED_IMPORT_ADDEND:
			return ReadChainedImportAddend32;
		case DYLD_CHAINED_IMPORT_ADDEND64:
			return ReadChainedImportAddend64;
	}

	throw std::invalid_argument("Unknown chained import format");
}

} // unnamed namespace

std::vector<ImportEntry> ChainedFixupProcessor::ProcessImports() const
{
	std::vector<ImportEntry> imports;

	BinaryReader reader(m_raw);
	reader.Seek(m_fixupsStartOffset);

	auto header = ReadHeader(reader);

	uint64_t symbolDataSize = m_fixupsSize - header.symbols_offset;
	if (!symbolDataSize) {
		return imports;
	}
	m_symbolData.resize(symbolDataSize);
	m_raw->Read(&m_symbolData[0], OffsetInFixups(header.symbols_offset), symbolDataSize);

	reader.Seek(OffsetInFixups(header.imports_offset));

	auto importHandler = ChainedImportReaderForFormat(header.imports_format);
	for (uint32_t i = 0; i < header.imports_count; i++)
	{
		ImportEntry entry = importHandler(reader, m_symbolData);

#if DEBUG_PRINT_DYLD_INFO
		fmt::println("  import[{}]: ", i);
		fmt::println("      name:            {}", entry.name);
		fmt::println("      addend:          0x{:X}", entry.addend);
		fmt::println("      library_ordinal: {}", entry.libraryOrdinal);
#endif

		imports.push_back(std::move(entry));
	}

	return imports;
}

void ChainedFixupProcessor::ProcessFixups(std::function<void(uint64_t, const FixupInfo&)> fixupHandler) const
{
	m_fixupHandler = std::move(fixupHandler);

	BinaryReader reader(m_raw);
	reader.Seek(m_fixupsStartOffset);

	auto header = ReadHeader(reader);
#if DEBUG_PRINT_DYLD_INFO
	fmt::println("Chained Fixups Header:");
	fmt::println("      fixups_version: 0x{:08X}", header.fixups_version);
	fmt::println("      starts_offset:  0x{:08X}", header.starts_offset);
	fmt::println("      imports_offset: 0x{:08X}", header.imports_offset);
	fmt::println("      symbols_offset: 0x{:08X}", header.symbols_offset);
	fmt::println("      imports_count:  {}", header.imports_count);
	fmt::println("      imports_format: {}", header.imports_format);
	fmt::println("      symbols_format: {}", header.symbols_format);
#endif
	ProcessChainedFixups(header, reader);

	m_fixupHandler = {};
}

dyld_chained_fixups_header ChainedFixupProcessor::ReadHeader(BinaryReader& reader) const
{
	return {
		reader.Read32(),
		reader.Read32(),
		reader.Read32(),
		reader.Read32(),
		reader.Read32(),
		reader.Read32(),
		reader.Read32(),
	};
}

void ChainedFixupProcessor::ProcessChainedFixups(const dyld_chained_fixups_header& header, BinaryReader& reader) const
{
	reader.Seek(OffsetInFixups(header.starts_offset));

	// Read dyld_chained_starts_in_image
	uint32_t segmentCount = reader.Read32();
	std::vector<uint32_t> segmentOffsets(segmentCount);
	for (uint32_t i = 0; i < segmentCount; i++)
		segmentOffsets[i] = reader.Read32();

	[[maybe_unused]] size_t i = 0;
	for (uint32_t offset : segmentOffsets)
	{
		i++;
		if (!offset)
			continue;

		reader.Seek(OffsetInFixups(header.starts_offset + offset));

		// Read dyld_chained_starts_in_segment
		dyld_chained_starts_in_segment segment = {
			reader.Read32(),
			reader.Read16(),
			reader.Read16(),
			reader.Read64(),
			reader.Read32(),
			reader.Read16(),
		};
#if DEBUG_PRINT_DYLD_INFO
		fmt::println("        seg[{}]:", i);
		fmt::println("          page_size:       0x{:04X}", segment.page_size);
		fmt::println("          pointer_format:  {}", segment.pointer_format);
		fmt::println("          segment_offset:  0x{:08X}", segment.segment_offset);
		fmt::println("          max_pointer:     0x{:08X}", segment.max_valid_pointer);
		fmt::println("          pages:           {}", segment.page_count);
#endif
		ProcessChainsInSegment(segment, reader);
	}

}

void ChainedFixupProcessor::ProcessChainsInSegment(const dyld_chained_starts_in_segment& segment, BinaryReader& reader) const
{
	uint64_t stride = Stride(segment.pointer_format);
	bool isOffset = IsOffsetBased(segment.pointer_format);
	auto fixupReader = FixupReaderForFormat(segment.pointer_format);
	if (!fixupReader)
	{
		m_logger->LogWarnF("Unsupported pointer format in chained fixups: {}", segment.pointer_format);
		return;
	}
	auto it = m_segmentVMAddrToFileOffset.find(segment.segment_offset + m_preferredLoadAddress);
	if (it == m_segmentVMAddrToFileOffset.end())
	{
		m_logger->LogWarnF("No file offset found for segment vmaddr {:#x}", segment.segment_offset);
		return;
	}
	uint64_t segmentFileOffset = it->second;

	auto chainStarts = ReadChainStartsInSegment(segment, reader);
	for (auto [pageIndex, offsetInPage] : chainStarts)
	{
#if DEBUG_PRINT_DYLD_INFO
		fmt::println("            start[{:2}]: 0x{:04X}", pageIndex, offsetInPage);
#endif

		uint64_t pageOffset = segmentFileOffset + (pageIndex * segment.page_size);
		reader.Seek(pageOffset + offsetInPage);

		bool done = false;
		while (!done)
		{
			uint64_t position = reader.GetOffset();
			auto [raw, fixupInfo] = fixupReader(reader);

			if (!isOffset)
				fixupInfo = ConvertFromAddressToOffset(fixupInfo, m_preferredLoadAddress);

			uint64_t positionVMAddr = position - segmentFileOffset + segment.segment_offset;
#if DEBUG_PRINT_DYLD_INFO
			fmt::println("  0x{:08X}:  raw: 0x{:016X}  {}", positionVMAddr, raw, fixupInfo);
#endif
			m_fixupHandler(positionVMAddr, fixupInfo);

			done = (fixupInfo.next == 0);
			reader.Seek(position + (fixupInfo.next * stride));
		}
	}
}

std::vector<std::pair<uint64_t, uint16_t>> ChainedFixupProcessor::ReadChainStartsInSegment(const dyld_chained_starts_in_segment& segment, BinaryReader& reader) const
{
	uint64_t chainStartsOffset = reader.GetOffset();
	std::vector<std::pair<uint64_t, uint16_t>> chainStarts;
	for (size_t i = 0; i < segment.page_count; i++) {
		uint16_t start = reader.Read16();
		if (start == DYLD_CHAINED_PTR_START_NONE)
			continue;

		if (!(start & DYLD_CHAINED_PTR_START_MULTI))
		{
			chainStarts.push_back({i, start});
			continue;
		}

		// For armv7, and potentially other architectures, there can be multiple chains per page.
		// When this is the case, the value has the DYLD_CHAINED_PTR_START_MULTI bit set, and the
		// lower 15 bits are an index into chain starts table.
		uint64_t savedOffset = reader.GetOffset();
		uint16_t overflowIndex = start & ~DYLD_CHAINED_PTR_START_MULTI;
		reader.Seek(chainStartsOffset + (overflowIndex * sizeof(uint16_t)));

		bool chainEnd = false;
		while (!chainEnd)
		{
			uint16_t start = reader.Read16();
			chainEnd = (start & DYLD_CHAINED_PTR_START_LAST);
			chainStarts.push_back({i, start & ~DYLD_CHAINED_PTR_START_LAST});

		}
		reader.Seek(savedOffset);
	}

	return chainStarts;
}

#ifdef DEBUG_PRINT_DYLD_INFO

std::string format_as(const FixupInfo& fixup)
{
	if (fixup.type == FixupType::Bind)
	{
		if (fixup.isAuthenticated)
		{
			return fmt::format("  auth-bind: (next: {:03}, key: {}, addrDiv: {:d}, diversity: 0x{:04X}, bindOrdinal: 0x{:06X})",
				fixup.next,
				fixup.authKeyType,
				fixup.usesAddressDiversity,
				fixup.addressDiversity,
				fixup.bind.ordinal);
		}

		std::string addend = "";
		if (fixup.bind.addend)
			addend = fmt::format(", addend: {}", fixup.bind.addend);

		return fmt::format("       bind: (next: {:03}, bindOrdinal: 0x{:06X}{})",
			fixup.next,
			fixup.bind.ordinal,
			addend);
	}

	if (fixup.isAuthenticated)
	{
		return fmt::format("auth-rebase: (next: {:03}, key: {}, addrDiv: {:d}, diversity: 0x{:04X}, target: 0x{:011X})",
			fixup.next,
			fixup.authKeyType,
			fixup.usesAddressDiversity,
			fixup.addressDiversity,
			fixup.rebase.target);
	}

	return fmt::format("     rebase: (next: {:03}, target: 0x{:011X})",
		fixup.next,
		fixup.rebase.target);
}

#endif

} // namespace BinaryNinja
