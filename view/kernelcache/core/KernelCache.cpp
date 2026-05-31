#include "KernelCache.h"

#include <regex>
#include <filesystem>

using namespace BinaryNinja;

std::pair<std::string, Ref<Type>> CacheSymbol::DemangledName(BinaryView &view) const
{
	QualifiedName qname;
	Ref<Type> outType;
	std::string shortName = name;
	if (DemangleGeneric(view.GetDefaultArchitecture(), name, outType, qname, &view, true))
		shortName = qname.GetString();
	return { shortName, outType };
}

std::pair<Ref<Symbol>, Ref<Type>> CacheSymbol::GetBNSymbolAndType(BinaryView& view) const
{
	auto [shortName, demangledType] = DemangledName(view);
	auto symbol = new Symbol(type, shortName, shortName, name, address, nullptr);
	return {symbol, demangledType};
}

std::vector<std::string> CacheImage::GetDependencies() const
{
	if (header)
		return header->dylibs;
	return {};
}

KernelCache::KernelCache(uint64_t addressSize)
{
	m_namedSymMutex = std::make_unique<std::shared_mutex>();
}


void KernelCache::AddImage(CacheImage&& image)
{
	m_images.insert({image.headerVirtualAddress, std::move(image)});
}

void KernelCache::AddSymbol(CacheSymbol symbol)
{
	m_symbols.insert({symbol.address, std::move(symbol)});
}

void KernelCache::AddSymbols(std::vector<CacheSymbol>&& symbols)
{
	for (auto& symbol : symbols)
		m_symbols.insert({symbol.address, std::move(symbol)});
}

bool KernelCache::ProcessEntryImage(Ref<BinaryView> bv, const std::filesystem::path& path, const fileset_entry_command& info)
{
	auto imageHeader = KernelCacheMachOHeader::ParseHeaderForAddress(bv, info.vmaddr, info.fileoff, path);
	if (!imageHeader.has_value())
		return false;

	// Add the image to the cache.
	CacheImage image;
	image.headerFileAddress = info.fileoff;
	image.headerVirtualAddress = info.vmaddr;
	image.path = path;

	// Add all image regions.
	for (const auto& segment : imageHeader->segments)
	{
		char segName[17];
		memcpy(segName, segment.segname, 16);
		segName[16] = 0;

		CacheRegion sectionRegion;
		sectionRegion.name = imageHeader->identifierPrefix + "::" + std::string(segName);
		sectionRegion.start = segment.vmaddr;
		sectionRegion.size = segment.vmsize;
		// Associate this region with this image, this makes it easier to identify what image owns this region.
		sectionRegion.imageStart = image.headerFileAddress;

		uint32_t flags = SegmentFlagsForSegment(segment);
		// if we're positive we have an entry point for some reason, force the segment
		// executable. this helps with kernel images.
		for (const auto& entryPoint : imageHeader->m_entryPoints)
			if (segment.vmaddr <= entryPoint && (entryPoint < (segment.vmaddr + segment.filesize)))
				flags |= SegmentExecutable;
		sectionRegion.flags = static_cast<BNSegmentFlag>(flags);

		image.regions.push_back(std::move(sectionRegion));
	}

	// Add the exported symbols to the available symbols.
	std::vector<CacheSymbol> exportSymbols = imageHeader->ReadExportSymbolTrie(bv);
	AddSymbols(std::move(exportSymbols));
	TableInfo symbolInfo = { imageHeader->symtab.symoff, imageHeader->symtab.nsyms };
	TableInfo stringInfo = { imageHeader->symtab.stroff, imageHeader->symtab.strsize };
	std::vector<CacheSymbol> symbols = imageHeader->ReadSymbolTable(bv, symbolInfo, stringInfo);
	AddSymbols(std::move(symbols));

	// This is behind a shared pointer as the header itself is very large.
	image.header = std::make_shared<KernelCacheMachOHeader>(std::move(*imageHeader));

	AddImage(std::move(image));
	return true;
}

void KernelCache::ProcessSymbols()
{
	std::unique_lock<std::shared_mutex> lock(*m_namedSymMutex);
	// Populate the named symbols from the regular symbols map.
	m_namedSymbols.reserve(m_symbols.size());
	for (const auto& [address, symbol] : m_symbols)
		m_namedSymbols.emplace(symbol.name, address);
}

void KernelCache::ProcessRelocations(Ref<BinaryView> view, linkedit_data_command chained_fixup_command)
{
	m_relocations.clear();
	if (chained_fixup_command.dataoff && chained_fixup_command.datasize)
	{
		BinaryReader parentReader(view->GetParentView());

		try {
			dyld_chained_fixups_header fixupsHeader {};
			uint64_t fixupHeaderAddress = chained_fixup_command.dataoff;
			parentReader.Seek(fixupHeaderAddress);
			fixupsHeader.fixups_version = parentReader.Read32();
			fixupsHeader.starts_offset = parentReader.Read32();
			fixupsHeader.imports_offset = parentReader.Read32();
			fixupsHeader.symbols_offset = parentReader.Read32();
			fixupsHeader.imports_count = parentReader.Read32();
			fixupsHeader.imports_format = parentReader.Read32();
			fixupsHeader.symbols_format = parentReader.Read32();

			LogDebugF("Chained Fixups: Header @ {:#x} // Fixups version {:#x}", fixupHeaderAddress, fixupsHeader.fixups_version);

			if (fixupsHeader.fixups_version > 0)
			{
				LogError("Chained Fixup parsing failed. Unknown Fixups Version");
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
					LogErrorF("Chained Fixups: Unknown or unsupported pointer format {}, "
						"unable to process chains for segment at 0x{:x}", starts.pointer_format, starts.segment_offset);
					continue;
				}
				}

				uint16_t fmt = starts.pointer_format;
				LogDebugF("Chained Fixups: Segment start @ 0x{:x}, fmt {}", starts.segment_offset, fmt);

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

							LogTraceF("Chained Fixups: @ 0x{:x} ( 0x{:x} ) - {} 0x{:x}", chainEntryAddress,
								view->GetStart() + (chainEntryAddress),
								bind, nextEntryStrideCount);

							if (!bind)
							{
								uint64_t entryOffset = 0;
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
										entryOffset += view->GetStart();

									break;
								}
								case DYLD_CHAINED_PTR_64:
									entryOffset = pointer.generic64.rebase.target;
									break;
								case DYLD_CHAINED_PTR_64_OFFSET:
									entryOffset = pointer.generic64.rebase.target + view->GetStart();
									break;
								// We expect only cases past this point will be applicable in this context.
								case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
								case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
									entryOffset = pointer.kernel64.target + view->GetStart();
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

								m_relocations.emplace_back(view->GetStart() + chainEntryAddress, entryOffset);
							}

							chainEntryAddress += (nextEntryStrideCount * strideSize);

							if (chainEntryAddress > pageAddress + starts.page_size)
							{
								// Something is seriously wrong here. likely malformed binary, or our parsing failed elsewhere.
								// This will log the pointer in mapped memory.
								LogErrorF("Chained Fixups: Pointer at 0x{:x} left page",
									view->GetStart() + ((chainEntryAddress - (nextEntryStrideCount * strideSize))));
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
			LogError("Chained Fixup parsing failed");
		}
	}


	std::sort(m_relocations.begin(), m_relocations.end(),
		[](const std::pair<uint64_t, uint64_t>& a, const std::pair<uint64_t, uint64_t>& b) {
			return a.first < b.first;
		});
}

std::optional<CacheImage> KernelCache::GetImageAt(const uint64_t address) const
{
	const auto it = m_images.find(address);
	if (it == m_images.end())
		return std::nullopt;
	return it->second;
}

std::optional<CacheImage> KernelCache::GetImageContaining(const uint64_t address) const
{
	for (const auto& [startAddress, image] : m_images)
	{
		for (const auto& region : image.regions)
		{
			if (region.AsAddressRange().start <= address && address < region.AsAddressRange().end)
				return image;
		}
	}
	return std::nullopt;
}

std::optional<CacheImage> KernelCache::GetImageWithName(const std::string& name) const
{
	auto imagePath = ImagePathFromString(name);
	for (const auto& [address, image] : m_images)
		if (image.path == imagePath)
			return image;
	return std::nullopt;
}

std::optional<CacheSymbol> KernelCache::GetSymbolAt(uint64_t address) const
{
	const auto it = m_symbols.find(address);
	if (it == m_symbols.end())
		return std::nullopt;
	return it->second;
}

std::optional<CacheSymbol> KernelCache::GetSymbolWithName(const std::string& name)
{
	std::shared_lock<std::shared_mutex> lock(*m_namedSymMutex);
	const auto it = m_namedSymbols.find(name);
	if (it == m_namedSymbols.end())
		return std::nullopt;
	return GetSymbolAt(it->second);
}
