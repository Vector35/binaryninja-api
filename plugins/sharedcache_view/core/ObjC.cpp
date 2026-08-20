#include "ObjC.h"

#include "SharedCacheController.h"

using namespace BinaryNinja;
using namespace DSCObjC;

SharedCacheObjCReader::SharedCacheObjCReader(VirtualMemoryReader reader) : m_reader(reader) {}

void SharedCacheObjCReader::Read(void* dest, size_t len)
{
	m_reader.Read(dest, len);
}

std::string SharedCacheObjCReader::ReadCString(size_t maxLength)
{
	return m_reader.ReadCString(m_reader.GetOffset(), maxLength);
}

uint8_t SharedCacheObjCReader::Read8()
{
	return m_reader.ReadUInt8();
}

uint16_t SharedCacheObjCReader::Read16()
{
	return m_reader.ReadUInt16();
}

uint32_t SharedCacheObjCReader::Read32()
{
	return m_reader.ReadUInt32();
}

uint64_t SharedCacheObjCReader::Read64()
{
	return m_reader.ReadUInt64();
}

int8_t SharedCacheObjCReader::ReadS8()
{
	return m_reader.ReadInt8();
}

int16_t SharedCacheObjCReader::ReadS16()
{
	return m_reader.ReadInt16();
}

int32_t SharedCacheObjCReader::ReadS32()
{
	return m_reader.ReadInt32();
}

int64_t SharedCacheObjCReader::ReadS64()
{
	return m_reader.ReadInt64();
}

uint64_t SharedCacheObjCReader::ReadPointer()
{
	return m_reader.ReadPointer();
}

uint64_t SharedCacheObjCReader::GetOffset() const
{
	return m_reader.GetOffset();
}

void SharedCacheObjCReader::Seek(uint64_t offset)
{
	m_reader.Seek(offset);
}

void SharedCacheObjCReader::SeekRelative(int64_t offset)
{
	m_reader.SeekRelative(offset);
}

VirtualMemoryReader& SharedCacheObjCReader::GetVMReader()
{
	return m_reader;
}

std::shared_ptr<ObjCReader> SharedCacheObjCProcessor::GetReader()
{
	const auto controller = DSC::SharedCacheController::FromView(*m_data);
	// TODO: This should never happen.
	if (!controller)
		throw std::runtime_error("SharedCacheController not found for SharedCacheObjCProcessor::GetReader!");
	auto reader = VirtualMemoryReader(controller->GetCache().GetVirtualMemory());
	return std::make_shared<SharedCacheObjCReader>(reader);
}

void SharedCacheObjCProcessor::GetRelativeMethod(ObjCReader* reader, method_t& meth, bool typesAreOffsetsFromSelectorBase)
{
	if (m_customRelativeMethodSelectorBase.has_value())
	{
		meth.name = m_customRelativeMethodSelectorBase.value() + reader->ReadS32();

		// `typesAreOffsetsFromSelectorBase` indicates that `types` is an unsigned offset into the cache's
		// deduplicated string pool, relative to the same base address as relative method selectors.
		if (typesAreOffsetsFromSelectorBase)
		{
			meth.types = m_customRelativeMethodSelectorBase.value() + reader->Read32();
		}
		else
		{
			uint64_t offset = reader->GetOffset();
			meth.types = offset + reader->ReadS32();
		}

		uint64_t offset = reader->GetOffset();
		meth.imp = offset + reader->ReadS32();
	}
	else
	{
		ObjCProcessor::GetRelativeMethod(reader, meth, typesAreOffsetsFromSelectorBase);
	}
}

std::optional<ObjCOptimizationHeader> GetObjCOptimizationHeader(SharedCache& cache, VirtualMemoryReader& reader)
{
	// Find the first primary entry and use that header to read the obj opt header.
	// Don't ask me why this is done like this...
	std::optional<dyld_cache_header> primaryCacheHeader = std::nullopt;
	for (const auto& entry : cache.GetEntries())
	{
		if (entry.GetType() == CacheEntryType::Primary)
		{
			primaryCacheHeader = entry.GetHeader();
			break;
		}
	}

	// Check if we even have the obj opt stuff.
	if (!primaryCacheHeader || !primaryCacheHeader->objcOptsOffset || !primaryCacheHeader->objcOptsSize)
		return std::nullopt;

	ObjCOptimizationHeader header = {};
	// Ignoring `objcOptsSize` in favor of `sizeof(ObjCOptimizationHeader)` matches dyld's behavior.
	// TODO: The base address is the lowest region, however is that going to be where the primary cache header resides?
	reader.Read(&header, cache.GetBaseAddress() + primaryCacheHeader->objcOptsOffset, sizeof(ObjCOptimizationHeader));

	return header;
}

std::optional<std::pair<uint64_t, LegacyObjCOptimizationHeader>> GetLegacyObjCOptimizationHeader(SharedCache& cache, VirtualMemoryReader& reader)
{
	// In older versions the header lives in the `__TEXT,__objc_opt_ro` section within /usr/lib/libobjc.A.dylib
	auto libObjC = cache.GetImageWithName("/usr/lib/libobjc.A.dylib");
	if (!libObjC)
		return std::nullopt;

	// Convert the header's `char[16]` to a `string_view`.
	auto AsStringView = []<size_t N>(const char (&arr)[N]) {
	    const char* end = std::find(arr, arr + N, '\0');
	    return std::string_view(arr, end - arr);
	};

	for (auto section : libObjC->header->sections) {
		if (AsStringView(section.segname) != "__TEXT" || AsStringView(section.sectname) != "__objc_opt_ro")
			continue;

		LegacyObjCOptimizationHeader header = {};
		reader.Read(&header, section.addr, sizeof(LegacyObjCOptimizationHeader));

		// The `relativeMethodSelectorBaseAddressOffset` field was added in version 16 (the final version of this struct).
		if (header.version >= 16)
			return {{section.addr, header}};

		break;
	}

	return std::nullopt;
}

uint64_t SharedCacheObjCProcessor::GetObjCRelativeMethodBaseAddress(ObjCReader* reader)
{
	// Try and retrieve the base address of the selector stuff.
	if (const auto controller = DSC::SharedCacheController::FromView(*m_data))
	{
		auto dangerReader = dynamic_cast<SharedCacheObjCReader*>(reader)->GetVMReader();
		if (const auto header = GetObjCOptimizationHeader(controller->GetCache(), dangerReader); header.has_value())
		{
			auto baseAddress = controller->GetCache().GetBaseAddress();
			m_customRelativeMethodSelectorBase = baseAddress + header->relativeMethodSelectorBaseAddressOffset;
		}
		else if (const auto info = GetLegacyObjCOptimizationHeader(controller->GetCache(), dangerReader); info.has_value())
		{
			const auto [optSectionAddr, header] = *info;
			m_customRelativeMethodSelectorBase = optSectionAddr + header.relativeMethodSelectorBaseAddressOffset;
		}
	}

	return m_customRelativeMethodSelectorBase.value_or(0);
}

Ref<Symbol> SharedCacheObjCProcessor::GetSymbol(uint64_t address)
{
	if (const auto symbol = m_data->GetSymbolByAddress(address))
		return symbol;

	const auto controller = DSC::SharedCacheController::FromView(*m_data);
	if (!controller)
		return nullptr;

	// No existing symbol located, try and search through the symbols of the cache.
	auto cacheSymbol = controller->GetCache().GetSymbolAt(address);
	if (!cacheSymbol.has_value())
		return nullptr;

	// Define the new symbol!
	// While the method is "getting a symbol" and not applying it to the view, currently this is the more effective
	// approach than monitoring every usage of this function to make sure they also define the symbol.
	Ref<Symbol> symbol(new Symbol(cacheSymbol->type, cacheSymbol->name, address));
	m_data->DefineAutoSymbol(symbol);
	return symbol;
}

Ref<Section> SharedCacheObjCProcessor::GetSectionWithName(const char *sectionName)
{
	const auto controller = DSC::SharedCacheController::FromView(*m_data);
	if (!controller)
		return nullptr;

	const auto image = controller->GetCache().GetImageAt(m_imageAddress);
	if (!image)
		return nullptr;

	for (const auto& section : image->header->sectionNames)
		if (section.find(sectionName) != std::string::npos)
			return m_data->GetSectionByName(section);

	return nullptr;
}

SharedCacheObjCProcessor::SharedCacheObjCProcessor(BinaryView *data, uint64_t imageAddress)
	: ObjCProcessor(data, "SharedCache.ObjC", true)
{
	m_imageAddress = imageAddress;
}
