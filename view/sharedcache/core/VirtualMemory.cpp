#include "VirtualMemory.h"

void VirtualMemory::MapRegion(WeakFileAccessor fileAccessor, AddressRange mappedRange, uint64_t fileOffset)
{
	// Create a new VirtualMemoryRegion object
	VirtualMemoryRegion region {fileOffset, std::move(fileAccessor)};

	// TODO: How to handle overlapping regions?
	for (const auto& [existingRange, existingRegion] : m_regions)
	{
		if (existingRange.Overlaps(mappedRange))
		{
			// Handle overlapping regions, e.g., throw an exception or skip the mapping
			BinaryNinja::LogError("Overlapping memory region %llx", existingRange.start);
		}
	}

	// Insert the region into the map
	m_regions.insert_or_assign(mappedRange, region);
}

std::optional<VirtualMemoryRegion> VirtualMemory::GetRegionAtAddress(uint64_t address, uint64_t& addressOffset)
{
	if (const auto& it = m_regions.find(address); it != m_regions.end())
	{
		// The VirtualMemoryRegion object returned contains the page, and more importantly, the file pointer (there can
		// be multiple in newer caches) This is relevant for reading out the data in the rest of this file. The second
		// item in the returned pair is the offset of `address` within the file.
		const auto& range = it->first;
		auto mapping = it->second;
		addressOffset = mapping.fileOffset + (address - range.start);
		return mapping;
	}

	return std::nullopt;
}

std::optional<VirtualMemoryRegion> VirtualMemory::GetRegionAtAddress(uint64_t address)
{
	uint64_t offset;
	return GetRegionAtAddress(address, offset);
}

bool VirtualMemory::IsAddressMapped(uint64_t address)
{
	return m_regions.find(address) != m_regions.end();
}

void VirtualMemory::WritePointer(uint64_t address, size_t pointer)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	region->fileAccessor.lock()->WritePointer(offset, pointer);
}

uint64_t VirtualMemory::ReadPointer(uint64_t address)
{
	switch (m_addressSize)
	{
	case 8:
		return ReadUInt64(address);
	case 4:
		return ReadUInt32(address);
	case 2:
		return ReadUInt16(address);
	default:
		throw std::runtime_error("Unsupported address size");
	}
}

std::string VirtualMemory::ReadCString(uint64_t address)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadNullTermString(offset);
}

uint8_t VirtualMemory::ReadUInt8(uint64_t address)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadUInt8(offset);
}

int8_t VirtualMemory::ReadInt8(uint64_t address)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadInt8(offset);
}

uint16_t VirtualMemory::ReadUInt16(uint64_t address)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadUInt16(offset);
}

int16_t VirtualMemory::ReadInt16(uint64_t address)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadInt16(offset);
}

uint32_t VirtualMemory::ReadUInt32(uint64_t address)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadUInt32(offset);
}

int32_t VirtualMemory::ReadInt32(uint64_t address)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadInt32(offset);
}

uint64_t VirtualMemory::ReadUInt64(uint64_t address)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadUInt64(offset);
}

int64_t VirtualMemory::ReadInt64(uint64_t address)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadInt64(offset);
}

BinaryNinja::DataBuffer VirtualMemory::ReadBuffer(uint64_t address, size_t length)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadBuffer(offset, length);
}

std::pair<const uint8_t*, const uint8_t*> VirtualMemory::ReadSpan(uint64_t address, size_t length)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	return region->fileAccessor.lock()->ReadSpan(offset, length);
}

void VirtualMemory::Read(void* dest, uint64_t address, size_t length)
{
	uint64_t offset;
	auto region = GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	region->fileAccessor.lock()->Read(dest, offset, length);
}

VirtualMemoryReader::VirtualMemoryReader(std::shared_ptr<VirtualMemory> memory)
{
	m_memory = memory;
	m_cursor = 0;
}

std::string VirtualMemoryReader::ReadCString(uint64_t address, size_t maxLength)
{
	uint64_t offset;
	auto region = m_memory->GetRegionAtAddress(address, offset);
	if (!region.has_value())
		throw UnmappedRegionException(address);
	// TODO: Advance cursor?
	return region->fileAccessor.lock()->ReadNullTermString(offset, maxLength);
}

uint64_t VirtualMemoryReader::ReadULEB128(size_t cursorLimit)
{
	uint64_t result = 0;
	int bit = 0;
	uint64_t offset;
	auto mapping = m_memory->GetRegionAtAddress(m_cursor, offset);
	auto fileLimit = offset + (cursorLimit - m_cursor);
	auto fa = mapping->fileAccessor.lock();
	auto* fileBuff = (uint8_t*)fa->Data();
	do
	{
		if (offset >= fileLimit)
			return -1;
		uint64_t slice = ((uint64_t*)&((fileBuff)[offset]))[0] & 0x7f;
		if (bit > 63)
			return -1;
		else
		{
			result |= (slice << bit);
			bit += 7;
		}
	} while (((uint64_t*)&(fileBuff[offset++]))[0] & 0x80);
	// TODO: There has got to be a better way to prevent this...
	fa->Data();  // prevent deallocation of the fileAccessor as we're operating on the raw data buffer
	return result;
}

int64_t VirtualMemoryReader::ReadSLEB128(size_t cursorLimit)
{
	constexpr size_t BYTE_SIZE = 7;    // Number of bits in each SLEB128 byte
	constexpr size_t INT64_BITS = 64;  // Total number of bits in an int64_t

	int64_t value = 0;
	size_t shift = 0;
	uint64_t offset;

	// Retrieve associated memory region and the file buffer
	auto mapping = m_memory->GetRegionAtAddress(m_cursor, offset);
	auto fileLimit = offset + (cursorLimit - m_cursor);
	auto fileAccessor = mapping->fileAccessor.lock();
	auto* fileBuffer = static_cast<uint8_t*>(fileAccessor->Data());

	// Loop through the SLEB128 encoded bytes
	while (offset < fileLimit)
	{
		uint8_t currentByte = fileBuffer[offset++];
		value |= (static_cast<int64_t>(currentByte & 0x7F) << shift);
		shift += BYTE_SIZE;

		if ((currentByte & 0x80) == 0)  // If MSB is not set, we're done
			break;
	}

	// Properly sign-extend the value according to its size
	value = (value << (INT64_BITS - shift)) >> (INT64_BITS - shift);

	// TODO: There has got to be a better way to prevent this...
	// Prevent deallocation of the fileAccessor
	fileAccessor->Data();

	return value;
}

uint64_t VirtualMemoryReader::ReadPointer()
{
	return ReadPointer(m_cursor);
}

uint64_t VirtualMemoryReader::ReadPointer(uint64_t address)
{
	m_cursor = address + m_memory->GetAddressSize();
	return m_memory->ReadPointer(address);
}

uint8_t VirtualMemoryReader::ReadUInt8()
{
	return ReadUInt8(m_cursor);
}

uint8_t VirtualMemoryReader::ReadUInt8(uint64_t address)
{
	m_cursor = address + 1;
	return m_memory->ReadUInt8(address);
}

int8_t VirtualMemoryReader::ReadInt8()
{
	return ReadInt8(m_cursor);
}

int8_t VirtualMemoryReader::ReadInt8(uint64_t address)
{
	m_cursor = address + 1;
	return m_memory->ReadInt8(address);
}

uint16_t VirtualMemoryReader::ReadUInt16()
{
	return ReadUInt16(m_cursor);
}

uint16_t VirtualMemoryReader::ReadUInt16(uint64_t address)
{
	m_cursor = address + 2;
	return m_memory->ReadUInt16(address);
}

int16_t VirtualMemoryReader::ReadInt16()
{
	return ReadInt16(m_cursor);
}

int16_t VirtualMemoryReader::ReadInt16(uint64_t address)
{
	m_cursor = address + 2;
	return m_memory->ReadInt16(address);
}

uint32_t VirtualMemoryReader::ReadUInt32()
{
	return ReadUInt32(m_cursor);
}

uint32_t VirtualMemoryReader::ReadUInt32(uint64_t address)
{
	m_cursor = address + 4;
	return m_memory->ReadUInt32(address);
}

int32_t VirtualMemoryReader::ReadInt32()
{
	return ReadInt32(m_cursor);
}

int32_t VirtualMemoryReader::ReadInt32(uint64_t address)
{
	m_cursor = address + 4;
	return m_memory->ReadInt32(address);
}

uint64_t VirtualMemoryReader::ReadUInt64()
{
	return ReadUInt64(m_cursor);
}

uint64_t VirtualMemoryReader::ReadUInt64(uint64_t address)
{
	m_cursor = address + 8;
	return m_memory->ReadUInt64(address);
}

int64_t VirtualMemoryReader::ReadInt64()
{
	return ReadInt64(m_cursor);
}

int64_t VirtualMemoryReader::ReadInt64(uint64_t address)
{
	m_cursor = address + 8;
	return m_memory->ReadInt64(address);
}

BinaryNinja::DataBuffer VirtualMemoryReader::ReadBuffer(size_t length)
{
	return ReadBuffer(m_cursor, length);
}

BinaryNinja::DataBuffer VirtualMemoryReader::ReadBuffer(uint64_t address, size_t length)
{
	m_cursor = address + length;
	return m_memory->ReadBuffer(address, length);
}

void VirtualMemoryReader::Read(void* dest, size_t length)
{
	Read(dest, m_cursor, length);
}

void VirtualMemoryReader::Read(void* dest, uint64_t address, size_t length)
{
	m_cursor = address + length;
	m_memory->Read(dest, address, length);
}
