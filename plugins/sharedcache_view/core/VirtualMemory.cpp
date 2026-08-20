#include "VirtualMemory.h"

void VirtualMemory::MapRegion(std::shared_ptr<MappedFileRegion> file, AddressRange mappedRange, uint64_t fileOffset)
{
	VirtualMemoryRegion region(fileOffset, std::move(file));

	// TODO: How to handle overlapping regions?
	for (const auto& [existingRange, existingRegion] : m_regions)
	{
		if (existingRange.Overlaps(mappedRange))
		{
			BinaryNinja::LogErrorF("Overlapping memory region {:#x}", existingRange.start);
		}
	}

	m_regions.insert_or_assign(mappedRange, std::move(region));
}

const VirtualMemoryRegion* VirtualMemory::FindRegionAtAddress(uint64_t address, uint64_t& addressOffset) const
{
	if (const auto& it = m_regions.find(address); it != m_regions.end())
	{
		// The VirtualMemoryRegion object returned contains the page, and more importantly, the file pointer (there can
		// be multiple in newer caches) This is relevant for reading out the data in the rest of this file. The second
		// item in the returned pair is the offset of `address` within the file.
		const auto& range = it->first;
		const auto& mapping = it->second;
		addressOffset = mapping.fileOffset + (address - range.start);
		return &mapping;
	}

	return nullptr;
}

const VirtualMemoryRegion* VirtualMemory::FindRegionAtAddress(uint64_t address) const
{
	uint64_t offset;
	return FindRegionAtAddress(address, offset);
}

bool VirtualMemory::IsAddressMapped(uint64_t address) const
{
	return m_regions.find(address) != m_regions.end();
}

uint64_t VirtualMemory::ReadPointer(uint64_t address) const
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

std::string VirtualMemory::ReadCString(uint64_t address) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadNullTermString(offset);
}

uint8_t VirtualMemory::ReadUInt8(uint64_t address) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadUInt8(offset);
}

int8_t VirtualMemory::ReadInt8(uint64_t address) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadInt8(offset);
}

uint16_t VirtualMemory::ReadUInt16(uint64_t address) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadUInt16(offset);
}

int16_t VirtualMemory::ReadInt16(uint64_t address) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadInt16(offset);
}

uint32_t VirtualMemory::ReadUInt32(uint64_t address) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadUInt32(offset);
}

int32_t VirtualMemory::ReadInt32(uint64_t address) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadInt32(offset);
}

uint64_t VirtualMemory::ReadUInt64(uint64_t address) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadUInt64(offset);
}

int64_t VirtualMemory::ReadInt64(uint64_t address) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadInt64(offset);
}

BinaryNinja::DataBuffer VirtualMemory::ReadBuffer(uint64_t address, size_t length) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadBuffer(offset, length);
}

std::span<const uint8_t> VirtualMemory::ReadSpan(uint64_t address, size_t length) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	return region->file->ReadSpan(offset, length);
}

void VirtualMemory::Read(void* dest, uint64_t address, size_t length) const
{
	uint64_t offset;
	auto* region = FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	region->file->Read(dest, offset, length);
}

VirtualMemoryReader::VirtualMemoryReader(std::shared_ptr<VirtualMemory> memory)
{
	m_memory = memory;
	m_cursor = 0;
}

std::string VirtualMemoryReader::ReadCString(uint64_t address, size_t maxLength)
{
	uint64_t offset;
	auto* region = m_memory->FindRegionAtAddress(address, offset);
	if (!region)
		throw UnmappedRegionException(address);
	// TODO: Advance cursor?
	return region->file->ReadNullTermString(offset, maxLength);
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
