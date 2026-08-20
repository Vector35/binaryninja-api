#pragma once
#include "MappedFileRegion.h"
#include "Utility.h"

class UnmappedRegionException : public std::exception
{
	uint64_t m_address;

public:
	explicit UnmappedRegionException(uint64_t address) : m_address(address) {}

	virtual const char* what() const throw()
	{
		thread_local std::string message;
		message = fmt::format("Tried to access unmapped region using address {0:x}", m_address);
		return message.c_str();
	}
};

// A region within the virtual memory
struct VirtualMemoryRegion
{
	uint64_t fileOffset;
	std::shared_ptr<MappedFileRegion> file;

	VirtualMemoryRegion(uint64_t offset, std::shared_ptr<MappedFileRegion> f)
		: fileOffset(offset), file(std::move(f)) {}
};

// Contains information to handle mapping of multiple mapped files into a single memory space.
// This models how the loader of DYLD shared caches would operate, so that we can effectively query memory regions
// and map them into Binary Ninja.
class VirtualMemory
{
	AddressRangeMap<VirtualMemoryRegion> m_regions;
	uint64_t m_addressSize = 8;

public:
	explicit VirtualMemory(uint64_t addressSize = 8) : m_addressSize(addressSize) {}

	uint64_t GetAddressSize() const { return m_addressSize; }

	void MapRegion(std::shared_ptr<MappedFileRegion> file, AddressRange mappedRange, uint64_t fileOffset);

	const VirtualMemoryRegion* FindRegionAtAddress(uint64_t address, uint64_t& addressOffset) const;

	const VirtualMemoryRegion* FindRegionAtAddress(uint64_t address) const;

	bool IsAddressMapped(uint64_t address) const;

	uint64_t ReadPointer(uint64_t address) const;

	std::string ReadCString(uint64_t address) const;

	uint8_t ReadUInt8(uint64_t address) const;

	int8_t ReadInt8(uint64_t address) const;

	uint16_t ReadUInt16(uint64_t address) const;

	int16_t ReadInt16(uint64_t address) const;

	uint32_t ReadUInt32(uint64_t address) const;

	int32_t ReadInt32(uint64_t address) const;

	uint64_t ReadUInt64(uint64_t address) const;

	int64_t ReadInt64(uint64_t address) const;

	BinaryNinja::DataBuffer ReadBuffer(uint64_t address, size_t length) const;

	std::span<const uint8_t> ReadSpan(uint64_t address, size_t length) const;

	void Read(void* dest, uint64_t address, size_t length) const;
};

class VirtualMemoryReader
{
	std::shared_ptr<VirtualMemory> m_memory;
	uint64_t m_cursor;
	BNEndianness m_endianness = LittleEndian;

public:
	explicit VirtualMemoryReader(std::shared_ptr<VirtualMemory> memory);

	void SetEndianness(BNEndianness endianness) { m_endianness = endianness; }

	BNEndianness GetEndianness() const { return m_endianness; }

	void Seek(const uint64_t address) { m_cursor = address; };

	void SeekRelative(const size_t offset) { m_cursor += offset; };

	size_t GetOffset() const { return m_cursor; }

	std::string ReadCString(uint64_t address, size_t maxLength = -1);

	uint64_t ReadPointer();

	uint64_t ReadPointer(uint64_t address);

	uint8_t ReadUInt8();

	uint8_t ReadUInt8(uint64_t address);

	int8_t ReadInt8();

	int8_t ReadInt8(uint64_t address);

	uint16_t ReadUInt16();

	uint16_t ReadUInt16(uint64_t address);

	int16_t ReadInt16();

	int16_t ReadInt16(uint64_t address);

	uint32_t ReadUInt32();

	uint32_t ReadUInt32(uint64_t address);

	int32_t ReadInt32();

	int32_t ReadInt32(uint64_t address);

	uint64_t ReadUInt64();

	uint64_t ReadUInt64(uint64_t address);

	int64_t ReadInt64();

	int64_t ReadInt64(uint64_t address);

	BinaryNinja::DataBuffer ReadBuffer(size_t length);

	BinaryNinja::DataBuffer ReadBuffer(uint64_t address, size_t length);

	void Read(void* dest, size_t length);

	void Read(void* dest, uint64_t address, size_t length);
};
