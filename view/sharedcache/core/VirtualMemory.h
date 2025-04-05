#pragma once
#include "FileAccessorCache.h"
#include "MappedFileAccessor.h"
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
	// Access the memory regions contents through this.
	// NOTE: Any read through this should be seeked to `fileOffset`
	WeakFileAccessor fileAccessor;

	VirtualMemoryRegion(const VirtualMemoryRegion&) = default;

	VirtualMemoryRegion& operator=(const VirtualMemoryRegion&) = default;

	VirtualMemoryRegion(VirtualMemoryRegion&&) = default;

	VirtualMemoryRegion& operator=(VirtualMemoryRegion&&) = default;
};

// Contains information to handle mapping of multiple mapped files into a single memory space.
// This models how the loader of DYLD shared caches would operate, so that we can effectively query memory regions
// and map them into Binary Ninja.
class VirtualMemory
{
	std::shared_mutex m_regionMutex;
	AddressRangeMap<VirtualMemoryRegion> m_regions;

public:
	// At no point do we ever store a strong pointer to a file accessor, that is the job of the `FileAccessorCache`.
	void MapRegion(WeakFileAccessor fileAccessor, AddressRange mappedRange, uint64_t fileOffset);

	// Returns the region in virtual memory, along with the offset into that region where the address is located.
	// Using the regions file accessor and the address offset you can read a regions content.
	std::optional<VirtualMemoryRegion> GetRegionAtAddress(uint64_t address, uint64_t& addressOffset);

	std::optional<VirtualMemoryRegion> GetRegionAtAddress(uint64_t address);

	bool IsAddressMapped(uint64_t address);

	// TODO: Bulk pointer writes here would alleviate a lot of the time spent in the slide info processor.
	// Write a pointer at a given address. This pointer will be persisted
	// for a given `VirtualMemoryRegion` region, unlike using the MappedFileAccessor directly.
	// The persistence is provided through the WeakFileAccessor itself and thus is unique to the construction.
	void WritePointer(size_t address, size_t pointer);

	std::string ReadCString(uint64_t address);

	uint8_t ReadUInt8(uint64_t address);

	int8_t ReadInt8(uint64_t address);

	uint16_t ReadUInt16(uint64_t address);

	int16_t ReadInt16(uint64_t address);

	uint32_t ReadUInt32(uint64_t address);

	int32_t ReadInt32(uint64_t address);

	uint64_t ReadUInt64(uint64_t address);

	int64_t ReadInt64(uint64_t address);

	BinaryNinja::DataBuffer ReadBuffer(uint64_t address, size_t length);

	std::pair<const uint8_t*, const uint8_t*> ReadSpan(size_t address, size_t length);

	void Read(void* dest, uint64_t address, size_t length);
};

class VirtualMemoryReader
{
	std::shared_ptr<VirtualMemory> m_memory;
	uint64_t m_cursor;
	uint64_t m_addressSize;
	BNEndianness m_endianness = LittleEndian;

public:
	explicit VirtualMemoryReader(std::shared_ptr<VirtualMemory> memory, uint64_t addressSize = 8);

	void SetEndianness(BNEndianness endianness) { m_endianness = endianness; }

	BNEndianness GetEndianness() const { return m_endianness; }

	void Seek(const uint64_t address) { m_cursor = address; };

	void SeekRelative(const size_t offset) { m_cursor += offset; };

	size_t GetOffset() const { return m_cursor; }

	std::string ReadCString(uint64_t address, size_t maxLength = -1);

	uint64_t ReadULEB128(size_t cursorLimit);

	int64_t ReadSLEB128(size_t cursorLimit);

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
