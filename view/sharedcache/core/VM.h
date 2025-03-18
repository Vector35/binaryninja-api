//
// Created by kat on 5/23/23.
//

#ifndef SHAREDCACHE_VM_H
#define SHAREDCACHE_VM_H

#include <binaryninjaapi.h>

#include <list>
#include <mutex>
#include <unordered_map>

void VMShutdown();

std::string ResolveFilePath(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView, const std::string& path);

template <typename T>
class SelfAllocatingWeakPtr {
public:
	SelfAllocatingWeakPtr(std::function<std::shared_ptr<T>()> allocator) : allocator(allocator) {}

	std::shared_ptr<T> lock() {
		std::shared_ptr<T> sharedPtr = weakPtr.lock();
		if (!sharedPtr) {
			sharedPtr = allocator();
			weakPtr = sharedPtr;
		}
		return sharedPtr;
	}

	std::shared_ptr<T> lock_no_allocate() {
		return weakPtr.lock();
	}

private:
	std::weak_ptr<T> weakPtr;                       // Weak reference to the object
	std::function<std::shared_ptr<T>()> allocator;	// Function to recreate the object
};


class MissingFileException : public std::exception
{
    virtual const char* what() const throw()
    {
        return "Missing File.";
    }
};

class MMappedFileAccessor;

class MMAP {
	friend MMappedFileAccessor;

    uint8_t *_mmap;
    FILE *fd;
    size_t len;

#ifdef _MSC_VER
	HANDLE hFile = INVALID_HANDLE_VALUE; // For Windows
#endif

	bool mapped = false;

    void Map();

    void Unmap();
};

class LazyMappedFileAccessor : public SelfAllocatingWeakPtr<MMappedFileAccessor> {
public:
	LazyMappedFileAccessor(
		std::string filePath, std::function<std::shared_ptr<MMappedFileAccessor>(const std::string&)> allocator) :
		SelfAllocatingWeakPtr([this, allocator = std::move(allocator)] { return allocator(m_filePath); }),
		m_filePath(std::move(filePath))
	{}
	~LazyMappedFileAccessor() = default;

	std::string_view filePath() const { return m_filePath; }

private:
	std::string m_filePath;
};

uint64_t MMapCount();

class MMappedFileAccessor {
    std::string m_path;
    MMAP m_mmap;
	bool m_slideInfoWasApplied = false;

public:
	MMappedFileAccessor(const std::string &path);
	~MMappedFileAccessor();

	static std::shared_ptr<LazyMappedFileAccessor> Open(const uint64_t sessionID, const std::string &path, std::function<void(std::shared_ptr<MMappedFileAccessor>)> postAllocationRoutine = nullptr);

	static void CloseAll(const uint64_t sessionID);

	static void InitialVMSetup();

	const std::string& Path() const { return m_path; };

	size_t Length() const { return m_mmap.len; };

    void *Data() const { return m_mmap._mmap; };

	bool SlideInfoWasApplied() const { return m_slideInfoWasApplied; }

	void SetSlideInfoWasApplied(bool slideInfoWasApplied) { m_slideInfoWasApplied = slideInfoWasApplied; }

	/**
	 * Writes to files are implemented for performance reasons and should be treated with utmost care
	 *
	 * They _MAY_ disappear as _soon_ as you release the lock on the this file.
	 * They may also NOT disappear for the lifetime of the application.
	 *
	 * The former is more likely to occur when concurrent DSC processing is happening. The latter is the typical scenario.
	 *
	 * This is used explicitly for slide information in a locked scope and _NOTHING_ else. It should probably not be used for anything else.
	 *
	 * \param address
	 * \param pointer
	 */
	void WritePointer(size_t address, size_t pointer);

    std::string ReadNullTermString(size_t address);

    uint8_t ReadUChar(size_t address);

    int8_t ReadChar(size_t address);

    uint16_t ReadUShort(size_t address);

    int16_t ReadShort(size_t address);

    uint32_t ReadUInt32(size_t address);

    int32_t ReadInt32(size_t address);

    uint64_t ReadULong(size_t address);

    int64_t ReadLong(size_t address);

    BinaryNinja::DataBuffer ReadBuffer(size_t addr, size_t length);

    // Returns a range of pointers within the mapped memory region corresponding to
    // {addr, length}.
    // WARNING: The pointers returned by this method is only valid for the lifetime
    // of this file accessor.
    // TODO: This should use std::span<const uint8_t> once the minimum supported
    // C++ version supports it.
    std::pair<const uint8_t*, const uint8_t*> ReadSpan(size_t addr, size_t length);

    void Read(void *dest, size_t addr, size_t length);

    template <typename T>
    T Read(size_t address);
};

class FileAccessorCache
{
public:
	static FileAccessorCache& Shared();

	std::shared_ptr<LazyMappedFileAccessor> OpenLazily(
		const uint64_t sessionID, const std::string& path,
		std::function<void(std::shared_ptr<MMappedFileAccessor>)> postAllocationRoutine);

	void SetCacheSize(uint64_t size);

private:
	FileAccessorCache();

	std::shared_ptr<MMappedFileAccessor> Open(
		const uint64_t sessionID, const std::string& path);

	void Close(MMappedFileAccessor* accessor);

	void RecordAccess(const std::string& path);
	void EvictFromCacheIfNeeded();

	std::mutex m_mutex;
	std::unordered_map<std::string, std::shared_ptr<LazyMappedFileAccessor>> m_lazyAccessors;

	// Ordered from least recently opened (front) to most recently opened (end).
	std::list<std::string> m_leastRecentlyOpened;
	std::unordered_map<std::string, std::pair<std::shared_ptr<MMappedFileAccessor>, std::list<std::string>::iterator>>
		m_accessors;

	uint64_t m_cacheSize = 8;
};

struct PageMapping {
    std::shared_ptr<LazyMappedFileAccessor> fileAccessor;
    size_t fileOffset;
    PageMapping(std::shared_ptr<LazyMappedFileAccessor> fileAccessor, size_t fileOffset)
        : fileAccessor(std::move(fileAccessor)), fileOffset(fileOffset) {}
};


class VMException : public std::exception {
    virtual const char *what() const throw() {
        return "Generic VM Exception";
    }
};

class MappingPageAlignmentException : public VMException {
    virtual const char *what() const throw() {
        return "Tried to create a mapping not aligned to given page size";
    }
};

class MappingReadException : VMException {
    virtual const char *what() const throw() {
        return "Tried to access unmapped page";
    }
};

class MappingCollisionException : VMException {
    virtual const char *what() const throw() {
        return "Tried to remap a page";
    }
};

class VMReader;

// Represents a range of addresses [start, end).
// Note that `end` is not included within the range.
struct AddressRange {
    uint64_t start;
    uint64_t end;

    bool operator<(const AddressRange& b) const {
        return start < b.start || (start == b.start && end < b.end);
    }

    friend bool operator<(const AddressRange& range, uint64_t address) {
        return range.end <= address;
    }

    friend bool operator<(uint64_t address, const AddressRange& range) {
        return address < range.start;
    }
};

// A map keyed by address ranges that can be looked up via any
// address within a range thanks to C++14's transparent comparators.
template <typename Value>
using AddressRangeMap = std::map<AddressRange, Value, std::less<>>;

class VM {
    // A map keyed by address ranges that can be looked up via any
    // address within a range thanks to C++14's transparent comparators.
    AddressRangeMap<PageMapping> m_map;
    size_t m_pageSize;
    bool m_safe;

    friend VMReader;

public:

    VM(size_t pageSize, bool safe = true);

    ~VM();

    void MapPages(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView, uint64_t sessionID, size_t vm_address, size_t fileoff, size_t size, const std::string& filePath, std::function<void(std::shared_ptr<MMappedFileAccessor>)> postAllocationRoutine);

    bool AddressIsMapped(uint64_t address);

    std::pair<PageMapping, size_t> MappingAtAddress(size_t address);

    std::string ReadNullTermString(size_t address);

    uint8_t ReadUChar(size_t address);

    int8_t ReadChar(size_t address);

    uint16_t ReadUShort(size_t address);

    int16_t ReadShort(size_t address);

    uint32_t ReadUInt32(size_t address);

    int32_t ReadInt32(size_t address);

    uint64_t ReadULong(size_t address);

    int64_t ReadLong(size_t address);

    BinaryNinja::DataBuffer ReadBuffer(size_t addr, size_t length);

    void Read(void *dest, size_t addr, size_t length);
};


class VMReader {
    std::shared_ptr<VM> m_vm;
    size_t m_cursor;
    size_t m_addressSize;

	BNEndianness m_endianness = LittleEndian;

public:
    VMReader(std::shared_ptr<VM> vm, size_t addressSize = 8);

	void SetEndianness(BNEndianness endianness) { m_endianness = endianness; }

	BNEndianness GetEndianness() const { return m_endianness; }

    void Seek(size_t address);

    void SeekRelative(size_t offset);

    [[nodiscard]] size_t GetOffset() const { return m_cursor; }

    std::string ReadCString(size_t address);

    uint64_t ReadULEB128(size_t cursorLimit);

    int64_t ReadSLEB128(size_t cursorLimit);

    uint8_t Read8();

    int8_t ReadS8();

    uint16_t Read16();

    int16_t ReadS16();

    uint32_t Read32();

    int32_t ReadS32();

    uint64_t Read64();

    int64_t ReadS64();

    size_t ReadPointer();

    uint8_t ReadUChar(size_t address);

    int8_t ReadChar(size_t address);

    uint16_t ReadUShort(size_t address);

    int16_t ReadShort(size_t address);

    uint32_t ReadUInt32(size_t address);

    int32_t ReadInt32(size_t address);

    uint64_t ReadULong(size_t address);

    int64_t ReadLong(size_t address);

    size_t ReadPointer(size_t address);

    BinaryNinja::DataBuffer ReadBuffer(size_t length);

    BinaryNinja::DataBuffer ReadBuffer(size_t addr, size_t length);

    void Read(void *dest, size_t length);

    void Read(void *dest, size_t addr, size_t length);
};

#endif //SHAREDCACHE_VM_H
