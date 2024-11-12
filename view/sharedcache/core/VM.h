//
// Created by kat on 5/23/23.
//

#ifndef SHAREDCACHE_VM_H
#define SHAREDCACHE_VM_H
#include <binaryninjaapi.h>
#include <condition_variable>

void VMShutdown();

std::string ResolveFilePath(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView, const std::string& path);

class counting_semaphore {
public:
	explicit counting_semaphore(int count = 0) : count_(count) {}

	void release(int update = 1) {
		std::unique_lock<std::mutex> lock(mutex_);
		count_ += update;
		cv_.notify_all();
	}

	void acquire() {
		std::unique_lock<std::mutex> lock(mutex_);
		cv_.wait(lock, [this]() { return count_ > 0; });
		--count_;
	}

	bool try_acquire() {
		std::unique_lock<std::mutex> lock(mutex_);
		if (count_ > 0) {
			--count_;
			return true;
		}
		return false;
	}

	void set_count(int new_count) {
		std::unique_lock<std::mutex> lock(mutex_);
		count_ = new_count;
		cv_.notify_all();
	}

private:
	std::mutex mutex_;
	std::condition_variable cv_;
	int count_;
};


template <typename T>
class SelfAllocatingWeakPtr {
public:
	SelfAllocatingWeakPtr(std::function<std::shared_ptr<T>()> allocator, std::function<void(std::shared_ptr<T>)> postAlloc)
		: allocator(allocator), postAlloc(postAlloc) {}

	std::shared_ptr<T> lock() {
		std::shared_ptr<T> sharedPtr = weakPtr.lock();
		if (!sharedPtr) {
			sharedPtr = allocator();
			postAlloc(sharedPtr);
			weakPtr = sharedPtr;
		}
		return sharedPtr;
	}

	std::shared_ptr<T> lock_no_allocate() {
		return weakPtr.lock();
	}

private:
	std::weak_ptr<T> weakPtr;                       // Weak reference to the object
	std::function<std::shared_ptr<T>()> allocator;  // Function to recreate the object
	std::function<void(std::shared_ptr<T>)> postAlloc;  // Function to call after the object is allocated
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

    void *_mmap;
    FILE *fd;
    size_t len;

#ifdef _MSC_VER
	HANDLE hFile = INVALID_HANDLE_VALUE; // For Windows
#endif

	bool mapped = false;

    void Map();

    void Unmap();
};

static uint64_t maxFPLimit;
static std::mutex fileAccessorDequeMutex;
static std::unordered_map<uint64_t, std::deque<std::shared_ptr<MMappedFileAccessor>>> fileAccessorReferenceHolder;
static std::set<uint64_t> blockedSessionIDs;
static std::mutex fileAccessorsMutex;
static std::unordered_map<std::string, std::shared_ptr<SelfAllocatingWeakPtr<MMappedFileAccessor>>> fileAccessors;
static counting_semaphore fileAccessorSemaphore(0);

static std::atomic<uint64_t> mmapCount = 0;

class MMappedFileAccessor {
    std::string m_path;
    MMAP m_mmap;
	bool m_slideInfoWasApplied = false;

public:
	MMappedFileAccessor(const std::string &path);
	~MMappedFileAccessor();

	static std::shared_ptr<SelfAllocatingWeakPtr<MMappedFileAccessor>> Open(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView, const uint64_t sessionID, const std::string &path, std::function<void(std::shared_ptr<MMappedFileAccessor>)> postAllocationRoutine = nullptr);

	static void CloseAll(const uint64_t sessionID);

	static void InitialVMSetup();

    std::string Path() const { return m_path; };

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

    void Read(void *dest, size_t addr, size_t length);
};


struct PageMapping {
    std::string filePath;
	std::shared_ptr<SelfAllocatingWeakPtr<MMappedFileAccessor>> fileAccessor;
    size_t fileOffset;
	PageMapping(std::string filePath, std::shared_ptr<SelfAllocatingWeakPtr<MMappedFileAccessor>> fileAccessor, size_t fileOffset)
		: filePath(filePath), fileAccessor(fileAccessor), fileOffset(fileOffset) {}
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


class VM {
    std::map<size_t, PageMapping> m_map;
    size_t m_pageSize;
    size_t m_pageSizeBits;
    bool m_safe;

    friend VMReader;

public:

    VM(size_t pageSize, bool safe = true);

    ~VM();

    void MapPages(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView, uint64_t sessionID, size_t vm_address, size_t fileoff, size_t size, std::string filePath, std::function<void(std::shared_ptr<MMappedFileAccessor>)> postAllocationRoutine);

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
