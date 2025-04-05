#pragma once

#include <shared_mutex>

#include "MappedFileAccessor.h"

typedef uint32_t CacheAccessorID;

// TODO: We might want to make this more than just the path, for example
// TODO: We might want to make it unique to a view session (session id).
// Get a unique entry id for the given file path.
CacheAccessorID GetCacheAccessorID(const std::string& filePath);

class WeakFileAccessor;

class FileAccessorCache
{
	size_t m_cacheSize;
	std::mutex m_mutex;
	// NOTE: If we end up wanting to handle 1000's of files we should consider std::list.
	std::deque<CacheAccessorID> m_cache;
	std::unordered_map<CacheAccessorID, std::shared_ptr<MappedFileAccessor>> m_accessors;

	explicit FileAccessorCache(size_t cacheSize = 8);

	void EvictLastUsed();

public:
	static FileAccessorCache& Global();

	// Get a weak reference to a file accessor, the reference at this point is alive.
	// The reference is always alive at this point either because it is in the cache or it has been inserted in.
	// Subsequent calls to this might kill the backing file accessor resulting in the weak ref recreating the file
	// accessor and inserting itself back into its related cache.
	WeakFileAccessor Open(const std::string& filePath);

	// Adjust the cache size limit.
	// This will NOT evict current cache entries, as they are already available.
	// Any subsequent call to `Open` will assume this cache size, evicting until the size is equal to the cache size.
	void SetCacheSize(uint64_t size) { m_cacheSize = size; };
};

// Write log to be used in conjunction with `WeakFileAccessor` to re-apply written data to a "revived" file.
struct FileAccessorWriteLog
{
	// To persist writes to a file accessor being revived (within the lock() function)
	// we keep a list of writes that will be re-applied in the lock function.
	std::shared_mutex m_persistedMutex;
	std::vector<std::pair<size_t, uint64_t>> m_persistedPointers;

	FileAccessorWriteLog() = default;

	// Add the pointer to the persisted pointers.
	void AddPointer(size_t address, size_t pointer);

	// Apply all logged writes to the given accessor.
	void ApplyWrites(MappedFileAccessor& accessor);
};

class WeakFileAccessor
{
	// Weak pointer to the mapped file accessor, once this is expired we will re-open.
	std::weak_ptr<MappedFileAccessor> m_weakPtr;
	// File path for re-opening if needed
	std::string m_filePath;

	// Used to re-add writes once the file accessor is "revived".
	std::shared_ptr<FileAccessorWriteLog> m_writeLog;

	// TODO: Store a weak_ptr/shared_ptr to FileAccessorCache? That way we dont access Global()
	// TODO: Only need to do the above if we want multiple caches.

public:
	explicit WeakFileAccessor(std::weak_ptr<MappedFileAccessor> weakPtr, std::string filePath) :
		m_weakPtr(std::move(weakPtr)), m_filePath(std::move(filePath)),
		m_writeLog(std::make_shared<FileAccessorWriteLog>())
	{}

	std::shared_ptr<MappedFileAccessor> lock();

	// Persists the written pointer within this weak file accessor.
	// This works as we expect the weak file accessor to be stored per virtual memory region.
	void WritePointer(size_t address, size_t pointer);
};
