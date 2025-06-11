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

	void RemoveAccessor(CacheAccessorID id);

	// Adjust the cache size limit.
	// This will NOT evict current cache entries, as they are already available.
	// Any subsequent call to `Open` will assume this cache size, evicting until the size is equal to the cache size.
	void SetCacheSize(const uint64_t size) { m_cacheSize = size; };

	size_t GetCacheSize() const { return m_cacheSize; }

	size_t GetCacheCount() const { return m_accessors.size(); }
};

class WeakFileAccessor
{
	using ReviveCallback = std::function<void(MappedFileAccessor&)>;

	// Weak pointer to the mapped file accessor, once this is expired we will re-open.
	std::weak_ptr<MappedFileAccessor> m_weakPtr;
	// File path for re-opening if needed
	std::string m_filePath;

	// Used to re-add writes once the file accessor is "revived".
	std::optional<ReviveCallback> m_reviveCallback;

	// TODO: Store a weak_ptr/shared_ptr to FileAccessorCache? That way we dont access Global()
	// TODO: Only need to do the above if we want multiple caches.

public:
	explicit WeakFileAccessor(std::weak_ptr<MappedFileAccessor> weakPtr, std::string filePath) :
		m_weakPtr(std::move(weakPtr)), m_filePath(std::move(filePath))
	{}

	// Register the function to be called once the file accessor is revived, this is typically
	// used to re-apply writes such as from slide info.
	void RegisterReviveCallback(const ReviveCallback& callback) {
		m_reviveCallback = callback;
	}

	std::shared_ptr<MappedFileAccessor> lock();
};
