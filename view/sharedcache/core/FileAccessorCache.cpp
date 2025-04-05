#include "FileAccessorCache.h"

#include <cassert>

CacheAccessorID GetCacheAccessorID(const std::string& filePath)
{
	constexpr std::hash<std::string> hasher;
	return static_cast<CacheAccessorID>(hasher(filePath));
}

FileAccessorCache::FileAccessorCache(size_t cacheSize)
{
	m_cacheSize = cacheSize;
	m_accessors = {};
}

void FileAccessorCache::EvictLastUsed()
{
	if (m_cache.empty())
		return;
	// Evict the least recently used element.
	const auto lruID = m_cache.front();
	m_cache.pop_front();
	// Ensure the least recently used ID actually exists in the accessors map.
	assert(m_accessors.find(lruID) != m_accessors.end() && "Evicting non-existent ID from accessors map");
	m_accessors.erase(lruID);
}

FileAccessorCache& FileAccessorCache::Global()
{
	static FileAccessorCache cache {};
	return cache;
}


WeakFileAccessor FileAccessorCache::Open(const std::string& filePath)
{
	const auto id = GetCacheAccessorID(filePath);
	std::unique_lock lock(m_mutex);

	// Check if the file is already in the cache.
	if (const auto it = m_accessors.find(id); it != m_accessors.end())
	{
		// Move the accessed ID to the back so we keep it in the cache.
		auto pos = std::find(m_cache.begin(), m_cache.end(), id);
		if (pos != m_cache.end())
			m_cache.erase(pos);
		m_cache.push_back(id);

		return WeakFileAccessor(it->second, filePath);
	}

	// Evict if we are going to go above the limit.
	if (m_cache.size() >= m_cacheSize)
		EvictLastUsed();

	// Create a new file accessor and add it to the cache.
	auto accessor = MappedFileAccessor::Open(filePath);
	if (accessor == nullptr)
	{
		// We failed to open the file, we must throw hard!
		// TODO: Make this mechanism more thought out...
		throw std::runtime_error("Failed to open file: " + filePath);
	}
	auto sharedAccessor = std::make_shared<MappedFileAccessor>(std::move(*accessor));
	m_accessors.insert_or_assign(id, sharedAccessor);
	m_cache.push_back(id);

	return WeakFileAccessor(sharedAccessor, filePath);
}

void FileAccessorWriteLog::AddPointer(const size_t address, const size_t pointer)
{
	// TODO: A sharded map here would be better. see: rust dashmap
	std::unique_lock<std::shared_mutex> lock(m_persistedMutex);
	m_persistedPointers.emplace_back(address, pointer);
}

void FileAccessorWriteLog::ApplyWrites(MappedFileAccessor& accessor)
{
	std::shared_lock<std::shared_mutex> lock(m_persistedMutex);
	for (const auto& [address, pointer] : m_persistedPointers)
		accessor.WritePointer(address, pointer);
}

std::shared_ptr<MappedFileAccessor> WeakFileAccessor::lock()
{
	auto sharedPtr = m_weakPtr.lock();
	if (!sharedPtr)
	{
		// This will revive other weak pointers to the same shared ptr.
		// Update the weak pointer to the newly created shared instance
		m_weakPtr = FileAccessorCache::Global().Open(m_filePath).m_weakPtr;
		sharedPtr = m_weakPtr.lock();

		// Apply any previously written pointers back.
		if (sharedPtr)
			m_writeLog->ApplyWrites(*sharedPtr);
	}

	return sharedPtr;
}

void WeakFileAccessor::WritePointer(const size_t address, const size_t pointer)
{
	// Persist the pointer after the file accessor is revived.
	m_writeLog->AddPointer(address, pointer);

	// And then actually apply the written pointer...
	if (auto sharedPtr = m_weakPtr.lock())
		sharedPtr->WritePointer(address, pointer);
}
