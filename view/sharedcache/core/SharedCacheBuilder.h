#pragma once

#include "binaryninjaapi.h"
#include "SharedCache.h"

// This constructs a Cache, give it a file path, and it will add all relevant cache entries.
class SharedCacheBuilder
{
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;

	// When we call `AddFile` it will start populating this caches entries.
	// This cache is what is returned via `Finalize`.
	SharedCache m_cache;

	// List of already processedFiles so we skip adding them again.
	std::set<std::string> m_processedFiles;
	// The base file name (i.e. "dyld_shared_cache_arm64e"), this is used to filter out non-relevant files.
	std::string m_primaryFileName;

public:
	explicit SharedCacheBuilder(BinaryNinja::Ref<BinaryNinja::BinaryView> view);

	SharedCache& GetCache() { return m_cache; };
	std::set<std::string> GetProcessedFiles() { return m_processedFiles; };
	std::string GetPrimaryFileName() { return m_primaryFileName; };

	// Set the base file name used when filtering in `AddFile`.
	void SetPrimaryFileName(const std::string& baseFileName) { m_primaryFileName = baseFileName; };

	// Returns a shared cache that is ready for processing, this should include all the required shared cache entries.
	SharedCache Finalize();

	// Tries to add the file to the shared cache, if the file has already been processed or is not valid
	// then false will be returned, true if the file was added to the shared cache. A file can only be added once.
	bool AddFile(
		const std::string& filePath, const std::string& fileName, CacheEntryType cacheType = CacheEntryType::Secondary);

	// Process a directory on the file system.
	size_t AddDirectory(const std::string& directoryPath);

	// Process a directory in a project.
	size_t AddProjectFolder(BinaryNinja::Ref<BinaryNinja::ProjectFolder> folder);
};
