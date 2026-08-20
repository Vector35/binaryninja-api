#include <filesystem>
#include "SharedCacheBuilder.h"

using namespace BinaryNinja;

SharedCacheBuilder::SharedCacheBuilder(Ref<BinaryView> view)
{
	m_view = std::move(view);
	m_logger = new Logger("SharedCache.Builder", m_view->GetFile()->GetSessionId());
	m_primaryFileName = BaseFileName(m_view->GetFile()->GetOriginalFilename());
	m_cache = SharedCache(m_view->GetAddressSize());
	m_processedFiles = {};
}

SharedCache SharedCacheBuilder::Finalize()
{
	// Reset the state to the builder to reuse.
	m_processedFiles = {};
	return std::move(m_cache);
}

bool SharedCacheBuilder::AddFile(
	const std::string& filePath, const std::string& fileName, const CacheEntryType cacheType)
{
	// Skip already processed files.
	if (auto [_, inserted] = m_processedFiles.insert(filePath); !inserted)
		return false;
	// We only want to process files containing the base file name.
	if (fileName.find(m_primaryFileName) == std::string::npos)
		return false;
	// Skip map files, they contain some nice information... we don't use.
	if (fileName.find(".map") != std::string::npos)
		return false;
	// Skip atlas files, they contain some nice information... we don't use.
	if (fileName.find(".atlas") != std::string::npos)
		return false;
	// Skip bndb files!
	if (fileName.find(".bndb") != std::string::npos)
		return false;
	// Skip a2s files
	if (fileName.find(".a2s") != std::string::npos)
		return false;

	try
	{
		m_cache.AddEntry(CacheEntry::FromFile(filePath, fileName, cacheType));
	}
	catch (const std::exception& e)
	{
		// Just return false so the view init can continue.
		m_logger->LogErrorForExceptionF(e, "Failed to add file '{}': {}", fileName, e.what());
		return false;
	}

	return true;
}

size_t SharedCacheBuilder::AddDirectory(const std::string& directoryPath)
{
	// Filters then attempts to process a single directory entry as a shared cache file.
	auto processDirEntry = [&](const std::filesystem::directory_entry& entry) {
		const auto currentFilePath = entry.path().string();
		const auto currentFileName = BaseFileName(currentFilePath);

		// Skip non-files.
		if (!entry.is_regular_file())
			return false;

		// Ok, we are now _sure_ that this file _might_ be a part of the cache, lets try and process it!
		return AddFile(currentFilePath, currentFileName, CacheEntryType::Secondary);
	};

	// TODO: This is ugly.
	size_t added = 0;
	// Locate all possible related entry files and add them to the cache.
	for (const auto& entry : std::filesystem::directory_iterator(directoryPath))
		if (processDirEntry(entry))
			added++;
	return added;
}

size_t SharedCacheBuilder::AddProjectFolder(Ref<ProjectFolder> folder)
{
	auto processProjectFile = [&](const ProjectFile& file) {
		const auto currentFilePath = file.GetPathOnDisk();
		const auto currentFileName = file.GetName();

		// Skip files not in the folder.
		if (!IsSameFolder(file.GetFolder(), folder))
			return false;

		// Ok, we are now _sure_ that this file _might_ be a part of the cache, lets try and process it!
		return AddFile(currentFilePath, currentFileName, CacheEntryType::Secondary);
	};

	auto viewProjectFile = m_view->GetFile()->GetProjectFile();
	if (!viewProjectFile)
		return 0;

	auto project = viewProjectFile->GetProject();
	size_t added = 0;
	for (const auto& projectFile : project->GetFiles())
		if (processProjectFile(*projectFile))
			added++;
	return added;
}
