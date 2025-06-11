//
// Created by kat on 5/23/23.
//

#ifndef SHAREDCACHE_DSCVIEW_H
#define SHAREDCACHE_DSCVIEW_H

#include <binaryninjaapi.h>

static const char* VIEW_METADATA_KEY = "shared_cache_view";

class SharedCacheView : public BinaryNinja::BinaryView
{
	bool m_parseOnly;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;

	// Restored primary file name from metadata, or the file name on first open.
	std::string m_primaryFileName;

	// Restored associated file names from metadata, this is all the associated cache entries.
	// NOTE: Currently this is just used to alert the user to supposed missing files.
	std::set<std::string> m_secondaryFileNames;

public:
	SharedCacheView(const std::string& typeName, BinaryView* data, bool parseOnly = false);

	~SharedCacheView() override = default;

	bool Init() override;

	// Initialized the shared cache controller for this view. This is what allows us to load images and regions.
	bool InitController();

	void SetPrimaryFileName(std::string primaryFileName);

	// Logs the secondary file name to `m_secondaryFileNames`, see the note on the field about usage.
	void LogSecondaryFileName(std::string associatedFileName);

	// Get the path to the primary file.
	std::optional<std::string> GetPrimaryFilePath();

	// Get the metadata for saving the state of the shared cache.
	BinaryNinja::Ref<BinaryNinja::Metadata> GetMetadata() const;

	void LoadMetadata(const BinaryNinja::Metadata& metadata);

	virtual bool PerformIsExecutable() const override { return true; }
};


class SharedCacheViewType : public BinaryNinja::BinaryViewType
{
public:
	SharedCacheViewType();

	static void Register();

	BinaryNinja::Ref<BinaryNinja::BinaryView> Create(BinaryNinja::BinaryView* data) override;

	BinaryNinja::Ref<BinaryNinja::BinaryView> Parse(BinaryNinja::BinaryView* data) override;

	bool IsTypeValidForData(BinaryNinja::BinaryView* data) override;

	bool IsDeprecated() override { return false; }

	BinaryNinja::Ref<BinaryNinja::Settings> GetLoadSettingsForData(BinaryNinja::BinaryView* data) override;
};


#endif  // SHAREDCACHE_DSCVIEW_H
