#pragma once
#include <string>
#include "binaryninjacore/filemetadata.h"

#include "refcount.hpp"
#include "navigationhandler.hpp"

namespace BinaryNinja {
	class BinaryView;
	class SaveSettings;
	class KeyValueStore;
	class Database;
	class MergeResult;
	class User;
	class UndoEntry;

	class NavigationHandler
	{
	  private:
		BNNavigationHandler m_callbacks;

		static char* GetCurrentViewCallback(void* ctxt);
		static uint64_t GetCurrentOffsetCallback(void* ctxt);
		static bool NavigateCallback(void* ctxt, const char* view, uint64_t offset);

	  public:
		NavigationHandler();
		virtual ~NavigationHandler() {}

		BNNavigationHandler* GetCallbacks() { return &m_callbacks; }

		virtual std::string GetCurrentView() = 0;
		virtual uint64_t GetCurrentOffset() = 0;
		virtual bool Navigate(const std::string& view, uint64_t offset) = 0;
	};

	class FileMetadata : public CoreRefCountObject<BNFileMetadata, BNNewFileReference, BNFreeFileMetadata>
	{
	  public:
		FileMetadata();
		FileMetadata(const std::string& filename);
		FileMetadata(BNFileMetadata* file);

		void Close();

		void SetNavigationHandler(NavigationHandler* handler);

		std::string GetOriginalFilename() const;
		void SetOriginalFilename(const std::string& name);

		std::string GetFilename() const;
		void SetFilename(const std::string& name);

		bool IsModified() const;
		bool IsAnalysisChanged() const;
		void MarkFileModified();
		void MarkFileSaved();

		bool IsSnapshotDataAppliedWithoutError() const;

		bool IsBackedByDatabase(const std::string& binaryViewType = "") const;
		bool CreateDatabase(const std::string& name, BinaryView* data, Ref<SaveSettings> settings);
		bool CreateDatabase(const std::string& name, BinaryView* data,
			const std::function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings);
		Ref<BinaryView> OpenExistingDatabase(const std::string& path);
		Ref<BinaryView> OpenExistingDatabase(
			const std::string& path, const std::function<bool(size_t progress, size_t total)>& progressCallback);
		Ref<BinaryView> OpenDatabaseForConfiguration(const std::string& path);
		bool SaveAutoSnapshot(BinaryView* data, Ref<SaveSettings> settings);
		bool SaveAutoSnapshot(BinaryView* data,
			const std::function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings);
		void GetSnapshotData(
			Ref<KeyValueStore> data, Ref<KeyValueStore> cache, const std::function<bool(size_t, size_t)>& progress);
		void ApplySnapshotData(BinaryView* file, Ref<KeyValueStore> data, Ref<KeyValueStore> cache,
			const std::function<bool(size_t, size_t)>& progress, bool openForConfiguration = false,
			bool restoreRawView = true);
		Ref<Database> GetDatabase();

		bool Rebase(BinaryView* data, uint64_t address);
		bool Rebase(BinaryView* data, uint64_t address,
			const std::function<bool(size_t progress, size_t total)>& progressCallback);
		bool CreateSnapshotedView(BinaryView* data, const std::string& viewName);
		bool CreateSnapshotedView(BinaryView* data, const std::string& viewName,
								  const std::function<bool(size_t progress, size_t total)>& progressCallback);

		MergeResult MergeUserAnalysis(const std::string& name, const std::function<bool(size_t, size_t)>& progress,
			const std::vector<std::string> excludedHashes = {});

		void BeginUndoActions();
		void CommitUndoActions();

		bool Undo();
		bool Redo();

		std::vector<Ref<User>> GetUsers();
		std::vector<UndoEntry> GetUndoEntries();
		void ClearUndoEntries();

		bool OpenProject();
		void CloseProject();
		bool IsProjectOpen();

		std::string GetCurrentView();
		uint64_t GetCurrentOffset();
		bool Navigate(const std::string& view, uint64_t offset);

		BinaryNinja::Ref<BinaryNinja::BinaryView> GetViewOfType(const std::string& name);
		std::vector<std::string> GetExistingViews() const;
		size_t GetSessionId() const;
	};

	class SaveSettings : public CoreRefCountObject<BNSaveSettings, BNNewSaveSettingsReference, BNFreeSaveSettings>
	{
	  public:
		SaveSettings();
		SaveSettings(BNSaveSettings* settings);

		bool IsOptionSet(BNSaveOption option) const;
		void SetOption(BNSaveOption option, bool state = true);
	};
}