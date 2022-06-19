#pragma once
#include "core/binaryninja_defs.h"
#include "core/database.h"

extern "C" {
	struct BNSaveSettings;
	struct BNBinaryView;
	struct BNSaveSettings;
	struct BNFileMetadata;
	struct BNKeyValueStore;
	struct BNDatabase;

	enum BNSaveOption
	{
		RemoveUndoData,
		TrimSnapshots,
	};

	struct BNNavigationHandler
	{
		void* context;
		char* (*getCurrentView)(void* ctxt);
		uint64_t (*getCurrentOffset)(void* ctxt);
		bool (*navigate)(void* ctxt, const char* view, uint64_t offset);
	};

	struct BNUser;
	struct BNUndoEntry
	{
		BNUser* user;
		char* hash;
		BNUndoAction* actions;
		uint64_t actionCount;
		uint64_t timestamp;
	};

	// File metadata object
	BINARYNINJACOREAPI BNFileMetadata* BNCreateFileMetadata(void);
	BINARYNINJACOREAPI BNFileMetadata* BNNewFileReference(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNFreeFileMetadata(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNCloseFile(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNSetFileMetadataNavigationHandler(BNFileMetadata* file, BNNavigationHandler* handler);
	BINARYNINJACOREAPI bool BNIsFileModified(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNIsAnalysisChanged(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNMarkFileModified(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNMarkFileSaved(BNFileMetadata* file);

	BINARYNINJACOREAPI bool BNIsBackedByDatabase(BNFileMetadata* file, const char* binaryViewType);

	BINARYNINJACOREAPI bool BNCreateDatabase(BNBinaryView* data, const char* path, BNSaveSettings* settings);
	BINARYNINJACOREAPI bool BNCreateDatabaseWithProgress(BNBinaryView* data, const char* path, void* ctxt,
		bool (*progress)(void* ctxt, size_t progress, size_t total), BNSaveSettings* settings);
	BINARYNINJACOREAPI BNBinaryView* BNOpenExistingDatabase(BNFileMetadata* file, const char* path);
	BINARYNINJACOREAPI BNBinaryView* BNOpenExistingDatabaseWithProgress(BNFileMetadata* file, const char* path,
		void* ctxt, bool (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI BNBinaryView* BNOpenDatabaseForConfiguration(BNFileMetadata* file, const char* path);
	BINARYNINJACOREAPI bool BNSaveAutoSnapshot(BNBinaryView* data, BNSaveSettings* settings);
	BINARYNINJACOREAPI bool BNSaveAutoSnapshotWithProgress(BNBinaryView* data, void* ctxt,
		bool (*progress)(void* ctxt, size_t progress, size_t total), BNSaveSettings* settings);
	BINARYNINJACOREAPI void BNGetSnapshotData(BNFileMetadata* file, BNKeyValueStore* data, BNKeyValueStore* cache,
		void* ctxt, bool (*progress)(void* ctxt, size_t current, size_t total));
	BINARYNINJACOREAPI void BNApplySnapshotData(BNFileMetadata* file, BNBinaryView* view, BNKeyValueStore* data,
		BNKeyValueStore* cache, void* ctxt, bool (*progress)(void* ctxt, size_t current, size_t total),
		bool openForConfiguration, bool restoreRawView);
	BINARYNINJACOREAPI BNDatabase* BNGetFileMetadataDatabase(BNFileMetadata* file);


	BINARYNINJACOREAPI bool BNOpenProject(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNCloseProject(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNIsProjectOpen(BNFileMetadata* file);

	BINARYNINJACOREAPI char* BNGetCurrentView(BNFileMetadata* file);
	BINARYNINJACOREAPI uint64_t BNGetCurrentOffset(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNNavigate(BNFileMetadata* file, const char* view, uint64_t offset);

	BINARYNINJACOREAPI BNBinaryView* BNGetFileViewOfType(BNFileMetadata* file, const char* name);

	BINARYNINJACOREAPI char** BNGetExistingViews(BNFileMetadata* file, size_t* count);
	BINARYNINJACOREAPI size_t BNFileMetadataGetSessionId(BNFileMetadata* file);

	BINARYNINJACOREAPI bool BNIsSnapshotDataAppliedWithoutError(BNFileMetadata* view);

	// Save settings
	BINARYNINJACOREAPI BNSaveSettings* BNCreateSaveSettings(void);
	BINARYNINJACOREAPI BNSaveSettings* BNNewSaveSettingsReference(BNSaveSettings* settings);
	BINARYNINJACOREAPI void BNFreeSaveSettings(BNSaveSettings* settings);

	BINARYNINJACOREAPI bool BNIsSaveSettingsOptionSet(BNSaveSettings* settings, BNSaveOption option);
	BINARYNINJACOREAPI void BNSetSaveSettingsOption(BNSaveSettings* settings, BNSaveOption option, bool state);

	BINARYNINJACOREAPI BNMergeResult BNMergeUserAnalysis(BNFileMetadata* file, const char* name, void* ctxt,
	    bool (*progress)(void* ctxt, size_t progress, size_t total), char** excludedHashes, size_t excludedHashesCount);

	BINARYNINJACOREAPI char* BNGetOriginalFilename(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNSetOriginalFilename(BNFileMetadata* file, const char* name);

	BINARYNINJACOREAPI char* BNGetFilename(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNSetFilename(BNFileMetadata* file, const char* name);

	BINARYNINJACOREAPI void BNBeginUndoActions(BNFileMetadata* file);
	BINARYNINJACOREAPI void BNCommitUndoActions(BNFileMetadata* file);

	BINARYNINJACOREAPI bool BNUndo(BNFileMetadata* file);
	BINARYNINJACOREAPI bool BNRedo(BNFileMetadata* file);

	BINARYNINJACOREAPI BNUndoEntry* BNGetUndoEntries(BNFileMetadata* file, size_t* count);
	BINARYNINJACOREAPI void BNFreeUndoEntries(BNUndoEntry* entries, size_t count);
	BINARYNINJACOREAPI void BNClearUndoEntries(BNFileMetadata* file);

	BINARYNINJACOREAPI bool BNRebase(BNBinaryView* data, uint64_t address);
	BINARYNINJACOREAPI bool BNRebaseWithProgress(
	    BNBinaryView* data, uint64_t address, void* ctxt, bool (*progress)(void* ctxt, size_t progress, size_t total));
	BINARYNINJACOREAPI bool BNCreateSnapshotedView(BNBinaryView* data, const char* viewName);
	BINARYNINJACOREAPI bool BNCreateSnapshotedViewWithProgress(BNBinaryView* data, const char* viewName, void* ctxt,
															   bool (*progress)(void* ctxt, size_t progress, size_t total));

}