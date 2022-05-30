#pragma once

extern "C" {
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

}