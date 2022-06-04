#pragma once

#include "binaryninja_defs.h"

extern "C" {
	struct BNDataBuffer;
	struct BNKeyValueStore;
	struct BNDatabase;
	struct BNSnapshot;
	struct BNBinaryView;
	struct BNFileMetadata;
	struct BNUser;
	struct BNUndoEntry;
	struct BNInstructionTextToken;

	enum BNActionType
	{
		TemporaryAction = 0,
		DataModificationAction = 1,
		AnalysisAction = 2,
		DataModificationAndAnalysisAction = 3
	};

	struct BNUndoAction
	{
		BNActionType actionType;
		char* summaryText;
		BNInstructionTextToken* summaryTokens;
		size_t summaryTokenCount;
	};

	enum BNMergeStatus
	{
		NOT_APPLICABLE = 0,
		OK = 1,
		CONFLICT = 2
	};

	struct BNMergeResult
	{
		BNMergeStatus status;
		BNUndoAction action;
		const char* hash;
	};

	// Key value store
	BINARYNINJACOREAPI BNKeyValueStore* BNCreateKeyValueStore(void);
	BINARYNINJACOREAPI BNKeyValueStore* BNCreateKeyValueStoreFromDataBuffer(BNDataBuffer* buffer);
	BINARYNINJACOREAPI BNKeyValueStore* BNNewKeyValueStoreReference(BNKeyValueStore* store);
	BINARYNINJACOREAPI void BNFreeKeyValueStore(BNKeyValueStore* store);

	BINARYNINJACOREAPI char** BNGetKeyValueStoreKeys(BNKeyValueStore* store, size_t* count);
	BINARYNINJACOREAPI bool BNKeyValueStoreHasValue(BNKeyValueStore* store, const char* name);
	BINARYNINJACOREAPI char* BNGetKeyValueStoreValue(BNKeyValueStore* store, const char* name);
	BINARYNINJACOREAPI BNDataBuffer* BNGetKeyValueStoreBuffer(BNKeyValueStore* store, const char* name);
	BINARYNINJACOREAPI bool BNSetKeyValueStoreValue(BNKeyValueStore* store, const char* name, const char* value);
	BINARYNINJACOREAPI bool BNSetKeyValueStoreBuffer(
		BNKeyValueStore* store, const char* name, const BNDataBuffer* value);
	BINARYNINJACOREAPI BNDataBuffer* BNGetKeyValueStoreSerializedData(BNKeyValueStore* store);
	BINARYNINJACOREAPI void BNBeginKeyValueStoreNamespace(BNKeyValueStore* store, const char* name);
	BINARYNINJACOREAPI void BNEndKeyValueStoreNamespace(BNKeyValueStore* store);
	BINARYNINJACOREAPI bool BNIsKeyValueStoreEmpty(BNKeyValueStore* store);
	BINARYNINJACOREAPI size_t BNGetKeyValueStoreValueSize(BNKeyValueStore* store);
	BINARYNINJACOREAPI size_t BNGetKeyValueStoreDataSize(BNKeyValueStore* store);
	BINARYNINJACOREAPI size_t BNGetKeyValueStoreValueStorageSize(BNKeyValueStore* store);
	BINARYNINJACOREAPI size_t BNGetKeyValueStoreNamespaceSize(BNKeyValueStore* store);

	// Database object
	BINARYNINJACOREAPI BNDatabase* BNNewDatabaseReference(BNDatabase* database);
	BINARYNINJACOREAPI void BNFreeDatabase(BNDatabase* database);
	BINARYNINJACOREAPI void BNSetDatabaseCurrentSnapshot(BNDatabase* database, int64_t id);
	BINARYNINJACOREAPI BNSnapshot* BNGetDatabaseCurrentSnapshot(BNDatabase* database);
	BINARYNINJACOREAPI BNSnapshot** BNGetDatabaseSnapshots(BNDatabase* database, size_t* count);
	BINARYNINJACOREAPI BNSnapshot* BNGetDatabaseSnapshot(BNDatabase* database, int64_t id);
	BINARYNINJACOREAPI int64_t BNWriteDatabaseSnapshotData(BNDatabase* database, int64_t* parents, size_t parentCount,
		BNBinaryView* file, const char* name, BNKeyValueStore* data, bool autoSave, void* ctxt,
		bool (*progress)(void*, size_t, size_t));
	BINARYNINJACOREAPI bool BNTrimDatabaseSnapshot(BNDatabase* database, int64_t id);
	BINARYNINJACOREAPI bool BNRemoveDatabaseSnapshot(BNDatabase* database, int64_t id);
	BINARYNINJACOREAPI char** BNGetDatabaseGlobalKeys(BNDatabase* database, size_t* count);
	BINARYNINJACOREAPI int BNDatabaseHasGlobal(BNDatabase* database, const char* key);
	BINARYNINJACOREAPI char* BNReadDatabaseGlobal(BNDatabase* database, const char* key);
	BINARYNINJACOREAPI bool BNWriteDatabaseGlobal(BNDatabase* database, const char* key, const char* val);
	BINARYNINJACOREAPI BNDataBuffer* BNReadDatabaseGlobalData(BNDatabase* database, const char* key);
	BINARYNINJACOREAPI bool BNWriteDatabaseGlobalData(BNDatabase* database, const char* key, BNDataBuffer* val);
	BINARYNINJACOREAPI BNFileMetadata* BNGetDatabaseFile(BNDatabase* database);
	BINARYNINJACOREAPI BNKeyValueStore* BNReadDatabaseAnalysisCache(BNDatabase* database);
	BINARYNINJACOREAPI bool BNWriteDatabaseAnalysisCache(BNDatabase* database, BNKeyValueStore* val);

	// Database snapshots
	BINARYNINJACOREAPI BNSnapshot* BNNewSnapshotReference(BNSnapshot* snapshot);
	BINARYNINJACOREAPI void BNFreeSnapshot(BNSnapshot* snapshot);
	BINARYNINJACOREAPI void BNFreeSnapshotList(BNSnapshot** snapshots, size_t count);
	BINARYNINJACOREAPI BNDatabase* BNGetSnapshotDatabase(BNSnapshot* snapshot);
	BINARYNINJACOREAPI int64_t BNGetSnapshotId(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNSnapshot* BNGetSnapshotFirstParent(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNSnapshot** BNGetSnapshotParents(BNSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI BNSnapshot** BNGetSnapshotChildren(BNSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI char* BNGetSnapshotName(BNSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNIsSnapshotAutoSave(BNSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNSnapshotHasContents(BNSnapshot* snapshot);
	BINARYNINJACOREAPI bool BNSnapshotHasUndo(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNDataBuffer* BNGetSnapshotFileContents(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNDataBuffer* BNGetSnapshotFileContentsHash(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNKeyValueStore* BNReadSnapshotData(BNSnapshot* snapshot);
	BINARYNINJACOREAPI BNKeyValueStore* BNReadSnapshotDataWithProgress(
		BNSnapshot* snapshot, void* ctxt, bool (*progress)(void* ctxt, size_t progress, size_t total));


	BINARYNINJACOREAPI BNUndoEntry* BNGetSnapshotUndoEntries(BNSnapshot* snapshot, size_t* count);
	BINARYNINJACOREAPI BNUndoEntry* BNGetSnapshotUndoEntriesWithProgress(
	    BNSnapshot* snapshot, void* ctxt, bool (*progress)(void* ctxt, size_t progress, size_t total), size_t* count);
	BINARYNINJACOREAPI bool BNSnapshotHasAncestor(BNSnapshot* snapshot, BNSnapshot* other);

}