#pragma once

#include "binaryninjacore.h"
#include "exceptions.h"
#include "refcount.h"
#include "json/json.h"
#include <functional>
#include <vector>

namespace BinaryNinja
{
	class BinaryView;
	class DataBuffer;
	class UndoEntry;

	/*!

		\ingroup database
	*/
	struct DatabaseException : ExceptionWithStackTrace
	{
		DatabaseException(const std::string& desc) : ExceptionWithStackTrace(desc.c_str()) {}
	};

	/*! Maintains access to the raw data stored in Snapshots and various
    	other Database-related structures.

		\ingroup database
	*/
	class KeyValueStore : public CoreRefCountObject<BNKeyValueStore, BNNewKeyValueStoreReference, BNFreeKeyValueStore>
	{
	  public:
		KeyValueStore();
		KeyValueStore(const DataBuffer& buffer);
		KeyValueStore(BNKeyValueStore* store);

		std::vector<std::string> GetKeys() const;

		bool HasValue(const std::string& name) const;
		Json::Value GetValue(const std::string& name) const;
		DataBuffer GetValueHash(const std::string& name) const;
		DataBuffer GetBuffer(const std::string& name) const;
		void SetValue(const std::string& name, const Json::Value& value);
		void SetBuffer(const std::string& name, const DataBuffer& value);

		DataBuffer GetSerializedData() const;

		void BeginNamespace(const std::string& name);
		void EndNamespace();

		bool IsEmpty() const;
		size_t ValueSize() const;
		size_t DataSize() const;
		size_t ValueStorageSize() const;
		size_t NamespaceSize() const;
	};

	class Database;

	/*! A model of an individual database snapshot, created on save.

		\ingroup database
	*/
	class Snapshot : public CoreRefCountObject<BNSnapshot, BNNewSnapshotReference, BNFreeSnapshot>
	{
	  public:
		Snapshot(BNSnapshot* snapshot);

		Ref<Database> GetDatabase();
		int64_t GetId();
		std::string GetName();
		void SetName(const std::string& name);
		bool IsAutoSave();
		bool HasContents();
		bool HasData();
		bool HasUndo();
		Ref<Snapshot> GetFirstParent();
		std::vector<Ref<Snapshot>> GetParents();
		std::vector<Ref<Snapshot>> GetChildren();
		DataBuffer GetFileContents();
		DataBuffer GetFileContentsHash();
		DataBuffer GetUndoData();
		std::vector<Ref<UndoEntry>> GetUndoEntries();
		std::vector<Ref<UndoEntry>> GetUndoEntries(const std::function<bool(size_t, size_t)>& progress);
		Ref<KeyValueStore> ReadData();
		Ref<KeyValueStore> ReadData(const std::function<bool(size_t, size_t)>& progress);
		bool StoreData(const Ref<KeyValueStore>& data, const std::function<bool(size_t, size_t)>& progress);
		bool HasAncestor(Ref<Snapshot> other);
	};

	class FileMetadata;

	/*! Provides lower level access to raw snapshot data used to construct analysis data

		\ingroup database
	*/
	class Database : public CoreRefCountObject<BNDatabase, BNNewDatabaseReference, BNFreeDatabase>
	{
	  public:
		Database(BNDatabase* database);

		bool SnapshotHasData(int64_t id);
		Ref<Snapshot> GetSnapshot(int64_t id);
		std::vector<Ref<Snapshot>> GetSnapshots();
		void SetCurrentSnapshot(int64_t id);
		Ref<Snapshot> GetCurrentSnapshot();
		int64_t WriteSnapshotData(std::vector<int64_t> parents, Ref<BinaryView> file, const std::string& name,
		    const Ref<KeyValueStore>& data, bool autoSave, const std::function<bool(size_t, size_t)>& progress);
		void TrimSnapshot(int64_t id);
		void RemoveSnapshot(int64_t id);

		std::vector<std::string> GetGlobalKeys() const;
		bool HasGlobal(const std::string& key) const;
		Json::Value ReadGlobal(const std::string& key) const;
		void WriteGlobal(const std::string& key, const Json::Value& val);
		DataBuffer ReadGlobalData(const std::string& key) const;
		void WriteGlobalData(const std::string& key, const DataBuffer& val);

		Ref<FileMetadata> GetFile();
		void ReloadConnection();

		Ref<KeyValueStore> ReadAnalysisCache() const;
		void WriteAnalysisCache(Ref<KeyValueStore> val);
	};

}
