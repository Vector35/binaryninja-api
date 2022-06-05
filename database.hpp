#pragma once
#include <string>
#include <vector>
#include <exception>
#include "refcount.hpp"
#include "databuffer.hpp"
#include "undoaction.hpp"
#include "binaryninjaapi_new.hpp"
#include "database.h"
#include "json/json.h"

namespace BinaryNinja
{
	class FileMetadata;
	class Database;
	class UndoEntry;
	class BinaryView;

	struct DatabaseException : std::runtime_error
	{
		DatabaseException(const std::string& desc) : std::runtime_error(desc.c_str()) {}
	};

	class KeyValueStore : public CoreRefCountObject<BNKeyValueStore, BNNewKeyValueStoreReference, BNFreeKeyValueStore>
	{
	  public:
		KeyValueStore();
		KeyValueStore(const DataBuffer& buffer);
		KeyValueStore(BNKeyValueStore* store);

		std::vector<std::string> GetKeys() const;

		bool HasValue(const std::string& name) const;
		Json::Value GetValue(const std::string& name) const;
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

	class Snapshot : public CoreRefCountObject<BNSnapshot, BNNewSnapshotReference, BNFreeSnapshot>
	{
	  public:
		Snapshot(BNSnapshot* snapshot);

		Ref<Database> GetDatabase();
		int64_t GetId();
		std::string GetName();
		bool IsAutoSave();
		bool HasContents();
		bool HasUndo();
		Ref<Snapshot> GetFirstParent();
		std::vector<Ref<Snapshot>> GetParents();
		std::vector<Ref<Snapshot>> GetChildren();
		DataBuffer GetFileContents();
		DataBuffer GetFileContentsHash();
		std::vector<UndoEntry> GetUndoEntries();
		std::vector<UndoEntry> GetUndoEntries(const std::function<bool(size_t, size_t)>& progress);
		Ref<KeyValueStore> ReadData();
		Ref<KeyValueStore> ReadData(const std::function<bool(size_t, size_t)>& progress);
		bool HasAncestor(Ref<Snapshot> other);
	};

	class Database : public CoreRefCountObject<BNDatabase, BNNewDatabaseReference, BNFreeDatabase>
	{
	  public:
		Database(BNDatabase* database);

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

		Ref<KeyValueStore> ReadAnalysisCache() const;
		void WriteAnalysisCache(Ref<KeyValueStore> val);
	};

	struct MergeResult
	{
		BNMergeStatus status;
		UndoAction action;
		std::string hash;

		MergeResult() : status(NOT_APPLICABLE) {}
		MergeResult(const BNMergeResult& result);
	};
}