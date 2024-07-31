#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace BinaryNinja
{
	class DataBuffer;
	class Metadata;
	class Platform;
	class QualifiedName;
	struct QualifiedNameAndType;
	class Type;
	class TypeArchive;


	class TypeArchiveNotification
	{
		BNTypeArchiveNotification m_callbacks;

		static void OnTypeAddedCallback(void* ctx, BNTypeArchive* archive, const char* id, BNType* definition);
		static void OnTypeUpdatedCallback(void* ctx, BNTypeArchive* archive, const char* id, BNType* oldDefinition, BNType* newDefinition);
		static void OnTypeRenamedCallback(void* ctx, BNTypeArchive* archive, const char* id, const BNQualifiedName* oldName, const BNQualifiedName* newName);
		static void OnTypeDeletedCallback(void* ctx, BNTypeArchive* archive, const char* id, BNType* definition);

	public:
		TypeArchiveNotification();
		virtual ~TypeArchiveNotification() = default;

		BNTypeArchiveNotification* GetCallbacks() { return &m_callbacks; }

		/*! Called when a type is added to the archive

		    \param archive
		    \param id Id of type added
		    \param definition Definition of type
		 */
		virtual void OnTypeAdded(Ref<TypeArchive> archive, const std::string& id, Ref<Type> definition)
		{
			(void)archive;
			(void)id;
		}

		/*! Called when a type in the archive is updated to a new definition

		    \param archive
		    \param id Id of type
		    \param oldDefinition Previous definition
		    \param newDefinition Current definition
		 */
		virtual void OnTypeUpdated(Ref<TypeArchive> archive, const std::string& id, Ref<Type> oldDefinition, Ref<Type> newDefinition)
		{
			(void)archive;
			(void)id;
			(void)oldDefinition;
			(void)newDefinition;
		}

		/*! Called when a type in the archive is renamed

		    \param archive
		    \param id Type id
		    \param oldName Previous name
		    \param newName Current name
		 */
		virtual void OnTypeRenamed(Ref<TypeArchive> archive, const std::string& id, const QualifiedName& oldName, const QualifiedName& newName)
		{
			(void)archive;
			(void)oldName;
			(void)newName;
		}

		/*! Called when a type in the archive is deleted from the archive

		    \param archive
		    \param id Id of type deleted
		    \param definition Definition of type deleted
		 */
		virtual void OnTypeDeleted(Ref<TypeArchive> archive, const std::string& id, Ref<Type> definition)
		{
			(void)archive;
			(void)id;
			(void)definition;
		}
	};

	/*! Type Archives are a collection of types which can be shared between different analysis
	    sessions and are backed by a database file on disk. Their types can be modified, and
	    a history of previous versions of types is stored in snapshots in the archive.

	    \ingroup typearchive
	 */
	class TypeArchive: public CoreRefCountObject<BNTypeArchive, BNNewTypeArchiveReference, BNFreeTypeArchiveReference>
	{
	public:
		TypeArchive(BNTypeArchive* archive);

		/*! Open the type archive at the given path, if it exists.

		    \param path Path to type archive file
		    \return Type archive, or nullptr if it could not be loaded.
		 */
		static Ref<TypeArchive> Open(const std::string& path);

		/*! Create a type archive at the given path.

		    \param path Path to type archive file
		    \param platform Relevant platform for types in the archive
		    \return Type archive, or nullptr if it could not be loaded.
		 */
		static Ref<TypeArchive> Create(const std::string& path, Ref<Platform> platform);

		/*! Create a type archive at the given path with a manually-specified id.

		    \note You probably want to use Create() and let BN handle picking an id for you.
		    \param path Path to type archive file
		    \param platform Relevant platform for types in the archive
		    \param id Assigned id for the type archive
		    \return Type archive, or nullptr if it could not be created.
		 */
		static Ref<TypeArchive> CreateWithId(const std::string& path, Ref<Platform> platform, const std::string& id);

		/*! Get a reference to the type archive with the known id, if one exists.

		    \param id Type archive id
		    \return Type archive, or nullptr if it could not be found.
		 */
		static Ref<TypeArchive> LookupById(const std::string& id);

		/*! Close a type archive, disconnecting it from any active views and closing any open file handles

		    \param archive Type Archive to close
		 */
		static void Close(Ref<TypeArchive> archive);

		/*! Determine if a file is a Type Archive

		    \param path File path
		    \return True if it's a type archive
		 */
		static bool IsTypeArchive(const std::string& path);

		/*! Get the unique id associated with this type archive

		    \return The id
		 */
		std::string GetId() const;

		/*! Get the path to the type archive

		    \return The path
		 */
		std::string GetPath() const;

		/*! Get the associated Platform for a Type Archive

		    \return Platform
		 */
		Ref<Platform> GetPlatform() const;

		/*! Get the id of the current snapshot in the type archive

		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Snapshot id
		 */
		std::string GetCurrentSnapshotId() const;

		/*! Revert the type archive's current snapshot to the given snapshot

		    \param id Snapshot id
		 */
		void SetCurrentSnapshot(const std::string& id);

		/*! Get a list of every snapshot's id

		    \throws ExceptionWithStackTrace if an exception occurs
		    \return All ids (including the empty first snapshot)
		 */
		std::vector<std::string> GetAllSnapshotIds() const;

		/*! Get the ids of the parents to the given snapshot

		    \param id Child snapshot id
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Parent snapshot ids, or empty vector if the snapshot is a root
		 */
		std::vector<std::string> GetSnapshotParentIds(const std::string& id) const;

		/*! Get the ids of the children to the given snapshot

		    \param id Parent snapshot id
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Child snapshot ids, or empty vector if the snapshot is a leaf
		 */
		std::vector<std::string> GetSnapshotChildIds(const std::string& id) const;

		/*! Get the TypeContainer interface for this Type Archive, presenting types
		    at the current snapshot in the archive.

		    \return TypeContainer interface
		 */
		class TypeContainer GetTypeContainer() const;

		/*! Add named types to the type archive. Types must have all dependant named
		    types prior to being added, or this function will fail.
		    Types already existing with any added names will be overwritten.

		    \param name Name of new type
		    \param types Type definitions
		    \return True if the types were added
		 */
		bool AddTypes(const std::vector<QualifiedNameAndType>& types);

		/*! Change the name of an existing type in the type archive.

		    \param id Type id
		    \param newName New type name
		    \return True if successful
		 */
		bool RenameType(const std::string& id, const QualifiedName& newName);

		/*! Delete an existing type in the type archive.

		    \param id Type id
		    \return True if successful
		 */
		bool DeleteType(const std::string& id);

		/*! Retrieve a stored type in the archive by id

		    \param id Type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \return Type, if it exists. Otherwise nullptr
		 */
		Ref<Type> GetTypeById(const std::string& id, std::string snapshot = "") const;

		/*! Retrieve a stored type in the archive

		    \param name Type name
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \return Type, if it exists. Otherwise nullptr
		 */
		Ref<Type> GetTypeByName(const QualifiedName& name, std::string snapshot = "") const;

		/*! Retrieve a type's id by its name

		    \param name Type name
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \return Type id, if it exists. Otherwise empty string
		 */
		std::string GetTypeId(const QualifiedName& name, std::string snapshot = "") const;

		/*! Retrieve a type's name by its id

		    \param id Type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \return Type name, if it exists. Otherwise empty string
		 */
		QualifiedName GetTypeName(const std::string& id, std::string snapshot = "") const;

		/*! Retrieve all stored types in the archive

		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return All types
		 */
		std::unordered_map<std::string, QualifiedNameAndType> GetTypes(std::string snapshot = "") const;

		/*! Get a list of all types' ids currently in the archive

		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return All type ids
		 */
		std::vector<std::string> GetTypeIds(std::string snapshot = "") const;

		/*! Get a list of all types' names currently in the archive

		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return All type names
		 */
		std::vector<QualifiedName> GetTypeNames(std::string snapshot = "") const;

		/*! Get a list of all types' names and ids currently in the archive

		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return All type names and ids
		 */
		std::unordered_map<std::string, QualifiedName> GetTypeNamesAndIds(std::string snapshot = "") const;

		/*! Get all types a given type references directly

		    \param id Source type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Target type ids
		 */
		std::unordered_set<std::string> GetOutgoingDirectTypeReferences(const std::string& id, std::string snapshot = "") const;

		/*! Get all types a given type references, and any types that the referenced types reference

		    \param id Source type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Target type ids
		 */
		std::unordered_set<std::string> GetOutgoingRecursiveTypeReferences(const std::string& id, std::string snapshot = "") const;

		/*! Get all types that reference a given type

		    \param id Target type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Source type ids
		 */
		std::unordered_set<std::string> GetIncomingDirectTypeReferences(const std::string& id, std::string snapshot = "") const;

		/*! Get all types that reference a given type, and all types that reference them, recursively

		    \param id Target type id
		    \param snapshot Snapshot id to search for types, or empty string to search the latest snapshot
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Source type ids
		 */
		std::unordered_set<std::string> GetIncomingRecursiveTypeReferences(const std::string& id, std::string snapshot = "") const;

		/*! Do some function in a transaction making a new snapshot whose id is passed to func. If func throws,
		    the transaction will be rolled back and the snapshot will not be created.

		    \param func Function to call
		    \param parents Parent snapshot ids
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Created snapshot id
		 */
		std::string NewSnapshotTransaction(std::function<void(const std::string& id)> func, const std::vector<std::string>& parents);

		/*! Register a notification listener

		    \param notification Object to receive notifications
		 */
		void RegisterNotification(TypeArchiveNotification* notification);

		/*! Unregister a notification listener

		    \param notification Object to no longer receive notifications
		 */
		void UnregisterNotification(TypeArchiveNotification* notification);

		/*! Store a key/value pair in the archive's metadata storage

		    \param key Metadata key
		    \param value Metadata value
		    \throws ExceptionWithStackTrace if an exception occurs
		 */
		void StoreMetadata(const std::string& key, Ref<Metadata> value);

		/*! Look up a metadata entry in the archive

		    \param key Metadata key
		    \return Metadata value, if it exists. Otherwise, nullptr
		 */
		Ref<Metadata> QueryMetadata(const std::string& key) const;

		/*! Delete a given metadata entry in the archive

		    \param key Metadata key
		    \throws ExceptionWithStackTrace if an exception occurs
		 */
		void RemoveMetadata(const std::string& key);

		/*! Turn a given snapshot into a data stream

		    \param snapshot Snapshot id
		    \return Buffer containing serialized snapshot data
		 */
		DataBuffer SerializeSnapshot(const std::string& snapshot) const;

		/*! Take a serialized snapshot data stream and create a new snapshot from it

		    \param data Snapshot data
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return String of created snapshot id
		 */
		std::string DeserializeSnapshot(const DataBuffer& data);

		/*! Merge two snapshots in the archive to produce a new snapshot

		    \param[in] baseSnapshot Common ancestor of snapshots
		    \param[in] firstSnapshot First snapshot to merge
		    \param[in] secondSnapshot Second snapshot to merge
		    \param[in] mergeConflictsIn Map of resolutions for all conflicting types, id <-> target snapshot
		    \param[out] mergeConflictsOut List of conflicting type ids
		    \param[in] progress Function to call for progress updates
		    \throws ExceptionWithStackTrace if an exception occurs
		    \return Snapshot id, if merge was successful. std::nullopt, otherwise
		 */
		std::optional<std::string> MergeSnapshots(
			const std::string& baseSnapshot,
			const std::string& firstSnapshot,
			const std::string& secondSnapshot,
			const std::unordered_map<std::string, std::string>& mergeConflictsIn,
			std::unordered_set<std::string>& mergeConflictsOut,
			std::function<bool(size_t, size_t)> progress
		);
	};
}
