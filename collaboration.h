#pragma once

#include "binaryninjacore.h"
#include "exceptions.h"
#include "refcount.h"
#include "json/json.h"
#include "vendor/nlohmann/json.hpp"
#include <any>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>


namespace BinaryNinja
{
	class Database;
	class FileMetadata;
	class Project;
	class ProjectFile;
	class ProjectFolder;
	class Snapshot;
	class TypeArchive;
}

namespace BinaryNinja::Http
{
	struct Request;
	struct Response;
}

namespace BinaryNinja::Collaboration
{

	class AnalysisMergeConflict;
	class TypeArchiveMergeConflict;
	class CollabChangeset;

	struct DatabaseConflictHandlerContext
	{
		std::function<bool(const std::unordered_map<std::string, Ref<AnalysisMergeConflict>>)> callback;
	};

	struct TypeArchiveConflictHandlerContext
	{
		std::function<bool(const std::vector<Ref<TypeArchiveMergeConflict>>)> callback;
	};

	struct NameChangesetContext
	{
		std::function<bool(Ref<CollabChangeset>)> callback;
	};

	bool DatabaseConflictHandlerCallback(void* ctxt, const char** keys, BNAnalysisMergeConflict** conflicts, size_t count);
	bool TypeArchiveConflictHandlerCallback(void* ctxt, BNTypeArchiveMergeConflict** conflicts, size_t count);
	bool NameChangesetCallback(void* ctxt, BNCollaborationChangeset* changeset);


	class Remote;
	class RemoteProject;

	struct SyncException : ExceptionWithStackTrace
	{
		SyncException(const std::string& desc) : ExceptionWithStackTrace(desc.c_str()) {}
	};

	/*!

		\ingroup collaboration
	*/
	struct RemoteException : std::runtime_error
	{
		RemoteException(const std::string& desc) : std::runtime_error(desc.c_str()) {}
	};

	/*!
		\ingroup collaboration
	*/
	class CollabUser : public CoreRefCountObject<BNCollaborationUser, BNNewCollaborationUserReference, BNFreeCollaborationUser>
	{
	public:
		CollabUser(BNCollaborationUser* collabUser);

		Ref<Remote> GetRemote();
		std::string GetUrl();
		std::string GetId();
		std::string GetUsername();
		std::string GetEmail();
		std::string GetLastLogin();
		bool IsActive();

		void SetUsername(const std::string& username);
		void SetEmail(const std::string& email);
		void SetIsActive(bool isActive);
	};

	/*!
		\ingroup collaboration
	*/
	class CollabGroup : public CoreRefCountObject<BNCollaborationGroup, BNNewCollaborationGroupReference, BNFreeCollaborationGroup>
	{
	public:
		CollabGroup(BNCollaborationGroup* group);

		uint64_t GetId();
		std::string GetName();
		void SetName(const std::string& name);
		void SetUsernames(const std::vector<std::string>& usernames);
		bool ContainsUser(const std::string& username);

	};

	/*!
		\ingroup collaboration
	*/
	class Remote : public CoreRefCountObject<BNRemote, BNNewRemoteReference, BNFreeRemote>
	{
	public:
		Remote(BNRemote* remote);

		std::string GetUniqueId();
		std::string GetName();
		std::string GetAddress();
		bool HasLoadedMetadata();
		bool IsConnected();
		std::string GetUsername();
		std::string GetToken();
		int GetServerVersion();
		std::string GetServerBuildId();
		std::vector<std::pair<std::string, std::string>> GetAuthBackends();
		bool HasPulledProjects();
		bool HasPulledUsers();
		bool HasPulledGroups();
		bool IsAdmin();

		/*!
			Determine if a remote is the same as the currently connected Enterprise Server
			On non-Enterprise clients, this always returns false.
			\return True if the remote is the same
		*/
		bool IsEnterprise();


		/*!
			Load remote metadata, including version, id, and auth backends
			\throws RemoteException If there is an error in any request, or if the remote version is not supported
		*/
		bool LoadMetadata();


		/*!
			Request an authentication token for a user given a username and password
			\param username CollabUser's username
			\param password CollabUser's password
			\return Authentication token
			\throws RemoteException If there is an error in any request
		*/
		std::string RequestAuthenticationToken(const std::string& username, const std::string& password);


		/*!
			Establish a connection to the remote, using a username and token
			\param username CollabUser's username
			\param token CollabUser's authentication token
			\throws RemoteException If there is an error in any request
		*/
		void Connect(const std::string& username, const std::string& token);


		/*!
			Disconnect from the remote
		*/
		void Disconnect();

		/*!
			Get all projects in the Remote
			\return All projects
			\throws RemoteException if projects have not been pulled or if the remote is not connected
		*/
		std::vector<Ref<RemoteProject>> GetProjects();


		/*!
			Get a project in the remote by its id
			\param id Project's id
			\return Project, or null shared_ptr if not found
			\throws RemoteException If projects have not been pulled or if the remote is not connected
		*/
		Ref<RemoteProject> GetProjectById(const std::string& id);


		/*!
			Get a project in the remote by its name
			\param name Project's name
			\return Project, or null shared_ptr if not found
			\throws RemoteException If projects have not been pulled or if the remote is not connected
		*/
		Ref<RemoteProject> GetProjectByName(const std::string& name);


		/*!
			Pull list of projects from the remote. Necessary before calling GetProjects()
			\param progress Function to call on progress updates
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PullProjects(std::function<bool(size_t, size_t)> progress = {});


		/*!
			Create a new project on the remote (and pull it)
			\param name Project name
			\param description Project description
			\return Reference to the created project
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		Ref<RemoteProject> CreateProject(const std::string& name, const std::string& description);


		/*!
			Create a new project on the remote from a local project
			\param localProject The local project that should be copied to the server
			\param progress Function to call on progress updates
			\return Reference to the created project
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		Ref<RemoteProject> ImportLocalProject(Ref<Project> localProject, std::function<bool(size_t, size_t)> progress = {});


		/*!
			Push fields of a modified project to the remote
			\param project Updated project
			\param extraFields Extra post fields for the request
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PushProject(Ref<RemoteProject> project, const std::vector<std::pair<std::string, std::string>>& extraFields = {});


		/*!
			Delete a project from the remote
			\param project Pointer to project to delete (will invalidate pointer)
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void DeleteProject(const Ref<RemoteProject> project);

		/*!
			Get all groups in the Project
			\return All groups
			\throws RemoteException if groups have not been pulled or if the remote is not connected
		*/
		std::vector<Ref<CollabGroup>> GetGroups();


		/*!
			Get a group in the project by its id
			\param id Group's id
			\return Group, or null shared_ptr if not found
			\throws RemoteException If groups have not been pulled or if the remote is not connected
		*/
		Ref<CollabGroup> GetGroupById(uint64_t id);


		/*!
			Get a group in the project by its name. Will check for both name and <project id>/name
			\param name Group's name
			\return Group, or null shared_ptr if not found
			\throws RemoteException If groups have not been pulled or if the remote is not connected
		*/
		Ref<CollabGroup> GetGroupByName(const std::string& name);


		/*!
			Search groups on the remote
			\param prefix Prefix to search for
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		std::vector<std::pair<uint64_t, std::string>> SearchGroups(const std::string& prefix);


		/*!
			Pull list of groups from the remote. Necessary before calling GetGroups()
			\param progress Function to call on progress updates
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PullGroups(std::function<bool(size_t, size_t)> progress = {});


		/*!
			Create a new group on the remote (and pull it)
			\param name Group name
			\return Reference to the created group
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		Ref<CollabGroup> CreateGroup(const std::string& name, const std::vector<std::string>& usernames);


		/*!
			Push fields of a modified group to the remote
			\param group Updated group
			\param extraFields Extra post fields for the request
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PushGroup(Ref<CollabGroup> group, const std::vector<std::pair<std::string, std::string>>& extraFields = {});


		/*!
			Delete a group from the remote
			\param group Pointer to group to delete (will invalidate pointer)
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void DeleteGroup(const Ref<CollabGroup> group);


		/*!
			Get all users in the Remote
			\return All users
			\throws RemoteException if users have not been pulled or if the remote is not connected
		*/
		std::vector<Ref<CollabUser>> GetUsers();


		/*!
			Get a user in the remote by their id
			\param id CollabUser's id
			\return CollabUser, or null shared_ptr if not found
			\throws RemoteException If users have not been pulled or if the remote is not connected
		*/
		Ref<CollabUser> GetUserById(const std::string& id);


		/*!
			Get a user in the remote by their username
			\param username CollabUser's username
			\return CollabUser, or null shared_ptr if not found
			\throws RemoteException If users have not been pulled or if the remote is not connected
		*/
		Ref<CollabUser> GetUserByUsername(const std::string& username);


		/*!
			Get the currently logged-in user's CollabUser object
			\return The current user's CollabUser, or null shared_ptr if not found
			\throws RemoteException if users have not been pulled or if the remote is not connected
		*/
		Ref<CollabUser> GetCurrentUser();


		/*!
			Search users on the remote
			\param prefix Prefix to search for
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		std::vector<std::pair<std::string, std::string>> SearchUsers(const std::string& prefix);


		/*!
			Pull list of users from the remote. Necessary before calling GetUsers()
			\param progress Function to call on progress updates
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PullUsers(std::function<bool(size_t, size_t)> progress = {});


		/*!
			Create a new user on the remote (and pull it)
			\param name CollabUser name
			\param email CollabUser email
			\param is_active If the user should initially be active
			\param password CollabUser password
			\param groupIds List of group ids the user will be added to
			\param userPermissionIds List of permission ids the user will be granted
			\return Reference to the created user
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		Ref<CollabUser> CreateUser(const std::string& username, const std::string& email, bool is_active,
			const std::string& password, const std::vector<uint64_t>& groupIds,
			const std::vector<uint64_t>& userPermissionIds);

		/*!
			Push fields of a modified user to the remote
			\param user Updated user
			\param extraFields Extra post fields for the request (eg password)
			\throws RemoteException If there is an error in any request or if the remote is not connected
		*/
		void PushUser(Ref<CollabUser> user, const std::vector<std::pair<std::string, std::string>>& extraFields = {});

		/*!
			Perform an arbitrary HTTP request. An "Authorization: Token <token>" header will be added
			with the Remote's token for the current login session.
			\param request Request structure with headers and content.
			\param response Response structure with body
			\return Zero or greater on success
		*/
		int Request(Http::Request request, Http::Response& ret);
	};

	/*!
		\ingroup collaboration
	*/
	class RemoteFolder : public CoreRefCountObject<BNRemoteFolder, BNNewRemoteFolderReference, BNFreeRemoteFolder>
	{
	public:
		RemoteFolder(BNRemoteFolder* remoteFolder);
	};

	class RemoteFile;

	class CollabUndoEntry : public CoreRefCountObject<BNCollaborationUndoEntry, BNNewCollaborationUndoEntryReference, BNFreeCollaborationUndoEntry>
	{
	public:
		CollabUndoEntry(BNCollaborationUndoEntry* entry);

	};

	class CollabSnapshot : public CoreRefCountObject<BNCollaborationSnapshot, BNNewCollaborationSnapshotReference, BNFreeCollaborationSnapshot>
	{
	public:
		CollabSnapshot(BNCollaborationSnapshot* snapshot);

		Ref<RemoteFile> GetFile();
		Ref<RemoteProject> GetProject();
		Ref<Remote> GetRemote();
		std::string GetUrl();
		std::string GetId();
		std::string GetName();
		std::string GetAuthor();
		int64_t GetCreated();
		int64_t GetLastModified();
		std::string GetHash();
		std::string GetSnapshotFileHash();
		bool HasPulledUndoEntries();
		bool IsFinalized();
		std::vector<std::string> GetParentIds();
		std::vector<std::string> GetChildIds();
		uint64_t GetAnalysisCacheBuildId();

		/*!
		    Get the title of a snapshot: the first line of its name
		    \return CollabSnapshot title as described
		 */
		std::string GetTitle();

		/*!
		    Get the description of a snapshot: the lines of its name after the first line
		    \return CollabSnapshot description as described
		 */
		std::string GetDescription();

		/*!
		    Get the username of the author of a snapshot, if possible (vs GetAuthor() which is user id)
		    \return CollabSnapshot author username
		 */
		std::string GetAuthorUsername();

		/*!
		    Get all snapshots in this snapshot's file that are parents of this snapshot
		    \return List of parent snapshots
		    \throws RemoteException If a parent snapshot does not exist in the file or if the remote is not connected
		 */
		std::vector<Ref<CollabSnapshot>> GetParents();

		/*!
		    Get all snapshots in this snapshot's file that are children of this snapshot
		    \return List of child snapshots
		    \throws RemoteException If a child snapshot does not exist in the file or if the remote is not connected
		 */
		std::vector<Ref<CollabSnapshot>> GetChildren();

		/*!
		    Get all undo entries in the snapshot
		    \return All undo entries
		    \throws RemoteException if undo entries have not been pulled or if the remote is not connected
		*/
		std::vector<Ref<CollabUndoEntry>> GetUndoEntries();

		/*!
		    Get a undo entry in the snapshot by its id
		    \param id Undo entry's id
		    \return Undo entry, or null shared_ptr if not found
		    \throws RemoteException If undo entries have not been pulled or if the remote is not connected
		 */
		Ref<CollabUndoEntry> GetUndoEntryById(uint64_t id);

		/*!
		    Pull list of undo entries from the remote. Necessary before calling GetUndoEntries()
		    \param progress Function to call on progress updates
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		void PullUndoEntries(std::function<bool(size_t, size_t)> progress = {});

		/*!
		    Create a new undo entry on the remote (and pull it)
		    \param parent Undo entry parent id (if exists)
		    \param data Undo entry data
		    \return Reference to the created undo entry
		    \throws RemoteException If there is an error in any request, or if the snapshot is finalized,
		                            or if the remote is not connected
		 */
		Ref<CollabUndoEntry> CreateUndoEntry(std::optional<uint64_t> parent, std::string data);

		/*!
		    Mark the snapshot as Finalized, preventing future modification and allowing child snapshots
		    This change is pushed instantly (calls the finalize endpoint)
		    \throws RemoteException if there is an error in any request or if the remote is not connected
		 */
		void Finalize();

		/*!
		    Download the contents of the file backing a snapshot
		    N.B. Multiple snapshots can be backed by the same file
		    \param progress Function to call on progress updates
		    \return Contents of the file at the point of the snapshot
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		std::vector<uint8_t> DownloadSnapshotFile(std::function<bool(size_t, size_t)> progress = {});

		/*!
		    Download the contents of the snapshot
		    \param progress Function to call on progress updates
		    \return Contents of the snapshot
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		std::vector<uint8_t> Download(std::function<bool(size_t, size_t)> progress = {});

		/*!
		    Download the contents of the analysis cache for this snapshot, returns an empty vector if there is no cache (eg: old snapshots)
		    \param progress Function to call on progress updates
		    \return Contents of the analysis cache
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		std::vector<uint8_t> DownloadAnalysisCache(std::function<bool(size_t, size_t)> progress = {});
	};

	/*!
		\ingroup collaboration
	*/
	class RemoteFile : public CoreRefCountObject<BNRemoteFile, BNNewRemoteFileReference, BNFreeRemoteFile>
	{
	public:
		RemoteFile(BNRemoteFile* remoteFile);

		Ref<ProjectFile> GetCoreFile();
		Ref<RemoteProject> GetProject();
		Ref<RemoteFolder> GetFolder();
		Ref<Remote> GetRemote();
		std::string GetUrl();
		std::string GetChatLogUrl();
		std::string GetUserPositionsUrl();
		std::string GetId();
		BNRemoteFileType GetType();
		int64_t GetCreated();
		std::string GetCreatedBy();
		int64_t GetLastModified();
		int64_t GetLastSnapshot();
		std::string GetLastSnapshotBy();
		std::string GetLastSnapshotName();
		std::string GetHash();
		std::string GetName();
		std::string GetDescription();
		std::string GetMetadata();
		uint64_t GetSize();
		bool HasPulledSnapshots();

		void SetName(const std::string& name);
		void SetDescription(const std::string& description);
		void SetFolder(const Ref<RemoteFolder>& folder);
		void SetMetadata(const std::string& metadata);

		/*!
		    Get all snapshots in the file
		    \return All snapshops
		    \throws RemoteException if snapshots have not been pulled or if the remote is not connected
		 */
		std::vector<Ref<CollabSnapshot>> GetSnapshots();

		/*!
		    Get a snapshot in the file by its id
		    \param id CollabSnapshot's id
		    \return CollabSnapshot, or nullptr
		    \throws RemoteException If snapshots have not been pulled or if the remote is not connected
		 */
		Ref<CollabSnapshot> GetSnapshotById(const std::string& id);

		/*!
		    Pull list of snapshots from the remote. Necessary before calling GetSnapshots()
		    \param progress Function to call on progress updates
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		void PullSnapshots(std::function<bool(size_t, size_t)> progress = {});

		/*!
		    Create a new snapshot on the remote (and pull it)
		    \param name CollabSnapshot name
		    \param parentIds List of ids of parent snapshots (or empty if this is a root snapshot)
		    \param contents CollabSnapshot contents
		    \param analysisCacheContents Analysis cache contents
		    \param fileContents New file contents (if contents changed)
		    \param progress Function to call on progress updates
		    \return Reference to the created snapshot
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		Ref<CollabSnapshot> CreateSnapshot(
			std::string name,
			std::vector<uint8_t> contents,
			std::vector<uint8_t> analysisCacheContents,
			std::optional<std::vector<uint8_t>> fileContents,
			std::vector<std::string> parentIds,
			std::function<bool(size_t, size_t)> progress = {}
		);

		/*!
		    Delete a snapshot from the remote
		    \param snapshot Pointer to snapshot to delete (will invalidate pointer)
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		void DeleteSnapshot(const Ref<CollabSnapshot> snapshot);

		/*!
		    Download the contents of a remote file
		    \param progress Function to call on progress updates
		    \return Contents of the file
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		std::vector<uint8_t> Download(std::function<bool(size_t, size_t)> progress = {});

		/*!
		    Get the current user positions for this file
		    \return User positions as json
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		Json::Value RequestUserPositions();

		/*!
		    Get the current chat log for this file
		    \return Chat log as json
		    \throws RemoteException If there is an error in any request or if the remote is not connected
		 */
		Json::Value RequestChatLog();
	};

	/*!
		\ingroup collaboration
	*/
	class CollabPermission : public CoreRefCountObject<BNCollaborationPermission, BNNewCollaborationPermissionReference, BNFreeCollaborationPermission>
	{
	public:
		CollabPermission(BNCollaborationPermission* permission);

		Ref<RemoteProject> GetProject();
		Ref<Remote> GetRemote();
		std::string GetId();
		std::string GetUrl();
		uint64_t GetGroupId();
		std::string GetGroupName();
		std::string GetUserId();
		std::string GetUsername();
		BNCollaborationPermissionLevel GetLevel();
		void SetLevel(BNCollaborationPermissionLevel level);
		bool CanView();
		bool CanEdit();
		bool CanAdmin();
	};

	/*!
		\ingroup collaboration
	*/
	class RemoteProject : public CoreRefCountObject<BNRemoteProject, BNNewRemoteProjectReference, BNFreeRemoteProject>
	{
	public:
		RemoteProject(BNRemoteProject* remoteProject);

		Ref<Project> GetCoreProject();
		bool IsOpen();
		bool Open(std::function<bool(size_t, size_t)> progress = {});
		void Close();

		Ref<Remote> GetRemote();
		std::string GetUrl();
		int64_t GetCreated();
		int64_t GetLastModified();
		std::string GetId();
		std::string GetName();
		void SetName(const std::string& name);
		std::string GetDescription();
		void SetDescription(const std::string& description);
		uint64_t GetReceivedFileCount();
		uint64_t GetReceivedFolderCount();
		bool HasPulledFiles();
		bool HasPulledGroupPermissions();
		bool HasPulledUserPermissions();
		bool IsAdmin();

		std::vector<Ref<RemoteFile>> GetFiles();
		std::vector<Ref<RemoteFolder>> GetFolders();
		Ref<RemoteFile> GetFileById(const std::string& id);
		Ref<RemoteFile> GetFileByName(const std::string& name);
		void PullFiles(std::function<bool(size_t, size_t)> progress = {});
		void PullFolders(std::function<bool(size_t, size_t)> progress = {});
		Ref<RemoteFile> CreateFile(const std::string& filename, std::vector<uint8_t>& contents, const std::string& name, const std::string& description, Ref<RemoteFolder> folder, BNRemoteFileType type, std::function<bool(size_t, size_t)> progress = {}, Ref<ProjectFile> coreFile = nullptr);
		Ref<RemoteFolder> CreateFolder(const std::string& name, const std::string& description, Ref<RemoteFolder> parent, std::function<bool(size_t, size_t)> progress = {}, Ref<ProjectFolder> coreFolder = nullptr);
		void PushFile(Ref<RemoteFile> file, const std::vector<std::pair<std::string, std::string>>& extraFields = {});
		void PushFolder(Ref<RemoteFolder> folder, const std::vector<std::pair<std::string, std::string>>& extraFields = {});
		void DeleteFolder(const Ref<RemoteFolder> folder);
		void DeleteFile(const Ref<RemoteFile> file);
		Ref<RemoteFolder> GetFolderById(const std::string& id);
		std::vector<Ref<CollabPermission>> GetGroupPermissions();
		std::vector<Ref<CollabPermission>> GetUserPermissions();
		Ref<CollabPermission> GetPermissionById(const std::string& id);
		void PullGroupPermissions(std::function<bool(size_t, size_t)> progress = {});
		void PullUserPermissions(std::function<bool(size_t, size_t)> progress = {});
		Ref<CollabPermission> CreateGroupPermission(int groupId, BNCollaborationPermissionLevel level, std::function<bool(size_t, size_t)> progress = {});
		Ref<CollabPermission> CreateUserPermission(const std::string& userId, BNCollaborationPermissionLevel level, std::function<bool(size_t, size_t)> progress = {});
		void PushPermission(Ref<CollabPermission> permission, const std::vector<std::pair<std::string, std::string>>& extraFields = {});
		void DeletePermission(Ref<CollabPermission> permission);
		bool CanUserView(const std::string& username);
		bool CanUserEdit(const std::string& username);
		bool CanUserAdmin(const std::string& username);
	};

	class AnalysisMergeConflict : public CoreRefCountObject<BNAnalysisMergeConflict, BNNewAnalysisMergeConflictReference, BNFreeAnalysisMergeConflict>
	{
	public:
		AnalysisMergeConflict(BNAnalysisMergeConflict* conflict);

		std::string GetType();
		BNMergeConflictDataType GetDataType();
		std::optional<nlohmann::json> GetBase();
		std::optional<nlohmann::json> GetFirst();
		std::optional<nlohmann::json> GetSecond();

		Ref<FileMetadata> GetBaseFile();
		Ref<FileMetadata> GetFirstFile();
		Ref<FileMetadata> GetSecondFile();

		Ref<Snapshot> GetBaseSnapshot();
		Ref<Snapshot> GetFirstSnapshot();
		Ref<Snapshot> GetSecondSnapshot();

		template<typename T> T GetPathItem(const std::string& key);

		bool Success(std::nullopt_t value);
		bool Success(std::optional<const nlohmann::json*> value);
		bool Success(const std::optional<nlohmann::json>& value);
	};

	template<> std::any AnalysisMergeConflict::GetPathItem<std::any>(const std::string& path);
	template<> std::string AnalysisMergeConflict::GetPathItem<std::string>(const std::string& path);
	template<> uint64_t AnalysisMergeConflict::GetPathItem<uint64_t>(const std::string& path);
	template<> nlohmann::json AnalysisMergeConflict::GetPathItem<nlohmann::json>(const std::string& path);

	class TypeArchiveMergeConflict : public CoreRefCountObject<BNTypeArchiveMergeConflict, BNNewTypeArchiveMergeConflictReference, BNFreeTypeArchiveMergeConflict>
	{
	public:
		TypeArchiveMergeConflict(BNTypeArchiveMergeConflict* conflict);

		Ref<TypeArchive> GetTypeArchive();
		std::string GetTypeId();
		std::string GetBaseSnapshotId();
		std::string GetFirstSnapshotId();
		std::string GetSecondSnapshotId();

		bool Success(const std::string& value);
	};

	class CollabChangeset : public CoreRefCountObject<BNCollaborationChangeset, BNNewCollaborationChangesetReference, BNFreeCollaborationChangeset>
	{
	public:
		CollabChangeset(BNCollaborationChangeset* changeset);

		Ref<Database> GetDatabase();
		Ref<RemoteFile> GetFile();
		std::vector<int64_t> GetSnapshotIds();
		Ref<CollabUser> GetAuthor();
		std::string GetName();
		void SetName(const std::string& name);
	};

	typedef std::function<bool(Ref<CollabChangeset>)> NameChangesetFunction;
	typedef std::function<bool(size_t, size_t)> ProgressFunction;
	typedef std::function<bool(const std::unordered_map<std::string, Ref<AnalysisMergeConflict>>& conflicts)> AnalysisConflictHandler;
	typedef std::function<bool(const std::vector<Ref<TypeArchiveMergeConflict>>& conflicts)> TypeArchiveConflictHandler;

	Ref<Remote> GetActiveRemote();
	void SetActiveRemote(Ref<Remote> remote);
	bool StoreDataInKeychain(const std::string& key, const std::map<std::string, std::string>& data);
	bool HasDataInKeychain(const std::string& key);
	std::optional<std::map<std::string, std::string>> GetDataFromKeychain(const std::string& key);
	bool DeleteDataFromKeychain(const std::string& key);

	void LoadRemotes();
	std::vector<Ref<Remote>> GetRemotes();
	Ref<Remote> GetRemoteById(const std::string& remoteId);
	Ref<Remote> GetRemoteByAddress(const std::string& remoteAddress);
	Ref<Remote> GetRemoteByName(const std::string& name);
	Ref<Remote> CreateRemote(const std::string& name, const std::string& address);
	void RemoveRemote(const Ref<Remote>& remote);

	/*!
	    Completely sync a database, pushing/pulling/merging/applying changes
	    \param database Database to sync
	    \param file Remote File to sync with
	    \param conflictHandler Function to call to resolve snapshot conflicts
	    \param progress Function to call for progress updates
	    \param nameChangeset Function to call for naming a pushed changeset, if necessary
	    \throws SyncException If there is an error syncing
	 */
	void SyncDatabase(Ref<Database> database, Ref<RemoteFile> file, AnalysisConflictHandler conflictHandler, std::function<bool(size_t, size_t)> progress = {}, NameChangesetFunction nameChangeset = [](Ref<CollabChangeset>){ return true; });

	/*!
	    Completely sync a type archive, pushing/pulling/merging/applying changes
	    \param archive Type archive
	    \param file Remote file
	    \param progress Function to call for progress updates
	 */
	void SyncTypeArchive(Ref<TypeArchive> archive, Ref<RemoteFile> file, TypeArchiveConflictHandler conflictHandler, ProgressFunction progress = {});

	/*!
	    Merge a pair of snapshots and create a new snapshot with the result.
	    \param first First snapshot to merge
	    \param second Second snapshot to merge
	    \param conflictHandler Function to call when merge conflicts are encountered
	    \param progress Function to call for progress updates and cancelling
	    \throws SyncException If the snapshots have no common ancestor
	    \return Result snapshot
	 */
	Ref<Snapshot> MergeSnapshots(Ref<Snapshot> first, Ref<Snapshot> second, AnalysisConflictHandler conflictHandler, ProgressFunction progress);

	/*!
	    Get the default directory path for a remote Project. This is based off the Setting for
	    collaboration.directory, the project's id, and the project's remote's id.
	    \param project Remote Project
	    \return Default project path
	 */
	std::string DefaultProjectPath(Ref<RemoteProject> project);

	/*!
	    Get the default filepath for a remote File. This is based off the Setting for
	    collaboration.directory, the file's id, the file's project's id, and the file's
	    remote's id.
	    \param file Remote File
	    \return Default file path
	 */
	std::string DefaultFilePath(Ref<RemoteFile> file);

		/*!
	    Download a file from its remote, saving all snapshots to a database in the
	    specified location. Returns a FileContext for opening the file later.
	    \param file Remote File to download and open
	    \param dbPath File path for saved database
	    \param progress Function to call for progress updates
	    \return FileContext for opening
	    \throws SyncException If there was an error downloading
	 */
	Ref<FileMetadata> DownloadFile(Ref<RemoteFile> file, const std::string& dbPath, ProgressFunction progress = {});

	/*!
	    Add a snapshot to the id map in a database
	    \param localSnapshot Local snapshot, will use this snapshot's database
	    \param remoteSnapshot Remote snapshot
	 */
	void AssignSnapshotMap(Ref<Snapshot> localSnapshot, Ref<CollabSnapshot> remoteSnapshot);

	/*!
	    Upload a file, with database, to the remote under the given project
	    \param metadata Local file with database
	    \param project Remote project under which to place the new file
	    \param progress Function to call for progress updates
	    \param nameChangeset Function to call for naming a pushed changeset, if necessary
	    \param folderId Id of folder that will contain the resulting file
	    \return Remote File created
	    \throws SyncException If there was an error uploading
	 */
	Ref<RemoteFile> UploadDatabase(Ref<FileMetadata> metadata, Ref<RemoteProject> project, Ref<RemoteFolder> folder, ProgressFunction progress, NameChangesetFunction nameChangeset = {});

	/*!
	    Get the remote author of a local snapshot
	    \param database Parent database
	    \param snapshot Snapshot to query
	 */
	std::optional<std::string> GetSnapshotAuthor(Ref<Database> database, Ref<Snapshot> snapshot);

	/*!
	    Test if a database is valid for use in collaboration
	    \param database Database
	    \return True if database is valid
	 */
	bool IsCollaborationDatabase(Ref<Database> database);

	/*!
	    Get the Remote for a Database
	    \param database BN database, potentially with collaboration metadata
	    \return Remote from one of the connected remotes, or nullptr if not found
	 */
	Ref<Remote> GetRemoteForLocalDatabase(Ref<Database> database);

	/*!
	    Get the Remote Project for a Database
	    \param database BN database, potentially with collaboration metadata
	    \return Remote project from one of the connected remotes, or nullptr if not found
	            or if projects are not pulled
	 */
	Ref<RemoteProject> GetRemoteProjectForLocalDatabase(Ref<Database> database);

	/*!
	    Get the Remote File for a Database
	    \param database BN database, potentially with collaboration metadata
	    \return Remote file from one of the connected remotes, or nullptr if not found
	            or if files are not pulled
	 */
	Ref<RemoteFile> GetRemoteFileForLocalDatabase(Ref<Database> database);

	/*!
	    Pull updated snapshots from the remote. Merge local changes with remote changes and
	    potentially create a new snapshot for unsaved changes, named via nameChangeset.
	    \param database Database to pull
	    \param file Remote File to pull to
	    \param conflictHandler Function to call to resolve snapshot conflicts
	    \param progress Function to call for progress updates
	    \param nameChangeset Function to call for naming a pushed changeset, if necessary
	    \return Number of snapshots pulled
	    \throws SyncException If there is an error pulling
	 */
	size_t PullDatabase(Ref<Database> database, Ref<RemoteFile> file, AnalysisConflictHandler conflictHandler, ProgressFunction progress = {}, NameChangesetFunction nameChangeset = {});

	/*!
	    Merge all leaf snapshots in a database down to a single leaf snapshot.
	    \param database Database to merge
	    \param progress Function to call for progress updates
	    \param conflictHandler Function to call to resolve snapshot conflicts
	    \throws SyncException If there was an error merging
	 */
	void MergeDatabase(Ref<Database> database, AnalysisConflictHandler conflictHandler, ProgressFunction progress = {});

	/*!
	    Push locally added snapshots to the remote
	    \param database Database to push
	    \param file Remote File to push to
	    \param progress Function to call for progress updates
	    \return Number of snapshots pushed
	    \throws SyncException If there is an error pushing
	 */
	size_t PushDatabase(Ref<Database> database, Ref<RemoteFile> file, ProgressFunction progress = {});

	/*!
	    Print debug information about a database to stdout
	    \param database Database to dump
	 */
	void DumpDatabase(Ref<Database> database);

	/*!
	    Ignore a snapshot from database syncing operations
	    TODO: This is in place of deleting differential snapshots (which is unimplemented)
	    \param database Parent database
	    \param snapshot Snapshot to ignore
	 */
	void IgnoreSnapshot(Ref<Database> database, Ref<Snapshot> snapshot);

	/*!
	    Test if a snapshot is ignored from the database
	    TODO: This is in place of deleting differential snapshots (which is unimplemented)
	    \param database Parent database
	    \param snapshot Snapshot to test
	    \return True if snapshot should be ignored
	 */
	bool IsSnapshotIgnored(Ref<Database> database, Ref<Snapshot> snapshot);

	/*!
	    Get the remote snapshot associated with a local snapshot (if it exists)
	    \param snapshot Local snapshot
	    \return Remote snapshot if it exists, or nullptr if not
	 */
	Ref<CollabSnapshot> GetRemoteSnapshotFromLocal(Ref<Snapshot> snapshot);

	/*!
	    Get the local snapshot associated with a remote snapshot (if it exists)
	    \param snapshot Remote snapshot
	    \param database Local database to search
	    \return Snapshot reference if it exists, or nullptr reference if not
	 */
	Ref<Snapshot> GetLocalSnapshotFromRemote(Ref<CollabSnapshot> snapshot, Ref<Database> database);


	/*!
	    Test if a type archive is valid for use in collaboration
	    \param archive Type archive
	    \return True if archive is valid
	 */
	bool IsCollaborationTypeArchive(Ref<TypeArchive> archive);


	/*!
	    Get the Remote for a Type Archive
	    \param archive Local Type Archive, potentially with collaboration metadata
	    \return Remote from one of the connected remotes, or nullptr if not found
	 */
	Ref<Remote> GetRemoteForLocalTypeArchive(Ref<TypeArchive> archive);


	/*!
	    Get the Remote Project for a Type Archive
	    \param archive Local Type Archive, potentially with collaboration metadata
	    \return Remote project from one of the connected remotes, or nullptr if not found
	            or if projects are not pulled
	 */
	Ref<RemoteProject> GetRemoteProjectForLocalTypeArchive(Ref<TypeArchive> archive);


	/*!
	    Get the Remote File for a Type Archive
	    \param archive Local Type Archive, potentially with collaboration metadata
	    \return Remote file from one of the connected remotes, or nullptr if not found
	            or if files are not pulled
	 */
	Ref<RemoteFile> GetRemoteFileForLocalTypeArchive(Ref<TypeArchive> archive);


	/*!
	    Get the remote snapshot associated with a local snapshot (if it exists) in a Type Archive
	    \param archive Local Type Archive
	    \param snapshotId Local snapshot id
	    \return Remote snapshot if it exists, or nullptr if not
	 */
	Ref<CollabSnapshot> GetRemoteSnapshotFromLocalTypeArchive(Ref<TypeArchive> archive, const std::string& snapshotId);


	/*!
	    Get the local snapshot associated with a remote snapshot (if it exists) in a Type Archive
	    \param snapshot Remote snapshot
	    \param archive Local type archive to search
	    \return Snapshot id if it exists, or nullopt if not
	 */
	std::optional<std::string> GetLocalSnapshotFromRemoteTypeArchive(Ref<CollabSnapshot> snapshot, Ref<TypeArchive> archive);

	/*!
	    Test if a snapshot is ignored from the archive
	    \param archive Type archive
	    \param snapshot Snapshot to test
	    \return True if snapshot should be ignored
	 */
	bool IsTypeArchiveSnapshotIgnored(Ref<TypeArchive> archive, const std::string& snapshot);

	/*!
	    Download a type archive from its remote, saving all snapshots to an archive in the
	    specified location. Returns a Ref<TypeArchive> for using later.
	    \param file Remote Type Archive file to download and open
	    \param dbPath File path for saved archive
	    \param progress Function to call for progress updates
	    \return TypeArchive for using
	    \throws SyncException If there was an error downloading
	 */
	Ref<TypeArchive> DownloadTypeArchive(Ref<RemoteFile> file, const std::string& dbPath, ProgressFunction progress = {});

	/*!
	    Upload a type archive
	    \param archive Type archive
	    \param project Containing project
	    \param folder Containing folder
	    \param progress Function to call for progress updates
	    \param coreFile Core ProjectFile structure, if archive is in a project
	    \return Created file
	 */
	Ref<RemoteFile> UploadTypeArchive(Ref<TypeArchive> archive, Ref<RemoteProject> project, Ref<RemoteFolder> folder = nullptr, ProgressFunction progress = {}, Ref<ProjectFile> coreFile = nullptr);

	/*!
	    Push locally added snapshots to the remote
	    \param archive Type Archive to push
	    \param file Remote File to push to
	    \param progress Function to call for progress updates
	    \return Number of snapshots pushed
	    \throws SyncException If there is an error pushing
	 */
	size_t PushTypeArchive(Ref<TypeArchive> archive, Ref<RemoteFile> file, ProgressFunction progress = {});

	/*!
	    Pull updated snapshots from the remote. Merge local changes with remote changes and
	    potentially create a new snapshot for unsaved changes, named via nameChangeset.
	    \param archive Type Archive to pull
	    \param file Remote File to pull to
	    \param conflictHandler Function to call to resolve snapshot conflicts
	    \param progress Function to call for progress updates
	    \param nameChangeset Function to call for naming a pushed changeset, if necessary
	    \return Number of snapshots pulled
	    \throws SyncException If there is an error pulling
	 */
	size_t PullTypeArchive(Ref<TypeArchive> archive, Ref<RemoteFile> file, std::function<bool(const std::vector<Ref<TypeArchiveMergeConflict>>)> conflictHandler, ProgressFunction progress = {});

	void DownloadDatabaseForFile(Ref<RemoteFile> file, const std::string& dbPath, bool force, ProgressFunction progress = {});

	/*!
	    Set the remote author of a local snapshot (does not upload)
	    \param database Parent database
	    \param snapshot Snapshot to edit
	    \param author Target author
	 */
	void SetSnapshotAuthor(Ref<Database> database, Ref<Snapshot> snapshot, const std::string& author);

} // namespace BinaryNinja::Collaboration
