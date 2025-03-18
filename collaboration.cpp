// Copyright (c) 2015-2024 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "http.h"

using namespace BinaryNinja;
using namespace BinaryNinja::Collaboration;

//TODO: this should really be split up and put in a collaboration directory


bool BinaryNinja::Collaboration::IsCollaborationDatabase(Ref<Database> database)
{
	return BNCollaborationIsCollaborationDatabase(database->m_object);
}


Ref<Remote> BinaryNinja::Collaboration::GetRemoteForLocalDatabase(Ref<Database> database)
{
	BNRemote* val;
	if (!BNCollaborationGetRemoteForLocalDatabase(database->m_object, &val))
		throw RemoteException("Failed to get remote for local database");
	if (val == nullptr)
		return nullptr;
	return new Remote(val);
}


Ref<RemoteProject> BinaryNinja::Collaboration::GetRemoteProjectForLocalDatabase(Ref<Database> database)
{
	BNRemoteProject* val;
	if (!BNCollaborationGetRemoteProjectForLocalDatabase(database->m_object, &val))
		throw RemoteException("Failed to get remote project for local database");
	if (val == nullptr)
		return nullptr;
	return new RemoteProject(val);
}


Ref<RemoteFile> BinaryNinja::Collaboration::GetRemoteFileForLocalDatabase(Ref<Database> database)
{
	BNRemoteFile* val;
	if (!BNCollaborationGetRemoteFileForLocalDatabase(database->m_object, &val))
		throw RemoteException("Failed to get remote file for local database");

	if (val == nullptr)
		return nullptr;
	return new RemoteFile(val);
}


size_t BinaryNinja::Collaboration::PullDatabase(Ref<Database> database, Ref<RemoteFile> file, AnalysisConflictHandler conflictHandler, ProgressFunction progress, NameChangesetFunction nameChangeset)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	DatabaseConflictHandlerContext chctxt;
	chctxt.callback = conflictHandler;

	NameChangesetContext ncctxt;
	ncctxt.callback = nameChangeset;

	size_t count = 0;

	if (!BNCollaborationPullDatabase(database->m_object, file->m_object, &count,
		DatabaseConflictHandlerCallback, &chctxt,
		ProgressCallback, &pctxt,
		NameChangesetCallback, &ncctxt)
	)
		throw SyncException("Failed to pull database");
	return count;
}


void BinaryNinja::Collaboration::MergeDatabase(Ref<Database> database, AnalysisConflictHandler conflictHandler, ProgressFunction progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	DatabaseConflictHandlerContext chctxt;
	chctxt.callback = conflictHandler;

	if (!BNCollaborationMergeDatabase(database->m_object, DatabaseConflictHandlerCallback, &chctxt, ProgressCallback, &pctxt))
		throw SyncException("Failed to merge database");
}


size_t BinaryNinja::Collaboration::PushDatabase(Ref<Database> database, Ref<RemoteFile> file, ProgressFunction progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	size_t count = 0;

	if (!BNCollaborationPushDatabase(database->m_object, file->m_object, &count, ProgressCallback, &pctxt))
		throw SyncException("Failed to push database");

	return count;
}


void BinaryNinja::Collaboration::DumpDatabase(Ref<Database> database)
{
	BNCollaborationDumpDatabase(database->m_object);
}


void BinaryNinja::Collaboration::IgnoreSnapshot(Ref<Database> database, Ref<Snapshot> snapshot)
{
	BNCollaborationIgnoreSnapshot(database->m_object, snapshot->m_object);
}


bool BinaryNinja::Collaboration::IsSnapshotIgnored(Ref<Database> database, Ref<Snapshot> snapshot)
{
	return BNCollaborationIsSnapshotIgnored(database->m_object, snapshot->m_object);
}


Ref<CollabSnapshot> BinaryNinja::Collaboration::GetRemoteSnapshotFromLocal(Ref<Snapshot> snapshot)
{
	BNCollaborationSnapshot* val;
	if (!BNCollaborationGetRemoteSnapshotFromLocal(snapshot->m_object, &val))
		throw RemoteException("Failed to get remote snapshot for local snapshot");
	if (val == nullptr)
		return nullptr;
	return new CollabSnapshot(val);
}


Ref<Snapshot> BinaryNinja::Collaboration::GetLocalSnapshotFromRemote(Ref<CollabSnapshot> snapshot, Ref<Database> database)
{
	BNSnapshot* val;
	if (!BNCollaborationGetLocalSnapshotFromRemote(snapshot->m_object, database->m_object, &val))
		throw RemoteException("Failed to get local snapshot for remote snapshot");
	if (val == nullptr)
		return nullptr;
	return new Snapshot(val);
}


bool BinaryNinja::Collaboration::IsCollaborationTypeArchive(Ref<TypeArchive> archive)
{
	return BNCollaborationIsCollaborationTypeArchive(archive->m_object);
}


Ref<Remote> BinaryNinja::Collaboration::GetRemoteForLocalTypeArchive(Ref<TypeArchive> archive)
{
	BNRemote* val = BNCollaborationGetRemoteForLocalTypeArchive(archive->m_object);
	if (val == nullptr)
		return nullptr;
	return new Remote(val);
}


Ref<RemoteProject> BinaryNinja::Collaboration::GetRemoteProjectForLocalTypeArchive(Ref<TypeArchive> archive)
{
	BNRemoteProject* val = BNCollaborationGetRemoteProjectForLocalTypeArchive(archive->m_object);
	if (val == nullptr)
		return nullptr;
	return new RemoteProject(val);
}


Ref<RemoteFile> BinaryNinja::Collaboration::GetRemoteFileForLocalTypeArchive(Ref<TypeArchive> archive)
{
	BNRemoteFile* val = BNCollaborationGetRemoteFileForLocalTypeArchive(archive->m_object);
	if (val == nullptr)
		return nullptr;
	return new RemoteFile(val);
}


Ref<CollabSnapshot> BinaryNinja::Collaboration::GetRemoteSnapshotFromLocalTypeArchive(Ref<TypeArchive> archive, const std::string& snapshotId)
{
	BNCollaborationSnapshot* val = BNCollaborationGetRemoteSnapshotFromLocalTypeArchive(archive->m_object, snapshotId.c_str());
	if (val == nullptr)
		return nullptr;
	return new CollabSnapshot(val);
}


std::optional<std::string> BinaryNinja::Collaboration::GetLocalSnapshotFromRemoteTypeArchive(Ref<CollabSnapshot> snapshot, Ref<TypeArchive> archive)
{
	char* val = BNCollaborationGetLocalSnapshotFromRemoteTypeArchive(snapshot->m_object, archive->m_object);
	if (val == nullptr)
		return {};
	std::string out = val;
	BNFreeString(val);
	return out;
}


bool BinaryNinja::Collaboration::IsTypeArchiveSnapshotIgnored(Ref<TypeArchive> archive, const std::string& snapshot)
{
	return BNCollaborationIsTypeArchiveSnapshotIgnored(archive->m_object, snapshot.c_str());
}


Ref<TypeArchive> BinaryNinja::Collaboration::DownloadTypeArchive(Ref<RemoteFile> file, const std::string& dbPath, ProgressFunction progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNTypeArchive* val;
	if (!BNCollaborationDownloadTypeArchive(file->m_object, dbPath.c_str(), ProgressCallback, &pctxt, &val))
		throw RemoteException("Failed to download type archive");

	if (val == nullptr)
		return nullptr;
	return new TypeArchive(val);
}


Ref<RemoteFile> BinaryNinja::Collaboration::UploadTypeArchive(Ref<TypeArchive> archive, Ref<RemoteProject> project, Ref<RemoteFolder> folder, ProgressFunction progress, Ref<ProjectFile> coreFile)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteFile* val;
	if (!BNCollaborationUploadTypeArchive(archive->m_object, project->m_object, folder ? folder->m_object : nullptr, ProgressCallback, &pctxt, coreFile ? coreFile->m_object : nullptr, &val))
		throw RemoteException("Failed to upload type archive");

	if (val == nullptr)
		return nullptr;
	return new RemoteFile(val);
}


size_t BinaryNinja::Collaboration::PushTypeArchive(Ref<TypeArchive> archive, Ref<RemoteFile> file, ProgressFunction progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	size_t count = 0;
	if (!BNCollaborationPushTypeArchive(archive->m_object, file->m_object, &count, ProgressCallback, &pctxt))
		throw RemoteException("Failed to push type archive for file");
	return count;
}


size_t BinaryNinja::Collaboration::PullTypeArchive(Ref<TypeArchive> archive, Ref<RemoteFile> file, std::function<bool(const std::vector<Ref<TypeArchiveMergeConflict>>)> conflictHandler, ProgressFunction progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	TypeArchiveConflictHandlerContext chctxt;
	chctxt.callback = conflictHandler;

	size_t count = 0;
	if (!BNCollaborationPullTypeArchive(archive->m_object, file->m_object, &count, TypeArchiveConflictHandlerCallback, &chctxt, ProgressCallback, &pctxt))
		throw RemoteException("Failed to pull type archive for file");
	return count;
}


void BinaryNinja::Collaboration::DownloadDatabaseForFile(Ref<RemoteFile> file, const std::string& dbPath, bool force, ProgressFunction progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	if (!BNCollaborationDownloadDatabaseForFile(file->m_object, dbPath.c_str(), force, ProgressCallback, &pctxt))
		throw RemoteException("Failed to download database for file");
}


void BinaryNinja::Collaboration::SetSnapshotAuthor(Ref<Database> database, Ref<Snapshot> snapshot, const std::string& author)
{
	BNCollaborationSetSnapshotAuthor(database->m_object, snapshot->m_object, author.c_str());
}


Ref<Remote> BinaryNinja::Collaboration::GetActiveRemote()
{
	BNRemote* remote = BNCollaborationGetActiveRemote();
	if (remote == nullptr)
		return nullptr;
	return new Remote(remote);
}


void BinaryNinja::Collaboration::SetActiveRemote(Ref<Remote> remote)
{
	BNCollaborationSetActiveRemote(remote ? remote->m_object : nullptr);
}


bool BinaryNinja::Collaboration::StoreDataInKeychain(const std::string& key, const std::map<std::string, std::string>& data)
{
	const char** dataKeys = new const char*[data.size()];
	const char** dataValues = new const char*[data.size()];

	size_t i = 0;
	for (const auto& entry : data)
	{
		dataKeys[i] = entry.first.c_str();
		dataValues[i] = entry.second.c_str();
		i++;
	}

	bool result = BNCollaborationStoreDataInKeychain(key.c_str(), dataKeys, dataValues, data.size());
	delete[] dataKeys;
	delete[] dataValues;
	return result;
}


bool BinaryNinja::Collaboration::HasDataInKeychain(const std::string& key)
{
	return BNCollaborationHasDataInKeychain(key.c_str());
}


std::optional<std::map<std::string, std::string>> BinaryNinja::Collaboration::GetDataFromKeychain(const std::string& key)
{
	char** keys;
	char** values;
	size_t count = BNCollaborationGetDataFromKeychain(key.c_str(), &keys, &values);
	if (count == 0)
		return {};

	std::map<std::string, std::string> results;
	for (size_t i = 0; i < count; i++)
	{
		results[keys[i]] = values[i];
	}

	BNFreeStringList(keys, count);
	BNFreeStringList(values, count);

	return results;
}


bool BinaryNinja::Collaboration::DeleteDataFromKeychain(const std::string& key)
{
	return BNCollaborationDeleteDataFromKeychain(key.c_str());
}


void BinaryNinja::Collaboration::LoadRemotes()
{
	BNCollaborationLoadRemotes();
}


std::vector<Ref<Remote>> BinaryNinja::Collaboration::GetRemotes()
{
	size_t count = 0;
	BNRemote** remotes = BNCollaborationGetRemotes(&count);
	std::vector<Ref<Remote>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new Remote(BNNewRemoteReference(remotes[i])));
	}
	BNFreeRemoteList(remotes, count);
	return out;
}


Ref<Remote> BinaryNinja::Collaboration::GetRemoteById(const std::string& remoteId)
{
	BNRemote* remote = BNCollaborationGetRemoteById(remoteId.c_str());
	if (!remote)
		return nullptr;
	return new Remote(remote);
}


Ref<Remote> BinaryNinja::Collaboration::GetRemoteByAddress(const std::string& remoteAddress)
{
	BNRemote* remote = BNCollaborationGetRemoteByAddress(remoteAddress.c_str());
	if (!remote)
		return nullptr;
	return new Remote(remote);
}


Ref<Remote> BinaryNinja::Collaboration::GetRemoteByName(const std::string& name)
{
	BNRemote* remote = BNCollaborationGetRemoteByName(name.c_str());
	if (!remote)
		return nullptr;
	return new Remote(remote);
}


Ref<Remote> BinaryNinja::Collaboration::CreateRemote(const std::string& name, const std::string& address)
{
	BNRemote* remote = BNCollaborationCreateRemote(name.c_str(), address.c_str());
	if (!remote)
		return nullptr;
	return new Remote(remote);
}


void BinaryNinja::Collaboration::RemoveRemote(const Ref<Remote>& remote)
{
	BNCollaborationRemoveRemote(remote->m_object);
}


bool BinaryNinja::Collaboration::DatabaseConflictHandlerCallback(void* ctxt, const char** keys, BNAnalysisMergeConflict** conflicts, size_t count)
{
	DatabaseConflictHandlerContext* chctxt = reinterpret_cast<DatabaseConflictHandlerContext*>(ctxt);
	if (!chctxt->callback)
		return true;
	std::unordered_map<std::string, Ref<AnalysisMergeConflict>> conflictMap;
	for (size_t i = 0; i < count; i++)
	{
		conflictMap[keys[i]] = new AnalysisMergeConflict(conflicts[i]);
	}
	return chctxt->callback(conflictMap);
};


bool BinaryNinja::Collaboration::TypeArchiveConflictHandlerCallback(void* ctxt, BNTypeArchiveMergeConflict** conflicts, size_t count)
{
	TypeArchiveConflictHandlerContext* chctxt = reinterpret_cast<TypeArchiveConflictHandlerContext*>(ctxt);
	if (!chctxt->callback)
		return true;
	std::vector<Ref<TypeArchiveMergeConflict>> conflictVec;
	for (size_t i = 0; i < count; i++)
	{
		conflictVec.push_back(new TypeArchiveMergeConflict(conflicts[i]));
	}
	return chctxt->callback(conflictVec);
}


bool BinaryNinja::Collaboration::NameChangesetCallback(void* ctxt, BNCollaborationChangeset* changeset)
{
	NameChangesetContext* ncctxt = reinterpret_cast<NameChangesetContext*>(ctxt);
	if (!ncctxt->callback)
		return true;
	return ncctxt->callback(new CollabChangeset(changeset));
};


void BinaryNinja::Collaboration::SyncDatabase(Ref<Database> database, Ref<RemoteFile> file, std::function<bool(const std::unordered_map<std::string, Ref<AnalysisMergeConflict>>& conflicts)> conflictHandler, std::function<bool(size_t, size_t)> progress, NameChangesetFunction nameChangeset)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	DatabaseConflictHandlerContext chctxt;
	chctxt.callback = conflictHandler;

	NameChangesetContext ncctxt;
	ncctxt.callback = nameChangeset;

	BNCollaborationSyncDatabase(database->m_object, file->m_object,
		DatabaseConflictHandlerCallback, &chctxt,
		ProgressCallback, &pctxt,
		NameChangesetCallback, &ncctxt
	);
}


void BinaryNinja::Collaboration::SyncTypeArchive(Ref<TypeArchive> archive, Ref<RemoteFile> file, std::function<bool(const std::vector<Ref<TypeArchiveMergeConflict>>& conflicts)> conflictHandler, ProgressFunction progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	TypeArchiveConflictHandlerContext chctxt;
	chctxt.callback = conflictHandler;

	BNCollaborationSyncTypeArchive(archive->m_object, file->m_object,
		TypeArchiveConflictHandlerCallback, &chctxt,
		ProgressCallback, &pctxt
	);
}


Ref<Snapshot> BinaryNinja::Collaboration::MergeSnapshots(Ref<Snapshot> first, Ref<Snapshot> second, std::function<bool(const std::unordered_map<std::string, Ref<AnalysisMergeConflict>>& conflicts)> conflictHandler, ProgressFunction progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	DatabaseConflictHandlerContext chctxt;
	chctxt.callback = conflictHandler;

	BNSnapshot* snapshot = BNCollaborationMergeSnapshots(first->m_object, second->m_object, DatabaseConflictHandlerCallback, &chctxt, ProgressCallback, &pctxt);
	if (snapshot == nullptr)
		throw SyncException("Failed to merge snapshots");

	return new Snapshot(snapshot);
}


std::string BinaryNinja::Collaboration::DefaultProjectPath(Ref<RemoteProject> project)
{
	char* path = BNCollaborationDefaultProjectPath(project->m_object);
	std::string result = path;
	BNFreeString(path);
	return result;
}


std::string BinaryNinja::Collaboration::DefaultFilePath(Ref<RemoteFile> file)
{
	char* path = BNCollaborationDefaultFilePath(file->m_object);
	std::string result = path;
	BNFreeString(path);
	return result;
}


Ref<FileMetadata> BinaryNinja::Collaboration::DownloadFile(Ref<RemoteFile> file, const std::string& dbPath, ProgressFunction progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNFileMetadata* metadata = BNCollaborationDownloadFile(file->m_object, dbPath.c_str(), ProgressCallback, &pctxt);
	if (metadata == nullptr)
		return nullptr;
	return new FileMetadata(metadata);
}


Ref<RemoteFile> BinaryNinja::Collaboration::UploadDatabase(Ref<FileMetadata> metadata, Ref<RemoteProject> project, Ref<RemoteFolder> folder, ProgressFunction progress, NameChangesetFunction nameChangeset)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	NameChangesetContext ncctxt;
	ncctxt.callback = nameChangeset;

	BNRemoteFile* file = BNCollaborationUploadDatabase(
		metadata->m_object,
		project->m_object,
		folder ? folder->m_object : nullptr,
		ProgressCallback, &pctxt,
		NameChangesetCallback, &ncctxt
	);

	if (file == nullptr)
		return nullptr;
	return new RemoteFile(file);
}


void BinaryNinja::Collaboration::AssignSnapshotMap(Ref<Snapshot> localSnapshot, Ref<CollabSnapshot> remoteSnapshot)
{
	if (!BNCollaborationAssignSnapshotMap(localSnapshot->m_object, remoteSnapshot->m_object))
		throw SyncException("Failed to assign snapshot map");
}


Remote::Remote(BNRemote* remote)
{
	m_object = remote;
}


std::string Remote::GetUniqueId()
{
	char* id = BNRemoteGetUniqueId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::string Remote::GetName()
{
	char* name = BNRemoteGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


std::string Remote::GetAddress()
{
	char* addr = BNRemoteGetAddress(m_object);
	std::string result = addr;
	BNFreeString(addr);
	return result;
}


bool Remote::HasLoadedMetadata()
{
	return BNRemoteHasLoadedMetadata(m_object);
}


bool Remote::IsConnected()
{
	return BNRemoteIsConnected(m_object);
}


std::string Remote::GetUsername()
{
	char* username = BNRemoteGetUsername(m_object);
	std::string result = username;
	BNFreeString(username);
	return result;
}


std::string Remote::GetToken()
{
	char* username = BNRemoteGetToken(m_object);
	std::string result = username;
	BNFreeString(username);
	return result;
}


int Remote::GetServerVersion()
{
	return BNRemoteGetServerVersion(m_object);
}


std::string Remote::GetServerBuildVersion()
{
	char* buildVersion = BNRemoteGetServerBuildVersion(m_object);
	std::string result = buildVersion;
	BNFreeString(buildVersion);
	return result;
}


std::string Remote::GetServerBuildId()
{
	char* buildId = BNRemoteGetServerBuildId(m_object);
	std::string result = buildId;
	BNFreeString(buildId);
	return result;
}


std::vector<std::pair<std::string, std::string>> Remote::GetAuthBackends()
{
	char** methods;
	char** names;
	size_t count;
	if (!BNRemoteGetAuthBackends(m_object, &methods, &names, &count))
		throw RemoteException("Failed to get authentication backends");

	std::vector<std::pair<std::string, std::string>> results;
	for (size_t i = 0; i < count; i++)
	{
		results.push_back({methods[i], names[i]});
	}

	BNFreeStringList(methods, count);
	BNFreeStringList(names, count);

	return results;
}


bool Remote::HasPulledProjects()
{
	return BNRemoteHasPulledProjects(m_object);
}


bool Remote::HasPulledUsers()
{
	return BNRemoteHasPulledUsers(m_object);
}


bool Remote::HasPulledGroups()
{
	return BNRemoteHasPulledGroups(m_object);
}


bool Remote::IsAdmin()
{
	return BNRemoteIsAdmin(m_object);
}


bool Remote::IsEnterprise()
{
	return BNRemoteIsEnterprise(m_object);
}


bool Remote::LoadMetadata()
{
	return BNRemoteLoadMetadata(m_object);
}


std::string Remote::RequestAuthenticationToken(const std::string& username, const std::string& password)
{
	char* token = BNRemoteRequestAuthenticationToken(m_object, username.c_str(), password.c_str());
	if (token == nullptr)
		throw RemoteException("Failed to authenticate");
	std::string result = token;
	BNFreeString(token);
	return result;
}


void Remote::Connect(const std::string& username, const std::string& token)
{
	BNRemoteConnect(m_object, username.c_str(), token.c_str());
}


void Remote::Disconnect()
{
	BNRemoteDisconnect(m_object);
}


std::vector<Ref<RemoteProject>> Remote::GetProjects()
{
	size_t count = 0;
	BNRemoteProject** projects = BNRemoteGetProjects(m_object, &count);
	std::vector<Ref<RemoteProject>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new RemoteProject(BNNewRemoteProjectReference(projects[i])));
	}
	BNFreeRemoteProjectList(projects, count);
	return out;
}


Ref<RemoteProject> Remote::GetProjectById(const std::string& id)
{
	BNRemoteProject* project = BNRemoteGetProjectById(m_object, id.c_str());
	if (project == nullptr)
		return nullptr;
	return new RemoteProject(project);
}


Ref<RemoteProject> Remote::GetProjectByName(const std::string& name)
{
	BNRemoteProject* project = BNRemoteGetProjectByName(m_object, name.c_str());
	if (project == nullptr)
		return nullptr;
	return new RemoteProject(project);
}


void Remote::PullProjects(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemotePullProjects(m_object, ProgressCallback, &pctxt);
}


Ref<RemoteProject> Remote::CreateProject(const std::string& name, const std::string& description)
{
	BNRemoteProject* project = BNRemoteCreateProject(m_object, name.c_str(), description.c_str());
	if (project == nullptr)
		return nullptr;
	return new RemoteProject(project);
}


Ref<RemoteProject> Remote::ImportLocalProject(Ref<Project> localProject, std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteProject* project = BNRemoteImportLocalProject(m_object, localProject->m_object, ProgressCallback, &pctxt);
	if (project == nullptr)
		return nullptr;
	return new RemoteProject(project);
}


void Remote::PushProject(Ref<RemoteProject> project, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char** fieldKeys = new const char*[extraFields.size()];
	const char** fieldValues = new const char*[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemotePushProject(m_object, project->m_object, fieldKeys, fieldValues, extraFields.size());
	delete[] fieldKeys;
	delete[] fieldValues;
}


void Remote::DeleteProject(const Ref<RemoteProject> project)
{
	BNRemoteDeleteProject(m_object, project->m_object);
}


std::vector<Ref<CollabGroup>> Remote::GetGroups()
{
	size_t count = 0;
	BNCollaborationGroup** groups = BNRemoteGetGroups(m_object, &count);
	std::vector<Ref<CollabGroup>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabGroup(BNNewCollaborationGroupReference(groups[i])));
	}
	BNFreeCollaborationGroupList(groups, count);
	return out;
}


Ref<CollabGroup> Remote::GetGroupById(uint64_t id)
{
	BNCollaborationGroup* group = BNRemoteGetGroupById(m_object, id);
	if (group == nullptr)
		return nullptr;
	return new CollabGroup(group);
}


Ref<CollabGroup> Remote::GetGroupByName(const std::string& name)
{
	BNCollaborationGroup* group = BNRemoteGetGroupByName(m_object, name.c_str());
	if (group == nullptr)
		return nullptr;
	return new CollabGroup(group);
}


std::vector<std::pair<uint64_t, std::string>> Remote::SearchGroups(const std::string& prefix)
{
	uint64_t* ids;
	char** names;
	size_t count;
	if (!BNRemoteSearchGroups(m_object, prefix.c_str(), &ids, &names, &count))
		throw RemoteException("Failed to search groups");

	std::vector<std::pair<uint64_t, std::string>> results;
	for (size_t i = 0; i < count; i++)
	{
		results.push_back({ids[i], names[i]});
	}

	delete[] ids;
	BNFreeStringList(names, count);

	return results;
}


void Remote::PullGroups(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemotePullGroups(m_object, ProgressCallback, &pctxt);
}


Ref<CollabGroup> Remote::CreateGroup(const std::string& name, const std::vector<std::string>& usernames)
{
	const char** cstrNames = new const char*[usernames.size()];
	for (size_t i = 0; i < usernames.size(); i++)
	{
		cstrNames[i] = usernames[i].c_str();
	}

	BNCollaborationGroup* group = BNRemoteCreateGroup(m_object, name.c_str(), cstrNames, usernames.size());
	delete[] cstrNames;
	if (!group)
		return nullptr;
	return new CollabGroup(group);
}


void Remote::PushGroup(Ref<CollabGroup> group, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char** fieldKeys = new const char*[extraFields.size()];
	const char** fieldValues = new const char*[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemotePushGroup(m_object, group->m_object, fieldKeys, fieldValues, extraFields.size());
	delete[] fieldKeys;
	delete[] fieldValues;
}


void Remote::DeleteGroup(Ref<CollabGroup> group)
{
	BNRemoteDeleteGroup(m_object, group->m_object);
}


std::vector<Ref<CollabUser>> Remote::GetUsers()
{
	size_t count = 0;
	BNCollaborationUser** users = BNRemoteGetUsers(m_object, &count);
	std::vector<Ref<CollabUser>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabUser(BNNewCollaborationUserReference(users[i])));
	}
	BNFreeCollaborationUserList(users, count);
	return out;
}


Ref<CollabUser> Remote::GetUserById(const std::string& id)
{
	BNCollaborationUser* user = BNRemoteGetUserById(m_object, id.c_str());
	if (user == nullptr)
		return nullptr;
	return new CollabUser(user);
}


Ref<CollabUser> Remote::GetUserByUsername(const std::string& username)
{
	BNCollaborationUser* user = BNRemoteGetUserByUsername(m_object, username.c_str());
	if (user == nullptr)
		return nullptr;
	return new CollabUser(user);
}


Ref<CollabUser> Remote::GetCurrentUser()
{
	BNCollaborationUser* user = BNRemoteGetCurrentUser(m_object);
	if (user == nullptr)
		return nullptr;
	return new CollabUser(user);
}


std::vector<std::pair<std::string, std::string>> Remote::SearchUsers(const std::string& prefix)
{
	char** ids;
	char** names;
	size_t count;
	if (!BNRemoteSearchUsers(m_object, prefix.c_str(), &ids, &names, &count))
		throw RemoteException("Failed to search users");

	std::vector<std::pair<std::string, std::string>> results;
	for (size_t i = 0; i < count; i++)
	{
		results.push_back({ids[i], names[i]});
	}

	BNFreeStringList(ids, count);
	BNFreeStringList(names, count);

	return results;
}


void Remote::PullUsers(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemotePullUsers(m_object, ProgressCallback, &pctxt);
}


Ref<CollabUser> Remote::CreateUser(const std::string& username, const std::string& email, bool is_active, const std::string& password, const std::vector<uint64_t>& groupIds, const std::vector<uint64_t>& userPermissionIds)
{
	BNCollaborationUser* user = BNRemoteCreateUser(m_object, username.c_str(), email.c_str(), is_active, password.c_str(), groupIds.data(), groupIds.size(), userPermissionIds.data(), userPermissionIds.size());
	if (user == nullptr)
		return nullptr;
	return new CollabUser(user);
}


void Remote::PushUser(Ref<CollabUser> user, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char** fieldKeys = new const char*[extraFields.size()];
	const char** fieldValues = new const char*[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemotePushUser(m_object, user->m_object, fieldKeys, fieldValues, extraFields.size());
	delete[] fieldKeys;
	delete[] fieldValues;
}


int Remote::Request(Http::Request request, Http::Response& ret)
{
	return BNRemoteRequest(m_object, &request, &ret);
}


CollabGroup::CollabGroup(BNCollaborationGroup* group)
{
	m_object = group;
}


uint64_t CollabGroup::GetId()
{
	return BNCollaborationGroupGetId(m_object);
}


std::string CollabGroup::GetName()
{
	char* name = BNCollaborationGroupGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


void CollabGroup::SetName(const std::string& name)
{
	BNCollaborationGroupSetName(m_object, name.c_str());
}


void CollabGroup::SetUsernames(const std::vector<std::string>& usernames)
{
	const char** cNames = new const char*[usernames.size()];
	for (size_t i = 0; i < usernames.size(); i++)
	{
		cNames[i] = usernames[i].c_str();
	}

	BNCollaborationGroupSetUsernames(m_object, cNames, usernames.size());
	delete[] cNames;
}


bool CollabGroup::ContainsUser(const std::string& username)
{
	return BNCollaborationGroupContainsUser(m_object, username.c_str());
}


CollabUser::CollabUser(BNCollaborationUser* user)
{
	m_object = user;
}


Ref<Remote> CollabUser::GetRemote()
{
	BNRemote* remote = BNCollaborationUserGetRemote(m_object);
	if (remote == nullptr)
		return nullptr;
	return new Remote(remote);
}


std::string CollabUser::GetUrl()
{
	char* url = BNCollaborationUserGetUrl(m_object);
	std::string result = url;
	BNFreeString(url);
	return result;
}


std::string CollabUser::GetId()
{
	char* id = BNCollaborationUserGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::string CollabUser::GetUsername()
{
	char* username = BNCollaborationUserGetUsername(m_object);
	std::string result = username;
	BNFreeString(username);
	return result;
}


std::string CollabUser::GetEmail()
{
	char* email = BNCollaborationUserGetEmail(m_object);
	std::string result = email;
	BNFreeString(email);
	return result;
}


std::string CollabUser::GetLastLogin()
{
	char* lastLogin = BNCollaborationUserGetLastLogin(m_object);
	std::string result = lastLogin;
	BNFreeString(lastLogin);
	return result;
}


bool CollabUser::IsActive()
{
	return BNCollaborationUserIsActive(m_object);
}


void CollabUser::SetUsername(const std::string& username)
{
	BNCollaborationUserSetUsername(m_object, username.c_str());
}


void CollabUser::SetEmail(const std::string& email)
{
	BNCollaborationUserSetEmail(m_object, email.c_str());
}


void CollabUser::SetIsActive(bool isActive)
{
	BNCollaborationUserSetIsActive(m_object, isActive);
}


RemoteProject::RemoteProject(BNRemoteProject* project)
{
	m_object = project;
}


Ref<Project> RemoteProject::GetCoreProject()
{
	BNProject* project = BNRemoteProjectGetCoreProject(m_object);
	if (project == nullptr)
		return nullptr;
	return new Project(project);
}


bool RemoteProject::IsOpen()
{
	return BNRemoteProjectIsOpen(m_object);
}


bool RemoteProject::Open(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	return BNRemoteProjectOpen(m_object, ProgressCallback, &pctxt);
}


void RemoteProject::Close()
{
	BNRemoteProjectClose(m_object);
}


Ref<Remote> RemoteProject::GetRemote()
{
	return new Remote(BNRemoteProjectGetRemote(m_object));
}


std::string RemoteProject::GetUrl()
{
	char* url = BNRemoteProjectGetUrl(m_object);
	std::string result = url;
	BNFreeString(url);
	return result;
}


int64_t RemoteProject::GetCreated()
{
	return BNRemoteProjectGetCreated(m_object);
}


int64_t RemoteProject::GetLastModified()
{
	return BNRemoteProjectGetLastModified(m_object);
}


std::string RemoteProject::GetId()
{
	char* id = BNRemoteProjectGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::string RemoteProject::GetName()
{
	char* name = BNRemoteProjectGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


void RemoteProject::SetName(const std::string& name)
{
	BNRemoteProjectSetName(m_object, name.c_str());
}


std::string RemoteProject::GetDescription()
{
	char* desc = BNRemoteProjectGetDescription(m_object);
	std::string result = desc;
	BNFreeString(desc);
	return result;
}


void RemoteProject::SetDescription(const std::string& description)
{
	BNRemoteProjectSetDescription(m_object, description.c_str());
}


uint64_t RemoteProject::GetReceivedFileCount()
{
	return BNRemoteProjectGetReceivedFileCount(m_object);
}


uint64_t RemoteProject::GetReceivedFolderCount()
{
	return BNRemoteProjectGetReceivedFolderCount(m_object);
}


bool RemoteProject::HasPulledFiles()
{
	return BNRemoteProjectHasPulledFiles(m_object);
}


bool RemoteProject::HasPulledGroupPermissions()
{
	return BNRemoteProjectHasPulledGroupPermissions(m_object);
}


bool RemoteProject::HasPulledUserPermissions()
{
	return BNRemoteProjectHasPulledUserPermissions(m_object);
}


bool RemoteProject::IsAdmin()
{
	return BNRemoteProjectIsAdmin(m_object);
}


std::vector<Ref<RemoteFile>> RemoteProject::GetFiles()
{
	size_t count;
	BNRemoteFile** files = BNRemoteProjectGetFiles(m_object, &count);

	std::vector<Ref<RemoteFile>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new RemoteFile(BNNewRemoteFileReference(files[i])));
	}

	BNFreeRemoteFileList(files, count);
	return result;
}


std::vector<Ref<RemoteFolder>> RemoteProject::GetFolders()
{
	size_t count;
	BNRemoteFolder** folders = BNRemoteProjectGetFolders(m_object, &count);

	std::vector<Ref<RemoteFolder>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new RemoteFolder(BNNewRemoteFolderReference(folders[i])));
	}

	BNFreeRemoteFolderList(folders, count);
	return result;
}


Ref<RemoteFile> RemoteProject::GetFileById(const std::string& id)
{
	BNRemoteFile* file = BNRemoteProjectGetFileById(m_object, id.c_str());
	if (file == nullptr)
		return nullptr;
	return new RemoteFile(file);
}


Ref<RemoteFile> RemoteProject::GetFileByName(const std::string& name)
{
	BNRemoteFile* file = BNRemoteProjectGetFileByName(m_object, name.c_str());
	if (file == nullptr)
		return nullptr;
	return new RemoteFile(file);
}


void RemoteProject::PullFiles(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteProjectPullFiles(m_object, ProgressCallback, &pctxt);
}


void RemoteProject::PullFolders(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	BNRemoteProjectPullFolders(m_object, ProgressCallback, &pctxt);
}


Ref<RemoteFile> RemoteProject::CreateFile(const std::string& filename, std::vector<uint8_t>& contents, const std::string& name, const std::string& description, Ref<RemoteFolder> folder, BNRemoteFileType type, std::function<bool(size_t, size_t)> progress, Ref<ProjectFile> coreFile)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteFile* file = BNRemoteProjectCreateFile(m_object, filename.c_str(), contents.data(), contents.size(), name.c_str(), description.c_str(), folder ? folder->m_object : nullptr, type, ProgressCallback, &pctxt);
	if (file == nullptr)
		return nullptr;
	return new RemoteFile(file);
}


Ref<RemoteFolder> RemoteProject::CreateFolder(const std::string& name, const std::string& description, Ref<RemoteFolder> parent, std::function<bool(size_t, size_t)> progress, Ref<ProjectFolder> coreFolder)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteFolder* folder = BNRemoteProjectCreateFolder(m_object, name.c_str(), description.c_str(), parent ? parent->m_object : nullptr, ProgressCallback, &pctxt);
	if (folder == nullptr)
		return nullptr;
	return new RemoteFolder(folder);
}


void RemoteProject::PushFile(Ref<RemoteFile> file, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char** fieldKeys = new const char*[extraFields.size()];
	const char** fieldValues = new const char*[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemoteProjectPushFile(m_object, file->m_object, fieldKeys, fieldValues, extraFields.size());
	delete[] fieldKeys;
	delete[] fieldValues;
}


void RemoteProject::PushFolder(Ref<RemoteFolder> folder, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char** fieldKeys = new const char*[extraFields.size()];
	const char** fieldValues = new const char*[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemoteProjectPushFolder(m_object, folder->m_object, fieldKeys, fieldValues, extraFields.size());
	delete[] fieldKeys;
	delete[] fieldValues;
}


void RemoteProject::DeleteFolder(const Ref<RemoteFolder> folder)
{
	BNRemoteProjectDeleteFolder(m_object, folder->m_object);
}


void RemoteProject::DeleteFile(const Ref<RemoteFile> file)
{
	BNRemoteProjectDeleteFile(m_object, file->m_object);
}


Ref<RemoteFolder> RemoteProject::GetFolderById(const std::string& id)
{
	BNRemoteFolder* folder = BNRemoteProjectGetFolderById(m_object, id.c_str());
	if (folder == nullptr)
		return nullptr;
	return new RemoteFolder(folder);
}


std::vector<Ref<CollabPermission>> RemoteProject::GetGroupPermissions()
{
	size_t count;
	BNCollaborationPermission** perms = BNRemoteProjectGetGroupPermissions(m_object, &count);

	std::vector<Ref<CollabPermission>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new CollabPermission(BNNewCollaborationPermissionReference(perms[i])));
	}

	BNFreeCollaborationPermissionList(perms, count);
	return result;
}


std::vector<Ref<CollabPermission>> RemoteProject::GetUserPermissions()
{
	size_t count;
	BNCollaborationPermission** perms = BNRemoteProjectGetUserPermissions(m_object, &count);

	std::vector<Ref<CollabPermission>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new CollabPermission(BNNewCollaborationPermissionReference(perms[i])));
	}

	BNFreeCollaborationPermissionList(perms, count);
	return result;
}


Ref<CollabPermission> RemoteProject::GetPermissionById(const std::string& id)
{
	BNCollaborationPermission* perm = BNRemoteProjectGetPermissionById(m_object, id.c_str());
	if (perm == nullptr)
		return nullptr;
	return new CollabPermission(perm);
}


void RemoteProject::PullGroupPermissions(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteProjectPullGroupPermissions(m_object, ProgressCallback, &pctxt);
}


void RemoteProject::PullUserPermissions(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteProjectPullUserPermissions(m_object, ProgressCallback, &pctxt);
}


Ref<CollabPermission> RemoteProject::CreateGroupPermission(int groupId, BNCollaborationPermissionLevel level, std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNCollaborationPermission* perm = BNRemoteProjectCreateGroupPermission(m_object, groupId, level, ProgressCallback, &pctxt);
	if (perm == nullptr)
		return nullptr;
	return new CollabPermission(perm);
}


Ref<CollabPermission> RemoteProject::CreateUserPermission(const std::string& userId, BNCollaborationPermissionLevel level, std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNCollaborationPermission* perm = BNRemoteProjectCreateUserPermission(m_object, userId.c_str(), level, ProgressCallback, &pctxt);
	if (perm == nullptr)
		return nullptr;
	return new CollabPermission(perm);
}


void RemoteProject::PushPermission(Ref<CollabPermission> permission, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char** fieldKeys = new const char*[extraFields.size()];
	const char** fieldValues = new const char*[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemoteProjectPushPermission(m_object, permission->m_object, fieldKeys, fieldValues, extraFields.size());
	delete[] fieldKeys;
	delete[] fieldValues;
}


void RemoteProject::DeletePermission(Ref<CollabPermission> permission)
{
	BNRemoteProjectDeletePermission(m_object, permission->m_object);
}


bool RemoteProject::CanUserView(const std::string& username)
{
	return BNRemoteProjectCanUserView(m_object, username.c_str());
}


bool RemoteProject::CanUserEdit(const std::string& username)
{
	return BNRemoteProjectCanUserEdit(m_object, username.c_str());
}


bool RemoteProject::CanUserAdmin(const std::string& username)
{
	return BNRemoteProjectCanUserAdmin(m_object, username.c_str());
}


RemoteFile::RemoteFile(BNRemoteFile* file)
{
	m_object = file;
}


Ref<ProjectFile> RemoteFile::GetCoreFile()
{
	BNProjectFile* res = BNRemoteFileGetCoreFile(m_object);
	if (!res)
		return nullptr;
	return new ProjectFile(res);
}


Ref<RemoteProject> RemoteFile::GetProject()
{
	BNRemoteProject* res = BNRemoteFileGetProject(m_object);
	if (!res)
		return nullptr;
	return new RemoteProject(res);
}


Ref<RemoteFolder> RemoteFile::GetFolder()
{
	BNRemoteFolder* res = BNRemoteFileGetFolder(m_object);
	if (!res)
		return nullptr;
	return new RemoteFolder(res);
}


Ref<Remote> RemoteFile::GetRemote()
{
	BNRemote* res = BNRemoteFileGetRemote(m_object);
	if (!res)
		return nullptr;
	return new Remote(res);
}


std::string RemoteFile::GetUrl()
{
	char* res = BNRemoteFileGetUrl(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFile::GetChatLogUrl()
{
	char* res = BNRemoteFileGetChatLogUrl(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFile::GetUserPositionsUrl()
{
	char* res = BNRemoteFileGetUserPositionsUrl(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFile::GetId()
{
	char* res = BNRemoteFileGetId(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


BNRemoteFileType RemoteFile::GetType()
{
	return BNRemoteFileGetType(m_object);
}


int64_t RemoteFile::GetCreated()
{
	return BNRemoteFileGetCreated(m_object);
}


std::string RemoteFile::GetCreatedBy()
{
	char* res = BNRemoteFileGetCreatedBy(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


int64_t RemoteFile::GetLastModified()
{
	return BNRemoteFileGetLastModified(m_object);
}


int64_t RemoteFile::GetLastSnapshot()
{
	return BNRemoteFileGetLastSnapshot(m_object);
}


std::string RemoteFile::GetLastSnapshotBy()
{
	char* res = BNRemoteFileGetLastSnapshotBy(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFile::GetLastSnapshotName()
{
	char* res = BNRemoteFileGetLastSnapshotName(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFile::GetHash()
{
	char* res = BNRemoteFileGetHash(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFile::GetName()
{
	char* res = BNRemoteFileGetName(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFile::GetDescription()
{
	char* res = BNRemoteFileGetDescription(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFile::GetMetadata()
{
	char* res = BNRemoteFileGetMetadata(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


uint64_t RemoteFile::GetSize()
{
	return BNRemoteFileGetSize(m_object);
}


bool RemoteFile::HasPulledSnapshots()
{
	return BNRemoteFileHasPulledSnapshots(m_object);
}


void RemoteFile::SetName(const std::string& name)
{
	BNRemoteFileSetName(m_object, name.c_str());
}


void RemoteFile::SetDescription(const std::string& description)
{
	BNRemoteFileSetDescription(m_object, description.c_str());
}


void RemoteFile::SetFolder(const Ref<RemoteFolder>& folder)
{
	BNRemoteFileSetFolder(m_object, folder ? folder->m_object : nullptr);
}


void RemoteFile::SetMetadata(const std::string& metadata)
{
	BNRemoteFileSetMetadata(m_object, metadata.c_str());
}


std::vector<Ref<CollabSnapshot>> RemoteFile::GetSnapshots()
{
	size_t count = 0;
	BNCollaborationSnapshot** collabSnapshots = BNRemoteFileGetSnapshots(m_object, &count);
	std::vector<Ref<CollabSnapshot>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabSnapshot(BNNewCollaborationSnapshotReference(collabSnapshots[i])));
	}
	BNFreeCollaborationSnapshotList(collabSnapshots, count);
	return out;
}


Ref<CollabSnapshot> RemoteFile::GetSnapshotById(const std::string& id)
{
	BNCollaborationSnapshot* snapshot = BNRemoteFileGetSnapshotById(m_object, id.c_str());
	if (snapshot == nullptr)
		return nullptr;
	return new CollabSnapshot(snapshot);
}


void RemoteFile::PullSnapshots(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteFilePullSnapshots(m_object, ProgressCallback, &pctxt);
}


Ref<CollabSnapshot> RemoteFile::CreateSnapshot(std::string name, std::vector<uint8_t> contents, std::vector<uint8_t> analysisCacheContents, std::optional<std::vector<uint8_t>> fileContents, std::vector<std::string> parentIds, std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	const char** cParentIds = new const char*[parentIds.size()];

	for (size_t i = 0; i < parentIds.size(); i++)
	{
		cParentIds[i] = parentIds[i].c_str();
	}

	BNCollaborationSnapshot* snapshot = BNRemoteFileCreateSnapshot(m_object,
		name.c_str(),
		contents.data(),
		contents.size(),
		analysisCacheContents.data(),
		analysisCacheContents.size(),
		fileContents.has_value() ? fileContents->data() : nullptr,
		fileContents.has_value() ? fileContents->size() : 0,
		cParentIds,
		parentIds.size(),
		ProgressCallback,
		&pctxt
	);

	delete[] cParentIds;

	if (snapshot == nullptr)
		return nullptr;
	return new CollabSnapshot(snapshot);
}


void RemoteFile::DeleteSnapshot(const Ref<CollabSnapshot> snapshot)
{
	BNRemoteFileDeleteSnapshot(m_object, snapshot->m_object);
}


std::vector<uint8_t> RemoteFile::Download(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	size_t size = 0;
	uint8_t* data;
	if (!BNRemoteFileDownload(m_object, ProgressCallback, &pctxt, &data, &size))
		throw SyncException("Failed to download file");

	std::vector<uint8_t> out;
	out.insert(out.end(), &data[0], &data[size]);
	delete[] data;
	return out;
}


Json::Value RemoteFile::RequestUserPositions()
{
	char* value = BNRemoteFileRequestUserPositions(m_object);
	if (value == nullptr)
		throw RemoteException("Failed to load user positions");


	Json::Value json;
	std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
	std::string errors;
	if (!reader->parse(value, value + strlen(value), &json, &errors))
	{
		throw RemoteException(errors);
	}

	BNFreeString(value);
	return json;
}


Json::Value RemoteFile::RequestChatLog()
{
	char* value = BNRemoteFileRequestChatLog(m_object);
	if (value == nullptr)
		throw RemoteException("Failed to load user positions");


	Json::Value json;
	std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
	std::string errors;
	if (!reader->parse(value, value + strlen(value), &json, &errors))
	{
		throw RemoteException(errors);
	}

	BNFreeString(value);
	return json;
}


RemoteFolder::RemoteFolder(BNRemoteFolder* folder)
{
	m_object = folder;
}


Ref<ProjectFolder> RemoteFolder::GetCoreFolder()
{
	BNProjectFolder* res = BNRemoteFolderGetCoreFolder(m_object);
	if (!res)
		return nullptr;
	return new ProjectFolder(res);
}


Ref<RemoteProject> RemoteFolder::GetProject()
{
	BNRemoteProject* res = BNRemoteFolderGetProject(m_object);
	if (!res)
		return nullptr;
	return new RemoteProject(res);
}


Ref<RemoteFolder> RemoteFolder::GetParent()
{
	BNRemoteFolder* res = nullptr;
	if (!BNRemoteFolderGetParent(m_object, &res))
		return nullptr;
	if (!res)
		return nullptr;
	return new RemoteFolder(res);
}


Ref<Remote> RemoteFolder::GetRemote()
{
	BNRemote* res = BNRemoteFolderGetRemote(m_object);
	if (!res)
		return nullptr;
	return new Remote(res);
}


std::string RemoteFolder::GetId()
{
	char* res = BNRemoteFolderGetId(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFolder::GetUrl()
{
	char* res = BNRemoteFolderGetUrl(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFolder::GetName()
{
	char* res = BNRemoteFolderGetName(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


std::string RemoteFolder::GetDescription()
{
	char* res = BNRemoteFolderGetDescription(m_object);
	std::string out = res;
	BNFreeString(res);
	return out;
}


CollabPermission::CollabPermission(BNCollaborationPermission* permission)
{
	m_object = permission;
}


Ref<RemoteProject> CollabPermission::GetProject()
{
	BNRemoteProject* project = BNCollaborationPermissionGetProject(m_object);
	if (project == nullptr)
		return nullptr;
	return new RemoteProject(project);
}


Ref<Remote> CollabPermission::GetRemote()
{
	BNRemote* remote = BNCollaborationPermissionGetRemote(m_object);
	if (remote == nullptr)
		return nullptr;
	return new Remote(remote);
}


std::string CollabPermission::GetId()
{
	char* id = BNCollaborationPermissionGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::string CollabPermission::GetUrl()
{
	char* url = BNCollaborationPermissionGetUrl(m_object);
	std::string result = url;
	BNFreeString(url);
	return result;
}


uint64_t CollabPermission::GetGroupId()
{
	return BNCollaborationPermissionGetGroupId(m_object);
}


std::string CollabPermission::GetGroupName()
{
	char* name = BNCollaborationPermissionGetGroupName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


std::string CollabPermission::GetUserId()
{
	char* id = BNCollaborationPermissionGetUserId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::string CollabPermission::GetUsername()
{
	char* username = BNCollaborationPermissionGetUsername(m_object);
	std::string result = username;
	BNFreeString(username);
	return result;
}


BNCollaborationPermissionLevel CollabPermission::GetLevel()
{
	return BNCollaborationPermissionGetLevel(m_object);
}


void CollabPermission::SetLevel(BNCollaborationPermissionLevel level)
{
	BNCollaborationPermissionSetLevel(m_object, level);
}


bool CollabPermission::CanView()
{
	return BNCollaborationPermissionCanView(m_object);
}


bool CollabPermission::CanEdit()
{
	return BNCollaborationPermissionCanEdit(m_object);
}


bool CollabPermission::CanAdmin()
{
	return BNCollaborationPermissionCanAdmin(m_object);
}


std::optional<std::string> BinaryNinja::Collaboration::GetSnapshotAuthor(Ref<Database> database, Ref<Snapshot> snapshot)
{
	char* cAuthor = nullptr;
	if (!BNCollaborationGetSnapshotAuthor(database->m_object, snapshot->m_object, &cAuthor))
		throw RemoteException("Failed to get snapshot author");

	if (cAuthor == nullptr)
		return {};

	std::string author = cAuthor;
	BNFreeString(cAuthor);
	return author;
}


AnalysisMergeConflict::AnalysisMergeConflict(BNAnalysisMergeConflict* conflict)
{
	m_object = conflict;
}


std::string AnalysisMergeConflict::GetType()
{
	char* val = BNAnalysisMergeConflictGetType(m_object);
	std::string result = val;
	BNFreeString(val);
	return result;
}


BNMergeConflictDataType AnalysisMergeConflict::GetDataType()
{
	return BNAnalysisMergeConflictGetDataType(m_object);
}


std::optional<nlohmann::json> AnalysisMergeConflict::GetBase()
{
	char* val = BNAnalysisMergeConflictGetBase(m_object);
	if (val == nullptr)
		return {};
	return nlohmann::json::parse(val);
	BNFreeString(val);
}


std::optional<nlohmann::json> AnalysisMergeConflict::GetFirst()
{
	char* val = BNAnalysisMergeConflictGetFirst(m_object);
	if (val == nullptr)
		return {};
	return nlohmann::json::parse(val);
	BNFreeString(val);
}


std::optional<nlohmann::json> AnalysisMergeConflict::GetSecond()
{
	char* val = BNAnalysisMergeConflictGetSecond(m_object);
	if (val == nullptr)
		return {};
	return nlohmann::json::parse(val);
	BNFreeString(val);
}


Ref<FileMetadata> AnalysisMergeConflict::GetBaseFile()
{
	BNFileMetadata* val = BNAnalysisMergeConflictGetBaseFile(m_object);
	if (val == nullptr)
		return nullptr;
	return new FileMetadata(val);
}


Ref<FileMetadata> AnalysisMergeConflict::GetFirstFile()
{
	BNFileMetadata* val = BNAnalysisMergeConflictGetFirstFile(m_object);
	if (val == nullptr)
		return nullptr;
	return new FileMetadata(val);
}


Ref<FileMetadata> AnalysisMergeConflict::GetSecondFile()
{
	BNFileMetadata* val = BNAnalysisMergeConflictGetSecondFile(m_object);
	if (val == nullptr)
		return nullptr;
	return new FileMetadata(val);
}


Ref<Snapshot> AnalysisMergeConflict::GetBaseSnapshot()
{
	BNSnapshot* val = BNAnalysisMergeConflictGetBaseSnapshot(m_object);
	if (val == nullptr)
		return nullptr;
	return new Snapshot(val);
}


Ref<Snapshot> AnalysisMergeConflict::GetFirstSnapshot()
{
	BNSnapshot* val = BNAnalysisMergeConflictGetFirstSnapshot(m_object);
	if (val == nullptr)
		return nullptr;
	return new Snapshot(val);
}


Ref<Snapshot> AnalysisMergeConflict::GetSecondSnapshot()
{
	BNSnapshot* val = BNAnalysisMergeConflictGetSecondSnapshot(m_object);
	if (val == nullptr)
		return nullptr;
	return new Snapshot(val);
}


template <>
std::any AnalysisMergeConflict::GetPathItem<std::any>(const std::string& path)
{
	void* val = BNAnalysisMergeConflictGetPathItem(m_object, path.c_str());
	if (val == nullptr)
		throw SyncException(fmt::format("Failed to find merge conflict path item \"{}\"", path));
	return *(std::any*)val;
}


template <>
uint64_t AnalysisMergeConflict::GetPathItem<uint64_t>(const std::string& path)
{
	std::any anyVal = GetPathItem<std::any>(path);
	try
	{
		return std::any_cast<uint64_t>(anyVal);
	}
	catch (const std::exception& e)
	{
		throw SyncException(fmt::format(
			"Failed to cast merge conflict path item \"{}\" from \"{}\" to \"{}\": {}",
			path, anyVal.type().name(), typeid(uint64_t).name(), e.what()
		));
	}
}


template <>
std::string AnalysisMergeConflict::GetPathItem<std::string>(const std::string& path)
{
	char* val = BNAnalysisMergeConflictGetPathItemString(m_object, path.c_str());
	if (val == nullptr)
		throw SyncException(fmt::format("Failed to find merge conflict path item \"{}\"", path));

	std::string strVal = val;
	BNFreeString(val);
	return strVal;
}


template <>
nlohmann::json AnalysisMergeConflict::GetPathItem<nlohmann::json>(const std::string& path)
{
	char* val = BNAnalysisMergeConflictGetPathItemSerialized(m_object, path.c_str());
	if (val == nullptr)
		throw SyncException(fmt::format("Failed to find merge conflict path item \"{}\"", path));

	std::string strVal = val;
	BNFreeString(val);
	return nlohmann::json::parse(strVal);
}


bool AnalysisMergeConflict::Success(std::nullopt_t value)
{
	return BNAnalysisMergeConflictSuccess(m_object, nullptr);
}


bool AnalysisMergeConflict::Success(std::optional<const nlohmann::json*> value)
{
	return BNAnalysisMergeConflictSuccess(m_object, value.has_value() ? (*value)->dump().c_str() : nullptr);
}


bool AnalysisMergeConflict::Success(const std::optional<nlohmann::json>& value)
{
	return BNAnalysisMergeConflictSuccess(m_object, value.has_value() ? value->dump().c_str() : nullptr);
}


TypeArchiveMergeConflict::TypeArchiveMergeConflict(BNTypeArchiveMergeConflict* conflict)
{
	m_object = conflict;
}


Ref<TypeArchive> TypeArchiveMergeConflict::GetTypeArchive()
{
	BNTypeArchive* archive = BNTypeArchiveMergeConflictGetTypeArchive(m_object);
	if (archive == nullptr)
		return nullptr;
	return new TypeArchive(archive);
}


std::string TypeArchiveMergeConflict::GetTypeId()
{
	char* val = BNTypeArchiveMergeConflictGetTypeId(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string TypeArchiveMergeConflict::GetBaseSnapshotId()
{
	char* val = BNTypeArchiveMergeConflictGetBaseSnapshotId(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string TypeArchiveMergeConflict::GetFirstSnapshotId()
{
	char* val = BNTypeArchiveMergeConflictGetFirstSnapshotId(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string TypeArchiveMergeConflict::GetSecondSnapshotId()
{
	char* val = BNTypeArchiveMergeConflictGetSecondSnapshotId(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


bool TypeArchiveMergeConflict::Success(const std::string& value)
{
	return BNTypeArchiveMergeConflictSuccess(m_object, value.c_str());
}


CollabChangeset::CollabChangeset(BNCollaborationChangeset* changeset)
{
	m_object = changeset;
}


Ref<Database> CollabChangeset::GetDatabase()
{
	BNDatabase* database = BNCollaborationChangesetGetDatabase(m_object);
	if (database == nullptr)
		return nullptr;
	return new Database(database);
}


Ref<RemoteFile> CollabChangeset::GetFile()
{
	BNRemoteFile* file = BNCollaborationChangesetGetFile(m_object);
	if (file == nullptr)
		return nullptr;
	return new RemoteFile(file);
}


std::vector<int64_t> CollabChangeset::GetSnapshotIds()
{
	size_t count = 0;
	int64_t* ids = BNCollaborationChangesetGetSnapshotIds(m_object, &count);
	std::vector<int64_t> result;
	result.insert(result.end(), ids, &ids[count]);
	delete[] ids;
	return result;
}


Ref<CollabUser> CollabChangeset::GetAuthor()
{
	BNCollaborationUser* author = BNCollaborationChangesetGetAuthor(m_object);
	if (author == nullptr)
		return nullptr;
	return new CollabUser(author);
}


std::string CollabChangeset::GetName()
{
	char* val = BNCollaborationChangesetGetName(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


void CollabChangeset::SetName(const std::string& name)
{
	BNCollaborationChangesetSetName(m_object, name.c_str());
}


CollabSnapshot::CollabSnapshot(BNCollaborationSnapshot* snapshot)
{
	m_object = snapshot;
}


Ref<RemoteFile> CollabSnapshot::GetFile()
{
	BNRemoteFile* file = BNCollaborationSnapshotGetFile(m_object);
	if (file == nullptr)
		return nullptr;
	return new RemoteFile(file);
}


Ref<RemoteProject> CollabSnapshot::GetProject()
{
	BNRemoteProject* project = BNCollaborationSnapshotGetProject(m_object);
	if (project == nullptr)
		return nullptr;
	return new RemoteProject(project);
}


Ref<Remote> CollabSnapshot::GetRemote()
{
	BNRemote* remote = BNCollaborationSnapshotGetRemote(m_object);
	if (remote == nullptr)
		return nullptr;
	return new Remote(remote);
}


std::string CollabSnapshot::GetUrl()
{
	char* val = BNCollaborationSnapshotGetUrl(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetId()
{
	char* val = BNCollaborationSnapshotGetId(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetName()
{
	char* val = BNCollaborationSnapshotGetName(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetAuthor()
{
	char* val = BNCollaborationSnapshotGetAuthor(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


int64_t CollabSnapshot::GetCreated()
{
	return BNCollaborationSnapshotGetCreated(m_object);
}


int64_t CollabSnapshot::GetLastModified()
{
	return BNCollaborationSnapshotGetLastModified(m_object);
}


std::string CollabSnapshot::GetHash()
{
	char* val = BNCollaborationSnapshotGetHash(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetSnapshotFileHash()
{
	char* val = BNCollaborationSnapshotGetSnapshotFileHash(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


bool CollabSnapshot::HasPulledUndoEntries()
{
	return BNCollaborationSnapshotHasPulledUndoEntries(m_object);
}


bool CollabSnapshot::IsFinalized()
{
	return BNCollaborationSnapshotIsFinalized(m_object);
}


std::vector<std::string> CollabSnapshot::GetParentIds()
{
	size_t count = 0;
	char** strs = BNCollaborationSnapshotGetParentIds(m_object, &count);
	std::vector<std::string> result;
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(strs[i]);
	}
	BNFreeStringList(strs, count);
	return result;
}


std::vector<std::string> CollabSnapshot::GetChildIds()
{
	size_t count = 0;
	char** strs = BNCollaborationSnapshotGetParentIds(m_object, &count);
	std::vector<std::string> result;
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(strs[i]);
	}
	BNFreeStringList(strs, count);
	return result;
}


uint64_t CollabSnapshot::GetAnalysisCacheBuildId()
{
	return BNCollaborationSnapshotGetAnalysisCacheBuildId(m_object);
}


std::string CollabSnapshot::GetTitle()
{
	char* val = BNCollaborationSnapshotGetTitle(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetDescription()
{
	char* val = BNCollaborationSnapshotGetDescription(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetAuthorUsername()
{
	char* val = BNCollaborationSnapshotGetAuthorUsername(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::vector<Ref<CollabSnapshot>> CollabSnapshot::GetParents()
{
	size_t count = 0;
	BNCollaborationSnapshot** snapshots = BNCollaborationSnapshotGetParents(m_object, &count);
	std::vector<Ref<CollabSnapshot>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabSnapshot(BNNewCollaborationSnapshotReference(snapshots[i])));
	}
	BNFreeCollaborationSnapshotList(snapshots, count);
	return out;
}


std::vector<Ref<CollabSnapshot>> CollabSnapshot::GetChildren()
{
	size_t count = 0;
	BNCollaborationSnapshot** snapshots = BNCollaborationSnapshotGetChildren(m_object, &count);
	std::vector<Ref<CollabSnapshot>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabSnapshot(BNNewCollaborationSnapshotReference(snapshots[i])));
	}
	BNFreeCollaborationSnapshotList(snapshots, count);
	return out;
}


std::vector<Ref<CollabUndoEntry>> CollabSnapshot::GetUndoEntries()
{
	size_t count = 0;
	BNCollaborationUndoEntry** entries = BNCollaborationSnapshotGetUndoEntries(m_object, &count);
	std::vector<Ref<CollabUndoEntry>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabUndoEntry(BNNewCollaborationUndoEntryReference(entries[i])));
	}
	BNFreeCollaborationUndoEntryList(entries, count);
	return out;
}


Ref<CollabUndoEntry> CollabSnapshot::GetUndoEntryById(uint64_t id)
{
	BNCollaborationUndoEntry* entry = BNCollaborationSnapshotGetUndoEntryById(m_object, id);
	if (entry == nullptr)
		return nullptr;
	return new CollabUndoEntry(entry);
}


void CollabSnapshot::PullUndoEntries(std::function<bool(size_t, size_t)> progress)
{
		ProgressContext pctxt;
	pctxt.callback = progress;
	BNCollaborationSnapshotPullUndoEntries(m_object, ProgressCallback, &pctxt);
}


Ref<CollabUndoEntry> CollabSnapshot::CreateUndoEntry(std::optional<uint64_t> parent, std::string data)
{
	BNCollaborationUndoEntry* entry = BNCollaborationSnapshotCreateUndoEntry(m_object, parent.has_value(), parent.has_value() ? *parent : 0, data.c_str());
	if (entry == nullptr)
		return nullptr;
	return new CollabUndoEntry(entry);
}


void CollabSnapshot::Finalize()
{
	BNCollaborationSnapshotFinalize(m_object);
}


std::vector<uint8_t> CollabSnapshot::DownloadSnapshotFile(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	size_t size = 0;
	uint8_t* data;

	if (!BNCollaborationSnapshotDownloadSnapshotFile(m_object, ProgressCallback, &pctxt, &data, &size))
		throw SyncException("Failed to download snapshot file");

	std::vector<uint8_t> out;
	out.insert(out.end(), data, &data[size]);
	delete[] data;
	return out;
}


std::vector<uint8_t> CollabSnapshot::Download(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	size_t size = 0;
	uint8_t* data;

	if (!BNCollaborationSnapshotDownload(m_object, ProgressCallback, &pctxt, &data, &size))
		throw SyncException("Failed to download snapshot");

	std::vector<uint8_t> out;
	out.insert(out.end(), data, &data[size]);
	delete[] data;
	return out;
}


std::vector<uint8_t> CollabSnapshot::DownloadAnalysisCache(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	size_t size = 0;
	uint8_t* data;
	if (!BNCollaborationSnapshotDownloadAnalysisCache(m_object, ProgressCallback, &pctxt, &data, &size))
		throw SyncException("Failed to download snapshot");

	std::vector<uint8_t> out;
	out.insert(out.end(), data, &data[size]);
	delete[] data;
	return out;
}


CollabUndoEntry::CollabUndoEntry(BNCollaborationUndoEntry* entry)
{
	m_object = entry;
}

