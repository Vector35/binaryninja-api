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

using namespace BinaryNinja;
using namespace BinaryNinja::Collaboration;

//TODO: this should really be split up and put in a collaboration directory


bool BinaryNinja::Collaboration::IsCollaborationDatabase(Ref<Database> database)
{
	return BNCollaborationIsCollaborationDatabase(database->m_object);
}


Ref<Remote> BinaryNinja::Collaboration::GetRemoteForLocalDatabase(Ref<Database> database)
{
	BNRemote* val = BNCollaborationGetRemoteForLocalDatabase(database->m_object);
	if (val == nullptr)
		return nullptr;
	return new Remote(val);
}


Ref<RemoteProject> BinaryNinja::Collaboration::GetRemoteProjectForLocalDatabase(Ref<Database> database)
{
	BNRemoteProject* val = BNCollaborationGetRemoteProjectForLocalDatabase(database->m_object);
	if (val == nullptr)
		return nullptr;
	return new RemoteProject(val);
}


Ref<RemoteFile> BinaryNinja::Collaboration::GetRemoteFileForLocalDatabase(Ref<Database> database)
{
	BNRemoteFile* val = BNCollaborationGetRemoteFileForLocalDatabase(database->m_object);
	if (val == nullptr)
		return nullptr;
	return new RemoteFile(val);
}


bool BinaryNinja::Collaboration::IsSnapshotIgnored(Ref<Database> database, Ref<Snapshot> snapshot)
{
	return BNCollaborationIsSnapshotIgnored(database->m_object, snapshot->m_object);
}


Ref<CollabSnapshot> BinaryNinja::Collaboration::GetRemoteSnapshotFromLocal(Ref<Snapshot> snapshot)
{
	BNCollabSnapshot* val = BNCollaborationGetRemoteSnapshotFromLocal(snapshot->m_object);
	if (val == nullptr)
		return nullptr;
	return new CollabSnapshot(val);
}


Ref<Snapshot> BinaryNinja::Collaboration::GetLocalSnapshotFromRemote(Ref<CollabSnapshot> snapshot, Ref<Database> database)
{
	BNSnapshot* val = BNCollaborationGetLocalSnapshotFromRemote(snapshot->m_object, database->m_object);
	if (val == nullptr)
		return nullptr;
	return new Snapshot(val);
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

	const char* dataKeys[data.size()];
	const char* dataValues[data.size()];

	size_t i = 0;
	for (const auto& entry : data)
	{
		dataKeys[i] = entry.first.c_str();
		dataValues[i] = entry.second.c_str();
		i++;
	}

	return BNCollaborationStoreDataInKeychain(key.c_str(), dataKeys, dataValues, data.size());
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
	BNRemote* remote = BNCollaborationGetRemoteById(remoteAddress.c_str());
	if (!remote)
		return nullptr;
	return new Remote(remote);
}


Ref<Remote> BinaryNinja::Collaboration::GetRemoteByName(const std::string& name)
{
	BNRemote* remote = BNCollaborationGetRemoteById(name.c_str());
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


void BinaryNinja::Collaboration::SyncDatabase(Ref<Database> database, Ref<RemoteFile> file, std::function<bool(const std::unordered_map<std::string, Ref<AnalysisMergeConflict>>& conflicts)> conflictHandler, std::function<bool(size_t, size_t)> progress, NameChangesetFunction nameChangeset)
{
	LogAlert("TODO");
	/*
	struct ConflictHandlerContext
	{
		std::function<bool(const std::unordered_map<std::string, Ref<AnalysisMergeConflict>>)> callback;
	};

	auto ConflictHandlerCallback = [=](void* ctxt, const char** keys, BNAnalysisMergeConflict** conflicts, size_t count) {
		ConflictHandlerContext* chctxt = reinterpret_cast<ConflictHandlerContext*>(ctxt);
		if (!chctxt->callback)
			return true;
		std::unordered_map<std::string, Ref<AnalysisMergeConflict>> conflictMap;
		for (size_t i = 0; i < count; i++)
		{
			conflictMap[keys[i]] = new AnalysisMergeConflict(conflicts[i]);
		}
		return chctxt->callback(conflictMap);
	};

	struct NameChangesetContext
	{
		std::function<bool(Ref<Changeset>)> callback;
	};

	auto NameChangesetCallback = [=](void* ctxt, BNChangeset* changeset) {
		NameChangesetContext* ncctxt = reinterpret_cast<NameChangesetContext*>(ctxt);
		if (!ncctxt->callback)
			return true;
		return ncctxt->callback(new Changeset(changeset));
	};


	ProgressContext pctxt;
	pctxt.callback = progress;

	ConflictHandlerContext chctxt;
	chctxt.callback = conflictHandler;

	NameChangesetContext ncctxt;
	ncctxt.callback = nameChangeset;

	BNCollaborationSyncDatabase(database->m_object, file->m_object,
		&chctxt, ConflictHandlerCallback,
		&pctxt, ProgressCallback,
		&ncctxt, NameChangesetCallback
	);

*/
}


void BinaryNinja::Collaboration::SyncTypeArchive(Ref<TypeArchive> archive, Ref<RemoteFile> file, std::function<bool(const std::vector<Ref<TypeArchiveMergeConflict>>& conflicts)> conflictHandler, ProgressFunction progress)
{
	LogAlert("TODO");
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
	size_t count = BNRemoteGetAuthBackends(m_object, &methods, &names);

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


void Remote::LoadMetadata()
{
	BNRemoteHasLoadedMetadata(m_object);
}


std::string Remote::RequestAuthenticationToken(const std::string& username, const std::string& password)
{
	char* token = BNRemoteRequestAuthenticationToken(m_object, username.c_str(), password.c_str());
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
	BNRemotePullProjects(m_object, &pctxt, ProgressCallback);
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
	BNRemoteProject* project = BNRemoteImportLocalProject(m_object, localProject->m_object, &pctxt, ProgressCallback);
	if (project == nullptr)
		return nullptr;
	return new RemoteProject(project);
}


void Remote::PushProject(Ref<RemoteProject> project, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char* fieldKeys[extraFields.size()];
	const char* fieldValues[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemotePushProject(m_object, project->m_object, fieldKeys, fieldValues, extraFields.size());
}


void Remote::DeleteProject(const Ref<RemoteProject> project)
{
	BNRemoteDeleteProject(m_object, project->m_object);
}


std::vector<Ref<Group>> Remote::GetGroups()
{
	size_t count = 0;
	BNGroup** groups = BNRemoteGetGroups(m_object, &count);
	std::vector<Ref<Group>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new Group(BNNewGroupReference(groups[i])));
	}
	BNFreeGroupList(groups, count);
	return out;
}


Ref<Group> Remote::GetGroupById(uint64_t id)
{
	BNGroup* group = BNRemoteGetGroupById(m_object, id);
	if (group == nullptr)
		return nullptr;
	return new Group(group);
}


Ref<Group> Remote::GetGroupByName(const std::string& name)
{
	BNGroup* group = BNRemoteGetGroupByName(m_object, name.c_str());
	if (group == nullptr)
		return nullptr;
	return new Group(group);
}


std::vector<std::pair<uint64_t, std::string>> Remote::SearchGroups(const std::string& prefix)
{
	uint64_t* ids;
	char** names;
	size_t count = BNRemoteSearchGroups(m_object, prefix.c_str(), &ids, &names);

	std::vector<std::pair<uint64_t, std::string>> results;
	for (size_t i = 0; i < count; i++)
	{
		results.push_back({ids[i], names[i]});
	}

	delete ids;
	BNFreeStringList(names, count);

	return results;
}


void Remote::PullGroups(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemotePullGroups(m_object, &pctxt, ProgressCallback);
}


Ref<Group> Remote::CreateGroup(const std::string& name, const std::vector<std::string>& usernames)
{
	const char* cstrNames[usernames.size()];
	for (size_t i = 0; i < usernames.size(); i++)
	{
		cstrNames[i] = usernames[i].c_str();
	}

	BNGroup* group = BNRemoteCreateGroup(m_object, name.c_str(), cstrNames, usernames.size());
	if (!group)
		return nullptr;
	return new Group(group);
}


void Remote::PushGroup(Ref<Group> group, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char* fieldKeys[extraFields.size()];
	const char* fieldValues[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemotePushGroup(m_object, group->m_object, fieldKeys, fieldValues, extraFields.size());
}


void Remote::DeleteGroup(Ref<Group> group)
{
	BNRemoteDeleteGroup(m_object, group->m_object);
}


std::vector<Ref<CollabUser>> Remote::GetUsers()
{
	size_t count = 0;
	BNCollabUser** users = BNRemoteGetUsers(m_object, &count);
	std::vector<Ref<CollabUser>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabUser(BNNewCollabUserReference(users[i])));
	}
	BNFreeCollabUserList(users, count);
	return out;
}


Ref<CollabUser> Remote::GetUserById(const std::string& id)
{
	BNCollabUser* user = BNRemoteGetUserById(m_object, id.c_str());
	if (user == nullptr)
		return nullptr;
	return new CollabUser(user);
}


Ref<CollabUser> Remote::GetUserByUsername(const std::string& username)
{
	BNCollabUser* user = BNRemoteGetUserByUsername(m_object, username.c_str());
	if (user == nullptr)
		return nullptr;
	return new CollabUser(user);
}


Ref<CollabUser> Remote::GetCurrentUser()
{
	BNCollabUser* user = BNRemoteGetCurrentUser(m_object);
	if (user == nullptr)
		return nullptr;
	return new CollabUser(user);
}


std::vector<std::pair<std::string, std::string>> Remote::SearchUsers(const std::string& prefix)
{
	char** ids;
	char** names;
	size_t count = BNRemoteSearchUsers(m_object, prefix.c_str(), &ids, &names);

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
	BNRemotePullUsers(m_object, &pctxt, ProgressCallback);
}


Ref<CollabUser> Remote::CreateUser(const std::string& username, const std::string& email, bool is_active, const std::string& password, const std::vector<uint64_t>& groupIds, const std::vector<uint64_t>& userPermissionIds)
{
	BNCollabUser* user = BNRemoteCreateUser(m_object, username.c_str(), email.c_str(), is_active, password.c_str(), groupIds.data(), groupIds.size(), userPermissionIds.data(), userPermissionIds.size());
	if (user == nullptr)
		return nullptr;
	return new CollabUser(user);
}


void Remote::PushUser(Ref<CollabUser> user, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char* fieldKeys[extraFields.size()];
	const char* fieldValues[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemotePushUser(m_object, user->m_object, fieldKeys, fieldValues, extraFields.size());
}


Group::Group(BNGroup* group)
{
	m_object = group;
}


uint64_t Group::GetId()
{
	return BNGroupGetId(m_object);
}


std::string Group::GetName()
{
	char* name = BNGroupGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


void Group::SetName(const std::string& name)
{
	BNGroupSetName(m_object, name.c_str());
}


void Group::SetUsernames(const std::vector<std::string>& usernames)
{
	const char* cNames[usernames.size()];
	for (size_t i = 0; i < usernames.size(); i++)
	{
		cNames[i] = usernames[i].c_str();
	}

	BNGroupSetUsernames(m_object, cNames, usernames.size());
}


bool Group::ContainsUser(const std::string& username)
{
	return BNGroupContainsUser(m_object, username.c_str());
}


CollabUser::CollabUser(BNCollabUser* user)
{
	m_object = user;
}


Ref<Remote> CollabUser::GetRemote()
{
	BNRemote* remote = BNCollabUserGetRemote(m_object);
	if (remote == nullptr)
		return nullptr;
	return new Remote(remote);
}


std::string CollabUser::GetUrl()
{
	char* url = BNCollabUserGetUrl(m_object);
	std::string result = url;
	BNFreeString(url);
	return result;
}


std::string CollabUser::GetId()
{
	char* id = BNCollabUserGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::string CollabUser::GetUsername()
{
	char* username = BNCollabUserGetUsername(m_object);
	std::string result = username;
	BNFreeString(username);
	return result;
}


std::string CollabUser::GetEmail()
{
	char* email = BNCollabUserGetEmail(m_object);
	std::string result = email;
	BNFreeString(email);
	return result;
}


std::string CollabUser::GetLastLogin()
{
	char* lastLogin = BNCollabUserGetLastLogin(m_object);
	std::string result = lastLogin;
	BNFreeString(lastLogin);
	return result;
}


bool CollabUser::IsActive()
{
	return BNCollabUserIsActive(m_object);
}


void CollabUser::SetUsername(const std::string& username)
{
	BNCollabUserSetUsername(m_object, username.c_str());
}


void CollabUser::SetEmail(const std::string& email)
{
	BNCollabUserSetEmail(m_object, email.c_str());
}


void CollabUser::SetIsActive(bool isActive)
{
	BNCollabUserSetIsActive(m_object, isActive);
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
	return BNRemoteProjectOpen(m_object, &pctxt, ProgressCallback);
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


bool RemoteProject::HasPulledPermissions()
{
	return BNRemoteProjectHasPulledPermissions(m_object);
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
	BNRemoteProjectPullFiles(m_object, &pctxt, ProgressCallback);
}


void RemoteProject::PullFolders(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	BNRemoteProjectPullFolders(m_object, &pctxt, ProgressCallback);
}


Ref<RemoteFile> RemoteProject::CreateFile(const std::string& filename, const std::vector<uint8_t>& contents, const std::string& name, const std::string& description, Ref<RemoteFolder> folder, BNRemoteFileType type, std::function<bool(size_t, size_t)> progress, Ref<ProjectFile> coreFile)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteFile* file = BNRemoteProjectCreateFile(m_object, filename.c_str(), contents.data(), contents.size(), name.c_str(), description.c_str(), folder ? folder->m_object : nullptr, type, &pctxt, ProgressCallback);
	if (file == nullptr)
		return nullptr;
	return new RemoteFile(file);
}


Ref<RemoteFolder> RemoteProject::CreateFolder(const std::string& name, const std::string& description, Ref<RemoteFolder> parent, std::function<bool(size_t, size_t)> progress, Ref<ProjectFolder> coreFolder)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteFolder* folder = BNRemoteProjectCreateFolder(m_object, name.c_str(), description.c_str(), parent ? parent->m_object : nullptr, &pctxt, ProgressCallback);
	if (folder == nullptr)
		return nullptr;
	return new RemoteFolder(folder);
}


void RemoteProject::PushFile(Ref<RemoteFile> file, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char* fieldKeys[extraFields.size()];
	const char* fieldValues[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemoteProjectPushFile(m_object, file->m_object, fieldKeys, fieldValues, extraFields.size());
}


void RemoteProject::PushFolder(Ref<RemoteFolder> folder, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char* fieldKeys[extraFields.size()];
	const char* fieldValues[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}
	BNRemoteProjectPushFolder(m_object, folder->m_object, fieldKeys, fieldValues, extraFields.size());
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


std::vector<Ref<Permission>> RemoteProject::GetGroupPermissions()
{
	size_t count;
	BNPermission** perms = BNRemoteProjectGetGroupPermissions(m_object, &count);

	std::vector<Ref<Permission>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new Permission(BNNewPermissionReference(perms[i])));
	}

	BNFreePermissionList(perms, count);
	return result;
}


std::vector<Ref<Permission>> RemoteProject::GetUserPermissions()
{
	size_t count;
	BNPermission** perms = BNRemoteProjectGetUserPermissions(m_object, &count);

	std::vector<Ref<Permission>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new Permission(BNNewPermissionReference(perms[i])));
	}

	BNFreePermissionList(perms, count);
	return result;
}


Ref<Permission> RemoteProject::GetPermissionById(const std::string& id)
{
	BNPermission* perm = BNRemoteProjectGetPermissionById(m_object, id.c_str());
	if (perm == nullptr)
		return nullptr;
	return new Permission(perm);
}


void RemoteProject::PullGroupPermissions(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteProjectPullGroupPermissions(m_object, &pctxt, ProgressCallback);
}


void RemoteProject::PullUserPermissions(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteProjectPullUserPermissions(m_object, &pctxt, ProgressCallback);
}


Ref<Permission> RemoteProject::CreateGroupPermission(int groupId, BNPermissionLevel level, std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNPermission* perm = BNRemoteProjectCreateGroupPermission(m_object, groupId, level, &pctxt, ProgressCallback);
	if (perm == nullptr)
		return nullptr;
	return new Permission(perm);
}


Ref<Permission> RemoteProject::CreateUserPermission(const std::string& userId, BNPermissionLevel level, std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNPermission* perm = BNRemoteProjectCreateUserPermission(m_object, userId.c_str(), level, &pctxt, ProgressCallback);
	if (perm == nullptr)
		return nullptr;
	return new Permission(perm);
}


void RemoteProject::PushPermission(Ref<Permission> permission, const std::vector<std::pair<std::string, std::string>>& extraFields)
{
	const char* fieldKeys[extraFields.size()];
	const char* fieldValues[extraFields.size()];

	for (size_t i = 0; i < extraFields.size(); i++)
	{
		auto& field = extraFields[i];
		fieldKeys[i] = field.first.c_str();
		fieldValues[i] = field.second.c_str();
	}

	BNRemoteProjectPushPermission(m_object, permission->m_object, fieldKeys, fieldValues, extraFields.size());
}


void RemoteProject::DeletePermission(Ref<Permission> permission)
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
	BNCollabSnapshot** collabSnapshots = BNRemoteFileGetSnapshots(m_object, &count);
	std::vector<Ref<CollabSnapshot>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabSnapshot(BNNewCollabSnapshotReference(collabSnapshots[i])));
	}
	BNFreeCollabSnapshotList(collabSnapshots, count);
	return out;
}


Ref<CollabSnapshot> RemoteFile::GetSnapshotById(const std::string& id)
{
	BNCollabSnapshot* snapshot = BNRemoteFileGetSnapshotById(m_object, id.c_str());
	if (snapshot == nullptr)
		return nullptr;
	return new CollabSnapshot(snapshot);
}


void RemoteFile::PullSnapshots(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	BNRemoteFilePullSnapshots(m_object, &pctxt, ProgressCallback);
}


Ref<CollabSnapshot> RemoteFile::CreateSnapshot(std::string name, std::vector<uint8_t> contents, std::vector<uint8_t> analysisCacheContents, std::optional<std::vector<uint8_t>> fileContents, std::vector<std::string> parentIds, std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;

	const char* cParentIds[parentIds.size()];

	for (size_t i = 0; i < parentIds.size(); i++)
	{
		cParentIds[i] = parentIds[i].c_str();
	}

	BNCollabSnapshot* snapshot = BNRemoteFileCreateSnapshot(m_object,
		name.c_str(),
		contents.data(),
		contents.size(),
		analysisCacheContents.data(),
		analysisCacheContents.size(),
		fileContents.has_value() ? fileContents->data() : nullptr,
		fileContents.has_value() ? fileContents->size() : 0,
		cParentIds,
		parentIds.size(),
		&pctxt,
		ProgressCallback
	);

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
	size_t count = 0;
	uint8_t* data = BNRemoteFileDownload(m_object, &count, &pctxt, ProgressCallback);

	// TODO: we probably want to throw here
	if (data == nullptr)
		return {};

	std::vector<uint8_t> out;
	out.insert(out.end(), &data[0], &data[count]);
	free(data);
	return out;
}


RemoteFolder::RemoteFolder(BNRemoteFolder* folder)
{
	m_object = folder;
}


Permission::Permission(BNPermission* permission)
{
	m_object = permission;
}


Ref<RemoteProject> Permission::GetProject()
{
	BNRemoteProject* project = BNPermissionGetProject(m_object);
	if (project == nullptr)
		return nullptr;
	return new RemoteProject(project);
}


Ref<Remote> Permission::GetRemote()
{
	BNRemote* remote = BNPermissionGetRemote(m_object);
	if (remote == nullptr)
		return nullptr;
	return new Remote(remote);
}


std::string Permission::GetId()
{
	char* id = BNPermissionGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::string Permission::GetUrl()
{
	char* url = BNPermissionGetUrl(m_object);
	std::string result = url;
	BNFreeString(url);
	return result;
}


uint64_t Permission::GetGroupId()
{
	return BNPermissionGetGroupId(m_object);
}


std::string Permission::GetGroupName()
{
	char* name = BNPermissionGetGroupName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


std::string Permission::GetUserId()
{
	char* id = BNPermissionGetUserId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::string Permission::GetUsername()
{
	char* username = BNPermissionGetUsername(m_object);
	std::string result = username;
	BNFreeString(username);
	return result;
}


BNPermissionLevel Permission::GetLevel()
{
	return BNPermissionGetLevel(m_object);
}


void Permission::SetLevel(BNPermissionLevel level)
{
	BNPermissionSetLevel(m_object, level);
}


bool Permission::CanView()
{
	return BNPermissionCanView(m_object);
}


bool Permission::CanEdit()
{
	return BNPermissionCanEdit(m_object);
}


bool Permission::CanAdmin()
{
	return BNPermissionCanAdmin(m_object);
}


static bool ResolveAnalysisMergeConflicts(void* ctxt, const char** keys, BNAnalysisMergeConflict** conflicts, size_t conflictCount)
{
	MergeConflictHandler* handler = (MergeConflictHandler*)ctxt;
	std::unordered_map<std::string, Ref<AnalysisMergeConflict>> conflictMap;
	for (size_t i = 0; i < conflictCount; i++)
	{
		conflictMap[keys[i]] = new AnalysisMergeConflict(conflicts[i]);
	}
	return handler->ResolveAnalysisMergeConflicts(conflictMap);
}


static bool ResolveTypeArchiveMergeConflicts(void* ctxt, BNTypeArchiveMergeConflict** conflicts, size_t conflictCount)
{
	MergeConflictHandler* handler = (MergeConflictHandler*)ctxt;
	std::vector<Ref<TypeArchiveMergeConflict>> conflictVec;
	for (size_t i = 0; i < conflictCount; i++)
	{
		conflictVec.push_back(new TypeArchiveMergeConflict(conflicts[i]));
	}
	return handler->ResolveTypeArchiveMergeConflicts(conflictVec);
}


void BinaryNinja::Collaboration::RegisterMergeConflictHandler(MergeConflictHandler* handler)
{
	BNMergeConflictHandlerCallbacks cb;
	cb.context = handler;
	cb.resolveAnalysisMergeConflicts = ResolveAnalysisMergeConflicts;
	cb.resolveTypeArchiveMergeConflicts = ResolveTypeArchiveMergeConflicts;
	BNRegisterMergeConflictHandler(&cb);
}


std::optional<std::string> BinaryNinja::Collaboration::GetSnapshotAuthor(Ref<Database> database, Ref<Snapshot> snapshot)
{
	char* cAuthor = BNCollaborationGetSnapshotAuthor(database->m_object, snapshot->m_object);
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


std::any AnalysisMergeConflict::GetPathItem(const std::string& path)
{
	void* val = BNAnalysisMergeConflictGetPathItem(m_object, path.c_str());
	if (val == nullptr)
		return {};
	return *(std::any*)val;
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


Changeset::Changeset(BNChangeset* changeset)
{
	m_object = changeset;
}


Ref<Database> Changeset::GetDatabase()
{
	BNDatabase* database = BNChangesetGetDatabase(m_object);
	if (database == nullptr)
		return nullptr;
	return new Database(database);
}


Ref<RemoteFile> Changeset::GetFile()
{
	BNRemoteFile* file = BNChangesetGetFile(m_object);
	if (file == nullptr)
		return nullptr;
	return new RemoteFile(file);
}


std::vector<int64_t> Changeset::GetSnapshotIds()
{
	size_t count = 0;
	int64_t* ids = BNChangesetGetSnapshotIds(m_object, &count);
	std::vector<int64_t> result;
	result.insert(result.end(), ids, &ids[count]);
	delete[] ids;
	return result;
}


Ref<CollabUser> Changeset::GetAuthor()
{
	BNCollabUser* author = BNChangesetGetAuthor(m_object);
	if (author == nullptr)
		return nullptr;
	return new CollabUser(author);
}


std::string Changeset::GetName()
{
	char* val = BNChangesetGetName(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


void Changeset::SetName(const std::string& name)
{
	BNChangesetSetName(m_object, name.c_str());
}


CollabSnapshot::CollabSnapshot(BNCollabSnapshot* snapshot)
{
	m_object = snapshot;
}


Ref<RemoteFile> CollabSnapshot::GetFile()
{
	BNRemoteFile* file = BNCollabSnapshotGetFile(m_object);
	if (file == nullptr)
		return nullptr;
	return new RemoteFile(file);
}


Ref<RemoteProject> CollabSnapshot::GetProject()
{
	BNRemoteProject* project = BNCollabSnapshotGetProject(m_object);
	if (project == nullptr)
		return nullptr;
	return new RemoteProject(project);
}


Ref<Remote> CollabSnapshot::GetRemote()
{
	BNRemote* remote = BNCollabSnapshotGetRemote(m_object);
	if (remote == nullptr)
		return nullptr;
	return new Remote(remote);
}


std::string CollabSnapshot::GetUrl()
{
	char* val = BNCollabSnapshotGetUrl(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetId()
{
	char* val = BNCollabSnapshotGetId(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetName()
{
	char* val = BNCollabSnapshotGetName(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetAuthor()
{
	char* val = BNCollabSnapshotGetAuthor(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


int64_t CollabSnapshot::GetCreated()
{
	return BNCollabSnapshotGetCreated(m_object);
}


int64_t CollabSnapshot::GetLastModified()
{
	return BNCollabSnapshotGetLastModified(m_object);
}


std::string CollabSnapshot::GetHash()
{
	char* val = BNCollabSnapshotGetHash(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetSnapshotFileHash()
{
	char* val = BNCollabSnapshotGetSnapshotFileHash(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


bool CollabSnapshot::HasPulledUndoEntries()
{
	return BNCollabSnapshotHasPulledUndoEntries(m_object);
}


bool CollabSnapshot::IsFinalized()
{
	return BNCollabSnapshotIsFinalized(m_object);
}


std::vector<std::string> CollabSnapshot::GetParentIds()
{
	size_t count = 0;
	char** strs = BNCollabSnapshotGetParentIds(m_object, &count);
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
	char** strs = BNCollabSnapshotGetParentIds(m_object, &count);
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
	return BNCollabSnapshotGetAnalysisCacheBuildId(m_object);
}


std::string CollabSnapshot::GetTitle()
{
	char* val = BNCollabSnapshotGetTitle(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetDescription()
{
	char* val = BNCollabSnapshotGetDescription(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::string CollabSnapshot::GetAuthorUsername()
{
	char* val = BNCollabSnapshotGetAuthorUsername(m_object);
	std::string out = val;
	BNFreeString(val);
	return out;
}


std::vector<Ref<CollabSnapshot>> CollabSnapshot::GetParents()
{
	size_t count = 0;
	BNCollabSnapshot** snapshots = BNCollabSnapshotGetParents(m_object, &count);
	std::vector<Ref<CollabSnapshot>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabSnapshot(BNNewCollabSnapshotReference(snapshots[i])));
	}
	BNFreeCollabSnapshotList(snapshots, count);
	return out;
}


std::vector<Ref<CollabSnapshot>> CollabSnapshot::GetChildren()
{
	size_t count = 0;
	BNCollabSnapshot** snapshots = BNCollabSnapshotGetChildren(m_object, &count);
	std::vector<Ref<CollabSnapshot>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabSnapshot(BNNewCollabSnapshotReference(snapshots[i])));
	}
	BNFreeCollabSnapshotList(snapshots, count);
	return out;
}


std::vector<Ref<CollabUndoEntry>> CollabSnapshot::GetUndoEntries()
{
	size_t count = 0;
	BNCollabUndoEntry** entries = BNCollabSnapshotGetUndoEntries(m_object, &count);
	std::vector<Ref<CollabUndoEntry>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new CollabUndoEntry(BNNewCollabUndoEntryReference(entries[i])));
	}
	BNFreeCollabUndoEntryList(entries, count);
	return out;
}


Ref<CollabUndoEntry> CollabSnapshot::GetUndoEntryById(uint64_t id)
{
	BNCollabUndoEntry* entry = BNCollabSnapshotGetUndoEntryById(m_object, id);
	if (entry == nullptr)
		return nullptr;
	return new CollabUndoEntry(entry);
}


void CollabSnapshot::PullUndoEntries(std::function<bool(size_t, size_t)> progress)
{
		ProgressContext pctxt;
	pctxt.callback = progress;
	BNCollabSnapshotPullUndoEntries(m_object, &pctxt, ProgressCallback);
}


Ref<CollabUndoEntry> CollabSnapshot::CreateUndoEntry(std::optional<uint64_t> parent, std::string data)
{
	BNCollabUndoEntry* entry = BNCollabSnapshotCreateUndoEntry(m_object, parent.has_value() ? &*parent : nullptr, data.c_str());
	if (entry == nullptr)
		return nullptr;
	return new CollabUndoEntry(entry);
}


void CollabSnapshot::Finalize()
{
	BNCollabSnapshotFinalize(m_object);
}


std::vector<uint8_t> CollabSnapshot::DownloadSnapshotFile(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	size_t count = 0;
	uint8_t* data = BNCollabSnapshotDownloadSnapshotFile(m_object, &count, &pctxt, ProgressCallback);

	// TODO: should probably error
	if (data == nullptr)
		return {};

	std::vector<uint8_t> out;
	out.insert(out.end(), data, &data[count]);
	free(data);
	return out;
}


std::vector<uint8_t> CollabSnapshot::Download(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	size_t count = 0;
	uint8_t* data = BNCollabSnapshotDownload(m_object, &count, &pctxt, ProgressCallback);

	// TODO: should probably error
	if (data == nullptr)
		return {};

	std::vector<uint8_t> out;
	out.insert(out.end(), data, &data[count]);
	free(data);
	return out;
}


std::vector<uint8_t> CollabSnapshot::DownloadAnalysisCache(std::function<bool(size_t, size_t)> progress)
{
	ProgressContext pctxt;
	pctxt.callback = progress;
	size_t count = 0;
	uint8_t* data = BNCollabSnapshotDownloadAnalysisCache(m_object, &count, &pctxt, ProgressCallback);

	// TODO: should probably error
	if (data == nullptr)
		return {};

	std::vector<uint8_t> out;
	out.insert(out.end(), data, &data[count]);
	free(data);
	return out;
}


CollabUndoEntry::CollabUndoEntry(BNCollabUndoEntry* entry)
{
	m_object = entry;
}
