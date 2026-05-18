// Copyright (c) 2015-2026 Vector 35 Inc
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
#include <cstring>
#include "binaryninjaapi.h"
#include "binaryninjacore.h"

using namespace BinaryNinja;


bool ProjectNotification::BeforeOpenProjectCallback(void* ctxt, BNProject* object)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	return notify->OnBeforeOpenProject(project);
}


void ProjectNotification::AfterOpenProjectCallback(void* ctxt, BNProject* object)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	notify->OnAfterOpenProject(project);
}


bool ProjectNotification::BeforeCloseProjectCallback(void* ctxt, BNProject* object)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	return notify->OnBeforeCloseProject(project);
}


void ProjectNotification::AfterCloseProjectCallback(void* ctxt, BNProject* object)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	notify->OnAfterCloseProject(project);
}


bool ProjectNotification::BeforeProjectMetadataWrittenCallback(void* ctxt, BNProject* object, char* key, BNMetadata* value)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	std::string keyStr = key;
	BNFreeString(key);
	Ref<Metadata> metaVal = new Metadata(BNNewMetadataReference(value));
	return notify->OnBeforeProjectMetadataWritten(project, keyStr, metaVal);
}


void ProjectNotification::AfterProjectMetadataWrittenCallback(void* ctxt, BNProject* object, char* key, BNMetadata* value)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	std::string keyStr = key;
	BNFreeString(key);
	Ref<Metadata> metaVal = new Metadata(BNNewMetadataReference(value));
	notify->OnAfterProjectMetadataWritten(project, keyStr, metaVal);
}


bool ProjectNotification::BeforeProjectFileCreatedCallback(void* ctxt, BNProject* object, BNProjectFile* bnProjectFile)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFile> projectFile = new ProjectFile(BNNewProjectFileReference(bnProjectFile));
	return notify->OnBeforeProjectFileCreated(project, projectFile);
}


void ProjectNotification::AfterProjectFileCreatedCallback(void* ctxt, BNProject* object, BNProjectFile* bnProjectFile)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFile> projectFile = new ProjectFile(BNNewProjectFileReference(bnProjectFile));
	notify->OnAfterProjectFileCreated(project, projectFile);
}


bool ProjectNotification::BeforeProjectFileUpdatedCallback(void* ctxt, BNProject* object, BNProjectFile* bnProjectFile)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFile> projectFile = new ProjectFile(BNNewProjectFileReference(bnProjectFile));
	return notify->OnBeforeProjectFileUpdated(project, projectFile);
}


void ProjectNotification::AfterProjectFileUpdatedCallback(void* ctxt, BNProject* object, BNProjectFile* bnProjectFile)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFile> projectFile = new ProjectFile(BNNewProjectFileReference(bnProjectFile));
	notify->OnAfterProjectFileUpdated(project, projectFile);
}


bool ProjectNotification::BeforeProjectFileDeletedCallback(void* ctxt, BNProject* object, BNProjectFile* bnProjectFile)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFile> projectFile = new ProjectFile(BNNewProjectFileReference(bnProjectFile));
	return notify->OnBeforeProjectFileDeleted(project, projectFile);
}


void ProjectNotification::AfterProjectFileDeletedCallback(void* ctxt, BNProject* object, BNProjectFile* bnProjectFile)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFile> projectFile = new ProjectFile(BNNewProjectFileReference(bnProjectFile));
	notify->OnAfterProjectFileDeleted(project, projectFile);
}


bool ProjectNotification::BeforeProjectFolderCreatedCallback(void* ctxt, BNProject* object, BNProjectFolder* bnProjectFolder)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFolder> projectFolder = new ProjectFolder(BNNewProjectFolderReference(bnProjectFolder));
	return notify->OnBeforeProjectFolderCreated(project, projectFolder);
}


void ProjectNotification::AfterProjectFolderCreatedCallback(void* ctxt, BNProject* object, BNProjectFolder* bnProjectFolder)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFolder> projectFolder = new ProjectFolder(BNNewProjectFolderReference(bnProjectFolder));
	notify->OnAfterProjectFolderCreated(project, projectFolder);
}


bool ProjectNotification::BeforeProjectFolderUpdatedCallback(void* ctxt, BNProject* object, BNProjectFolder* bnProjectFolder)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFolder> projectFolder = new ProjectFolder(BNNewProjectFolderReference(bnProjectFolder));
	return notify->OnBeforeProjectFolderUpdated(project, projectFolder);
}


void ProjectNotification::AfterProjectFolderUpdatedCallback(void* ctxt, BNProject* object, BNProjectFolder* bnProjectFolder)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFolder> projectFolder = new ProjectFolder(BNNewProjectFolderReference(bnProjectFolder));
	notify->OnAfterProjectFolderUpdated(project, projectFolder);
}


bool ProjectNotification::BeforeProjectFolderDeletedCallback(void* ctxt, BNProject* object, BNProjectFolder* bnProjectFolder)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFolder> projectFolder = new ProjectFolder(BNNewProjectFolderReference(bnProjectFolder));
	return notify->OnBeforeProjectFolderDeleted(project, projectFolder);
}


void ProjectNotification::AfterProjectFolderDeletedCallback(void* ctxt, BNProject* object, BNProjectFolder* bnProjectFolder)
{
	ProjectNotification* notify = (ProjectNotification*)ctxt;
	Ref<Project> project = new Project(BNNewProjectReference(object));
	Ref<ProjectFolder> projectFolder = new ProjectFolder(BNNewProjectFolderReference(bnProjectFolder));
	notify->OnAfterProjectFolderDeleted(project, projectFolder);
}


ProjectNotification::ProjectNotification()
{
	m_callbacks.context = this;
	m_callbacks.beforeOpenProject = BeforeOpenProjectCallback;
	m_callbacks.afterOpenProject = AfterOpenProjectCallback;
	m_callbacks.beforeCloseProject = BeforeCloseProjectCallback;
	m_callbacks.afterCloseProject = AfterCloseProjectCallback;
	m_callbacks.beforeProjectMetadataWritten = BeforeProjectMetadataWrittenCallback;
	m_callbacks.afterProjectMetadataWritten = AfterProjectMetadataWrittenCallback;
	m_callbacks.beforeProjectFileCreated = BeforeProjectFileCreatedCallback;
	m_callbacks.afterProjectFileCreated = AfterProjectFileCreatedCallback;
	m_callbacks.beforeProjectFileUpdated = BeforeProjectFileUpdatedCallback;
	m_callbacks.afterProjectFileUpdated = AfterProjectFileUpdatedCallback;
	m_callbacks.beforeProjectFileDeleted = BeforeProjectFileDeletedCallback;
	m_callbacks.afterProjectFileDeleted = AfterProjectFileDeletedCallback;
	m_callbacks.beforeProjectFolderCreated = BeforeProjectFolderCreatedCallback;
	m_callbacks.afterProjectFolderCreated = AfterProjectFolderCreatedCallback;
	m_callbacks.beforeProjectFolderUpdated = BeforeProjectFolderUpdatedCallback;
	m_callbacks.afterProjectFolderUpdated = AfterProjectFolderUpdatedCallback;
	m_callbacks.beforeProjectFolderDeleted = BeforeProjectFolderDeletedCallback;
	m_callbacks.afterProjectFolderDeleted = AfterProjectFolderDeletedCallback;
}


Project::Project(BNProject* project)
{
	m_object = project;
}


Ref<Project> Project::CreateProject(const std::string& path, const std::string& name)
{
	BNProject* bnproj = BNCreateProject(path.c_str(), name.c_str());
	if (!bnproj)
		return nullptr;
	return new Project(bnproj);
}


Ref<Project> Project::OpenProject(const std::string& path)
{
	BNProject* bnproj = BNOpenProject(path.c_str());
	if (!bnproj)
		return nullptr;
	return new Project(bnproj);
}


std::vector<Ref<Project>> Project::GetOpenProjects()
{
	size_t count = 0;
	BNProject** bnprojs = BNGetOpenProjects(&count);

	std::vector<Ref<Project>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new Project(BNNewProjectReference(bnprojs[i])));
	}
	BNFreeProjectList(bnprojs, count);
	return result;
}


bool Project::Open()
{
	return BNProjectOpen(m_object);
}


bool Project::Close()
{
	return BNProjectClose(m_object);
}


std::string Project::GetId() const
{
	char* id = BNProjectGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


bool Project::IsOpen() const
{
	return BNProjectIsOpen(m_object);
}


std::string Project::GetPath() const
{
	char* path = BNProjectGetPath(m_object);
	std::string result = path;
	BNFreeString(path);
	return result;
}

std::string Project::GetFilePathInProject(const Ref<ProjectFile>& file) const
{
	char* path = BNProjectGetFilePathInProject(m_object, file->m_object);
	std::string result = path;
	BNFreeString(path);
	return result;
}



std::string Project::GetName() const
{
	char* name = BNProjectGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


bool Project::SetName(const std::string& name)
{
	return BNProjectSetName(m_object, name.c_str());
}


std::string Project::GetDescription() const
{
	char* description = BNProjectGetDescription(m_object);
	std::string result = description;
	BNFreeString(description);
	return result;
}


bool Project::SetDescription(const std::string& description)
{
	return BNProjectSetDescription(m_object, description.c_str());
}


Ref<Metadata> Project::QueryMetadata(const std::string& key)
{
	BNMetadata* value = BNProjectQueryMetadata(m_object, key.c_str());
	if (value == nullptr)
		return nullptr;
	return new Metadata(value);
}


bool Project::StoreMetadata(const std::string& key, Ref<Metadata> value)
{
	return BNProjectStoreMetadata(m_object, key.c_str(), value->m_object);
}


bool Project::RemoveMetadata(const std::string& key)
{
	return BNProjectRemoveMetadata(m_object, key.c_str());
}


Ref<ProjectFolder> Project::CreateFolderFromPath(const std::string& path, Ref<ProjectFolder> parent, const std::string& description,
	const ProgressFunction& progressCallback)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	BNProjectFolder* folder = BNProjectCreateFolderFromPath(m_object, path.c_str(), parent ? parent->m_object : nullptr, description.c_str(), &cb, ProgressCallback);
	if (folder == nullptr)
		return nullptr;
	return new ProjectFolder(folder);
}


Ref<ProjectFolder> Project::CreateFolder(Ref<ProjectFolder> parent, const std::string& name, const std::string& description)
{
	BNProjectFolder* folder = BNProjectCreateFolder(m_object, parent ? parent->m_object : nullptr, name.c_str(), description.c_str());
	if (folder == nullptr)
		return nullptr;
	return new ProjectFolder(folder);
}


Ref<ProjectFolder> Project::CreateFolderUnsafe(Ref<ProjectFolder> parent, const std::string& name, const std::string& description, const std::string& id)
{
	BNProjectFolder* folder = BNProjectCreateFolderUnsafe(m_object, parent ? parent->m_object : nullptr, name.c_str(), description.c_str(), id.c_str());
	if (folder == nullptr)
		return nullptr;
	return new ProjectFolder(folder);
}


std::vector<Ref<ProjectFolder>> Project::GetFolders() const
{
	size_t count;

	BNProjectFolder** folders = BNProjectGetFolders(m_object, &count);
	std::vector<Ref<ProjectFolder>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new ProjectFolder(BNNewProjectFolderReference(folders[i])));
	}

	BNFreeProjectFolderList(folders, count);
	return result;
}


Ref<ProjectFolder> Project::GetFolderById(const std::string& id) const
{
	BNProjectFolder* folder = BNProjectGetFolderById(m_object, id.c_str());
	if (folder == nullptr)
		return nullptr;
	return new ProjectFolder(folder);
}


bool Project::PushFolder(Ref<ProjectFolder> folder)
{
	return BNProjectPushFolder(m_object, folder->m_object);
}


bool Project::DeleteFolder(Ref<ProjectFolder> folder, const ProgressFunction& progressCallback)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	return BNProjectDeleteFolder(m_object, folder->m_object, &cb, ProgressCallback);
}


Ref<ProjectFile> Project::CreateFileFromPath(const std::string& path, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const ProgressFunction& progressCallback)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	BNProjectFile* file = BNProjectCreateFileFromPath(m_object, path.c_str(), folder ? folder->m_object : nullptr, name.c_str(), description.c_str(), &cb, ProgressCallback);
	if (file == nullptr)
		return nullptr;
	return new ProjectFile(file);
}


Ref<ProjectFile> Project::CreateFileFromPathUnsafe(const std::string& path, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const std::string& id, int64_t creationTimestamp, const ProgressFunction& progressCallback)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	BNProjectFile* file = BNProjectCreateFileFromPathUnsafe(m_object, path.c_str(), folder ? folder->m_object : nullptr, name.c_str(), description.c_str(), id.c_str(), creationTimestamp, &cb, ProgressCallback);
	if (file == nullptr)
		return nullptr;
	return new ProjectFile(file);
}


Ref<ProjectFile> Project::CreateFile_(const std::vector<uint8_t>& contents, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const ProgressFunction& progressCallback)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	BNProjectFile* file = BNProjectCreateFile(m_object, contents.data(), contents.size(), folder ? folder->m_object : nullptr, name.c_str(), description.c_str(), &cb, ProgressCallback);
	if (file == nullptr)
		return nullptr;
	return new ProjectFile(file);
}


Ref<ProjectFile> Project::CreateFileUnsafe(const std::vector<uint8_t>& contents, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const std::string& id, int64_t creationTimestamp, const ProgressFunction& progressCallback)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	BNProjectFile* file = BNProjectCreateFileUnsafe(m_object, contents.data(), contents.size(), folder ? folder->m_object : nullptr, name.c_str(), description.c_str(), id.c_str(), creationTimestamp, &cb, ProgressCallback);
	if (file == nullptr)
		return nullptr;
	return new ProjectFile(file);
}


std::vector<Ref<ProjectFile>> Project::GetFiles() const
{
	size_t count;
	BNProjectFile** files = BNProjectGetFiles(m_object, &count);

	std::vector<Ref<ProjectFile>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new ProjectFile(BNNewProjectFileReference(files[i])));
	}

	BNFreeProjectFileList(files, count);
	return result;
}


Ref<ProjectFile> Project::GetFileById(const std::string& id) const
{
	BNProjectFile* file = BNProjectGetFileById(m_object, id.c_str());
	if (file == nullptr)
		return nullptr;
	return new ProjectFile(file);
}


Ref<ProjectFile> Project::GetFileByPathOnDisk(const std::string& path) const
{
	BNProjectFile* file = BNProjectGetFileByPathOnDisk(m_object, path.c_str());
	if (file == nullptr)
		return nullptr;
	return new ProjectFile(file);
}


std::vector<Ref<ProjectFile>> Project::GetFilesByPathInProject(
	const std::string& path
) const
{
	size_t count;
	BNProjectFile** files = BNProjectGetFilesByPathInProject(m_object, path.c_str(), &count);

	std::vector<Ref<ProjectFile>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.emplace_back(new ProjectFile(BNNewProjectFileReference(files[i])));
	}

	BNFreeProjectFileList(files, count);
	return result;
}


std::vector<Ref<ProjectFile>> Project::GetFilesInFolder(Ref<ProjectFolder> folder) const
{
	size_t count;
	BNProjectFile** files = BNProjectGetFilesInFolder(m_object, folder ? folder->m_object : nullptr, &count);
	if (!files)
		return {};

	std::vector<Ref<ProjectFile>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.emplace_back(new ProjectFile(BNNewProjectFileReference(files[i])));
	}

	BNFreeProjectFileList(files, count);
	return result;
}


bool Project::PushFile(Ref<ProjectFile> file)
{
	return BNProjectPushFile(m_object, file->m_object);
}


bool Project::DeleteFile_(Ref<ProjectFile> file)
{
	return BNProjectDeleteFile(m_object, file->m_object);
}


void Project::RegisterNotification(ProjectNotification* notify)
{
	BNRegisterProjectNotification(m_object, notify->GetCallbacks());
}


void Project::UnregisterNotification(ProjectNotification* notify)
{
	BNUnregisterProjectNotification(m_object, notify->GetCallbacks());
}


bool Project::BeginBulkOperation()
{
	return BNProjectBeginBulkOperation(m_object);
}


bool Project::EndBulkOperation()
{
	return BNProjectEndBulkOperation(m_object);
}


Ref<Collaboration::RemoteProject> Project::GetRemoteProject()
{

	BNRemoteProject* project = BNProjectGetRemoteProject(m_object);
	if (project == nullptr)
		return nullptr;
	return new Collaboration::RemoteProject(project);
}


ProjectFile::ProjectFile(BNProjectFile* file)
{
	m_object = file;
}


Ref<Project> ProjectFile::GetProject() const
{
	return new Project(BNProjectFileGetProject(m_object));
}


std::string ProjectFile::GetPathOnDisk() const
{
	char* path = BNProjectFileGetPathOnDisk(m_object);
	std::string result = path;
	BNFreeString(path);
	return result;
}

std::string ProjectFile::GetPathInProject() const
{
	char* path = BNProjectFileGetPathInProject(m_object);
	std::string result = path;
	BNFreeString(path);
	return result;
}


bool ProjectFile::ExistsOnDisk() const
{
	return BNProjectFileExistsOnDisk(m_object);
}


std::string ProjectFile::GetName() const
{
	char* name = BNProjectFileGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


std::string ProjectFile::GetDescription() const
{
	char* description = BNProjectFileGetDescription(m_object);
	std::string result = description;
	BNFreeString(description);
	return result;
}


bool ProjectFile::SetName(const std::string& name)
{
	return BNProjectFileSetName(m_object, name.c_str());
}


bool ProjectFile::SetDescription(const std::string& description)
{
	return BNProjectFileSetDescription(m_object, description.c_str());
}


std::string ProjectFile::GetId() const
{
	char* id = BNProjectFileGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


Ref<ProjectFolder> ProjectFile::GetFolder() const
{
	BNProjectFolder* folder = BNProjectFileGetFolder(m_object);
	if (!folder)
		return nullptr;
	return new ProjectFolder(folder);
}


bool ProjectFile::SetFolder(Ref<ProjectFolder> folder)
{
	return BNProjectFileSetFolder(m_object, folder ? folder->m_object : nullptr);
}


bool ProjectFile::Export(const std::string& destination) const
{
	return BNProjectFileExport(m_object, destination.c_str());
}


int64_t ProjectFile::GetCreationTimestamp() const
{
	return BNProjectFileGetCreationTimestamp(m_object);
}


bool ProjectFile::IsReady() const
{
	return BNProjectFileIsReady(m_object);
}


bool ProjectFile::SetReady(bool ready)
{
	return BNProjectFileSetReady(m_object, ready);
}


bool ProjectFile::AddDependency(Ref<ProjectFile> file)
{
	return BNProjectFileAddDependency(m_object, file->m_object);
}


bool ProjectFile::RemoveDependency(Ref<ProjectFile> file)
{
	return BNProjectFileRemoveDependency(m_object, file->m_object);
}


std::vector<Ref<ProjectFile>> ProjectFile::GetDependencies() const
{
	size_t count = 0;
	BNProjectFile** deps = BNProjectFileGetDependencies(m_object, &count);
	std::vector<Ref<ProjectFile>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new ProjectFile(BNNewProjectFileReference(deps[i])));
	}
	BNFreeProjectFileList(deps, count);
	return out;
}


std::vector<Ref<ProjectFile>> ProjectFile::GetRequiredBy() const
{
	size_t count = 0;
	BNProjectFile** reqBy = BNProjectFileGetRequiredBy(m_object, &count);
	std::vector<Ref<ProjectFile>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new ProjectFile(BNNewProjectFileReference(reqBy[i])));
	}
	BNFreeProjectFileList(reqBy, count);
	return out;
}


ProjectFolder::ProjectFolder(BNProjectFolder* folder)
{
	m_object = folder;
}


Ref<Project> ProjectFolder::GetProject() const
{
	return new Project(BNProjectFolderGetProject(m_object));
}


std::string ProjectFolder::GetId() const
{
	char* id = BNProjectFolderGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::string ProjectFolder::GetName() const
{
	char* name = BNProjectFolderGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


std::string ProjectFolder::GetDescription() const
{
	char* desc = BNProjectFolderGetDescription(m_object);
	std::string result = desc;
	BNFreeString(desc);
	return result;
}


bool ProjectFolder::SetName(const std::string& name)
{
	return BNProjectFolderSetName(m_object, name.c_str());
}


bool ProjectFolder::SetDescription(const std::string& description)
{
	return BNProjectFolderSetDescription(m_object, description.c_str());
}


Ref<ProjectFolder> ProjectFolder::GetParent() const
{
	BNProjectFolder* parent = BNProjectFolderGetParent(m_object);
	if (!parent)
		return nullptr;
	return new ProjectFolder(parent);
}


bool ProjectFolder::SetParent(Ref<ProjectFolder> parent)
{
	return BNProjectFolderSetParent(m_object, parent ? parent->m_object : nullptr);
}


bool ProjectFolder::Export(const std::string& destination, const ProgressFunction& progressCallback) const
{
	ProgressContext cb;
	cb.callback = progressCallback;
	return BNProjectFolderExport(m_object, destination.c_str(), &cb, ProgressCallback);
}


std::vector<Ref<ProjectFile>> ProjectFolder::GetFiles() const
{
	size_t count = 0;
	BNProjectFile** files = BNProjectFolderGetFiles(m_object, &count);
	if (!files)
		return {};

	std::vector<Ref<ProjectFile>> out;
	out.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		out.push_back(new ProjectFile(BNNewProjectFileReference(files[i])));
	}
	BNFreeProjectFileList(files, count);
	return out;
}
