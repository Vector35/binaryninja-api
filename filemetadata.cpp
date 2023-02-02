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
#include <cstring>
#include "binaryninjaapi.h"
#include "binaryninjacore.h"

using namespace BinaryNinja;
using namespace Json;
using namespace std;


char* NavigationHandler::GetCurrentViewCallback(void* ctxt)
{
	NavigationHandler* handler = (NavigationHandler*)ctxt;
	string result = handler->GetCurrentView();
	return BNAllocString(result.c_str());
}


uint64_t NavigationHandler::GetCurrentOffsetCallback(void* ctxt)
{
	NavigationHandler* handler = (NavigationHandler*)ctxt;
	return handler->GetCurrentOffset();
}


bool NavigationHandler::NavigateCallback(void* ctxt, const char* view, uint64_t offset)
{
	NavigationHandler* handler = (NavigationHandler*)ctxt;
	return handler->Navigate(view, offset);
}


NavigationHandler::NavigationHandler()
{
	m_callbacks.context = this;
	m_callbacks.getCurrentView = GetCurrentViewCallback;
	m_callbacks.getCurrentOffset = GetCurrentOffsetCallback;
	m_callbacks.navigate = NavigateCallback;
}


FileMetadata::FileMetadata()
{
	m_object = BNCreateFileMetadata();
}


FileMetadata::FileMetadata(const string& filename)
{
	m_object = BNCreateFileMetadata();
	BNSetFilename(m_object, filename.c_str());
}


FileMetadata::FileMetadata(Ref<ProjectFile> projectFile)
{
	m_object = BNCreateFileMetadata();
	BNSetProjectFile(m_object, projectFile->m_object);
	BNSetFilename(m_object, projectFile->GetPathOnDisk().c_str());
}


FileMetadata::FileMetadata(BNFileMetadata* file)
{
	m_object = file;
}


void FileMetadata::Close()
{
	BNCloseFile(m_object);
}


void FileMetadata::SetNavigationHandler(NavigationHandler* handler)
{
	if (handler)
		BNSetFileMetadataNavigationHandler(m_object, handler->GetCallbacks());
	else
		BNSetFileMetadataNavigationHandler(m_object, nullptr);
}


string FileMetadata::GetOriginalFilename() const
{
	char* str = BNGetOriginalFilename(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


void FileMetadata::SetOriginalFilename(const string& name)
{
	BNSetOriginalFilename(m_object, name.c_str());
}


string FileMetadata::GetFilename() const
{
	char* str = BNGetFilename(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


void FileMetadata::SetFilename(const string& name)
{
	BNSetFilename(m_object, name.c_str());
}


bool FileMetadata::IsModified() const
{
	return BNIsFileModified(m_object);
}


bool FileMetadata::IsAnalysisChanged() const
{
	return BNIsAnalysisChanged(m_object);
}


void FileMetadata::MarkFileModified()
{
	BNMarkFileModified(m_object);
}


void FileMetadata::MarkFileSaved()
{
	BNMarkFileSaved(m_object);
}


bool FileMetadata::IsBackedByDatabase(const string& binaryViewType) const
{
	return BNIsBackedByDatabase(m_object, binaryViewType.c_str());
}


bool FileMetadata::CreateDatabase(const string& name, BinaryView* data, Ref<SaveSettings> settings)
{
	return BNCreateDatabase(data->GetObject(), name.c_str(), settings ? settings->GetObject() : nullptr);
}


bool FileMetadata::CreateDatabase(const string& name, BinaryView* data,
    const function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	return BNCreateDatabaseWithProgress(
	    data->GetObject(), name.c_str(), &cb, ProgressCallback, settings ? settings->GetObject() : nullptr);
}


Ref<BinaryView> FileMetadata::OpenExistingDatabase(const string& path)
{
	BNBinaryView* data = BNOpenExistingDatabase(m_object, path.c_str());
	if (!data)
		return nullptr;
	return new BinaryView(data);
}


Ref<BinaryView> FileMetadata::OpenExistingDatabase(
    const string& path, const function<bool(size_t progress, size_t total)>& progressCallback)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	BNBinaryView* data = BNOpenExistingDatabaseWithProgress(m_object, path.c_str(), &cb, ProgressCallback);
	if (!data)
		return nullptr;
	return new BinaryView(data);
}


Ref<BinaryView> FileMetadata::OpenDatabaseForConfiguration(const string& path)
{
	BNBinaryView* data = BNOpenDatabaseForConfiguration(m_object, path.c_str());
	if (!data)
		return nullptr;
	return new BinaryView(data);
}


bool FileMetadata::SaveAutoSnapshot(BinaryView* data, Ref<SaveSettings> settings)
{
	return BNSaveAutoSnapshot(data->GetObject(), settings ? settings->GetObject() : nullptr);
}


bool FileMetadata::SaveAutoSnapshot(
    BinaryView* data, const function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	return BNSaveAutoSnapshotWithProgress(
	    data->GetObject(), &cb, ProgressCallback, settings ? settings->GetObject() : nullptr);
}


void FileMetadata::GetSnapshotData(
    Ref<KeyValueStore> data, Ref<KeyValueStore> cache, const std::function<bool(size_t, size_t)>& progress)
{
	ProgressContext cb;
	cb.callback = progress;
	BNGetSnapshotData(GetObject(), data->GetObject(), cache->GetObject(), &cb, ProgressCallback);
}


void FileMetadata::ApplySnapshotData(BinaryView* file, Ref<KeyValueStore> data, Ref<KeyValueStore> cache,
    const std::function<bool(size_t, size_t)>& progress, bool openForConfiguration, bool restoreRawView)
{
	ProgressContext cb;
	cb.callback = progress;
	BNApplySnapshotData(GetObject(), file->GetObject(), data->GetObject(), cache->GetObject(), &cb,
	    ProgressCallback, openForConfiguration, restoreRawView);
}


Ref<Database> FileMetadata::GetDatabase()
{
	BNDatabase* db = BNGetFileMetadataDatabase(m_object);
	if (db == nullptr)
		return nullptr;
	return new Database(db);
}


bool FileMetadata::Rebase(BinaryView* data, uint64_t address)
{
	return BNRebase(data->GetObject(), address);
}


bool FileMetadata::Rebase(
    BinaryView* data, uint64_t address, const function<bool(size_t progress, size_t total)>& progressCallback)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	return BNRebaseWithProgress(data->GetObject(), address, &cb, ProgressCallback);
}


bool FileMetadata::CreateSnapshotedView(BinaryView *data, const std::string &viewName)
{
	return BNCreateSnapshotedView(data->GetObject(), viewName.c_str());
}


bool FileMetadata::CreateSnapshotedView(BinaryView* data, const std::string& viewName,
										const function<bool(size_t progress, size_t total)>& progressCallback)
{
	ProgressContext cb;
	cb.callback = progressCallback;
	return BNCreateSnapshotedViewWithProgress(data->GetObject(), viewName.c_str(), &cb, ProgressCallback);
}


bool FileMetadata::RunUndoableTransaction(std::function<bool()> func)
{
	auto undo = BeginUndoActions(false);
	try
	{
		bool result = func();
		if (result)
		{
			CommitUndoActions(undo);
		}
		else
		{
			RevertUndoActions(undo);
		}
		return result;
	}
	catch (...)
	{
		RevertUndoActions(undo);
		throw;
	}
}


std::string FileMetadata::BeginUndoActions(bool anonymousAllowed)
{
	char* id = BNBeginUndoActions(m_object, anonymousAllowed);
	std::string result = id;
	BNFreeString(id);
	return result;
}


void FileMetadata::CommitUndoActions(const std::string& id)
{
	BNCommitUndoActions(m_object, id.c_str());
}


void FileMetadata::RevertUndoActions(const std::string& id)
{
	BNRevertUndoActions(m_object, id.c_str());
}


void FileMetadata::ForgetUndoActions(const std::string &id)
{
	BNForgetUndoActions(m_object, id.c_str());
}


bool FileMetadata::CanUndo()
{
	return BNCanUndo(m_object);
}


bool FileMetadata::Undo()
{
	return BNUndo(m_object);
}


bool FileMetadata::CanRedo()
{
	return BNCanRedo(m_object);
}


bool FileMetadata::Redo()
{
	return BNRedo(m_object);
}

vector<Ref<User>> FileMetadata::GetUsers()
{
	size_t count;
	BNUser** users = BNGetUsers(m_object, &count);

	vector<Ref<User>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new User(BNNewUserReference(users[i])));

	BNFreeUserList(users, count);
	return result;
}


vector<UndoEntry> FileMetadata::GetUndoEntries()
{
	size_t numEntries;
	BNUndoEntry* entries = BNGetUndoEntries(m_object, &numEntries);

	vector<UndoEntry> result;
	result.reserve(numEntries);
	for (size_t i = 0; i < numEntries; i++)
	{
		if (!entries[i].valid)
			continue;
		UndoEntry temp;
		temp.timestamp = entries[i].timestamp;
		temp.id = entries[i].id;
		temp.user = new User(BNNewUserReference(entries[i].user));
		size_t actionCount = entries[i].actionCount;
		for (size_t actionIndex = 0; actionIndex < actionCount; actionIndex++)
		{
			temp.actions.emplace_back(entries[i].actions[actionIndex]);
		}
		result.push_back(temp);
	}

	// BNFreeUndoEntries(entries, count);
	return result;
}


vector<UndoEntry> FileMetadata::GetRedoEntries()
{
	size_t numEntries;
	BNUndoEntry* entries = BNGetRedoEntries(m_object, &numEntries);

	vector<UndoEntry> result;
	result.reserve(numEntries);
	for (size_t i = 0; i < numEntries; i++)
	{
		if (!entries[i].valid)
			continue;
		UndoEntry temp;
		temp.timestamp = entries[i].timestamp;
		temp.id = entries[i].id;
		temp.user = new User(BNNewUserReference(entries[i].user));
		size_t actionCount = entries[i].actionCount;
		for (size_t actionIndex = 0; actionIndex < actionCount; actionIndex++)
		{
			temp.actions.emplace_back(entries[i].actions[actionIndex]);
		}
		result.push_back(temp);
	}

	// BNFreeUndoEntries(entries, count);
	return result;
}


std::optional<UndoEntry> FileMetadata::GetLastUndoEntry()
{
	BNUndoEntry bnEntry = BNGetLastUndoEntry(m_object);

	if (!bnEntry.valid)
		return {};

	UndoEntry entry;
	entry.timestamp = bnEntry.timestamp;
	entry.id = bnEntry.id;
	entry.user = new User(BNNewUserReference(bnEntry.user));
	size_t actionCount = bnEntry.actionCount;
	for (size_t actionIndex = 0; actionIndex < actionCount; actionIndex++)
	{
		entry.actions.emplace_back(bnEntry.actions[actionIndex]);
	}

	return entry;
}


std::optional<UndoEntry> FileMetadata::GetLastRedoEntry()
{
	BNUndoEntry bnEntry = BNGetLastRedoEntry(m_object);

	if (!bnEntry.valid)
		return {};

	UndoEntry entry;
	entry.timestamp = bnEntry.timestamp;
	entry.id = bnEntry.id;
	entry.user = new User(BNNewUserReference(bnEntry.user));
	size_t actionCount = bnEntry.actionCount;
	for (size_t actionIndex = 0; actionIndex < actionCount; actionIndex++)
	{
		entry.actions.emplace_back(bnEntry.actions[actionIndex]);
	}

	return entry;
}


std::optional<std::string> FileMetadata::GetLastUndoEntryTitle()
{
	char* title = BNGetLastUndoEntryTitle(m_object);
	if (!title)
	{
		return std::nullopt;
	}
	std::string titleStr = title;
	BNFreeString(title);
	return titleStr;
}


std::optional<std::string> FileMetadata::GetLastRedoEntryTitle()
{
	char* title = BNGetLastRedoEntryTitle(m_object);
	if (!title)
	{
		return std::nullopt;
	}
	std::string titleStr = title;
	BNFreeString(title);
	return titleStr;
}


void FileMetadata::ClearUndoEntries()
{
	BNClearUndoEntries(m_object);
}


string FileMetadata::GetCurrentView()
{
	char* view = BNGetCurrentView(m_object);
	string result = view;
	BNFreeString(view);
	return result;
}


uint64_t FileMetadata::GetCurrentOffset()
{
	return BNGetCurrentOffset(m_object);
}


bool FileMetadata::Navigate(const string& view, uint64_t offset)
{
	return BNNavigate(m_object, view.c_str(), offset);
}


Ref<BinaryView> FileMetadata::GetViewOfType(const string& name)
{
	BNBinaryView* view = BNGetFileViewOfType(m_object, name.c_str());
	if (!view)
		return nullptr;
	return new BinaryView(view);
}

std::vector<std::string> FileMetadata::GetExistingViews() const
{
	size_t count;
	char** views = BNGetExistingViews(m_object, &count);
	vector<string> result;
	result.reserve(count);

	for (size_t i = 0; i < count; i++)
		result.push_back(string(views[i]));

	BNFreeStringList(views, count);
	return result;
}


size_t FileMetadata::GetSessionId() const
{
	return BNFileMetadataGetSessionId(m_object);
}


bool FileMetadata::IsSnapshotDataAppliedWithoutError() const
{
	return BNIsSnapshotDataAppliedWithoutError(m_object);
}


void FileMetadata::UnregisterViewOfType(const std::string& type, BinaryNinja::Ref<BinaryNinja::BinaryView> data)
{
	BNUnregisterViewOfType(m_object, type.c_str(), data->GetObject());
}


void FileMetadata::SetProjectFile(Ref<ProjectFile> projectFile)
{
	BNSetProjectFile(m_object, projectFile ? projectFile->m_object : nullptr);
}


Ref<ProjectFile> FileMetadata::GetProjectFile() const
{
	BNProjectFile* bin = BNGetProjectFile(m_object);
	if (!bin)
		return nullptr;
	return new ProjectFile(bin);
}


SaveSettings::SaveSettings()
{
	m_object = BNCreateSaveSettings();
}


SaveSettings::SaveSettings(BNSaveSettings* settings)
{
	m_object = settings;
}


bool SaveSettings::IsOptionSet(BNSaveOption option) const
{
	return BNIsSaveSettingsOptionSet(m_object, option);
}


void SaveSettings::SetOption(BNSaveOption option, bool state)
{
	BNSetSaveSettingsOption(m_object, option, state);
}


std::string SaveSettings::GetName() const
{
	char* name = BNGetSaveSettingsName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


void SaveSettings::SetName(const std::string& name)
{
	BNSetSaveSettingsName(m_object, name.c_str());
}
