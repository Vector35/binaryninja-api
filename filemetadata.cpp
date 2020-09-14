// Copyright (c) 2015-2021 Vector 35 Inc
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

using namespace BinaryNinja;
using namespace Json;
using namespace std;


struct DatabaseProgressCallbackContext
{
	std::function<void(size_t, size_t)> func;
};


static void DatabaseProgressCallback(void* ctxt, size_t progress, size_t total)
{
	DatabaseProgressCallbackContext* cb = (DatabaseProgressCallbackContext*)ctxt;
	cb->func(progress, total);
}


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
	const function<void(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings)
{
	DatabaseProgressCallbackContext cb;
	cb.func = progressCallback;
	return BNCreateDatabaseWithProgress(data->GetObject(), name.c_str(), &cb, DatabaseProgressCallback, settings ? settings->GetObject() : nullptr);
}


Ref<BinaryView> FileMetadata::OpenExistingDatabase(const string& path)
{
	BNBinaryView* data = BNOpenExistingDatabase(m_object, path.c_str());
	if (!data)
		return nullptr;
	return new BinaryView(data);
}


Ref<BinaryView> FileMetadata::OpenExistingDatabase(const string& path,
	const function<void(size_t progress, size_t total)>& progressCallback)
{
	DatabaseProgressCallbackContext cb;
	cb.func = progressCallback;
	BNBinaryView* data = BNOpenExistingDatabaseWithProgress(m_object, path.c_str(), &cb, DatabaseProgressCallback);
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


bool FileMetadata::SaveAutoSnapshot(BinaryView* data,
	const function<void(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings)
{
	DatabaseProgressCallbackContext cb;
	cb.func = progressCallback;
	return BNSaveAutoSnapshotWithProgress(data->GetObject(), &cb, DatabaseProgressCallback, settings ? settings->GetObject() : nullptr);
}


void FileMetadata::GetSnapshotData(Ref<KeyValueStore> data, Ref<KeyValueStore> cache,
	const std::function<void(size_t, size_t)>& progress)
{
	DatabaseProgressCallbackContext cb;
	cb.func = progress;
	BNGetSnapshotData(GetObject(), data->GetObject(), cache->GetObject(), &cb, DatabaseProgressCallback);
}


void FileMetadata::ApplySnapshotData(BinaryView* file, Ref<KeyValueStore> data, Ref<KeyValueStore> cache,
	const std::function<void(size_t, size_t)>& progress, bool openForConfiguration, bool restoreRawView)
{
	DatabaseProgressCallbackContext cb;
	cb.func = progress;
	BNApplySnapshotData(GetObject(), file->GetObject(), data->GetObject(), cache->GetObject(), &cb, DatabaseProgressCallback, openForConfiguration, restoreRawView);
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


bool FileMetadata::Rebase(BinaryView* data, uint64_t address, const function<void(size_t progress, size_t total)>& progressCallback)
{
	DatabaseProgressCallbackContext cb;
	cb.func = progressCallback;
	return BNRebaseWithProgress(data->GetObject(), address, &cb, DatabaseProgressCallback);
}


MergeResult FileMetadata::MergeUserAnalysis(const std::string& name, const std::function<void(size_t, size_t)>& progress, std::vector<string> excludedHashes)
{
	size_t numHashes = excludedHashes.size();
	char** tempList = new char*[numHashes];
	for (size_t i = 0; i < numHashes; i++)
	{
		tempList[i] = BNAllocString(excludedHashes[i].c_str());
	}

	DatabaseProgressCallbackContext cb;
	cb.func = progress;

	BNMergeResult bnResult = BNMergeUserAnalysis(m_object, name.c_str(), &cb, DatabaseProgressCallback, tempList, numHashes);
	//BNFreeStringList(hashList, numHashes);
	MergeResult result(bnResult);
	return result;
}


void FileMetadata::BeginUndoActions()
{
	BNBeginUndoActions(m_object);
}


void FileMetadata::CommitUndoActions()
{
	BNCommitUndoActions(m_object);
}


bool FileMetadata::Undo()
{
	return BNUndo(m_object);
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
		UndoEntry temp;
		temp.timestamp = entries[i].timestamp;
		temp.hash = entries[i].hash;
		temp.user = new User(BNNewUserReference(entries[i].user));
		size_t actionCount = entries[i].actionCount;
		for (size_t actionIndex = 0; actionIndex < actionCount; actionIndex++)
		{
			temp.actions.emplace_back(entries[i].actions[actionIndex]);
		}
		result.push_back(temp);
	}

	//BNFreeUndoEntries(entries, count);
	return result;
}


void FileMetadata::ClearUndoEntries()
{
	BNClearUndoEntries(m_object);
}


bool FileMetadata::OpenProject()
{
	return BNOpenProject(m_object);
}


void FileMetadata::CloseProject()
{
	BNCloseProject(m_object);
}


bool FileMetadata::IsProjectOpen()
{
	return BNIsProjectOpen(m_object);
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

bool FileMetadata::IsSnapshotDataAppliedWithoutError() const
{
	return BNIsSnapshotDataAppliedWithoutError(m_object);
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
