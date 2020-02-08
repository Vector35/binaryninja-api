// Copyright (c) 2015-2020 Vector 35 Inc
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


void UndoAction::FreeCallback(void* ctxt)
{
	UndoAction* action = (UndoAction*)ctxt;
	delete action;
}


void UndoAction::UndoCallback(void* ctxt, BNBinaryView* data)
{
	UndoAction* action = (UndoAction*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	action->Undo(view);
}


void UndoAction::RedoCallback(void* ctxt, BNBinaryView* data)
{
	UndoAction* action = (UndoAction*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	action->Redo(view);
}


char* UndoAction::SerializeCallback(void* ctxt)
{
	try
	{
		UndoAction* action = (UndoAction*)ctxt;
		Value data = action->Serialize();
		Json::StreamWriterBuilder builder;
		builder["indentation"] = "";
		string json = Json::writeString(builder, data);
		return BNAllocString(json.c_str());
	}
	catch (exception& e)
	{
		LogError("Undo action failed to serialize: %s", e.what());
		return nullptr;
	}
}


UndoAction::UndoAction(const string& name, BNActionType action): m_typeName(name), m_actionType(action)
{
}


BNUndoAction UndoAction::GetCallbacks()
{
	BNUndoAction action;
	action.type = m_actionType;
	action.context = this;
	action.freeObject = FreeCallback;
	action.undo = UndoCallback;
	action.redo = RedoCallback;
	action.serialize = SerializeCallback;
	return action;
}


void UndoAction::Add(BNBinaryView* view)
{
	BNUndoAction action = GetCallbacks();
	BNAddUndoAction(view, m_typeName.c_str(), &action);
}


bool UndoActionType::DeserializeCallback(void* ctxt, const char* data, BNUndoAction* result)
{
	try
	{
		UndoActionType* type = (UndoActionType*)ctxt;
		unique_ptr<CharReader> reader(CharReaderBuilder().newCharReader());
		Value val;
		string errors;
		if (!reader->parse(data, data + strlen(data), &val, &errors))
		{
			LogError("Invalid JSON while deserializing undo action");
			return false;
		}

		UndoAction* action = type->Deserialize(val);
		if (!action)
			return false;

		*result = action->GetCallbacks();
		return true;
	}
	catch (exception& e)
	{
		LogError("Error while deserializing undo action: %s", e.what());
		return false;
	}
}


UndoActionType::UndoActionType(const string& name): m_nameForRegister(name)
{
}


void UndoActionType::Register(UndoActionType* type)
{
	BNRegisterUndoActionType(type->m_nameForRegister.c_str(), type, DeserializeCallback);
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


bool FileMetadata::IsBackedByDatabase() const
{
	return BNIsBackedByDatabase(m_object);
}


bool FileMetadata::CreateDatabase(const string& name, BinaryView* data, bool clean)
{
	return BNCreateDatabase(data->GetObject(), name.c_str(), clean);
}


bool FileMetadata::CreateDatabase(const string& name, BinaryView* data,
	const function<void(size_t progress, size_t total)>& progressCallback, bool clean)
{
	DatabaseProgressCallbackContext cb;
	cb.func = progressCallback;
	return BNCreateDatabaseWithProgress(data->GetObject(), name.c_str(), &cb, DatabaseProgressCallback, clean);
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


bool FileMetadata::SaveAutoSnapshot(BinaryView* data, bool clean)
{
	return BNSaveAutoSnapshot(data->GetObject(), clean);
}


bool FileMetadata::SaveAutoSnapshot(BinaryView* data,
	const function<void(size_t progress, size_t total)>& progressCallback, bool clean)
{
	DatabaseProgressCallbackContext cb;
	cb.func = progressCallback;
	return BNSaveAutoSnapshotWithProgress(data->GetObject(), &cb, DatabaseProgressCallback, clean);
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


bool FileMetadata::MergeUndo(const std::string& name, const std::function<void(size_t, size_t)>& progress)
{
	DatabaseProgressCallbackContext cb;
	cb.func = progress;
	return BNMergeUndo(m_object, name.c_str(), &cb, DatabaseProgressCallback);
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
