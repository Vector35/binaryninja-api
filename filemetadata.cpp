#include "binaryninjaapi.h"

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
		FastWriter writer;
		string json = writer.write(data);
		return BNAllocString(json.c_str());
	}
	catch (exception& e)
	{
		LogError("Undo action failed to serialize: %s", e.what());
		return nullptr;
	}
}


UndoAction::UndoAction(const string& name): m_name(name)
{
}


BNUndoAction UndoAction::GetCallbacks()
{
	BNUndoAction action;
	action.context = this;
	action.undo = UndoCallback;
	action.redo = RedoCallback;
	action.serialize = SerializeCallback;
	return action;
}


void UndoAction::Add(BNBinaryView* view)
{
	BNUndoAction action = GetCallbacks();
	BNAddUndoAction(view, GetName().c_str(), &action);
}


bool UndoActionType::DeserializeCallback(void* ctxt, const char* data, BNUndoAction* result)
{
	try
	{
		UndoActionType* type = (UndoActionType*)ctxt;
		Reader reader;
		Value val;
		if (!reader.parse(data, val, false))
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
	m_file = BNCreateFileMetadata();
}


FileMetadata::FileMetadata(const string& filename)
{
	m_file = BNCreateFileMetadata();
	BNSetFilename(m_file, filename.c_str());
}


FileMetadata::FileMetadata(BNFileMetadata* file)
{
	m_file = file;
}


FileMetadata::~FileMetadata()
{
	BNFreeFileMetadata(m_file);
}


void FileMetadata::SetNavigationHandler(NavigationHandler* handler)
{
	BNSetFileMetadataNavigationHandler(m_file, handler->GetCallbacks());
}


string FileMetadata::GetFilename() const
{
	char* str = BNGetFilename(m_file);
	string result = str;
	BNFreeString(str);
	return result;
}


void FileMetadata::SetFilename(const string& name)
{
	BNSetFilename(m_file, name.c_str());
}


bool FileMetadata::IsModified() const
{
	return BNIsFileModified(m_file);
}


void FileMetadata::MarkFileModified()
{
	BNMarkFileModified(m_file);
}


void FileMetadata::MarkFileSaved()
{
	BNMarkFileSaved(m_file);
}


void FileMetadata::BeginUndoActions()
{
	BNBeginUndoActions(m_file);
}


void FileMetadata::CommitUndoActions()
{
	BNCommitUndoActions(m_file);
}


bool FileMetadata::Undo()
{
	return BNUndo(m_file);
}


bool FileMetadata::Redo()
{
	return BNRedo(m_file);
}


string FileMetadata::GetCurrentView()
{
	char* view = BNGetCurrentView(m_file);
	string result = view;
	BNFreeString(view);
	return result;
}


uint64_t FileMetadata::GetCurrentOffset()
{
	return BNGetCurrentOffset(m_file);
}


bool FileMetadata::Navigate(const string& view, uint64_t offset)
{
	return BNNavigate(m_file, view.c_str(), offset);
}
