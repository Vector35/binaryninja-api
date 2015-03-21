#include "binaryninjaapi.h"

using namespace BinaryNinja;
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


void UndoAction::UndoCallback(void* ctxt)
{
	UndoAction* action = (UndoAction*)ctxt;
	action->Undo();
}


void UndoAction::RedoCallback(void* ctxt)
{
	UndoAction* action = (UndoAction*)ctxt;
	action->Redo();
}


void UndoAction::Add(BNFileMetadata* file)
{
	BNAddUndoAction(file, this, UndoCallback, RedoCallback);
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


const string& FileMetadata::GetFilename() const
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


void FileMetadata::AddUndoAction(UndoAction* action)
{
	action->Add(m_file);
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
