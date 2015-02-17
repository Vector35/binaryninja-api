#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


void BinaryDataNotification::DataWrittenCallback(void* ctxt, BNBinaryView* object, uint64_t offset, size_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnBinaryDataWritten(view, offset, len);
}


void BinaryDataNotification::DataInsertedCallback(void* ctxt, BNBinaryView* object, uint64_t offset, size_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnBinaryDataInserted(view, offset, len);
}


void BinaryDataNotification::DataRemovedCallback(void* ctxt, BNBinaryView* object, uint64_t offset, uint64_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnBinaryDataRemoved(view, offset, len);
}


BinaryDataNotification::BinaryDataNotification()
{
	m_callbacks.context = this;
	m_callbacks.dataWritten = DataWrittenCallback;
	m_callbacks.dataInserted = DataInsertedCallback;
	m_callbacks.dataRemoved = DataRemovedCallback;
}


BinaryView::BinaryView(FileMetadata* file)
{
	BNCustomBinaryView view;
	view.context = this;
	view.read = ReadCallback;
	view.write = WriteCallback;
	view.insert = InsertCallback;
	view.remove = RemoveCallback;
	view.getModification = GetModificationCallback;
	view.getStart = GetStartCallback;
	view.getLength = GetLengthCallback;
	view.isExecutable = IsExecutableCallback;
	view.save = SaveCallback;

	m_file = file;
	m_view = BNCreateCustomBinaryView(m_file->GetFileObject(), &view);
}


BinaryView::BinaryView(BNBinaryView* view)
{
	m_view = view;
	m_file = new FileMetadata(BNNewFileReference(BNGetFileForView(m_view)));
}


BinaryView::~BinaryView()
{
	BNFreeBinaryView(m_view);
}


size_t BinaryView::ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformRead(dest, offset, len);
}


size_t BinaryView::WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformWrite(offset, src, len);
}


size_t BinaryView::InsertCallback(void* ctxt, uint64_t offset, const void* src, size_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformInsert(offset, src, len);
}


size_t BinaryView::RemoveCallback(void* ctxt, uint64_t offset, uint64_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformRemove(offset, len);
}


BNModificationStatus BinaryView::GetModificationCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetModification(offset);
}


uint64_t BinaryView::GetStartCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetStart();
}


uint64_t BinaryView::GetLengthCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetLength();
}


bool BinaryView::IsExecutableCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsExecutable();
}


bool BinaryView::SaveCallback(void* ctxt, BNFileAccessor* file)
{
	BinaryView* view = (BinaryView*)ctxt;
	CoreFileAccessor accessor(file);
	return view->PerformSave(&accessor);
}


bool BinaryView::IsModified() const
{
	return BNIsViewModified(m_view);
}


void BinaryView::BeginUndoActions()
{
	m_file->BeginUndoActions();
}


void BinaryView::AddUndoAction(UndoAction* action)
{
	m_file->AddUndoAction(action);
}


void BinaryView::CommitUndoActions()
{
	m_file->CommitUndoActions();
}


bool BinaryView::Undo()
{
	return m_file->Undo();
}


bool BinaryView::Redo()
{
	return m_file->Redo();
}


string BinaryView::GetCurrentView()
{
	return m_file->GetCurrentView();
}


uint64_t BinaryView::GetCurrentOffset()
{
	return m_file->GetCurrentOffset();
}


bool BinaryView::Navigate(const string& view, uint64_t offset)
{
	return m_file->Navigate(view, offset);
}


DataBuffer BinaryView::ReadBuffer(uint64_t offset, size_t len)
{
	BNDataBuffer* result = BNReadViewBuffer(m_view, offset, len);
	return DataBuffer(result);
}


size_t BinaryView::WriteBuffer(uint64_t offset, const DataBuffer& data)
{
	return BNWriteViewBuffer(m_view, offset, data.GetBufferObject());
}


size_t BinaryView::InsertBuffer(uint64_t offset, const DataBuffer& data)
{
	return BNInsertViewBuffer(m_view, offset, data.GetBufferObject());
}


vector<BNModificationStatus> BinaryView::GetModification(uint64_t offset, size_t len)
{
	BNModificationStatus* mod = new BNModificationStatus[len];
	len = BNGetModificationArray(m_view, offset, mod, len);

	vector<BNModificationStatus> result;
	for (size_t i = 0; i < len; i++)
		result.push_back(mod[i]);

	delete[] mod;
	return result;
}


uint64_t BinaryView::GetEnd() const
{
	return BNGetEndOffset(m_view);
}


bool BinaryView::Save(const string& path)
{
	return BNSaveToFilename(m_view, path.c_str());
}


void BinaryView::RegisterNotification(BinaryDataNotification* notify)
{
	BNRegisterDataNotification(m_view, notify->GetCallbacks());
}


void BinaryView::UnregisterNotification(BinaryDataNotification* notify)
{
	BNUnregisterDataNotification(m_view, notify->GetCallbacks());
}


size_t BinaryView::Read(void* dest, uint64_t offset, size_t len)
{
	return BNReadViewData(m_view, dest, offset, len);
}


size_t BinaryView::Write(uint64_t offset, const void* data, size_t len)
{
	return BNWriteViewData(m_view, offset, data, len);
}


size_t BinaryView::Insert(uint64_t offset, const void* data, size_t len)
{
	return BNInsertViewData(m_view, offset, data, len);
}


size_t BinaryView::Remove(uint64_t offset, uint64_t len)
{
	return BNRemoveViewData(m_view, offset, len);
}


BNModificationStatus BinaryView::GetModification(uint64_t offset)
{
	return BNGetModification(m_view, offset);
}


uint64_t BinaryView::GetStart() const
{
	return BNGetStartOffset(m_view);
}


uint64_t BinaryView::GetLength() const
{
	return BNGetViewLength(m_view);
}


bool BinaryView::IsExecutable() const
{
	return BNIsExecutableView(m_view);
}


bool BinaryView::Save(FileAccessor* file)
{
	return BNSaveToFile(m_view, file->GetCallbacks());
}


BinaryData::BinaryData(FileMetadata* file): BinaryView(BNCreateBinaryDataView(file->GetFileObject()))
{
}


BinaryData::BinaryData(FileMetadata* file, const DataBuffer& data):
	BinaryView(BNCreateBinaryDataViewFromBuffer(file->GetFileObject(), data.GetBufferObject()))
{
}


BinaryData::BinaryData(FileMetadata* file, const void* data, size_t len):
	BinaryView(BNCreateBinaryDataViewFromData(file->GetFileObject(), data, len))
{
}


BinaryData::BinaryData(FileMetadata* file, const string& path):
	BinaryView(BNCreateBinaryDataViewFromFilename(file->GetFileObject(), path.c_str()))
{
}


BinaryData::BinaryData(FileMetadata* file, FileAccessor* accessor):
	BinaryView(BNCreateBinaryDataViewFromFile(file->GetFileObject(), accessor->GetCallbacks()))
{
}
