#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


DataBuffer::DataBuffer()
{
	m_buffer = BNCreateDataBuffer(nullptr, 0);
}


DataBuffer::DataBuffer(size_t len)
{
	m_buffer = BNCreateDataBuffer(nullptr, len);
}


DataBuffer::DataBuffer(const DataBuffer& buf)
{
	m_buffer = BNDuplicateDataBuffer(buf.m_buffer);
}


DataBuffer::DataBuffer(BNDataBuffer* buf)
{
	m_buffer = buf;
}


DataBuffer::~DataBuffer()
{
	BNFreeDataBuffer(m_buffer);
}


DataBuffer& DataBuffer::operator=(const DataBuffer& buf)
{
	BNFreeDataBuffer(m_buffer);
	m_buffer = BNDuplicateDataBuffer(buf.m_buffer);
	return *this;
}


void* DataBuffer::GetData()
{
	return BNGetDataBufferContents(m_buffer);
}


const void* DataBuffer::GetData() const
{
	return BNGetDataBufferContents(m_buffer);
}


void* DataBuffer::GetDataAt(size_t offset)
{
	return BNGetDataBufferContentsAt(m_buffer, offset);
}


size_t DataBuffer::GetLength() const
{
	return BNGetDataBufferLength(m_buffer);
}


void DataBuffer::SetSize(size_t len)
{
	BNSetDataBufferLength(m_buffer, len);
}


void DataBuffer::Append(const void* data, size_t len)
{
	BNAppendDataBufferContents(m_buffer, data, len);
}


void DataBuffer::Append(const DataBuffer& buf)
{
	BNAppendDataBuffer(m_buffer, buf.m_buffer);
}


DataBuffer DataBuffer::GetSlice(size_t start, size_t len)
{
	BNDataBuffer* result = BNGetDataBufferSlice(m_buffer, start, len);
	return DataBuffer(result);
}


uint8_t& DataBuffer::operator[](size_t offset)
{
	return ((uint8_t*)GetData())[offset];
}


const uint8_t& DataBuffer::operator[](size_t offset) const
{
	return ((const uint8_t*)GetData())[offset];
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


void BinaryDataNotification::DataWrittenCallback(void* ctxt, BNBinaryView* object, uint64_t offset, size_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new CoreBinaryView(BNNewViewReference(object));
	notify->OnBinaryDataWritten(view, offset, len);
}


void BinaryDataNotification::DataInsertedCallback(void* ctxt, BNBinaryView* object, uint64_t offset, size_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new CoreBinaryView(BNNewViewReference(object));
	notify->OnBinaryDataInserted(view, offset, len);
}


void BinaryDataNotification::DataRemovedCallback(void* ctxt, BNBinaryView* object, uint64_t offset, uint64_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new CoreBinaryView(BNNewViewReference(object));
	notify->OnBinaryDataRemoved(view, offset, len);
}


BinaryDataNotification::BinaryDataNotification()
{
	m_callbacks.context = this;
	m_callbacks.dataWritten = DataWrittenCallback;
	m_callbacks.dataInserted = DataInsertedCallback;
	m_callbacks.dataRemoved = DataRemovedCallback;
}


uint64_t FileAccessor::GetLengthCallback(void* ctxt)
{
	FileAccessor* file = (FileAccessor*)ctxt;
	return file->GetLength();
}


size_t FileAccessor::ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len)
{
	FileAccessor* file = (FileAccessor*)ctxt;
	return file->Read(dest, offset, len);
}


size_t FileAccessor::WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len)
{
	FileAccessor* file = (FileAccessor*)ctxt;
	return file->Write(offset, src, len);
}


FileAccessor::FileAccessor()
{
	m_callbacks.context = this;
	m_callbacks.getLength = GetLengthCallback;
	m_callbacks.read = ReadCallback;
	m_callbacks.write = WriteCallback;
}


FileAccessor::FileAccessor(BNFileAccessor* accessor): m_callbacks(*accessor)
{
}


CoreFileAccessor::CoreFileAccessor(BNFileAccessor* accessor): FileAccessor(accessor)
{
}


uint64_t CoreFileAccessor::GetLength() const
{
	return m_callbacks.getLength(m_callbacks.context);
}


size_t CoreFileAccessor::Read(void* dest, uint64_t offset, size_t len)
{
	return m_callbacks.read(m_callbacks.context, dest, offset, len);
}


size_t CoreFileAccessor::Write(uint64_t offset, const void* src, size_t len)
{
	return m_callbacks.write(m_callbacks.context, offset, src, len);
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
	return view->Read(dest, offset, len);
}


size_t BinaryView::WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->Write(offset, src, len);
}


size_t BinaryView::InsertCallback(void* ctxt, uint64_t offset, const void* src, size_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->Insert(offset, src, len);
}


size_t BinaryView::RemoveCallback(void* ctxt, uint64_t offset, uint64_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->Remove(offset, len);
}


BNModificationStatus BinaryView::GetModificationCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->GetModification(offset);
}


uint64_t BinaryView::GetStartCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->GetStart();
}


uint64_t BinaryView::GetLengthCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->GetLength();
}


bool BinaryView::SaveCallback(void* ctxt, BNFileAccessor* file)
{
	BinaryView* view = (BinaryView*)ctxt;
	CoreFileAccessor accessor(file);
	return view->Save(&accessor);
}


bool BinaryView::IsModified() const
{
	return m_file->IsModified();
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


BNDefaultEndianness BinaryView::GetDefaultEndianness() const
{
	return BNGetDefaultEndianness(m_view);
}


void BinaryView::SetDefaultEndianness(BNDefaultEndianness endian)
{
	BNSetDefaultEndianness(m_view, endian);
}


uint8_t BinaryView::Read8(uint64_t offset)
{
	return BNRead8(m_view, offset);
}


uint16_t BinaryView::Read16(uint64_t offset)
{
	return BNRead16(m_view, offset);
}


uint32_t BinaryView::Read32(uint64_t offset)
{
	return BNRead32(m_view, offset);
}


uint64_t BinaryView::Read64(uint64_t offset)
{
	return BNRead64(m_view, offset);
}


uint16_t BinaryView::ReadLE16(uint64_t offset)
{
	return BNReadLE16(m_view, offset);
}


uint32_t BinaryView::ReadLE32(uint64_t offset)
{
	return BNReadLE32(m_view, offset);
}


uint64_t BinaryView::ReadLE64(uint64_t offset)
{
	return BNReadLE64(m_view, offset);
}


uint16_t BinaryView::ReadBE16(uint64_t offset)
{
	return BNReadBE16(m_view, offset);
}


uint32_t BinaryView::ReadBE32(uint64_t offset)
{
	return BNReadBE32(m_view, offset);
}


uint64_t BinaryView::ReadBE64(uint64_t offset)
{
	return BNReadBE64(m_view, offset);
}


DataBuffer BinaryView::ReadBuffer(uint64_t offset, size_t len)
{
	BNDataBuffer* result = BNReadBuffer(m_view, offset, len);
	return DataBuffer(result);
}


bool BinaryView::Write8(uint64_t offset, uint8_t val)
{
	return BNWrite8(m_view, offset, val);
}


bool BinaryView::Write16(uint64_t offset, uint16_t val)
{
	return BNWrite16(m_view, offset, val);
}


bool BinaryView::Write32(uint64_t offset, uint32_t val)
{
	return BNWrite32(m_view, offset, val);
}


bool BinaryView::Write64(uint64_t offset, uint64_t val)
{
	return BNWrite64(m_view, offset, val);
}


bool BinaryView::WriteLE16(uint64_t offset, uint16_t val)
{
	return BNWriteLE16(m_view, offset, val);
}


bool BinaryView::WriteLE32(uint64_t offset, uint32_t val)
{
	return BNWriteLE32(m_view, offset, val);
}


bool BinaryView::WriteLE64(uint64_t offset, uint64_t val)
{
	return BNWriteLE64(m_view, offset, val);
}


bool BinaryView::WriteBE16(uint64_t offset, uint16_t val)
{
	return BNWriteBE16(m_view, offset, val);
}


bool BinaryView::WriteBE32(uint64_t offset, uint32_t val)
{
	return BNWriteBE32(m_view, offset, val);
}


bool BinaryView::WriteBE64(uint64_t offset, uint64_t val)
{
	return BNWriteBE64(m_view, offset, val);
}


size_t BinaryView::WriteBuffer(uint64_t offset, const DataBuffer& data)
{
	return BNWriteBuffer(m_view, offset, data.GetBufferObject());
}


size_t BinaryView::InsertBuffer(uint64_t offset, const DataBuffer& data)
{
	return BNInsertBuffer(m_view, offset, data.GetBufferObject());
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


CoreBinaryView::CoreBinaryView(BNBinaryView* view): BinaryView(view)
{
}


size_t CoreBinaryView::Read(void* dest, uint64_t offset, size_t len)
{
	return BNReadData(m_view, dest, offset, len);
}


size_t CoreBinaryView::Write(uint64_t offset, const void* data, size_t len)
{
	return BNWriteData(m_view, offset, data, len);
}


size_t CoreBinaryView::Insert(uint64_t offset, const void* data, size_t len)
{
	return BNInsertData(m_view, offset, data, len);
}


size_t CoreBinaryView::Remove(uint64_t offset, uint64_t len)
{
	return BNRemoveData(m_view, offset, len);
}


BNModificationStatus CoreBinaryView::GetModification(uint64_t offset)
{
	return BNGetModification(m_view, offset);
}


uint64_t CoreBinaryView::GetStart() const
{
	return BNGetStartOffset(m_view);
}


uint64_t CoreBinaryView::GetLength() const
{
	return BNGetViewLength(m_view);
}


bool CoreBinaryView::Save(FileAccessor* file)
{
	return BNSaveToFile(m_view, file->GetCallbacks());
}


BinaryData::BinaryData(FileMetadata* file): CoreBinaryView(BNCreateBinaryDataView(file->GetFileObject()))
{
}


BinaryData::BinaryData(FileMetadata* file, const DataBuffer& data):
	CoreBinaryView(BNCreateBinaryDataViewFromBuffer(file->GetFileObject(), data.GetBufferObject()))
{
}


BinaryData::BinaryData(FileMetadata* file, const void* data, size_t len):
	CoreBinaryView(BNCreateBinaryDataViewFromData(file->GetFileObject(), data, len))
{
}


BinaryData::BinaryData(FileMetadata* file, const string& path):
	CoreBinaryView(BNCreateBinaryDataViewFromFilename(file->GetFileObject(), path.c_str()))
{
}


BinaryData::BinaryData(FileMetadata* file, FileAccessor* accessor):
	CoreBinaryView(BNCreateBinaryDataViewFromFile(file->GetFileObject(), accessor->GetCallbacks()))
{
}
