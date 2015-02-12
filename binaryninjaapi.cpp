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


bool BinaryView::IsExecutableCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->IsExecutable();
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


CoreBinaryView::CoreBinaryView(BNBinaryView* view): BinaryView(view)
{
}


size_t CoreBinaryView::Read(void* dest, uint64_t offset, size_t len)
{
	return BNReadViewData(m_view, dest, offset, len);
}


size_t CoreBinaryView::Write(uint64_t offset, const void* data, size_t len)
{
	return BNWriteViewData(m_view, offset, data, len);
}


size_t CoreBinaryView::Insert(uint64_t offset, const void* data, size_t len)
{
	return BNInsertViewData(m_view, offset, data, len);
}


size_t CoreBinaryView::Remove(uint64_t offset, uint64_t len)
{
	return BNRemoveViewData(m_view, offset, len);
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


bool CoreBinaryView::IsExecutable() const
{
	return BNIsExecutableView(m_view);
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


BNBinaryView* BinaryViewType::CreateCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new CoreBinaryView(BNNewViewReference(data));
	Ref<BinaryView> result = type->Create(view);
	return BNNewViewReference(result->GetViewObject());
}


bool BinaryViewType::IsValidCallback(void* ctxt, BNBinaryView* data)
{
	BinaryViewType* type = (BinaryViewType*)ctxt;
	Ref<BinaryView> view = new CoreBinaryView(BNNewViewReference(data));
	return type->IsTypeValidForData(view);
}


BinaryViewType::BinaryViewType(BNBinaryViewType* type): m_type(type)
{
}


BinaryViewType::BinaryViewType(const string& name, const string& longName):
	m_type(nullptr), m_nameForRegister(name), m_longNameForRegister(longName)
{
}


BinaryViewType::~BinaryViewType()
{
	BNFreeBinaryViewType(m_type);
}


void BinaryViewType::Register(BinaryViewType* type)
{
	BNCustomBinaryViewType callbacks;
	callbacks.context = type;
	callbacks.create = CreateCallback;
	callbacks.isValidForData = IsValidCallback;

	type->m_type = BNRegisterBinaryViewType(type->m_nameForRegister.c_str(),
		type->m_longNameForRegister.c_str(), &callbacks);
}


Ref<BinaryViewType> BinaryViewType::GetByName(const string& name)
{
	BNBinaryViewType* type = BNGetBinaryViewTypeByName(name.c_str());
	if (!type)
		return nullptr;
	return new CoreBinaryViewType(type);
}


vector<Ref<BinaryViewType>> BinaryViewType::GetViewTypesForData(BinaryView* data)
{
	BNBinaryViewType** types;
	size_t count;
	types = BNGetBinaryViewTypesForData(data->GetViewObject(), &count);

	vector<Ref<BinaryViewType>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreBinaryViewType(BNNewViewTypeReference(types[i])));

	BNFreeBinaryViewTypeList(types, count);
	return result;
}


string BinaryViewType::GetName()
{
	char* contents = BNGetBinaryViewTypeName(m_type);
	string result = contents;
	BNFreeString(contents);
	return result;
}


string BinaryViewType::GetLongName()
{
	char* contents = BNGetBinaryViewTypeLongName(m_type);
	string result = contents;
	BNFreeString(contents);
	return result;
}


CoreBinaryViewType::CoreBinaryViewType(BNBinaryViewType* type): BinaryViewType(type)
{
}


BinaryView* CoreBinaryViewType::Create(BinaryView* data)
{
	BNBinaryView* view = BNCreateBinaryViewOfType(m_type, data->GetViewObject());
	if (!view)
		return nullptr;
	return new CoreBinaryView(view);
}


bool CoreBinaryViewType::IsTypeValidForData(BinaryView* data)
{
	return BNIsBinaryViewTypeValidForData(m_type, data->GetViewObject());
}


BinaryReader::BinaryReader(BinaryView* data, BNEndianness endian): m_view(data)
{
	m_stream = BNCreateBinaryReader(data->GetViewObject());
	BNSetBinaryReaderEndianness(m_stream, endian);
}


BinaryReader::~BinaryReader()
{
	BNFreeBinaryReader(m_stream);
}


BNEndianness BinaryReader::GetEndianness() const
{
	return BNGetBinaryReaderEndianness(m_stream);
}


void BinaryReader::SetEndianness(BNEndianness endian)
{
	BNSetBinaryReaderEndianness(m_stream, endian);
}


void BinaryReader::Read(void* dest, size_t len)
{
	if (!BNReadData(m_stream, dest, len))
		throw ReadException();
}


DataBuffer BinaryReader::Read(size_t len)
{
	DataBuffer result(len);
	Read(result.GetData(), len);
	return result;
}


string BinaryReader::ReadString(size_t len)
{
	DataBuffer result = Read(len);
	return string((const char*)result.GetData(), len);
}


uint8_t BinaryReader::Read8()
{
	uint8_t result;
	if (!BNRead8(m_stream, &result))
		throw ReadException();
	return result;
}


uint16_t BinaryReader::Read16()
{
	uint16_t result;
	if (!BNRead16(m_stream, &result))
		throw ReadException();
	return result;
}


uint32_t BinaryReader::Read32()
{
	uint32_t result;
	if (!BNRead32(m_stream, &result))
		throw ReadException();
	return result;
}


uint64_t BinaryReader::Read64()
{
	uint64_t result;
	if (!BNRead64(m_stream, &result))
		throw ReadException();
	return result;
}


uint16_t BinaryReader::ReadLE16()
{
	uint16_t result;
	if (!BNReadLE16(m_stream, &result))
		throw ReadException();
	return result;
}


uint32_t BinaryReader::ReadLE32()
{
	uint32_t result;
	if (!BNReadLE32(m_stream, &result))
		throw ReadException();
	return result;
}


uint64_t BinaryReader::ReadLE64()
{
	uint64_t result;
	if (!BNReadLE64(m_stream, &result))
		throw ReadException();
	return result;
}


uint16_t BinaryReader::ReadBE16()
{
	uint16_t result;
	if (!BNReadBE16(m_stream, &result))
		throw ReadException();
	return result;
}


uint32_t BinaryReader::ReadBE32()
{
	uint32_t result;
	if (!BNReadBE32(m_stream, &result))
		throw ReadException();
	return result;
}


uint64_t BinaryReader::ReadBE64()
{
	uint64_t result;
	if (!BNReadBE64(m_stream, &result))
		throw ReadException();
	return result;
}


bool BinaryReader::TryRead(void* dest, size_t len)
{
	return BNReadData(m_stream, dest, len);
}


bool BinaryReader::TryRead(DataBuffer& dest, size_t len)
{
	dest.SetSize(len);
	return TryRead(dest.GetData(), len);
}


bool BinaryReader::TryReadString(string& dest, size_t len)
{
	DataBuffer result(len);
	if (!TryRead(result.GetData(), len))
		return false;
	dest = string((const char*)result.GetData(), len);
	return true;
}


bool BinaryReader::TryRead8(uint8_t& result)
{
	return BNRead8(m_stream, &result);
}


bool BinaryReader::TryRead16(uint16_t& result)
{
	return BNRead16(m_stream, &result);
}


bool BinaryReader::TryRead32(uint32_t& result)
{
	return BNRead32(m_stream, &result);
}


bool BinaryReader::TryRead64(uint64_t& result)
{
	return BNRead64(m_stream, &result);
}


bool BinaryReader::TryReadLE16(uint16_t& result)
{
	return BNReadLE16(m_stream, &result);
}


bool BinaryReader::TryReadLE32(uint32_t& result)
{
	return BNReadLE32(m_stream, &result);
}


bool BinaryReader::TryReadLE64(uint64_t& result)
{
	return BNReadLE64(m_stream, &result);
}


bool BinaryReader::TryReadBE16(uint16_t& result)
{
	return BNReadBE16(m_stream, &result);
}


bool BinaryReader::TryReadBE32(uint32_t& result)
{
	return BNReadBE32(m_stream, &result);
}


bool BinaryReader::TryReadBE64(uint64_t& result)
{
	return BNReadBE64(m_stream, &result);
}


uint64_t BinaryReader::GetOffset() const
{
	return BNGetReaderPosition(m_stream);
}


void BinaryReader::Seek(uint64_t offset)
{
	BNSeekBinaryReader(m_stream, offset);
}


void BinaryReader::SeekRelative(int64_t offset)
{
	BNSeekBinaryReaderRelative(m_stream, offset);
}


bool BinaryReader::IsEndOfFile() const
{
	return BNIsEndOfFile(m_stream);
}


BinaryWriter::BinaryWriter(BinaryView* data, BNEndianness endian): m_view(data)
{
	m_stream = BNCreateBinaryWriter(data->GetViewObject());
	BNSetBinaryWriterEndianness(m_stream, endian);
}


BinaryWriter::~BinaryWriter()
{
	BNFreeBinaryWriter(m_stream);
}


BNEndianness BinaryWriter::GetEndianness() const
{
	return BNGetBinaryWriterEndianness(m_stream);
}


void BinaryWriter::SetEndianness(BNEndianness endian)
{
	BNSetBinaryWriterEndianness(m_stream, endian);
}


void BinaryWriter::Write(const void* src, size_t len)
{
	if (!BNWriteData(m_stream, src, len))
		throw WriteException();
}


void BinaryWriter::Write(const DataBuffer& buf)
{
	Write(buf.GetData(), buf.GetLength());
}


void BinaryWriter::Write(const string& str)
{
	Write(str.c_str(), str.size());
}


void BinaryWriter::Write8(uint8_t val)
{
	if (!BNWrite8(m_stream, val))
		throw WriteException();
}


void BinaryWriter::Write16(uint16_t val)
{
	if (!BNWrite16(m_stream, val))
		throw WriteException();
}


void BinaryWriter::Write32(uint32_t val)
{
	if (!BNWrite32(m_stream, val))
		throw WriteException();
}


void BinaryWriter::Write64(uint64_t val)
{
	if (!BNWrite64(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteLE16(uint16_t val)
{
	if (!BNWriteLE16(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteLE32(uint32_t val)
{
	if (!BNWriteLE32(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteLE64(uint64_t val)
{
	if (!BNWriteLE64(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteBE16(uint16_t val)
{
	if (!BNWriteBE16(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteBE32(uint32_t val)
{
	if (!BNWriteBE32(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteBE64(uint64_t val)
{
	if (!BNWriteBE64(m_stream, val))
		throw WriteException();
}


bool BinaryWriter::TryWrite(const void* src, size_t len)
{
	return BNWriteData(m_stream, src, len);
}


bool BinaryWriter::TryWrite(const DataBuffer& buf)
{
	return TryWrite(buf.GetData(), buf.GetLength());
}


bool BinaryWriter::TryWrite(const string& str)
{
	return TryWrite(str.c_str(), str.size());
}


bool BinaryWriter::TryWrite8(uint8_t val)
{
	return BNWrite8(m_stream, val);
}


bool BinaryWriter::TryWrite16(uint16_t val)
{
	return BNWrite16(m_stream, val);
}


bool BinaryWriter::TryWrite32(uint32_t val)
{
	return BNWrite32(m_stream, val);
}


bool BinaryWriter::TryWrite64(uint64_t val)
{
	return BNWrite64(m_stream, val);
}


bool BinaryWriter::TryWriteLE16(uint16_t val)
{
	return BNWriteLE16(m_stream, val);
}


bool BinaryWriter::TryWriteLE32(uint32_t val)
{
	return BNWriteLE32(m_stream, val);
}


bool BinaryWriter::TryWriteLE64(uint64_t val)
{
	return BNWriteLE64(m_stream, val);
}


bool BinaryWriter::TryWriteBE16(uint16_t val)
{
	return BNWriteBE16(m_stream, val);
}


bool BinaryWriter::TryWriteBE32(uint32_t val)
{
	return BNWriteBE32(m_stream, val);
}


bool BinaryWriter::TryWriteBE64(uint64_t val)
{
	return BNWriteBE64(m_stream, val);
}


uint64_t BinaryWriter::GetOffset() const
{
	return BNGetWriterPosition(m_stream);
}


void BinaryWriter::Seek(uint64_t offset)
{
	BNSeekBinaryWriter(m_stream, offset);
}


void BinaryWriter::SeekRelative(int64_t offset)
{
	BNSeekBinaryWriterRelative(m_stream, offset);
}


Transform::Transform(BNTransform* xform): m_xform(xform)
{
}


Transform::Transform(BNTransformType type, const string& name, const string& longName):
	m_xform(nullptr), m_typeForRegister(type), m_nameForRegister(name), m_longNameForRegister(longName)
{
}


BNTransformParameterInfo* Transform::GetParametersCallback(void* ctxt, size_t* count)
{
	Transform* xform = (Transform*)ctxt;
	vector<TransformParameter> params = xform->GetParameters();
	*count = params.size();
	BNTransformParameterInfo* result = new BNTransformParameterInfo[params.size()];

	for (size_t i = 0; i < params.size(); i++)
	{
		result[i].name = BNAllocString(params[i].name.c_str());
		result[i].longName = BNAllocString(params[i].longName.c_str());
		result[i].fixedLength = params[i].fixedLength;
	}

	return result;
}


void Transform::FreeParametersCallback(BNTransformParameterInfo* params, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNFreeString(params[i].name);
		BNFreeString(params[i].longName);
	}
	delete[] params;
}


bool Transform::DecodeCallback(void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount)
{
	map<string, DataBuffer> paramMap;
	for (size_t i = 0; i < paramCount; i++)
		paramMap[params[i].name] = DataBuffer(BNDuplicateDataBuffer(params[i].value));

	DataBuffer inputBuf(BNDuplicateDataBuffer(input));
	DataBuffer outputBuf;

	Transform* xform = (Transform*)ctxt;
	bool result = xform->Decode(inputBuf, outputBuf, paramMap);
	BNAssignDataBuffer(output, outputBuf.GetBufferObject());
	return result;
}


bool Transform::EncodeCallback(void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount)
{
	map<string, DataBuffer> paramMap;
	for (size_t i = 0; i < paramCount; i++)
		paramMap[params[i].name] = DataBuffer(BNDuplicateDataBuffer(params[i].value));

	DataBuffer inputBuf(BNDuplicateDataBuffer(input));
	DataBuffer outputBuf;

	Transform* xform = (Transform*)ctxt;
	bool result = xform->Encode(inputBuf, outputBuf, paramMap);
	BNAssignDataBuffer(output, outputBuf.GetBufferObject());
	return result;
}


vector<TransformParameter> Transform::EncryptionKeyParameters(size_t fixedKeyLength)
{
	vector<TransformParameter> params;
	TransformParameter key;
	key.name = "key";
	key.longName = "Encryption key";
	key.fixedLength = fixedKeyLength;
	params.push_back(key);
	return params;
}


vector<TransformParameter> Transform::EncryptionKeyAndIVParameters(size_t fixedKeyLength, size_t fixedIVLength)
{
	vector<TransformParameter> params;
	TransformParameter key, iv;
	key.name = "key";
	key.longName = "Encryption key";
	key.fixedLength = fixedKeyLength;
	iv.name = "iv";
	iv.longName = "Initialization vector";
	iv.fixedLength = fixedIVLength;
	params.push_back(key);
	params.push_back(iv);
	return params;
}


void Transform::Register(Transform* xform)
{
	BNCustomTransform callbacks;
	callbacks.context = xform;
	callbacks.getParameters = GetParametersCallback;
	callbacks.freeParameters = FreeParametersCallback;
	callbacks.decode = DecodeCallback;
	callbacks.encode = EncodeCallback;
	xform->m_xform = BNRegisterTransformType(xform->m_typeForRegister, xform->m_nameForRegister.c_str(),
		xform->m_longNameForRegister.c_str(), &callbacks);
}


Ref<Transform> Transform::GetByName(const string& name)
{
	BNTransform* result = BNGetTransformByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreTransform(result);
}


vector<Ref<Transform>> Transform::GetTransformTypes()
{
	size_t count;
	BNTransform** list = BNGetTransformTypeList(&count);

	vector<Ref<Transform>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreTransform(BNNewTransformReference(list[i])));

	BNFreeTransformTypeList(list, count);
	return result;
}


BNTransformType Transform::GetType() const
{
	return BNGetTransformType(m_xform);
}


string Transform::GetName() const
{
	char* name = BNGetTransformName(m_xform);
	string result = name;
	BNFreeString(name);
	return result;
}


string Transform::GetLongName() const
{
	char* name = BNGetTransformLongName(m_xform);
	string result = name;
	BNFreeString(name);
	return result;
}


vector<TransformParameter> Transform::GetParameters() const
{
	return vector<TransformParameter>();
}


bool Transform::Decode(const DataBuffer& input, DataBuffer& output, const map<string, DataBuffer>& params)
{
	if (GetType() == InvertingTransform)
		return Encode(input, output, params);
	return false;
}


bool Transform::Encode(const DataBuffer&, DataBuffer&, const map<string, DataBuffer>&)
{
	return false;
}


CoreTransform::CoreTransform(BNTransform* xform): Transform(xform)
{
}


vector<TransformParameter> CoreTransform::GetParameters() const
{
	size_t count;
	BNTransformParameterInfo* list = BNGetTransformParameterList(m_xform, &count);

	vector<TransformParameter> result;
	for (size_t i = 0; i < count; i++)
	{
		TransformParameter param;
		param.name = list[i].name;
		param.longName = list[i].longName;
		param.fixedLength = list[i].fixedLength;
	}

	BNFreeTransformParameterList(list, count);
	return result;
}


bool CoreTransform::Decode(const DataBuffer& input, DataBuffer& output, const map<string, DataBuffer>& params)
{
	BNTransformParameter* list = new BNTransformParameter[params.size()];
	size_t idx = 0;
	for (auto i : params)
	{
		list[idx].name = i.first.c_str();
		list[idx].value = i.second.GetBufferObject();
	}

	bool result = BNDecode(m_xform, input.GetBufferObject(), output.GetBufferObject(), list, idx);

	delete[] list;
	return result;
}


bool CoreTransform::Encode(const DataBuffer& input, DataBuffer& output, const map<string, DataBuffer>& params)
{
	BNTransformParameter* list = new BNTransformParameter[params.size()];
	size_t idx = 0;
	for (auto i : params)
	{
		list[idx].name = i.first.c_str();
		list[idx].value = i.second.GetBufferObject();
	}

	bool result = BNEncode(m_xform, input.GetBufferObject(), output.GetBufferObject(), list, idx);

	delete[] list;
	return result;
}
