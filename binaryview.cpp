// Copyright (c) 2015-2017 Vector 35 LLC
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

#include <algorithm>
#include <iterator>
#include <memory>
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


void BinaryDataNotification::FunctionAddedCallback(void* ctxt, BNBinaryView* object, BNFunction* func)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	notify->OnAnalysisFunctionAdded(view, funcObj);
}


void BinaryDataNotification::FunctionRemovedCallback(void* ctxt, BNBinaryView* object, BNFunction* func)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	notify->OnAnalysisFunctionRemoved(view, funcObj);
}


void BinaryDataNotification::FunctionUpdatedCallback(void* ctxt, BNBinaryView* object, BNFunction* func)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	notify->OnAnalysisFunctionUpdated(view, funcObj);
}


void BinaryDataNotification::FunctionUpdateRequestedCallback(void* ctxt, BNBinaryView* object, BNFunction* func)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	notify->OnAnalysisFunctionUpdateRequested(view, funcObj);
}


void BinaryDataNotification::DataVariableAddedCallback(void* ctxt, BNBinaryView* object, BNDataVariable* var)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	DataVariable varObj(var->address, Confidence<Ref<Type>>(new Type(BNNewTypeReference(var->type)), var->typeConfidence), var->autoDiscovered);
	notify->OnDataVariableAdded(view, varObj);
}


void BinaryDataNotification::DataVariableRemovedCallback(void* ctxt, BNBinaryView* object, BNDataVariable* var)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	DataVariable varObj(var->address, Confidence<Ref<Type>>(new Type(BNNewTypeReference(var->type)), var->typeConfidence), var->autoDiscovered);
	notify->OnDataVariableRemoved(view, varObj);
}


void BinaryDataNotification::DataVariableUpdatedCallback(void* ctxt, BNBinaryView* object, BNDataVariable* var)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	DataVariable varObj(var->address, Confidence<Ref<Type>>(new Type(BNNewTypeReference(var->type)), var->typeConfidence), var->autoDiscovered);
	notify->OnDataVariableUpdated(view, varObj);
}


void BinaryDataNotification::StringFoundCallback(void* ctxt, BNBinaryView* object, BNStringType type, uint64_t offset, size_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnStringFound(view, type, offset, len);
}


void BinaryDataNotification::StringRemovedCallback(void* ctxt, BNBinaryView* object, BNStringType type, uint64_t offset, size_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnStringRemoved(view, type, offset, len);
}


void BinaryDataNotification::TypeDefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	notify->OnTypeDefined(view, QualifiedName::FromAPIObject(name), typeObj);
}


void BinaryDataNotification::TypeUndefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	notify->OnTypeUndefined(view, QualifiedName::FromAPIObject(name), typeObj);
}


BinaryDataNotification::BinaryDataNotification()
{
	m_callbacks.context = this;
	m_callbacks.dataWritten = DataWrittenCallback;
	m_callbacks.dataInserted = DataInsertedCallback;
	m_callbacks.dataRemoved = DataRemovedCallback;
	m_callbacks.functionAdded = FunctionAddedCallback;
	m_callbacks.functionRemoved = FunctionRemovedCallback;
	m_callbacks.functionUpdated = FunctionUpdatedCallback;
	m_callbacks.functionUpdateRequested = FunctionUpdateRequestedCallback;
	m_callbacks.dataVariableAdded = DataVariableAddedCallback;
	m_callbacks.dataVariableRemoved = DataVariableRemovedCallback;
	m_callbacks.dataVariableUpdated = DataVariableUpdatedCallback;
	m_callbacks.stringFound = StringFoundCallback;
	m_callbacks.stringRemoved = StringRemovedCallback;
	m_callbacks.typeDefined = TypeDefinedCallback;
	m_callbacks.typeUndefined = TypeUndefinedCallback;
}


Symbol::Symbol(BNSymbolType type, const string& shortName, const string& fullName, const string& rawName, uint64_t addr)
{
	m_object = BNCreateSymbol(type, shortName.c_str(), fullName.c_str(), rawName.c_str(), addr);
}


Symbol::Symbol(BNSymbolType type, const std::string& name, uint64_t addr)
{
	m_object = BNCreateSymbol(type, name.c_str(), name.c_str(), name.c_str(), addr);
}


Symbol::Symbol(BNSymbol* sym)
{
	m_object = sym;
}


BNSymbolType Symbol::GetType() const
{
	return BNGetSymbolType(m_object);
}


NameSpace Symbol::GetNameSpace() const
{
	BNNameSpace name = BNGetSymbolNameSpace(m_object);
	NameSpace result = NameSpace::FromAPIObject(&name);
	BNFreeNameSpace(&name);
	return result;
}


string Symbol::GetShortName() const
{
	char* name = BNGetSymbolShortName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


string Symbol::GetFullName() const
{
	char* name = BNGetSymbolFullName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


string Symbol::GetRawName() const
{
	char* name = BNGetSymbolRawName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


uint64_t Symbol::GetAddress() const
{
	return BNGetSymbolAddress(m_object);
}


bool Symbol::IsAutoDefined() const
{
	return BNIsSymbolAutoDefined(m_object);
}


Ref<Symbol> Symbol::ImportedFunctionFromImportAddressSymbol(Symbol* sym, uint64_t addr)
{
	return new Symbol(BNImportedFunctionFromImportAddressSymbol(sym->GetObject(), addr));
}


AnalysisCompletionEvent::AnalysisCompletionEvent(BinaryView* view, const std::function<void()>& callback):
	m_callback(callback)
{
	m_object = BNAddAnalysisCompletionEvent(view->GetObject(), this, CompletionCallback);
}


void AnalysisCompletionEvent::CompletionCallback(void* ctxt)
{
	AnalysisCompletionEvent* event = (AnalysisCompletionEvent*)ctxt;

	unique_lock<recursive_mutex> lock(event->m_mutex);
	event->m_callback();
	event->m_callback = []() {};
}


void AnalysisCompletionEvent::Cancel()
{
	unique_lock<recursive_mutex> lock(m_mutex);
	m_callback = []() {};
}


Segment::Segment(BNSegment* seg)
{
	m_object = seg;
}


vector<pair<uint64_t, uint64_t>> Segment::GetRelocationRanges() const
{
	size_t count = 0;
	BNRange* ranges = BNSegmentGetRelocationRanges(m_object, &count);
	vector<pair<uint64_t, uint64_t>> result(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back({ranges[i].start, ranges[i].end});
	}
	BNFreeRelocationRanges(ranges);
	return result;
}


vector<pair<uint64_t, uint64_t>> Segment::GetRelocationRangesAtAddress(uint64_t addr) const
{
	size_t count = 0;
	BNRange* ranges = BNSegmentGetRelocationRangesAtAddress(m_object, addr, &count);
	vector<pair<uint64_t, uint64_t>> result(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back({ranges[i].start, ranges[i].end});
	}
	BNFreeRelocationRanges(ranges);
	return result;
}


uint64_t Segment::GetRelocationsCount() const
{
	return BNSegmentGetRelocationsCount(m_object);
}


uint64_t Segment::GetStart() const
{
	return BNSegmentGetStart(m_object);
}


uint64_t Segment::GetLength() const
{
	return BNSegmentGetLength(m_object);
}


uint64_t Segment::GetEnd() const
{
	return BNSegmentGetEnd(m_object);
}


uint64_t Segment::GetDataEnd() const
{
	return BNSegmentGetDataEnd(m_object);
}


uint64_t Segment::GetDataOffset() const
{
	return BNSegmentGetDataOffset(m_object);
}


uint64_t Segment::GetDataLength() const
{
	return BNSegmentGetDataLength(m_object);
}


uint32_t Segment::GetFlags() const
{
	return BNSegmentGetFlags(m_object);
}


bool Segment::IsAutoDefined() const
{
	return BNSegmentIsAutoDefined(m_object);
}


void Segment::SetLength(uint64_t length)
{
	BNSegmentSetLength(m_object, length);
}


void Segment::SetDataOffset(uint64_t dataOffset)
{
	BNSegmentSetDataOffset(m_object, dataOffset);
}


void Segment::SetDataLength(uint64_t dataLength)
{
	BNSegmentSetDataLength(m_object, dataLength);
}


void Segment::SetFlags(uint64_t flags)
{
	BNSegmentSetFlags(m_object, flags);
}


size_t Segment::Read(BinaryView* view, uint8_t* dest, uint64_t offset, size_t len)
{
	return BNSegmentRead(m_object, view->GetObject(), dest, offset, len);
}


Section::Section(BNSection* sec)
{
	m_object = sec;
}


std::string Section::GetName() const
{
	return BNSectionGetName(m_object);
}


std::string Section::GetType() const
{
	return BNSectionGetType(m_object);
}


uint64_t Section::GetStart() const
{
	return BNSectionGetStart(m_object);
}


uint64_t Section::GetLength() const
{
	return BNSectionGetLength(m_object);
}


uint64_t Section::GetInfoData() const
{
	return BNSectionGetInfoData(m_object);
}


uint64_t Section::GetAlignment() const
{
	return BNSectionGetAlign(m_object);
}


uint64_t Section::GetEntrySize() const
{
	return BNSectionGetEntrySize(m_object);
}


std::string Section::GetLinkedSection() const
{
	return BNSectionGetLinkedSection(m_object);
}


std::string Section::GetInfoSection() const
{
	return BNSectionGetInfoSection(m_object);
}


BNSectionSemantics Section::GetSemantics() const
{
	return BNSectionGetSemantics(m_object);
}


bool Section::AutoDefined() const
{
	return BNSectionIsAutoDefined(m_object);
}


BinaryView::BinaryView(const std::string& typeName, FileMetadata* file, BinaryView* parentView)
{
	BNCustomBinaryView view;
	view.context = this;
	view.init = InitCallback;
	view.freeObject = FreeCallback;
	view.read = ReadCallback;
	view.write = WriteCallback;
	view.insert = InsertCallback;
	view.remove = RemoveCallback;
	view.getModification = GetModificationCallback;
	view.isValidOffset = IsValidOffsetCallback;
	view.isOffsetReadable = IsOffsetReadableCallback;
	view.isOffsetWritable = IsOffsetWritableCallback;
	view.isOffsetExecutable = IsOffsetExecutableCallback;
	view.isOffsetBackedByFile = IsOffsetBackedByFileCallback;
	view.getNextValidOffset = GetNextValidOffsetCallback;
	view.getStart = GetStartCallback;
	view.getLength = GetLengthCallback;
	view.getEntryPoint = GetEntryPointCallback;
	view.isExecutable = IsExecutableCallback;
	view.getDefaultEndianness = GetDefaultEndiannessCallback;
	view.isRelocatable = IsRelocatableCallback;
	view.getAddressSize = GetAddressSizeCallback;
	view.save = SaveCallback;
	view.defineRelocation = DefineRelocationCallback;
	view.defineSymbolRelocation = DefineSymbolRelocationCallback;
	m_file = file;
	AddRefForRegistration();
	m_object = BNCreateCustomBinaryView(typeName.c_str(), m_file->GetObject(),
		parentView ? parentView->GetObject() : nullptr, &view);
}


BinaryView::BinaryView(BNBinaryView* view)
{
	m_object = view;
	m_file = new FileMetadata(BNGetFileForView(m_object));
}


bool BinaryView::InitCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->Init();
}


void BinaryView::FreeCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	view->ReleaseForRegistration();
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


bool BinaryView::IsValidOffsetCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsValidOffset(offset);
}


bool BinaryView::IsOffsetReadableCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsOffsetReadable(offset);
}


bool BinaryView::IsOffsetWritableCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsOffsetWritable(offset);
}


bool BinaryView::IsOffsetExecutableCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsOffsetExecutable(offset);
}


bool BinaryView::IsOffsetBackedByFileCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsOffsetBackedByFile(offset);
}


uint64_t BinaryView::GetNextValidOffsetCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetNextValidOffset(offset);
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


uint64_t BinaryView::GetEntryPointCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetEntryPoint();
}


bool BinaryView::IsExecutableCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsExecutable();
}


BNEndianness BinaryView::GetDefaultEndiannessCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->GetDefaultEndianness();
}


bool BinaryView::IsRelocatableCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsRelocatable();
}


size_t BinaryView::GetAddressSizeCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->GetAddressSize();
}


bool BinaryView::SaveCallback(void* ctxt, BNFileAccessor* file)
{
	BinaryView* view = (BinaryView*)ctxt;
	CoreFileAccessor accessor(file);
	return view->PerformSave(&accessor);
}


void BinaryView::DefineRelocationCallback(void* ctxt, BNArchitecture* arch, BNRelocationInfo* info, uint64_t target,
	uint64_t reloc)
{
	BinaryView* view = (BinaryView*)ctxt;
	BNRelocationInfo curInfo = *info;
	Architecture* curArch = new CoreArchitecture(arch);
	return view->PerformDefineRelocation(curArch, curInfo, target, reloc);
}


void BinaryView::DefineSymbolRelocationCallback(void* ctxt, BNArchitecture* arch, BNRelocationInfo* info, BNSymbol* sym,
	uint64_t reloc)
{
	BinaryView* view = (BinaryView*)ctxt;
	BNRelocationInfo curInfo = *info;
	Architecture* curArch = new CoreArchitecture(arch);
	Ref<Symbol> curSymbol = new Symbol(sym);
	return view->PerformDefineRelocation(curArch, curInfo, curSymbol, reloc);
}


bool BinaryView::PerformIsValidOffset(uint64_t offset)
{
	uint8_t val;
	return PerformRead(&val, offset, 1) == 1;
}


bool BinaryView::PerformIsOffsetReadable(uint64_t offset)
{
	return PerformIsValidOffset(offset);
}


bool BinaryView::PerformIsOffsetWritable(uint64_t offset)
{
	return PerformIsValidOffset(offset);
}


bool BinaryView::PerformIsOffsetExecutable(uint64_t offset)
{
	return PerformIsValidOffset(offset);
}


bool BinaryView::PerformIsOffsetBackedByFile(uint64_t offset)
{
	return PerformIsValidOffset(offset);
}


uint64_t BinaryView::PerformGetNextValidOffset(uint64_t offset)
{
	if (offset < PerformGetStart())
		return PerformGetStart();
	return offset;
}


BNEndianness BinaryView::PerformGetDefaultEndianness() const
{
	Ref<Architecture> arch = GetDefaultArchitecture();
	if (arch)
		return arch->GetEndianness();
	return LittleEndian;
}


bool BinaryView::PerformIsRelocatable() const
{
	return false;
}

size_t BinaryView::PerformGetAddressSize() const
{
	Ref<Architecture> arch = GetDefaultArchitecture();
	if (arch)
		return arch->GetAddressSize();
	if (GetEnd() > (1LL << 32))
		return 8;
	return 4;
}


bool BinaryView::PerformSave(FileAccessor* file)
{
	Ref<BinaryView> parent = GetParentView();
	if (parent)
		return parent->Save(file);
	return false;
}


void BinaryView::PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc)
{
	DefineRelocation(arch, info, target, reloc);
}


void BinaryView::PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> target, uint64_t reloc)
{
	DefineRelocation(arch, info, target, reloc);
}


void BinaryView::NotifyDataWritten(uint64_t offset, size_t len)
{
	BNNotifyDataWritten(m_object, offset, len);
}


void BinaryView::NotifyDataInserted(uint64_t offset, size_t len)
{
	BNNotifyDataInserted(m_object, offset, len);
}


void BinaryView::NotifyDataRemoved(uint64_t offset, uint64_t len)
{
	BNNotifyDataRemoved(m_object, offset, len);
}


Ref<BinaryView> BinaryView::GetParentView() const
{
	BNBinaryView* view = BNGetParentView(m_object);
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


string BinaryView::GetTypeName() const
{
	char* str = BNGetViewType(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


bool BinaryView::IsModified() const
{
	return BNIsViewModified(m_object);
}


bool BinaryView::IsAnalysisChanged() const
{
	return m_file->IsAnalysisChanged();
}


bool BinaryView::IsBackedByDatabase() const
{
	return m_file->IsBackedByDatabase();
}


bool BinaryView::CreateDatabase(const string& path)
{
	auto parent = GetParentView();
	if (parent)
		return parent->CreateDatabase(path);
	return m_file->CreateDatabase(path, this);
}


bool BinaryView::CreateDatabase(const string& path,
	const function<void(size_t progress, size_t total)>& progressCallback)
{
	auto parent = GetParentView();
	if (parent)
		return parent->CreateDatabase(path);
	return m_file->CreateDatabase(path, this, progressCallback);
}


bool BinaryView::SaveAutoSnapshot()
{
	return m_file->SaveAutoSnapshot(this);
}


bool BinaryView::SaveAutoSnapshot(const function<void(size_t progress, size_t total)>& progressCallback)
{
	return m_file->SaveAutoSnapshot(this, progressCallback);
}


void BinaryView::BeginUndoActions()
{
	m_file->BeginUndoActions();
}


void BinaryView::AddUndoAction(UndoAction* action)
{
	action->Add(m_object);
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
	BNDataBuffer* result = BNReadViewBuffer(m_object, offset, len);
	return DataBuffer(result);
}


size_t BinaryView::WriteBuffer(uint64_t offset, const DataBuffer& data)
{
	return BNWriteViewBuffer(m_object, offset, data.GetBufferObject());
}


size_t BinaryView::InsertBuffer(uint64_t offset, const DataBuffer& data)
{
	return BNInsertViewBuffer(m_object, offset, data.GetBufferObject());
}


vector<BNModificationStatus> BinaryView::GetModification(uint64_t offset, size_t len)
{
	BNModificationStatus* mod = new BNModificationStatus[len];
	len = BNGetModificationArray(m_object, offset, mod, len);

	vector<BNModificationStatus> result;
	result.reserve(len);
	for (size_t i = 0; i < len; i++)
		result.push_back(mod[i]);

	delete[] mod;
	return result;
}


uint64_t BinaryView::GetEnd() const
{
	return BNGetEndOffset(m_object);
}


bool BinaryView::Save(const string& path)
{
	return BNSaveToFilename(m_object, path.c_str());
}


void BinaryView::DefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc)
{
	BNDefineRelocation(m_object, arch->GetObject(), &info, target, reloc);
}


void BinaryView::DefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> target, uint64_t reloc)
{
	BNDefineSymbolRelocation(m_object, arch->GetObject(), &info, target->GetObject(), reloc);
}


vector<pair<uint64_t, uint64_t>> BinaryView::GetRelocationRanges() const
{
	size_t count = 0;
	BNRange* ranges = BNGetRelocationRanges(m_object, &count);
	vector<pair<uint64_t, uint64_t>> result(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back({ranges[i].start, ranges[i].end});
	}
	BNFreeRelocationRanges(ranges);
	return result;
}


vector<pair<uint64_t, uint64_t>> BinaryView::GetRelocationRangesAtAddress(uint64_t addr) const
{
	size_t count = 0;
	BNRange* ranges = BNGetRelocationRangesAtAddress(m_object, addr, &count);
	vector<pair<uint64_t, uint64_t>> result(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back({ranges[i].start, ranges[i].end});
	}
	BNFreeRelocationRanges(ranges);
	return result;
}


void BinaryView::RegisterNotification(BinaryDataNotification* notify)
{
	BNRegisterDataNotification(m_object, notify->GetCallbacks());
}


void BinaryView::UnregisterNotification(BinaryDataNotification* notify)
{
	BNUnregisterDataNotification(m_object, notify->GetCallbacks());
}


size_t BinaryView::Read(void* dest, uint64_t offset, size_t len)
{
	return BNReadViewData(m_object, dest, offset, len);
}


size_t BinaryView::Write(uint64_t offset, const void* data, size_t len)
{
	return BNWriteViewData(m_object, offset, data, len);
}


size_t BinaryView::Insert(uint64_t offset, const void* data, size_t len)
{
	return BNInsertViewData(m_object, offset, data, len);
}


size_t BinaryView::Remove(uint64_t offset, uint64_t len)
{
	return BNRemoveViewData(m_object, offset, len);
}


BNModificationStatus BinaryView::GetModification(uint64_t offset)
{
	return BNGetModification(m_object, offset);
}


bool BinaryView::IsValidOffset(uint64_t offset) const
{
	return BNIsValidOffset(m_object, offset);
}


bool BinaryView::IsOffsetReadable(uint64_t offset) const
{
	return BNIsOffsetReadable(m_object, offset);
}


bool BinaryView::IsOffsetWritable(uint64_t offset) const
{
	return BNIsOffsetWritable(m_object, offset);
}


bool BinaryView::IsOffsetExecutable(uint64_t offset) const
{
	return BNIsOffsetExecutable(m_object, offset);
}


bool BinaryView::IsOffsetBackedByFile(uint64_t offset) const
{
	return BNIsOffsetBackedByFile(m_object, offset);
}


bool BinaryView::IsOffsetCodeSemantics(uint64_t offset) const
{
	return BNIsOffsetCodeSemantics(m_object, offset);
}


bool BinaryView::IsOffsetExternSemantics(uint64_t offset) const
{
	return BNIsOffsetExternSemantics(m_object, offset);
}


bool BinaryView::IsOffsetWritableSemantics(uint64_t offset) const
{
	return BNIsOffsetWritableSemantics(m_object, offset);
}


uint64_t BinaryView::GetNextValidOffset(uint64_t offset) const
{
	return BNGetNextValidOffset(m_object, offset);
}


uint64_t BinaryView::GetStart() const
{
	return BNGetStartOffset(m_object);
}


uint64_t BinaryView::GetLength() const
{
	return BNGetViewLength(m_object);
}


uint64_t BinaryView::GetEntryPoint() const
{
	return BNGetEntryPoint(m_object);
}


Ref<Architecture> BinaryView::GetDefaultArchitecture() const
{
	BNArchitecture* arch = BNGetDefaultArchitecture(m_object);
	if (!arch)
		return nullptr;
	return new CoreArchitecture(arch);
}


void BinaryView::SetDefaultArchitecture(Architecture* arch)
{
	if (arch)
		BNSetDefaultArchitecture(m_object, arch->GetObject());
	else
		BNSetDefaultArchitecture(m_object, nullptr);
}


Ref<Platform> BinaryView::GetDefaultPlatform() const
{
	BNPlatform* platform = BNGetDefaultPlatform(m_object);
	if (!platform)
		return nullptr;
	return new Platform(platform);
}


void BinaryView::SetDefaultPlatform(Platform* platform)
{
	if (platform)
		BNSetDefaultPlatform(m_object, platform->GetObject());
	else
		BNSetDefaultPlatform(m_object, nullptr);
}


BNEndianness BinaryView::GetDefaultEndianness() const
{
	return BNGetDefaultEndianness(m_object);
}


bool BinaryView::IsRelocatable() const
{
	return BNIsRelocatable(m_object);
}


size_t BinaryView::GetAddressSize() const
{
	return BNGetViewAddressSize(m_object);
}


bool BinaryView::IsExecutable() const
{
	return BNIsExecutableView(m_object);
}


bool BinaryView::Save(FileAccessor* file)
{
	return BNSaveToFile(m_object, file->GetCallbacks());
}


void BinaryView::AddAnalysisOption(const string& name)
{
	BNAddAnalysisOption(m_object, name.c_str());
}


void BinaryView::AddFunctionForAnalysis(Platform* platform, uint64_t addr)
{
	BNAddFunctionForAnalysis(m_object, platform->GetObject(), addr);
}


void BinaryView::AddEntryPointForAnalysis(Platform* platform, uint64_t addr)
{
	BNAddEntryPointForAnalysis(m_object, platform->GetObject(), addr);
}


void BinaryView::RemoveAnalysisFunction(Function* func)
{
	BNRemoveAnalysisFunction(m_object, func->GetObject());
}


void BinaryView::CreateUserFunction(Platform* platform, uint64_t start)
{
	BNCreateUserFunction(m_object, platform->GetObject(), start);
}


void BinaryView::RemoveUserFunction(Function* func)
{
	BNRemoveUserFunction(m_object, func->GetObject());
}


void BinaryView::UpdateAnalysisAndWait()
{
	BNUpdateAnalysisAndWait(m_object);
}


void BinaryView::UpdateAnalysis()
{
	BNUpdateAnalysis(m_object);
}


void BinaryView::AbortAnalysis()
{
	BNAbortAnalysis(m_object);
}


void BinaryView::DefineDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNDefineDataVariable(m_object, addr, &tc);
}


void BinaryView::DefineUserDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNDefineUserDataVariable(m_object, addr, &tc);
}


void BinaryView::UndefineDataVariable(uint64_t addr)
{
	BNUndefineDataVariable(m_object, addr);
}


void BinaryView::UndefineUserDataVariable(uint64_t addr)
{
	BNUndefineUserDataVariable(m_object, addr);
}


map<uint64_t, DataVariable> BinaryView::GetDataVariables()
{
	size_t count;
	BNDataVariable* vars = BNGetDataVariables(m_object, &count);

	map<uint64_t, DataVariable> result;
	for (size_t i = 0; i < count; i++)
	{
		result.emplace(piecewise_construct, forward_as_tuple(vars[i].address),
			forward_as_tuple(vars[i].address, Confidence<Ref<Type>>(new Type(BNNewTypeReference(vars[i].type)), vars[i].typeConfidence), vars[i].autoDiscovered));
	}

	BNFreeDataVariables(vars, count);
	return result;
}


bool BinaryView::GetDataVariableAtAddress(uint64_t addr, DataVariable& var)
{
	var.address = 0;
	var.type = Confidence<Ref<Type>>(nullptr, 0);
	var.autoDiscovered = false;

	BNDataVariable result;
	if (!BNGetDataVariableAtAddress(m_object, addr, &result))
		return false;

	var.address = result.address;
	var.type = Confidence<Ref<Type>>(new Type(result.type), result.typeConfidence);
	var.autoDiscovered = result.autoDiscovered;
	return true;
}


vector<Ref<Function>> BinaryView::GetAnalysisFunctionList()
{
	size_t count;
	BNFunction** list = BNGetAnalysisFunctionList(m_object, &count);

	vector<Ref<Function>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Function(BNNewFunctionReference(list[i])));

	BNFreeFunctionList(list, count);

	return result;
}


AnalysisInfo BinaryView::GetAnalysisInfo()
{
	AnalysisInfo result;
	BNAnalysisInfo* info = BNGetAnalysisInfo(m_object);
	result.state = info->state;
	result.analysisTime = info->analysisTime;
	result.activeInfo.reserve(info->count);
	for (size_t i = 0; i < info->count; i++)
		result.activeInfo.emplace_back(new Function(BNNewFunctionReference(info->activeInfo[i].func)),
			info->activeInfo[i].analysisTime, info->activeInfo[i].submitCount, info->activeInfo[i].updateCount);
	BNFreeAnalysisInfo(info);
	return result;
}


bool BinaryView::HasFunctions() const
{
	return BNHasFunctions(m_object);
}


Ref<Function> BinaryView::GetAnalysisFunction(Platform* platform, uint64_t addr)
{
	BNFunction* func = BNGetAnalysisFunction(m_object, platform->GetObject(), addr);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<Function> BinaryView::GetRecentAnalysisFunctionForAddress(uint64_t addr)
{
	BNFunction* func = BNGetRecentAnalysisFunctionForAddress(m_object, addr);
	if (!func)
		return nullptr;
	return new Function(func);
}


vector<Ref<Function>> BinaryView::GetAnalysisFunctionsForAddress(uint64_t addr)
{
	size_t count;
	BNFunction** list = BNGetAnalysisFunctionsForAddress(m_object, addr, &count);

	vector<Ref<Function>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Function(BNNewFunctionReference(list[i])));

	BNFreeFunctionList(list, count);
	return result;
}


Ref<Function> BinaryView::GetAnalysisEntryPoint()
{
	BNFunction* func = BNGetAnalysisEntryPoint(m_object);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<BasicBlock> BinaryView::GetRecentBasicBlockForAddress(uint64_t addr)
{
	BNBasicBlock* block = BNGetRecentBasicBlockForAddress(m_object, addr);
	if (!block)
		return nullptr;
	return new BasicBlock(block);
}


vector<Ref<BasicBlock>> BinaryView::GetBasicBlocksForAddress(uint64_t addr)
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlocksForAddress(m_object, addr, &count);

	vector<Ref<BasicBlock>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


vector<Ref<BasicBlock>> BinaryView::GetBasicBlocksStartingAtAddress(uint64_t addr)
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlocksStartingAtAddress(m_object, addr, &count);

	vector<Ref<BasicBlock>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


vector<ReferenceSource> BinaryView::GetCodeReferences(uint64_t addr)
{
	size_t count;
	BNReferenceSource* refs = BNGetCodeReferences(m_object, addr, &count);

	vector<ReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		ReferenceSource src;
		src.func = new Function(BNNewFunctionReference(refs[i].func));
		src.arch = new CoreArchitecture(refs[i].arch);
		src.addr = refs[i].addr;
		result.push_back(src);
	}

	BNFreeCodeReferences(refs, count);
	return result;
}


vector<ReferenceSource> BinaryView::GetCodeReferences(uint64_t addr, uint64_t len)
{
	size_t count;
	BNReferenceSource* refs = BNGetCodeReferencesInRange(m_object, addr, len, &count);

	vector<ReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		ReferenceSource src;
		src.func = new Function(BNNewFunctionReference(refs[i].func));
		src.arch = new CoreArchitecture(refs[i].arch);
		src.addr = refs[i].addr;
		result.push_back(src);
	}

	BNFreeCodeReferences(refs, count);
	return result;
}


Ref<Symbol> BinaryView::GetSymbolByAddress(uint64_t addr, const NameSpace& nameSpace)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol* sym = BNGetSymbolByAddress(m_object, addr, &ns);
	NameSpace::FreeAPIObject(&ns);
	if (!sym)
		return nullptr;
	return new Symbol(sym);
}


Ref<Symbol> BinaryView::GetSymbolByRawName(const string& name, const NameSpace& nameSpace)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol* sym = BNGetSymbolByRawName(m_object, name.c_str(), &ns);
	if (!sym)
		return nullptr;
	return new Symbol(sym);
}


vector<Ref<Symbol>> BinaryView::GetSymbolsByName(const string& name, const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetSymbolsByName(m_object, name.c_str(), &count, &ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbols(const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetSymbols(m_object, &count, &ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbols(uint64_t start, uint64_t len, const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetSymbolsInRange(m_object, start, len, &count, &ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbolsOfType(BNSymbolType type, const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetSymbolsOfType(m_object, type, &count, &ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbolsOfType(BNSymbolType type, uint64_t start, uint64_t len, const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetSymbolsOfTypeInRange(m_object, type, start, len, &count, &ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


void BinaryView::DefineAutoSymbol(Ref<Symbol> sym, const NameSpace& nameSpace)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNDefineAutoSymbol(m_object, sym->GetObject(), &ns);
}


void BinaryView::DefineAutoSymbolAndVariableOrFunction(Ref<Platform> platform, Ref<Symbol> sym, Ref<Type> type, const NameSpace& nameSpace)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNDefineAutoSymbolAndVariableOrFunction(m_object, platform ? platform->GetObject() : nullptr, sym->GetObject(),
		type ? type->GetObject() : nullptr, &ns);
}


void BinaryView::UndefineAutoSymbol(Ref<Symbol> sym, const NameSpace& nameSpace)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNUndefineAutoSymbol(m_object, sym->GetObject(), &ns);
}


void BinaryView::DefineUserSymbol(Ref<Symbol> sym, const NameSpace& nameSpace)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNDefineUserSymbol(m_object, sym->GetObject(), &ns);
}


void BinaryView::UndefineUserSymbol(Ref<Symbol> sym, const NameSpace& nameSpace)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNUndefineUserSymbol(m_object, sym->GetObject(), &ns);
}


void BinaryView::DefineImportedFunction(Ref<Symbol> importAddressSym, Ref<Function> func)
{
	BNDefineImportedFunction(m_object, importAddressSym->GetObject(), func->GetObject());
}


bool BinaryView::IsNeverBranchPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsNeverBranchPatchAvailable(m_object, arch->GetObject(), addr);
}


bool BinaryView::IsAlwaysBranchPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsAlwaysBranchPatchAvailable(m_object, arch->GetObject(), addr);
}


bool BinaryView::IsInvertBranchPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsInvertBranchPatchAvailable(m_object, arch->GetObject(), addr);
}


bool BinaryView::IsSkipAndReturnZeroPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsSkipAndReturnZeroPatchAvailable(m_object, arch->GetObject(), addr);
}


bool BinaryView::IsSkipAndReturnValuePatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsSkipAndReturnValuePatchAvailable(m_object, arch->GetObject(), addr);
}


bool BinaryView::ConvertToNop(Architecture* arch, uint64_t addr)
{
	return BNConvertToNop(m_object, arch->GetObject(), addr);
}


bool BinaryView::AlwaysBranch(Architecture* arch, uint64_t addr)
{
	return BNAlwaysBranch(m_object, arch->GetObject(), addr);
}


bool BinaryView::InvertBranch(Architecture* arch, uint64_t addr)
{
	return BNInvertBranch(m_object, arch->GetObject(), addr);
}


bool BinaryView::SkipAndReturnValue(Architecture* arch, uint64_t addr, uint64_t value)
{
	return BNSkipAndReturnValue(m_object, arch->GetObject(), addr, value);
}


size_t BinaryView::GetInstructionLength(Architecture* arch, uint64_t addr)
{
	return BNGetInstructionLength(m_object, arch->GetObject(), addr);
}


vector<BNStringReference> BinaryView::GetStrings()
{
	size_t count;
	BNStringReference* strings = BNGetStrings(m_object, &count);
	vector<BNStringReference> result;
	result.insert(result.end(), strings, strings + count);
	BNFreeStringReferenceList(strings);
	return result;
}


vector<BNStringReference> BinaryView::GetStrings(uint64_t start, uint64_t len)
{
	size_t count;
	BNStringReference* strings = BNGetStringsInRange(m_object, start, len, &count);
	vector<BNStringReference> result;
	result.insert(result.end(), strings, strings + count);
	BNFreeStringReferenceList(strings);
	return result;
}


Ref<AnalysisCompletionEvent> BinaryView::AddAnalysisCompletionEvent(const function<void()>& callback)
{
	return new AnalysisCompletionEvent(this, callback);
}


BNAnalysisProgress BinaryView::GetAnalysisProgress()
{
	return BNGetAnalysisProgress(m_object);
}


Ref<BackgroundTask> BinaryView::GetBackgroundAnalysisTask()
{
	BNBackgroundTask* task = BNGetBackgroundAnalysisTask(m_object);
	if (!task)
		return nullptr;

	return new BackgroundTask(BNNewBackgroundTaskReference(task));
}


uint64_t BinaryView::GetNextFunctionStartAfterAddress(uint64_t addr)
{
	return BNGetNextFunctionStartAfterAddress(m_object, addr);
}


uint64_t BinaryView::GetNextBasicBlockStartAfterAddress(uint64_t addr)
{
	return BNGetNextBasicBlockStartAfterAddress(m_object, addr);
}


uint64_t BinaryView::GetNextDataAfterAddress(uint64_t addr)
{
	return BNGetNextDataAfterAddress(m_object, addr);
}

uint64_t BinaryView::GetNextDataVariableAfterAddress(uint64_t addr)
{
	return BNGetNextDataVariableAfterAddress(m_object, addr);
}

uint64_t BinaryView::GetPreviousFunctionStartBeforeAddress(uint64_t addr)
{
	return BNGetPreviousFunctionStartBeforeAddress(m_object, addr);
}


uint64_t BinaryView::GetPreviousBasicBlockStartBeforeAddress(uint64_t addr)
{
	return BNGetPreviousBasicBlockStartBeforeAddress(m_object, addr);
}


uint64_t BinaryView::GetPreviousBasicBlockEndBeforeAddress(uint64_t addr)
{
	return BNGetPreviousBasicBlockEndBeforeAddress(m_object, addr);
}


uint64_t BinaryView::GetPreviousDataBeforeAddress(uint64_t addr)
{
	return BNGetPreviousDataBeforeAddress(m_object, addr);
}


LinearDisassemblyPosition BinaryView::GetLinearDisassemblyPositionForAddress(uint64_t addr,
	DisassemblySettings* settings)
{
	BNLinearDisassemblyPosition pos = BNGetLinearDisassemblyPositionForAddress(m_object, addr,
		settings ? settings->GetObject() : nullptr);

	LinearDisassemblyPosition result;
	result.function = pos.function ? new Function(pos.function) : nullptr;
	result.block = pos.block ? new BasicBlock(pos.block) : nullptr;
	result.address = pos.address;
	return result;
}


vector<LinearDisassemblyLine> BinaryView::GetPreviousLinearDisassemblyLines(LinearDisassemblyPosition& pos,
	DisassemblySettings* settings)
{
	BNLinearDisassemblyPosition linearPos;
	linearPos.function = pos.function ? BNNewFunctionReference(pos.function->GetObject()) : nullptr;
	linearPos.block = pos.block ? BNNewBasicBlockReference(pos.block->GetObject()) : nullptr;
	linearPos.address = pos.address;

	size_t count;
	BNLinearDisassemblyLine* lines = BNGetPreviousLinearDisassemblyLines(m_object, &linearPos,
		settings ? settings->GetObject() : nullptr, &count);

	vector<LinearDisassemblyLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		LinearDisassemblyLine line;
		line.type = lines[i].type;
		line.function = lines[i].function ? new Function(BNNewFunctionReference(lines[i].function)) : nullptr;
		line.block = lines[i].block ? new BasicBlock(BNNewBasicBlockReference(lines[i].block)) : nullptr;
		line.lineOffset = lines[i].lineOffset;
		line.contents.addr = lines[i].contents.addr;
		line.contents.instrIndex = lines[i].contents.instrIndex;
		line.contents.highlight = lines[i].contents.highlight;
		line.contents.tokens.reserve(lines[i].contents.count);
		for (size_t j = 0; j < lines[i].contents.count; j++)
		{
			InstructionTextToken token;
			token.type = lines[i].contents.tokens[j].type;
			token.text = lines[i].contents.tokens[j].text;
			token.value = lines[i].contents.tokens[j].value;
			token.size = lines[i].contents.tokens[j].size;
			token.operand = lines[i].contents.tokens[j].operand;
			token.context = lines[i].contents.tokens[j].context;
			token.confidence = lines[i].contents.tokens[j].confidence;
			token.address = lines[i].contents.tokens[j].address;
			line.contents.tokens.push_back(token);
		}
		result.push_back(line);
	}

	pos.function = linearPos.function ? new Function(linearPos.function) : nullptr;
	pos.block = linearPos.block ? new BasicBlock(linearPos.block) : nullptr;
	pos.address = linearPos.address;

	BNFreeLinearDisassemblyLines(lines, count);
	return result;
}


vector<LinearDisassemblyLine> BinaryView::GetNextLinearDisassemblyLines(LinearDisassemblyPosition& pos,
	DisassemblySettings* settings)
{
	BNLinearDisassemblyPosition linearPos;
	linearPos.function = pos.function ? BNNewFunctionReference(pos.function->GetObject()) : nullptr;
	linearPos.block = pos.block ? BNNewBasicBlockReference(pos.block->GetObject()) : nullptr;
	linearPos.address = pos.address;

	size_t count;
	BNLinearDisassemblyLine* lines = BNGetNextLinearDisassemblyLines(m_object, &linearPos,
		settings ? settings->GetObject() : nullptr, &count);

	vector<LinearDisassemblyLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		LinearDisassemblyLine line;
		line.type = lines[i].type;
		line.function = lines[i].function ? new Function(BNNewFunctionReference(lines[i].function)) : nullptr;
		line.block = lines[i].block ? new BasicBlock(BNNewBasicBlockReference(lines[i].block)) : nullptr;
		line.lineOffset = lines[i].lineOffset;
		line.contents.addr = lines[i].contents.addr;
		line.contents.instrIndex = lines[i].contents.instrIndex;
		line.contents.highlight = lines[i].contents.highlight;
		line.contents.tokens.reserve(lines[i].contents.count);
		for (size_t j = 0; j < lines[i].contents.count; j++)
		{
			InstructionTextToken token;
			token.type = lines[i].contents.tokens[j].type;
			token.text = lines[i].contents.tokens[j].text;
			token.value = lines[i].contents.tokens[j].value;
			token.size = lines[i].contents.tokens[j].size;
			token.operand = lines[i].contents.tokens[j].operand;
			token.context = lines[i].contents.tokens[j].context;
			token.confidence = lines[i].contents.tokens[j].confidence;
			token.address = lines[i].contents.tokens[j].address;
			line.contents.tokens.push_back(token);
		}
		result.push_back(line);
	}

	pos.function = linearPos.function ? new Function(linearPos.function) : nullptr;
	pos.block = linearPos.block ? new BasicBlock(linearPos.block) : nullptr;
	pos.address = linearPos.address;

	BNFreeLinearDisassemblyLines(lines, count);
	return result;
}


bool BinaryView::ParseTypeString(const string& text, QualifiedNameAndType& result, string& errors)
{
	BNQualifiedNameAndType nt;
	char* errorStr;

	if (!BNParseTypeString(m_object, text.c_str(), &nt, &errorStr))
	{
		errors = errorStr;
		BNFreeString(errorStr);
		return false;
	}

	result.name = QualifiedName::FromAPIObject(&nt.name);
	result.type = new Type(BNNewTypeReference(nt.type));
	errors = "";
	BNFreeQualifiedNameAndType(&nt);
	return true;
}


map<QualifiedName, Ref<Type>> BinaryView::GetTypes()
{
	size_t count;
	BNQualifiedNameAndType* types = BNGetAnalysisTypeList(m_object, &count);

	map<QualifiedName, Ref<Type>> result;
	for (size_t i = 0; i < count; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&types[i].name);
		result[name] = new Type(BNNewTypeReference(types[i].type));
	}

	BNFreeTypeList(types, count);
	return result;
}


Ref<Type> BinaryView::GetTypeByName(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNType* type = BNGetAnalysisTypeByName(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);

	if (!type)
		return nullptr;
	return new Type(type);
}


Ref<Type> BinaryView::GetTypeById(const string& id)
{
	BNType* type = BNGetAnalysisTypeById(m_object, id.c_str());
	if (!type)
		return nullptr;
	return new Type(type);
}


QualifiedName BinaryView::GetTypeNameById(const string& id)
{
	BNQualifiedName name = BNGetAnalysisTypeNameById(m_object, id.c_str());
	QualifiedName result = QualifiedName::FromAPIObject(&name);
	BNFreeQualifiedName(&name);
	return result;
}


string BinaryView::GetTypeId(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	char* id = BNGetAnalysisTypeId(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
	string result = id;
	BNFreeString(id);
	return result;
}


bool BinaryView::IsTypeAutoDefined(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	bool result = BNIsAnalysisTypeAutoDefined(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
	return result;
}


QualifiedName BinaryView::DefineType(const string& id, const QualifiedName& defaultName, Ref<Type> type)
{
	BNQualifiedName nameObj = defaultName.GetAPIObject();
	BNQualifiedName regName = BNDefineAnalysisType(m_object, id.c_str(), &nameObj, type->GetObject());
	QualifiedName::FreeAPIObject(&nameObj);
	QualifiedName result = QualifiedName::FromAPIObject(&regName);
	BNFreeQualifiedName(&regName);
	return result;
}


void BinaryView::DefineUserType(const QualifiedName& name, Ref<Type> type)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNDefineUserAnalysisType(m_object, &nameObj, type->GetObject());
	QualifiedName::FreeAPIObject(&nameObj);
}


void BinaryView::UndefineType(const string& id)
{
	BNUndefineAnalysisType(m_object, id.c_str());
}


void BinaryView::UndefineUserType(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNUndefineUserAnalysisType(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
}


void BinaryView::RenameType(const QualifiedName& oldName, const QualifiedName& newName)
{
	BNQualifiedName oldNameObj = oldName.GetAPIObject();
	BNQualifiedName newNameObj = newName.GetAPIObject();
	BNRenameAnalysisType(m_object, &oldNameObj, &newNameObj);
	QualifiedName::FreeAPIObject(&oldNameObj);
	QualifiedName::FreeAPIObject(&newNameObj);
}


void BinaryView::RegisterPlatformTypes(Platform* platform)
{
	BNRegisterPlatformTypes(m_object, platform->GetObject());
}


bool BinaryView::FindNextData(uint64_t start, const DataBuffer& data, uint64_t& result, BNFindFlag flags)
{
	return BNFindNextData(m_object, start, data.GetBufferObject(), &result, flags);
}


void BinaryView::Reanalyze()
{
	BNReanalyzeAllFunctions(m_object);
}


void BinaryView::ShowPlainTextReport(const string& title, const string& contents)
{
	BNShowPlainTextReport(m_object, title.c_str(), contents.c_str());
}


void BinaryView::ShowMarkdownReport(const string& title, const string& contents, const string& plainText)
{
	BNShowMarkdownReport(m_object, title.c_str(), contents.c_str(), plainText.c_str());
}


void BinaryView::ShowHTMLReport(const string& title, const string& contents, const string& plainText)
{
	BNShowHTMLReport(m_object, title.c_str(), contents.c_str(), plainText.c_str());
}


void BinaryView::ShowGraphReport(const string& title, FlowGraph* graph)
{
	BNShowGraphReport(m_object, title.c_str(), graph->GetObject());
}


bool BinaryView::GetAddressInput(uint64_t& result, const string& prompt, const string& title)
{
	uint64_t currentAddress = 0;
	if (m_file)
		currentAddress = m_file->GetCurrentOffset();
	return BNGetAddressInput(&result, prompt.c_str(), title.c_str(), m_object, currentAddress);
}


bool BinaryView::GetAddressInput(uint64_t& result, const string& prompt, const string& title, uint64_t currentAddress)
{
	return BNGetAddressInput(&result, prompt.c_str(), title.c_str(), m_object, currentAddress);
}


void BinaryView::AddAutoSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength,
	uint32_t flags)
{
	BNAddAutoSegment(m_object, start, length, dataOffset, dataLength, flags);
}


void BinaryView::RemoveAutoSegment(uint64_t start, uint64_t length)
{
	BNRemoveAutoSegment(m_object, start, length);
}


void BinaryView::AddUserSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength,
	uint32_t flags)
{
	BNAddUserSegment(m_object, start, length, dataOffset, dataLength, flags);
}


void BinaryView::RemoveUserSegment(uint64_t start, uint64_t length)
{
	BNRemoveUserSegment(m_object, start, length);
}


vector<Ref<Segment>> BinaryView::GetSegments()
{
	size_t count;
	BNSegment** segments = BNGetSegments(m_object, &count);

	vector<Ref<Segment>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Segment(BNNewSegmentReference(segments[i])));

	BNFreeSegmentList(segments, count);
	return result;
}


Ref<Segment> BinaryView::GetSegmentAt(uint64_t addr)
{
	BNSegment* segment = BNGetSegmentAt(m_object, addr);
	if (!segment)
		return nullptr;

	return new Segment(BNNewSegmentReference(segment));
}


bool BinaryView::GetAddressForDataOffset(uint64_t offset, uint64_t& addr)
{
	return BNGetAddressForDataOffset(m_object, offset, &addr);
}


void BinaryView::AddAutoSection(const string& name, uint64_t start, uint64_t length, BNSectionSemantics semantics,
	const string& type, uint64_t align, uint64_t entrySize, const string& linkedSection,
	const string& infoSection, uint64_t infoData)
{
	BNAddAutoSection(m_object, name.c_str(), start, length, semantics, type.c_str(), align, entrySize,
		linkedSection.c_str(), infoSection.c_str(), infoData);
}


void BinaryView::RemoveAutoSection(const string& name)
{
	BNRemoveAutoSection(m_object, name.c_str());
}


void BinaryView::AddUserSection(const string& name, uint64_t start, uint64_t length, BNSectionSemantics semantics,
	const string& type, uint64_t align, uint64_t entrySize, const string& linkedSection,
	const string& infoSection, uint64_t infoData)
{
	BNAddUserSection(m_object, name.c_str(), start, length, semantics, type.c_str(), align, entrySize,
		linkedSection.c_str(), infoSection.c_str(), infoData);
}


void BinaryView::RemoveUserSection(const string& name)
{
	BNRemoveUserSection(m_object, name.c_str());
}


vector<Ref<Section>> BinaryView::GetSections()
{
	size_t count;
	BNSection** sections = BNGetSections(m_object, &count);

	vector<Ref<Section>> result;
    result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Section(BNNewSectionReference(sections[i])));

	BNFreeSectionList(sections, count);
	return result;
}


vector<Ref<Section>> BinaryView::GetSectionsAt(uint64_t addr)
{
	size_t count;
	BNSection** sections = BNGetSectionsAt(m_object, addr, &count);

	vector<Ref<Section>> result;
    result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new Section(BNNewSectionReference(sections[i])));
	}

	BNFreeSectionList(sections, count);
	return result;
}


Ref<Section> BinaryView::GetSectionByName(const string& name)
{
	BNSection* section = BNGetSectionByName(m_object, name.c_str());
	if (section)
		return new Section(BNNewSectionReference(section));
	return nullptr;
}


vector<string> BinaryView::GetUniqueSectionNames(const vector<string>& names)
{
	const char** incomingNames = new const char*[names.size()];
	for (size_t i = 0; i < names.size(); i++)
		incomingNames[i] = names[i].c_str();

	char** outgoingNames = BNGetUniqueSectionNames(m_object, incomingNames, names.size());
	vector<string> result;
	result.reserve(names.size());
	for (size_t i = 0; i < names.size(); i++)
		result.push_back(outgoingNames[i]);

	BNFreeStringList(outgoingNames, names.size());
	return result;
}


vector<BNAddressRange> BinaryView::GetAllocatedRanges()
{
	size_t count;
	BNAddressRange* ranges = BNGetAllocatedRanges(m_object, &count);

	vector<BNAddressRange> result;
	copy(&ranges[0], &ranges[count], back_inserter(result));
	BNFreeAddressRanges(ranges);
	return result;
}


void BinaryView::StoreMetadata(const std::string& key, Ref<Metadata> inValue)
{
	if (!inValue)
		return;
	BNBinaryViewStoreMetadata(m_object, key.c_str(), inValue->GetObject());
}

Ref<Metadata> BinaryView::QueryMetadata(const std::string& key)
{
	BNMetadata* value = BNBinaryViewQueryMetadata(m_object, key.c_str());
	if (!value)
		return nullptr;
	return new Metadata(value);
}

void BinaryView::RemoveMetadata(const std::string& key)
{
	BNBinaryViewRemoveMetadata(m_object, key.c_str());
}

string BinaryView::GetStringMetadata(const string& key)
{
	auto data = QueryMetadata(key);
	if (!data || !data->IsString())
		throw QueryMetadataException("Failed to find key: " + key);
	return data->GetString();
}

vector<uint8_t> BinaryView::GetRawMetadata(const string& key)
{
	auto data = QueryMetadata(key);
	if (!data || !data->IsRaw())
		throw QueryMetadataException("Failed to find key: " + key);
	return data->GetRaw();
}

uint64_t BinaryView::GetUIntMetadata(const string& key)
{
	auto data = QueryMetadata(key);
	if (!data || !data->IsUnsignedInteger())
		throw QueryMetadataException("Failed to find key: " + key);
	return data->GetUnsignedInteger();
}


BNAnalysisParameters BinaryView::GetParametersForAnalysis()
{
	return BNGetParametersForAnalysis(m_object);
}


void BinaryView::SetParametersForAnalysis(BNAnalysisParameters params)
{
	BNSetParametersForAnalysis(m_object, params);
}


uint64_t BinaryView::GetMaxFunctionSizeForAnalysis()
{
	return BNGetMaxFunctionSizeForAnalysis(m_object);
}


void BinaryView::SetMaxFunctionSizeForAnalysis(uint64_t size)
{
	BNSetMaxFunctionSizeForAnalysis(m_object, size);
}


bool BinaryView::GetNewAutoFunctionAnalysisSuppressed()
{
	return BNGetNewAutoFunctionAnalysisSuppressed(m_object);
}


void BinaryView::SetNewAutoFunctionAnalysisSuppressed(bool suppress)
{
	BNSetNewAutoFunctionAnalysisSuppressed(m_object, suppress);
}


set<NameSpace> BinaryView::GetNameSpaces() const
{
	set<NameSpace> nameSpaces;
	size_t count = 0;
	BNNameSpace* nameSpaceList = BNGetNameSpaces(m_object, &count);
	for (size_t i = 0; i < count; i++)
		nameSpaces.insert(NameSpace::FromAPIObject(&nameSpaceList[i]));
	BNFreeNameSpaceList(nameSpaceList, count);
	return nameSpaces;
}


NameSpace BinaryView::GetInternalNameSpace() const
{
	BNNameSpace ns = BNGetInternalNameSpace(m_object);
	NameSpace nameSpace = NameSpace::FromAPIObject(&ns);
	BNFreeNameSpace(&ns);
	return nameSpace;
}


NameSpace BinaryView::GetExternalNameSpace() const
{
	BNNameSpace ns = BNGetExternalNameSpace(m_object);
	NameSpace nameSpace = NameSpace::FromAPIObject(&ns);
	BNFreeNameSpace(&ns);
	return nameSpace;
}


Relocation::Relocation(BNRelocation* reloc)
{
	m_object = reloc;
}


BNRelocationInfo Relocation::GetInfo() const
{
	return BNRelocationGetInfo(m_object);
}


Architecture* Relocation::GetArchitecture() const
{
	return new CoreArchitecture(BNRelocationGetArchitecture(m_object));
}


uint64_t Relocation::GetTarget() const
{
	return BNRelocationGetTarget(m_object);
}


uint64_t Relocation::GetAddress() const
{
	return BNRelocationGetReloc(m_object);
}


Ref<Symbol> Relocation::GetSymbol() const
{
	BNSymbol* sym = BNRelocationGetSymbol(m_object);
	if (!sym)
		return nullptr;
	return new Symbol(sym);
}


BinaryData::BinaryData(FileMetadata* file): BinaryView(BNCreateBinaryDataView(file->GetObject()))
{
}


BinaryData::BinaryData(FileMetadata* file, const DataBuffer& data):
	BinaryView(BNCreateBinaryDataViewFromBuffer(file->GetObject(), data.GetBufferObject()))
{
}


BinaryData::BinaryData(FileMetadata* file, const void* data, size_t len):
	BinaryView(BNCreateBinaryDataViewFromData(file->GetObject(), data, len))
{
}


BinaryData::BinaryData(FileMetadata* file, const string& path):
	BinaryView(BNCreateBinaryDataViewFromFilename(file->GetObject(), path.c_str()))
{
}


BinaryData::BinaryData(FileMetadata* file, FileAccessor* accessor):
	BinaryView(BNCreateBinaryDataViewFromFile(file->GetObject(), accessor->GetCallbacks()))
{
}
