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


BinaryDataNotification::BinaryDataNotification()
{
	m_callbacks.context = this;
	m_callbacks.dataWritten = DataWrittenCallback;
	m_callbacks.dataInserted = DataInsertedCallback;
	m_callbacks.dataRemoved = DataRemovedCallback;
	m_callbacks.functionAdded = FunctionAddedCallback;
	m_callbacks.functionRemoved = FunctionRemovedCallback;
	m_callbacks.functionUpdated = FunctionUpdatedCallback;
}


Symbol::Symbol(BNSymbolType type, const string& shortName, const string& fullName, const string& rawName, uint64_t addr)
{
	m_sym = BNCreateSymbol(type, shortName.c_str(), fullName.c_str(), rawName.c_str(), addr);
}


Symbol::Symbol(BNSymbolType type, const std::string& name, uint64_t addr)
{
	m_sym = BNCreateSymbol(type, name.c_str(), name.c_str(), name.c_str(), addr);
}


Symbol::Symbol(BNSymbol* sym)
{
	m_sym = sym;
}


Symbol::~Symbol()
{
	BNFreeSymbol(m_sym);
}


BNSymbolType Symbol::GetType() const
{
	return BNGetSymbolType(m_sym);
}


string Symbol::GetShortName() const
{
	char* name = BNGetSymbolShortName(m_sym);
	string result = name;
	BNFreeString(name);
	return result;
}


string Symbol::GetFullName() const
{
	char* name = BNGetSymbolFullName(m_sym);
	string result = name;
	BNFreeString(name);
	return result;
}


string Symbol::GetRawName() const
{
	char* name = BNGetSymbolRawName(m_sym);
	string result = name;
	BNFreeString(name);
	return result;
}


uint64_t Symbol::GetAddress() const
{
	return BNGetSymbolAddress(m_sym);
}


bool Symbol::IsAutoDefined() const
{
	return BNIsSymbolAutoDefined(m_sym);
}


void Symbol::SetAutoDefined(bool val)
{
	BNSetSymbolAutoDefined(m_sym, val);
}


BinaryView::BinaryView(const std::string& typeName, FileMetadata* file)
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
	view.getEntryPoint = GetEntryPointCallback;
	view.isExecutable = IsExecutableCallback;
	view.getDefaultEndianness = GetDefaultEndiannessCallback;
	view.getAddressSize = GetAddressSizeCallback;
	view.save = SaveCallback;

	m_file = file;
	m_view = BNCreateCustomBinaryView(typeName.c_str(), m_file->GetFileObject(), &view);
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


bool BinaryView::IsValidOffsetCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsValidOffset(offset);
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


bool BinaryView::PerformIsValidOffset(uint64_t offset)
{
	uint8_t val;
	return PerformRead(&val, offset, 1) == 1;
}


BNEndianness BinaryView::PerformGetDefaultEndianness() const
{
	Ref<Architecture> arch = GetDefaultArchitecture();
	if (arch)
		return arch->GetEndianness();
	return LittleEndian;
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


void BinaryView::NotifyDataWritten(uint64_t offset, size_t len)
{
	BNNotifyDataWritten(m_view, offset, len);
}


void BinaryView::NotifyDataInserted(uint64_t offset, size_t len)
{
	BNNotifyDataInserted(m_view, offset, len);
}


void BinaryView::NotifyDataRemoved(uint64_t offset, uint64_t len)
{
	BNNotifyDataRemoved(m_view, offset, len);
}


bool BinaryView::IsModified() const
{
	return BNIsViewModified(m_view);
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
	return m_file->CreateDatabase(path, this);
}


bool BinaryView::SaveAutoSnapshot()
{
	return m_file->SaveAutoSnapshot(this);
}


void BinaryView::BeginUndoActions()
{
	m_file->BeginUndoActions();
}


void BinaryView::AddUndoAction(UndoAction* action)
{
	action->Add(m_view);
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


bool BinaryView::IsValidOffset(uint64_t offset) const
{
	return BNIsValidOffset(m_view, offset);
}


uint64_t BinaryView::GetStart() const
{
	return BNGetStartOffset(m_view);
}


uint64_t BinaryView::GetLength() const
{
	return BNGetViewLength(m_view);
}


uint64_t BinaryView::GetEntryPoint() const
{
	return BNGetEntryPoint(m_view);
}


Ref<Architecture> BinaryView::GetDefaultArchitecture() const
{
	BNArchitecture* arch = BNGetDefaultArchitecture(m_view);
	if (!arch)
		return nullptr;
	return new CoreArchitecture(arch);
}


void BinaryView::SetDefaultArchitecture(Architecture* arch)
{
	if (arch)
		BNSetDefaultArchitecture(m_view, arch->GetArchitectureObject());
	else
		BNSetDefaultArchitecture(m_view, nullptr);
}


BNEndianness BinaryView::GetDefaultEndianness() const
{
	return BNGetDefaultEndianness(m_view);
}


size_t BinaryView::GetAddressSize() const
{
	return BNGetViewAddressSize(m_view);
}


bool BinaryView::IsExecutable() const
{
	return BNIsExecutableView(m_view);
}


bool BinaryView::Save(FileAccessor* file)
{
	return BNSaveToFile(m_view, file->GetCallbacks());
}


void BinaryView::AddFunctionForAnalysis(Architecture* arch, uint64_t addr)
{
	BNAddFunctionForAnalysis(m_view, arch->GetArchitectureObject(), addr);
}


void BinaryView::AddEntryPointForAnalysis(Architecture* arch, uint64_t addr)
{
	BNAddEntryPointForAnalysis(m_view, arch->GetArchitectureObject(), addr);
}


void BinaryView::RemoveAnalysisFunction(Function* func)
{
	BNRemoveAnalysisFunction(m_view, func->GetFunctionObject());
}


void BinaryView::CreateUserFunction(Architecture* arch, uint64_t start)
{
	BNCreateUserFunction(m_view, arch->GetArchitectureObject(), start);
}


void BinaryView::UpdateAnalysis()
{
	BNUpdateAnalysis(m_view);
}


void BinaryView::AbortAnalysis()
{
	BNAbortAnalysis(m_view);
}


vector<Ref<Function>> BinaryView::GetAnalysisFunctionList()
{
	size_t count;
	BNFunction** list = BNGetAnalysisFunctionList(m_view, &count);

	vector<Ref<Function>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Function(BNNewFunctionReference(list[i])));

	BNFreeFunctionList(list, count);
	return result;
}


Ref<Function> BinaryView::GetAnalysisFunction(Architecture* arch, uint64_t addr)
{
	BNFunction* func = BNGetAnalysisFunction(m_view, arch->GetArchitectureObject(), addr);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<Function> BinaryView::GetRecentAnalysisFunctionForAddress(uint64_t addr)
{
	BNFunction* func = BNGetRecentAnalysisFunctionForAddress(m_view, addr);
	if (!func)
		return nullptr;
	return new Function(func);
}


vector<Ref<Function>> BinaryView::GetAnalysisFunctionsForAddress(uint64_t addr)
{
	size_t count;
	BNFunction** list = BNGetAnalysisFunctionsForAddress(m_view, addr, &count);

	vector<Ref<Function>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Function(BNNewFunctionReference(list[i])));

	BNFreeFunctionList(list, count);
	return result;
}


Ref<Function> BinaryView::GetAnalysisEntryPoint()
{
	BNFunction* func = BNGetAnalysisEntryPoint(m_view);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<BasicBlock> BinaryView::GetRecentBasicBlockForAddress(uint64_t addr)
{
	BNBasicBlock* block = BNGetRecentBasicBlockForAddress(m_view, addr);
	if (!block)
		return nullptr;
	return new BasicBlock(block);
}


vector<Ref<BasicBlock>> BinaryView::GetBasicBlocksForAddress(uint64_t addr)
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlocksForAddress(m_view, addr, &count);

	vector<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


vector<ReferenceSource> BinaryView::GetCodeReferences(uint64_t addr)
{
	size_t count;
	BNReferenceSource* refs = BNGetCodeReferences(m_view, addr, &count);

	vector<ReferenceSource> result;
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


Ref<Symbol> BinaryView::GetSymbolByAddress(uint64_t addr)
{
	BNSymbol* sym = BNGetSymbolByAddress(m_view, addr);
	if (!sym)
		return nullptr;
	return new Symbol(sym);
}


Ref<Symbol> BinaryView::GetSymbolByRawName(const string& name)
{
	BNSymbol* sym = BNGetSymbolByRawName(m_view, name.c_str());
	if (!sym)
		return nullptr;
	return new Symbol(sym);
}


vector<Ref<Symbol>> BinaryView::GetSymbolsByName(const string& name)
{
	size_t count;
	BNSymbol** syms = BNGetSymbolsByName(m_view, name.c_str(), &count);

	vector<Ref<Symbol>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbols()
{
	size_t count;
	BNSymbol** syms = BNGetSymbols(m_view, &count);

	vector<Ref<Symbol>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbolsOfType(BNSymbolType type)
{
	size_t count;
	BNSymbol** syms = BNGetSymbolsOfType(m_view, type, &count);

	vector<Ref<Symbol>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


void BinaryView::DefineAutoSymbol(Symbol* sym)
{
	BNDefineAutoSymbol(m_view, sym->GetSymbolObject());
}


void BinaryView::UndefineAutoSymbol(Symbol* sym)
{
	BNUndefineAutoSymbol(m_view, sym->GetSymbolObject());
}


void BinaryView::DefineSymbol(Symbol* sym)
{
	BNDefineSymbol(m_view, sym->GetSymbolObject());
}


void BinaryView::UndefineSymbol(Symbol* sym)
{
	BNUndefineSymbol(m_view, sym->GetSymbolObject());
}


void BinaryView::DefineUserSymbol(Symbol* sym)
{
	BNDefineUserSymbol(m_view, sym->GetSymbolObject());
}


void BinaryView::UndefineUserSymbol(Symbol* sym)
{
	BNUndefineUserSymbol(m_view, sym->GetSymbolObject());
}


bool BinaryView::IsNeverBranchPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsNeverBranchPatchAvailable(m_view, arch->GetArchitectureObject(), addr);
}


bool BinaryView::IsAlwaysBranchPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsAlwaysBranchPatchAvailable(m_view, arch->GetArchitectureObject(), addr);
}


bool BinaryView::IsInvertBranchPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsInvertBranchPatchAvailable(m_view, arch->GetArchitectureObject(), addr);
}


bool BinaryView::IsSkipAndReturnZeroPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsSkipAndReturnZeroPatchAvailable(m_view, arch->GetArchitectureObject(), addr);
}


bool BinaryView::IsSkipAndReturnValuePatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsSkipAndReturnValuePatchAvailable(m_view, arch->GetArchitectureObject(), addr);
}


bool BinaryView::ConvertToNop(Architecture* arch, uint64_t addr)
{
	return BNConvertToNop(m_view, arch->GetArchitectureObject(), addr);
}


bool BinaryView::AlwaysBranch(Architecture* arch, uint64_t addr)
{
	return BNAlwaysBranch(m_view, arch->GetArchitectureObject(), addr);
}


bool BinaryView::InvertBranch(Architecture* arch, uint64_t addr)
{
	return BNInvertBranch(m_view, arch->GetArchitectureObject(), addr);
}


bool BinaryView::SkipAndReturnValue(Architecture* arch, uint64_t addr, uint64_t value)
{
	return BNSkipAndReturnValue(m_view, arch->GetArchitectureObject(), addr, value);
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
