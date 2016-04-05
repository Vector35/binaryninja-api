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


BinaryDataNotification::BinaryDataNotification()
{
	m_callbacks.context = this;
	m_callbacks.dataWritten = DataWrittenCallback;
	m_callbacks.dataInserted = DataInsertedCallback;
	m_callbacks.dataRemoved = DataRemovedCallback;
	m_callbacks.functionAdded = FunctionAddedCallback;
	m_callbacks.functionRemoved = FunctionRemovedCallback;
	m_callbacks.functionUpdated = FunctionUpdatedCallback;
	m_callbacks.stringFound = StringFoundCallback;
	m_callbacks.stringRemoved = StringRemovedCallback;
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


void Symbol::SetAutoDefined(bool val)
{
	BNSetSymbolAutoDefined(m_object, val);
}


Ref<Symbol> Symbol::ImportedFunctionFromImportAddressSymbol(Symbol* sym, uint64_t addr)
{
	return new Symbol(BNImportedFunctionFromImportAddressSymbol(sym->GetObject(), addr));
}


BinaryView::BinaryView(const std::string& typeName, FileMetadata* file)
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
	view.getNextValidOffset = GetNextValidOffsetCallback;
	view.getStart = GetStartCallback;
	view.getLength = GetLengthCallback;
	view.getEntryPoint = GetEntryPointCallback;
	view.isExecutable = IsExecutableCallback;
	view.getDefaultEndianness = GetDefaultEndiannessCallback;
	view.getAddressSize = GetAddressSizeCallback;
	view.save = SaveCallback;

	m_file = file;
	AddRefForRegistration();
	m_object = BNCreateCustomBinaryView(typeName.c_str(), m_file->GetObject(), &view);
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


void BinaryView::UpdateAnalysis()
{
	BNUpdateAnalysis(m_object);
}


void BinaryView::AbortAnalysis()
{
	BNAbortAnalysis(m_object);
}


vector<Ref<Function>> BinaryView::GetAnalysisFunctionList()
{
	size_t count;
	BNFunction** list = BNGetAnalysisFunctionList(m_object, &count);

	vector<Ref<Function>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Function(BNNewFunctionReference(list[i])));

	BNFreeFunctionList(list, count);
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
	BNSymbol* sym = BNGetSymbolByAddress(m_object, addr);
	if (!sym)
		return nullptr;
	return new Symbol(sym);
}


Ref<Symbol> BinaryView::GetSymbolByRawName(const string& name)
{
	BNSymbol* sym = BNGetSymbolByRawName(m_object, name.c_str());
	if (!sym)
		return nullptr;
	return new Symbol(sym);
}


vector<Ref<Symbol>> BinaryView::GetSymbolsByName(const string& name)
{
	size_t count;
	BNSymbol** syms = BNGetSymbolsByName(m_object, name.c_str(), &count);

	vector<Ref<Symbol>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbols()
{
	size_t count;
	BNSymbol** syms = BNGetSymbols(m_object, &count);

	vector<Ref<Symbol>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbols(uint64_t start, uint64_t len)
{
	size_t count;
	BNSymbol** syms = BNGetSymbolsInRange(m_object, start, len, &count);

	vector<Ref<Symbol>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbolsOfType(BNSymbolType type)
{
	size_t count;
	BNSymbol** syms = BNGetSymbolsOfType(m_object, type, &count);

	vector<Ref<Symbol>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbolsOfType(BNSymbolType type, uint64_t start, uint64_t len)
{
	size_t count;
	BNSymbol** syms = BNGetSymbolsOfTypeInRange(m_object, type, start, len, &count);

	vector<Ref<Symbol>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


void BinaryView::DefineAutoSymbol(Symbol* sym)
{
	BNDefineAutoSymbol(m_object, sym->GetObject());
}


void BinaryView::UndefineAutoSymbol(Symbol* sym)
{
	BNUndefineAutoSymbol(m_object, sym->GetObject());
}


void BinaryView::DefineUserSymbol(Symbol* sym)
{
	BNDefineUserSymbol(m_object, sym->GetObject());
}


void BinaryView::UndefineUserSymbol(Symbol* sym)
{
	BNUndefineUserSymbol(m_object, sym->GetObject());
}


void BinaryView::DefineImportedFunction(Symbol* importAddressSym, Function* func)
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
	BNFreeStringList(strings);
	return result;
}


vector<BNStringReference> BinaryView::GetStrings(uint64_t start, uint64_t len)
{
	size_t count;
	BNStringReference* strings = BNGetStringsInRange(m_object, start, len, &count);
	vector<BNStringReference> result;
	result.insert(result.end(), strings, strings + count);
	BNFreeStringList(strings);
	return result;
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
