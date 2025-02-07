#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;

LanguageRepresentationFunction::LanguageRepresentationFunction(
	LanguageRepresentationFunctionType* type, Architecture* arch, Function* func, HighLevelILFunction* highLevelIL)
{
	BNCustomLanguageRepresentationFunction callbacks;
	callbacks.context = this;
	callbacks.freeObject = FreeCallback;
	callbacks.externalRefTaken = nullptr;
	callbacks.externalRefReleased = nullptr;
	callbacks.initTokenEmitter = InitTokenEmitterCallback;
	callbacks.getExprText = GetExprTextCallback;
	callbacks.beginLines = BeginLinesCallback;
	callbacks.endLines = EndLinesCallback;
	callbacks.getCommentStartString = GetCommentStartStringCallback;
	callbacks.getCommentEndString = GetCommentEndStringCallback;
	callbacks.getAnnotationStartString = GetAnnotationStartStringCallback;
	callbacks.getAnnotationEndString = GetAnnotationEndStringCallback;
	AddRefForRegistration();
	m_object = BNCreateCustomLanguageRepresentationFunction(
		type->GetObject(), arch->GetObject(), func->GetObject(), highLevelIL->GetObject(), &callbacks);
}


LanguageRepresentationFunction::LanguageRepresentationFunction(BNLanguageRepresentationFunction* func)
{
	m_object = func;
}


vector<DisassemblyTextLine> LanguageRepresentationFunction::GetExprText(
	const HighLevelILInstruction& instr, DisassemblySettings* settings, BNOperatorPrecedence precedence, bool statement)
{
	size_t count = 0;
	BNDisassemblyTextLine* lines = BNGetLanguageRepresentationFunctionExprText(m_object, instr.function->GetObject(),
		instr.exprIndex, settings ? settings->GetObject() : nullptr, instr.ast, precedence, statement, &count);

	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.instrIndex = lines[i].instrIndex;
		line.highlight = lines[i].highlight;
		line.tokens = InstructionTextToken::ConvertInstructionTextTokenList(lines[i].tokens, lines[i].count);
		line.tags = Tag::ConvertTagList(lines[i].tags, lines[i].tagCount);
		result.push_back(line);
	}

	BNFreeDisassemblyTextLines(lines, count);
	return result;
}


vector<DisassemblyTextLine> LanguageRepresentationFunction::GetLinearLines(
	const HighLevelILInstruction& instr, DisassemblySettings* settings)
{
	size_t count = 0;
	BNDisassemblyTextLine* lines = BNGetLanguageRepresentationFunctionLinearLines(m_object, instr.function->GetObject(),
		instr.exprIndex, settings ? settings->GetObject() : nullptr, instr.ast, &count);

	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.instrIndex = lines[i].instrIndex;
		line.highlight = lines[i].highlight;
		line.tokens = InstructionTextToken::ConvertInstructionTextTokenList(lines[i].tokens, lines[i].count);
		line.tags = Tag::ConvertTagList(lines[i].tags, lines[i].tagCount);
		result.push_back(line);
	}

	BNFreeDisassemblyTextLines(lines, count);
	return result;
}


vector<DisassemblyTextLine> LanguageRepresentationFunction::GetBlockLines(
	BasicBlock* block, DisassemblySettings* settings)
{
	size_t count = 0;
	BNDisassemblyTextLine* lines = BNGetLanguageRepresentationFunctionBlockLines(
		m_object, block->GetObject(), settings ? settings->GetObject() : nullptr, &count);

	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.instrIndex = lines[i].instrIndex;
		line.highlight = lines[i].highlight;
		line.tokens = InstructionTextToken::ConvertInstructionTextTokenList(lines[i].tokens, lines[i].count);
		line.tags = Tag::ConvertTagList(lines[i].tags, lines[i].tagCount);
		result.push_back(line);
	}

	BNFreeDisassemblyTextLines(lines, count);
	return result;
}


BNHighlightColor LanguageRepresentationFunction::GetHighlight(BasicBlock* block)
{
	return BNGetLanguageRepresentationFunctionHighlight(m_object, block->GetObject());
}


Ref<LanguageRepresentationFunctionType> LanguageRepresentationFunction::GetLanguage() const
{
	return new CoreLanguageRepresentationFunctionType(BNGetLanguageRepresentationType(m_object));
}


Ref<Architecture> LanguageRepresentationFunction::GetArchitecture() const
{
	return new CoreArchitecture(BNGetLanguageRepresentationArchitecture(m_object));
}


Ref<Function> LanguageRepresentationFunction::GetFunction() const
{
	return new Function(BNGetLanguageRepresentationOwnerFunction(m_object));
}


Ref<HighLevelILFunction> LanguageRepresentationFunction::GetHighLevelILFunction() const
{
	return new HighLevelILFunction(BNGetLanguageRepresentationILFunction(m_object));
}


void LanguageRepresentationFunction::InitTokenEmitter(HighLevelILTokenEmitter&)
{
}


void LanguageRepresentationFunction::BeginLines(const HighLevelILInstruction&, HighLevelILTokenEmitter&)
{
}


void LanguageRepresentationFunction::EndLines(const HighLevelILInstruction&, HighLevelILTokenEmitter&)
{
}


void LanguageRepresentationFunction::FreeCallback(void* ctxt)
{
	LanguageRepresentationFunction* func = (LanguageRepresentationFunction*)ctxt;
	func->ReleaseForRegistration();
}


void LanguageRepresentationFunction::InitTokenEmitterCallback(void* ctxt, BNHighLevelILTokenEmitter* tokens)
{
	LanguageRepresentationFunction* func = (LanguageRepresentationFunction*)ctxt;
	Ref<HighLevelILTokenEmitter> tokenObj = new HighLevelILTokenEmitter(BNNewHighLevelILTokenEmitterReference(tokens));
	func->InitTokenEmitter(*tokenObj);
}


void LanguageRepresentationFunction::GetExprTextCallback(void* ctxt, BNHighLevelILFunction* il, size_t exprIndex,
	BNHighLevelILTokenEmitter* tokens, BNDisassemblySettings* settings, bool asFullAst,
	BNOperatorPrecedence precedence, bool statement)
{
	LanguageRepresentationFunction* func = (LanguageRepresentationFunction*)ctxt;
	Ref<HighLevelILFunction> ilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(il));
	HighLevelILInstruction instr = ilObj->GetExpr(exprIndex, asFullAst);
	Ref<HighLevelILTokenEmitter> tokenObj = new HighLevelILTokenEmitter(BNNewHighLevelILTokenEmitterReference(tokens));
	Ref<DisassemblySettings> settingsObj = settings ? new DisassemblySettings(BNNewDisassemblySettingsReference(settings)) : nullptr;
	func->GetExprText(instr, *tokenObj, settingsObj, precedence, statement);
}


void LanguageRepresentationFunction::BeginLinesCallback(void* ctxt, BNHighLevelILFunction* il, size_t exprIndex,
	BNHighLevelILTokenEmitter* tokens)
{
	LanguageRepresentationFunction* func = (LanguageRepresentationFunction*)ctxt;
	Ref<HighLevelILFunction> ilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(il));
	HighLevelILInstruction instr = ilObj->GetExpr(exprIndex);
	Ref<HighLevelILTokenEmitter> tokenObj = new HighLevelILTokenEmitter(BNNewHighLevelILTokenEmitterReference(tokens));
	func->BeginLines(instr, *tokenObj);
}


void LanguageRepresentationFunction::EndLinesCallback(void* ctxt, BNHighLevelILFunction* il, size_t exprIndex,
	BNHighLevelILTokenEmitter* tokens)
{
	LanguageRepresentationFunction* func = (LanguageRepresentationFunction*)ctxt;
	Ref<HighLevelILFunction> ilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(il));
	HighLevelILInstruction instr = ilObj->GetExpr(exprIndex);
	Ref<HighLevelILTokenEmitter> tokenObj = new HighLevelILTokenEmitter(BNNewHighLevelILTokenEmitterReference(tokens));
	func->EndLines(instr, *tokenObj);
}


char* LanguageRepresentationFunction::GetCommentStartStringCallback(void* ctxt)
{
	LanguageRepresentationFunction* func = (LanguageRepresentationFunction*)ctxt;
	return BNAllocString(func->GetCommentStartString().c_str());
}


char* LanguageRepresentationFunction::GetCommentEndStringCallback(void* ctxt)
{
	LanguageRepresentationFunction* func = (LanguageRepresentationFunction*)ctxt;
	return BNAllocString(func->GetCommentEndString().c_str());
}


char* LanguageRepresentationFunction::GetAnnotationStartStringCallback(void* ctxt)
{
	LanguageRepresentationFunction* func = (LanguageRepresentationFunction*)ctxt;
	return BNAllocString(func->GetAnnotationStartString().c_str());
}


char* LanguageRepresentationFunction::GetAnnotationEndStringCallback(void* ctxt)
{
	LanguageRepresentationFunction* func = (LanguageRepresentationFunction*)ctxt;
	return BNAllocString(func->GetAnnotationEndString().c_str());
}


CoreLanguageRepresentationFunction::CoreLanguageRepresentationFunction(BNLanguageRepresentationFunction* func):
    LanguageRepresentationFunction(func)
{
}


void CoreLanguageRepresentationFunction::GetExprText(
	const HighLevelILInstruction&, HighLevelILTokenEmitter&, DisassemblySettings*, BNOperatorPrecedence, bool)
{
}


string CoreLanguageRepresentationFunction::GetCommentStartString() const
{
	char* result = BNGetLanguageRepresentationFunctionCommentStartString(m_object);
	string resultStr(result);
	BNFreeString(result);
	return resultStr;
}


string CoreLanguageRepresentationFunction::GetCommentEndString() const
{
	char* result = BNGetLanguageRepresentationFunctionCommentEndString(m_object);
	string resultStr(result);
	BNFreeString(result);
	return resultStr;
}


string CoreLanguageRepresentationFunction::GetAnnotationStartString() const
{
	char* result = BNGetLanguageRepresentationFunctionAnnotationStartString(m_object);
	string resultStr(result);
	BNFreeString(result);
	return resultStr;
}


string CoreLanguageRepresentationFunction::GetAnnotationEndString() const
{
	char* result = BNGetLanguageRepresentationFunctionAnnotationEndString(m_object);
	string resultStr(result);
	BNFreeString(result);
	return resultStr;
}


LanguageRepresentationFunctionType::LanguageRepresentationFunctionType(const std::string& name): m_nameForRegister(name)
{
	m_object = nullptr;
}


LanguageRepresentationFunctionType::LanguageRepresentationFunctionType(BNLanguageRepresentationFunctionType* type)
{
	m_object = type;
}


string LanguageRepresentationFunctionType::GetName() const
{
	char* name = BNGetLanguageRepresentationFunctionTypeName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


bool LanguageRepresentationFunctionType::IsValid(BinaryView*)
{
	return true;
}


vector<DisassemblyTextLine> LanguageRepresentationFunctionType::GetFunctionTypeTokens(Function*, DisassemblySettings*)
{
	return {};
}


void LanguageRepresentationFunctionType::Register(LanguageRepresentationFunctionType* type)
{
	BNCustomLanguageRepresentationFunctionType callbacks;
	callbacks.context = type;
	callbacks.create = CreateCallback;
	callbacks.isValid = IsValidCallback;
	callbacks.getTypePrinter = GetTypePrinterCallback;
	callbacks.getTypeParser = GetTypeParserCallback;
	callbacks.getLineFormatter = GetLineFormatterCallback;
	callbacks.getFunctionTypeTokens = GetFunctionTypeTokensCallback;
	callbacks.freeLines = FreeLinesCallback;

	type->AddRefForRegistration();
	type->m_object =
		BNRegisterLanguageRepresentationFunctionType(type->m_nameForRegister.c_str(), &callbacks);
}


BNLanguageRepresentationFunction* LanguageRepresentationFunctionType::CreateCallback(
	void* ctxt, BNArchitecture* arch, BNFunction* owner, BNHighLevelILFunction* highLevelIL)
{
	LanguageRepresentationFunctionType* type = (LanguageRepresentationFunctionType*)ctxt;
	Ref<Architecture> archObj = new CoreArchitecture(arch);
	Ref<Function> ownerObj = new Function(BNNewFunctionReference(owner));
	Ref<HighLevelILFunction> il = new HighLevelILFunction(BNNewHighLevelILFunctionReference(highLevelIL));
	Ref<LanguageRepresentationFunction> result = type->Create(archObj, ownerObj, il);
	if (!result)
		return nullptr;
	return BNNewLanguageRepresentationFunctionReference(result->GetObject());
}


bool LanguageRepresentationFunctionType::IsValidCallback(void* ctxt, BNBinaryView* view)
{
	LanguageRepresentationFunctionType* type = (LanguageRepresentationFunctionType*)ctxt;
	Ref<BinaryView> viewObj = new BinaryView(BNNewViewReference(view));
	return type->IsValid(viewObj);
}


BNTypePrinter* LanguageRepresentationFunctionType::GetTypePrinterCallback(void* ctxt)
{
	LanguageRepresentationFunctionType* type = (LanguageRepresentationFunctionType*)ctxt;
	Ref<TypePrinter> result = type->GetTypePrinter();
	if (!result)
		return nullptr;
	return result->GetObject();
}


BNTypeParser* LanguageRepresentationFunctionType::GetTypeParserCallback(void* ctxt)
{
	LanguageRepresentationFunctionType* type = (LanguageRepresentationFunctionType*)ctxt;
    Ref<TypeParser> result = type->GetTypeParser();
    if (!result)
        return nullptr;
    return result->GetObject();
}


BNLineFormatter* LanguageRepresentationFunctionType::GetLineFormatterCallback(void* ctxt)
{
	LanguageRepresentationFunctionType* type = (LanguageRepresentationFunctionType*)ctxt;
	Ref<LineFormatter> result = type->GetLineFormatter();
	if (!result)
		return nullptr;
	return result->GetObject();
}


BNDisassemblyTextLine* LanguageRepresentationFunctionType::GetFunctionTypeTokensCallback(
	void* ctxt, BNFunction* func, BNDisassemblySettings* settings, size_t* count)
{
	LanguageRepresentationFunctionType* type = (LanguageRepresentationFunctionType*)ctxt;
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	Ref<DisassemblySettings> settingsObj = settings ? new DisassemblySettings(BNNewDisassemblySettingsReference(settings)) : nullptr;
	auto lines = type->GetFunctionTypeTokens(funcObj, settingsObj);
	*count = lines.size();
	BNDisassemblyTextLine* buf = new BNDisassemblyTextLine[lines.size()];
	for (size_t i = 0; i < lines.size(); i++)
	{
		const DisassemblyTextLine& line = lines[i];
		buf[i].addr = line.addr;
		buf[i].instrIndex = line.instrIndex;
		buf[i].highlight = line.highlight;
		buf[i].tokens = InstructionTextToken::CreateInstructionTextTokenList(line.tokens);
		buf[i].count = line.tokens.size();
		buf[i].tags = Tag::CreateTagList(line.tags, &(buf[i].tagCount));
	}

	return buf;
}


void LanguageRepresentationFunctionType::FreeLinesCallback(void*, BNDisassemblyTextLine* lines, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		InstructionTextToken::FreeInstructionTextTokenList(lines[i].tokens, lines[i].count);
		Tag::FreeTagList(lines[i].tags, lines[i].tagCount);
	}
	delete[] lines;
}


Ref<LanguageRepresentationFunctionType> LanguageRepresentationFunctionType::GetByName(const std::string& name)
{
	BNLanguageRepresentationFunctionType* type = BNGetLanguageRepresentationFunctionTypeByName(name.c_str());
	if (!type)
		return nullptr;
    return new CoreLanguageRepresentationFunctionType(type);
}


bool LanguageRepresentationFunctionType::IsValidByName(const std::string& name, BinaryView* view)
{
	Ref<LanguageRepresentationFunctionType> type = GetByName(name);
	if (!type)
		return false;
	return type->IsValid(view);
}


vector<Ref<LanguageRepresentationFunctionType>> LanguageRepresentationFunctionType::GetTypes()
{
	size_t count = 0;
    BNLanguageRepresentationFunctionType** types = BNGetLanguageRepresentationFunctionTypeList(&count);

    vector<Ref<LanguageRepresentationFunctionType>> result;
    result.reserve(count);
    for (size_t i = 0; i < count; i++)
        result.push_back(new CoreLanguageRepresentationFunctionType(types[i]));

    BNFreeLanguageRepresentationFunctionTypeList(types);
    return result;
}


CoreLanguageRepresentationFunctionType::CoreLanguageRepresentationFunctionType(BNLanguageRepresentationFunctionType* type):
    LanguageRepresentationFunctionType(type)
{
}


Ref<LanguageRepresentationFunction> CoreLanguageRepresentationFunctionType::Create(
	Architecture* arch, Function* owner, HighLevelILFunction* highLevelIL)
{
	BNLanguageRepresentationFunction* func = BNCreateLanguageRepresentationFunction(
		m_object, arch->GetObject(), owner->GetObject(), highLevelIL->GetObject());
	if (!func)
		return nullptr;
	return new CoreLanguageRepresentationFunction(func);
}


bool CoreLanguageRepresentationFunctionType::IsValid(BinaryView* view)
{
	return BNIsLanguageRepresentationFunctionTypeValid(m_object, view->GetObject());
}


Ref<TypePrinter> CoreLanguageRepresentationFunctionType::GetTypePrinter()
{
	BNTypePrinter* printer = BNGetLanguageRepresentationFunctionTypePrinter(m_object);
	if (!printer)
		return nullptr;
    return new CoreTypePrinter(printer);
}


Ref<TypeParser> CoreLanguageRepresentationFunctionType::GetTypeParser()
{
	BNTypeParser* parser = BNGetLanguageRepresentationFunctionTypeParser(m_object);
    if (!parser)
        return nullptr;
    return new CoreTypeParser(parser);
}


Ref<LineFormatter> CoreLanguageRepresentationFunctionType::GetLineFormatter()
{
	BNLineFormatter* formatter = BNGetLanguageRepresentationFunctionTypeLineFormatter(m_object);
	if (!formatter)
		return nullptr;
	return new CoreLineFormatter(formatter);
}


vector<DisassemblyTextLine> CoreLanguageRepresentationFunctionType::GetFunctionTypeTokens(
	Function* func, DisassemblySettings* settings)
{
	size_t count = 0;
	BNDisassemblyTextLine* lines = BNGetLanguageRepresentationFunctionTypeFunctionTypeTokens(m_object,
		func->GetObject(), settings ? settings->GetObject() : nullptr, &count);

	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.instrIndex = lines[i].instrIndex;
		line.highlight = lines[i].highlight;
		line.tokens = InstructionTextToken::ConvertInstructionTextTokenList(lines[i].tokens, lines[i].count);
		line.tags = Tag::ConvertTagList(lines[i].tags, lines[i].tagCount);
		result.push_back(line);
	}

	BNFreeDisassemblyTextLines(lines, count);
	return result;
}
