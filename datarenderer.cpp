#include "binaryninjaapi.h"

using namespace std;
using namespace BinaryNinja;


DataRenderer::DataRenderer(BNDataRenderer* renderer)
{
	m_object = renderer;
}


DataRenderer::DataRenderer()
{
	BNCustomDataRenderer renderer;
	renderer.context = this;
	renderer.freeObject = FreeCallback;
	renderer.isValidForData = IsValidForDataCallback;
	renderer.getLinesForData = GetLinesForDataCallback;
	renderer.freeLines = FreeLinesCallback;
	AddRefForRegistration();
	m_object = BNCreateDataRenderer(&renderer);
}


bool DataRenderer::IsStructOfTypeName(Type* type, const QualifiedName& name, vector<pair<Type*, size_t>>& context)
{
	return (type->GetClass() == StructureTypeClass) && (context.size() > 0)
	       && (context[context.size() - 1].first->GetClass() == NamedTypeReferenceClass)
	       && (context[context.size() - 1].first->GetNamedTypeReference()->GetName() == name);
}


bool DataRenderer::IsStructOfTypeName(Type* type, const string& name, vector<pair<Type*, size_t>>& context)
{
	return DataRenderer::IsStructOfTypeName(type, QualifiedName(name), context);
}


bool DataRenderer::IsValidForDataCallback(
    void* ctxt, BNBinaryView* view, uint64_t addr, BNType* type, BNTypeContext* typeCtx, size_t ctxCount)
{
	CallbackRef<DataRenderer> renderer(ctxt);
	Ref<BinaryView> viewObj = new BinaryView(BNNewViewReference(view));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	vector<pair<Type*, size_t>> context;
	context.reserve(ctxCount);
	for (size_t i = 0; i < ctxCount; i++)
	{
		// To keep API compatibility we have to manually do the refcounting here
		Type* contextType = new Type(BNNewTypeReference(typeCtx[i].type));
		contextType->AddRef();
		context.push_back({contextType, typeCtx[i].offset});
	}

	bool result = renderer->IsValidForData(viewObj, addr, typeObj, context);

	for (size_t i = 0; i < ctxCount; i++)
		context[i].first->Release();

	return result;
}


BNDisassemblyTextLine* DataRenderer::GetLinesForDataCallback(void* ctxt, BNBinaryView* view, uint64_t addr,
    BNType* type, const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count,
    BNTypeContext* typeCtx, size_t ctxCount, const char* language)
{
	CallbackRef<DataRenderer> renderer(ctxt);
	Ref<BinaryView> viewObj = new BinaryView(BNNewViewReference(view));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	vector<InstructionTextToken> prefixes = InstructionTextToken::ConvertInstructionTextTokenList(prefix, prefixCount);

	vector<pair<Type*, size_t>> context;
	context.reserve(ctxCount);
	for (size_t i = 0; i < ctxCount; i++)
	{
		// To keep API compatibility we have to manually do the refcounting here
		Type* contextType = new Type(BNNewTypeReference(typeCtx[i].type));
		contextType->AddRef();
		context.push_back({contextType, typeCtx[i].offset});
	}
	auto lines = renderer->GetLinesForData(viewObj, addr, typeObj, prefixes, width, context,
		language ? language : string());
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

	for (size_t i = 0; i < ctxCount; i++)
		context[i].first->Release();
	return buf;
}


void DataRenderer::FreeCallback(void* ctxt)
{
	DataRenderer* renderer = (DataRenderer*)ctxt;
	renderer->ReleaseForRegistration();
}


void DataRenderer::FreeLinesCallback(void* ctxt, BNDisassemblyTextLine* lines, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		InstructionTextToken::FreeInstructionTextTokenList(lines[i].tokens, lines[i].count);
		Tag::FreeTagList(lines[i].tags, lines[i].tagCount);
	}
	delete[] lines;
}


bool DataRenderer::IsValidForData(BinaryView* data, uint64_t addr, Type* type, vector<pair<Type*, size_t>>& context)
{
	BNTypeContext* typeCtx = new BNTypeContext[context.size()];
	for (size_t i = 0; i < context.size(); i++)
	{
		typeCtx[i].type = context[i].first->GetObject();
		typeCtx[i].offset = context[i].second;
	}
	bool result = BNIsValidForData(m_object, data->GetObject(), addr, type->GetObject(), typeCtx, context.size());
	delete[] typeCtx;
	return result;
}


vector<DisassemblyTextLine> DataRenderer::GetLinesForData(BinaryView* data, uint64_t addr, Type* type,
    const std::vector<InstructionTextToken>& prefix, size_t width, vector<pair<Type*, size_t>>& context, const string& language)
{
	BNInstructionTextToken* prefixes = InstructionTextToken::CreateInstructionTextTokenList(prefix);
	BNTypeContext* typeCtx = new BNTypeContext[context.size()];
	for (size_t i = 0; i < context.size(); i++)
	{
		typeCtx[i].type = context[i].first->GetObject();
		typeCtx[i].offset = context[i].second;
	}
	size_t count = 0;
	BNDisassemblyTextLine* lines = BNGetLinesForData(m_object, data->GetObject(), addr, type->GetObject(), prefixes,
	    prefix.size(), width, &count, typeCtx, context.size(), language.c_str());

	delete[] typeCtx;
	for (size_t i = 0; i < prefix.size(); i++)
	{
		BNFreeString(prefixes[i].text);
		for (size_t j = 0; j < prefixes[j].namesCount; j++)
			BNFreeString(prefixes[i].typeNames[j]);
		delete[] prefixes[i].typeNames;
	}
	delete[] prefixes;

	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.instrIndex = lines[i].instrIndex;
		line.highlight = lines[i].highlight;
		line.tokens = InstructionTextToken::ConvertAndFreeInstructionTextTokenList(lines[i].tokens, lines[i].count);
		line.tags = Tag::ConvertAndFreeTagList(lines[i].tags, lines[i].tagCount);
		result.push_back(line);
	}
	BNFreeDisassemblyTextLines(lines, count);
	return result;
}


vector<DisassemblyTextLine> DataRenderer::RenderLinesForData(BinaryView* data, uint64_t addr, Type* type,
    const std::vector<InstructionTextToken>& prefix, size_t width, vector<pair<Type*, size_t>>& context, const string& language)
{
	BNInstructionTextToken* prefixes = InstructionTextToken::CreateInstructionTextTokenList(prefix);
	BNTypeContext* typeCtx = new BNTypeContext[context.size()];
	for (size_t i = 0; i < context.size(); i++)
	{
		typeCtx[i].type = context[i].first->GetObject();
		typeCtx[i].offset = context[i].second;
	}
	size_t count = 0;
	BNDisassemblyTextLine* lines = BNRenderLinesForData(
	    data->GetObject(), addr, type->GetObject(), prefixes, prefix.size(), width, &count, typeCtx, context.size(),
	    language.c_str());

	delete[] typeCtx;
	for (size_t i = 0; i < prefix.size(); i++)
	{
		BNFreeString(prefixes[i].text);
		for (size_t j = 0; j < prefixes[j].namesCount; j++)
			BNFreeString(prefixes[i].typeNames[j]);
		delete[] prefixes[i].typeNames;
	}
	delete[] prefixes;

	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.instrIndex = lines[i].instrIndex;
		line.highlight = lines[i].highlight;
		line.tokens = InstructionTextToken::ConvertAndFreeInstructionTextTokenList(lines[i].tokens, lines[i].count);
		line.tags = Tag::ConvertAndFreeTagList(lines[i].tags, lines[i].tagCount);
		result.push_back(line);
	}

	BNFreeDisassemblyTextLines(lines, count);
	return result;
}


void DataRendererContainer::RegisterGenericDataRenderer(DataRenderer* renderer)
{
	BNRegisterGenericDataRenderer(BNGetDataRendererContainer(), renderer->GetObject());
}


void DataRendererContainer::RegisterTypeSpecificDataRenderer(DataRenderer* renderer)
{
	BNRegisterTypeSpecificDataRenderer(BNGetDataRendererContainer(), renderer->GetObject());
}
