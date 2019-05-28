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
	AddRefForRegistration();
	m_object = BNCreateDataRenderer(&renderer);
}


bool DataRenderer::IsStructOfTypeName(Type* type, const QualifiedName& name, vector<Type*>& context)
{
	return (type->GetClass() == StructureTypeClass) &&
		(context.size() > 0) &&
		(context[0]->GetClass() == NamedTypeReferenceClass) &&
		(context[0]->GetNamedTypeReference()->GetName() == name);
}


bool DataRenderer::IsStructOfTypeName(Type* type, const string& name, vector<Type*>& context)
{
	return DataRenderer::IsStructOfTypeName(type, QualifiedName(name), context);
}


bool DataRenderer::IsValidForDataCallback(void* ctxt, BNBinaryView* view, uint64_t addr, BNType* type,
	BNType** typeCtx, size_t ctxCount)
{
	DataRenderer* renderer = (DataRenderer*)ctxt;
	Ref<BinaryView> viewObj = new BinaryView(BNNewViewReference(view));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	vector<Type*> context;
	context.reserve(ctxCount);
	for (size_t i = 0; i < ctxCount; i++)
		context.push_back(new Type(BNNewTypeReference(typeCtx[i])));

	return renderer->IsValidForData(viewObj, addr, typeObj, context);
}


BNDisassemblyTextLine* DataRenderer::GetLinesForDataCallback(void* ctxt, BNBinaryView* view, uint64_t addr, BNType* type,
	const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count, BNType** typeCtx,
	size_t ctxCount)
{
	DataRenderer* renderer = (DataRenderer*)ctxt;
	Ref<BinaryView> viewObj = new BinaryView(BNNewViewReference(view));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	vector<InstructionTextToken> prefixes = InstructionTextToken::ConvertInstructionTextTokenList(prefix, prefixCount);

	vector<Type*> context;
	context.reserve(ctxCount);
	for (size_t i = 0; i < ctxCount; i++)
		context.push_back(new Type(BNNewTypeReference(typeCtx[i])));
	auto lines = renderer->GetLinesForData(viewObj, addr, typeObj, prefixes, width, context);
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


void DataRenderer::FreeCallback(void* ctxt)
{
	DataRenderer* renderer = (DataRenderer*)ctxt;
	renderer->ReleaseForRegistration();
}


bool DataRenderer::IsValidForData(BinaryView* data, uint64_t addr, Type* type, vector<Type*>& context)
{
	BNType** typeCtx = new BNType*[context.size()];
	for (size_t i = 0; i < context.size(); i++)
		typeCtx[i] = context[i]->GetObject();
	bool result = BNIsValidForData(m_object, data->GetObject(), addr, type->GetObject(), typeCtx, context.size());
	delete[] typeCtx;
	return result;
}


vector<DisassemblyTextLine> DataRenderer::GetLinesForData(BinaryView* data, uint64_t addr, Type* type,
	const std::vector<InstructionTextToken>& prefix, size_t width, vector<Type*>& context)
{
	BNInstructionTextToken* prefixes = InstructionTextToken::CreateInstructionTextTokenList(prefix);
	BNType** typeCtx = new BNType*[context.size()];
	for (size_t i = 0; i < context.size(); i++)
		typeCtx[i] = context[i]->GetObject();

	size_t count = 0;
	BNDisassemblyTextLine* lines = BNGetLinesForData(m_object, data->GetObject(), addr, type->GetObject(), prefixes,
		prefix.size(), width, &count, typeCtx, context.size());

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
