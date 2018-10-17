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
	vector<InstructionTextToken> prefixes;
	prefixes.reserve(prefixCount);
	for (size_t i = 0; i < prefixCount; i++)
	{
		prefixes.emplace_back(prefix[i].type, prefix[i].context, prefix[i].text, prefix[i].address,
			prefix[i].value, prefix[i].size, prefix[i].operand, prefix[i].confidence);
	}
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
		buf[i].tokens = new BNInstructionTextToken[line.tokens.size()];
		buf[i].count = line.tokens.size();
		for (size_t j = 0; j < line.tokens.size(); j++)
		{
			const InstructionTextToken& token = line.tokens[j];
			buf[i].tokens[j].type = token.type;
			buf[i].tokens[j].text = BNAllocString(token.text.c_str());
			buf[i].tokens[j].value = token.value;
			buf[i].tokens[j].size = token.size;
			buf[i].tokens[j].operand = token.operand;
			buf[i].tokens[j].context = token.context;
			buf[i].tokens[j].confidence = token.confidence;
			buf[i].tokens[j].address = token.address;
		}
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
	BNInstructionTextToken* prefixes = new BNInstructionTextToken[prefix.size()];
	for (size_t i = 0; i < prefix.size(); i++)
	{
		prefixes[i].type = prefix[i].type;
		prefixes[i].text = BNAllocString(prefix[i].text.c_str());
		prefixes[i].value = prefix[i].value;
		prefixes[i].size = prefix[i].size;
		prefixes[i].operand = prefix[i].operand;
		prefixes[i].context = prefix[i].context;
		prefixes[i].confidence = prefix[i].confidence;
		prefixes[i].address = prefix[i].address;
	}
	BNType** typeCtx = new BNType*[context.size()];
	for (size_t i = 0; i < context.size(); i++)
		typeCtx[i] = context[i]->GetObject();

	size_t count = 0;
	BNDisassemblyTextLine* lines = BNGetLinesForData(m_object, data->GetObject(), addr, type->GetObject(), prefixes,
		prefix.size(), width, &count, typeCtx, context.size());

	delete[] typeCtx;
	for (size_t i = 0; i < prefix.size(); i++)
		BNFreeString(prefixes[i].text);

	delete[] prefixes;
	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.instrIndex = lines[i].instrIndex;
		line.highlight = lines[i].highlight;
		line.tokens.reserve(lines[i].count);
		for (size_t j = 0; j < lines[i].count; j++)
		{
			InstructionTextToken token;
			token.type = lines[i].tokens[j].type;
			token.text = lines[i].tokens[j].text;
			token.value = lines[i].tokens[j].value;
			token.size = lines[i].tokens[j].size;
			token.operand = lines[i].tokens[j].operand;
			token.context = lines[i].tokens[j].context;
			token.confidence = lines[i].tokens[j].confidence;
			token.address = lines[i].tokens[j].address;
			line.tokens.push_back(token);
		}
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