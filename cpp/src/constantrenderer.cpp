#include "binaryninjaapi.h"
#include "ffi.h"
#include "highlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


ConstantRenderer::ConstantRenderer(const std::string& name): m_nameForRegister(name)
{
	m_object = nullptr;
}


ConstantRenderer::ConstantRenderer(BNConstantRenderer* renderer)
{
	m_object = renderer;
}


string ConstantRenderer::GetName() const
{
	char* name = BNGetConstantRendererName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


bool ConstantRenderer::IsValidForType(HighLevelILFunction*, Type*)
{
	return true;
}


bool ConstantRenderer::RenderConstant(const HighLevelILInstruction&, Type*, int64_t,
	HighLevelILTokenEmitter&, DisassemblySettings*, BNOperatorPrecedence)
{
	return false;
}


bool ConstantRenderer::RenderConstantPointer(const HighLevelILInstruction&, Type*, int64_t,
	HighLevelILTokenEmitter&, DisassemblySettings*, BNSymbolDisplayType, BNOperatorPrecedence)
{
	return false;
}


void ConstantRenderer::Register(ConstantRenderer* renderer)
{
	BNCustomConstantRenderer callbacks;
	callbacks.context = renderer;
	callbacks.isValidForType = IsValidForTypeCallback;
	callbacks.renderConstant = RenderConstantCallback;
	callbacks.renderConstantPointer = RenderConstantPointerCallback;

	renderer->AddRefForRegistration();
	renderer->m_object = BNRegisterConstantRenderer(renderer->m_nameForRegister.c_str(), &callbacks);
}


bool ConstantRenderer::IsValidForTypeCallback(void* ctxt, BNHighLevelILFunction* hlil, BNType* type)
{
	ConstantRenderer* renderer = (ConstantRenderer*)ctxt;
	Ref<HighLevelILFunction> hlilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(hlil));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	return renderer->IsValidForType(hlilObj, typeObj);
}


bool ConstantRenderer::RenderConstantCallback(void* ctxt, BNHighLevelILFunction* hlil, size_t expr, BNType* type,
	int64_t val, BNHighLevelILTokenEmitter* tokens, BNDisassemblySettings* settings,
	BNOperatorPrecedence precedence)
{
	ConstantRenderer* renderer = (ConstantRenderer*)ctxt;
	Ref<HighLevelILFunction> hlilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(hlil));
	HighLevelILInstruction instr = hlilObj->GetExpr(expr);
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	Ref<HighLevelILTokenEmitter> tokenObj = new HighLevelILTokenEmitter(BNNewHighLevelILTokenEmitterReference(tokens));
	Ref<DisassemblySettings> settingsObj = settings ? new DisassemblySettings(BNNewDisassemblySettingsReference(settings)) : nullptr;
	return renderer->RenderConstant(instr, typeObj, val, *tokenObj, settingsObj, precedence);
}


bool ConstantRenderer::RenderConstantPointerCallback(void* ctxt, BNHighLevelILFunction* hlil, size_t expr, BNType* type,
	int64_t val, BNHighLevelILTokenEmitter* tokens, BNDisassemblySettings* settings, BNSymbolDisplayType symbolDisplay,
	BNOperatorPrecedence precedence)
{
	ConstantRenderer* renderer = (ConstantRenderer*)ctxt;
	Ref<HighLevelILFunction> hlilObj = new HighLevelILFunction(BNNewHighLevelILFunctionReference(hlil));
	HighLevelILInstruction instr = hlilObj->GetExpr(expr);
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	Ref<HighLevelILTokenEmitter> tokenObj = new HighLevelILTokenEmitter(BNNewHighLevelILTokenEmitterReference(tokens));
	Ref<DisassemblySettings> settingsObj = settings ? new DisassemblySettings(BNNewDisassemblySettingsReference(settings)) : nullptr;
	return renderer->RenderConstantPointer(instr, typeObj, val, *tokenObj, settingsObj, symbolDisplay, precedence);
}


Ref<ConstantRenderer> ConstantRenderer::GetByName(const std::string& name)
{
	BNConstantRenderer* renderer = BNGetConstantRendererByName(name.c_str());
	if (!renderer)
		return nullptr;
    return new CoreConstantRenderer(renderer);
}


vector<Ref<ConstantRenderer>> ConstantRenderer::GetRenderers()
{
	size_t count = 0;
    BNConstantRenderer** renderers = BNGetConstantRendererList(&count);

    vector<Ref<ConstantRenderer>> result;
    result.reserve(count);
    for (size_t i = 0; i < count; i++)
        result.push_back(new CoreConstantRenderer(renderers[i]));

    BNFreeConstantRendererList(renderers);
    return result;
}


CoreConstantRenderer::CoreConstantRenderer(BNConstantRenderer* renderer):
    ConstantRenderer(renderer)
{
}


bool CoreConstantRenderer::IsValidForType(HighLevelILFunction* func, Type* type)
{
	return BNIsConstantRendererValidForType(m_object, func->GetObject(), type->GetObject());
}


bool CoreConstantRenderer::RenderConstant(const HighLevelILInstruction& instr, Type* type, int64_t val,
	HighLevelILTokenEmitter& tokens, DisassemblySettings* settings, BNOperatorPrecedence precedence)
{
	return BNConstantRendererRenderConstant(m_object, instr.function->GetObject(), instr.exprIndex,
		type->GetObject(), val, tokens.GetObject(), settings ? settings->GetObject() : nullptr, precedence);
}


bool CoreConstantRenderer::RenderConstantPointer(const HighLevelILInstruction& instr, Type* type, int64_t val,
	HighLevelILTokenEmitter& tokens, DisassemblySettings* settings, BNSymbolDisplayType symbolDisplay,
	BNOperatorPrecedence precedence)
{
	return BNConstantRendererRenderConstantPointer(m_object, instr.function->GetObject(), instr.exprIndex,
		type->GetObject(), val, tokens.GetObject(), settings ? settings->GetObject() : nullptr,
		symbolDisplay, precedence);
}
