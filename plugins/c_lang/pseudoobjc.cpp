#include "pseudoobjc.h"

#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"
#include "objctypes.h"
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace BinaryNinja;

namespace {

bool ParameterIsString(const HighLevelILInstruction& expr)
{
	if (expr.operation != HLIL_CONST_PTR)
		return false;

	auto exprType = expr.GetType();
	if (!exprType || exprType->GetClass() != PointerTypeClass)
		return false;

	if (auto child = exprType->GetChildType(); child.GetValue())
	{
		child = child->IsArray() ? child->GetChildType() : child;
		return child->IsInteger() && child->IsSigned() && child->GetWidth() == 1;
	}
	return false;
}

struct SelectorReference
{
	std::string name;
	uint64_t address;
};

std::optional<SelectorReference> GetSelectorFromParameter(
	const HighLevelILInstruction& expr, const Function& function)
{
	if (expr.operation != HLIL_CONST_PTR)
		return std::nullopt;

	if (!ParameterIsString(expr))
		return std::nullopt;

	uint64_t constant = expr.GetConstant<HLIL_CONST_PTR>();
	std::string string;
	auto stringType = function.GetView()->CheckForStringAnnotationType(constant, string, true, true, 1);

	if (!stringType || (stringType != AsciiString && stringType != Utf8String))
		return std::nullopt;

	return SelectorReference {string, constant};
}

void SplitSelector(const std::string& selector, std::vector<std::string>& tokens)
{
	std::stringstream ss(selector);
	std::string token;
	while (std::getline(ss, token, ':'))
		tokens.push_back(token);
}

std::optional<std::pair<uint64_t, Ref<Symbol>>> GetCallTargetInfo(const HighLevelILInstruction& callTarget,
	const std::vector<HighLevelILInstruction>& parameterExprs, const Function& function)
{
	uint64_t constant = 0;
	Ref<Symbol> symbol;

	switch (callTarget.operation)
	{
	case HLIL_CONST_PTR:
	{
		constant = callTarget.GetConstant<HLIL_CONST_PTR>();
		symbol = function.GetView()->GetSymbolByAddress(constant);
		break;
	}
	case HLIL_IMPORT:
	{
		constant = callTarget.GetConstant<HLIL_IMPORT>();
		auto importAddressSymbol = function.GetView()->GetSymbolByAddress(constant);
		if (!importAddressSymbol)
			return std::nullopt;

		const auto symbolType = importAddressSymbol->GetType();
		if (symbolType != ImportedDataSymbol && symbolType != ImportAddressSymbol)
			return std::nullopt;

		symbol = Symbol::ImportedFunctionFromImportAddressSymbol(importAddressSymbol, constant);
	}
	default:
		break;
	}

	if (!symbol)
		return std::nullopt;

	return std::make_pair(constant, symbol);
}

Ref<Type> TypeResolvingNamedTypeReference(Ref<Type> type, const Function& function)
{
	if (!type || !type->IsNamedTypeRefer())
		return type;

	if (auto resolvedType = function.GetView()->GetTypeByRef(type->GetNamedTypeReference()))
		return resolvedType;

	return type;
}

struct RuntimeCall
{
	enum Type
	{
		MessageSend,
		MessageSendSuper,
		Alloc,
		AllocInit,
		New,
		Retain,
		Release,
		Autorelease,
		RetainAutorelease,
		Class,
		Self,
		RespondsToSelector,
		IsKindOfClass
	};

	Type type;
	uint64_t address;
	bool isRewritten = false;
};

constexpr std::array RUNTIME_CALLS = {
	std::make_pair("_objc_alloc_init", RuntimeCall::AllocInit),
	std::make_pair("_objc_alloc", RuntimeCall::Alloc),
	std::make_pair("_objc_autorelease", RuntimeCall::Autorelease),
	std::make_pair("_objc_autoreleaseReturnValue", RuntimeCall::Autorelease),
	std::make_pair("_objc_msgSend", RuntimeCall::MessageSend),
	std::make_pair("_objc_msgSendSuper", RuntimeCall::MessageSendSuper),
	std::make_pair("_objc_msgSendSuper2", RuntimeCall::MessageSendSuper),
	std::make_pair("_objc_opt_class", RuntimeCall::Class),
	std::make_pair("_objc_opt_new", RuntimeCall::New),
	std::make_pair("_objc_opt_self", RuntimeCall::Self),
	std::make_pair("_objc_opt_respondsToSelector", RuntimeCall::RespondsToSelector),
	std::make_pair("_objc_opt_isKindOfClass", RuntimeCall::IsKindOfClass),
	std::make_pair("_objc_release", RuntimeCall::Release),
	std::make_pair("_objc_retain", RuntimeCall::Retain),
	std::make_pair("_objc_retainAutoreleasedReturnValue", RuntimeCall::Retain),
	std::make_pair("_objc_retainAutoreleaseReturnValue", RuntimeCall::RetainAutorelease),
	std::make_pair("_objc_retainBlock", RuntimeCall::Retain),
	std::make_pair("j__objc_alloc_init", RuntimeCall::AllocInit),
	std::make_pair("j__objc_alloc", RuntimeCall::Alloc),
	std::make_pair("j__objc_autorelease", RuntimeCall::Autorelease),
	std::make_pair("j__objc_autoreleaseReturnValue", RuntimeCall::Autorelease),
	std::make_pair("j__objc_msgSend", RuntimeCall::MessageSend),
	std::make_pair("j__objc_msgSendSuper", RuntimeCall::MessageSendSuper),
	std::make_pair("j__objc_msgSendSuper2", RuntimeCall::MessageSendSuper),
	std::make_pair("j__objc_opt_class", RuntimeCall::Class),
	std::make_pair("j__objc_opt_new", RuntimeCall::New),
	std::make_pair("j__objc_opt_self", RuntimeCall::Self),
	std::make_pair("j__objc_opt_respondsToSelector", RuntimeCall::RespondsToSelector),
	std::make_pair("j__objc_opt_isKindOfClass", RuntimeCall::IsKindOfClass),
	std::make_pair("j__objc_release", RuntimeCall::Release),
	std::make_pair("j__objc_retain", RuntimeCall::Retain),
	std::make_pair("j__objc_retainAutoreleasedReturnValue", RuntimeCall::Retain),
	std::make_pair("j__objc_retainAutoreleaseReturnValue", RuntimeCall::RetainAutorelease),
	std::make_pair("j__objc_retainBlock", RuntimeCall::Retain),
};

std::optional<RuntimeCall> DetectObjCRuntimeCall(const HighLevelILInstruction& callTarget,
	const std::vector<HighLevelILInstruction>& parameterExprs, const Function& function)
{
	auto callTargetInfo = GetCallTargetInfo(callTarget, parameterExprs, function);
	if (!callTargetInfo)
		return std::nullopt;
	auto [constant, symbol] = callTargetInfo.value();

	const auto symbolShortName = symbol->GetShortName();
	auto it = std::find_if(RUNTIME_CALLS.begin(), RUNTIME_CALLS.end(), [&](const auto& pair) {
		return pair.first == symbolShortName;
	});
	if (it == RUNTIME_CALLS.end())
		return std::nullopt;

	return RuntimeCall {it->second, constant};
}

std::optional<RuntimeCall> DetectRewrittenDirectObjCMethodCall(const HighLevelILInstruction& callTarget,
	const std::vector<HighLevelILInstruction>& parameterExprs, const Function& function)
{
	auto callTargetInfo = GetCallTargetInfo(callTarget, parameterExprs, function);
	if (!callTargetInfo)
		return std::nullopt;
	auto [constant, symbol] = callTargetInfo.value();

	const auto symbolShortName = symbol->GetShortName();
	if (symbolShortName.length() < 6)
		return std::nullopt;

	// Look for the pattern -[ClassName methodName:] or +[ClassName methodName:]
	if ((symbolShortName[0] != '-' && symbolShortName[0] != '+') || symbolShortName[1] != '['
		|| symbolShortName.back() != ']' || symbolShortName.find(' ') == std::string::npos)
		return std::nullopt;

	return RuntimeCall {RuntimeCall::MessageSend, constant, true};
}

bool VariableIsObjCSuperStruct(const Variable& variable, Function& function)
{
	auto variableName = function.GetVariableName(variable);
	if (variableName != "super")
		return false;

	const auto variableType = TypeResolvingNamedTypeReference(function.GetVariableType(variable).GetValue(), function);
	if (!variableType || variableType->GetClass() != StructureTypeClass)
		return false;

	if (variableType->GetStructureName().GetString() != "objc_super")
		return false;

	return true;
}

bool IsAssignmentToObjCSuperStructField(const HighLevelILInstruction& assignInstr, Function& function)
{
	// Check if this is an assignment to a field of the objc_super struct
	// Pattern: HLIL_ASSIGN { dest = HLIL_STRUCT_FIELD { source = HLIL_VAR { super }, }, field = ... }

	if (assignInstr.operation != HLIL_ASSIGN)
		return false;

	const auto destExpr = assignInstr.GetDestExpr();
	if (destExpr.operation != HLIL_STRUCT_FIELD)
		return false;

	const auto sourceExpr = destExpr.GetSourceExpr();
	if (sourceExpr.operation != HLIL_VAR)
		return false;

	auto variable = sourceExpr.GetVariable<HLIL_VAR>();
	return VariableIsObjCSuperStruct(variable, function);
}

}  // unnamed namespace

PseudoObjCFunction::PseudoObjCFunction(LanguageRepresentationFunctionType* type, Architecture* arch, Function* owner,
	HighLevelILFunction* highLevelILFunction) : PseudoCFunction(type, arch, owner, highLevelILFunction)
{}

void PseudoObjCFunction::GetExpr_CALL_OR_TAILCALL(const BinaryNinja::HighLevelILInstruction& instr,
	BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
	BNOperatorPrecedence precedence, bool statement)
{
	const auto destExpr = instr.GetDestExpr();
	const auto parameterExprs = instr.GetParameterExprs();

	auto objCRuntimeCall = DetectObjCRuntimeCall(destExpr, parameterExprs, *GetFunction());
	if (!objCRuntimeCall)
		objCRuntimeCall = DetectRewrittenDirectObjCMethodCall(destExpr, parameterExprs, *GetFunction());

	if (!objCRuntimeCall)
		return PseudoCFunction::GetExpr_CALL_OR_TAILCALL(instr, tokens, settings, precedence, statement);

	std::vector<std::string_view> runtimeCallTokens;
	switch (objCRuntimeCall->type)
	{
	case RuntimeCall::MessageSend:
	case RuntimeCall::MessageSendSuper:
		if (GetExpr_ObjCMsgSend(objCRuntimeCall->address, objCRuntimeCall->type == RuntimeCall::MessageSendSuper,
				objCRuntimeCall->isRewritten, destExpr, tokens, settings, parameterExprs))
		{
			if (statement)
				tokens.AppendSemicolon();
			return;
		}
		break;
	case RuntimeCall::Alloc:
		runtimeCallTokens = {"alloc"};
		break;
	case RuntimeCall::AllocInit:
		runtimeCallTokens = {"alloc", "init"};
		break;
	case RuntimeCall::New:
		runtimeCallTokens = {"new"};
		break;
	case RuntimeCall::Retain:
		runtimeCallTokens = {"retain"};
		break;
	case RuntimeCall::Release:
		runtimeCallTokens = {"release"};
		break;
	case RuntimeCall::Autorelease:
		runtimeCallTokens = {"autorelease"};
		break;
	case RuntimeCall::RetainAutorelease:
		runtimeCallTokens = {"retain", "autorelease"};
		break;
	case RuntimeCall::Class:
		runtimeCallTokens = {"class"};
		break;
	case RuntimeCall::Self:
		runtimeCallTokens = {"self"};
		break;
	case RuntimeCall::RespondsToSelector:
	case RuntimeCall::IsKindOfClass:
		std::string_view selectorToken =
			objCRuntimeCall->type == RuntimeCall::RespondsToSelector ? "respondsToSelector:" : "isKindOfClass:";
		if (GetExpr_TwoParamObjCRuntimeCall(
				objCRuntimeCall->address, instr, tokens, settings, parameterExprs, selectorToken))
		{
			if (statement)
				tokens.AppendSemicolon();
			return;
		}
		break;
	}

	if (runtimeCallTokens.size()
		&& GetExpr_GenericObjCRuntimeCall(
			objCRuntimeCall->address, instr, tokens, settings, parameterExprs, runtimeCallTokens))
	{
		if (statement)
			tokens.AppendSemicolon();
		return;
	}

	return PseudoCFunction::GetExpr_CALL_OR_TAILCALL(instr, tokens, settings, precedence, statement);
}

bool PseudoObjCFunction::GetExpr_ObjCMsgSend(uint64_t msgSendAddress, bool isSuper, bool isRewritten,
	const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens, DisassemblySettings* settings,
	const std::vector<HighLevelILInstruction>& parameterExprs)
{
	if (parameterExprs.size() < 2)
		return false;

	auto maybeSelector = GetSelectorFromParameter(parameterExprs[1], *GetFunction());
	if (!maybeSelector)
		return false;

	auto [selector, selectorAddress] = maybeSelector.value();
	std::vector<std::string> selectorTokens {2};
	SplitSelector(selector, selectorTokens);

	uint64_t referencedAddress = isRewritten ? msgSendAddress : selectorAddress;

	tokens.AppendOpenBracket();

	if (isSuper)
		tokens.Append(LocalVariableToken, "super", instr.address);
	else
		GetExprText(parameterExprs[0], tokens, settings);

	for (size_t index = 2; index < parameterExprs.size(); index++)
	{
		const auto& parameterExpr = parameterExprs[index];
		tokens.Append(TextToken, " ");
		if (index < selectorTokens.size())
		{
			tokens.Append(
				DataSymbolToken, StringReferenceTokenContext, selectorTokens[index], instr.address, referencedAddress);
			tokens.Append(TextToken, ":");
		}
		else
		{
			tokens.Append(TextToken, ", ");
		}
		GetExprText(parameterExpr, tokens, settings);
	}
	if (selectorTokens.size() > parameterExprs.size())
	{
		tokens.Append(TextToken, " ");
		for (size_t index = parameterExprs.size(); index < selectorTokens.size(); index++)
		{
			tokens.Append(
				DataSymbolToken, StringReferenceTokenContext, selectorTokens[index], instr.address, referencedAddress);
			if (index != selectorTokens.size() - 1 || selector.back() == ':')
				tokens.Append(TextToken, ":");
		}
	}
	tokens.AppendCloseBracket();
	return true;
}

bool PseudoObjCFunction::GetExpr_GenericObjCRuntimeCall(uint64_t address, const HighLevelILInstruction& instr,
	HighLevelILTokenEmitter& tokens, DisassemblySettings* settings,
	const std::vector<HighLevelILInstruction>& parameterExprs, const std::vector<std::string_view>& selectorTokens)
{
	if (parameterExprs.size() < 1)
		return false;

	for ([[maybe_unused]] auto _ : selectorTokens)
		tokens.AppendOpenBracket();

	GetExprText(parameterExprs[0], tokens, settings);
	for (auto& token : selectorTokens)
	{
		tokens.Append(TextToken, " ");
		tokens.Append(CodeSymbolToken, StringReferenceTokenContext, std::string(token), instr.address, address);
		tokens.AppendCloseBracket();
	}
	return true;
}

bool PseudoObjCFunction::GetExpr_TwoParamObjCRuntimeCall(uint64_t address, const HighLevelILInstruction& instr,
	HighLevelILTokenEmitter& tokens, DisassemblySettings* settings,
	const std::vector<HighLevelILInstruction>& parameterExprs, std::string_view selectorToken)
{
	if (parameterExprs.size() < 2)
		return false;

	tokens.AppendOpenBracket();

	GetExprText(parameterExprs[0], tokens, settings);
	tokens.Append(TextToken, " ");
	tokens.Append(CodeSymbolToken, StringReferenceTokenContext, std::string(selectorToken), instr.address, address);
	GetExprText(parameterExprs[1], tokens, settings, MemberAndFunctionOperatorPrecedence);
	tokens.AppendCloseBracket();

	return true;
}

void PseudoObjCFunction::GetExpr_CONST_PTR(const BinaryNinja::HighLevelILInstruction& instr,
	BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
	BNOperatorPrecedence precedence, bool statement)
{
	uint64_t constant = instr.GetConstant<HLIL_CONST_PTR>();
	auto symbol = GetFunction()->GetView()->GetSymbolByAddress(constant);
	if (!symbol)
		return PseudoCFunction::GetExpr_CONST_PTR(instr, tokens, settings, precedence, statement);

	auto shortName = symbol->GetShortName();

	// Match class references based only on the symbol name as the class metadata may be imported
	// from a different image.
	if (shortName.rfind("_OBJC_CLASS_$_", 0) == 0 || shortName.rfind("cls_", 0) == 0)
	{
		if (GetExpr_OBJC_CLASS(*symbol, constant, instr, tokens, settings, precedence, statement))
			return;
	}

	if (shortName.rfind("sel_", 0) == 0
		&& GetExpr_Selector(
			std::string_view(shortName).substr(4), constant, instr, tokens, settings, precedence, statement))
		return;

	DataVariable variable {};
	auto hasVariable = GetFunction()->GetView()->GetDataVariableAtAddress(constant, variable);
	if (!hasVariable)
		return PseudoCFunction::GetExpr_CONST_PTR(instr, tokens, settings, precedence, statement);

	auto type = TypeResolvingNamedTypeReference(variable.type.GetValue(), *GetFunction());
	if (!type || type->GetClass() != StructureTypeClass)
		return PseudoCFunction::GetExpr_CONST_PTR(instr, tokens, settings, precedence, statement);

	auto structureName = type->GetStructureName().GetString();
	if (structureName == "__NSConstantString")
	{
		if (GetExpr_NSConstantString(type, constant, instr, tokens, settings, precedence, statement))
			return;
	}

	PseudoCFunction::GetExpr_CONST_PTR(instr, tokens, settings, precedence, statement);
}

bool PseudoObjCFunction::GetExpr_OBJC_CLASS(const Symbol& symbol, uint64_t constant,
	const BinaryNinja::HighLevelILInstruction& instr, BinaryNinja::HighLevelILTokenEmitter& tokens,
	BinaryNinja::DisassemblySettings* settings, BNOperatorPrecedence precedence, bool statement)
{
	auto shortName = symbol.GetShortName();
	std::string className;
	if (shortName.rfind("_OBJC_CLASS_$_", 0) == 0)
		className = shortName.substr(14);
	else if (shortName.rfind("cls_", 0) == 0)
		className = shortName.substr(4);

	if (className.empty())
		return false;

	tokens.Append(DataSymbolToken, ConstDataTokenContext, className, instr.address, constant);
	if (statement)
		tokens.AppendSemicolon();

	return true;
}

bool PseudoObjCFunction::GetExpr_Selector(std::string_view selector, uint64_t constant,
	const BinaryNinja::HighLevelILInstruction& instr, BinaryNinja::HighLevelILTokenEmitter& tokens,
	BinaryNinja::DisassemblySettings* settings, BNOperatorPrecedence precedence, bool statement)
{
	if (selector.empty())
		return false;

	tokens.Append(KeywordToken, "@selector");
	tokens.AppendOpenParen();
	tokens.Append(DataSymbolToken, ConstDataTokenContext, std::string(selector), instr.address, constant);
	tokens.AppendCloseParen();

	return true;
}

bool PseudoObjCFunction::GetExpr_NSConstantString(Ref<Type> type, uint64_t constant,
	const BinaryNinja::HighLevelILInstruction& instr, BinaryNinja::HighLevelILTokenEmitter& tokens,
	BinaryNinja::DisassemblySettings* settings, BNOperatorPrecedence precedence, bool statement)
{
	StructureMember dataMember;
	bool hasDataField = type->GetStructure()->GetMemberByName("data", dataMember);
	if (!hasDataField)
		return false;

	uint64_t dataPointer = 0;
	if (!GetFunction()->GetView()->Read(
			&dataPointer, constant + dataMember.offset, GetFunction()->GetView()->GetAddressSize()))
		return false;

	std::string stringValue;
	if (!GetFunction()->GetView()->CheckForStringAnnotationType(dataPointer, stringValue, true, true, 1))
		return false;

	// TODO: Ideally this'd be part of the same token as the quotes for the string literal.
	// Sometimes the view ends up wrapping between the @ and the quote.
	tokens.Append(TextToken, "@");
	tokens.AppendConstantTextToken(
		instr, dataPointer, GetFunction()->GetView()->GetAddressSize(), settings, MemberAndFunctionOperatorPrecedence);
	if (statement)
		tokens.AppendSemicolon();

	return true;
}

void PseudoObjCFunction::GetExpr_IMPORT(const BinaryNinja::HighLevelILInstruction& instr,
	BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
	BNOperatorPrecedence precedence, bool statement)
{
	const auto constant = instr.GetConstant<HLIL_IMPORT>();
	auto symbol = GetFunction()->GetView()->GetSymbolByAddress(constant);
	const auto symbolType = symbol->GetType();

	if (symbol && (symbolType == ImportedDataSymbol || symbolType == ImportAddressSymbol))
	{
		symbol = Symbol::ImportedFunctionFromImportAddressSymbol(symbol, constant);
		const auto symbolShortName = symbol->GetShortName();
		if (symbolShortName.rfind("_OBJC_CLASS_$_", 0) == 0)
		{
			tokens.Append(IndirectImportToken, ConstDataTokenContext, symbolShortName.substr(14), instr.address,
				constant);
			if (statement)
				tokens.AppendSemicolon();
			return;
		}
		tokens.Append(IndirectImportToken, NoTokenContext, symbolShortName, instr.address, constant, instr.size, instr.sourceOperand);
		return;
	}

	PseudoCFunction::GetExpr_IMPORT(instr, tokens, settings, precedence, statement);
}

bool PseudoObjCFunction::ShouldSkipStatement(const BinaryNinja::HighLevelILInstruction& instr)
{
	// Skip statements that are compiler-generated artifacts of Objective-C runtime calls
	// For now this is limited to the declaration / initialization of the `objc_super` variable
	// used for `objc_msgSendSuper` calls.
	switch (instr.operation)
	{
	case HLIL_VAR_DECLARE:
		if (VariableIsObjCSuperStruct(instr.GetVariable<HLIL_VAR_DECLARE>(), *GetFunction()))
			return true;
		break;
	case HLIL_ASSIGN:
		if (IsAssignmentToObjCSuperStructField(instr, *GetFunction()))
			return true;
		break;
	default:
		break;
	}

	return PseudoCFunction::ShouldSkipStatement(instr);
}


PseudoObjCFunctionType::PseudoObjCFunctionType() : PseudoCFunctionType("Pseudo Objective-C") {}

Ref<LanguageRepresentationFunction> PseudoObjCFunctionType::Create(
	Architecture* arch, Function* owner, HighLevelILFunction* highLevelILFunction)
{
	return new PseudoObjCFunction(this, arch, owner, highLevelILFunction);
}

Ref<TypePrinter> PseudoObjCFunctionType::GetTypePrinter()
{
	return new PseudoObjCTypePrinter();
}
