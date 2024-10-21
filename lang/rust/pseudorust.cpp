#include <inttypes.h>
#include "pseudorust.h"
#include "rusttypes.h"
#include "highlevelilinstruction.h"

using namespace std;
using namespace BinaryNinja;


PseudoRustFunction::PseudoRustFunction(
	Architecture* arch, Function* owner, HighLevelILFunction* highLevelILFunction) :
	LanguageRepresentationFunction(arch, owner, highLevelILFunction), m_highLevelIL(highLevelILFunction)
{
}


void PseudoRustFunction::InitTokenEmitter(HighLevelILTokenEmitter& tokens)
{
	// Braces must always be turned on for Rust
	tokens.SetBraceRequirement(BracesAlwaysRequired);

	// Multiple statements in a `match` require braces around them
	tokens.SetBracesAroundSwitchCases(true);

	// If the user hasn't specified a preference on brace placement, use the Rust standard style
	tokens.SetDefaultBracesOnSameLine(true);

	// Rust doesn't allow omitting the braces around conditional bodies
	tokens.SetSimpleScopeAllowed(false);
}


void PseudoRustFunction::BeginLines(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens)
{
	if (instr.exprIndex == m_highLevelIL->GetRootExpr().exprIndex)
	{
		// At top level, add braces around the entire function
		tokens.AppendOpenBrace();
		tokens.NewLine();
		tokens.IncreaseIndent();
	}
}


void PseudoRustFunction::EndLines(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens)
{
	if (instr.exprIndex == m_highLevelIL->GetRootExpr().exprIndex)
	{
		// At top level, add braces around the entire function
		tokens.NewLine();
		tokens.DecreaseIndent();
		tokens.AppendCloseBrace();
	}
}


BNSymbolDisplayResult PseudoRustFunction::AppendPointerTextToken(const HighLevelILInstruction& instr, int64_t val,
	vector<InstructionTextToken>& tokens, DisassemblySettings* settings, BNSymbolDisplayType symbolDisplay, BNOperatorPrecedence precedence)
{
	Confidence<Ref<Type>> type = instr.GetType();
	if (type && (type->GetClass() == PointerTypeClass) && type->IsConst())
	{
		string stringValue;
		size_t childWidth = 0;
		if (auto child = type->GetChildType(); child)
			childWidth = child->GetWidth();
		if (auto strType = GetFunction()->GetView()->CheckForStringAnnotationType(val, stringValue, false, false, childWidth); strType.has_value())
		{
			if (symbolDisplay == DereferenceNonDataSymbols)
			{
				if (precedence > UnaryOperatorPrecedence)
					tokens.emplace_back(BraceToken, "(");
				tokens.emplace_back(OperationToken, "*");
			}
			tokens.emplace_back(BraceToken, DisassemblyTextRenderer::GetStringLiteralPrefix(strType.value()) + string("\""));
			tokens.emplace_back(StringToken, StringReferenceTokenContext, stringValue, instr.address, strType.value());
			tokens.emplace_back(BraceToken, "\"");
			if (symbolDisplay == DereferenceNonDataSymbols && precedence > UnaryOperatorPrecedence)
				tokens.emplace_back(BraceToken, ")");
			return OtherSymbolResult;
		}
	}

	if (GetFunction())
	{
		// If the pointer has a value of 0, check if it points to a valid address by
		// 1. If the binary is relocatable, assign the pointer as nullptr
		// 2. else, check if the constant zero which being referenced is a pointer(display as symbol) or not(display as nullptr)
		if(val == 0x0 && type && (type->GetClass() == PointerTypeClass))
		{
			if (GetFunction()->GetView()->IsRelocatable())
			{
				if (symbolDisplay == DereferenceNonDataSymbols)
				{
					if (precedence > UnaryOperatorPrecedence)
						tokens.emplace_back(BraceToken, "(");
					tokens.emplace_back(OperationToken, "*");
				}
				tokens.emplace_back(CodeSymbolToken, InstructionAddressTokenContext, "nullptr", instr.address, val);
				if (symbolDisplay == DereferenceNonDataSymbols && precedence > UnaryOperatorPrecedence)
					tokens.emplace_back(BraceToken, ")");
				return OtherSymbolResult;
			}

			auto arch = GetHighLevelILFunction()->GetArchitecture();
			auto refs = GetHighLevelILFunction()->GetFunction()->GetConstantsReferencedByInstructionIfAvailable(
				arch, instr.address);
			bool constantZeroBeingReferencedIsPointer = false;

			for (const BNConstantReference& ref : refs)
				if (ref.value == 0x0 && ref.pointer)
					constantZeroBeingReferencedIsPointer = true;
			if (!constantZeroBeingReferencedIsPointer)
			{
				if (symbolDisplay == DereferenceNonDataSymbols)
				{
					if (precedence > UnaryOperatorPrecedence)
						tokens.emplace_back(BraceToken, "(");
					tokens.emplace_back(OperationToken, "*");
				}
				tokens.emplace_back(CodeSymbolToken, InstructionAddressTokenContext, "nullptr", instr.address, val);
				if (symbolDisplay == DereferenceNonDataSymbols && precedence > UnaryOperatorPrecedence)
					tokens.emplace_back(BraceToken, ")");
				return OtherSymbolResult;
			}
		}

		Ref<BinaryView> data = GetFunction()->GetView();
		vector<InstructionTextToken> symTokens;
		BNSymbolDisplayResult result = DisassemblyTextRenderer::AddSymbolTokenStatic(symTokens, val, 0,
			BN_INVALID_OPERAND, data, settings ? settings->GetMaximumSymbolWidth() : 0, GetFunction(),
			BN_FULL_CONFIDENCE, symbolDisplay, precedence, instr.address);
		if (result != NoSymbolAvailable)
		{
			for (auto& i : symTokens)
				tokens.emplace_back(i);
			return result;
		}
	}

	if (symbolDisplay == DereferenceNonDataSymbols)
	{
		if (precedence > UnaryOperatorPrecedence)
			tokens.emplace_back(BraceToken, "(");

		tokens.emplace_back(OperationToken, "*");
		if (!settings || settings->IsOptionSet(ShowTypeCasts))
		{
			tokens.emplace_back(BraceToken, "(");
			tokens.emplace_back(TypeNameToken, GetSizeToken(instr.size, false));
			tokens.emplace_back(OperationToken, "*");
			tokens.emplace_back(BraceToken, ")");
		}
	}

	char valStr[32];
	if (val >= 0)
	{
		if (val <= 9)
			snprintf(valStr, sizeof(valStr), "%" PRIx64, val);
		else
			snprintf(valStr, sizeof(valStr), "0x%" PRIx64, val);
	}
	else
	{
		if (val >= -9)
			snprintf(valStr, sizeof(valStr), "-%" PRIx64, val);
		else
			snprintf(valStr, sizeof(valStr), "-0x%" PRIx64, val);
	}

	tokens.emplace_back(PossibleAddressToken, InstructionAddressTokenContext, valStr, instr.address, val);

	if (symbolDisplay == DereferenceNonDataSymbols && precedence > UnaryOperatorPrecedence)
		tokens.emplace_back(BraceToken, ")");
	return OtherSymbolResult;
}


string PseudoRustFunction::GetSizeToken(size_t size, bool isSigned)
{
	char sizeStr[32];

	switch (size)
	{
		case 0:
			return {};
		case 1:
			return (isSigned ? "i8" : "u8");
		case 2:
			return (isSigned ? "i16" : "u16");
		case 4:
			return (isSigned ? "i32" : "u32");
		case 8:
			return (isSigned ? "i64" : "u64");
		case 10:
			return (isSigned ? "i80" : "u80");
		case 16:
			return (isSigned ? "i128" : "u128");
	}

	snprintf(sizeStr, sizeof(sizeStr), "%s%" PRIuPTR, isSigned ? "i" : "u", size);
	return {sizeStr};
}


void PseudoRustFunction::AppendSizeToken(size_t size, bool isSigned, HighLevelILTokenEmitter& emitter)
{
	const auto token = GetSizeToken(size, isSigned);
	if (!token.empty())
		emitter.Append(TypeNameToken, token);
}


void PseudoRustFunction::AppendSingleSizeToken(
	size_t size, BNInstructionTextTokenType type, HighLevelILTokenEmitter& emitter)
{
	char sizeStr[32];

	switch (size)
	{
		case 0:
			break;
		case 1:
			emitter.Append(type, "B");
			break;
		case 2:
			emitter.Append(type, "W");
			break;
		case 4:
			emitter.Append(type, "D");
			break;
		case 8:
			emitter.Append(type, "Q");
			break;
		case 10:
			emitter.Append(type, "T");
			break;
		case 16:
			emitter.Append(type, "O");
			break;
		default:
			snprintf(sizeStr, sizeof(sizeStr), "%" PRIuPTR "", size);
			emitter.Append(type, sizeStr);
			break;
	}
}


void PseudoRustFunction::AppendComparison(const string& comparison, const HighLevelILInstruction& instr,
	HighLevelILTokenEmitter& emitter, DisassemblySettings* settings, bool asFullAst, BNOperatorPrecedence precedence,
	std::optional<bool> signedHint)
{
	const auto leftExpr = instr.GetLeftExpr();
	const auto rightExpr = instr.GetRightExpr();

	GetExprText(leftExpr, emitter, settings, asFullAst, precedence, InnerExpression, signedHint);
	emitter.Append(OperationToken, comparison);
	GetExprText(rightExpr, emitter, settings, asFullAst, precedence, InnerExpression, signedHint);
}


void PseudoRustFunction::AppendTwoOperand(const string& operand, const HighLevelILInstruction& instr,
	HighLevelILTokenEmitter& emitter, DisassemblySettings* settings, bool asFullAst, BNOperatorPrecedence precedence,
	std::optional<bool> signedHint)
{
	const auto& twoOperand = instr.AsTwoOperand();
	const auto leftExpr = twoOperand.GetLeftExpr();
	const auto rightExpr = twoOperand.GetRightExpr();
	BNOperatorPrecedence leftPrecedence = precedence;
	switch (precedence)
	{
	case SubOperatorPrecedence:
		// Treat left side of subtraction as same level as addition. This lets
		// (a - b) - c be represented as a - b - c, but a - (b - c) does not
		// simplify at rendering
		leftPrecedence = AddOperatorPrecedence;
		break;
	case DivideOperatorPrecedence:
		// Treat left side of divison as same level as multiplication. This lets
		// (a / b) / c be represented as a / b / c, but a / (b / c) does not
		// simplify at rendering
		leftPrecedence = MultiplyOperatorPrecedence;
		break;
	default:
		break;
	}

	if (leftExpr.operation == HLIL_SPLIT)
	{
		const auto low = leftExpr.GetLowExpr();
		const auto high = leftExpr.GetHighExpr();

		emitter.Append(OperationToken, "COMBINE");
		emitter.AppendOpenParen();
		GetExprText(high, emitter, settings, asFullAst);
		emitter.Append(TextToken, ", ");
		GetExprText(low, emitter, settings, asFullAst);
		emitter.AppendCloseParen();
	}

	if (operand == " + " || operand == " - ")
	{
		const auto exprType = leftExpr.GetType();
		if (exprType && exprType->IsPointer())
		{
			GetExprText(leftExpr, emitter, settings, asFullAst, MemberAndFunctionOperatorPrecedence);
			emitter.Append(TextToken, ".");
			emitter.Append(OperationToken, "byte_offset");
			emitter.AppendOpenParen();
			if (operand == " - ")
			{
				emitter.Append(OperationToken, "-");
				GetExprText(rightExpr, emitter, settings, asFullAst, UnaryOperatorPrecedence);
			}
			else
			{
				GetExprText(rightExpr, emitter, settings, asFullAst);
			}
			emitter.AppendCloseParen();
			return;
		}
	}

	GetExprText(leftExpr, emitter, settings, asFullAst, leftPrecedence, InnerExpression, signedHint);

	auto lessThanZero = [](uint64_t value, uint64_t width) -> bool {
		return ((1UL << ((width * 8) - 1UL)) & value) != 0;
	};

	if ((operand == " + ") && (rightExpr.operation == HLIL_CONST) && lessThanZero(rightExpr.GetConstant<HLIL_CONST>(), rightExpr.size) &&
			rightExpr.size >= leftExpr.size)
	{
		// Convert addition of a negative constant into subtraction of a positive constant
		emitter.Append(OperationToken, " - ");
		emitter.AppendIntegerTextToken(
			rightExpr, -BNSignExtend(rightExpr.GetConstant<HLIL_CONST>(), rightExpr.size, 8), rightExpr.size);
		return;
	}
	if ((operand == " - ") && (rightExpr.operation == HLIL_CONST) && lessThanZero(rightExpr.GetConstant<HLIL_CONST>(), rightExpr.size) &&
			rightExpr.size >= leftExpr.size)
	{
		// Convert subtraction of a negative constant into addition of a positive constant
		emitter.Append(OperationToken, " + ");
		emitter.AppendIntegerTextToken(
			rightExpr, -BNSignExtend(rightExpr.GetConstant<HLIL_CONST>(), rightExpr.size, 8), rightExpr.size);
		return;
	}

	emitter.Append(OperationToken, operand);
	GetExprText(rightExpr, emitter, settings, asFullAst, precedence, InnerExpression, signedHint);
}


void PseudoRustFunction::AppendTwoOperandFunction(const string& function,
	const HighLevelILInstruction& instr, HighLevelILTokenEmitter& emitter, DisassemblySettings* settings,
	bool sizeToken)
{
	const auto& twoOperand = instr.AsTwoOperand();
	const auto leftExpr = twoOperand.GetLeftExpr();
	const auto rightExpr = twoOperand.GetRightExpr();

	emitter.Append(OperationToken, function);
	if (sizeToken)
		AppendSingleSizeToken(twoOperand.size, OperationToken, emitter);
	emitter.AppendOpenParen();

	if (leftExpr.operation == HLIL_SPLIT)
	{
		const auto low = leftExpr.GetLowExpr();
		const auto high = leftExpr.GetHighExpr();

		emitter.Append(OperationToken, "COMBINE");
		emitter.AppendOpenParen();
		GetExprText(high, emitter, settings);
		emitter.Append(TextToken, ", ");
		GetExprText(low, emitter, settings);
		emitter.AppendCloseParen();
	}

	GetExprText(leftExpr, emitter, settings);
	emitter.Append(TextToken, ", ");
	GetExprText(rightExpr, emitter, settings);

	emitter.AppendCloseParen();
}


void PseudoRustFunction::AppendTwoOperandMethodCall(const string& function,
	const HighLevelILInstruction& instr, HighLevelILTokenEmitter& emitter, DisassemblySettings* settings)
{
	const auto& twoOperand = instr.AsTwoOperand();
	const auto leftExpr = twoOperand.GetLeftExpr();
	const auto rightExpr = twoOperand.GetRightExpr();

	if (leftExpr.operation == HLIL_SPLIT)
	{
		const auto low = leftExpr.GetLowExpr();
		const auto high = leftExpr.GetHighExpr();

		emitter.Append(OperationToken, "COMBINE");
		emitter.AppendOpenParen();
		GetExprText(high, emitter, settings);
		emitter.Append(TextToken, ", ");
		GetExprText(low, emitter, settings);
		emitter.AppendCloseParen();
	}
	else
	{
		GetExprText(leftExpr, emitter, settings, MemberAndFunctionOperatorPrecedence);
	}

	emitter.Append(TextToken, ".");
	emitter.Append(OperationToken, function);
	emitter.AppendOpenParen();
	GetExprText(rightExpr, emitter, settings);
	emitter.AppendCloseParen();
}


void PseudoRustFunction::AppendTwoOperandFunctionWithCarry(const string& function,
	const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens, DisassemblySettings* settings)
{
	const auto leftExpr = instr.GetLeftExpr();
	const auto rightExpr = instr.GetRightExpr();
	const auto carryExpr = instr.GetCarryExpr();

	tokens.Append(OperationToken, function);
	AppendSingleSizeToken(instr.size, OperationToken, tokens);
	tokens.AppendOpenParen();

	if (leftExpr.operation == HLIL_SPLIT)
	{
		const auto low = leftExpr.GetLowExpr();
		const auto high = leftExpr.GetHighExpr();

		tokens.Append(OperationToken, "COMBINE");
		tokens.AppendOpenParen();
		GetExprText(high, tokens, settings);
		tokens.Append(TextToken, ", ");
		GetExprText(low, tokens, settings);
		tokens.AppendCloseParen();
	}

	GetExprText(leftExpr, tokens, settings);
	tokens.Append(TextToken, ", ");
	GetExprText(rightExpr, tokens, settings);
	tokens.Append(TextToken, ", ");
	GetExprText(carryExpr, tokens, settings);

	tokens.AppendCloseParen();
}


Ref<Type> PseudoRustFunction::GetFieldType(const HighLevelILInstruction& var, bool deref)
{
	Ref<Type> type = var.GetType().GetValue();
	if (deref && type && (type->GetClass() == PointerTypeClass))
		type = type->GetChildType().GetValue();

	if (type && (type->GetClass() == NamedTypeReferenceClass))
		type = GetFunction()->GetView()->GetTypeByRef(type->GetNamedTypeReference());

	return type;
}


PseudoRustFunction::FieldDisplayType PseudoRustFunction::GetFieldDisplayType(
	Ref<Type> type, uint64_t offset, size_t memberIndex, bool deref)
{
	if (type && (type->GetClass() == StructureTypeClass))
	{
		std::optional<size_t> memberIndexHint;
		if (memberIndex != BN_INVALID_EXPR)
			memberIndexHint = memberIndex;

		if (type->GetStructure()->ResolveMemberOrBaseMember(GetFunction()->GetView(), offset, 0,
				[&](NamedTypeReference*, Structure*, size_t, uint64_t, uint64_t, const StructureMember&) {}),
			memberIndexHint)
			return FieldDisplayName;
		return FieldDisplayOffset;
	}
	else if (deref || offset != 0)
		return FieldDisplayMemberOffset;
	else
		return FieldDisplayNone;
}


void PseudoRustFunction::AppendFieldTextTokens(const HighLevelILInstruction& var, uint64_t offset,
	size_t memberIndex, size_t size, HighLevelILTokenEmitter& tokens, bool deref)
{
	const auto type = GetFieldType(var, deref);
	const auto fieldDisplayType = GetFieldDisplayType(type, offset, memberIndex, deref);
	switch (fieldDisplayType)
	{
		case FieldDisplayName:
		{
			std::optional<size_t> memberIndexHint;
			if (memberIndex != BN_INVALID_EXPR)
				memberIndexHint = memberIndex;

			if (type->GetStructure()->ResolveMemberOrBaseMember(GetFunction()->GetView(), offset, 0,
					[&](NamedTypeReference*, Structure* s, size_t memberIndex, uint64_t structOffset,
						uint64_t adjustedOffset, const StructureMember& member) {
						tokens.Append(OperationToken, ".");

						vector<string> nameList {member.name};
						HighLevelILTokenEmitter::AddNamesForOuterStructureMembers(
							GetFunction()->GetView(), type, var, nameList);

						tokens.Append(FieldNameToken, member.name, structOffset + member.offset, 0, 0,
							BN_FULL_CONFIDENCE, nameList);
					}),
				memberIndexHint)
				return;

			// Part of structure but no defined field, use __offset syntax
			tokens.Append(OperationToken, ".");
			char offsetStr[64];
			snprintf(
				offsetStr, sizeof(offsetStr), "__offset(0x%" PRIx64 ")%s", offset, Type::GetSizeSuffix(size).c_str());

			vector<string> nameList {offsetStr};
			HighLevelILTokenEmitter::AddNamesForOuterStructureMembers(GetFunction()->GetView(), type, var, nameList);

			tokens.Append(StructOffsetToken, offsetStr, offset, size, 0, BN_FULL_CONFIDENCE, nameList);
			return;
		}

		case FieldDisplayOffset:
		{
			/* this is handled before the display */
			return;
		}

		case FieldDisplayMemberOffset:
		{
			tokens.AppendOpenBracket();
			tokens.AppendIntegerTextToken(var, offset, size);
			tokens.AppendCloseBracket();
			return;
		}

		default: break;
	}
}


bool PseudoRustFunction::IsMutable(const Variable& var) const
{
	for (auto i : GetHighLevelILFunction()->GetVariableDefinitions(var))
	{
		auto expr = GetHighLevelILFunction()->GetExpr(i);
		if (expr.operation == HLIL_VAR_DECLARE || expr.operation == HLIL_VAR_INIT)
			continue;
		return true;
	}
	return GetHighLevelILFunction()->GetAliasedVariables().count(var) != 0;
}


void PseudoRustFunction::GetExprText(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens,
	DisassemblySettings* settings, bool asFullAst, BNOperatorPrecedence precedence, ExpressionType exprType,
	std::optional<bool> signedHint)
{
	// The lambdas in this function are here to reduce stack frame size of this function. Without them,
	// complex expression can cause the process to crash from a stack overflow.
	auto exprGuard = tokens.SetCurrentExpr(instr);

	if (settings && settings->IsOptionSet(ShowILTypes) && instr.GetType())
	{
		tokens.AppendOpenParen();
		tokens.AppendOpenParen();
		for (auto& token: instr.GetType()->GetTokens(GetArchitecture()->GetStandalonePlatform()))
		{
			tokens.Append(token);
		}
		tokens.AppendCloseParen();
		tokens.Append(TextToken, " ");
	}
	if (settings && settings->IsOptionSet(ShowILOpcodes))
	{
		tokens.Append(OperationToken, "/*");
		switch (instr.operation)
		{
		case HLIL_NOP: tokens.Append(OperationToken, "HLIL_NOP"); break;
		case HLIL_BLOCK: tokens.Append(OperationToken, "HLIL_BLOCK"); break;
		case HLIL_IF: tokens.Append(OperationToken, "HLIL_IF"); break;
		case HLIL_WHILE: tokens.Append(OperationToken, "HLIL_WHILE"); break;
		case HLIL_DO_WHILE: tokens.Append(OperationToken, "HLIL_DO_WHILE"); break;
		case HLIL_FOR: tokens.Append(OperationToken, "HLIL_FOR"); break;
		case HLIL_SWITCH: tokens.Append(OperationToken, "HLIL_SWITCH"); break;
		case HLIL_CASE: tokens.Append(OperationToken, "HLIL_CASE"); break;
		case HLIL_BREAK: tokens.Append(OperationToken, "HLIL_BREAK"); break;
		case HLIL_CONTINUE: tokens.Append(OperationToken, "HLIL_CONTINUE"); break;
		case HLIL_JUMP: tokens.Append(OperationToken, "HLIL_JUMP"); break;
		case HLIL_RET: tokens.Append(OperationToken, "HLIL_RET"); break;
		case HLIL_NORET: tokens.Append(OperationToken, "HLIL_NORET"); break;
		case HLIL_GOTO: tokens.Append(OperationToken, "HLIL_GOTO"); break;
		case HLIL_LABEL: tokens.Append(OperationToken, "HLIL_LABEL"); break;
		case HLIL_VAR_DECLARE: tokens.Append(OperationToken, "HLIL_VAR_DECLARE"); break;
		case HLIL_VAR_INIT: tokens.Append(OperationToken, "HLIL_VAR_INIT"); break;
		case HLIL_ASSIGN: tokens.Append(OperationToken, "HLIL_ASSIGN"); break;
		case HLIL_ASSIGN_UNPACK: tokens.Append(OperationToken, "HLIL_ASSIGN_UNPACK"); break;
		case HLIL_VAR: tokens.Append(OperationToken, "HLIL_VAR"); break;
		case HLIL_STRUCT_FIELD: tokens.Append(OperationToken, "HLIL_STRUCT_FIELD"); break;
		case HLIL_ARRAY_INDEX: tokens.Append(OperationToken, "HLIL_ARRAY_INDEX"); break;
		case HLIL_SPLIT: tokens.Append(OperationToken, "HLIL_SPLIT"); break;
		case HLIL_DEREF: tokens.Append(OperationToken, "HLIL_DEREF"); break;
		case HLIL_DEREF_FIELD: tokens.Append(OperationToken, "HLIL_DEREF_FIELD"); break;
		case HLIL_ADDRESS_OF: tokens.Append(OperationToken, "HLIL_ADDRESS_OF"); break;
		case HLIL_CONST: tokens.Append(OperationToken, "HLIL_CONST"); break;
		case HLIL_CONST_DATA: tokens.Append(OperationToken, "HLIL_CONST_DATA"); break;
		case HLIL_CONST_PTR: tokens.Append(OperationToken, "HLIL_CONST_PTR"); break;
		case HLIL_EXTERN_PTR: tokens.Append(OperationToken, "HLIL_EXTERN_PTR"); break;
		case HLIL_FLOAT_CONST: tokens.Append(OperationToken, "HLIL_FLOAT_CONST"); break;
		case HLIL_IMPORT: tokens.Append(OperationToken, "HLIL_IMPORT"); break;
		case HLIL_ADD: tokens.Append(OperationToken, "HLIL_ADD"); break;
		case HLIL_ADC: tokens.Append(OperationToken, "HLIL_ADC"); break;
		case HLIL_SUB: tokens.Append(OperationToken, "HLIL_SUB"); break;
		case HLIL_SBB: tokens.Append(OperationToken, "HLIL_SBB"); break;
		case HLIL_AND: tokens.Append(OperationToken, "HLIL_AND"); break;
		case HLIL_OR: tokens.Append(OperationToken, "HLIL_OR"); break;
		case HLIL_XOR: tokens.Append(OperationToken, "HLIL_XOR"); break;
		case HLIL_LSL: tokens.Append(OperationToken, "HLIL_LSL"); break;
		case HLIL_LSR: tokens.Append(OperationToken, "HLIL_LSR"); break;
		case HLIL_ASR: tokens.Append(OperationToken, "HLIL_ASR"); break;
		case HLIL_ROL: tokens.Append(OperationToken, "HLIL_ROL"); break;
		case HLIL_RLC: tokens.Append(OperationToken, "HLIL_RLC"); break;
		case HLIL_ROR: tokens.Append(OperationToken, "HLIL_ROR"); break;
		case HLIL_RRC: tokens.Append(OperationToken, "HLIL_RRC"); break;
		case HLIL_MUL: tokens.Append(OperationToken, "HLIL_MUL"); break;
		case HLIL_MULU_DP: tokens.Append(OperationToken, "HLIL_MULU_DP"); break;
		case HLIL_MULS_DP: tokens.Append(OperationToken, "HLIL_MULS_DP"); break;
		case HLIL_DIVU: tokens.Append(OperationToken, "HLIL_DIVU"); break;
		case HLIL_DIVU_DP: tokens.Append(OperationToken, "HLIL_DIVU_DP"); break;
		case HLIL_DIVS: tokens.Append(OperationToken, "HLIL_DIVS"); break;
		case HLIL_DIVS_DP: tokens.Append(OperationToken, "HLIL_DIVS_DP"); break;
		case HLIL_MODU: tokens.Append(OperationToken, "HLIL_MODU"); break;
		case HLIL_MODU_DP: tokens.Append(OperationToken, "HLIL_MODU_DP"); break;
		case HLIL_MODS: tokens.Append(OperationToken, "HLIL_MODS"); break;
		case HLIL_MODS_DP: tokens.Append(OperationToken, "HLIL_MODS_DP"); break;
		case HLIL_NEG: tokens.Append(OperationToken, "HLIL_NEG"); break;
		case HLIL_NOT: tokens.Append(OperationToken, "HLIL_NOT"); break;
		case HLIL_SX: tokens.Append(OperationToken, "HLIL_SX"); break;
		case HLIL_ZX: tokens.Append(OperationToken, "HLIL_ZX"); break;
		case HLIL_LOW_PART: tokens.Append(OperationToken, "HLIL_LOW_PART"); break;
		case HLIL_CALL: tokens.Append(OperationToken, "HLIL_CALL"); break;
		case HLIL_CMP_E: tokens.Append(OperationToken, "HLIL_CMP_E"); break;
		case HLIL_CMP_NE: tokens.Append(OperationToken, "HLIL_CMP_NE"); break;
		case HLIL_CMP_SLT: tokens.Append(OperationToken, "HLIL_CMP_SLT"); break;
		case HLIL_CMP_ULT: tokens.Append(OperationToken, "HLIL_CMP_ULT"); break;
		case HLIL_CMP_SLE: tokens.Append(OperationToken, "HLIL_CMP_SLE"); break;
		case HLIL_CMP_ULE: tokens.Append(OperationToken, "HLIL_CMP_ULE"); break;
		case HLIL_CMP_SGE: tokens.Append(OperationToken, "HLIL_CMP_SGE"); break;
		case HLIL_CMP_UGE: tokens.Append(OperationToken, "HLIL_CMP_UGE"); break;
		case HLIL_CMP_SGT: tokens.Append(OperationToken, "HLIL_CMP_SGT"); break;
		case HLIL_CMP_UGT: tokens.Append(OperationToken, "HLIL_CMP_UGT"); break;
		case HLIL_TEST_BIT: tokens.Append(OperationToken, "HLIL_TEST_BIT"); break;
		case HLIL_BOOL_TO_INT: tokens.Append(OperationToken, "HLIL_BOOL_TO_INT"); break;
		case HLIL_ADD_OVERFLOW: tokens.Append(OperationToken, "HLIL_ADD_OVERFLOW"); break;
		case HLIL_SYSCALL: tokens.Append(OperationToken, "HLIL_SYSCALL"); break;
		case HLIL_TAILCALL: tokens.Append(OperationToken, "HLIL_TAILCALL"); break;
		case HLIL_INTRINSIC: tokens.Append(OperationToken, "HLIL_INTRINSIC"); break;
		case HLIL_BP: tokens.Append(OperationToken, "HLIL_BP"); break;
		case HLIL_TRAP: tokens.Append(OperationToken, "HLIL_TRAP"); break;
		case HLIL_UNDEF: tokens.Append(OperationToken, "HLIL_UNDEF"); break;
		case HLIL_UNIMPL: tokens.Append(OperationToken, "HLIL_UNIMPL"); break;
		case HLIL_UNIMPL_MEM: tokens.Append(OperationToken, "HLIL_UNIMPL_MEM"); break;
		case HLIL_FADD: tokens.Append(OperationToken, "HLIL_FADD"); break;
		case HLIL_FSUB: tokens.Append(OperationToken, "HLIL_FSUB"); break;
		case HLIL_FMUL: tokens.Append(OperationToken, "HLIL_FMUL"); break;
		case HLIL_FDIV: tokens.Append(OperationToken, "HLIL_FDIV"); break;
		case HLIL_FSQRT: tokens.Append(OperationToken, "HLIL_FSQRT"); break;
		case HLIL_FNEG: tokens.Append(OperationToken, "HLIL_FNEG"); break;
		case HLIL_FABS: tokens.Append(OperationToken, "HLIL_FABS"); break;
		case HLIL_FLOAT_TO_INT: tokens.Append(OperationToken, "HLIL_FLOAT_TO_INT"); break;
		case HLIL_INT_TO_FLOAT: tokens.Append(OperationToken, "HLIL_INT_TO_FLOAT"); break;
		case HLIL_FLOAT_CONV: tokens.Append(OperationToken, "HLIL_FLOAT_CONV"); break;
		case HLIL_ROUND_TO_INT: tokens.Append(OperationToken, "HLIL_ROUND_TO_INT"); break;
		case HLIL_FLOOR: tokens.Append(OperationToken, "HLIL_FLOOR"); break;
		case HLIL_CEIL: tokens.Append(OperationToken, "HLIL_CEIL"); break;
		case HLIL_FTRUNC: tokens.Append(OperationToken, "HLIL_FTRUNC"); break;
		case HLIL_FCMP_E: tokens.Append(OperationToken, "HLIL_FCMP_E"); break;
		case HLIL_FCMP_NE: tokens.Append(OperationToken, "HLIL_FCMP_NE"); break;
		case HLIL_FCMP_LT: tokens.Append(OperationToken, "HLIL_FCMP_LT"); break;
		case HLIL_FCMP_LE: tokens.Append(OperationToken, "HLIL_FCMP_LE"); break;
		case HLIL_FCMP_GE: tokens.Append(OperationToken, "HLIL_FCMP_GE"); break;
		case HLIL_FCMP_GT: tokens.Append(OperationToken, "HLIL_FCMP_GT"); break;
		case HLIL_FCMP_O: tokens.Append(OperationToken, "HLIL_FCMP_O"); break;
		case HLIL_FCMP_UO: tokens.Append(OperationToken, "HLIL_FCMP_UO"); break;
		case HLIL_UNREACHABLE: tokens.Append(OperationToken, "HLIL_UNREACHABLE"); break;
		case HLIL_WHILE_SSA: tokens.Append(OperationToken, "HLIL_WHILE_SSA"); break;
		case HLIL_DO_WHILE_SSA: tokens.Append(OperationToken, "HLIL_DO_WHILE_SSA"); break;
		case HLIL_FOR_SSA: tokens.Append(OperationToken, "HLIL_FOR_SSA"); break;
		case HLIL_VAR_INIT_SSA: tokens.Append(OperationToken, "HLIL_VAR_INIT_SSA"); break;
		case HLIL_ASSIGN_MEM_SSA: tokens.Append(OperationToken, "HLIL_ASSIGN_MEM_SSA"); break;
		case HLIL_ASSIGN_UNPACK_MEM_SSA: tokens.Append(OperationToken, "HLIL_ASSIGN_UNPACK_MEM_SSA"); break;
		case HLIL_VAR_SSA: tokens.Append(OperationToken, "HLIL_VAR_SSA"); break;
		case HLIL_ARRAY_INDEX_SSA: tokens.Append(OperationToken, "HLIL_ARRAY_INDEX_SSA"); break;
		case HLIL_DEREF_SSA: tokens.Append(OperationToken, "HLIL_DEREF_SSA"); break;
		case HLIL_DEREF_FIELD_SSA: tokens.Append(OperationToken, "HLIL_DEREF_FIELD_SSA"); break;
		case HLIL_CALL_SSA: tokens.Append(OperationToken, "HLIL_CALL_SSA"); break;
		case HLIL_SYSCALL_SSA: tokens.Append(OperationToken, "HLIL_SYSCALL_SSA"); break;
		case HLIL_INTRINSIC_SSA: tokens.Append(OperationToken, "HLIL_INTRINSIC_SSA"); break;
		case HLIL_VAR_PHI: tokens.Append(OperationToken, "HLIL_VAR_PHI"); break;
		case HLIL_MEM_PHI: tokens.Append(OperationToken, "HLIL_MEM_PHI"); break;
		}
		tokens.Append(OperationToken, "*/");
		tokens.Append(TextToken, " ");
	}

	switch (instr.operation)
	{
	case HLIL_BLOCK:
		[&]() {
			const auto exprs = instr.GetBlockExprs<HLIL_BLOCK>();
			bool needSeparator = false;
			for (auto i = exprs.begin(); i != exprs.end(); ++i)
			{
				// Don't show void returns at the very end of the function when printing
				// the root of an AST, as it is implicit and almost always omitted in
				// normal source code.
				auto next = i;
				++next;
				if (asFullAst && (instr.exprIndex == GetHighLevelILFunction()->GetRootExpr().exprIndex) && (exprs.size() > 1) &&
					(next == exprs.end()) && ((*i).operation == HLIL_RET) &&
					((*i).GetSourceExprs<HLIL_RET>().size() == 0))
					continue;

				// If the statement is one that contains additional blocks of code, insert a scope separator
				// to visually separate the logic.
				bool hasBlocks = false;
				switch ((*i).operation)
				{
				case HLIL_IF:
				case HLIL_WHILE:
				case HLIL_WHILE_SSA:
				case HLIL_DO_WHILE:
				case HLIL_DO_WHILE_SSA:
				case HLIL_FOR:
				case HLIL_FOR_SSA:
				case HLIL_SWITCH:
					hasBlocks = true;
					break;
				default:
					hasBlocks = false;
					break;
				}
				if (needSeparator || (i != exprs.begin() && hasBlocks))
				{
					tokens.ScopeSeparator();
				}
				needSeparator = hasBlocks;

				// Emit the lines for the statement itself
				GetExprText(*i, tokens, settings, true, TopLevelOperatorPrecedence,
					exprType == TrailingStatementExpression && next == exprs.end() ?
					TrailingStatementExpression : StatementExpression);
				tokens.NewLine();
			}
		}();
		break;

	case HLIL_FOR:
		[&]() {
			const auto initExpr = instr.GetInitExpr<HLIL_FOR>();
			const auto condExpr = instr.GetConditionExpr<HLIL_FOR>();
			const auto updateExpr = instr.GetUpdateExpr<HLIL_FOR>();
			const auto loopExpr = instr.GetLoopExpr<HLIL_FOR>();

			if (asFullAst)
			{
				tokens.Append(KeywordToken, "for ");

				// If the loop can be represented as a ranged for in idiomatic Rust, show it that way
				if (initExpr.operation == HLIL_VAR_INIT &&
					(condExpr.operation == HLIL_CMP_SLT || condExpr.operation == HLIL_CMP_SLE ||
						condExpr.operation == HLIL_CMP_ULT || condExpr.operation == HLIL_CMP_ULE) &&
					condExpr.GetLeftExpr().operation == HLIL_VAR &&
					condExpr.GetLeftExpr().GetVariable<HLIL_VAR>() == initExpr.GetDestVariable<HLIL_VAR_INIT>() &&
					updateExpr.operation == HLIL_ASSIGN &&
					updateExpr.GetDestExpr<HLIL_ASSIGN>() == condExpr.GetLeftExpr() &&
					updateExpr.GetSourceExpr<HLIL_ASSIGN>().operation == HLIL_ADD &&
					updateExpr.GetSourceExpr<HLIL_ASSIGN>().GetLeftExpr<HLIL_ADD>() == condExpr.GetLeftExpr())
				{
					bool stepBy = updateExpr.GetSourceExpr<HLIL_ASSIGN>().GetRightExpr<HLIL_ADD>().operation != HLIL_CONST ||
						updateExpr.GetSourceExpr<HLIL_ASSIGN>().GetRightExpr<HLIL_ADD>().GetConstant() != 1;

					const auto variable = initExpr.GetDestVariable<HLIL_VAR_INIT>();
					const auto variableName = GetHighLevelILFunction()->GetFunction()->GetVariableNameOrDefault(variable);
					tokens.Append(LocalVariableToken, LocalVariableTokenContext, variableName,
								  instr.exprIndex, variable.ToIdentifier(), instr.size);
					tokens.Append(KeywordToken, " in ");

					if (stepBy)
						tokens.AppendOpenParen();

					GetExprText(initExpr.GetSourceExpr<HLIL_VAR_INIT>(), tokens, settings, asFullAst, AssignmentOperatorPrecedence);
					if (condExpr.operation == HLIL_CMP_SLT || condExpr.operation == HLIL_CMP_ULT)
						tokens.Append(TextToken, "..");
					else
						tokens.Append(TextToken, "..=");
					GetExprText(condExpr.GetRightExpr(), tokens, settings, asFullAst, AssignmentOperatorPrecedence);

					if (stepBy)
					{
						tokens.AppendCloseParen();
						tokens.Append(TextToken, ".");
						tokens.Append(OperationToken, "step_by");
						tokens.AppendOpenParen();
						GetExprText(updateExpr.GetSourceExpr<HLIL_ASSIGN>().GetRightExpr<HLIL_ADD>(),
							tokens, settings, asFullAst);
						tokens.AppendCloseParen();
					}
				}
				else
				{
					// For loop isn't directly representable in standard Rust
					if (initExpr.operation != HLIL_NOP)
						GetExprText(initExpr, tokens, settings, asFullAst);
					tokens.Append(TextToken, "; ");
					if (condExpr.operation != HLIL_NOP)
						GetExprText(condExpr, tokens, settings, asFullAst);
					tokens.Append(TextToken, "; ");
					if (updateExpr.operation != HLIL_NOP)
						GetExprText(updateExpr, tokens, settings, asFullAst);
				}
				auto scopeType = HighLevelILFunction::GetExprScopeType(loopExpr);
				tokens.BeginScope(scopeType);
				GetExprText(loopExpr, tokens, settings, asFullAst, TopLevelOperatorPrecedence, StatementExpression);
				tokens.EndScope(scopeType);
				tokens.FinalizeScope();
			}
			else
			{
				tokens.Append(KeywordToken, "while ");
				GetExprText(condExpr, tokens, settings);
			}
		}();
		break;

	case HLIL_IF:
		[&]() {
			const auto condExpr = instr.GetConditionExpr<HLIL_IF>();
			const auto trueExpr = instr.GetTrueExpr<HLIL_IF>();
			const auto falseExpr = instr.GetFalseExpr<HLIL_IF>();

			tokens.Append(KeywordToken, "if ");
			GetExprText(condExpr, tokens, settings, asFullAst);
			if (!asFullAst)
				return;

			auto scopeType = HighLevelILFunction::GetExprScopeType(trueExpr);
			tokens.BeginScope(scopeType);

			GetExprText(trueExpr, tokens, settings, asFullAst, TopLevelOperatorPrecedence, exprType);
			tokens.EndScope(scopeType);
			//tokens.SetCurrentExpr(falseExpr);
			if (falseExpr.operation == HLIL_IF)
			{
				tokens.ScopeContinuation(false);
				tokens.Append(KeywordToken, "else ");
				GetExprText(falseExpr, tokens, settings, asFullAst, TopLevelOperatorPrecedence, exprType);
			}
			else if (falseExpr.operation != HLIL_NOP)
			{
				tokens.ScopeContinuation(false);
				tokens.Append(KeywordToken, "else");
				scopeType = HighLevelILFunction::GetExprScopeType(falseExpr);
				tokens.BeginScope(scopeType);
				GetExprText(falseExpr, tokens, settings, asFullAst, TopLevelOperatorPrecedence, exprType);
				tokens.EndScope(scopeType);
				tokens.FinalizeScope();
			}
			else
			{
				tokens.FinalizeScope();
			}
		}();
		break;

	case HLIL_WHILE:
		[&]() {
			const auto condExpr = instr.GetConditionExpr<HLIL_WHILE>();
			const auto loopExpr = instr.GetLoopExpr<HLIL_WHILE>();

			if (condExpr.operation == HLIL_CONST && condExpr.GetConstant<HLIL_CONST>() != 0)
			{
				tokens.Append(KeywordToken, "loop");
			}
			else
			{
				tokens.Append(KeywordToken, "while ");
				GetExprText(condExpr, tokens, settings);
			}
			if (!asFullAst)
				return;

			auto scopeType = HighLevelILFunction::GetExprScopeType(loopExpr);
			tokens.BeginScope(scopeType);
			GetExprText(loopExpr, tokens, settings, true, TopLevelOperatorPrecedence, StatementExpression);
			tokens.EndScope(scopeType);
			tokens.FinalizeScope();

		}();
		break;

	case HLIL_DO_WHILE:
		[&]() {
			const auto loopExpr = instr.GetLoopExpr<HLIL_DO_WHILE>();
			const auto condExpr = instr.GetConditionExpr<HLIL_DO_WHILE>();
			if (asFullAst)
			{
				tokens.Append(KeywordToken, "do");
				auto scopeType = HighLevelILFunction::GetExprScopeType(loopExpr);
				tokens.BeginScope(scopeType);
				GetExprText(loopExpr, tokens, settings, true, TopLevelOperatorPrecedence, StatementExpression);
				tokens.EndScope(scopeType);
				tokens.ScopeContinuation(true);
				tokens.Append(KeywordToken, "while ");
				GetExprText(condExpr, tokens, settings);
				tokens.Append(KeywordToken, ";");
				tokens.FinalizeScope();
			}
			else
			{
				tokens.Append(TextToken, "/* do */ ");
				tokens.Append(KeywordToken, "while ");
				GetExprText(condExpr, tokens, settings);
			}
		}();
		break;

	case HLIL_SWITCH:
		[&]() {
			const auto condExpr = instr.GetConditionExpr<HLIL_SWITCH>();
			const auto caseExprs = instr.GetCases<HLIL_SWITCH>();
			const auto defaultExpr = instr.GetDefaultExpr<HLIL_SWITCH>();

			tokens.Append(KeywordToken, "match ");
			GetExprText(condExpr, tokens, settings, asFullAst);
			tokens.BeginScope(SwitchScopeType);
			if (!asFullAst)
				return;

			for (const auto caseExpr : caseExprs)
			{
				GetExprText(caseExpr, tokens, settings, asFullAst, TopLevelOperatorPrecedence, exprType);
				tokens.NewLine();
			}

			// Check for default case
			if (defaultExpr.operation != HLIL_NOP && defaultExpr.operation != HLIL_UNREACHABLE)
			{
				tokens.Append(TextToken, "_ =>");
				tokens.BeginScope(CaseScopeType);
				GetExprText(defaultExpr, tokens, settings, asFullAst, TopLevelOperatorPrecedence, exprType);
				tokens.EndScope(CaseScopeType);
				tokens.FinalizeScope();
			}

			tokens.EndScope(SwitchScopeType);
			tokens.FinalizeScope();

		}();
		break;

	case HLIL_CASE:
		[&]() {
			const auto valueExprs = instr.GetValueExprs<HLIL_CASE>();
			const auto trueExpr = instr.GetTrueExpr<HLIL_CASE>();

			for (size_t index{}; index < valueExprs.size(); index++)
			{
				const auto& valueExpr = valueExprs[index];
				if (index != 0)
					tokens.Append(TextToken, " | ");
				GetExprText(valueExpr, tokens, settings, asFullAst);
			}
			tokens.Append(TextToken, " =>");

			if (!asFullAst)
				return;

			tokens.BeginScope(CaseScopeType);
			GetExprText(trueExpr, tokens, settings, asFullAst, TopLevelOperatorPrecedence, exprType);
			tokens.EndScope(CaseScopeType);
			tokens.FinalizeScope();
		}();
		break;

	case HLIL_BREAK:
		[&]() {
			tokens.Append(KeywordToken, "break");
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CONTINUE:
		[&]() {
			tokens.Append(KeywordToken, "continue");
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ZX:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_ZX>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprText(srcExpr, tokens, settings, asFullAst, precedence);
				return;
			}
			bool parens = precedence > LowUnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			GetExprText(srcExpr, tokens, settings, asFullAst, LowUnaryOperatorPrecedence, InnerExpression, false);
			tokens.Append(KeywordToken, " as ");
			AppendSizeToken(instr.size, false, tokens);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_SX:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_SX>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprText(srcExpr, tokens, settings, asFullAst, precedence);
				return;
			}
			bool parens = precedence > LowUnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			GetExprText(srcExpr, tokens, settings, asFullAst, LowUnaryOperatorPrecedence, InnerExpression, true);
			tokens.Append(KeywordToken, " as ");
			AppendSizeToken(instr.size, true, tokens);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CALL:
		[&]() {
			const auto destExpr = instr.GetDestExpr<HLIL_CALL>();
			const auto parameterExprs = instr.GetParameterExprs<HLIL_CALL>();

			GetExprText(destExpr, tokens, settings, asFullAst, MemberAndFunctionOperatorPrecedence);
			tokens.AppendOpenParen();

			vector<FunctionParameter> namedParams;
			Ref<Type> functionType = instr.GetDestExpr<HLIL_CALL>().GetType();
			if (functionType && (functionType->GetClass() == PointerTypeClass)
				&& (functionType->GetChildType()->GetClass() == FunctionTypeClass))
				namedParams = functionType->GetChildType()->GetParameters();

			for (size_t index{}; index < parameterExprs.size(); index++)
			{
				const auto& parameterExpr = parameterExprs[index];
				if (index != 0) tokens.Append(TextToken, ", ");

				// If the type of the parameter is known to be a pointer to a string, then we directly render it as a
				// string, regardless of its length
				bool renderedAsString = false;
				if (index < namedParams.size() && parameterExprs[index].operation == HLIL_CONST_PTR)
				{
					auto exprType = namedParams[index].type;
					if (exprType && (exprType->GetClass() == PointerTypeClass))
					{
						if (auto child = exprType->GetChildType(); child)
						{
							if ((child->IsInteger() && child->IsSigned() && child->GetWidth() == 1)
								|| child->IsWideChar())
							{
								tokens.AppendPointerTextToken(parameterExprs[index],
									parameterExprs[index].GetConstant<HLIL_CONST_PTR>(), settings, AddressOfDataSymbols,
									precedence, true);
								renderedAsString = true;
							}
						}
					}
				}

				if (!renderedAsString)
					GetExprText(parameterExpr, tokens, settings, asFullAst);
			}
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_IMPORT:
		[&]() {
			const auto constant = instr.GetConstant<HLIL_IMPORT>();
			auto symbol = GetHighLevelILFunction()->GetFunction()->GetView()->GetSymbolByAddress(constant);
			const auto symbolType = symbol->GetType();

			if (symbol && (symbolType == ImportedDataSymbol || symbolType == ImportAddressSymbol))
			{
				symbol = Symbol::ImportedFunctionFromImportAddressSymbol(symbol, constant);
				const auto symbolShortName = symbol->GetShortName();
				tokens.Append(IndirectImportToken, NoTokenContext, symbolShortName, instr.address, constant, instr.size, instr.sourceOperand);
				return;
			}

			tokens.AppendPointerTextToken(instr, constant, settings, DereferenceNonDataSymbols, precedence);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ARRAY_INDEX:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_ARRAY_INDEX>();
			const auto indexExpr = instr.GetIndexExpr<HLIL_ARRAY_INDEX>();

			GetExprText(srcExpr, tokens, settings, asFullAst, MemberAndFunctionOperatorPrecedence);
			tokens.AppendOpenBracket();
			GetExprText(indexExpr, tokens, settings, asFullAst);
			tokens.AppendCloseBracket();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_VAR_INIT:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_VAR_INIT>();
			const auto destExpr = instr.GetDestVariable<HLIL_VAR_INIT>();

			const auto variableType = GetHighLevelILFunction()->GetFunction()->GetVariableType(destExpr);
			const auto platform = GetHighLevelILFunction()->GetFunction()->GetPlatform();
			RustTypePrinter printer;
			const auto prevTypeTokens = variableType ?
				printer.GetTypeTokensBeforeName(variableType, platform, variableType.GetConfidence()) :
				vector<InstructionTextToken> {};
			const auto postTypeTokens = variableType ?
				printer.GetTypeTokensAfterName(variableType, platform, variableType.GetConfidence()) :
				vector<InstructionTextToken> {};

			// Check to see if the variable appears live
			bool appearsDead = false;
			if (const auto ssaForm = instr.GetSSAForm(); ssaForm.operation == HLIL_VAR_INIT_SSA)
			{
				const auto ssaDest = ssaForm.GetDestSSAVariable<HLIL_VAR_INIT_SSA>();
				appearsDead = !GetHighLevelILFunction()->IsSSAVarLive(ssaDest);
			}

			// If the variable does not appear live, show the assignment as zero confidence (grayed out)
			if (appearsDead)
				tokens.BeginForceZeroConfidence();

			tokens.Append(KeywordToken, "let ");

			// Only show `mut` keyword if the variable is actually changed
			if (IsMutable(destExpr))
				tokens.Append(KeywordToken, "mut ");

			if (variableType)
			{
				for (auto typeToken : prevTypeTokens)
				{
					typeToken.context = LocalVariableTokenContext;
					typeToken.address = destExpr.ToIdentifier();
					tokens.Append(typeToken);
				}
			}
			tokens.AppendVarTextToken(destExpr, instr, instr.size);
			if (variableType)
			{
				for (auto typeToken : postTypeTokens)
				{
					typeToken.context = LocalVariableTokenContext;
					typeToken.address = destExpr.ToIdentifier();
					tokens.Append(typeToken);
				}
			}
			tokens.Append(OperationToken, " = ");

			// For the right side of the assignment, only use zero confidence if the instruction does
			// not have any side effects
			if (appearsDead && GetHighLevelILFunction()->HasSideEffects(srcExpr))
			{
				tokens.EndForceZeroConfidence();
				appearsDead = false;
			}

			GetExprText(srcExpr, tokens, settings, asFullAst, AssignmentOperatorPrecedence);

			if (appearsDead)
				tokens.EndForceZeroConfidence();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_VAR_DECLARE:
		[&]() {
			const auto variable = instr.GetVariable<HLIL_VAR_DECLARE>();

			const auto variableType = GetHighLevelILFunction()->GetFunction()->GetVariableType(variable);
			const auto platform = GetHighLevelILFunction()->GetFunction()->GetPlatform();
			RustTypePrinter printer;
			const auto prevTypeTokens =
					variableType ?
					printer.GetTypeTokensBeforeName(variableType, platform, variableType.GetConfidence()) :
					vector<InstructionTextToken>{};
			const auto postTypeTokens =
					variableType ?
					printer.GetTypeTokensAfterName(variableType, platform, variableType.GetConfidence()) :
					vector<InstructionTextToken>{};

			tokens.Append(KeywordToken, "let ");

			// Only show `mut` keyword if the variable is actually changed
			if (IsMutable(variable))
				tokens.Append(KeywordToken, "mut ");

			if (variableType)
			{
				for (auto typeToken: prevTypeTokens)
				{
					typeToken.context = LocalVariableTokenContext;
					typeToken.address = variable.ToIdentifier();
					tokens.Append(typeToken);
				}
			}
			tokens.AppendVarTextToken(variable, instr, instr.size);
			if (variableType)
			{
				for (auto typeToken: postTypeTokens)
				{
					typeToken.context = LocalVariableTokenContext;
					typeToken.address = variable.ToIdentifier();
					tokens.Append(typeToken);
				}
			}

			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FLOAT_CONST:
		[&]() {
			const auto constant = instr.GetConstant<HLIL_FLOAT_CONST>();
			if (instr.size == 4)
			{
				char valueStr[64];
				union
				{
					float f;
					uint32_t i;
				} bits{};
				bits.i = constant;
				snprintf(valueStr, sizeof(valueStr), "%.9gf", bits.f);
				tokens.Append(FloatingPointToken, InstructionAddressTokenContext, valueStr, instr.address);
			}
			else if (instr.size == 8)
			{
				char valueStr[64];
				union
				{
					double f;
					uint64_t i;
				} bits{};
				bits.i = constant;
				snprintf(valueStr, sizeof(valueStr), "%.17g", bits.f);
				string s = valueStr;
				if ((s.find('.') == string::npos) && (s.find('e') == string::npos))
					s += ".0";
				tokens.Append(FloatingPointToken, InstructionAddressTokenContext, s, instr.address);
			}
			else
			{
				tokens.AppendIntegerTextToken(instr, constant, 8);
			}

			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CONST:
		[&]() {
			tokens.AppendConstantTextToken(instr, instr.GetConstant<HLIL_CONST>(), instr.size, settings, precedence);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CONST_DATA:
		[&]() {
			// Constant data should be rendered according to the type of builtin function being used.
			const ConstantData& data = instr.GetConstantData<HLIL_CONST_DATA>();
			if (auto [db, builtin] = data.ToDataBuffer(); db.GetLength())
			{
				switch (builtin)
				{
					case BuiltinStrcpy:
					case BuiltinStrncpy:
					{
						string result(db.ToEscapedString(true));
						tokens.Append(BraceToken, "\"");
						tokens.Append(StringToken, ConstStringDataTokenContext, result, instr.address, data.value);
						tokens.Append(BraceToken, "\"");
						break;
					}
					case BuiltinMemset:
					{
						char buf[32];
						if (data.value < 10)
							snprintf(buf, sizeof(buf), "%" PRId64 "", data.value);
						else
							snprintf(buf, sizeof(buf), "0x%" PRIx64 "", data.value);

						tokens.Append(BraceToken, "{");
						tokens.Append(StringToken, ConstDataTokenContext, string(buf), instr.address, data.value);
						tokens.Append(BraceToken, "}");
						break;
					}
					default:
					{
						if (auto unicode = GetFunction()->GetView()->StringifyUnicodeData(instr.function->GetArchitecture(), db); unicode.has_value())
						{
							auto wideStringPrefix = (builtin == BuiltinWcscpy) ? "L" : "";
							auto tokenContext = (builtin == BuiltinWcscpy) ? ConstStringDataTokenContext : ConstDataTokenContext;
							tokens.Append(BraceToken, wideStringPrefix + string("\""));
							tokens.Append(StringToken, tokenContext, unicode.value().first, instr.address, data.value);
							tokens.Append(BraceToken, "\"");
						}
						else
						{
							string result(db.ToEscapedString(false, true));

							tokens.Append(BraceToken, "\"");
							tokens.Append(StringToken, ConstDataTokenContext, result, instr.address, data.value);
							tokens.Append(BraceToken, "\"");
							// TODO controls for emitting an initializer list?
							// char str[32];
							// string result;
							// const uint8_t* bytes = (const uint8_t*)db.GetData();
							// for (size_t i = 0; i < db.GetLength(); i++)
							// {
							// 	snprintf(str, sizeof(str), "0x%" PRIx8 ", ", bytes[i]);
							// 	result += str;
							// }
							// if (result.size() > 2)
							// 	result.erase(result.end() - 2);
							// tokens.Append(StringToken, StringDisplayTokenContext, string("{ ") + result + string(" }"), instr.address, bytes.value);
						}
						break;
					}
				}
			}
			else
				tokens.Append(StringToken, StringDisplayTokenContext, string("<invalid constant data>"), instr.address, data.value);

			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CONST_PTR:
		[&]() {
			tokens.AppendPointerTextToken(
				instr, instr.GetConstant<HLIL_CONST_PTR>(), settings, AddressOfDataSymbols, precedence);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_VAR:
		[&]() {
			const auto variable = instr.GetVariable<HLIL_VAR>();
			const auto variableName = GetHighLevelILFunction()->GetFunction()->GetVariableNameOrDefault(variable);
			tokens.Append(LocalVariableToken, LocalVariableTokenContext, variableName,
						  instr.exprIndex, variable.ToIdentifier(), instr.size);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ASSIGN:
		[&]() {
			const auto destExpr = instr.GetDestExpr<HLIL_ASSIGN>();
			const auto srcExpr = instr.GetSourceExpr<HLIL_ASSIGN>();

			// Check to see if the variable appears live
			bool appearsDead = false;
			if (destExpr.operation == HLIL_VAR_SSA)
			{
				const auto ssaForm = destExpr.GetSSAVariable<HLIL_VAR_SSA>();
				appearsDead = !GetHighLevelILFunction()->IsSSAVarLive(ssaForm);
			}
			else if (destExpr.operation == HLIL_VAR)
			{
				if (const auto ssaForm = destExpr.GetSSAForm(); ssaForm.operation == HLIL_VAR_SSA)
				{
					const auto ssaDest = ssaForm.GetSSAVariable<HLIL_VAR_SSA>();
					appearsDead = !GetHighLevelILFunction()->IsSSAVarLive(ssaDest);
				}
			}

			// If the variable does not appear live, show the assignment as zero confidence (grayed out)
			if (appearsDead)
				tokens.BeginForceZeroConfidence();

			std::optional<string> assignUpdateOperator;
			std::optional<HighLevelILInstruction> assignUpdateSource;
			bool assignUpdateNegate = false;
			const auto isSplit = destExpr.operation == HLIL_SPLIT;
			std::optional<bool> assignSignHint;
			if (isSplit)
			{
				const auto high = destExpr.GetHighExpr<HLIL_SPLIT>();
				const auto low = destExpr.GetLowExpr<HLIL_SPLIT>();

				GetExprText(high, tokens, settings, asFullAst, precedence);
				tokens.Append(OperationToken, " = ");
				tokens.Append(OperationToken, "HIGH");
				AppendSingleSizeToken(high.size, OperationToken, tokens);
				tokens.AppendOpenParen();
				GetExprText(srcExpr, tokens, settings, asFullAst, precedence);
				tokens.AppendCloseParen();
				tokens.AppendSemicolon();
				tokens.NewLine();
				GetExprText(low, tokens, settings, asFullAst, precedence);
			}
			else
			{
				// Check for assignment with an operator on the same variable as the destination
				// (for example, `a = a + 2` should be shown as `a += 2`)
				if ((srcExpr.operation == HLIL_ADD || srcExpr.operation == HLIL_SUB || srcExpr.operation == HLIL_MUL
						|| srcExpr.operation == HLIL_DIVU || srcExpr.operation == HLIL_DIVS
						|| srcExpr.operation == HLIL_LSL || srcExpr.operation == HLIL_LSR
						|| srcExpr.operation == HLIL_ASR || (instr.size != 0 && srcExpr.operation == HLIL_AND)
						|| (instr.size != 0 && srcExpr.operation == HLIL_OR)
						|| (instr.size != 0 && srcExpr.operation == HLIL_XOR))
					&& (srcExpr.GetLeftExpr() == destExpr))
				{
					auto lessThanZero = [](uint64_t value, uint64_t width) -> bool {
						return ((1UL << ((width * 8) - 1UL)) & value) != 0;
					};
					switch (srcExpr.operation)
					{
					case HLIL_ADD:
						assignUpdateOperator = " += ";
						assignUpdateSource = srcExpr.GetRightExpr();

						if ((assignUpdateSource.value().operation == HLIL_CONST)
							&& lessThanZero(
								assignUpdateSource.value().GetConstant<HLIL_CONST>(), assignUpdateSource.value().size)
							&& assignUpdateSource.value().size >= instr.size)
						{
							// Convert addition of a negative constant into subtraction of a positive constant
							assignUpdateOperator = " -= ";
							assignUpdateNegate = true;
						}
						break;
					case HLIL_SUB:
						assignUpdateOperator = " -= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						break;
					case HLIL_MUL:
						assignUpdateOperator = " *= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						break;
					case HLIL_DIVU:
						assignUpdateOperator = " /= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						assignSignHint = false;
						break;
					case HLIL_DIVS:
						assignUpdateOperator = " /= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						assignSignHint = false;
						break;
					case HLIL_LSL:
						assignUpdateOperator = " <<= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						break;
					case HLIL_LSR:
						assignUpdateOperator = " >>= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						break;
					case HLIL_ASR:
						assignUpdateOperator = " >>= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						break;
					case HLIL_AND:
						assignUpdateOperator = " &= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						break;
					case HLIL_OR:
						assignUpdateOperator = " |= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						break;
					case HLIL_XOR:
						assignUpdateOperator = " ^= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						break;
					default:
						break;
					}
				}
				else if (
					(srcExpr.operation == HLIL_ADD || srcExpr.operation == HLIL_MUL
						|| (instr.size != 0 && srcExpr.operation == HLIL_AND)
						|| (instr.size != 0 && srcExpr.operation == HLIL_OR)
						|| (instr.size != 0 && srcExpr.operation == HLIL_XOR))
					&& (srcExpr.GetRightExpr() == destExpr))
				{
					switch (srcExpr.operation)
					{
					case HLIL_ADD:
						assignUpdateOperator = " += ";
						assignUpdateSource = srcExpr.GetLeftExpr();
						break;
					case HLIL_MUL:
						assignUpdateOperator = " *= ";
						assignUpdateSource = srcExpr.GetLeftExpr();
						break;
					case HLIL_AND:
						assignUpdateOperator = " &= ";
						assignUpdateSource = srcExpr.GetLeftExpr();
						break;
					case HLIL_OR:
						assignUpdateOperator = " |= ";
						assignUpdateSource = srcExpr.GetLeftExpr();
						break;
					case HLIL_XOR:
						assignUpdateOperator = " ^= ";
						assignUpdateSource = srcExpr.GetLeftExpr();
						break;
					default:
						break;
					}
				}
			}

			GetExprText(destExpr, tokens, settings, asFullAst, precedence);
			if (assignUpdateOperator.has_value() && assignUpdateSource.has_value())
				tokens.Append(OperationToken, assignUpdateOperator.value());
			else
				tokens.Append(OperationToken, " = ");

			// For the right side of the assignment, only use zero confidence if the instruction does
			// not have any side effects
			if (appearsDead && GetHighLevelILFunction()->HasSideEffects(srcExpr))
			{
				tokens.EndForceZeroConfidence();
				appearsDead = false;
			}

			if (isSplit)
			{
//				const auto high = destExpr.GetHighExpr<HLIL_SPLIT>();
				const auto low = destExpr.GetLowExpr<HLIL_SPLIT>();

				tokens.Append(OperationToken, "LOW");
				AppendSingleSizeToken(low.size, OperationToken, tokens);
				tokens.AppendOpenParen();
			}

			if (assignUpdateOperator.has_value() && assignUpdateSource.has_value())
			{
				if (assignUpdateNegate)
				{
					tokens.AppendIntegerTextToken(assignUpdateSource.value(),
						-BNSignExtend(
							assignUpdateSource.value().GetConstant<HLIL_CONST>(), assignUpdateSource.value().size, 8),
						assignUpdateSource.value().size);
				}
				else
				{
					GetExprText(assignUpdateSource.value(), tokens, settings, asFullAst, AssignmentOperatorPrecedence,
						InnerExpression, assignSignHint);
				}
			}
			else
			{
				GetExprText(srcExpr, tokens, settings, asFullAst, AssignmentOperatorPrecedence, InnerExpression,
					assignSignHint);
			}

			if (isSplit)
				tokens.AppendCloseParen();

			if (appearsDead)
				tokens.EndForceZeroConfidence();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ASSIGN_UNPACK:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_ASSIGN_UNPACK>();
			const auto destExprs = instr.GetDestExprs<HLIL_ASSIGN_UNPACK>();
			const auto firstExpr = destExprs[0];

			GetExprText(firstExpr, tokens, settings, asFullAst, AssignmentOperatorPrecedence);
			tokens.Append(OperationToken, " = ");
			GetExprText(srcExpr, tokens, settings, asFullAst, AssignmentOperatorPrecedence);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_STRUCT_FIELD:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_STRUCT_FIELD>();
			const auto fieldOffset = instr.GetOffset<HLIL_STRUCT_FIELD>();
			const auto memberIndex = instr.GetMemberIndex<HLIL_STRUCT_FIELD>();

			const auto type = GetFieldType(srcExpr, false);
			const auto fieldDisplayType = GetFieldDisplayType(type, fieldOffset, memberIndex, false);
			if (fieldDisplayType == FieldDisplayOffset)
			{
				tokens.Append(OperationToken, "*");
				if (!settings || settings->IsOptionSet(ShowTypeCasts))
					tokens.AppendOpenParen();

				GetExprText(srcExpr, tokens, settings, true, MemberAndFunctionOperatorPrecedence);

				tokens.Append(TextToken, ".");
				tokens.Append(OperationToken, "byte_offset");
				tokens.AppendOpenParen();
				tokens.AppendIntegerTextToken(instr, fieldOffset, instr.size);
				tokens.AppendCloseParen();

				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.Append(KeywordToken, " as ");
					tokens.Append(TextToken, "*");
					Ref<Type> srcType = srcExpr.GetType();
					if (srcType && srcType->IsPointer() && srcType->GetChildType()->IsConst())
						tokens.Append(KeywordToken, "const ");
					else
						tokens.Append(KeywordToken, "mut ");
					AppendSizeToken(!instr.size ? srcExpr.size : instr.size, false, tokens);
					tokens.AppendCloseParen();
				}

				char offsetStr[64];
				snprintf(offsetStr, sizeof(offsetStr), "0x%" PRIx64, fieldOffset);

				vector<string> nameList { offsetStr };
				HighLevelILTokenEmitter::AddNamesForOuterStructureMembers(
					GetFunction()->GetView(), type, srcExpr, nameList);
			}
			else if (fieldDisplayType == FieldDisplayMemberOffset)
			{
				tokens.Append(OperationToken, "*");
				BNOperatorPrecedence srcPrecedence = UnaryOperatorPrecedence;
				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.AppendOpenParen();
					srcPrecedence = LowUnaryOperatorPrecedence;
				}
				GetExprText(srcExpr, tokens, settings, true, srcPrecedence);
				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.Append(KeywordToken, " as ");
					tokens.Append(TextToken, "*");
					Ref<Type> srcType = srcExpr.GetType();
					if (srcType && srcType->IsPointer() && srcType->GetChildType()->IsConst())
						tokens.Append(KeywordToken, "const ");
					else
						tokens.Append(KeywordToken, "mut ");
					AppendSizeToken(!instr.size ? srcExpr.size : instr.size, false, tokens);
					tokens.AppendCloseParen();
				}
				/* rest is rendered in AppendFieldTextTokens */
			}
			else
			{
				GetExprText(srcExpr, tokens, settings, true, MemberAndFunctionOperatorPrecedence);
			}

			AppendFieldTextTokens(srcExpr, fieldOffset, memberIndex, instr.size, tokens, false);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_DEREF:
		[&]() {
			auto srcExpr = instr.GetSourceExpr<HLIL_DEREF>();

			auto appendMaybeBrace = [&](const InstructionTextToken& token)
			{
				if (token.type == BraceToken)
				{
					if (token.text == "(")
						tokens.AppendOpenParen();
					else if (token.text == ")")
						tokens.AppendCloseParen();
					else if (token.text == "[")
						tokens.AppendOpenBracket();
					else if (token.text == "]")
						tokens.AppendCloseBracket();
					else if (token.text == "{")
						tokens.AppendOpenBrace();
					else if (token.text == "}")
						tokens.AppendCloseBrace();
					else
						tokens.Append(token);
				}
				else
				{
					tokens.Append(token);
				}
			};

			if (srcExpr.operation == HLIL_CONST_PTR)
			{
				const auto constant = srcExpr.GetConstant<HLIL_CONST_PTR>();

				const auto type = srcExpr.GetType();
				BNOperatorPrecedence srcPrecedence = UnaryOperatorPrecedence;
				if (type && type->GetClass() == PointerTypeClass && instr.size != type->GetChildType()->GetWidth() &&
					(!settings || settings->IsOptionSet(ShowTypeCasts)))
					srcPrecedence = LowUnaryOperatorPrecedence;

				vector<InstructionTextToken> pointerTokens{};
				if (AppendPointerTextToken(srcExpr, constant, pointerTokens, settings, DereferenceNonDataSymbols, srcPrecedence) == DataSymbolResult)
				{
					if (type && type->GetClass() == PointerTypeClass && instr.size != type->GetChildType()->GetWidth())
					{
						tokens.Append(OperationToken, "*");
						if (!settings || settings->IsOptionSet(ShowTypeCasts))
							tokens.AppendOpenParen();

						for (const auto& token : pointerTokens)
						{
							appendMaybeBrace(token);
						}

						if (!settings || settings->IsOptionSet(ShowTypeCasts))
						{
							tokens.Append(KeywordToken, " as ");
							tokens.Append(TextToken, "*");
							Ref<Type> srcType = srcExpr.GetType();
							if (srcType && srcType->IsPointer() && srcType->GetChildType()->IsConst())
								tokens.Append(KeywordToken, "const ");
							else
								tokens.Append(KeywordToken, "mut ");
							AppendSizeToken(instr.size, false, tokens);
							tokens.AppendCloseParen();
						}
					}
					else
					{
						for (const auto& token : pointerTokens)
						{
							appendMaybeBrace(token);
						}
					}
				}
				else
				{
					for (const auto& token : pointerTokens)
					{
						appendMaybeBrace(token);
					}
				}
			}
			else
			{
				vector<bool> derefConst;
				Ref<Type> srcType = srcExpr.GetType().GetValue();
				derefConst.push_back(srcType && srcType->IsPointer() && srcType->GetChildType()->IsConst());
				while (srcExpr.operation == HLIL_DEREF)
				{
					auto next = srcExpr.GetSourceExpr<HLIL_DEREF>();
					if (next.size == srcExpr.size)
					{
						srcType = srcExpr.GetType().GetValue();
						derefConst.push_back(srcType && srcType->IsPointer() && srcType->GetChildType()->IsConst());
						srcExpr = srcExpr.GetSourceExpr<HLIL_DEREF>();
					}
					else
					{
						break;
					}
				}

				bool parens = precedence > UnaryOperatorPrecedence;
				if (parens)
					tokens.AppendOpenParen();
				for (size_t index = 0; index < derefConst.size(); index++)
					tokens.Append(OperationToken, "*");

				BNOperatorPrecedence srcPrecedence = UnaryOperatorPrecedence;
				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.AppendOpenParen();
					srcPrecedence = LowUnaryOperatorPrecedence;
				}

				GetExprText(srcExpr, tokens, settings, asFullAst, srcPrecedence);

				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.Append(KeywordToken, " as ");
					for (auto isConst : derefConst)
					{
						tokens.Append(TextToken, "*");
						tokens.Append(KeywordToken, isConst ? "const ": "mut ");
					}
					AppendSizeToken(instr.size, false, tokens);

					tokens.AppendCloseParen();
				}

				if (parens)
					tokens.AppendCloseParen();
			}

			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_TAILCALL:
		[&]() {
			const auto destExpr = instr.GetDestExpr<HLIL_TAILCALL>();
			const auto parameterExprs = instr.GetParameterExprs<HLIL_TAILCALL>();

			tokens.Append(AnnotationToken, "/* tailcall */");
			tokens.NewLine();
			if (exprType != TrailingStatementExpression)
				tokens.Append(KeywordToken, "return ");
			GetExprText(destExpr, tokens, settings, asFullAst, MemberAndFunctionOperatorPrecedence);
			tokens.AppendOpenParen();
			for (size_t index{}; index < parameterExprs.size(); index++)
			{
				const auto& parameterExpr = parameterExprs[index];
				if (index != 0) tokens.Append(TextToken, ", ");
				GetExprText(parameterExpr, tokens, settings, asFullAst);
			}
			tokens.AppendCloseParen();
			if (exprType == StatementExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ADDRESS_OF:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_ADDRESS_OF>();
			bool parens = precedence > UnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			tokens.Append(OperationToken, "&");
			GetExprText(srcExpr, tokens, settings, asFullAst, UnaryOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_E:
	case HLIL_CMP_E:
		[&]() {
			bool parens = precedence > EqualityOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendComparison(" == ", instr, tokens, settings, asFullAst, EqualityOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_NE:
	case HLIL_CMP_NE:
		[&]() {
			bool parens = precedence > EqualityOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendComparison(" != ", instr, tokens, settings, asFullAst, EqualityOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_LT:
	case HLIL_CMP_SLT:
	case HLIL_CMP_ULT:
		[&]() {
			bool parens = precedence > CompareOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			std::optional<bool> cmpSigned;
			if (instr.operation == HLIL_CMP_ULT)
				cmpSigned = false;
			else if (instr.operation == HLIL_CMP_SLT)
				cmpSigned = true;
			AppendComparison(" < ", instr, tokens, settings, asFullAst, CompareOperatorPrecedence, cmpSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_LE:
	case HLIL_CMP_SLE:
	case HLIL_CMP_ULE:
		[&]() {
			bool parens = precedence > CompareOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			std::optional<bool> cmpSigned;
			if (instr.operation == HLIL_CMP_ULE)
				cmpSigned = false;
			else if (instr.operation == HLIL_CMP_SLE)
				cmpSigned = true;
			AppendComparison(" <= ", instr, tokens, settings, asFullAst, CompareOperatorPrecedence, cmpSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_GE:
	case HLIL_CMP_SGE:
	case HLIL_CMP_UGE:
		[&]() {
			bool parens = precedence > CompareOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			std::optional<bool> cmpSigned;
			if (instr.operation == HLIL_CMP_UGE)
				cmpSigned = false;
			else if (instr.operation == HLIL_CMP_SGE)
				cmpSigned = true;
			AppendComparison(" >= ", instr, tokens, settings, asFullAst, CompareOperatorPrecedence, cmpSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_GT:
	case HLIL_CMP_SGT:
	case HLIL_CMP_UGT:
		[&]() {
			bool parens = precedence > CompareOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			std::optional<bool> cmpSigned;
			if (instr.operation == HLIL_CMP_UGT)
				cmpSigned = false;
			else if (instr.operation == HLIL_CMP_SGT)
				cmpSigned = true;
			AppendComparison(" > ", instr, tokens, settings, asFullAst, CompareOperatorPrecedence, cmpSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;


	case HLIL_AND:
		[&]() {
			bool parens = instr.size == 0 ?
				precedence >= BitwiseOrOperatorPrecedence || precedence == LogicalOrOperatorPrecedence :
				precedence >= EqualityOperatorPrecedence || precedence == BitwiseOrOperatorPrecedence ||
					precedence == BitwiseXorOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(instr.size == 0 ? " && " : " & ", instr, tokens, settings, asFullAst,
				instr.size == 0 ? LogicalAndOperatorPrecedence : BitwiseAndOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_OR:
		[&]() {
			bool parens = (instr.size == 0) ?
				precedence >= BitwiseOrOperatorPrecedence || precedence == LogicalAndOperatorPrecedence :
				precedence >= EqualityOperatorPrecedence || precedence == BitwiseAndOperatorPrecedence ||
					precedence == BitwiseXorOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(instr.size == 0 ? " || " : " | ", instr, tokens, settings, asFullAst,
				instr.size == 0 ? LogicalOrOperatorPrecedence : BitwiseOrOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_XOR:
		[&]() {
			bool parens = precedence >= EqualityOperatorPrecedence || precedence == BitwiseAndOperatorPrecedence ||
				precedence == BitwiseOrOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" ^ ", instr, tokens, settings, asFullAst, BitwiseXorOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ADC:
	case HLIL_ADD_OVERFLOW:
	case HLIL_FADD:
	case HLIL_ADD:
		[&]() {
			const auto leftType = instr.GetLeftExpr().GetType();
			bool parens;
			BNOperatorPrecedence opPrecedence = AddOperatorPrecedence;
			if (leftType && leftType->IsPointer())
			{
				parens = false;
				opPrecedence = MemberAndFunctionOperatorPrecedence;
			}
			else
			{
				parens = precedence > AddOperatorPrecedence || precedence == ShiftOperatorPrecedence ||
					precedence == BitwiseAndOperatorPrecedence || precedence == BitwiseOrOperatorPrecedence ||
					precedence == BitwiseXorOperatorPrecedence;
			}

			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" + ", instr, tokens, settings, asFullAst, opPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_SUB:
		[&]{
			// Check for offset pointers
			auto left = instr.GetLeftExpr<HLIL_SUB>();
			auto right = instr.GetRightExpr<HLIL_SUB>();
			if (left.operation == HLIL_VAR && right.operation == HLIL_CONST)
			{
				auto var = left.GetVariable<HLIL_VAR>();
				auto srcOffset = right.GetConstant<HLIL_CONST>();
				auto varType = GetFunction()->GetVariableType(var);
				if (varType
					&& varType->GetClass() == PointerTypeClass
					&& varType->GetNamedTypeReference()
					&& varType->GetOffset() == srcOffset)
				{
					// Yes
					tokens.Append(OperationToken, "ADJ");
					tokens.AppendOpenParen();
					GetExprText(left, tokens, settings, true, MemberAndFunctionOperatorPrecedence);
					tokens.AppendCloseParen();
					return;
				}
			}

			const auto leftType = instr.GetLeftExpr().GetType();
			bool parens;
			BNOperatorPrecedence opPrecedence = SubOperatorPrecedence;
			if (leftType && leftType->IsPointer())
			{
				parens = false;
				opPrecedence = MemberAndFunctionOperatorPrecedence;
			}
			else
			{
				parens = precedence > AddOperatorPrecedence || precedence == ShiftOperatorPrecedence ||
					precedence == BitwiseAndOperatorPrecedence || precedence == BitwiseOrOperatorPrecedence ||
					precedence == BitwiseXorOperatorPrecedence;
			}

			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" - ", instr, tokens, settings, asFullAst, opPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;
	case HLIL_SBB:
	case HLIL_FSUB:
		[&]() {
			bool parens = precedence > AddOperatorPrecedence || precedence == ShiftOperatorPrecedence ||
				precedence == BitwiseAndOperatorPrecedence || precedence == BitwiseOrOperatorPrecedence ||
				precedence == BitwiseXorOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" - ", instr, tokens, settings, asFullAst, SubOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_LSL:
		[&]() {
			bool parens = precedence > ShiftOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" << ", instr, tokens, settings, asFullAst, ShiftOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_LSR:
	case HLIL_ASR:
		[&]() {
			bool parens = precedence > ShiftOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" >> ", instr, tokens, settings, asFullAst, ShiftOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;


	case HLIL_FMUL:
	case HLIL_MUL:
	case HLIL_MULU_DP:
	case HLIL_MULS_DP:
		[&]() {
			bool parens = precedence > MultiplyOperatorPrecedence || precedence == ShiftOperatorPrecedence ||
				precedence == BitwiseAndOperatorPrecedence || precedence == BitwiseOrOperatorPrecedence ||
				precedence == BitwiseXorOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			std::optional<bool> mulSigned;
			if (instr.operation == HLIL_MULU_DP)
				mulSigned = false;
			else if (instr.operation == HLIL_MULS_DP)
				mulSigned = true;
			AppendTwoOperand(" * ", instr, tokens, settings, asFullAst, MultiplyOperatorPrecedence, mulSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FDIV:
	case HLIL_DIVU:
	case HLIL_DIVU_DP:
	case HLIL_DIVS:
	case HLIL_DIVS_DP:
		[&]() {
			bool parens = precedence > MultiplyOperatorPrecedence || precedence == ShiftOperatorPrecedence
				|| precedence == BitwiseAndOperatorPrecedence || precedence == BitwiseOrOperatorPrecedence
				|| precedence == BitwiseXorOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			std::optional<bool> divSigned;
			if (instr.operation == HLIL_DIVU || instr.operation == HLIL_DIVU_DP)
				divSigned = false;
			else if (instr.operation == HLIL_DIVS || instr.operation == HLIL_DIVS_DP)
				divSigned = true;
			AppendTwoOperand(" / ", instr, tokens, settings, asFullAst, DivideOperatorPrecedence, divSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_MODU:
	case HLIL_MODU_DP:
	case HLIL_MODS:
	case HLIL_MODS_DP:
		[&]() {
			bool parens = precedence > MultiplyOperatorPrecedence || precedence == ShiftOperatorPrecedence
				|| precedence == BitwiseAndOperatorPrecedence || precedence == BitwiseOrOperatorPrecedence
				|| precedence == BitwiseXorOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			std::optional<bool> modSigned;
			if (instr.operation == HLIL_MODU || instr.operation == HLIL_MODU_DP)
				modSigned = false;
			else if (instr.operation == HLIL_MODS || instr.operation == HLIL_MODS_DP)
				modSigned = true;
			AppendTwoOperand(" % ", instr, tokens, settings, asFullAst, DivideOperatorPrecedence, modSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;


	case HLIL_ROR:
		[&]() {
			AppendTwoOperandMethodCall("rotate_right", instr, tokens, settings);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ROL:
		[&]() {
			AppendTwoOperandMethodCall("rotate_left", instr, tokens, settings);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_RLC:
		[&]() {
			AppendTwoOperandFunctionWithCarry("RLC", instr, tokens, settings);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_RRC:
		[&]() {
			AppendTwoOperandFunctionWithCarry("RRC", instr, tokens, settings);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_TEST_BIT:
		[&]() {
			AppendTwoOperandFunction("TEST_BIT", instr, tokens, settings);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FLOOR:
		[&]() {
			GetExprText(instr.GetSourceExpr<HLIL_FLOOR>(), tokens, settings, MemberAndFunctionOperatorPrecedence);
			tokens.Append(TextToken, ".");
			tokens.Append(OperationToken, "floor");
			tokens.AppendOpenParen();
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CEIL:
		[&]() {
			GetExprText(instr.GetSourceExpr<HLIL_CEIL>(), tokens, settings, MemberAndFunctionOperatorPrecedence);
			tokens.Append(TextToken, ".");
			tokens.Append(OperationToken, "ceil");
			tokens.AppendOpenParen();
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FTRUNC:
		[&]() {
			GetExprText(instr.GetSourceExpr<HLIL_FTRUNC>(), tokens, settings, MemberAndFunctionOperatorPrecedence);
			tokens.Append(TextToken, ".");
			tokens.Append(OperationToken, "trunc");
			tokens.AppendOpenParen();
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FABS:
		[&]() {
			GetExprText(instr.GetSourceExpr<HLIL_FABS>(), tokens, settings, MemberAndFunctionOperatorPrecedence);
			tokens.Append(TextToken, ".");
			tokens.Append(OperationToken, "abs");
			tokens.AppendOpenParen();
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FSQRT:
		[&]() {
			GetExprText(instr.GetSourceExpr<HLIL_FSQRT>(), tokens, settings, MemberAndFunctionOperatorPrecedence);
			tokens.Append(TextToken, ".");
			tokens.Append(OperationToken, "sqrt");
			tokens.AppendOpenParen();
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ROUND_TO_INT:
		[&]() {
			GetExprText(instr.GetSourceExpr<HLIL_ROUND_TO_INT>(), tokens, settings, MemberAndFunctionOperatorPrecedence);
			tokens.Append(TextToken, ".");
			tokens.Append(OperationToken, "round");
			tokens.AppendOpenParen();
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_O:
		[&]() {
			AppendTwoOperandFunction("FCMP_O", instr, tokens, settings, false);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_UO:
		[&]() {
			AppendTwoOperandFunction("FCMP_UO", instr, tokens, settings, false);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;


	case HLIL_NOT:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_NOT>();
			bool parens = precedence > UnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			tokens.Append(OperationToken, "!");
			GetExprText(srcExpr, tokens, settings, UnaryOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FNEG:
	case HLIL_NEG:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr();
			bool parens = precedence > UnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			tokens.Append(OperationToken, "-");
			tokens.AppendOpenParen();
			GetExprText(srcExpr, tokens, settings, asFullAst, UnaryOperatorPrecedence, InnerExpression, true);
			tokens.AppendCloseParen();
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FLOAT_CONV:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_FLOAT_CONV>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprText(srcExpr, tokens, settings, asFullAst, precedence);
				return;
			}
			const auto floatType = "f" + std::to_string(instr.size * 8);

			bool parens = precedence > LowUnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			GetExprText(srcExpr, tokens, settings, asFullAst, LowUnaryOperatorPrecedence);
			tokens.Append(KeywordToken, " as ");
			tokens.Append(TypeNameToken, floatType.c_str());
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FLOAT_TO_INT:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_FLOAT_TO_INT>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprText(srcExpr, tokens, settings, asFullAst, precedence);
				return;
			}

			bool parens = precedence > LowUnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			GetExprText(srcExpr, tokens, settings, asFullAst, LowUnaryOperatorPrecedence);
			tokens.Append(KeywordToken, " as ");
			AppendSizeToken(instr.size, true, tokens);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_BOOL_TO_INT:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_BOOL_TO_INT>();

			bool parens = precedence > LowUnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			GetExprText(srcExpr, tokens, settings, asFullAst, LowUnaryOperatorPrecedence);
			tokens.Append(KeywordToken, " as ");
			AppendSizeToken(instr.size, true, tokens);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_INT_TO_FLOAT:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_INT_TO_FLOAT>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprText(srcExpr, tokens, settings, asFullAst, precedence);
				return;
			}
			const auto floatType = "f" + std::to_string(instr.size * 8);

			bool parens = precedence > LowUnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			GetExprText(srcExpr, tokens, settings, asFullAst, LowUnaryOperatorPrecedence);
			tokens.Append(KeywordToken, " as ");
			tokens.Append(TypeNameToken, floatType.c_str());
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_INTRINSIC:
		[&]() {
			const auto intrinsic = instr.GetIntrinsic<HLIL_INTRINSIC>();
			const auto intrinsicName = GetHighLevelILFunction()->GetArchitecture()->GetIntrinsicName(intrinsic);
			const auto parameterExprs = instr.GetParameterExprs<HLIL_INTRINSIC>();

			tokens.Append(KeywordToken, intrinsicName, intrinsic);
			tokens.AppendOpenParen();
			for (size_t index{}; index < parameterExprs.size(); index++)
			{
				const auto& parameterExpr = parameterExprs[index];
				if (index != 0) tokens.Append(TextToken, ", ");
				GetExprText(parameterExpr, tokens, settings, asFullAst);
			}
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_RET:
		[&]() {
			const auto srcExprs = instr.GetSourceExprs<HLIL_RET>();

			if (!asFullAst || exprType != TrailingStatementExpression)
				tokens.Append(KeywordToken, "return");
			if (srcExprs.size() != 0)
			{
				if (!asFullAst || exprType != TrailingStatementExpression)
					tokens.Append(TextToken, " ");
				if (srcExprs.size() > 1)
					tokens.AppendOpenParen();
				for (size_t index = 0; index < srcExprs.size(); index++)
				{
					const auto& srcExpr = srcExprs[index];
					if (index != 0)
						tokens.Append(TextToken, ", ");
					GetExprText(srcExpr, tokens, settings, asFullAst);
				}
				if (srcExprs.size() > 1)
					tokens.AppendCloseParen();
			}
			if (exprType == StatementExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_NORET:
		[&]() {
			tokens.Append(AnnotationToken, "/* no return */");
		}();
		break;

	case HLIL_UNREACHABLE:
		[&]() {
			tokens.Append(AnnotationToken, "/* unreachable */");
		}();
		break;

	case HLIL_JUMP:
		[&]() {
			const auto destExpr = instr.GetDestExpr<HLIL_JUMP>();
			tokens.Append(AnnotationToken, "/* jump -> ");
			GetExprText(destExpr, tokens, settings);
			tokens.Append(AnnotationToken, " */");
		}();
		break;

	case HLIL_UNDEF:
		[&]() {
			tokens.Append(AnnotationToken, "/* undefined */");
		}();
		break;

	case HLIL_TRAP:
		[&]() {
			const auto vector = instr.GetVector<HLIL_TRAP>();
			tokens.Append(KeywordToken, "trap");
			tokens.AppendOpenParen();
			tokens.AppendIntegerTextToken(instr, vector, 8);
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_DEREF_FIELD:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_DEREF_FIELD>();
			const auto offset = instr.GetOffset<HLIL_DEREF_FIELD>();
			const auto memberIndex = instr.GetMemberIndex<HLIL_DEREF_FIELD>();
			auto type = srcExpr.GetType().GetValue();

			if (type && (type->GetClass() == PointerTypeClass))
				type = type->GetChildType().GetValue();

			if (type && (type->GetClass() == NamedTypeReferenceClass))
				type = GetFunction()->GetView()->GetTypeByRef(type->GetNamedTypeReference());

			bool derefOffset = false;
			if (type && (type->GetClass() == StructureTypeClass))
			{
				std::optional<size_t> memberIndexHint;
				if (memberIndex != BN_INVALID_EXPR)
					memberIndexHint = memberIndex;

				bool outer = true;
				if (type->GetStructure()->ResolveMemberOrBaseMember(GetFunction()->GetView(), offset, 0,
						[&](NamedTypeReference*, Structure* s, size_t memberIndex, uint64_t structOffset,
							uint64_t adjustedOffset, const StructureMember& member) {
							BNSymbolDisplayResult symbolType;
							if (srcExpr.operation == HLIL_CONST_PTR)
							{
								const auto constant = srcExpr.GetConstant<HLIL_CONST_PTR>();
								symbolType = tokens.AppendPointerTextToken(
									srcExpr, constant, settings, DisplaySymbolOnly, precedence);
							}
							else
							{
								GetExprText(srcExpr, tokens, settings, true, MemberAndFunctionOperatorPrecedence);
								symbolType = OtherSymbolResult;
							}

							const auto displayDeref = symbolType != DataSymbolResult;
							if (displayDeref && outer)
								tokens.Append(OperationToken, "->");
							else
								tokens.Append(OperationToken, ".");
							outer = false;

							vector<string> nameList {member.name};
							HighLevelILTokenEmitter::AddNamesForOuterStructureMembers(
								GetFunction()->GetView(), type, srcExpr, nameList);

							tokens.Append(FieldNameToken, member.name, structOffset + member.offset, 0, 0,
								BN_FULL_CONFIDENCE, nameList);
						}),
					memberIndexHint)
					return;
			}
			else if (type && (type->GetClass() == StructureTypeClass))
			{
				derefOffset = true;
			}

			if (derefOffset || offset != 0)
			{
				bool parens = precedence > UnaryOperatorPrecedence;
				if (parens)
					tokens.AppendOpenParen();

				tokens.Append(OperationToken, "*");
				if (!settings || settings->IsOptionSet(ShowTypeCasts))
					tokens.AppendOpenParen();

				if (srcExpr.operation == HLIL_CONST_PTR)
				{
					const auto constant = srcExpr.GetConstant<HLIL_CONST_PTR>();
					tokens.AppendPointerTextToken(srcExpr, constant, settings, DisplaySymbolOnly, precedence);
				}
				else
				{
					GetExprText(srcExpr, tokens, settings, true, MemberAndFunctionOperatorPrecedence);
				}

				tokens.Append(TextToken, ".");
				tokens.Append(OperationToken, "byte_offset");
				tokens.AppendOpenParen();
				tokens.AppendIntegerTextToken(instr, offset, instr.size);
				tokens.AppendCloseParen();

				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.Append(KeywordToken, " as ");
					tokens.Append(TextToken, "*");
					Ref<Type> srcType = srcExpr.GetType();
					if (srcType && srcType->IsPointer() && srcType->GetChildType()->IsConst())
						tokens.Append(KeywordToken, "const ");
					else
						tokens.Append(KeywordToken, "mut ");
					AppendSizeToken(!derefOffset ? srcExpr.size : instr.size, true, tokens);
					tokens.AppendCloseParen();
				}

				if (parens)
					tokens.AppendCloseParen();
			}

			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_EXTERN_PTR:
		[&]() {
			const int64_t val = instr.GetOffset<HLIL_EXTERN_PTR>();
			if (val != 0)
				tokens.AppendOpenParen();
			tokens.AppendPointerTextToken(
				instr, instr.GetConstant<HLIL_EXTERN_PTR>(), settings, AddressOfDataSymbols, precedence);
			if (val != 0)
			{
				char valStr[32];
				if (val >= 0)
				{
					tokens.Append(OperationToken, " + ");
					if (val <= 9)
						snprintf(valStr, sizeof(valStr), "%" PRIx64, val);
					else
						snprintf(valStr, sizeof(valStr), "0x%" PRIx64, val);
				}
				else
				{
					tokens.Append(OperationToken, " - ");
					if (val >= -9)
						snprintf(valStr, sizeof(valStr), "%" PRIx64, -val);
					else
						snprintf(valStr, sizeof(valStr), "0x%" PRIx64, -val);
				}
				tokens.Append(IntegerToken, valStr, val);
				tokens.AppendCloseParen();
			}

			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_SYSCALL:
		[&]() {
			tokens.Append(KeywordToken, "syscall");
			tokens.AppendOpenParen();
			const auto operandList = instr.GetParameterExprs<HLIL_SYSCALL>();
			vector<FunctionParameter> namedParams;
			bool skipSyscallNumber = false;
			if (GetFunction() && (operandList.size() > 0) && (operandList[0].operation == HLIL_CONST))
			{
				const auto platform = GetFunction()->GetPlatform();
				if (platform)
				{
					const auto syscall = (uint32_t)operandList[0].GetConstant<HLIL_CONST>();
					const auto syscallName = platform->GetSystemCallName(syscall);
					if (settings && settings->GetCallParameterHints() != NeverShowParameterHints)
					{
						const auto functionType = platform->GetSystemCallType(syscall);
						if (functionType && (functionType->GetClass() == FunctionTypeClass))
							namedParams = functionType->GetParameters();
					}
					if (syscallName.length())
					{
						tokens.Append(TextToken, syscallName);
						tokens.Append(TextToken, " ");
						tokens.AppendOpenBrace();
						GetExprText(operandList[0], tokens, settings);
						tokens.AppendCloseBrace();
						skipSyscallNumber = true;
					}
				}
			}
			for (size_t i = (skipSyscallNumber ? 1 : 0); i < operandList.size(); i++)
			{
				if (i != 0)
					tokens.Append(TextToken, ", ");
				GetExprText(operandList[i], tokens, settings);
			}
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_BP:
		[&]() {
			tokens.Append(KeywordToken, "breakpoint");
			tokens.AppendOpenParen();
			tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_UNIMPL_MEM:
	case HLIL_UNIMPL:
		[&]() {
			const auto hlilFunc = GetHighLevelILFunction();
			const auto instructionText = hlilFunc->GetExprText(hlilFunc->GetInstruction(
				hlilFunc->GetInstructionForExpr(instr.exprIndex)).exprIndex, true, settings);
			tokens.Append(AnnotationToken, "/* ");
			for (const auto& token : instructionText[0].tokens)
				tokens.Append(token.type, token.text, token.value);

			if (instructionText.size() > 1)
				tokens.Append(AnnotationToken, "...");

			tokens.Append(AnnotationToken, " */");
		}();
		break;

	case HLIL_NOP:
		[&]() {
			tokens.Append(AnnotationToken, "/* nop */");
		}();
		break;

	case HLIL_GOTO:
		[&]() {
			const auto target = instr.GetTarget<HLIL_GOTO>();
			tokens.Append(KeywordToken, "goto ");
			tokens.Append(GotoLabelToken, "'" + GetFunction()->GetGotoLabelName(target), target);
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_LABEL:
		[&]() {
			const auto target = instr.GetTarget<HLIL_LABEL>();
			tokens.DecreaseIndent();
			tokens.Append(GotoLabelToken, "'" + GetFunction()->GetGotoLabelName(target), target);
			tokens.Append(TextToken, ":");
			tokens.IncreaseIndent();
		}();
		break;

	case HLIL_LOW_PART:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_LOW_PART>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprText(srcExpr, tokens, settings, asFullAst, precedence);
				return;
			}
			bool parens = precedence > LowUnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			GetExprText(srcExpr, tokens, settings, asFullAst, LowUnaryOperatorPrecedence);
			tokens.Append(KeywordToken, " as ");
			AppendSizeToken(instr.size, signedHint.value_or(true), tokens);
			if (parens)
				tokens.AppendCloseParen();
			if (exprType != InnerExpression)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_SPLIT: break;
	default:
		[&]() {
			char buf[64] {};
			snprintf(buf, sizeof(buf), "/* <UNIMPLEMENTED, %x> */", instr.operation);
			tokens.Append(AnnotationToken, buf);
		}();
		break;
	}

	if (settings && settings->IsOptionSet(ShowILTypes) && instr.GetType())
	{
		tokens.AppendCloseParen();
	}
}


void PseudoRustFunction::GetExprText(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens,
	DisassemblySettings* settings, bool asFullAst, BNOperatorPrecedence precedence, bool statement)
{
	GetExprText(instr, tokens, settings, asFullAst, precedence, statement ? TrailingStatementExpression : InnerExpression);
}


string PseudoRustFunction::GetAnnotationStartString() const
{
	// Show annotations as Rust-style inline comments
	return "/* ";
}


string PseudoRustFunction::GetAnnotationEndString() const
{
	// Show annotations as Rust-style inline comments
	return " */";
}


PseudoRustFunctionType::PseudoRustFunctionType(): LanguageRepresentationFunctionType("Pseudo Rust")
{
	// Create a type printer for Rust-style types and register it
	m_typePrinter =  new RustTypePrinter();
	TypePrinter::Register(m_typePrinter);
}


Ref<LanguageRepresentationFunction> PseudoRustFunctionType::Create(Architecture* arch, Function* owner,
	HighLevelILFunction* highLevelILFunction)
{
	return new PseudoRustFunction(arch, owner, highLevelILFunction);
}


Ref<TypePrinter> PseudoRustFunctionType::GetTypePrinter()
{
	// Return the Rust type printer as the default type printer for this language
	return m_typePrinter;
}


vector<DisassemblyTextLine> PseudoRustFunctionType::GetFunctionTypeTokens(Function* func, DisassemblySettings* settings)
{
	vector<DisassemblyTextLine> result;
	DisassemblyTextLine line;
	line.addr = func->GetStart();

	RustTypePrinter printer;
	Ref<Type> funcType = func->GetType();
	if (!funcType)
		return {};

	// Use the Rust type printer to generate a Rust formatted function declaration
	vector<InstructionTextToken> before = printer.GetTypeTokensBeforeName(funcType, func->GetPlatform());
	vector<InstructionTextToken> after = printer.GetTypeTokensAfterNameInternal(funcType, func->GetPlatform(),
		BN_FULL_CONFIDENCE, nullptr, NoTokenEscapingType, true);

	line.tokens = before;
	if (!before.empty())
		line.tokens.emplace_back(TextToken, " ");

	Ref<Symbol> sym = func->GetSymbol();
	line.tokens.emplace_back(CodeSymbolToken, sym->GetShortName(), func->GetStart());

	line.tokens.insert(line.tokens.end(), after.begin(), after.end());
	return {line};
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_VERSION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}
#endif

#ifdef DEMO_VERSION
	bool PseudoCPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		LanguageRepresentationFunctionType* type = new PseudoRustFunctionType();
		LanguageRepresentationFunctionType::Register(type);
		return true;
	}
}
