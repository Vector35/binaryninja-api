#include <inttypes.h>
#include "pseudoc.h"
#include "highlevelilinstruction.h"

using namespace std;
using namespace BinaryNinja;


PseudoCFunction::PseudoCFunction(LanguageRepresentationFunctionType* type, Architecture* arch, Function* owner,
	HighLevelILFunction* highLevelILFunction) :
	LanguageRepresentationFunction(type, arch, owner, highLevelILFunction), m_highLevelIL(highLevelILFunction)
{
}


void PseudoCFunction::InitTokenEmitter(HighLevelILTokenEmitter& tokens)
{
	// Braces must always be turned on for C
	tokens.SetBraceRequirement(BracesAlwaysRequired);

	// For switch cases in C, declarations inside aren't scoped by default. Add braces around the cases
	// to give them scope.
	tokens.SetBracesAroundSwitchCases(true);

	tokens.SetHasCollapsableRegions(true);
}


void PseudoCFunction::BeginLines(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens)
{
	if (instr.exprIndex == m_highLevelIL->GetRootExpr().exprIndex)
	{
		// At top level, add braces around the entire function
		tokens.PrependCollapseIndicator();
		tokens.AppendOpenBrace();
		tokens.NewLine();
		tokens.IncreaseIndent();
	}
}


void PseudoCFunction::EndLines(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens)
{
	if (instr.exprIndex == m_highLevelIL->GetRootExpr().exprIndex)
	{
		// At top level, add braces around the entire function
		tokens.NewLine();
		tokens.DecreaseIndent();
		tokens.PrependCollapseIndicator();
		tokens.AppendCloseBrace();
	}
}


BNSymbolDisplayResult PseudoCFunction::AppendPointerTextToken(const HighLevelILInstruction& instr, int64_t val,
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


string PseudoCFunction::GetSizeToken(size_t size, bool isSigned)
{
	return TypePrinter::GetDefault()->GetTypeString(
		Type::IntegerType(size, isSigned),
		nullptr,
		QualifiedName()
	);
}


void PseudoCFunction::AppendSizeToken(size_t size, bool isSigned, HighLevelILTokenEmitter& emitter)
{
	const auto token = GetSizeToken(size, isSigned);
	if (!token.empty())
		emitter.Append(TypeNameToken, token);
}


void PseudoCFunction::AppendSingleSizeToken(
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


void PseudoCFunction::AppendComparison(const string& comparison, const HighLevelILInstruction& instr,
	HighLevelILTokenEmitter& emitter, DisassemblySettings* settings, BNOperatorPrecedence precedence,
	std::optional<bool> signedHint)
{
	const auto leftExpr = instr.GetLeftExpr();
	const auto rightExpr = instr.GetRightExpr();

	GetExprTextInternal(leftExpr, emitter, settings, precedence, false, signedHint);
	emitter.Append(OperationToken, comparison);
	GetExprTextInternal(rightExpr, emitter, settings, precedence, false, signedHint);
}


void PseudoCFunction::AppendTwoOperand(const string& operand, const HighLevelILInstruction& instr,
	HighLevelILTokenEmitter& emitter, DisassemblySettings* settings, BNOperatorPrecedence precedence,
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
		GetExprTextInternal(high, emitter, settings);
		emitter.Append(TextToken, ", ");
		GetExprTextInternal(low, emitter, settings);
		emitter.AppendCloseParen();
	}


	if (!settings || settings->IsOptionSet(ShowTypeCasts))
	{
		if (leftExpr.operation == HLIL_VAR && (operand == " + " || operand == " - "))
		{
			const auto variableType = GetFunction()->GetVariableType(leftExpr.GetVariable());
			if (variableType)
			{
				const auto childType = variableType->GetChildType();
				if (variableType->IsPointer() && childType && childType->GetWidth() != 1)
				{
					emitter.AppendOpenParen();
					emitter.Append(TypeNameToken, "char");
					emitter.Append(TextToken, "*");
					emitter.AppendCloseParen();
				}
			}
		}
	}

	GetExprTextInternal(leftExpr, emitter, settings, leftPrecedence, false, signedHint);

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
	GetExprTextInternal(rightExpr, emitter, settings, precedence, false, signedHint);
}


void PseudoCFunction::AppendTwoOperandFunction(const string& function,
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
		GetExprTextInternal(high, emitter, settings);
		emitter.Append(TextToken, ", ");
		GetExprTextInternal(low, emitter, settings);
		emitter.AppendCloseParen();
	}
	else
	{
		GetExprTextInternal(leftExpr, emitter, settings);
	}

	emitter.Append(TextToken, ", ");
	GetExprTextInternal(rightExpr, emitter, settings);

	emitter.AppendCloseParen();
}


void PseudoCFunction::AppendTwoOperandFunctionWithCarry(const string& function,
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
		GetExprTextInternal(high, tokens, settings);
		tokens.Append(TextToken, ", ");
		GetExprTextInternal(low, tokens, settings);
		tokens.AppendCloseParen();
	}

	GetExprTextInternal(leftExpr, tokens, settings);
	tokens.Append(TextToken, ", ");
	GetExprTextInternal(rightExpr, tokens, settings);
	tokens.Append(TextToken, ", ");
	GetExprTextInternal(carryExpr, tokens, settings);

	tokens.AppendCloseParen();
}


Ref<Type> PseudoCFunction::GetFieldType(const HighLevelILInstruction& var, bool deref)
{
	Ref<Type> type = var.GetType().GetValue();
	if (deref && type && (type->GetClass() == PointerTypeClass))
		type = type->GetChildType().GetValue();

	if (type && (type->GetClass() == NamedTypeReferenceClass))
		type = GetFunction()->GetView()->GetTypeByRef(type->GetNamedTypeReference());

	return type;
}


PseudoCFunction::FieldDisplayType PseudoCFunction::GetFieldDisplayType(
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


void PseudoCFunction::AppendFieldTextTokens(const HighLevelILInstruction& var, uint64_t offset,
	size_t memberIndex, size_t size, HighLevelILTokenEmitter& tokens, bool deref, bool displayDeref)
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
						if (deref && displayDeref)
							tokens.Append(OperationToken, "->");
						else
							tokens.Append(OperationToken, ".");
						deref = false;

						vector<string> nameList {member.name};
						HighLevelILTokenEmitter::AddNamesForOuterStructureMembers(
							GetFunction()->GetView(), type, var, nameList);

						tokens.Append(FieldNameToken, member.name, structOffset + member.offset, 0, 0,
							BN_FULL_CONFIDENCE, nameList);
					}),
				memberIndexHint)
				return;

			// Part of structure but no defined field, use __offset syntax
			if (deref && displayDeref)
				tokens.Append(OperationToken, "->");
			else
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


void PseudoCFunction::GetExprText(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens,
	DisassemblySettings* settings, BNOperatorPrecedence precedence, bool statement)
{
	GetExprTextInternal(instr, tokens, settings, precedence, statement);
}


void PseudoCFunction::GetExprTextInternal(const HighLevelILInstruction& instr, HighLevelILTokenEmitter& tokens,
	DisassemblySettings* settings, BNOperatorPrecedence precedence, bool statement, optional<bool> signedHint)
{
	// The lambdas in this function are here to reduce stack frame size of this function. Without them,
	// complex expression can cause the process to crash from a stack overflow.
	auto exprGuard = tokens.SetCurrentExpr(instr);

	if (settings && settings->IsOptionSet(ShowILTypes) && instr.GetType())
	{
		tokens.AppendOpenParen();
		tokens.AppendOpenParen();
		auto typeTokens = TypePrinter::GetDefault()->GetTypeTokens(
			instr.GetType(),
			GetArchitecture()->GetStandalonePlatform(),
			QualifiedName()
		);
		for (auto& token: typeTokens)
		{
			tokens.Append(token);
		}
		tokens.AppendCloseParen();
		tokens.Append(TextToken, " ");
	}
	if (settings && settings->IsOptionSet(ShowILOpcodes))
	{
		tokens.Append(OperationToken, "/*");
		tokens.Append(OperationToken, fmt::format("{}", instr.operation));
		tokens.Append(OperationToken, "*/");
		tokens.Append(TextToken, " ");
	}

	auto function = m_highLevelIL->GetFunction();
	if (instr.ast)
		tokens.PrependCollapseIndicator(function, instr);

	// ensure we claim the line address for top level instrs on a line
	if (instr.operation != HLIL_BLOCK)
		tokens.InitLine();

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
				if (instr.ast && (instr.exprIndex == GetHighLevelILFunction()->GetRootExpr().exprIndex)
					&& (exprs.size() > 1) && (next == exprs.end()) && ((*i).operation == HLIL_RET)
					&& ((*i).GetSourceExprs<HLIL_RET>().size() == 0))
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
				GetExprTextInternal(*i, tokens, settings, TopLevelOperatorPrecedence, true);
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

			if (instr.ast)
			{
				tokens.Append(KeywordToken, "for ");
				tokens.AppendOpenParen();
				if (initExpr.operation != HLIL_NOP)
					GetExprTextInternal(initExpr, tokens, settings);
				tokens.Append(TextToken, "; ");
				if (condExpr.operation != HLIL_NOP)
					GetExprTextInternal(condExpr, tokens, settings);
				tokens.Append(TextToken, "; ");
				if (updateExpr.operation != HLIL_NOP)
					GetExprTextInternal(updateExpr, tokens, settings);
				tokens.AppendCloseParen();
				if (function->IsInstructionCollapsed(instr))
				{
					tokens.Append(CollapsedInformationToken, " {...}");
				}
				else
				{
					auto scopeType = HighLevelILFunction::GetExprScopeType(loopExpr);
					tokens.BeginScope(scopeType);
					GetExprTextInternal(loopExpr, tokens, settings, TopLevelOperatorPrecedence, true);
					tokens.EndScope(scopeType);
					tokens.FinalizeScope();
				}

			}
			else
			{
				tokens.Append(KeywordToken, "while ");
				tokens.AppendOpenParen();
				GetExprTextInternal(condExpr, tokens, settings);
				tokens.AppendCloseParen();
			}
		}();
		break;

	case HLIL_IF:
		[&]()
		{
			const auto condExpr = instr.GetConditionExpr<HLIL_IF>();
			const auto trueExpr = instr.GetTrueExpr<HLIL_IF>();
			const auto falseExpr = instr.GetFalseExpr<HLIL_IF>();

			tokens.Append(KeywordToken, "if ");
			tokens.AppendOpenParen();
			GetExprTextInternal(condExpr, tokens, settings);
			tokens.AppendCloseParen();
			if (!instr.ast)
				return;

			if (function->IsInstructionCollapsed(instr))
			{
				tokens.Append(CollapsedInformationToken, " {...}");
			}
			else
			{
				auto scopeType = HighLevelILFunction::GetExprScopeType(trueExpr);
				tokens.BeginScope(scopeType);
				GetExprTextInternal(trueExpr, tokens, settings, TopLevelOperatorPrecedence, true);
				tokens.EndScope(scopeType);
			}
			//tokens.SetCurrentExpr(falseExpr);
			if (falseExpr.operation == HLIL_IF)
			{
				tokens.ScopeContinuation(false);
				tokens.Append(KeywordToken, "else ");
				GetExprTextInternal(falseExpr, tokens, settings, TopLevelOperatorPrecedence, true);
			}
			else if (falseExpr.operation != HLIL_NOP)
			{
				tokens.ScopeContinuation(false);
				tokens.PrependCollapseIndicator(function, instr, 1);
				tokens.Append(KeywordToken, "else");
				if (function->IsInstructionCollapsed(instr, 1))
				{
					tokens.Append(CollapsedInformationToken, " {...}");
					tokens.NewLine();
				}
				else
				{
					auto scopeType = HighLevelILFunction::GetExprScopeType(falseExpr);
					tokens.BeginScope(scopeType);
					GetExprTextInternal(falseExpr, tokens, settings, TopLevelOperatorPrecedence, true);
					tokens.EndScope(scopeType);
					tokens.FinalizeScope();
				}
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

			tokens.Append(KeywordToken, "while ");
			tokens.AppendOpenParen();
			GetExprTextInternal(condExpr, tokens, settings);
			tokens.AppendCloseParen();
			if (!instr.ast)
				return;

			if (function->IsInstructionCollapsed(instr))
			{
				tokens.Append(CollapsedInformationToken, " {...}");
			}
			else
			{
				auto scopeType = HighLevelILFunction::GetExprScopeType(loopExpr);
				tokens.BeginScope(scopeType);
				GetExprTextInternal(loopExpr, tokens, settings, TopLevelOperatorPrecedence, true);
				tokens.EndScope(scopeType);
				tokens.FinalizeScope();
			}

		}();
		break;

	case HLIL_DO_WHILE:
		[&]() {
			const auto loopExpr = instr.GetLoopExpr<HLIL_DO_WHILE>();
			const auto condExpr = instr.GetConditionExpr<HLIL_DO_WHILE>();
			if (instr.ast)
			{
				tokens.Append(KeywordToken, "do");
				if (function->IsInstructionCollapsed(instr))
				{
					tokens.Append(CollapsedInformationToken, " {...}");
					tokens.NewLine();
					tokens.Append(KeywordToken, "while ");
					tokens.AppendOpenParen();
					GetExprTextInternal(condExpr, tokens, settings);
					tokens.AppendCloseParen();
					tokens.Append(KeywordToken, ";");
				}
				else
				{
					auto scopeType = HighLevelILFunction::GetExprScopeType(loopExpr);
					tokens.BeginScope(scopeType);
					GetExprTextInternal(loopExpr, tokens, settings, TopLevelOperatorPrecedence, true);
					tokens.EndScope(scopeType);

					tokens.ScopeContinuation(true);
					tokens.Append(KeywordToken, "while ");
					tokens.AppendOpenParen();
					GetExprTextInternal(condExpr, tokens, settings);
					tokens.AppendCloseParen();
					tokens.Append(KeywordToken, ";");
					tokens.FinalizeScope();
				}
			}
			else
			{
				tokens.Append(TextToken, "/* do */ ");
				tokens.Append(KeywordToken, "while ");
				tokens.AppendOpenParen();
				GetExprTextInternal(condExpr, tokens, settings);
				tokens.AppendCloseParen();
			}
		}();
		break;

	case HLIL_SWITCH:
		[&]() {
			const auto condExpr = instr.GetConditionExpr<HLIL_SWITCH>();
			const auto caseExprs = instr.GetCases<HLIL_SWITCH>();
			const auto defaultExpr = instr.GetDefaultExpr<HLIL_SWITCH>();

			tokens.Append(KeywordToken, "switch ");
			tokens.AppendOpenParen();
			GetExprTextInternal(condExpr, tokens, settings);
			tokens.AppendCloseParen();
			if (!instr.ast)
				return;

			if (function->IsInstructionCollapsed(instr))
			{
				tokens.Append(CollapsedInformationToken, " {...}");
			}
			else
			{
				tokens.BeginScope(SwitchScopeType);
				for (const auto caseExpr: caseExprs)
				{
					GetExprTextInternal(caseExpr, tokens, settings, TopLevelOperatorPrecedence, true);
					tokens.NewLine();
				}

				if (defaultExpr.operation != HLIL_NOP && defaultExpr.operation != HLIL_UNREACHABLE)
				{
					tokens.PrependCollapseIndicator(function, instr, 1);
					tokens.Append(KeywordToken, "default");
					tokens.Append(TextToken, ":");
					if (function->IsInstructionCollapsed(instr, 1))
					{
						tokens.Append(CollapsedInformationToken, " {...}");
					}
					else
					{
						tokens.BeginScope(CaseScopeType);
						GetExprTextInternal(defaultExpr, tokens, settings, TopLevelOperatorPrecedence, true);
						tokens.EndScope(CaseScopeType);
						tokens.FinalizeScope();
					}
				}
				tokens.EndScope(SwitchScopeType);
				tokens.FinalizeScope();
			}

		}();
		break;

	case HLIL_CASE:
		[&]() {
			const auto valueExprs = instr.GetValueExprs<HLIL_CASE>();
			const auto trueExpr = instr.GetTrueExpr<HLIL_CASE>();

			for (size_t index{}; index < valueExprs.size(); index++)
			{
				const auto& valueExpr = valueExprs[index];
				tokens.Append(KeywordToken, "case ");
				GetExprTextInternal(valueExpr, tokens, settings);
				tokens.Append(TextToken, ":");
				if (index != valueExprs.size() - 1)
					tokens.NewLine();
			}

			if (!instr.ast)
				return;

			if (function->IsInstructionCollapsed(instr))
			{
				tokens.Append(CollapsedInformationToken, " {...}");
			}
			else
			{
				tokens.PrependCollapseIndicator(function, instr);
				tokens.BeginScope(CaseScopeType);
				GetExprTextInternal(trueExpr, tokens, settings, TopLevelOperatorPrecedence, true);

				static const std::vector<BNHighLevelILOperation> operations {
						HLIL_CONTINUE, HLIL_NORET, HLIL_UNREACHABLE, HLIL_JUMP, HLIL_GOTO, HLIL_TAILCALL};

				// If the case doesn't have an instruction that implicitly exits the case, append a break statement
				// at the end of the case
				if (trueExpr.operation == HLIL_BLOCK)
				{
					const auto& blockExprs = trueExpr.GetBlockExprs<HLIL_BLOCK>();
					bool disallowedOperation = false;
					for (const auto expr : blockExprs)
					{
						if (std::find(operations.begin(), operations.end(), expr.operation) != operations.end())
						{
							disallowedOperation = true;
							break;
						}
					}
					if (!disallowedOperation)
					{
						tokens.NewLine();
						tokens.PrependCollapseIndicator();
						tokens.Append(KeywordToken, "break");
						tokens.Append(TextToken, ";");
					}
				}
				else if (std::find(operations.begin(), operations.end(), trueExpr.operation) == operations.end())
				{
					tokens.NewLine();
					tokens.PrependCollapseIndicator();
					tokens.Append(KeywordToken, "break");
					tokens.Append(TextToken, ";");
				}

				tokens.EndScope(CaseScopeType);
				tokens.FinalizeScope();
			}
		}();
		break;

	case HLIL_BREAK:
		[&]() {
			tokens.Append(KeywordToken, "break");
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CONTINUE:
		[&]() {
			tokens.Append(KeywordToken, "continue");
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ZX:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_ZX>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprTextInternal(srcExpr, tokens, settings, precedence);
				return;
			}
			bool parens = precedence > UnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			tokens.AppendOpenParen();
			AppendSizeToken(instr.size, false, tokens);
			tokens.AppendCloseParen();
			GetExprTextInternal(srcExpr, tokens, settings, UnaryOperatorPrecedence, false, false);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_SX:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_SX>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprTextInternal(srcExpr, tokens, settings, precedence);
				return;
			}
			bool parens = precedence > UnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			tokens.AppendOpenParen();
			AppendSizeToken(instr.size, true, tokens);
			tokens.AppendCloseParen();
			GetExprTextInternal(srcExpr, tokens, settings, UnaryOperatorPrecedence, false, true);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CALL:
		[&]() {
			const auto destExpr = instr.GetDestExpr<HLIL_CALL>();
			const auto parameterExprs = instr.GetParameterExprs<HLIL_CALL>();

			GetExprTextInternal(destExpr, tokens, settings, MemberAndFunctionOperatorPrecedence);
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
					GetExprText(parameterExpr, tokens, settings);
			}
			tokens.AppendCloseParen();
			if (statement)
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
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ARRAY_INDEX:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_ARRAY_INDEX>();
			const auto indexExpr = instr.GetIndexExpr<HLIL_ARRAY_INDEX>();

			GetExprTextInternal(srcExpr, tokens, settings, MemberAndFunctionOperatorPrecedence);
			tokens.AppendOpenBracket();
			GetExprTextInternal(indexExpr, tokens, settings);
			tokens.AppendCloseBracket();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_VAR_INIT:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_VAR_INIT>();
			const auto destExpr = instr.GetDestVariable<HLIL_VAR_INIT>();

			const auto variableType = GetHighLevelILFunction()->GetFunction()->GetVariableType(destExpr);
			const auto platform = GetHighLevelILFunction()->GetFunction()->GetPlatform();
			const auto prevTypeTokens =
					variableType ?
					TypePrinter::GetDefault()->GetTypeTokensBeforeName(variableType, platform, variableType.GetConfidence()) :
					vector<InstructionTextToken>{};
			const auto postTypeTokens =
					variableType ?
					TypePrinter::GetDefault()->GetTypeTokensAfterName(variableType, platform, variableType.GetConfidence()) :
					vector<InstructionTextToken>{};

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

			if (variableType)
			{
				for (auto typeToken: prevTypeTokens)
				{
					typeToken.context = LocalVariableTokenContext;
					typeToken.address = destExpr.ToIdentifier();
					tokens.Append(typeToken);
				}
				tokens.Append(TextToken, " ");
			}
			tokens.AppendVarTextToken(destExpr, instr, instr.size);
			if (variableType)
			{
				for (auto typeToken: postTypeTokens)
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

			GetExprTextInternal(srcExpr, tokens, settings, AssignmentOperatorPrecedence);

			if (appearsDead)
				tokens.EndForceZeroConfidence();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_VAR_DECLARE:
		[&]() {
			const auto variable = instr.GetVariable<HLIL_VAR_DECLARE>();

			const auto variableType = GetHighLevelILFunction()->GetFunction()->GetVariableType(variable);
			const auto platform = GetHighLevelILFunction()->GetFunction()->GetPlatform();
			const auto prevTypeTokens =
					variableType ?
					TypePrinter::GetDefault()->GetTypeTokensBeforeName(variableType, platform, variableType.GetConfidence()) :
					vector<InstructionTextToken>{};
			const auto postTypeTokens =
					variableType ?
					TypePrinter::GetDefault()->GetTypeTokensAfterName(variableType, platform, variableType.GetConfidence()) :
					vector<InstructionTextToken>{};

			if (variableType)
			{
				for (auto typeToken: prevTypeTokens)
				{
					typeToken.context = LocalVariableTokenContext;
					typeToken.address = variable.ToIdentifier();
					tokens.Append(typeToken);
				}
				tokens.Append(TextToken, " ");
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

			if (statement)
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

			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CONST:
		[&]() {
			tokens.AppendConstantTextToken(instr, instr.GetConstant<HLIL_CONST>(), instr.size, settings, precedence);
			if (statement)
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

			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CONST_PTR:
		[&]() {
			tokens.AppendPointerTextToken(
				instr, instr.GetConstant<HLIL_CONST_PTR>(), settings, AddressOfDataSymbols, precedence);
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_VAR:
		[&]() {
			const auto variable = instr.GetVariable<HLIL_VAR>();
			const auto variableName = GetHighLevelILFunction()->GetFunction()->GetVariableNameOrDefault(variable);
			tokens.Append(LocalVariableToken, LocalVariableTokenContext, variableName,
						  instr.exprIndex, variable.ToIdentifier(), instr.size);
			if (statement)
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
			std::optional<bool> assignSignedHint;
			if (isSplit)
			{
				const auto high = destExpr.GetHighExpr<HLIL_SPLIT>();
				const auto low = destExpr.GetLowExpr<HLIL_SPLIT>();

				GetExprTextInternal(high, tokens, settings, precedence);
				tokens.Append(OperationToken, " = ");
				tokens.Append(OperationToken, "HIGH");
				AppendSingleSizeToken(high.size, OperationToken, tokens);
				tokens.AppendOpenParen();
				GetExprTextInternal(srcExpr, tokens, settings, precedence);
				tokens.AppendCloseParen();
				tokens.AppendSemicolon();
				tokens.NewLine();
				GetExprTextInternal(low, tokens, settings, precedence);
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
						assignUpdateOperator = " u/= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						assignSignedHint = false;
						break;
					case HLIL_DIVS:
						assignUpdateOperator = " s/= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						assignSignedHint = true;
						break;
					case HLIL_LSL:
						assignUpdateOperator = " <<= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						break;
					case HLIL_LSR:
						assignUpdateOperator = " u>>= ";
						assignUpdateSource = srcExpr.GetRightExpr();
						break;
					case HLIL_ASR:
						assignUpdateOperator = " s>>= ";
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

			GetExprTextInternal(destExpr, tokens, settings, precedence);
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
					GetExprTextInternal(assignUpdateSource.value(), tokens, settings, AssignmentOperatorPrecedence,
						false, assignSignedHint);
				}
			}
			else
			{
				GetExprTextInternal(srcExpr, tokens, settings, AssignmentOperatorPrecedence, false, assignSignedHint);
			}

			if (isSplit)
				tokens.AppendCloseParen();

			if (appearsDead)
				tokens.EndForceZeroConfidence();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ASSIGN_UNPACK:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_ASSIGN_UNPACK>();
			const auto destExprs = instr.GetDestExprs<HLIL_ASSIGN_UNPACK>();
			const auto firstExpr = destExprs[0];

			GetExprTextInternal(firstExpr, tokens, settings, AssignmentOperatorPrecedence);
			tokens.Append(OperationToken, " = ");
			GetExprTextInternal(srcExpr, tokens, settings, AssignmentOperatorPrecedence);
			if (statement)
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
				{
					tokens.AppendOpenParen();
					AppendSizeToken(!instr.size ? srcExpr.size : instr.size, false, tokens);
					tokens.Append(TextToken, "*");
					tokens.AppendCloseParen();
				}
				tokens.AppendOpenParen();
				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.AppendOpenParen();
					tokens.Append(TypeNameToken, "char");
					tokens.Append(TextToken, "*");
					tokens.AppendCloseParen();
				}
				GetExprTextInternal(srcExpr, tokens, settings, MemberAndFunctionOperatorPrecedence);

				tokens.Append(OperationToken, " + ");
				tokens.AppendIntegerTextToken(instr, fieldOffset, instr.size);
				tokens.AppendCloseParen();

				char offsetStr[64];
				snprintf(offsetStr, sizeof(offsetStr), "0x%" PRIx64, fieldOffset);

				vector<string> nameList { offsetStr };
				HighLevelILTokenEmitter::AddNamesForOuterStructureMembers(
					GetFunction()->GetView(), type, srcExpr, nameList);
			}
			else if (fieldDisplayType == FieldDisplayMemberOffset)
			{
				tokens.Append(OperationToken, "*");
				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.AppendOpenParen();
					AppendSizeToken(!instr.size ? srcExpr.size : instr.size, false, tokens);
					tokens.Append(TextToken, "*");
					tokens.AppendCloseParen();
					tokens.AppendOpenParen();
					tokens.AppendOpenParen();
					tokens.Append(TypeNameToken, "char");
					tokens.Append(TextToken, "*");
					tokens.AppendCloseParen();
				}
				GetExprTextInternal(srcExpr, tokens, settings, MemberAndFunctionOperatorPrecedence);
				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.AppendCloseParen();
				}
				/* rest is rendered in AppendFieldTextTokens */
			}
			else
			{
				GetExprTextInternal(srcExpr, tokens, settings, MemberAndFunctionOperatorPrecedence);
			}

			AppendFieldTextTokens(srcExpr, fieldOffset, memberIndex, instr.size, tokens, false);
			if (statement)
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

				vector<InstructionTextToken> pointerTokens{};
				if (AppendPointerTextToken(srcExpr, constant, pointerTokens, settings, DereferenceNonDataSymbols, precedence) == DataSymbolResult)
				{
					const auto type = srcExpr.GetType();
					if (type && type->GetClass() == PointerTypeClass && instr.size != type->GetChildType()->GetWidth())
					{
						if (!settings || settings->IsOptionSet(ShowTypeCasts))
						{
							tokens.AppendOpenParen();
						}
						tokens.Append(OperationToken, "*");
						if (!settings || settings->IsOptionSet(ShowTypeCasts))
						{
							tokens.AppendOpenParen();
							AppendSizeToken(instr.size, false, tokens);
							tokens.Append(TextToken, "*");
							tokens.AppendCloseParen();
						}

						for (const auto& token : pointerTokens)
						{
							appendMaybeBrace(token);
						}

						if (!settings || settings->IsOptionSet(ShowTypeCasts))
						{
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
				size_t derefCount{};
				while (srcExpr.operation == HLIL_DEREF)
				{
					auto next = srcExpr.GetSourceExpr<HLIL_DEREF>();
					if (next.size == srcExpr.size)
					{
						srcExpr = srcExpr.GetSourceExpr<HLIL_DEREF>();
						derefCount++;
					}
					else
					{
						break;
					}
				}

				bool parens = precedence > UnaryOperatorPrecedence;
				if (parens)
					tokens.AppendOpenParen();
				for (size_t index{}; index <= derefCount; index++)
					tokens.Append(OperationToken, "*");
				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.AppendOpenParen();

					AppendSizeToken(instr.size, false, tokens);

					for (size_t index{}; index <= derefCount; index++)
						tokens.Append(TextToken, "*");
					tokens.AppendCloseParen();
				}

				GetExprTextInternal(srcExpr, tokens, settings, UnaryOperatorPrecedence);
				if (parens)
					tokens.AppendCloseParen();
			}

			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_TAILCALL:
		[&]() {
			const auto destExpr = instr.GetDestExpr<HLIL_TAILCALL>();
			const auto parameterExprs = instr.GetParameterExprs<HLIL_TAILCALL>();

			tokens.Append(AnnotationToken, "/* tailcall */");
			tokens.NewLine();
			tokens.Append(KeywordToken, "return ");
			GetExprTextInternal(destExpr, tokens, settings, MemberAndFunctionOperatorPrecedence);
			tokens.AppendOpenParen();
			for (size_t index{}; index < parameterExprs.size(); index++)
			{
				const auto& parameterExpr = parameterExprs[index];
				if (index != 0) tokens.Append(TextToken, ", ");
				GetExprTextInternal(parameterExpr, tokens, settings);
			}
			tokens.AppendCloseParen();
			if (statement)
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
			GetExprTextInternal(srcExpr, tokens, settings, UnaryOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_E:
		[&]() {
			bool parens = precedence > EqualityOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendComparison(" == ", instr, tokens, settings, EqualityOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CMP_E:
		[&]() {
			if ((instr.GetRightExpr<HLIL_CMP_E>().operation == HLIL_CONST
					|| instr.GetRightExpr<HLIL_CMP_E>().operation == HLIL_CONST_PTR)
				&& instr.GetRightExpr<HLIL_CMP_E>().GetConstant() == 0)
			{
				bool parens = precedence > UnaryOperatorPrecedence;
				if (parens)
					tokens.AppendOpenParen();
				tokens.Append(OperationToken, "!");
				GetExprTextInternal(instr.GetLeftExpr<HLIL_CMP_E>(), tokens, settings, UnaryOperatorPrecedence);
				if (parens)
					tokens.AppendCloseParen();
			}
			else
			{
				bool parens = precedence > EqualityOperatorPrecedence;
				if (parens)
					tokens.AppendOpenParen();
				AppendComparison(" == ", instr, tokens, settings, EqualityOperatorPrecedence);
				if (parens)
					tokens.AppendCloseParen();
			}
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_NE:
		[&]() {
			bool parens = precedence > EqualityOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendComparison(" != ", instr, tokens, settings, EqualityOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CMP_NE:
		[&]() {
			if ((instr.GetRightExpr<HLIL_CMP_NE>().operation == HLIL_CONST
					|| instr.GetRightExpr<HLIL_CMP_NE>().operation == HLIL_CONST_PTR)
				&& instr.GetRightExpr<HLIL_CMP_NE>().GetConstant() == 0)
			{
				GetExprTextInternal(instr.GetLeftExpr<HLIL_CMP_NE>(), tokens, settings, precedence);
			}
			else
			{
				bool parens = precedence > EqualityOperatorPrecedence;
				if (parens)
					tokens.AppendOpenParen();
				AppendComparison(" != ", instr, tokens, settings, EqualityOperatorPrecedence);
				if (parens)
					tokens.AppendCloseParen();
			}
			if (statement)
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
			AppendComparison(" < ", instr, tokens, settings, CompareOperatorPrecedence, cmpSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
			AppendComparison(" <= ", instr, tokens, settings, CompareOperatorPrecedence, cmpSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
			AppendComparison(" >= ", instr, tokens, settings, CompareOperatorPrecedence, cmpSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
			AppendComparison(" > ", instr, tokens, settings, CompareOperatorPrecedence, cmpSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
			AppendTwoOperand(instr.size == 0 ? " && " : " & ", instr, tokens, settings,
				instr.size == 0 ? LogicalAndOperatorPrecedence : BitwiseAndOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
			AppendTwoOperand(instr.size == 0 ? " || " : " | ", instr, tokens, settings,
				instr.size == 0 ? LogicalOrOperatorPrecedence : BitwiseOrOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_XOR:
		[&]() {
			bool parens = precedence >= EqualityOperatorPrecedence || precedence == BitwiseAndOperatorPrecedence ||
				precedence == BitwiseOrOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" ^ ", instr, tokens, settings, BitwiseXorOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ADC:
	case HLIL_ADD_OVERFLOW:
	case HLIL_FADD:
	case HLIL_ADD:
		[&]() {
			bool parens = precedence > AddOperatorPrecedence || precedence == ShiftOperatorPrecedence ||
				precedence == BitwiseAndOperatorPrecedence || precedence == BitwiseOrOperatorPrecedence ||
				precedence == BitwiseXorOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" + ", instr, tokens, settings, AddOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
					GetExprTextInternal(left, tokens, settings, MemberAndFunctionOperatorPrecedence);
					tokens.AppendCloseParen();
					return;
				}
			}

			// No
			bool parens = precedence > AddOperatorPrecedence || precedence == ShiftOperatorPrecedence ||
				precedence == BitwiseAndOperatorPrecedence || precedence == BitwiseOrOperatorPrecedence ||
				precedence == BitwiseXorOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" - ", instr, tokens, settings, SubOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
			AppendTwoOperand(" - ", instr, tokens, settings, SubOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_LSL:
		[&]() {
			bool parens = precedence > ShiftOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" << ", instr, tokens, settings, ShiftOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_LSR:
	case HLIL_ASR:
		[&]() {
			bool parens = precedence > ShiftOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			AppendTwoOperand(" >> ", instr, tokens, settings, ShiftOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
			AppendTwoOperand(" * ", instr, tokens, settings, MultiplyOperatorPrecedence, mulSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
			AppendTwoOperand(" / ", instr, tokens, settings, DivideOperatorPrecedence, divSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
			AppendTwoOperand(" % ", instr, tokens, settings, DivideOperatorPrecedence, modSigned);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;


	case HLIL_ROR:
		[&]() {
			AppendTwoOperandFunction("ROR", instr, tokens, settings);
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ROL:
		[&]() {
			AppendTwoOperandFunction("ROL", instr, tokens, settings);
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_RLC:
		[&]() {
			AppendTwoOperandFunctionWithCarry("RLC", instr, tokens, settings);
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_RRC:
		[&]() {
			AppendTwoOperandFunctionWithCarry("RRC", instr, tokens, settings);
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_TEST_BIT:
		[&]() {
			AppendTwoOperandFunction("TEST_BIT", instr, tokens, settings);
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FLOOR:
		[&]() {
			tokens.Append(OperationToken, "floor");
			tokens.AppendOpenParen();
			GetExprTextInternal(instr.GetSourceExpr<HLIL_FLOOR>(), tokens, settings);
			tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_CEIL:
		[&]() {
			tokens.Append(OperationToken, "ceil");
			tokens.AppendOpenParen();
			GetExprTextInternal(instr.GetSourceExpr<HLIL_CEIL>(), tokens, settings);
			tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FTRUNC:
		[&]() {
			auto src = instr.GetSourceExpr<HLIL_FTRUNC>();
			string trunc;
			if (src.size == 4)
				trunc = "truncf";
			else if (src.size == 8)
				trunc = "trunc";
			else if (src.size == 10)
				trunc = "truncl";
			else
				trunc = "trunc" + std::to_string(src.size) + "f";
			tokens.Append(OperationToken, trunc);
			tokens.AppendOpenParen();
			GetExprTextInternal(src, tokens, settings);
			tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FABS:
		[&]() {
			auto src = instr.GetSourceExpr<HLIL_FABS>();
			string fabs;
			if (src.size == 4)
				fabs = "fabsf";
			else if (src.size == 8)
				fabs = "fabs";
			else if (src.size == 10)
				fabs = "fabsl";
			else
				fabs = "fabs" + std::to_string(src.size) + "f";
			tokens.Append(OperationToken, fabs);
			tokens.AppendOpenParen();
			GetExprTextInternal(src, tokens, settings);
			tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FSQRT:
		[&]() {
			auto src = instr.GetSourceExpr<HLIL_FSQRT>();
			string sqrt;
			if (src.size == 4)
				sqrt = "sqrtf";
			else if (src.size == 8)
				sqrt = "sqrt";
			else if (src.size == 10)
				sqrt = "sqrtl";
			else
				sqrt = "sqrt" + std::to_string(src.size) + "f";
			tokens.Append(OperationToken, sqrt);
			tokens.AppendOpenParen();
			GetExprTextInternal(src, tokens, settings);
			tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_ROUND_TO_INT:
		[&]() {
			AppendTwoOperandFunction("round", instr, tokens, settings, false);
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_O:
		[&]() {
			AppendTwoOperandFunction("FCMP_O", instr, tokens, settings, false);
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FCMP_UO:
		[&]() {
			AppendTwoOperandFunction("FCMP_UO", instr, tokens, settings, false);
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;


	case HLIL_NOT:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_NOT>();
			bool parens = precedence > UnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			tokens.Append(OperationToken, instr.size == 0 ? "!" : "~");
			GetExprTextInternal(srcExpr, tokens, settings, UnaryOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
			GetExprTextInternal(srcExpr, tokens, settings, UnaryOperatorPrecedence, false, true);
			tokens.AppendCloseParen();
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FLOAT_CONV:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_FLOAT_CONV>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprTextInternal(srcExpr, tokens, settings, precedence);
				return;
			}
			const auto floatType =
					instr.size == 2 ? "float16_t" :
					instr.size == 4 ? "float" :
					instr.size == 8 ? "double" :
					instr.size == 10 ? "long double" : "float" + std::to_string(instr.size) + "_t";

			bool parens = precedence > UnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			tokens.AppendOpenParen();
			tokens.Append(TypeNameToken, floatType.c_str());
			tokens.AppendCloseParen();
			GetExprTextInternal(srcExpr, tokens, settings, UnaryOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_FLOAT_TO_INT:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_FLOAT_TO_INT>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprTextInternal(srcExpr, tokens, settings, precedence);
				return;
			}

			bool parens = precedence > UnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			tokens.AppendOpenParen();
			AppendSizeToken(instr.size, true, tokens);
			tokens.AppendCloseParen();
			GetExprTextInternal(srcExpr, tokens, settings, UnaryOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_BOOL_TO_INT:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_BOOL_TO_INT>();

			bool parens = precedence > TernaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			GetExprTextInternal(srcExpr, tokens, settings, TernaryOperatorPrecedence);
			tokens.Append(OperationToken, " ? ");
			tokens.AppendIntegerTextToken(instr, 1, 1);
			tokens.Append(OperationToken, " : ");
			tokens.AppendIntegerTextToken(instr, 0, 1);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_INT_TO_FLOAT:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_INT_TO_FLOAT>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprTextInternal(srcExpr, tokens, settings, precedence);
				return;
			}
			const auto floatType =
					instr.size == 2 ? "float16_t" :
					instr.size == 4 ? "float" :
					instr.size == 8 ? "double" :
					instr.size == 10 ? "long double" : "float" + std::to_string(instr.size) + "_t";

			bool parens = precedence > UnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			tokens.AppendOpenParen();
			tokens.Append(TypeNameToken, floatType.c_str());
			tokens.AppendCloseParen();
			GetExprTextInternal(srcExpr, tokens, settings, UnaryOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
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
				GetExprTextInternal(parameterExpr, tokens, settings);
			}
			tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_RET:
		[&]() {
			const auto srcExprs = instr.GetSourceExprs<HLIL_RET>();

			tokens.Append(KeywordToken, "return");
			for (size_t index{}; index < srcExprs.size(); index++)
			{
				const auto& srcExpr = srcExprs[index];
				if (index == 0) tokens.Append(TextToken, " ");
				if (index != 0) tokens.Append(TextToken, ", ");
				GetExprTextInternal(srcExpr, tokens, settings);
			}
			if (statement)
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
			GetExprTextInternal(destExpr, tokens, settings);
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
			if (statement)
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
								GetExprTextInternal(srcExpr, tokens, settings, MemberAndFunctionOperatorPrecedence);
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
				{
					tokens.AppendOpenParen();
					AppendSizeToken(!derefOffset ? srcExpr.size : instr.size, true, tokens);
					tokens.Append(TextToken, "*");
					tokens.AppendCloseParen();
				}
				tokens.AppendOpenParen();
				if (!settings || settings->IsOptionSet(ShowTypeCasts))
				{
					tokens.AppendOpenParen();
					tokens.Append(TypeNameToken, "char");
					tokens.Append(TextToken, "*");
					tokens.AppendCloseParen();
				}

				if (srcExpr.operation == HLIL_CONST_PTR)
				{
					const auto constant = srcExpr.GetConstant<HLIL_CONST_PTR>();
					tokens.AppendPointerTextToken(srcExpr, constant, settings, DisplaySymbolOnly, precedence);
				}
				else
				{
					GetExprTextInternal(srcExpr, tokens, settings, AddOperatorPrecedence);
				}

				tokens.Append(OperationToken, " + ");
				tokens.AppendIntegerTextToken(instr, offset, instr.size);
				tokens.AppendCloseParen();
				if (parens)
					tokens.AppendCloseParen();
			}

			if (statement)
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

			if (statement)
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
						GetExprTextInternal(operandList[0], tokens, settings);
						tokens.AppendCloseBrace();
						skipSyscallNumber = true;
					}
				}
			}
			for (size_t i = (skipSyscallNumber ? 1 : 0); i < operandList.size(); i++)
			{
				if (i != 0)
					tokens.Append(TextToken, ", ");
				GetExprTextInternal(operandList[i], tokens, settings);
			}
			tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_BP:
		[&]() {
			tokens.Append(KeywordToken, "breakpoint");
			tokens.AppendOpenParen();
			tokens.AppendCloseParen();
			if (statement)
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
			tokens.Append(GotoLabelToken, GetFunction()->GetGotoLabelName(target), target);
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_LABEL:
		[&]() {
			const auto target = instr.GetTarget<HLIL_LABEL>();
			tokens.DecreaseIndent();
			tokens.Append(GotoLabelToken, GetFunction()->GetGotoLabelName(target), target);
			tokens.Append(TextToken, ":");
			tokens.IncreaseIndent();
		}();
		break;

	case HLIL_LOW_PART:
		[&]() {
			const auto srcExpr = instr.GetSourceExpr<HLIL_LOW_PART>();
			if (settings && !settings->IsOptionSet(ShowTypeCasts))
			{
				GetExprTextInternal(srcExpr, tokens, settings, precedence);
				return;
			}
			bool parens = precedence > UnaryOperatorPrecedence;
			if (parens)
				tokens.AppendOpenParen();
			tokens.AppendOpenParen();
			AppendSizeToken(instr.size, signedHint.value_or(true), tokens);
			tokens.AppendCloseParen();
			GetExprTextInternal(srcExpr, tokens, settings, UnaryOperatorPrecedence);
			if (parens)
				tokens.AppendCloseParen();
			if (statement)
				tokens.AppendSemicolon();
		}();
		break;

	case HLIL_SPLIT: break;
	default:
		[&]() {
			char buf[64]{};
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


string PseudoCFunction::GetAnnotationStartString() const
{
	// Show annotations as C-style inline comments
	return "/* ";
}


string PseudoCFunction::GetAnnotationEndString() const
{
	// Show annotations as C-style inline comments
	return " */";
}


PseudoCFunctionType::PseudoCFunctionType(): LanguageRepresentationFunctionType("Pseudo C")
{
}


Ref<LanguageRepresentationFunction> PseudoCFunctionType::Create(Architecture* arch, Function* owner,
	HighLevelILFunction* highLevelILFunction)
{
	return new PseudoCFunction(this, arch, owner, highLevelILFunction);
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_EDITION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}
#endif

#ifdef DEMO_EDITION
	bool PseudoCPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		LanguageRepresentationFunctionType* type = new PseudoCFunctionType();
		LanguageRepresentationFunctionType::Register(type);
		return true;
	}
}
