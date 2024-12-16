#include <inttypes.h>
#include "rusttypes.h"

using namespace std;
using namespace BinaryNinja;


RustTypePrinter::RustTypePrinter(): TypePrinter("RustTypePrinter")
{
}


void RustTypePrinter::AppendCallingConventionTokens(Type* type, Platform* platform, uint8_t baseConfidence,
	vector<InstructionTextToken>& tokens)
{
	if (type->GetCallingConvention() && platform &&
		type->GetCallingConvention().GetValue() != platform->GetDefaultCallingConvention())
	{
		uint8_t ccConfidence = type->GetCallingConvention().GetCombinedConfidence(baseConfidence);
		tokens.emplace_back(baseConfidence, KeywordToken, "extern");
		tokens.emplace_back(ccConfidence, TextToken, " ");
		tokens.emplace_back(ccConfidence, BraceToken, "\"");
		if (type->GetCallingConvention().GetValue() == platform->GetCdeclCallingConvention())
		{
			tokens.emplace_back(StringToken, StringDisplayTokenContext, "C", 0,
				Utf8String, 0, BN_INVALID_OPERAND, ccConfidence);
		}
		else
		{
			tokens.emplace_back(StringToken, StringDisplayTokenContext, type->GetCallingConvention()->GetName(), 0,
				Utf8String, 0, BN_INVALID_OPERAND, ccConfidence);
		}
		tokens.emplace_back(ccConfidence, BraceToken, "\"");
		tokens.emplace_back(ccConfidence, TextToken, " ");
	}
}


void RustTypePrinter::GetStructureMemberTokens(Platform* platform, Type* type, uint8_t baseConfidence,
	BNTokenEscapingType escaping, vector<InstructionTextToken>& out)
{
	uint64_t offset = 0;
	vector<StructureMember> members = type->GetStructure()->GetMembers();
	for (size_t i = 0; i < members.size(); i++)
	{
		if (members[i].type->GetClass() == FunctionTypeClass)
			continue;
		if (i != 0)
			out.emplace_back(baseConfidence, TextToken, ", ");
		else
			out.emplace_back(baseConfidence, TextToken, " ");

		if ((!type->GetStructure()->IsPacked()) && (members[i].type->GetAlignment() != 0) &&
			((offset % members[i].type->GetAlignment()) != 0))
			offset += members[i].type->GetAlignment() - (offset % members[i].type->GetAlignment());

		if (members[i].offset < offset)
		{
			out.emplace_back(baseConfidence, KeywordToken, "__offset");
			out.emplace_back(baseConfidence, BraceToken, "(");
			out.emplace_back(IntegerToken, DisassemblyTextRenderer::GetDisplayStringForInteger(
				nullptr, UnsignedHexadecimalDisplayType, members[i].offset, 8),
				members[i].offset, 0, BN_INVALID_OPERAND, baseConfidence);
			out.emplace_back(baseConfidence, BraceToken, ")");
			offset = members[i].offset;
		}
		else if (members[i].offset > offset)
		{
			char offsetStr[32];
			snprintf(offsetStr, sizeof(offsetStr), "_%" PRIx64, offset);
			out.emplace_back(baseConfidence, KeywordToken, "__padding");
			out.emplace_back(baseConfidence, TextToken, " ");
			out.emplace_back(baseConfidence, TextToken, offsetStr);
			out.emplace_back(baseConfidence, TextToken, ": ");
			out.emplace_back(baseConfidence, BraceToken, "[");
			out.emplace_back(baseConfidence, KeywordToken, "u8");
			out.emplace_back(baseConfidence, TextToken, "; ");
			out.emplace_back(IntegerToken, DisassemblyTextRenderer::GetDisplayStringForInteger(
				nullptr, UnsignedHexadecimalDisplayType, members[i].offset - offset, 8),
				members[i].offset - offset, 0, BN_INVALID_OPERAND, baseConfidence);
			out.emplace_back(baseConfidence, BraceToken, "]");
			offset = members[i].offset;
		}

		vector<InstructionTextToken> after =
			GetTypeTokensAfterName(members[i].type, platform, BN_FULL_CONFIDENCE, nullptr, escaping);

		out.emplace_back(baseConfidence, FieldNameToken,
			NameList::EscapeTypeName(members[i].name, escaping));
		out.insert(out.end(), after.begin(), after.end());

		if (!type->GetStructure()->IsUnion())
			offset = members[i].offset + members[i].type->GetWidth();
	}
	out.emplace_back(baseConfidence, TextToken, " ");
}


vector<InstructionTextToken> RustTypePrinter::GetTypeTokensBeforeName(
	Ref<Type> type, Ref<Platform> platform, uint8_t baseConfidence, Ref<Type> parentType,
	BNTokenEscapingType escaping)
{
	vector<InstructionTextToken> tokens;
	if ((!parentType || !parentType->IsPointer()) && type->GetClass() == FunctionTypeClass)
	{
		AppendCallingConventionTokens(type, platform, baseConfidence, tokens);
		tokens.emplace_back(baseConfidence, KeywordToken, "fn");
	}
	return tokens;
}


vector<InstructionTextToken> RustTypePrinter::GetTypeTokensAfterName(
	Ref<Type> type, Ref<Platform> platform, uint8_t baseConfidence, Ref<Type> parentType,
	BNTokenEscapingType escaping)
{
	return GetTypeTokensAfterNameInternal(type, platform, baseConfidence, parentType, escaping);
}


vector<InstructionTextToken> RustTypePrinter::GetTypeTokensAfterNameInternal(
	Ref<Type> type, Ref<Platform> platform, uint8_t baseConfidence, Ref<Type> parentType,
	BNTokenEscapingType escaping, bool functionHeader)
{
	vector<InstructionTextToken> tokens;
	if (!parentType && type->GetClass() != FunctionTypeClass)
		tokens.emplace_back(TextToken, ": ");

	switch (type->GetClass())
	{
	case FunctionTypeClass:
	{
		if (parentType && parentType->IsPointer())
		{
			AppendCallingConventionTokens(type, platform, baseConfidence, tokens);
			tokens.emplace_back(baseConfidence, KeywordToken, "fn");
		}

		tokens.emplace_back(baseConfidence, BraceToken, "(");

		auto params = type->GetParameters();
		for (size_t i = 0; i < params.size(); i++)
		{
			if (i != 0)
				tokens.emplace_back(baseConfidence, TextToken, ", ");

			vector<InstructionTextToken> paramTokens = GetTypeTokensAfterName(params[i].type, platform,
				params[i].type.GetCombinedConfidence(baseConfidence), type, escaping);

			if (functionHeader)
			{
				for (auto& token : paramTokens)
				{
					token.context = LocalVariableTokenContext;
					token.address = params[i].location.ToIdentifier();
				}
			}

			InstructionTextToken nameToken;
			if (params[i].name.length() == 0)
			{
				nameToken = InstructionTextToken(TextToken, "_");
			}
			else
			{
				nameToken = InstructionTextToken(ArgumentNameToken, NameList::EscapeTypeName(params[i].name, escaping), i);
				if (functionHeader)
				{
					nameToken.context = LocalVariableTokenContext;
					nameToken.address = params[i].location.ToIdentifier();
				}
			}
			tokens.push_back(nameToken);
			tokens.emplace_back(TextToken, ": ");
			tokens.insert(tokens.end(), paramTokens.begin(), paramTokens.end());

			if (!params[i].defaultLocation && platform)
			{
				switch (params[i].location.type)
				{
				case RegisterVariableSourceType:
				{
					string registerName = platform->GetArchitecture()->GetRegisterName((uint32_t)params[i].location.storage);
					tokens.emplace_back(TextToken, " @ ");
					tokens.emplace_back(RegisterToken, NameList::EscapeTypeName(registerName, escaping), params[i].location.storage);
					break;
				}
				case FlagVariableSourceType:
				{
					string flagName = platform->GetArchitecture()->GetFlagName((uint32_t)params[i].location.storage);
					tokens.emplace_back(TextToken, " @ ");
					tokens.emplace_back(AnnotationToken, NameList::EscapeTypeName(flagName, escaping), params[i].location.storage);
					break;
				}
				case StackVariableSourceType:
				{
					tokens.emplace_back(TextToken, " @ ");
					char storageStr[32];
					snprintf(storageStr, sizeof(storageStr), "%" PRIi64, params[i].location.storage);
					tokens.emplace_back(IntegerToken, storageStr, params[i].location.storage);
					break;
				}
				}
			}
		}

		if (type->HasVariableArguments())
		{
			if (params.size() != 0)
				tokens.emplace_back(TextToken, ", ");
			tokens.emplace_back(type->HasVariableArguments().GetCombinedConfidence(baseConfidence), TextToken, "...");
		}

		tokens.emplace_back(baseConfidence, BraceToken, ")");

		if (!type->CanReturn())
		{
			// No return functions are part of the Rust language, marked by returning the "never" type.
			tokens.emplace_back(baseConfidence, TextToken, " -> ");
			tokens.emplace_back(type->CanReturn().GetCombinedConfidence(baseConfidence), TextToken, "!");
		}
		else if (type->GetChildType() && type->GetChildType()->GetClass() != VoidTypeClass)
		{
			tokens.emplace_back(baseConfidence, TextToken, " -> ");
			vector<InstructionTextToken> retn = GetTypeTokensAfterName(type->GetChildType(), platform,
				type->GetChildType().GetCombinedConfidence(baseConfidence), type, escaping);
			if (functionHeader)
			{
				for (auto& i : retn)
					i.context = FunctionReturnTokenContext;
			}
			tokens.insert(tokens.end(), retn.begin(), retn.end());
		}
		break;
	}
	case IntegerTypeClass:
		tokens.emplace_back(baseConfidence, TypeNameToken,
			(type->IsSigned() ? "i" : "u") + to_string(type->GetWidth() * 8));
		break;
	case FloatTypeClass:
		tokens.emplace_back(baseConfidence, TypeNameToken, "f" + to_string(type->GetWidth() * 8));
		break;
	case WideCharTypeClass:
		if (type->GetWidth() == 4)
			tokens.emplace_back(baseConfidence, TypeNameToken, "char");
		else
			tokens.emplace_back(baseConfidence, TypeNameToken, "char" + to_string(type->GetWidth() * 8));
		break;
	case BoolTypeClass:
		tokens.emplace_back(baseConfidence, TypeNameToken, "bool");
        break;
    case VoidTypeClass:
    	if (parentType && parentType->IsPointer())
    	{
    		tokens.emplace_back(baseConfidence, TypeNameToken, "c_void");
    	}
		else
		{
			tokens.emplace_back(baseConfidence, BraceToken, "(");
			tokens.emplace_back(baseConfidence, BraceToken, ")");
		}
        break;
	case StructureTypeClass:
		if (type->GetRegisteredName())
		{
			tokens.emplace_back(baseConfidence, TypeNameToken, type->GetRegisteredName()->GetName().GetString(escaping));
		}
		else
		{
			tokens.emplace_back(baseConfidence, KeywordToken, "struct");
			tokens.emplace_back(baseConfidence, TextToken, " ");
			tokens.emplace_back(baseConfidence, BraceToken, "{");
			GetStructureMemberTokens(platform, type, baseConfidence, escaping, tokens);
			tokens.emplace_back(baseConfidence, BraceToken, "}");
		}
		break;
	case EnumerationTypeClass:
		if (type->GetRegisteredName())
			tokens.emplace_back(baseConfidence, TypeNameToken, type->GetRegisteredName()->GetName().GetString(escaping));
		else
			tokens.emplace_back(baseConfidence, TypeNameToken, "i" + to_string(type->GetWidth() * 8));
		break;
	case VarArgsTypeClass:
		tokens.emplace_back(baseConfidence, TextToken, "...");
        break;
	case PointerTypeClass:
	{
		if (type->GetChildType()->GetClass() == FunctionTypeClass)
		{
			vector<InstructionTextToken> inner = GetTypeTokensAfterName(
			type->GetChildType(), platform, baseConfidence, type, escaping);
			tokens.insert(tokens.end(), inner.begin(), inner.end());
			return tokens;
		}

		tokens.emplace_back(baseConfidence, TextToken, "*");
		if (type->GetChildType()->IsConst())
			tokens.emplace_back(baseConfidence, KeywordToken, "const");
		else
			tokens.emplace_back(baseConfidence, KeywordToken, "mut");
		tokens.emplace_back(baseConfidence, TextToken, " ");
		vector<InstructionTextToken> inner = GetTypeTokensAfterName(type->GetChildType(), platform,
			type->GetChildType().GetCombinedConfidence(baseConfidence), type, escaping);
		tokens.insert(tokens.end(), inner.begin(), inner.end());
		break;
	}
	case ArrayTypeClass:
	{
		tokens.emplace_back(baseConfidence, BraceToken, "[");
		vector<InstructionTextToken> inner = GetTypeTokensAfterName(type->GetChildType(), platform,
			type->GetChildType().GetCombinedConfidence(baseConfidence), type, escaping);
		tokens.insert(tokens.end(), inner.begin(), inner.end());
		tokens.emplace_back(baseConfidence, TextToken, "; ");
		tokens.emplace_back(ArrayIndexToken, DisassemblyTextRenderer::GetDisplayStringForInteger(
			nullptr, type->GetIntegerTypeDisplayType(), type->GetElementCount(), 8).c_str(), type->GetElementCount());
		tokens.emplace_back(baseConfidence, BraceToken, "]");
	}
	case ValueTypeClass:
		tokens.emplace_back(baseConfidence, TextToken, NameList::EscapeTypeName(type->GetAlternateName(), escaping));
		break;
	case NamedTypeReferenceClass:
		tokens.emplace_back(baseConfidence, TypeNameToken, type->GetNamedTypeReference()->GetName().GetString(escaping));
		break;
	default:
		tokens.emplace_back(AnnotationToken, "/* invalid type */");
		break;
	}

	return tokens;
}


vector<TypeDefinitionLine> RustTypePrinter::GetTypeLines(
	Ref<Type> type, const TypeContainer& types, const QualifiedName& name, int paddingCols,
	bool collapsed, BNTokenEscapingType escaping)
{
	// TODO: Implement this to get type rendering in the Types view
	return {};
}
