#pragma once

#include "binaryninjaapi.h"

class RustTypePrinter: public BinaryNinja::TypePrinter
{
	void AppendCallingConventionTokens(BinaryNinja::Type* type, BinaryNinja::Platform* platform, uint8_t baseConfidence,
		std::vector<BinaryNinja::InstructionTextToken>& tokens);
	void GetStructureMemberTokens(BinaryNinja::Platform* platform, BinaryNinja::Type* type, uint8_t baseConfidence,
		BNTokenEscapingType escaping, std::vector<BinaryNinja::InstructionTextToken>& out);

public:
	RustTypePrinter();

	std::vector<BinaryNinja::InstructionTextToken> GetTypeTokensBeforeName(
		BinaryNinja::Ref<BinaryNinja::Type> type, BinaryNinja::Ref<BinaryNinja::Platform> platform,
		uint8_t baseConfidence = BN_FULL_CONFIDENCE, BinaryNinja::Ref<BinaryNinja::Type> parentType = nullptr,
		BNTokenEscapingType escaping = NoTokenEscapingType) override;
	std::vector<BinaryNinja::InstructionTextToken> GetTypeTokensAfterName(
		BinaryNinja::Ref<BinaryNinja::Type> type, BinaryNinja::Ref<BinaryNinja::Platform> platform,
		uint8_t baseConfidence = BN_FULL_CONFIDENCE, BinaryNinja::Ref<BinaryNinja::Type> parentType = nullptr,
		BNTokenEscapingType escaping = NoTokenEscapingType) override;
	std::vector<BinaryNinja::TypeDefinitionLine> GetTypeLines(
		BinaryNinja::Ref<BinaryNinja::Type> type, const BinaryNinja::TypeContainer& types,
		const BinaryNinja::QualifiedName& name, int paddingCols = 64, bool collapsed = false,
		BNTokenEscapingType escaping = NoTokenEscapingType) override;

	std::vector<BinaryNinja::InstructionTextToken> GetTypeTokensAfterNameInternal(
		BinaryNinja::Ref<BinaryNinja::Type> type, BinaryNinja::Ref<BinaryNinja::Platform> platform,
		uint8_t baseConfidence = BN_FULL_CONFIDENCE, BinaryNinja::Ref<BinaryNinja::Type> parentType = nullptr,
		BNTokenEscapingType escaping = NoTokenEscapingType, bool functionHeader = false);
};
