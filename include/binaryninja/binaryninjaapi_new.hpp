#pragma once
#include "binaryninjacore/binaryninja_defs.h"

#ifndef BINARYNINJACORE_LIBRARY
	#include "refcount.hpp"
#endif

namespace BinaryNinja
{
	// ReferenceSource describes code reference source; TypeReferenceSource describes type reference source.
	// When we query references, code references return vector<ReferenceSource>, data references return
	// vector<uint64_t>, type references return vector<TypeReferenceSource>.
	class Function;
	class Architecture;
	class Type;

	struct ReferenceSource
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
	};

	struct DisassemblyTextLineTypeInfo
	{
		bool hasTypeInfo;
		Ref<Type> parentType;
		size_t fieldIndex;
		uint64_t offset;

		DisassemblyTextLineTypeInfo() : hasTypeInfo(false), parentType(nullptr), fieldIndex(-1), offset(0) {}
	};

	class Tag;
	class BasicBlock;
	struct InstructionTextToken;

	struct DisassemblyTextLine
	{
		uint64_t addr;
		size_t instrIndex;
		std::vector<InstructionTextToken> tokens;
		BNHighlightColor highlight;
		std::vector<Ref<Tag>> tags;
		DisassemblyTextLineTypeInfo typeInfo;

		DisassemblyTextLine();
	};

	struct LinearDisassemblyLine
	{
		BNLinearDisassemblyLineType type;
		Ref<Function> function;
		Ref<BasicBlock> block;
		DisassemblyTextLine contents;

		static LinearDisassemblyLine FromAPIObject(BNLinearDisassemblyLine* line);
	};


	struct InstructionTextToken
	{
		enum
		{
			WidthIsByteCount = 0
		};

		BNInstructionTextTokenType type;
		std::string text;
		uint64_t value;
		uint64_t width;
		size_t size, operand;
		BNInstructionTextTokenContext context;
		uint8_t confidence;
		uint64_t address;
		std::vector<std::string> typeNames;

		InstructionTextToken();
		InstructionTextToken(uint8_t confidence, BNInstructionTextTokenType t, const std::string& txt);
		InstructionTextToken(BNInstructionTextTokenType type, const std::string& text, uint64_t value = 0,
		    size_t size = 0, size_t operand = BN_INVALID_OPERAND, uint8_t confidence = BN_FULL_CONFIDENCE,
		    const std::vector<std::string>& typeName = {}, uint64_t width = WidthIsByteCount);
		InstructionTextToken(BNInstructionTextTokenType type, BNInstructionTextTokenContext context,
		    const std::string& text, uint64_t address, uint64_t value = 0, size_t size = 0,
		    size_t operand = BN_INVALID_OPERAND, uint8_t confidence = BN_FULL_CONFIDENCE,
		    const std::vector<std::string>& typeName = {}, uint64_t width = WidthIsByteCount);
		InstructionTextToken(const BNInstructionTextToken& token);

		InstructionTextToken WithConfidence(uint8_t conf);
		static BNInstructionTextToken* CreateInstructionTextTokenList(const std::vector<InstructionTextToken>& tokens);
		static void FreeInstructionTextTokenList(
		    BNInstructionTextToken* tokens, size_t count);
		static std::vector<InstructionTextToken> ConvertAndFreeInstructionTextTokenList(
		    BNInstructionTextToken* tokens, size_t count);
		static std::vector<InstructionTextToken> ConvertInstructionTextTokenList(
		    const BNInstructionTextToken* tokens, size_t count);
	};

	std::string GetUniqueIdentifierString();
}