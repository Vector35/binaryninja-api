#pragma once

#include "binaryninjaapi.h"

class PseudoRustFunction: public BinaryNinja::LanguageRepresentationFunction
{
	BinaryNinja::Ref<BinaryNinja::HighLevelILFunction> m_highLevelIL;

	enum FieldDisplayType
	{
		FieldDisplayName,
		FieldDisplayOffset,
		FieldDisplayMemberOffset,
		FieldDisplayNone
	};

	enum ExpressionType
	{
		StatementExpression,
		TrailingStatementExpression,
		InnerExpression
	};

	BinaryNinja::Ref<BinaryNinja::Type> GetFieldType(const BinaryNinja::HighLevelILInstruction& var, bool deref);
	FieldDisplayType GetFieldDisplayType(BinaryNinja::Ref<BinaryNinja::Type> type, uint64_t offset, size_t memberIndex, bool deref);

	BNSymbolDisplayResult AppendPointerTextToken(const BinaryNinja::HighLevelILInstruction& instr, int64_t val,
		std::vector<BinaryNinja::InstructionTextToken>& tokens, BinaryNinja::DisassemblySettings* settings,
		BNSymbolDisplayType symbolDisplay, BNOperatorPrecedence precedence);
	std::string GetSizeToken(size_t size, bool isSigned);
	void AppendSizeToken(size_t size, bool isSigned, BinaryNinja::HighLevelILTokenEmitter& emitter);
	void AppendSingleSizeToken(size_t size, BNInstructionTextTokenType type, BinaryNinja::HighLevelILTokenEmitter& emitter);
	void AppendComparison(const std::string& comparison, const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& emitter, BinaryNinja::DisassemblySettings* settings,
		BNOperatorPrecedence precedence, std::optional<bool> signedHint = std::nullopt);
	void AppendTwoOperand(const std::string& operand, const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& emitter, BinaryNinja::DisassemblySettings* settings,
		BNOperatorPrecedence precedence, std::optional<bool> signedHint = std::nullopt);
	void AppendTwoOperandFunction(const std::string& function, const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings, bool sizeToken = true);
	void AppendTwoOperandMethodCall(const std::string& function, const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings);
	void AppendTwoOperandFunctionWithCarry(const std::string& function, const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings);
	void AppendFieldTextTokens(const BinaryNinja::HighLevelILInstruction& var, uint64_t offset, size_t memberIndex, size_t size,
		BinaryNinja::HighLevelILTokenEmitter& tokens, bool deref);
	bool IsMutable(const BinaryNinja::Variable& var) const;

	void GetExprText(const BinaryNinja::HighLevelILInstruction& instr, BinaryNinja::HighLevelILTokenEmitter& tokens,
		BinaryNinja::DisassemblySettings* settings, BNOperatorPrecedence precedence = TopLevelOperatorPrecedence,
		ExpressionType exprType = InnerExpression, std::optional<bool> signedHint = std::nullopt);

protected:
	virtual void InitTokenEmitter(BinaryNinja::HighLevelILTokenEmitter& tokens) override;
	virtual void GetExprText(const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		BNOperatorPrecedence precedence, bool statement) override;
	virtual void BeginLines(const BinaryNinja::HighLevelILInstruction& instr, BinaryNinja::HighLevelILTokenEmitter& tokens) override;
	virtual void EndLines(const BinaryNinja::HighLevelILInstruction& instr, BinaryNinja::HighLevelILTokenEmitter& tokens) override;

public:
	PseudoRustFunction(BinaryNinja::LanguageRepresentationFunctionType* type, BinaryNinja::Architecture* arch,
		BinaryNinja::Function* owner, BinaryNinja::HighLevelILFunction* highLevelILFunction);

	std::string GetAnnotationStartString() const override;
	std::string GetAnnotationEndString() const override;
};

class PseudoRustFunctionType: public BinaryNinja::LanguageRepresentationFunctionType
{
	BinaryNinja::Ref<BinaryNinja::TypePrinter> m_typePrinter;

public:
	PseudoRustFunctionType();
	BinaryNinja::Ref<BinaryNinja::LanguageRepresentationFunction> Create(BinaryNinja::Architecture* arch,
		BinaryNinja::Function* owner, BinaryNinja::HighLevelILFunction* highLevelILFunction) override;
	BinaryNinja::Ref<BinaryNinja::TypePrinter> GetTypePrinter() override;
	std::vector<BinaryNinja::DisassemblyTextLine> GetFunctionTypeTokens(BinaryNinja::Function* func,
		BinaryNinja::DisassemblySettings* settings) override;
};
