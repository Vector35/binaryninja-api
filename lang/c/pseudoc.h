#pragma once

#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"

class PseudoCFunction: public BinaryNinja::LanguageRepresentationFunction
{
	BinaryNinja::Ref<BinaryNinja::HighLevelILFunction> m_highLevelIL;
	BinaryNinja::Ref<BinaryNinja::TypePrinter> m_typePrinter;

	enum FieldDisplayType
	{
		FieldDisplayName,
		FieldDisplayOffset,
		FieldDisplayMemberOffset,
		FieldDisplayNone
	};

	struct TernaryInfo
	{
		BinaryNinja::HighLevelILInstruction conditional;
		BinaryNinja::HighLevelILInstruction assignDest;
		BinaryNinja::HighLevelILInstruction trueAssign;
		BinaryNinja::HighLevelILInstruction falseAssign;
	};

	std::optional<PseudoCFunction::TernaryInfo> CanSimplifyToTernary(
		const BinaryNinja::HighLevelILInstruction& instr
	) const;
	bool TryEmitSimplifiedTernary(
		const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::DisassemblySettings* settings,
		BinaryNinja::HighLevelILTokenEmitter& emitter
	);

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
	void AppendTwoOperandFunctionWithCarry(const std::string& function, const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings);
	void AppendFieldTextTokens(const BinaryNinja::HighLevelILInstruction& var, uint64_t offset, size_t memberIndex, size_t size,
		BinaryNinja::HighLevelILTokenEmitter& tokens, bool deref, bool displayDeref = true);
	void AppendDefaultSplitExpr(const BinaryNinja::HighLevelILInstruction& instr, BinaryNinja::HighLevelILTokenEmitter& tokens,
		BinaryNinja::DisassemblySettings* settings, BNOperatorPrecedence precedence);
	void GetExprTextInternal(const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		BNOperatorPrecedence precedence = TopLevelOperatorPrecedence, bool statement = false,
		std::optional<bool> signedHint = std::nullopt);

protected:
	void InitTokenEmitter(BinaryNinja::HighLevelILTokenEmitter& tokens) override;
	void GetExprText(const BinaryNinja::HighLevelILInstruction& instr, BinaryNinja::HighLevelILTokenEmitter& tokens,
		BinaryNinja::DisassemblySettings* settings, BNOperatorPrecedence precedence = TopLevelOperatorPrecedence,
		bool statement = false) override;
	void BeginLines(
		const BinaryNinja::HighLevelILInstruction& instr, BinaryNinja::HighLevelILTokenEmitter& tokens) override;
	void EndLines(
		const BinaryNinja::HighLevelILInstruction& instr, BinaryNinja::HighLevelILTokenEmitter& tokens) override;

	BinaryNinja::TypePrinter* GetTypePrinter() const;

	virtual bool ShouldSkipStatement(const BinaryNinja::HighLevelILInstruction& instr);
	virtual void GetExpr_CALL_OR_TAILCALL(const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		BNOperatorPrecedence precedence, bool statement);
	virtual void GetExpr_CONST_PTR(const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		BNOperatorPrecedence precedence, bool statement);
	virtual void GetExpr_IMPORT(const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		BNOperatorPrecedence precedence, bool statement);

public:
	PseudoCFunction(BinaryNinja::LanguageRepresentationFunctionType* type, BinaryNinja::Architecture* arch,
		BinaryNinja::Function* owner, BinaryNinja::HighLevelILFunction* highLevelILFunction);

	std::string GetAnnotationStartString() const override;
	std::string GetAnnotationEndString() const override;
};

class PseudoCFunctionType: public BinaryNinja::LanguageRepresentationFunctionType
{
public:
	PseudoCFunctionType();
	BinaryNinja::Ref<BinaryNinja::LanguageRepresentationFunction> Create(BinaryNinja::Architecture* arch,
		BinaryNinja::Function* owner, BinaryNinja::HighLevelILFunction* highLevelILFunction) override;

protected:
	PseudoCFunctionType(const std::string& name);
};
