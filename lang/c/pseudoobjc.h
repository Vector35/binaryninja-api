#pragma once

#include "pseudoc.h"

#include "binaryninjaapi.h"

class PseudoObjCFunction : public PseudoCFunction
{
public:
	PseudoObjCFunction(BinaryNinja::LanguageRepresentationFunctionType* type, BinaryNinja::Architecture* arch,
		BinaryNinja::Function* owner, BinaryNinja::HighLevelILFunction* highLevelILFunction);

protected:
	void GetExpr_CALL_OR_TAILCALL(const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		BNOperatorPrecedence precedence, bool statement) override;
	void GetExpr_CONST_PTR(const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		BNOperatorPrecedence precedence, bool statement) override;
	void GetExpr_IMPORT(const BinaryNinja::HighLevelILInstruction& instr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		BNOperatorPrecedence precedence, bool statement) override;

	bool ShouldSkipStatement(const BinaryNinja::HighLevelILInstruction& instr) override;

private:
	bool GetExpr_ObjCMsgSend(uint64_t msgSendAddress, bool isSuper, bool isRewritten, const BinaryNinja::HighLevelILInstruction& expr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		const std::vector<BinaryNinja::HighLevelILInstruction>& parameterExprs);
	bool GetExpr_GenericObjCRuntimeCall(uint64_t address, const BinaryNinja::HighLevelILInstruction& expr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		const std::vector<BinaryNinja::HighLevelILInstruction>& parameterExprs, const std::vector<std::string_view>& selectorTokens);
	bool GetExpr_TwoParamObjCRuntimeCall(uint64_t address, const BinaryNinja::HighLevelILInstruction& expr,
		BinaryNinja::HighLevelILTokenEmitter& tokens, BinaryNinja::DisassemblySettings* settings,
		const std::vector<BinaryNinja::HighLevelILInstruction>& parameterExprs, std::string_view selectorToken);
	bool GetExpr_OBJC_CLASS(const BinaryNinja::Symbol& symbol, uint64_t constant,
		const BinaryNinja::HighLevelILInstruction& expr, BinaryNinja::HighLevelILTokenEmitter& tokens,
		BinaryNinja::DisassemblySettings* settings, BNOperatorPrecedence precedence, bool statement);
	bool GetExpr_Selector(std::string_view selector, uint64_t constant,
		const BinaryNinja::HighLevelILInstruction& expr, BinaryNinja::HighLevelILTokenEmitter& tokens,
		BinaryNinja::DisassemblySettings* settings, BNOperatorPrecedence precedence, bool statement);
	bool GetExpr_NSConstantString(BinaryNinja::Ref<BinaryNinja::Type> type, uint64_t constant,
		const BinaryNinja::HighLevelILInstruction& expr, BinaryNinja::HighLevelILTokenEmitter& tokens,
		BinaryNinja::DisassemblySettings* settings, BNOperatorPrecedence precedence, bool statement);
};

class PseudoObjCFunctionType : public PseudoCFunctionType {
public:
	PseudoObjCFunctionType();
	BinaryNinja::Ref<BinaryNinja::LanguageRepresentationFunction> Create(BinaryNinja::Architecture* arch,
		BinaryNinja::Function* owner, BinaryNinja::HighLevelILFunction* highLevelILFunction) override;
	BinaryNinja::Ref<BinaryNinja::TypePrinter> GetTypePrinter() override;
};
