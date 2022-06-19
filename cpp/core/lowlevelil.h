#pragma once
#include "core/binaryninja_defs.h"
#include "core/registervalue.h"

extern "C" {
	struct BNArchitecture;
	struct BNArchitectureAndAddress;
	struct BNBasicBlock;
	struct BNFunction;
	struct BNInstructionTextToken;
	struct BNLowLevelILFunction;
	struct BNMediumLevelILFunction;

	struct BNLowLevelILLabel
	{
		bool resolved;
		size_t ref;
		size_t operand;
	};

	struct BNRegisterOrConstant
	{
		bool constant;
		uint32_t reg;
		uint64_t value;
	};

	struct BNLowLevelILInstruction
	{
		BNLowLevelILOperation operation;
		size_t size;
		uint32_t flags;
		uint32_t sourceOperand;
		uint64_t operands[4];
		uint64_t address;
	};
	// Low-level IL
	BINARYNINJACOREAPI BNLowLevelILFunction* BNCreateLowLevelILFunction(BNArchitecture* arch, BNFunction* func);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNNewLowLevelILFunctionReference(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNFreeLowLevelILFunction(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI BNFunction* BNGetLowLevelILOwnerFunction(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI uint64_t BNLowLevelILGetCurrentAddress(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNLowLevelILSetCurrentAddress(
		BNLowLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI void BNLowLevelILSetCurrentSourceBlock(BNLowLevelILFunction* func, BNBasicBlock* source);
	BINARYNINJACOREAPI size_t BNLowLevelILGetInstructionStart(
		BNLowLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI void BNLowLevelILClearIndirectBranches(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNLowLevelILSetIndirectBranches(
		BNLowLevelILFunction* func, BNArchitectureAndAddress* branches, size_t count);
	BINARYNINJACOREAPI size_t BNLowLevelILAddExpr(BNLowLevelILFunction* func, BNLowLevelILOperation operation,
		size_t size, uint32_t flags, uint64_t a, uint64_t b, uint64_t c, uint64_t d);
	BINARYNINJACOREAPI size_t BNLowLevelILAddExprWithLocation(BNLowLevelILFunction* func, uint64_t addr,
		uint32_t sourceOperand, BNLowLevelILOperation operation, size_t size, uint32_t flags, uint64_t a, uint64_t b,
		uint64_t c, uint64_t d);
	BINARYNINJACOREAPI void BNLowLevelILSetExprSourceOperand(BNLowLevelILFunction* func, size_t expr, uint32_t operand);
	BINARYNINJACOREAPI size_t BNLowLevelILAddInstruction(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNLowLevelILGoto(BNLowLevelILFunction* func, BNLowLevelILLabel* label);
	BINARYNINJACOREAPI size_t BNLowLevelILGotoWithLocation(
		BNLowLevelILFunction* func, BNLowLevelILLabel* label, uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI size_t BNLowLevelILIf(
		BNLowLevelILFunction* func, uint64_t op, BNLowLevelILLabel* t, BNLowLevelILLabel* f);
	BINARYNINJACOREAPI size_t BNLowLevelILIfWithLocation(BNLowLevelILFunction* func, uint64_t op, BNLowLevelILLabel* t,
		BNLowLevelILLabel* f, uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI void BNLowLevelILInitLabel(BNLowLevelILLabel* label);
	BINARYNINJACOREAPI void BNLowLevelILMarkLabel(BNLowLevelILFunction* func, BNLowLevelILLabel* label);
	BINARYNINJACOREAPI void BNFinalizeLowLevelILFunction(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI void BNGenerateLowLevelILSSAForm(BNLowLevelILFunction* func);

	BINARYNINJACOREAPI void BNPrepareToCopyLowLevelILFunction(BNLowLevelILFunction* func, BNLowLevelILFunction* src);
	BINARYNINJACOREAPI void BNPrepareToCopyLowLevelILBasicBlock(BNLowLevelILFunction* func, BNBasicBlock* block);
	BINARYNINJACOREAPI BNLowLevelILLabel* BNGetLabelForLowLevelILSourceInstruction(
		BNLowLevelILFunction* func, size_t instr);

	BINARYNINJACOREAPI size_t BNLowLevelILAddLabelMap(
		BNLowLevelILFunction* func, uint64_t* values, BNLowLevelILLabel** labels, size_t count);
	BINARYNINJACOREAPI size_t BNLowLevelILAddOperandList(BNLowLevelILFunction* func, uint64_t* operands, size_t count);
	BINARYNINJACOREAPI uint64_t* BNLowLevelILGetOperandList(
		BNLowLevelILFunction* func, size_t expr, size_t operand, size_t* count);
	BINARYNINJACOREAPI void BNLowLevelILFreeOperandList(uint64_t* operands);

	BINARYNINJACOREAPI BNLowLevelILInstruction BNGetLowLevelILByIndex(BNLowLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetLowLevelILIndexForInstruction(BNLowLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetLowLevelILInstructionForExpr(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILInstructionCount(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILExprCount(BNLowLevelILFunction* func);

	BINARYNINJACOREAPI void BNUpdateLowLevelILOperand(
		BNLowLevelILFunction* func, size_t instr, size_t operandIndex, uint64_t value);
	BINARYNINJACOREAPI void BNReplaceLowLevelILExpr(BNLowLevelILFunction* func, size_t expr, size_t newExpr);

	BINARYNINJACOREAPI void BNAddLowLevelILLabelForAddress(
		BNLowLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI BNLowLevelILLabel* BNGetLowLevelILLabelForAddress(
		BNLowLevelILFunction* func, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI bool BNGetLowLevelILExprText(
		BNLowLevelILFunction* func, BNArchitecture* arch, size_t i, BNInstructionTextToken** tokens, size_t* count);
	BINARYNINJACOREAPI bool BNGetLowLevelILInstructionText(BNLowLevelILFunction* il, BNFunction* func,
		BNArchitecture* arch, size_t i, BNInstructionTextToken** tokens, size_t* count);

	BINARYNINJACOREAPI uint32_t BNGetLowLevelILTemporaryRegisterCount(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI uint32_t BNGetLowLevelILTemporaryFlagCount(BNLowLevelILFunction* func);

	BINARYNINJACOREAPI BNBasicBlock** BNGetLowLevelILBasicBlockList(BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock* BNGetLowLevelILBasicBlockForInstruction(BNLowLevelILFunction* func, size_t i);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetLowLevelILSSAForm(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetLowLevelILNonSSAForm(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILNonSSAInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAExprIndex(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILNonSSAExprIndex(BNLowLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI size_t BNGetLowLevelILSSARegisterDefinition(
		BNLowLevelILFunction* func, uint32_t reg, size_t version);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAFlagDefinition(
		BNLowLevelILFunction* func, uint32_t reg, size_t version);
	BINARYNINJACOREAPI size_t BNGetLowLevelILSSAMemoryDefinition(BNLowLevelILFunction* func, size_t version);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILSSARegisterUses(
		BNLowLevelILFunction* func, uint32_t reg, size_t version, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILSSAFlagUses(
		BNLowLevelILFunction* func, uint32_t reg, size_t version, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILSSAMemoryUses(BNLowLevelILFunction* func, size_t version, size_t* count);

	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILSSARegisterValue(
		BNLowLevelILFunction* func, uint32_t reg, size_t version);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILSSAFlagValue(
		BNLowLevelILFunction* func, uint32_t flag, size_t version);

	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILExprValue(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleExprValues(
		BNLowLevelILFunction* func, size_t expr, BNDataFlowQueryOption* options, size_t optionCount);

	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILRegisterValueAtInstruction(
		BNLowLevelILFunction* func, uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILRegisterValueAfterInstruction(
		BNLowLevelILFunction* func, uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleRegisterValuesAtInstruction(
		BNLowLevelILFunction* func, uint32_t reg, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleRegisterValuesAfterInstruction(
		BNLowLevelILFunction* func, uint32_t reg, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILFlagValueAtInstruction(
		BNLowLevelILFunction* func, uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILFlagValueAfterInstruction(
		BNLowLevelILFunction* func, uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleFlagValuesAtInstruction(
		BNLowLevelILFunction* func, uint32_t flag, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleFlagValuesAfterInstruction(
		BNLowLevelILFunction* func, uint32_t flag, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILStackContentsAtInstruction(
		BNLowLevelILFunction* func, int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetLowLevelILStackContentsAfterInstruction(
		BNLowLevelILFunction* func, int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleStackContentsAtInstruction(BNLowLevelILFunction* func,
		int64_t offset, size_t len, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetLowLevelILPossibleStackContentsAfterInstruction(
		BNLowLevelILFunction* func, int64_t offset, size_t len, size_t instr, BNDataFlowQueryOption* options,
		size_t optionCount);

	BINARYNINJACOREAPI uint32_t* BNGetLowLevelRegisters(BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetLowLevelRegisterStacks(BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetLowLevelFlags(BNLowLevelILFunction* func, size_t* count);

	BINARYNINJACOREAPI size_t* BNGetLowLevelRegisterSSAVersions(
		BNLowLevelILFunction* func, const uint32_t var, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelRegisterStackSSAVersions(
		BNLowLevelILFunction* func, const uint32_t var, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelFlagSSAVersions(
		BNLowLevelILFunction* func, const uint32_t var, size_t* count);

	BINARYNINJACOREAPI size_t* BNGetLowLevelMemoryVersions(BNLowLevelILFunction* func, size_t* count);

	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILForLowLevelIL(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMappedMediumLevelIL(BNLowLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILExprIndex(BNLowLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILExprIndexes(BNLowLevelILFunction* func, size_t expr, size_t* count);
	BINARYNINJACOREAPI size_t BNGetMappedMediumLevelILInstructionIndex(BNLowLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMappedMediumLevelILExprIndex(BNLowLevelILFunction* func, size_t expr);

}