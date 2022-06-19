#pragma once
#include "core/binaryninja_defs.h"
#include "core/registervalue.h"

extern "C" {
	struct BNArchitecture;
	struct BNArchitectureAndAddress;
	struct BNBasicBlock;
	struct BNFunction;
	struct BNInstructionTextToken;
	struct BNLowLevelILLabel;
	struct BNMediumLevelILFunction;
	struct BNDisassemblySettings;
	struct BNHighLevelILFunction;
	struct BNLowLevelILFunction;

	enum BNMediumLevelILOperation
	{
		MLIL_NOP,
		MLIL_SET_VAR,        // Not valid in SSA form (see MLIL_SET_VAR_SSA)
		MLIL_SET_VAR_FIELD,  // Not valid in SSA form (see MLIL_SET_VAR_FIELD)
		MLIL_SET_VAR_SPLIT,  // Not valid in SSA form (see MLIL_SET_VAR_SPLIT_SSA)
		MLIL_LOAD,           // Not valid in SSA form (see MLIL_LOAD_SSA)
		MLIL_LOAD_STRUCT,    // Not valid in SSA form (see MLIL_LOAD_STRUCT_SSA)
		MLIL_STORE,          // Not valid in SSA form (see MLIL_STORE_SSA)
		MLIL_STORE_STRUCT,   // Not valid in SSA form (see MLIL_STORE_STRUCT_SSA)
		MLIL_VAR,            // Not valid in SSA form (see MLIL_VAR_SSA)
		MLIL_VAR_FIELD,      // Not valid in SSA form (see MLIL_VAR_SSA_FIELD)
		MLIL_VAR_SPLIT,      // Not valid in SSA form (see MLIL_VAR_SPLIT_SSA)
		MLIL_ADDRESS_OF,
		MLIL_ADDRESS_OF_FIELD,
		MLIL_CONST,
		MLIL_CONST_PTR,
		MLIL_EXTERN_PTR,
		MLIL_FLOAT_CONST,
		MLIL_IMPORT,
		MLIL_ADD,
		MLIL_ADC,
		MLIL_SUB,
		MLIL_SBB,
		MLIL_AND,
		MLIL_OR,
		MLIL_XOR,
		MLIL_LSL,
		MLIL_LSR,
		MLIL_ASR,
		MLIL_ROL,
		MLIL_RLC,
		MLIL_ROR,
		MLIL_RRC,
		MLIL_MUL,
		MLIL_MULU_DP,
		MLIL_MULS_DP,
		MLIL_DIVU,
		MLIL_DIVU_DP,
		MLIL_DIVS,
		MLIL_DIVS_DP,
		MLIL_MODU,
		MLIL_MODU_DP,
		MLIL_MODS,
		MLIL_MODS_DP,
		MLIL_NEG,
		MLIL_NOT,
		MLIL_SX,
		MLIL_ZX,
		MLIL_LOW_PART,
		MLIL_JUMP,
		MLIL_JUMP_TO,
		MLIL_RET_HINT,      // Intermediate stages, does not appear in final forms
		MLIL_CALL,          // Not valid in SSA form (see MLIL_CALL_SSA)
		MLIL_CALL_UNTYPED,  // Not valid in SSA form (see MLIL_CALL_UNTYPED_SSA)
		MLIL_CALL_OUTPUT,   // Only valid within MLIL_CALL, MLIL_SYSCALL, MLIL_TAILCALL family instructions
		MLIL_CALL_PARAM,    // Only valid within MLIL_CALL, MLIL_SYSCALL, MLIL_TAILCALL family instructions
		MLIL_RET,
		MLIL_NORET,
		MLIL_IF,
		MLIL_GOTO,
		MLIL_CMP_E,
		MLIL_CMP_NE,
		MLIL_CMP_SLT,
		MLIL_CMP_ULT,
		MLIL_CMP_SLE,
		MLIL_CMP_ULE,
		MLIL_CMP_SGE,
		MLIL_CMP_UGE,
		MLIL_CMP_SGT,
		MLIL_CMP_UGT,
		MLIL_TEST_BIT,
		MLIL_BOOL_TO_INT,
		MLIL_ADD_OVERFLOW,
		MLIL_SYSCALL,           // Not valid in SSA form (see MLIL_SYSCALL_SSA)
		MLIL_SYSCALL_UNTYPED,   // Not valid in SSA form (see MLIL_SYSCALL_UNTYPED_SSA)
		MLIL_TAILCALL,          // Not valid in SSA form (see MLIL_TAILCALL_SSA)
		MLIL_TAILCALL_UNTYPED,  // Not valid in SSA form (see MLIL_TAILCALL_UNTYPED_SSA)
		MLIL_INTRINSIC,         // Not valid in SSA form (see MLIL_INTRINSIC_SSA)
		MLIL_FREE_VAR_SLOT,     // Not valid in SSA from (see MLIL_FREE_VAR_SLOT_SSA)
		MLIL_BP,
		MLIL_TRAP,
		MLIL_UNDEF,
		MLIL_UNIMPL,
		MLIL_UNIMPL_MEM,

		// Floating point
		MLIL_FADD,
		MLIL_FSUB,
		MLIL_FMUL,
		MLIL_FDIV,
		MLIL_FSQRT,
		MLIL_FNEG,
		MLIL_FABS,
		MLIL_FLOAT_TO_INT,
		MLIL_INT_TO_FLOAT,
		MLIL_FLOAT_CONV,
		MLIL_ROUND_TO_INT,
		MLIL_FLOOR,
		MLIL_CEIL,
		MLIL_FTRUNC,
		MLIL_FCMP_E,
		MLIL_FCMP_NE,
		MLIL_FCMP_LT,
		MLIL_FCMP_LE,
		MLIL_FCMP_GE,
		MLIL_FCMP_GT,
		MLIL_FCMP_O,
		MLIL_FCMP_UO,

		// The following instructions are only used in SSA form
		MLIL_SET_VAR_SSA,
		MLIL_SET_VAR_SSA_FIELD,
		MLIL_SET_VAR_SPLIT_SSA,
		MLIL_SET_VAR_ALIASED,
		MLIL_SET_VAR_ALIASED_FIELD,
		MLIL_VAR_SSA,
		MLIL_VAR_SSA_FIELD,
		MLIL_VAR_ALIASED,
		MLIL_VAR_ALIASED_FIELD,
		MLIL_VAR_SPLIT_SSA,
		MLIL_CALL_SSA,
		MLIL_CALL_UNTYPED_SSA,
		MLIL_SYSCALL_SSA,
		MLIL_SYSCALL_UNTYPED_SSA,
		MLIL_TAILCALL_SSA,
		MLIL_TAILCALL_UNTYPED_SSA,
		MLIL_CALL_PARAM_SSA,   // Only valid within the MLIL_CALL_SSA, MLIL_SYSCALL_SSA, MLIL_TAILCALL_SSA family
							   // instructions
		MLIL_CALL_OUTPUT_SSA,  // Only valid within the MLIL_CALL_SSA or MLIL_SYSCALL_SSA, MLIL_TAILCALL_SSA family
							   // instructions
		MLIL_LOAD_SSA,
		MLIL_LOAD_STRUCT_SSA,
		MLIL_STORE_SSA,
		MLIL_STORE_STRUCT_SSA,
		MLIL_INTRINSIC_SSA,
		MLIL_FREE_VAR_SLOT_SSA,
		MLIL_VAR_PHI,
		MLIL_MEM_PHI
	};

	struct BNMediumLevelILInstruction
	{
		BNMediumLevelILOperation operation;
		uint32_t sourceOperand;
		size_t size;
		uint64_t operands[5];
		uint64_t address;
	};

	enum BNILBranchDependence
	{
		NotBranchDependent,
		TrueBranchDependent,
		FalseBranchDependent
	};

	struct BNILBranchInstructionAndDependence
	{
		size_t branch;
		BNILBranchDependence dependence;
	};

	struct BNMediumLevelILLabel
	{
		bool resolved;
		size_t ref;
		size_t operand;
	};

	// Medium-level IL
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNCreateMediumLevelILFunction(BNArchitecture* arch, BNFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNNewMediumLevelILFunctionReference(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNFreeMediumLevelILFunction(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI BNFunction* BNGetMediumLevelILOwnerFunction(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI uint64_t BNMediumLevelILGetCurrentAddress(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNMediumLevelILSetCurrentAddress(
		BNMediumLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t BNMediumLevelILGetInstructionStart(
		BNMediumLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddExpr(BNMediumLevelILFunction* func, BNMediumLevelILOperation operation,
		size_t size, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddExprWithLocation(BNMediumLevelILFunction* func,
		BNMediumLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size, uint64_t a, uint64_t b,
		uint64_t c, uint64_t d, uint64_t e);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddInstruction(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNMediumLevelILGoto(BNMediumLevelILFunction* func, BNMediumLevelILLabel* label);
	BINARYNINJACOREAPI size_t BNMediumLevelILGotoWithLocation(
		BNMediumLevelILFunction* func, BNMediumLevelILLabel* label, uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI size_t BNMediumLevelILIf(
		BNMediumLevelILFunction* func, uint64_t op, BNMediumLevelILLabel* t, BNMediumLevelILLabel* f);
	BINARYNINJACOREAPI size_t BNMediumLevelILIfWithLocation(BNMediumLevelILFunction* func, uint64_t op,
		BNMediumLevelILLabel* t, BNMediumLevelILLabel* f, uint64_t addr, uint32_t sourceOperand);
	BINARYNINJACOREAPI void BNMediumLevelILInitLabel(BNMediumLevelILLabel* label);
	BINARYNINJACOREAPI void BNMediumLevelILMarkLabel(BNMediumLevelILFunction* func, BNMediumLevelILLabel* label);
	BINARYNINJACOREAPI void BNFinalizeMediumLevelILFunction(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI void BNGenerateMediumLevelILSSAForm(BNMediumLevelILFunction* func, bool analyzeConditionals,
		bool handleAliases, BNVariable* knownNotAliases, size_t knownNotAliasCount, BNVariable* knownAliases,
		size_t knownAliasCount);

	BINARYNINJACOREAPI void BNPrepareToCopyMediumLevelILFunction(
		BNMediumLevelILFunction* func, BNMediumLevelILFunction* src);
	BINARYNINJACOREAPI void BNPrepareToCopyMediumLevelILBasicBlock(BNMediumLevelILFunction* func, BNBasicBlock* block);
	BINARYNINJACOREAPI BNMediumLevelILLabel* BNGetLabelForMediumLevelILSourceInstruction(
		BNMediumLevelILFunction* func, size_t instr);

	BINARYNINJACOREAPI size_t BNMediumLevelILAddLabelMap(
		BNMediumLevelILFunction* func, uint64_t* values, BNMediumLevelILLabel** labels, size_t count);
	BINARYNINJACOREAPI size_t BNMediumLevelILAddOperandList(
		BNMediumLevelILFunction* func, uint64_t* operands, size_t count);
	BINARYNINJACOREAPI uint64_t* BNMediumLevelILGetOperandList(
		BNMediumLevelILFunction* func, size_t expr, size_t operand, size_t* count);
	BINARYNINJACOREAPI void BNMediumLevelILFreeOperandList(uint64_t* operands);

	BINARYNINJACOREAPI BNMediumLevelILInstruction BNGetMediumLevelILByIndex(BNMediumLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILIndexForInstruction(BNMediumLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILInstructionForExpr(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILInstructionCount(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILExprCount(BNMediumLevelILFunction* func);

	BINARYNINJACOREAPI void BNUpdateMediumLevelILOperand(
		BNMediumLevelILFunction* func, size_t instr, size_t operandIndex, uint64_t value);
	BINARYNINJACOREAPI void BNMarkMediumLevelILInstructionForRemoval(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI void BNReplaceMediumLevelILInstruction(BNMediumLevelILFunction* func, size_t instr, size_t expr);
	BINARYNINJACOREAPI void BNReplaceMediumLevelILExpr(BNMediumLevelILFunction* func, size_t expr, size_t newExpr);

	BINARYNINJACOREAPI bool BNGetMediumLevelILExprText(BNMediumLevelILFunction* func, BNArchitecture* arch, size_t i,
		BNInstructionTextToken** tokens, size_t* count, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI bool BNGetMediumLevelILInstructionText(BNMediumLevelILFunction* il, BNFunction* func,
		BNArchitecture* arch, size_t i, BNInstructionTextToken** tokens, size_t* count,
		BNDisassemblySettings* settings);

	BINARYNINJACOREAPI BNBasicBlock** BNGetMediumLevelILBasicBlockList(BNMediumLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock* BNGetMediumLevelILBasicBlockForInstruction(
		BNMediumLevelILFunction* func, size_t i);

	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILSSAForm(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILNonSSAForm(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILNonSSAInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAExprIndex(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILNonSSAExprIndex(BNMediumLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAVarDefinition(
		BNMediumLevelILFunction* func, const BNVariable* var, size_t version);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAMemoryDefinition(BNMediumLevelILFunction* func, size_t version);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILSSAVarUses(
		BNMediumLevelILFunction* func, const BNVariable* var, size_t version, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILSSAMemoryUses(
		BNMediumLevelILFunction* func, size_t version, size_t* count);
	BINARYNINJACOREAPI bool BNIsMediumLevelILSSAVarLive(
		BNMediumLevelILFunction* func, const BNVariable* var, size_t version);

	BINARYNINJACOREAPI BNVariable* BNGetMediumLevelILVariables(BNMediumLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNVariable* BNGetMediumLevelILAliasedVariables(BNMediumLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILVariableSSAVersions(
		BNMediumLevelILFunction* func, const BNVariable* var, size_t* count);

	BINARYNINJACOREAPI size_t* BNGetMediumLevelILVariableDefinitions(
		BNMediumLevelILFunction* func, const BNVariable* var, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILVariableUses(
		BNMediumLevelILFunction* func, const BNVariable* var, size_t* count);

	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILSSAVarValue(
		BNMediumLevelILFunction* func, const BNVariable* var, size_t version);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILExprValue(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleSSAVarValues(BNMediumLevelILFunction* func,
		const BNVariable* var, size_t version, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleExprValues(
		BNMediumLevelILFunction* func, size_t expr, BNDataFlowQueryOption* options, size_t optionCount);

	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAVarVersionAtILInstruction(
		BNMediumLevelILFunction* func, const BNVariable* var, size_t instr);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILSSAMemoryVersionAtILInstruction(
		BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI BNVariable BNGetMediumLevelILVariableForRegisterAtInstruction(
		BNMediumLevelILFunction* func, uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNVariable BNGetMediumLevelILVariableForFlagAtInstruction(
		BNMediumLevelILFunction* func, uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNVariable BNGetMediumLevelILVariableForStackLocationAtInstruction(
		BNMediumLevelILFunction* func, int64_t offset, size_t instr);

	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILRegisterValueAtInstruction(
		BNMediumLevelILFunction* func, uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILRegisterValueAfterInstruction(
		BNMediumLevelILFunction* func, uint32_t reg, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleRegisterValuesAtInstruction(
		BNMediumLevelILFunction* func, uint32_t reg, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleRegisterValuesAfterInstruction(
		BNMediumLevelILFunction* func, uint32_t reg, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILFlagValueAtInstruction(
		BNMediumLevelILFunction* func, uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILFlagValueAfterInstruction(
		BNMediumLevelILFunction* func, uint32_t flag, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleFlagValuesAtInstruction(
		BNMediumLevelILFunction* func, uint32_t flag, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleFlagValuesAfterInstruction(
		BNMediumLevelILFunction* func, uint32_t flag, size_t instr, BNDataFlowQueryOption* options, size_t optionCount);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILStackContentsAtInstruction(
		BNMediumLevelILFunction* func, int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNRegisterValue BNGetMediumLevelILStackContentsAfterInstruction(
		BNMediumLevelILFunction* func, int64_t offset, size_t len, size_t instr);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleStackContentsAtInstruction(
		BNMediumLevelILFunction* func, int64_t offset, size_t len, size_t instr, BNDataFlowQueryOption* options,
		size_t optionCount);
	BINARYNINJACOREAPI BNPossibleValueSet BNGetMediumLevelILPossibleStackContentsAfterInstruction(
		BNMediumLevelILFunction* func, int64_t offset, size_t len, size_t instr, BNDataFlowQueryOption* options,
		size_t optionCount);

	BINARYNINJACOREAPI BNILBranchDependence BNGetMediumLevelILBranchDependence(
		BNMediumLevelILFunction* func, size_t curInstr, size_t branchInstr);
	BINARYNINJACOREAPI BNILBranchInstructionAndDependence* BNGetAllMediumLevelILBranchDependence(
		BNMediumLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI void BNFreeILBranchDependenceList(BNILBranchInstructionAndDependence* branches);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetLowLevelILForMediumLevelIL(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetLowLevelILExprIndex(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILExprIndexes(BNMediumLevelILFunction* func, size_t expr, size_t* count);

	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetHighLevelILForMediumLevelIL(BNMediumLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetHighLevelILInstructionIndex(BNMediumLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILExprIndex(BNMediumLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILExprIndexes(BNMediumLevelILFunction* func, size_t expr, size_t* count);

	BINARYNINJACOREAPI BNTypeWithConfidence BNGetMediumLevelILExprType(BNMediumLevelILFunction* func, size_t expr);
}