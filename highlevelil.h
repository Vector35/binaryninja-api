#pragma once
#include "binaryninja_defs.h"

extern "C" {
	struct BNArchitecture;
	struct BNFunction;

	enum BNHighLevelILOperation
	{
		HLIL_NOP,

		HLIL_BLOCK,
		HLIL_IF,
		HLIL_WHILE,
		HLIL_DO_WHILE,
		HLIL_FOR,
		HLIL_SWITCH,
		HLIL_CASE,
		HLIL_BREAK,
		HLIL_CONTINUE,
		HLIL_JUMP,
		HLIL_RET,
		HLIL_NORET,
		HLIL_GOTO,
		HLIL_LABEL,

		HLIL_VAR_DECLARE,
		HLIL_VAR_INIT,
		HLIL_ASSIGN,
		HLIL_ASSIGN_UNPACK,
		HLIL_VAR,
		HLIL_STRUCT_FIELD,
		HLIL_ARRAY_INDEX,
		HLIL_SPLIT,
		HLIL_DEREF,
		HLIL_DEREF_FIELD,
		HLIL_ADDRESS_OF,
		HLIL_CONST,
		HLIL_CONST_PTR,
		HLIL_EXTERN_PTR,
		HLIL_FLOAT_CONST,
		HLIL_IMPORT,
		HLIL_ADD,
		HLIL_ADC,
		HLIL_SUB,
		HLIL_SBB,
		HLIL_AND,
		HLIL_OR,
		HLIL_XOR,
		HLIL_LSL,
		HLIL_LSR,
		HLIL_ASR,
		HLIL_ROL,
		HLIL_RLC,
		HLIL_ROR,
		HLIL_RRC,
		HLIL_MUL,
		HLIL_MULU_DP,
		HLIL_MULS_DP,
		HLIL_DIVU,
		HLIL_DIVU_DP,
		HLIL_DIVS,
		HLIL_DIVS_DP,
		HLIL_MODU,
		HLIL_MODU_DP,
		HLIL_MODS,
		HLIL_MODS_DP,
		HLIL_NEG,
		HLIL_NOT,
		HLIL_SX,
		HLIL_ZX,
		HLIL_LOW_PART,
		HLIL_CALL,
		HLIL_CMP_E,
		HLIL_CMP_NE,
		HLIL_CMP_SLT,
		HLIL_CMP_ULT,
		HLIL_CMP_SLE,
		HLIL_CMP_ULE,
		HLIL_CMP_SGE,
		HLIL_CMP_UGE,
		HLIL_CMP_SGT,
		HLIL_CMP_UGT,
		HLIL_TEST_BIT,
		HLIL_BOOL_TO_INT,
		HLIL_ADD_OVERFLOW,
		HLIL_SYSCALL,
		HLIL_TAILCALL,
		HLIL_INTRINSIC,
		HLIL_BP,
		HLIL_TRAP,
		HLIL_UNDEF,
		HLIL_UNIMPL,
		HLIL_UNIMPL_MEM,

		// Floating point
		HLIL_FADD,
		HLIL_FSUB,
		HLIL_FMUL,
		HLIL_FDIV,
		HLIL_FSQRT,
		HLIL_FNEG,
		HLIL_FABS,
		HLIL_FLOAT_TO_INT,
		HLIL_INT_TO_FLOAT,
		HLIL_FLOAT_CONV,
		HLIL_ROUND_TO_INT,
		HLIL_FLOOR,
		HLIL_CEIL,
		HLIL_FTRUNC,
		HLIL_FCMP_E,
		HLIL_FCMP_NE,
		HLIL_FCMP_LT,
		HLIL_FCMP_LE,
		HLIL_FCMP_GE,
		HLIL_FCMP_GT,
		HLIL_FCMP_O,
		HLIL_FCMP_UO,

		// The following instructions are only used in SSA form
		HLIL_WHILE_SSA,
		HLIL_DO_WHILE_SSA,
		HLIL_FOR_SSA,
		HLIL_VAR_INIT_SSA,
		HLIL_ASSIGN_MEM_SSA,
		HLIL_ASSIGN_UNPACK_MEM_SSA,
		HLIL_VAR_SSA,
		HLIL_ARRAY_INDEX_SSA,
		HLIL_DEREF_SSA,
		HLIL_DEREF_FIELD_SSA,
		HLIL_CALL_SSA,
		HLIL_SYSCALL_SSA,
		HLIL_INTRINSIC_SSA,
		HLIL_VAR_PHI,
		HLIL_MEM_PHI
	};

	struct BNHighLevelILInstruction
	{
		BNHighLevelILOperation operation;
		uint32_t sourceOperand;
		size_t size;
		uint64_t operands[5];
		uint64_t address;
		size_t parent;
	};

	// High-level IL
	BINARYNINJACOREAPI BNHighLevelILFunction* BNCreateHighLevelILFunction(BNArchitecture* arch, BNFunction* func);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNNewHighLevelILFunctionReference(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI void BNFreeHighLevelILFunction(BNHighLevelILFunction* func);

	BINARYNINJACOREAPI BNFunction* BNGetHighLevelILOwnerFunction(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI uint64_t BNHighLevelILGetCurrentAddress(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI void BNHighLevelILSetCurrentAddress(
		BNHighLevelILFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t BNHighLevelILAddExpr(BNHighLevelILFunction* func, BNHighLevelILOperation operation,
		size_t size, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e);
	BINARYNINJACOREAPI size_t BNHighLevelILAddExprWithLocation(BNHighLevelILFunction* func,
		BNHighLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size, uint64_t a, uint64_t b,
		uint64_t c, uint64_t d, uint64_t e);
	BINARYNINJACOREAPI size_t BNGetHighLevelILRootExpr(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI void BNSetHighLevelILRootExpr(BNHighLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI void BNFinalizeHighLevelILFunction(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI void BNGenerateHighLevelILSSAForm(BNHighLevelILFunction* func, BNVariable* aliases, size_t aliasCount);

	BINARYNINJACOREAPI size_t BNHighLevelILAddOperandList(
		BNHighLevelILFunction* func, uint64_t* operands, size_t count);
	BINARYNINJACOREAPI uint64_t* BNHighLevelILGetOperandList(
		BNHighLevelILFunction* func, size_t expr, size_t operand, size_t* count);
	BINARYNINJACOREAPI void BNHighLevelILFreeOperandList(uint64_t* operands);

	BINARYNINJACOREAPI BNHighLevelILInstruction BNGetHighLevelILByIndex(
		BNHighLevelILFunction* func, size_t i, bool asFullAst);
	BINARYNINJACOREAPI size_t BNGetHighLevelILIndexForInstruction(BNHighLevelILFunction* func, size_t i);
	BINARYNINJACOREAPI size_t BNGetHighLevelILInstructionForExpr(BNHighLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILInstructionCount(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetHighLevelILExprCount(BNHighLevelILFunction* func);

	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetMediumLevelILForHighLevelILFunction(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetMediumLevelILExprIndexFromHighLevelIL(BNHighLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t* BNGetMediumLevelILExprIndexesFromHighLevelIL(
		BNHighLevelILFunction* func, size_t expr, size_t* count);

	BINARYNINJACOREAPI void BNUpdateHighLevelILOperand(
		BNHighLevelILFunction* func, size_t instr, size_t operandIndex, uint64_t value);
	BINARYNINJACOREAPI void BNReplaceHighLevelILExpr(BNHighLevelILFunction* func, size_t expr, size_t newExpr);

	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetHighLevelILExprText(
		BNHighLevelILFunction* func, size_t expr, bool asFullAst, size_t* count, BNDisassemblySettings* settings);

	BINARYNINJACOREAPI BNTypeWithConfidence BNGetHighLevelILExprType(BNHighLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI BNBasicBlock** BNGetHighLevelILBasicBlockList(BNHighLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNBasicBlock* BNGetHighLevelILBasicBlockForInstruction(BNHighLevelILFunction* func, size_t i);

	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetHighLevelILSSAForm(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetHighLevelILNonSSAForm(BNHighLevelILFunction* func);
	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAInstructionIndex(BNHighLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILNonSSAInstructionIndex(BNHighLevelILFunction* func, size_t instr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAExprIndex(BNHighLevelILFunction* func, size_t expr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILNonSSAExprIndex(BNHighLevelILFunction* func, size_t expr);

	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAVarDefinition(
		BNHighLevelILFunction* func, const BNVariable* var, size_t version);
	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAMemoryDefinition(BNHighLevelILFunction* func, size_t version);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILSSAVarUses(
		BNHighLevelILFunction* func, const BNVariable* var, size_t version, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILSSAMemoryUses(
		BNHighLevelILFunction* func, size_t version, size_t* count);
	BINARYNINJACOREAPI bool BNIsHighLevelILSSAVarLive(
		BNHighLevelILFunction* func, const BNVariable* var, size_t version);
	BINARYNINJACOREAPI bool BNIsHighLevelILSSAVarLiveAt(
		BNHighLevelILFunction* func, const BNVariable* var, const size_t version, const size_t instr);
	BINARYNINJACOREAPI bool BNIsHighLevelILVarLiveAt(
		BNHighLevelILFunction* func, const BNVariable* var, const size_t instr);

	BINARYNINJACOREAPI BNVariable* BNGetHighLevelILVariables(BNHighLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNVariable* BNGetHighLevelILAliasedVariables(BNHighLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILVariableSSAVersions(
		BNHighLevelILFunction* func, const BNVariable* var, size_t* count);

	BINARYNINJACOREAPI size_t* BNGetHighLevelILVariableDefinitions(
		BNHighLevelILFunction* func, const BNVariable* var, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILVariableUses(
		BNHighLevelILFunction* func, const BNVariable* var, size_t* count);
	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAVarVersionAtILInstruction(
		BNHighLevelILFunction* func, const BNVariable* var, size_t instr);
	BINARYNINJACOREAPI size_t BNGetHighLevelILSSAMemoryVersionAtILInstruction(
		BNHighLevelILFunction* func, size_t instr);

	BINARYNINJACOREAPI size_t BNGetHighLevelILExprIndexForLabel(BNHighLevelILFunction* func, uint64_t label);
	BINARYNINJACOREAPI size_t* BNGetHighLevelILUsesForLabel(BNHighLevelILFunction* func, uint64_t label, size_t* count);

	BINARYNINJACOREAPI bool BNHighLevelILExprLessThan(
		BNHighLevelILFunction* leftFunc, size_t leftExpr, BNHighLevelILFunction* rightFunc, size_t rightExpr);
	BINARYNINJACOREAPI bool BNHighLevelILExprEqual(
		BNHighLevelILFunction* leftFunc, size_t leftExpr, BNHighLevelILFunction* rightFunc, size_t rightExpr);
}