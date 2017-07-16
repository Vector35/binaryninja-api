#ifndef __LOWLEVEL_IL_PARSER_H_
#define __LOWLEVEL_IL_PARSER_H_

#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include <map>

std::string get_plugins_directory();
void ShowBanner();

using namespace BinaryNinja;

enum OperandPurpose
{
	kDest,
	kSrc,
	kConstant,
	kLeft,
	kRight,
	kHi,
	kLow,
	kTargets,
	kCondition,
	kVector,
	kOutput,
	kStack,
	kParam,
	kDestMemory,
	kSrcMemory,
	kTrue,
	kFalse,
	kBit,
	kCarry,
	kFullReg,
};

enum OperandType
{
	kReg,
	kExpr,
	kFlag,
	kIntList,
	kInt,
	kRegSsa,
	kRegSsaList,
	kFlagSsa,
	kCond,
	kFlagSsaList,
};

struct BNLowLevelILOperationSyntax
{
	OperandPurpose purpose;
	OperandType type;
};


static std::map<BNLowLevelILOperation, std::vector<BNLowLevelILOperationSyntax>> g_llilSyntaxMap = { \
{ LLIL_NOP,{} }, \
{ LLIL_SET_REG,{ { kDest, kReg },{ kSrc,kExpr } } }, \
{ LLIL_SET_REG_SPLIT,{ { kHi, kReg },{ kLow,kReg },{ kSrc,kExpr } } } , \
{ LLIL_SET_FLAG,{ { kDest, kFlag },{ kSrc,kExpr } } }, \
{ LLIL_LOAD,{ { kSrc, kExpr } } }, \
{ LLIL_STORE,{ { kDest, kExpr },{ kSrc,kExpr } } }, \
{ LLIL_PUSH,{ { kSrc, kExpr } } }, \
{ LLIL_POP,{} }, \
{ LLIL_REG,{ { kSrc, kReg } } }, \
{ LLIL_CONST,{ { kConstant, kInt } } }, \
{ LLIL_CONST_PTR,{ { kConstant, kInt } } }, \
{ LLIL_FLAG,{ { kSrc, kFlag } } }, \
{ LLIL_FLAG_BIT,{ { kSrc, kFlag },{ kBit,kInt } } }, \
{ LLIL_ADD,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_ADC,{ { kLeft, kExpr },{ kRight,kExpr },{ kCarry,kExpr } } }, \
{ LLIL_SUB,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_SBB,{ { kLeft, kExpr },{ kRight,kExpr },{ kCarry,kExpr } } }, \
{ LLIL_AND,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_OR,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_XOR,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_LSL,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_LSR,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_ASR,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_ROL,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_RLC,{ { kLeft, kExpr },{ kRight,kExpr },{ kCarry,kExpr } } }, \
{ LLIL_ROR,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_RRC,{ { kLeft, kExpr },{ kRight,kExpr },{ kCarry,kExpr } } }, \
{ LLIL_MUL,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_MULU_DP,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_MULS_DP,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_DIVU,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_DIVU_DP,{ { kHi, kExpr },{ kLow,kExpr },{ kRight,kExpr } } }, \
{ LLIL_DIVS,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_DIVS_DP,{ { kHi, kExpr },{ kLow,kExpr },{ kRight,kExpr } } }, \
{ LLIL_MODU,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_MODU_DP,{ { kHi, kExpr },{ kLow,kExpr },{ kRight,kExpr } } }, \
{ LLIL_MODS,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_MODS_DP,{ { kHi, kExpr },{ kLow,kExpr },{ kRight,kExpr } } }, \
{ LLIL_NEG,{ { kSrc, kExpr } } }, \
{ LLIL_NOT,{ { kSrc, kExpr } } }, \
{ LLIL_SX,{ { kSrc, kExpr } } }, \
{ LLIL_ZX,{ { kSrc, kExpr } } }, \
{ LLIL_LOW_PART,{ { kSrc, kExpr } } }, \
{ LLIL_JUMP,{ { kDest, kExpr } } }, \
{ LLIL_JUMP_TO,{ { kDest, kExpr },{ kTargets,kIntList } } }, \
{ LLIL_CALL,{ { kDest, kExpr } } }, \
{ LLIL_RET,{ { kDest, kExpr } } }, \
{ LLIL_NORET,{} }, \
{ LLIL_IF,{ { kCondition, kExpr },{ kTrue,kInt },{ kFalse,kInt } } }, \
{ LLIL_GOTO,{ { kDest, kInt } } }, \
{ LLIL_FLAG_COND,{ { kCondition, kCond } } }, \
{ LLIL_CMP_E,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_CMP_NE,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_CMP_SLT,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_CMP_ULT,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_CMP_SLE,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_CMP_ULE,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_CMP_SGE,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_CMP_UGE,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_CMP_SGT,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_CMP_UGT,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_TEST_BIT,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_BOOL_TO_INT,{ { kSrc, kExpr } } }, \
{ LLIL_ADD_OVERFLOW,{ { kLeft, kExpr },{ kRight,kExpr } } }, \
{ LLIL_SYSCALL,{} }, \
{ LLIL_BP,{} }, \
{ LLIL_TRAP,{ { kVector, kInt } } }, \
{ LLIL_UNDEF,{} }, \
{ LLIL_UNIMPL,{} }, \
{ LLIL_UNIMPL_MEM,{ { kSrc, kExpr } } }, \
{ LLIL_SET_REG_SSA,{ { kDest, kRegSsa },{ kSrc,kExpr } } }, \
{ LLIL_IF,{ { kFullReg, kRegSsa },{ kDest,kReg },{ kSrc,kExpr } } }, \
{ LLIL_SET_REG_SPLIT_SSA,{ { kHi, kExpr },{ kLow,kExpr },{ kSrc,kExpr } } }, \
{ LLIL_REG_SPLIT_DEST_SSA,{ { kDest, kRegSsa } } }, \
{ LLIL_REG_SSA,{ { kSrc, kRegSsa } } }, \
{ LLIL_REG_SSA_PARTIAL,{ { kFullReg, kRegSsa },{ kSrc,kReg } } }, \
{ LLIL_SET_FLAG_SSA,{ { kDest, kFlagSsa },{ kSrc,kExpr } } }, \
{ LLIL_FLAG_SSA,{ { kSrc, kFlagSsa } } }, \
{ LLIL_FLAG_BIT_SSA,{ { kSrc, kFlagSsa },{ kBit, kInt } } }, \
{ LLIL_CALL_SSA,{ { kOutput, kExpr },{ kDest,kExpr },{ kStack,kExpr },{ kParam,kExpr } } }, \
{ LLIL_SYSCALL_SSA,{ { kOutput, kExpr },{ kStack,kExpr },{ kParam,kExpr } } }, \
{ LLIL_CALL_OUTPUT_SSA,{ { kDestMemory, kInt },{ kDest, kRegSsaList } } }, \
{ LLIL_CALL_STACK_SSA,{ { kSrc, kRegSsa },{ kSrcMemory, kInt } } }, \
{ LLIL_CALL_PARAM_SSA,{ { kSrc, kRegSsaList } } }, \
{ LLIL_LOAD_SSA,{ { kSrc, kExpr },{ kSrcMemory, kInt } } }, \
{ LLIL_STORE_SSA,{ { kDest, kExpr },{ kDestMemory,kInt },{ kSrcMemory,kInt },{ kSrc,kExpr } } }, \
{ LLIL_REG_PHI,{ { kDest, kRegSsa },{ kSrc, kRegSsaList } } }, \
{ LLIL_FLAG_PHI,{ { kDest, kFlagSsa },{ kSrc, kFlagSsaList } } }, \
{ LLIL_MEM_PHI,{ { kDestMemory, kInt },{ kSrcMemory, kIntList } } }, \
};


class LlilParser
{

public:
	LlilParser(BinaryView *bv);
	const std::string getLowLevelILOperationName(const BNLowLevelILOperation id) const;
	void decodeIndexInFunction(uint64_t functionAddress, int indexIl);
	void decodeWholeFunction(uint64_t functionAddress);
	void decodeWholeFunction(BinaryNinja::Function *function);
private:
	void showIndent() const;
	void analysisInstruction(const BNLowLevelILInstruction& insn);

	BinaryView *m_bv;
	std::vector<BinaryNinja::Ref<BinaryNinja::Function>> m_currentFunction;
	int m_tabs;
	size_t m_currentInstructionId;
};


#endif /* __LOWLEVEL_IL_PARSER_H_ */