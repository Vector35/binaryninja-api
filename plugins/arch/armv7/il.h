#pragma once

#include "binaryninjaapi.h"
#include "armv7.h"

#define IL_FLAG_N 0
#define IL_FLAG_Z 2
#define IL_FLAG_C 4
#define IL_FLAG_V 6
#define IL_FLAG_Q 8

#define IL_FLAGWRITE_NONE 0
#define IL_FLAGWRITE_ALL 1
#define IL_FLAGWRITE_NZ 2
#define IL_FLAGWRITE_CNZ 3

struct decomp_result;

enum Armv7Intrinsic : uint32_t
{
	ARMV7_INTRIN_DBG,
	ARMV7_INTRIN_DMB_SY,
	ARMV7_INTRIN_DMB_ST,
	ARMV7_INTRIN_DMB_ISH,
	ARMV7_INTRIN_DMB_ISHST,
	ARMV7_INTRIN_DMB_NSH,
	ARMV7_INTRIN_DMB_NSHST,
	ARMV7_INTRIN_DMB_OSH,
	ARMV7_INTRIN_DMB_OSHST,
	ARMV7_INTRIN_DSB_SY,
	ARMV7_INTRIN_DSB_ST,
	ARMV7_INTRIN_DSB_ISH,
	ARMV7_INTRIN_DSB_ISHST,
	ARMV7_INTRIN_DSB_NSH,
	ARMV7_INTRIN_DSB_NSHST,
	ARMV7_INTRIN_DSB_OSH,
	ARMV7_INTRIN_DSB_OSHST,
	ARMV7_INTRIN_ISB,
	ARMV7_INTRIN_MRS,
	ARMV7_INTRIN_MSR,
	ARMV7_INTRIN_SEV,
	ARMV7_INTRIN_WFE,
	ARMV7_INTRIN_WFI,
	ARM_M_INTRIN_SET_BASEPRI,
	// Following names are from Table D17-2 of ARM DDI 0406C.d, changed  from
	// CamelCase to UPPERCASE with underscores preserved and ARMV7_INTRIN_ prefixed.
	ARMV7_INTRIN_COPROC_GETONEWORD, // MRC, MRC2
	ARMV7_INTRIN_COPROC_GETTWOWORDS, // MRRC, MRRC2
	ARMV7_INTRIN_COPROC_SENDONEWORD, // MCR, MCR2
	ARMV7_INTRIN_COPROC_SENDTWOWORDS, // MCRR, MCRR2

	ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS,
	ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS,
};

enum ArmFakeRegister: uint32_t
{
	FAKEREG_SYSCALL_INFO = armv7::REG_INVALID+1
};

bool GetLowLevelILForArmInstruction(BinaryNinja::Architecture* arch, uint64_t addr,
    BinaryNinja::LowLevelILFunction& il, armv7::Instruction& instr, size_t addrSize);
bool GetLowLevelILForThumbInstruction(BinaryNinja::Architecture* arch,
    BinaryNinja::LowLevelILFunction& il, decomp_result *instr, bool ifThenBlock = false);
void SetupThumbConditionalInstructionIL(BinaryNinja::LowLevelILFunction& il, BinaryNinja::LowLevelILLabel& trueLabel,
    BinaryNinja::LowLevelILLabel& falseLabel, uint32_t cond);
BinaryNinja::ExprId GetCondition(BinaryNinja::LowLevelILFunction& il, uint32_t cond);
