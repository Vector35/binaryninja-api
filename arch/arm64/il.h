#pragma once

#include "binaryninjaapi.h"
#include "disassembler/arm64dis.h"
#include "disassembler/encodings_dec.h"
#include "disassembler/encodings_fmt.h"
#include "disassembler/operations.h"

/* Do we lift pointer authentication instructions as intrinsics?
   If no, the below define should be preceeded with "//"
   If yes, the below define should start with "#define" and intrinsics are used.
   This is read by il.cpp and arm64test.py */
//#define LIFT_PAC_AS_INTRINSIC 1

#define IL_FLAG_N 31
#define IL_FLAG_Z 30
#define IL_FLAG_C 29
#define IL_FLAG_V 28

#define IL_FLAG_WRITE_NONE 0
#define IL_FLAG_WRITE_ALL  1
#define IL_FLAG_WRITE_ALL_FLOAT  2

#define IL_FLAG_CLASS_INT 1
#define IL_FLAG_CLASS_FLOAT 2

#define IL_FLAG_GROUP_EQ 1
#define IL_FLAG_GROUP_NE 2
#define IL_FLAG_GROUP_CS 3
#define IL_FLAG_GROUP_CC 4
#define IL_FLAG_GROUP_MI 5
#define IL_FLAG_GROUP_PL 6
#define IL_FLAG_GROUP_VS 7
#define IL_FLAG_GROUP_VC 8
#define IL_FLAG_GROUP_HI 9
#define IL_FLAG_GROUP_LS 10
#define IL_FLAG_GROUP_GE 11
#define IL_FLAG_GROUP_LT 12
#define IL_FLAG_GROUP_GT 13
#define IL_FLAG_GROUP_LE 14

enum Arm64Intrinsic : uint32_t
{
	ARM64_INTRIN_AUTDA,
	ARM64_INTRIN_AUTDB,
	ARM64_INTRIN_AUTIA,
	ARM64_INTRIN_AUTIB,
	ARM64_INTRIN_DC,
	ARM64_INTRIN_DMB,
	ARM64_INTRIN_DSB,
	ARM64_INTRIN_ESB,
	ARM64_INTRIN_HINT_BTI,
	ARM64_INTRIN_HINT_CSDB,
	ARM64_INTRIN_HINT_DGH,
	ARM64_INTRIN_HINT_TSB,
	ARM64_INTRIN_ISB,
	ARM64_INTRIN_MRS,
	ARM64_INTRIN_MSR,
	ARM64_INTRIN_PACDA,
	ARM64_INTRIN_PACDB,
	ARM64_INTRIN_PACGA,
	ARM64_INTRIN_PACIA,
	ARM64_INTRIN_PACIB,
	ARM64_INTRIN_PRFM,
	ARM64_INTRIN_PSBCSYNC,
	ARM64_INTRIN_SEV,
	ARM64_INTRIN_SEVL,
	ARM64_INTRIN_WFE,
	ARM64_INTRIN_WFI,
	ARM64_INTRIN_XPACD,
	ARM64_INTRIN_XPACI,
	ARM64_INTRIN_YIELD,
	ARM64_INTRIN_ERET,
	ARM64_INTRIN_CLZ,
	ARM64_INTRIN_CLREX,
	ARM64_INTRIN_REV,
	ARM64_INTRIN_RBIT,
	ARM64_INTRIN_AESD,
	ARM64_INTRIN_AESE,
	ARM64_INTRIN_LDXR,
	ARM64_INTRIN_LDXRB,
	ARM64_INTRIN_LDXRH,
	ARM64_INTRIN_LDAXR,
	ARM64_INTRIN_LDAXRB,
	ARM64_INTRIN_LDAXRH,
	ARM64_INTRIN_STXR,
	ARM64_INTRIN_STXRB,
	ARM64_INTRIN_STXRH,
	ARM64_INTRIN_STLXR,
	ARM64_INTRIN_STLXRB,
	ARM64_INTRIN_STLXRH,
	ARM64_INTRIN_NORMAL_END, /* needed so intrinsics can be extended by other lists, like neon
	                            intrinsics */
	ARM64_INTRIN_INVALID = 0xFFFFFFFF,
};

enum Arm64FakeRegister : uint32_t
{
	FAKEREG_SYSREG_UNKNOWN = SYSREG_END + 1,
	FAKEREG_SYSCALL_INFO = SYSREG_END + 2
};

bool GetLowLevelILForInstruction(BinaryNinja::Architecture* arch, uint64_t addr,
    BinaryNinja::LowLevelILFunction& il, Instruction& instr, size_t addrSize, bool alignmentRequired);

BinaryNinja::ExprId ExtractRegister(BinaryNinja::LowLevelILFunction& il,
    InstructionOperand& operand, size_t regNum, size_t extractSize, bool signExtend,
    size_t resultSize);
