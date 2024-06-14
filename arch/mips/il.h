#pragma once

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mips.h"

enum MipsIntrinsic : uint32_t
{
		MIPS_INTRIN_WSBH,
		MIPS_INTRIN_DSBH,
		MIPS_INTRIN_DSHD,
		MIPS_INTRIN_MFC0,
		MIPS_INTRIN_MFC_UNIMPLEMENTED,
		MIPS_INTRIN_MTC0,
		MIPS_INTRIN_MTC_UNIMPLEMENTED,
		MIPS_INTRIN_DMFC0,
		MIPS_INTRIN_DMFC_UNIMPLEMENTED,
		MIPS_INTRIN_DMTC0,
		MIPS_INTRIN_DMTC_UNIMPLEMENTED,
		MIPS_INTRIN_SYNC,
		MIPS_INTRIN_DI,
		MIPS_INTRIN_EHB,
		MIPS_INTRIN_EI,
		MIPS_INTRIN_WAIT,
		MIPS_INTRIN_HWR0,
		MIPS_INTRIN_HWR1,
		MIPS_INTRIN_HWR2,
		MIPS_INTRIN_HWR3,
		MIPS_INTRIN_HWR29,
		MIPS_INTRIN_HWR_UNKNOWN,
		MIPS_INTRIN_LLBIT_SET,
		MIPS_INTRIN_LLBIT_CHECK,

		CNMIPS_INTRIN_SYNCIOBDMA,
		CNMIPS_INTRIN_SYNCS,
		CNMIPS_INTRIN_SYNCW,
		CNMIPS_INTRIN_SYNCWS,
		CNMIPS_INTRIN_HWR30,
		CNMIPS_INTRIN_HWR31,
		CNMIPS_INTRIN_POP,
		CNMIPS_INTRIN_DPOP,
		MIPS_INTRIN_INVALID=0xFFFFFFFF,
};

bool GetLowLevelILForInstruction(
		BinaryNinja::Architecture* arch,
		uint64_t addr,
		BinaryNinja::LowLevelILFunction& il,
		mips::Instruction& instr,
		size_t addrSize,
		uint32_t decomposeFlags);

BinaryNinja::ExprId GetConditionForInstruction(BinaryNinja::LowLevelILFunction& il, mips::Instruction& instr, size_t registerSize);
