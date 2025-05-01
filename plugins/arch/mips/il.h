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
		MIPS_INTRIN_MFC2,
		MIPS_INTRIN_MFC_UNIMPLEMENTED,
		MIPS_INTRIN_MTC0,
		MIPS_INTRIN_MTC2,
		MIPS_INTRIN_MTC_UNIMPLEMENTED,
		MIPS_INTRIN_DMFC0,
		MIPS_INTRIN_DMFC2,
		MIPS_INTRIN_DMFC_UNIMPLEMENTED,
		MIPS_INTRIN_DMTC0,
		MIPS_INTRIN_DMTC2,
		MIPS_INTRIN_DMTC_UNIMPLEMENTED,
		MIPS_INTRIN_SYNC,
		MIPS_INTRIN_SYNCI,
		MIPS_INTRIN_DI,
		MIPS_INTRIN_EHB,
		MIPS_INTRIN_EI,
		MIPS_INTRIN_PAUSE,
		MIPS_INTRIN_WAIT,
		MIPS_INTRIN_HWR0,
		MIPS_INTRIN_HWR1,
		MIPS_INTRIN_HWR2,
		MIPS_INTRIN_HWR3,
		MIPS_INTRIN_HWR29,
		MIPS_INTRIN_HWR_UNKNOWN,
		MIPS_INTRIN_LLBIT_SET,
		MIPS_INTRIN_LLBIT_CHECK,
		MIPS_INTRIN_PREFETCH,
		MIPS_INTRIN_CACHE,
		MIPS_INTRIN_SDBBP,

		// there's no clean way to lift LWL/LWR, SWL/SWR, etc when not
		// a pair of adjacent instructions, since the number and position
		// of the bytes written to/read from depends on the alignment of
		// the address
		//
		// consider writing a register to an unaligned address with
		// SWL rX, 0(rY)/SWR rX, 3(rY); this could write either 1, 2, 3,
		// or 4 bytes in each instruction, and then later in the function
		// to load the value of rX back, the number of bytes read by
		// LWL rX, 0(rY)/LWR rX, 3(rY) is again variable...the number of
		// bytes, shifts, and bitmasks all depend on (rY & 3)
		//
		// lifting these instructions faithfully, even when the analysis
		// engine is able to follow this, would be a total mess to read,
		// so it might as well be an intrinsic-like black box anyways, to
		// help data cross-references work
		MIPS_INTRIN_GET_LEFT_PART32,
		MIPS_INTRIN_GET_RIGHT_PART32,
		MIPS_INTRIN_SET_LEFT_PART32,
		MIPS_INTRIN_SET_RIGHT_PART32,
		MIPS_INTRIN_GET_LEFT_PART64,
		MIPS_INTRIN_GET_RIGHT_PART64,
		MIPS_INTRIN_SET_LEFT_PART64,
		MIPS_INTRIN_SET_RIGHT_PART64,

		MIPS_INTRIN_TLBSET,
		MIPS_INTRIN_TLBGET,
		MIPS_INTRIN_TLBSEARCH,
		MIPS_INTRIN_TLBINV,
		MIPS_INTRIN_TLBINVF,

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
