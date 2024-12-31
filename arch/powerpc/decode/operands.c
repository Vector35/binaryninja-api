#include <string.h>

#include "decode.h"
#include "priv.h"

// see stanford bit twiddling hacks
static int32_t sign_extend(uint32_t x, unsigned numBits)
{
	int32_t const m = 1U << (numBits - 1);

	x = x & ((1U << numBits) - 1);
	return (x ^ m) - m;
}

static void CopyOperand(Operand* dst, const Operand* src)
{
	memcpy(dst, src, sizeof *dst);
}

static Register Gpr(uint32_t value)
{
	return PPC_REG_GPR0 + value;
}

static Register Fr(uint32_t value)
{
	return PPC_REG_FR0 + value;
}

static Register Crf(uint32_t value)
{
	return PPC_REG_CRF0 + value;
}

static Register AltivecVr(uint32_t value)
{
	return PPC_REG_AV_VR0 + value;
}

static Register VsxVr(uint32_t value)
{
	return PPC_REG_VSX_VR0 + value;
}

static Register VsxVrHi(uint32_t value)
{
	return PPC_REG_VSX_VR0 + value + 32;
}

static void PushUIMMValue(Instruction* instruction, uint32_t uimm)
{
	instruction->operands[instruction->numOperands].cls = PPC_OP_UIMM;
	instruction->operands[instruction->numOperands].uimm = uimm;
	++instruction->numOperands;
}

static void PushSIMMValue(Instruction* instruction, int32_t simm)
{
	instruction->operands[instruction->numOperands].cls = PPC_OP_SIMM;
	instruction->operands[instruction->numOperands].simm = simm;
	++instruction->numOperands;
}

static void PushRegister(Instruction* instruction, OperandClass cls, Register reg)
{
	instruction->operands[instruction->numOperands].cls = cls;
	instruction->operands[instruction->numOperands].reg = reg;
	++instruction->numOperands;
}

static uint64_t ComputeBranchTarget(Instruction* instruction, uint64_t address, uint32_t word32)
{
	int32_t bd = (int32_t)((int16_t)(word32 & 0xfffc));

	return instruction->flags.aa ? bd : address + bd;
}

static void PushLabel(Instruction* instruction, uint64_t address)
{
	instruction->operands[instruction->numOperands].cls = PPC_OP_LABEL;
	instruction->operands[instruction->numOperands].label = address;
	++instruction->numOperands;
}

// this assumes that instruction->flags.aa has been properly set!
static void PushBranchTarget(Instruction* instruction, uint64_t address, uint32_t word32)
{
	PushLabel(instruction, ComputeBranchTarget(instruction, address, word32));
}

static void PushRA(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_RA, Gpr(GetA(word32)));
}

static void PushRAor0(Instruction* instruction, uint32_t word32)
{
	uint32_t ra = GetA(word32);

	if (ra == 0)
		PushUIMMValue(instruction, 0);
	else
		PushRegister(instruction, PPC_OP_REG_RA, Gpr(ra));
}

static void PushRB(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_RB, Gpr(GetB(word32)));
}

static void PushRC(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_RC, Gpr(GetC(word32)));
}

static void PushRD(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_RD, Gpr(GetD(word32)));
}

static void PushRS(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_RS, Gpr(GetS(word32)));
}

static void PushFRA(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_FRA, Fr(GetA(word32)));
}

static void PushFRB(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_FRB, Fr(GetB(word32)));
}

static void PushFRC(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_FRC, Fr(GetC(word32)));
}

static void PushFRD(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_FRD, Fr(GetD(word32)));
}

static void PushFRS(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_FRS, Fr(GetS(word32)));
}

static void PushCRFD(Instruction* instruction, uint32_t word32)
{
	uint32_t crfd = (word32 >> 23) & 0x7;
	PushRegister(instruction, PPC_OP_REG_CRFD, Crf(crfd));
}

static void PushCRFDImplyCR0(Instruction* instruction, uint32_t word32)
{
	uint32_t crfd = (word32 >> 23) & 0x7;

	PushRegister(instruction, PPC_OP_REG_CRFD_IMPLY0, Crf(crfd));
}

static void PushCRFS(Instruction* instruction, uint32_t word32)
{
	uint32_t crfs = (word32 >> 18) & 0x7;
	PushRegister(instruction, PPC_OP_REG_CRFS, Crf(crfs));
}

static void PushCRBitA(Instruction* instruction, uint32_t word32)
{
	instruction->operands[instruction->numOperands].cls = PPC_OP_CRBIT_A;
	instruction->operands[instruction->numOperands].crbit = GetA(word32);
	++instruction->numOperands;
}

static void PushCRBitB(Instruction* instruction, uint32_t word32)
{
	instruction->operands[instruction->numOperands].cls = PPC_OP_CRBIT_B;
	instruction->operands[instruction->numOperands].crbit = GetB(word32);
	++instruction->numOperands;
}

static void PushCRBitD(Instruction* instruction, uint32_t word32)
{
	instruction->operands[instruction->numOperands].cls = PPC_OP_CRBIT_D;
	instruction->operands[instruction->numOperands].crbit = GetD(word32);
	++instruction->numOperands;
}

static void PushMem(Instruction* instruction, OperandClass cls, Register reg, int32_t offset)
{
	instruction->operands[instruction->numOperands].cls = cls;
	instruction->operands[instruction->numOperands].mem.reg = reg;
	instruction->operands[instruction->numOperands].mem.offset = offset;
	++instruction->numOperands;
}

static void FillBranchLikelyHint(Instruction* instruction, uint32_t word32)
{
	uint32_t bo = GetBO(word32);

	switch (bo >> 2)
	{
		// 001at
		// 011at
		case 1:
		case 3:
			instruction->flags.branchLikelyHint = bo & 0x3;
			break;

		// 1a00t
		// 1a01t
		case 4:
		case 6:
			instruction->flags.branchLikelyHint = ((bo >> 2) & 0x2) | (bo & 0x1);
			break;

		// all others don't have hints
		default:
			instruction->flags.branchLikelyHint = 0;
	}
}

static void PushMemRA(Instruction* instruction, uint32_t word32)
{
	int32_t offset = (int32_t)((int16_t)(word32 & 0xffff));
	PushMem(instruction, PPC_OP_MEM_RA, Gpr(GetA(word32)), offset);
}

static void PushVsxA(Instruction* instruction, uint32_t word32, VsxWidth width)
{
	PushRegister(instruction,
		width == VSX_WIDTH_FULL ? PPC_OP_REG_VSX_RA : PPC_OP_REG_VSX_RA_DWORD0,
		VsxVr(GetVsxA(word32)));
}

static void PushVsxHiA(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_VSX_RA, VsxVrHi(GetA(word32)));
}

static void PushVsxB(Instruction* instruction, uint32_t word32, VsxWidth width)
{
	PushRegister(instruction,
		width == VSX_WIDTH_FULL ? PPC_OP_REG_VSX_RB : PPC_OP_REG_VSX_RB_DWORD0,
		VsxVr(GetVsxB(word32)));
}

static void PushVsxHiB(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_VSX_RB, VsxVrHi(GetB(word32)));
}

static void PushVsxC(Instruction* instruction, uint32_t word32, VsxWidth width)
{
	PushRegister(instruction,
		width == VSX_WIDTH_FULL ? PPC_OP_REG_VSX_RC : PPC_OP_REG_VSX_RC_DWORD0,
		VsxVr(GetVsxC(word32)));
}

static void PushVsxD(Instruction* instruction, uint32_t word32, VsxWidth width)
{
	PushRegister(instruction,
		width == VSX_WIDTH_FULL ? PPC_OP_REG_VSX_RD : PPC_OP_REG_VSX_RD_DWORD0,
		VsxVr(GetVsxD(word32)));
}

static void PushVsxHiD(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_VSX_RD, VsxVrHi(GetD(word32)));
}

static void PushVsxS(Instruction* instruction, uint32_t word32, VsxWidth width)
{
	uint32_t sx = word32 & 0x1;
	uint32_t s = (word32 >> 21) & 0x1f;
	PushRegister(instruction,
		width == VSX_WIDTH_FULL ? PPC_OP_REG_VSX_RS : PPC_OP_REG_VSX_RS_DWORD0,
		VsxVr((sx << 5) | s));
}

static void PushVsxHiS(Instruction* instruction, uint32_t word32)
{
	PushRegister(instruction, PPC_OP_REG_VSX_RS, VsxVrHi(GetS(word32)));
}

static void PushAltivecVA(Instruction* instruction, uint32_t word32)
{
	uint32_t va = (word32 >> 16) & 0x1f;
	PushRegister(instruction, PPC_OP_REG_AV_VA, AltivecVr(va));
}

static void PushAltivecVB(Instruction* instruction, uint32_t word32)
{
	uint32_t vb = (word32 >> 11) & 0x1f;
	PushRegister(instruction, PPC_OP_REG_AV_VB, AltivecVr(vb));
}

static void PushAltivecVC(Instruction* instruction, uint32_t word32)
{
	uint32_t vc = (word32 >> 6) & 0x1f;
	PushRegister(instruction, PPC_OP_REG_AV_VC, AltivecVr(vc));
}

static void PushAltivecVD(Instruction* instruction, uint32_t word32)
{
	uint32_t vd = (word32 >> 21) & 0x1f;
	PushRegister(instruction, PPC_OP_REG_AV_VD, AltivecVr(vd));
}

static void PushAltivecVS(Instruction* instruction, uint32_t word32)
{
	uint32_t vs = (word32 >> 21) & 0x1f;
	PushRegister(instruction, PPC_OP_REG_AV_VS, AltivecVr(vs));
}

void FillOperands32(Instruction* instruction, uint32_t word32, uint64_t address)
{
	switch (instruction->id)
	{
		// instructions with no operands
		case PPC_ID_ATTN:
		case PPC_ID_CP_ABORT:
		case PPC_ID_DCCCI:
		case PPC_ID_HRFID:
		case PPC_ID_ICCCI:
		case PPC_ID_ISYNC:
		case PPC_ID_LWSYNC:
		case PPC_ID_MSGSYNC:
		case PPC_ID_NAP:
		case PPC_ID_NOP:
		case PPC_ID_PTESYNC:
		case PPC_ID_RFCI:
		case PPC_ID_RFDI:
		case PPC_ID_RFI:
		case PPC_ID_RFID:
		case PPC_ID_RFMCI:
		case PPC_ID_STOP:
		case PPC_ID_SYNC:
		case PPC_ID_TLBIA:
		case PPC_ID_TLBSYNC:
		case PPC_ID_TRAP:
		case PPC_ID_TRECHKPT:
		case PPC_ID_SLBIA:
		case PPC_ID_SLBSYNC:
		case PPC_ID_XNOP:
		case PPC_ID_WAITIMPL:
		case PPC_ID_WAITRSV:
		case PPC_ID_AV_DSSALL:
			break;

		// <op> rD
		case PPC_ID_LNIA:
		case PPC_ID_MFBR0:
		case PPC_ID_MFBR1:
		case PPC_ID_MFBR2:
		case PPC_ID_MFBR3:
		case PPC_ID_MFBR4:
		case PPC_ID_MFBR5:
		case PPC_ID_MFBR6:
		case PPC_ID_MFBR7:
		case PPC_ID_MFCR:
		case PPC_ID_MFCTR:
		case PPC_ID_MFLR:
		case PPC_ID_MFMSR:
		case PPC_ID_MFTBU:
		case PPC_ID_MFXER:
			PushRD(instruction, word32);
			break;

		// <op> rS
		case PPC_ID_MTBR0:
		case PPC_ID_MTBR1:
		case PPC_ID_MTBR2:
		case PPC_ID_MTBR3:
		case PPC_ID_MTBR4:
		case PPC_ID_MTBR5:
		case PPC_ID_MTBR6:
		case PPC_ID_MTBR7:
		case PPC_ID_MTCTR:
		case PPC_ID_MTLR:
		case PPC_ID_MTMSR:
		case PPC_ID_MTMSRD:
		case PPC_ID_MTXER:
		case PPC_ID_WRTEE:
			PushRS(instruction, word32);
			break;

		// <op> rA
		case PPC_ID_TABORT:
		case PPC_ID_TRECLAIM:
			PushRA(instruction, word32);
			break;

		// <op> rB
		case PPC_ID_TLBIEL:
		case PPC_ID_TLBLI:
		case PPC_ID_SLBIE:
			PushRB(instruction, word32);
			break;

		// <op>[.] rD, rA (arithmetic)
		case PPC_ID_NEGx:
		case PPC_ID_SUBFZEx:
		case PPC_ID_ADDZEx:
		case PPC_ID_SUBFMEx:
		case PPC_ID_ADDMEx:
			PushRD(instruction, word32);
			PushRA(instruction, word32);

			// some of these instructions don't have an "oe" flag,
			// but we rely on the fact that those instructions have
			// bitmask 0x400 clear in the switch statement on the
			instruction->flags.rc = word32 & 0x1;
			instruction->flags.oe = (word32 & 0x400) != 0;
			break;

		// <op>[.] rD, rA, rB (arithmetic)
		case PPC_ID_ADDx:
		case PPC_ID_ADDCx:
		case PPC_ID_ADDEx:
		case PPC_ID_DIVDx:
		case PPC_ID_DIVDEx:
		case PPC_ID_DIVDEUx:
		case PPC_ID_DIVDUx:
		case PPC_ID_DIVWx:
		case PPC_ID_DIVWEx:
		case PPC_ID_DIVWEUx:
		case PPC_ID_DIVWUx:
		case PPC_ID_MODSD:
		case PPC_ID_MODSW:
		case PPC_ID_MODUD:
		case PPC_ID_MODUW:
		case PPC_ID_MULHDx:
		case PPC_ID_MULHDUx:
		case PPC_ID_MULHWx:
		case PPC_ID_MULHWUx:
		case PPC_ID_MULLDx:
		case PPC_ID_MULLWx:
		case PPC_ID_SUBFx:
		case PPC_ID_SUBFCx:
		case PPC_ID_SUBFEx:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushRB(instruction, word32);

			// some of these instructions don't have an "oe" flag,
			// but we rely on the fact that those instructions have
			// bitmask 0x400 clear in the switch statement on the
			// 0x7ff mask
			instruction->flags.rc = word32 & 0x1;
			instruction->flags.oe = (word32 & 0x400) != 0;
			break;


		// <op>[.] rA, rS (logical)
		case PPC_ID_CNTLZWx:
		case PPC_ID_CNTLZDx:
		case PPC_ID_CNTTZWx:
		case PPC_ID_CNTTZDx:
		case PPC_ID_POPCNTB:
		case PPC_ID_POPCNTD:
		case PPC_ID_POPCNTW:
		case PPC_ID_EXTSHx:
		case PPC_ID_EXTSBx:
		case PPC_ID_EXTSWx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);

			// not all of these have RC bits, but it gets filtered
			// at subop decode step
			instruction->flags.rc = word32 & 0x1;
			break;

		// <op>[.] rA, rS, rB
		case PPC_ID_ANDx:
		case PPC_ID_ANDCx:
		case PPC_ID_BPERMD:
		case PPC_ID_CMPB:
		case PPC_ID_ECIWX:
		case PPC_ID_ECOWX:
		case PPC_ID_EQVx:
		case PPC_ID_NANDx:
		case PPC_ID_NORx:
		case PPC_ID_ORx:
		case PPC_ID_ORCx:
		case PPC_ID_ROTLWx:
		case PPC_ID_ROTLDx:
		case PPC_ID_SLDx:
		case PPC_ID_SLWx:
		case PPC_ID_SRADx:
		case PPC_ID_SRAWx:
		case PPC_ID_SRDx:
		case PPC_ID_SRWx:
		case PPC_ID_XORx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushRB(instruction, word32);

			// not all of these have an rc bit, but they just don't
			// get recognized at the switch statement with &0x7ff
			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_ROTLWIx:
		case PPC_ID_SLWIx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, GetSH(word32));

			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_CLRLWIx:
		case PPC_ID_SRWIx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, GetMB(word32));
			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_CLRRWIx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);

			// me = 31 - n --> n = 31 - me
			PushUIMMValue(instruction, 31 - GetME(word32));
			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_RLDCLx:
		case PPC_ID_RLDCRx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushRB(instruction, word32);
			PushUIMMValue(instruction, GetMX64(word32));

			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_RLDICx:
		case PPC_ID_RLDICLx:
		case PPC_ID_RLDICRx:
		case PPC_ID_RLDIMIx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, GetSH64(word32));
			PushUIMMValue(instruction, GetMX64(word32));

			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_CLRLDIx:
		case PPC_ID_SRDIx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, GetMX64(word32));

			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_ROTLDIx:
		case PPC_ID_SLDIx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, GetSH64(word32));

			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_BCx:
		{
			uint32_t bo = GetBO(word32);
			uint32_t bi = GetBI(word32);

			instruction->flags.lk = word32 & 0x1;
			instruction->flags.aa = (word32 & 0x2) != 0;

			// not all BCx have hints, but if they don't, then those
			// hints won't be read by anything anyways
			FillBranchLikelyHint(instruction, word32);

			PushUIMMValue(instruction, bo);
			PushUIMMValue(instruction, bi);
			PushBranchTarget(instruction, address, word32);

			break;
		}

		// <op> crfD, rA, rB
		case PPC_ID_CMPD:
		case PPC_ID_CMPEQB:
		case PPC_ID_CMPW:
		case PPC_ID_CMPLD:
		case PPC_ID_CMPLW:
			PushCRFDImplyCR0(instruction, word32);
			PushRA(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op> crfD, rA, SIMM
		case PPC_ID_CMPDI:
		case PPC_ID_CMPWI:
		{
			int32_t simm = (int32_t)((int16_t)(word32 & 0xffff));

			PushCRFDImplyCR0(instruction, word32);
			PushRA(instruction, word32);
			PushSIMMValue(instruction, simm);
			break;
		}

		// <op> crfD, rA, UIMM
		case PPC_ID_CMPLDI:
		case PPC_ID_CMPLWI:
		{
			uint32_t uimm = word32 & 0xffff;

			PushCRFDImplyCR0(instruction, word32);
			PushRA(instruction, word32);
			PushUIMMValue(instruction, uimm);
			break;
		}

		// <op> rA, rB
		case PPC_ID_COPY:
		case PPC_ID_PASTE:
		case PPC_ID_TDEQ:
		case PPC_ID_TDGT:
		case PPC_ID_TDLGT:
		case PPC_ID_TDLLT:
		case PPC_ID_TDLT:
		case PPC_ID_TDNE:
		case PPC_ID_TDU:
		case PPC_ID_TLBSX:
		case PPC_ID_TWEQ:
		case PPC_ID_TWGT:
		case PPC_ID_TWLGT:
		case PPC_ID_TWLLT:
		case PPC_ID_TWLT:
		case PPC_ID_TWNE:
		case PPC_ID_TWU:
			PushRA(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <trap> TO, rA, rB
		case PPC_ID_TD:
		case PPC_ID_TW:
		case PPC_ID_TABORTDC:
		case PPC_ID_TABORTWC:
		{
			uint32_t to = (word32 >> 21) & 0x1f;

			PushUIMMValue(instruction, to);
			PushRA(instruction, word32);
			PushRB(instruction, word32);
			break;
		}

		// <trap> rA, SIMM
		case PPC_ID_TDEQI:
		case PPC_ID_TDGTI:
		case PPC_ID_TDLGTI:
		case PPC_ID_TDLLTI:
		case PPC_ID_TDLTI:
		case PPC_ID_TDNEI:
		case PPC_ID_TDUI:
		case PPC_ID_TWEQI:
		case PPC_ID_TWGTI:
		case PPC_ID_TWLGTI:
		case PPC_ID_TWLLTI:
		case PPC_ID_TWLTI:
		case PPC_ID_TWNEI:
		case PPC_ID_TWUI:
		{
			int32_t simm = (int32_t)((int16_t)(word32 & 0xffff));

			PushRA(instruction, word32);
			PushSIMMValue(instruction, simm);
			break;
		}

		// <trap> TO, rA, SIMM
		case PPC_ID_TDI:
		case PPC_ID_TWI:
		{
			uint32_t to = (word32 >> 21) & 0x1f;
			int32_t simm = (int32_t)((int16_t)(word32 & 0xffff));

			PushUIMMValue(instruction, to);
			PushRA(instruction, word32);
			PushSIMMValue(instruction, simm);
			break;
		}

		// <tabort> TO, rA, SIMM
		case PPC_ID_TABORTDCI:
		case PPC_ID_TABORTWCI:
		{
			uint32_t to = (word32 >> 21) & 0x1f;
			int32_t simm = sign_extend((word32 >> 11) & 0x1f, 5);

			PushUIMMValue(instruction, to);
			PushRA(instruction, word32);
			PushSIMMValue(instruction, simm);
			break;
		}

		// <op> rD, rA, SIMM
		case PPC_ID_ADDI:
		case PPC_ID_MULLI:
		case PPC_ID_SUBFIC:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushSIMMValue(instruction, (int32_t)((int16_t)(word32 & 0xffff)));
			break;

		// <op> rA, rS, UIMM
		case PPC_ID_ORI:
		case PPC_ID_XORI:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, word32 & 0xffff);
			break;

		// differentiated in case it makes sense to use the shifted value as an operand
		// (which we do for now since it matches capstone)
		// <op> rA, rS, UIMM
		case PPC_ID_ORIS:
		case PPC_ID_XORIS:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, word32 & 0xffff);
			break;

		// <op> rD, d(rA)
		case PPC_ID_LBZ:
		case PPC_ID_LBZU:
		case PPC_ID_LHA:
		case PPC_ID_LHAU:
		case PPC_ID_LHZ:
		case PPC_ID_LHZU:
		case PPC_ID_LMW:
		case PPC_ID_LWZ:
		case PPC_ID_LWZU:
			PushRD(instruction, word32);
			PushMemRA(instruction, word32);
			break;

		// <op> rD, d(rA) (64-bit)
		case PPC_ID_LD:
		case PPC_ID_LDU:
		case PPC_ID_LWA:
		{
			PushRD(instruction, word32);

			int32_t ds = (int32_t)((int16_t)(word32 & 0xfffc));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(GetA(word32)), ds);
			break;
		}

		// <op> rD, rA, rB (indexed load)
		case PPC_ID_LBEPX:
		case PPC_ID_LBZCIX:
		case PPC_ID_LBZUX:
		case PPC_ID_LBZX:
		case PPC_ID_LDBRX:
		case PPC_ID_LDCIX:
		case PPC_ID_LDUX:
		case PPC_ID_LDX:
		case PPC_ID_LHAUX:
		case PPC_ID_LHAX:
		case PPC_ID_LHBRX:
		case PPC_ID_LHEPX:
		case PPC_ID_LHZCIX:
		case PPC_ID_LHZX:
		case PPC_ID_LHZUX:
		case PPC_ID_LSWX:
		case PPC_ID_LWAX:
		case PPC_ID_LWAUX:
		case PPC_ID_LWBRX:
		case PPC_ID_LWEPX:
		case PPC_ID_LWZCIX:
		case PPC_ID_LWZUX:
		case PPC_ID_LWZX:
			PushRD(instruction, word32);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op> rD, rA, rB, [EH if nonzero] (indexed load)
		case PPC_ID_LBARX:
		case PPC_ID_LDARX:
		case PPC_ID_LHARX:
		case PPC_ID_LWARX:
		{
			PushRD(instruction, word32);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			uint32_t eh = word32 & 0x1;
			// NOTE: this breaks with convention by only
			// conditionally including EH
			if (eh)
				PushUIMMValue(instruction, word32 & 0x1);
			break;
		}

		// <op> rD, rA, FC
		case PPC_ID_LDAT:
		case PPC_ID_LWAT:
		{
			uint32_t fc = (word32 >> 11) & 0x1f;
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushUIMMValue(instruction, fc);
			break;
		}
		
		// <op> rS, rA, FC
		case PPC_ID_STDAT:
		case PPC_ID_STWAT:
		{
			uint32_t fc = (word32 >> 11) & 0x1f;
			PushRS(instruction, word32);
			PushRA(instruction, word32);
			PushUIMMValue(instruction, fc);
			break;
		}
		

		// <op> rS, d(RA)
		case PPC_ID_STB:
		case PPC_ID_STBU:
		case PPC_ID_STH:
		case PPC_ID_STHU:
		case PPC_ID_STMW:
		case PPC_ID_STW:
		case PPC_ID_STWU:
			PushRS(instruction, word32);
			PushMemRA(instruction, word32);
			break;

		// <op> rS, d(RA) (64-bit)
		case PPC_ID_STD:
		case PPC_ID_STDU:
		{
			PushRS(instruction, word32);

			int32_t ds = (int32_t)((int16_t)(word32 & 0xfffc));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(GetA(word32)), ds);
			break;
		}

		// <op> rS, rA, rB (indexed store)
		case PPC_ID_STBCX:
		case PPC_ID_STBCIX:
		case PPC_ID_STBEPX:
		case PPC_ID_STBUX:
		case PPC_ID_STBX:
		case PPC_ID_STDBRX:
		case PPC_ID_STDCIX:
		case PPC_ID_STDEPX:
		case PPC_ID_STDUX:
		case PPC_ID_STDX:
		case PPC_ID_STHBRX:
		case PPC_ID_STHCIX:
		case PPC_ID_STHCX:
		case PPC_ID_STHEPX:
		case PPC_ID_STHUX:
		case PPC_ID_STHX:
		case PPC_ID_STSWX:
		case PPC_ID_STWBRX:
		case PPC_ID_STWCIX:
		case PPC_ID_STWEPX:
		case PPC_ID_STWUX:
		case PPC_ID_STWX:
			PushRS(instruction, word32);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op>. rS, rA, rB (indexed store with reserve)
		case PPC_ID_STDCX:
		case PPC_ID_STWCX:
			PushRS(instruction, word32);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			instruction->flags.rc = 1;
			break;

		// <op> frD, d(rA)
		case PPC_ID_LFD:
		case PPC_ID_LFDU:
		case PPC_ID_LFS:
		case PPC_ID_LFSU:
			PushFRD(instruction, word32);
			PushMemRA(instruction, word32);
			break;

		// <op> frD, rA, rB
		case PPC_ID_LFDEPX:
		case PPC_ID_LFDUX:
		case PPC_ID_LFDX:
		case PPC_ID_LFIWAX:
		case PPC_ID_LFIWZX:
		case PPC_ID_LFSUX:
		case PPC_ID_LFSX:
			PushFRD(instruction, word32);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op> frS, d(rA)
		case PPC_ID_STFD:
		case PPC_ID_STFDU:
		case PPC_ID_STFS:
		case PPC_ID_STFSU:
			PushFRS(instruction, word32);
			PushMemRA(instruction, word32);
			break;

		// <op> frS, rA, rB
		case PPC_ID_STFDEPX:
		case PPC_ID_STFDUX:
		case PPC_ID_STFDX:
		case PPC_ID_STFIWX:
		case PPC_ID_STFSUX:
		case PPC_ID_STFSX:
			PushFRS(instruction, word32);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op> crfD, crfS
		case PPC_ID_MCRF:
		case PPC_ID_MCRFS:
			PushCRFD(instruction, word32);
			PushCRFS(instruction, word32);
			break;

		// <op> crbD, crbA
		case PPC_ID_CRMOVE:
		case PPC_ID_CRNOT:
			PushCRBitD(instruction, word32);
			PushCRBitA(instruction, word32);
			break;

		// <op> crbD, crbA, crbB
		case PPC_ID_CRAND:
		case PPC_ID_CRANDC:
		case PPC_ID_CREQV:
		case PPC_ID_CRNAND:
		case PPC_ID_CRNOR:
		case PPC_ID_CROR:
		case PPC_ID_CRORC:
		case PPC_ID_CRXOR:
			PushCRBitD(instruction, word32);
			PushCRBitA(instruction, word32);
			PushCRBitB(instruction, word32);
			break;

		// <op> crbD
		case PPC_ID_CRCLR:
		case PPC_ID_CRSET:
			PushCRBitD(instruction, word32);
			break;

		// <op> crfS
		case PPC_ID_MCRXRX:
		case PPC_ID_TCHECK:
			PushCRFD(instruction, word32);
			break;

		// conditional branches to registers
		case PPC_ID_BCLRx:
		case PPC_ID_BCCTRx:
			// not all BC<reg>x have hints, but if they don't, then those
			// hints won't be read by anything anyways
			FillBranchLikelyHint(instruction, word32);

			PushUIMMValue(instruction, GetBO(word32));
			PushUIMMValue(instruction, GetBI(word32));

			instruction->flags.lk = word32 & 0x1;
			break;

		// <op> frD, frA, frB
		case PPC_ID_FADDx:
		case PPC_ID_FADDSx:
		case PPC_ID_FCPSGNx:
		case PPC_ID_FDIVx:
		case PPC_ID_FDIVSx:
		case PPC_ID_FSUBx:
		case PPC_ID_FSUBSx:
			PushFRD(instruction, word32);
			PushFRA(instruction, word32);
			PushFRB(instruction, word32);

			instruction->flags.rc = word32 & 0x1;
			break;

		// <op>[.] frD, frA, frC
		case PPC_ID_FMULx:
		case PPC_ID_FMULSx:
			PushFRD(instruction, word32);
			PushFRA(instruction, word32);
			PushFRC(instruction, word32);

			instruction->flags.rc = word32 & 0x1;
			break;

		// <op>[.] frD, frA, frC, frB
		case PPC_ID_FMADDx:
		case PPC_ID_FMADDSx:
		case PPC_ID_FMSUBx:
		case PPC_ID_FMSUBSx:
		case PPC_ID_FNMADDx:
		case PPC_ID_FNMADDSx:
		case PPC_ID_FNMSUBx:
		case PPC_ID_FNMSUBSx:
		case PPC_ID_FSELx:
			PushFRD(instruction, word32);
			PushFRA(instruction, word32);
			PushFRC(instruction, word32);
			PushFRB(instruction, word32);

			instruction->flags.rc = word32 & 0x1;
			break;

		// <op>[.] frD, frB
		case PPC_ID_FABSx:
		case PPC_ID_FCFIDx:
		case PPC_ID_FCFIDSx:
		case PPC_ID_FCFIDUx:
		case PPC_ID_FCFIDUSx:
		case PPC_ID_FCTIDx:
		case PPC_ID_FCTIDUx:
		case PPC_ID_FCTIDUZx:
		case PPC_ID_FCTIDZx:
		case PPC_ID_FCTIWx:
		case PPC_ID_FCTIWUx:
		case PPC_ID_FCTIWUZx:
		case PPC_ID_FCTIWZx:
		case PPC_ID_FMRx:
		case PPC_ID_FNABSx:
		case PPC_ID_FNEGx:
		case PPC_ID_FREx:
		case PPC_ID_FRESx:
		case PPC_ID_FRIMx:
		case PPC_ID_FRINx:
		case PPC_ID_FRIPx:
		case PPC_ID_FRIZx:
		case PPC_ID_FRSPx:
		case PPC_ID_FRSQRTEx:
		case PPC_ID_FRSQRTESx:
		case PPC_ID_FSQRTx:
		case PPC_ID_FSQRTSx:
			PushFRD(instruction, word32);
			PushFRB(instruction, word32);

			instruction->flags.rc = word32 & 0x1;
			break;


		case PPC_ID_FCMPO:
		case PPC_ID_FCMPU:
			PushCRFD(instruction, word32);
			PushFRA(instruction, word32);
			PushFRB(instruction, word32);
			break;

		// <op> rD, UIMM (special register)
		case PPC_ID_MFDCR:
		case PPC_ID_MFPMR:
		case PPC_ID_MFSPR:
		case PPC_ID_MFTB:
		{
			uint32_t special = GetSpecialRegisterCommon(word32);

			PushRD(instruction, word32);
			PushUIMMValue(instruction, special);
			break;
		}

		// <op> UIMM, rS (special register)
		case PPC_ID_MTDCR:
		case PPC_ID_MTPMR:
		case PPC_ID_MTSPR:
		{
			uint32_t special = GetSpecialRegisterCommon(word32);

			PushUIMMValue(instruction, special);
			PushRS(instruction, word32);
			break;
		}

		// <op> rA, rB (cache-related)
		case PPC_ID_DCBA:
		case PPC_ID_DCBST:
		case PPC_ID_DCBSTEP:
		case PPC_ID_DCBFL:
		case PPC_ID_DCBFLP:
		case PPC_ID_DCBI:
		case PPC_ID_DCBTSTT:
		case PPC_ID_DCBTT:
		case PPC_ID_DCBZ:
		case PPC_ID_DCBZEP:
		case PPC_ID_DCBZL:
		case PPC_ID_ICBI:
		case PPC_ID_ICBIEP:
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op> CT (cache-related)
		case PPC_ID_DCI:
		case PPC_ID_ICI:
		{
			uint32_t ct = (word32 >> 21) & 0xf;

			PushUIMMValue(instruction, ct);
			break;
		}

		// <op> CT, rA, rB (cache-related)
		case PPC_ID_ICBLC:
		case PPC_ID_ICBLQ:
		case PPC_ID_ICBTLS:
			uint32_t ct = (word32 >> 21) & 0xf;

			PushUIMMValue(instruction, ct);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op> TH, rA, rB (cache-related)
		case PPC_ID_DCBTEP:
		case PPC_ID_DCBTSTEP:
		{
			uint32_t th = (word32 >> 21) & 0x1f;
			PushUIMMValue(instruction, th);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;
		}

		// <op> rA, rB, TH
		case PPC_ID_DCBT:
		{
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			uint32_t th = (word32 >> 21) & 0x1f;
			if (th != 0)
				PushUIMMValue(instruction, th);
			break;
		}

		case PPC_ID_DCBTST:
		{
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			uint32_t th = (word32 >> 21) & 0x1f;
			if (th != 0)
				PushUIMMValue(instruction, th);
			break;
		}

		case PPC_ID_MTFSB0x:
		case PPC_ID_MTFSB1x:
		{
			uint32_t bt = (word32 >> 21) & 0x1f;

			PushUIMMValue(instruction, bt);
			instruction->flags.rc = word32 & 0x1;
			break;
		}

		case PPC_ID_TLBREHI:
		case PPC_ID_TLBRELO:
			// TODO: this is how capstone disassembles these
			//       instructions, but some architectures have no
			//       operands and this is just "tlbre"
			PushRD(instruction, word32);
			PushRA(instruction, word32);

			break;

		case PPC_ID_TLBWEHI:
		case PPC_ID_TLBWELO:
			// TODO: this is how capstone disassembles these
			//       instructions, but some architectures have no
			//       operands and this is just "tlbwe"
			PushRS(instruction, word32);
			PushRA(instruction, word32);

			break;

		// one-off instructions
		case PPC_ID_ADDICx:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushSIMMValue(instruction, (int32_t)((int16_t)(word32 & 0xffff)));

			instruction->flags.rc = (word32 >> 26) == 0x0d;
			break;

		case PPC_ID_ADDIS:
			// different from other shifted immediates because signed imm
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushSIMMValue(instruction, (int32_t)((int16_t)(word32 & 0xffff)));
			break;

		case PPC_ID_ADDPCIS:
		{
			PushRD(instruction, word32);
			uint64_t d1 = (word32 >> 16) & 0x1f;
			uint64_t d0 = (word32 >> 6) & 0x3ff;
			uint64_t d2 = word32 & 0x1;
			uint64_t d = (d0 << 6) | (d1 << 1) | d2;
			PushUIMMValue(instruction, d);
			break;
		}

		case PPC_ID_ANDI:
			// different from other logical immediates because of rc bit
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, word32 & 0xffff);
			instruction->flags.rc = 1;
			break;

		case PPC_ID_ANDIS:
			// different from other logical shifted immediates because of rc bit
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, word32 & 0xffff);

			instruction->flags.rc = 1;
			break;

		case PPC_ID_Bx:
		{
			instruction->flags.lk = word32 & 0x1;
			instruction->flags.aa = (word32 & 0x2) != 0;

			uint64_t li = word32 & 0x03fffffc;
			li = (uint64_t)(int64_t)sign_extend(li, 26);
			uint64_t target = instruction->flags.aa ? li : address + li;

			PushLabel(instruction, target);

			break;
		}

		case PPC_ID_CMPRB:
		{
			PushCRFD(instruction, word32);

			uint32_t l = (word32 >> 21) & 0x1;
			PushUIMMValue(instruction, l);

			PushRA(instruction, word32);
			PushRB(instruction, word32);
			break;
		}

		case PPC_ID_DARN:
		{
			uint32_t l = (word32 >> 16) & 0x3;
			PushRD(instruction, word32);
			PushUIMMValue(instruction, l);
			break;
		}

		case PPC_ID_DCBF:
		case PPC_ID_DCBFEP:
		{
			uint32_t l = (word32 >> 21) & 0x3;
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			if (l != 0)
				PushUIMMValue(instruction, l);

			break;
		}

		case PPC_ID_EXTSWSLIx:
		{
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			uint32_t sh5 = (word32 >> 1) & 0x1;
			uint32_t sh0_4 = (word32 >> 11) & 0x1f;
			PushUIMMValue(instruction, (sh5 << 5) | sh0_4);

			instruction->flags.rc = word32 & 0x1;
			break;
		}

		case PPC_ID_FTDIV:
			PushCRFD(instruction, word32);
			PushFRA(instruction, word32);
			PushFRB(instruction, word32);
			break;

		case PPC_ID_FTSQRT:
			PushCRFD(instruction, word32);
			PushFRB(instruction, word32);
			break;

		case PPC_ID_MFBHRBE:
		{
			uint32_t bhrbe = (word32 >> 11) & 0x3ff;
			PushRD(instruction, word32);
			PushUIMMValue(instruction, bhrbe);
			break;
		}

		case PPC_ID_MFOCRF:
		{
			uint32_t fxm = (word32 >> 12) & 0xff;

			PushRD(instruction, word32);
			PushUIMMValue(instruction, fxm);
			break;
		}


		case PPC_ID_ICBT:
		{
			uint32_t ct = (word32 >> 21) & 0xf;

			PushUIMMValue(instruction, ct);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);

			break;
		}

		case PPC_ID_ISEL:
		{
			uint32_t bc = (word32 >> 6) & 0x1f;

			PushRD(instruction, word32);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			PushUIMMValue(instruction, bc);
			break;
		}

		case PPC_ID_LI:
			PushRD(instruction, word32);
			PushSIMMValue(instruction, (int32_t)((int16_t)(word32 & 0xffff)));
			break;

		case PPC_ID_LIS:
		{
			PushRD(instruction, word32);
			PushSIMMValue(instruction, (int32_t)(word32 & 0xffff));
			break;
		}

		case PPC_ID_LSWI:
		{
			uint32_t nb = (word32 >> 11) & 0x1f;

			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushUIMMValue(instruction, nb);
			break;
		}

		case PPC_ID_MBAR:
		{
			uint32_t mo = (word32 >> 21) & 0x1f;
			PushUIMMValue(instruction, mo);
			break;
		}

		case PPC_ID_MFFSx:
		case PPC_ID_MFFSCE:
		case PPC_ID_MFFSL:
			PushFRD(instruction, word32);
			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_MFFSCDRN:
		case PPC_ID_MFFSCRN:
			PushFRD(instruction, word32);
			PushFRB(instruction, word32);
			break;

		case PPC_ID_MFFSCDRNI:
		{
			uint32_t drm = (word32 >> 11) & 0x7;
			PushFRD(instruction, word32);
			PushUIMMValue(instruction, drm);
			break;
		}

		case PPC_ID_MFFSCRNI:
		{
			uint32_t rm = (word32 >> 11) & 0x3;
			PushFRD(instruction, word32);
			PushUIMMValue(instruction, rm);
			break;
		}

		case PPC_ID_MFSR:
		{
			uint32_t sr = (word32 >> 16) & 0xf;

			PushRD(instruction, word32);
			PushUIMMValue(instruction, sr);
			break;
		}

		case PPC_ID_MFSRIN:
			PushRD(instruction, word32);
			PushRB(instruction, word32);
			break;


		case PPC_ID_MRx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);

			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_MTCRF:
		{
			uint32_t crm = (word32 >> 12) & 0xff;

			PushUIMMValue(instruction, crm);
			PushRS(instruction, word32);
			break;
		}

		case PPC_ID_MTFSFx:
		{
			uint32_t w = (word32 >> 16) & 0x1;
			uint32_t l = (word32 >> 25) & 0x1;
			uint32_t flm = (word32 >> 17) & 0xff;

			PushUIMMValue(instruction, flm);
			PushFRB(instruction, word32);

			if (w != 0 || l != 0)
			{
				PushUIMMValue(instruction, l);
				PushUIMMValue(instruction, w);
			}

			instruction->flags.rc = word32 & 0x1;
			break;
		}

		case PPC_ID_MTFSFIx:
		{
			uint32_t u = (word32 >> 12) & 0xf;
			uint32_t w = (word32 >> 16) & 0x1;

			PushCRFD(instruction, word32);
			PushUIMMValue(instruction, u);
			if (w != 0)
				PushUIMMValue(instruction, w);

			instruction->flags.rc = word32 & 0x1;
			break;
		}

		case PPC_ID_MTOCRF:
		{
			uint32_t fxm = (word32 >> 12) & 0xff;

			PushRS(instruction, word32);
			PushUIMMValue(instruction, fxm);
			break;
		}

		case PPC_ID_MTSR:
		{
			uint32_t sr = (word32 >> 16) & 0xf;

			PushUIMMValue(instruction, sr);
			PushRS(instruction, word32);

			break;
		}

		case PPC_ID_MTSRIN:
			PushRS(instruction, word32);
			PushRB(instruction, word32);
			break;

		case PPC_ID_RFEBB:
			PushUIMMValue(instruction, (word32 >> 11) & 0x1);
			break;

		case PPC_ID_RLWIMIx:
		case PPC_ID_RLWINMx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, GetSH(word32));
			PushUIMMValue(instruction, GetMB(word32));
			PushUIMMValue(instruction, GetME(word32));

			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_RLWNMx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushRB(instruction, word32);
			PushUIMMValue(instruction, GetMB(word32));
			PushUIMMValue(instruction, GetME(word32));

			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_SC:
		{
			uint32_t lev = (word32 >> 5) & 0x7f;
			if (lev != 0)
				PushUIMMValue(instruction, lev);

			break;
		}

		case PPC_ID_SETB:
			PushRD(instruction, word32);
			PushCRFS(instruction, word32);
			break;

		case PPC_ID_SLBMFEE:
		case PPC_ID_SLBMFEV:
			PushRD(instruction, word32);
			PushRB(instruction, word32);
			break;

		case PPC_ID_SLBMTE:
		case PPC_ID_SLBIEG:
			PushRS(instruction, word32);
			PushRB(instruction, word32);
			break;

		case PPC_ID_SRADIx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, GetSH64(word32));

			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_SRAWIx:
			PushRA(instruction, word32);
			PushRS(instruction, word32);
			PushUIMMValue(instruction, GetSH(word32));

			instruction->flags.rc = word32 & 0x1;
			break;

		case PPC_ID_STSWI:
		{
			uint32_t nb = (word32 >> 11) & 0x1f;

			PushRS(instruction, word32);
			PushRA(instruction, word32);
			PushUIMMValue(instruction, nb);
			break;
		}

		case PPC_ID_TBEGIN:
		{
			uint32_t r = (word32 >> 21) & 0x1;

			PushUIMMValue(instruction, r);
			break;
		}

		case PPC_ID_TEND:
		{
			uint32_t a = (word32 >> 25) & 0x1;

			PushUIMMValue(instruction, a);
			break;
		}

		case PPC_ID_TLBIE:
			PushRB(instruction, word32);
			PushRS(instruction, word32);
			break;

		case PPC_ID_TLBIVAX:
			PushRA(instruction, word32);
			PushRB(instruction, word32);
			break;

		case PPC_ID_TSR:
		{
			uint32_t l = (word32 >> 21) & 0x1;

			PushUIMMValue(instruction, l);
			break;
		}

		case PPC_ID_WAIT:
		{
			uint32_t wc = (word32 >> 21) & 0x3;

			if (wc != 0)
				PushUIMMValue(instruction, wc);

			break;
		}

		case PPC_ID_WRTEEI:
		{
			uint32_t e = (word32 & 0x00008000) != 0;

			PushUIMMValue(instruction, e);
			break;
		}

		// ALTIVEC INSTRUCTIONS

		// <op> vD, vA, vB, vC
		case PPC_ID_AV_VADDECUQ:
		case PPC_ID_AV_VADDEUQM:
		case PPC_ID_AV_VMHADDSHS:
		case PPC_ID_AV_VMHRADDSHS:
		case PPC_ID_AV_VMLADDUHM:
		case PPC_ID_AV_VSUBECUQ:
		case PPC_ID_AV_VSUBEUQM:
		case PPC_ID_AV_VMSUMMBM:
		case PPC_ID_AV_VMSUMUBM:
		case PPC_ID_AV_VMSUMSHM:
		case PPC_ID_AV_VMSUMSHS:
		case PPC_ID_AV_VMSUMUHM:
		case PPC_ID_AV_VMSUMUHS:
		case PPC_ID_AV_VPERM:
		case PPC_ID_AV_VPERMR:
		case PPC_ID_AV_VPERMXOR:
		case PPC_ID_AV_VSEL:
			PushAltivecVD(instruction, word32);
			PushAltivecVA(instruction, word32);
			PushAltivecVB(instruction, word32);
			PushAltivecVC(instruction, word32);
			break;

		// <op> vD, vA, vC, vB (note swapped vC, vB)
		case PPC_ID_AV_VMADDFP:
		case PPC_ID_AV_VNMSUBFP:
			PushAltivecVD(instruction, word32);
			PushAltivecVA(instruction, word32);
			PushAltivecVC(instruction, word32);
			PushAltivecVB(instruction, word32);
			break;

		// <op> vD, vA, vB
		case PPC_ID_AV_VABSDUB:
		case PPC_ID_AV_VABSDUH:
		case PPC_ID_AV_VABSDUW:
		case PPC_ID_AV_VADDUQM:
		case PPC_ID_AV_VADDCUQ:
		case PPC_ID_AV_BCDUS:
		case PPC_ID_AV_BCDUTRUNC:
		case PPC_ID_AV_BCDCPSGN:
		case PPC_ID_AV_VADDCUW:
		case PPC_ID_AV_VADDFP:
		case PPC_ID_AV_VADDSBS:
		case PPC_ID_AV_VADDSHS:
		case PPC_ID_AV_VADDSWS:
		case PPC_ID_AV_VADDUBM:
		case PPC_ID_AV_VADDUBS:
		case PPC_ID_AV_VADDUDM:
		case PPC_ID_AV_VADDUHM:
		case PPC_ID_AV_VADDUHS:
		case PPC_ID_AV_VADDUWM:
		case PPC_ID_AV_VADDUWS:
		case PPC_ID_AV_VAND:
		case PPC_ID_AV_VANDC:
		case PPC_ID_AV_VAVGSB:
		case PPC_ID_AV_VAVGSH:
		case PPC_ID_AV_VAVGSW:
		case PPC_ID_AV_VAVGUB:
		case PPC_ID_AV_VAVGUH:
		case PPC_ID_AV_VAVGUW:
		case PPC_ID_AV_VBPERMD:
		case PPC_ID_AV_VBPERMQ:
		case PPC_ID_AV_VCIPHER:
		case PPC_ID_AV_VCIPHERLAST:
		case PPC_ID_AV_VEQV:
		case PPC_ID_AV_VMAXFP:
		case PPC_ID_AV_VMAXSB:
		case PPC_ID_AV_VMAXSD:
		case PPC_ID_AV_VMAXSH:
		case PPC_ID_AV_VMAXSW:
		case PPC_ID_AV_VMAXUB:
		case PPC_ID_AV_VMAXUD:
		case PPC_ID_AV_VMAXUH:
		case PPC_ID_AV_VMAXUW:
		case PPC_ID_AV_VMINFP:
		case PPC_ID_AV_VMINUB:
		case PPC_ID_AV_VMINUD:
		case PPC_ID_AV_VMINUH:
		case PPC_ID_AV_VMINUW:
		case PPC_ID_AV_VMINSB:
		case PPC_ID_AV_VMINSD:
		case PPC_ID_AV_VMINSH:
		case PPC_ID_AV_VMINSW:
		case PPC_ID_AV_VMRGEW:
		case PPC_ID_AV_VMRGHB:
		case PPC_ID_AV_VMRGHH:
		case PPC_ID_AV_VMRGHW:
		case PPC_ID_AV_VMRGLB:
		case PPC_ID_AV_VMRGLH:
		case PPC_ID_AV_VMRGLW:
		case PPC_ID_AV_VMRGOW:
		case PPC_ID_AV_VMUL10EUQ:
		case PPC_ID_AV_VMUL10ECUQ:
		case PPC_ID_AV_VMULESB:
		case PPC_ID_AV_VMULESH:
		case PPC_ID_AV_VMULESW:
		case PPC_ID_AV_VMULEUB:
		case PPC_ID_AV_VMULEUH:
		case PPC_ID_AV_VMULEUW:
		case PPC_ID_AV_VMULOSB:
		case PPC_ID_AV_VMULOSH:
		case PPC_ID_AV_VMULOSW:
		case PPC_ID_AV_VMULOUB:
		case PPC_ID_AV_VMULOUH:
		case PPC_ID_AV_VMULOUW:
		case PPC_ID_AV_VMULUWM:
		case PPC_ID_AV_VNAND:
		case PPC_ID_AV_VNCIPHER:
		case PPC_ID_AV_VNCIPHERLAST:
		case PPC_ID_AV_VNOR:
		case PPC_ID_AV_VOR:
		case PPC_ID_AV_VORC:
		case PPC_ID_AV_VPKPX:
		case PPC_ID_AV_VPKSDSS:
		case PPC_ID_AV_VPKSDUS:
		case PPC_ID_AV_VPKSHSS:
		case PPC_ID_AV_VPKSHUS:
		case PPC_ID_AV_VPKSWSS:
		case PPC_ID_AV_VPKSWUS:
		case PPC_ID_AV_VPKUDUM:
		case PPC_ID_AV_VPKUDUS:
		case PPC_ID_AV_VPKUHUM:
		case PPC_ID_AV_VPKUHUS:
		case PPC_ID_AV_VPKUWUM:
		case PPC_ID_AV_VPKUWUS:
		case PPC_ID_AV_VPMSUMB:
		case PPC_ID_AV_VPMSUMD:
		case PPC_ID_AV_VPMSUMH:
		case PPC_ID_AV_VPMSUMW:
		case PPC_ID_AV_VRLB:
		case PPC_ID_AV_VRLD:
		case PPC_ID_AV_VRLDMI:
		case PPC_ID_AV_VRLDNM:
		case PPC_ID_AV_VRLH:
		case PPC_ID_AV_VRLW:
		case PPC_ID_AV_VRLWMI:
		case PPC_ID_AV_VRLWNM:
		case PPC_ID_AV_VSL:
		case PPC_ID_AV_VSLB:
		case PPC_ID_AV_VSLD:
		case PPC_ID_AV_VSLH:
		case PPC_ID_AV_VSLO:
		case PPC_ID_AV_VSLV:
		case PPC_ID_AV_VSLW:
		case PPC_ID_AV_VSR:
		case PPC_ID_AV_VSRAB:
		case PPC_ID_AV_VSRAD:
		case PPC_ID_AV_VSRAH:
		case PPC_ID_AV_VSRAW:
		case PPC_ID_AV_VSRB:
		case PPC_ID_AV_VSRD:
		case PPC_ID_AV_VSRH:
		case PPC_ID_AV_VSRO:
		case PPC_ID_AV_VSRV:
		case PPC_ID_AV_VSRW:
		case PPC_ID_AV_VSUBCUQ:
		case PPC_ID_AV_VSUBCUW:
		case PPC_ID_AV_VSUBFP:
		case PPC_ID_AV_VSUBSBS:
		case PPC_ID_AV_VSUBSHS:
		case PPC_ID_AV_VSUBSWS:
		case PPC_ID_AV_VSUBUBS:
		case PPC_ID_AV_VSUBUHS:
		case PPC_ID_AV_VSUBUQM:
		case PPC_ID_AV_VSUBUWS:
		case PPC_ID_AV_VSUBUBM:
		case PPC_ID_AV_VSUBUDM:
		case PPC_ID_AV_VSUBUHM:
		case PPC_ID_AV_VSUBUWM:
		case PPC_ID_AV_VSUM2SWS:
		case PPC_ID_AV_VSUM4SBS:
		case PPC_ID_AV_VSUM4SHS:
		case PPC_ID_AV_VSUM4UBS:
		case PPC_ID_AV_VSUMSWS:
		case PPC_ID_AV_VXOR:
			PushAltivecVD(instruction, word32);
			PushAltivecVA(instruction, word32);
			PushAltivecVB(instruction, word32);
			break;

		// <op>[.] vD, vA, vB
		case PPC_ID_AV_VCMPBFPx:
		case PPC_ID_AV_VCMPEQFPx:
		case PPC_ID_AV_VCMPGEFPx:
		case PPC_ID_AV_VCMPEQUBx:
		case PPC_ID_AV_VCMPEQUDx:
		case PPC_ID_AV_VCMPEQUHx:
		case PPC_ID_AV_VCMPEQUWx:
		case PPC_ID_AV_VCMPGTFPx:
		case PPC_ID_AV_VCMPGTSBx:
		case PPC_ID_AV_VCMPGTSDx:
		case PPC_ID_AV_VCMPGTSHx:
		case PPC_ID_AV_VCMPGTSWx:
		case PPC_ID_AV_VCMPGTUBx:
		case PPC_ID_AV_VCMPGTUDx:
		case PPC_ID_AV_VCMPGTUHx:
		case PPC_ID_AV_VCMPGTUWx:
		case PPC_ID_AV_VCMPNEBx:
		case PPC_ID_AV_VCMPNEHx:
		case PPC_ID_AV_VCMPNEWx:
		case PPC_ID_AV_VCMPNEZBx:
		case PPC_ID_AV_VCMPNEZHx:
		case PPC_ID_AV_VCMPNEZWx:
			PushAltivecVD(instruction, word32);
			PushAltivecVA(instruction, word32);
			PushAltivecVB(instruction, word32);

			instruction->flags.rc = (word32 >> 10) & 0x1;
			break;

		// <op> vD, vA
		case PPC_ID_AV_VMUL10CUQ:
		case PPC_ID_AV_VMUL10UQ:
		case PPC_ID_AV_VSBOX:
			PushAltivecVD(instruction, word32);
			PushAltivecVA(instruction, word32);
			break;

		// <op> vD, vB
		case PPC_ID_AV_BCDCTN:
		case PPC_ID_AV_BCDCTSQ:
		case PPC_ID_AV_VCLZB:
		case PPC_ID_AV_VCLZD:
		case PPC_ID_AV_VCLZH:
		case PPC_ID_AV_VCLZW:
		case PPC_ID_AV_VCTZB:
		case PPC_ID_AV_VCTZD:
		case PPC_ID_AV_VCTZH:
		case PPC_ID_AV_VCTZW:
		case PPC_ID_AV_VEXPTEFP:
		case PPC_ID_AV_VEXTSB2D:
		case PPC_ID_AV_VEXTSB2W:
		case PPC_ID_AV_VEXTSH2D:
		case PPC_ID_AV_VEXTSH2W:
		case PPC_ID_AV_VEXTSW2D:
		case PPC_ID_AV_VGBBD:
		case PPC_ID_AV_VLOGEFP:
		case PPC_ID_AV_VMR:
		case PPC_ID_AV_VNEGD:
		case PPC_ID_AV_VNEGW:
		case PPC_ID_AV_VNOT:
		case PPC_ID_AV_VPOPCNTB:
		case PPC_ID_AV_VPOPCNTD:
		case PPC_ID_AV_VPOPCNTH:
		case PPC_ID_AV_VPOPCNTW:
		case PPC_ID_AV_VPRTYBD:
		case PPC_ID_AV_VPRTYBQ:
		case PPC_ID_AV_VPRTYBW:
		case PPC_ID_AV_VREFP:
		case PPC_ID_AV_VRFIM:
		case PPC_ID_AV_VRFIN:
		case PPC_ID_AV_VRFIP:
		case PPC_ID_AV_VRFIZ:
		case PPC_ID_AV_VRSQRTEFP:
		case PPC_ID_AV_VUPKHPX:
		case PPC_ID_AV_VUPKHSB:
		case PPC_ID_AV_VUPKHSH:
		case PPC_ID_AV_VUPKHSW:
		case PPC_ID_AV_VUPKLPX:
		case PPC_ID_AV_VUPKLSB:
		case PPC_ID_AV_VUPKLSH:
		case PPC_ID_AV_VUPKLSW:
			PushAltivecVD(instruction, word32);
			PushAltivecVB(instruction, word32);
			break;

		// <op> vD, vB, UIMM
		case PPC_ID_AV_VCFSX:
		case PPC_ID_AV_VCFUX:
		case PPC_ID_AV_VCTSXS:
		case PPC_ID_AV_VCTUXS:
		case PPC_ID_AV_VSPLTB:
		case PPC_ID_AV_VSPLTH:
		case PPC_ID_AV_VSPLTW:
			PushAltivecVD(instruction, word32);
			PushAltivecVB(instruction, word32);
			PushUIMMValue(instruction, (word32 >> 16) & 0x1f);
			break;

		// <op> vD, SIMM
		case PPC_ID_AV_VSPLTISB:
		case PPC_ID_AV_VSPLTISH:
		case PPC_ID_AV_VSPLTISW:
		{
			PushAltivecVD(instruction, word32);

			int32_t simm = sign_extend((word32 >> 16) & 0x1f, 5);
			PushSIMMValue(instruction, simm);
			break;
		}

		// <op> vD, d(rA)
		case PPC_ID_AV_LVEBX:
		case PPC_ID_AV_LVEHX:
		case PPC_ID_AV_LVEWX:
		case PPC_ID_AV_LVSL:
		case PPC_ID_AV_LVSR:
		case PPC_ID_AV_LVX:
		case PPC_ID_AV_LVXL:
			PushAltivecVD(instruction, word32);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op> vS, d(rA)
		case PPC_ID_AV_STVEBX:
		case PPC_ID_AV_STVEHX:
		case PPC_ID_AV_STVEWX:
		case PPC_ID_AV_STVX:
		case PPC_ID_AV_STVXL:
			PushAltivecVS(instruction, word32);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		case PPC_ID_AV_DST:
		case PPC_ID_AV_DSTST:
		case PPC_ID_AV_DSTSTT:
		case PPC_ID_AV_DSTT:
		{
			uint32_t strm = (word32 >> 21) & 0x3;

			PushRA(instruction, word32);
			PushRB(instruction, word32);
			PushUIMMValue(instruction, strm);
			break;
		}

		case PPC_ID_AV_DSS:
		{
			uint32_t strm = (word32 >> 21) & 0x3;
			PushUIMMValue(instruction, strm);
			break;
		}

		case PPC_ID_AV_MFVSCR:
			// mfvscr vD
			PushAltivecVD(instruction, word32);
			break;

		case PPC_ID_AV_MTVSCR:
			// mtvscr vB
			PushAltivecVB(instruction, word32);
			break;

		case PPC_ID_AV_VSLDOI:
			// vsldoi vD, vA, vB, UIMM
			PushAltivecVD(instruction, word32);
			PushAltivecVA(instruction, word32);
			PushAltivecVB(instruction, word32);
			PushUIMMValue(instruction, (word32 >> 6) & 0xf);
			break;

		// rD, rA, rB, rC (normal registers)
		case PPC_ID_AV_MADDHD:
		case PPC_ID_AV_MADDHDU:
		case PPC_ID_AV_MADDLD:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushRB(instruction, word32);
			PushRC(instruction, word32);
			break;

		// vrD, vrA, vrB, ps
		case PPC_ID_AV_BCDADD:
		case PPC_ID_AV_BCDSUB:
		case PPC_ID_AV_BCDS:
		case PPC_ID_AV_BCDSR:
		case PPC_ID_AV_BCDTRUNC:
		{
			PushAltivecVD(instruction, word32);
			PushAltivecVA(instruction, word32);
			PushAltivecVB(instruction, word32);
			uint32_t ps = (word32 & 0x200) != 0;
			PushUIMMValue(instruction, ps);
			break;
		}


		// vrD, vrB, ps
		case PPC_ID_AV_BCDCFN:
		case PPC_ID_AV_BCDCFZ:
		case PPC_ID_AV_BCDCTZ:
		case PPC_ID_AV_BCDCFSQ:
		case PPC_ID_AV_BCDSETSGN:
			// PS isn't in all of these instructions, but it gets
			// filtered out in subop decode
			PushAltivecVD(instruction, word32);
			PushAltivecVB(instruction, word32);
			uint32_t ps = (word32 & 0x200) != 0;
			PushUIMMValue(instruction, ps);
			break;


		// vrD, vrB, UIM
		case PPC_ID_AV_VEXTRACTD:
		case PPC_ID_AV_VEXTRACTUB:
		case PPC_ID_AV_VEXTRACTUH:
		case PPC_ID_AV_VEXTRACTUW:
		case PPC_ID_AV_VINSERTB:
		case PPC_ID_AV_VINSERTD:
		case PPC_ID_AV_VINSERTH:
		case PPC_ID_AV_VINSERTW:
			PushAltivecVD(instruction, word32);
			PushAltivecVB(instruction, word32);
			PushUIMMValue(instruction, (word32 >> 16) & 0xf);
			break;
			
		// <op> rD, rA, vB
		case PPC_ID_AV_VEXTUBLX:
		case PPC_ID_AV_VEXTUHLX:
		case PPC_ID_AV_VEXTUWLX:
		case PPC_ID_AV_VEXTUBRX:
		case PPC_ID_AV_VEXTUHRX:
		case PPC_ID_AV_VEXTUWRX:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushAltivecVB(instruction, word32);
			break;

		// <op> vD, vA, ST, SIX
		case PPC_ID_AV_VSHASIGMAD:
		case PPC_ID_AV_VSHASIGMAW:
			PushAltivecVD(instruction, word32);
			PushAltivecVA(instruction, word32);
			PushUIMMValue(instruction, (word32 >> 15) & 0x1);
			PushUIMMValue(instruction, (word32 >> 11) & 0xf);
			break;

		// <op> rD, vB
		case PPC_ID_AV_VCLZLSBB:
		case PPC_ID_AV_VCTZLSBB:
			PushRD(instruction, word32);
			PushAltivecVB(instruction, word32);
			break;

		// VSX INSTRUCTIONS

		// <op> vrD, vrA, vrB <full width>
		case PPC_ID_VSX_XVADDDP:
		case PPC_ID_VSX_XVADDSP:
		case PPC_ID_VSX_XVCPSGNDP:
		case PPC_ID_VSX_XVCPSGNSP:
		case PPC_ID_VSX_XVDIVDP:
		case PPC_ID_VSX_XVDIVSP:
		case PPC_ID_VSX_XVIEXPDP:
		case PPC_ID_VSX_XVIEXPSP:
		case PPC_ID_VSX_XVMADDADP:
		case PPC_ID_VSX_XVMADDASP:
		case PPC_ID_VSX_XVMADDMDP:
		case PPC_ID_VSX_XVMADDMSP:
		case PPC_ID_VSX_XVMAXDP:
		case PPC_ID_VSX_XVMAXSP:
		case PPC_ID_VSX_XVMINDP:
		case PPC_ID_VSX_XVMINSP:
		case PPC_ID_VSX_XVMSUBADP:
		case PPC_ID_VSX_XVMSUBMDP:
		case PPC_ID_VSX_XVMSUBASP:
		case PPC_ID_VSX_XVMSUBMSP:
		case PPC_ID_VSX_XVMULDP:
		case PPC_ID_VSX_XVMULSP:
		case PPC_ID_VSX_XVNMADDADP:
		case PPC_ID_VSX_XVNMADDASP:
		case PPC_ID_VSX_XVNMADDMDP:
		case PPC_ID_VSX_XVNMADDMSP:
		case PPC_ID_VSX_XVNMSUBADP:
		case PPC_ID_VSX_XVNMSUBASP:
		case PPC_ID_VSX_XVNMSUBMDP:
		case PPC_ID_VSX_XVNMSUBMSP:
		case PPC_ID_VSX_XVSUBDP:
		case PPC_ID_VSX_XVSUBSP:
		case PPC_ID_VSX_XXLAND:
		case PPC_ID_VSX_XXLANDC:
		case PPC_ID_VSX_XXLEQV:
		case PPC_ID_VSX_XXLOR:
		case PPC_ID_VSX_XXLNAND:
		case PPC_ID_VSX_XXLNOR:
		case PPC_ID_VSX_XXLORC:
		case PPC_ID_VSX_XXLXOR:
		case PPC_ID_VSX_XXMRGHD:
		case PPC_ID_VSX_XXMRGHW:
		case PPC_ID_VSX_XXMRGLD:
		case PPC_ID_VSX_XXMRGLW:
		case PPC_ID_VSX_XXPERM:
		case PPC_ID_VSX_XXPERMR:
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushVsxA(instruction, word32, VSX_WIDTH_FULL);
			PushVsxB(instruction, word32, VSX_WIDTH_FULL);
			break;

		// <op>[.] vrD, rA, vrB <full>
		case PPC_ID_VSX_XVCMPEQDPx:
		case PPC_ID_VSX_XVCMPEQSPx:
		case PPC_ID_VSX_XVCMPGEDPx:
		case PPC_ID_VSX_XVCMPGESPx:
		case PPC_ID_VSX_XVCMPGTDPx:
		case PPC_ID_VSX_XVCMPGTSPx:
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushVsxA(instruction, word32, VSX_WIDTH_FULL);
			PushVsxB(instruction, word32, VSX_WIDTH_FULL);
			instruction->flags.rc = (word32 & 0x400) != 0;
			break;

		// <op> vrD, vrA, vrB <dword0>
		case PPC_ID_VSX_XSADDSP:
		case PPC_ID_VSX_XSADDDP:
		case PPC_ID_VSX_XSCMPEQDP:
		case PPC_ID_VSX_XSCMPGEDP:
		case PPC_ID_VSX_XSCMPGTDP:
		case PPC_ID_VSX_XSCPSGNDP:
		case PPC_ID_VSX_XSDIVDP:
		case PPC_ID_VSX_XSDIVSP:
		case PPC_ID_VSX_XSMADDADP:
		case PPC_ID_VSX_XSMADDMDP:
		case PPC_ID_VSX_XSMADDASP:
		case PPC_ID_VSX_XSMADDMSP:
		case PPC_ID_VSX_XSMAXCDP:
		case PPC_ID_VSX_XSMAXDP:
		case PPC_ID_VSX_XSMAXJDP:
		case PPC_ID_VSX_XSMINCDP:
		case PPC_ID_VSX_XSMINDP:
		case PPC_ID_VSX_XSMINJDP:
		case PPC_ID_VSX_XSMSUBADP:
		case PPC_ID_VSX_XSMSUBASP:
		case PPC_ID_VSX_XSMSUBMDP:
		case PPC_ID_VSX_XSMSUBMSP:
		case PPC_ID_VSX_XSMULDP:
		case PPC_ID_VSX_XSMULSP:
		case PPC_ID_VSX_XSNMADDADP:
		case PPC_ID_VSX_XSNMADDASP:
		case PPC_ID_VSX_XSNMADDMDP:
		case PPC_ID_VSX_XSNMADDMSP:
		case PPC_ID_VSX_XSNMSUBADP:
		case PPC_ID_VSX_XSNMSUBASP:
		case PPC_ID_VSX_XSNMSUBMDP:
		case PPC_ID_VSX_XSNMSUBMSP:
		case PPC_ID_VSX_XSSUBDP:
		case PPC_ID_VSX_XSSUBSP:
			PushVsxD(instruction, word32, VSX_WIDTH_DWORD0);
			PushVsxA(instruction, word32, VSX_WIDTH_DWORD0);
			PushVsxB(instruction, word32, VSX_WIDTH_DWORD0);
			break;

		// <op> vrD, vrB
		case PPC_ID_VSX_XVABSDP:
		case PPC_ID_VSX_XVABSSP:
		case PPC_ID_VSX_XVCVDPSP:
		case PPC_ID_VSX_XVCVDPSXDS:
		case PPC_ID_VSX_XVCVDPSXWS:
		case PPC_ID_VSX_XVCVDPUXDS:
		case PPC_ID_VSX_XVCVDPUXWS:
		case PPC_ID_VSX_XVCVSPDP:
		case PPC_ID_VSX_XVCVSPSXDS:
		case PPC_ID_VSX_XVCVSPSXWS:
		case PPC_ID_VSX_XVCVSPUXDS:
		case PPC_ID_VSX_XVCVSPUXWS:
		case PPC_ID_VSX_XVCVSXDDP:
		case PPC_ID_VSX_XVCVSXDSP:
		case PPC_ID_VSX_XVCVSXWDP:
		case PPC_ID_VSX_XVCVSXWSP:
		case PPC_ID_VSX_XVCVUXDDP:
		case PPC_ID_VSX_XVCVUXDSP:
		case PPC_ID_VSX_XVCVUXWDP:
		case PPC_ID_VSX_XVCVUXWSP:
		case PPC_ID_VSX_XVNABSDP:
		case PPC_ID_VSX_XVNABSSP:
		case PPC_ID_VSX_XVNEGDP:
		case PPC_ID_VSX_XVNEGSP:
		case PPC_ID_VSX_XVRDPI:
		case PPC_ID_VSX_XVRDPIC:
		case PPC_ID_VSX_XVRDPIM:
		case PPC_ID_VSX_XVRDPIP:
		case PPC_ID_VSX_XVRDPIZ:
		case PPC_ID_VSX_XVREDP:
		case PPC_ID_VSX_XVRESP:
		case PPC_ID_VSX_XVRSPI:
		case PPC_ID_VSX_XVRSPIC:
		case PPC_ID_VSX_XVRSPIM:
		case PPC_ID_VSX_XVRSPIP:
		case PPC_ID_VSX_XVRSPIZ:
		case PPC_ID_VSX_XVRSQRTEDP:
		case PPC_ID_VSX_XVRSQRTESP:
		case PPC_ID_VSX_XVSQRTSP:
		case PPC_ID_VSX_XVSQRTDP:
		case PPC_ID_VSX_XVMOVDP:
		case PPC_ID_VSX_XVMOVSP:
		case PPC_ID_VSX_XVXEXPDP:
		case PPC_ID_VSX_XVXEXPSP:
		case PPC_ID_VSX_XVXSIGDP:
		case PPC_ID_VSX_XVXSIGSP:
		case PPC_ID_VSX_XXBRD:
		case PPC_ID_VSX_XXBRH:
		case PPC_ID_VSX_XXBRQ:
		case PPC_ID_VSX_XXBRW:
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushVsxB(instruction, word32, VSX_WIDTH_FULL);
			break;

		// <op> vrD, vrB
		case PPC_ID_VSX_XSABSDP:
		case PPC_ID_VSX_XSCVDPHP:
		case PPC_ID_VSX_XSCVDPSXDS:
		case PPC_ID_VSX_XSCVDPSP:
		case PPC_ID_VSX_XSCVDPSPN:
		case PPC_ID_VSX_XSCVDPSXWS:
		case PPC_ID_VSX_XSCVDPUXDS:
		case PPC_ID_VSX_XSCVDPUXWS:
		case PPC_ID_VSX_XSCVSPDP:
		case PPC_ID_VSX_XSCVHPDP:
		case PPC_ID_VSX_XSCVSPDPN:
		case PPC_ID_VSX_XSCVSXDDP:
		case PPC_ID_VSX_XSCVSXDSP:
		case PPC_ID_VSX_XSCVUXDDP:
		case PPC_ID_VSX_XSCVUXDSP:
		case PPC_ID_VSX_XSNABSDP:
		case PPC_ID_VSX_XSNEGDP:
		case PPC_ID_VSX_XSRDPI:
		case PPC_ID_VSX_XSRDPIC:
		case PPC_ID_VSX_XSRDPIM:
		case PPC_ID_VSX_XSRDPIP:
		case PPC_ID_VSX_XSRDPIZ:
		case PPC_ID_VSX_XSREDP:
		case PPC_ID_VSX_XSRESP:
		case PPC_ID_VSX_XSRSP:
		case PPC_ID_VSX_XSRSQRTESP:
		case PPC_ID_VSX_XSRSQRTEDP:
		case PPC_ID_VSX_XSSQRTDP:
		case PPC_ID_VSX_XSSQRTSP:
		case PPC_ID_VSX_XVCVHPSP:
		case PPC_ID_VSX_XVCVSPHP:
			PushVsxD(instruction, word32, VSX_WIDTH_DWORD0);
			PushVsxB(instruction, word32, VSX_WIDTH_DWORD0);
			break;

		// <op> vrD, vrA, vrB, <UIMM>
		case PPC_ID_VSX_XXPERMDI:
		case PPC_ID_VSX_XXSLDWI:
		{
			uint32_t uimm = (word32 >> 8) & 0x3;

			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushVsxA(instruction, word32, VSX_WIDTH_FULL);
			PushVsxB(instruction, word32, VSX_WIDTH_FULL);
			PushUIMMValue(instruction, uimm);
			break;
		}

		// <op> vrD, rA, rB
		case PPC_ID_VSX_MTVSRDD:
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op> vrD, rA, rB (load indexed)
		case PPC_ID_VSX_LXVB16X:
		case PPC_ID_VSX_LXVD2X:
		case PPC_ID_VSX_LXVDSX:
		case PPC_ID_VSX_LXVH8X:
		case PPC_ID_VSX_LXVL:
		case PPC_ID_VSX_LXVLL:
		case PPC_ID_VSX_LXVW4X:
		case PPC_ID_VSX_LXVWSX:
		case PPC_ID_VSX_LXVX:
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		case PPC_ID_VSX_LXSDX:
		case PPC_ID_VSX_LXSIBZX:
		case PPC_ID_VSX_LXSIHZX:
		case PPC_ID_VSX_LXSIWAX:
		case PPC_ID_VSX_LXSIWZX:
		case PPC_ID_VSX_LXSSPX:
			PushVsxD(instruction, word32, VSX_WIDTH_DWORD0);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op> vrS, rA, rB (store indexed)
		case PPC_ID_VSX_STXVB16X:
		case PPC_ID_VSX_STXVD2X:
		case PPC_ID_VSX_STXVH8X:
		case PPC_ID_VSX_STXVL:
		case PPC_ID_VSX_STXVLL:
		case PPC_ID_VSX_STXVW4X:
		case PPC_ID_VSX_STXVX:
			PushVsxS(instruction, word32, VSX_WIDTH_FULL);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		case PPC_ID_VSX_STXSDX:
		case PPC_ID_VSX_STXSIBX:
		case PPC_ID_VSX_STXSIHX:
		case PPC_ID_VSX_STXSIWX:
		case PPC_ID_VSX_STXSSPX:
			PushVsxS(instruction, word32, VSX_WIDTH_DWORD0);
			PushRAor0(instruction, word32);
			PushRB(instruction, word32);
			break;

		// <op> crfD, vrA, vrB <dword0>
		case PPC_ID_VSX_XSCMPEXPDP:
		case PPC_ID_VSX_XSCMPODP:
		case PPC_ID_VSX_XSCMPUDP:
		case PPC_ID_VSX_XSTDIVDP:
			PushCRFD(instruction, word32);
			PushVsxA(instruction, word32, VSX_WIDTH_DWORD0);
			PushVsxB(instruction, word32, VSX_WIDTH_DWORD0);
			break;

		// <op> crfD, vrA, vrB <full>
		case PPC_ID_VSX_XVTDIVDP:
		case PPC_ID_VSX_XVTDIVSP:
			PushCRFD(instruction, word32);
			PushVsxA(instruction, word32, VSX_WIDTH_FULL);
			PushVsxB(instruction, word32, VSX_WIDTH_FULL);
			break;

		// <op> crfD, vrB
		case PPC_ID_VSX_XVTSQRTSP:
		case PPC_ID_VSX_XVTSQRTDP:
			PushCRFD(instruction, word32);
			PushVsxB(instruction, word32, VSX_WIDTH_FULL);
			break;

		case PPC_ID_VSX_XSTSQRTDP:
			PushCRFD(instruction, word32);
			PushVsxB(instruction, word32, VSX_WIDTH_DWORD0);
			break;

		// <op> vrD, rA
		case PPC_ID_VSX_MTVSRWS:
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushRA(instruction, word32);
			break;

		case PPC_ID_VSX_MTVSRD:
		case PPC_ID_VSX_MTVSRWA:
		case PPC_ID_VSX_MTVSRWZ:
			PushVsxD(instruction, word32, VSX_WIDTH_DWORD0);
			PushRA(instruction, word32);
			break;

		// <op> rA, vrS
		case PPC_ID_VSX_MFVSRLD:
			PushRA(instruction, word32);
			PushVsxS(instruction, word32, VSX_WIDTH_FULL);
			break;

		case PPC_ID_VSX_MFFPRD:
		case PPC_ID_VSX_MFVSRWZ:
		case PPC_ID_VSX_MFVSRD:
			PushRA(instruction, word32);
			PushVsxS(instruction, word32, VSX_WIDTH_DWORD0);
			break;

		// <op> vrD, vrB, UIM
		case PPC_ID_VSX_XXINSERTW:
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushVsxB(instruction, word32, VSX_WIDTH_FULL);
			PushUIMMValue(instruction, (word32 >> 16) & 0xf);
			break;

		case PPC_ID_VSX_XXEXTRACTUW:
			PushVsxD(instruction, word32, VSX_WIDTH_DWORD0);
			PushVsxB(instruction, word32, VSX_WIDTH_DWORD0);
			PushUIMMValue(instruction, (word32 >> 16) & 0xf);
			break;

		case PPC_ID_VSX_LXSD:
		case PPC_ID_VSX_LXSSP:
		{
			PushVsxHiD(instruction, word32);

			int32_t ds = (int32_t)((int16_t)(word32 & 0xfffc));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(GetA(word32)), ds);
			break;
		}

		case PPC_ID_VSX_LXV:
		{
			uint32_t dx = (word32 >> 3) & 0x1;
			uint32_t d = GetD(word32);
			uint32_t vsxd = (dx << 5) | d;

			PushRegister(instruction, PPC_OP_REG_VSX_RD, VsxVr(vsxd));

			uint32_t dq = (int32_t)((int16_t)(word32 & 0xfff0));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(GetA(word32)), dq);

			break;
		}

		case PPC_ID_VSX_STXV:
		{
			uint32_t sx = (word32 >> 3) & 0x1;
			uint32_t s = GetS(word32);
			uint32_t vsxs = (sx << 5) | s;

			PushRegister(instruction, PPC_OP_REG_VSX_RS, VsxVr(vsxs));

			int32_t dq = (int32_t)((int16_t)(word32 & 0xfff0));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(GetA(word32)), dq);

			break;
		}

		case PPC_ID_VSX_STXSD:
		case PPC_ID_VSX_STXSSP:
		{
			PushVsxHiS(instruction, word32);

			int32_t ds = (int32_t)((int16_t)(word32 & 0xfffc));
			PushMem(instruction, PPC_OP_MEM_RA, Gpr(GetA(word32)), ds);
			break;
		}

		// <op>[o] vrdHi, vraHi, vrbHi
		case PPC_ID_VSX_XSADDQPx:
		case PPC_ID_VSX_XSCPSGNQP:
		case PPC_ID_VSX_XSDIVQPx:
		case PPC_ID_VSX_XSIEXPQP:
		case PPC_ID_VSX_XSMADDQPx:
		case PPC_ID_VSX_XSMSUBQPx:
		case PPC_ID_VSX_XSMULQPx:
		case PPC_ID_VSX_XSNMADDQPx:
		case PPC_ID_VSX_XSNMSUBQPx:
		case PPC_ID_VSX_XSSUBQPx:
		{
			PushVsxHiD(instruction, word32);
			PushVsxHiA(instruction, word32);
			PushVsxHiB(instruction, word32);

			instruction->flags.round2odd = word32 & 0x1;
			break;
		}

		case PPC_ID_VSX_XSABSQP:
		case PPC_ID_VSX_XSCVQPUWZ:
		case PPC_ID_VSX_XSCVUDQP:
		case PPC_ID_VSX_XSNABSQP:
		case PPC_ID_VSX_XSCVDPQP:
		case PPC_ID_VSX_XSCVQPDPx:
		case PPC_ID_VSX_XSCVQPSDZ:
		case PPC_ID_VSX_XSCVQPSWZ:
		case PPC_ID_VSX_XSCVQPUDZ:
		case PPC_ID_VSX_XSCVSDQP:
		case PPC_ID_VSX_XSNEGQP:
		case PPC_ID_VSX_XSSQRTQPx:
		case PPC_ID_VSX_XSXEXPQP:
		case PPC_ID_VSX_XSXSIGQP:
		{
			PushVsxHiD(instruction, word32);
			PushVsxHiB(instruction, word32);

			instruction->flags.round2odd = word32 & 0x1;
			break;
		}

		case PPC_ID_VSX_XSCMPEXPQP:
		case PPC_ID_VSX_XSCMPOQP:
		case PPC_ID_VSX_XSCMPUQP:
			PushCRFD(instruction, word32);
			PushVsxHiA(instruction, word32);
			PushVsxHiB(instruction, word32);

			break;

		case PPC_ID_VSX_XSTSTDCQP:
		{
			uint32_t dcmx = (word32 >> 16) & 0x7f;
			PushCRFD(instruction, word32);
			PushVsxHiB(instruction, word32);
			PushUIMMValue(instruction, dcmx);
			break;
		}

		// one-off VSX instructions
		case PPC_ID_VSX_XSIEXPDP:
		{
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushRA(instruction, word32);
			PushRB(instruction, word32);
			break;
		}

		case PPC_ID_VSX_XSRQPIx:
		case PPC_ID_VSX_XSRQPXP:
		{
			uint32_t r = (word32 >> 16) & 0x1;
			PushUIMMValue(instruction, r);
			PushVsxHiD(instruction, word32);
			PushVsxHiB(instruction, word32);

			uint32_t rmc = (word32 >> 9) & 0x3;
			PushUIMMValue(instruction, rmc);

			instruction->flags.inexact = word32 & 0x1;
			break;
		}

		case PPC_ID_VSX_XSTSTDCDP:
		case PPC_ID_VSX_XSTSTDCSP:
		{
			uint32_t dcmx = (word32 >> 16) & 0x7f;
			PushCRFD(instruction, word32);
			PushVsxB(instruction, word32, VSX_WIDTH_DWORD0);
			PushUIMMValue(instruction, dcmx);
			break;
		}

		case PPC_ID_VSX_XSXEXPDP:
		case PPC_ID_VSX_XSXSIGDP:
			PushRD(instruction, word32);
			PushVsxB(instruction, word32, VSX_WIDTH_DWORD0);
			break;

		case PPC_ID_VSX_XVTSTDCDP:
		case PPC_ID_VSX_XVTSTDCSP:
		{
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushVsxB(instruction, word32, VSX_WIDTH_FULL);
			uint32_t dm = (word32 >> 2) & 0x1;
			uint32_t dc = (word32 >> 6) & 0x1;
			uint32_t dx = (word32 >> 16) & 0x1f;
			uint32_t dcmx = (dc << 6) | (dm << 5) | dx;
			PushUIMMValue(instruction, dcmx);
			break;
		}


		case PPC_ID_VSX_XXSPLTD:
		{
			uint32_t uimm = (word32 >> 8) & 0x3;

			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushVsxA(instruction, word32, VSX_WIDTH_FULL);

			if (uimm == 3)
				PushUIMMValue(instruction, 1);
			else
				PushUIMMValue(instruction, 0);

			break;
		}

		case PPC_ID_VSX_XXSPLTIB:
		{
			uint32_t uimm8 = (word32 >> 11) & 0xff;
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushUIMMValue(instruction, uimm8);
			break;
		}

		case PPC_ID_VSX_XXSPLTW:
		{
			uint32_t um = (word32 >> 16) & 0x3;

			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushVsxB(instruction, word32, VSX_WIDTH_FULL);
			PushUIMMValue(instruction, um);
			break;
		}

		case PPC_ID_VSX_XXSWAPD:
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushVsxA(instruction, word32, VSX_WIDTH_FULL);
			break;

		case PPC_ID_VSX_XXSEL:
			PushVsxD(instruction, word32, VSX_WIDTH_FULL);
			PushVsxA(instruction, word32, VSX_WIDTH_FULL);
			PushVsxB(instruction, word32, VSX_WIDTH_FULL);
			PushVsxC(instruction, word32, VSX_WIDTH_FULL);
			break;

		// SPE INSTRUCTIONS

		// SPE rD, rA, rB
		case PPC_ID_SPE_BRINC:
		case PPC_ID_SPE_EFDADD:
		case PPC_ID_SPE_EFDDIV:
		case PPC_ID_SPE_EFDMUL:
		case PPC_ID_SPE_EFDSUB:
		case PPC_ID_SPE_EFSADD:
		case PPC_ID_SPE_EFSDIV:
		case PPC_ID_SPE_EFSMUL:
		case PPC_ID_SPE_EFSSUB:
		case PPC_ID_SPE_EVADDW:
		case PPC_ID_SPE_EVAND:
		case PPC_ID_SPE_EVANDC:
		case PPC_ID_SPE_EVDIVWS:
		case PPC_ID_SPE_EVDIVWU:
		case PPC_ID_SPE_EVEQV:
		case PPC_ID_SPE_EVFSADD:
		case PPC_ID_SPE_EVFSDIV:
		case PPC_ID_SPE_EVFSMUL:
		case PPC_ID_SPE_EVFSSUB:
		case PPC_ID_SPE_EVLDDX:
		case PPC_ID_SPE_EVLDHX:
		case PPC_ID_SPE_EVLDWX:
		case PPC_ID_SPE_EVLHHESPLATX:
		case PPC_ID_SPE_EVLHHOSSPLATX:
		case PPC_ID_SPE_EVLHHOUSPLATX:
		case PPC_ID_SPE_EVLWHEX:
		case PPC_ID_SPE_EVLWHOSX:
		case PPC_ID_SPE_EVLWHOUX:
		case PPC_ID_SPE_EVLWHSPLATX:
		case PPC_ID_SPE_EVLWWSPLATX:
		case PPC_ID_SPE_EVMERGEHI:
		case PPC_ID_SPE_EVMERGEHILO:
		case PPC_ID_SPE_EVMERGELO:
		case PPC_ID_SPE_EVMERGELOHI:
		case PPC_ID_SPE_EVMHEGSMFAA:
		case PPC_ID_SPE_EVMHEGSMFAN:
		case PPC_ID_SPE_EVMHEGSMIAA:
		case PPC_ID_SPE_EVMHEGSMIAN:
		case PPC_ID_SPE_EVMHEGUMIAA:
		case PPC_ID_SPE_EVMHEGUMIAN:
		case PPC_ID_SPE_EVMHESMF:
		case PPC_ID_SPE_EVMHESMFA:
		case PPC_ID_SPE_EVMHESMFAAW:
		case PPC_ID_SPE_EVMHESMFANW:
		case PPC_ID_SPE_EVMHESMI:
		case PPC_ID_SPE_EVMHESMIA:
		case PPC_ID_SPE_EVMHESMIAAW:
		case PPC_ID_SPE_EVMHESMIANW:
		case PPC_ID_SPE_EVMHESSF:
		case PPC_ID_SPE_EVMHESSFA:
		case PPC_ID_SPE_EVMHESSFAAW:
		case PPC_ID_SPE_EVMHESSFANW:
		case PPC_ID_SPE_EVMHESSIAAW:
		case PPC_ID_SPE_EVMHESSIANW:
		case PPC_ID_SPE_EVMHEUMI:
		case PPC_ID_SPE_EVMHEUMIA:
		case PPC_ID_SPE_EVMHEUMIAAW:
		case PPC_ID_SPE_EVMHEUMIANW:
		case PPC_ID_SPE_EVMHEUSIAAW:
		case PPC_ID_SPE_EVMHEUSIANW:
		case PPC_ID_SPE_EVMHOGSMFAA:
		case PPC_ID_SPE_EVMHOGSMFAN:
		case PPC_ID_SPE_EVMHOGSMIAA:
		case PPC_ID_SPE_EVMHOGSMIAN:
		case PPC_ID_SPE_EVMHOGUMIAA:
		case PPC_ID_SPE_EVMHOGUMIAN:
		case PPC_ID_SPE_EVMHOSMF:
		case PPC_ID_SPE_EVMHOSMFA:
		case PPC_ID_SPE_EVMHOSMFAAW:
		case PPC_ID_SPE_EVMHOSMFANW:
		case PPC_ID_SPE_EVMHOSMI:
		case PPC_ID_SPE_EVMHOSMIA:
		case PPC_ID_SPE_EVMHOSMIAAW:
		case PPC_ID_SPE_EVMHOSMIANW:
		case PPC_ID_SPE_EVMHOSSF:
		case PPC_ID_SPE_EVMHOSSFA:
		case PPC_ID_SPE_EVMHOSSFAAW:
		case PPC_ID_SPE_EVMHOSSFANW:
		case PPC_ID_SPE_EVMHOSSIAAW:
		case PPC_ID_SPE_EVMHOSSIANW:
		case PPC_ID_SPE_EVMHOUMI:
		case PPC_ID_SPE_EVMHOUMIA:
		case PPC_ID_SPE_EVMHOUMIAAW:
		case PPC_ID_SPE_EVMHOUMIANW:
		case PPC_ID_SPE_EVMHOUSIAAW:
		case PPC_ID_SPE_EVMHOUSIANW:
		case PPC_ID_SPE_EVMWHSMF:
		case PPC_ID_SPE_EVMWHSMFA:
		case PPC_ID_SPE_EVMWHSMI:
		case PPC_ID_SPE_EVMWHSMIA:
		case PPC_ID_SPE_EVMWHSSF:
		case PPC_ID_SPE_EVMWHSSFA:
		case PPC_ID_SPE_EVMWLSMIAAW:
		case PPC_ID_SPE_EVMWLSMIANW:
		case PPC_ID_SPE_EVMWLSSIAAW:
		case PPC_ID_SPE_EVMWLSSIANW:
		case PPC_ID_SPE_EVMWHUMI:
		case PPC_ID_SPE_EVMWHUMIA:
		case PPC_ID_SPE_EVMWHUSIAAW:
		case PPC_ID_SPE_EVMWHUSIANW:
		case PPC_ID_SPE_EVMWLUMI:
		case PPC_ID_SPE_EVMWLUMIA:
		case PPC_ID_SPE_EVMWLUMIAAW:
		case PPC_ID_SPE_EVMWLUMIANW:
		case PPC_ID_SPE_EVMWLUSIAAW:
		case PPC_ID_SPE_EVMWLUSIANW:
		case PPC_ID_SPE_EVMWSMF:
		case PPC_ID_SPE_EVMWSMFA:
		case PPC_ID_SPE_EVMWSMFAA:
		case PPC_ID_SPE_EVMWSMFAN:
		case PPC_ID_SPE_EVMWSMI:
		case PPC_ID_SPE_EVMWSMIA:
		case PPC_ID_SPE_EVMWSMIAA:
		case PPC_ID_SPE_EVMWSMIAN:
		case PPC_ID_SPE_EVMWSSF:
		case PPC_ID_SPE_EVMWSSFA:
		case PPC_ID_SPE_EVMWSSFAA:
		case PPC_ID_SPE_EVMWSSFAN:
		case PPC_ID_SPE_EVMWUMI:
		case PPC_ID_SPE_EVMWUMIA:
		case PPC_ID_SPE_EVMWUMIAA:
		case PPC_ID_SPE_EVMWUMIAN:
		case PPC_ID_SPE_EVNAND:
		case PPC_ID_SPE_EVNOR:
		case PPC_ID_SPE_EVOR:
		case PPC_ID_SPE_EVORC:
		case PPC_ID_SPE_EVRLW:
		case PPC_ID_SPE_EVSLW:
		case PPC_ID_SPE_EVSRWS:
		case PPC_ID_SPE_EVSRWU:
		case PPC_ID_SPE_EVSUBFW:
		case PPC_ID_SPE_EVXOR:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushRB(instruction, word32);
			break;

		// rD, rA, ///
		case PPC_ID_SPE_EFDABS:
		case PPC_ID_SPE_EFDNABS:
		case PPC_ID_SPE_EFDNEG:
		case PPC_ID_SPE_EFSABS:
		case PPC_ID_SPE_EFSNABS:
		case PPC_ID_SPE_EFSNEG:
		case PPC_ID_SPE_EVABS:
		case PPC_ID_SPE_EVADDSMIAAW:
		case PPC_ID_SPE_EVADDSSIAAW:
		case PPC_ID_SPE_EVADDUMIAAW:
		case PPC_ID_SPE_EVADDUSIAAW:
		case PPC_ID_SPE_EVCNTLSW:
		case PPC_ID_SPE_EVCNTLZW:
		case PPC_ID_SPE_EVEXTSB:
		case PPC_ID_SPE_EVEXTSH:
		case PPC_ID_SPE_EVFSABS:
		case PPC_ID_SPE_EVFSNABS:
		case PPC_ID_SPE_EVFSNEG:
		case PPC_ID_SPE_EVMRA:
		case PPC_ID_SPE_EVNEG:
		case PPC_ID_SPE_EVSUBFSMIAAW:
		case PPC_ID_SPE_EVSUBFSSIAAW:
		case PPC_ID_SPE_EVSUBFUMIAAW:
		case PPC_ID_SPE_EVSUBFUSIAAW:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			break;

		// rD, ///, rB
		case PPC_ID_SPE_EFDCFS:
		case PPC_ID_SPE_EFDCFSF:
		case PPC_ID_SPE_EFDCFSI:
		case PPC_ID_SPE_EFDCFSID:
		case PPC_ID_SPE_EFDCFUF:
		case PPC_ID_SPE_EFDCFUI:
		case PPC_ID_SPE_EFDCFUID:
		case PPC_ID_SPE_EFDCTSF:
		case PPC_ID_SPE_EFDCTSI:
		case PPC_ID_SPE_EFDCTSIDZ:
		case PPC_ID_SPE_EFDCTSIZ:
		case PPC_ID_SPE_EFDCTUF:
		case PPC_ID_SPE_EFDCTUI:
		case PPC_ID_SPE_EFDCTUIDZ:
		case PPC_ID_SPE_EFDCTUIZ:
		case PPC_ID_SPE_EFSCFD:
		case PPC_ID_SPE_EFSCFSF:
		case PPC_ID_SPE_EFSCFSI:
		case PPC_ID_SPE_EFSCFUF:
		case PPC_ID_SPE_EFSCFUI:
		case PPC_ID_SPE_EFSCTSF:
		case PPC_ID_SPE_EFSCTSI:
		case PPC_ID_SPE_EFSCTSIZ:
		case PPC_ID_SPE_EFSCTUF:
		case PPC_ID_SPE_EFSCTUI:
		case PPC_ID_SPE_EFSCTUIZ:
		case PPC_ID_SPE_EVFSCFSF:
		case PPC_ID_SPE_EVFSCFSI:
		case PPC_ID_SPE_EVFSCFUF:
		case PPC_ID_SPE_EVFSCFUI:
		case PPC_ID_SPE_EVFSCTSF:
		case PPC_ID_SPE_EVFSCTSI:
		case PPC_ID_SPE_EVFSCTSIZ:
		case PPC_ID_SPE_EVFSCTUF:
		case PPC_ID_SPE_EVFSCTUI:
		case PPC_ID_SPE_EVFSCTUIZ:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			break;

		// crfD//, rA, rB
		case PPC_ID_SPE_EFDCMPEQ:
		case PPC_ID_SPE_EFDCMPGT:
		case PPC_ID_SPE_EFDCMPLT:
		case PPC_ID_SPE_EFDTSTEQ:
		case PPC_ID_SPE_EFDTSTGT:
		case PPC_ID_SPE_EFDTSTLT:
		case PPC_ID_SPE_EFSCMPEQ:
		case PPC_ID_SPE_EFSCMPGT:
		case PPC_ID_SPE_EFSCMPLT:
		case PPC_ID_SPE_EFSTSTEQ:
		case PPC_ID_SPE_EFSTSTGT:
		case PPC_ID_SPE_EFSTSTLT:
		case PPC_ID_SPE_EVCMPEQ:
		case PPC_ID_SPE_EVCMPGTS:
		case PPC_ID_SPE_EVCMPGTU:
		case PPC_ID_SPE_EVCMPLTS:
		case PPC_ID_SPE_EVCMPLTU:
		case PPC_ID_SPE_EVFSCMPEQ:
		case PPC_ID_SPE_EVFSCMPGT:
		case PPC_ID_SPE_EVFSCMPLT:
		case PPC_ID_SPE_EVFSTSTEQ:
		case PPC_ID_SPE_EVFSTSTGT:
		case PPC_ID_SPE_EVFSTSTLT:
			PushCRFDImplyCR0(instruction, word32);
			PushRA(instruction, word32);
			PushRB(instruction, word32);
			break;

		// rD, UIMM, rB
		case PPC_ID_SPE_EVADDIW:
		case PPC_ID_SPE_EVSUBIFW:
			PushRD(instruction, word32);
			PushUIMMValue(instruction, (word32 >> 16) & 0x1f);
			PushRB(instruction, word32);
			break;

		// rD, SIMM, ///
		case PPC_ID_SPE_EVSPLATFI:
		case PPC_ID_SPE_EVSPLATI:
		{
			int32_t simm = sign_extend((word32 >> 16) & 0x1f, 5);
			PushRD(instruction, word32);
			PushSIMMValue(instruction, simm);
			break;
		}

		// rD, rA, UIMM (SPE)
		case PPC_ID_SPE_EVRLWI:
		case PPC_ID_SPE_EVSLWI:
		case PPC_ID_SPE_EVSRWIS:
		case PPC_ID_SPE_EVSRWIU:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushUIMMValue(instruction, (word32 >> 11) & 0x1f);
			break;

		// rD, rA, UIMM (SPE loads)
		case PPC_ID_SPE_EVLDD:
		case PPC_ID_SPE_EVLDH:
		case PPC_ID_SPE_EVLDW:
		case PPC_ID_SPE_EVLHHESPLAT:
		case PPC_ID_SPE_EVLHHOSSPLAT:
		case PPC_ID_SPE_EVLHHOUSPLAT:
		case PPC_ID_SPE_EVLWHE:
		case PPC_ID_SPE_EVLWHOS:
		case PPC_ID_SPE_EVLWHOU:
		case PPC_ID_SPE_EVLWHSPLAT:
		case PPC_ID_SPE_EVLWWSPLAT:
			PushRD(instruction, word32);
			PushRAor0(instruction, word32);
			PushUIMMValue(instruction, (word32 >> 11) & 0x1f);
			break;

		// rS, rA, UIMM (SPE)
		case PPC_ID_SPE_EVSTDD:
		case PPC_ID_SPE_EVSTDH:
		case PPC_ID_SPE_EVSTDW:
		case PPC_ID_SPE_EVSTWHE:
		case PPC_ID_SPE_EVSTWHO:
		case PPC_ID_SPE_EVSTWWE:
		case PPC_ID_SPE_EVSTWWO:
			PushRS(instruction, word32);
			PushRAor0(instruction, word32);
			PushUIMMValue(instruction, (word32 >> 11) & 0x1f);
			break;

		// rS, rA, rB (SPE store-indexed)
		case PPC_ID_SPE_EVSTDDX:
		case PPC_ID_SPE_EVSTDHX:
		case PPC_ID_SPE_EVSTDWX:
		case PPC_ID_SPE_EVSTWHEX:
		case PPC_ID_SPE_EVSTWHOX:
		case PPC_ID_SPE_EVSTWWEX:
		case PPC_ID_SPE_EVSTWWOX:
			PushRS(instruction, word32);
			PushRA(instruction, word32);
			PushUIMMValue(instruction, (word32 >> 11) & 0x1f);
			break;

		// rD, rA
		case PPC_ID_SPE_EVMR:
		case PPC_ID_SPE_EVNOT:
		case PPC_ID_SPE_EVRNDW:
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			break;

		// rD, rA, rB, crfS
		case PPC_ID_SPE_EVSEL:
		{
			PushRD(instruction, word32);
			PushRA(instruction, word32);
			PushRB(instruction, word32);
			uint32_t crfs = word32 & 0x7;
			PushRegister(instruction, PPC_OP_REG_CRFS, Crf(crfs));
			break;
		}

		default:
			break;
	}
}

void FillBcxOperands(OperandsList* bcx, const Instruction* instruction)
{
	memset(bcx, 0, sizeof *bcx);

	if (instruction->id != PPC_ID_BCx)
		return;

	uint32_t bo = instruction->operands[0].uimm;
	uint32_t bi = instruction->operands[1].uimm;

	switch (bo & 0x1e)
	{
		// copy BI, target
		case 0:
		case 2:
		case 8:
		case 10:
			CopyOperand(&bcx->operands[0], &instruction->operands[1]);
			CopyOperand(&bcx->operands[1], &instruction->operands[2]);
			bcx->numOperands = 2;
			break;

		// copy BI, target
		case 4:
		case 6:
		case 12:
		case 14:
		{
			uint32_t crn = bi >> 2;

			bcx->operands[0].cls = PPC_OP_REG_CRFS_IMPLY0;
			bcx->operands[0].reg = Crf(crn);
			CopyOperand(&bcx->operands[1], &instruction->operands[2]);
			bcx->numOperands = 2;
			break;
		}

		// just copy target
		case 16:
		case 18:
		case 20:
		case 22:
		case 24:
		case 26:
		case 28:
		case 30:
			CopyOperand(&bcx->operands[0], &instruction->operands[2]);
			bcx->numOperands = 1;
			break;

		// copy BO, BI, target
		default:
			CopyOperand(&bcx->operands[0], &instruction->operands[0]);
			CopyOperand(&bcx->operands[1], &instruction->operands[1]);
			CopyOperand(&bcx->operands[2], &instruction->operands[2]);
			bcx->numOperands = 3;

			break;
	}
}

void FillBcctrxOperands(OperandsList* bcctrx, const Instruction* instruction)
{
	memset(bcctrx, 0, sizeof *bcctrx);

	if (instruction->id != PPC_ID_BCCTRx)
		return;

	uint32_t bo = instruction->operands[0].uimm;
	uint32_t bi = instruction->operands[1].uimm;

	switch (bo & 0x1e)
	{
		// copy BI --> crn
		case 4:
		case 6:
		case 12:
		case 14:
		{
			uint32_t crn = bi >> 2;

			bcctrx->operands[0].cls = PPC_OP_REG_CRFS_IMPLY0;
			bcctrx->operands[0].reg = Crf(crn);
			bcctrx->numOperands = 1;
			break;
		}

		// no ops (BCTR, BCTRL)
		case 20:
			break;

		// copy BO, BI
		default:
			CopyOperand(&bcctrx->operands[0], &instruction->operands[0]);
			CopyOperand(&bcctrx->operands[1], &instruction->operands[1]);
			bcctrx->numOperands = 2;

			break;
	}

}

void FillBclrxOperands(OperandsList* bclrx, const Instruction* instruction)
{
	memset(bclrx, 0, sizeof *bclrx);

	if (instruction->id != PPC_ID_BCLRx)
		return;

	uint32_t bo = instruction->operands[0].uimm;
	uint32_t bi = instruction->operands[1].uimm;

	switch (bo & 0x1e)
	{
		// copy BI
		case 0:
		case 2:
		case 8:
		case 10:
			CopyOperand(&bclrx->operands[0], &instruction->operands[1]);
			bclrx->operands[0].cls = PPC_OP_CRBIT;
			bclrx->operands[0].crbit = (uint32_t)instruction->operands[1].uimm;
			bclrx->numOperands = 1;
			break;

		// copy BI --> crn
		case 4:
		case 6:
		case 12:
		case 14:
		{
			uint32_t crn = bi >> 2;

			bclrx->operands[0].cls = PPC_OP_REG_CRFS_IMPLY0;
			bclrx->operands[0].reg = Crf(crn);
			bclrx->numOperands = 1;
			break;
		}

		// no ops (decrement CTR, compare to 0, but no condition check)
		case 16:
		case 18:
		case 24:
		case 26:

		// no ops (BLR, BLRL)
		case 20:
			break;

		// copy BO, BI
		default:
			CopyOperand(&bclrx->operands[0], &instruction->operands[0]);
			CopyOperand(&bclrx->operands[1], &instruction->operands[1]);
			bclrx->numOperands = 2;

			break;
	}
}
