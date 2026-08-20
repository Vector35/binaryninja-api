#include <string.h>

#include "priv.h"

uint32_t GetA(uint32_t word32)
{
	return (word32 >> 16) & 0x1f;
}

uint32_t GetB(uint32_t word32)
{
	return (word32 >> 11) & 0x1f;
}

uint32_t GetC(uint32_t word32)
{
	return (word32 >> 6) & 0x1f;
}

uint32_t GetD(uint32_t word32)
{
	return (word32 >> 21) & 0x1f;
}

uint32_t GetS(uint32_t word32)
{
	return (word32 >> 21) & 0x1f;
}

uint32_t GetBI(uint32_t word32)
{
	return (word32 >> 16) & 0x1f;
}

uint32_t GetBO(uint32_t word32)
{
	return (word32 >> 21) & 0x1f;
}

uint32_t GetVsxA(uint32_t word32)
{
	uint32_t ax = (word32 >> 2) & 0x1;
	uint32_t a = (word32 >> 16) & 0x1f;

	return (ax << 5) | a;
}

uint32_t GetVsxB(uint32_t word32)
{
	uint32_t bx = (word32 >> 1) & 0x1;
	uint32_t b = (word32 >> 11) & 0x1f;
	
	return (bx << 5) | b;
}

uint32_t GetVsxC(uint32_t word32)
{
	uint32_t cx = (word32 >> 3) & 0x1;
	uint32_t c = (word32 >> 6) & 0x1f;

	return (cx << 5) | c;
}

uint32_t GetVsxD(uint32_t word32)
{
	uint32_t dx = word32 & 0x1;
	uint32_t d = (word32 >> 21) & 0x1f;

	return (dx << 5) | d;
}

uint32_t GetSpecialRegisterCommon(uint32_t word32)
{
	uint32_t xr5_9 = (word32 >> 16) & 0x1f;
	uint32_t xr0_4 = (word32 >> 11) & 0x1f;
	uint32_t xr = (xr0_4 << 5) | xr5_9;

	return xr;
}

uint32_t GetME(uint32_t word32)
{
	return (word32 >> 1) & 0x1f;
}

uint32_t GetMB(uint32_t word32)
{
	return (word32 >> 6) & 0x1f;
}

uint32_t GetSH(uint32_t word32)
{
	return (word32 >> 11) & 0x1f;
}

uint32_t GetSH64(uint32_t word32)
{
	uint32_t sh5 = (word32 >> 1) & 0x1;
	uint32_t sh4_0 = (word32 >> 11) & 0x1f;

	return (sh5 << 5) | sh4_0;
}

uint32_t GetMX64(uint32_t word32)
{
	uint32_t mx = (word32 >> 5) & 0x3f;

	// x <- mx5 || mx[0:5] in powerpc's bit order
	return ((mx & 0x1) << 5) | (mx >> 1);
}

void CopyOperand(Operand* dst, const Operand* src)
{
	memcpy(dst, src, sizeof *dst);
}

InstructionId VleTranslateMnemonic(InstructionId id)
{
	switch (id)
	{
		case PPC_ID_VLE_E_ADDIx: return PPC_ID_ADDIx;
		case PPC_ID_VLE_E_ADDICx: return PPC_ID_ADDICx;
		case PPC_ID_VLE_E_ADD2I: return PPC_ID_ADDIx;
		case PPC_ID_VLE_E_ADD2IS: return PPC_ID_ADDIS;
		case PPC_ID_VLE_E_ADD16I: return PPC_ID_ADDIx;
		case PPC_ID_VLE_E_ANDIx: return PPC_ID_ANDIx;
		case PPC_ID_VLE_E_AND2I: return PPC_ID_ANDIx;
		case PPC_ID_VLE_E_AND2IS: return PPC_ID_ANDIS;
		case PPC_ID_VLE_E_Bx: return PPC_ID_Bx;
		case PPC_ID_VLE_E_CMP16I: return PPC_ID_CMPWI;
		case PPC_ID_VLE_E_CMPI: return PPC_ID_CMPWI;
		case PPC_ID_VLE_E_CMPL16I: return PPC_ID_CMPLWI;
		case PPC_ID_VLE_E_CMPLI: return PPC_ID_CMPLWI;
		case PPC_ID_VLE_E_CRAND: return PPC_ID_CRAND;
		case PPC_ID_VLE_E_CRANDC: return PPC_ID_CRANDC;
		case PPC_ID_VLE_E_CREQV: return PPC_ID_CREQV;
		case PPC_ID_VLE_E_CRNAND: return PPC_ID_CRNAND;
		case PPC_ID_VLE_E_CRNOR: return PPC_ID_CRNOR;
		case PPC_ID_VLE_E_CROR: return PPC_ID_CROR;
		case PPC_ID_VLE_E_CRORC: return PPC_ID_CRORC;
		case PPC_ID_VLE_E_CRXOR: return PPC_ID_CRXOR;
		case PPC_ID_VLE_E_LBZ: return PPC_ID_LBZ;
		case PPC_ID_VLE_E_LBZU: return PPC_ID_LBZU;
		case PPC_ID_VLE_E_LHA: return PPC_ID_LHA;
		case PPC_ID_VLE_E_LHAU: return PPC_ID_LHAU;
		case PPC_ID_VLE_E_LHZ: return PPC_ID_LHZ;
		case PPC_ID_VLE_E_LHZU: return PPC_ID_LHZU;
		case PPC_ID_VLE_E_LI: return PPC_ID_LI;
		case PPC_ID_VLE_E_LIS: return PPC_ID_LIS;
		case PPC_ID_VLE_E_LMW: return PPC_ID_LMW;
		case PPC_ID_VLE_E_LWZ: return PPC_ID_LWZ;
		case PPC_ID_VLE_E_LWZU: return PPC_ID_LWZU;
		case PPC_ID_VLE_E_MCRF: return PPC_ID_MCRF;
		case PPC_ID_VLE_E_MULL2I: return PPC_ID_MULLI;
		case PPC_ID_VLE_E_MULLI: return PPC_ID_MULLI;
		case PPC_ID_VLE_E_OR2I: return PPC_ID_ORIx;
		case PPC_ID_VLE_E_OR2IS: return PPC_ID_ORIS;
		case PPC_ID_VLE_E_ORIx: return PPC_ID_ORIx;
		case PPC_ID_VLE_E_RLWIMI: return PPC_ID_RLWIMIx;
		case PPC_ID_VLE_E_RLWINM: return PPC_ID_RLWINMx;
		case PPC_ID_VLE_E_SLWIx: return PPC_ID_SLWIx;
		case PPC_ID_VLE_E_SRWIx: return PPC_ID_SRWIx;
		case PPC_ID_VLE_E_STB: return PPC_ID_STB;
		case PPC_ID_VLE_E_STBU: return PPC_ID_STBU;
		case PPC_ID_VLE_E_STH: return PPC_ID_STH;
		case PPC_ID_VLE_E_STHU: return PPC_ID_STHU;
		case PPC_ID_VLE_E_STMW: return PPC_ID_STMW;
		case PPC_ID_VLE_E_STW: return PPC_ID_STW;
		case PPC_ID_VLE_E_STWU: return PPC_ID_STWU;
		case PPC_ID_VLE_E_SUBFICx: return PPC_ID_SUBFICx;
		case PPC_ID_VLE_E_XORIx: return PPC_ID_XORIx;

		// 16-bit VLE instructions
		case PPC_ID_VLE_SE_ADD: return PPC_ID_ADDx;
		case PPC_ID_VLE_SE_ADDI: return PPC_ID_ADDIx;
		case PPC_ID_VLE_SE_ANDx: return PPC_ID_ANDx;
		case PPC_ID_VLE_SE_ANDC: return PPC_ID_ANDCx;
		case PPC_ID_VLE_SE_ANDI: return PPC_ID_ANDIx;
		case PPC_ID_VLE_SE_Bx: return PPC_ID_Bx;
		case PPC_ID_VLE_SE_BCLRI: return PPC_ID_ANDIx;
		case PPC_ID_VLE_SE_BGENI: return PPC_ID_LI;
		case PPC_ID_VLE_SE_BMASKI: return PPC_ID_LI;
		case PPC_ID_VLE_SE_BSETI: return PPC_ID_ORIx;
		case PPC_ID_VLE_SE_CMP: return PPC_ID_CMPW;
		case PPC_ID_VLE_SE_CMPI: return PPC_ID_CMPWI;
		case PPC_ID_VLE_SE_CMPL: return PPC_ID_CMPLW;
		case PPC_ID_VLE_SE_CMPLI: return PPC_ID_CMPLWI;
		case PPC_ID_VLE_SE_EXTSB: return PPC_ID_EXTSBx;
		case PPC_ID_VLE_SE_EXTSH: return PPC_ID_EXTSHx;
		case PPC_ID_VLE_SE_EXTZB: return PPC_ID_ANDIx;
		case PPC_ID_VLE_SE_EXTZH: return PPC_ID_ANDIx;
		case PPC_ID_VLE_SE_ISYNC: return PPC_ID_ISYNC;
		case PPC_ID_VLE_SE_LI: return PPC_ID_LI;
		case PPC_ID_VLE_SE_MFAR: return PPC_ID_MRx;
		case PPC_ID_VLE_SE_MFCTR: return PPC_ID_MFCTR;
		case PPC_ID_VLE_SE_MFLR: return PPC_ID_MFLR;
		case PPC_ID_VLE_SE_MR: return PPC_ID_MRx;
		case PPC_ID_VLE_SE_MTAR: return PPC_ID_MRx;
		case PPC_ID_VLE_SE_MTCTR: return PPC_ID_MTCTR;
		case PPC_ID_VLE_SE_MTLR: return PPC_ID_MTLR;
		case PPC_ID_VLE_SE_MULLW: return PPC_ID_MULLWx;
		case PPC_ID_VLE_SE_NEG: return PPC_ID_NEGx;
		case PPC_ID_VLE_SE_NOP: return PPC_ID_NOP;
		case PPC_ID_VLE_SE_NOT: return PPC_ID_NORx;
		case PPC_ID_VLE_SE_OR: return PPC_ID_ORx;
		case PPC_ID_VLE_SE_RFCI: return PPC_ID_RFCI;
		case PPC_ID_VLE_SE_RFDI: return PPC_ID_RFDI;
		case PPC_ID_VLE_SE_RFI: return PPC_ID_RFI;
		case PPC_ID_VLE_SE_RFMCI: return PPC_ID_RFMCI;
		case PPC_ID_VLE_SE_SC: return PPC_ID_SC;
		case PPC_ID_VLE_SE_SLW: return PPC_ID_SLWx;
		case PPC_ID_VLE_SE_SLWI: return PPC_ID_SLWIx;
		case PPC_ID_VLE_SE_SRAW: return PPC_ID_SRAWx;
		case PPC_ID_VLE_SE_SRAWI: return PPC_ID_SRAWIx;
		case PPC_ID_VLE_SE_SRW: return PPC_ID_SRWx;
		case PPC_ID_VLE_SE_SRWI: return PPC_ID_SRWIx;
		case PPC_ID_VLE_SE_SUB: return PPC_ID_SUBFx;
		case PPC_ID_VLE_SE_SUBF: return PPC_ID_SUBFx;
		case PPC_ID_VLE_SE_SUBIx: return PPC_ID_ADDIx;

		// We purposefully keep some branch instructions as VLE
		// instructions, for translating their operand lists as
		// a special case
		case PPC_ID_VLE_E_BCx:
		case PPC_ID_VLE_SE_BC:
		case PPC_ID_VLE_SE_BCTRx:
		case PPC_ID_VLE_SE_BLRx:
			return id;

		// These instructions don't have a non-VLE equivalent
		case PPC_ID_VLE_E_CMPH16I:
		case PPC_ID_VLE_E_CMPHL:
		case PPC_ID_VLE_E_CMPHL16I:
		case PPC_ID_VLE_E_RLWx:
		case PPC_ID_VLE_E_RLWIx:
		case PPC_ID_VLE_SE_BTSTI:
		case PPC_ID_VLE_SE_CMPH:
		case PPC_ID_VLE_SE_CMPHL:
		case PPC_ID_VLE_SE_ILLEGAL:
		case PPC_ID_VLE_SE_LBZ: // VLE treats rA=0 as valid base
		case PPC_ID_VLE_SE_LHZ: // VLE treats rA=0 as valid base
		case PPC_ID_VLE_SE_LWZ: // VLE treats rA=0 as valid base
		case PPC_ID_VLE_SE_STB: // VLE treats rA=0 as valid base
		case PPC_ID_VLE_SE_STH: // VLE treats rA=0 as valid base
		case PPC_ID_VLE_SE_STW: // VLE treats rA=0 as valid base
			return id;

		default:
			return id;
	}
}
