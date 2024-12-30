#include <stdio.h>
#include <string.h>

#include "decode.h"

// Documentation:
//  * [ProgrammingEnvironments32]: "Programming Environments Manual for 32-bit
//    Implementations of the PowerPC^TM Architecture" by Freescale/NXP
//

// see stanford bit twiddling hacks
static int32_t sign_extend(uint32_t x, unsigned numBits)
{
	int32_t r;
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

static uint32_t GetA(uint32_t word32)
{
	return (word32 >> 16) & 0x1f;
}

static uint32_t GetB(uint32_t word32)
{
	return (word32 >> 11) & 0x1f;
}

static uint32_t GetC(uint32_t word32)
{
	return (word32 >> 6) & 0x1f;
}

static uint32_t GetD(uint32_t word32)
{
	return (word32 >> 21) & 0x1f;
}

static uint32_t GetS(uint32_t word32)
{
	return (word32 >> 21) & 0x1f;
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

static void PushCRFSImply0(Instruction* instruction, uint32_t word32)
{
	uint32_t crfs = (word32 >> 18) & 0x7;
	PushRegister(instruction, PPC_OP_REG_CRFS_IMPLY0, Crf(crfs));
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

static uint32_t GetBI(uint32_t word32)
{
	return (word32 >> 16) & 0x1f;
}

static uint32_t GetBO(uint32_t word32)
{
	return (word32 >> 21) & 0x1f;
}

static void FillBranchLikelyHint(Instruction* instruction, uint32_t word32)
{
	uint32_t bo = GetBO(word32);
	uint32_t bi = GetBI(word32);

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

static uint32_t GetVsxA(uint32_t word32)
{
	uint32_t ax = (word32 >> 2) & 0x1;
	uint32_t a = (word32 >> 16) & 0x1f;

	return (ax << 5) | a;
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

static uint32_t GetVsxB(uint32_t word32)
{
	uint32_t bx = (word32 >> 1) & 0x1;
	uint32_t b = (word32 >> 11) & 0x1f;
	
	return (bx << 5) | b;
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

static uint32_t GetVsxC(uint32_t word32)
{
	uint32_t cx = (word32 >> 3) & 0x1;
	uint32_t c = (word32 >> 6) & 0x1f;

	return (cx << 5) | c;
}

static void PushVsxC(Instruction* instruction, uint32_t word32, VsxWidth width)
{
	PushRegister(instruction,
		width == VSX_WIDTH_FULL ? PPC_OP_REG_VSX_RC : PPC_OP_REG_VSX_RC_DWORD0,
		VsxVr(GetVsxC(word32)));
}

static uint32_t GetVsxD(uint32_t word32)
{
	uint32_t dx = word32 & 0x1;
	uint32_t d = (word32 >> 21) & 0x1f;

	return (dx << 5) | d;
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

static uint32_t GetSpecialRegisterCommon(uint32_t word32)
{
	uint32_t xr5_9 = (word32 >> 16) & 0x1f;
	uint32_t xr0_4 = (word32 >> 11) & 0x1f;
	uint32_t xr = (xr0_4 << 5) | xr5_9;

	return xr;
}

static uint32_t GetME(uint32_t word32)
{
	return (word32 >> 1) & 0x1f;
}

static uint32_t GetMB(uint32_t word32)
{
	return (word32 >> 6) & 0x1f;
}

static uint32_t GetSH(uint32_t word32)
{
	return (word32 >> 11) & 0x1f;
}

static uint32_t GetSH64(uint32_t word32)
{
	uint32_t sh5 = (word32 >> 1) & 0x1;
	uint32_t sh4_0 = (word32 >> 11) & 0x1f;

	return (sh5 << 5) | sh4_0;
}

static uint32_t GetMX64(uint32_t word32)
{
	uint32_t mx = (word32 >> 5) & 0x3f;

	// x <- mx5 || mx[0:5] in powerpc's stupid bit order
	return ((mx & 0x1) << 5) | (mx >> 1);
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

static InstructionId DecodeAltivec0x04(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t subop = word32 & 0x3f;

	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);
	uint32_t d = GetD(word32);

	switch (subop)
	{
		case 0x20:
			return PPC_ID_AV_VMHADDSHS;

		case 0x21:
			return PPC_ID_AV_VMHRADDSHS;

		case 0x22:
			return PPC_ID_AV_VMLADDUHM;

		case 0x24:
			return PPC_ID_AV_VMSUMUBM;

		case 0x25:
			return PPC_ID_AV_VMSUMMBM;

		case 0x26:
			return PPC_ID_AV_VMSUMUHM;

		case 0x27:
			return PPC_ID_AV_VMSUMUHS;

		case 0x28:
			return PPC_ID_AV_VMSUMSHM;

		case 0x29:
			return PPC_ID_AV_VMSUMSHS;

		case 0x2a:
			return PPC_ID_AV_VSEL;

		case 0x2b:
			return PPC_ID_AV_VPERM;

		case 0x2c:
			if ((word32 & 0x400) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VSLDOI;

		case 0x2d:
			return PPC_ID_AV_VPERMXOR;

		case 0x2e:
			return PPC_ID_AV_VMADDFP;

		case 0x2f:
			return PPC_ID_AV_VNMSUBFP;

		case 0x30:
			return PPC_ID_AV_MADDHD;

		case 0x31:
			return PPC_ID_AV_MADDHDU;

		case 0x33:
			return PPC_ID_AV_MADDLD;

		case 0x3b:
			return PPC_ID_AV_VPERMR;

		case 0x3c:
			return PPC_ID_AV_VADDEUQM;

		case 0x3d:
			return PPC_ID_AV_VADDECUQ;

		case 0x3e:
			return PPC_ID_AV_VSUBEUQM;

		case 0x3f:
			return PPC_ID_AV_VSUBECUQ;

		default:
			;
	}

	subop = word32 & 0x7ff;
	switch (subop)
	{
		case 0x000:
			return PPC_ID_AV_VADDUBM;

		case 0x001:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VMUL10CUQ;

		case 0x002:
			return PPC_ID_AV_VMAXUB;

		case 0x004:
			return PPC_ID_AV_VRLB;


		case 0x006:
		case 0x406:
			return PPC_ID_AV_VCMPEQUBx;

		case 0x007:
		case 0x407:
			return PPC_ID_AV_VCMPNEBx;

		case 0x008:
			return PPC_ID_AV_VMULOUB;

		case 0x00a:
			return PPC_ID_AV_VADDFP;

		case 0x00c:
			return PPC_ID_AV_VMRGHB;

		case 0x00e:
			return PPC_ID_AV_VPKUHUM;

		case 0x040:
			return PPC_ID_AV_VADDUHM;

		case 0x041:
			return PPC_ID_AV_VMUL10ECUQ;

		case 0x042:
			return PPC_ID_AV_VMAXUH;

		case 0x044:
			return PPC_ID_AV_VRLH;


		case 0x046:
		case 0x446:
			return PPC_ID_AV_VCMPEQUHx;

		case 0x047:
		case 0x447:
			return PPC_ID_AV_VCMPNEHx;

		case 0x048:
			return PPC_ID_AV_VMULOUH;

		case 0x04a:
			return PPC_ID_AV_VSUBFP;

		case 0x04c:
			return PPC_ID_AV_VMRGHH;

		case 0x04e:
			return PPC_ID_AV_VPKUWUM;

		case 0x080:
			return PPC_ID_AV_VADDUWM;

		case 0x082:
			return PPC_ID_AV_VMAXUW;

		case 0x084:
			return PPC_ID_AV_VRLW;

		case 0x085:
			return PPC_ID_AV_VRLWMI;

		case 0x086:
		case 0x486:
			return PPC_ID_AV_VCMPEQUWx;

		case 0x087:
		case 0x487:
			return PPC_ID_AV_VCMPNEWx;

		case 0x88:
			return PPC_ID_AV_VMULOUW;

		case 0x89:
			return PPC_ID_AV_VMULUWM;

		case 0x08c:
			return PPC_ID_AV_VMRGHW;

		case 0x08e:
			return PPC_ID_AV_VPKUHUS;

		case 0x0c0:
			return PPC_ID_AV_VADDUDM;

		case 0x0c2:
			return PPC_ID_AV_VMAXUD;

		case 0x0c4:
			return PPC_ID_AV_VRLD;

		case 0x0c5:
			return PPC_ID_AV_VRLDMI;

		case 0x0c6:
		case 0x4c6:
			return PPC_ID_AV_VCMPEQFPx;

		case 0x0c7:
		case 0x4c7:
			return PPC_ID_AV_VCMPEQUDx;

		case 0x0ce:
			return PPC_ID_AV_VPKUWUS;

		case 0x100:
			return PPC_ID_AV_VADDUQM;

		case 0x102:
			return PPC_ID_AV_VMAXSB;

		case 0x104:
			return PPC_ID_AV_VSLB;

		case 0x107:
		case 0x507:
			return PPC_ID_AV_VCMPNEZBx;

		case 0x108:
			return PPC_ID_AV_VMULOSB;

		case 0x10a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VREFP;

		case 0x10c:
			return PPC_ID_AV_VMRGLB;

		case 0x10e:
			return PPC_ID_AV_VPKSHUS;

		case 0x140:
			return PPC_ID_AV_VADDCUQ;

		case 0x142:
			return PPC_ID_AV_VMAXSH;

		case 0x144:
			return PPC_ID_AV_VSLH;

		case 0x147:
		case 0x547:
			return PPC_ID_AV_VCMPNEZHx;

		case 0x148:
			return PPC_ID_AV_VMULOSH;

		case 0x14a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VRSQRTEFP;

		case 0x14c:
			return PPC_ID_AV_VMRGLH;

		case 0x14e:
			return PPC_ID_AV_VPKSWUS;

		case 0x180:
			return PPC_ID_AV_VADDCUW;

		case 0x182:
			return PPC_ID_AV_VMAXSW;

		case 0x184:
			return PPC_ID_AV_VSLW;

		case 0x185:
			return PPC_ID_AV_VRLWNM;

		case 0x187:
		case 0x587:
			return PPC_ID_AV_VCMPNEZWx;

		case 0x188:
			return PPC_ID_AV_VMULOSW;

		case 0x18a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VEXPTEFP;

		case 0x18c:
			return PPC_ID_AV_VMRGLW;

		case 0x18e:
			return PPC_ID_AV_VPKSHSS;

		case 0x1c2:
			return PPC_ID_AV_VMAXSD;

		case 0x1c4:
			return PPC_ID_AV_VSL;

		case 0x1c5:
			return PPC_ID_AV_VRLDNM;

		case 0x1c6:
		case 0x5c6:
			return PPC_ID_AV_VCMPGEFPx;

		case 0x1ca:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VLOGEFP;

		case 0x1ce:
			return PPC_ID_AV_VPKSWSS;

		case 0x200:
			return PPC_ID_AV_VADDUBS;

		case 0x201:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VMUL10UQ;

		case 0x202:
			return PPC_ID_AV_VMINUB;

		case 0x204:
			return PPC_ID_AV_VSRB;


		case 0x206:
		case 0x606:
			return PPC_ID_AV_VCMPGTUBx;

		case 0x208:
			return PPC_ID_AV_VMULEUB;

		case 0x20a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VRFIN;

		case 0x20c:
			return PPC_ID_AV_VSPLTB;

		case 0x20d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VEXTRACTUB;

		case 0x20e:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKHSB;

		case 0x240:
			return PPC_ID_AV_VADDUHS;

		case 0x241:
			return PPC_ID_AV_VMUL10EUQ;

		case 0x242:
			return PPC_ID_AV_VMINUH;

		case 0x244:
			return PPC_ID_AV_VSRH;

		case 0x246:
		case 0x646:
			return PPC_ID_AV_VCMPGTUHx;

		case 0x248:
			return PPC_ID_AV_VMULEUH;

		case 0x24a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VRFIZ;

		case 0x24c:
			return PPC_ID_AV_VSPLTH;

		case 0x24d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VEXTRACTUH;

		case 0x24e:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKHSH;

		case 0x280:
			return PPC_ID_AV_VADDUWS;

		case 0x282:
			return PPC_ID_AV_VMINUW;

		case 0x284:
			return PPC_ID_AV_VSRW;

		case 0x286:
		case 0x686:
			return PPC_ID_AV_VCMPGTUWx;

		case 0x288:
			return PPC_ID_AV_VMULEUW;

		case 0x28a:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VRFIP;

		case 0x28c:
			return PPC_ID_AV_VSPLTW;

		case 0x28d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VEXTRACTUW;

		case 0x28e:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKLSB;

		case 0x2c2:
			return PPC_ID_AV_VMINUD;

		case 0x2c4:
			return PPC_ID_AV_VSR;

		case 0x2c6:
		case 0x6c6:
			return PPC_ID_AV_VCMPGTFPx;

		case 0x2c7:
		case 0x6c7:
			return PPC_ID_AV_VCMPGTUDx;

		case 0x2ca:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VRFIM;

		case 0x2cd:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VEXTRACTD;

		case 0x2ce:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKLSH;

		case 0x300:
			return PPC_ID_AV_VADDSBS;

		case 0x302:
			return PPC_ID_AV_VMINSB;

		case 0x304:
			return PPC_ID_AV_VSRAB;

		case 0x306:
		case 0x706:
			return PPC_ID_AV_VCMPGTSBx;

		case 0x308:
			return PPC_ID_AV_VMULESB;

		case 0x30a:
			return PPC_ID_AV_VCFUX;

		case 0x30c:
			if ((b) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VSPLTISB;

		case 0x30d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VINSERTB;

		case 0x30e:
			return PPC_ID_AV_VPKPX;

		case 0x340:
			return PPC_ID_AV_VADDSHS;

		case 0x341:
			return PPC_ID_AV_BCDCPSGN;

		case 0x342:
			return PPC_ID_AV_VMINSH;

		case 0x344:
			return PPC_ID_AV_VSRAH;

		case 0x346:
		case 0x746:
			return PPC_ID_AV_VCMPGTSHx;

		case 0x348:
			return PPC_ID_AV_VMULESH;

		case 0x34a:
			return PPC_ID_AV_VCFSX;

		case 0x34c:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VSPLTISH;

		case 0x34d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VINSERTH;

		case 0x34e:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKHPX;

		case 0x380:
			return PPC_ID_AV_VADDSWS;

		case 0x382:
			return PPC_ID_AV_VMINSW;

		case 0x384:
			return PPC_ID_AV_VSRAW;

		case 0x386:
		case 0x786:
			return PPC_ID_AV_VCMPGTSWx;

		case 0x388:
			return PPC_ID_AV_VMULESW;

		case 0x38a:
			return PPC_ID_AV_VCTUXS;

		case 0x38c:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VSPLTISW;

		case 0x38d:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VINSERTW;

		case 0x3c2:
			return PPC_ID_AV_VMINSD;

		case 0x3c4:
			return PPC_ID_AV_VSRAD;

		case 0x3c6:
		case 0x7c6:
			return PPC_ID_AV_VCMPBFPx;

		case 0x3c7:
		case 0x7c7:
			return PPC_ID_AV_VCMPGTSDx;

		case 0x3ca:
			return PPC_ID_AV_VCTSXS;

		case 0x3cd:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VINSERTD;

		case 0x3ce:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKLPX;

		case 0x400:
			return PPC_ID_AV_VSUBUBM;

		case 0x401:
		case 0x601:
			return PPC_ID_AV_BCDADD;

		case 0x402:
			return PPC_ID_AV_VAVGUB;

		case 0x403:
			return PPC_ID_AV_VABSDUB;

		case 0x404:
			return PPC_ID_AV_VAND;

		case 0x408:
			return PPC_ID_AV_VPMSUMB;

		case 0x40a:
			return PPC_ID_AV_VMAXFP;

		case 0x40c:
			return PPC_ID_AV_VSLO;

		case 0x440:
			return PPC_ID_AV_VSUBUHM;

		case 0x441:
		case 0x641:
			return PPC_ID_AV_BCDSUB;

		case 0x442:
			return PPC_ID_AV_VAVGUH;

		case 0x443:
			return PPC_ID_AV_VABSDUH;

		case 0x444:
			return PPC_ID_AV_VANDC;

		case 0x448:
			return PPC_ID_AV_VPMSUMH;

		case 0x44a:
			return PPC_ID_AV_VMINFP;

		case 0x44c:
			return PPC_ID_AV_VSRO;

		case 0x44e:
			return PPC_ID_AV_VPKUDUM;

		case 0x480:
			return PPC_ID_AV_VSUBUWM;

		case 0x481:
			return PPC_ID_AV_BCDUS;

		case 0x482:
			return PPC_ID_AV_VAVGUW;

		case 0x483:
			return PPC_ID_AV_VABSDUW;

		case 0x484:
			if (a == b)
				return PPC_ID_AV_VMR;
			else
				return PPC_ID_AV_VOR;

		case 0x488:
			return PPC_ID_AV_VPMSUMW;

		case 0x4c0:
			return PPC_ID_AV_VSUBUDM;

		case 0x4c1:
		case 0x6c1:
			return PPC_ID_AV_BCDS;

		case 0x4c4:
			return PPC_ID_AV_VXOR;

		case 0x4c8:
			return PPC_ID_AV_VPMSUMD;

		case 0x4ce:
			return PPC_ID_AV_VPKUDUS;

		case 0x500:
			return PPC_ID_AV_VSUBUQM;

		case 0x501:
		case 0x701:
			return PPC_ID_AV_BCDTRUNC;

		case 0x502:
			return PPC_ID_AV_VAVGSB;

		case 0x504:
			if (a == b)
				return PPC_ID_AV_VNOT;
			else 
				return PPC_ID_AV_VNOR;

		case 0x508:
			return PPC_ID_AV_VCIPHER;

		case 0x509:
			return PPC_ID_AV_VCIPHERLAST;

		case 0x50c:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VGBBD;

		case 0x540:
			return PPC_ID_AV_VSUBCUQ;

		case 0x541:
			return PPC_ID_AV_BCDUTRUNC;

		case 0x542:
			return PPC_ID_AV_VAVGSH;

		case 0x544:
			return PPC_ID_AV_VORC;

		case 0x548:
			return PPC_ID_AV_VNCIPHER;

		case 0x549:
			return PPC_ID_AV_VNCIPHERLAST;

		case 0x54c:
			return PPC_ID_AV_VBPERMQ;

		case 0x54e:
			return PPC_ID_AV_VPKSDUS;

		case 0x580:
			return PPC_ID_AV_VSUBCUW;

		case 0x581:
		case 0x781:
			switch (a)
			{
			case 0x00:
				if (subop == 0x581)
					return PPC_ID_AV_BCDCTSQ;
				else
					return PPC_ID_INVALID;

			case 0x02:
				return PPC_ID_AV_BCDCFSQ;

			case 0x04:
				return PPC_ID_AV_BCDCTZ;

			case 0x05:
				if (subop == 0x581)
					return PPC_ID_AV_BCDCTN;
				else
					return PPC_ID_INVALID;

			case 0x06:
				return PPC_ID_AV_BCDCFZ;

			case 0x07:
				return PPC_ID_AV_BCDCFN;

			case 0x1f:
				return PPC_ID_AV_BCDSETSGN;

			default:
				return PPC_ID_INVALID;
			}

		case 0x582:
			return PPC_ID_AV_VAVGSW;

		case 0x584:
			return PPC_ID_AV_VNAND;

		case 0x5c1:
		case 0x7c1:
			return PPC_ID_AV_BCDSR;

		case 0x5c4:
			return PPC_ID_AV_VSLD;

		case 0x5c8:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VSBOX;

		case 0x5cc:
			return PPC_ID_AV_VBPERMD;

		case 0x5ce:
			return PPC_ID_AV_VPKSDSS;

		case 0x600:
			return PPC_ID_AV_VSUBUBS;

		case 0x602:
			switch (a)
			{
			case 0x00:
				return PPC_ID_AV_VCLZLSBB;

			case 0x01:
				return PPC_ID_AV_VCTZLSBB;

			case 0x06:
				return PPC_ID_AV_VNEGW;

			case 0x07:
				return PPC_ID_AV_VNEGD;

			case 0x08:
				return PPC_ID_AV_VPRTYBW;

			case 0x09:
				return PPC_ID_AV_VPRTYBD;

			case 0x0a:
				return PPC_ID_AV_VPRTYBQ;

			case 0x10:
				return PPC_ID_AV_VEXTSB2W;

			case 0x11:
				return PPC_ID_AV_VEXTSH2W;

			case 0x18:
				return PPC_ID_AV_VEXTSB2D;

			case 0x19:
				return PPC_ID_AV_VEXTSH2D;

			case 0x1a:
				return PPC_ID_AV_VEXTSW2D;

			case 0x1c:
				return PPC_ID_AV_VCTZB;

			case 0x1d:
				return PPC_ID_AV_VCTZH;

			case 0x1e:
				return PPC_ID_AV_VCTZW;

			case 0x1f:
				return PPC_ID_AV_VCTZD;

			default:
				return PPC_ID_INVALID;
			}

		case 0x604:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_AV_MFVSCR;

		case 0x60d:
			return PPC_ID_AV_VEXTUBLX;

		case 0x608:
			return PPC_ID_AV_VSUM4UBS;

		case 0x640:
			return PPC_ID_AV_VSUBUHS;

		case 0x644:
			if ((d != 0) || (a != 0))
				return PPC_ID_INVALID;

			return PPC_ID_AV_MTVSCR;

		case 0x648:
			return PPC_ID_AV_VSUM4SHS;

		case 0x64d:
			return PPC_ID_AV_VEXTUHLX;

		case 0x64e:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKHSW;

		case 0x680:
			return PPC_ID_AV_VSUBUWS;

		case 0x682:
			return PPC_ID_AV_VSHASIGMAW;

		case 0x684:
			return PPC_ID_AV_VEQV;

		case 0x688:
			return PPC_ID_AV_VSUM2SWS;

		case 0x68c:
			return PPC_ID_AV_VMRGOW;

		case 0x68d:
			return PPC_ID_AV_VEXTUWLX;

		case 0x6c2:
			return PPC_ID_AV_VSHASIGMAD;

		case 0x6c4:
			return PPC_ID_AV_VSRD;

		case 0x6ce:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VUPKLSW;

		case 0x700:
			return PPC_ID_AV_VSUBSBS;

		case 0x702:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VCLZB;

		case 0x703:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VPOPCNTB;

		case 0x704:
			return PPC_ID_AV_VSRV;

		case 0x708:
			return PPC_ID_AV_VSUM4SBS;

		case 0x70d:
			return PPC_ID_AV_VEXTUBRX;

		case 0x740:
			return PPC_ID_AV_VSUBSHS;

		case 0x742:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VCLZH;

		case 0x743:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VPOPCNTH;

		case 0x744:
			return PPC_ID_AV_VSLV;

		case 0x74d:
			return PPC_ID_AV_VEXTUHRX;

		case 0x780:
			return PPC_ID_AV_VSUBSWS;

		case 0x782:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VCLZW;

		case 0x783:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VPOPCNTW;

		case 0x788:
			return PPC_ID_AV_VSUMSWS;

		case 0x78c:
			return PPC_ID_AV_VMRGEW;

		case 0x78d:
			return PPC_ID_AV_VEXTUWRX;

		case 0x7c2:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VCLZD;

		case 0x7c3:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_AV_VPOPCNTD;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId DecodeSpe0x04(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);
	uint32_t d = GetD(word32);
	uint32_t subop = word32 & 0x7ff;

	switch (subop)
	{
		case 512:
			return PPC_ID_SPE_EVADDW;

		case 514:
			return PPC_ID_SPE_EVADDIW;

		case 516:
			return PPC_ID_SPE_EVSUBFW;

		case 518:
			return PPC_ID_SPE_EVSUBIFW;

		case 520:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVABS;

		case 521:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVNEG;

		case 522:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVEXTSB;

		case 523:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVEXTSH;

		case 524:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVRNDW;

		case 525:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCNTLZW;

		case 526:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCNTLSW;

		case 527:
			return PPC_ID_SPE_BRINC;

		case 529:
			return PPC_ID_SPE_EVAND;

		case 530:
			return PPC_ID_SPE_EVANDC;

		case 534:
			return PPC_ID_SPE_EVXOR;

		case 535:
			if (a == b)
				return PPC_ID_SPE_EVMR;
			else
				return PPC_ID_SPE_EVOR;

		case 536:
			if (a == b)
				return PPC_ID_SPE_EVNOT;
			else
				return PPC_ID_SPE_EVNOR;

		case 537:
			return PPC_ID_SPE_EVEQV;

		case 539:
			return PPC_ID_SPE_EVORC;

		case 542:
			return PPC_ID_SPE_EVNAND;

		case 544:
			return PPC_ID_SPE_EVSRWU;

		case 545:
			return PPC_ID_SPE_EVSRWS;

		case 546:
			return PPC_ID_SPE_EVSRWIU;

		case 547:
			return PPC_ID_SPE_EVSRWIS;

		case 548:
			return PPC_ID_SPE_EVSLW;

		case 550:
			return PPC_ID_SPE_EVSLWI;

		case 552:
			return PPC_ID_SPE_EVRLW;

		case 553:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSPLATI;

		case 554:
			return PPC_ID_SPE_EVRLWI;

		case 555:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSPLATFI;

		case 556:
			return PPC_ID_SPE_EVMERGEHI;

		case 557:
			return PPC_ID_SPE_EVMERGELO;

		case 558:
			return PPC_ID_SPE_EVMERGEHILO;

		case 559:
			return PPC_ID_SPE_EVMERGELOHI;

		case 560:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCMPGTU;

		case 561:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCMPGTS;

		case 562:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCMPLTU;

		case 563:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCMPLTS;

		case 564:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVCMPEQ;

		case 632:
			return PPC_ID_SPE_EVSEL;

		case 633:
			return PPC_ID_SPE_EVSEL;

		case 634:
			return PPC_ID_SPE_EVSEL;

		case 635:
			return PPC_ID_SPE_EVSEL;

		case 636:
			return PPC_ID_SPE_EVSEL;

		case 637:
			return PPC_ID_SPE_EVSEL;

		case 638:
			return PPC_ID_SPE_EVSEL;

		case 639:
			return PPC_ID_SPE_EVSEL;

		case 640:
			return PPC_ID_SPE_EVFSADD;

		case 641:
			return PPC_ID_SPE_EVFSSUB;

		case 644:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSABS;

		case 645:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSNABS;

		case 646:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSNEG;

		case 648:
			return PPC_ID_SPE_EVFSMUL;

		case 649:
			return PPC_ID_SPE_EVFSDIV;

		case 652:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCMPGT;

		case 653:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCMPLT;

		case 654:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCMPEQ;

		case 656:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCFUI;

		case 657:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCFSI;

		case 658:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCFUF;

		case 659:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCFSF;

		case 660:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTUI;

		case 661:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTSI;

		case 662:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTUF;

		case 663:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTSF;

		case 664:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTUIZ;

		case 666:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSCTSIZ;

		case 668:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSTSTGT;

		case 669:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSTSTLT;

		case 670:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVFSTSTEQ;

		case 704:
			return PPC_ID_SPE_EFSADD;

		case 705:
			return PPC_ID_SPE_EFSSUB;

		case 708:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSABS;

		case 709:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSNABS;

		case 710:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSNEG;

		case 712:
			return PPC_ID_SPE_EFSMUL;

		case 713:
			return PPC_ID_SPE_EFSDIV;

		case 716:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCMPGT;

		case 717:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCMPLT;

		case 718:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCMPEQ;

		case 719:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCFD;

		case 720:
			return PPC_ID_SPE_EFSCFUI;

		case 721:
			return PPC_ID_SPE_EFSCFSI;

		case 722:
			return PPC_ID_SPE_EFSCFUF;

		case 723:
			return PPC_ID_SPE_EFSCFSF;

		case 724:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCTUI;

		case 725:
			return PPC_ID_SPE_EFSCTSI;

		case 726:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCTUF;

		case 727:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCTSF;

		case 728:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCTUIZ;

		case 730:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSCTSIZ;

		case 732:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSTSTGT;

		case 733:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSTSTLT;

		case 734:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFSTSTEQ;

		case 736:
			return PPC_ID_SPE_EFDADD;

		case 737:
			return PPC_ID_SPE_EFDSUB;

		case 738:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFUID;

		case 739:
			return PPC_ID_SPE_EFDCFSID;

		case 740:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDABS;

		case 741:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDNABS;

		case 742:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDNEG;

		case 744:
			return PPC_ID_SPE_EFDMUL;

		case 745:
			return PPC_ID_SPE_EFDDIV;

		case 746:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTUIDZ;

		case 747:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTSIDZ;

		case 748:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCMPGT;

		case 749:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCMPLT;

		case 750:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCMPEQ;

		case 751:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFS;

		case 752:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFUI;

		case 753:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFSI;

		case 754:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFUF;

		case 755:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCFSF;

		case 756:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTUI;

		case 757:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTSI;

		case 758:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTUF;

		case 759:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTSF;

		case 760:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTUIZ;

		case 762:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDCTSIZ;

		case 764:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDTSTGT;

		case 765:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDTSTLT;

		case 766:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EFDTSTEQ;

		case 768:
			return PPC_ID_SPE_EVLDDX;

		case 769:
			return PPC_ID_SPE_EVLDD;

		case 770:
			return PPC_ID_SPE_EVLDWX;

		case 771:
			return PPC_ID_SPE_EVLDW;

		case 772:
			return PPC_ID_SPE_EVLDHX;

		case 773:
			return PPC_ID_SPE_EVLDH;

		case 776:
			return PPC_ID_SPE_EVLHHESPLATX;

		case 777:
			return PPC_ID_SPE_EVLHHESPLAT;

		case 780:
			return PPC_ID_SPE_EVLHHOUSPLATX;

		case 781:
			return PPC_ID_SPE_EVLHHOUSPLAT;

		case 782:
			return PPC_ID_SPE_EVLHHOSSPLATX;

		case 783:
			return PPC_ID_SPE_EVLHHOSSPLAT;

		case 784:
			return PPC_ID_SPE_EVLWHEX;

		case 785:
			return PPC_ID_SPE_EVLWHE;

		case 788:
			return PPC_ID_SPE_EVLWHOUX;

		case 789:
			return PPC_ID_SPE_EVLWHOU;

		case 790:
			return PPC_ID_SPE_EVLWHOSX;

		case 791:
			return PPC_ID_SPE_EVLWHOS;

		case 792:
			return PPC_ID_SPE_EVLWWSPLATX;

		case 793:
			return PPC_ID_SPE_EVLWWSPLAT;

		case 796:
			return PPC_ID_SPE_EVLWHSPLATX;

		case 797:
			return PPC_ID_SPE_EVLWHSPLAT;

		case 800:
			return PPC_ID_SPE_EVSTDDX;

		case 801:
			return PPC_ID_SPE_EVSTDD;

		case 802:
			return PPC_ID_SPE_EVSTDWX;

		case 803:
			return PPC_ID_SPE_EVSTDW;

		case 804:
			return PPC_ID_SPE_EVSTDHX;

		case 805:
			return PPC_ID_SPE_EVSTDH;

		case 816:
			return PPC_ID_SPE_EVSTWHEX;

		case 817:
			return PPC_ID_SPE_EVSTWHE;

		case 820:
			return PPC_ID_SPE_EVSTWHOX;

		case 821:
			return PPC_ID_SPE_EVSTWHO;

		case 824:
			return PPC_ID_SPE_EVSTWWEX;

		case 825:
			return PPC_ID_SPE_EVSTWWE;

		case 828:
			return PPC_ID_SPE_EVSTWWOX;

		case 829:
			return PPC_ID_SPE_EVSTWWO;

		case 1027:
			return PPC_ID_SPE_EVMHESSF;

		case 1031:
			return PPC_ID_SPE_EVMHOSSF;

		case 1032:
			return PPC_ID_SPE_EVMHEUMI;

		case 1033:
			return PPC_ID_SPE_EVMHESMI;

		case 1035:
			return PPC_ID_SPE_EVMHESMF;

		case 1036:
			return PPC_ID_SPE_EVMHOUMI;

		case 1037:
			return PPC_ID_SPE_EVMHOSMI;

		case 1039:
			return PPC_ID_SPE_EVMHOSMF;

		case 1059:
			return PPC_ID_SPE_EVMHESSFA;

		case 1063:
			return PPC_ID_SPE_EVMHOSSFA;

		case 1064:
			return PPC_ID_SPE_EVMHEUMIA;

		case 1065:
			return PPC_ID_SPE_EVMHESMIA;

		case 1067:
			return PPC_ID_SPE_EVMHESMFA;

		case 1068:
			return PPC_ID_SPE_EVMHOUMIA;

		case 1069:
			return PPC_ID_SPE_EVMHOSMIA;

		case 1071:
			return PPC_ID_SPE_EVMHOSMFA;

		case 1095:
			return PPC_ID_SPE_EVMWHSSF;

		case 1096:
			return PPC_ID_SPE_EVMWLUMI;

		case 1100:
			return PPC_ID_SPE_EVMWHUMI;

		case 1101:
			return PPC_ID_SPE_EVMWHSMI;

		case 1103:
			return PPC_ID_SPE_EVMWHSMF;

		case 1107:
			return PPC_ID_SPE_EVMWSSF;

		case 1112:
			return PPC_ID_SPE_EVMWUMI;

		case 1113:
			return PPC_ID_SPE_EVMWSMI;

		case 1115:
			return PPC_ID_SPE_EVMWSMF;

		case 1127:
			return PPC_ID_SPE_EVMWHSSFA;

		case 1128:
			return PPC_ID_SPE_EVMWLUMIA;

		case 1132:
			return PPC_ID_SPE_EVMWHUMIA;

		case 1133:
			return PPC_ID_SPE_EVMWHSMIA;

		case 1135:
			return PPC_ID_SPE_EVMWHSMFA;

		case 1139:
			return PPC_ID_SPE_EVMWSSFA;

		case 1144:
			return PPC_ID_SPE_EVMWUMIA;

		case 1145:
			return PPC_ID_SPE_EVMWSMIA;

		case 1147:
			return PPC_ID_SPE_EVMWSMFA;

		case 1216:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVADDUSIAAW;

		case 1217:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVADDSSIAAW;

		case 1218:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSUBFUSIAAW;

		case 1219:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSUBFSSIAAW;

		case 1220:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVMRA;

		case 1222:
			return PPC_ID_SPE_EVDIVWS;

		case 1223:
			return PPC_ID_SPE_EVDIVWU;

		case 1224:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVADDUMIAAW;

		case 1225:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVADDSMIAAW;

		case 1226:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSUBFUMIAAW;

		case 1227:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SPE_EVSUBFSMIAAW;

		case 1280:
			return PPC_ID_SPE_EVMHEUSIAAW;

		case 1281:
			return PPC_ID_SPE_EVMHESSIAAW;

		case 1283:
			return PPC_ID_SPE_EVMHESSFAAW;

		case 1284:
			return PPC_ID_SPE_EVMHOUSIAAW;

		case 1285:
			return PPC_ID_SPE_EVMHOSSIAAW;

		case 1287:
			return PPC_ID_SPE_EVMHOSSFAAW;

		case 1288:
			return PPC_ID_SPE_EVMHEUMIAAW;

		case 1289:
			return PPC_ID_SPE_EVMHESMIAAW;

		case 1291:
			return PPC_ID_SPE_EVMHESMFAAW;

		case 1292:
			return PPC_ID_SPE_EVMHOUMIAAW;

		case 1293:
			return PPC_ID_SPE_EVMHOSMIAAW;

		case 1295:
			return PPC_ID_SPE_EVMHOSMFAAW;

		case 1320:
			return PPC_ID_SPE_EVMHEGUMIAA;

		case 1321:
			return PPC_ID_SPE_EVMHEGSMIAA;

		case 1323:
			return PPC_ID_SPE_EVMHEGSMFAA;

		case 1324:
			return PPC_ID_SPE_EVMHOGUMIAA;

		case 1325:
			return PPC_ID_SPE_EVMHOGSMIAA;

		case 1327:
			return PPC_ID_SPE_EVMHOGSMFAA;

		case 1344:
			return PPC_ID_SPE_EVMWLUSIAAW;

		case 1345:
			return PPC_ID_SPE_EVMWLSSIAAW;

		case 1352:
			return PPC_ID_SPE_EVMWLUMIAAW;

		case 1353:
			return PPC_ID_SPE_EVMWLSMIAAW;

		case 1363:
			return PPC_ID_SPE_EVMWSSFAA;

		case 1368:
			return PPC_ID_SPE_EVMWUMIAA;

		case 1369:
			return PPC_ID_SPE_EVMWSMIAA;

		case 1371:
			return PPC_ID_SPE_EVMWSMFAA;

		case 1408:
			return PPC_ID_SPE_EVMHEUSIANW;

		case 1409:
			return PPC_ID_SPE_EVMHESSIANW;

		case 1411:
			return PPC_ID_SPE_EVMHESSFANW;

		case 1412:
			return PPC_ID_SPE_EVMHOUSIANW;

		case 1413:
			return PPC_ID_SPE_EVMHOSSIANW;

		case 1415:
			return PPC_ID_SPE_EVMHOSSFANW;

		case 1416:
			return PPC_ID_SPE_EVMHEUMIANW;

		case 1417:
			return PPC_ID_SPE_EVMHESMIANW;

		case 1419:
			return PPC_ID_SPE_EVMHESMFANW;

		case 1420:
			return PPC_ID_SPE_EVMHOUMIANW;

		case 1421:
			return PPC_ID_SPE_EVMHOSMIANW;

		case 1423:
			return PPC_ID_SPE_EVMHOSMFANW;

		case 1448:
			return PPC_ID_SPE_EVMHEGUMIAN;

		case 1449:
			return PPC_ID_SPE_EVMHEGSMIAN;

		case 1451:
			return PPC_ID_SPE_EVMHEGSMFAN;

		case 1452:
			return PPC_ID_SPE_EVMHOGUMIAN;

		case 1453:
			return PPC_ID_SPE_EVMHOGSMIAN;

		case 1455:
			return PPC_ID_SPE_EVMHOGSMFAN;

		case 1472:
			return PPC_ID_SPE_EVMWLUSIANW;

		case 1473:
			return PPC_ID_SPE_EVMWLSSIANW;

		case 1480:
			return PPC_ID_SPE_EVMWLUMIANW;

		case 1481:
			return PPC_ID_SPE_EVMWLSMIANW;

		case 1491:
			return PPC_ID_SPE_EVMWSSFAN;

		case 1496:
			return PPC_ID_SPE_EVMWUMIAN;

		case 1497:
			return PPC_ID_SPE_EVMWSMIAN;

		case 1499:
			return PPC_ID_SPE_EVMWSMFAN;

		default:
			   return PPC_ID_INVALID;
	}
}

static InstructionId Decode0x13(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);
	uint32_t d = GetD(word32);

	uint32_t subop = (word32 >> 1) & 0x1f;
	switch (subop)
	{
		case 0x2:
			if ((word32 & 0x001fffff) == 4)
				return PPC_ID_LNIA;

			return PPC_ID_ADDPCIS;

		default:
			;
	}

	subop = word32 & 0x7ff;
	switch (subop)
	{
		case 0x000:
			if ((word32 & 0x0063f800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MCRF;

		case 0x020:
		case 0x021:
			// for PowerPC, this is 0x0000f800, but POWER
			// introduces BH bits
			if ((word32 & 0x0000e000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_BCLRx;

		case 0x024:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_RFID;

		case 0x042:
			if (a == b)
				return PPC_ID_CRNOT;
			else
				return PPC_ID_CRNOR;

		case 0x04c:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_RFMCI;

		case 0x04e:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_RFDI;

		case 0x064:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_RFI;

		case 0x066:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_RFCI;

		case 0x102:
			return PPC_ID_CRANDC;

		case 0x12c:
			if ((word32 & 0x3fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ISYNC;

		case 0x182:
			if (d == a && d == b)
				return PPC_ID_CRCLR;
			else
				return PPC_ID_CRXOR;

		case 0x1c2:
			return PPC_ID_CRNAND;

		case 0x202:
			return PPC_ID_CRAND;

		case 0x242:
			if (d == a && d == b)
				return PPC_ID_CRSET;
			else
				return PPC_ID_CREQV;

		case 0x342:
			return PPC_ID_CRORC;

		case 0x382:
			if (a == b)
				return PPC_ID_CRMOVE;
			else
				return PPC_ID_CROR;

		case 0x420:
		case 0x421:
			// TODO: return invalid when BO[2] == 0 (ie when & 0x00800000 == 0)
			//       keeping it in makes it easier to compare against capstone
			//       for now

			// for PowerPC, this is 0x0000f800, but POWER
			// introduces BH bits
			if ((word32 & 0x0000e000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_BCCTRx;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId Decode0x1E(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t sh = GetSH64(word32);
	uint32_t mx = GetMX64(word32);

	uint32_t subop = (word32 >> 1) & 0xf;
	switch (subop)
	{
		case 0x0:
		case 0x1:
			if (mx == 0)
				return PPC_ID_ROTLDIx;
			else if (sh == 0)
				return PPC_ID_CLRLDIx;
			else
				return PPC_ID_RLDICLx;

		case 0x2:
		case 0x3:
			if (sh + mx == 63)
				return PPC_ID_SLDIx;
			else
				return PPC_ID_RLDICRx;

		case 0x4:
		case 0x5:
			return PPC_ID_RLDICx;

		case 0x6:
		case 0x7:
			return PPC_ID_RLDIMIx;

		case 0x8:
			if (mx == 0)
				return PPC_ID_ROTLDx;
			else
				return PPC_ID_RLDCLx;

		case 0x9:
			return PPC_ID_RLDCRx;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId Decode0x1F(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);
	uint32_t d = GetD(word32);
	uint32_t s = GetS(word32);

	uint32_t subop = word32 & 0x3f;
	switch (subop)
	{
		case 0x1e:
			return PPC_ID_ISEL;

		default:   break;
	}

	subop = word32 & 0x7ff;
	switch (subop)
	{
		case 0x000:
			if ((word32 & 0x00400000) == 0)
			{
				if ((word32 & 0x00200000) != 0)
				{
					if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
						return PPC_ID_INVALID;

					return PPC_ID_CMPD;
				}
				else
				{
					return PPC_ID_CMPW;
				}
			}

			return PPC_ID_INVALID;

		case 0x008:
		{
			uint32_t to = (word32 >> 21) & 0x1f;

			switch (to)
			{
				case 1: return PPC_ID_TWLGT;
				case 2: return PPC_ID_TWLLT;
				case 4: return PPC_ID_TWEQ;
				case 8: return PPC_ID_TWGT;
				case 16: return PPC_ID_TWLT;
				case 24: return PPC_ID_TWNE;
				case 31:
				{
					if ((GetA(word32) == 0) && (GetB(word32) == 0))
						return PPC_ID_TRAP;

					return PPC_ID_TWU;
				}
				default: return PPC_ID_TW;
			}
		}

		case 0x00c:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVSL;

			return PPC_ID_INVALID;

		case 0x00e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVEBX;

			return PPC_ID_INVALID;

		case 0x010:
		case 0x011:
		case 0x410:
		case 0x411:
			return PPC_ID_SUBFCx;

		case 0x012:
		case 0x013:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_MULHDUx;

		case 0x014:
		case 0x015:
		case 0x414:
		case 0x415:
			return PPC_ID_ADDCx;

		case 0x016:
		case 0x017:
			return PPC_ID_MULHWUx;

		case 0x018:
		case 0x019:
			return PPC_ID_VSX_LXSIWZX;

		case 0x026:
			if ((word32 & 0x00100000) != 0)
			{
				if ((word32 & 0x800) != 0)
					return PPC_ID_INVALID;

				uint32_t fxm = (word32 >> 12) & 0xff;
				if (fxm == 0)
					return PPC_ID_INVALID;

				return PPC_ID_MFOCRF;
			}

			if ((word32 & 0x000ff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MFCR;

		case 0x028:
		case 0x029:
			return PPC_ID_LWARX;

		case 0x02a:
			return PPC_ID_LDX;

		case 0x02c:
			if ((word32 & 0x02000000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ICBT;

		case 0x02e:
			return PPC_ID_LWZX;

		case 0x030:
		case 0x031:
			return PPC_ID_SLWx;

		case 0x034:
		case 0x035:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CNTLZWx;

		case 0x036:
		case 0x037:
			return PPC_ID_SLDx;

		case 0x038:
		case 0x039:
			return PPC_ID_ANDx;

		case 0x03e:
			return PPC_ID_LWEPX;

		case 0x040:
			if ((word32 & 0x00400000) == 0)
			{
				if ((word32 & 0x00200000) != 0)
				{
					if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
						return PPC_ID_INVALID;

					return PPC_ID_CMPLD;
				}
				else
				{
					return PPC_ID_CMPLW;
				}

				break;
			}

			return PPC_ID_INVALID;

		case 0x04c:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVSR;

			return PPC_ID_INVALID;

		case 0x04e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVEHX;

			return PPC_ID_INVALID;

		case 0x050:
		case 0x051:
		case 0x450:
		case 0x451:
			return PPC_ID_SUBFx;

		case 0x066:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MFFPRD;

		case 0x067:
			if (b != 0)
				return PPC_ID_INVALID;

			// either MFVSRD or MFVRD; we use MFVRD for backwards
			// compatibility with capstone
			return PPC_ID_VSX_MFVSRD;

		case 0x068:
		case 0x069:
			return PPC_ID_LBARX;

		case 0x06a:
			return PPC_ID_LDUX;

		case 0x06c:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBST;

		case 0x06e:
			return PPC_ID_LWZUX;

		case 0x074:
		case 0x075:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CNTLZDx;

		case 0x078:
		case 0x079:
			return PPC_ID_ANDCx;

		case 0x07e:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBSTEP;

		case 0x03c:
		{
			if ((word32 & 0x039ff800) != 0)
				return false;

			uint32_t wc = (word32 >> 21) & 0x3;
			switch (wc)
			{
				case 0: return PPC_ID_WAIT;
				case 1: return PPC_ID_WAITRSV;
				case 2: return PPC_ID_WAITIMPL;

				default: return PPC_ID_WAIT;
			}
		}

		case 0x088:
		{
			uint32_t to = (word32 >> 21) & 0x1f;

			switch (to)
			{
				case 1: return PPC_ID_TDLGT;
				case 2: return PPC_ID_TDLLT;
				case 4: return PPC_ID_TDEQ;
				case 8: return PPC_ID_TDGT;
				case 16: return PPC_ID_TDLT;
				case 24: return PPC_ID_TDNE;
				case 31: return PPC_ID_TDU;
				default: return PPC_ID_TD;
			}
		}

		case 0x08e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVEWX;

			return PPC_ID_INVALID;

		case 0x092:
		case 0x093:
			if ((decodeFlags & DECODE_FLAGS_PPC64) != 0)
				return PPC_ID_MULHDx;

			return PPC_ID_INVALID;


		case 0x096:
		case 0x097:
			return PPC_ID_MULHWx;

		case 0x098:
		case 0x099:
			return PPC_ID_VSX_LXSIWAX;

		case 0x0a6:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MFMSR;

		case 0x0a8:
		case 0x0a9:
			return PPC_ID_LDARX;

		case 0x0ac:
		{
			if ((word32 & 0x03800000) != 0)
				return PPC_ID_INVALID;

			uint32_t l = (word32 >> 21) & 0x3;
			switch (l)
			{
				case 1:
					return PPC_ID_DCBFL;

				case 3:
					return PPC_ID_DCBFLP;

				default:
					return PPC_ID_DCBF;
			}
		}

		case 0x0ae:
			return PPC_ID_LBZX;

		case 0x0be:
			return PPC_ID_LBEPX;

		case 0x0ce:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVX;

			return PPC_ID_INVALID;

		case 0x0d0:
		case 0x0d1:
		case 0x4d0:
		case 0x4d1:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_NEGx;

		case 0xe6:
		case 0xe7:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MFVSRWZ;

		case 0x0e8:
		case 0x0e9:
			return PPC_ID_LHARX;

		case 0x0ee:
			return PPC_ID_LBZUX;

		case 0x0f4:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_POPCNTB;

		case 0x0f8:
		case 0x0f9:
			return PPC_ID_NORx;

		case 0x0fe:
			if ((word32 & 0x03800000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBFEP;

		case 0x100:
			if ((word32 & 0x0003f800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SETB;

		case 0x106:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_WRTEE;

		case 0x10e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_STVEBX;

			return PPC_ID_INVALID;

		case 0x110:
		case 0x111:
		case 0x510:
		case 0x511:
			return PPC_ID_SUBFEx;

		case 0x114:
		case 0x115:
		case 0x514:
		case 0x515:
			return PPC_ID_ADDEx;

		case 0x118:
		case 0x119:
			return PPC_ID_VSX_STXSIWX;

		case 0x120:
			if ((word32 & 0x00100000) != 0)
			{
				if ((word32 & 0x800) != 0)
					return PPC_ID_INVALID;

				uint32_t fxm = (word32 >> 12) & 0xff;
				if (fxm == 0)
					return PPC_ID_INVALID;

				return PPC_ID_MTOCRF;
			}

			if ((word32 & 0x00000800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MTCRF;

		case 0x124:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MTMSR;

		case 0x12a:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_STDX;

		case 0x12d:
			return PPC_ID_STWCX;

		case 0x12e:
			return PPC_ID_STWX;

		case 0x13a:
			return PPC_ID_STDEPX;

		case 0x13e:
			return PPC_ID_STWEPX;

		case 0x146:
			if ((word32 & 0x03ff7800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_WRTEEI;

		case 0x14e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_STVEHX;

			return PPC_ID_INVALID;

		case 0x164:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MTMSRD;

		case 0x166:
		case 0x167:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MTVSRD;

		case 0x16a:
			return PPC_ID_STDUX;

		case 0x16e:
			return PPC_ID_STWUX;

		case 0x180:
			if ((word32 & 0x00400000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CMPRB;

		case 0x18d:
			if ((word32 & 0x02000000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ICBLQ;

		case 0x18e:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_STVEWX;

			return PPC_ID_INVALID;

		case 0x190:
		case 0x191:
		case 0x590:
		case 0x591:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SUBFZEx;

		case 0x194:
		case 0x195:
		case 0x594:
		case 0x595:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ADDZEx;

		case 0x1a4:
			if ((word32 & 0x0010f800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MTSR;

		case 0x1a6:
		case 0x1a7:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MTVSRWA;

		case 0x1ad:
			return PPC_ID_STDCX;

		case 0x1ae:
			return PPC_ID_STBX;

		case 0x1be:
			return PPC_ID_STBEPX;

		case 0x1c0:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CMPEQB;

		case 0x1cc:
			if ((word32 & 0x02000000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ICBLC;

		case 0x1ce:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_STVX;

			return PPC_ID_INVALID;

		case 0x1d0:
		case 0x1d1:
		case 0x5d0:
		case 0x5d1:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SUBFMEx;

		case 0x1d2:
		case 0x1d3:
		case 0x5d2:
		case 0x5d3:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_MULLDx;

		case 0x1d4:
		case 0x1d5:
		case 0x5d4:
		case 0x5d5:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ADDMEx;

		case 0x1d6:
		case 0x1d7:
		case 0x5d6:
		case 0x5d7:
			return PPC_ID_MULLWx;

		case 0x1e4:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MTSRIN;

		case 0x1e6:
		case 0x1e7:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MTVSRWZ;

		case 0x1ec:
		{
			uint32_t th = (word32 >> 21) & 0x1f;
			if (th == 0x10)
				return PPC_ID_DCBTSTT;
			else
				return PPC_ID_DCBTST;
		}

		case 0x1ee:
			return PPC_ID_STBUX;

		case 0x1f8:
			return PPC_ID_BPERMD;

		case 0x1fe:
			return PPC_ID_DCBTSTEP;

		case 0x212:
			return PPC_ID_MODUD;

		case 0x214:
		case 0x215:
		case 0x614:
		case 0x615:
			return PPC_ID_ADDx;

		case 0x216:
			return PPC_ID_MODUW;

		case 0x218:
		case 0x219:
			return PPC_ID_VSX_LXVX;

		case 0x21a:
		case 0x21b:
			return PPC_ID_VSX_LXVL;

		case 0x224:
			if ((d != 0) || (a != 0))
				return PPC_ID_INVALID;
			
			return PPC_ID_TLBIEL;

		case 0x22c:
		{
			uint32_t th = (word32 >> 21) & 0x1f;
			if (th == 0x10)
				return PPC_ID_DCBTT;
			else
				return PPC_ID_DCBT;
		}

		case 0x22e:
			return PPC_ID_LHZX;

		case 0x238:
		case 0x239:
			return PPC_ID_EQVx;

		case 0x23e:
			return PPC_ID_LHEPX;

		case 0x25a:
		case 0x25b:
			return PPC_ID_VSX_LXVLL;

		case 0x25c:
			return PPC_ID_MFBHRBE;

		case 0x264:
			if (a != 0)
				return PPC_ID_INVALID;
			
			return PPC_ID_TLBIE;

		case 0x266:
		case 0x267:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MFVSRLD;

		case 0x26c:
			return PPC_ID_ECIWX;

		case 0x26e:
			return PPC_ID_LHZUX;

		case 0x278:
		case 0x279:
			return PPC_ID_XORx;

		case 0x27e:
			return PPC_ID_DCBTEP;

		case 0x286:
		{
			uint32_t dcr = GetSpecialRegisterCommon(word32);

			switch (dcr)
			{
				case 0x80: return PPC_ID_MFBR0;
				case 0x81: return PPC_ID_MFBR1;
				case 0x82: return PPC_ID_MFBR2;
				case 0x83: return PPC_ID_MFBR3;
				case 0x84: return PPC_ID_MFBR4;
				case 0x85: return PPC_ID_MFBR5;
				case 0x86: return PPC_ID_MFBR6;
				case 0x87: return PPC_ID_MFBR7;

				default:   return PPC_ID_MFDCR;
			}
		}

		case 0x298:
		case 0x299:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_LXVDSX;

		case 0x29c:
			return PPC_ID_MFPMR;

		case 0x2a4:
			if (a != 0 || b != 0 || d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBSYNC;

		case 0x2a6:
		{
			uint32_t spr = GetSpecialRegisterCommon(word32);

			// there are a bunch of other MF<some specific SPR>
			// instructions; instead of handling them all, we just
			// give a few common SPRs their own special opcodes, and
			// bundle the rest into MFSPR
			//
			// this avoids adding a bazillion separate instructions
			// that need to be lifted separately, AND are highly
			// arch-dependent
			switch (spr)
			{
				case 1:    return PPC_ID_MFXER;
				case 8:    return PPC_ID_MFLR;
				case 9:    return PPC_ID_MFCTR;

				default:   return PPC_ID_MFSPR;
			}
		}

		case 0x2aa:
			return PPC_ID_LWAX;

		case 0x2ac:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) == 0)
				return PPC_ID_INVALID;

			if ((word32 & 0x01800000) != 0)
				return PPC_ID_INVALID;

			if ((word32 & 0x02000000) != 0)
				return PPC_ID_AV_DSTT;
			else
				return PPC_ID_AV_DST;

		case 0x2ae:
			return PPC_ID_LHAX;

		case 0x2ce:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_LVXL;

			return PPC_ID_INVALID;

		case 0x2d8:
		case 0x2d9:
			return PPC_ID_VSX_LXVWSX;

		case 0x2e4:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TLBIA;

		case 0x2e6:
		{
			uint32_t special = GetSpecialRegisterCommon(word32);
			switch (special)
			{
				case 269: return PPC_ID_MFTBU;

				default: return PPC_ID_MFTB;
			}
		}

		case 0x2ea:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_LWAUX;

		case 0x2ec:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) == 0)
				return PPC_ID_INVALID;

			if ((word32 & 0x01800000) != 0)
				return PPC_ID_INVALID;

			if ((word32 & 0x02000000) != 0)
				return PPC_ID_AV_DSTSTT;
			else
				return PPC_ID_AV_DSTST;

		case 0x2ee:
			return PPC_ID_LHAUX;

		case 0x2f4:
			if (b != 0)
				return PPC_ID_INVALID;

			// TODO: [Category: Server]
			// TODO: [Category: Embedded.Phased-In]
			return PPC_ID_POPCNTW;

		case 0x312:
		case 0x313:
		case 0x712:
		case 0x713:
			return PPC_ID_DIVDEUx;

		case 0x316:
		case 0x317:
		case 0x716:
		case 0x717:
			return PPC_ID_DIVWEUx;

		case 0x318:
		case 0x319:
			return PPC_ID_VSX_STXVX;

		case 0x31a:
		case 0x31b:
			return PPC_ID_VSX_STXVL;

		case 0x324:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBMTE;

		case 0x326:
		case 0x327:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_MTVSRWS;

		case 0x32e:
			return PPC_ID_STHX;

		case 0x338:
		case 0x339:
			return PPC_ID_ORCx;

		case 0x33e:
			return PPC_ID_STHEPX;

		case 0x352:
		case 0x353:
		case 0x752:
		case 0x753:
			return PPC_ID_DIVDEx;

		case 0x356:
		case 0x357:
		case 0x756:
		case 0x757:
			return PPC_ID_DIVWEx;

		case 0x35a:
		case 0x35b:
			return PPC_ID_VSX_STXVLL;

		case 0x35c:
			if ((a != 0) || (b != 0) || (d != 0))
				return PPC_ID_INVALID;

			return PPC_ID_CLRBHRB;

		case 0x364:
			if ((d != 0) || (a != 0))
				return PPC_ID_INVALID;
			
			return PPC_ID_SLBIE;

		case 0x366:
		case 0x367:
			return PPC_ID_VSX_MTVSRDD;

		case 0x36c:
			return PPC_ID_ECOWX;

		case 0x36e:
			return PPC_ID_STHUX;

		case 0x378:
		case 0x379:
			// TODO: it would be nice to disassemble "mr.", but
			//       capstone doesn't handle this (and technically
			//       "mr." isn't listed as a valid instruction in
			//       the documentation, but it IS a bit more user
			//       friendly for disassembly purposes)
			if (b == s && ((word32 & 0x1) == 0))
				return PPC_ID_MRx;
			else
				return PPC_ID_ORx;

		case 0x386:
		{
			uint32_t dcr = GetSpecialRegisterCommon(word32);

			switch (dcr)
			{
				case 0x80: return PPC_ID_MTBR0;
				case 0x81: return PPC_ID_MTBR1;
				case 0x82: return PPC_ID_MTBR2;
				case 0x83: return PPC_ID_MTBR3;
				case 0x84: return PPC_ID_MTBR4;
				case 0x85: return PPC_ID_MTBR5;
				case 0x86: return PPC_ID_MTBR6;
				case 0x87: return PPC_ID_MTBR7;

				default: return PPC_ID_MTDCR;
			}
		}

		case 0x38c:
		{
			if ((word32 & 0x021ff800) != 0)
				return PPC_ID_INVALID;

			uint32_t ct = (word32 >> 21) & 0xf;

			if (ct == 0)
				return PPC_ID_DCCCI;
			else
				return PPC_ID_DCI;
		}

		case 0x392:
		case 0x393:
		case 0x792:
		case 0x793:
			return PPC_ID_DIVDUx;

		case 0x396:
		case 0x397:
		case 0x796:
		case 0x797:
			return PPC_ID_DIVWUx;

		case 0x39c:
			return PPC_ID_MTPMR;

		case 0x3a4:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBIEG;

		case 0x3a6:
		{
			uint32_t spr = GetSpecialRegisterCommon(word32);

			switch (spr)
			{
				// there are a bunch of other MF<some specific SPR>
				// instructions; instead of handling them all, we just
				// give a few common SPRs their own special opcodes, and
				// bundle the rest into MFSPR
				//
				// this avoids adding a bazillion separate instructions
				// that need to be lifted separately, AND are highly
				// arch-dependent
				case 1:    return PPC_ID_MTXER;
				case 8:    return PPC_ID_MTLR;
				case 9:    return PPC_ID_MTCTR;

				default:   return PPC_ID_MTSPR;
			}
		}

		case 0x3ac:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBI;

		case 0x3b8:
		case 0x3b9:
			return PPC_ID_NANDx;

		case 0x3cc:
			if ((word32 & 0x02000000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ICBTLS;

		case 0x3ce:
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC) != 0)
				return PPC_ID_AV_STVXL;

			return PPC_ID_INVALID;

		case 0x3d2:
		case 0x3d3:
		case 0x7d2:
		case 0x7d3:
			return PPC_ID_DIVDx;

		case 0x3d6:
		case 0x3d7:
		case 0x7d6:
		case 0x7d7:
			return PPC_ID_DIVWx;

		case 0x3e4:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBIA;

		case 0x3f4:
			if (b != 0)
				return PPC_ID_INVALID;

			// TODO: [Category: Server.64-bit]
			// TODO: [Category: Embedded.64-bit.Phased-In]
			return PPC_ID_POPCNTD;

		case 0x3f8:
			return PPC_ID_CMPB;

		case 0x400:
			if ((word32 & 0x00fff800) != 0)
				return PPC_ID_INVALID;

			break;

		case 0x418:
		case 0x419:
			return PPC_ID_VSX_LXSSPX;

		case 0x428:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_LDBRX;

		case 0x42a:
			return PPC_ID_LSWX;

		case 0x42c:
			return PPC_ID_LWBRX;

		case 0x42e:
			return PPC_ID_LFSX;

		case 0x430:
		case 0x431:
			return PPC_ID_SRWx;

		case 0x434:
		case 0x435:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CNTTZWx;

		case 0x436:
		case 0x437:
			return PPC_ID_SRDx;

		case 0x46c:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TLBSYNC;

		case 0x46e:
			return PPC_ID_LFSUX;

		case 0x474:
		case 0x475:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CNTTZDx;

		case 0x480:
			if ((word32 & 0x007ff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MCRXRX;

		case 0x48c:
			return PPC_ID_LWAT;

		case 0x498:
		case 0x499:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_LXSDX;

		case 0x4a6:
			if ((word32 & 0x0010f801) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MFSR;

		case 0x4aa:
			return PPC_ID_LSWI;

		case 0x4ac:
		{
			if ((word32 & 0x039ff800) != 0)
				return PPC_ID_INVALID;

			uint32_t l = (word32 >> 21) & 0x3;
			switch (l)
			{
				case 0:  return PPC_ID_SYNC;
				case 1:  return PPC_ID_LWSYNC;
				case 2:  return PPC_ID_PTESYNC;

				default: return PPC_ID_SYNC;

			}
		}

		case 0x4ae:
			return PPC_ID_LFDX;

		case 0x4be:
			return PPC_ID_LFDEPX;

		case 0x4cc:
			return PPC_ID_LDAT;

		case 0x4ee:
			return PPC_ID_LFDUX;

		case 0x4e4:
			if ((word32 & 0x03fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TLBIA;

		case 0x518:
		case 0x519:
			return PPC_ID_VSX_STXSSPX;

		case 0x51d:
			if ((word32 & 0x03eff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TBEGIN;

		case 0x526:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MFSRIN;

		case 0x528:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_STDBRX;

		case 0x52a:
			return PPC_ID_STSWX;

		case 0x52c:
			return PPC_ID_STWBRX;

		case 0x52e:
			return PPC_ID_STFSX;

		case 0x55d:
			if ((word32 & 0x01fff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TEND;

		case 0x56d:
			return PPC_ID_STBCX;

		case 0x56e:
			return PPC_ID_STFSUX;

		case 0x58c:
			return PPC_ID_STWAT;

		case 0x598:
		case 0x599:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_STXSDX;

		case 0x59c:
			if ((word32 & 0x007ff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TCHECK;

		case 0x5aa:
			return PPC_ID_STSWI;

		case 0x5ad:
			return PPC_ID_STHCX;

		case 0x5ae:
			return PPC_ID_STFDX;

		case 0x5be:
			return PPC_ID_STFDEPX;

		case 0x5cc:
			return PPC_ID_STDAT;

		case 0x5dd:
			if ((word32 & 0x03dff800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TSR;

		case 0x5e6:
			if ((word32 & 0x001cf800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DARN;

		case 0x5ec:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBA;

		case 0x5ee:
			return PPC_ID_STFDUX;

		case 0x60c:
			if (d != 1)
				return PPC_ID_INVALID;

			return PPC_ID_COPY;

		case 0x612:
			return PPC_ID_MODSD;

		case 0x616:
			return PPC_ID_MODSW;

		case 0x618:
		case 0x619:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_LXVW4X;

		case 0x61a:
		case 0x61b:
			return PPC_ID_VSX_LXSIBZX;

		case 0x61d:
			return PPC_ID_TABORTWC;

		case 0x624:
			if ((word32 & 0x03e00000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TLBIVAX;

		case 0x62a:
			return PPC_ID_LWZCIX;

		case 0x62c:
			return PPC_ID_LHBRX;

		case 0x630:
		case 0x631:
			return PPC_ID_SRAWx;

		case 0x634:
		case 0x635:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_SRADx;

		case 0x658:
		case 0x659:
			return PPC_ID_VSX_LXVH8X;

		case 0x65a:
		case 0x65b:
			return PPC_ID_VSX_LXSIHZX;

		case 0x65d:
			return PPC_ID_TABORTDC;

		case 0x66a:
			return PPC_ID_LHZCIX;

		case 0x66c:
		{
			if ((word32 & 0x019ff800) != 0)
				return PPC_ID_INVALID;

			uint32_t all = ((word32 >> 25) & 0x1) != 0;

			if (all)
			{
				if ((word32 & 0x00600000) != 0)
					return PPC_ID_INVALID;
				else
					return PPC_ID_AV_DSSALL;
			}
			else
			{
				return PPC_ID_AV_DSS;
			}
		}

		case 0x670:
		case 0x671:
			return PPC_ID_SRAWIx;

		case 0x674:
		case 0x675:
		case 0x676:
		case 0x677:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_SRADIx;

		case 0x68c:
			if (a != 0 || b != 0 || d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_CP_ABORT;

		case 0x698:
		case 0x699:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_LXVD2X;

		case 0x69d:
			return PPC_ID_TABORTWCI;

		case 0x6a6:
			if ((word32 & 0x001e0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBMFEV;

		case 0x6aa:
			return PPC_ID_LBZCIX;

		case 0x6ac:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			if (d == 0)
				return PPC_ID_EIEIO;
			else
				return PPC_ID_MBAR;

		case 0x6ae:
			return PPC_ID_LFIWAX;

		case 0x6d8:
		case 0x6d9:
			return PPC_ID_VSX_LXVB16X;

		case 0x6dd:
			return PPC_ID_TABORTDCI;

		case 0x6ea:
			return PPC_ID_LDCIX;

		case 0x6ec:
			if ((a != 0) || (b != 0) || (d != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MSGSYNC;

		case 0x6ee:
			return PPC_ID_LFIWZX;

		case 0x6f4:
		case 0x6f5:
		case 0x6f6:
		case 0x6f7:
			return PPC_ID_EXTSWSLIx;

		case 0x70d:
			if (d != 1)
				return PPC_ID_INVALID;

			return PPC_ID_PASTE;

		case 0x718:
		case 0x719:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_STXVW4X;

		case 0x71a:
		case 0x71b:
			return PPC_ID_VSX_STXSIBX;

		case 0x71d:
			if (d != 0 || b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TABORT;

		case 0x724:
			if ((word32 & 0x03e00000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_TLBSX;

		case 0x726:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_SLBMFEE;

		case 0x72a:
			return PPC_ID_STWCIX;

		case 0x72c:
			return PPC_ID_STHBRX;

		case 0x734:
		case 0x735:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_EXTSHx;

		case 0x758:
		case 0x759:
			return PPC_ID_VSX_STXVH8X;

		case 0x75a:
		case 0x75b:
			return PPC_ID_VSX_STXSIHX;

		case 0x75d:
			if ((d != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_TRECLAIM;

		case 0x764:
			if ((word32 & 0x800) != 0)
				return PPC_ID_TLBREHI;
			else
				return PPC_ID_TLBRELO;

		case 0x76a:
			return PPC_ID_STHCIX;

		case 0x774:
		case 0x775:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_EXTSBx;

		case 0x78c:
		{
			if ((word32 & 0x021ff801) != 0)
				return PPC_ID_INVALID;

			uint32_t ct = (word32 >> 21) & 0xf;

			if (ct == 0)
				return PPC_ID_ICCCI;
			else
				return PPC_ID_ICI;
		}

		case 0x798:
		case 0x799:
			if ((decodeFlags & DECODE_FLAGS_VSX) == 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_STXVD2X;

		case 0x7a4:
			if ((word32 & 0x800) != 0)
				return PPC_ID_TLBWELO;
			else
				return PPC_ID_TLBWEHI;

		case 0x7aa:
			return PPC_ID_STBCIX;

		case 0x7ac:
			if (d != 0)
				return PPC_ID_INVALID;
			
			return PPC_ID_ICBI;

		case 0x7ae:
			return PPC_ID_STFIWX;

		case 0x7b4:
		case 0x7b5:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_EXTSWx;

		case 0x7be:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_ICBIEP;

		case 0x7d8:
		case 0x7d9:
			return PPC_ID_VSX_STXVB16X;

		case 0x7dd:
			if ((a != 0) || (b != 0) || (d != 0))
				return PPC_ID_INVALID;

			return PPC_ID_TRECHKPT;

		case 0x7e4:
			if (d != 0 || a != 0)
				return PPC_ID_INVALID;

			// NOTE: this is only valid for 603 processors?
			return PPC_ID_TLBLI;

		case 0x7ea:
			return PPC_ID_STDCIX;

		case 0x7ec:
		{
			// NOTE: I can't find anything about the "DCBZL" opcode
			//       anywhere, but this seems to match capstone
			if ((word32 & 0x03e00000) == 0x00200000)
				return PPC_ID_DCBZL;
			else if ((word32 & 0x03e00000) == 0)
				return PPC_ID_DCBZ;
			else
				return PPC_ID_INVALID;
		}

		case 0x7fe:
			if (d != 0)
				return PPC_ID_INVALID;

			return PPC_ID_DCBZEP;

		default:
			return PPC_ID_INVALID;
	}

	return true;
}

static InstructionId Decode0x3B(uint32_t word32, uint32_t flags)
{
	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);
	uint32_t c = GetC(word32);

	uint32_t subop = word32 & 0x3f;
	switch (subop)
	{
		case 0x24:
		case 0x25:
			if (c != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FDIVSx;

		case 0x28:
		case 0x29:
			if (c != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FSUBSx;

		case 0x2a:
		case 0x2b:
			if (c != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FADDSx;

		case 0x2c:
		case 0x2d:
			if ((a != 0) || (c != 0))
				return PPC_ID_INVALID;

			return PPC_ID_FSQRTSx;

		case 0x30:
		case 0x31:
			if ((a != 0) || (c != 0))
				return PPC_ID_INVALID;

			return PPC_ID_FRESx;

		case 0x32:
		case 0x33:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FMULSx;

		case 0x34:
		case 0x35:
			if ((a != 0) || (c != 0))
				return PPC_ID_INVALID;

			return PPC_ID_FRSQRTESx;

		case 0x38:
		case 0x39:
			return PPC_ID_FMSUBSx;

		case 0x3a:
		case 0x3b:
			return PPC_ID_FMADDSx;

		case 0x3c:
		case 0x3d:
			return PPC_ID_FNMSUBSx;

		case 0x3e:
		case 0x3f:
			return PPC_ID_FNMADDSx;

		default:
			break;
	}

	subop = word32 & 0x7ff;
	switch (subop)
	{
		case 0x69c:
		case 0x69d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCFIDSx;

		case 0x79c:
		case 0x79d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCFIDUSx;

		default:
			return PPC_ID_INVALID;
	}

	return true;
}

static InstructionId DecodeVsx0x3C(uint32_t word32, uint32_t flags)
{
	uint32_t bit21 = (word32 >> 10) & 0x1;
	uint32_t subop = (word32 >> 4) & 0x3;
	uint32_t vsxA = GetVsxA(word32);
	uint32_t vsxB = GetVsxB(word32);

	switch (subop)
	{
		case 0x3: return PPC_ID_VSX_XXSEL;
		default:  break;
	}

	subop = (word32 >> 1) & 0x3ff;
	switch (subop)
	{
		case 0x168:
			if ((word32 & 0x00180000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XXSPLTIB;

		case 0x396:
			return PPC_ID_VSX_XSIEXPDP;

		default:
			;
	}

	subop = (word32 >> 2) & 0x1ff;
	switch (subop)
	{
		case 0x00a:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRSQRTESP;

		case 0x00b:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSSQRTSP;

		case 0x01a:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRESP;

		case 0x048:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPUXWS;

		case 0x049:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRDPI;

		case 0x04a:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRSQRTEDP;

		case 0x04b:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSSQRTDP;

		case 0x058:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPSXWS;

		case 0x059:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRDPIZ;

		case 0x05a:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSREDP;

		case 0x069:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRDPIP;

		case 0x6a:
			if ((word32 & 0x007f0001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSTSQRTDP;

		case 0x06b:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRDPIC;

		case 0x079:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRDPIM;

		case 0x088:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSPUXWS;

		case 0x089:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSPI;

		case 0x08a:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSQRTESP;

		case 0x08b:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVSQRTSP;

		case 0x098:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSPSXWS;

		case 0x099:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSPIZ;

		case 0x09a:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRESP;

		case 0x0a4:
			if ((word32 & 0x001c0004) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XXSPLTW;

		case 0x0a5:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XXEXTRACTUW;

		case 0x0a8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVUXWSP;

		case 0x0a9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSPIP;

		case 0x0aa:
			if ((word32 & 0x007f0001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVTSQRTSP;

		case 0x0ab:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSPIC;

		case 0x0b5:
			if ((word32 & 0x00100000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XXINSERTW;

		case 0x0b8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSXWSP;

		case 0x0b9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSPIM;

		case 0x0c8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVDPUXWS;

		case 0x0c9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRDPI;

		case 0x0ca:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRSQRTEDP;

		case 0x0cb:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVSQRTDP;

		case 0x0d8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVDPSXWS;

		case 0x0d9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRDPIZ;

		case 0x0da:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVREDP;

		case 0x0e8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVUXWDP;

		case 0x0e9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRDPIP;

		case 0xea:
			if ((word32 & 0x007f0001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVTSQRTDP;

		case 0x0eb:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRDPIC;

		case 0x0f8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSXWDP;

		case 0x0f9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVRDPIM;

		case 0x109:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPSP;

		case 0x10b:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPSPN;

		case 0x119:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRSP;

		case 0x128:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVUXDSP;

		case 0x12a:
			if ((word32 & 0x1) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSTSTDCSP;

		case 0x138:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVSXDSP;

		case 0x148:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPUXDS;

		case 0x149:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVSPDP;

		case 0x14b:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVSPDPN;

		case 0x158:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVDPSXDS;

		case 0x159:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSABSDP;

		case 0x15b:
		{
			uint32_t subsubop = (word32 >> 16) & 0x1f;
			switch (subsubop)
			{
				case 0x00:
					if ((word32 & 0x1) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_VSX_XSXEXPDP;

				case 0x01:
					if ((word32 & 0x1) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_VSX_XSXSIGDP;

				case 0x10:
					return PPC_ID_VSX_XSCVHPDP;

				case 0x11:
					return PPC_ID_VSX_XSCVDPHP;

				default:
					return PPC_ID_INVALID;
			}
		}

		case 0x168:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVUXDDP;

		case 0x169:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSNABSDP;

		case 0x16a:
			if ((word32 & 0x1) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSTSTDCDP;

		case 0x178:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCVSXDDP;

		case 0x179:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSNEGDP;

		case 0x188:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSPUXDS;

		case 0x189:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVDPSP;

		case 0x198:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSPSXDS;

		case 0x199:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVABSSP;

		case 0x1a8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVUXDSP;

		case 0x1a9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVNABSSP;

		case 0x1b8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSXDSP;

		case 0x1b9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVNEGSP;

		case 0x1c8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVDPUXDS;

		case 0x1c9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSPDP;

		case 0x1d8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVDPSXDS;

		case 0x1d9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVABSDP;

		case 0x1db:
		{
			uint32_t subsubop = (word32 >> 16) & 0x1f;
			switch (subsubop)
			{
				case 0x00:
					return PPC_ID_VSX_XVXEXPDP;

				case 0x01:
					return PPC_ID_VSX_XVXSIGDP;

				case 0x07:
					return PPC_ID_VSX_XXBRH;

				case 0x08:
					return PPC_ID_VSX_XVXEXPSP;

				case 0x09:
					return PPC_ID_VSX_XVXSIGSP;

				case 0x0f:
					return PPC_ID_VSX_XXBRW;

				case 0x17:
					return PPC_ID_VSX_XXBRD;

				case 0x18:
					return PPC_ID_VSX_XVCVHPSP;

				case 0x19:
					return PPC_ID_VSX_XVCVSPHP;

				case 0x1f:
					return PPC_ID_VSX_XXBRQ;

				default:
					return PPC_ID_INVALID;

			}
		}

		case 0x1e8:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVUXDDP;

		case 0x1e9:
			if ((word32 & 0x001f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVNABSDP;

		case 0x1f8:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVCVSXDDP;

		case 0x1f9:
			if ((word32 & 0x001f0000) != 0x0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVNEGDP;

		default:
			break;
	}

	subop = (word32 >> 3) & 0xff;
	switch (subop)
	{
		case 0x00:
			return PPC_ID_VSX_XSADDSP;

		case 0x01:
			return PPC_ID_VSX_XSMADDASP;

		case 0x02:
		case 0x22:
		case 0x42:
		case 0x62:
			return PPC_ID_VSX_XXSLDWI;

		case 0x03:
			return PPC_ID_VSX_XSCMPEQDP;

		case 0x08:
			return PPC_ID_VSX_XSSUBSP;

		case 0x09:
			return PPC_ID_VSX_XSMADDMSP;

		case 0x0a:
		case 0x2a:
		case 0x4a:
		case 0x6a:
		{
			uint32_t dm = (word32 >> 8) & 0x3;

			if (vsxA == vsxB)
			{
				switch (dm)
				{
					case 0:  return PPC_ID_VSX_XXSPLTD;
					case 2:  return PPC_ID_VSX_XXSWAPD;
					case 3:  return PPC_ID_VSX_XXSPLTD;
					default: return PPC_ID_VSX_XXPERMDI;
				}
			}
			else
			{
				switch (dm)
				{
					case 0:  return PPC_ID_VSX_XXMRGHD;
					case 3:  return PPC_ID_VSX_XXMRGLD;
					default: return PPC_ID_VSX_XXPERMDI;
				}
			}
		}

		case 0x0b:
			return PPC_ID_VSX_XSCMPGTDP;

		case 0x10:
			return PPC_ID_VSX_XSMULSP;

		case 0x11:
			return PPC_ID_VSX_XSMSUBASP;

		case 0x12:
			return PPC_ID_VSX_XXMRGHW;

		case 0x13:
			return PPC_ID_VSX_XSCMPGEDP;

		case 0x18:
			return PPC_ID_VSX_XSDIVSP;

		case 0x19:
			return PPC_ID_VSX_XSMSUBMSP;

		case 0x1a:
			return PPC_ID_VSX_XXPERM;

		case 0x20:
			return PPC_ID_VSX_XSADDDP;

		case 0x21:
			return PPC_ID_VSX_XSMADDADP;

		case 0x23:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCMPUDP;

		case 0x28:
			return PPC_ID_VSX_XSSUBDP;

		case 0x29:
			return PPC_ID_VSX_XSMADDMDP;

		case 0x2b:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCMPODP;

		case 0x30:
			return PPC_ID_VSX_XSMULDP;

		case 0x31:
			return PPC_ID_VSX_XSMSUBADP;

		case 0x32:
			return PPC_ID_VSX_XXMRGLW;

		case 0x38:
			return PPC_ID_VSX_XSDIVDP;

		case 0x39:
			return PPC_ID_VSX_XSMSUBMDP;

		case 0x3a:
			return PPC_ID_VSX_XXPERMR;

		case 0x3b:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSCMPEXPDP;

		case 0x3d:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSTDIVDP;

		case 0x40:
			return PPC_ID_VSX_XVADDSP;

		case 0x41:
			return PPC_ID_VSX_XVMADDASP;

		case 0x43:
		case 0xc3:
			return PPC_ID_VSX_XVCMPEQSPx;

		case 0x48:
			return PPC_ID_VSX_XVSUBSP;

		case 0x49:
			return PPC_ID_VSX_XVMADDMSP;

		case 0x4b:
		case 0xcb:
			return PPC_ID_VSX_XVCMPGTSPx;

		case 0x50:
			return PPC_ID_VSX_XVMULSP;

		case 0x51:
			return PPC_ID_VSX_XVMSUBASP;

		case 0x53:
		case 0xd3:
			return PPC_ID_VSX_XVCMPGESPx;

		case 0x58:
			return PPC_ID_VSX_XVDIVSP;

		case 0x59:
			return PPC_ID_VSX_XVMSUBMSP;

		case 0x5d:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVTDIVSP;

		case 0x60:
			return PPC_ID_VSX_XVADDDP;

		case 0x61:
			return PPC_ID_VSX_XVMADDADP;

		case 0x63:
		case 0xe3:
			return PPC_ID_VSX_XVCMPEQDPx;

		case 0x68:
			return PPC_ID_VSX_XVSUBDP;

		case 0x69:
			return PPC_ID_VSX_XVMADDMDP;

		case 0x6b:
		case 0xeb:
			return PPC_ID_VSX_XVCMPGTDPx;

		case 0x70:
			return PPC_ID_VSX_XVMULDP;

		case 0x71:
			return PPC_ID_VSX_XVMSUBADP;

		case 0x73:
		case 0xf3:
			return PPC_ID_VSX_XVCMPGEDPx;

		case 0x78:
			return PPC_ID_VSX_XVDIVDP;

		case 0x79:
			return PPC_ID_VSX_XVMSUBMDP;

		case 0x7d:
			if ((word32 & 0x00600001) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XVTDIVDP;

		case 0x80:
			return PPC_ID_VSX_XSMAXCDP;

		case 0x81:
			return PPC_ID_VSX_XSNMADDASP;

		case 0x82:
			return PPC_ID_VSX_XXLAND;

		case 0x88:
			return PPC_ID_VSX_XSMINCDP;

		case 0x89:
			return PPC_ID_VSX_XSNMADDMSP;

		case 0x8a:
			return PPC_ID_VSX_XXLANDC;

		case 0x90:
			return PPC_ID_VSX_XSMAXJDP;

		case 0x91:
			return PPC_ID_VSX_XSNMSUBASP;

		case 0x92:
			return PPC_ID_VSX_XXLOR;

		case 0x98:
			return PPC_ID_VSX_XSMINJDP;

		case 0x99:
			return PPC_ID_VSX_XSNMSUBMSP;

		case 0x9a:
			return PPC_ID_VSX_XXLXOR;

		case 0xa0:
			return PPC_ID_VSX_XSMAXDP;

		case 0xa1:
			return PPC_ID_VSX_XSNMADDADP;

		case 0xa9:
			return PPC_ID_VSX_XSNMADDMDP;

		case 0xa2:
			return PPC_ID_VSX_XXLNOR;

		case 0xa8:
			return PPC_ID_VSX_XSMINDP;

		case 0xaa:
			return PPC_ID_VSX_XXLORC;

		case 0xb0:
			return PPC_ID_VSX_XSCPSGNDP;

		case 0xb1:
			return PPC_ID_VSX_XSNMSUBADP;

		case 0xb2:
			return PPC_ID_VSX_XXLNAND;

		case 0xb9:
			return PPC_ID_VSX_XSNMSUBMDP;

		case 0xba:
			return PPC_ID_VSX_XXLEQV;

		case 0xc0:
			return PPC_ID_VSX_XVMAXSP;

		case 0xc1:
			return PPC_ID_VSX_XVNMADDASP;

		case 0xc8:
			return PPC_ID_VSX_XVMINSP;

		case 0xc9:
			return PPC_ID_VSX_XVNMADDMSP;

		case 0xd0:
			if (vsxA == vsxB)
				return PPC_ID_VSX_XVMOVSP;
			else
				return PPC_ID_VSX_XVCPSGNSP;

		case 0xd1:
			return PPC_ID_VSX_XVNMSUBASP;

		case 0xd5:
		case 0xdd:
			return PPC_ID_VSX_XVTSTDCSP;

		case 0xd8:
			return PPC_ID_VSX_XVIEXPSP;

		case 0xd9:
			return PPC_ID_VSX_XVNMSUBMSP;

		case 0xe0:
			return PPC_ID_VSX_XVMAXDP;

		case 0xe1:
			return PPC_ID_VSX_XVNMADDADP;

		case 0xe8:
			return PPC_ID_VSX_XVMINDP;

		case 0xe9:
			return PPC_ID_VSX_XVNMADDMDP;

		case 0xf0:
			if (vsxA == vsxB)
				return PPC_ID_VSX_XVMOVDP;
			else
				return PPC_ID_VSX_XVCPSGNDP;

		case 0xf1:
			return PPC_ID_VSX_XVNMSUBADP;

		case 0xf5:
		case 0xfd:
			return PPC_ID_VSX_XVTSTDCDP;

		case 0xf8:
			return PPC_ID_VSX_XVIEXPDP;

		case 0xf9:
			return PPC_ID_VSX_XVNMSUBMDP;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId DecodeVsx0x3D(uint32_t word32, uint32_t flags)
{
	uint32_t subop = word32 & 0x7;
	switch (subop)
	{
		case 1:
			return PPC_ID_VSX_LXV;

		case 2:
		case 6:
			return PPC_ID_VSX_STXSD;

		case 3:
		case 7:
			return PPC_ID_VSX_STXSSP;

		case 5:
			return PPC_ID_VSX_STXV;

		default:
			return PPC_ID_INVALID;
	}
}

static InstructionId Decode0x3F(uint32_t word32, uint32_t flags)
{
	uint32_t a = GetA(word32);
	uint32_t b = GetB(word32);

	uint32_t subop = word32 & 0x3f;
	switch (subop)
	{
		case 0x02e:
		case 0x02f:
			return PPC_ID_FSELx;

		case 0x032:
		case 0x033:
			if (b != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FMULx;

		case 0x038:
		case 0x039:
			return PPC_ID_FMSUBx;

		case 0x03a:
		case 0x03b:
			return PPC_ID_FMADDx;

		case 0x03c:
		case 0x03d:
			return PPC_ID_FNMSUBx;

		case 0x03e:
		case 0x03f:
			return PPC_ID_FNMADDx;

		default:
			break;
	}

	subop = word32 & 0x7ff;
	switch (subop)
	{
		case 0x000:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCMPU;

		case 0x008:
		case 0x009:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSADDQPx;
			else
				return PPC_ID_INVALID;

		case 0x00a:
		case 0x00b:
		case 0x20a:
		case 0x20b:
		case 0x40a:
		case 0x40b:
		case 0x60a:
		case 0x60b:
			if ((word32 & 0x001e0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_VSX_XSRQPIx;

		case 0x010:
		case 0x011:
			return PPC_ID_FCPSGNx;

		case 0x018:
		case 0x019:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRSPx;

		case 0x01c:
		case 0x01d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIWx;

		case 0x01e:
		case 0x01f:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIWZx;

		case 0x024:
		case 0x025:
			return PPC_ID_FDIVx;

		case 0x028:
		case 0x029:
			return PPC_ID_FSUBx;

		case 0x02a:
		case 0x02b:
			return PPC_ID_FADDx;

		case 0x02c:
		case 0x02d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FSQRTx;

		case 0x030:
		case 0x031:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FREx;

		case 0x034:
		case 0x035:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRSQRTEx;

		case 0x040:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCMPO;

		case 0x048:
		case 0x049:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSMULQPx;
			else
				return PPC_ID_INVALID;

		case 0x04a:
		case 0x24a:
		case 0x44a:
		case 0x64a:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				if ((word32 & 0x001e0000) != 0)
					return PPC_ID_INVALID;

				return PPC_ID_VSX_XSRQPXP;
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x04c:
		case 0x04d:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MTFSB1x;

		case 0x050:
		case 0x051:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FNEGx;

		case 0x080:
			if ((word32 & 0x0063f800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MCRFS;

		case 0x08c:
		case 0x08d:
			if ((a != 0) || (b != 0))
				return PPC_ID_INVALID;

			return PPC_ID_MTFSB0x;

		case 0x090:
		case 0x091:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FMRx;

		case 0x0c8:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSCPSGNQP;
			else
				return PPC_ID_INVALID;

		case 0x100:
			if ((word32 & 0x00600000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FTDIV;

		case 0x108:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				if ((word32 & 0x00600000) != 0)
					return PPC_ID_INVALID;

				return PPC_ID_VSX_XSCMPOQP;
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x10c:
		case 0x10d:
			if ((word32 & 0x007e0800) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_MTFSFIx;

		case 0x110:
		case 0x111:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FNABSx;

		case 0x11c:
		case 0x11d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIWUx;

		case 0x11e:
		case 0x11f:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIWUZx;

		case 0x140:
			if ((word32 & 0x007f0000) != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FTSQRT;

		case 0x148:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				if ((word32 & 0x00600000) != 0)
					return PPC_ID_INVALID;

				return PPC_ID_VSX_XSCMPEXPQP;
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x210:
		case 0x211:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FABSx;

		case 0x308:
		case 0x309:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSMADDQPx;
			else
				return PPC_ID_INVALID;

		case 0x310:
		case 0x311:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRINx;

		case 0x348:
		case 0x349:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSMSUBQPx;
			else
				return PPC_ID_INVALID;

		case 0x350:
		case 0x351:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRIZx;

		case 0x388:
		case 0x389:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSNMADDQPx;
			else
				return PPC_ID_INVALID;

		case 0x390:
		case 0x391:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRIPx;

		case 0x3c8:
		case 0x3c9:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSNMSUBQPx;
			else
				return PPC_ID_INVALID;

		case 0x3d0:
		case 0x3d1:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FRIMx;

		case 0x408:
		case 0x409:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSSUBQPx;
			else
				return PPC_ID_INVALID;

		case 0x448:
		case 0x449:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSDIVQPx;
			else
				return PPC_ID_INVALID;

		case 0x48e:
		case 0x48f:
		{
			uint32_t subsubop = (word32 >> 16) & 0x1f;
			switch (subsubop)
			{
				case 0x00:
					if ((word32 & 0x0000f800) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSx;

				case 0x01:
					if ((word32 & 0x0000f801) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSCE;

				case 0x14:
					if ((word32 & 0x1) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSCDRN;

				case 0x15:
					if ((word32 & 0x0000c001) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSCDRNI;

				case 0x16:
					if ((word32 & 0x1) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSCRN;

				case 0x17:
					if ((word32 & 0x0000e001) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSCRNI;

				case 0x18:
					if ((word32 & 0x0000f801) != 0)
						return PPC_ID_INVALID;

					return PPC_ID_MFFSL;

				default:
					return PPC_ID_INVALID;
			}
		}

		case 0x508:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				if ((word32 & 0x00600000) != 0)
					return PPC_ID_INVALID;

				return PPC_ID_VSX_XSCMPUQP;
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x588:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSTSTDCQP;
			else
				return PPC_ID_INVALID;

		case 0x58e:
		case 0x58f:
			return PPC_ID_MTFSFx;

		case 0x648:
		case 0x649:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				uint32_t subsubop = (word32 >> 16) & 0x1f;
				switch (subsubop)
				{
					case 0x00:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSABSQP;

					case 0x02:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSXEXPQP;

					case 0x08:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSNABSQP;

					case 0x10:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSNEGQP;

					case 0x12:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSXSIGQP;

					case 0x1b:
						return PPC_ID_VSX_XSSQRTQPx;

					default:
						PPC_ID_INVALID;

				}
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x65c:
		case 0x65d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIDx;

		case 0x65e:
		case 0x65f:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIDZx;

		case 0x688:
		case 0x689:
			if ((flags & DECODE_FLAGS_VSX) != 0)
			{
				uint32_t subsubop = (word32 >> 16) & 0x1f;
				switch (subsubop)
				{
					case 0x01:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVQPUWZ;

					case 0x02:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVUDQP;

					case 0x09:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVQPSWZ;

					case 0x0a:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVSDQP;

					case 0x11:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVQPUDZ;

					case 0x14:
						return PPC_ID_VSX_XSCVQPDPx;

					case 0x16:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVDPQP;

					case 0x19:
						if ((word32 & 0x1) != 0)
							return PPC_ID_INVALID;

						return PPC_ID_VSX_XSCVQPSDZ;

					default:
						return PPC_ID_INVALID;
				}
			}
			else
			{
				return PPC_ID_INVALID;
			}

		case 0x69c:
		case 0x69d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCFIDx;

		case 0x6c8:
			if ((flags & DECODE_FLAGS_VSX) != 0)
				return PPC_ID_VSX_XSIEXPQP;
			else
				return PPC_ID_INVALID;

		case 0x75c:
		case 0x75d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIDUx;

		case 0x75e:
		case 0x75f:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCTIDUZx;

		case 0x79c:
		case 0x79d:
			if (a != 0)
				return PPC_ID_INVALID;

			return PPC_ID_FCFIDUx;

		default:
			return PPC_ID_INVALID;
	}

	return true;
}

static InstructionId Decode(uint32_t word32, uint32_t decodeFlags)
{
	uint32_t a = GetA(word32);

	uint32_t primary = (word32 >> 26) & 0x3f;
	switch (primary)
	{
		case 0x00:
		{
			// "ATTN" instruction documented in section 12.1.1 of
			// the user manual for the IBM A2 processor
			if ((word32 & 0x7fe) != 0x200)
				return PPC_ID_INVALID;

			return PPC_ID_ATTN;
		}

		case 0x02:
		{
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			uint32_t to = (word32 >> 21) & 0x1f;
			switch (to)
			{
				case 1: return PPC_ID_TDLGTI;
				case 2: return PPC_ID_TDLLTI;
				case 4: return PPC_ID_TDEQI;
				case 8: return PPC_ID_TDGTI;
				case 16: return PPC_ID_TDLTI;
				case 24: return PPC_ID_TDNEI;
				case 31: return PPC_ID_TDUI;
				default: return PPC_ID_TDI;
			}
		}

		case 0x03:
		{
			uint32_t to = (word32 >> 21) & 0x1f;

			switch (to)
			{
				case 1: return PPC_ID_TWLGTI;
				case 2: return PPC_ID_TWLLTI;
				case 4: return PPC_ID_TWEQI;
				case 8: return PPC_ID_TWGTI;
				case 16: return PPC_ID_TWLTI;
				case 24: return PPC_ID_TWNEI;
				case 31: return PPC_ID_TWUI;
				default: return PPC_ID_TWI;
			}
		}

		case 0x04:
		{
			if ((decodeFlags & DECODE_FLAGS_ALTIVEC))
				return DecodeAltivec0x04(word32, decodeFlags);
			else if ((decodeFlags & DECODE_FLAGS_SPE))
				return DecodeSpe0x04(word32, decodeFlags);
			else
				return PPC_ID_INVALID;
		}

		case 0x07:
			return PPC_ID_MULLI;

		case 0x08:
			return PPC_ID_SUBFIC;


		case 0x0a:
			if ((word32 & 0x00400000) == 0)
			{
				if ((word32 & 0x00200000) != 0)
				{
					if (decodeFlags & DECODE_FLAGS_PPC64 == 0)
						return PPC_ID_INVALID;

					return PPC_ID_CMPLDI;
				}
				else
				{
					return PPC_ID_CMPLWI;
				}
			}

			return PPC_ID_INVALID;

		case 0x0b:
			if ((word32 & 0x00400000) == 0)
			{
				if ((word32 & 0x00200000) != 0)
				{
					if (decodeFlags & DECODE_FLAGS_PPC64 == 0)
						return PPC_ID_INVALID;

					return PPC_ID_CMPDI;
				}
				else
				{
					return PPC_ID_CMPWI;
				}
			}

			return PPC_ID_INVALID;

		case 0x0c:
			return PPC_ID_ADDICx;

		case 0x0d:
			return PPC_ID_ADDICx;

		case 0x0e:
			if (a == 0)
				return PPC_ID_LI;
			else
				return PPC_ID_ADDI;

		case 0x0f:
			if (a == 0)
				return PPC_ID_LIS;
			else
				return PPC_ID_ADDIS;

		case 0x10:
			return PPC_ID_BCx;

		case 0x11:
			if ((word32 & 0x03fff01f) != 2)
				return PPC_ID_INVALID;

			return PPC_ID_SC;

		case 0x12:
			return PPC_ID_Bx;

		case 0x13:
			return Decode0x13(word32, decodeFlags);

		case 0x14:
			return PPC_ID_RLWIMIx;

		case 0x15:
		{
			uint32_t me = GetME(word32);
			uint32_t mb = GetMB(word32);
			uint32_t sh = GetSH(word32);

			if (mb == 0 && ((sh + me) == 31))
				return PPC_ID_SLWIx;
			else if (mb == 0 && me == 31)
				return PPC_ID_ROTLWIx;
			else if (me == 31 && ((sh + mb) == 32))
				return PPC_ID_SRWIx;
			else if (sh == 0 && mb == 0)
				return PPC_ID_CLRRWIx;
			else if (sh == 0 && me == 31)
				return PPC_ID_CLRLWIx;
			else
				return PPC_ID_RLWINMx;
		}

		case 0x17:
		{
			uint32_t me = GetME(word32);
			uint32_t mb = GetMB(word32);

			if (mb == 0 && me == 31)
				return PPC_ID_ROTLWx;
			else
				return PPC_ID_RLWNMx;
		}

		case 0x18:
			if (word32 == 0x60000000)
				return PPC_ID_NOP;
			else
				return PPC_ID_ORI;

		case 0x19:
			return PPC_ID_ORIS;

		case 0x1a:
			if (word32 == 0x68000000)
				return PPC_ID_XNOP;
			else
				return PPC_ID_XORI;

		case 0x1b:
			return PPC_ID_XORIS;

		case 0x1c:
			return PPC_ID_ANDI;

		case 0x1d:
			return PPC_ID_ANDIS;

		case 0x1e:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;
			
			return Decode0x1E(word32, decodeFlags);

		case 0x1f:
			return Decode0x1F(word32, decodeFlags);

		case 0x20:
			return PPC_ID_LWZ;

		case 0x21:
			return PPC_ID_LWZU;

		case 0x22:
			return PPC_ID_LBZ;

		case 0x23:
			return PPC_ID_LBZU;

		case 0x24:
			return PPC_ID_STW;

		case 0x25:
			return PPC_ID_STWU;

		case 0x26:
			return PPC_ID_STB;

		case 0x27:
			return PPC_ID_STBU;

		case 0x28:
			return PPC_ID_LHZ;

		case 0x29:
			return PPC_ID_LHZU;

		case 0x2a:
			return PPC_ID_LHA;

		case 0x2b:
			return PPC_ID_LHAU;

		case 0x2c:
			return PPC_ID_STH;

		case 0x2d:
			return PPC_ID_STHU;

		case 0x2e:
			return PPC_ID_LMW;

		case 0x2f:
			return PPC_ID_STMW;

		case 0x30:
			return PPC_ID_LFS;

		case 0x31:
			return PPC_ID_LFSU;

		case 0x32:
			return PPC_ID_LFD;

		case 0x33:
			return PPC_ID_LFDU;

		case 0x34:
			return PPC_ID_STFS;

		case 0x35:
			return PPC_ID_STFSU;

		case 0x36:
			return PPC_ID_STFD;

		case 0x37:
			return PPC_ID_STFDU;

		case 0x3a:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			switch (word32 & 0x3)
			{
				case 0:  return PPC_ID_LD;
				case 1:  return PPC_ID_LDU;
				case 2:  return PPC_ID_LWA;
				default: return PPC_ID_INVALID;
			}

		case 0x3b:
			return Decode0x3B(word32, decodeFlags);

		case 0x3c:
			if ((decodeFlags & DECODE_FLAGS_VSX) != 0)
				return DecodeVsx0x3C(word32, decodeFlags);
			else
				return PPC_ID_INVALID;

		case 0x3d:
			if ((decodeFlags & DECODE_FLAGS_VSX) != 0)
				return DecodeVsx0x3D(word32, decodeFlags);
			else
				return PPC_ID_INVALID;

		case 0x3e:
			if ((decodeFlags & DECODE_FLAGS_PPC64) == 0)
				return PPC_ID_INVALID;

			switch (word32 & 0x3)
			{
				case 0:  return PPC_ID_STD;
				case 1:  return PPC_ID_STDU;
				default: return PPC_ID_INVALID;
			}

		case 0x3f:
			return Decode0x3F(word32, decodeFlags);

		default:
			return PPC_ID_INVALID;
	}
}

static void FillOperands(Instruction* instruction, uint32_t word32, uint64_t address)
{
	switch (instruction->id)
	{
		// instructions with no operands
		case PPC_ID_ATTN:
		case PPC_ID_CP_ABORT:
		case PPC_ID_DCCCI:
		case PPC_ID_ICCCI:
		case PPC_ID_ISYNC:
		case PPC_ID_LWSYNC:
		case PPC_ID_MSGSYNC:
		case PPC_ID_NOP:
		case PPC_ID_PTESYNC:
		case PPC_ID_RFCI:
		case PPC_ID_RFDI:
		case PPC_ID_RFI:
		case PPC_ID_RFID:
		case PPC_ID_RFMCI:
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
			uint32_t xs = GetS(word32) + 32;
			PushRegister(instruction, PPC_OP_REG_VSX_RS, VsxVr(xs));

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

// the hope is to avoid having to manipulate strings in something that's
// somewhat hot, so we create a bunch of lookup tables for each mnemonic

// for "OP" and "OP."
#define DEFINE_SUBMNEM_RC(_identifier, base)    \
	const char* _identifier[2] =            \
	{                                       \
		base,                           \
		base ".",                       \
	};

// for "OP", "OP.", "OPo", and "OPo."
#define DEFINE_SUBMNEM_OE_RC(_identifier, base) \
	const char* _identifier[4] =            \
	{                                       \
		base,                           \
		base ".",                       \
		base "o",                       \
		base "o.",                      \
	};

// for "OP" and "OPl"
#define DEFINE_SUBMNEM_LK(_identifier, base) \
	const char* _identifier[2] =            \
	{                                       \
		base,                           \
		base "l",                       \
	};

// for "OP" and "OPl" and +/- hints
#define DEFINE_SUBMNEM_LK_HINT(_identifier, base) \
	const char* _identifier[8] =            \
	{                                       \
		base,                           \
		base "l",                       \
		base,                           \
		base "l",                       \
		base "-",                       \
		base "l-",                      \
		base "+",                       \
		base "l+",                      \
	};

// for "OP", "OPl", "OPa", and "OPla"
#define DEFINE_SUBMNEM_AA_LK(_identifier, base) \
	const char* _identifier[4] =            \
	{                                       \
		base,                           \
		base "l",                       \
		base "a",                       \
		base "la",                      \
	};

// for "OP", "OPl", "OPa", "OPla" and +/- hints
#define DEFINE_SUBMNEM_AA_LK_HINT(_identifier, base) \
	const char* _identifier[16] =            \
	{                                       \
		base,                           \
		base "l",                       \
		base "a",                       \
		base "la",                      \
		base,                           \
		base "l",                       \
		base "a",                       \
		base "la",                      \
		base "-",                       \
		base "l-",                      \
		base "a-",                      \
		base "la-",                     \
		base "+",                       \
		base "l+",                      \
		base "a+",                      \
		base "la+"                      \
	};

#define DEFINE_SUBMNEM_ROUND2ODD(_identifier, base)    \
	const char* _identifier[2] =            \
	{                                       \
		base,                           \
		base "o",                       \
	};

#define DEFINE_SUBMNEM_INEXACT(_identifier, base)    \
	const char* _identifier[2] =            \
	{                                       \
		base,                           \
		base "x",                       \
	};

DEFINE_SUBMNEM_OE_RC(SubMnemADDx, "add")
DEFINE_SUBMNEM_OE_RC(SubMnemADDCx, "addc")
DEFINE_SUBMNEM_OE_RC(SubMnemADDEx, "adde")
DEFINE_SUBMNEM_RC(SubMnemADDICx, "addic")
DEFINE_SUBMNEM_OE_RC(SubMnemADDMEx, "addme")
DEFINE_SUBMNEM_OE_RC(SubMnemADDZEx, "addze")
DEFINE_SUBMNEM_RC(SubMnemANDx, "and")
DEFINE_SUBMNEM_RC(SubMnemANDCx, "andc")
DEFINE_SUBMNEM_AA_LK(SubMnemBx, "b")
DEFINE_SUBMNEM_AA_LK(SubMnemBCx, "bc")
DEFINE_SUBMNEM_LK(SubMnemBCTRx, "bctr")
DEFINE_SUBMNEM_LK(SubMnemBCCTRx, "bcctr")
DEFINE_SUBMNEM_LK(SubMnemBCLRx, "bclr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBDZx, "bdz")
DEFINE_SUBMNEM_LK_HINT(SubMnemBDZLRx, "bdzlr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBDNZx, "bdnz")
DEFINE_SUBMNEM_LK_HINT(SubMnemBDNZLRx, "bdnzlr")
DEFINE_SUBMNEM_AA_LK(SubMnemBDNZFx, "bdnzf")
DEFINE_SUBMNEM_LK(SubMnemBDNZFLRx, "bdnzflr")
DEFINE_SUBMNEM_AA_LK(SubMnemBDNZTx, "bdnzt")
DEFINE_SUBMNEM_LK(SubMnemBDNZTLRx, "bdnztlr")
DEFINE_SUBMNEM_AA_LK(SubMnemBDZFx, "bdzf")
DEFINE_SUBMNEM_LK(SubMnemBDZFLRx, "bdzflr")
DEFINE_SUBMNEM_LK(SubMnemBDFLRx, "bdzlr")
DEFINE_SUBMNEM_AA_LK(SubMnemBDZTx, "bdzt")
DEFINE_SUBMNEM_LK(SubMnemBDZTLRx, "bdztlr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBEQx, "beq")
DEFINE_SUBMNEM_LK_HINT(SubMnemBEQCTRx, "beqctr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBEQLRx, "beqlr")
DEFINE_SUBMNEM_AA_LK(SubMnemBFx, "bf")
DEFINE_SUBMNEM_AA_LK(SubMnemBFLRx, "bflr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBGEx, "bge")
DEFINE_SUBMNEM_LK_HINT(SubMnemBGECTRx, "bgectr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBGELRx, "bgelr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBGTx, "bgt")
DEFINE_SUBMNEM_LK_HINT(SubMnemBGTCTRx, "bgtctr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBGTLRx, "bgtlr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBLEx, "ble")
DEFINE_SUBMNEM_LK_HINT(SubMnemBLECTRx, "blectr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBLELRx, "blelr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBLTx, "blt")
DEFINE_SUBMNEM_LK_HINT(SubMnemBLTCTRx, "bltctr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBLTLRx, "bltlr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBLRx, "blr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBNEx, "bne")
DEFINE_SUBMNEM_LK_HINT(SubMnemBNECTRx, "bnectr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBNELRx, "bnelr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBNSx, "bns")
DEFINE_SUBMNEM_LK_HINT(SubMnemBNSCTRx, "bnsctr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBNSLRx, "bnslr")
DEFINE_SUBMNEM_AA_LK_HINT(SubMnemBSOx, "bso")
DEFINE_SUBMNEM_LK_HINT(SubMnemBSOCTRx, "bsoctr")
DEFINE_SUBMNEM_LK_HINT(SubMnemBSOLRx, "bsolr")
DEFINE_SUBMNEM_AA_LK(SubMnemBTx, "bt")
DEFINE_SUBMNEM_AA_LK(SubMnemBTLRx, "btlr")
DEFINE_SUBMNEM_RC(SubMnemCLRLDIx, "clrldi")
DEFINE_SUBMNEM_RC(SubMnemCLRLWIx, "clrlwi")
DEFINE_SUBMNEM_RC(SubMnemCLRRWIx, "clrrwi")
DEFINE_SUBMNEM_RC(SubMnemCNTLZDx, "cntlzd")
DEFINE_SUBMNEM_RC(SubMnemCNTLZWx, "cntlzw")
DEFINE_SUBMNEM_RC(SubMnemCNTTZDx, "cnttzd")
DEFINE_SUBMNEM_RC(SubMnemCNTTZWx, "cnttzw")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVDx, "divd")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVDEx, "divde")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVDEUx, "divdeu")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVDUx, "divdu")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVWx, "divw")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVWEx, "divwe")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVWEUx, "divweu")
DEFINE_SUBMNEM_OE_RC(SubMnemDIVWUx, "divwu")
DEFINE_SUBMNEM_RC(SubMnemEQVx, "eqv")
DEFINE_SUBMNEM_RC(SubMnemEXTSBx, "extsb")
DEFINE_SUBMNEM_RC(SubMnemEXTSHx, "extsh")
DEFINE_SUBMNEM_RC(SubMnemEXTSWx, "extsw")
DEFINE_SUBMNEM_RC(SubMnemEXTSWSLIx, "extswsli")
DEFINE_SUBMNEM_RC(SubMnemFABSx, "fabs")
DEFINE_SUBMNEM_RC(SubMnemFADDx, "fadd")
DEFINE_SUBMNEM_RC(SubMnemFADDSx, "fadds")
DEFINE_SUBMNEM_RC(SubMnemFCFIDx, "fcfid")
DEFINE_SUBMNEM_RC(SubMnemFCFIDSx, "fcfids")
DEFINE_SUBMNEM_RC(SubMnemFCFIDUx, "fcfidu")
DEFINE_SUBMNEM_RC(SubMnemFCFIDUSx, "fcfidus")
DEFINE_SUBMNEM_RC(SubMnemFCPSGNx, "fcpsgn")
DEFINE_SUBMNEM_RC(SubMnemFCTIDx, "fctid")
DEFINE_SUBMNEM_RC(SubMnemFCTIDUx, "fctidu")
DEFINE_SUBMNEM_RC(SubMnemFCTIDUZx, "fctiduz")
DEFINE_SUBMNEM_RC(SubMnemFCTIDZx, "fctidz")
DEFINE_SUBMNEM_RC(SubMnemFCTIWx, "fctiw")
DEFINE_SUBMNEM_RC(SubMnemFCTIWUx, "fctiwu")
DEFINE_SUBMNEM_RC(SubMnemFCTIWUZx, "fctiwuz")
DEFINE_SUBMNEM_RC(SubMnemFCTIWZx, "fctiwz")
DEFINE_SUBMNEM_RC(SubMnemFDIVx, "fdiv")
DEFINE_SUBMNEM_RC(SubMnemFDIVSx, "fdivs")
DEFINE_SUBMNEM_RC(SubMnemFMADDx, "fmadd")
DEFINE_SUBMNEM_RC(SubMnemFMADDSx, "fmadds")
DEFINE_SUBMNEM_RC(SubMnemFMRx, "fmr")
DEFINE_SUBMNEM_RC(SubMnemFMSUBx, "fmsub")
DEFINE_SUBMNEM_RC(SubMnemFMSUBSx, "fmsubs")
DEFINE_SUBMNEM_RC(SubMnemFMULx, "fmul")
DEFINE_SUBMNEM_RC(SubMnemFMULSx, "fmuls")
DEFINE_SUBMNEM_RC(SubMnemFNABSx, "fnabs")
DEFINE_SUBMNEM_RC(SubMnemFNEGx, "fneg")
DEFINE_SUBMNEM_RC(SubMnemFNMADDx, "fnmadd")
DEFINE_SUBMNEM_RC(SubMnemFNMADDSx, "fnmadds")
DEFINE_SUBMNEM_RC(SubMnemFNMSUBx, "fnmsub")
DEFINE_SUBMNEM_RC(SubMnemFNMSUBSx, "fnmsubs")
DEFINE_SUBMNEM_RC(SubMnemFREx, "fre")
DEFINE_SUBMNEM_RC(SubMnemFRESx, "fres")
DEFINE_SUBMNEM_RC(SubMnemFRIMx, "frim")
DEFINE_SUBMNEM_RC(SubMnemFRINx, "frin")
DEFINE_SUBMNEM_RC(SubMnemFRIPx, "frip")
DEFINE_SUBMNEM_RC(SubMnemFRIZx, "friz")
DEFINE_SUBMNEM_RC(SubMnemFRSPx, "frsp")
DEFINE_SUBMNEM_RC(SubMnemFRSQRTEx, "frsqrte")
DEFINE_SUBMNEM_RC(SubMnemFRSQRTESx, "frsqrtes")
DEFINE_SUBMNEM_RC(SubMnemFSELx, "fsel")
DEFINE_SUBMNEM_RC(SubMnemFSQRTx, "fsqrt")
DEFINE_SUBMNEM_RC(SubMnemFSQRTSx, "fsqrts")
DEFINE_SUBMNEM_RC(SubMnemFSUBx, "fsub")
DEFINE_SUBMNEM_RC(SubMnemFSUBSx, "fsubs")
DEFINE_SUBMNEM_RC(SubMnemMFFSx, "mffs")
DEFINE_SUBMNEM_RC(SubMnemMTFSB0x, "mtfsb0")
DEFINE_SUBMNEM_RC(SubMnemMTFSB1x, "mtfsb1")
DEFINE_SUBMNEM_RC(SubMnemMTFSFx, "mtfsf")
DEFINE_SUBMNEM_RC(SubMnemMTFSFIx, "mtfsfi")
DEFINE_SUBMNEM_RC(SubMnemMRx, "mr")
DEFINE_SUBMNEM_RC(SubMnemMULHDx, "mulhd")
DEFINE_SUBMNEM_RC(SubMnemMULHDUx, "mulhdu")
DEFINE_SUBMNEM_RC(SubMnemMULHWx, "mulhw")
DEFINE_SUBMNEM_RC(SubMnemMULHWUx, "mulhwu")
DEFINE_SUBMNEM_OE_RC(SubMnemMULLDx, "mulld")
DEFINE_SUBMNEM_OE_RC(SubMnemMULLWx, "mullw")
DEFINE_SUBMNEM_RC(SubMnemNANDx, "nand")
DEFINE_SUBMNEM_OE_RC(SubMnemNEGx, "neg")
DEFINE_SUBMNEM_RC(SubMnemNORx, "nor")
DEFINE_SUBMNEM_RC(SubMnemORx, "or")
DEFINE_SUBMNEM_RC(SubMnemORCx, "orc")
DEFINE_SUBMNEM_RC(SubMnemRLDICLx, "rldicl")
DEFINE_SUBMNEM_RC(SubMnemRLDICRx, "rldicr")
DEFINE_SUBMNEM_RC(SubMnemRLDICx, "rldic")
DEFINE_SUBMNEM_RC(SubMnemRLDIMIx, "rldimi")
DEFINE_SUBMNEM_RC(SubMnemRLDCLx, "rldcl")
DEFINE_SUBMNEM_RC(SubMnemRLDCRx, "rldcr")
DEFINE_SUBMNEM_RC(SubMnemRLWIMIx, "rlwimi")
DEFINE_SUBMNEM_RC(SubMnemRLWINMx, "rlwinm")
DEFINE_SUBMNEM_RC(SubMnemRLWNMx, "rlwnm")
DEFINE_SUBMNEM_RC(SubMnemROTLDx, "rotld")
DEFINE_SUBMNEM_RC(SubMnemROTLDIx, "rotldi")
DEFINE_SUBMNEM_RC(SubMnemROTLWx, "rotlw")
DEFINE_SUBMNEM_RC(SubMnemROTLWIx, "rotlwi")
DEFINE_SUBMNEM_RC(SubMnemSLDx, "sld")
DEFINE_SUBMNEM_RC(SubMnemSLDIx, "sldi")
DEFINE_SUBMNEM_RC(SubMnemSLWx, "slw")
DEFINE_SUBMNEM_RC(SubMnemSLWIx, "slwi")
DEFINE_SUBMNEM_RC(SubMnemSRADx, "srad")
DEFINE_SUBMNEM_RC(SubMnemSRADIx, "sradi")
DEFINE_SUBMNEM_RC(SubMnemSRAWx, "sraw")
DEFINE_SUBMNEM_RC(SubMnemSRAWIx, "srawi")
DEFINE_SUBMNEM_RC(SubMnemSRDx, "srd")
DEFINE_SUBMNEM_RC(SubMnemSRDIx, "srdi")
DEFINE_SUBMNEM_RC(SubMnemSRWx, "srw")
DEFINE_SUBMNEM_RC(SubMnemSRWIx, "srwi")
DEFINE_SUBMNEM_OE_RC(SubMnemSUBFx, "subf")
DEFINE_SUBMNEM_OE_RC(SubMnemSUBFCx, "subfc")
DEFINE_SUBMNEM_OE_RC(SubMnemSUBFEx, "subfe")
DEFINE_SUBMNEM_OE_RC(SubMnemSUBFMEx, "subfme")
DEFINE_SUBMNEM_OE_RC(SubMnemSUBFZEx, "subfze")
DEFINE_SUBMNEM_RC(SubMnemXORx, "xor")

// ALTIVEC MNEMONICS
DEFINE_SUBMNEM_RC(SubMnemVCMPBFPx, "vcmpbfp");
DEFINE_SUBMNEM_RC(SubMnemVCMPEQFPx, "vcmpeqfp");
DEFINE_SUBMNEM_RC(SubMnemVCMPEQUBx, "vcmpequb");
DEFINE_SUBMNEM_RC(SubMnemVCMPEQUDx, "vcmpequd");
DEFINE_SUBMNEM_RC(SubMnemVCMPEQUHx, "vcmpequh");
DEFINE_SUBMNEM_RC(SubMnemVCMPEQUWx, "vcmpequw");
DEFINE_SUBMNEM_RC(SubMnemVCMPGEFPx, "vcmpgefp");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTFPx, "vcmpgtfp");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTSBx, "vcmpgtsb");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTSDx, "vcmpgtsd");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTSHx, "vcmpgtsh");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTSWx, "vcmpgtsw");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTUBx, "vcmpgtub");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTUDx, "vcmpgtud");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTUHx, "vcmpgtuh");
DEFINE_SUBMNEM_RC(SubMnemVCMPGTUWx, "vcmpgtuw");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEBx, "vcmpneb");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEHx, "vcmpneh");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEWx, "vcmpnew");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEZBx, "vcmpnezb");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEZHx, "vcmpnezh");
DEFINE_SUBMNEM_RC(SubMnemVCMPNEZWx, "vcmpnezw");

// VSX MNEMONICS
DEFINE_SUBMNEM_RC(SubMnemXVCMPEQDPx, "xvcmpeqdp");
DEFINE_SUBMNEM_RC(SubMnemXVCMPEQSPx, "xvcmpeqsp");
DEFINE_SUBMNEM_RC(SubMnemXVCMPGEDPx, "xvcmpgedp");
DEFINE_SUBMNEM_RC(SubMnemXVCMPGESPx, "xvcmpgesp");
DEFINE_SUBMNEM_RC(SubMnemXVCMPGTDPx, "xvcmpgtdp");
DEFINE_SUBMNEM_RC(SubMnemXVCMPGTSPx, "xvcmpgtsp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSADDQPx, "xsaddqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSCVQPDPx, "xscvqpdp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSDIVQPx, "xsdivqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSMADDQPx, "xsmaddqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSMULQPx, "xsmulqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSMSUBQPx, "xsmsubqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSNMADDQPx, "xsnmaddqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSNMSUBQPx, "xsnmsubqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSSQRTQPx, "xssqrtqp");
DEFINE_SUBMNEM_ROUND2ODD(SubMnemXSSUBQPx, "xssubqp");
DEFINE_SUBMNEM_INEXACT(SubMnemXSRQPIx, "xsrqpi");

static const char* RcMnemonic(const Instruction* instruction, const char* names[2])
{
	return names[instruction->flags.rc];
}

static const char* OeRcMnemonic(const Instruction* instruction, const char* names[4])
{
	return names[2*instruction->flags.oe + instruction->flags.rc];
}

static const char* LkMnemonic(const Instruction* instruction, const char* names[2])
{
	return names[instruction->flags.lk];
}

static const char* LkHintMnemonic(const Instruction* instruction, const char* names[8])
{
	return names[2*instruction->flags.branchLikelyHint + instruction->flags.lk];
}

static const char* AaLkMnemonic(const Instruction* instruction, const char* names[4])
{
	return names[2*instruction->flags.aa + instruction->flags.lk];
}

static const char* AaLkHintMnemonic(const Instruction* instruction, const char* names[16])
{
	return names[4*instruction->flags.branchLikelyHint + 2*instruction->flags.aa + instruction->flags.lk];
}

static const char* Round2OddMnemonic(const Instruction* instruction, const char* names[2])
{
	return names[instruction->flags.round2odd];
}

static const char* InexactMnemonic(const Instruction* instruction, const char* names[2])
{
	return names[instruction->flags.inexact];
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

const char* GetMnemonic(const Instruction* instruction)
{
	unsigned int index;

	switch (instruction->id)
	{
		case PPC_ID_ADDx: return OeRcMnemonic(instruction, SubMnemADDx);
		case PPC_ID_ADDCx: return OeRcMnemonic(instruction, SubMnemADDCx);
		case PPC_ID_ADDEx: return OeRcMnemonic(instruction, SubMnemADDEx);
		case PPC_ID_ADDI: return "addi";
		case PPC_ID_ADDICx: return RcMnemonic(instruction, SubMnemADDICx);
		case PPC_ID_ADDIS: return "addis";
		case PPC_ID_ADDMEx: return OeRcMnemonic(instruction, SubMnemADDMEx);
		case PPC_ID_ADDPCIS: return "addpcis";
		case PPC_ID_ADDZEx: return OeRcMnemonic(instruction, SubMnemADDZEx);
		case PPC_ID_ANDx: return RcMnemonic(instruction, SubMnemANDx);
		case PPC_ID_ANDCx: return RcMnemonic(instruction, SubMnemANDCx);
		case PPC_ID_ANDI: return "andi.";
		case PPC_ID_ANDIS: return "andis.";
		case PPC_ID_ATTN: return "attn";
		case PPC_ID_Bx: return AaLkMnemonic(instruction, SubMnemBx);
		case PPC_ID_BCx:
		{
			uint32_t bo = instruction->operands[0].uimm;
			uint32_t bi = instruction->operands[1].uimm;

			const char** mnemonics = NULL;
			const char** mnemonicsHint = NULL;

			// mask away the "y" bit
			switch (bo & 0x1e)
			{
				case 0:
					mnemonics = SubMnemBDNZFx;
					break;

				case 2:
					mnemonics = SubMnemBDZFx;
					break;

				case 4:
				case 6:
					switch (bi & 0x3)
					{
						case 0:
							mnemonicsHint = SubMnemBGEx;
							break;
						case 1:
							mnemonicsHint = SubMnemBLEx;
							break;
						case 2:
							mnemonicsHint = SubMnemBNEx;
							break;
						case 3:
							mnemonicsHint = SubMnemBNSx;
							break;

						// should be unreachable
						default:
							return NULL;
					}

					break;

				case 8:
					mnemonics = SubMnemBDNZTx;
					break;

				case 10:
					mnemonics = SubMnemBDZTx;
					break;

				case 12:
				case 14:
					switch (bi & 0x3)
					{
						case 0:
						       mnemonicsHint = SubMnemBLTx;
						       break;

						case 1:
						       mnemonicsHint = SubMnemBGTx;
						       break;

						case 2:
						       mnemonicsHint = SubMnemBEQx;
						       break;

						case 3:
						       mnemonicsHint = SubMnemBSOx;
						       break;

						// should be unreachable
						default:
						       return NULL;
					}
					break;

				// technically these aren't terribly well defined
				// when BI != 0, since these BOs don't involve
				// a condition bit to test in BI to test against
				case 16:
				case 24:
					mnemonicsHint = SubMnemBDNZx;
					break;

				// these represent "branch always" in the BO field, so it's
				// not super clear why these disassemble to bdnz
				case 20:
				case 28:
					 mnemonicsHint = SubMnemBDNZx;
					 break;

				case 18:
				case 22:
				case 26:
					mnemonicsHint = SubMnemBDZx;
					break;

				// these represent "branch always" in the BO field, so it's
				// not super clear why these disassemble to bdz
				case 30:
					mnemonicsHint = SubMnemBDZx;
					break;

				default:
					mnemonics = SubMnemBCx;
			}

			if (mnemonicsHint)
				return AaLkHintMnemonic(instruction, mnemonicsHint);

			if (mnemonics)
				return AaLkMnemonic(instruction, mnemonics);

			// should be unreachable
			return NULL;
		}

		case PPC_ID_BCCTRx:
		{
			uint32_t bo = instruction->operands[0].uimm;
			uint32_t bi = instruction->operands[1].uimm;

			// mask away the "y" bit
			switch (bo & 0x1e)
			{
				case 4:
				case 6:
					switch (bi & 0x3)
					{
						case 0: return LkHintMnemonic(instruction, SubMnemBGECTRx);
						case 1: return LkHintMnemonic(instruction, SubMnemBLECTRx);
						case 2: return LkHintMnemonic(instruction, SubMnemBNECTRx);
						case 3: return LkHintMnemonic(instruction, SubMnemBNSCTRx);

						// should be unreachable
						default: return NULL;
					}

					break;

				case 12:
				case 14:
					switch (bi & 0x3)
					{
						case 0: return LkHintMnemonic(instruction, SubMnemBLTCTRx);
						case 1: return LkHintMnemonic(instruction, SubMnemBGTCTRx);
						case 2: return LkHintMnemonic(instruction, SubMnemBEQCTRx);
						case 3: return LkHintMnemonic(instruction, SubMnemBSOCTRx);

						// should be unreachable
						default: return NULL;
					}

					break;

				case 20:
					return LkMnemonic(instruction, SubMnemBCTRx);

				default:
					return LkMnemonic(instruction, SubMnemBCCTRx);
			}
		}

		case PPC_ID_BCLRx:
		{
			uint32_t bo = instruction->operands[0].uimm;
			uint32_t bi = instruction->operands[1].uimm;

			// mask away the "y" bit
			switch (bo & 0x1e)
			{
				case 0:
					return LkMnemonic(instruction, SubMnemBDNZFLRx);

				case 2:
					return LkMnemonic(instruction, SubMnemBDZFLRx);

				case 4:
				case 6:
					switch (bi & 0x3)
					{
						case 0: return LkHintMnemonic(instruction, SubMnemBGELRx);
						case 1: return LkHintMnemonic(instruction, SubMnemBLELRx);
						case 2: return LkHintMnemonic(instruction, SubMnemBNELRx);
						case 3: return LkHintMnemonic(instruction, SubMnemBNSLRx);

						// should be unreachable
						default: return NULL;
					}

				case 8:
					return LkMnemonic(instruction, SubMnemBDNZTLRx);

				case 10:
					return LkMnemonic(instruction, SubMnemBDZTLRx);

				case 12:
				case 14:
					switch (bi & 0x3)
					{
						case 0: return LkHintMnemonic(instruction, SubMnemBLTLRx);
						case 1: return LkHintMnemonic(instruction, SubMnemBGTLRx);
						case 2: return LkHintMnemonic(instruction, SubMnemBEQLRx);
						case 3: return LkHintMnemonic(instruction, SubMnemBSOLRx);

						// should be unreachable
						default: return NULL;
					}

				// technically these aren't terribly well defined
				// when BI != 0, since these BOs don't involve
				// a condition bit to test in BI to test against
				case 16:
				case 24:
					return LkHintMnemonic(instruction, SubMnemBDNZLRx);

				case 18:
				case 26:
					return LkHintMnemonic(instruction, SubMnemBDZLRx);

				case 20:
					return LkHintMnemonic(instruction, SubMnemBLRx);

				default:
					return LkMnemonic(instruction, SubMnemBCLRx);
			}
		}

		case PPC_ID_BPERMD: return "bpermd";
		case PPC_ID_CLRBHRB: return "clrbhrb";
		case PPC_ID_CLRLDIx: return RcMnemonic(instruction, SubMnemCLRLDIx);
		case PPC_ID_CLRLWIx: return RcMnemonic(instruction, SubMnemCLRLWIx);
		case PPC_ID_CLRRWIx: return RcMnemonic(instruction, SubMnemCLRRWIx);
		case PPC_ID_CMPB: return "cmpb";
		case PPC_ID_CMPD: return "cmpd";
		case PPC_ID_CMPDI: return "cmpdi";
		case PPC_ID_CMPEQB: return "cmpeqb";
		case PPC_ID_CMPRB: return "cmprb";
		case PPC_ID_CMPW: return "cmpw";
		case PPC_ID_CMPWI: return "cmpwi";
		case PPC_ID_CMPLD: return "cmpld";
		case PPC_ID_CMPLDI: return "cmpldi";
		case PPC_ID_CMPLW: return "cmplw";
		case PPC_ID_CMPLWI: return "cmplwi";
		case PPC_ID_CNTLZDx: return RcMnemonic(instruction, SubMnemCNTLZDx);
		case PPC_ID_CNTLZWx: return RcMnemonic(instruction, SubMnemCNTLZWx);
		case PPC_ID_CNTTZDx: return RcMnemonic(instruction, SubMnemCNTTZDx);
		case PPC_ID_CNTTZWx: return RcMnemonic(instruction, SubMnemCNTTZWx);
		case PPC_ID_COPY: return "copy";
		case PPC_ID_CP_ABORT: return "cp_abort";
		case PPC_ID_CRAND: return "crand";
		case PPC_ID_CRANDC: return "crandc";
		case PPC_ID_CRCLR: return "crclr";
		case PPC_ID_CREQV: return "creqv";
		case PPC_ID_CRMOVE: return "crmove";
		case PPC_ID_CRNAND: return "crnand";
		case PPC_ID_CRNOR: return "crnor";
		case PPC_ID_CRNOT: return "crnot";
		case PPC_ID_CROR: return "cror";
		case PPC_ID_CRORC: return "crorc";
		case PPC_ID_CRSET: return "crset";
		case PPC_ID_CRXOR: return "crxor";
		case PPC_ID_DARN: return "darn";
		case PPC_ID_DCBA: return "dcba";
		case PPC_ID_DCBF: return "dcbf";
		case PPC_ID_DCBFEP: return "dcbfep";
		case PPC_ID_DCBFL: return "dcbfl";
		case PPC_ID_DCBFLP: return "dcbflp";
		case PPC_ID_DCBI: return "dcbi";
		case PPC_ID_DCBST: return "dcbst";
		case PPC_ID_DCBSTEP: return "dcbstep";
		case PPC_ID_DCBT: return "dcbt";
		case PPC_ID_DCBTT: return "dcbtt";
		case PPC_ID_DCBTEP: return "dcbtep";
		case PPC_ID_DCBTST: return "dcbtst";
		case PPC_ID_DCBTSTEP: return "dcbtstep";
		case PPC_ID_DCBTSTT: return "dcbtstt";
		case PPC_ID_DCBZ: return "dcbz";
		case PPC_ID_DCBZEP: return "dcbzep";
		case PPC_ID_DCBZL: return "dcbzl";
		case PPC_ID_DCCCI: return "dccci";
		case PPC_ID_DCI: return "dci";
		case PPC_ID_DIVDx: return OeRcMnemonic(instruction, SubMnemDIVDx);
		case PPC_ID_DIVDEx: return OeRcMnemonic(instruction, SubMnemDIVDEx);
		case PPC_ID_DIVDEUx: return OeRcMnemonic(instruction, SubMnemDIVDEUx);
		case PPC_ID_DIVDUx: return OeRcMnemonic(instruction, SubMnemDIVDUx);
		case PPC_ID_DIVWx: return OeRcMnemonic(instruction, SubMnemDIVWx);
		case PPC_ID_DIVWEx: return OeRcMnemonic(instruction, SubMnemDIVWEx);
		case PPC_ID_DIVWEUx: return OeRcMnemonic(instruction, SubMnemDIVWEUx);
		case PPC_ID_DIVWUx: return OeRcMnemonic(instruction, SubMnemDIVWUx);
		case PPC_ID_ECIWX: return "eciwx";
		case PPC_ID_ECOWX: return "ecowx";
		case PPC_ID_EIEIO: return "eieio";
		case PPC_ID_EQVx: return RcMnemonic(instruction, SubMnemEQVx);
		case PPC_ID_EXTSBx: return RcMnemonic(instruction, SubMnemEXTSBx);
		case PPC_ID_EXTSHx: return RcMnemonic(instruction, SubMnemEXTSHx);
		case PPC_ID_EXTSWx: return RcMnemonic(instruction, SubMnemEXTSWx);
		case PPC_ID_EXTSWSLIx: return RcMnemonic(instruction, SubMnemEXTSWSLIx);
		case PPC_ID_FABSx: return RcMnemonic(instruction, SubMnemFABSx);
		case PPC_ID_FADDx: return RcMnemonic(instruction, SubMnemFADDx);
		case PPC_ID_FADDSx: return RcMnemonic(instruction, SubMnemFADDSx);
		case PPC_ID_FCFIDx: return RcMnemonic(instruction, SubMnemFCFIDx);
		case PPC_ID_FCFIDSx: return RcMnemonic(instruction, SubMnemFCFIDSx);
		case PPC_ID_FCFIDUx: return RcMnemonic(instruction, SubMnemFCFIDUx);
		case PPC_ID_FCFIDUSx: return RcMnemonic(instruction, SubMnemFCFIDUSx);
		case PPC_ID_FCMPO: return "fcmpo";
		case PPC_ID_FCMPU: return "fcmpu";
		case PPC_ID_FCPSGNx: return RcMnemonic(instruction, SubMnemFCPSGNx);
		case PPC_ID_FCTIDx: return RcMnemonic(instruction, SubMnemFCTIDx);
		case PPC_ID_FCTIDUx: return RcMnemonic(instruction, SubMnemFCTIDUx);
		case PPC_ID_FCTIDUZx: return RcMnemonic(instruction, SubMnemFCTIDUZx);
		case PPC_ID_FCTIDZx: return RcMnemonic(instruction, SubMnemFCTIDZx);
		case PPC_ID_FCTIWx: return RcMnemonic(instruction, SubMnemFCTIWx);
		case PPC_ID_FCTIWUx: return RcMnemonic(instruction, SubMnemFCTIWUx);
		case PPC_ID_FCTIWUZx: return RcMnemonic(instruction, SubMnemFCTIWUZx);
		case PPC_ID_FCTIWZx: return RcMnemonic(instruction, SubMnemFCTIWZx);
		case PPC_ID_FDIVx: return RcMnemonic(instruction, SubMnemFDIVx);
		case PPC_ID_FDIVSx: return RcMnemonic(instruction, SubMnemFDIVSx);
		case PPC_ID_FMADDx: return RcMnemonic(instruction, SubMnemFMADDx);
		case PPC_ID_FMADDSx: return RcMnemonic(instruction, SubMnemFMADDSx);
		case PPC_ID_FMRx: return RcMnemonic(instruction, SubMnemFMRx);
		case PPC_ID_FMSUBx: return RcMnemonic(instruction, SubMnemFMSUBx);
		case PPC_ID_FMSUBSx: return RcMnemonic(instruction, SubMnemFMSUBSx);
		case PPC_ID_FMULx: return RcMnemonic(instruction, SubMnemFMULx);
		case PPC_ID_FMULSx: return RcMnemonic(instruction, SubMnemFMULSx);
		case PPC_ID_FNABSx: return RcMnemonic(instruction, SubMnemFNABSx);
		case PPC_ID_FNEGx: return RcMnemonic(instruction, SubMnemFNEGx);
		case PPC_ID_FNMADDx: return RcMnemonic(instruction, SubMnemFNMADDx);
		case PPC_ID_FNMADDSx: return RcMnemonic(instruction, SubMnemFNMADDSx);
		case PPC_ID_FNMSUBx: return RcMnemonic(instruction, SubMnemFNMSUBx);
		case PPC_ID_FNMSUBSx: return RcMnemonic(instruction, SubMnemFNMSUBSx);
		case PPC_ID_FREx: return RcMnemonic(instruction, SubMnemFREx);
		case PPC_ID_FRESx: return RcMnemonic(instruction, SubMnemFRESx);
		case PPC_ID_FRIMx: return RcMnemonic(instruction, SubMnemFRIMx);
		case PPC_ID_FRINx: return RcMnemonic(instruction, SubMnemFRINx);
		case PPC_ID_FRIPx: return RcMnemonic(instruction, SubMnemFRIPx);
		case PPC_ID_FRIZx: return RcMnemonic(instruction, SubMnemFRIZx);
		case PPC_ID_FRSPx:  return RcMnemonic(instruction, SubMnemFRSPx);
		case PPC_ID_FRSQRTEx:  return RcMnemonic(instruction, SubMnemFRSQRTEx);
		case PPC_ID_FRSQRTESx:  return RcMnemonic(instruction, SubMnemFRSQRTESx);
		case PPC_ID_FSELx:  return RcMnemonic(instruction, SubMnemFSELx);
		case PPC_ID_FSQRTx:  return RcMnemonic(instruction, SubMnemFSQRTx);
		case PPC_ID_FSQRTSx:  return RcMnemonic(instruction, SubMnemFSQRTSx);
		case PPC_ID_FSUBx:  return RcMnemonic(instruction, SubMnemFSUBx);
		case PPC_ID_FSUBSx:  return RcMnemonic(instruction, SubMnemFSUBSx);
		case PPC_ID_FTDIV: return "ftdiv";
		case PPC_ID_FTSQRT: return "ftsqrt";
		case PPC_ID_ICBI: return "icbi";
		case PPC_ID_ICBIEP: return "icbiep";
		case PPC_ID_ICBLC: return "icblc";
		case PPC_ID_ICBLQ: return "icblq.";
		case PPC_ID_ICBT: return "icbt";
		case PPC_ID_ICBTLS: return "icbtls";
		case PPC_ID_ICCCI: return "iccci";
		case PPC_ID_ICI: return "ici";
		case PPC_ID_ISEL: return "isel";
		case PPC_ID_ISYNC: return "isync";
		case PPC_ID_LBARX: return "lbarx";
		case PPC_ID_LBEPX: return "lbepx";
		case PPC_ID_LBZ: return "lbz";
		case PPC_ID_LBZCIX: return "lbzcix";
		case PPC_ID_LBZU: return "lbzu";
		case PPC_ID_LBZUX: return "lbzux";
		case PPC_ID_LBZX: return "lbzx";
		case PPC_ID_LDARX: return "ldarx";
		case PPC_ID_LDAT: return "ldat";
		case PPC_ID_LDBRX: return "ldbrx";
		case PPC_ID_LDCIX: return "ldcix";
		case PPC_ID_LD: return "ld";
		case PPC_ID_LDU: return "ldu";
		case PPC_ID_LDUX: return "ldux";
		case PPC_ID_LDX: return "ldx";
		case PPC_ID_LFD: return "lfd";
		case PPC_ID_LFDEPX: return "lfdepx";
		case PPC_ID_LFDU: return "lfdu";
		case PPC_ID_LFDUX: return "lfdux";
		case PPC_ID_LFDX: return "lfdx";
		case PPC_ID_LFIWAX: return "lfiwax";
		case PPC_ID_LFIWZX: return "lfiwzx";
		case PPC_ID_LFS: return "lfs";
		case PPC_ID_LFSU: return "lfsu";
		case PPC_ID_LFSUX: return "lfsux";
		case PPC_ID_LFSX: return "lfsx";
		case PPC_ID_LHA: return "lha";
		case PPC_ID_LHARX: return "lharx";
		case PPC_ID_LHAU: return "lhau";
		case PPC_ID_LHAUX: return "lhaux";
		case PPC_ID_LHAX: return "lhax";
		case PPC_ID_LHBRX: return "lhbrx";
		case PPC_ID_LHEPX: return "lhepx";
		case PPC_ID_LHZ: return "lhz";
		case PPC_ID_LHZCIX: return "lhzcix";
		case PPC_ID_LHZU: return "lhzu";
		case PPC_ID_LHZUX: return "lhzux";
		case PPC_ID_LHZX: return "lhzx";
		case PPC_ID_LI: return "li";
		case PPC_ID_LIS: return "lis";
		case PPC_ID_LMW: return "lmw";
		case PPC_ID_LNIA: return "lnia";
		case PPC_ID_LSWI: return "lswi";
		case PPC_ID_LSWX: return "lswx";
		case PPC_ID_LWA: return "lwa";
		case PPC_ID_LWAT: return "lwat";
		case PPC_ID_LWAX: return "lwax";
		case PPC_ID_LWARX: return "lwarx";
		case PPC_ID_LWAUX: return "lwaux";
		case PPC_ID_LWBRX: return "lwbrx";
		case PPC_ID_LWEPX: return "lwepx";
		case PPC_ID_LWSYNC: return "lwsync";
		case PPC_ID_LWZ: return "lwz";
		case PPC_ID_LWZCIX: return "lwzcix";
		case PPC_ID_LWZU: return "lwzu";
		case PPC_ID_LWZUX: return "lwzux";
		case PPC_ID_LWZX: return "lwzx";
		case PPC_ID_MBAR: return "mbar";
		case PPC_ID_MCRF: return "mcrf";
		case PPC_ID_MCRFS: return "mcrfs";
		case PPC_ID_MCRXR: return "mcrxr";
		case PPC_ID_MCRXRX: return "mcrxrx";
		case PPC_ID_MFBHRBE: return "mfbhrbe";
		case PPC_ID_MFBR0: return "mfbr0";
		case PPC_ID_MFBR1: return "mfbr1";
		case PPC_ID_MFBR2: return "mfbr2";
		case PPC_ID_MFBR3: return "mfbr3";
		case PPC_ID_MFBR4: return "mfbr4";
		case PPC_ID_MFBR5: return "mfbr5";
		case PPC_ID_MFBR6: return "mfbr6";
		case PPC_ID_MFBR7: return "mfbr7";
		case PPC_ID_MFCR: return "mfcr";
		case PPC_ID_MFCTR: return "mfctr";
		case PPC_ID_MFDCR: return "mfdcr";
		case PPC_ID_MFDCRUX: return "mfdcrux";
		case PPC_ID_MFDCRX: return "mfdcrx";
		case PPC_ID_MFFSx: return RcMnemonic(instruction, SubMnemMFFSx);
		case PPC_ID_MFFSCDRN: return "mffscdrn";
		case PPC_ID_MFFSCDRNI: return "mffscdrni";
		case PPC_ID_MFFSCE: return "mffsce";
		case PPC_ID_MFFSCRN: return "mffscrn";
		case PPC_ID_MFFSCRNI: return "mffscrni";
		case PPC_ID_MFFSL: return "mffsl";
		case PPC_ID_MFLR: return "mflr";
		case PPC_ID_MFMSR: return "mfmsr";
		case PPC_ID_MFOCRF: return "mfocrf";
		case PPC_ID_MFPMR: return "mfpmr";
		case PPC_ID_MFSPR: return "mfspr";
		case PPC_ID_MFSR: return "mfsr";
		case PPC_ID_MFSRIN: return "mfsrin";
		case PPC_ID_MFTB: return "mftb";
		case PPC_ID_MFTBU: return "mftbu";
		case PPC_ID_MFXER: return "mfxer";
		case PPC_ID_MRx: return RcMnemonic(instruction, SubMnemMRx);
		case PPC_ID_MSGSYNC: return "msgsync";
		case PPC_ID_MTAMR: return "mtamr";
		case PPC_ID_MTBR0: return "mtbr0";
		case PPC_ID_MTBR1: return "mtbr1";
		case PPC_ID_MTBR2: return "mtbr2";
		case PPC_ID_MTBR3: return "mtbr3";
		case PPC_ID_MTBR4: return "mtbr4";
		case PPC_ID_MTBR5: return "mtbr5";
		case PPC_ID_MTBR6: return "mtbr6";
		case PPC_ID_MTBR7: return "mtbr7";
		case PPC_ID_MTCRF: return "mtcrf";
		case PPC_ID_MTCTR: return "mtctr";
		case PPC_ID_MTDCR: return "mtdcr";
		case PPC_ID_MTDCRUX: return "mtdcrux";
		case PPC_ID_MTDCRX: return "mtdcrx";
		case PPC_ID_MTFSB0x: return RcMnemonic(instruction, SubMnemMTFSB0x);
		case PPC_ID_MTFSB1x: return RcMnemonic(instruction, SubMnemMTFSB1x);
		case PPC_ID_MTFSFx: return RcMnemonic(instruction, SubMnemMTFSFx);
		case PPC_ID_MTFSFIx: return RcMnemonic(instruction, SubMnemMTFSFIx);
		case PPC_ID_MODSD: return "modsd";
		case PPC_ID_MODSW: return "modsw";
		case PPC_ID_MODUD: return "modud";
		case PPC_ID_MODUW: return "moduw";
		case PPC_ID_MTLR: return "mtlr";
		case PPC_ID_MTMSR: return "mtmsr";
		case PPC_ID_MTMSRD: return "mtmsrd";
		case PPC_ID_MTOCRF: return "mtocrf";
		case PPC_ID_MTPMR: return "mtpmr";
		case PPC_ID_MTSPR: return "mtspr";
		case PPC_ID_MTSR: return "mtsr";
		case PPC_ID_MTSRIN: return "mtsrin";
		case PPC_ID_MTXER: return "mtxer";
		case PPC_ID_MULHDx: return RcMnemonic(instruction, SubMnemMULHDx);
		case PPC_ID_MULHDUx: return RcMnemonic(instruction, SubMnemMULHDUx);
		case PPC_ID_MULHWx: return RcMnemonic(instruction, SubMnemMULHWx);
		case PPC_ID_MULHWUx: return RcMnemonic(instruction, SubMnemMULHWUx);
		case PPC_ID_MULLI: return "mulli";
		case PPC_ID_MULLDx: return OeRcMnemonic(instruction, SubMnemMULLDx);
		case PPC_ID_MULLWx: return OeRcMnemonic(instruction, SubMnemMULLWx);
		case PPC_ID_NANDx: return RcMnemonic(instruction, SubMnemNANDx);
		case PPC_ID_NEGx: return OeRcMnemonic(instruction, SubMnemNEGx);
		case PPC_ID_NOP: return "nop";
		case PPC_ID_NORx: return RcMnemonic(instruction, SubMnemNORx);
		case PPC_ID_ORx: return RcMnemonic(instruction, SubMnemORx);
		case PPC_ID_ORCx: return RcMnemonic(instruction, SubMnemORCx);
		case PPC_ID_ORI: return "ori";
		case PPC_ID_ORIS: return "oris";
		case PPC_ID_PASTE: return "paste.";
		case PPC_ID_POPCNTB: return "popcntb";
		case PPC_ID_POPCNTD: return "popcntd";
		case PPC_ID_POPCNTW: return "popcntw";
		case PPC_ID_PTESYNC: return "ptesync";
		case PPC_ID_RFCI: return "rfci";
		case PPC_ID_RFDI: return "rfdi";
		case PPC_ID_RFI: return "rfi";
		case PPC_ID_RFID: return "rfid";
		case PPC_ID_RFMCI: return "rfmci";
		case PPC_ID_RLDICLx: return RcMnemonic(instruction, SubMnemRLDICLx);
		case PPC_ID_RLDICRx: return RcMnemonic(instruction, SubMnemRLDICRx);
		case PPC_ID_RLDICx: return RcMnemonic(instruction, SubMnemRLDICx);
		case PPC_ID_RLDIMIx: return RcMnemonic(instruction, SubMnemRLDIMIx);
		case PPC_ID_RLDCLx: return RcMnemonic(instruction, SubMnemRLDCLx);
		case PPC_ID_RLDCRx: return RcMnemonic(instruction, SubMnemRLDCRx);
		case PPC_ID_RLWIMIx: return RcMnemonic(instruction, SubMnemRLWIMIx);
		case PPC_ID_RLWINMx: return RcMnemonic(instruction, SubMnemRLWINMx);
		case PPC_ID_RLWNMx: return RcMnemonic(instruction, SubMnemRLWNMx);
		case PPC_ID_ROTLDx: return RcMnemonic(instruction, SubMnemROTLDx);
		case PPC_ID_ROTLDIx: return RcMnemonic(instruction, SubMnemROTLDIx);
		case PPC_ID_ROTLWx: return RcMnemonic(instruction, SubMnemROTLWx);
		case PPC_ID_ROTLWIx: return RcMnemonic(instruction, SubMnemROTLWIx);
		case PPC_ID_SC: return "sc";
		case PPC_ID_SETB: return "setb";
		case PPC_ID_SLBIA: return "slbia";
		case PPC_ID_SLBIE: return "slbie";
		case PPC_ID_SLBIEG: return "slbieg";
		case PPC_ID_SLBMFEE: return "slbmfee";
		case PPC_ID_SLBMFEV: return "slbmfev";
		case PPC_ID_SLBMTE: return "slbmte";
		case PPC_ID_SLBSYNC: return "slbsync";
		case PPC_ID_SLDx: return RcMnemonic(instruction, SubMnemSLDx);
		case PPC_ID_SLDIx: return RcMnemonic(instruction, SubMnemSLDIx);
		case PPC_ID_SLWx: return RcMnemonic(instruction, SubMnemSLWx);
		case PPC_ID_SLWIx: return RcMnemonic(instruction, SubMnemSLWIx);
		case PPC_ID_SRADx: return RcMnemonic(instruction, SubMnemSRADx);
		case PPC_ID_SRADIx: return RcMnemonic(instruction, SubMnemSRADIx);
		case PPC_ID_SRAWx: return RcMnemonic(instruction, SubMnemSRAWx);
		case PPC_ID_SRAWIx: return RcMnemonic(instruction, SubMnemSRAWIx);
		case PPC_ID_SRDx: return RcMnemonic(instruction, SubMnemSRDx);
		case PPC_ID_SRDIx: return RcMnemonic(instruction, SubMnemSRDIx);
		case PPC_ID_SRWx: return RcMnemonic(instruction, SubMnemSRWx);
		case PPC_ID_SRWIx: return RcMnemonic(instruction, SubMnemSRWIx);
		case PPC_ID_STB: return "stb";
		case PPC_ID_STBCIX: return "stbcix";
		case PPC_ID_STBCX: return "stbcx.";
		case PPC_ID_STBEPX: return "stbepx";
		case PPC_ID_STBU: return "stbu";
		case PPC_ID_STBUX: return "stbux";
		case PPC_ID_STBX: return "stbx";
		case PPC_ID_STD: return "std";
		case PPC_ID_STDAT: return "stdat";
		case PPC_ID_STDBRX: return "stdbrx";
		case PPC_ID_STDCIX: return "stdcix";
		case PPC_ID_STDCX: return "stdcx.";
		case PPC_ID_STDEPX: return "stdepx";
		case PPC_ID_STDU: return "stdu";
		case PPC_ID_STDUX: return "stdux";
		case PPC_ID_STDX: return "stdx";
		case PPC_ID_STFD: return "stfd";
		case PPC_ID_STFDEPX: return "stfdepx";
		case PPC_ID_STFDU: return "stfdu";
		case PPC_ID_STFDUX: return "stfdux";
		case PPC_ID_STFDX: return "stfdx";
		case PPC_ID_STFIWX: return "stfiwx";
		case PPC_ID_STFS: return "stfs";
		case PPC_ID_STFSU: return "stfsu";
		case PPC_ID_STFSUX: return "stfsux";
		case PPC_ID_STFSX: return "stfsx";
		case PPC_ID_STH: return "sth";
		case PPC_ID_STHBRX: return "sthbrx";
		case PPC_ID_STHCIX: return "sthcix";
		case PPC_ID_STHCX: return "sthcx.";
		case PPC_ID_STHEPX: return "sthepx";
		case PPC_ID_STHU: return "sthu";
		case PPC_ID_STHUX: return "sthux";
		case PPC_ID_STHX: return "sthx";
		case PPC_ID_STMW: return "stmw";
		case PPC_ID_STSWI: return "stswi";
		case PPC_ID_STSWX: return "stswx";
		case PPC_ID_STW: return "stw";
		case PPC_ID_STWAT: return "stwat";
		case PPC_ID_STWBRX: return "stwbrx";
		case PPC_ID_STWCIX: return "stwcix";
		case PPC_ID_STWCX: return "stwcx.";
		case PPC_ID_STWEPX: return "stwepx";
		case PPC_ID_STWU: return "stwu";
		case PPC_ID_STWUX: return "stwux";
		case PPC_ID_STWX: return "stwx";
		case PPC_ID_SUBFx: return OeRcMnemonic(instruction, SubMnemSUBFx);
		case PPC_ID_SUBFCx: return OeRcMnemonic(instruction, SubMnemSUBFCx);
		case PPC_ID_SUBFEx: return OeRcMnemonic(instruction, SubMnemSUBFEx);
		case PPC_ID_SUBFIC: return "subfic";
		case PPC_ID_SUBFMEx: return OeRcMnemonic(instruction, SubMnemSUBFMEx);
		case PPC_ID_SUBFZEx: return OeRcMnemonic(instruction, SubMnemSUBFZEx);
		case PPC_ID_SYNC: return "sync";
		case PPC_ID_TABORT: return "tabort.";
		case PPC_ID_TABORTDC: return "tabortdc.";
		case PPC_ID_TABORTDCI: return "tabortdci.";
		case PPC_ID_TABORTWC: return "tabortwc.";
		case PPC_ID_TABORTWCI: return "tabortwci.";
		case PPC_ID_TBEGIN: return "tbegin.";
		case PPC_ID_TCHECK: return "tcheck";
		case PPC_ID_TD: return "td";
		case PPC_ID_TDEQ: return "tdeq";
		case PPC_ID_TDEQI: return "tdeqi";
		case PPC_ID_TDGT: return "tdgt";
		case PPC_ID_TDGTI: return "tdgti";
		case PPC_ID_TDI: return "tdi";
		case PPC_ID_TDLGT: return "tdlgt";
		case PPC_ID_TDLGTI: return "tdlgti";
		case PPC_ID_TDLLT: return "tdllt";
		case PPC_ID_TDLLTI: return "tdllti";
		case PPC_ID_TDLT: return "tdlt";
		case PPC_ID_TDLTI: return "tdlti";
		case PPC_ID_TDNE: return "tdne";
		case PPC_ID_TDNEI: return "tdnei";
		case PPC_ID_TDU: return "tdu";
		case PPC_ID_TDUI: return "tdui";
		case PPC_ID_TEND: return "tend.";
		case PPC_ID_TLBIA: return "tlbia";
		case PPC_ID_TLBIE: return "tlbie";
		case PPC_ID_TLBIEL: return "tlbiel";
		case PPC_ID_TLBIVAX: return "tlbivax";
		case PPC_ID_TLBLI: return "tlbli";
		case PPC_ID_TLBSX: return "tlbsx";
		case PPC_ID_TLBSYNC: return "tlbsync";
		case PPC_ID_TLBRE: return "tlbre";
		case PPC_ID_TLBRELO: return "tlbrehi";
		case PPC_ID_TLBREHI: return "tlbrelo";
		case PPC_ID_TLBWE: return "tlbwe";
		case PPC_ID_TLBWEHI: return "tlbwehi";
		case PPC_ID_TLBWELO: return "tlbwelo";
		case PPC_ID_TRAP: return "trap";
		case PPC_ID_TRECHKPT: return "trechkpt.";
		case PPC_ID_TRECLAIM: return "treclaim.";
		case PPC_ID_TSR: return "tsr.";
		case PPC_ID_TW: return "tw";
		case PPC_ID_TWEQ: return "tweq";
		case PPC_ID_TWEQI: return "tweqi";
		case PPC_ID_TWGT: return "twgt";
		case PPC_ID_TWGTI: return "twgti";
		case PPC_ID_TWGEI: return "twgei";
		case PPC_ID_TWI: return "twi";
		case PPC_ID_TWLEI: return "twlei";
		case PPC_ID_TWLLEI: return "twllei";
		case PPC_ID_TWLGT: return "twlgt";
		case PPC_ID_TWLGTI: return "twlgti";
		case PPC_ID_TWLLT: return "twllt";
		case PPC_ID_TWLLTI: return "twllti";
		case PPC_ID_TWLT: return "twlt";
		case PPC_ID_TWLTI: return "twlti";
		case PPC_ID_TWNE: return "twne";
		case PPC_ID_TWNEI: return "twnei";
		case PPC_ID_TWU: return "twu";
		case PPC_ID_TWUI: return "twui";
		case PPC_ID_WAIT: return "wait";
		case PPC_ID_WAITIMPL: return "waitimpl";
		case PPC_ID_WAITRSV: return "waitrsv";
		case PPC_ID_WRTEE: return "wrtee";
		case PPC_ID_WRTEEI: return "wrteei";
		case PPC_ID_XNOP: return "xnop";
		case PPC_ID_XORx: return RcMnemonic(instruction, SubMnemXORx);
		case PPC_ID_XORI: return "xori";
		case PPC_ID_XORIS: return "xoris";

		case PPC_ID_AV_VABSDUB: return "vabsdub";
		case PPC_ID_AV_VABSDUH: return "vabsduh";
		case PPC_ID_AV_VABSDUW: return "vabsduw";
		case PPC_ID_AV_VADDUQM: return "vadduqm";
		case PPC_ID_AV_VADDCUQ: return "vaddcuq";
		case PPC_ID_AV_BCDADD: return "bcdadd.";
		case PPC_ID_AV_BCDCFN: return "bcdcfn.";
		case PPC_ID_AV_BCDCFSQ: return "bcdcfsq.";
		case PPC_ID_AV_BCDCFZ: return "bcdcfz.";
		case PPC_ID_AV_BCDCPSGN: return "bcdcpsgn.";
		case PPC_ID_AV_BCDCTN: return "bcdctn.";
		case PPC_ID_AV_BCDCTSQ: return "bcdctsq.";
		case PPC_ID_AV_BCDCTZ: return "bcdctz.";
		case PPC_ID_AV_BCDS: return "bcds.";
		case PPC_ID_AV_BCDSETSGN: return "bcdsetsgn.";
		case PPC_ID_AV_BCDSR: return "bcdsr.";
		case PPC_ID_AV_BCDSUB: return "bcdsub.";
		case PPC_ID_AV_BCDTRUNC: return "bcdtrunc.";
		case PPC_ID_AV_BCDUS: return "bcdus.";
		case PPC_ID_AV_BCDUTRUNC: return "bcdutrunc.";
		case PPC_ID_AV_DSS: return "dss";
		case PPC_ID_AV_DSSALL: return "dssall";
		case PPC_ID_AV_DST: return "dst";
		case PPC_ID_AV_DSTST: return "dstst";
		case PPC_ID_AV_DSTSTT: return "dststt";
		case PPC_ID_AV_DSTT: return "dstt";
		case PPC_ID_AV_LVEBX: return "lvebx";
		case PPC_ID_AV_LVEHX: return "lvehx";
		case PPC_ID_AV_LVEWX: return "lvewx";
		case PPC_ID_AV_LVSL: return "lvsl";
		case PPC_ID_AV_LVSR: return "lvsr";
		case PPC_ID_AV_LVX: return "lvx";
		case PPC_ID_AV_LVXL: return "lvxl";
		case PPC_ID_AV_MADDHD: return "maddhd";
		case PPC_ID_AV_MADDHDU: return "maddhdu";
		case PPC_ID_AV_MADDLD: return "maddld";
		case PPC_ID_AV_MFVSCR: return "mfvscr";
		case PPC_ID_AV_MTVSCR: return "mtvscr";
		case PPC_ID_AV_STVEBX: return "stvebx";
		case PPC_ID_AV_STVEHX: return "stvehx";
		case PPC_ID_AV_STVEWX: return "stvewx";
		case PPC_ID_AV_STVX: return "stvx";
		case PPC_ID_AV_STVXL: return "stvxl";
		case PPC_ID_AV_VADDCUW: return "vaddcuw";
		case PPC_ID_AV_VADDECUQ: return "vaddecuq";
		case PPC_ID_AV_VADDEUQM: return "vaddeuqm";
		case PPC_ID_AV_VADDFP: return "vaddfp";
		case PPC_ID_AV_VADDSBS: return "vaddsbs";
		case PPC_ID_AV_VADDSHS: return "vaddshs";
		case PPC_ID_AV_VADDSWS: return "vaddsws";
		case PPC_ID_AV_VADDUBM: return "vaddubm";
		case PPC_ID_AV_VADDUBS: return "vaddubs";
		case PPC_ID_AV_VADDUDM: return "vaddudm";
		case PPC_ID_AV_VADDUHM: return "vadduhm";
		case PPC_ID_AV_VADDUHS: return "vadduhs";
		case PPC_ID_AV_VADDUWM: return "vadduwm";
		case PPC_ID_AV_VADDUWS: return "vadduws";
		case PPC_ID_AV_VAND: return "vand";
		case PPC_ID_AV_VANDC: return "vandc";
		case PPC_ID_AV_VAVGSB: return "vavgsb";
		case PPC_ID_AV_VAVGSH: return "vavgsh";
		case PPC_ID_AV_VAVGSW: return "vavgsw";
		case PPC_ID_AV_VAVGUB: return "vavgub";
		case PPC_ID_AV_VAVGUH: return "vavguh";
		case PPC_ID_AV_VAVGUW: return "vavguw";
		case PPC_ID_AV_VBPERMD: return "vbpermd";
		case PPC_ID_AV_VBPERMQ: return "vbpermq";
		case PPC_ID_AV_VCFSX: return "vcfsx";
		case PPC_ID_AV_VCFUX: return "vcfux";
		case PPC_ID_AV_VCIPHER: return "vcipher";
		case PPC_ID_AV_VCIPHERLAST: return "vcipherlast";
		case PPC_ID_AV_VCLZB: return "vclzb";
		case PPC_ID_AV_VCLZD: return "vclzd";
		case PPC_ID_AV_VCLZH: return "vclzh";
		case PPC_ID_AV_VCLZLSBB: return "vclzlsbb";
		case PPC_ID_AV_VCLZW: return "vclzw";
		case PPC_ID_AV_VCMPBFPx: return RcMnemonic(instruction, SubMnemVCMPBFPx);
		case PPC_ID_AV_VCMPEQFPx: return RcMnemonic(instruction, SubMnemVCMPEQFPx);
		case PPC_ID_AV_VCMPEQUBx: return RcMnemonic(instruction, SubMnemVCMPEQUBx);
		case PPC_ID_AV_VCMPEQUDx: return RcMnemonic(instruction, SubMnemVCMPEQUDx);
		case PPC_ID_AV_VCMPEQUHx: return RcMnemonic(instruction, SubMnemVCMPEQUHx);
		case PPC_ID_AV_VCMPEQUWx: return RcMnemonic(instruction, SubMnemVCMPEQUWx);
		case PPC_ID_AV_VCMPGEFPx: return RcMnemonic(instruction, SubMnemVCMPGEFPx);
		case PPC_ID_AV_VCMPGTFPx: return RcMnemonic(instruction, SubMnemVCMPGTFPx);
		case PPC_ID_AV_VCMPGTSBx: return RcMnemonic(instruction, SubMnemVCMPGTSBx);
		case PPC_ID_AV_VCMPGTSDx: return RcMnemonic(instruction, SubMnemVCMPGTSDx);
		case PPC_ID_AV_VCMPGTSHx: return RcMnemonic(instruction, SubMnemVCMPGTSHx);
		case PPC_ID_AV_VCMPGTSWx: return RcMnemonic(instruction, SubMnemVCMPGTSWx);
		case PPC_ID_AV_VCMPGTUBx: return RcMnemonic(instruction, SubMnemVCMPGTUBx);
		case PPC_ID_AV_VCMPGTUDx: return RcMnemonic(instruction, SubMnemVCMPGTUDx);
		case PPC_ID_AV_VCMPGTUHx: return RcMnemonic(instruction, SubMnemVCMPGTUHx);
		case PPC_ID_AV_VCMPGTUWx: return RcMnemonic(instruction, SubMnemVCMPGTUWx);
		case PPC_ID_AV_VCMPNEBx: return RcMnemonic(instruction, SubMnemVCMPNEBx);
		case PPC_ID_AV_VCMPNEHx: return RcMnemonic(instruction, SubMnemVCMPNEHx);
		case PPC_ID_AV_VCMPNEWx: return RcMnemonic(instruction, SubMnemVCMPNEWx);
		case PPC_ID_AV_VCMPNEZBx: return RcMnemonic(instruction, SubMnemVCMPNEZBx);
		case PPC_ID_AV_VCMPNEZHx: return RcMnemonic(instruction, SubMnemVCMPNEZHx);
		case PPC_ID_AV_VCMPNEZWx: return RcMnemonic(instruction, SubMnemVCMPNEZWx);
		case PPC_ID_AV_VCTSXS: return "vctsxs";
		case PPC_ID_AV_VCTUXS: return "vctuxs";
		case PPC_ID_AV_VCTZB: return "vctzb";
		case PPC_ID_AV_VCTZD: return "vctzd";
		case PPC_ID_AV_VCTZH: return "vctzh";
		case PPC_ID_AV_VCTZLSBB: return "vctzlsbb";
		case PPC_ID_AV_VCTZW: return "vctzw";
		case PPC_ID_AV_VEQV: return "veqv";
		case PPC_ID_AV_VEXPTEFP: return "vexptefp";
		case PPC_ID_AV_VEXTRACTD: return "vextractd";
		case PPC_ID_AV_VEXTRACTUB: return "vextractub";
		case PPC_ID_AV_VEXTRACTUH: return "vextractuh";
		case PPC_ID_AV_VEXTRACTUW: return "vextractuw";
		case PPC_ID_AV_VEXTSB2D: return "vextsb2d";
		case PPC_ID_AV_VEXTSB2W: return "vextsb2w";
		case PPC_ID_AV_VEXTSH2D: return "vextsh2d";
		case PPC_ID_AV_VEXTSH2W: return "vextsh2w";
		case PPC_ID_AV_VEXTSW2D: return "vextsw2d";
		case PPC_ID_AV_VEXTUBLX: return "vextublx";
		case PPC_ID_AV_VEXTUHLX: return "vextuhlx";
		case PPC_ID_AV_VEXTUWLX: return "vextuwlx";
		case PPC_ID_AV_VEXTUBRX: return "vextubrx";
		case PPC_ID_AV_VEXTUHRX: return "vextuhrx";
		case PPC_ID_AV_VEXTUWRX: return "vextuwrx";
		case PPC_ID_AV_VGBBD: return "vgbbd";
		case PPC_ID_AV_VINSERTB: return "vinsertb";
		case PPC_ID_AV_VINSERTD: return "vinsertd";
		case PPC_ID_AV_VINSERTH: return "vinserth";
		case PPC_ID_AV_VINSERTW: return "vinsertw";
		case PPC_ID_AV_VLOGEFP: return "vlogefp";
		case PPC_ID_AV_VMADDFP: return "vmaddfp";
		case PPC_ID_AV_VMAXFP: return "vmaxfp";
		case PPC_ID_AV_VMAXSB: return "vmaxsb";
		case PPC_ID_AV_VMAXSD: return "vmaxsd";
		case PPC_ID_AV_VMAXSH: return "vmaxsh";
		case PPC_ID_AV_VMAXSW: return "vmaxsw";
		case PPC_ID_AV_VMAXUB: return "vmaxub";
		case PPC_ID_AV_VMAXUD: return "vmaxud";
		case PPC_ID_AV_VMAXUH: return "vmaxuh";
		case PPC_ID_AV_VMAXUW: return "vmaxuw";
		case PPC_ID_AV_VMHADDSHS: return "vmhaddshs";
		case PPC_ID_AV_VMHRADDSHS: return "vmhraddshs";
		case PPC_ID_AV_VMINFP: return "vminfp";
		case PPC_ID_AV_VMINSB: return "vminsb";
		case PPC_ID_AV_VMINSD: return "vminsd";
		case PPC_ID_AV_VMINSH: return "vminsh";
		case PPC_ID_AV_VMINSW: return "vminsw";
		case PPC_ID_AV_VMINUB: return "vminub";
		case PPC_ID_AV_VMINUD: return "vminud";
		case PPC_ID_AV_VMINUH: return "vminuh";
		case PPC_ID_AV_VMINUW: return "vminuw";
		case PPC_ID_AV_VMLADDUHM: return "vmladduhm";
		case PPC_ID_AV_VMR: return "vmr";
		case PPC_ID_AV_VMRGEW: return "vmrgew";
		case PPC_ID_AV_VMRGHB: return "vmrghb";
		case PPC_ID_AV_VMRGHH: return "vmrghh";
		case PPC_ID_AV_VMRGHW: return "vmrghw";
		case PPC_ID_AV_VMRGLB: return "vmrglb";
		case PPC_ID_AV_VMRGLH: return "vmrglh";
		case PPC_ID_AV_VMRGLW: return "vmrglw";
		case PPC_ID_AV_VMRGOW: return "vmrgow";
		case PPC_ID_AV_VMSUMMBM: return "vmsummbm";
		case PPC_ID_AV_VMSUMSHM: return "vmsumshm";
		case PPC_ID_AV_VMSUMSHS: return "vmsumshs";
		case PPC_ID_AV_VMSUMUBM: return "vmsumubm";
		case PPC_ID_AV_VMSUMUHM: return "vmsumuhm";
		case PPC_ID_AV_VMSUMUHS: return "vmsumuhs";
		case PPC_ID_AV_VMUL10CUQ: return "vmul10cuq";
		case PPC_ID_AV_VMUL10EUQ: return "vmul10euq";
		case PPC_ID_AV_VMUL10ECUQ: return "vmul10ecuq";
		case PPC_ID_AV_VMUL10UQ: return "vmul10uq";
		case PPC_ID_AV_VMULESB: return "vmulesb";
		case PPC_ID_AV_VMULESH: return "vmulesh";
		case PPC_ID_AV_VMULESW: return "vmulesw";
		case PPC_ID_AV_VMULEUB: return "vmuleub";
		case PPC_ID_AV_VMULEUH: return "vmuleuh";
		case PPC_ID_AV_VMULEUW: return "vmuleuw";
		case PPC_ID_AV_VMULOSB: return "vmulosb";
		case PPC_ID_AV_VMULOSH: return "vmulosh";
		case PPC_ID_AV_VMULOSW: return "vmulosw";
		case PPC_ID_AV_VMULOUB: return "vmuloub";
		case PPC_ID_AV_VMULOUH: return "vmulouh";
		case PPC_ID_AV_VMULOUW: return "vmulouw";
		case PPC_ID_AV_VMULUWM: return "vmuluwm";
		case PPC_ID_AV_VNAND: return "vnand";
		case PPC_ID_AV_VNCIPHER: return "vncipher";
		case PPC_ID_AV_VNCIPHERLAST: return "vncipherlast";
		case PPC_ID_AV_VNMSUBFP: return "vnmsubfp";
		case PPC_ID_AV_VNEGD: return "vnegd";
		case PPC_ID_AV_VNEGW: return "vnegw";
		case PPC_ID_AV_VNOR: return "vnor";
		case PPC_ID_AV_VNOT: return "vnot";
		case PPC_ID_AV_VOR: return "vor";
		case PPC_ID_AV_VORC: return "vorc";
		case PPC_ID_AV_VPERM: return "vperm";
		case PPC_ID_AV_VPERMR: return "vpermr";
		case PPC_ID_AV_VPERMXOR: return "vpermxor";
		case PPC_ID_AV_VPKPX: return "vpkpx";
		case PPC_ID_AV_VPKSDSS: return "vpksdss";
		case PPC_ID_AV_VPKSDUS: return "vpksdus";
		case PPC_ID_AV_VPKSHSS: return "vpkshss";
		case PPC_ID_AV_VPKSHUS: return "vpkshus";
		case PPC_ID_AV_VPKSWSS: return "vpkswss";
		case PPC_ID_AV_VPKSWUS: return "vpkswus";
		case PPC_ID_AV_VPKUDUM: return "vpkudum";
		case PPC_ID_AV_VPKUDUS: return "vpkudus";
		case PPC_ID_AV_VPKUHUM: return "vpkuhum";
		case PPC_ID_AV_VPKUHUS: return "vpkuhus";
		case PPC_ID_AV_VPKUWUM: return "vpkuwum";
		case PPC_ID_AV_VPKUWUS: return "vpkuwus";
		case PPC_ID_AV_VPMSUMB: return "vpmsumb";
		case PPC_ID_AV_VPMSUMD: return "vpmsumd";
		case PPC_ID_AV_VPMSUMH: return "vpmsumh";
		case PPC_ID_AV_VPMSUMW: return "vpmsumw";
		case PPC_ID_AV_VPOPCNTB: return "vpopcntb";
		case PPC_ID_AV_VPOPCNTD: return "vpopcntd";
		case PPC_ID_AV_VPOPCNTH: return "vpopcnth";
		case PPC_ID_AV_VPOPCNTW: return "vpopcntw";
		case PPC_ID_AV_VPRTYBD: return "vprtybd";
		case PPC_ID_AV_VPRTYBQ: return "vprtybq";
		case PPC_ID_AV_VPRTYBW: return "vprtybw";
		case PPC_ID_AV_VREFP: return "vrefp";
		case PPC_ID_AV_VRFIM: return "vrfim";
		case PPC_ID_AV_VRFIN: return "vrfin";
		case PPC_ID_AV_VRFIP: return "vrfip";
		case PPC_ID_AV_VRFIZ: return "vrfiz";
		case PPC_ID_AV_VRLB: return "vrlb";
		case PPC_ID_AV_VRLD: return "vrld";
		case PPC_ID_AV_VRLDNM: return "vrldnm";
		case PPC_ID_AV_VRLDMI: return "vrldmi";
		case PPC_ID_AV_VRLH: return "vrlh";
		case PPC_ID_AV_VRLW: return "vrlw";
		case PPC_ID_AV_VRLWMI: return "vrlwmi";
		case PPC_ID_AV_VRLWNM: return "vrlwnm";
		case PPC_ID_AV_VRSQRTEFP: return "vrsqrtefp";
		case PPC_ID_AV_VSBOX: return "vsbox";
		case PPC_ID_AV_VSEL: return "vsel";
		case PPC_ID_AV_VSHASIGMAD: return "vshasigmad";
		case PPC_ID_AV_VSHASIGMAW: return "vshasigmaw";
		case PPC_ID_AV_VSL: return "vsl";
		case PPC_ID_AV_VSLB: return "vslb";
		case PPC_ID_AV_VSLD: return "vsld";
		case PPC_ID_AV_VSLDOI: return "vsldoi";
		case PPC_ID_AV_VSLH: return "vslh";
		case PPC_ID_AV_VSLO: return "vslo";
		case PPC_ID_AV_VSLV: return "vslv";
		case PPC_ID_AV_VSLW: return "vslw";
		case PPC_ID_AV_VSPLTB: return "vspltb";
		case PPC_ID_AV_VSPLTH: return "vsplth";
		case PPC_ID_AV_VSPLTISB: return "vspltisb";
		case PPC_ID_AV_VSPLTISH: return "vspltish";
		case PPC_ID_AV_VSPLTISW: return "vspltisw";
		case PPC_ID_AV_VSPLTW: return "vspltw";
		case PPC_ID_AV_VSR: return "vsr";
		case PPC_ID_AV_VSRAB: return "vsrab";
		case PPC_ID_AV_VSRAD: return "vsrad";
		case PPC_ID_AV_VSRAH: return "vsrah";
		case PPC_ID_AV_VSRAW: return "vsraw";
		case PPC_ID_AV_VSRB: return "vsrb";
		case PPC_ID_AV_VSRD: return "vsrd";
		case PPC_ID_AV_VSRH: return "vsrh";
		case PPC_ID_AV_VSRO: return "vsro";
		case PPC_ID_AV_VSRV: return "vsrv";
		case PPC_ID_AV_VSRW: return "vsrw";
		case PPC_ID_AV_VSUBCUQ: return "vsubcuq";
		case PPC_ID_AV_VSUBCUW: return "vsubcuw";
		case PPC_ID_AV_VSUBECUQ: return "vsubecuq";
		case PPC_ID_AV_VSUBEUQM: return "vsubeuqm";
		case PPC_ID_AV_VSUBFP: return "vsubfp";
		case PPC_ID_AV_VSUBSBS: return "vsubsbs";
		case PPC_ID_AV_VSUBSHS: return "vsubshs";
		case PPC_ID_AV_VSUBSWS: return "vsubsws";
		case PPC_ID_AV_VSUBUBM: return "vsububm";
		case PPC_ID_AV_VSUBUBS: return "vsububs";
		case PPC_ID_AV_VSUBUDM: return "vsubudm";
		case PPC_ID_AV_VSUBUHM: return "vsubuhm";
		case PPC_ID_AV_VSUBUHS: return "vsubuhs";
		case PPC_ID_AV_VSUBUQM: return "vsubuqm";
		case PPC_ID_AV_VSUBUWM: return "vsubuwm";
		case PPC_ID_AV_VSUBUWS: return "vsubuws";
		case PPC_ID_AV_VSUMSWS: return "vsumsws";
		case PPC_ID_AV_VSUM2SWS: return "vsum2sws";
		case PPC_ID_AV_VSUM4SBS: return "vsum4sbs";
		case PPC_ID_AV_VSUM4SHS: return "vsum4shs";
		case PPC_ID_AV_VSUM4UBS: return "vsum4ubs";
		case PPC_ID_AV_VUPKHPX: return "vupkhpx";
		case PPC_ID_AV_VUPKHSB: return "vupkhsb";
		case PPC_ID_AV_VUPKHSH: return "vupkhsh";
		case PPC_ID_AV_VUPKHSW: return "vupkhsw";
		case PPC_ID_AV_VUPKLPX: return "vupklpx";
		case PPC_ID_AV_VUPKLSB: return "vupklsb";
		case PPC_ID_AV_VUPKLSH: return "vupklsh";
		case PPC_ID_AV_VUPKLSW: return "vupklsw";
		case PPC_ID_AV_VXOR: return "vxor";

		case PPC_ID_VSX_LXSDX: return "lxsdx";
		case PPC_ID_VSX_LXSIBZX: return "lxsibzx";
		case PPC_ID_VSX_LXSIHZX: return "lxsihzx";
		case PPC_ID_VSX_LXSIWAX: return "lxsiwax";
		case PPC_ID_VSX_LXSIWZX: return "lxsiwzx";
		case PPC_ID_VSX_LXSSPX: return "lxsspx";
		case PPC_ID_VSX_LXV: return "lxv";
		case PPC_ID_VSX_LXVB16X: return "lxvb16x";
		case PPC_ID_VSX_LXVD2X: return "lxvd2x";
		case PPC_ID_VSX_LXVDSX: return "lxvdsx";
		case PPC_ID_VSX_LXVH8X: return "lxvh8x";
		case PPC_ID_VSX_LXVL: return "lxvl";
		case PPC_ID_VSX_LXVLL: return "lxvll";
		case PPC_ID_VSX_LXVW4X: return "lxvw4x";
		case PPC_ID_VSX_LXVWSX: return "lxvwsx";
		case PPC_ID_VSX_LXVX: return "lxvx";
		case PPC_ID_VSX_MFFPRD: return "mffprd";
		case PPC_ID_VSX_MFVSRD: return "mfvsrd";
		case PPC_ID_VSX_MFVSRLD: return "mfvsrld";
		case PPC_ID_VSX_MFVSRWZ: return "mfvsrwz";
		case PPC_ID_VSX_MTVSRD: return "mtvsrd";
		case PPC_ID_VSX_MTVSRDD: return "mtvsrdd";
		case PPC_ID_VSX_MTVSRWA: return "mtvsrwa";
		case PPC_ID_VSX_MTVSRWS: return "mtvsrws";
		case PPC_ID_VSX_MTVSRWZ: return "mtvsrwz";
		case PPC_ID_VSX_STXSD: return "stxsd";
		case PPC_ID_VSX_STXSDX: return "stxsdx";
		case PPC_ID_VSX_STXSIBX: return "stxsibx";
		case PPC_ID_VSX_STXSIHX: return "stxsihx";
		case PPC_ID_VSX_STXSIWX: return "stxsiwx";
		case PPC_ID_VSX_STXSSP: return "stxssp";
		case PPC_ID_VSX_STXSSPX: return "stxsspx";
		case PPC_ID_VSX_STXVB16X: return "stxvb16x";
		case PPC_ID_VSX_STXVD2X: return "stxvd2x";
		case PPC_ID_VSX_STXVH8X: return "stxvh8x";
		case PPC_ID_VSX_STXV: return "stxv";
		case PPC_ID_VSX_STXVL: return "stxvl";
		case PPC_ID_VSX_STXVLL: return "stxvll";
		case PPC_ID_VSX_STXVW4X: return "stxvw4x";
		case PPC_ID_VSX_STXVX: return "stxvx";
		case PPC_ID_VSX_XSABSDP: return "xsabsdp";
		case PPC_ID_VSX_XSABSQP: return "xsabsqp";
		case PPC_ID_VSX_XSADDDP: return "xsadddp";
		case PPC_ID_VSX_XSADDSP: return "xsaddsp";
		case PPC_ID_VSX_XSADDQPx: return Round2OddMnemonic(instruction, SubMnemXSADDQPx);
		case PPC_ID_VSX_XSCMPEQDP: return "xscmpeqdp";
		case PPC_ID_VSX_XSCMPEXPDP: return "xscmpexpdp";
		case PPC_ID_VSX_XSCMPEXPQP: return "xscmpexpqp";
		case PPC_ID_VSX_XSCMPGEDP: return "xscmpgedp";
		case PPC_ID_VSX_XSCMPGTDP: return "xscmpgtdp";
		case PPC_ID_VSX_XSCMPODP: return "xscmpodp";
		case PPC_ID_VSX_XSCMPOQP: return "xscmpoqp";
		case PPC_ID_VSX_XSCMPUDP: return "xscmpudp";
		case PPC_ID_VSX_XSCMPUQP: return "xscmpuqp";
		case PPC_ID_VSX_XSCPSGNDP: return "xscpsgndp";
		case PPC_ID_VSX_XSCPSGNQP: return "xscpsgnqp";
		case PPC_ID_VSX_XSCVDPHP: return "xscvdphp";
		case PPC_ID_VSX_XSCVDPQP: return "xscvdpqp";
		case PPC_ID_VSX_XSCVDPSP: return "xscvdpsp";
		case PPC_ID_VSX_XSCVDPSPN: return "xscvdpspn";
		case PPC_ID_VSX_XSCVDPSXDS: return "xscvdpsxds";
		case PPC_ID_VSX_XSCVDPSXWS: return "xscvdpsxws";
		case PPC_ID_VSX_XSCVDPUXDS: return "xscvdpuxds";
		case PPC_ID_VSX_XSCVDPUXWS: return "xscvdpuxws";
		case PPC_ID_VSX_XSCVHPDP: return "xscvhpdp";
		case PPC_ID_VSX_XSCVQPDPx: return Round2OddMnemonic(instruction, SubMnemXSCVQPDPx);
		case PPC_ID_VSX_XSCVQPSDZ: return "xscvqpsdz";
		case PPC_ID_VSX_XSCVQPSWZ: return "xscvqpswz";
		case PPC_ID_VSX_XSCVQPUDZ: return "xscvqpudz";
		case PPC_ID_VSX_XSCVQPUWZ: return "xscvqpuwz";
		case PPC_ID_VSX_XSCVSDQP: return "xscvsdqp";
		case PPC_ID_VSX_XSCVSPDP: return "xscvspdp";
		case PPC_ID_VSX_XSCVSPDPN: return "xscvspdpn";
		case PPC_ID_VSX_XSCVSXDDP: return "xscvsxddp";
		case PPC_ID_VSX_XSCVSXDSP: return "xscvsxdsp";
		case PPC_ID_VSX_XSCVUDQP: return "xscvudqp";
		case PPC_ID_VSX_XSCVUXDDP: return "xscvuxddp";
		case PPC_ID_VSX_XSCVUXDSP: return "xscvuxdsp";
		case PPC_ID_VSX_XSDIVDP: return "xsdivdp";
		case PPC_ID_VSX_XSDIVSP: return "xsdivsp";
		case PPC_ID_VSX_XSDIVQPx: return Round2OddMnemonic(instruction, SubMnemXSDIVQPx);
		case PPC_ID_VSX_XSIEXPDP: return "xsiexpdp";
		case PPC_ID_VSX_XSIEXPQP: return "xsiexpqp";
		case PPC_ID_VSX_XSMADDADP: return "xsmaddadp";
		case PPC_ID_VSX_XSMADDASP: return "xsmaddasp";
		case PPC_ID_VSX_XSMADDMDP: return "xsmaddmdp";
		case PPC_ID_VSX_XSMADDMSP: return "xsmaddmsp";
		case PPC_ID_VSX_XSMADDQPx: return Round2OddMnemonic(instruction, SubMnemXSMADDQPx);
		case PPC_ID_VSX_XSMAXCDP: return "xsmaxcdp";
		case PPC_ID_VSX_XSMAXDP: return "xsmaxdp";
		case PPC_ID_VSX_XSMAXJDP: return "xsmaxjdp";
		case PPC_ID_VSX_XSMINDP: return "xsmindp";
		case PPC_ID_VSX_XSMINCDP: return "xsmincdp";
		case PPC_ID_VSX_XSMINJDP: return "xsminjdp";
		case PPC_ID_VSX_XSMSUBADP: return "xsmsubadp";
		case PPC_ID_VSX_XSMSUBASP: return "xsmsubasp";
		case PPC_ID_VSX_XSMSUBMDP: return "xsmsubmdp";
		case PPC_ID_VSX_XSMSUBMSP: return "xsmsubmsp";
		case PPC_ID_VSX_XSMSUBQPx: return Round2OddMnemonic(instruction, SubMnemXSMSUBQPx);
		case PPC_ID_VSX_XSMULDP: return "xsmuldp";
		case PPC_ID_VSX_XSMULSP: return "xsmulsp";
		case PPC_ID_VSX_XSMULQPx: return Round2OddMnemonic(instruction, SubMnemXSMULQPx);
		case PPC_ID_VSX_XSNABSDP: return "xsnabsdp";
		case PPC_ID_VSX_XSNABSQP: return "xsnabsqp";
		case PPC_ID_VSX_XSNEGDP: return "xsnegdp";
		case PPC_ID_VSX_XSNEGQP: return "xsnegqp";
		case PPC_ID_VSX_XSNMADDADP: return "xsnmaddadp";
		case PPC_ID_VSX_XSNMADDASP: return "xsnmaddasp";
		case PPC_ID_VSX_XSNMADDQPx: return Round2OddMnemonic(instruction, SubMnemXSNMADDQPx);
		case PPC_ID_VSX_XSNMADDMDP: return "xsnmaddmdp";
		case PPC_ID_VSX_XSNMADDMSP: return "xsnmaddmsp";
		case PPC_ID_VSX_XSNMSUBADP: return "xsnmsubadp";
		case PPC_ID_VSX_XSNMSUBASP: return "xsnmsubasp";
		case PPC_ID_VSX_XSNMSUBMDP: return "xsnmsubmdp";
		case PPC_ID_VSX_XSNMSUBMSP: return "xsnmsubmsp";
		case PPC_ID_VSX_XSNMSUBQPx: return Round2OddMnemonic(instruction, SubMnemXSNMSUBQPx);
		case PPC_ID_VSX_XSRDPI: return "xsrdpi";
		case PPC_ID_VSX_XSRDPIC: return "xsrdpic";
		case PPC_ID_VSX_XSRDPIM: return "xsrdpim";
		case PPC_ID_VSX_XSRDPIP: return "xsrdpip";
		case PPC_ID_VSX_XSRDPIZ: return "xsrdpiz";
		case PPC_ID_VSX_XSREDP: return "xsredp";
		case PPC_ID_VSX_XSRESP: return "xsresp";
		case PPC_ID_VSX_XSRSP: return "xsrsp";
		case PPC_ID_VSX_XSRSQRTEDP: return "xsrsqrtedp";
		case PPC_ID_VSX_XSRSQRTESP: return "xsrsqrtesp";
		case PPC_ID_VSX_XSSQRTDP: return "xssqrtdp";
		case PPC_ID_VSX_XSSQRTQPx: return Round2OddMnemonic(instruction, SubMnemXSSQRTQPx);
		case PPC_ID_VSX_XSSQRTSP: return "xssqrtsp";
		case PPC_ID_VSX_XSSUBDP: return "xssubdp";
		case PPC_ID_VSX_XSSUBSP: return "xssubsp";
		case PPC_ID_VSX_XSSUBQPx: return Round2OddMnemonic(instruction, SubMnemXSSUBQPx);
		case PPC_ID_VSX_XSRQPIx: return InexactMnemonic(instruction, SubMnemXSRQPIx);
		case PPC_ID_VSX_XSRQPXP: return "xsrqpxp";
		case PPC_ID_VSX_XSTDIVDP: return "xstdivdp";
		case PPC_ID_VSX_XSTDIVSP: return "xstdivsp";
		case PPC_ID_VSX_XSTSTDCDP: return "xststdcdp";
		case PPC_ID_VSX_XSTSTDCQP: return "xststdcqp";
		case PPC_ID_VSX_XSTSTDCSP: return "xststdcsp";
		case PPC_ID_VSX_XSTSQRTDP: return "xstsqrtdp";
		case PPC_ID_VSX_XSXEXPDP: return "xsxexpdp";
		case PPC_ID_VSX_XSXEXPQP: return "xsxexpqp";
		case PPC_ID_VSX_XSXSIGDP: return "xsxsigdp";
		case PPC_ID_VSX_XSXSIGQP: return "xsxsigqp";
		case PPC_ID_VSX_XVABSSP: return "xvabssp";
		case PPC_ID_VSX_XVABSDP: return "xvabsdp";
		case PPC_ID_VSX_XVADDSP: return "xvaddsp";
		case PPC_ID_VSX_XVADDDP: return "xvadddp";
		case PPC_ID_VSX_XVCMPEQDPx: return RcMnemonic(instruction, SubMnemXVCMPEQDPx);
		case PPC_ID_VSX_XVCMPEQSPx: return RcMnemonic(instruction, SubMnemXVCMPEQSPx);
		case PPC_ID_VSX_XVCMPGEDPx: return RcMnemonic(instruction, SubMnemXVCMPGEDPx);
		case PPC_ID_VSX_XVCMPGESPx: return RcMnemonic(instruction, SubMnemXVCMPGESPx);
		case PPC_ID_VSX_XVCMPGTDPx: return RcMnemonic(instruction, SubMnemXVCMPGTDPx);
		case PPC_ID_VSX_XVCMPGTSPx: return RcMnemonic(instruction, SubMnemXVCMPGTSPx);
		case PPC_ID_VSX_XVCPSGNDP: return "xvcpsgndp";
		case PPC_ID_VSX_XVCPSGNSP: return "xvcpsgnsp";
		case PPC_ID_VSX_XVCVDPSP: return "xvcvdpsp";
		case PPC_ID_VSX_XVCVDPSXDS: return "xvcvdpsxds";
		case PPC_ID_VSX_XVCVDPSXWS: return "xvcvdpsxws";
		case PPC_ID_VSX_XVCVDPUXDS: return "xvcvdpuxds";
		case PPC_ID_VSX_XVCVDPUXWS: return "xvcvdpuxws";
		case PPC_ID_VSX_XVCVHPSP: return "xvcvhpsp";
		case PPC_ID_VSX_XVCVSPDP: return "xvcvspdp";
		case PPC_ID_VSX_XVCVSPHP: return "xvcvsphp";
		case PPC_ID_VSX_XVCVSPSXDS: return "xvcvspsxds";
		case PPC_ID_VSX_XVCVSPSXWS: return "xvcvspsxws";
		case PPC_ID_VSX_XVCVSPUXDS: return "xvcvspuxds";
		case PPC_ID_VSX_XVCVSPUXWS: return "xvcvspuxws";
		case PPC_ID_VSX_XVCVSXDDP: return "xvcvsxddp";
		case PPC_ID_VSX_XVCVSXDSP: return "xvcvsxdsp";
		case PPC_ID_VSX_XVCVSXWDP: return "xvcvsxwdp";
		case PPC_ID_VSX_XVCVSXWSP: return "xvcvsxwsp";
		case PPC_ID_VSX_XVCVUXDDP: return "xvcvuxddp";
		case PPC_ID_VSX_XVCVUXDSP: return "xvcvuxdsp";
		case PPC_ID_VSX_XVCVUXWDP: return "xvcvuxwdp";
		case PPC_ID_VSX_XVCVUXWSP: return "xvcvuxwsp";
		case PPC_ID_VSX_XVDIVDP: return "xvdivdp";
		case PPC_ID_VSX_XVDIVSP: return "xvdivsp";
		case PPC_ID_VSX_XVIEXPDP: return "xviexpdp";
		case PPC_ID_VSX_XVIEXPSP: return "xviexpsp";
		case PPC_ID_VSX_XVMADDADP: return "xvmaddadp";
		case PPC_ID_VSX_XVMADDASP: return "xvmaddasp";
		case PPC_ID_VSX_XVMADDMDP: return "xvmaddmdp";
		case PPC_ID_VSX_XVMADDMSP: return "xvmaddmsp";
		case PPC_ID_VSX_XVMAXDP: return "xvmaxdp";
		case PPC_ID_VSX_XVMAXSP: return "xvmaxsp";
		case PPC_ID_VSX_XVMINDP: return "xvmindp";
		case PPC_ID_VSX_XVMINSP: return "xvminsp";
		case PPC_ID_VSX_XVMOVDP: return "xvmovdp";
		case PPC_ID_VSX_XVMOVSP: return "xvmovsp";
		case PPC_ID_VSX_XVMSUBADP: return "xvmsubadp";
		case PPC_ID_VSX_XVMSUBASP: return "xvmsubasp";
		case PPC_ID_VSX_XVMSUBMDP: return "xvmsubmdp";
		case PPC_ID_VSX_XVMSUBMSP: return "xvmsubmsp";
		case PPC_ID_VSX_XVMULSP: return "xvmulsp";
		case PPC_ID_VSX_XVMULDP: return "xvmuldp";
		case PPC_ID_VSX_XVNABSDP: return "xvnabsdp";
		case PPC_ID_VSX_XVNABSSP: return "xvnabssp";
		case PPC_ID_VSX_XVNMADDADP: return "xvnmaddadp";
		case PPC_ID_VSX_XVNMADDASP: return "xvnmaddasp";
		case PPC_ID_VSX_XVNMADDMDP: return "xvnmaddmdp";
		case PPC_ID_VSX_XVNMADDMSP: return "xvnmaddmsp";
		case PPC_ID_VSX_XVNEGDP: return "xvnegdp";
		case PPC_ID_VSX_XVNEGSP: return "xvnegsp";
		case PPC_ID_VSX_XVNMSUBADP: return "xvnmsubadp";
		case PPC_ID_VSX_XVNMSUBASP: return "xvnmsubasp";
		case PPC_ID_VSX_XVNMSUBMSP: return "xvnmsubmsp";
		case PPC_ID_VSX_XVNMSUBMDP: return "xvnmsubmdp";
		case PPC_ID_VSX_XVRDPI: return "xvrdpi";
		case PPC_ID_VSX_XVRDPIC: return "xvrdpic";
		case PPC_ID_VSX_XVRDPIM: return "xvrdpim";
		case PPC_ID_VSX_XVRDPIP: return "xvrdpip";
		case PPC_ID_VSX_XVRDPIZ: return "xvrdpiz";
		case PPC_ID_VSX_XVREDP: return "xvredp";
		case PPC_ID_VSX_XVRESP: return "xvresp";
		case PPC_ID_VSX_XVRSPI: return "xvrspi";
		case PPC_ID_VSX_XVRSPIC: return "xvrspic";
		case PPC_ID_VSX_XVRSPIM: return "xvrspim";
		case PPC_ID_VSX_XVRSPIP: return "xvrspip";
		case PPC_ID_VSX_XVRSPIZ: return "xvrspiz";
		case PPC_ID_VSX_XVRSQRTEDP: return "xvrsqrtedp";
		case PPC_ID_VSX_XVRSQRTESP: return "xvrsqrtesp";
		case PPC_ID_VSX_XVSQRTDP: return "xvsqrtdp";
		case PPC_ID_VSX_XVSQRTSP: return "xvsqrtsp";
		case PPC_ID_VSX_XVSUBSP: return "xvsubsp";
		case PPC_ID_VSX_XVSUBDP: return "xvsubdp";
		case PPC_ID_VSX_XVTDIVDP: return "xvtdivdp";
		case PPC_ID_VSX_XVTDIVSP: return "xvtdivsp";
		case PPC_ID_VSX_XVTSQRTDP: return "xvtsqrtdp";
		case PPC_ID_VSX_XVTSQRTSP: return "xvtsqrtsp";
		case PPC_ID_VSX_XVTSTDCDP: return "xvtstdcdp";
		case PPC_ID_VSX_XVTSTDCSP: return "xvtstdcsp";
		case PPC_ID_VSX_XVXEXPDP: return "xvxexpdp";
		case PPC_ID_VSX_XVXEXPSP: return "xvxexpsp";
		case PPC_ID_VSX_XVXSIGDP: return "xvxsigdp";
		case PPC_ID_VSX_XVXSIGSP: return "xvxsigsp";
		case PPC_ID_VSX_XXBRD: return "xxbrd";
		case PPC_ID_VSX_XXBRH: return "xxbrh";
		case PPC_ID_VSX_XXBRQ: return "xxbrq";
		case PPC_ID_VSX_XXBRW: return "xxbrw";
		case PPC_ID_VSX_XXEXTRACTUW: return "xxextractuw";
		case PPC_ID_VSX_XXINSERTW: return "xxinsertw";
		case PPC_ID_VSX_XXLAND: return "xxland";
		case PPC_ID_VSX_XXLANDC: return "xxlandc";
		case PPC_ID_VSX_XXLEQV: return "xxleqv";
		case PPC_ID_VSX_XXLNAND: return "xxlnand";
		case PPC_ID_VSX_XXLNOR: return "xxlnor";
		case PPC_ID_VSX_XXLORC: return "xxlorc";
		case PPC_ID_VSX_XXMRGHD: return "xxmrghd";
		case PPC_ID_VSX_XXMRGHW: return "xxmrghw";
		case PPC_ID_VSX_XXMRGLD: return "xxmrgld";
		case PPC_ID_VSX_XXMRGLW: return "xxmrglw";
		case PPC_ID_VSX_XXLOR: return "xxlor";
		case PPC_ID_VSX_XXLXOR: return "xxlxor";
		case PPC_ID_VSX_XXPERM: return "xxperm";
		case PPC_ID_VSX_XXPERMDI: return "xxpermdi";
		case PPC_ID_VSX_XXPERMR: return "xxpermr";
		case PPC_ID_VSX_XXSEL: return "xxsel";
		case PPC_ID_VSX_XXSLDWI: return "xxsldwi";
		case PPC_ID_VSX_XXSPLTD: return "xxspltd";
		case PPC_ID_VSX_XXSPLTIB: return "xxspltib";
		case PPC_ID_VSX_XXSPLTW: return "xxspltw";
		case PPC_ID_VSX_XXSWAPD: return "xxswapd";

		case PPC_ID_PSQ_L: return "psq_l";
		case PPC_ID_PSQ_LU: return "psq_lu";
		case PPC_ID_PSQ_LUX: return "psq_lux";
		case PPC_ID_PSQ_LX: return "psq_lx";
		case PPC_ID_PSQ_ST: return "psq_st";
		case PPC_ID_PSQ_STU: return "psq_stu";
		case PPC_ID_PSQ_STUX: return "psq_stux";
		case PPC_ID_PSQ_STX: return "psq_stx";

		case PPC_ID_SPE_BRINC: return "brinc";
		case PPC_ID_SPE_EFDABS: return "efdabs";
		case PPC_ID_SPE_EFDADD: return "efdadd";
		case PPC_ID_SPE_EFDCFS: return "efdcfs";
		case PPC_ID_SPE_EFDCFSF: return "efdcfsf";
		case PPC_ID_SPE_EFDCFSI: return "efdcfsi";
		case PPC_ID_SPE_EFDCFSID: return "efdcfsid";
		case PPC_ID_SPE_EFDCFUF: return "efdcfuf";
		case PPC_ID_SPE_EFDCFUI: return "efdcfui";
		case PPC_ID_SPE_EFDCFUID: return "efdcfuid";
		case PPC_ID_SPE_EFDCMPEQ: return "efdcmpeq";
		case PPC_ID_SPE_EFDCMPGT: return "efdcmpgt";
		case PPC_ID_SPE_EFDCMPLT: return "efdcmplt";
		case PPC_ID_SPE_EFDCTSF: return "efdctsf";
		case PPC_ID_SPE_EFDCTSI: return "efdctsi";
		case PPC_ID_SPE_EFDCTSIDZ: return "efdctsidz";
		case PPC_ID_SPE_EFDCTSIZ: return "efdctsiz";
		case PPC_ID_SPE_EFDCTUF: return "efdctuf";
		case PPC_ID_SPE_EFDCTUI: return "efdctui";
		case PPC_ID_SPE_EFDCTUIDZ: return "efdctuidz";
		case PPC_ID_SPE_EFDCTUIZ: return "efdctuiz";
		case PPC_ID_SPE_EFDDIV: return "efddiv";
		case PPC_ID_SPE_EFDMUL: return "efdmul";
		case PPC_ID_SPE_EFDNABS: return "efdnabs";
		case PPC_ID_SPE_EFDNEG: return "efdneg";
		case PPC_ID_SPE_EFDSUB: return "efdsub";
		case PPC_ID_SPE_EFDTSTEQ: return "efdtsteq";
		case PPC_ID_SPE_EFDTSTGT: return "efdtstgt";
		case PPC_ID_SPE_EFDTSTLT: return "efdtstlt";
		case PPC_ID_SPE_EFSABS: return "efsabs";
		case PPC_ID_SPE_EFSADD: return "efsadd";
		case PPC_ID_SPE_EFSCFD: return "efscfd";
		case PPC_ID_SPE_EFSCFSF: return "efscfsf";
		case PPC_ID_SPE_EFSCFSI: return "efscfsi";
		case PPC_ID_SPE_EFSCFUF: return "efscfuf";
		case PPC_ID_SPE_EFSCFUI: return "efscfui";
		case PPC_ID_SPE_EFSCMPEQ: return "efscmpeq";
		case PPC_ID_SPE_EFSCMPGT: return "efscmpgt";
		case PPC_ID_SPE_EFSCMPLT: return "efscmplt";
		case PPC_ID_SPE_EFSCTSF: return "efsctsf";
		case PPC_ID_SPE_EFSCTSI: return "efsctsi";
		case PPC_ID_SPE_EFSCTSIZ: return "efsctsiz";
		case PPC_ID_SPE_EFSCTUF: return "efsctuf";
		case PPC_ID_SPE_EFSCTUI: return "efsctui";
		case PPC_ID_SPE_EFSCTUIZ: return "efsctuiz";
		case PPC_ID_SPE_EFSDIV: return "efsdiv";
		case PPC_ID_SPE_EFSMUL: return "efsmul";
		case PPC_ID_SPE_EFSNABS: return "efsnabs";
		case PPC_ID_SPE_EFSNEG: return "efsneg";
		case PPC_ID_SPE_EFSSUB: return "efssub";
		case PPC_ID_SPE_EFSTSTEQ: return "efststeq";
		case PPC_ID_SPE_EFSTSTGT: return "efststgt";
		case PPC_ID_SPE_EFSTSTLT: return "efststlt";
		case PPC_ID_SPE_EVABS: return "evabs";
		case PPC_ID_SPE_EVADDIW: return "evaddiw";
		case PPC_ID_SPE_EVADDSMIAAW: return "evaddsmiaaw";
		case PPC_ID_SPE_EVADDSSIAAW: return "evaddssiaaw";
		case PPC_ID_SPE_EVADDUMIAAW: return "evaddumiaaw";
		case PPC_ID_SPE_EVADDUSIAAW: return "evaddusiaaw";
		case PPC_ID_SPE_EVADDW: return "evaddw";
		case PPC_ID_SPE_EVAND: return "evand";
		case PPC_ID_SPE_EVANDC: return "evandc";
		case PPC_ID_SPE_EVCMPEQ: return "evcmpeq";
		case PPC_ID_SPE_EVCMPGTS: return "evcmpgts";
		case PPC_ID_SPE_EVCMPGTU: return "evcmpgtu";
		case PPC_ID_SPE_EVCMPLTS: return "evcmplts";
		case PPC_ID_SPE_EVCMPLTU: return "evcmpltu";
		case PPC_ID_SPE_EVCNTLSW: return "evcntlsw";
		case PPC_ID_SPE_EVCNTLZW: return "evcntlzw";
		case PPC_ID_SPE_EVDIVWS: return "evdivws";
		case PPC_ID_SPE_EVDIVWU: return "evdivwu";
		case PPC_ID_SPE_EVEQV: return "eveqv";
		case PPC_ID_SPE_EVEXTSB: return "evextsb";
		case PPC_ID_SPE_EVEXTSH: return "evextsh";
		case PPC_ID_SPE_EVFSABS: return "evfsabs";
		case PPC_ID_SPE_EVFSADD: return "evfsadd";
		case PPC_ID_SPE_EVFSCFSF: return "evfscfsf";
		case PPC_ID_SPE_EVFSCFSI: return "evfscfsi";
		case PPC_ID_SPE_EVFSCFUF: return "evfscfuf";
		case PPC_ID_SPE_EVFSCFUI: return "evfscfui";
		case PPC_ID_SPE_EVSCFUI: return "evscfui";
		case PPC_ID_SPE_EVFSCMPEQ: return "evfscmpeq";
		case PPC_ID_SPE_EVFSCMPGT: return "evfscmpgt";
		case PPC_ID_SPE_EVFSCMPLT: return "evfscmplt";
		case PPC_ID_SPE_EVFSCTSF: return "evfsctsf";
		case PPC_ID_SPE_EVFSCTSI: return "evfsctsi";
		case PPC_ID_SPE_EVFSCTSIZ: return "evfsctsiz";
		case PPC_ID_SPE_EVFSCTUF: return "evfsctuf";
		case PPC_ID_SPE_EVFSCTUI: return "evfsctui";
		case PPC_ID_SPE_EVFSCTUIZ: return "evfsctuiz";
		case PPC_ID_SPE_EVFSDIV: return "evfsdiv";
		case PPC_ID_SPE_EVFSMUL: return "evfsmul";
		case PPC_ID_SPE_EVFSNABS: return "evfsnabs";
		case PPC_ID_SPE_EVFSNEG: return "evfsneg";
		case PPC_ID_SPE_EVFSSUB: return "evfssub";
		case PPC_ID_SPE_EVFSTSTEQ: return "evfststeq";
		case PPC_ID_SPE_EVFSTSTGT: return "evfststgt";
		case PPC_ID_SPE_EVFSTSTLT: return "evfststlt";
		case PPC_ID_SPE_EVLDD: return "evldd";
		case PPC_ID_SPE_EVLDDX: return "evlddx";
		case PPC_ID_SPE_EVLDH: return "evldh";
		case PPC_ID_SPE_EVLDHX: return "evldhx";
		case PPC_ID_SPE_EVLDW: return "evldw";
		case PPC_ID_SPE_EVLDWX: return "evldwx";
		case PPC_ID_SPE_EVLHHESPLAT: return "evlhhesplat";
		case PPC_ID_SPE_EVLHHESPLATX: return "evlhhesplatx";
		case PPC_ID_SPE_EVLHHOSSPLAT: return "evlhhossplat";
		case PPC_ID_SPE_EVLHHOSSPLATX: return "evlhhossplatx";
		case PPC_ID_SPE_EVLHHOUSPLAT: return "evlhhousplat";
		case PPC_ID_SPE_EVLHHOUSPLATX: return "evlhhousplatx";
		case PPC_ID_SPE_EVLWHE: return "evlwhe";
		case PPC_ID_SPE_EVLWHEX: return "evlwhex";
		case PPC_ID_SPE_EVLWHOS: return "evlwhos";
		case PPC_ID_SPE_EVLWHOSX: return "evlwhosx";
		case PPC_ID_SPE_EVLWHOU: return "evlwhou";
		case PPC_ID_SPE_EVLWHOUX: return "evlwhoux";
		case PPC_ID_SPE_EVLWHSPLAT: return "evlwhsplat";
		case PPC_ID_SPE_EVLWHSPLATX: return "evlwhsplatx";
		case PPC_ID_SPE_EVLWWSPLAT: return "evlwwsplat";
		case PPC_ID_SPE_EVLWWSPLATX: return "evlwwsplatx";
		case PPC_ID_SPE_EVMERGEHI: return "evmergehi";
		case PPC_ID_SPE_EVMERGEHILO: return "evmergehilo";
		case PPC_ID_SPE_EVMERGELO: return "evmergelo";
		case PPC_ID_SPE_EVMERGELOHI: return "evmergelohi";
		case PPC_ID_SPE_EVMHEGSMFAA: return "evmhegsmfaa";
		case PPC_ID_SPE_EVMHEGSMFAN: return "evmhegsmfan";
		case PPC_ID_SPE_EVMHEGSMIAA: return "evmhegsmiaa";
		case PPC_ID_SPE_EVMHEGSMIAN: return "evmhegsmian";
		case PPC_ID_SPE_EVMHEGUMIAA: return "evmhegumiaa";
		case PPC_ID_SPE_EVMHEGUMIAN: return "evmhegumian";
		case PPC_ID_SPE_EVMHESMF: return "evmhesmf";
		case PPC_ID_SPE_EVMHESMFA: return "evmhesmfa";
		case PPC_ID_SPE_EVMHESMFAAW: return "evmhesmfaaw";
		case PPC_ID_SPE_EVMHESMFANW: return "evmhesmfanw";
		case PPC_ID_SPE_EVMHESMI: return "evmhesmi";
		case PPC_ID_SPE_EVMHESMIA: return "evmhesmia";
		case PPC_ID_SPE_EVMHESMIAAW: return "evmhesmiaaw";
		case PPC_ID_SPE_EVMHESMIANW: return "evmhesmianw";
		case PPC_ID_SPE_EVMHESSF: return "evmhessf";
		case PPC_ID_SPE_EVMHESSFA: return "evmhessfa";
		case PPC_ID_SPE_EVMHESSFAAW: return "evmhessfaaw";
		case PPC_ID_SPE_EVMHESSFANW: return "evmhessfanw";
		case PPC_ID_SPE_EVMHESSIAAW: return "evmhessiaaw";
		case PPC_ID_SPE_EVMHESSIANW: return "evmhessianw";
		case PPC_ID_SPE_EVMHEUMI: return "evmheumi";
		case PPC_ID_SPE_EVMHEUMIA: return "evmheumia";
		case PPC_ID_SPE_EVMHEUMIAAW: return "evmheumiaaw";
		case PPC_ID_SPE_EVMHEUMIANW: return "evmheumianw";
		case PPC_ID_SPE_EVMHEUSIAAW: return "evmheusiaaw";
		case PPC_ID_SPE_EVMHEUSIANW: return "evmheusianw";
		case PPC_ID_SPE_EVMHOGSMFAA: return "evmhogsmfaa";
		case PPC_ID_SPE_EVMHOGSMFAN: return "evmhogsmfan";
		case PPC_ID_SPE_EVMHOGSMIAA: return "evmhogsmiaa";
		case PPC_ID_SPE_EVMHOGSMIAN: return "evmhogsmian";
		case PPC_ID_SPE_EVMHOGUMIAA: return "evmhogumiaa";
		case PPC_ID_SPE_EVMHOGUMIAN: return "evmhogumian";
		case PPC_ID_SPE_EVMHOSMF: return "evmhosmf";
		case PPC_ID_SPE_EVMHOSMFA: return "evmhosmfa";
		case PPC_ID_SPE_EVMHOSMFAAW: return "evmhosmfaaw";
		case PPC_ID_SPE_EVMHOSMFANW: return "evmhosmfanw";
		case PPC_ID_SPE_EVMHOSMI: return "evmhosmi";
		case PPC_ID_SPE_EVMHOSMIA: return "evmhosmia";
		case PPC_ID_SPE_EVMHOSMIAAW: return "evmhosmiaaw";
		case PPC_ID_SPE_EVMHOSMIANW: return "evmhosmianw";
		case PPC_ID_SPE_EVMHOSSF: return "evmhossf";
		case PPC_ID_SPE_EVMHOSSFA: return "evmhossfa";
		case PPC_ID_SPE_EVMHOSSFAAW: return "evmhossfaaw";
		case PPC_ID_SPE_EVMHOSSFANW: return "evmhossfanw";
		case PPC_ID_SPE_EVMHOSSIAAW: return "evmhossiaaw";
		case PPC_ID_SPE_EVMHOSSIANW: return "evmhossianw";
		case PPC_ID_SPE_EVMHOUMI: return "evmhoumi";
		case PPC_ID_SPE_EVMHOUMIA: return "evmhoumia";
		case PPC_ID_SPE_EVMHOUMIAAW: return "evmhoumiaaw";
		case PPC_ID_SPE_EVMHOUMIANW: return "evmhoumianw";
		case PPC_ID_SPE_EVMHOUSIAAW: return "evmhousiaaw";
		case PPC_ID_SPE_EVMHOUSIANW: return "evmhousianw";
		case PPC_ID_SPE_EVMR: return "evmr";
		case PPC_ID_SPE_EVMRA: return "evmra";
		case PPC_ID_SPE_EVMWHSMF: return "evmwhsmf";
		case PPC_ID_SPE_EVMWHSMFA: return "evmwhsmfa";
		case PPC_ID_SPE_EVMWHSMI: return "evmwhsmi";
		case PPC_ID_SPE_EVMWHSMIA: return "evmwhsmia";
		case PPC_ID_SPE_EVMWHSSF: return "evmwhssf";
		case PPC_ID_SPE_EVMWHSSFA: return "evmwhssfa";
		case PPC_ID_SPE_EVMWHUMI: return "evmwhumi";
		case PPC_ID_SPE_EVMWHUMIA: return "evmwhumia";
		case PPC_ID_SPE_EVMWHUSIAAW: return "evmwhusiaaw";
		case PPC_ID_SPE_EVMWHUSIANW: return "evmwhusianw";
		case PPC_ID_SPE_EVMWLSMIAAW: return "evmwlsmiaaw";
		case PPC_ID_SPE_EVMWLSMIANW: return "evmwlsmianw";
		case PPC_ID_SPE_EVMWLSSIANW: return "evmwlssianw";
		case PPC_ID_SPE_EVMWLSSIAAW: return "evmwlssiaaw";
		case PPC_ID_SPE_EVMWLUMI: return "evmwlumi";
		case PPC_ID_SPE_EVMWLUMIA: return "evmwlumia";
		case PPC_ID_SPE_EVMWLUMIAAW: return "evmwlumiaaw";
		case PPC_ID_SPE_EVMWLUMIANW: return "evmwlumianw";
		case PPC_ID_SPE_EVMWLUSIAAW: return "evmwlusiaaw";
		case PPC_ID_SPE_EVMWLUSIANW: return "evmwlusianw";
		case PPC_ID_SPE_EVMWSMF: return "evmwsmf";
		case PPC_ID_SPE_EVMWSMFA: return "evmwsmfa";
		case PPC_ID_SPE_EVMWSMFAA: return "evmwsmfaa";
		case PPC_ID_SPE_EVMWSMFAN: return "evmwsmfan";
		case PPC_ID_SPE_EVMWSMI: return "evmwsmi";
		case PPC_ID_SPE_EVMWSMIA: return "evmwsmia";
		case PPC_ID_SPE_EVMWSMIAA: return "evmwsmiaa";
		case PPC_ID_SPE_EVMWSMIAN: return "evmwsmian";
		case PPC_ID_SPE_EVMWSSF: return "evmwssf";
		case PPC_ID_SPE_EVMWSSFA: return "evmwssfa";
		case PPC_ID_SPE_EVMWSSFAA: return "evmwssfaa";
		case PPC_ID_SPE_EVMWSSFAN: return "evmwssfan";
		case PPC_ID_SPE_EVMWUMI: return "evmwumi";
		case PPC_ID_SPE_EVMWUMIA: return "evmwumia";
		case PPC_ID_SPE_EVMWUMIAA: return "evmwumiaa";
		case PPC_ID_SPE_EVMWUMIAN: return "evmwumian";
		case PPC_ID_SPE_EVNAND: return "evnand";
		case PPC_ID_SPE_EVNEG: return "evneg";
		case PPC_ID_SPE_EVNOR: return "evnor";
		case PPC_ID_SPE_EVNOT: return "evnot";
		case PPC_ID_SPE_EVOR: return "evor";
		case PPC_ID_SPE_EVORC: return "evorc";
		case PPC_ID_SPE_EVRLW: return "evrlw";
		case PPC_ID_SPE_EVRLWI: return "evrlwi";
		case PPC_ID_SPE_EVRNDW: return "evrndw";
		case PPC_ID_SPE_EVSEL: return "evsel";
		case PPC_ID_SPE_EVSLW: return "evslw";
		case PPC_ID_SPE_EVSLWI: return "evslwi";
		case PPC_ID_SPE_EVSPLATFI: return "evsplatfi";
		case PPC_ID_SPE_EVSPLATI: return "evsplati";
		case PPC_ID_SPE_EVSRWIS: return "evsrwis";
		case PPC_ID_SPE_EVSRWIU: return "evsrwiu";
		case PPC_ID_SPE_EVSRWS: return "evsrws";
		case PPC_ID_SPE_EVSRWU: return "evsrwu";
		case PPC_ID_SPE_EVSTDD: return "evstdd";
		case PPC_ID_SPE_EVSTDDX: return "evstddx";
		case PPC_ID_SPE_EVSTDH: return "evstdh";
		case PPC_ID_SPE_EVSTDHX: return "evstdhx";
		case PPC_ID_SPE_EVSTDW: return "evstdw";
		case PPC_ID_SPE_EVSTDWX: return "evstdwx";
		case PPC_ID_SPE_EVSTWHE: return "evstwhe";
		case PPC_ID_SPE_EVSTWHEX: return "evstwhex";
		case PPC_ID_SPE_EVSTWHO: return "evstwho";
		case PPC_ID_SPE_EVSTWHOX: return "evstwhox";
		case PPC_ID_SPE_EVSTWWE: return "evstwwe";
		case PPC_ID_SPE_EVSTWWEX: return "evstwwex";
		case PPC_ID_SPE_EVSTWWO: return "evstwwo";
		case PPC_ID_SPE_EVSTWWOX: return "evstwwox";
		case PPC_ID_SPE_EVSUBFSMIAAW: return "evsubfsmiaaw";
		case PPC_ID_SPE_EVSUBFSSIAAW: return "evsubfssiaaw";
		case PPC_ID_SPE_EVSUBFUMIAAW: return "evsubfumiaaw";
		case PPC_ID_SPE_EVSUBFUSIAAW: return "evsubfusiaaw";
		case PPC_ID_SPE_EVSUBFW: return "evsubfw";
		case PPC_ID_SPE_EVSUBIFW: return "evsubifw";
		case PPC_ID_SPE_EVXOR: return "evxor";

		default: return NULL;
	}
}


bool Decompose(Instruction* instruction, uint32_t word32, uint64_t address, uint32_t flags)
{
	memset(instruction, 0, sizeof *instruction);

	instruction->id = Decode(word32, flags);
	if (instruction->id == PPC_ID_INVALID)
		return false;

	FillOperands(instruction, word32, address);
	return true;
}

const char* PowerPCRegisterName(uint32_t regId)
{
	switch (regId)
	{
		case PPC_REG_GPR0: return "r0";
		case PPC_REG_GPR1: return "r1";
		case PPC_REG_GPR2: return "r2";
		case PPC_REG_GPR3: return "r3";
		case PPC_REG_GPR4: return "r4";
		case PPC_REG_GPR5: return "r5";
		case PPC_REG_GPR6: return "r6";
		case PPC_REG_GPR7: return "r7";
		case PPC_REG_GPR8: return "r8";
		case PPC_REG_GPR9: return "r9";
		case PPC_REG_GPR10: return "r10";
		case PPC_REG_GPR11: return "r11";
		case PPC_REG_GPR12: return "r12";
		case PPC_REG_GPR13: return "r13";
		case PPC_REG_GPR14: return "r14";
		case PPC_REG_GPR15: return "r15";
		case PPC_REG_GPR16: return "r16";
		case PPC_REG_GPR17: return "r17";
		case PPC_REG_GPR18: return "r18";
		case PPC_REG_GPR19: return "r19";
		case PPC_REG_GPR20: return "r20";
		case PPC_REG_GPR21: return "r21";
		case PPC_REG_GPR22: return "r22";
		case PPC_REG_GPR23: return "r23";
		case PPC_REG_GPR24: return "r24";
		case PPC_REG_GPR25: return "r25";
		case PPC_REG_GPR26: return "r26";
		case PPC_REG_GPR27: return "r27";
		case PPC_REG_GPR28: return "r28";
		case PPC_REG_GPR29: return "r29";
		case PPC_REG_GPR30: return "r30";
		case PPC_REG_GPR31: return "r31";

		case PPC_REG_XER: return "xer";
		case PPC_REG_LR: return "lr";
		case PPC_REG_CTR: return "ctr";

		case PPC_REG_FR0: return "f0";
		case PPC_REG_FR1: return "f1";
		case PPC_REG_FR2: return "f2";
		case PPC_REG_FR3: return "f3";
		case PPC_REG_FR4: return "f4";
		case PPC_REG_FR5: return "f5";
		case PPC_REG_FR6: return "f6";
		case PPC_REG_FR7: return "f7";
		case PPC_REG_FR8: return "f8";
		case PPC_REG_FR9: return "f9";
		case PPC_REG_FR10: return "f10";
		case PPC_REG_FR11: return "f11";
		case PPC_REG_FR12: return "f12";
		case PPC_REG_FR13: return "f13";
		case PPC_REG_FR14: return "f14";
		case PPC_REG_FR15: return "f15";
		case PPC_REG_FR16: return "f16";
		case PPC_REG_FR17: return "f17";
		case PPC_REG_FR18: return "f18";
		case PPC_REG_FR19: return "f19";
		case PPC_REG_FR20: return "f20";
		case PPC_REG_FR21: return "f21";
		case PPC_REG_FR22: return "f22";
		case PPC_REG_FR23: return "f23";
		case PPC_REG_FR24: return "f24";
		case PPC_REG_FR25: return "f25";
		case PPC_REG_FR26: return "f26";
		case PPC_REG_FR27: return "f27";
		case PPC_REG_FR28: return "f28";
		case PPC_REG_FR29: return "f29";
		case PPC_REG_FR30: return "f30";
		case PPC_REG_FR31: return "f31";

		case PPC_REG_CRF0: return "cr0";
		case PPC_REG_CRF1: return "cr1";
		case PPC_REG_CRF2: return "cr2";
		case PPC_REG_CRF3: return "cr3";
		case PPC_REG_CRF4: return "cr4";
		case PPC_REG_CRF5: return "cr5";
		case PPC_REG_CRF6: return "cr6";
		case PPC_REG_CRF7: return "cr7";

		case PPC_REG_AV_VR0: return "v0";
		case PPC_REG_AV_VR1: return "v1";
		case PPC_REG_AV_VR2: return "v2";
		case PPC_REG_AV_VR3: return "v3";
		case PPC_REG_AV_VR4: return "v4";
		case PPC_REG_AV_VR5: return "v5";
		case PPC_REG_AV_VR6: return "v6";
		case PPC_REG_AV_VR7: return "v7";
		case PPC_REG_AV_VR8: return "v8";
		case PPC_REG_AV_VR9: return "v9";
		case PPC_REG_AV_VR10: return "v10";
		case PPC_REG_AV_VR11: return "v11";
		case PPC_REG_AV_VR12: return "v12";
		case PPC_REG_AV_VR13: return "v13";
		case PPC_REG_AV_VR14: return "v14";
		case PPC_REG_AV_VR15: return "v15";
		case PPC_REG_AV_VR16: return "v16";
		case PPC_REG_AV_VR17: return "v17";
		case PPC_REG_AV_VR18: return "v18";
		case PPC_REG_AV_VR19: return "v19";
		case PPC_REG_AV_VR20: return "v20";
		case PPC_REG_AV_VR21: return "v21";
		case PPC_REG_AV_VR22: return "v22";
		case PPC_REG_AV_VR23: return "v23";
		case PPC_REG_AV_VR24: return "v24";
		case PPC_REG_AV_VR25: return "v25";
		case PPC_REG_AV_VR26: return "v26";
		case PPC_REG_AV_VR27: return "v27";
		case PPC_REG_AV_VR28: return "v28";
		case PPC_REG_AV_VR29: return "v29";
		case PPC_REG_AV_VR30: return "v30";
		case PPC_REG_AV_VR31: return "v31";

		case PPC_REG_VSX_VR0: return "vs0";
		case PPC_REG_VSX_VR1: return "vs1";
		case PPC_REG_VSX_VR2: return "vs2";
		case PPC_REG_VSX_VR3: return "vs3";
		case PPC_REG_VSX_VR4: return "vs4";
		case PPC_REG_VSX_VR5: return "vs5";
		case PPC_REG_VSX_VR6: return "vs6";
		case PPC_REG_VSX_VR7: return "vs7";
		case PPC_REG_VSX_VR8: return "vs8";
		case PPC_REG_VSX_VR9: return "vs9";
		case PPC_REG_VSX_VR10: return "vs10";
		case PPC_REG_VSX_VR11: return "vs11";
		case PPC_REG_VSX_VR12: return "vs12";
		case PPC_REG_VSX_VR13: return "vs13";
		case PPC_REG_VSX_VR14: return "vs14";
		case PPC_REG_VSX_VR15: return "vs15";
		case PPC_REG_VSX_VR16: return "vs16";
		case PPC_REG_VSX_VR17: return "vs17";
		case PPC_REG_VSX_VR18: return "vs18";
		case PPC_REG_VSX_VR19: return "vs19";
		case PPC_REG_VSX_VR20: return "vs20";
		case PPC_REG_VSX_VR21: return "vs21";
		case PPC_REG_VSX_VR22: return "vs22";
		case PPC_REG_VSX_VR23: return "vs23";
		case PPC_REG_VSX_VR24: return "vs24";
		case PPC_REG_VSX_VR25: return "vs25";
		case PPC_REG_VSX_VR26: return "vs26";
		case PPC_REG_VSX_VR27: return "vs27";
		case PPC_REG_VSX_VR28: return "vs28";
		case PPC_REG_VSX_VR29: return "vs29";
		case PPC_REG_VSX_VR30: return "vs30";
		case PPC_REG_VSX_VR31: return "vs31";
		case PPC_REG_VSX_VR32: return "vs32";
		case PPC_REG_VSX_VR33: return "vs33";
		case PPC_REG_VSX_VR34: return "vs34";
		case PPC_REG_VSX_VR35: return "vs35";
		case PPC_REG_VSX_VR36: return "vs36";
		case PPC_REG_VSX_VR37: return "vs37";
		case PPC_REG_VSX_VR38: return "vs38";
		case PPC_REG_VSX_VR39: return "vs39";
		case PPC_REG_VSX_VR40: return "vs40";
		case PPC_REG_VSX_VR41: return "vs41";
		case PPC_REG_VSX_VR42: return "vs42";
		case PPC_REG_VSX_VR43: return "vs43";
		case PPC_REG_VSX_VR44: return "vs44";
		case PPC_REG_VSX_VR45: return "vs45";
		case PPC_REG_VSX_VR46: return "vs46";
		case PPC_REG_VSX_VR47: return "vs47";
		case PPC_REG_VSX_VR48: return "vs48";
		case PPC_REG_VSX_VR49: return "vs49";
		case PPC_REG_VSX_VR50: return "vs50";
		case PPC_REG_VSX_VR51: return "vs51";
		case PPC_REG_VSX_VR52: return "vs52";
		case PPC_REG_VSX_VR53: return "vs53";
		case PPC_REG_VSX_VR54: return "vs54";
		case PPC_REG_VSX_VR55: return "vs55";
		case PPC_REG_VSX_VR56: return "vs56";
		case PPC_REG_VSX_VR57: return "vs57";
		case PPC_REG_VSX_VR58: return "vs58";
		case PPC_REG_VSX_VR59: return "vs59";
		case PPC_REG_VSX_VR60: return "vs60";
		case PPC_REG_VSX_VR61: return "vs61";
		case PPC_REG_VSX_VR62: return "vs62";
		case PPC_REG_VSX_VR63: return "vs63";

		case PPC_REG_GQR0: return "gqr0";
		case PPC_REG_GQR1: return "gqr1";
		case PPC_REG_GQR2: return "gqr2";
		case PPC_REG_GQR3: return "gqr3";
		case PPC_REG_GQR4: return "gqr4";
		case PPC_REG_GQR5: return "gqr5";
		case PPC_REG_GQR6: return "gqr6";
		case PPC_REG_GQR7: return "gqr7";

		default: return NULL;
	}
}

const char* OperandClassName(uint32_t cls)
{
	switch (cls)
	{
		case PPC_OP_NONE: return "<none>";
		case PPC_OP_UIMM: return "UIMM";
		case PPC_OP_SIMM: return "SIMM";
		case PPC_OP_LABEL: return "LABEL";
		case PPC_OP_MEM_RA: return "MEM(RA)";

		case PPC_OP_REG_RA: return "RA";
		case PPC_OP_REG_RB: return "RB";
		case PPC_OP_REG_RC: return "RC";
		case PPC_OP_REG_RD: return "RD";
		case PPC_OP_REG_RS: return "RS";

		case PPC_OP_REG_FRA: return "FRA";
		case PPC_OP_REG_FRB: return "FRB";
		case PPC_OP_REG_FRC: return "FRC";
		case PPC_OP_REG_FRD: return "FRD";
		case PPC_OP_REG_FRS: return "FRS";

		case PPC_OP_REG_CRFD: return "CRFD";
		case PPC_OP_REG_CRFD_IMPLY0: return "CRFD";
		case PPC_OP_REG_CRFS: return "CRFS";
		case PPC_OP_CRBIT: return "CRBIT";
		case PPC_OP_CRBIT_A: return "CRBIT_A";
		case PPC_OP_CRBIT_B: return "CRBIT_B";
		case PPC_OP_CRBIT_D: return "CRBIT_C";

		case PPC_OP_REG_AV_VA: return "ALTIVEC_VA";
		case PPC_OP_REG_AV_VB: return "ALTIVEC_VB";
		case PPC_OP_REG_AV_VC: return "ALTIVEC_VC";
		case PPC_OP_REG_AV_VD: return "ALTIVEC_VD";
		case PPC_OP_REG_AV_VS: return "ALTIVEC_VS";

		case PPC_OP_REG_VSX_RA: return "VSX_RA";
		case PPC_OP_REG_VSX_RA_DWORD0: return "VSX_RA0";

		case PPC_OP_REG_VSX_RB: return "VSX_RB";
		case PPC_OP_REG_VSX_RB_DWORD0: return "VSX_RB0";

		case PPC_OP_REG_VSX_RC: return "VSX_RC";
		case PPC_OP_REG_VSX_RC_DWORD0: return "VSX_RC0";

		case PPC_OP_REG_VSX_RD: return "VSX_RD";
		case PPC_OP_REG_VSX_RD_DWORD0: return "VSX_RD0";

		case PPC_OP_REG_VSX_RS: return "VSX_RS";
		case PPC_OP_REG_VSX_RS_DWORD0: return "VSX_RS0";

		return "???";
	}
}

// These match the names in the "Condition Register" section
const char* GetCRBitName(uint32_t crbit)
{
	switch (crbit)
	{
		case 0: return "lt";
		case 1: return "gt";
		case 2: return "eq";
		case 3: return "so";
		case 4: return "cr1lt";
		case 5: return "cr1gt";
		case 6: return "cr1eq";
		case 7: return "cr1so";
		case 8: return "cr2lt";
		case 9: return "cr2gt";
		case 10: return "cr2eq";
		case 11: return "cr2so";
		case 12: return "cr3lt";
		case 13: return "cr3gt";
		case 14: return "cr3eq";
		case 15: return "cr3so";
		case 16: return "cr4lt";
		case 17: return "cr4gt";
		case 18: return "cr4eq";
		case 19: return "cr4so";
		case 20: return "cr5lt";
		case 21: return "cr5gt";
		case 22: return "cr5eq";
		case 23: return "cr5so";
		case 24: return "cr6lt";
		case 25: return "cr6gt";
		case 26: return "cr6eq";
		case 27: return "cr6so";
		case 28: return "cr7lt";
		case 29: return "cr7gt";
		case 30: return "cr7eq";
		case 31: return "cr7so";
		default:
			return NULL;
	}
}
