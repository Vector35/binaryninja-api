#include <binaryninjaapi.h>

#include "disassembler.h"

using namespace BinaryNinja;

#include "il.h"
#include "util.h"

#define OTI_SEXT32_REGS 1
#define OTI_SEXT64_REGS 2
#define OTI_ZEXT32_REGS 4
#define OTI_ZEXT64_REGS 8
#define OTI_SEXT32_IMMS 16
#define OTI_SEXT64_IMMS 32
#define OTI_ZEXT32_IMMS 64
#define OTI_ZEXT64_IMMS 128
#define OTI_IMM_CPTR 256
#define OTI_IMM_REL_CPTR 512
#define OTI_IMM_BIAS 1024
#define OTI_GPR0_ZERO 2048

#define MYLOG(...) while(0);
//#define MYLOG BinaryNinja::LogDebug

static uint32_t genMask(uint32_t mb, uint32_t me)
{
	uint32_t maskBegin = ~0u >> mb;
	uint32_t maskEnd = ~0u << (31 - me);

	return (mb <= me) ? (maskBegin & maskEnd) : (maskBegin | maskEnd);
}

static ExprId operToIL(LowLevelILFunction &il, struct cs_ppc_op *op,
	int options=0, uint64_t extra=0)
{
	ExprId res;

	if(!op) {
		MYLOG("ERROR: operToIL() got NULL operand\n");
		return il.Unimplemented();
	}

	switch(op->type) {
		case PPC_OP_REG:
			//MYLOG("case PPC_OP_REG returning reg %d\n", op->reg);
			if (options & OTI_GPR0_ZERO && op->reg == PPC_REG_R0)
				res = il.Const(4, 0);
			else
				res = il.Register(4, op->reg);
			break;
		case PPC_OP_IMM:
			/* the immediate is a constant pointer (eg: absolute address) */
			if(options & OTI_IMM_CPTR) {
				res = il.ConstPointer(4, op->imm);
			}
			/* the immediate is a displacement (eg: relative addressing) */
			else if(options & OTI_IMM_REL_CPTR) {
				res = il.ConstPointer(4, op->imm + extra);
			}
			/* the immediate should be biased with given value */
			else if(options & OTI_IMM_BIAS) {
				res = il.Const(4, op->imm + extra);
			}
			/* the immediate is just a plain boring immediate */
			else {
				res = il.Const(4, op->imm);
			}
			break;

		case PPC_OP_MEM:
			//MYLOG("case PPC_OP_MEM returning regs (%d,%d)\n", op->mem.base, op->mem.disp);

			if (options & OTI_GPR0_ZERO && op->mem.base == PPC_REG_R0)
				res = il.Const(4, 0);
			else
				res = il.Register(4, op->mem.base);

			if(options & OTI_IMM_BIAS)
				res = il.Add(4, res, il.Const(4, op->mem.disp + extra));
			else
				res = il.Add(4, res, il.Const(4, op->mem.disp));
			break;

		case PPC_OP_CRX:
		case PPC_OP_INVALID:
		default:
			MYLOG("ERROR: don't know how to convert operand to IL\n");
			res = il.Unimplemented();
	}

	switch(options) {
		case OTI_SEXT32_REGS:
			if(op->type == PPC_OP_REG)
				res = il.SignExtend(4, res);
			break;
		case OTI_SEXT64_REGS:
			if(op->type == PPC_OP_REG)
				res = il.SignExtend(8, res);
			break;
		case OTI_ZEXT32_REGS:
			if(op->type == PPC_OP_REG)
				res = il.ZeroExtend(4, res);
			break;
		case OTI_ZEXT64_REGS:
			if(op->type == PPC_OP_REG)
				res = il.ZeroExtend(8, res);
			break;
		case OTI_SEXT32_IMMS:
			if(op->type == PPC_OP_REG)
				res = il.SignExtend(4, res);
			break;
		case OTI_SEXT64_IMMS:
			if(op->type == PPC_OP_REG)
				res = il.SignExtend(8, res);
			break;
		case OTI_ZEXT32_IMMS:
			if(op->type == PPC_OP_REG)
				res = il.ZeroExtend(4, res);
			break;
		case OTI_ZEXT64_IMMS:
			if(op->type == PPC_OP_REG)
				res = il.ZeroExtend(8, res);
			break;
	}

	return res;
}


/* map PPC_REG_CRX to an IL flagwrite type (a named set of written flags */
int crxToFlagWriteType(int crx, bool signedComparison = true)
{
	/* when we have more flags... */
	switch(crx)
	{
		case PPC_REG_CR0:
			return signedComparison ? IL_FLAGWRITE_CR0_S : IL_FLAGWRITE_CR0_U;
		case PPC_REG_CR1:
			return signedComparison ? IL_FLAGWRITE_CR1_S : IL_FLAGWRITE_CR1_U;
		case PPC_REG_CR2:
			return signedComparison ? IL_FLAGWRITE_CR2_S : IL_FLAGWRITE_CR2_U;
		case PPC_REG_CR3:
			return signedComparison ? IL_FLAGWRITE_CR3_S : IL_FLAGWRITE_CR3_U;
		case PPC_REG_CR4:
			return signedComparison ? IL_FLAGWRITE_CR4_S : IL_FLAGWRITE_CR4_U;
		case PPC_REG_CR5:
			return signedComparison ? IL_FLAGWRITE_CR5_S : IL_FLAGWRITE_CR5_U;
		case PPC_REG_CR6:
			return signedComparison ? IL_FLAGWRITE_CR6_S : IL_FLAGWRITE_CR6_U;
		case PPC_REG_CR7:
			return signedComparison ? IL_FLAGWRITE_CR7_S : IL_FLAGWRITE_CR7_U;
		default:
			return 0;
	}
}


static ExprId ExtractConditionClause(LowLevelILFunction& il, uint8_t crBit, bool negate = false)
{
	uint32_t flagBase = (crBit / 4) * 10;

	switch (crBit & 3)
	{
		case IL_FLAG_LT:
			if (negate) return il.FlagGroup(flagBase + IL_FLAGGROUP_CR0_GE);
			else        return il.FlagGroup(flagBase + IL_FLAGGROUP_CR0_LT);
		case IL_FLAG_GT:
			if (negate) return il.FlagGroup(flagBase + IL_FLAGGROUP_CR0_LE);
			else        return il.FlagGroup(flagBase + IL_FLAGGROUP_CR0_GT);
		case IL_FLAG_EQ:
			if (negate) return il.FlagGroup(flagBase + IL_FLAGGROUP_CR0_NE);
			else        return il.FlagGroup(flagBase + IL_FLAGGROUP_CR0_EQ);
	}

	ExprId result = il.Flag(crBit);

	if (negate)
		result = il.Not(0, result);

	return result;
}


static bool LiftConditionalBranch(LowLevelILFunction& il, uint8_t bo, uint8_t bi, BNLowLevelILLabel& takenLabel, BNLowLevelILLabel& falseLabel)
{
	bool testsCtr = !(bo & 4);
	bool testsCrBit = !(bo & 0x10);
	bool isConditional = testsCtr || testsCrBit;

	if (testsCtr)
	{
		ExprId cond, left, right;

		il.AddInstruction(
			il.SetRegister(4, PPC_REG_CTR,
				il.Sub(4,
					il.Register(4, PPC_REG_CTR),
					il.Const(4, 1))));

		left = il.Register(4, PPC_REG_CTR);
		right = il.Const(4, 0);

		if (bo & 2)
			cond = il.CompareEqual(4, left, right);
		else
			cond = il.CompareNotEqual(4, left, right);

		if (!testsCrBit)
		{
			il.AddInstruction(il.If(cond, takenLabel, falseLabel));
		}
		else
		{
			LowLevelILLabel trueLabel;
			il.AddInstruction(il.If(cond, trueLabel, falseLabel));
			il.MarkLabel(trueLabel);
		}
	}

	if (testsCrBit)
	{
		ExprId cond = ExtractConditionClause(il, bi, !(bo & 8));
		il.AddInstruction(il.If(cond, takenLabel, falseLabel));
	}

	return isConditional;
}


static bool LiftBranches(Architecture* arch, LowLevelILFunction &il, const uint8_t* data, uint64_t addr, bool le)
{
	uint32_t insn = *(const uint32_t *) data;

	if (!le)
		insn = bswap32(insn);

	bool lk = insn & 1;

	switch (insn >> 26)
	{
		case 18: /* b (b, ba, bl, bla) */
		{
			uint32_t target = insn & 0x03fffffc;

			/* sign extend target */
			if ((target >> 25) & 1)
				target |= 0xfc000000;

			/* account for absolute addressing */
			if (!(insn & 2))
				target += (uint32_t) addr;

			BNLowLevelILLabel *label = il.GetLabelForAddress(arch, target);

			if (label && !(lk && (target != (addr+4))))
			{
				/* branch to an instruction within the same function -- take
				 * 'lk' bit behavior into account, but don't emit as a call
				 */
				if (lk)
					il.AddInstruction(il.SetRegister(4, PPC_REG_LR, il.ConstPointer(4, addr + 4)));

				il.AddInstruction(il.Goto(*label));
			}
			else
			{
				ExprId dest = il.ConstPointer(4, target);

				if (lk)
					il.AddInstruction(il.Call(dest));
				else
					il.AddInstruction(il.Jump(dest));
			}

			break;
		}
		case 16: /* bc */
		{
			uint32_t target = insn & 0xfffc;
			uint8_t bo = (insn >> 21) & 0x1f;
			uint8_t bi = (insn >> 16) & 0x1f;

			/* sign extend target */
			if ((target >> 15) & 1)
				target |= 0xffff0000;

			/* account for absolute addressing */
			if (!(insn & 2))
				target += (uint32_t) addr;

			BNLowLevelILLabel *existingTakenLabel = il.GetLabelForAddress(arch, target);
			BNLowLevelILLabel *existingFalseLabel = il.GetLabelForAddress(arch, addr + 4);

			if (lk)
				il.AddInstruction(il.SetRegister(4, PPC_REG_LR, il.ConstPointer(4, addr + 4)));

			LowLevelILLabel takenLabelManual, falseLabelManual;
			BNLowLevelILLabel* takenLabel = existingTakenLabel;
			BNLowLevelILLabel* falseLabel = existingFalseLabel;

			if (!takenLabel)
				takenLabel = &takenLabelManual;

			if (!falseLabel)
				falseLabel = &falseLabelManual;

			bool wasConditionalBranch = LiftConditionalBranch(il, bo, bi, *takenLabel, *falseLabel);

			if (wasConditionalBranch && !existingTakenLabel)
				il.MarkLabel(*takenLabel);

			if (!wasConditionalBranch && existingTakenLabel)
				il.AddInstruction(il.Goto(*takenLabel));
			else if (target != addr + 4)
			{
				if (lk)
				{
					il.AddInstruction(il.Call(il.ConstPointer(4, target)));
					if (wasConditionalBranch)
						il.AddInstruction(il.Goto(*falseLabel));
				}
				else
					il.AddInstruction(il.Jump(il.ConstPointer(4, target)));
			}

			if (wasConditionalBranch && !existingFalseLabel)
				il.MarkLabel(*falseLabel);

			break;
		}
		case 19: /* bcctr, bclr */
		{
			uint8_t bo = (insn >> 21) & 0x1f;
			uint8_t bi = (insn >> 16) & 0x1f;
			bool blr = false;
			ExprId expr;

			switch ((insn >> 1) & 0x3ff)
			{
				case 16:
					expr = il.Register(4, PPC_REG_LR);
					blr = true;
					break;
				case 528:
					if (!(bo & 4))
						return false;
					expr = il.Register(4, PPC_REG_CTR);
					break;
				default:
					return false;
			}

			BNLowLevelILLabel *existingFalseLabel = il.GetLabelForAddress(arch, addr + 4);
			BNLowLevelILLabel* falseLabel = existingFalseLabel;

			LowLevelILLabel takenLabel, falseLabelManual;

			if (!falseLabel)
				falseLabel = &falseLabelManual;

			bool wasConditionalBranch = LiftConditionalBranch(il, bo, bi, takenLabel, *falseLabel);

			if (wasConditionalBranch)
				il.MarkLabel(takenLabel);

			if (lk)
			{
				il.AddInstruction(il.Call(expr));
				if (wasConditionalBranch)
					il.AddInstruction(il.Goto(*falseLabel));
			}
			else if (blr)
				il.AddInstruction(il.Return(expr));
			else
				il.AddInstruction(il.Jump(expr));

			if (wasConditionalBranch && !existingFalseLabel)
				il.MarkLabel(*falseLabel);

			break;
		}
		default:
			return false;
	}

	return true;
}


static ExprId ByteReverseRegister(LowLevelILFunction &il, uint32_t reg, size_t size)
{
	ExprId swap = BN_INVALID_EXPR;

	for (size_t srcIndex = 0; srcIndex < size; srcIndex++)
	{
		ExprId extracted = il.Register(4, reg);
		size_t dstIndex = size - srcIndex - 1;

		if (dstIndex > srcIndex)
		{
			ExprId mask = il.Const(4, 0xffull << (srcIndex * 8));
			extracted = il.And(4, extracted, mask);
			extracted = il.ShiftLeft(4, extracted, il.Const(4, (dstIndex - srcIndex) * 8));
		}
		else if (srcIndex > dstIndex)
		{
			ExprId mask = il.Const(4, 0xffull << (dstIndex * 8));
			extracted = il.LogicalShiftRight(4, extracted, il.Const(4, (srcIndex - dstIndex) * 8));
			extracted = il.And(4, extracted, mask);
		}

		if (swap == BN_INVALID_EXPR)
			swap = extracted;
		else
			swap = il.Or(4, swap, extracted);
	}

	return swap;
}


static void ByteReversedLoad(LowLevelILFunction &il, struct cs_ppc* ppc, size_t size)
{
	ExprId addr = operToIL(il, &ppc->operands[1], OTI_GPR0_ZERO);                  // (rA|0)
	ExprId  val = il.Load(size, il.Add(4, addr, operToIL(il, &ppc->operands[2]))); // [(rA|0) + (rB)]

	if (size < 4)
		val = il.ZeroExtend(4, val);

	/* set reg immediately; this will cause xrefs to be sized correctly,
	 * we'll use this as the scratch while we calculate the swapped value */
	il.AddInstruction(il.SetRegister(4, ppc->operands[0].reg, val));               // rD = [(rA|0) + (rB)]
	ExprId swap = ByteReverseRegister(il, ppc->operands[0].reg, size);

	il.AddInstruction(il.SetRegister(4, ppc->operands[0].reg, swap));              // rD = swap([(rA|0) + (rB)])
}

static void ByteReversedStore(LowLevelILFunction &il, struct cs_ppc* ppc, size_t size)
{
	ExprId addr = operToIL(il, &ppc->operands[1], OTI_GPR0_ZERO);     // (rA|0)
	addr = il.Add(4, addr, operToIL(il, &ppc->operands[2]));          // (rA|0) + (rB)
	ExprId val = ByteReverseRegister(il, ppc->operands[0].reg, size); // rS = swap(rS)
	il.AddInstruction(il.Store(size, addr, val));                     // [(rA|0) + (rB)] = swap(rS)
}

/* returns TRUE - if this IL continues
          FALSE - if this IL terminates a block */
bool GetLowLevelILForPPCInstruction(Architecture *arch, LowLevelILFunction &il,
  const uint8_t* data, uint64_t addr, decomp_result *res, bool le)
{
	int i;
	bool rc = true;

	/* bypass capstone path for *all* branching instructions; capstone
	 * is too difficult to work with and is outright broken for some
	 * branch instructions (bdnz, etc.)
	 */
	if (LiftBranches(arch, il, data, addr, le))
		return true;

	struct cs_insn *insn = &(res->insn);
	struct cs_detail *detail = &(res->detail);
	struct cs_ppc *ppc = &(detail->ppc);

	/* There is a simplifying reduction available for:
	 *   rlwinm <reg>, <reg>, <rol_amt>, <mask_begin>, <mask_end>
	 * When <rol_amt> == <mask_begin> == 0, this can be translated to:
	 *   clrwi <reg>, <reg>, 31-<mask_end>
	 *
	 * Unfortunately capstone screws this up, replacing just the instruction id with PPC_INSN_CLRWI.
	 * The mnemonic ("rlwinm"), operands, etc. all stay the same.
	 */
	if (insn->id == PPC_INS_CLRLWI && insn->mnemonic[0] == 'r')
	{
		insn->id = PPC_INS_RLWINM;
	}

	/* create convenient access to instruction operands */
	cs_ppc_op *oper0=NULL, *oper1=NULL, *oper2=NULL, *oper3=NULL, *oper4=NULL;
	#define REQUIRE1OP if(!oper0) goto ReturnUnimpl;
	#define REQUIRE2OPS if(!oper0 || !oper1) goto ReturnUnimpl;
	#define REQUIRE3OPS if(!oper0 || !oper1 || !oper2) goto ReturnUnimpl;
	#define REQUIRE4OPS if(!oper0 || !oper1 || !oper2 || !oper3) goto ReturnUnimpl;
	#define REQUIRE5OPS if(!oper0 || !oper1 || !oper2 || !oper3 || !oper4) goto ReturnUnimpl;

	switch(ppc->op_count) {
		default:
		case 5: oper4 = &(ppc->operands[4]); FALL_THROUGH
		case 4: oper3 = &(ppc->operands[3]); FALL_THROUGH
		case 3: oper2 = &(ppc->operands[2]); FALL_THROUGH
		case 2: oper1 = &(ppc->operands[1]); FALL_THROUGH
		case 1: oper0 = &(ppc->operands[0]); FALL_THROUGH
		case 0: while(0);
	}

	/* for conditionals that specify a crx, treat it special */
	if(ppc->bc != PPC_BC_INVALID) {
		if(oper0 && oper0->type == PPC_OP_REG && oper0->reg >= PPC_REG_CR0 &&
		  ppc->operands[0].reg <= PPC_REG_CR7) {
			oper0 = oper1;
			oper1 = oper2;
			oper2 = oper3;
			oper3 = NULL;
		}
	}

	if(0 && insn->id == PPC_INS_CMPLWI) {
		MYLOG("%s() %08llx: %02X %02X %02X %02X %s %s has %d operands\n",
			__func__, addr, data[0], data[1], data[2], data[3],
			insn->mnemonic, insn->op_str, ppc->op_count
		);

		//printInstructionVerbose(res);
		//MYLOG("oper0: %p\n", oper0);
		//MYLOG("oper1: %p\n", oper1);
		//MYLOG("oper2: %p\n", oper2);
		//MYLOG("oper3: %p\n", oper3);
	}

	ExprId ei0, ei1, ei2;

	switch(insn->id) {
		/* add
			"add." also updates the CR0 bits */
		case PPC_INS_ADD: /* add */
			REQUIRE2OPS
			ei0 = il.Add(
				4,
				operToIL(il, oper1),
				operToIL(il, oper2)
			);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
				(insn->id == PPC_INS_ADD && ppc->update_cr0) ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_ADDE: /* add, extended (+ carry flag) */
			REQUIRE3OPS
			ei0 = il.AddCarry(
				4,
				operToIL(il, oper1),
				operToIL(il, oper2),
				il.Flag(IL_FLAG_XER_CA),
				IL_FLAGWRITE_XER_CA
			);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
			  ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_ADDME: /* add, extended (+ carry flag) minus one */
		case PPC_INS_ADDZE:
			REQUIRE2OPS
			if (insn->id == PPC_INS_ADDME)
				ei0 = il.Const(4, 0xffffffff);
			else
				ei0 = il.Const(4, 0);
			ei0 = il.AddCarry(
				4,
				operToIL(il, oper1),
				ei0,
				il.Flag(IL_FLAG_XER_CA),
				IL_FLAGWRITE_XER_CA
			);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_ADDC: /* add, carrying */
		case PPC_INS_ADDIC: /* add immediate, carrying */
			REQUIRE3OPS
			ei0 = il.Add(
				4,
				operToIL(il, oper1),
				operToIL(il, oper2),
				IL_FLAGWRITE_XER_CA
			);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_ADDI: /* add immediate, eg: addi rD, rA, <imm> */
		case PPC_INS_ADDIS: /* add immediate, shifted */
			REQUIRE2OPS
			if (insn->id == PPC_INS_ADDIS)
				ei0 = il.Const(4, oper2->imm << 16);
			else
				ei0 = il.Const(4, oper2->imm);
			ei0 = il.Add(
				4,
				operToIL(il, oper1, OTI_GPR0_ZERO),
				ei0
			);
			ei0 = il.SetRegister(4, oper0->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_LIS: /* load immediate, shifted */
			REQUIRE2OPS
			ei0 = il.SetRegister(
				4,
				oper0->reg,
				il.ConstPointer(4, oper1->imm << 16)
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_LI: /* load immediate */
		case PPC_INS_LA: /* load displacement */
			REQUIRE2OPS
			il.AddInstruction(il.SetRegister(4, oper0->reg, operToIL(il, oper1)));
			break;

		case PPC_INS_AND:
		case PPC_INS_ANDC: // and [with complement]
		case PPC_INS_NAND:
			REQUIRE3OPS
			ei0 = operToIL(il, oper2);
			if (insn->id == PPC_INS_ANDC)
				ei0 = il.Not(4, ei0);
			ei0 = il.And(4, operToIL(il, oper1), ei0);
			if (insn->id == PPC_INS_NAND)
				ei0 = il.Not(4, ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_ANDIS:
		case PPC_INS_ANDI:
			REQUIRE3OPS
			if (insn->id == PPC_INS_ANDIS)
				ei0 = il.Const(4, oper2->imm << 16);
			else
				ei0 = il.Const(4, oper2->imm);
			ei0 = il.And(4, operToIL(il, oper1), ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0, IL_FLAGWRITE_CR0_S);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_CMP:
		case PPC_INS_CMPW: /* compare (signed) word(32-bit) */
			REQUIRE2OPS
			ei0 = operToIL(il, oper2 ? oper1 : oper0);
			ei1 = operToIL(il, oper2 ? oper2 : oper1);
			ei2 = il.Sub(4, ei0, ei1, crxToFlagWriteType(oper2 ? oper0->reg : PPC_REG_CR0));
			il.AddInstruction(ei2);
			break;

		case PPC_INS_CMPL:
		case PPC_INS_CMPLW: /* compare logical(unsigned) word(32-bit) */
			REQUIRE2OPS
			ei0 = operToIL(il, oper2 ? oper1 : oper0);
			ei1 = operToIL(il, oper2 ? oper2 : oper1);
			ei2 = il.Sub(4, ei0, ei1, crxToFlagWriteType(oper2 ? oper0->reg : PPC_REG_CR0, false));
			il.AddInstruction(ei2);
			break;

		case PPC_INS_CMPI:
		case PPC_INS_CMPWI: /* compare (signed) word(32-bit) immediate */
			REQUIRE2OPS
			ei0 = operToIL(il, oper2 ? oper1 : oper0);
			ei1 = operToIL(il, oper2 ? oper2 : oper1, OTI_SEXT32_IMMS);
			ei2 = il.Sub(4, ei0, ei1, crxToFlagWriteType(oper2 ? oper0->reg : PPC_REG_CR0));
			il.AddInstruction(ei2);
			break;

		case PPC_INS_CMPLI:
		case PPC_INS_CMPLWI: /* compare logical(unsigned) word(32-bit) immediate */
			REQUIRE2OPS
			ei0 = operToIL(il, oper2 ? oper1 : oper0);
			ei1 = operToIL(il, oper2 ? oper2 : oper1, OTI_ZEXT32_IMMS);
			ei2 = il.Sub(4, ei0, ei1, crxToFlagWriteType(oper2 ? oper0->reg : PPC_REG_CR0, false));
			il.AddInstruction(ei2);
			break;

	//case PPC_INS_CMPD: /* compare (signed) d-word(64-bit) */
	//	REQUIRE2OPS
	//	ei0 = operToIL(il, oper0);
	//	ei1 = operToIL(il, oper1, OTI_SEXT64_REGS);
	//	ei2 = il.Sub(4, ei0, ei1, flagWriteType);
	//	il.AddInstruction(ei2);
	//	break;

	//case PPC_INS_CMPLD: /* compare logical(unsigned) d-word(64-bit) */
	//	REQUIRE2OPS
	//	ei0 = operToIL(il, oper0);
	//	ei1 = operToIL(il, oper1, OTI_ZEXT64_REGS);
	//	ei2 = il.Sub(4, ei0, ei1, flagWriteType);
	//	il.AddInstruction(ei2);
	//	break;

	//case PPC_INS_CMPDI: /* compare (signed) d-word(64-bit) immediate */
	//	REQUIRE2OPS
	//	ei0 = operToIL(il, oper0);
	//	ei1 = operToIL(il, oper1, OTI_SEXT64_IMMS);
	//	ei2 = il.Sub(4, ei0, ei1, flagWriteType);
	//	il.AddInstruction(ei2);
	//	break;

	//case PPC_INS_CMPLDI: /* compare logical(unsigned) d-word(64-bit) immediate */
	//	REQUIRE2OPS
	//	ei0 = operToIL(il, oper0);
	//	ei1 = operToIL(il, oper1, OTI_ZEXT64_IMMS);
	//	ei2 = il.Sub(4, ei0, ei1, flagWriteType);
	//	il.AddInstruction(ei2);
	//	break;

	//	case PPC_INS_FCMPU:
	//		REQUIRE3OPS
	//		ei0 = il.FloatSub(4, il.Unimplemented(), il.Unimplemented(), (oper0->reg - PPC_REG_CR0) + IL_FLAGWRITE_INVL0);
	//		il.AddInstruction(ei0);
	//		break;

		case PPC_INS_CRAND:
		case PPC_INS_CRANDC:
		case PPC_INS_CRNAND:
			REQUIRE3OPS
			ei0 = il.Flag(oper1->reg - PPC_REG_R0);
			ei1 = il.Flag(oper2->reg - PPC_REG_R0);
			if (insn->id == PPC_INS_CRANDC)
				ei1 = il.Not(0, ei1);
			ei0 = il.And(0, ei0, ei1);
			if (insn->id == PPC_INS_CRNAND)
				ei0 = il.Not(0, ei0);
			il.AddInstruction(il.SetFlag(oper0->reg - PPC_REG_R0, ei0));
			break;

		case PPC_INS_CROR:
		case PPC_INS_CRORC:
		case PPC_INS_CRNOR:
			REQUIRE3OPS
			ei0 = il.Flag(oper1->reg - PPC_REG_R0);
			ei1 = il.Flag(oper2->reg - PPC_REG_R0);
			if (insn->id == PPC_INS_CRORC)
				ei1 = il.Not(0, ei1);
			ei0 = il.Or(0, ei0, ei1);
			if (insn->id == PPC_INS_CRNOR)
				ei0 = il.Not(0, ei0);
			il.AddInstruction(il.SetFlag(oper0->reg - PPC_REG_R0, ei0));
			break;

		case PPC_INS_CREQV:
		case PPC_INS_CRXOR:
			REQUIRE3OPS
			ei0 = il.Flag(oper1->reg - PPC_REG_R0);
			ei1 = il.Flag(oper2->reg - PPC_REG_R0);
			ei0 = il.Xor(0, ei0, ei1);
			if (insn->id == PPC_INS_CREQV)
				ei0 = il.Not(0, ei0);
			il.AddInstruction(il.SetFlag(oper0->reg - PPC_REG_R0, ei0));
			break;

		case PPC_INS_CRSET:
			REQUIRE1OP
			ei0 = il.SetFlag(oper0->reg - PPC_REG_R0, il.Const(0, 1));
			il.AddInstruction(ei0);
			break;

		case PPC_INS_CRCLR:
			REQUIRE1OP
			ei0 = il.SetFlag(oper0->reg - PPC_REG_R0, il.Const(0, 0));
			il.AddInstruction(ei0);
			break;

		case PPC_INS_CRNOT:
		case PPC_INS_CRMOVE:
			REQUIRE2OPS
			ei0 = il.Flag(oper1->reg - PPC_REG_R0);
			if (insn->id == PPC_INS_CRNOT)
				ei0 = il.Not(0, ei0);
			ei0 = il.SetFlag(oper0->reg - PPC_REG_R0, ei0);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_MFCR:
			REQUIRE1OP
			il.AddInstruction(il.SetRegister(4, oper0->reg,
				il.Or(4, il.FlagBit(4, IL_FLAG_LT, 31),
				il.Or(4, il.FlagBit(4, IL_FLAG_GT, 30),
				il.Or(4, il.FlagBit(4, IL_FLAG_EQ, 29),
				il.Or(4, il.FlagBit(4, IL_FLAG_SO, 28),
				il.Or(4, il.FlagBit(4, IL_FLAG_LT_1, 27),
				il.Or(4, il.FlagBit(4, IL_FLAG_GT_1, 26),
				il.Or(4, il.FlagBit(4, IL_FLAG_EQ_1, 25),
				il.Or(4, il.FlagBit(4, IL_FLAG_SO_1, 24),
				il.Or(4, il.FlagBit(4, IL_FLAG_LT_2, 23),
				il.Or(4, il.FlagBit(4, IL_FLAG_GT_2, 22),
				il.Or(4, il.FlagBit(4, IL_FLAG_EQ_2, 21),
				il.Or(4, il.FlagBit(4, IL_FLAG_SO_2, 20),
				il.Or(4, il.FlagBit(4, IL_FLAG_LT_3, 19),
				il.Or(4, il.FlagBit(4, IL_FLAG_GT_3, 18),
				il.Or(4, il.FlagBit(4, IL_FLAG_EQ_3, 17),
				il.Or(4, il.FlagBit(4, IL_FLAG_SO_3, 16),
				il.Or(4, il.FlagBit(4, IL_FLAG_LT_4, 15),
				il.Or(4, il.FlagBit(4, IL_FLAG_GT_4, 14),
				il.Or(4, il.FlagBit(4, IL_FLAG_EQ_4, 13),
				il.Or(4, il.FlagBit(4, IL_FLAG_SO_4, 12),
				il.Or(4, il.FlagBit(4, IL_FLAG_LT_5, 11),
				il.Or(4, il.FlagBit(4, IL_FLAG_GT_5, 10),
				il.Or(4, il.FlagBit(4, IL_FLAG_EQ_5, 9),
				il.Or(4, il.FlagBit(4, IL_FLAG_SO_5, 8),
				il.Or(4, il.FlagBit(4, IL_FLAG_LT_6, 7),
				il.Or(4, il.FlagBit(4, IL_FLAG_GT_6, 6),
				il.Or(4, il.FlagBit(4, IL_FLAG_EQ_6, 5),
				il.Or(4, il.FlagBit(4, IL_FLAG_SO_6, 4),
				il.Or(4, il.FlagBit(4, IL_FLAG_LT_7, 3),
				il.Or(4, il.FlagBit(4, IL_FLAG_GT_7, 2),
				il.Or(4, il.FlagBit(4, IL_FLAG_EQ_7, 1),
				il.FlagBit(4, IL_FLAG_SO_7, 0))))))))))))))))))))))))))))))))));
			break;

		case PPC_INS_MTCRF:
			REQUIRE2OPS
			for (uint8_t test = 0x80, i = 0; test; test >>= 1, i++)
			{
				if (test & oper0->imm)
				{
					ei0 = il.Or(4, il.Register(4, oper1->reg), il.Const(4, 0), IL_FLAGWRITE_MTCR0 + i);
					il.AddInstruction(ei0);
				}
			}
			break;

		case PPC_INS_EXTSB:
		case PPC_INS_EXTSH:
			REQUIRE2OPS
			ei0 = il.Register(4, oper1->reg);
			if (insn->id == PPC_INS_EXTSB)
				ei0 = il.LowPart(1, ei0);
			else
				ei0 = il.LowPart(2, ei0);
			ei0 = il.SignExtend(4, ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_ISEL:
			REQUIRE4OPS
			{
				LowLevelILLabel trueLabel, falseLabel, doneLabel;
				uint32_t crBit = oper3->reg - PPC_REG_R0;
				uint32_t cr = crBit / 4;

				switch (crBit % 4)
				{
				case 3:
					// summary overflow - no nice conditions right now
					ei0 = il.Flag(IL_FLAG_LT + crBit);
					break;
				default:
					// turn it into the simplest flag groups/conditionals
					// the flag groups representing set bits are always even,
					// and each cr's flag group starts at a multiple of 10
					ei0 = il.FlagGroup(IL_FLAGGROUP_CR0_LT + (cr * 10) + ((crBit % 4) * 2));
					break;
				}

				ei1 = il.Register(4, oper1->reg);
				ei2 = il.Register(4, oper2->reg);
				il.AddInstruction(il.If(ei0, trueLabel, falseLabel));

				/* true case */
				il.MarkLabel(trueLabel);
				ei0 = il.SetRegister(4, oper0->reg, ei1);
				il.AddInstruction(ei0);
				il.AddInstruction(il.Goto(doneLabel));

				/* false case */
				il.MarkLabel(falseLabel);
				ei0 = il.SetRegister(4, oper0->reg, ei2);
				il.AddInstruction(ei0);
				il.AddInstruction(il.Goto(doneLabel));

				/* done */
				il.MarkLabel(doneLabel);
			}
			break;

		case PPC_INS_LMW:
			REQUIRE2OPS
			for(i=oper0->reg; i<=PPC_REG_R31; ++i) {
				ei0 = il.SetRegister(4,
					i,             // dest
					il.Load(4,     // source
						operToIL(il, oper1, OTI_IMM_BIAS, (i-(oper0->reg))*4)
					)
				);

				il.AddInstruction(ei0);
			}

			break;

		/*
			load byte and zero extend [and update]
		*/
		case PPC_INS_LBZ:
		case PPC_INS_LBZU:
			REQUIRE2OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO); // d(rA) or 0
			ei0 = il.Load(1, ei0);                    // [d(rA)]
			ei0 = il.ZeroExtend(4, ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0); // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(insn->id == PPC_INS_LBZU) {
				ei0 = il.SetRegister(4, oper1->mem.base, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load half word [and zero/sign extend] [and update]
		*/
		case PPC_INS_LBZX:
		case PPC_INS_LBZUX:
			REQUIRE3OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO);              // d(rA) or 0
			ei0 = il.Load(1, il.Add(4, ei0, operToIL(il, oper2))); // [d(rA) + d(rB)]
			ei0 = il.ZeroExtend(4, ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0);              // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(insn->id == PPC_INS_LBZUX && oper1->reg != oper0->reg && oper1->reg != PPC_REG_R0) {
				ei0 = il.SetRegister(4, oper1->reg, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load half word [and zero/sign extend] [and update]
		*/
		case PPC_INS_LHZ:
		case PPC_INS_LHZU:
		case PPC_INS_LHA:
		case PPC_INS_LHAU:
			REQUIRE2OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO); // d(rA) or 0
			ei0 = il.Load(2, ei0);                    // [d(rA)]
			if(insn->id == PPC_INS_LHZ || insn->id == PPC_INS_LHZU)
				ei0 = il.ZeroExtend(4, ei0);
			else
				ei0 = il.SignExtend(4, ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0); // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(insn->id == PPC_INS_LHZU || insn->id == PPC_INS_LHAU) {
				ei0 = il.SetRegister(4, oper1->mem.base, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load half word [and zero/sign extend] [and update]
		*/
		case PPC_INS_LHZX:
		case PPC_INS_LHZUX:
		case PPC_INS_LHAX:
		case PPC_INS_LHAUX:
			REQUIRE3OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO);              // d(rA) or 0
			ei0 = il.Load(2, il.Add(4, ei0, operToIL(il, oper2))); // [d(rA) + d(rB)]
			if(insn->id == PPC_INS_LHZX || insn->id == PPC_INS_LHZUX)
				ei0 = il.ZeroExtend(4, ei0);
			else
				ei0 = il.SignExtend(4, ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0);              // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if((insn->id == PPC_INS_LHZUX || insn->id == PPC_INS_LHAUX) && oper1->reg != oper0->reg && oper1->reg != PPC_REG_R0) {
				ei0 = il.SetRegister(4, oper1->reg, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load word [and zero] [and update]
		*/
		case PPC_INS_LWZ:
		case PPC_INS_LWZU:
			REQUIRE2OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO); // d(rA) or 0
			ei0 = il.Load(4, ei0);                    // [d(rA)]
			ei0 = il.SetRegister(4, oper0->reg, ei0); // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(insn->id == PPC_INS_LWZU) {
				ei0 = il.SetRegister(4, oper1->mem.base, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load word [and zero] [and update]
		*/
		case PPC_INS_LWZX:
		case PPC_INS_LWZUX:
			REQUIRE3OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO);              // d(rA) or 0
			ei0 = il.Load(4, il.Add(4, ei0, operToIL(il, oper2))); // [d(rA) + d(rB)]
			ei0 = il.SetRegister(4, oper0->reg, ei0);              // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(insn->id == PPC_INS_LWZUX && oper1->reg != oper0->reg && oper1->reg != PPC_REG_R0) {
				ei0 = il.SetRegister(4, oper1->reg, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		case PPC_INS_LHBRX:
			REQUIRE3OPS
			ByteReversedLoad(il, ppc, 2);
			break;

		case PPC_INS_LWBRX:
			REQUIRE3OPS
			ByteReversedLoad(il, ppc, 4);
			break;

		case PPC_INS_STHBRX:
			REQUIRE3OPS
			ByteReversedStore(il, ppc, 2);
			break;

		case PPC_INS_STWBRX:
			REQUIRE3OPS
			ByteReversedStore(il, ppc, 4);
			break;

		case PPC_INS_MFCTR: // move from ctr
			REQUIRE1OP
			il.AddInstruction(il.SetRegister(4, oper0->reg, il.Register(4, PPC_REG_CTR)));
			break;

		case PPC_INS_MFLR: // move from link register
			REQUIRE1OP
			il.AddInstruction(il.SetRegister(4, oper0->reg, il.Register(4, PPC_REG_LR)));
			break;

		case PPC_INS_MTCTR: // move to ctr
			REQUIRE1OP
			il.AddInstruction(il.SetRegister(4, PPC_REG_CTR, operToIL(il, oper0)));
			break;

		case PPC_INS_MTLR: // move to link register
			REQUIRE1OP
			il.AddInstruction(il.SetRegister(4, PPC_REG_LR, operToIL(il, oper0)));
			break;

		case PPC_INS_NEG:
			REQUIRE2OPS
			ei0 = il.Neg(4, operToIL(il, oper1));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_INS_NOP:
			il.AddInstruction(il.Nop());
			break;

		case PPC_INS_NOT:
			REQUIRE2OPS
			ei0 = il.Not(4, operToIL(il, oper1));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_INS_OR:
		case PPC_INS_ORC:
		case PPC_INS_NOR:
			REQUIRE3OPS
			ei0 = operToIL(il, oper2);
			if (insn->id == PPC_INS_ORC)
				ei0 = il.Not(4, ei0);
			ei0 = il.Or(4, operToIL(il, oper1), ei0);
			if (insn->id == PPC_INS_NOR)
				ei0 = il.Not(4, ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_ORI:
		case PPC_INS_ORIS:
			REQUIRE3OPS
			if (insn->id == PPC_INS_ORIS)
				ei0 = il.Const(4, oper2->imm << 16);
			else
				ei0 = il.Const(4, oper2->imm);
			ei0 = il.Or(4, operToIL(il, oper1), ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_XOR:
		case PPC_INS_EQV:
			REQUIRE3OPS
			ei0 = il.Xor(4,
				operToIL(il, oper1),
				operToIL(il, oper2)
			);
			if (insn->id == PPC_INS_EQV)
				ei0 = il.Not(4, ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_XORI:
		case PPC_INS_XORIS:
			REQUIRE3OPS
			if (insn->id == PPC_INS_XORIS)
				ei0 = il.Const(4, oper2->imm << 16);
			else
				ei0 = il.Const(4, oper2->imm);
			ei0 = il.SetRegister(
				4,
				oper0->reg,
				il.Xor(4,
					operToIL(il, oper1),
					ei0
				)
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_SUBF:
		case PPC_INS_SUBFC:
		case PPC_INS_SUBFIC:
			REQUIRE3OPS
			ei0 = il.Sub(
				4,
				operToIL(il, oper2),
				operToIL(il, oper1),
				(insn->id != PPC_INS_SUBF) ? IL_FLAGWRITE_XER_CA : 0
			);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_SUBFE:
			REQUIRE3OPS
			ei0 = il.SubBorrow(
				4,
				operToIL(il, oper2),
				operToIL(il, oper1),
				il.Flag(IL_FLAG_XER_CA),
				IL_FLAGWRITE_XER_CA
			);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_SUBFME:
		case PPC_INS_SUBFZE:
			REQUIRE2OPS
			if (insn->id == PPC_INS_SUBFME)
				ei0 = il.Const(4, 0xffffffff);
			else
				ei0 = il.Const(4, 0);
			ei0 = il.AddCarry(
				4,
				ei0,
				operToIL(il, oper1),
				il.Flag(IL_FLAG_XER_CA),
				IL_FLAGWRITE_XER_CA
			);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
				ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_STMW:
			REQUIRE2OPS
			for(i=oper0->reg; i<=PPC_REG_R31; ++i) {
				ei0 = il.Register(4, i); // source
				ei1 = operToIL(il, oper1, OTI_IMM_BIAS, (i-(oper0->reg))*4);
				il.AddInstruction(
					il.Store(4,
						ei1,
						ei0
					)
				);
			}

			break;

		/* store half word [with update] */
		case PPC_INS_STB:
		case PPC_INS_STBU: /* store(size, addr, val) */
			REQUIRE2OPS
			ei0 = il.Store(1,
				operToIL(il, oper1, OTI_GPR0_ZERO),
				il.LowPart(1, operToIL(il, oper0))
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(insn->id == PPC_INS_STBU) {
				ei0 = il.SetRegister(4, oper1->mem.base, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		/* store half word indexed [with update] */
		case PPC_INS_STBX:
		case PPC_INS_STBUX: /* store(size, addr, val) */
			REQUIRE3OPS
			ei0 = il.Store(1,
				il.Add(4, operToIL(il, oper1, OTI_GPR0_ZERO), operToIL(il, oper2)),
				il.LowPart(1, operToIL(il, oper0))
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(insn->id == PPC_INS_STBUX) {
				ei0 = il.SetRegister(4, oper1->reg,
					il.Add(4, operToIL(il, oper1), operToIL(il, oper2))
				);
				il.AddInstruction(ei0);
			}

			break;

		/* store half word [with update] */
		case PPC_INS_STH:
		case PPC_INS_STHU: /* store(size, addr, val) */
			REQUIRE2OPS
			ei0 = il.Store(2,
				operToIL(il, oper1, OTI_GPR0_ZERO),
				il.LowPart(2, operToIL(il, oper0))
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(insn->id == PPC_INS_STHU) {
				ei0 = il.SetRegister(4, oper1->mem.base, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		/* store half word indexed [with update] */
		case PPC_INS_STHX:
		case PPC_INS_STHUX: /* store(size, addr, val) */
			REQUIRE3OPS
			ei0 = il.Store(2,
				il.Add(4, operToIL(il, oper1, OTI_GPR0_ZERO), operToIL(il, oper2)),
				il.LowPart(2, operToIL(il, oper0))
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(insn->id == PPC_INS_STHUX) {
				ei0 = il.SetRegister(4, oper1->reg,
					il.Add(4, operToIL(il, oper1), operToIL(il, oper2))
				);
				il.AddInstruction(ei0);
			}

			break;

		/* store word [with update] */
		case PPC_INS_STW:
		case PPC_INS_STWU: /* store(size, addr, val) */
			REQUIRE2OPS
			ei0 = il.Store(4,
				operToIL(il, oper1, OTI_GPR0_ZERO),
				operToIL(il, oper0)
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(insn->id == PPC_INS_STWU) {
				ei0 = il.SetRegister(4, oper1->mem.base, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		/* store word indexed [with update] */
		case PPC_INS_STWX:
		case PPC_INS_STWUX: /* store(size, addr, val) */
			REQUIRE3OPS
			ei0 = il.Store(4,
				il.Add(4, operToIL(il, oper1, OTI_GPR0_ZERO), operToIL(il, oper2)),
				operToIL(il, oper0)
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(insn->id == PPC_INS_STWUX) {
				ei0 = il.SetRegister(4, oper1->reg,
					il.Add(4, operToIL(il, oper1), operToIL(il, oper2))
				);
				il.AddInstruction(ei0);
			}

			break;

		case PPC_INS_RLWIMI:
			REQUIRE5OPS
			{
				uint32_t mask = genMask(oper3->imm, oper4->imm);

				ei0 = il.Register(4, oper1->reg);

				if (oper2->imm != 0)
				{
					if ((mask & (~0u >> (32 - oper2->imm))) == 0)
						ei0 = il.ShiftLeft(4, ei0, il.Const(4, oper2->imm));
					else if ((mask & (~0u << oper2->imm)) == 0)
						ei0 = il.LogicalShiftRight(4, ei0, il.Const(4, 32 - oper2->imm));
					else
						ei0 = il.RotateLeft(4, ei0, il.Const(4, oper2->imm));
				}

				ei0 = il.And(4, ei0, il.Const(4, mask));
				uint32_t invertMask = ~mask;
				ei0 = il.Or(4, il.And(4, il.Register(4, oper0->reg), il.Const(4, invertMask)), ei0);

				ei0 = il.SetRegister(4, oper0->reg, ei0,
						ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
				);
				il.AddInstruction(ei0);
			}
			break;

		case PPC_INS_RLWINM:
			REQUIRE5OPS
			{
				uint32_t mask = genMask(oper3->imm, oper4->imm);

				ei0 = il.Register(4, oper1->reg);

				if (oper2->imm != 0)
				{
					if ((mask & (~0u >> (32 - oper2->imm))) == 0)
					{
						if (mask != 0xffffffff)
							ei0 = il.And(4, ei0, il.Const(4, mask >> oper2->imm));

						ei0 = il.ShiftLeft(4, ei0, il.Const(4, oper2->imm));
					}
					else if ((mask & (~0u << oper2->imm)) == 0)
					{
						if (mask != 0xffffffff)
							ei0 = il.And(4, ei0, il.Const(4, mask << (32 - oper2->imm)));

						ei0 = il.LogicalShiftRight(4, ei0, il.Const(4, 32 - oper2->imm));
					}
					else
					{
						ei0 = il.RotateLeft(4, ei0, il.Const(4, oper2->imm));

						if (mask != 0xffffffff)
							ei0 = il.And(4, ei0, il.Const(4, mask));
					}
				}
				else if (mask != 0xffffffff)
				{
					ei0 = il.And(4, ei0, il.Const(4, mask));
				}

				ei0 = il.SetRegister(4, oper0->reg, ei0,
						ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
				);
				il.AddInstruction(ei0);
			}
			break;

		case PPC_INS_SLWI:
			REQUIRE3OPS
			ei0 = il.Const(4, oper2->imm);           // amt: shift amount
			ei1 = il.Register(4, oper1->reg);        //  rS: reg to be shifted
			ei0 = il.ShiftLeft(4, ei1, ei0);         // (rS << amt)
			ei0 = il.SetRegister(4, oper0->reg, ei0, // rD = (rs << amt)
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_SRWI:
			REQUIRE3OPS
			ei0 = il.Const(4, oper2->imm);           // amt: shift amount
			ei1 = il.Register(4, oper1->reg);        //  rS: reg to be shifted
			ei0 = il.LogicalShiftRight(4, ei1, ei0);        // (rS << amt)
			ei0 = il.SetRegister(4, oper0->reg, ei0, // rD = (rs << amt)
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_CLRLWI:
			REQUIRE3OPS
			ei0 = il.Const(4, (uint32_t) (0xffffffff >> oper2->imm));
			ei1 = il.Register(4, oper1->reg);
			ei0 = il.And(4, ei1, ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_ROTLWI:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.RotateLeft(4, ei0, il.Const(4, oper2->imm));
			ei0 = il.SetRegister(4, oper0->reg, ei0,
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_ROTLW:
		case PPC_INS_RLWNM:
			REQUIRE3OPS
			{
				uint32_t mask = 0xffffffff;
				if (insn->id == PPC_INS_RLWNM)
				{
					REQUIRE5OPS
					mask = genMask(oper3->imm, oper4->imm);
				}
				ei0 = il.Register(4, oper1->reg);
				ei1 = il.Register(4, oper2->reg);
				ei1 = il.And(4, ei1, il.Const(4, 0x1f));
				ei0 = il.RotateLeft(4, ei0, ei1);
				if (mask != 0xffffffff)
					ei0 = il.And(4, ei0, il.Const(4, mask));
				ei0 = il.SetRegister(4, oper0->reg, ei0,
						ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
				);
				il.AddInstruction(ei0);
			}
			break;


		case PPC_INS_SLW:
		case PPC_INS_SRW:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			// permit bit 26 to survive to enable clearing the whole register
			ei1 = il.And(4, il.Register(4, oper2->reg), il.Const(4, 0x3f));
			if (insn->id == PPC_INS_SLW)
				ei0 = il.ShiftLeft(4, ei0, ei1);
			else
				ei0 = il.LogicalShiftRight(4, ei0, ei1);
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_INS_SRAW:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei1 = il.And(4, il.Register(4, oper2->reg), il.Const(4, 0x1f));
			ei0 = il.ArithShiftRight(4, ei0, ei1, IL_FLAGWRITE_XER_CA);
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_INS_SRAWI:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.ArithShiftRight(4, ei0, il.Const(4, oper2->imm), IL_FLAGWRITE_XER_CA);
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_INS_MULLW:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.Mult(4, ei0, il.Register(4, oper2->reg));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_INS_MULLI:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.Mult(4, ei0, il.Const(4, oper2->imm));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0));
			break;

		case PPC_INS_MULHW:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.MultDoublePrecSigned(4, ei0, il.Register(4, oper2->reg));
			ei0 = il.LowPart(4, il.LogicalShiftRight(8, ei0, il.Const(1, 32)));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_INS_MULHWU:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.MultDoublePrecUnsigned(4, ei0, il.Register(4, oper2->reg));
			ei0 = il.LowPart(4, il.LogicalShiftRight(8, ei0, il.Const(1, 32)));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_INS_DIVW:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.DivSigned(4, ei0, il.Register(4, oper2->reg));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_INS_DIVWU:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.DivUnsigned(4, ei0, il.Register(4, oper2->reg));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					ppc->update_cr0 ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_INS_MR: /* move register */
			REQUIRE2OPS
			il.AddInstruction(il.SetRegister(4, oper0->reg, operToIL(il, oper1)));
			break;

		case PPC_INS_SC:
			il.AddInstruction(il.SystemCall());
			break;

		case PPC_INS_RFI:
			il.AddInstruction(il.Return(il.Unimplemented()));
			break;

		case PPC_INS_TRAP:
			il.AddInstruction(il.Trap(0));
			break;

		case PPC_INS_BCL:
		case PPC_INS_BCLR:
		case PPC_INS_BCLRL:
		case PPC_INS_CNTLZD:
		case PPC_INS_CNTLZW:
		case PPC_INS_DCBA:
		case PPC_INS_DCBF:
		case PPC_INS_DCBI:
		case PPC_INS_DCBST:
		case PPC_INS_DCBT:
		case PPC_INS_DCBTST:
		case PPC_INS_DCBZ:
		case PPC_INS_DCBZL:
		case PPC_INS_DCCCI:
		case PPC_INS_DIVD:
		case PPC_INS_DIVDU:
		case PPC_INS_DSS:
		case PPC_INS_DSSALL:
		case PPC_INS_DST:
		case PPC_INS_DSTST:
		case PPC_INS_DSTSTT:
		case PPC_INS_DSTT:
		case PPC_INS_EIEIO:
		case PPC_INS_EVABS:
		case PPC_INS_EVADDIW:
		case PPC_INS_EVADDSMIAAW:
		case PPC_INS_EVADDSSIAAW:
		case PPC_INS_EVADDUMIAAW:
		case PPC_INS_EVADDUSIAAW:
		case PPC_INS_EVADDW:
		case PPC_INS_EVAND:
		case PPC_INS_EVANDC:
		case PPC_INS_EVCMPEQ:
		case PPC_INS_EVCMPGTS:
		case PPC_INS_EVCMPGTU:
		case PPC_INS_EVCMPLTS:
		case PPC_INS_EVCMPLTU:
		case PPC_INS_EVCNTLSW:
		case PPC_INS_EVCNTLZW:
		case PPC_INS_EVDIVWS:
		case PPC_INS_EVDIVWU:
		case PPC_INS_EVEQV:
		case PPC_INS_EVEXTSB:
		case PPC_INS_EVEXTSH:
		case PPC_INS_EVLDD:
		case PPC_INS_EVLDDX:
		case PPC_INS_EVLDH:
		case PPC_INS_EVLDHX:
		case PPC_INS_EVLDW:
		case PPC_INS_EVLDWX:
		case PPC_INS_EVLHHESPLAT:
		case PPC_INS_EVLHHESPLATX:
		case PPC_INS_EVLHHOSSPLAT:
		case PPC_INS_EVLHHOSSPLATX:
		case PPC_INS_EVLHHOUSPLAT:
		case PPC_INS_EVLHHOUSPLATX:
		case PPC_INS_EVLWHE:
		case PPC_INS_EVLWHEX:
		case PPC_INS_EVLWHOS:
		case PPC_INS_EVLWHOSX:
		case PPC_INS_EVLWHOU:
		case PPC_INS_EVLWHOUX:
		case PPC_INS_EVLWHSPLAT:
		case PPC_INS_EVLWHSPLATX:
		case PPC_INS_EVLWWSPLAT:
		case PPC_INS_EVLWWSPLATX:
		case PPC_INS_EVMERGEHI:
		case PPC_INS_EVMERGEHILO:
		case PPC_INS_EVMERGELO:
		case PPC_INS_EVMERGELOHI:
		case PPC_INS_EVMHEGSMFAA:
		case PPC_INS_EVMHEGSMFAN:
		case PPC_INS_EVMHEGSMIAA:
		case PPC_INS_EVMHEGSMIAN:
		case PPC_INS_EVMHEGUMIAA:
		case PPC_INS_EVMHEGUMIAN:
		case PPC_INS_EVMHESMF:
		case PPC_INS_EVMHESMFA:
		case PPC_INS_EVMHESMFAAW:
		case PPC_INS_EVMHESMFANW:
		case PPC_INS_EVMHESMI:
		case PPC_INS_EVMHESMIA:
		case PPC_INS_EVMHESMIAAW:
		case PPC_INS_EVMHESMIANW:
		case PPC_INS_EVMHESSF:
		case PPC_INS_EVMHESSFA:
		case PPC_INS_EVMHESSFAAW:
		case PPC_INS_EVMHESSFANW:
		case PPC_INS_EVMHESSIAAW:
		case PPC_INS_EVMHESSIANW:
		case PPC_INS_EVMHEUMI:
		case PPC_INS_EVMHEUMIA:
		case PPC_INS_EVMHEUMIAAW:
		case PPC_INS_EVMHEUMIANW:
		case PPC_INS_EVMHEUSIAAW:
		case PPC_INS_EVMHEUSIANW:
		case PPC_INS_EVMHOGSMFAA:
		case PPC_INS_EVMHOGSMFAN:
		case PPC_INS_EVMHOGSMIAA:
		case PPC_INS_EVMHOGSMIAN:
		case PPC_INS_EVMHOGUMIAA:
		case PPC_INS_EVMHOGUMIAN:
		case PPC_INS_EVMHOSMF:
		case PPC_INS_EVMHOSMFA:
		case PPC_INS_EVMHOSMFAAW:
		case PPC_INS_EVMHOSMFANW:
		case PPC_INS_EVMHOSMI:
		case PPC_INS_EVMHOSMIA:
		case PPC_INS_EVMHOSMIAAW:
		case PPC_INS_EVMHOSMIANW:
		case PPC_INS_EVMHOSSF:
		case PPC_INS_EVMHOSSFA:
		case PPC_INS_EVMHOSSFAAW:
		case PPC_INS_EVMHOSSFANW:
		case PPC_INS_EVMHOSSIAAW:
		case PPC_INS_EVMHOSSIANW:
		case PPC_INS_EVMHOUMI:
		case PPC_INS_EVMHOUMIA:
		case PPC_INS_EVMHOUMIAAW:
		case PPC_INS_EVMHOUMIANW:
		case PPC_INS_EVMHOUSIAAW:
		case PPC_INS_EVMHOUSIANW:
		case PPC_INS_EVMRA:
		case PPC_INS_EVMWHSMF:
		case PPC_INS_EVMWHSMFA:
		case PPC_INS_EVMWHSMI:
		case PPC_INS_EVMWHSMIA:
		case PPC_INS_EVMWHSSF:
		case PPC_INS_EVMWHSSFA:
		case PPC_INS_EVMWHUMI:
		case PPC_INS_EVMWHUMIA:
		case PPC_INS_EVMWLSMIAAW:
		case PPC_INS_EVMWLSMIANW:
		case PPC_INS_EVMWLSSIAAW:
		case PPC_INS_EVMWLSSIANW:
		case PPC_INS_EVMWLUMI:
		case PPC_INS_EVMWLUMIA:
		case PPC_INS_EVMWLUMIAAW:
		case PPC_INS_EVMWLUMIANW:
		case PPC_INS_EVMWLUSIAAW:
		case PPC_INS_EVMWLUSIANW:
		case PPC_INS_EVMWSMF:
		case PPC_INS_EVMWSMFA:
		case PPC_INS_EVMWSMFAA:
		case PPC_INS_EVMWSMFAN:
		case PPC_INS_EVMWSMI:
		case PPC_INS_EVMWSMIA:
		case PPC_INS_EVMWSMIAA:
		case PPC_INS_EVMWSMIAN:
		case PPC_INS_EVMWSSF:
		case PPC_INS_EVMWSSFA:
		case PPC_INS_EVMWSSFAA:
		case PPC_INS_EVMWSSFAN:
		case PPC_INS_EVMWUMI:
		case PPC_INS_EVMWUMIA:
		case PPC_INS_EVMWUMIAA:
		case PPC_INS_EVMWUMIAN:
		case PPC_INS_EVNAND:
		case PPC_INS_EVNEG:
		case PPC_INS_EVNOR:
		case PPC_INS_EVOR:
		case PPC_INS_EVORC:
		case PPC_INS_EVRLW:
		case PPC_INS_EVRLWI:
		case PPC_INS_EVRNDW:
		case PPC_INS_EVSLW:
		case PPC_INS_EVSLWI:
		case PPC_INS_EVSPLATFI:
		case PPC_INS_EVSPLATI:
		case PPC_INS_EVSRWIS:
		case PPC_INS_EVSRWIU:
		case PPC_INS_EVSRWS:
		case PPC_INS_EVSRWU:
		case PPC_INS_EVSTDD:
		case PPC_INS_EVSTDDX:
		case PPC_INS_EVSTDH:
		case PPC_INS_EVSTDHX:
		case PPC_INS_EVSTDW:
		case PPC_INS_EVSTDWX:
		case PPC_INS_EVSTWHE:
		case PPC_INS_EVSTWHEX:
		case PPC_INS_EVSTWHO:
		case PPC_INS_EVSTWHOX:
		case PPC_INS_EVSTWWE:
		case PPC_INS_EVSTWWEX:
		case PPC_INS_EVSTWWO:
		case PPC_INS_EVSTWWOX:
		case PPC_INS_EVSUBFSMIAAW:
		case PPC_INS_EVSUBFSSIAAW:
		case PPC_INS_EVSUBFUMIAAW:
		case PPC_INS_EVSUBFUSIAAW:
		case PPC_INS_EVSUBFW:
		case PPC_INS_EVSUBIFW:
		case PPC_INS_EVXOR:
		case PPC_INS_EXTSW:
		case PPC_INS_FABS:
		case PPC_INS_FADD:
		case PPC_INS_FADDS:
		case PPC_INS_FCFID:
		case PPC_INS_FCFIDS:
		case PPC_INS_FCFIDU:
		case PPC_INS_FCFIDUS:
		case PPC_INS_FCPSGN:
		case PPC_INS_FCTID:
		case PPC_INS_FCTIDUZ:
		case PPC_INS_FCTIDZ:
		case PPC_INS_FCTIW:
		case PPC_INS_FCTIWUZ:
		case PPC_INS_FCTIWZ:
		case PPC_INS_FDIV:
		case PPC_INS_FDIVS:
		case PPC_INS_FMADD:
		case PPC_INS_FMADDS:
		case PPC_INS_FMR:
		case PPC_INS_FMSUB:
		case PPC_INS_FMSUBS:
		case PPC_INS_FMUL:
		case PPC_INS_FMULS:
		case PPC_INS_FNABS:
		case PPC_INS_FNEG:
		case PPC_INS_FNMADD:
		case PPC_INS_FNMADDS:
		case PPC_INS_FNMSUB:
		case PPC_INS_FNMSUBS:
		case PPC_INS_FRE:
		case PPC_INS_FRES:
		case PPC_INS_FRIM:
		case PPC_INS_FRIN:
		case PPC_INS_FRIP:
		case PPC_INS_FRIZ:
		case PPC_INS_FRSP:
		case PPC_INS_FRSQRTE:
		case PPC_INS_FRSQRTES:
		case PPC_INS_FSEL:
		case PPC_INS_FSQRT:
		case PPC_INS_FSQRTS:
		case PPC_INS_FSUB:
		case PPC_INS_FSUBS:
		case PPC_INS_ICBI:
		case PPC_INS_ICCCI:
		case PPC_INS_ISYNC:
		case PPC_INS_LD:
		case PPC_INS_LDARX:
		case PPC_INS_LDBRX:
		case PPC_INS_LDU:
		case PPC_INS_LDUX:
		case PPC_INS_LDX:
		case PPC_INS_LFD:
		case PPC_INS_LFDU:
		case PPC_INS_LFDUX:
		case PPC_INS_LFDX:
		case PPC_INS_LFIWAX:
		case PPC_INS_LFIWZX:
		case PPC_INS_LFS:
		case PPC_INS_LFSU:
		case PPC_INS_LFSUX:
		case PPC_INS_LFSX:
		case PPC_INS_LSWI:
		case PPC_INS_LVEBX:
		case PPC_INS_LVEHX:
		case PPC_INS_LVEWX:
		case PPC_INS_LVSL:
		case PPC_INS_LVSR:
		case PPC_INS_LVX:
		case PPC_INS_LVXL:
		case PPC_INS_LWA:
		case PPC_INS_LWARX:
		case PPC_INS_LWAUX:
		case PPC_INS_LWAX:
		case PPC_INS_LXSDX:
		case PPC_INS_LXVD2X:
		case PPC_INS_LXVDSX:
		case PPC_INS_LXVW4X:
		case PPC_INS_MBAR:
		case PPC_INS_MCRF:
		case PPC_INS_MFDCR:
		case PPC_INS_MFFS:
		case PPC_INS_MFMSR:
		case PPC_INS_MFOCRF:
		case PPC_INS_MFSPR:
		case PPC_INS_MFSR:
		case PPC_INS_MFSRIN:
		case PPC_INS_MFTB:
		case PPC_INS_MFVSCR:
		case PPC_INS_MSYNC:
		case PPC_INS_MTDCR:
		case PPC_INS_MTFSB0:
		case PPC_INS_MTFSB1:
		case PPC_INS_MTFSF:
		case PPC_INS_MTMSR:
		case PPC_INS_MTMSRD:
		case PPC_INS_MTOCRF:
		case PPC_INS_MTSPR:
		case PPC_INS_MTSR:
		case PPC_INS_MTSRIN:
		case PPC_INS_MTVSCR:
		case PPC_INS_MULHD:
		case PPC_INS_MULHDU:
		case PPC_INS_MULLD:
		case PPC_INS_POPCNTD:
		case PPC_INS_POPCNTW:
		case PPC_INS_RFCI:
		case PPC_INS_RFDI:
		case PPC_INS_RFID:
		case PPC_INS_RFMCI:
		case PPC_INS_RLDCL:
		case PPC_INS_RLDCR:
		case PPC_INS_RLDIC:
		case PPC_INS_RLDICL:
		case PPC_INS_RLDICR:
		case PPC_INS_RLDIMI:
		case PPC_INS_SLBIA:
		case PPC_INS_SLBIE:
		case PPC_INS_SLBMFEE:
		case PPC_INS_SLBMTE:
		case PPC_INS_SLD:
		case PPC_INS_SRAD:
		case PPC_INS_SRADI:
		case PPC_INS_SRD:
		case PPC_INS_STD:
		case PPC_INS_STDBRX:
		case PPC_INS_STDCX:
		case PPC_INS_STDU:
		case PPC_INS_STDUX:
		case PPC_INS_STDX:
		case PPC_INS_STFD:
		case PPC_INS_STFDU:
		case PPC_INS_STFDUX:
		case PPC_INS_STFDX:
		case PPC_INS_STFIWX:
		case PPC_INS_STFS:
		case PPC_INS_STFSU:
		case PPC_INS_STFSUX:
		case PPC_INS_STFSX:
		case PPC_INS_STSWI:
		case PPC_INS_STVEBX:
		case PPC_INS_STVEHX:
		case PPC_INS_STVEWX:
		case PPC_INS_STVX:
		case PPC_INS_STVXL:
		case PPC_INS_STWCX:
		case PPC_INS_STXSDX:
		case PPC_INS_STXVD2X:
		case PPC_INS_STXVW4X:
		case PPC_INS_SYNC:
		case PPC_INS_TD:
		case PPC_INS_TDI:
		case PPC_INS_TLBIA:
		case PPC_INS_TLBIE:
		case PPC_INS_TLBIEL:
		case PPC_INS_TLBIVAX:
		case PPC_INS_TLBLD:
		case PPC_INS_TLBLI:
		case PPC_INS_TLBRE:
		case PPC_INS_TLBSX:
		case PPC_INS_TLBSYNC:
		case PPC_INS_TLBWE:
		case PPC_INS_TW:
		case PPC_INS_TWI:
		case PPC_INS_VADDCUW:
		case PPC_INS_VADDFP:
		case PPC_INS_VADDSBS:
		case PPC_INS_VADDSHS:
		case PPC_INS_VADDSWS:
		case PPC_INS_VADDUBM:
		case PPC_INS_VADDUBS:
		case PPC_INS_VADDUHM:
		case PPC_INS_VADDUHS:
		case PPC_INS_VADDUWM:
		case PPC_INS_VADDUWS:
		case PPC_INS_VAND:
		case PPC_INS_VANDC:
		case PPC_INS_VAVGSB:
		case PPC_INS_VAVGSH:
		case PPC_INS_VAVGSW:
		case PPC_INS_VAVGUB:
		case PPC_INS_VAVGUH:
		case PPC_INS_VAVGUW:
		case PPC_INS_VCFSX:
		case PPC_INS_VCFUX:
		case PPC_INS_VCMPBFP:
		case PPC_INS_VCMPEQFP:
		case PPC_INS_VCMPEQUB:
		case PPC_INS_VCMPEQUH:
		case PPC_INS_VCMPEQUW:
		case PPC_INS_VCMPGEFP:
		case PPC_INS_VCMPGTFP:
		case PPC_INS_VCMPGTSB:
		case PPC_INS_VCMPGTSH:
		case PPC_INS_VCMPGTSW:
		case PPC_INS_VCMPGTUB:
		case PPC_INS_VCMPGTUH:
		case PPC_INS_VCMPGTUW:
		case PPC_INS_VCTSXS:
		case PPC_INS_VCTUXS:
		case PPC_INS_VEXPTEFP:
		case PPC_INS_VLOGEFP:
		case PPC_INS_VMADDFP:
		case PPC_INS_VMAXFP:
		case PPC_INS_VMAXSB:
		case PPC_INS_VMAXSH:
		case PPC_INS_VMAXSW:
		case PPC_INS_VMAXUB:
		case PPC_INS_VMAXUH:
		case PPC_INS_VMAXUW:
		case PPC_INS_VMHADDSHS:
		case PPC_INS_VMHRADDSHS:
		case PPC_INS_VMINFP:
		case PPC_INS_VMINSB:
		case PPC_INS_VMINSH:
		case PPC_INS_VMINSW:
		case PPC_INS_VMINUB:
		case PPC_INS_VMINUH:
		case PPC_INS_VMINUW:
		case PPC_INS_VMLADDUHM:
		case PPC_INS_VMRGHB:
		case PPC_INS_VMRGHH:
		case PPC_INS_VMRGHW:
		case PPC_INS_VMRGLB:
		case PPC_INS_VMRGLH:
		case PPC_INS_VMRGLW:
		case PPC_INS_VMSUMMBM:
		case PPC_INS_VMSUMSHM:
		case PPC_INS_VMSUMSHS:
		case PPC_INS_VMSUMUBM:
		case PPC_INS_VMSUMUHM:
		case PPC_INS_VMSUMUHS:
		case PPC_INS_VMULESB:
		case PPC_INS_VMULESH:
		case PPC_INS_VMULEUB:
		case PPC_INS_VMULEUH:
		case PPC_INS_VMULOSB:
		case PPC_INS_VMULOSH:
		case PPC_INS_VMULOUB:
		case PPC_INS_VMULOUH:
		case PPC_INS_VNMSUBFP:
		case PPC_INS_VNOR:
		case PPC_INS_VOR:
		case PPC_INS_VPERM:
		case PPC_INS_VPKPX:
		case PPC_INS_VPKSHSS:
		case PPC_INS_VPKSHUS:
		case PPC_INS_VPKSWSS:
		case PPC_INS_VPKSWUS:
		case PPC_INS_VPKUHUM:
		case PPC_INS_VPKUHUS:
		case PPC_INS_VPKUWUM:
		case PPC_INS_VPKUWUS:
		case PPC_INS_VREFP:
		case PPC_INS_VRFIM:
		case PPC_INS_VRFIN:
		case PPC_INS_VRFIP:
		case PPC_INS_VRFIZ:
		case PPC_INS_VRLB:
		case PPC_INS_VRLH:
		case PPC_INS_VRLW:
		case PPC_INS_VRSQRTEFP:
		case PPC_INS_VSEL:
		case PPC_INS_VSL:
		case PPC_INS_VSLB:
		case PPC_INS_VSLDOI:
		case PPC_INS_VSLH:
		case PPC_INS_VSLO:
		case PPC_INS_VSLW:
		case PPC_INS_VSPLTB:
		case PPC_INS_VSPLTH:
		case PPC_INS_VSPLTISB:
		case PPC_INS_VSPLTISH:
		case PPC_INS_VSPLTISW:
		case PPC_INS_VSPLTW:
		case PPC_INS_VSR:
		case PPC_INS_VSRAB:
		case PPC_INS_VSRAH:
		case PPC_INS_VSRAW:
		case PPC_INS_VSRB:
		case PPC_INS_VSRH:
		case PPC_INS_VSRO:
		case PPC_INS_VSRW:
		case PPC_INS_VSUBCUW:
		case PPC_INS_VSUBFP:
		case PPC_INS_VSUBSBS:
		case PPC_INS_VSUBSHS:
		case PPC_INS_VSUBSWS:
		case PPC_INS_VSUBUBM:
		case PPC_INS_VSUBUBS:
		case PPC_INS_VSUBUHM:
		case PPC_INS_VSUBUHS:
		case PPC_INS_VSUBUWM:
		case PPC_INS_VSUBUWS:
		case PPC_INS_VSUM2SWS:
		case PPC_INS_VSUM4SBS:
		case PPC_INS_VSUM4SHS:
		case PPC_INS_VSUM4UBS:
		case PPC_INS_VSUMSWS:
		case PPC_INS_VUPKHPX:
		case PPC_INS_VUPKHSB:
		case PPC_INS_VUPKHSH:
		case PPC_INS_VUPKLPX:
		case PPC_INS_VUPKLSB:
		case PPC_INS_VUPKLSH:
		case PPC_INS_VXOR:
		case PPC_INS_WAIT:
		case PPC_INS_WRTEE:
		case PPC_INS_WRTEEI:
		case PPC_INS_XSABSDP:
		case PPC_INS_XSADDDP:
		case PPC_INS_XSCMPODP:
		case PPC_INS_XSCMPUDP:
		case PPC_INS_XSCPSGNDP:
		case PPC_INS_XSCVDPSP:
		case PPC_INS_XSCVDPSXDS:
		case PPC_INS_XSCVDPSXWS:
		case PPC_INS_XSCVDPUXDS:
		case PPC_INS_XSCVDPUXWS:
		case PPC_INS_XSCVSPDP:
		case PPC_INS_XSCVSXDDP:
		case PPC_INS_XSCVUXDDP:
		case PPC_INS_XSDIVDP:
		case PPC_INS_XSMADDADP:
		case PPC_INS_XSMADDMDP:
		case PPC_INS_XSMAXDP:
		case PPC_INS_XSMINDP:
		case PPC_INS_XSMSUBADP:
		case PPC_INS_XSMSUBMDP:
		case PPC_INS_XSMULDP:
		case PPC_INS_XSNABSDP:
		case PPC_INS_XSNEGDP:
		case PPC_INS_XSNMADDADP:
		case PPC_INS_XSNMADDMDP:
		case PPC_INS_XSNMSUBADP:
		case PPC_INS_XSNMSUBMDP:
		case PPC_INS_XSRDPI:
		case PPC_INS_XSRDPIC:
		case PPC_INS_XSRDPIM:
		case PPC_INS_XSRDPIP:
		case PPC_INS_XSRDPIZ:
		case PPC_INS_XSREDP:
		case PPC_INS_XSRSQRTEDP:
		case PPC_INS_XSSQRTDP:
		case PPC_INS_XSSUBDP:
		case PPC_INS_XSTDIVDP:
		case PPC_INS_XSTSQRTDP:
		case PPC_INS_XVABSDP:
		case PPC_INS_XVABSSP:
		case PPC_INS_XVADDDP:
		case PPC_INS_XVADDSP:
		case PPC_INS_XVCMPEQDP:
		case PPC_INS_XVCMPEQSP:
		case PPC_INS_XVCMPGEDP:
		case PPC_INS_XVCMPGESP:
		case PPC_INS_XVCMPGTDP:
		case PPC_INS_XVCMPGTSP:
		case PPC_INS_XVCPSGNDP:
		case PPC_INS_XVCPSGNSP:
		case PPC_INS_XVCVDPSP:
		case PPC_INS_XVCVDPSXDS:
		case PPC_INS_XVCVDPSXWS:
		case PPC_INS_XVCVDPUXDS:
		case PPC_INS_XVCVDPUXWS:
		case PPC_INS_XVCVSPDP:
		case PPC_INS_XVCVSPSXDS:
		case PPC_INS_XVCVSPSXWS:
		case PPC_INS_XVCVSPUXDS:
		case PPC_INS_XVCVSPUXWS:
		case PPC_INS_XVCVSXDDP:
		case PPC_INS_XVCVSXDSP:
		case PPC_INS_XVCVSXWDP:
		case PPC_INS_XVCVSXWSP:
		case PPC_INS_XVCVUXDDP:
		case PPC_INS_XVCVUXDSP:
		case PPC_INS_XVCVUXWDP:
		case PPC_INS_XVCVUXWSP:
		case PPC_INS_XVDIVDP:
		case PPC_INS_XVDIVSP:
		case PPC_INS_XVMADDADP:
		case PPC_INS_XVMADDASP:
		case PPC_INS_XVMADDMDP:
		case PPC_INS_XVMADDMSP:
		case PPC_INS_XVMAXDP:
		case PPC_INS_XVMAXSP:
		case PPC_INS_XVMINDP:
		case PPC_INS_XVMINSP:
		case PPC_INS_XVMSUBADP:
		case PPC_INS_XVMSUBASP:
		case PPC_INS_XVMSUBMDP:
		case PPC_INS_XVMSUBMSP:
		case PPC_INS_XVMULDP:
		case PPC_INS_XVMULSP:
		case PPC_INS_XVNABSDP:
		case PPC_INS_XVNABSSP:
		case PPC_INS_XVNEGDP:
		case PPC_INS_XVNEGSP:
		case PPC_INS_XVNMADDADP:
		case PPC_INS_XVNMADDASP:
		case PPC_INS_XVNMADDMDP:
		case PPC_INS_XVNMADDMSP:
		case PPC_INS_XVNMSUBADP:
		case PPC_INS_XVNMSUBASP:
		case PPC_INS_XVNMSUBMDP:
		case PPC_INS_XVNMSUBMSP:
		case PPC_INS_XVRDPI:
		case PPC_INS_XVRDPIC:
		case PPC_INS_XVRDPIM:
		case PPC_INS_XVRDPIP:
		case PPC_INS_XVRDPIZ:
		case PPC_INS_XVREDP:
		case PPC_INS_XVRESP:
		case PPC_INS_XVRSPI:
		case PPC_INS_XVRSPIC:
		case PPC_INS_XVRSPIM:
		case PPC_INS_XVRSPIP:
		case PPC_INS_XVRSPIZ:
		case PPC_INS_XVRSQRTEDP:
		case PPC_INS_XVRSQRTESP:
		case PPC_INS_XVSQRTDP:
		case PPC_INS_XVSQRTSP:
		case PPC_INS_XVSUBDP:
		case PPC_INS_XVSUBSP:
		case PPC_INS_XVTDIVDP:
		case PPC_INS_XVTDIVSP:
		case PPC_INS_XVTSQRTDP:
		case PPC_INS_XVTSQRTSP:
		case PPC_INS_XXLAND:
		case PPC_INS_XXLANDC:
		case PPC_INS_XXLNOR:
		case PPC_INS_XXLOR:
		case PPC_INS_XXLXOR:
		case PPC_INS_XXMRGHW:
		case PPC_INS_XXMRGLW:
		case PPC_INS_XXPERMDI:
		case PPC_INS_XXSEL:
		case PPC_INS_XXSLDWI:
		case PPC_INS_XXSPLTW:
		case PPC_INS_BCA:
		case PPC_INS_BCLA:
		case PPC_INS_SLDI:
		case PPC_INS_BTA:
		case PPC_INS_MFBR0:
		case PPC_INS_MFBR1:
		case PPC_INS_MFBR2:
		case PPC_INS_MFBR3:
		case PPC_INS_MFBR4:
		case PPC_INS_MFBR5:
		case PPC_INS_MFBR6:
		case PPC_INS_MFBR7:
		case PPC_INS_MFXER:
		case PPC_INS_MFRTCU:
		case PPC_INS_MFRTCL:
		case PPC_INS_MFDSCR:
		case PPC_INS_MFDSISR:
		case PPC_INS_MFDAR:
		case PPC_INS_MFSRR2:
		case PPC_INS_MFSRR3:
		case PPC_INS_MFCFAR:
		case PPC_INS_MFAMR:
		case PPC_INS_MFPID:
		case PPC_INS_MFTBLO:
		case PPC_INS_MFTBHI:
		case PPC_INS_MFDBATU:
		case PPC_INS_MFDBATL:
		case PPC_INS_MFIBATU:
		case PPC_INS_MFIBATL:
		case PPC_INS_MFDCCR:
		case PPC_INS_MFICCR:
		case PPC_INS_MFDEAR:
		case PPC_INS_MFESR:
		case PPC_INS_MFSPEFSCR:
		case PPC_INS_MFTCR:
		case PPC_INS_MFASR:
		case PPC_INS_MFPVR:
		case PPC_INS_MFTBU:
		case PPC_INS_MTCR:
		case PPC_INS_MTBR0:
		case PPC_INS_MTBR1:
		case PPC_INS_MTBR2:
		case PPC_INS_MTBR3:
		case PPC_INS_MTBR4:
		case PPC_INS_MTBR5:
		case PPC_INS_MTBR6:
		case PPC_INS_MTBR7:
		case PPC_INS_MTXER:
		case PPC_INS_MTDSCR:
		case PPC_INS_MTDSISR:
		case PPC_INS_MTDAR:
		case PPC_INS_MTSRR2:
		case PPC_INS_MTSRR3:
		case PPC_INS_MTCFAR:
		case PPC_INS_MTAMR:
		case PPC_INS_MTPID:
		case PPC_INS_MTTBL:
		case PPC_INS_MTTBU:
		case PPC_INS_MTTBLO:
		case PPC_INS_MTTBHI:
		case PPC_INS_MTDBATU:
		case PPC_INS_MTDBATL:
		case PPC_INS_MTIBATU:
		case PPC_INS_MTIBATL:
		case PPC_INS_MTDCCR:
		case PPC_INS_MTICCR:
		case PPC_INS_MTDEAR:
		case PPC_INS_MTESR:
		case PPC_INS_MTSPEFSCR:
		case PPC_INS_MTTCR:
		case PPC_INS_ROTLD:
		case PPC_INS_ROTLDI:
		case PPC_INS_CLRLDI:
		case PPC_INS_SUB:
		case PPC_INS_SUBC:
		case PPC_INS_LWSYNC:
		case PPC_INS_PTESYNC:
		case PPC_INS_TDLT:
		case PPC_INS_TDEQ:
		case PPC_INS_TDGT:
		case PPC_INS_TDNE:
		case PPC_INS_TDLLT:
		case PPC_INS_TDLGT:
		case PPC_INS_TDU:
		case PPC_INS_TDLTI:
		case PPC_INS_TDEQI:
		case PPC_INS_TDGTI:
		case PPC_INS_TDNEI:
		case PPC_INS_TDLLTI:
		case PPC_INS_TDLGTI:
		case PPC_INS_TDUI:
		case PPC_INS_TLBREHI:
		case PPC_INS_TLBRELO:
		case PPC_INS_TLBWEHI:
		case PPC_INS_TLBWELO:
		case PPC_INS_TWLT:
		case PPC_INS_TWEQ:
		case PPC_INS_TWGT:
		case PPC_INS_TWNE:
		case PPC_INS_TWLLT:
		case PPC_INS_TWLGT:
		case PPC_INS_TWU:
		case PPC_INS_TWLTI:
		case PPC_INS_TWEQI:
		case PPC_INS_TWGTI:
		case PPC_INS_TWNEI:
		case PPC_INS_TWLLTI:
		case PPC_INS_TWLGTI:
		case PPC_INS_TWUI:
		case PPC_INS_WAITRSV:
		case PPC_INS_WAITIMPL:
		case PPC_INS_XNOP:
		case PPC_INS_XVMOVDP:
		case PPC_INS_XVMOVSP:
		case PPC_INS_XXSPLTD:
		case PPC_INS_XXMRGHD:
		case PPC_INS_XXMRGLD:
		case PPC_INS_XXSWAPD:
		case PPC_INS_BT:
		case PPC_INS_BF:
		case PPC_INS_BDNZT:
		case PPC_INS_BDNZF:
		case PPC_INS_BDZF:
		case PPC_INS_BDZT:
		case PPC_INS_BFA:
		case PPC_INS_BDNZTA:
		case PPC_INS_BDNZFA:
		case PPC_INS_BDZTA:
		case PPC_INS_BDZFA:
		case PPC_INS_BTCTR:
		case PPC_INS_BFCTR:
		case PPC_INS_BTCTRL:
		case PPC_INS_BFCTRL:
		case PPC_INS_BTL:
		case PPC_INS_BFL:
		case PPC_INS_BDNZTL:
		case PPC_INS_BDNZFL:
		case PPC_INS_BDZTL:
		case PPC_INS_BDZFL:
		case PPC_INS_BTLA:
		case PPC_INS_BFLA:
		case PPC_INS_BDNZTLA:
		case PPC_INS_BDNZFLA:
		case PPC_INS_BDZTLA:
		case PPC_INS_BDZFLA:
		case PPC_INS_BTLR:
		case PPC_INS_BFLR:
		case PPC_INS_BDNZTLR:
		case PPC_INS_BDZTLR:
		case PPC_INS_BDZFLR:
		case PPC_INS_BTLRL:
		case PPC_INS_BFLRL:
		case PPC_INS_BDNZTLRL:
		case PPC_INS_BDNZFLRL:
		case PPC_INS_BDZTLRL:
		case PPC_INS_BDZFLRL:
		case PPC_INS_BRINC:

		ReturnUnimpl:
		default:
			MYLOG("%s:%s() returning Unimplemented(...) on:\n",
			  __FILE__, __func__);

			MYLOG("    %08llx: %02X %02X %02X %02X %s %s\n",
			  addr, data[0], data[1], data[2], data[3],
			  res->insn.mnemonic, res->insn.op_str);

			il.AddInstruction(il.Unimplemented());
	}

	return rc;
}

