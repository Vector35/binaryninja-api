#include "lowlevelilinstruction.h"
#include <binaryninjaapi.h>

#include "decode/decode.h"

using namespace BinaryNinja;

#include "il.h"
#include "util.h"

#define OTI_IMM_BIAS 1024
#define OTI_GPR0_ZERO 2048

#define MYLOG(...) while(0);
// #define MYLOG BinaryNinja::LogWarn

static uint32_t genMask(uint32_t mb, uint32_t me)
{
	uint32_t maskBegin = ~0u >> mb;
	uint32_t maskEnd = ~0u << (31 - me);

	return (mb <= me) ? (maskBegin & maskEnd) : (maskBegin | maskEnd);
}

#define PPC_IL_OPTIONS_DEFAULT	0
#define PPC_IL_EXTRA_DEFAULT	0
#define RZF 4

static ExprId operToIL(LowLevelILFunction &il, Operand* op,
	int options=PPC_IL_OPTIONS_DEFAULT, uint64_t extra=PPC_IL_EXTRA_DEFAULT, size_t regsz=4)
{
	ExprId res;

	if (!op)
	{
		MYLOG("ERROR: operToIL() got NULL operand\n");
		return il.Unimplemented();
	}

	switch (op->cls)
	{
		case PPC_OP_REG_RA:
		case PPC_OP_REG_RB:
		case PPC_OP_REG_RD:
		case PPC_OP_REG_RS:
			if (options & OTI_GPR0_ZERO && op->reg == PPC_REG_GPR0)
				res = il.Const(regsz, 0);
			else
				res = il.Register(regsz, op->reg);
			break;

		case PPC_OP_SIMM:
			if (options & OTI_IMM_BIAS)
			{
				/* the immediate should be biased with given value */
				res = il.Const(regsz, op->simm + extra);
			}
			else
			{
				/* the immediate is just a plain boring immediate */
				res = il.Const(regsz, op->simm);
			}
			break;

		case PPC_OP_UIMM:
			if (options & OTI_IMM_BIAS)
			{
				/* the immediate should be biased with given value */
				res = il.Const(regsz, op->uimm + extra);
			}
			else
			{
				/* the immediate is just a plain boring immediate */
				res = il.Const(regsz, op->uimm);
			}
			break;

		case PPC_OP_MEM_RA:
			if (options & OTI_GPR0_ZERO && op->mem.reg == PPC_REG_GPR0)
				res = il.Const(regsz, 0);
			else
				res = il.Register(regsz, op->mem.reg);

			if(options & OTI_IMM_BIAS)
				res = il.Add(regsz, res, il.Const(regsz, op->mem.offset + extra));
			else
				res = il.Add(regsz, res, il.Const(regsz, op->mem.offset));
			break;

		case PPC_OP_NONE:
		default:
			MYLOG("ERROR: don't know how to convert operand to IL\n");
			res = il.Unimplemented();
	}

	return res;
}

#define operToIL_a(il, op, regSz) operToIL(il, op, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, regSz)

/* map PPC_REG_CRX to an IL flagwrite type (a named set of written flags */
int crxToFlagWriteType(Register reg, ppc_suf suf)
{
	if ((reg < PPC_REG_CRF0) || (reg > PPC_REG_CRF7))
		return IL_FLAGWRITE_NONE;

	/* when we have more flags... */
	int crx_index = reg - PPC_REG_CRF0;
	return (crx_index * PPC_SUF_SZ) + IL_FLAGWRITE_CR0_S + suf;
}

static ExprId ExtractConditionClause(LowLevelILFunction& il, uint8_t crBit, bool negate = false)
{
	// MYLOG("%s() crbit:%x", __func__, crBit);
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


static bool LiftConditionalBranch(LowLevelILFunction& il, uint8_t bo, uint8_t bi, BNLowLevelILLabel& takenLabel, BNLowLevelILLabel& falseLabel, size_t addressSize_a=4)
{
	bool testsCtr = !(bo & 4);
	bool testsCrBit = !(bo & 0x10);
	bool isConditional = testsCtr || testsCrBit;

	if (testsCtr)
	{
		ExprId cond, left, right;

		il.AddInstruction(
			il.SetRegister(addressSize_a, PPC_REG_CTR,
				il.Sub(addressSize_a,
					il.Register(addressSize_a, PPC_REG_CTR),
					il.Const(addressSize_a, 1))));

		left = il.Register(addressSize_a, PPC_REG_CTR);
		right = il.Const(addressSize_a, 0);

		if (bo & 2)
			cond = il.CompareEqual(addressSize_a, left, right);
		else
			cond = il.CompareNotEqual(addressSize_a, left, right);

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

static bool LiftBranches(Architecture* arch, LowLevelILFunction &il, const Instruction *instruction, uint64_t addr)
{
	size_t addressSize_l = arch->GetAddressSize();
	switch (instruction->id)
	{
		case PPC_ID_Bx:
		{
			uint64_t target = instruction->operands[0].label;

			BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);

			if (label && !(instruction->flags.lk && (target != (addr+4))))
			{
				/* branch to an instruction within the same function -- take
				 * 'lk' bit behavior into account, but don't emit as a call
				 */
				if (instruction->flags.lk)
				{
					il.AddInstruction(il.SetRegister(addressSize_l, PPC_REG_LR, il.ConstPointer(addressSize_l, addr + 4)));
				}	

				il.AddInstruction(il.Goto(*label));
			}
			else
			{
				ExprId dest = il.ConstPointer(addressSize_l, target);

				if (instruction->flags.lk)
					il.AddInstruction(il.Call(dest));
				else
					il.AddInstruction(il.Jump(dest));
			}

			break;
		}
		case PPC_ID_BCx: /* bc */
		{
			uint8_t bo = instruction->operands[0].uimm;
			uint8_t bi = instruction->operands[1].uimm;
			uint64_t target = instruction->operands[2].label;

			BNLowLevelILLabel *existingTakenLabel = il.GetLabelForAddress(arch, target);
			BNLowLevelILLabel *existingFalseLabel = il.GetLabelForAddress(arch, addr + 4);

			if (instruction->flags.lk)
			{
				il.AddInstruction(il.SetRegister(addressSize_l, PPC_REG_LR, il.ConstPointer(addressSize_l, addr + 4)));
			}

			LowLevelILLabel takenLabelManual, falseLabelManual;
			BNLowLevelILLabel* takenLabel = existingTakenLabel;
			BNLowLevelILLabel* falseLabel = existingFalseLabel;

			if (!takenLabel)
				takenLabel = &takenLabelManual;

			if (!falseLabel)
				falseLabel = &falseLabelManual;

			bool wasConditionalBranch = LiftConditionalBranch(il, bo, bi, *takenLabel, *falseLabel, addressSize_l);

			if (wasConditionalBranch && !existingTakenLabel)
			{
				il.MarkLabel(*takenLabel);
			}

			if (!wasConditionalBranch && existingTakenLabel)
			{
				il.AddInstruction(il.Goto(*takenLabel));
			}
			else if (target != addr + 4)
			{
				if (instruction->flags.lk)
				{
					il.AddInstruction(il.Call(il.ConstPointer(addressSize_l, target)));
					if (wasConditionalBranch)
					{
						il.AddInstruction(il.Goto(*falseLabel));
					}
				}
				else
					il.AddInstruction(il.Jump(il.ConstPointer(addressSize_l, target)));
			}

			if (wasConditionalBranch && !existingFalseLabel)
			{
				il.MarkLabel(*falseLabel);
			}

			break;
		}
		case PPC_ID_BCCTRx: /* bcctr, bclr */
		case PPC_ID_BCLRx:
		{
			uint8_t bo = instruction->operands[0].uimm;
			uint8_t bi = instruction->operands[1].uimm;
			bool blr = false;
			ExprId expr;
			switch (instruction->id)
			{
				case PPC_ID_BCCTRx:
					if (!(bo & 0x4))
						return false;
					expr = il.Register(addressSize_l, PPC_REG_CTR);
					blr = false;
					break;
				case PPC_ID_BCLRx:
					expr = il.Register(addressSize_l, PPC_REG_LR);
					blr = true;
					break;
				default:
					return false;
			}

			BNLowLevelILLabel *existingFalseLabel = il.GetLabelForAddress(arch, addr + 4);
			BNLowLevelILLabel* falseLabel = existingFalseLabel;

			LowLevelILLabel takenLabel, falseLabelManual;

			if (!falseLabel)
				falseLabel = &falseLabelManual;

			bool wasConditionalBranch = LiftConditionalBranch(il, bo, bi, takenLabel, *falseLabel, addressSize_l);

			if (wasConditionalBranch)
				il.MarkLabel(takenLabel);

			if (instruction->flags.lk)
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


static void ByteReversedLoad(LowLevelILFunction &il, Instruction* instruction, size_t size, size_t address_size_a=4)
{
	ExprId addr = operToIL(il, &instruction->operands[1], OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, address_size_a);          // (rA|0)
	ExprId  val = il.Load(size, il.Add(address_size_a, addr, operToIL_a(il, &instruction->operands[2], address_size_a))); // [(rA|0) + (rB)]

	if (size < address_size_a)
	{
		val = il.ZeroExtend(address_size_a, val);
	}

	/* set reg immediately; this will cause xrefs to be sized correctly,
	 * we'll use this as the scratch while we calculate the swapped value */
	il.AddInstruction(il.SetRegister(address_size_a, instruction->operands[0].reg, val));               // rD = [(rA|0) + (rB)]
	ExprId swap = ByteReverseRegister(il, instruction->operands[0].reg, size);

	il.AddInstruction(il.SetRegister(address_size_a, instruction->operands[0].reg, swap));              // rD = swap([(rA|0) + (rB)])
}

static void ByteReversedStore(LowLevelILFunction &il, Instruction* instruction, size_t size, size_t addressSize_a=4)
{
	ExprId addr = operToIL(il, &instruction->operands[1], OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_a);   // (rA|0)
	addr = il.Add(addressSize_a, addr, operToIL_a(il, &instruction->operands[2], addressSize_a));          // (rA|0) + (rB)
	ExprId val = ByteReverseRegister(il, instruction->operands[0].reg, size); // rS = swap(rS)
	il.AddInstruction(il.Store(size, addr, val));                             // [(rA|0) + (rB)] = swap(rS)
}

static void load_float(LowLevelILFunction& il,
	int load_sz,
	Operand* operand1, /* register that gets read/written */
	Operand* operand2, /* location the read/write occurs */
	Operand* operand3=0,
	bool update=false
	)
{
	ExprId tmp;
	const int addrsz = 4;
	// assume single
	if (!load_sz)
		load_sz = 4;

	// operand1.reg = [operand2.reg + operand2.imm]
	if (operand2->cls == PPC_OP_MEM_RA)
	{
		if (operand2->mem.reg == 0)
		{
			tmp = il.Const(addrsz, operand2->mem.offset);
		}
		else
		{
			tmp = il.Add(addrsz, il.Register(addrsz, operand2->mem.reg), il.Const(addrsz, operand2->mem.offset));
		}		
	}
	else if(operand2->cls == PPC_OP_REG_RA)
	{
		if ((operand3 != 0) && (operand3->cls == PPC_OP_REG_RB))
		{
			tmp = il.Add(4, il.Register(addrsz, operand2->reg), il.Register(addrsz, operand3->reg));
		}
	}

	il.AddInstruction(il.SetRegister(load_sz, operand1->reg, il.FloatConvert(load_sz, il.Operand(1, il.Load(load_sz, tmp)))));
	
	if (update == true)
	{
		tmp = il.SetRegister(4, operand2->reg, tmp);
		il.AddInstruction(tmp);
	}
}

/* returns TRUE - if this IL continues
          FALSE - if this IL terminates a block */
bool GetLowLevelILForPPCInstruction(Architecture *arch, LowLevelILFunction &il,
	Instruction* instruction, uint64_t addr)
{
	if (LiftBranches(arch, il, instruction, addr))
		return true;

	int i;
	size_t addressSize_l = arch->GetAddressSize();

	// for ppc_ps
	int w_l = 0;
	bool rc = true;

	/* create convenient access to instruction operands */
	Operand *oper0=NULL, *oper1=NULL, *oper2=NULL, *oper3=NULL, *oper4=NULL;
	#define REQUIRE1OP if(!oper0) goto ReturnUnimpl;
	#define REQUIRE2OPS if(!oper0 || !oper1) goto ReturnUnimpl;
	#define REQUIRE3OPS if(!oper0 || !oper1 || !oper2) goto ReturnUnimpl;
	#define REQUIRE4OPS if(!oper0 || !oper1 || !oper2 || !oper3) goto ReturnUnimpl;
	#define REQUIRE5OPS if(!oper0 || !oper1 || !oper2 || !oper3 || !oper4) goto ReturnUnimpl;

	switch (instruction->numOperands)
	{
		default:
		case 5: oper4 = &(instruction->operands[4]); FALL_THROUGH
		case 4: oper3 = &(instruction->operands[3]); FALL_THROUGH
		case 3: oper2 = &(instruction->operands[2]); FALL_THROUGH
		case 2: oper1 = &(instruction->operands[1]); FALL_THROUGH
		case 1: oper0 = &(instruction->operands[0]); FALL_THROUGH
		case 0: while(0);
	}

	ExprId ei0, ei1, ei2;

	switch (instruction->id)
	{
		/* add
			"add." also updates the CR0 bits */
		case PPC_ID_ADDx: /* add */
			REQUIRE2OPS
			ei0 = il.Add(
				addressSize_l,
				operToIL_a(il, oper1, addressSize_l),
				operToIL_a(il, oper2, addressSize_l)
			);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_ADDEx: /* add, extended (+ carry flag) */
			REQUIRE3OPS
			ei0 = il.AddCarry(
				addressSize_l,
				operToIL_a(il, oper1, addressSize_l),
				operToIL_a(il, oper2, addressSize_l),
				il.Flag(IL_FLAG_XER_CA),
				IL_FLAGWRITE_XER_CA
			);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_ADDMEx: /* add, extended (+ carry flag) minus one */
		case PPC_ID_ADDZEx:
			REQUIRE2OPS
			if (instruction->id == PPC_ID_ADDMEx)
				ei0 = il.Const(addressSize_l, ADDRNEG1(addressSize_l));
			else
				ei0 = il.Const(addressSize_l, 0);
			ei0 = il.AddCarry(
				addressSize_l,
				operToIL_a(il, oper1, addressSize_l),
				ei0,
				il.Flag(IL_FLAG_XER_CA),
				IL_FLAGWRITE_XER_CA
			);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_ADDCx: /* add, carrying */
		case PPC_ID_ADDICx: /* add immediate, carrying */
			REQUIRE3OPS
			ei0 = il.Add(
				addressSize_l,
				operToIL_a(il, oper1, addressSize_l),
				operToIL_a(il, oper2, addressSize_l),
				IL_FLAGWRITE_XER_CA
			);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_ADDI: /* add immediate, eg: addi rD, rA, <imm> */
		case PPC_ID_ADDIS: /* add immediate, shifted */
			REQUIRE2OPS
			if (instruction->id == PPC_ID_ADDIS)
				ei0 = il.Const(addressSize_l, oper2->simm << 16);
			else
				ei0 = il.Const(addressSize_l, oper2->simm);
			ei0 = il.Add(
				addressSize_l,
				operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l),
				ei0
			);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_LIS: /* load immediate, shifted */
			REQUIRE2OPS
			ei0 = il.SetRegister(
				addressSize_l,
				oper0->reg,
				il.ConstPointer(addressSize_l, oper1->simm << 16)
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_LI: /* load immediate */
			REQUIRE2OPS
			il.AddInstruction(il.SetRegister(addressSize_l, oper0->reg, operToIL_a(il, oper1, addressSize_l)));
			break;

		case PPC_ID_ANDx:
		case PPC_ID_ANDCx: // and [with complement]
		case PPC_ID_NANDx:
			REQUIRE3OPS
			ei0 = operToIL(il, oper2);
			if (instruction->id == PPC_ID_ANDCx)
				ei0 = il.Not(addressSize_l, ei0);
			ei0 = il.And(addressSize_l, operToIL(il, oper1), ei0);
			if (instruction->id == PPC_ID_NANDx)
				ei0 = il.Not(addressSize_l, ei0);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_ANDIS:
		case PPC_ID_ANDI:
			REQUIRE3OPS
			if (instruction->id == PPC_ID_ANDIS)
				ei0 = il.Const(addressSize_l, oper2->uimm << 16);
			else
				ei0 = il.Const(addressSize_l, oper2->uimm);
			ei0 = il.And(addressSize_l, operToIL(il, oper1), ei0);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0, IL_FLAGWRITE_CR0_S);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_CMPW: /* compare (signed) word(32-bit) */
			REQUIRE2OPS
			ei0 = operToIL(il, oper1);
			ei1 = operToIL(il, oper2);
			ei2 = il.Sub(addressSize_l, ei0, ei1, crxToFlagWriteType(oper0->reg, PPC_SUF_S));
			il.AddInstruction(ei2);
			break;

		case PPC_ID_CMPLW: /* compare logical(unsigned) word(32-bit) */
			REQUIRE2OPS
			ei0 = operToIL(il, oper1);
			ei1 = operToIL(il, oper2);
			ei2 = il.Sub(addressSize_l, ei0, ei1, crxToFlagWriteType(oper0->reg, PPC_SUF_U));
			il.AddInstruction(ei2);
			break;

		case PPC_ID_CMPWI: /* compare (signed) word(32-bit) immediate */
			REQUIRE2OPS
			ei0 = operToIL(il, oper1);
			ei1 = operToIL_a(il, oper2, addressSize_l);
			ei2 = il.Sub(addressSize_l, ei0, ei1, crxToFlagWriteType(oper0->reg, PPC_SUF_S));
			il.AddInstruction(ei2);
			break;

		case PPC_ID_CMPLWI: /* compare logical(unsigned) word(32-bit) immediate */
			REQUIRE2OPS
			ei0 = operToIL(il, oper1);
			ei1 = operToIL_a(il, oper2, addressSize_l);
			ei2 = il.Sub(addressSize_l, ei0, ei1, crxToFlagWriteType(oper0->reg, PPC_SUF_U));
			il.AddInstruction(ei2);
			break;

		case PPC_ID_CMPDI:
			REQUIRE2OPS
			ei0 = operToIL(il, oper1, 8);
			ei1 = operToIL_a(il, oper2, 8);
			ei2 = il.Sub(8, ei0, ei1, crxToFlagWriteType(oper0->reg, PPC_SUF_S));
			il.AddInstruction(ei2);
			break;

		case PPC_ID_CMPLDI:
			REQUIRE2OPS
			ei0 = operToIL(il, oper1, 8);
			ei1 = operToIL_a(il, oper2, 8);
			ei2 = il.Sub(8, ei0, ei1, crxToFlagWriteType(oper0->reg, PPC_SUF_U));
			il.AddInstruction(ei2);
			break;

	//case PPC_ID_CMPD: /* compare (signed) d-word(64-bit) */
	//	REQUIRE2OPS
	//	ei0 = operToIL(il, oper0);
	//	ei1 = operToIL(il, oper1, OTI_SEXT64_REGS);
	//	ei2 = il.Sub(4, ei0, ei1, flagWriteType);
	//	il.AddInstruction(ei2);
	//	break;

	//case PPC_ID_CMPLD: /* compare logical(unsigned) d-word(64-bit) */
	//	REQUIRE2OPS
	//	ei0 = operToIL(il, oper0);
	//	ei1 = operToIL(il, oper1, OTI_ZEXT64_REGS);
	//	ei2 = il.Sub(4, ei0, ei1, flagWriteType);
	//	il.AddInstruction(ei2);
	//	break;

	//case PPC_ID_CMPLDI: /* compare logical(unsigned) d-word(64-bit) immediate */
	//	REQUIRE2OPS
	//	ei0 = operToIL(il, oper0);
	//	ei1 = operToIL(il, oper1, OTI_ZEXT64_IMMS);
	//	ei2 = il.Sub(4, ei0, ei1, flagWriteType);
	//	il.AddInstruction(ei2);
	//	break;

	//	case PPC_ID_FCMPU:
	//		REQUIRE3OPS
	//		ei0 = il.FloatSub(4, il.Unimplemented(), il.Unimplemented(), (oper0->reg - PPC_REG_CR0) + IL_FLAGWRITE_INVL0);
	//		il.AddInstruction(ei0);
	//		break;

		case PPC_ID_CRAND:
		case PPC_ID_CRANDC:
		case PPC_ID_CRNAND:
			REQUIRE3OPS
			ei0 = il.Flag(oper1->crbit);
			ei1 = il.Flag(oper2->crbit);
			if (instruction->id == PPC_ID_CRANDC)
				ei1 = il.Not(0, ei1);
			ei0 = il.And(0, ei0, ei1);
			if (instruction->id == PPC_ID_CRNAND)
				ei0 = il.Not(0, ei0);
			il.AddInstruction(il.SetFlag(oper0->crbit, ei0));
			break;

		case PPC_ID_CROR:
		case PPC_ID_CRORC:
		case PPC_ID_CRNOR:
			REQUIRE3OPS
			ei0 = il.Flag(oper1->crbit);
			ei1 = il.Flag(oper2->crbit);
			if (instruction->id == PPC_ID_CRORC)
				ei1 = il.Not(0, ei1);
			ei0 = il.Or(0, ei0, ei1);
			if (instruction->id == PPC_ID_CRNOR)
				ei0 = il.Not(0, ei0);
			il.AddInstruction(il.SetFlag(oper0->crbit, ei0));
			break;

		case PPC_ID_CREQV:
		case PPC_ID_CRXOR:
			REQUIRE3OPS
			ei0 = il.Flag(oper1->crbit);
			ei1 = il.Flag(oper2->crbit);
			ei0 = il.Xor(0, ei0, ei1);
			if (instruction->id == PPC_ID_CREQV)
				ei0 = il.Not(0, ei0);
			il.AddInstruction(il.SetFlag(oper0->crbit, ei0));
			break;

		case PPC_ID_CRSET:
			REQUIRE1OP
			ei0 = il.SetFlag(oper0->crbit, il.Const(0, 1));
			il.AddInstruction(ei0);
			break;

		case PPC_ID_CRCLR:
			REQUIRE1OP
			ei0 = il.SetFlag(oper0->crbit, il.Const(0, 0));
			il.AddInstruction(ei0);
			break;

		case PPC_ID_CRNOT:
		case PPC_ID_CRMOVE:
			REQUIRE2OPS
			ei0 = il.Flag(oper1->crbit);
			if (instruction->id == PPC_ID_CRNOT)
				ei0 = il.Not(0, ei0);
			ei0 = il.SetFlag(oper0->crbit, ei0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_MFCR:
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

		case PPC_ID_MTCRF:
			REQUIRE2OPS
			for (uint8_t test = 0x80, i = 0; test; test >>= 1, i++)
			{
				if (test & oper0->uimm)
				{
					ei0 = il.Or(4, il.Register(4, oper1->reg), il.Const(4, 0), IL_FLAGWRITE_MTCR0 + i);
					il.AddInstruction(ei0);
				}
			}
			break;

		case PPC_ID_EXTSBx:
		case PPC_ID_EXTSHx:
			REQUIRE2OPS
			ei0 = il.Register(addressSize_l, oper1->reg);
			if (instruction->id == PPC_ID_EXTSBx)
			{
				ei0 = il.LowPart(1, ei0);
			}
			else
			{
				ei0 = il.LowPart(2, ei0);
			}
			ei0 = il.SignExtend(addressSize_l, ei0);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_EXTSWx:
			REQUIRE2OPS
			ei0 = il.Register(8, oper1->reg);
			ei0 = il.LowPart(4, ei0);
			ei0 = il.SignExtend(8, ei0);
			ei0 = il.SetRegister(8, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_ISEL:
			REQUIRE4OPS
			{
				LowLevelILLabel trueLabel, falseLabel, doneLabel;
				uint32_t crBit = oper3->crbit;
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

		case PPC_ID_LMW:
			REQUIRE2OPS
			for (i = oper0->reg; i <= PPC_REG_GPR31; ++i)
			{
				ei0 = il.SetRegister(4,
					i,             // dest
					il.Load(4,     // source
						operToIL(il, oper1, OTI_IMM_BIAS, (i-(oper0->reg))*4, addressSize_l)
					)
				);

				il.AddInstruction(ei0);
			}

			break;

		/*
			load byte and zero extend [and update]
		*/
		case PPC_ID_LBZ:
		case PPC_ID_LBZU:
			REQUIRE2OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l); // d(rA) or 0
			ei0 = il.Load(1, ei0);                    // [d(rA)]
			ei0 = il.ZeroExtend(addressSize_l, ei0);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0); // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(instruction->id == PPC_ID_LBZU) {
				ei0 = il.SetRegister(addressSize_l, oper1->mem.reg, operToIL(il, oper1, addressSize_l));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load half word [and zero/sign extend] [and update]
		*/
		case PPC_ID_LBZX:
		case PPC_ID_LBZUX:
			REQUIRE3OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l);              // d(rA) or 0
			ei0 = il.Load(1, il.Add(addressSize_l, ei0, operToIL_a(il, oper2, addressSize_l))); // [d(rA) + d(rB)]
			ei0 = il.ZeroExtend(addressSize_l, ei0);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0);              // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if (instruction->id == PPC_ID_LBZUX && oper1->reg != oper0->reg && oper1->reg != PPC_REG_GPR0)
			{
				ei0 = il.SetRegister(addressSize_l, oper1->reg, operToIL_a(il, oper1, addressSize_l));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load half word [and zero/sign extend] [and update]
		*/
		case PPC_ID_LHZ:
		case PPC_ID_LHZU:
		case PPC_ID_LHA:
		case PPC_ID_LHAU:
			REQUIRE2OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l); // d(rA) or 0
			ei0 = il.Load(2, ei0);                    // [d(rA)]
			if(instruction->id == PPC_ID_LHZ || instruction->id == PPC_ID_LHZU)
				ei0 = il.ZeroExtend(addressSize_l, ei0);
			else
				ei0 = il.SignExtend(addressSize_l, ei0);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0); // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if (instruction->id == PPC_ID_LHZU || instruction->id == PPC_ID_LHAU)
			{
				ei0 = il.SetRegister(addressSize_l, oper1->mem.reg, operToIL_a(il, oper1, addressSize_l));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load half word [and zero/sign extend] [and update]
		*/
		case PPC_ID_LHZX:
		case PPC_ID_LHZUX:
		case PPC_ID_LHAX:
		case PPC_ID_LHAUX:
			REQUIRE3OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l);              // d(rA) or 0
			ei0 = il.Load(2, il.Add(addressSize_l, ei0, operToIL_a(il, oper2, addressSize_l))); // [d(rA) + d(rB)]
			if(instruction->id == PPC_ID_LHZX || instruction->id == PPC_ID_LHZUX)
				ei0 = il.ZeroExtend(addressSize_l, ei0);
			else
				ei0 = il.SignExtend(addressSize_l, ei0);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0);              // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if((instruction->id == PPC_ID_LHZUX || instruction->id == PPC_ID_LHAUX) && oper1->reg != oper0->reg && oper1->reg != PPC_REG_GPR0) {
				ei0 = il.SetRegister(addressSize_l, oper1->reg, operToIL_a(il, oper1, addressSize_l));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load word [and zero] [and update]
		*/
		case PPC_ID_LWZ:
		case PPC_ID_LWZU:
			REQUIRE2OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l); // d(rA) or 0
			ei0 = il.Load(4, ei0);                    // [d(rA)]
			if(addressSize_l == 8)
			{
				ei0 = il.ZeroExtend(addressSize_l, ei0);
			}
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0); // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(instruction->id == PPC_ID_LWZU) {
				ei0 = il.SetRegister(addressSize_l, oper1->mem.reg, operToIL_a(il, oper1, addressSize_l));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load word [and zero] [and update]
		*/
		case PPC_ID_LWZX:
		case PPC_ID_LWZUX:
			REQUIRE3OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l);              // d(rA) or 0
			ei0 = il.Load(4, il.Add(addressSize_l, ei0, operToIL_a(il, oper2, addressSize_l))); // [d(rA) + d(rB)]
			if(addressSize_l == 8)
			{
				ei0 = il.ZeroExtend(addressSize_l, ei0);
			}
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0);              // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(instruction->id == PPC_ID_LWZUX && oper1->reg != oper0->reg && oper1->reg != PPC_REG_GPR0) {
				ei0 = il.SetRegister(addressSize_l, oper1->reg, operToIL_a(il, oper1, addressSize_l));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load doubleword [and update]
		*/
		case PPC_ID_LD:
		case PPC_ID_LDU:
			REQUIRE2OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO); // d(rA) or 0
			ei0 = il.Load(8, ei0);                    // [d(rA)]
			ei0 = il.SetRegister(8, oper0->reg, ei0); // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(instruction->id == PPC_ID_LWZU) {
				ei0 = il.SetRegister(8, oper1->mem.reg, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		/*
			load doubleword [and update]
		*/
		case PPC_ID_LDX:
		case PPC_ID_LDUX:
			REQUIRE3OPS
			ei0 = operToIL(il, oper1, OTI_GPR0_ZERO);              // d(rA) or 0
			ei0 = il.Load(8, il.Add(8, ei0, operToIL(il, oper2))); // [d(rA) + d(rB)]
			ei0 = il.SetRegister(8, oper0->reg, ei0);              // rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(instruction->id == PPC_ID_LWZUX && oper1->reg != oper0->reg && oper1->reg != PPC_REG_GPR0) {
				ei0 = il.SetRegister(8, oper1->reg, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		case PPC_ID_LHBRX:
			REQUIRE3OPS
			ByteReversedLoad(il, instruction, 2, addressSize_l);
			break;

		case PPC_ID_LWBRX:
			REQUIRE3OPS
			ByteReversedLoad(il, instruction, 4, addressSize_l);
			break;

		case PPC_ID_STHBRX:
			REQUIRE3OPS
			ByteReversedStore(il, instruction, 2, addressSize_l);
			break;

		case PPC_ID_STWBRX:
			REQUIRE3OPS
			ByteReversedStore(il, instruction, 4, addressSize_l);
			break;

		case PPC_ID_MFCTR: // move from ctr
			REQUIRE1OP
			il.AddInstruction(il.SetRegister(addressSize_l, oper0->reg, il.Register(addressSize_l, PPC_REG_CTR)));
			break;

		case PPC_ID_MFLR: // move from link register
			REQUIRE1OP
			il.AddInstruction(il.SetRegister(addressSize_l, oper0->reg, il.Register(addressSize_l, PPC_REG_LR)));
			break;

		case PPC_ID_MTCTR: // move to ctr
			REQUIRE1OP
			il.AddInstruction(il.SetRegister(addressSize_l, PPC_REG_CTR, operToIL_a(il, oper0, addressSize_l)));
			break;

		case PPC_ID_MTLR: // move to link register
			REQUIRE1OP
			il.AddInstruction(il.SetRegister(addressSize_l, PPC_REG_LR, operToIL_a(il, oper0, addressSize_l)));
			break;

		case PPC_ID_NEGx:
			REQUIRE2OPS
			ei0 = il.Neg(addressSize_l, operToIL(il, oper1));
			il.AddInstruction(il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_NOP:
			il.AddInstruction(il.Nop());
			break;

		case PPC_ID_ORx:
		case PPC_ID_ORCx:
		case PPC_ID_NORx:
			REQUIRE3OPS
			ei0 = operToIL_a(il, oper2, addressSize_l);
			if (instruction->id == PPC_ID_ORCx)
				ei0 = il.Not(addressSize_l, ei0);
			ei0 = il.Or(addressSize_l, operToIL_a(il, oper1, addressSize_l), ei0);
			if (instruction->id == PPC_ID_NORx)
				ei0 = il.Not(addressSize_l, ei0);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_ORI:
		case PPC_ID_ORIS:
			REQUIRE3OPS
			if (instruction->id == PPC_ID_ORIS)
				ei0 = il.Const(addressSize_l, oper2->uimm << 16);
			else
				ei0 = il.Const(addressSize_l, oper2->uimm);
			ei0 = il.Or(addressSize_l, operToIL_a(il, oper1, addressSize_l), ei0);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_XORx:
		case PPC_ID_EQVx:
			REQUIRE3OPS
			ei0 = il.Xor(addressSize_l,
				operToIL_a(il, oper1, addressSize_l),
				operToIL_a(il, oper2, addressSize_l)
			);
			if (instruction->id == PPC_ID_EQVx)
				ei0 = il.Not(addressSize_l, ei0);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_XORI:
		case PPC_ID_XORIS:
			REQUIRE3OPS
			if (instruction->id == PPC_ID_XORIS)
				ei0 = il.Const(addressSize_l, oper2->uimm << 16);
			else
				ei0 = il.Const(addressSize_l, oper2->uimm);
			ei0 = il.SetRegister(
				addressSize_l,
				oper0->reg,
				il.Xor(addressSize_l,
					operToIL_a(il, oper1, addressSize_l),
					ei0
				)
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_SUBFx:
		case PPC_ID_SUBFCx:
		case PPC_ID_SUBFIC:
			REQUIRE3OPS
			ei0 = il.Sub(
				addressSize_l,
				operToIL_a(il, oper2, addressSize_l),
				operToIL_a(il, oper1, addressSize_l),
				(instruction->id != PPC_ID_SUBFx) ? IL_FLAGWRITE_XER_CA : 0
			);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_SUBFEx:
			REQUIRE3OPS
			ei0 = il.SubBorrow(
				addressSize_l,
				operToIL_a(il, oper2, addressSize_l),
				operToIL_a(il, oper1, addressSize_l),
				il.Flag(IL_FLAG_XER_CA),
				IL_FLAGWRITE_XER_CA
			);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_SUBFMEx:
		case PPC_ID_SUBFZEx:
			REQUIRE2OPS
			if (instruction->id == PPC_ID_SUBFMEx)
				ei0 = il.Const(addressSize_l, ADDRNEG1(addressSize_l));
			else
				ei0 = il.Const(addressSize_l, 0);
			ei0 = il.AddCarry(
				addressSize_l,
				ei0,
				operToIL_a(il, oper1, addressSize_l),
				il.Flag(IL_FLAG_XER_CA),
				IL_FLAGWRITE_XER_CA
			);
			ei0 = il.SetRegister(addressSize_l, oper0->reg, ei0,
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_STMW:
			REQUIRE2OPS
			for (i = oper0->reg; i <= PPC_REG_GPR31; ++i)
			{
				ei0 = il.Register(4, i); // source
				ei1 = operToIL(il, oper1, OTI_IMM_BIAS, (i-(oper0->reg))*4, addressSize_l);
				il.AddInstruction(
					il.Store(4,
						ei1,
						ei0
					)
				);
			}

			break;

		/* store half word [with update] */
		case PPC_ID_STB:
		case PPC_ID_STBU: /* store(size, addr, val) */
			REQUIRE2OPS
			ei0 = il.Store(1,
				operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l),
				il.LowPart(1, operToIL_a(il, oper0, addressSize_l))
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(instruction->id == PPC_ID_STBU) {
				ei0 = il.SetRegister(addressSize_l, oper1->mem.reg, operToIL_a(il, oper1, addressSize_l));
				il.AddInstruction(ei0);
			}

			break;

		/* store half word indexed [with update] */
		case PPC_ID_STBX:
		case PPC_ID_STBUX: /* store(size, addr, val) */
			REQUIRE3OPS
			ei0 = il.Store(1,
				il.Add(
					addressSize_l,
					operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l),
					operToIL_a(il, oper2, addressSize_l)),
				il.LowPart(1, operToIL_a(il, oper0, addressSize_l))
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(instruction->id == PPC_ID_STBUX) {
				ei0 = il.SetRegister(addressSize_l, oper1->reg,
					il.Add(addressSize_l, operToIL_a(il, oper1, addressSize_l), operToIL_a(il, oper2, addressSize_l))
				);
				il.AddInstruction(ei0);
			}

			break;

		/* store half word [with update] */
		case PPC_ID_STH:
		case PPC_ID_STHU: /* store(size, addr, val) */
			REQUIRE2OPS
			ei0 = il.Store(2,
				operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l),
				il.LowPart(2, operToIL_a(il, oper0, addressSize_l))
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(instruction->id == PPC_ID_STHU) {
				ei0 = il.SetRegister(addressSize_l, oper1->mem.reg, operToIL_a(il, oper1, addressSize_l));
				il.AddInstruction(ei0);
			}

			break;

		/* store half word indexed [with update] */
		case PPC_ID_STHX:
		case PPC_ID_STHUX: /* store(size, addr, val) */
			REQUIRE3OPS
			ei0 = il.Store(2,
				il.Add(
					addressSize_l,
					operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l),
					operToIL_a(il, oper2, addressSize_l)),
				il.LowPart(2, operToIL_a(il, oper0, addressSize_l))
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(instruction->id == PPC_ID_STHUX) {
				ei0 = il.SetRegister(addressSize_l, oper1->reg,
					il.Add(addressSize_l, operToIL_a(il, oper1, addressSize_l), operToIL_a(il, oper2, addressSize_l))
				);
				il.AddInstruction(ei0);
			}

			break;

		/* store word [with update] */
		case PPC_ID_STW:
		case PPC_ID_STWU: /* store(size, addr, val) */
			REQUIRE2OPS
			if (addressSize_l == 8)
			{
				ei0 = il.LowPart(4, operToIL_a(il, oper0, addressSize_l));
			}
			else if (addressSize_l == 4)
			{
				ei0 = operToIL(il, oper0);
			}
			ei0 = il.Store(4,
				operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l),
				ei0
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(instruction->id == PPC_ID_STWU) {
				ei0 = il.SetRegister(addressSize_l, oper1->mem.reg, operToIL_a(il, oper1, addressSize_l));
				il.AddInstruction(ei0);
			}

			break;

		/* store word indexed [with update] */
		case PPC_ID_STWX:
		case PPC_ID_STWUX: /* store(size, addr, val) */
			REQUIRE3OPS
			if (addressSize_l == 8)
			{
				ei0 = il.LowPart(4, operToIL_a(il, oper0, addressSize_l));
			}
			else if (addressSize_l == 4)
			{
				ei0 = operToIL(il, oper0);
			}
			ei0 = il.Store(4,
				il.Add(
					addressSize_l,
					operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_EXTRA_DEFAULT, addressSize_l),
					operToIL_a(il, oper2, addressSize_l)),
				ei0
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(instruction->id == PPC_ID_STWUX) {
				ei0 = il.SetRegister(addressSize_l, oper1->reg,
					il.Add(addressSize_l, operToIL_a(il, oper1, addressSize_l), operToIL_a(il, oper2, addressSize_l))
				);
				il.AddInstruction(ei0);
			}

			break;

		/* store double word [with update] */
		case PPC_ID_STD:
		case PPC_ID_STDU: /* store(size, addr, val) */
			REQUIRE2OPS
			ei0 = il.Store(8,
				operToIL(il, oper1, OTI_GPR0_ZERO, PPC_IL_OPTIONS_DEFAULT, addressSize_l),
				operToIL_a(il, oper0, addressSize_l)
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(instruction->id == PPC_ID_STWU) {
				ei0 = il.SetRegister(8, oper1->mem.reg, operToIL_a(il, oper1, 8));
				il.AddInstruction(ei0);
			}

			break;

		/* store word indexed [with update] */
		case PPC_ID_STDX:
		case PPC_ID_STDUX: /* store(size, addr, val) */
			REQUIRE3OPS
			ei0 = il.Store(8,
				il.Add(8, operToIL(il, oper1, OTI_GPR0_ZERO), operToIL_a(il, oper2, addressSize_l)),
				operToIL(il, oper0)
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address
			if(instruction->id == PPC_ID_STDUX) {
				ei0 = il.SetRegister(8, oper1->reg,
					il.Add(8, operToIL_a(il, oper1, 8), operToIL_a(il, oper2, 8))
				);
				il.AddInstruction(ei0);
			}

			break;

		case PPC_ID_RLWIMIx:
			REQUIRE5OPS
			{
				uint32_t mask = genMask(oper3->uimm, oper4->uimm);

				ei0 = il.Register(4, oper1->reg);

				if (oper2->uimm != 0)
				{
					if ((mask & (~0u >> (32 - oper2->uimm))) == 0)
						ei0 = il.ShiftLeft(4, ei0, il.Const(4, oper2->uimm));
					else if ((mask & (~0u << oper2->uimm)) == 0)
						ei0 = il.LogicalShiftRight(4, ei0, il.Const(4, 32 - oper2->uimm));
					else
						ei0 = il.RotateLeft(4, ei0, il.Const(4, oper2->uimm));
				}

				ei0 = il.And(4, ei0, il.Const(4, mask));
				uint32_t invertMask = ~mask;
				ei0 = il.Or(4, il.And(4, il.Register(4, oper0->reg), il.Const(4, invertMask)), ei0);

				ei0 = il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
				);
				il.AddInstruction(ei0);
			}
			break;

		case PPC_ID_RLWINMx:
			REQUIRE5OPS
			{
				uint32_t mask = genMask(oper3->uimm, oper4->uimm);

				ei0 = il.Register(4, oper1->reg);

				if (oper2->uimm != 0)
				{
					if ((mask & (~0u >> (32 - oper2->uimm))) == 0)
					{
						if (mask != 0xffffffff)
							ei0 = il.And(4, ei0, il.Const(4, mask >> oper2->uimm));

						ei0 = il.ShiftLeft(4, ei0, il.Const(4, oper2->uimm));
					}
					else if ((mask & (~0u << oper2->uimm)) == 0)
					{
						if (mask != 0xffffffff)
							ei0 = il.And(4, ei0, il.Const(4, mask << (32 - oper2->uimm)));

						ei0 = il.LogicalShiftRight(4, ei0, il.Const(4, 32 - oper2->uimm));
					}
					else
					{
						ei0 = il.RotateLeft(4, ei0, il.Const(4, oper2->uimm));

						if (mask != 0xffffffff)
							ei0 = il.And(4, ei0, il.Const(4, mask));
					}
				}
				else if (mask != 0xffffffff)
				{
					ei0 = il.And(4, ei0, il.Const(4, mask));
				}

				ei0 = il.SetRegister(4, oper0->reg, ei0,
						instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
				);
				il.AddInstruction(ei0);
			}
			break;

		case PPC_ID_SLWIx:
			REQUIRE3OPS
			ei0 = il.Const(4, oper2->uimm);           // amt: shift amount
			ei1 = il.Register(4, oper1->reg);        //  rS: reg to be shifted
			ei0 = il.ShiftLeft(4, ei1, ei0);         // (rS << amt)
			ei0 = il.SetRegister(4, oper0->reg, ei0, // rD = (rs << amt)
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_SRWIx:
			REQUIRE3OPS
			ei0 = il.Const(4, oper2->uimm);           // amt: shift amount
			ei1 = il.Register(4, oper1->reg);        //  rS: reg to be shifted
			ei0 = il.LogicalShiftRight(4, ei1, ei0);        // (rS << amt)
			ei0 = il.SetRegister(4, oper0->reg, ei0, // rD = (rs << amt)
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_CLRLWIx:
			REQUIRE3OPS
			ei0 = il.Const(4, (uint32_t) (0xffffffff >> oper2->uimm));
			ei1 = il.Register(4, oper1->reg);
			ei0 = il.And(4, ei1, ei0);
			ei0 = il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_ROTLWIx:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.RotateLeft(4, ei0, il.Const(4, oper2->uimm));
			ei0 = il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_ROTLWx:
		case PPC_ID_RLWNMx:
			REQUIRE3OPS
			{
				uint32_t mask = 0xffffffff;
				if (instruction->id == PPC_ID_RLWNMx)
				{
					REQUIRE5OPS
					mask = genMask(oper3->uimm, oper4->uimm);
				}
				ei0 = il.Register(4, oper1->reg);
				ei1 = il.Register(4, oper2->reg);
				ei1 = il.And(4, ei1, il.Const(4, 0x1f));
				ei0 = il.RotateLeft(4, ei0, ei1);
				if (mask != 0xffffffff)
					ei0 = il.And(4, ei0, il.Const(4, mask));
				ei0 = il.SetRegister(4, oper0->reg, ei0,
						instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
				);
				il.AddInstruction(ei0);
			}
			break;


		case PPC_ID_SLWx:
		case PPC_ID_SRWx:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			// permit bit 26 to survive to enable clearing the whole register
			ei1 = il.And(4, il.Register(4, oper2->reg), il.Const(4, 0x3f));
			if (instruction->id == PPC_ID_SLWx)
				ei0 = il.ShiftLeft(4, ei0, ei1);
			else
				ei0 = il.LogicalShiftRight(4, ei0, ei1);
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_SLDx:
		case PPC_ID_SRDx:
			REQUIRE3OPS
			ei0 = il.Register(8, oper1->reg);
			// permit bit 25 to survive to enable clearing the whole register
			ei1 = il.And(8, il.Register(8, oper2->reg), il.Const(8, 0x7f));
			if (instruction->id == PPC_ID_SLDx)
				ei0 = il.ShiftLeft(8, ei0, ei1);
			else
				ei0 = il.LogicalShiftRight(8, ei0, ei1);
			il.AddInstruction(il.SetRegister(8, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_SRAWx:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei1 = il.And(4, il.Register(4, oper2->reg), il.Const(4, 0x1f));
			ei0 = il.ArithShiftRight(4, ei0, ei1, IL_FLAGWRITE_XER_CA);
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_SRAWIx:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.ArithShiftRight(4, ei0, il.Const(4, oper2->uimm), IL_FLAGWRITE_XER_CA);
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_SRADx:
			REQUIRE3OPS
			ei0 = il.Register(8, oper1->reg);
			ei1 = il.And(8, il.Register(8, oper2->reg), il.Const(8, 0x3f));
			ei0 = il.ArithShiftRight(8, ei0, ei1, IL_FLAGWRITE_XER_CA);
			il.AddInstruction(il.SetRegister(8, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_SRADIx:
			REQUIRE3OPS
			ei0 = il.Register(8, oper1->reg);
			ei0 = il.ArithShiftRight(8, ei0, il.Const(8, oper2->uimm), IL_FLAGWRITE_XER_CA);
			il.AddInstruction(il.SetRegister(8, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_MULLWx:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.Mult(4, ei0, il.Register(4, oper2->reg));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_MULLI:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.Mult(4, ei0, il.Const(4, oper2->uimm));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0));
			break;

		case PPC_ID_MULHWx:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.MultDoublePrecSigned(4, ei0, il.Register(4, oper2->reg));
			ei0 = il.LowPart(4, il.LogicalShiftRight(8, ei0, il.Const(1, 32)));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_MULHWUx:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.MultDoublePrecUnsigned(4, ei0, il.Register(4, oper2->reg));
			ei0 = il.LowPart(4, il.LogicalShiftRight(8, ei0, il.Const(1, 32)));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_DIVWx:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.DivSigned(4, ei0, il.Register(4, oper2->reg));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_DIVWUx:
			REQUIRE3OPS
			ei0 = il.Register(4, oper1->reg);
			ei0 = il.DivUnsigned(4, ei0, il.Register(4, oper2->reg));
			il.AddInstruction(il.SetRegister(4, oper0->reg, ei0,
					instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0
			));
			break;

		case PPC_ID_MRx: /* move register */
			REQUIRE2OPS
			ei0 = il.SetRegister(addressSize_l, oper0->reg, operToIL_a(il, oper1, addressSize_l),
				instruction->flags.rc ? IL_FLAGWRITE_CR0_S : 0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_SC:
			il.AddInstruction(il.SystemCall());
			break;

		case PPC_ID_RFI:
			il.AddInstruction(il.Return(il.Unimplemented()));
			break;

		case PPC_ID_TWU:
			il.AddInstruction(il.Trap(0));
			break;

		// =====================================
		// =====FLOATING POINT INSTRUCTIONS=====
		// =====================================

		case PPC_ID_FADDx:
			REQUIRE3OPS
			ei0 = il.FloatAdd(8, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8),
				operToIL(il, oper2, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei0 = il.SetRegister(8, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_FADDSx:
			REQUIRE3OPS
			ei0 = il.FloatAdd(4, operToIL(il, oper1), operToIL(il, oper2));
			ei0 = il.SetRegister(4, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_FSUBx:
			REQUIRE3OPS
			ei0 = il.FloatSub(8, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8),
				operToIL(il, oper2, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei0 = il.SetRegister(8, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_FSUBSx:
			REQUIRE3OPS
			ei0 = il.FloatSub(4, operToIL(il, oper1), operToIL(il, oper2));
			ei0 = il.SetRegister(4, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_FCMPU:
			REQUIRE3OPS
			ei0 = il.Register(RZF, oper1->reg);
			ei1 = il.Register(RZF, oper2->reg);
			ei2 = il.FloatSub(RZF, ei0, ei1, crxToFlagWriteType(oper0->reg, PPC_SUF_F));
			il.AddInstruction(ei2);
			break;

		case PPC_ID_FCMPO:
			REQUIRE3OPS
			ei0 = il.Register(RZF, oper1->reg);
			ei1 = il.Register(RZF, oper2->reg);
			ei2 = il.FloatSub(RZF, ei0, ei1, crxToFlagWriteType(oper0->reg, PPC_SUF_F));
			il.AddInstruction(ei2);
			break;

		case PPC_ID_FMRx:
			REQUIRE2OPS
			ei0 = il.SetRegister(8, oper0->reg, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			il.AddInstruction(ei0);
			break;

		case PPC_ID_STFS:
			REQUIRE2OPS
			ei0 = il.FloatConvert(4, operToIL(il, oper0));
			ei0 = il.Store(4, operToIL(il, oper1), ei0);
			// ei0 = il.FloatConvert(4, ei0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_STFSX:
			REQUIRE3OPS
			ei0 = il.FloatConvert(4, operToIL(il, oper0));
			ei1 = il.Add(4, operToIL(il, oper1), operToIL(il, oper2));
			ei0 = il.Store(4, ei1, ei0);
			// ei0 = il.FloatConvert(4, ei0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_STFD:
			REQUIRE2OPS
			ei0 = il.Store(8, operToIL(il, oper1),
				il.FloatConvert(8, operToIL(il, oper0, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8)));
			// ei0 = il.FloatConvert(8, ei0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_LFS:
			REQUIRE2OPS
			// ei0 = operToIL(il, oper1); // d(rA) or 0
		    // ei0 = il.Load(4, ei0);                    // [d(rA)]
		    // ei0 = il.SetRegister(4, oper0->reg, ei0); // rD = [d(rA)]
		    // // ei1 = il.IntToFloat(4, ei0);
		    // il.AddInstruction(ei1);

			// alternatively, do it the way arm64 does it
			load_float(il, 4, oper0, oper1);
			break;

		case PPC_ID_LFSX:
			REQUIRE3OPS
			// ei0 = il.Add(4, operToIL(il, oper1), operToIL(il, oper2));
			// ei0 = il.Load(4, ei0);
			// ei0 = il.Operand(1, ei0);
			// ei0 = il.FloatConvert(4, ei0);
			// ei0 = il.SetRegister(4, oper0->reg, ei0);
			// // alternatively, do it the way arm64 does it
			// il.AddInstruction(ei0);

			load_float(il, 4, oper0, oper1, oper2);
			break;

		case PPC_ID_LFSU:
			REQUIRE2OPS
			load_float(il, 4, oper0, oper1, 0, true);
			break;

		case PPC_ID_LFSUX:
			REQUIRE3OPS
			load_float(il, 4, oper0, oper1, oper2, true);
			break;

		case PPC_ID_LFD:
			REQUIRE2OPS
			// ei0 = operToIL(il, oper1); // d(rA) or 0
		    // ei0 = il.Load(8, ei0);                    // [d(rA)]
		    // ei0 = il.SetRegister(8, oper0->reg, ei0); // rD = [d(rA)]
		    // il.AddInstruction(ei0);

			// same as lfs
			load_float(il, 8, oper0, oper1);
			break;

		case PPC_ID_FMULx:
			REQUIRE3OPS
			ei0 = il.MultDoublePrecSigned(8, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8),
				operToIL(il, oper2, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei1 = il.SetRegister(8, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FMULSx:
			REQUIRE3OPS
			ei0 = il.FloatMult(4, operToIL(il, oper1), operToIL(il, oper2));
			ei1 = il.SetRegister(4, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FDIVx:
			REQUIRE3OPS
			ei0 = il.DivDoublePrecSigned(8, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8),
				operToIL(il, oper2, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei1 = il.SetRegister(8, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FDIVSx:
			REQUIRE3OPS
			ei0 = il.FloatDiv(4, operToIL(il, oper1), operToIL(il, oper2));
			ei1 = il.SetRegister(4, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FMADDx:
			REQUIRE4OPS
			ei0 = il.MultDoublePrecSigned(8, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8),
				operToIL(il, oper3, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei0 = il.FloatAdd(8, ei0, operToIL(il, oper2, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei1 = il.SetRegister(8, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FMADDSx:
			REQUIRE4OPS
			ei0 = il.FloatMult(4, operToIL(il, oper1), operToIL(il, oper3), (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			ei0 = il.FloatAdd(4, ei0, operToIL(il, oper2), (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			ei1 = il.SetRegister(4, oper0->reg, ei0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FMSUBx:
			REQUIRE4OPS
			ei0 = il.MultDoublePrecSigned(8, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8),
				operToIL(il, oper3, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei0 = il.FloatSub(8, ei0, operToIL(il, oper2, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei1 = il.SetRegister(8, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FMSUBSx:
			REQUIRE4OPS
			ei0 = il.FloatMult(4, operToIL(il, oper1), operToIL(il, oper3));
			ei0 = il.FloatSub(4, ei0, operToIL(il, oper2));
			ei1 = il.SetRegister(4, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		// this is a weird one, its described as round a float to an int towards 0, then set
		// bits 32-63 of a double reg to that result, ignoring the lower 32 bits 0-31.
		// TODO: needs further testing to verify that this is functional, and verify that the
		// method used was correct, as well as the registers afffected, like FPSCR.
		case PPC_ID_FCTIWZx:
			REQUIRE2OPS
			ei0 = il.FloatTrunc(RZF, operToIL(il, oper1));
			ei1 = il.Const(4, 32);
			ei2 = il.ShiftLeft(8, ei0, ei1);
			ei0 = il.SetRegister(8, oper0->reg, ei2, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_FNEGx:
			REQUIRE2OPS
			ei0 = il.FloatNeg(4, operToIL(il, oper1));
			ei0 = il.SetRegister(4, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei0);
			break;

		case PPC_ID_FNMADDx:
			REQUIRE4OPS
			ei0 = il.MultDoublePrecSigned(8, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8),
				operToIL(il, oper3, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei0 = il.FloatAdd(8, ei0, operToIL(il, oper2, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei0 = il.FloatNeg(8, ei0);
			ei1 = il.SetRegister(8, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FNMADDSx:
			REQUIRE4OPS
			ei0 = il.FloatMult(4, operToIL(il, oper1), operToIL(il, oper3), (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			ei0 = il.FloatAdd(4, ei0, operToIL(il, oper2), (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			ei0 = il.FloatNeg(4, ei0);
			ei1 = il.SetRegister(4, oper0->reg, ei0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FNMSUBx:
			REQUIRE4OPS
			ei0 = il.MultDoublePrecSigned(8, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8),
				operToIL(il, oper3, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei0 = il.FloatSub(8, ei0, operToIL(il, oper2, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei0 = il.FloatNeg(8, ei0);
			ei1 = il.SetRegister(8, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FNMSUBSx:
			REQUIRE4OPS
			ei0 = il.FloatMult(4, operToIL(il, oper1), operToIL(il, oper3));
			ei0 = il.FloatSub(4, ei0, operToIL(il, oper2));
			ei0 = il.FloatNeg(4, ei0);
			ei1 = il.SetRegister(4, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FABSx:
			REQUIRE2OPS
			ei0 = il.FloatAbs(4, operToIL(il, oper1));
			ei1 = il.SetRegister(4, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FNABSx:
			REQUIRE2OPS
			ei0 = il.FloatAbs(4, operToIL(il, oper1));
			ei0 = il.FloatNeg(4, ei0);
			ei1 = il.SetRegister(4, oper0->reg, ei0, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		// TODO: needs more testing to make sure that stuff is good. the decompilation is a
		// little rough, seems to be making the const double 1 into an int by default,
		// gonna have to figure out how if its right and FPSCR is correct.
		case PPC_ID_FRSQRTEx:
			REQUIRE2OPS
			ei0 = il.FloatConstDouble(1);
			ei1 = il.FloatSqrt(8, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei1 = il.DivDoublePrecSigned(8, ei0, ei1);
			ei1 = il.SetRegister(8, oper0->reg, ei1, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_FRSQRTESx:
			REQUIRE2OPS
			ei0 = il.FloatConstSingle(1);
			ei1 = il.FloatSqrt(4, operToIL(il, oper1, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 8));
			ei1 = il.FloatDiv(4, ei0, ei1);
			ei1 = il.SetRegister(4, oper0->reg, ei1, (instruction->flags.rc) ? IL_FLAGWRITE_CR0_F : 0);
			il.AddInstruction(ei1);
			break;

		case PPC_ID_CNTLZWx:
			ei0 = il.Intrinsic({RegisterOrFlag::Register(oper1->reg)}, PPC_INTRIN_CNTLZW,
				{operToIL(il, oper0)});
			il.AddInstruction(ei0);
			break;

		case PPC_ID_PSQ_ST:
			REQUIRE4OPS
		    MYLOG("0x%08x psq_st args f%d r%d[%d] w:%lldd gcqr:%lld\n",
		      (uint32_t)addr, oper0->reg - PPC_REG_F0, oper1->mem.base - PPC_REG_R0, oper1->mem.disp, oper2->imm,
		      oper3->imm);
		    MYLOG("opcount %d insn pnem %s\n", ppc->op_count, insn->op_str);

			// w_l = oper2->imm;

			// The intrinsic used to perform the quantize operation.
			// optional, use output {} for empty.
			ei0 = il.Intrinsic(
				{RegisterOrFlag::Register(oper0->reg)},
				PPC_PS_INTRIN_QUANTIZE,
				{
					operToIL(il, oper0, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 4),
					il.Const(4, oper3->uimm)
					}
				);

			il.AddInstruction(ei0);

			// Then store the quantized value
			ei0 = il.Store(8, operToIL(il, oper1),
				// temporary measure to allow it to resemble the instruction, just oper2il oper0
		        // ei0
				operToIL(il, oper0, PPC_IL_OPTIONS_DEFAULT, PPC_IL_EXTRA_DEFAULT, 4)
				// ei2
			);
			il.AddInstruction(ei0);

			// we are supposed to quantize the upper 32 bits as well, ps1 if w=0
			// if (w_l == 0)
			// {

			// }
			break;

		case PPC_ID_PSQ_L:
			REQUIRE4OPS
		    // w_l = oper2->imm;

		    ei0 = il.Load(8, operToIL(il, oper1));                    // [d(rA)]
			ei0 = il.Intrinsic(
				{RegisterOrFlag::Register(oper0->reg)},
				PPC_PS_INTRIN_DEQUANTIZE,
				{
					ei0,
					operToIL(il, oper0),
					il.Const(4, oper3->uimm)
					}
				);

			il.AddInstruction(ei0);

			// again, if w=0 qdequantize ps1
			// if (w_l == 0)
			// {

			// }

			break;

		case PPC_ID_FRSPx:
			ei0 = il.Intrinsic(
				{RegisterOrFlag::Register(oper0->reg)},
				PPC_INTRIN_FRSP,
				{operToIL(il, oper1)});
			il.AddInstruction(ei0);
			break;

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

