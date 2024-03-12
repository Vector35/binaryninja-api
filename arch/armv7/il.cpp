#include <stdarg.h>
#include "il.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;
using namespace armv7;

#define ILREG(op) il.Register(get_register_size((op).reg), (op).reg)
#define ILOFFSETREG(op) il.Register(get_register_size((op).offset), (op).offset)

//Get N set bits at offset O
#define BITMASK(N,O) (((1LL << N) - 1) << O)

static inline ExprId DirectJump(Architecture* arch, LowLevelILFunction& il, uint64_t target, size_t addrSize)
{
	BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);
	if (label)
		return il.Goto(*label);
	else
		return il.Jump(il.ConstPointer(addrSize, target));

	return 0;
}


static inline ExprId SetRegisterOrBranch(LowLevelILFunction& il, enum Register reg, ExprId expr, uint32_t flags=0)
{
	if (reg == REG_PC)
		return il.Jump(expr);
	else
		return il.SetRegister(get_register_size(reg), reg, expr, flags);
}


static inline ExprId ReadRegisterOrPointer(LowLevelILFunction& il, const InstructionOperand& op, size_t addr)
{
	if (op.reg == REG_PC)
		return il.ConstPointer(4, (addr+8));
	return il.Register(get_register_size(op.reg), op.reg);
}


ExprId GetCondition(LowLevelILFunction& il, Condition cond)
{
	switch(cond)
	{
	 	case COND_EQ: return il.FlagCondition(LLFC_E);
	 	case COND_NE: return il.FlagCondition(LLFC_NE);
	 	case COND_CS: return il.FlagCondition(LLFC_UGE);
	 	case COND_CC: return il.FlagCondition(LLFC_ULT);
	 	case COND_MI: return il.FlagCondition(LLFC_NEG);
	 	case COND_PL: return il.FlagCondition(LLFC_POS);
	 	case COND_VS: return il.FlagCondition(LLFC_O);
	 	case COND_VC: return il.FlagCondition(LLFC_NO);
	 	case COND_HI: return il.FlagCondition(LLFC_UGT);
	 	case COND_LS: return il.FlagCondition(LLFC_ULE);
	 	case COND_GE: return il.FlagCondition(LLFC_SGE);
	 	case COND_LT: return il.FlagCondition(LLFC_SLT);
	 	case COND_GT: return il.FlagCondition(LLFC_SGT);
	 	case COND_LE: return il.FlagCondition(LLFC_SLE);
		case COND_NONE:
		case COND_NONE2:
		 return il.Const(0, 1); //Always branch
		default:
			return il.Const(0, 0); //Never branch
	}
}

static void ConditionalJump(Architecture* arch, LowLevelILFunction& il, Condition cond, size_t addrSize, uint64_t t, uint64_t f)
{
	BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
	BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);

	if (UNCONDITIONAL(cond))
	{
		il.AddInstruction(DirectJump(arch, il, t, addrSize));
		return;
	}

	if (trueLabel && falseLabel)
	{
		il.AddInstruction(il.If(GetCondition(il, cond), *trueLabel, *falseLabel));
		return;
	}

	LowLevelILLabel trueCode, falseCode;

	if (trueLabel)
	{
		il.AddInstruction(il.If(GetCondition(il, cond), *trueLabel, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
		return;
	}

	if (falseLabel)
	{
		il.AddInstruction(il.If(GetCondition(il, cond), trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
		return;
	}

	il.AddInstruction(il.If(GetCondition(il, cond), trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
	il.MarkLabel(falseCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
}


static void ConditionExecute(LowLevelILFunction& il, Condition cond, ExprId trueCase)
{
	LowLevelILLabel trueCode, falseCode;
	if (UNCONDITIONAL(cond))
	{
		il.AddInstruction(trueCase);
		return;
	}

	il.AddInstruction(il.If(GetCondition(il, cond), trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(trueCase);
	il.MarkLabel(falseCode);
}


static ExprId GetShifted(LowLevelILFunction& il, Register reg, uint32_t ShiftAmount, Shift shift)
{
	if (ShiftAmount == 0)
		return il.Register(get_register_size(reg), reg);

	switch (shift)
	{
		case SHIFT_NONE:
			return il.Register(get_register_size(reg), reg);
		case SHIFT_LSR:
			return il.LogicalShiftRight(get_register_size(reg),
					il.Register(get_register_size(reg), reg),
					il.Const(1, ShiftAmount));
		case SHIFT_LSL:
			return il.ShiftLeft(get_register_size(reg),
					il.Register(get_register_size(reg), reg),
					il.Const(1, ShiftAmount));
		case SHIFT_ASR:
			return il.ArithShiftRight(get_register_size(reg),
					il.Register(get_register_size(reg), reg),
					il.Const(1, ShiftAmount));
		case SHIFT_ROR:
			return il.RotateRight(get_register_size(reg),
					il.Register(get_register_size(reg), reg),
					il.Const(1, ShiftAmount));
		case SHIFT_RRX:
			//RRX can only shift 1 at a time
			return il.RotateRightCarry(get_register_size(reg),
					il.Register(get_register_size(reg), reg),
					il.Const(1, 1), il.Flag(IL_FLAG_C));
		default:
			return 0;
	}
}


static ExprId GetShiftedOffset(LowLevelILFunction& il, InstructionOperand& op)
{
	return GetShifted(il, op.offset, op.imm, op.shift);
}


static ExprId GetShiftedRegister(LowLevelILFunction& il, InstructionOperand& op)
{
	return GetShifted(il, op.reg, op.imm, op.shift);
}



static ExprId ReadAddress(LowLevelILFunction& il, InstructionOperand& op, size_t addr)
{
	//This should only be called by with cls or MEM_* or label
	// <op.imm>
	// <op.reg> +/- <op.imm>
	// <op.reg> +/- (<op.offset> <shift> <op.imm>)
	ExprId expr;
	if (op.cls == LABEL)
		return il.ConstPointer(4, op.imm);

	if (op.shift == SHIFT_NONE)
	{
		if (op.flags.offsetRegUsed == 1)
		{
			expr = il.Register(get_register_size(op.offset), op.offset);
		}
		else
		{
			expr = il.Const(4, op.imm);
		}
	}
	else
	{
		if (op.flags.offsetRegUsed == 1)
			expr = GetShiftedOffset(il, op);
		else
			return GetShiftedRegister(il, op);
	}

	if (op.flags.add == 1)
		return il.Add(4, ReadRegisterOrPointer(il, op, addr), expr);
	else
		return il.Sub(4, ReadRegisterOrPointer(il, op, addr), expr);
}


static ExprId ReadILOperand(LowLevelILFunction& il, InstructionOperand& op, size_t addr, bool isPointer=false)
{
	switch (op.cls)
	{

		case IMM64:
			if (isPointer)
				return il.ConstPointer(8, op.imm);
			return il.Const(8, op.imm);
		case IMM:
		case LABEL:
			if (isPointer)
				return il.ConstPointer(4, op.imm);
			return il.Const(4, op.imm);
		case REG:
			if (op.shift == SHIFT_NONE)
				return ReadRegisterOrPointer(il, op, addr);
			else if (op.flags.offsetRegUsed == 1)
			{
				return GetShiftedOffset(il, op);
			}
			else
			{
				return GetShiftedRegister(il, op);
			}
			break;
		case MEM_IMM:
			if (op.shift == SHIFT_NONE)
			{
				if (op.flags.offsetRegUsed == 1)
				{
					return op.flags.add?
						il.Add(4, ReadRegisterOrPointer(il, op, addr), il.Register(get_register_size(op.reg), op.offset)):
						il.Sub(4, ReadRegisterOrPointer(il, op, addr), il.Register(get_register_size(op.reg), op.offset));
				}
				else
				{
					if (op.imm == 0)
					{
						return ReadRegisterOrPointer(il, op, addr);
					}
					return op.flags.add?
						il.Add(4, ReadRegisterOrPointer(il, op, addr), il.Const(4, op.imm)):
						il.Sub(4, ReadRegisterOrPointer(il, op, addr), il.Const(4, op.imm));
				}
			}
			else
				return op.flags.add?
						il.Add(4, ReadRegisterOrPointer(il, op, addr), GetShiftedOffset(il, op)):
						il.Sub(4, ReadRegisterOrPointer(il, op, addr), GetShiftedOffset(il, op));
		case MEM_PRE_IDX:
		case MEM_POST_IDX:
			return GetShiftedRegister(il, op);
		case FIMM32:
		case NONE:
		default:
			il.AddInstruction(il.Unimplemented());
			break;
	}
	return 0;
}


static void Load(
		LowLevelILFunction& il,
		bool sx,
		size_t size,
		InstructionOperand& dst,
		InstructionOperand& src,
		size_t addr)
{
	ExprId value, memValue;
	size_t dstSize = get_register_size(dst.reg);
	value = ReadAddress(il, src, addr);

	switch (src.cls)
	{
		case MEM_PRE_IDX:
			memValue = il.Load(size, ILREG(src));

			if (size != dstSize)
			{
				if (sx)
					memValue = il.SignExtend(dstSize, memValue);
				else
					memValue = il.ZeroExtend(dstSize, memValue);
			}

			il.AddInstruction(SetRegisterOrBranch(il, src.reg, value));
			il.AddInstruction(SetRegisterOrBranch(il, dst.reg, memValue));
			break;
		case MEM_POST_IDX:
			memValue = il.Load(size, ILREG(src));

			if (size != dstSize)
			{
				if (sx)
					memValue = il.SignExtend(dstSize, memValue);
				else
					memValue = il.ZeroExtend(dstSize, memValue);
			}

			if (dst.reg == REG_PC)
			{
				// don't update Rd, update Rs, jump to pre-updated Rs
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), memValue));
				il.AddInstruction(SetRegisterOrBranch(il, src.reg, value));
				il.AddInstruction(il.Jump(il.Register(4, LLIL_TEMP(0))));
			}
			else
			{
				// set Rd, update Rs, don't jump
				il.AddInstruction(il.SetRegister(get_register_size(dst.reg), dst.reg, memValue));
				il.AddInstruction(SetRegisterOrBranch(il, src.reg, value));
			}

			break;
		case MEM_IMM:
		case LABEL:
			memValue = il.Load(size, value);

			if (size != dstSize)
			{
				if (sx)
					memValue = il.SignExtend(dstSize, memValue);
				else
					memValue = il.ZeroExtend(dstSize, memValue);
			}

			il.AddInstruction(SetRegisterOrBranch(il, dst.reg, memValue));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
	}
}


static void LoadExclusive(
		LowLevelILFunction& il,
		bool sx,
		size_t size,
		InstructionOperand& dst,
		InstructionOperand& src,
		size_t addr)
{
	ExprId address = ReadAddress(il, src, addr);
	size_t srcSize = get_register_size(src.reg);

	il.AddInstruction(il.Intrinsic({ },
				ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS,
				{ address, il.Const(1, srcSize) }));
	Load(il, sx, size, dst, src, addr);
}


static void LoadPair(
		Architecture* arch,
		LowLevelILFunction& il,
		InstructionOperand& dst1,
		InstructionOperand& dst2,
		InstructionOperand& src,
		size_t addr)
{
	ExprId address, value;
	size_t dstSize = get_register_size(dst1.reg);

	if (src.cls == MEM_PRE_IDX || src.cls == MEM_POST_IDX)
		address = ILREG(src);
	else
		address = ReadAddress(il, src, addr);
	value = il.Load(dstSize * 2, address);

	if (src.cls == MEM_PRE_IDX)
		il.AddInstruction(SetRegisterOrBranch(il, src.reg, ReadAddress(il, src, addr)));

	ExprId setReg;
	if (arch->GetEndianness() == LittleEndian)
		setReg = il.SetRegisterSplit(dstSize, dst2.reg, dst1.reg, value);
	else
		setReg = il.SetRegisterSplit(dstSize, dst1.reg, dst2.reg, value);
	il.AddInstruction(setReg);

	if (src.cls == MEM_POST_IDX)
		il.AddInstruction(SetRegisterOrBranch(il, src.reg, ReadAddress(il, src, addr)));
}


static void LoadPairExclusive(
		Architecture* arch,
		LowLevelILFunction& il,
		InstructionOperand& dst1,
		InstructionOperand& dst2,
		InstructionOperand& src,
		size_t addr)
{
	ExprId address = ReadAddress(il, src, addr);
	size_t srcSize = get_register_size(src.reg);

	il.AddInstruction(il.Intrinsic({ },
				ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS,
				{ address, il.Const(1, srcSize) }));
	LoadPair(arch, il, dst1, dst2, src, addr);
}


static void Store(
		LowLevelILFunction& il,
		uint8_t size,
		InstructionOperand& src,
		InstructionOperand& dst,
		size_t addr)
{
	ExprId address = ReadAddress(il, dst, addr);
	size_t dstSize = get_register_size(dst.reg);

	ExprId regSrc = ILREG(src);
	size_t srcSize = get_register_size(src.reg);
	if (size < srcSize)
		regSrc = il.LowPart(size, regSrc);

	switch (dst.cls)
	{
		case MEM_IMM:
			il.AddInstruction(il.Store(size, address, regSrc));
			break;
		case MEM_PRE_IDX:
			il.AddInstruction(il.SetRegister(dstSize, dst.reg, address));
			il.AddInstruction(il.Store(size, ILREG(dst), regSrc));
			break;
		case MEM_POST_IDX:
			il.AddInstruction(il.Store(size, ILREG(dst), regSrc));
			il.AddInstruction(il.SetRegister(dstSize, dst.reg, address));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
	}
}


static void StoreExclusive(
		LowLevelILFunction& il,
		uint8_t size,
		InstructionOperand& status,
		InstructionOperand& src,
		InstructionOperand& dst,
		size_t addr)
{
	ExprId address = ReadAddress(il, dst, addr);
	size_t dstSize = get_register_size(dst.reg);

	LowLevelILLabel trueCode, falseCode;
	size_t statusSize = get_register_size(status.reg);
	il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(status.reg) },
				ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS,
				{ address, il.Const(1, dstSize) }));
	il.AddInstruction(il.If(il.CompareEqual(statusSize, il.Register(statusSize, status.reg), il.Const(statusSize, 1)),
				trueCode, falseCode));
	il.MarkLabel(trueCode);

	Store(il, size, src, dst, addr);

	il.MarkLabel(falseCode);
}


static void StorePair(
		Architecture* arch,
		LowLevelILFunction& il,
		InstructionOperand& src1,
		InstructionOperand& src2,
		InstructionOperand& dst,
		size_t addr)
{
	ExprId address, value;
	size_t srcSize = get_register_size(src1.reg);
	LowLevelILLabel trueCode, falseCode;

	if (dst.cls == MEM_POST_IDX)
		address = ILREG(dst);
	else
		address = ReadAddress(il, dst, addr);

	if (arch->GetEndianness() == LittleEndian)
		value = il.RegisterSplit(srcSize, src2.reg, src1.reg);
	else
		value = il.RegisterSplit(srcSize, src1.reg, src2.reg);

	il.AddInstruction(il.Store(srcSize * 2, address, value));

	if (dst.cls == MEM_POST_IDX || dst.cls == MEM_PRE_IDX)
		il.AddInstruction(SetRegisterOrBranch(il, dst.reg, ReadAddress(il, dst, addr)));
}


static void StorePairExclusive(
		Architecture* arch,
		LowLevelILFunction& il,
		InstructionOperand& status,
		InstructionOperand& src1,
		InstructionOperand& src2,
		InstructionOperand& dst,
		size_t addr)
{
	ExprId address = ReadAddress(il, dst, addr);

	LowLevelILLabel trueCode, falseCode;
	size_t statusSize = get_register_size(status.reg);
	il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(status.reg) },
				ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS,
				{ address, il.Const(1, 8) }));
	il.AddInstruction(il.If(il.CompareEqual(statusSize, il.Register(statusSize, status.reg), il.Const(statusSize, 1)),
				trueCode, falseCode));
	il.MarkLabel(trueCode);

	StorePair(arch, il, src1, src2, dst, addr);

	il.MarkLabel(falseCode);
}


static void Saturate(LowLevelILFunction& il, uint32_t dest, ExprId to_saturate, ExprId saturate_to, bool is_signed)
{

	LowLevelILLabel trueCode, falseCode, endCode;
	LowLevelILLabel trueCode2, falseCode2, endCode2;

	if (is_signed)
	{
		il.AddInstruction(il.If(il.CompareSignedLessThan(4, to_saturate, il.Neg(4, saturate_to)), trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.SetRegister(4, dest, il.Neg(4, saturate_to)));
		il.AddInstruction(il.Goto(endCode));
		il.MarkLabel(falseCode);
		il.MarkLabel(endCode);

		il.AddInstruction(il.If(il.CompareSignedGreaterThan(4, to_saturate, saturate_to), trueCode2, falseCode2));
		il.MarkLabel(trueCode2);
		il.AddInstruction(il.SetRegister(4, dest, saturate_to));
		il.AddInstruction(il.Goto(endCode2));
		il.MarkLabel(falseCode2);
		il.AddInstruction(il.SetRegister(4, dest, to_saturate));
		il.MarkLabel(endCode2);
	}
	else
	{
		il.AddInstruction(il.If(il.CompareSignedLessThan(4, to_saturate, il.Const(4, 0)), trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.SetRegister(4, dest, il.Const(4, 0)));
		il.AddInstruction(il.Goto(endCode));
		il.MarkLabel(falseCode);
		il.MarkLabel(endCode);

		il.AddInstruction(il.If(il.CompareSignedGreaterThan(4, to_saturate, saturate_to), trueCode2, falseCode2));
		il.MarkLabel(trueCode2);
		il.AddInstruction(il.SetRegister(4, dest, saturate_to));
		il.AddInstruction(il.Goto(endCode2));
		il.MarkLabel(falseCode2);
		il.AddInstruction(il.SetRegister(4, dest, to_saturate));
		il.MarkLabel(endCode2);
	}
}


uint32_t GetNumberOfRegs(uint16_t regList)
{
	uint32_t nregs = 0;
	for (uint32_t i = 0; i < 16; i++)
	{
		if (((regList >> i) & 1) == 1)
			nregs++;
	}
	return nregs;
}


void ConditionExecute(size_t addrSize, Condition cond, Instruction& instr, LowLevelILFunction& il,
	std::function<void (size_t addrSize, Instruction& instr, LowLevelILFunction& il)> conditionalCode)
{
	if (UNCONDITIONAL(cond))
	{
		conditionalCode(addrSize, instr, il);
		return;
	}

	LowLevelILLabel trueLabel, falseLabel;
	il.AddInstruction(il.If(GetCondition(il, cond), trueLabel, falseLabel));
	il.MarkLabel(trueLabel);
	conditionalCode(addrSize, instr, il);
	il.AddInstruction(il.Goto(falseLabel));
	il.MarkLabel(falseLabel);
}

void LoadOrStoreWithAdjustment(InstructionOperand& src,
	InstructionOperand& dst,
	LowLevelILFunction& il,
	bool load,
	bool increment,
	bool before)
{
	if (before)
	{
		if (increment)
		{
			il.AddInstruction(il.SetRegister(get_register_size(src.reg), src.reg,
				il.Add(get_register_size(src.reg), ILREG(src), il.Const(1, get_register_size(src.reg)))));
		}
		else
		{
			il.AddInstruction(il.SetRegister(get_register_size(src.reg), src.reg,
				il.Sub(get_register_size(src.reg), ILREG(src), il.Const(1, get_register_size(src.reg)))));
		}
	}

	if (load)
	{
		il.AddInstruction(il.SetRegister(get_register_size(dst.reg), dst.reg,
			il.Load(get_register_size(dst.reg), ILREG(src))));
	}
	else
	{
		il.AddInstruction(il.Store(get_register_size(dst.reg), ILREG(dst), ILREG(src)));
	}

	if (!before)
	{
		if (increment)
		{
			il.AddInstruction(il.SetRegister(get_register_size(src.reg), src.reg,
				il.Add(get_register_size(src.reg), ILREG(src), il.Const(1, get_register_size(src.reg)))));
		}
		else
		{
			il.AddInstruction(il.SetRegister(get_register_size(src.reg), src.reg,
				il.Sub(get_register_size(src.reg), ILREG(src), il.Const(1, get_register_size(src.reg)))));
		}
	}
}


bool GetLowLevelILForArmInstruction(Architecture* arch, uint64_t addr, LowLevelILFunction& il, Instruction& instr, size_t addrSize)
{
	(void)arch;
	(void)addr;
	(void)addrSize;
	InstructionOperand& op1 = instr.operands[0];
	InstructionOperand& op2 = instr.operands[1];
	InstructionOperand& op3 = instr.operands[2];
	InstructionOperand& op4 = instr.operands[3];
	InstructionOperand& op5 = instr.operands[4];
	InstructionOperand& op6 = instr.operands[5];
	LowLevelILLabel trueLabel, falseLabel, endLabel, loopBody, loopStart, loopExit;
	uint32_t flagOperation[2] = {IL_FLAGWRITE_NONE, IL_FLAGWRITE_ALL};
	LowLevelILLabel trueCode, falseCode, endCode;
	switch (instr.operation)
	{
		case ARMV7_ADD:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Add(get_register_size(op1.reg),
					ReadRegisterOrPointer(il, op2, addr),
					ReadILOperand(il, op3, addr), flagOperation[instr.setsFlags])));
			break;
		case ARMV7_ADDW:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Add(get_register_size(op1.reg),
					ReadRegisterOrPointer(il, op2, addr),
					ReadILOperand(il, op3, addr), IL_FLAGWRITE_NONE)));
			break;
		case ARMV7_ADC:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.AddCarry(get_register_size(op1.reg),
					ReadRegisterOrPointer(il, op2, addr),
					ReadILOperand(il, op3, addr), il.Flag(IL_FLAG_C), flagOperation[instr.setsFlags])));
			break;
		case ARMV7_ADR:
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg,
					il.ConstPointer(get_register_size(op1.reg), op2.imm)));
			break;
		case ARMV7_AND:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.And(get_register_size(op1.reg),
					ReadRegisterOrPointer(il, op2, addr),
					ReadILOperand(il, op3, addr), flagOperation[instr.setsFlags])));
			break;
		case ARMV7_ASR:
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg,
					il.ArithShiftRight(get_register_size(op2.reg),
						ReadRegisterOrPointer(il, op2, addr),
						ReadILOperand(il, op3, addr), flagOperation[instr.setsFlags])));
			break;
		case ARMV7_B:
			ConditionalJump(arch, il, instr.cond, addrSize, op1.imm, addr + 4);
			return false;
		case ARMV7_BFC:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.And(get_register_size(op1.reg), ReadRegisterOrPointer(il, op1, addr),
					il.Const(get_register_size(op1.reg), ~(((1<<op3.imm) - 1) << op2.imm)))));
			break;
		case ARMV7_BFI:
		{
			uint32_t lsb = op3.imm;
			uint32_t width_mask = (1<<op4.imm) - 1;
			uint32_t mask = width_mask << lsb;

			//bit field insert: op1 = (op1 & (~(<width_mask> << lsb))) | ((op2 & <width_mask>) << lsb)
			//width_mask = (1<<width)-1
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Or(get_register_size(op1.reg),
					il.And(get_register_size(op1.reg),
						ReadRegisterOrPointer(il, op1, addr),
						il.Const(4, ~mask)
					),
				il.ShiftLeft(4,
					il.And(get_register_size(op1.reg),
						ReadRegisterOrPointer(il, op2, addr),
						il.Const(get_register_size(op1.reg), width_mask)
					),
					il.Const(4, lsb)))));
			break;
		}
        case ARMV7_BKPT:
            il.AddInstruction(il.Breakpoint());
            break;
		case ARMV7_BL:
			ConditionExecute(il, instr.cond, il.Call(il.ConstPointer(4, op1.imm)));
			break;
		case ARMV7_BXJ:
		case ARMV7_BX:
			ConditionExecute(il, instr.cond, il.Jump(ReadILOperand(il, op1, addr, true)));
			break;
		case ARMV7_BLX:
			ConditionExecute(il, instr.cond, il.Call(ReadILOperand(il, op1, addr, true)));
			break;
		case ARMV7_BIC:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.And(get_register_size(op2.reg),
					ReadRegisterOrPointer(il, op2, addr),
					il.Not(get_register_size(op2.reg),
						ReadILOperand(il, op3, addr)), flagOperation[instr.setsFlags]
						)));
			break;
		case ARMV7_CLZ:
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				//Count leading zeros
				//
				// TEMP0 = 0
				// TEMP1 = op2.reg
				// while (TEMP1 != 0)
				// 		TEMP1 = TEMP1 >> 1
				// 		TEMP0 = TEMP0 + 1
				// op1.reg = 32 - TEMP0
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Const(4, 0)));
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1), ReadRegisterOrPointer(il, op2, addr)));
				il.AddInstruction(il.Goto(loopStart));
				il.MarkLabel(loopStart);
				il.AddInstruction(il.If(il.CompareNotEqual(4, il.Register(4, LLIL_TEMP(1)), il.Const(4, 0)), loopBody, loopExit));
				il.MarkLabel(loopBody);
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1), il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(4,1))));
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(4,1))));
				il.AddInstruction(il.Goto(loopStart));
				il.MarkLabel(loopExit);
				il.AddInstruction(SetRegisterOrBranch(il, op1.reg, il.Sub(4, il.Const(4, 32), il.Register(4, LLIL_TEMP(0)))));
			});
			break;
		case ARMV7_CMN:
			ConditionExecute(il, instr.cond, il.Add(get_register_size(op1.reg),
				ReadRegisterOrPointer(il, op1, addr),
				ReadILOperand(il, op2, addr), IL_FLAGWRITE_ALL));
			break;
		case ARMV7_CMP:
			ConditionExecute(il, instr.cond, il.Sub(get_register_size(op1.reg),
				ReadRegisterOrPointer(il, op1, addr),
				ReadILOperand(il, op2, addr), IL_FLAGWRITE_ALL));
			break;
		case ARMV7_EOR:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Xor(get_register_size(op1.reg),
					ReadRegisterOrPointer(il, op2, addr),
					ReadILOperand(il, op3, addr), flagOperation[instr.setsFlags])));
			break;
		case ARMV7_LDM:
		case ARMV7_LDMIA:
		case ARMV7_LDMIB:
		case ARMV7_LDMDA:
		case ARMV7_LDMDB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					//Cache src address register in case it's mutated by loads
					ExprId base = 0;
					switch (instr.operation)
					{
					case ARMV7_LDM:
					case ARMV7_LDMIA:
						base = ILREG(op1);
						break;
					case ARMV7_LDMIB:
						base = il.Add(4, ILREG(op1), il.Const(1, 4));
						break;
					case ARMV7_LDMDB:
						base = il.Sub(4, ILREG(op1), il.Const(1, 4 * GetNumberOfRegs(op2.reg)));
						break;
					case ARMV7_LDMDA:
						base = il.Sub(4, ILREG(op1), il.Const(1, 4 * GetNumberOfRegs(op2.reg) - 4));
						break;
					default:
						break;
					}
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), base));

					for (int reg = 0, slot = 0; reg < 16; reg++)
					{
						if (op2.reg & 1 << reg)
						{
							il.AddInstruction(
								il.SetRegister(4,
									// writes to PC are deferred to a final Jump
									(reg != REG_PC) ? reg : LLIL_TEMP(1),
									il.Load(4,
										il.Add(4,
											il.Register(4, LLIL_TEMP(0)),
											il.Const(1, 4 * slot++)
										)
									)
								)
							);
						}
					}
					if (op1.flags.wb)
					{
						ExprId wb;
						switch (instr.operation)
						{
						case ARMV7_LDM:
						case ARMV7_LDMIA:
							wb = il.Const(1, 4 * GetNumberOfRegs(op2.reg));
							wb = il.Add(4, il.Register(4, LLIL_TEMP(0)), wb);
							break;
						case ARMV7_LDMIB:
							wb = il.Const(1, 4 * GetNumberOfRegs(op2.reg) - 4);
							wb = il.Add(4, il.Register(4, LLIL_TEMP(0)), wb);
							break;
						case ARMV7_LDMDB:
							wb = il.Register(4, LLIL_TEMP(0));
							break;
						case ARMV7_LDMDA:
							wb = il.Const(1, 4);
							wb = il.Sub(4, il.Register(4, LLIL_TEMP(0)), wb);
							break;
						default:
							break;
						}
						//if (1 << op1.reg & op2.reg) [[unlikely]] {
						if (1 << op1.reg & op2.reg) {
							wb = il.Undefined();
						}
						il.AddInstruction(il.SetRegister(4, op1.reg, wb));
					}
					if (op2.reg & REG_LIST_PC)
					{
						il.AddInstruction(il.Jump(il.Register(4, LLIL_TEMP(1))));
					}
				});
			break;
		case ARMV7_LDREX:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						LoadExclusive(il, false, 4, op1, op2, addr);
					});
			break;
		case ARMV7_LDR:
		case ARMV7_LDRT:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						Load(il, false, 4, op1, op2, addr);
					});
			break;
		case ARMV7_LDREXH:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						LoadExclusive(il, false, 2, op1, op2, addr);
					});
			break;
		case ARMV7_LDRH:
		case ARMV7_LDRHT:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						Load(il, false, 2, op1, op2, addr);
					});
			break;
		case ARMV7_LDREXB:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						LoadExclusive(il, false, 1, op1, op2, addr);
					});
			break;
		case ARMV7_LDRB:
		case ARMV7_LDRBT:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						Load(il, false, 1, op1, op2, addr);
					});
			break;
		case ARMV7_LDRSH:
		case ARMV7_LDRSHT:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						Load(il, true,  2, op1, op2, addr);
					});
			break;
		case ARMV7_LDRSB:
		case ARMV7_LDRSBT:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						Load(il, true,  1, op1, op2, addr);
					});
			break;
		case ARMV7_LDREXD:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						LoadPairExclusive(arch, il, op1, op2, op3, addr);
					});
			break;
		case ARMV7_LDRD:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						LoadPair(arch, il, op1, op2, op3, addr);
					});
			break;
		case ARMV7_LSL:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.ShiftLeft(get_register_size(op2.reg),
					ReadRegisterOrPointer(il, op2, addr),
					ReadILOperand(il, op3, addr), flagOperation[instr.setsFlags])));
			break;
		case ARMV7_LSR:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.LogicalShiftRight(get_register_size(op2.reg),
					ReadRegisterOrPointer(il, op2, addr),
					ReadILOperand(il, op3, addr), flagOperation[instr.setsFlags])));
			break;
		case ARMV7_MCR:
		case ARMV7_MCR2:
			ConditionExecute(il, instr.cond,
				il.Intrinsic({ }, ARMV7_INTRIN_COPROC_SENDONEWORD,
					{
						il.Register(4, op3.reg),
						il.Const(1, op1.reg),
						il.Const(1, op2.imm),
						il.Const(1, op4.reg),
						il.Const(1, op5.reg),
						il.Const(1, op6.imm),
					}
				)
			);
			break;
		case ARMV7_MCRR:
		case ARMV7_MCRR2:
			ConditionExecute(il, instr.cond,
				il.Intrinsic({ }, ARMV7_INTRIN_COPROC_SENDTWOWORDS,
					{
						il.Register(4, op4.reg),
						il.Register(4, op3.reg),
						il.Const(1, op1.reg),
						il.Const(1, op2.imm),
						il.Const(1, op5.reg),
					}
				)
			);
			break;
		case ARMV7_MLA:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Add(get_register_size(op1.reg),
					ReadRegisterOrPointer(il, op4, addr),
					il.Mult(get_register_size(op2.reg),
						ReadRegisterOrPointer(il, op2, addr),
						(op3.cls == NONE) ? ReadRegisterOrPointer(il, op1, addr) : ReadRegisterOrPointer(il, op3, addr)),
					instr.setsFlags ? IL_FLAGWRITE_NZ : IL_FLAGWRITE_NONE)));
			break;
		case ARMV7_MLS:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Sub(get_register_size(op1.reg),
					ReadRegisterOrPointer(il, op4, addr),
					il.Mult(get_register_size(op2.reg),
						ReadRegisterOrPointer(il, op2, addr),
						(op3.cls == NONE) ? ReadRegisterOrPointer(il, op1, addr) : ReadRegisterOrPointer(il, op3, addr)),
					flagOperation[instr.setsFlags])));
			break;
		case ARMV7_MOV:
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg,
					ReadILOperand(il, op2, addr),
					instr.setsFlags ? IL_FLAGWRITE_NZ : IL_FLAGWRITE_NONE));
			break;
		case ARMV7_MOVT:
			// op1.reg = (op2.imm << 16) | (op1 & 0x0000ffff)
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg,
					il.Or(4,
						il.ShiftLeft(4, il.Const(2, op2.imm), il.Const(1,16)),
						il.And(4, il.Const(4, 0x0000ffff), ReadRegisterOrPointer(il, op1, addr)))));
			break;
		case ARMV7_MOVW:
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg, il.Const(4, op2.imm)));
			break;
		case ARMV7_MRC:
		case ARMV7_MRC2:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void)addrSize;
					(void)instr;
					auto params = {
						il.Const(1, op1.reg),
						il.Const(1, op2.imm),
						il.Const(1, op4.reg),
						il.Const(1, op5.reg),
						il.Const(1, op6.imm),
					};
					switch (op3.cls) {
					case REG:
						il.AddInstruction(
							il.Intrinsic(
								{ RegisterOrFlag::Register(op3.reg) },
								ARMV7_INTRIN_COPROC_GETONEWORD,
								params
							)
						);
						break;
					case REG_SPEC:
						il.AddInstruction(
							il.Intrinsic(
								{ RegisterOrFlag::Register(LLIL_TEMP(0)) },
								ARMV7_INTRIN_COPROC_GETONEWORD,
								params
							)
						);
						il.AddInstruction(il.SetFlag(IL_FLAG_N, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 31))));
						il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 30))));
						il.AddInstruction(il.SetFlag(IL_FLAG_C, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 29))));
						il.AddInstruction(il.SetFlag(IL_FLAG_V, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 28))));
						break;
					default:
						break;
					}
				});
			break;
		case ARMV7_MRRC:
		case ARMV7_MRRC2:
			ConditionExecute(il, instr.cond,
				il.Intrinsic(
					{ RegisterOrFlag::Register(op4.reg), RegisterOrFlag::Register(op3.reg) },
					ARMV7_INTRIN_COPROC_GETTWOWORDS,
					{
						il.Const(1, op1.reg),
						il.Const(1, op2.imm),
						il.Const(1, op5.reg),
					}
				)
			);
			break;
		case ARMV7_MUL:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Mult(get_register_size(op2.reg),
					ReadRegisterOrPointer(il, op2, addr),
					(op3.cls == NONE) ? ReadRegisterOrPointer(il, op1, addr) : ReadRegisterOrPointer(il, op3, addr),
					instr.setsFlags ? IL_FLAGWRITE_NZ : IL_FLAGWRITE_NONE)));
			break;
		case ARMV7_MVN:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Not(get_register_size(op2.reg),
					ReadILOperand(il, op2, addr), flagOperation[instr.setsFlags])));
			break;
		case ARMV7_NOP:
		case ARMV7_DSB:
		case ARMV7_DMB:
		case ARMV7_ISB:
			ConditionExecute(il, instr.cond, il.Nop());
			break;
		case ARMV7_ORR:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Or(get_register_size(op1.reg),
					ReadRegisterOrPointer(il, op2, addr),
					ReadILOperand(il, op3, addr), flagOperation[instr.setsFlags])));
			break;
		case ARMV7_PKHBT:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Or(4,
					il.And(2,
						ReadRegisterOrPointer(il, op2, addr),
						il.Const(4, 0xffff0000)),
					il.And(2,
						ReadRegisterOrPointer(il, op3, addr),
						il.Const(2, 0xffff))
					)
				));
			break;
		case ARMV7_PKHTB:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Or(4,
					il.And(2,
						ReadRegisterOrPointer(il, op3, addr),
						il.Const(4, 0xffff0000)),
					il.And(2,
						ReadRegisterOrPointer(il, op2, addr),
						il.Const(2, 0xffff))
					)
				));
			break;
		case ARMV7_POP:
			if (CONDITIONAL(instr.cond))
			{
				il.AddInstruction(il.If(GetCondition(il, instr.cond), trueCode, falseCode));
				il.MarkLabel(trueCode);
			}
			for (int32_t j = 0; j <= 15; j++)
			{
				if (((op1.reg >> j) & 1) == 1)
				{
					if (1 << j == REG_LIST_PC)
					{
						il.AddInstruction(
							il.SetRegister(4, LLIL_TEMP(0),
								il.Pop(get_register_size((enum Register)j))));
					}
					else
					{
						il.AddInstruction(SetRegisterOrBranch(il, (Register)j,
							il.Pop(get_register_size((enum Register)j))));
					}

				}
			}
			if ((op1.reg & REG_LIST_PC) == REG_LIST_PC)
				il.AddInstruction(il.Jump(il.Register(4, LLIL_TEMP(0))));

			if (CONDITIONAL(instr.cond))
				il.MarkLabel(falseCode);
			break;
		case ARMV7_PUSH:

			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					for (int32_t j = 15; j >= 0; j--)
					{
						if (((op1.reg >> j) & 1) == 1)
						{
							il.AddInstruction(il.Push(get_register_size((enum Register)j),
								il.Register(get_register_size((enum Register)j), j)));
						}
					}
				});
			break;
		case ARMV7_QADD:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(get_register_size(op1.reg), op1.reg,
						il.Add(get_register_size(op1.reg),
							ReadRegisterOrPointer(il, op2, addr),
							ReadRegisterOrPointer(il, op3, addr)
							)));
					il.AddInstruction(il.SetRegister(get_register_size(op1.reg), op1.reg,
						il.Or(get_register_size(op1.reg),
							ReadRegisterOrPointer(il, op1, addr),
							il.Neg(get_register_size(op1.reg),
								il.CompareSignedLessThan(get_register_size(op1.reg),
									ReadRegisterOrPointer(il, op1, addr),
									ReadRegisterOrPointer(il, op2, addr)
							)))));
				});
			break;
		case ARMV7_QADD16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0),
						il.Add(2,
							il.LowPart(2,
								ReadRegisterOrPointer(il, op2, addr)),
							il.LowPart(2,
								ReadRegisterOrPointer(il, op3, addr))
							)));
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0),
						il.Or(2,
							il.Register(2, LLIL_TEMP(0)),
							il.LowPart(2,
								il.Neg(2,
									il.CompareSignedLessThan(2,
										il.Register(2, LLIL_TEMP(0)),
										il.LowPart(2, ReadRegisterOrPointer(il, op2, addr))))))
							));

					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1),
						il.Add(2,
							il.LowPart(2, il.ArithShiftRight(2,
								ReadRegisterOrPointer(il, op2, addr),
								il.Const(1, 16))),
							il.LowPart(2, il.ArithShiftRight(2,
								ReadRegisterOrPointer(il, op3, addr),
								il.Const(1, 16)))
							)));
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1),
						il.Or(2,
							il.Register(2, LLIL_TEMP(1)),
							il.LowPart(2,
								il.Neg(2,
									il.CompareSignedLessThan(get_register_size(op2.reg),
										il.Register(2, LLIL_TEMP(1)),
										il.LowPart(2,
											il.ArithShiftRight(2,
												ReadRegisterOrPointer(il, op2, addr),
												il.Const(1, 16)))))
							))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4, il.Register(2, LLIL_TEMP(1)), il.Const(1, 0x10)),
							il.Register(2, LLIL_TEMP(0))
							)));
				});
			break;
		case ARMV7_UQADD16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0),
						il.Add(2,
							il.LowPart(2,
								ReadRegisterOrPointer(il, op2, addr)),
							il.LowPart(2,
								ReadRegisterOrPointer(il, op3, addr))
							)));
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0),
						il.Or(2,
							il.Register(2, LLIL_TEMP(0)),
							il.LowPart(2,
								il.Neg(2,
									il.CompareUnsignedLessThan(2,
										il.Register(2, LLIL_TEMP(0)),
										il.LowPart(2, ReadRegisterOrPointer(il, op2, addr))))))
							));

					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1),
						il.Add(2,
							il.LowPart(2, il.LogicalShiftRight(2,
								ReadRegisterOrPointer(il, op2, addr),
								il.Const(1, 16))),
							il.LowPart(2, il.LogicalShiftRight(2,
								ReadRegisterOrPointer(il, op3, addr),
								il.Const(1, 16)))
							)));
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1),
						il.Or(2,
							il.Register(2, LLIL_TEMP(1)),
							il.LowPart(2,
								il.Neg(2,
									il.CompareUnsignedLessThan(get_register_size(op2.reg),
										il.Register(2, LLIL_TEMP(1)),
										il.LowPart(2,
											il.LogicalShiftRight(2,
												ReadRegisterOrPointer(il, op2, addr),
												il.Const(1, 16)))))
							))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4, il.Register(2, LLIL_TEMP(1)), il.Const(1, 0x10)),
							il.Register(2, LLIL_TEMP(0))
							)));
				});
			break;
		case ARMV7_QADD8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					for (int i = 0; i < 4; i++)
					{
						il.AddInstruction(il.SetRegister(1, LLIL_TEMP(i),
							il.Add(1,
								il.LowPart(1,
									il.ArithShiftRight(4,
										ReadRegisterOrPointer(il, op2, addr),
										il.Const(1, 8*i))),
								il.LowPart(1,
									il.ArithShiftRight(4,
										ReadRegisterOrPointer(il, op3, addr),
										il.Const(1, 8*i))))));
						il.AddInstruction(il.SetRegister(1, LLIL_TEMP(i),
							il.Or(1,
								il.Register(1, LLIL_TEMP(i)),
								il.Neg(1,
									il.CompareSignedLessThan(1,
										il.Register(1, LLIL_TEMP(i)),
										il.LowPart(1,
											il.ArithShiftRight(4,
												ReadRegisterOrPointer(il, op2, addr),
												il.Const(1, 8*i))))))));
					}

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.Or(4,
								il.ShiftLeft(4,
									il.Register(1, LLIL_TEMP(3)),
									il.Const(1,24)),
								il.ShiftLeft(3,
									il.Register(1, LLIL_TEMP(2)),
									il.Const(1,16))),
							il.Or(2,
								il.ShiftLeft(4,
									il.Register(1, LLIL_TEMP(1)),
									il.Const(1,8)),
								il.Register(1, LLIL_TEMP(0))))));
				});
			break;
		case ARMV7_UQADD8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					for (int i = 0; i < 4; i++)
					{
						il.AddInstruction(il.SetRegister(1, LLIL_TEMP(i),
							il.Add(1,
								il.LowPart(1,
									il.LogicalShiftRight(4,
										ReadRegisterOrPointer(il, op2, addr),
										il.Const(1, 8*i))),
								il.LowPart(1,
									il.LogicalShiftRight(4,
										ReadRegisterOrPointer(il, op3, addr),
										il.Const(1, 8*i))))));
						il.AddInstruction(il.SetRegister(1, LLIL_TEMP(i),
							il.Or(1,
								il.Register(1, LLIL_TEMP(i)),
								il.Neg(1,
									il.CompareUnsignedLessThan(1,
										il.Register(1, LLIL_TEMP(i)),
										il.LowPart(1,
											il.LogicalShiftRight(4,
												ReadRegisterOrPointer(il, op2, addr),
												il.Const(1, 8*i))))))));
					}

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.Or(4,
								il.ShiftLeft(4,
									il.Register(1, LLIL_TEMP(3)),
									il.Const(1,24)),
								il.ShiftLeft(3,
									il.Register(1, LLIL_TEMP(2)),
									il.Const(1,16))),
							il.Or(2,
								il.ShiftLeft(4,
									il.Register(1, LLIL_TEMP(1)),
									il.Const(1,8)),
								il.Register(1, LLIL_TEMP(0))))));
				});
			break;
		case ARMV7_QDADD:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(get_register_size(op1.reg), op1.reg,
								il.Add(get_register_size(op1.reg),
									ReadRegisterOrPointer(il, op2, addr),
									il.Mult(4,
										ReadRegisterOrPointer(il, op3, addr),
										il.Const(1, 2))
									)));
					il.AddInstruction(il.SetRegister(get_register_size(op1.reg), op1.reg,
								il.Or(get_register_size(op1.reg),
									ReadRegisterOrPointer(il, op1, addr),
									il.Neg(get_register_size(op1.reg),
										il.CompareSignedLessThan(get_register_size(op1.reg),
											ReadRegisterOrPointer(il, op1, addr),
											ReadRegisterOrPointer(il, op2, addr)
									)))));
				});
			break;
		case ARMV7_QASX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.LowPart(2,
								ReadILOperand(il, op2, addr)
							),
							il.ArithShiftRight(2,
								ReadILOperand(il, op3, addr),
								il.Const(1,16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Add(4,
							il.ArithShiftRight(2,
								ReadILOperand(il, op2, addr),
								il.Const(1,16)
							),
							il.LowPart(2,
								ReadILOperand(il, op3, addr)
							)
						)
					));

					Saturate(il, LLIL_TEMP(2), il.Register(4, LLIL_TEMP(0)), il.Const(2, 0x7fff), true);
					Saturate(il, LLIL_TEMP(3), il.Register(4, LLIL_TEMP(1)), il.Const(2, 0x7fff), true);

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.Register(2, LLIL_TEMP(3)),
								il.Const(1, 16)
							),
							il.Register(2, LLIL_TEMP(2))
						)
					));
				});
			break;
		case ARMV7_QSAX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Add(4,
							il.LowPart(2,
								ReadILOperand(il, op2, addr)
							),
							il.ArithShiftRight(2,
								ReadILOperand(il, op3, addr),
								il.Const(1,16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Sub(4,
							il.ArithShiftRight(2,
								ReadILOperand(il, op2, addr),
								il.Const(1,16)
							),
							il.LowPart(2,
								ReadILOperand(il, op3, addr)
							)
						)
					));

					Saturate(il, LLIL_TEMP(2), il.Register(4, LLIL_TEMP(0)), il.Const(2, 0x7fff), true);
					Saturate(il, LLIL_TEMP(3), il.Register(4, LLIL_TEMP(1)), il.Const(2, 0x7fff), true);

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.Register(2, LLIL_TEMP(3)),
								il.Const(1, 16)
							),
							il.Register(2, LLIL_TEMP(2))
						)
					));
				});
			break;
		case ARMV7_QDSUB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(get_register_size(op1.reg), op1.reg,
								il.Sub(get_register_size(op1.reg),
									ReadRegisterOrPointer(il, op2, addr),
									il.Mult(4,
										ReadRegisterOrPointer(il, op3, addr),
										il.Const(1, 2))
									)));
					il.AddInstruction(il.SetRegister(get_register_size(op1.reg), op1.reg,
								il.And(get_register_size(op1.reg),
									ReadRegisterOrPointer(il, op1, addr),
									il.Neg(get_register_size(op1.reg),
										il.CompareSignedLessEqual(get_register_size(op1.reg),
											ReadRegisterOrPointer(il, op1, addr),
											ReadRegisterOrPointer(il, op2, addr)
									)))));
				});
			break;
		case ARMV7_QSUB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(get_register_size(op1.reg), op1.reg,
						il.Sub(get_register_size(op1.reg),
							ReadRegisterOrPointer(il, op2, addr),
							ReadRegisterOrPointer(il, op3, addr)
							)));
					il.AddInstruction(il.SetRegister(get_register_size(op1.reg), op1.reg,
						il.And(get_register_size(op1.reg),
							ReadRegisterOrPointer(il, op1, addr),
							il.Neg(get_register_size(op1.reg),
								il.CompareSignedLessEqual(get_register_size(op1.reg),
									ReadRegisterOrPointer(il, op1, addr),
									ReadRegisterOrPointer(il, op2, addr)
							)))));
				});
			break;
		case ARMV7_QSUB16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0),
						il.Sub(2,
							il.LowPart(2,
								ReadRegisterOrPointer(il, op2, addr)),
							il.LowPart(2,
								ReadRegisterOrPointer(il, op3, addr))
							)));
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0),
						il.And(2,
							il.Register(2, LLIL_TEMP(0)),
							il.LowPart(2,
								il.Neg(2,
									il.CompareSignedLessEqual(2,
										il.Register(2, LLIL_TEMP(0)),
										il.LowPart(2, ReadRegisterOrPointer(il, op2, addr))))))
							));

					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1),
						il.Sub(2,
							il.LowPart(2, il.ArithShiftRight(2,
								ReadRegisterOrPointer(il, op2, addr),
								il.Const(1, 16))),
							il.LowPart(2, il.ArithShiftRight(2,
								ReadRegisterOrPointer(il, op3, addr),
								il.Const(1, 16)))
							)));
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1),
						il.And(2,
							il.Register(2, LLIL_TEMP(1)),
							il.LowPart(2,
								il.Neg(2,
									il.CompareSignedLessEqual(get_register_size(op2.reg),
										il.Register(2, LLIL_TEMP(1)),
										il.LowPart(2,
											il.ArithShiftRight(2,
												ReadRegisterOrPointer(il, op2, addr),
												il.Const(1, 16)))))
							))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4, il.Register(2, LLIL_TEMP(1)), il.Const(1, 0x10)),
							il.Register(2, LLIL_TEMP(0))
							)));
				});
			break;
		case ARMV7_UQSUB16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0),
						il.Sub(2,
							il.LowPart(2,
								ReadRegisterOrPointer(il, op2, addr)),
							il.LowPart(2,
								ReadRegisterOrPointer(il, op3, addr))
							)));
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0),
						il.And(2,
							il.Register(2, LLIL_TEMP(0)),
							il.LowPart(2,
								il.Neg(2,
									il.CompareUnsignedLessEqual(2,
										il.Register(2, LLIL_TEMP(0)),
										il.LowPart(2, ReadRegisterOrPointer(il, op2, addr))))))
							));

					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1),
						il.Sub(2,
							il.LowPart(2, il.LogicalShiftRight(2,
								ReadRegisterOrPointer(il, op2, addr),
								il.Const(1, 16))),
							il.LowPart(2, il.LogicalShiftRight(2,
								ReadRegisterOrPointer(il, op3, addr),
								il.Const(1, 16)))
							)));
					il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1),
						il.And(2,
							il.Register(2, LLIL_TEMP(1)),
							il.LowPart(2,
								il.Neg(2,
									il.CompareUnsignedLessEqual(get_register_size(op2.reg),
										il.Register(2, LLIL_TEMP(1)),
										il.LowPart(2,
											il.LogicalShiftRight(2,
												ReadRegisterOrPointer(il, op2, addr),
												il.Const(1, 16)))))
							))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4, il.Register(2, LLIL_TEMP(1)), il.Const(1, 0x10)),
							il.Register(2, LLIL_TEMP(0))
							)));
				});
			break;
		case ARMV7_QSUB8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					for (int i = 0; i < 4; i++)
					{
						il.AddInstruction(il.SetRegister(1, LLIL_TEMP(i),
							il.Sub(1,
								il.LowPart(1,
									il.ArithShiftRight(4,
										ReadRegisterOrPointer(il, op2, addr),
										il.Const(1, 8*i))),
								il.LowPart(1,
									il.ArithShiftRight(4,
										ReadRegisterOrPointer(il, op3, addr),
										il.Const(1, 8*i))))));
						il.AddInstruction(il.SetRegister(1, LLIL_TEMP(i),
							il.And(1,
								il.Register(1, LLIL_TEMP(i)),
								il.Neg(1,
									il.CompareSignedLessEqual(1,
										il.Register(1, LLIL_TEMP(i)),
										il.LowPart(1,
											il.ArithShiftRight(4,
												ReadRegisterOrPointer(il, op2, addr),
												il.Const(1, 8*i))))))));
					}

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.Or(4,
								il.ShiftLeft(4,
									il.Register(1, LLIL_TEMP(3)),
									il.Const(1,24)),
								il.ShiftLeft(3,
									il.Register(1, LLIL_TEMP(2)),
									il.Const(1,16))),
							il.Or(2,
								il.ShiftLeft(4,
									il.Register(1, LLIL_TEMP(1)),
									il.Const(1,8)),
								il.Register(1, LLIL_TEMP(0))))));
				});
			break;
		case ARMV7_UQSUB8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					for (int i = 0; i < 4; i++)
					{
						il.AddInstruction(il.SetRegister(1, LLIL_TEMP(i),
							il.Sub(1,
								il.LowPart(1,
									il.LogicalShiftRight(4,
										ReadRegisterOrPointer(il, op2, addr),
										il.Const(1, 8*i))),
								il.LowPart(1,
									il.LogicalShiftRight(4,
										ReadRegisterOrPointer(il, op3, addr),
										il.Const(1, 8*i))))));
						il.AddInstruction(il.SetRegister(1, LLIL_TEMP(i),
							il.And(1,
								il.Register(1, LLIL_TEMP(i)),
								il.Neg(1,
									il.CompareSignedLessEqual(1,
										il.Register(1, LLIL_TEMP(i)),
										il.LowPart(1,
											il.LogicalShiftRight(4,
												ReadRegisterOrPointer(il, op2, addr),
												il.Const(1, 8*i))))))));
					}

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.Or(4,
								il.ShiftLeft(4,
									il.Register(1, LLIL_TEMP(3)),
									il.Const(1,24)),
								il.ShiftLeft(3,
									il.Register(1, LLIL_TEMP(2)),
									il.Const(1,16))),
							il.Or(2,
								il.ShiftLeft(4,
									il.Register(1, LLIL_TEMP(1)),
									il.Const(1,8)),
								il.Register(1, LLIL_TEMP(0))))));
				});
			break;
		case ARMV7_RBIT:
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				//Reverse bits
				//
				// TEMP0 = 0
				// TEMP1 = op2.reg
				// TEMP2 = 0
				// while (TEMP0 != 31)
				//		TEMP2 = TEMP2 | (TEMP1 & 1)
				//		TEMP2 = TEMP2 << 1
				// 		TEMP1 = TEMP1 >> 1
				// 		TEMP0 = TEMP0 + 1
				// op1.reg = 32 - TEMP0
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Const(4, 0)));
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1), ReadRegisterOrPointer(il, op2, addr)));
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(2), il.Const(4, 0)));
				il.AddInstruction(il.Goto(loopStart));
				il.MarkLabel(loopStart);
				il.AddInstruction(il.If(il.CompareNotEqual(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 31)), loopBody, loopExit));
				il.MarkLabel(loopBody);
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(2), il.Or(4, il.Register(4, LLIL_TEMP(2)), il.And(4, il.Register(4, LLIL_TEMP(1)), il.Const(4,1)))));
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(2), il.ShiftLeft(4, il.Register(4, LLIL_TEMP(2)), il.Const(4,1))));
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1), il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(4,1))));
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(4,1))));
				il.AddInstruction(il.Goto(loopStart));
				il.MarkLabel(loopExit);
				il.AddInstruction(SetRegisterOrBranch(il, op1.reg, il.Register(4, LLIL_TEMP(2))));
			});
			break;
		case ARMV7_REV:
			ConditionExecute(il, instr.cond, il.SetRegister(4, op1.reg,
				il.Or(4,
					il.LogicalShiftRight(4, il.Register(4, op2.reg), il.Const(1, 24)),
					il.Or(4,
						il.ShiftLeft(4, il.And(4, il.LogicalShiftRight(4, il.Register(4, op2.reg), il.Const(1, 16)), il.Const(4, 0xff)), il.Const(1, 8)),
						il.Or(4,
							il.ShiftLeft(4, il.And(4, il.LogicalShiftRight(4, il.Register(4, op2.reg), il.Const(1, 8)), il.Const(4, 0xff)), il.Const(1, 16)),
							il.ShiftLeft(4, il.And(4, il.Register(4, op2.reg), il.Const(4, 0xff)), il.Const(1, 24))
						)
					)
				),
				flagOperation[instr.setsFlags]));
			break;
		case ARMV7_REV16:
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0), il.RotateRight(2, il.LowPart(2, ReadILOperand(il, op2, addr)), il.Const(1, 16))));
				il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1), il.RotateRight(2, il.LogicalShiftRight(2, ReadILOperand(il, op2, addr), il.Const(1, 16)), il.Const(1, 16))));
				il.AddInstruction(il.SetRegister(4, op1.reg, il.Or(4, il.ShiftLeft(4, il.Register(2, LLIL_TEMP(1)), il.Const(1, 16)), il.Register(2, LLIL_TEMP(0)))));
			});
			break;
		case ARMV7_REVSH:
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0), il.RotateRight(2, il.LowPart(2, ReadILOperand(il, op2, addr)), il.Const(1, 16))));
				il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1), il.RotateRight(2, il.LogicalShiftRight(2, ReadILOperand(il, op2, addr), il.Const(1, 16)), il.Const(1, 16))));
				il.AddInstruction(il.SetRegister(4, op1.reg, il.SignExtend(4, il.Or(4, il.ShiftLeft(4, il.Register(2, LLIL_TEMP(1)), il.Const(1, 16)), il.Register(2, LLIL_TEMP(0))))));
			});
			break;

		case ARMV7_RSB:
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg,
					il.Sub(get_register_size(op2.reg),
						ReadILOperand(il, op3, addr),
						ReadRegisterOrPointer(il, op2, addr),
						flagOperation[instr.setsFlags])));
			break;
		case ARMV7_RSC:
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg,
					il.SubBorrow(get_register_size(op2.reg),
						ReadILOperand(il, op3, addr),
						ReadRegisterOrPointer(il, op2, addr),
						il.Not(1,il.Flag(IL_FLAG_C))),
						flagOperation[instr.setsFlags]));
			break;
		case ARMV7_ROR:
		case ARMV7_RORS:
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg,
					il.RotateRight(get_register_size(op1.reg),
						ReadRegisterOrPointer(il, op2, addr),
						il.And(1,
							ReadILOperand(il, op3, addr),
							il.Const(1, 0xff)
							),
						flagOperation[instr.setsFlags]
					)
				)
			);
			break;
		case ARMV7_RRX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4, il.Flag(IL_FLAG_C), il.Const(1,31)),
							il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1,1))
							)
						));
				});
			break;
		case ARMV7_SADD16: //TODO: APSR
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.And(2,
							il.Add(2,
								ReadILOperand(il, op2, addr),
								ReadILOperand(il, op3, addr)
							),
							il.Const(2, 0xffff)
						)));
					il.AddInstruction(
						il.SetRegister(4, LLIL_TEMP(1),
							il.And(2,
								il.Add(2,
									il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
									il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
								),
								il.Const(2, 0xffff)
							)));
					il.AddInstruction(
						il.SetRegister(4, op1.reg,
							il.Or(4,
								il.ShiftLeft(4,
									il.And(2,
										il.Register(4, LLIL_TEMP(1)), il.Const(2, 0xffff)
									),
									il.Const(1, 16)
								),
								il.And(2,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(2, 0xffff)
								)
							)
						));
				});
			break;
		case ARMV7_UADD16: //TODO: APSR
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.And(2,
							il.Add(2,
								ReadILOperand(il, op2, addr),
								ReadILOperand(il, op3, addr)
							),
							il.Const(2, 0xffff)
						)));
					il.AddInstruction(
						il.SetRegister(4, LLIL_TEMP(1),
							il.And(2,
								il.Add(2,
									il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
									il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
								),
								il.Const(2, 0xffff)
							)));
					il.AddInstruction(
						il.SetRegister(4, op1.reg,
							il.Or(4,
								il.ShiftLeft(4,
									il.And(2,
										il.Register(4, LLIL_TEMP(1)), il.Const(2, 0xffff)
									),
									il.Const(1, 16)
								),
								il.And(2,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(2, 0xffff)
								)
							)
						));
				});
			break;
		case ARMV7_SADD8: //TODO: APSR
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.And(1,
							il.Add(1,
								ReadILOperand(il, op2, addr),
								ReadILOperand(il, op3, addr)
							),
							il.Const(1, 0xff)
						)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(1),
							il.And(1,
								il.Add(1,
									il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 8)),
									il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 8))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(2),
							il.And(1,
								il.Add(1,
									il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
									il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(3),
							il.And(1,
								il.Add(1,
									il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 24)),
									il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 24))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(4, op1.reg,
							il.Or(4,
								il.Or(4,
									il.ShiftLeft(4,
										il.Register(1, LLIL_TEMP(3)),
										il.Const(1, 24)
									),
									il.ShiftLeft(3,
										il.Register(1, LLIL_TEMP(2)),
										il.Const(1, 16)
									)
								),
								il.Or(4,
									il.ShiftLeft(2,
										il.Register(1, LLIL_TEMP(1)),
										il.Const(1, 8)
									),
									il.Register(1, LLIL_TEMP(0))
								)
							)
						));
				});
			break;
		case ARMV7_UADD8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.And(1,
							il.Add(1,
								ReadILOperand(il, op2, addr),
								ReadILOperand(il, op3, addr)
							),
							il.Const(1, 0xff)
						)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(1),
							il.And(1,
								il.Add(1,
									il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 8)),
									il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 8))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(2),
							il.And(1,
								il.Add(1,
									il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
									il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(3),
							il.And(1,
								il.Add(1,
									il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 24)),
									il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 24))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(4, op1.reg,
							il.Or(4,
								il.Or(4,
									il.ShiftLeft(4,
										il.Register(1, LLIL_TEMP(3)),
										il.Const(1, 24)
									),
									il.ShiftLeft(3,
										il.Register(1, LLIL_TEMP(2)),
										il.Const(1, 16)
									)
								),
								il.Or(4,
									il.ShiftLeft(2,
										il.Register(1, LLIL_TEMP(1)),
										il.Const(1, 8)
									),
									il.Register(1, LLIL_TEMP(0))
								)
							)
						));
				});
			break;
		case ARMV7_SASX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.LowPart(2,
								ReadILOperand(il, op2, addr)
							),
							il.ArithShiftRight(2,
								ReadILOperand(il, op3, addr),
								il.Const(1,16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Add(4,
							il.ArithShiftRight(2,
								ReadILOperand(il, op2, addr),
								il.Const(1,16)
							),
							il.LowPart(2,
								ReadILOperand(il, op3, addr)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.Register(2, LLIL_TEMP(1)),
								il.Const(1, 16)
							),
							il.Register(2, LLIL_TEMP(0))
						)
					));
				});
			break;
		case ARMV7_UASX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.LowPart(2,
								ReadILOperand(il, op2, addr)
							),
							il.LogicalShiftRight(2,
								ReadILOperand(il, op3, addr),
								il.Const(1,16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Add(4,
							il.LogicalShiftRight(2,
								ReadILOperand(il, op2, addr),
								il.Const(1,16)
							),
							il.LowPart(2,
								ReadILOperand(il, op3, addr)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.Register(2, LLIL_TEMP(1)),
								il.Const(1, 16)
							),
							il.Register(2, LLIL_TEMP(0))
						)
					));
				});
			break;
		case ARMV7_SHASX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.LowPart(2,
								ReadILOperand(il, op2, addr)
							),
							il.ArithShiftRight(2,
								ReadILOperand(il, op3, addr),
								il.Const(1,16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Add(4,
							il.ArithShiftRight(2,
								ReadILOperand(il, op2, addr),
								il.Const(1,16)
							),
							il.LowPart(2,
								ReadILOperand(il, op3, addr)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.LowPart(2,
									il.ArithShiftRight(2,
										il.Register(4, LLIL_TEMP(1)),
										il.Const(1,1)
									)
								),
								il.Const(1, 16)
							),
							il.LowPart(2,
								il.ArithShiftRight(2,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(1, 1)
								)
							)
						)
					));
				});
			break;
		case ARMV7_UHASX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.LowPart(2,
								ReadILOperand(il, op2, addr)
							),
							il.LogicalShiftRight(2,
								ReadILOperand(il, op3, addr),
								il.Const(1,16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Add(4,
							il.LogicalShiftRight(2,
								ReadILOperand(il, op2, addr),
								il.Const(1,16)
							),
							il.LowPart(2,
								ReadILOperand(il, op3, addr)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.LowPart(2,
									il.LogicalShiftRight(2,
										il.Register(4, LLIL_TEMP(1)),
										il.Const(1,1)
									)
								),
								il.Const(1, 16)
							),
							il.LowPart(2,
								il.LogicalShiftRight(2,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(1, 1)
								)
							)
						)
					));
				});
			break;
		case ARMV7_SHSAX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Add(4,
							il.LowPart(2,
								ReadILOperand(il, op2, addr)
							),
							il.ArithShiftRight(2,
								ReadILOperand(il, op3, addr),
								il.Const(1,16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Sub(4,
							il.ArithShiftRight(2,
								ReadILOperand(il, op2, addr),
								il.Const(1,16)
							),
							il.LowPart(2,
								ReadILOperand(il, op3, addr)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.LowPart(2,
									il.ArithShiftRight(2,
										il.Register(4, LLIL_TEMP(1)),
										il.Const(1,1)
									)
								),
								il.Const(1, 16)
							),
							il.LowPart(2,
								il.ArithShiftRight(2,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(1, 1)
								)
							)
						)
					));
				});
			break;
		case ARMV7_UHSAX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Add(4,
							il.LowPart(2,
								ReadILOperand(il, op2, addr)
							),
							il.LogicalShiftRight(2,
								ReadILOperand(il, op3, addr),
								il.Const(1,16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Sub(4,
							il.LogicalShiftRight(2,
								ReadILOperand(il, op2, addr),
								il.Const(1,16)
							),
							il.LowPart(2,
								ReadILOperand(il, op3, addr)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.LowPart(2,
									il.LogicalShiftRight(2,
										il.Register(4, LLIL_TEMP(1)),
										il.Const(1,1)
									)
								),
								il.Const(1, 16)
							),
							il.LowPart(2,
								il.LogicalShiftRight(2,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(1, 1)
								)
							)
						)
					));
				});
			break;
		case ARMV7_SSAX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Add(4,
							il.LowPart(2,
								ReadILOperand(il, op2, addr)
							),
							il.ArithShiftRight(2,
								ReadILOperand(il, op3, addr),
								il.Const(1,16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Sub(4,
							il.ArithShiftRight(2,
								ReadILOperand(il, op2, addr),
								il.Const(1,16)
							),
							il.LowPart(2,
								ReadILOperand(il, op3, addr)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.Register(2, LLIL_TEMP(1)),
								il.Const(1, 16)
							),
							il.Register(2, LLIL_TEMP(0))
						)
					));
				});
			break;
		case ARMV7_UMAAL:
			/* op2:op1 = op4 * op3 + op2 + op1 */
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(
						il.SetRegisterSplit(4,
							op2.reg, /* hi result */
							op1.reg, /* lo result */
							il.Add(8,
								il.MultDoublePrecUnsigned(4,
									il.Register(4, op4.reg),
									il.Register(4, op3.reg)
								),
								il.Add(8,
									il.Register(4, op2.reg),
									il.Register(4, op1.reg)
								)
							)
						)
					);
				});
			break;
		case ARMV7_UMLAL:
			/* op2:op1 = op4 * op3 + op2:op1 */
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(
						il.SetRegisterSplit(4,
							op2.reg, /* hi result */
							op1.reg, /* lo result */
							il.Add(8,
								il.MultDoublePrecUnsigned(4,
									il.Register(4, op4.reg),
									il.Register(4, op3.reg)
								),
								il.RegisterSplit(
									4,
									op2.reg,
									op1.reg
								)
							),
							instr.setsFlags ? IL_FLAGWRITE_NZ : IL_FLAGWRITE_NONE
						)
					);
				});
			break;
		case ARMV7_SSUB16: //TODO: APSR
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.And(2,
							il.Sub(2,
								ReadILOperand(il, op2, addr),
								ReadILOperand(il, op3, addr)
							),
							il.Const(2, 0xffff)
						)));
					il.AddInstruction(
						il.SetRegister(4, LLIL_TEMP(1),
							il.And(2,
								il.Sub(2,
									il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
									il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
								),
								il.Const(2, 0xffff)
							)));
					il.AddInstruction(
						il.SetRegister(4, op1.reg,
							il.Or(4,
								il.ShiftLeft(4,
									il.And(2,
										il.Register(4, LLIL_TEMP(1)), il.Const(2, 0xffff)
									),
									il.Const(1, 16)
								),
								il.And(2,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(2, 0xffff)
								)
							)
						));
				});
			break;
		case ARMV7_USUB16: //TODO: APSR
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.And(2,
							il.Sub(2,
								ReadILOperand(il, op2, addr),
								ReadILOperand(il, op3, addr)
							),
							il.Const(2, 0xffff)
						)));
					il.AddInstruction(
						il.SetRegister(4, LLIL_TEMP(1),
							il.And(2,
								il.Sub(2,
									il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
									il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
								),
								il.Const(2, 0xffff)
							)));
					il.AddInstruction(
						il.SetRegister(4, op1.reg,
							il.Or(4,
								il.ShiftLeft(4,
									il.And(2,
										il.Register(4, LLIL_TEMP(1)), il.Const(2, 0xffff)
									),
									il.Const(1, 16)
								),
								il.And(2,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(2, 0xffff)
								)
							)
						));
				});
			break;
		case ARMV7_SSUB8: //TODO: APSR
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.And(1,
							il.Sub(1,
								ReadILOperand(il, op2, addr),
								ReadILOperand(il, op3, addr)
							),
							il.Const(1, 0xff)
						)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(1),
							il.And(1,
								il.Sub(1,
									il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 8)),
									il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 8))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(2),
							il.And(1,
								il.Sub(1,
									il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
									il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(3),
							il.And(1,
								il.Sub(1,
									il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 24)),
									il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 24))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(4, op1.reg,
							il.Or(4,
								il.Or(4,
									il.ShiftLeft(4,
										il.Register(1, LLIL_TEMP(3)),
										il.Const(1, 24)
									),
									il.ShiftLeft(4,
										il.Register(1, LLIL_TEMP(2)),
										il.Const(1, 16)
									)
								),
								il.Or(4,
									il.ShiftLeft(4,
										il.Register(1, LLIL_TEMP(1)),
										il.Const(1, 8)
									),
									il.Register(1, LLIL_TEMP(0))
								)
							)
						));
				});
			break;
		case ARMV7_USUB8: //TODO: APSR
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.And(1,
							il.Sub(1,
								ReadILOperand(il, op2, addr),
								ReadILOperand(il, op3, addr)
							),
							il.Const(1, 0xff)
						)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(1),
							il.And(1,
								il.Sub(1,
									il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 8)),
									il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 8))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(2),
							il.And(1,
								il.Sub(1,
									il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
									il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(1, LLIL_TEMP(3),
							il.And(1,
								il.Sub(1,
									il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 24)),
									il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 24))
								),
								il.Const(1, 0xff)
							)));
					il.AddInstruction(
						il.SetRegister(4, op1.reg,
							il.Or(4,
								il.Or(4,
									il.ShiftLeft(4,
										il.Register(1, LLIL_TEMP(3)),
										il.Const(1, 24)
									),
									il.ShiftLeft(4,
										il.Register(1, LLIL_TEMP(2)),
										il.Const(1, 16)
									)
								),
								il.Or(4,
									il.ShiftLeft(4,
										il.Register(1, LLIL_TEMP(1)),
										il.Const(1, 8)
									),
									il.Register(1, LLIL_TEMP(0))
								)
							)
						));
				});
			break;
		case ARMV7_SBC:
		case ARMV7_SBCS:
			ConditionExecute(il, instr.cond,
					SetRegisterOrBranch(il, op1.reg,
						il.SubBorrow(get_register_size(op2.reg),
							ReadILOperand(il, op2, addr),
							ReadRegisterOrPointer(il, op3, addr),
							il.Not(1,il.Flag(IL_FLAG_C))),
							flagOperation[instr.setsFlags]));
			break;
		case ARMV7_SBFX:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.ArithShiftRight(get_register_size(op1.reg),
					il.ShiftLeft(get_register_size(op2.reg),
						ReadILOperand(il, op2, addr),
						il.Const(1, (get_register_size(op2.reg) * 8) - op3.imm - op4.imm)),
					il.Const(1, (get_register_size(op2.reg) * 8) - op4.imm))));
			break;
		case ARMV7_SDIV:
			if (op3.cls == NONE)
				ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
					il.DivSigned(get_register_size(op1.reg), ReadRegisterOrPointer(il, op1, addr), ReadRegisterOrPointer(il, op2, addr))));
			else
				ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
					il.DivSigned(get_register_size(op2.reg), ReadRegisterOrPointer(il, op2, addr), ReadRegisterOrPointer(il, op3, addr))));
			break;
		case ARMV7_SHADD16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Add(4,
							il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
							il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Add(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4, il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(0)), il.Const(1,1)), il.Const(1,16)),
							il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(1,1))
						)
					));
				});
			break;
		case ARMV7_UHADD16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Add(4,
							il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
							il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Add(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4, il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(0)), il.Const(1,1)), il.Const(1,16)),
							il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(1,1))
						)
					));
				});
			break;
		case ARMV7_SHADD8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Add(4,
							il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 24)),
							il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 24))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Add(4,
							il.LowPart(1, il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16))),
							il.LowPart(1, il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16)))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(2),
						il.Add(4,
							il.LowPart(1, il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 8))),
							il.LowPart(1, il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 8)))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(3),
						il.Add(4,
							il.LowPart(1, ReadILOperand(il, op2, addr)),
							il.LowPart(1, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.Or(4,
								il.ShiftLeft(4, il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(0)), il.Const(1,1)), il.Const(1,24)),
								il.ShiftLeft(4, il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(1,1)), il.Const(1,16))
							),
							il.Or(4,
								il.ShiftLeft(4, il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(2)), il.Const(1,1)), il.Const(1,8)),
								il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(3)), il.Const(1,1))
							)
						)
					));
				});
			break;
		case ARMV7_UHADD8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Add(4,
							il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 24)),
							il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 24))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Add(4,
							il.LowPart(1, il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16))),
							il.LowPart(1, il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16)))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(2),
						il.Add(4,
							il.LowPart(1, il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 8))),
							il.LowPart(1, il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 8)))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(3),
						il.Add(4,
							il.LowPart(1, ReadILOperand(il, op2, addr)),
							il.LowPart(1, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.Or(4,
								il.ShiftLeft(4, il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(0)), il.Const(1,1)), il.Const(1,24)),
								il.ShiftLeft(4, il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(1,1)), il.Const(1,16))
							),
							il.Or(4,
								il.ShiftLeft(4, il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(2)), il.Const(1,1)), il.Const(1,8)),
								il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(3)), il.Const(1,1))
							)
						)
					));
				});
			break;
		case ARMV7_SHSUB16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
							il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Sub(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4, il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(0)), il.Const(1,1)), il.Const(1,16)),
							il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(1,1))
						)
					));
				});
			break;
		case ARMV7_UHSUB16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
							il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Sub(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4, il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(0)), il.Const(1,1)), il.Const(1,16)),
							il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(1,1))
						)
					));
				});
			break;
		case ARMV7_SHSUB8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 24)),
							il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 24))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Sub(4,
							il.LowPart(1, il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16))),
							il.LowPart(1, il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16)))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(2),
						il.Sub(4,
							il.LowPart(1, il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 8))),
							il.LowPart(1, il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 8)))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(3),
						il.Sub(4,
							il.LowPart(1, ReadILOperand(il, op2, addr)),
							il.LowPart(1, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.Or(4,
								il.ShiftLeft(4, il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(0)), il.Const(1,1)), il.Const(1,24)),
								il.ShiftLeft(4, il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(1,1)), il.Const(1,16))
							),
							il.Or(4,
								il.ShiftLeft(4, il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(2)), il.Const(1,1)), il.Const(1,8)),
								il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(3)), il.Const(1,1))
							)
						)
					));
				});
			break;
		case ARMV7_UHSUB8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 24)),
							il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 24))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Sub(4,
							il.LowPart(1, il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16))),
							il.LowPart(1, il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16)))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(2),
						il.Sub(4,
							il.LowPart(1, il.LogicalShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 8))),
							il.LowPart(1, il.LogicalShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 8)))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(3),
						il.Sub(4,
							il.LowPart(1, ReadILOperand(il, op2, addr)),
							il.LowPart(1, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.Or(4,
								il.ShiftLeft(4, il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(0)), il.Const(1,1)), il.Const(1,24)),
								il.ShiftLeft(4, il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(1,1)), il.Const(1,16))
							),
							il.Or(4,
								il.ShiftLeft(4, il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(2)), il.Const(1,1)), il.Const(1,8)),
								il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(3)), il.Const(1,1))
							)
						)
					));
				});
			break;
		case ARMV7_SMLABB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.Mult(4,
								il.LowPart(2, ReadILOperand(il, op2, addr)),
								il.LowPart(2, ReadILOperand(il, op3, addr))
							),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMLABT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.Mult(4,
								il.LowPart(2, ReadILOperand(il, op2, addr)),
								il.LowPart(2, il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16)))
							),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMLATB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.Mult(4,
								il.LowPart(2, il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16))),
								il.LowPart(2, ReadILOperand(il, op3, addr))
							),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMLATT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.Mult(4,
								il.LowPart(2, il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16))),
								il.LowPart(2, il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16)))
							),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMLAD:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.ArithShiftRight(2, ReadILOperand(il, op2, addr), il.Const(1,16)),
							il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1,16))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							ReadILOperand(il, op4, addr),
							il.Add(4,
								il.Register(4, LLIL_TEMP(0)),
								il.Register(4, LLIL_TEMP(1))
							)
						)
					));
				});
			break;
		case ARMV7_SMLADX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1,16))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.ArithShiftRight(2, ReadILOperand(il, op2, addr), il.Const(1,16)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							ReadILOperand(il, op4, addr),
							il.Add(4,
								il.Register(4, LLIL_TEMP(0)),
								il.Register(4, LLIL_TEMP(1))
							)
						)
					));
				});
			break;
		case ARMV7_SMLAL:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0), il.Mult(8, ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr))));
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1),
								il.Add(8,
									il.Or(8,
										il.ShiftLeft(8,
											ReadILOperand(il, op2, addr),
											il.Const(1, 32)
											),
										ReadILOperand(il, op1, addr)
									),
									il.Register(8, LLIL_TEMP(0))
								)
							));
					il.AddInstruction(il.SetRegister(4, op2.reg,
						il.ArithShiftRight(4,
							il.Register(8, LLIL_TEMP(1)),
							il.Const(1, 32)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.LowPart(4,
							il.Register(8, LLIL_TEMP(1))
						),
						flagOperation[instr.setsFlags])
					);
				});
			break;
		case ARMV7_SMLALBB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.Add(8,
							il.SignExtend(8,
								il.Mult(4,
									il.LowPart(2, ReadILOperand(il, op2, addr)),
									il.LowPart(2, ReadILOperand(il, op3, addr))
								)
							),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMLALBT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.Add(8,
							il.SignExtend(8,
								il.Mult(4,
									il.LowPart(2, ReadILOperand(il, op2, addr)),
									il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1, 16))
								)
							),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMLALTB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.Add(8,
							il.SignExtend(8,
								il.Mult(4,
									il.ArithShiftRight(2, ReadILOperand(il, op2, addr), il.Const(1, 16)),
									il.LowPart(2, ReadILOperand(il, op3, addr))
								)
							),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMLALTT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.Add(8,
							il.SignExtend(8,
								il.Mult(4,
									il.ArithShiftRight(2, ReadILOperand(il, op2, addr), il.Const(1, 16)),
									il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1, 16))
								)
							),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMLALD:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op3, addr)),
							il.LowPart(2, ReadILOperand(il, op4, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1,16)),
							il.ArithShiftRight(2, ReadILOperand(il, op4, addr), il.Const(1,16))
						)
					));
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(2),
						il.Add(8,
							il.Or(8,
								il.ShiftLeft(8,
									ReadILOperand(il, op2, addr),
									il.Const(1, 32)
								),
								ReadILOperand(il, op1, addr)
							),
							il.Add(4,
								il.Register(4, LLIL_TEMP(0)),
								il.Register(4, LLIL_TEMP(1))
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.LowPart(4,
							il.Register(8, LLIL_TEMP(2))
						)
					));
					il.AddInstruction(il.SetRegister(4, op2.reg,
						il.ArithShiftRight(4,
							il.Register(8, LLIL_TEMP(2)),
							il.Const(1, 32)
						)
					));
				});
			break;
		case ARMV7_SMLALDX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op3, addr)),
							il.ArithShiftRight(2, ReadILOperand(il, op4, addr), il.Const(1,16))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1,16)),
							il.LowPart(2, ReadILOperand(il, op4, addr))
						)
					));
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(2),
						il.Add(8,
							il.Or(8,
								il.ShiftLeft(8,
									ReadILOperand(il, op2, addr),
									il.Const(1, 32)
								),
								ReadILOperand(il, op1, addr)
							),
							il.Add(4,
								il.Register(4, LLIL_TEMP(0)),
								il.Register(4, LLIL_TEMP(1))
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.LowPart(4,
							il.Register(8, LLIL_TEMP(2))
						)
					));
					il.AddInstruction(il.SetRegister(4, op2.reg,
						il.ArithShiftRight(4,
							il.Register(8, LLIL_TEMP(2)),
							il.Const(1, 32)
						)
					));
				});
			break;
		case ARMV7_SMLAWB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.Add(8,
							il.Mult(8,
								ReadILOperand(il, op2, addr),
								il.LowPart(2, ReadILOperand(il, op3, addr))
							),
							il.ShiftLeft(8,
								ReadILOperand(il, op4, addr),
								il.Const(1, 16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.And(4,
							il.ArithShiftRight(8,
								il.Register(8, LLIL_TEMP(0)),
								il.Const(1, 16)
							),
							il.Const(4, 0xffffffff)
						)
					));
				});
			break;
		case ARMV7_SMLAWT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.Add(8,
							il.Mult(8,
								ReadILOperand(il, op2, addr),
								il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1, 16))
							),
							il.ShiftLeft(8,
								ReadILOperand(il, op4, addr),
								il.Const(1, 16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.And(4,
							il.ArithShiftRight(8,
								il.Register(8, LLIL_TEMP(0)),
								il.Const(1, 16)
							),
							il.Const(4, 0xffffffff)
						)
					));
				});
			break;
		case ARMV7_SMLSD:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
							il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.Sub(4,
								il.Register(4, LLIL_TEMP(1)),
								il.Register(4, LLIL_TEMP(0))
							),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMLSDX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.Sub(4,
								il.Register(4, LLIL_TEMP(1)),
								il.Register(4, LLIL_TEMP(0))
							),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMLSLD:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op3, addr)),
							il.LowPart(2, ReadILOperand(il, op4, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1,16)),
							il.ArithShiftRight(2, ReadILOperand(il, op4, addr), il.Const(1,16))
						)
					));
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(2),
						il.Add(8,
							il.Or(8,
								il.ShiftLeft(8,
									ReadILOperand(il, op2, addr),
									il.Const(1, 32)
								),
								ReadILOperand(il, op1, addr)
							),
							il.Sub(4,
								il.Register(4, LLIL_TEMP(0)),
								il.Register(4, LLIL_TEMP(1))
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.LowPart(4,
							il.Register(8, LLIL_TEMP(2))
						)
					));
					il.AddInstruction(il.SetRegister(4, op2.reg,
						il.ArithShiftRight(4,
							il.Register(8, LLIL_TEMP(2)),
							il.Const(1, 32)
						)
					));
				});
			break;
		case ARMV7_SMLSLDX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op3, addr)),
							il.ArithShiftRight(2, ReadILOperand(il, op4, addr), il.Const(1,16))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1,16)),
							il.LowPart(2, ReadILOperand(il, op4, addr))
						)
					));
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(2),
						il.Add(8,
							il.Or(8,
								il.ShiftLeft(8,
									ReadILOperand(il, op2, addr),
									il.Const(1, 32)
								),
								ReadILOperand(il, op1, addr)
							),
							il.Sub(4,
								il.Register(4, LLIL_TEMP(0)),
								il.Register(4, LLIL_TEMP(1))
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.LowPart(4,
							il.Register(8, LLIL_TEMP(2))
						)
					));
					il.AddInstruction(il.SetRegister(4, op2.reg,
						il.ArithShiftRight(4,
							il.Register(8, LLIL_TEMP(2)),
							il.Const(1, 32)
						)
					));
				});
			break;
		case ARMV7_SMMLA:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.ArithShiftRight(8, il.Mult(8, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr)), il.Const(1, 32))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.Register(4, LLIL_TEMP(0)),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMMLAR:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0), il.Add(8, il.Mult(8, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr)), il.Const(8, 0x80000000))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.ArithShiftRight(4,
								il.Register(8, LLIL_TEMP(0)),
								il.Const(1, 32)
								),
							ReadILOperand(il, op4, addr)
						)
					));
				});
			break;
		case ARMV7_SMMLS:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0), il.Mult(8, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr))));
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1), il.ShiftLeft(8, ReadILOperand(il, op4, addr), il.Const(1, 32))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.ArithShiftRight(4,
							il.Sub(8,
								il.Register(8, LLIL_TEMP(1)),
								il.Register(8, LLIL_TEMP(0))
							),
							il.Const(1, 32)
						)
					));
				});
			break;
		case ARMV7_SMMLSR:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0), il.Mult(8, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr))));
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1), il.ShiftLeft(8, ReadILOperand(il, op4, addr), il.Const(1, 32))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.ArithShiftRight(4,
							il.Add(8,
								il.Sub(8,
									il.Register(8, LLIL_TEMP(1)),
									il.Register(8, LLIL_TEMP(0))
								),
								il.Const(8, 0x80000000)
							),
							il.Const(1, 32)
						)
					));
				});
			break;
		case ARMV7_SMUAD:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
							il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.Register(4, LLIL_TEMP(1)),
							il.Register(4, LLIL_TEMP(0))
						)
					));
				});
			break;
		case ARMV7_SMUADX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.Register(4, LLIL_TEMP(1)),
							il.Register(4, LLIL_TEMP(0))
						)
					));
				});
			break;
		case ARMV7_SMMUL:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0), il.Mult(8, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr))));
					il.AddInstruction(il.SetRegister(4, op1.reg, il.ArithShiftRight(4, il.Register(8, LLIL_TEMP(0)), il.Const(1, 32))));
				});
			break;
		case ARMV7_SMMULR:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0), il.Add(8, il.Mult(8, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr)), il.Const(4, 0x80000000))));
					il.AddInstruction(il.SetRegister(4, op1.reg, il.ArithShiftRight(4, il.Register(8, LLIL_TEMP(0)), il.Const(1, 32))));
				});
			break;
		case ARMV7_UMULL:
		case ARMV7_SMULL:
			/* op2:op1 = op3 * op4 */
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					ExprId product;
					if (instr.operation == ARMV7_UMULL)
						product = il.MultDoublePrecUnsigned(get_register_size(op3.reg), ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr));
					else
						product = il.MultDoublePrecSigned(get_register_size(op3.reg), ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr));

					il.AddInstruction(
						il.SetRegisterSplit(get_register_size(op1.reg),
							op2.reg,
							op1.reg,
							product
						)
					);
				});
			break;
		case ARMV7_SMULBB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Mult(4,
								il.LowPart(2, ReadILOperand(il, op2, addr)),
								il.LowPart(2, ReadILOperand(il, op3, addr))
							)
						)
					);
				});
			break;
		case ARMV7_SMULBT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Mult(4,
								il.LowPart(2, ReadILOperand(il, op2, addr)),
								il.LowPart(2, il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16)))
							)
						)
					);
				});
			break;
		case ARMV7_SMULTB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Mult(4,
								il.LowPart(2, il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16))),
								il.LowPart(2, ReadILOperand(il, op3, addr))
							)
						)
					);
				});
			break;
		case ARMV7_SMULTT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Mult(4,
								il.LowPart(2, il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16))),
								il.LowPart(2, il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16)))
							)
						)
					);
				});
			break;
		case ARMV7_SMULWB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Mult(4,
							ReadILOperand(il, op2, addr),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
				});
			break;
		case ARMV7_SMULWT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Mult(4,
							ReadILOperand(il, op2, addr),
							il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1,16))
						)
					));
				});
			break;
		case ARMV7_SMUSD:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
							il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Sub(4,
							il.Register(4, LLIL_TEMP(1)),
							il.Register(4, LLIL_TEMP(0))
						)
					));
				});
			break;
		case ARMV7_SMUSDX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Mult(4,
							il.ArithShiftRight(4, ReadILOperand(il, op2, addr), il.Const(1, 16)),
							il.LowPart(2, ReadILOperand(il, op3, addr))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Mult(4,
							il.LowPart(2, ReadILOperand(il, op2, addr)),
							il.ArithShiftRight(4, ReadILOperand(il, op3, addr), il.Const(1, 16))
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Sub(4,
							il.Register(4, LLIL_TEMP(1)),
							il.Register(4, LLIL_TEMP(0))
						)
					));
				});
			break;
		case ARMV7_SSAT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.ShiftLeft(4,
								il.Const(1, 2),
								ReadILOperand(il, op2, addr)
							),
							il.Const(1,1)
						)
					));

					Saturate(il, op1.reg, ReadILOperand(il, op3, addr), il.Register(4, LLIL_TEMP(0)), true);
				});
			break;
		case ARMV7_SSAT16:
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0),
					il.Sub(2,
						il.ShiftLeft(2,
							il.Const(1, 2),
							ReadILOperand(il, op2, addr)
						),
						il.Const(1, 1)
					)
				));

				Saturate(il, LLIL_TEMP(1), il.LowPart(2, ReadILOperand(il, op3, addr)), il.Register(4, LLIL_TEMP(0)), true);
				Saturate(il, LLIL_TEMP(2), il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1, 16)), il.Register(4, LLIL_TEMP(0)), true);

				il.AddInstruction(il.SetRegister(4, op1.reg,
					il.Or(4,
						il.ZeroExtend(4,
							il.ShiftLeft(4,
								il.Register(2, LLIL_TEMP(2)),
								il.Const(1, 16)
							)
						),
						il.ZeroExtend(2, il.Register(2, LLIL_TEMP(1)))
					)
				));
			});
			break;
		case ARMV7_STMDA:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					uint32_t lowestSetBit = 1337;
					uint32_t numToLoad = 0;
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
						{
							numToLoad++;
							if (j < lowestSetBit)
								lowestSetBit = j;
						}
					}
					//Set base address
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							ReadRegisterOrPointer(il, op1, addr),
							il.Const(4, (4*numToLoad) - 4)
						)
					));
					//Check only the first 15 bits, 16th bit is PC which is handled at the bottom
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
						{
							if (j == op1.reg && op1.flags.wb == 1 && j != lowestSetBit)
							{
								il.AddInstruction(
									il.Store(4,
										il.Register(4, LLIL_TEMP(0)),
										il.Unimplemented()
									)
								);
							}
							else
							{
								il.AddInstruction(
									il.Store(4,
										il.Register(4, LLIL_TEMP(0)),
										il.Register(get_register_size((enum Register)j), j)
									)
								);
							}
							il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
								il.Add(4,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(1, 4)
								)
							));
						}
					}
					// Check if PC is stored
					if (((op2.reg >> 15) & 1) == 1)
					{
						il.AddInstruction(
							il.Store(4,
								il.Register(4, LLIL_TEMP(0)),
								il.Register(4, REG_PC)
							)
						);
					}
					// Check for writeback
					if (op1.flags.wb == 1)
					{
						il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Sub(4,
								ReadRegisterOrPointer(il, op1, addr),
								il.Const(4, 4*numToLoad)
							)
						));
					}
				});
			break;
		case ARMV7_STMDB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					uint32_t lowestSetBit = 1337;
					uint32_t numToLoad = 0;
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
						{
							numToLoad++;
							if (j < lowestSetBit)
								lowestSetBit = j;
						}
					}
					//Set base address
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							ReadRegisterOrPointer(il, op1, addr),
							il.Const(4, 4*numToLoad)
						)
					));
					//Check only the first 15 bits, 16th bit is PC which is handled at the bottom
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
						{
							if (j == op1.reg && op1.flags.wb == 1 && j != lowestSetBit)
							{
								il.AddInstruction(
									il.Store(4,
										il.Register(4, LLIL_TEMP(0)),
										il.Unimplemented()
									)
								);
							}
							else
							{
								il.AddInstruction(
									il.Store(4,
										il.Register(4, LLIL_TEMP(0)),
										il.Register(get_register_size((enum Register)j), j)
									)
								);
							}
							il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
								il.Add(4,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(1, 4)
								)
							));
						}
					}
					// Check if PC is stored
					if (((op2.reg >> 15) & 1) == 1)
					{
						il.AddInstruction(
							il.Store(4,
								il.Register(4, LLIL_TEMP(0)),
								il.Register(4, REG_PC)
							)
						);
					}
					// Check for writeback
					if (op1.flags.wb == 1)
					{
						il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Sub(4,
								ReadRegisterOrPointer(il, op1, addr),
								il.Const(4, 4*numToLoad)
							)
						));
					}
				});
			break;
		case ARMV7_STMIB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					uint32_t lowestSetBit = 1337;
					uint32_t numToLoad = 0;
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
						{
							numToLoad++;
							if (j < lowestSetBit)
								lowestSetBit = j;
						}
					}
					//Set base address
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Add(4,
							ReadRegisterOrPointer(il, op1, addr),
							il.Const(1, 4)
						)
					));
					//Check only the first 15 bits, 16th bit is PC which is handled at the bottom
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
						{
							if (j == op1.reg && op1.flags.wb == 1 && j != lowestSetBit)
							{
								il.AddInstruction(
									il.Store(4,
										il.Register(4, LLIL_TEMP(0)),
										il.Unimplemented()
									)
								);
							}
							else
							{
								il.AddInstruction(
									il.Store(4,
										il.Register(4, LLIL_TEMP(0)),
										il.Register(get_register_size((enum Register)j), j)
									)
								);
							}
							il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
								il.Add(4,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(1, 4)
								)
							));
						}
					}
					// Check if PC is stored
					if (((op2.reg >> 15) & 1) == 1)
					{
						il.AddInstruction(
							il.Store(4,
								il.Register(4, LLIL_TEMP(0)),
								il.Register(4, REG_PC)
							)
						);
					}
					// Check for writeback
					if (op1.flags.wb == 1)
					{
						il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Add(4,
								ReadRegisterOrPointer(il, op1, addr),
								il.Const(4, 4*numToLoad)
							)
						));
					}
				});
			break;
		case ARMV7_STM:
		case ARMV7_STMIA:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					uint32_t lowestSetBit = 1337;
					uint32_t numToLoad = 0;
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
						{
							numToLoad++;
							if (j < lowestSetBit)
								lowestSetBit = j;
						}
					}
					//Set base address
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						ReadRegisterOrPointer(il, op1, addr)
					));
					//Check only the first 15 bits, 16th bit is PC which is handled at the bottom
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
						{
							if (j == op1.reg && op1.flags.wb == 1 && j != lowestSetBit)
							{
								il.AddInstruction(
									il.Store(4,
										il.Register(4, LLIL_TEMP(0)),
										il.Unimplemented()
									)
								);
							}
							else
							{
								il.AddInstruction(
									il.Store(4,
										il.Register(4, LLIL_TEMP(0)),
										il.Register(get_register_size((enum Register)j), j)
									)
								);
							}
							il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
								il.Add(4,
									il.Register(4, LLIL_TEMP(0)),
									il.Const(1, 4)
								)
							));
						}
					}
					// Check if PC is stored
					if (((op2.reg >> 15) & 1) == 1)
					{
						il.AddInstruction(
							il.Store(4,
								il.Register(4, LLIL_TEMP(0)),
								il.Register(4, REG_PC)
							)
						);
					}
					// Check for writeback
					if (op1.flags.wb == 1)
					{
						il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Add(4,
								ReadRegisterOrPointer(il, op1, addr),
								il.Const(4, 4*numToLoad)
							)
						));
					}
				});
			break;
		case ARMV7_STREX:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						StoreExclusive(il, 4, op1, op2, op3, addr);
					});
			break;
		case ARMV7_STREXH:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						StoreExclusive(il, 2, op1, op2, op3, addr);
					});
			break;
		case ARMV7_STREXB:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						StoreExclusive(il, 1, op1, op2, op3, addr);
					});
			break;
		case ARMV7_STR:
		case ARMV7_STRT:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						Store(il, 4, op1, op2, addr);
					});
			break;
		case ARMV7_STRH:
		case ARMV7_STRHT:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						Store(il, 2, op1, op2, addr);
					});
			break;
		case ARMV7_STRB:
		case ARMV7_STRBT:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						Store(il, 1, op1, op2, addr);
					});
			break;
		case ARMV7_STREXD:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						StorePairExclusive(arch, il, op1, op2, op3, op4, addr);
					});
			break;
		case ARMV7_STRD:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						StorePair(arch, il, op1, op2, op3, addr);
					});
			break;
		case ARMV7_SUB:
			ConditionExecute(il, instr.cond,
					SetRegisterOrBranch(il, op1.reg,
						il.Sub(get_register_size(op2.reg),
							ReadRegisterOrPointer(il, op2, addr),
							ReadILOperand(il, op3, addr), flagOperation[instr.setsFlags])));
			break;
		case ARMV7_SVC:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;

						il.AddInstruction(il.SetRegister(4, FAKEREG_SYSCALL_INFO, il.Const(4, op1.imm)));
						il.AddInstruction(il.SystemCall());
					});
			break;
		case ARMV7_SWP:
			if (op1.reg == op2.reg)
			{
				ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;

						il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
							il.Load(get_register_size(op1.reg),
								ReadRegisterOrPointer(il, op3, addr)
							)
						));
						il.AddInstruction(il.Store(get_register_size(op1.reg),
							ReadRegisterOrPointer(il, op3, addr),
							ReadRegisterOrPointer(il, op2, addr)
						));
						il.AddInstruction(SetRegisterOrBranch(il, op1.reg,
							il.Register(4, LLIL_TEMP(0))
						));
					});
			}
			else
			{
				ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;

						il.AddInstruction(SetRegisterOrBranch(il, op1.reg,
							il.Load(get_register_size(op1.reg),
								ReadRegisterOrPointer(il, op3, addr)
							)
						));
						il.AddInstruction(il.Store(get_register_size(op1.reg),
							ReadRegisterOrPointer(il, op3, addr),
							ReadRegisterOrPointer(il, op2, addr)
						));
					});
			}
			break;
		case ARMV7_SWPB:
			if (op1.reg == op2.reg)
			{
				ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;

						il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0),
							il.Load(1,
								ReadRegisterOrPointer(il, op3, addr)
							)
						));
						il.AddInstruction(il.Store(1,
							ReadRegisterOrPointer(il, op3, addr),
							il.And(1,
								ReadRegisterOrPointer(il, op2, addr),
								il.Const(1, 0xff)
							)
						));
						il.AddInstruction(SetRegisterOrBranch(il, op1.reg,
							il.ZeroExtend(4, il.Register(1, LLIL_TEMP(0)))
						));
					});
			}
			else
			{
				ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;

						il.AddInstruction(SetRegisterOrBranch(il, op1.reg,
							il.ZeroExtend(4,
								il.Load(1,
									ReadRegisterOrPointer(il, op3, addr)
								)
							)
						));
						il.AddInstruction(il.Store(1,
							ReadRegisterOrPointer(il, op3, addr),
							il.And(1,
								ReadRegisterOrPointer(il, op2, addr),
								il.Const(1, 0xff)
							)
						));
					});
			}
			break;
		case ARMV7_SXTAB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						ReadILOperand(il, op3, addr)
					));

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							ReadILOperand(il, op2, addr),
							il.SignExtend(4,
								il.Register(1, LLIL_TEMP(0))
							)
						)
					));
				});
			break;
		case ARMV7_SXTAB16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						ReadILOperand(il, op3, addr)
					));

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.Add(2,
									il.LowPart(2,
										ReadILOperand(il, op2, addr)
									),
									il.SignExtend(2,
										il.LowPart(1,
											il.ArithShiftRight(4,
												il.Register(4, LLIL_TEMP(0)),
												il.Const(1, 16)
											)
										)
									)
								),
								il.Const(1, 16)
							),
							il.Add(2,
								il.LowPart(2,
									ReadILOperand(il, op2, addr)
								),
								il.SignExtend(2,
									il.Register(1, LLIL_TEMP(0))
								)
							)
						)
					));
				});
			break;
		case ARMV7_SXTAH:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							ReadILOperand(il, op2, addr),
							il.SignExtend(4,
								il.LowPart(2, ReadILOperand(il, op3, addr))
							)
						)
					));
				});
			break;
		case ARMV7_SXTB:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.ArithShiftRight(get_register_size(op1.reg),
					il.ShiftLeft(get_register_size(op1.reg), ReadRegisterOrPointer(il, op2, addr), il.Const(get_register_size(op1.reg), get_register_size(op1.reg)-8)),
					il.Const(get_register_size(op1.reg), (get_register_size(op1.reg)*8)-8))));
			break;
		case ARMV7_SXTB16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						ReadILOperand(il, op2, addr)
					));

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.SignExtend(2,
									il.LowPart(1,
										il.ArithShiftRight(4,
											il.Register(4, LLIL_TEMP(0)),
											il.Const(1, 16)
										)
									)
								),
								il.Const(1, 16)
							),
							il.SignExtend(2,
								il.Register(1, LLIL_TEMP(0))
							)
						)
					));
				});
			break;
		case ARMV7_SXTH:
		{
			ExprId source = il.Register(4, op2.reg);

			if (op2.shift == SHIFT_ROR && op2.imm)
				source = il.RotateRight(4, source, il.Const(1, op2.imm));

			ConditionExecute(il, instr.cond,
				il.SetRegister(4,
					op1.reg,
					il.SignExtend(4,
						il.LowPart(2,
							source
						)
					)
				)
			);

			break;
		}

		/*case ARMV7_SXTW:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
						il.ArithShiftRight(get_register_size(op1.reg),
							il.ShiftLeft(get_register_size(op1.reg), ReadRegisterOrPointer(il, op2, addr), il.Const(get_register_size(op1.reg), get_register_size(op1.reg)-16)),
							il.Const(get_register_size(op1.reg), (get_register_size(op1.reg)*8)-16))));
			break;
			*/
		case ARMV7_TEQ:
			ConditionExecute(il, instr.cond, il.Xor(get_register_size(op1.reg),
				ReadRegisterOrPointer(il, op1, addr),
				ReadILOperand(il, op2, addr), IL_FLAGWRITE_CNZ));
			break;
		case ARMV7_TST:
			ConditionExecute(il, instr.cond, il.And(get_register_size(op1.reg),
				ReadRegisterOrPointer(il, op1, addr),
				ReadILOperand(il, op2, addr), IL_FLAGWRITE_ALL));
			break;
		case ARMV7_UBFX:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.And(get_register_size(op1.reg),
					il.LogicalShiftRight(get_register_size(op2.reg), ReadILOperand(il, op2, addr), il.Const(1, op3.imm)),
					il.Const(get_register_size(op2.reg), BITMASK(op4.imm, 0)))));
			break;
		case ARMV7_USAD8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					for (int i = 0; i < 4; i++)
					{
						il.AddInstruction(il.SetRegister(4, LLIL_TEMP(i),
							il.Sub(4,
								il.LowPart(1,
									il.ArithShiftRight(4,
										ReadILOperand(il, op2, addr),
										il.Const(1, i*8)
									)
								),
								il.LowPart(1,
									il.ArithShiftRight(4,
										ReadILOperand(il, op3, addr),
										il.Const(1, i*8)
									)
								)
							)
						));
						il.AddInstruction(il.SetRegister(4, LLIL_TEMP(i),
							il.Sub(4,
								il.Xor(4,
									il.Register(4, LLIL_TEMP(i)),
									il.ArithShiftRight(4,
										il.Register(4, LLIL_TEMP(i)),
										il.Const(1, 31)
									)
								),
								il.ArithShiftRight(4,
									il.Register(4, LLIL_TEMP(i)),
									il.Const(1, 31)
								)
							)
						));
					}
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.LowPart(4,
							il.Add(4,
								il.Add(4,
									il.Register(4, LLIL_TEMP(0)),
									il.Register(4, LLIL_TEMP(1))
								),
								il.Add(4,
									il.Register(4, LLIL_TEMP(2)),
									il.Register(4, LLIL_TEMP(3))
								)
							)
						)
					));
				});
			break;
		case ARMV7_USADA8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					for (int i = 0; i < 4; i++)
					{
						il.AddInstruction(il.SetRegister(4, LLIL_TEMP(i),
							il.Sub(4,
								il.LowPart(1,
									il.ArithShiftRight(4,
										ReadILOperand(il, op2, addr),
										il.Const(1, i*8)
									)
								),
								il.LowPart(1,
									il.ArithShiftRight(4,
										ReadILOperand(il, op3, addr),
										il.Const(1, i*8)
									)
								)
							)
						));
						il.AddInstruction(il.SetRegister(4, LLIL_TEMP(i),
							il.Sub(4,
								il.Xor(4,
									il.Register(4, LLIL_TEMP(i)),
									il.ArithShiftRight(4,
										il.Register(4, LLIL_TEMP(i)),
										il.Const(1, 31)
									)
								),
								il.ArithShiftRight(4,
									il.Register(4, LLIL_TEMP(i)),
									il.Const(1, 31)
								)
							)
						));
					}
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.LowPart(4,
							il.Add(4,
								ReadILOperand(il, op4, addr),
								il.Add(4,
									il.Add(4,
										il.Register(4, LLIL_TEMP(0)),
										il.Register(4, LLIL_TEMP(1))
									),
									il.Add(4,
										il.Register(4, LLIL_TEMP(2)),
										il.Register(4, LLIL_TEMP(3))
									)
								)
							)
						)
					));
				});
			break;
		case ARMV7_USAT:
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
					il.Sub(4,
						il.ShiftLeft(4,
							il.Const(1, 1),
							ReadILOperand(il, op2, addr)
						),
						il.Const(1, 1)
					)
				));

				Saturate(il, op1.reg, ReadILOperand(il, op3, addr), il.Register(4, LLIL_TEMP(0)), false);

			});
			break;
		case ARMV7_USAT16:
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0),
					il.Sub(2,
						il.ShiftLeft(2,
							il.Const(1, 1),
							ReadILOperand(il, op2, addr)
						),
						il.Const(1, 1)
					)
				));

				Saturate(il, LLIL_TEMP(1), il.LowPart(2, ReadILOperand(il, op3, addr)), il.Register(4, LLIL_TEMP(0)), false);
				Saturate(il, LLIL_TEMP(2), il.ArithShiftRight(2, ReadILOperand(il, op3, addr), il.Const(1, 16)), il.Register(4, LLIL_TEMP(0)), false);

				il.AddInstruction(il.SetRegister(4, op1.reg,
					il.Or(4,
						il.ZeroExtend(4,
							il.ShiftLeft(4,
								il.Register(2, LLIL_TEMP(2)),
								il.Const(1, 16)
							)
						),
						il.ZeroExtend(2, il.Register(2, LLIL_TEMP(1)))
					)
				));
			});
			break;
		case ARMV7_USAX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Add(4,
							il.LowPart(2,
								ReadILOperand(il, op2, addr)
							),
							il.LogicalShiftRight(2,
								ReadILOperand(il, op3, addr),
								il.Const(1,16)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Sub(4,
							il.LogicalShiftRight(2,
								ReadILOperand(il, op2, addr),
								il.Const(1,16)
							),
							il.LowPart(2,
								ReadILOperand(il, op3, addr)
							)
						)
					));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.Register(2, LLIL_TEMP(1)),
								il.Const(1, 16)
							),
							il.Register(2, LLIL_TEMP(0))
						)
					));
				});
			break;
		case ARMV7_UXTAB:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Add(get_register_size(op2.reg), ReadRegisterOrPointer(il, op2, addr),
					il.And(get_register_size(op3.reg),
						GetShiftedRegister(il, op3), il.Const(get_register_size(op3.reg), 0xff)))));
			break;
		case ARMV7_UXTAB16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), ReadILOperand(il, op3, addr)));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.Add(4,
									il.LowPart(2, ReadILOperand(il, op2, addr)),
									il.ZeroExtend(2, il.Register(1, LLIL_TEMP(0)))
								),
								il.Const(1, 32)
							),
							il.Add(4,
								il.LogicalShiftRight(2,
									ReadILOperand(il, op2, addr),
									il.Const(1, 16)
								),
								il.ZeroExtend(2,
									il.LowPart(1,
										il.LogicalShiftRight(2,
											il.Register(4, LLIL_TEMP(0)),
											il.Const(1, 16)
										)
									)
								)
							)
						)
					));
				});
			break;
		case ARMV7_UXTAH:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							ReadILOperand(il, op2, addr),
							il.ZeroExtend(4,
								il.LowPart(2,
									ReadILOperand(il, op3, addr)
								)
							)
						)
					));
				});
			break;
		case ARMV7_UXTB:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.And(get_register_size(op2.reg), GetShiftedRegister(il, op2), il.Const(get_register_size(op2.reg), 0xff))));
			break;
		case ARMV7_UXTB16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), ReadILOperand(il, op2, addr)));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								il.ZeroExtend(2,
									il.LowPart(1,
										il.LogicalShiftRight(2,
											il.Register(4, LLIL_TEMP(0)),
											il.Const(1, 16)
										)
									)
								),
								il.Const(1, 16)
							),
							il.ZeroExtend(2, il.Register(1, LLIL_TEMP(0)))
						)
					));
				});
			break;
		case ARMV7_UXTH:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.And(get_register_size(op2.reg), GetShiftedRegister(il, op2), il.Const(get_register_size(op2.reg), 0xffff))));
			break;
		case ARMV7_UDF:
			il.AddInstruction(il.Trap(op1.imm));
			break;
		case ARMV7_UDIV:
			if (op3.cls == NONE)
				ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
					il.DivUnsigned(get_register_size(op1.reg), ReadRegisterOrPointer(il, op1, addr), ReadRegisterOrPointer(il, op2, addr))));
			else
				ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
					il.DivUnsigned(get_register_size(op2.reg), ReadRegisterOrPointer(il, op2, addr), ReadRegisterOrPointer(il, op3, addr))));
			break;
		case ARMV7_VADD:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;

			ConditionExecute(il, instr.cond,
				il.SetRegister(get_register_size(op1.reg), op1.reg,
					il.FloatAdd(get_register_size(op1.reg),
						il.Register(get_register_size(op2.reg), op2.reg),
						il.Register(get_register_size(op3.reg), op3.reg)
					)
				)
			);
			break;
		case ARMV7_VDIV:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;

			ConditionExecute(il, instr.cond,
				il.SetRegister(get_register_size(op1.reg), op1.reg,
					il.FloatDiv(get_register_size(op1.reg),
						il.Register(get_register_size(op2.reg), op2.reg),
						il.Register(get_register_size(op3.reg), op3.reg)
					)
				)
			);
			break;
		case ARMV7_VLDR:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						Load(il, false, get_register_size(op1.reg), op1, op2, addr);
					});
			break;
		case ARMV7_VMOV:
			/* VMOV(register) */
			if (op1.cls == REG && op2.cls == REG && op3.cls == NONE)
			{
				ConditionExecute(il, instr.cond,
					SetRegisterOrBranch(il, op1.reg,
						ReadILOperand(il, op2, addr), flagOperation[instr.setsFlags]));
			} else if (op1.cls == REG && (op2.cls == IMM || op2.cls == IMM64) && op3.cls == NONE) {
			/* VMOV(immediate) */
				if (get_register_size(op1.reg) == 16)
				{
					ConditionExecute(il, instr.cond,
						SetRegisterOrBranch(il, op1.reg,
							il.Or(16, il.Const(8, op2.imm64), il.ShiftLeft(16, il.Const(8, op2.imm64), il.Const(8, 64))),
								flagOperation[instr.setsFlags]));
				} else
				{
					ConditionExecute(il, instr.cond,
						SetRegisterOrBranch(il, op1.reg,
							il.Const(get_register_size(op1.reg), op2.imm64), flagOperation[instr.setsFlags]));
				}
			} else
			{
				ConditionExecute(il, instr.cond, il.Unimplemented());
			}
			break;
		case ARMV7_VMUL:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;

			ConditionExecute(il, instr.cond,
				il.SetRegister(get_register_size(op1.reg), op1.reg,
					il.FloatMult(get_register_size(op1.reg),
						il.Register(get_register_size(op2.reg), op2.reg),
						il.Register(get_register_size(op3.reg), op3.reg)
					)
				)
			);
			break;
		case ARMV7_VSTR:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						Store(il, get_register_size(op1.reg), op1, op2, addr);
					});
			break;
		case ARMV7_VSUB:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;

			ConditionExecute(il, instr.cond,
				il.SetRegister(get_register_size(op1.reg), op1.reg,
					il.FloatSub(get_register_size(op1.reg),
						il.Register(get_register_size(op2.reg), op2.reg),
						il.Register(get_register_size(op3.reg), op3.reg)
					)
				)
			);
			break;
		default:
			//printf("Instruction: %s\n", get_operation(instr.operation));
			ConditionExecute(il, instr.cond, il.Unimplemented());
			break;
	}
	return true;
}
