#include <stdarg.h>
#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "il.h"
#include "spec.h"
#include "disassembler.h"

using namespace BinaryNinja;
using namespace armv7;

// align 32-bit number to 4
#define ALIGN4(a) ((a) & 0xFFFFFFFC)

bool GetLowLevelILForNEONInstruction(Architecture* arch, LowLevelILFunction& il, decomp_result* instr, bool ifThenBlock);

static uint32_t GetRegisterByIndex(uint32_t i, const char* prefix = "")
{
	if (strcmp(prefix, "s") == 0)
		return REG_R0 + (i/2) + (i%2) + REG_S0;
	if (strcmp(prefix, "d") == 0)
		return REG_R0 + (i/2) + (i%2) + REG_D0;
	if (strcmp(prefix, "q") == 0)
		return REG_R0 + (i/2) + (i%2) + REG_Q0;
	return REG_R0 + i;
}

static ExprId ReadRegister(LowLevelILFunction& il, decomp_result* instr, uint32_t reg, size_t size = 4, const char* prefix = "")
{
	if (reg == armv7::REG_PC)
		return il.ConstPointer(size, instr->pc);
	if (strcmp(prefix, "s") == 0)
		size = 4;
	if (strcmp(prefix, "d") == 0)
		size = 8;
	if (strcmp(prefix, "q") == 0)
		size = 16;
	return il.Register(size, GetRegisterByIndex(reg, prefix));
}

static int GetSpecialRegister(LowLevelILFunction& il, decomp_result* instr, size_t operand)
{
	uint32_t mask = instr->fields[FIELD_mask] & 0xF;

	if(IS_FIELD_PRESENT(instr, FIELD_write_spsr)) {
		if(instr->fields[FIELD_write_spsr])
			return REGS_SPSR + mask;
		else
			return REGS_CPSR + mask;
	}

	uint32_t tmp = (instr->fields[FIELD_write_nzcvq] << 1) | instr->fields[FIELD_write_g];
	uint8_t sysm = instr->fields[FIELD_SYSm];
	switch (sysm >> 3) {
		case 0:
			switch(tmp) {
				case 1: return REGS_APSR_G;
				case 2:	return REGS_APSR_NZCVQ;
				case 3: return REGS_APSR_NZCVQG;
			}
			break;
		case 1:
			switch (sysm & 7) {
				case 0: return REGS_MSP;
				case 1: return REGS_PSP;
			}
			break;
		case 2:
			switch (sysm & 7) {
				case 0: return REGS_PRIMASK;
				case 1:
				case 2: return REGS_BASEPRI;
				case 3: return REGS_FAULTMASK;
				case 4: return REGS_CONTROL;
			}
			break;
	}

	return REG_INVALID;
}

static ExprId ReadILOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t size = 4)
{
	uint32_t value;
	uint64_t imm64;
	switch (instr->format->operands[operand].type)
	{
	case OPERAND_FORMAT_IMM64:
		imm64 = instr->fields[FIELD_imm64h];
		imm64 <<= 32;
		imm64 |= instr->fields[FIELD_imm64l];
		return il.Const(8, imm64);
	case OPERAND_FORMAT_IMM:
	case OPERAND_FORMAT_OPTIONAL_IMM:
		value = instr->fields[instr->format->operands[operand].field0];
		if ((instr->mnem == armv7::ARMV7_B) || (instr->mnem == armv7::ARMV7_BL) ||
			(instr->mnem == armv7::ARMV7_CBNZ) || (instr->mnem == armv7::ARMV7_CBZ)) {
			value += instr->pc;
			return il.ConstPointer(size, value);
		} else if ((instr->mnem == armv7::ARMV7_BX) || (instr->mnem == armv7::ARMV7_BLX)) {
			value += instr->pc & (~3);
			return il.ConstPointer(size, value);
		}
		return il.Const(size, value);
	case OPERAND_FORMAT_ADD_IMM:
	case OPERAND_FORMAT_OPTIONAL_ADD_IMM:
		value = instr->fields[instr->format->operands[operand].field0];
		if (instr->fields[FIELD_add])
			return il.Const(4, value);
		return il.Const(size, -(int64_t)value);
	case OPERAND_FORMAT_ZERO:
		return il.Const(size, 0);
	case OPERAND_FORMAT_REG:
		value = instr->fields[instr->format->operands[operand].field0];
		return ReadRegister(il, instr, GetRegisterByIndex(value), size);
	case OPERAND_FORMAT_REG_FP:
		value = instr->fields[instr->format->operands[operand].field0];
		return ReadRegister(il, instr, value, size, instr->format->operands[operand].prefix);
	case OPERAND_FORMAT_SP:
		return il.Register(size, armv7::REG_SP);
	case OPERAND_FORMAT_LR:
		return il.Register(size, armv7::REG_LR);
	case OPERAND_FORMAT_PC:
		return il.ConstPointer(size, instr->pc);
	default:
		return il.Unimplemented();
	}
}

static uint32_t GetRegisterSize(decomp_result* instr, size_t operand)
{
	if (strcmp(instr->format->operands[operand].prefix, "q") == 0)
		return 16;
	if (strcmp(instr->format->operands[operand].prefix, "d") == 0)
		return 8;
	if (strcmp(instr->format->operands[operand].prefix, "s") == 0)
		return 4;
	return 4;
}

static ExprId ReadShiftedOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t size = 4)
{
	uint32_t shift_t = instr->fields[FIELD_shift_t];
	uint32_t shift_n = instr->fields[FIELD_shift_n];
	ExprId value = ReadILOperand(il, instr, operand, size);

	if(shift_n == 0)
		return value;

	switch (shift_t)
	{
	case SRType_LSL:
		return il.ShiftLeft(size, value, il.Const(4, shift_n));
	case SRType_LSR:
		return il.LogicalShiftRight(size, value, il.Const(4, shift_n));
	case SRType_ASR:
		return il.ArithShiftRight(size, value, il.Const(4, shift_n));
	case SRType_RRX:
		return il.RotateRightCarry(size, value, il.Const(4, 1), il.Flag(IL_FLAG_C));
	case SRType_ROR:
		return il.RotateRight(size, value, il.Const(4, shift_n));
	default:
		return value;
	}
}

static ExprId ReadRotatedOperand(LowLevelILFunction& il, decomp_result *instr, size_t operand, size_t size = 4)
{
	uint32_t rot_n = instr->fields[FIELD_rotation];
	ExprId value = ReadILOperand(il, instr, operand, size);

	if (IS_FIELD_PRESENT(instr, FIELD_rotation) && 0 != rot_n) {
		return il.RotateRight(size, value, il.Const(4, rot_n));
	}

	return value;
}

static ExprId ReadArithOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t size = 4)
{
	if (operand == 0)
	{
		if (instr->format->operandCount == 2)
			return ReadILOperand(il, instr, 0, size);
		if ((instr->format->operandCount == 3) && (instr->format->operands[2].type == OPERAND_FORMAT_SHIFT))
			return ReadILOperand(il, instr, 0, size);
		return ReadILOperand(il, instr, 1, size);
	}

	if (instr->format->operandCount == 2)
		return ReadILOperand(il, instr, 1, size);
	if (instr->format->operandCount == 3)
	{
		if (instr->format->operands[2].type != OPERAND_FORMAT_SHIFT)
			return ReadILOperand(il, instr, 2, size);
		return ReadShiftedOperand(il, instr, 1, size);
	}
	return ReadShiftedOperand(il, instr, 2, size);
}


static ExprId WriteILOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, ExprId value,
	size_t size = 4, uint32_t flags = 0)
{
	uint32_t reg;
	switch (instr->format->operands[operand].type)
	{
	case OPERAND_FORMAT_REG:
		reg = instr->fields[instr->format->operands[operand].field0];
		if (reg == 15)
			return il.Jump(value);
		return il.SetRegister(size, GetRegisterByIndex(reg), value, flags);
	case OPERAND_FORMAT_REG_FP:
		reg = instr->fields[instr->format->operands[operand].field0];
		size = GetRegisterSize(instr, operand);
		return il.SetRegister(size, GetRegisterByIndex(reg, instr->format->operands[operand].prefix), value, flags);
	case OPERAND_FORMAT_SP:
		return il.SetRegister(size, armv7::REG_SP, value, flags);
	case OPERAND_FORMAT_LR:
		return il.SetRegister(size, armv7::REG_LR, value, flags);
	case OPERAND_FORMAT_PC:
		return il.Jump(value);
	default:
		return il.Unimplemented();
	}
}


static ExprId WriteArithOperand(LowLevelILFunction& il, decomp_result* instr, ExprId value, size_t size = 4,
	uint32_t flags = 0)
{
	return WriteILOperand(il, instr, 0, value, size, flags);
}


static ExprId WriteSplitOperands(LowLevelILFunction& il, decomp_result *instr, size_t operandHi, size_t operandLo, ExprId value,
	size_t size = 4, uint32_t flags = 0)
{
	uint32_t regHi = instr->fields[instr->format->operands[operandHi].field0];
	uint32_t regLo = instr->fields[instr->format->operands[operandLo].field0];

	return il.SetRegisterSplit(size, GetRegisterByIndex(regHi), GetRegisterByIndex(regLo), value, flags);
}


static bool HasWriteback(decomp_result* instr, size_t operand)
{
	switch (instr->format->operands[operand].writeback)
	{
	case WRITEBACK_YES:
		return true;
	case WRITEBACK_OPTIONAL:
		return thumb_has_writeback(instr);
	default:
		return false;
	}
}


static ExprId ShiftedRegister(LowLevelILFunction& il, decomp_result* instr, uint32_t reg, uint32_t t, uint32_t n)
{
	if (n == 0)
		return il.Register(4, reg);
	switch (t)
	{
	case SRType_LSL:
		return il.ShiftLeft(4, ReadRegister(il, instr, reg), il.Const(4, n));
	case SRType_LSR:
		return il.LogicalShiftRight(4, ReadRegister(il, instr, reg), il.Const(4, n));
	case SRType_ASR:
		return il.ArithShiftRight(4, ReadRegister(il, instr, reg), il.Const(4, n));
	case SRType_ROR:
		return il.RotateRight(4, ReadRegister(il, instr, reg), il.Const(4, n));
	case SRType_RRX:
		return il.RotateRightCarry(4, ReadRegister(il, instr, reg), il.Const(4, 1), il.Flag(IL_FLAG_C));
	default:
		return il.Unimplemented();
	}
}


static ExprId GetMemoryAddress(LowLevelILFunction& il, decomp_result* instr, size_t operand, uint32_t size,
	bool canWriteback = true)
{
	uint32_t reg, second, t, n;
	switch (instr->format->operands[operand].type)
	{
	case OPERAND_FORMAT_MEMORY_ONE_REG:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		return il.Register(4, reg);
	case OPERAND_FORMAT_MEMORY_ONE_REG_IMM:
	case OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = instr->fields[instr->format->operands[operand].field1];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegister(il, instr, reg), il.Const(4, second))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegister(il, instr, reg), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_ONE_REG_NEG_IMM:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = instr->fields[instr->format->operands[operand].field1];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Sub(4, ReadRegister(il, instr, reg), il.Const(4, second))));
			return il.Register(4, reg);
		}
		return il.Sub(4, ReadRegister(il, instr, reg), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_ONE_REG_ADD_IMM:
	case OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_ADD_IMM:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = instr->fields[instr->format->operands[operand].field1];
		if (canWriteback && HasWriteback(instr, operand))
		{
			if (instr->fields[FIELD_add])
				il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegister(il, instr, reg), il.Const(4, second))));
			else
				il.AddInstruction(il.SetRegister(4, reg, il.Sub(4, ReadRegister(il, instr, reg), il.Const(4, second))));
			return il.Register(4, reg);
		}
		if (instr->fields[FIELD_add])
			return il.Add(4, ReadRegister(il, instr, reg), il.Const(4, second));
		return il.Sub(4, ReadRegister(il, instr, reg), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_TWO_REG:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field1]);
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegister(il, instr, reg), il.Register(4, second))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegister(il, instr, reg), il.Register(4, second));
	case OPERAND_FORMAT_MEMORY_TWO_REG_SHIFT:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field1]);
		t = instr->fields[FIELD_shift_t];
		n = instr->fields[FIELD_shift_n];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegister(il, instr, reg),
				ShiftedRegister(il, instr, second, t, n))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegister(il, instr, reg), ShiftedRegister(il, instr, second, t, n));
	case OPERAND_FORMAT_MEMORY_TWO_REG_LSL_ONE:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field1]);
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegister(il, instr, reg),
				il.ShiftLeft(4, ReadRegister(il, instr, second), il.Const(4, 1)))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegister(il, instr, reg), il.ShiftLeft(4, ReadRegister(il, instr, second), il.Const(4, 1)));
	case OPERAND_FORMAT_MEMORY_SP_IMM:
	case OPERAND_FORMAT_MEMORY_SP_OPTIONAL_IMM:
		second = instr->fields[instr->format->operands[operand].field0];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, armv7::REG_SP, il.Add(4, il.Register(4, armv7::REG_SP), il.Const(4, second))));
			return il.Register(4, armv7::REG_SP);
		}
		return il.Add(4, il.Register(4, armv7::REG_SP), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_PC:
		return il.ConstPointer(4, instr->pc);
	case OPERAND_FORMAT_LABEL:
		if (instr->fields[FIELD_add])
			return il.ConstPointer(4, ALIGN4(instr->pc) + instr->fields[FIELD_imm32]);
		return il.ConstPointer(4, ALIGN4(instr->pc) - instr->fields[FIELD_imm32]);
	default:
		return il.Unimplemented();
	}
}


ExprId GetCondition(LowLevelILFunction& il, uint32_t cond)
{
	switch(cond)
	{
	 	case armv7::COND_EQ: return il.FlagCondition(LLFC_E);
	 	case armv7::COND_NE: return il.FlagCondition(LLFC_NE);
	 	case armv7::COND_CS: return il.FlagCondition(LLFC_UGE);
	 	case armv7::COND_CC: return il.FlagCondition(LLFC_ULT);
	 	case armv7::COND_MI: return il.FlagCondition(LLFC_NEG);
	 	case armv7::COND_PL: return il.FlagCondition(LLFC_POS);
	 	case armv7::COND_VS: return il.FlagCondition(LLFC_O);
	 	case armv7::COND_VC: return il.FlagCondition(LLFC_NO);
	 	case armv7::COND_HI: return il.FlagCondition(LLFC_UGT);
	 	case armv7::COND_LS: return il.FlagCondition(LLFC_ULE);
	 	case armv7::COND_GE: return il.FlagCondition(LLFC_SGE);
	 	case armv7::COND_LT: return il.FlagCondition(LLFC_SLT);
	 	case armv7::COND_GT: return il.FlagCondition(LLFC_SGT);
	 	case armv7::COND_LE: return il.FlagCondition(LLFC_SLE);
	 	case armv7::COND_NONE: return il.Const(0, 1); //Always branch
		default:
			return il.Const(0, 0); //Never branch
	}
}


static void ConditionalJump(Architecture* arch, LowLevelILFunction& il, uint32_t cond, uint32_t t, uint32_t f)
{
	BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
	BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);

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
		il.AddInstruction(il.Jump(il.ConstPointer(4, f)));
		return;
	}

	if (falseLabel)
	{
		il.AddInstruction(il.If(GetCondition(il, cond), trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(4, t)));
		return;
	}

	il.AddInstruction(il.If(GetCondition(il, cond), trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(il.Jump(il.ConstPointer(4, t)));
	il.MarkLabel(falseCode);
	il.AddInstruction(il.Jump(il.ConstPointer(4, f)));
}


static void CompareWithZeroAndConditionalJump(Architecture* arch, LowLevelILFunction& il, uint32_t reg,
	BNLowLevelILOperation cond, uint32_t t, uint32_t f)
{
	BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
	BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);
	ExprId condExpr = il.AddExpr(cond, 4, 0, il.Register(4, GetRegisterByIndex(reg)), il.Const(4, 0));

	if (trueLabel && falseLabel)
	{
		il.AddInstruction(il.If(condExpr, *trueLabel, *falseLabel));
		return;
	}

	LowLevelILLabel trueCode, falseCode;

	if (trueLabel)
	{
		il.AddInstruction(il.If(condExpr, *trueLabel, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(4, f)));
		return;
	}

	if (falseLabel)
	{
		il.AddInstruction(il.If(condExpr, trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(4, t)));
		return;
	}

	il.AddInstruction(il.If(condExpr, trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(il.Jump(il.ConstPointer(4, t)));
	il.MarkLabel(falseCode);
	il.AddInstruction(il.Jump(il.ConstPointer(4, f)));
}


void SetupThumbConditionalInstructionIL(LowLevelILFunction& il, LowLevelILLabel& trueLabel,
	LowLevelILLabel& falseLabel, uint32_t cond)
{
	il.AddInstruction(il.If(GetCondition(il, cond), trueLabel, falseLabel));
}


static void Push(LowLevelILFunction& il, uint32_t regs)
{
	for (int32_t i = 15; i >= 0; i--)
	{
		if (((regs >> i) & 1) == 1)
		{
			il.AddInstruction(il.Push(4, il.Register(4, GetRegisterByIndex(i))));
		}
	}
}


static void Pop(LowLevelILFunction& il, uint32_t regs)
{
	for (int32_t i = 0; i <= 15; i++)
	{
		if (((regs >> i) & 1) == 1)
		{
			if (i == 15)
				il.AddInstruction(il.Return(il.Pop(4)));
			else
				il.AddInstruction(il.SetRegister(4, GetRegisterByIndex(i), il.Pop(4)));
		}
	}
}


static bool WritesToStatus(decomp_result* instr, bool ifThenBlock)
{
	if (ifThenBlock)
		return false;
	if (instr->format->operationFlags & INSTR_FORMAT_FLAG_OPTIONAL_STATUS)
	{
		if(IS_FIELD_PRESENT(instr, FIELD_S))
		{
			if (instr->fields[FIELD_S])
				return true;
		}
	}
	return false;
}

static bool IsPCRelativeDataAddress(decomp_result* instr, bool ifThenBlock)
{
	if ((instr->format->operandCount == 3) && (instr->format->operands[1].type == OPERAND_FORMAT_PC) &&
			(instr->format->operands[2].type == OPERAND_FORMAT_IMM) && !WritesToStatus(instr, ifThenBlock))
		return true;

	return false;
}


bool GetLowLevelILForThumbInstruction(Architecture* arch, LowLevelILFunction& il, decomp_result* instr, bool ifThenBlock)
{
	if ((instr->status & STATUS_UNDEFINED) || (!instr->format))
		return false;

	switch (instr->mnem)
	{
	case armv7::ARMV7_ADC:
			il.AddInstruction(WriteArithOperand(il, instr, il.AddCarry(4, ReadArithOperand(il, instr, 0),
				ReadArithOperand(il, instr, 1), il.Flag(IL_FLAG_C), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_ADCS:
			il.AddInstruction(WriteArithOperand(il, instr, il.AddCarry(4, ReadArithOperand(il, instr, 0),
				ReadArithOperand(il, instr, 1), il.Flag(IL_FLAG_C), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv7::ARMV7_ADD:
	case armv7::ARMV7_ADDW:
		if (IsPCRelativeDataAddress(instr, ifThenBlock))
			il.AddInstruction(WriteArithOperand(il, instr, il.Add(4, il.And(4, ReadILOperand(il, instr, 1, 4), il.Const(4, ~3)),
				ReadILOperand(il, instr, 2, 4))));
		else
			il.AddInstruction(WriteArithOperand(il, instr, il.Add(4, ReadArithOperand(il, instr, 0),
				ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_ADDS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Add(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv7::ARMV7_ADR:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.ConstPointer(4, (instr->pc + instr->fields[
			instr->format->operands[1].field0]) & (~3))));
		break;
	case armv7::ARMV7_AND:
		il.AddInstruction(WriteArithOperand(il, instr, il.And(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_ANDS:
		il.AddInstruction(WriteArithOperand(il, instr, il.And(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv7::ARMV7_ASR:
		il.AddInstruction(WriteArithOperand(il, instr, il.ArithShiftRight(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_CNZ : 0)));
		break;
	case armv7::ARMV7_ASRS:
		il.AddInstruction(WriteArithOperand(il, instr, il.ArithShiftRight(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_CNZ)));
		break;
	case armv7::ARMV7_B:
		if ((!(instr->format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL)) ||
			(instr->fields[FIELD_cond] == COND_AL))
		{
			uint32_t dest = instr->pc + instr->fields[instr->format->operands[0].field0];
			BNLowLevelILLabel* label = il.GetLabelForAddress(arch, dest);
			if (label)
				il.AddInstruction(il.Goto(*label));
			else
				il.AddInstruction(il.Jump(il.ConstPointer(4, dest)));
		}
		else
		{
			uint32_t t = instr->pc + instr->fields[instr->format->operands[0].field0];
			uint32_t f = (instr->pc - 4) + (instr->instrSize / 8);
			ConditionalJump(arch, il, instr->fields[FIELD_cond], t, f);
		}
		break;
	case armv7::ARMV7_BFC:
		{
			uint32_t lsb = instr->fields[instr->format->operands[1].field0];
			uint32_t clear_width = instr->fields[instr->format->operands[2].field0];
			uint32_t mask = ((1 << clear_width) - 1) << lsb;
			il.AddInstruction(WriteILOperand(il, instr, 0,
						il.And(4,
							ReadILOperand(il, instr, 0),
							il.Const(4, ~mask))));
		}
		break;
	case armv7::ARMV7_BFI:
	{
		uint32_t width_mask;
		uint32_t mask;
		uint32_t lsb;
		uint32_t width;

		width = instr->fields[instr->format->operands[3].field0];
		lsb = instr->fields[instr->format->operands[2].field0];
		width_mask = (1 << width) - 1;
		mask = width_mask << lsb;
		//bit field insert: op1 = (op1 & (~(<width_mask> << lsb))) | ((op2 & <width_mask>) << lsb)
		il.AddInstruction(WriteILOperand(il, instr, 0,
			il.Or(4,
				il.And(4, ReadILOperand(il, instr, 0), il.Const(4, ~mask)),
			il.ShiftLeft(4,
				il.And(4, ReadILOperand(il, instr, 1), il.Const(4, width_mask)),
				il.Const(4, lsb)))));
		break;
	}
	case armv7::ARMV7_BIC:
		il.AddInstruction(WriteArithOperand(il, instr, il.And(4, ReadArithOperand(il, instr, 0),
			il.Not(4, ReadArithOperand(il, instr, 1)), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_BICS:
		il.AddInstruction(WriteArithOperand(il, instr, il.And(4, ReadArithOperand(il, instr, 0),
			il.Not(4, ReadArithOperand(il, instr, 1)), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv7::ARMV7_BKPT:
		il.AddInstruction(il.Breakpoint());
		break;
	case armv7::ARMV7_BL:
	case armv7::ARMV7_BLX:
		il.AddInstruction(il.Call(ReadILOperand(il, instr, 0)));
		break;
	case armv7::ARMV7_BX:
		if ((instr->format->operands[0].type == OPERAND_FORMAT_LR) ||
			(instr->fields[instr->format->operands[0].field0] == 14))
		{
			il.AddInstruction(il.Return(il.Register(4, armv7::REG_LR)));
		}
		else
		{
			il.AddInstruction(il.Jump(ReadRegister(il, instr, GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]), 4)));
		}
		break;
	case armv7::ARMV7_CBNZ:
		CompareWithZeroAndConditionalJump(arch, il, instr->fields[instr->format->operands[0].field0], LLIL_CMP_NE,
			(instr->pc - 4) + instr->fields[instr->format->operands[1].field0], (instr->pc - 4) + (instr->instrSize / 8));
		break;
	case armv7::ARMV7_CBZ:
		CompareWithZeroAndConditionalJump(arch, il, instr->fields[instr->format->operands[0].field0], LLIL_CMP_E,
			(instr->pc - 4) + instr->fields[instr->format->operands[1].field0], (instr->pc - 4) + (instr->instrSize / 8));
		break;
	case armv7::ARMV7_CLZ:
	{
		LowLevelILLabel loopStart,
				loopBody,
				loopExit;
		//Count leading zeros
		//Based on the non-thumb CLZ lifter
		//
		// TEMP0 = 0
		// TEMP1 = op2.reg
		// while (TEMP1 != 0)
		// 		TEMP1 = TEMP1 >> 1
		// 		TEMP0 = TEMP0 + 1
		// op1.reg = 32 - TEMP0
		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Const(4, 0)));
		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1), ReadILOperand(il, instr, 1)));
		il.AddInstruction(il.Goto(loopStart));
		il.MarkLabel(loopStart);
		il.AddInstruction(il.If(il.CompareNotEqual(4, il.Register(4, LLIL_TEMP(1)), il.Const(4, 0)), loopBody, loopExit));
		il.MarkLabel(loopBody);
		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1), il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(4, 1))));
		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 1))));
		il.AddInstruction(il.Goto(loopStart));
		il.MarkLabel(loopExit);
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Sub(4, il.Const(4, 32), il.Register(4, LLIL_TEMP(0)))));
		break;
	}
	case armv7::ARMV7_CMP:
		il.AddInstruction(il.Sub(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1), IL_FLAGWRITE_ALL));
		break;
	case armv7::ARMV7_CMN:
		il.AddInstruction(il.Add(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1), IL_FLAGWRITE_ALL));
		break;
	case armv7::ARMV7_DBG:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DBG, {il.Const(1, instr->fields[FIELD_option])}));
		break;
	case armv7::ARMV7_DMB:
		switch (instr->fields[FIELD_barrier_option]) {
		case 0xf: /* 0b1111 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DMB_SY, {}));
			break;
		case 0xe: /* 0b1110 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DMB_ST, {}));
			break;
		case 0xb: /* 0b1011 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DMB_ISH, {}));
			break;
		case 0xa: /* 0b1010 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DMB_ISHST, {}));
			break;
		case 0x7: /* 0b0111 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DMB_NSH, {}));
			break;
		case 0x6: /* 0b0110 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DMB_NSHST, {}));
			break;
		case 0x3: /* 0b0011 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DMB_OSH, {}));
			break;
		case 0x2: /* 0b0011 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DMB_OSHST, {}));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
		break;
	case armv7::ARMV7_DSB:
		switch (instr->fields[FIELD_barrier_option]) {
		case 0xf: /* 0b1111 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DSB_SY, {}));
			break;
		case 0xe: /* 0b1110 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DSB_ST, {}));
			break;
		case 0xb: /* 0b1011 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DSB_ISH, {}));
			break;
		case 0xa: /* 0b1010 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DSB_ISHST, {}));
			break;
		case 0x7: /* 0b0111 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DSB_NSH, {}));
			break;
		case 0x6: /* 0b0110 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DSB_NSHST, {}));
			break;
		case 0x3: /* 0b0011 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DSB_OSH, {}));
			break;
		case 0x2: /* 0b0011 */
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DSB_OSHST, {}));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
		break;
	case armv7::ARMV7_EOR:
		il.AddInstruction(WriteArithOperand(il, instr, il.Xor(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_EORS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Xor(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case ARMV7_ISB:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_ISB, {}));
		break;
	case ARMV7_LDM:
	case ARMV7_LDMIA:
	case ARMV7_LDMDB:
	{
		bool decBeforeMode = instr->mnem == ARMV7_LDMDB;
		bool is16BitForm = (instr->instrSize == 16);
		uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
		uint32_t regs = instr->fields[instr->format->operands[1].field0];
		uint32_t lrpcBits = (1 << armv7::REG_LR) | (1 << armv7::REG_PC);
		bool valid = true;
		if (baseReg == armv7::REG_PC)
			valid = false;
		else if (!is16BitForm)
		{
			if (((regs & (1 << armv7::REG_SP)) || (regs & (1 << armv7::REG_PC)) || ((regs & lrpcBits) == lrpcBits) || !(regs & (regs - 1)) || (HasWriteback(instr, 0) && (regs & (1 << baseReg)))))
				valid = false;
		}
		else // is16BitForm
		{
			if (decBeforeMode)
				valid = false;
			else if (!HasWriteback(instr, 0) && !(regs & (1 << baseReg)))
				valid = false;
		}

		if (!valid)
		{
			il.AddInstruction(il.Undefined());
			break;
		}

		int32_t regLimit = is16BitForm ? 7 : 15;
		int32_t regCnt = 0;
		bool baseIsNotFirst = true;
		for (int32_t i = 0; i <= regLimit; i++)
		{
			if ((regs >> i) & 1)
			{
				if (!regCnt && (i == baseReg))
					baseIsNotFirst = false;
				regCnt++;
			}
		}

		if (decBeforeMode)
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Add(4, il.Register(4, baseReg), il.Const(4, regCnt * -4))));
		else
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Register(4, baseReg)));

		for (int32_t i = 0, slot = 0; i <= regLimit; i++)
		{
			if ((regs >> i) & 1)
			{
				il.AddInstruction(il.SetRegister(4, GetRegisterByIndex(i),
					il.Load(4, il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 4 * slot++)))));
			}
		}

		if (HasWriteback(instr, 0) && baseIsNotFirst)
		{
			if (decBeforeMode)
				il.AddInstruction(il.SetRegister(4, baseReg, il.Register(4, LLIL_TEMP(0))));
			else
				il.AddInstruction(il.SetRegister(4, baseReg,
					il.Add(4, ReadRegister(il, instr, baseReg), il.Const(4, regCnt * 4))));
		}

		if (regs & (1 << armv7::REG_PC))
			il.AddInstruction(il.Jump(ReadRegister(il, instr, armv7::REG_PC, 4)));
		break;
	}
	case armv7::ARMV7_LDA:
	case armv7::ARMV7_LDR:
	case armv7::ARMV7_LDREX:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(WriteILOperand(il, instr, 0, il.Load(4, GetMemoryAddress(il, instr, 1, 4, false))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, il.Load(4, GetMemoryAddress(il, instr, 1, 4))));
		}
		break;
	case armv7::ARMV7_LDAB:
	case armv7::ARMV7_LDRB:
	case armv7::ARMV7_LDREXB:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(WriteILOperand(il, instr, 0, il.ZeroExtend(4,
				il.Load(1, GetMemoryAddress(il, instr, 1, 4, false)))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, il.ZeroExtend(4,
				il.Load(1, GetMemoryAddress(il, instr, 1, 4)))));
		}
		break;
	case armv7::ARMV7_LDAH:
	case armv7::ARMV7_LDRH:
	case armv7::ARMV7_LDREXH:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(WriteILOperand(il, instr, 0, il.ZeroExtend(4,
				il.Load(2, GetMemoryAddress(il, instr, 1, 4, false)))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, il.ZeroExtend(4,
				il.Load(2, GetMemoryAddress(il, instr, 1, 4)))));
		}
		break;
	case armv7::ARMV7_LDRD:
	case armv7::ARMV7_LDREXD:
		{
			ExprId mem;

			uint32_t rt = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
			uint32_t rt2 = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);

			mem = GetMemoryAddress(il, instr, 2, 4, instr->format->operandCount != 4);
			if (arch->GetEndianness() == LittleEndian) {
				il.AddInstruction(il.SetRegister(4, rt, il.Load(4, mem)));
				il.AddInstruction(il.SetRegister(4, rt2, il.Load(4, il.Add(4, mem, il.Const(4, 4)))));
			} else {
				il.AddInstruction(il.SetRegister(4, rt2, il.Load(4, mem)));
				il.AddInstruction(il.SetRegister(4, rt, il.Load(4, il.Add(4, mem, il.Const(4, 4)))));
			}

			if (instr->format->operandCount == 4)
			{
				uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[2].field0]);
				il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 3))));
			}
		}
		break;
	case armv7::ARMV7_LDRSB:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(WriteILOperand(il, instr, 0, il.SignExtend(4,
				il.Load(1, GetMemoryAddress(il, instr, 1, 4, false)))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, il.SignExtend(4,
				il.Load(1, GetMemoryAddress(il, instr, 1, 4)))));
		}
		break;
	case armv7::ARMV7_LDRSH:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(WriteILOperand(il, instr, 0, il.SignExtend(4,
				il.Load(2, GetMemoryAddress(il, instr, 1, 4, false)))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, il.SignExtend(4,
				il.Load(2, GetMemoryAddress(il, instr, 1, 4)))));
		}
		break;
	case armv7::ARMV7_LSL:
		il.AddInstruction(WriteArithOperand(il, instr, il.ShiftLeft(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_CNZ : 0)));
		break;
	case armv7::ARMV7_LSLS:
		il.AddInstruction(WriteArithOperand(il, instr, il.ShiftLeft(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_CNZ)));
		break;
	case armv7::ARMV7_LSR:
		il.AddInstruction(WriteArithOperand(il, instr, il.LogicalShiftRight(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_CNZ : 0)));
		break;
	case armv7::ARMV7_LSRS:
		il.AddInstruction(WriteArithOperand(il, instr, il.LogicalShiftRight(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_CNZ)));
		break;
	case armv7::ARMV7_MLA:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Add(4, ReadILOperand(il, instr, 3), il.Mult(4, ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2)))));
		break;
	case armv7::ARMV7_MLS:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Sub(4, ReadILOperand(il, instr, 3), il.Mult(4, ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2)))));
		break;
	case armv7::ARMV7_MOV:
	case armv7::ARMV7_MOVW:
		il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1)));
		break;
	case armv7::ARMV7_MOVS:
		il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1), 4,
			ifThenBlock ? 0 : IL_FLAGWRITE_NZ));
		break;
	case armv7::ARMV7_MOVT:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Or(4,
			il.ShiftLeft(4, il.Const(2, instr->fields[instr->format->operands[1].field0]), il.Const(1, 16)),
			il.And(4, il.Const(4, 0x0000ffff), ReadILOperand(il, instr, 0)))));
		break;
	case ARMV7_MSR:
		{
			int dest_reg = GetSpecialRegister(il, instr, 0);
			int intrinsic_id = ARMV7_INTRIN_MSR;

			/* certain MSR scenarios earn a specialized intrinsic */
			if(dest_reg == REGS_BASEPRI)
				intrinsic_id = ARM_M_INTRIN_SET_BASEPRI;

			il.AddInstruction(
				il.Intrinsic(
					{RegisterOrFlag::Register(dest_reg)}, /* outputs */
					intrinsic_id,
					{ReadILOperand(il, instr, 1)} /* inputs */
				)
			);
		}
		break;
	case armv7::ARMV7_MUL:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_NZ : 0)));
		break;
	case armv7::ARMV7_MULS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_NZ)));
		break;
	case armv7::ARMV7_MVN:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Not(4, ReadArithOperand(il, instr, 1))));
		break;
	case armv7::ARMV7_MVNS:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Not(4, ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv7::ARMV7_NOP:
		il.AddInstruction(il.Nop());
		break;
	case ARMV7_ORN:
		il.AddInstruction(WriteArithOperand(il, instr, il.Or(4, ReadArithOperand(il, instr, 0),
			il.Not(4, ReadArithOperand(il, instr, 1)), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_ORR:
		il.AddInstruction(WriteArithOperand(il, instr, il.Or(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_ORRS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Or(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv7::ARMV7_POP:
		Pop(il, instr->fields[FIELD_registers]);
		break;
	case armv7::ARMV7_PUSH:
		Push(il, instr->fields[FIELD_registers]);
		break;
	case armv7::ARMV7_REV:
		il.AddInstruction(WriteILOperand(il, instr, 0,
			il.Or(4, il.LogicalShiftRight(4, ReadILOperand(il, instr, 1), il.Const(4, 24)),
				 il.Or(4, il.And(4, il.LogicalShiftRight(4, ReadILOperand(il, instr, 1), il.Const(4, 16)), il.Const(4, 0xff)),
					  il.Or(4, il.And(4, il.LogicalShiftRight(4, ReadILOperand(il, instr, 1), il.Const(4, 8)), il.Const(4, 0xff)),
						   il.And(4, ReadILOperand(il, instr, 1), il.Const(4, 0xff)))))));
		break;
	case armv7::ARMV7_REV16:
		il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0), il.RotateRight(2, il.LowPart(2, ReadILOperand(il, instr, 1)), il.Const(1, 16))));
		il.AddInstruction(il.SetRegister(2, LLIL_TEMP(1), il.RotateRight(2, il.LogicalShiftRight(2, ReadILOperand(il, instr, 1), il.Const(1, 16)), il.Const(1, 16))));
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Or(4, il.ShiftLeft(4, il.Register(2, LLIL_TEMP(1)), il.Const(1, 16)), il.Register(2, LLIL_TEMP(0)))));
		break;
    case armv7::ARMV7_ROR:
        il.AddInstruction(WriteArithOperand(il, instr, il.RotateRight(4, ReadArithOperand(il, instr, 0),
            ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
        break;
    case armv7::ARMV7_RORS:
        il.AddInstruction(WriteArithOperand(il, instr, il.RotateRight(4, ReadArithOperand(il, instr, 0),
            ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
        break;
	case armv7::ARMV7_RSB:
		il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, ReadArithOperand(il, instr, 1),
			ReadArithOperand(il, instr, 0), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_RSBS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, ReadArithOperand(il, instr, 1),
			ReadArithOperand(il, instr, 0), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv7::ARMV7_UADD8:
	{
		uint32_t c = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
		ExprId a = ReadILOperand(il, instr, 1, 4);
		ExprId b = ReadILOperand(il, instr, 2, 4);
		ExprId a0 = il.LowPart(1, a);
		ExprId b0 = il.LowPart(1, b);
		ExprId a1 = il.LowPart(1, il.LogicalShiftRight(4, a, il.Const(1, 8)));
		ExprId b1 = il.LowPart(1, il.LogicalShiftRight(4, b, il.Const(1, 8)));
		ExprId a2 = il.LowPart(1, il.LogicalShiftRight(4, a, il.Const(1, 16)));
		ExprId b2 = il.LowPart(1, il.LogicalShiftRight(4, b, il.Const(1, 16)));
		ExprId a3 = il.LowPart(1, il.LogicalShiftRight(4, a, il.Const(1, 24)));
		ExprId b3 = il.LowPart(1, il.LogicalShiftRight(4, b, il.Const(1, 24)));

		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Add(1, a0, b0)));
		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1), il.Add(1, a1, b1)));
		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(2), il.Add(1, a2, b2)));
		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(3), il.Add(1, a3, b3)));

		il.AddInstruction(
			il.SetRegister(4, c,
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
			)
		);
		break;
	}
	case armv7::ARMV7_UADD16:
	{
		uint32_t c = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
		ExprId a = ReadILOperand(il, instr, 1, 4);
		ExprId b = ReadILOperand(il, instr, 2, 4);
		ExprId a0 = il.LowPart(2, a);
		ExprId b0 = il.LowPart(2, b);
		ExprId a1 = il.LowPart(2, il.LogicalShiftRight(4, a, il.Const(1, 16)));
		ExprId b1 = il.LowPart(2, il.LogicalShiftRight(4, b, il.Const(1, 16)));

		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Add(2, a0, b0)));
		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1), il.Add(2, a1, b1)));

		il.AddInstruction(
			il.SetRegister(4, c,
				il.Or(4,
					il.ShiftLeft(4,
						il.Register(1, LLIL_TEMP(0)),
						il.Const(1, 16)
					),
					il.Register(1, LLIL_TEMP(1))
				)
			)
		);
		break;
	}
	case armv7::ARMV7_UDIV:
		il.AddInstruction(WriteArithOperand(il, instr, il.DivUnsigned(4, ReadArithOperand(il, instr, 0), ReadArithOperand(il, instr, 1))));
		break;
	case armv7::ARMV7_SDIV:
		il.AddInstruction(WriteArithOperand(il, instr, il.DivSigned(4, ReadArithOperand(il, instr, 0), ReadArithOperand(il, instr, 1))));
		break;
	case armv7::ARMV7_SBC:
		il.AddInstruction(WriteArithOperand(il, instr, il.SubBorrow(4, ReadArithOperand(il, instr, 0),
									       ReadArithOperand(il, instr, 1),
									       il.Not(1, il.Flag(IL_FLAG_C)),
									       WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_SBCS:
		il.AddInstruction(WriteArithOperand(il, instr, il.SubBorrow(4, ReadArithOperand(il, instr, 0),
									       ReadArithOperand(il, instr, 1),
									       il.Not(1, il.Flag(IL_FLAG_C)),
									       ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv7::ARMV7_SBFX:
	{
		uint32_t Rd = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
		uint32_t Rn = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
		uint8_t lsb = instr->fields[instr->format->operands[2].field0];
		uint8_t width = instr->fields[instr->format->operands[3].field0];
		uint8_t msb = lsb + width - 1;
		msb = msb > 31 ? 31 : msb; /* spec says UNPREDICTABLE, we'll be tolerant */

		il.AddInstruction(
			il.SetRegister(4, Rd,
				il.ArithShiftRight(4,
					(31 - msb) ?
						il.ShiftLeft(4,
							ReadRegister(il, instr, Rn, 4),
							il.Const(1, 31 - msb)
						)
						:
						ReadRegister(il, instr, Rn, 4),
					il.Const(1, 31 - msb + lsb)
				)
			)
		);
		break;
	}
	case ARMV7_SEV:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_SEV, {}));
		break;
	case ARMV7_STM:
	case ARMV7_STMIA:
	case ARMV7_STMDB:
	{
		bool decBeforeMode = instr->mnem == ARMV7_STMDB;
		bool is16BitForm = (instr->instrSize == 16);
		uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
		uint32_t regs = instr->fields[instr->format->operands[1].field0];
		bool valid = true;
		if (baseReg == armv7::REG_PC)
			valid = false;
		else if (!is16BitForm)
		{
			if (((regs & (1 << armv7::REG_SP)) || (regs & (1 << armv7::REG_PC)) || !(regs & (regs - 1)) || (HasWriteback(instr, 0) && (regs & (1 << baseReg)))))
				valid = false;
		}
		else // is16BitForm
		{
			if (decBeforeMode || !HasWriteback(instr, 0))
				valid = false;
			// TODO technically not allowed...perhaps add a tag for indication of cases like this
			// else if ((regs & (1 << baseReg)) && (((1 << baseReg) - 1) & regs))
			// 	valid = false;
		}

		if (!valid)
		{
			il.AddInstruction(il.Undefined());
			break;
		}

		int32_t regLimit = is16BitForm ? 7 : 15;
		int32_t regCnt = 0;
		bool baseIsNotFirst = true;
		for (int32_t i = 0; i <= regLimit; i++)
		{
			if ((regs >> i) & 1)
			{
				if (!regCnt && (i == baseReg))
					baseIsNotFirst = false;
				regCnt++;
			}
		}

		if (decBeforeMode)
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Add(4, il.Register(4, baseReg), il.Const(4, regCnt * -4))));
		else
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Register(4, baseReg)));

		for (int32_t i = 0, slot = 0; i <= regLimit; i++)
		{
			if ((regs >> i) & 1)
			{
				il.AddInstruction(il.Store(4,
					il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 4 * slot++)),
						il.Register(4, GetRegisterByIndex(i))));
			}
		}

		if (HasWriteback(instr, 0) && baseIsNotFirst)
		{
			if (decBeforeMode)
				il.AddInstruction(il.SetRegister(4, baseReg, il.Register(4, LLIL_TEMP(0))));
			else
				il.AddInstruction(il.SetRegister(4, baseReg,
					il.Add(4, ReadRegister(il, instr, baseReg), il.Const(4, regCnt * 4))));
		}

		if (regs & (1 << armv7::REG_PC))
			il.AddInstruction(il.Jump(ReadRegister(il, instr, armv7::REG_PC, 4)));
		break;
	}
	case armv7::ARMV7_STL:
	case armv7::ARMV7_STR:
	//case armv7::ARMV7_STREX:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(il.Store(4, GetMemoryAddress(il, instr, 1, 4, false), ReadILOperand(il, instr, 0)));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(il.Store(4, GetMemoryAddress(il, instr, 1, 4), ReadILOperand(il, instr, 0)));
		}
		break;
	case armv7::ARMV7_STLB:
	case armv7::ARMV7_STRB:
	//case armv7::ARMV7_STREXB:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(il.Store(1, GetMemoryAddress(il, instr, 1, 4, false), il.LowPart(1, ReadILOperand(il, instr, 0))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(il.Store(1, GetMemoryAddress(il, instr, 1, 4), il.LowPart(1, ReadILOperand(il, instr, 0))));
		}
		break;
	case armv7::ARMV7_STLH:
	case armv7::ARMV7_STRH:
	//case armv7::ARMV7_STREXH:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(il.Store(2, GetMemoryAddress(il, instr, 1, 4, false), il.LowPart(2, ReadILOperand(il, instr, 0))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(il.Store(2, GetMemoryAddress(il, instr, 1, 4), il.LowPart(2, ReadILOperand(il, instr, 0))));
		}
		break;
	case armv7::ARMV7_STRD:
	//case armv7::ARMV7_STREXD:
		{
			ExprId mem;

			mem = GetMemoryAddress(il, instr, 2, 4, instr->format->operandCount != 4);
			if (arch->GetEndianness() == LittleEndian) {
				il.AddInstruction(il.Store(4, mem, ReadILOperand(il, instr, 0)));
				il.AddInstruction(il.Store(4, il.Add(4, mem, il.Const(4, 4)), ReadILOperand(il, instr, 1)));
			} else {
				il.AddInstruction(il.Store(4, mem, ReadILOperand(il, instr, 1)));
				il.AddInstruction(il.Store(4, il.Add(4, mem, il.Const(4, 4)), ReadILOperand(il, instr, 0)));
			}

			if (instr->format->operandCount == 4)
			{
				uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[2].field0]);
				il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 3))));
			}
		}
		break;
	case armv7::ARMV7_SUB:
	case armv7::ARMV7_SUBW:
		if (IsPCRelativeDataAddress(instr, ifThenBlock))
			il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, il.And(4, ReadILOperand(il, instr, 1, 4), il.Const(4, ~3)),
				ReadILOperand(il, instr, 2, 4))));
		else
			il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, ReadArithOperand(il, instr, 0),
				ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_SUBS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
    case armv7::ARMV7_SVC:
        il.AddInstruction(il.SetRegister(4, FAKEREG_SYSCALL_INFO, il.Const(4, instr->fields[instr->format->operands[0].field0])));
        il.AddInstruction(il.SystemCall());
        break;
	case armv7::ARMV7_SXTAB:
		il.AddInstruction(WriteArithOperand(il, instr, il.Add(4, ReadILOperand(il, instr, 1), il.SignExtend(4, il.LowPart(1, ReadRotatedOperand(il, instr, 2))))));
		break;
	case armv7::ARMV7_SXTAH:
		il.AddInstruction(WriteArithOperand(il, instr, il.Add(4, ReadILOperand(il, instr, 1), il.SignExtend(4, il.LowPart(2, ReadRotatedOperand(il, instr, 2))))));
		break;
	case armv7::ARMV7_SXTB:
		il.AddInstruction(WriteArithOperand(il, instr, il.SignExtend(4, il.LowPart(1, ReadRotatedOperand(il, instr, 1)))));
		break;
	case armv7::ARMV7_SXTH:
		il.AddInstruction(WriteArithOperand(il, instr, il.SignExtend(4, il.LowPart(2, ReadRotatedOperand(il, instr, 1)))));
		break;
	case armv7::ARMV7_TBB:
		il.AddInstruction(il.Jump(il.Add(4, il.ConstPointer(4, instr->pc), il.Mult(4, il.Const(4, 2),
			il.ZeroExtend(4, il.Load(1, GetMemoryAddress(il, instr, 0, 4, false)))))));
		break;
	case armv7::ARMV7_TBH:
		il.AddInstruction(il.Jump(il.Add(4, il.ConstPointer(4, instr->pc), il.Mult(4, il.Const(4, 2),
			il.ZeroExtend(4, il.Load(2, GetMemoryAddress(il, instr, 0, 4, false)))))));
		break;
	case armv7::ARMV7_TEQ:
		il.AddInstruction(il.Xor(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1), IL_FLAGWRITE_CNZ));
		break;
	case armv7::ARMV7_TST:
		il.AddInstruction(il.And(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1), IL_FLAGWRITE_CNZ));
		break;
	case armv7::ARMV7_UBFX:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.And(4, il.LogicalShiftRight(4, ReadILOperand(il, instr, 1),
												 ReadILOperand(il, instr, 2)),
									 il.Const(4, (1 << instr->fields[instr->format->operands[3].field0]) - 1))));
		break;
	case armv7::ARMV7_UDF:
		il.AddInstruction(il.Trap(instr->fields[instr->format->operands[0].field0]));
		break;
	case armv7::ARMV7_UMLAL:
	{
		uint32_t RdLo = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
		uint32_t RdHi = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
		uint32_t Rm = GetRegisterByIndex(instr->fields[instr->format->operands[2].field0]);
		uint32_t Rn = GetRegisterByIndex(instr->fields[instr->format->operands[3].field0]);

		il.AddInstruction(
			il.SetRegisterSplit(4,
				RdHi, /* hi result */
				RdLo, /* lo result */
				il.Add(8,
					il.MultDoublePrecUnsigned(4, il.Register(4, Rn), il.Register(4, Rm)),
					il.RegisterSplit(4, RdHi, RdLo)
				),
				WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_NZ : 0
			)
		);
		break;
	}
	case armv7::ARMV7_UMULL:
		il.AddInstruction(WriteSplitOperands(il, instr, 1, 0, il.MultDoublePrecUnsigned(8, ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3))));
		break;
	case armv7::ARMV7_SMULL:
		il.AddInstruction(WriteSplitOperands(il, instr, 1, 0, il.MultDoublePrecSigned(8, ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3))));
		break;
	case armv7::ARMV7_SMULBB:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, il.LowPart(2, ReadILOperand(il, instr, 1)),
			il.LowPart(2, ReadILOperand(il, instr, 2)), IL_FLAGWRITE_NONE)));
		break;
	case armv7::ARMV7_SMULBT:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, il.LowPart(2, ReadILOperand(il, instr, 1)),
			il.LowPart(2, il.LogicalShiftRight(4, ReadILOperand(il, instr, 2), il.Const(1, 16))), IL_FLAGWRITE_NONE)));
		break;
	case armv7::ARMV7_SMULTB:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, il.LowPart(2, il.LogicalShiftRight(4, ReadILOperand(il, instr, 1), il.Const(1, 16))),
			il.LowPart(2, ReadILOperand(il, instr, 2)), IL_FLAGWRITE_NONE)));
		break;
	case armv7::ARMV7_SMULTT:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, il.LowPart(2, il.LogicalShiftRight(4, ReadILOperand(il, instr, 1), il.Const(1, 16))),
			il.LowPart(2, il.LogicalShiftRight(4, ReadILOperand(il, instr, 2), il.Const(1, 16))), IL_FLAGWRITE_NONE)));
		break;
	case armv7::ARMV7_UXTAB:
		il.AddInstruction(WriteArithOperand(il, instr,
			il.Add(4,
				ReadILOperand(il, instr, 1),
				il.ZeroExtend(4, il.LowPart(1, ReadRotatedOperand(il, instr, 2))))));
		break;
	case armv7::ARMV7_UXTAH:
		il.AddInstruction(WriteArithOperand(il, instr,
			il.Add(4,
				ReadILOperand(il, instr, 1),
				il.ZeroExtend(4, il.LowPart(2, ReadRotatedOperand(il, instr, 2))))));
		break;
	case armv7::ARMV7_UXTB:
		il.AddInstruction(WriteArithOperand(il, instr, il.ZeroExtend(4, il.LowPart(1, ReadRotatedOperand(il, instr, 1)))));
		break;
	case armv7::ARMV7_UXTH:
		il.AddInstruction(WriteArithOperand(il, instr, il.ZeroExtend(4, il.LowPart(2, ReadRotatedOperand(il, instr, 1)))));
		break;
	case ARMV7_WFE:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_WFE, {}));
		break;
	case ARMV7_WFI:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_WFI, {}));
		break;
	default:
		GetLowLevelILForNEONInstruction(arch, il, instr, ifThenBlock);
		break;
	}
	return true;
}

bool GetLowLevelILForNEONInstruction(Architecture* arch, LowLevelILFunction& il, decomp_result* instr, bool ifThenBlock)
{
	(void)arch;
	(void)ifThenBlock;
	switch (instr->mnem){
	case armv7::ARMV7_VADD:
		il.AddInstruction(WriteArithOperand(il, instr, il.Add(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		break;
	case armv7::ARMV7_VBIF:
		il.AddInstruction(WriteArithOperand(il, instr, il.Or(GetRegisterSize(instr, 0),
			il.And(GetRegisterSize(instr, 0),
				ReadILOperand(il, instr, 0),
				ReadILOperand(il, instr, 2)),
			il.And(GetRegisterSize(instr, 0),
				ReadILOperand(il, instr, 1),
				il.Not(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 2))))
			));
		break;
	case armv7::ARMV7_VBIT:
		il.AddInstruction(WriteArithOperand(il, instr, il.Or(GetRegisterSize(instr, 0),
			il.And(GetRegisterSize(instr, 0),
				ReadILOperand(il, instr, 1),
				ReadILOperand(il, instr, 2)),
			il.And(GetRegisterSize(instr, 0),
				ReadILOperand(il, instr, 0),
				il.Not(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 2))))
			));
		break;
	case armv7::ARMV7_VBSL:
		il.AddInstruction(WriteArithOperand(il, instr, il.Or(GetRegisterSize(instr, 0),
			il.And(GetRegisterSize(instr, 0),
				ReadILOperand(il, instr, 1),
				ReadILOperand(il, instr, 0)),
			il.And(GetRegisterSize(instr, 0),
				ReadILOperand(il, instr, 2),
				il.Not(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 0))))
			));
		break;
	case armv7::ARMV7_VEOR:
		il.AddInstruction(WriteArithOperand(il, instr, il.Xor(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		break;
	case armv7::ARMV7_VSUB:
		il.AddInstruction(WriteArithOperand(il, instr, il.Sub(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		break;
	default:
		il.AddInstruction(il.Unimplemented());
		break;
	}
	return true;
}
