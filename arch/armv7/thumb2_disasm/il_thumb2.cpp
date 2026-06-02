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
static void WriteAddCarryOperand(LowLevelILFunction& il, decomp_result* instr, bool writeFlags);
static void WriteAsrOperand(LowLevelILFunction& il, decomp_result* instr, bool writeFlags);
static ExprId GetMemoryAddress(LowLevelILFunction& il, decomp_result* instr, size_t operand, uint32_t size,
	bool canWriteback = true, uint32_t align = 0);

static uint32_t GetRegisterByIndex(uint32_t i, const char* prefix = "")
{
	if (strcmp(prefix, "s") == 0)
		return REG_S0 + i;
	if (strcmp(prefix, "d") == 0)
		return REG_D0 + i;
	if (strcmp(prefix, "q") == 0)
		return REG_Q0 + (i >> 1);
	return REG_R0 + i;
}

static uint32_t RegisterSizeFromPrefix(const char* prefix = "")
{
	if (strcmp(prefix, "s") == 0)
		return 4;
	if (strcmp(prefix, "d") == 0)
		return 8;
	if (strcmp(prefix, "q") == 0)
		return 16;
	return 4;
}

static ExprId ReadRegister(LowLevelILFunction& il, decomp_result* instr, uint32_t reg, size_t size = 4, const char* prefix = "", uint32_t align=0)
{
	if (reg == armv7::REG_PC && strcmp(prefix, "") == 0)
		return il.ConstPointer(size, instr->pc & (align ? ~(align - 1) : ~0));
	return il.Register(RegisterSizeFromPrefix(prefix), GetRegisterByIndex(reg, prefix));
}

static int GetSpecialRegister(LowLevelILFunction& il, decomp_result* instr, size_t operand)
{
	uint32_t mask = instr->fields[FIELD_mask] & 0xF;

	if (IS_FIELD_PRESENT(instr, FIELD_write_spsr))
	{
		if (instr->fields[FIELD_write_spsr])
			return REGS_SPSR + mask;
		else
			return REGS_CPSR + mask;
	}

	uint32_t tmp = (instr->fields[FIELD_write_nzcvq] << 1) | instr->fields[FIELD_write_g];
	uint8_t sysm = instr->fields[FIELD_SYSm];
	switch (sysm >> 3)
	{
		case 0:
			switch (sysm & 7)
			{
			case 0:
				switch(tmp)
				{
					case 1: return REGS_APSR_G;
					case 2:	return REGS_APSR_NZCVQ;
					case 3: return REGS_APSR_NZCVQG;
					case 0:
					default:
						return REGS_APSR;
				}
			case 1:
				switch(tmp)
				{
					case 1: return REGS_IAPSR_G;
					case 2:	return REGS_IAPSR_NZCVQ;
					case 3: return REGS_IAPSR_NZCVQG;
					case 0:
					default:
						return REGS_IAPSR;
				}
			case 2:
				switch(tmp)
				{
					case 1: return REGS_EAPSR_G;
					case 2:	return REGS_EAPSR_NZCVQ;
					case 3: return REGS_EAPSR_NZCVQG;
					case 0:
					default:
						return REGS_EAPSR;
				}
			case 3:
				switch(tmp)
				{
					case 1: return REGS_XPSR_G;
					case 2:	return REGS_XPSR_NZCVQ;
					case 3: return REGS_XPSR_NZCVQG;
					case 0:
					default:
						return REGS_XPSR;
				}
			case 5:
				return REGS_IPSR;
			case 6:
				return REGS_EPSR;
			case 7:
				return REGS_IEPSR;
			default:
				return REG_INVALID;
			}
			break;
		case 1:
			switch (sysm & 7)
			{
				case 0: return REGS_MSP;
				case 1: return REGS_PSP;
			}
			break;
		case 2:
			switch (sysm & 7)
			{
				case 0: return REGS_PRIMASK;
				case 1: return REGS_BASEPRI;
				case 2: return REGS_BASEPRI_MAX;
				case 3: return REGS_FAULTMASK;
				case 4: return REGS_CONTROL;
			}
			break;
	}

	return REG_INVALID;
}

static int GetVfpStatusRegister(decomp_result* instr, size_t operand)
{
	if (instr->format->operands[operand].type != OPERAND_FORMAT_FPSCR)
		return REG_INVALID;

	switch (instr->fields[FIELD_FPSCR])
	{
	case 0:
		return REGS_FPSID;
	case 1:
		return REGS_FPSCR;
	case 5:
		return REGS_MVFR2;
	case 6:
		return REGS_MVFR1;
	case 7:
		return REGS_MVFR0;
	case 8:
		return REGS_FPEXC;
	case 9:
		return REGS_FPINST;
	case 10:
		return REGS_FPINST2;
	default:
		return REG_INVALID;
	}
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
		if ((instr->mnem == armv7::ARMV7_B) || (instr->mnem == armv7::ARMV7_BL) || (instr->mnem == armv7::ARMV7_CBNZ)
			|| (instr->mnem == armv7::ARMV7_CBZ))
		{
			value += instr->pc;
			return il.ConstPointer(size, value);
		}
		else if ((instr->mnem == armv7::ARMV7_BX) || (instr->mnem == armv7::ARMV7_BLX))
		{
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
		return ReadRegister(il, instr, GetRegisterByIndex(value), size, instr->format->operands[operand].prefix);
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
	return RegisterSizeFromPrefix(instr->format->operands[operand].prefix);
}

static ExprId ReadFloatOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t size)
{
	const instruction_operand_format& op = instr->format->operands[operand];
	switch (op.type)
	{
	case OPERAND_FORMAT_REG_FP:
		return il.Register(size, GetRegisterByIndex(instr->fields[op.field0], op.prefix));
	case OPERAND_FORMAT_ZERO:
		return il.FloatConstRaw(size, 0);
	default:
		return ReadILOperand(il, instr, operand, size);
	}
}

static void FloatCompare(LowLevelILFunction& il, decomp_result* instr)
{
	size_t size = GetRegisterSize(instr, 0);
	ExprId lhs = ReadFloatOperand(il, instr, 0, size);
	ExprId rhs = ReadFloatOperand(il, instr, 1, size);

	il.AddInstruction(il.FloatSub(size, lhs, rhs, IL_FLAGWRITE_FLOAT_COMPARE));
}

static ExprId RoundFloatOperand(LowLevelILFunction& il, decomp_result* instr)
{
	size_t size = GetRegisterSize(instr, 0);
	ExprId src = ReadILOperand(il, instr, 1, size);
	if (strncmp(instr->format->operation, "vrintn", 6) == 0)
		return il.RoundToInt(size, src);
	if (strncmp(instr->format->operation, "vrintp", 6) == 0)
		return il.Ceil(size, src);
	if (strncmp(instr->format->operation, "vrintm", 6) == 0)
		return il.Floor(size, src);
	if (strncmp(instr->format->operation, "vrintz", 6) == 0)
		return il.FloatTrunc(size, src);
	return il.Unimplemented();
}

static ExprId FixedPointScale(LowLevelILFunction& il, size_t size, uint64_t fractionalBits)
{
	double scale = static_cast<double>(UINT64_C(1) << fractionalBits);
	if (size == 8)
		return il.FloatConstDouble(scale);
	return il.FloatConstSingle(static_cast<float>(scale));
}

static bool IsSignedVectorElement(decomp_result* instr)
{
	return IS_FIELD_PRESENT(instr, FIELD_unsigned) && (instr->fields[FIELD_unsigned] == 0);
}

static ExprId ReadVectorElement(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t outputSize)
{
	const instruction_operand_format& op = instr->format->operands[operand];
	size_t elementSize = instr->fields[FIELD_esize] / 8;
	size_t regSize = RegisterSizeFromPrefix(op.prefix);
	size_t shift = instr->fields[op.field1] * elementSize * 8;
	uint32_t reg = GetRegisterByIndex(instr->fields[op.field0], op.prefix);

	ExprId value = il.Register(regSize, reg);
	if (shift != 0)
		value = il.LogicalShiftRight(regSize, value, il.Const(1, shift));
	if (elementSize < regSize)
		value = il.LowPart(elementSize, value);
	if (outputSize > elementSize)
		return IsSignedVectorElement(instr) ? il.SignExtend(outputSize, value) : il.ZeroExtend(outputSize, value);
	return value;
}

static ExprId InsertVectorElement(LowLevelILFunction& il, decomp_result* instr, size_t operand, ExprId src, size_t srcSize)
{
	const instruction_operand_format& op = instr->format->operands[operand];
	size_t elementSize = instr->fields[FIELD_esize] / 8;
	size_t regSize = RegisterSizeFromPrefix(op.prefix);
	size_t shift = instr->fields[op.field1] * elementSize * 8;
	size_t elementBits = elementSize * 8;
	uint64_t elementMask = (elementBits == 64) ? UINT64_MAX : ((1ULL << elementBits) - 1);
	uint64_t shiftedMask = elementMask << shift;
	uint32_t reg = GetRegisterByIndex(instr->fields[op.field0], op.prefix);

	ExprId value = src;
	if (srcSize > elementSize)
		value = il.LowPart(elementSize, value);
	if (regSize > elementSize)
		value = il.ZeroExtend(regSize, value);
	if (shift != 0)
		value = il.ShiftLeft(regSize, value, il.Const(1, shift));

	return il.Or(regSize,
		il.And(regSize, il.Register(regSize, reg), il.Const(regSize, ~shiftedMask)),
		value);
}

static ExprId ReadVst1Element(LowLevelILFunction& il, uint32_t reg, size_t elementSize, size_t index)
{
	size_t shift = index * elementSize * 8;
	ExprId value = il.Register(8, reg);
	if (shift != 0)
		value = il.LogicalShiftRight(8, value, il.Const(1, shift));
	return il.LowPart(elementSize, value);
}

static ExprId InsertVld1Element(LowLevelILFunction& il, uint32_t reg, ExprId src, size_t elementSize, size_t index)
{
	size_t shift = index * elementSize * 8;
	size_t elementBits = elementSize * 8;
	uint64_t elementMask = (elementBits == 64) ? UINT64_MAX : ((1ULL << elementBits) - 1);
	uint64_t shiftedMask = elementMask << shift;

	ExprId value = src;
	if (elementSize < 8)
		value = il.ZeroExtend(8, value);
	if (shift != 0)
		value = il.ShiftLeft(8, value, il.Const(1, shift));

	return il.Or(8,
		il.And(8, il.Register(8, reg), il.Const(8, ~shiftedMask)),
		value);
}

static ExprId ReadShiftedOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t size = 4)
{
	uint32_t shift_t = instr->fields[FIELD_shift_t];
	uint32_t shift_n = instr->fields[FIELD_shift_n];
	ExprId value = ReadILOperand(il, instr, operand, size);

	if (shift_n == 0)
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

static ExprId ReadRotatedOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t size = 4)
{
	uint32_t rot_n = instr->fields[FIELD_rotation];
	ExprId value = ReadILOperand(il, instr, operand, size);

	if (IS_FIELD_PRESENT(instr, FIELD_rotation) && 0 != rot_n)
	{
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

static uint32_t GetRegisterOperand(decomp_result* instr, size_t operand)
{
	uint32_t reg;
	switch (instr->format->operands[operand].type)
	{
		case OPERAND_FORMAT_REG:
			reg = instr->fields[instr->format->operands[operand].field0];
			return GetRegisterByIndex(reg);
		case OPERAND_FORMAT_REG_FP:
			reg = instr->fields[instr->format->operands[operand].field0];
			return GetRegisterByIndex(reg, instr->format->operands[operand].prefix);
		case OPERAND_FORMAT_SP:
			return armv7::REG_SP;
		case OPERAND_FORMAT_LR:
			return armv7::REG_LR;
		case OPERAND_FORMAT_PC:
			return armv7::REG_PC;
		default:
			return armv7::REG_INVALID;
	}
}

static uint32_t GetCrc32Intrinsic(armv7::Operation operation)
{
	switch (operation)
	{
	case armv7::ARMV7_CRC32B:
		return ARMV7_INTRIN_CRC32B;
	case armv7::ARMV7_CRC32CB:
		return ARMV7_INTRIN_CRC32CB;
	case armv7::ARMV7_CRC32CH:
		return ARMV7_INTRIN_CRC32CH;
	case armv7::ARMV7_CRC32CW:
		return ARMV7_INTRIN_CRC32CW;
	case armv7::ARMV7_CRC32H:
		return ARMV7_INTRIN_CRC32H;
	case armv7::ARMV7_CRC32W:
		return ARMV7_INTRIN_CRC32W;
	default:
		return 0;
	}
}

static size_t GetCrc32ValueSize(armv7::Operation operation)
{
	switch (operation)
	{
	case armv7::ARMV7_CRC32B:
	case armv7::ARMV7_CRC32CB:
		return 1;
	case armv7::ARMV7_CRC32H:
	case armv7::ARMV7_CRC32CH:
		return 2;
	case armv7::ARMV7_CRC32W:
	case armv7::ARMV7_CRC32CW:
		return 4;
	default:
		return 0;
	}
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

static void WriteLogicalOperand(LowLevelILFunction& il, decomp_result* instr, bool writeFlags, bool exclusiveOr)
{
	uint32_t flags = writeFlags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE;
	il.AddInstruction(WriteArithOperand(il, instr,
		exclusiveOr
			? il.Xor(4, ReadArithOperand(il, instr, 0), ReadArithOperand(il, instr, 1), flags)
			: il.And(4, ReadArithOperand(il, instr, 0), ReadArithOperand(il, instr, 1), flags)));
}

static void WriteTestOperand(LowLevelILFunction& il, decomp_result* instr)
{
	il.AddInstruction(il.And(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1),
		IL_FLAGWRITE_CNZ));
}

static void WriteTestEquivalenceOperand(LowLevelILFunction& il, decomp_result* instr)
{
	il.AddInstruction(il.Xor(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1),
		IL_FLAGWRITE_CNZ));
}

static void WriteBitClearOperand(LowLevelILFunction& il, decomp_result* instr, bool writeFlags)
{
	il.AddInstruction(WriteArithOperand(il, instr,
		il.And(4, ReadArithOperand(il, instr, 0),
			il.Not(4, ReadArithOperand(il, instr, 1)),
			writeFlags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE)));
}

static void WriteMoveNotOperand(LowLevelILFunction& il, decomp_result* instr, bool writeFlags)
{
	il.AddInstruction(WriteILOperand(il, instr, 0,
		il.Not(4, ReadArithOperand(il, instr, 1), writeFlags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE)));
}

static void WriteOrOperand(LowLevelILFunction& il, decomp_result* instr, bool writeFlags)
{
	il.AddInstruction(WriteArithOperand(il, instr,
		il.Or(4, ReadArithOperand(il, instr, 0), ReadArithOperand(il, instr, 1),
			writeFlags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE)));
}

static void WritePackHalfwordOperand(LowLevelILFunction& il, decomp_result* instr, bool shiftedRmTop)
{
	ExprId rn = ReadILOperand(il, instr, 1);
	ExprId shiftedRm = ReadShiftedOperand(il, instr, 2);
	ExprId result = shiftedRmTop
		? il.Or(4,
			il.And(4, shiftedRm, il.Const(4, 0xffff0000)),
			il.And(4, rn, il.Const(4, 0xffff)))
		: il.Or(4,
			il.And(4, rn, il.Const(4, 0xffff0000)),
			il.And(4, shiftedRm, il.Const(4, 0xffff)));
	il.AddInstruction(WriteILOperand(il, instr, 0, result));
}

static void WriteParallelGEIntrinsic(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)), RegisterOrFlag::Register(REGS_APSR_G) },
		intrinsic,
		{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
}

static void WriteQFlagIntrinsic(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic,
	const std::vector<ExprId>& inputs)
{
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)), RegisterOrFlag::Flag(IL_FLAG_Q) },
		intrinsic,
		inputs));
}

static void WriteSaturatingAddSubOperand(LowLevelILFunction& il, decomp_result* instr, bool subtract)
{
	WriteQFlagIntrinsic(il, instr,
		subtract ? ARMV7_INTRIN_QSUB : ARMV7_INTRIN_QADD,
		{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
}

static void WriteSaturatingDoubleAddSubOperand(LowLevelILFunction& il, decomp_result* instr, bool subtract)
{
	WriteQFlagIntrinsic(il, instr,
		subtract ? ARMV7_INTRIN_QDSUB : ARMV7_INTRIN_QDADD,
		{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
}

static void WriteSignedSaturatingParallelAddSubOperand(LowLevelILFunction& il, decomp_result* instr, size_t elementSize, bool subtract)
{
	uint32_t intrinsic = 0;
	if (elementSize == 2)
		intrinsic = subtract ? ARMV7_INTRIN_QSUB16 : ARMV7_INTRIN_QADD16;
	else
		intrinsic = subtract ? ARMV7_INTRIN_QSUB8 : ARMV7_INTRIN_QADD8;

	WriteQFlagIntrinsic(il, instr,
		intrinsic,
		{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
}

static void WriteUnsignedSaturatingParallelAddSubOperand(LowLevelILFunction& il, decomp_result* instr, size_t elementSize, bool subtract)
{
	uint32_t intrinsic = 0;
	if (elementSize == 2)
		intrinsic = subtract ? ARMV7_INTRIN_UQSUB16 : ARMV7_INTRIN_UQADD16;
	else
		intrinsic = subtract ? ARMV7_INTRIN_UQSUB8 : ARMV7_INTRIN_UQADD8;

	WriteQFlagIntrinsic(il, instr,
		intrinsic,
		{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
}

static void WriteAddCarryOperand(LowLevelILFunction& il, decomp_result* instr, bool writeFlags)
{
	ExprId lhs = ReadArithOperand(il, instr, 0);
	ExprId rhs = ReadArithOperand(il, instr, 1);
	ExprId carry = il.Flag(IL_FLAG_C);
	il.AddInstruction(WriteArithOperand(il, instr,
		il.AddCarry(4, lhs, rhs, carry, writeFlags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE)));
}

static void WriteAsrOperand(LowLevelILFunction& il, decomp_result* instr, bool writeFlags)
{
	ExprId source = ReadArithOperand(il, instr, 0);
	ExprId shift = ReadArithOperand(il, instr, 1);
	il.AddInstruction(WriteArithOperand(il, instr,
		il.ArithShiftRight(4, source, shift, writeFlags ? IL_FLAGWRITE_CNZ : IL_FLAGWRITE_NONE)));
}

static void WriteRorOperand(LowLevelILFunction& il, decomp_result* instr, bool writeFlags)
{
	ExprId source = ReadArithOperand(il, instr, 0);
	ExprId shift = ReadArithOperand(il, instr, 1);
	ExprId shiftAmount = il.And(4, shift, il.Const(4, 0xff));
	il.AddInstruction(WriteArithOperand(il, instr,
		il.RotateRight(4, source, shiftAmount, writeFlags ? IL_FLAGWRITE_CNZ : IL_FLAGWRITE_NONE)));
}

static bool VectorMultiplyAccumulateIntrinsic(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize))
		return false;
	if (IS_FIELD_PRESENT(instr, FIELD_floating_point) && instr->fields[FIELD_floating_point])
		return false;
	if (instr->format->operandCount < 3)
		return false;

	size_t destSize = GetRegisterSize(instr, 0);
	size_t sourceSize = GetRegisterSize(instr, 1);
	if (destSize == 0 || sourceSize == 0)
		return false;

	uint32_t dest = GetRegisterOperand(instr, 0);
	uint32_t source = GetRegisterOperand(instr, 1);
	if (dest == armv7::REG_INVALID || source == armv7::REG_INVALID)
		return false;

	const instruction_operand_format& source2Op = instr->format->operands[2];
	if (!IS_FIELD_PRESENT(instr, source2Op.field0))
		return false;

	uint32_t source2Reg = GetRegisterByIndex(instr->fields[source2Op.field0], source2Op.prefix);
	uint32_t source2Size = RegisterSizeFromPrefix(source2Op.prefix);
	uint32_t source2Index = 0xff;
	if (source2Op.type == OPERAND_FORMAT_REG_INDEX)
	{
		if (!IS_FIELD_PRESENT(instr, source2Op.field1))
			return false;
		source2Index = instr->fields[source2Op.field1];
	}

	std::vector<ExprId> inputs;
	inputs.push_back(il.Const(1, instr->fields[FIELD_esize]));
	if ((intrinsic == ARMV7_INTRIN_VMLAL) || (intrinsic == ARMV7_INTRIN_VMLSL))
		inputs.push_back(il.Const(1,
			IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] ? 1 : 0));
	inputs.push_back(il.Register(destSize, dest));
	inputs.push_back(il.Register(sourceSize, source));
	inputs.push_back(il.Register(source2Size, source2Reg));
	inputs.push_back(il.Const(1, source2Index));
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		inputs));
	return true;
}

static bool VectorMultiplyIntrinsic(LowLevelILFunction& il, decomp_result* instr)
{
	if (instr->format->operandCount < 3)
		return false;

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
		return false;

	size_t source1Size = GetRegisterSize(instr, 1);
	size_t source2Size = GetRegisterSize(instr, 2);
	if (source1Size == 0 || source2Size == 0)
		return false;

	uint32_t elementSize = 0;
	if (IS_FIELD_PRESENT(instr, FIELD_esize))
		elementSize = instr->fields[FIELD_esize];
	else if (IS_FIELD_PRESENT(instr, FIELD_size))
		elementSize = 8 << instr->fields[FIELD_size];
	else
		return false;

	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		ARMV7_INTRIN_VMUL,
		{
			il.Const(1, elementSize),
			il.Const(1, isUnsigned ? 1 : 0),
			ReadILOperand(il, instr, 1, source1Size),
			ReadILOperand(il, instr, 2, source2Size),
		}));
	return true;
}

static bool VectorSaturatingDoublingMultiplyLongIntrinsic(LowLevelILFunction& il, decomp_result* instr)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 3)
		return false;

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
		return false;

	size_t source1Size = GetRegisterSize(instr, 1);
	size_t source2Size = GetRegisterSize(instr, 2);
	if (source1Size == 0 || source2Size == 0)
		return false;

	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		ARMV7_INTRIN_VQDMULL,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, isUnsigned ? 1 : 0),
			ReadILOperand(il, instr, 1, source1Size),
			ReadILOperand(il, instr, 2, source2Size),
		}));
	return true;
}

static void VectorTableLookup(LowLevelILFunction& il, decomp_result* instr)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_length) || !IS_FIELD_PRESENT(instr, FIELD_n)
		|| !IS_FIELD_PRESENT(instr, FIELD_is_vtbl))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	uint32_t indices = GetRegisterOperand(instr, 2);
	if (dest == armv7::REG_INVALID || indices == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t length = instr->fields[FIELD_length];
	uint32_t tableStart = instr->fields[FIELD_n];
	std::vector<ExprId> inputs;
	inputs.push_back(il.Const(1, length));
	for (uint32_t i = 0; i < 4; i++)
	{
		if (i < length)
			inputs.push_back(il.Register(8, GetRegisterByIndex(tableStart + i, "d")));
		else
			inputs.push_back(il.Const(8, 0));
	}
	inputs.push_back(il.Register(8, indices));

	bool isVtbl = instr->fields[FIELD_is_vtbl] != 0;
	if (!isVtbl)
		inputs.push_back(il.Register(8, dest));

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		isVtbl ? ARMV7_INTRIN_VTBL : ARMV7_INTRIN_VTBX,
		inputs));
}

static void VectorShiftLeft(LowLevelILFunction& il, decomp_result* instr)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	uint32_t source = GetRegisterOperand(instr, 1);
	if (dest == armv7::REG_INVALID || source == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	size_t elementSize = instr->fields[FIELD_esize] / 8;
	if (regSize == 0 || elementSize == 0 || elementSize > regSize || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	if (instr->format->operands[2].type == OPERAND_FORMAT_IMM)
	{
		uint64_t shift = instr->fields[instr->format->operands[2].field0];
		if (elementSize == regSize)
		{
			il.AddInstruction(WriteILOperand(il, instr, 0,
				il.ShiftLeft(regSize, il.Register(regSize, source), il.Const(1, shift)), regSize));
			return;
		}

		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(dest) },
			ARMV7_INTRIN_VSHL,
			{
				il.Const(1, instr->fields[FIELD_esize]),
				il.Const(1, (IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned]) ? 1 : 0),
				ReadILOperand(il, instr, 1, regSize),
				il.Const(regSize, shift),
			}));
		return;
	}

	if (!IS_FIELD_PRESENT(instr, FIELD_unsigned))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		ARMV7_INTRIN_VSHL,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, instr->fields[FIELD_unsigned] ? 1 : 0),
			ReadILOperand(il, instr, 1, regSize),
			ReadILOperand(il, instr, 2, regSize),
		}));
}

static void VectorShiftRight(LowLevelILFunction& il, decomp_result* instr)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || (!IS_FIELD_PRESENT(instr, FIELD_unsigned) && !IS_FIELD_PRESENT(instr, FIELD_type)))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID || GetRegisterOperand(instr, 1) == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	size_t elementSize = instr->fields[FIELD_esize] / 8;
	if (regSize == 0 || elementSize == 0 || elementSize > regSize || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint64_t shift = instr->fields[instr->format->operands[2].field0];
	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned)
		? instr->fields[FIELD_unsigned] != 0
		: instr->fields[FIELD_type] != 2;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		ARMV7_INTRIN_VSHR,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, isUnsigned ? 1 : 0),
			ReadILOperand(il, instr, 1, regSize),
			il.Const(regSize, shift),
		}));
}

static void VectorBitSelect(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	if (regSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Register(regSize, dest),
			ReadILOperand(il, instr, 1, regSize),
			ReadILOperand(il, instr, 2, regSize),
		}));
}

static void RoundedVectorShift(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	if (regSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned)
		? instr->fields[FIELD_unsigned] != 0
		: IS_FIELD_PRESENT(instr, FIELD_type) && instr->fields[FIELD_type] != 2;
	ExprId shift = instr->format->operands[2].type == OPERAND_FORMAT_IMM
		? il.Const(regSize, instr->fields[instr->format->operands[2].field0])
		: ReadILOperand(il, instr, 2, regSize);

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, isUnsigned ? 1 : 0),
			ReadILOperand(il, instr, 1, regSize),
			shift,
		}));
}

static void ShiftRightAccumulateOrInsert(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	if (regSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	ExprId shift = instr->format->operands[2].type == OPERAND_FORMAT_IMM
		? il.Const(regSize, instr->fields[instr->format->operands[2].field0])
		: ReadILOperand(il, instr, 2, regSize);

	if (intrinsic == ARMV7_INTRIN_VSRA || intrinsic == ARMV7_INTRIN_VRSRA)
	{
		bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned)
			? instr->fields[FIELD_unsigned] != 0
			: IS_FIELD_PRESENT(instr, FIELD_type) && instr->fields[FIELD_type] != 2;
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(dest) },
			intrinsic,
			{
				il.Const(1, instr->fields[FIELD_esize]),
				il.Const(1, isUnsigned ? 1 : 0),
				il.Register(regSize, dest),
				ReadILOperand(il, instr, 1, regSize),
				shift,
			}));
		return;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Register(regSize, dest),
			ReadILOperand(il, instr, 1, regSize),
			shift,
		}));
}

static void VectorDuplicate(LowLevelILFunction& il, decomp_result* instr)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 2)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	const instruction_operand_format& sourceOp = instr->format->operands[1];
	uint32_t source = armv7::REG_INVALID;
	size_t sourceSize = 0;
	uint32_t index = 0;
	if (sourceOp.type == OPERAND_FORMAT_REG)
	{
		source = GetRegisterByIndex(instr->fields[sourceOp.field0]);
		sourceSize = GetRegisterSize(instr, 1);
	}
	else if (sourceOp.type == OPERAND_FORMAT_REG_INDEX)
	{
		source = GetRegisterByIndex(instr->fields[sourceOp.field0], sourceOp.prefix);
		sourceSize = RegisterSizeFromPrefix(sourceOp.prefix);
		index = instr->fields[sourceOp.field1];
	}

	if (source == armv7::REG_INVALID || sourceSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		ARMV7_INTRIN_VDUP,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Register(sourceSize, source),
			il.Const(1, index),
		}));
}

static void SaturatingVectorAdd(LowLevelILFunction& il, decomp_result* instr)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	if (regSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		ARMV7_INTRIN_VQADD,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, isUnsigned ? 1 : 0),
			ReadILOperand(il, instr, 1, regSize),
			ReadILOperand(il, instr, 2, regSize),
		}));
}

static void VectorAddSubtract(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	if (regSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, IsSignedVectorElement(instr) ? 0 : 1),
			ReadILOperand(il, instr, 1, regSize),
			ReadILOperand(il, instr, 2, regSize),
		}));
}

static void VectorMaximumMinimum(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	if (regSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, isUnsigned ? 1 : 0),
			ReadILOperand(il, instr, 1, regSize),
			ReadILOperand(il, instr, 2, regSize),
		}));
}

static void VectorReverse(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 2)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t sourceSize = GetRegisterSize(instr, 1);
	if (sourceSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			ReadILOperand(il, instr, 1, sourceSize),
		}));
}

static void VectorExtract(LowLevelILFunction& il, decomp_result* instr)
{
	if (instr->format->operandCount < 4)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t source1Size = GetRegisterSize(instr, 1);
	size_t source2Size = GetRegisterSize(instr, 2);
	if (source1Size == 0 || source2Size == 0 || !IS_FIELD_PRESENT(instr, FIELD_imm))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		ARMV7_INTRIN_VEXT,
		{
			il.Const(1, 8),
			ReadILOperand(il, instr, 1, source1Size),
			ReadILOperand(il, instr, 2, source2Size),
			il.Const(1, instr->fields[FIELD_imm]),
		}));
}

static void VectorAbsoluteDifferenceAccumulate(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t destSize = GetRegisterSize(instr, 0);
	size_t source1Size = GetRegisterSize(instr, 1);
	size_t source2Size = GetRegisterSize(instr, 2);
	if (destSize == 0 || source1Size == 0 || source2Size == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t elementSize = 0;
	if (IS_FIELD_PRESENT(instr, FIELD_size))
		elementSize = 8 << instr->fields[FIELD_size];
	else if (IS_FIELD_PRESENT(instr, FIELD_esize))
		elementSize = instr->fields[FIELD_esize];
	else
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, elementSize),
			il.Const(1, isUnsigned ? 1 : 0),
			il.Register(destSize, dest),
			ReadILOperand(il, instr, 1, source1Size),
			ReadILOperand(il, instr, 2, source2Size),
		}));
}

static void VectorAbsoluteDifference(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t source1Size = GetRegisterSize(instr, 1);
	size_t source2Size = GetRegisterSize(instr, 2);
	if (source1Size == 0 || source2Size == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t elementSize = 0;
	if (IS_FIELD_PRESENT(instr, FIELD_size))
		elementSize = 8 << instr->fields[FIELD_size];
	else if (IS_FIELD_PRESENT(instr, FIELD_esize))
		elementSize = instr->fields[FIELD_esize];
	else
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, elementSize),
			il.Const(1, isUnsigned ? 1 : 0),
			ReadILOperand(il, instr, 1, source1Size),
			ReadILOperand(il, instr, 2, source2Size),
		}));
}

static void VectorWideningAdd(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t source1Size = GetRegisterSize(instr, 1);
	size_t source2Size = GetRegisterSize(instr, 2);
	if (source1Size == 0 || source2Size == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	if (instr->format->operands[1].type == OPERAND_FORMAT_REG_FP &&
		strcmp(instr->format->operands[1].prefix, "q") == 0)
		intrinsic = ARMV7_INTRIN_VADDW;

	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, isUnsigned ? 1 : 0),
			ReadILOperand(il, instr, 1, source1Size),
			ReadILOperand(il, instr, 2, source2Size),
		}));
}

static void VectorRoundingAddNarrow(LowLevelILFunction& il, decomp_result* instr)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t source1Size = GetRegisterSize(instr, 1);
	size_t source2Size = GetRegisterSize(instr, 2);
	if (source1Size == 0 || source2Size == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		ARMV7_INTRIN_VRADDHN,
		{
			il.Const(1, instr->fields[FIELD_esize] * 2),
			ReadILOperand(il, instr, 1, source1Size),
			ReadILOperand(il, instr, 2, source2Size),
		}));
}

static void SaturatingVectorShiftLeft(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	bool sourceUnsigned = IS_FIELD_PRESENT(instr, FIELD_src_unsigned)
		? instr->fields[FIELD_src_unsigned] != 0
		: IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	bool destinationUnsigned = IS_FIELD_PRESENT(instr, FIELD_dest_unsigned)
		? instr->fields[FIELD_dest_unsigned] != 0
		: IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	ExprId shift = instr->format->operands[2].type == OPERAND_FORMAT_IMM
		? il.Const(regSize, instr->fields[instr->format->operands[2].field0])
		: ReadILOperand(il, instr, 2, regSize);

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, sourceUnsigned ? 1 : 0),
			il.Const(1, destinationUnsigned ? 1 : 0),
			ReadILOperand(il, instr, 1, regSize),
			shift,
		}));
}

static void VectorShiftLeftLong(LowLevelILFunction& il, decomp_result* instr)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t sourceSize = GetRegisterSize(instr, 1);
	if (sourceSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	ExprId shift = instr->format->operands[2].type == OPERAND_FORMAT_IMM
		? il.Const(sourceSize, instr->fields[instr->format->operands[2].field0])
		: ReadILOperand(il, instr, 2, sourceSize);

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		ARMV7_INTRIN_VSHLL,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, isUnsigned ? 1 : 0),
			ReadILOperand(il, instr, 1, sourceSize),
			shift,
		}));
}

static void SaturatingVectorShiftRightNarrow(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || !IS_FIELD_PRESENT(instr, FIELD_src_unsigned)
		|| !IS_FIELD_PRESENT(instr, FIELD_dest_unsigned) || instr->format->operandCount < 3)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t sourceSize = GetRegisterSize(instr, 1);
	if (sourceSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	ExprId shift = instr->format->operands[2].type == OPERAND_FORMAT_IMM
		? il.Const(sourceSize, instr->fields[instr->format->operands[2].field0])
		: ReadILOperand(il, instr, 2, sourceSize);
	if (intrinsic == 0)
	{
		intrinsic = (instr->fields[FIELD_dest_unsigned] && !instr->fields[FIELD_src_unsigned])
			? ARMV7_INTRIN_VQSHRUN
			: ARMV7_INTRIN_VQSHRN;
	}
	if (intrinsic == static_cast<uint32_t>(-1))
	{
		intrinsic = (instr->fields[FIELD_dest_unsigned] && !instr->fields[FIELD_src_unsigned])
			? ARMV7_INTRIN_VQRSHRUN
			: ARMV7_INTRIN_VQRSHRN;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, instr->fields[FIELD_esize] * 2),
			il.Const(1, instr->fields[FIELD_src_unsigned] ? 1 : 0),
			il.Const(1, instr->fields[FIELD_dest_unsigned] ? 1 : 0),
			ReadILOperand(il, instr, 1, sourceSize),
			shift,
		}));
}

static void SaturatingVectorMoveNarrow(LowLevelILFunction& il, decomp_result* instr)
{
	if (!IS_FIELD_PRESENT(instr, FIELD_esize) || !IS_FIELD_PRESENT(instr, FIELD_src_unsigned)
		|| !IS_FIELD_PRESENT(instr, FIELD_dest_unsigned) || instr->format->operandCount < 2)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t dest = GetRegisterOperand(instr, 0);
	if (dest == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t sourceSize = GetRegisterSize(instr, 1);
	if (sourceSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t intrinsic = (instr->fields[FIELD_dest_unsigned] && !instr->fields[FIELD_src_unsigned])
		? ARMV7_INTRIN_VQMOVUN
		: ARMV7_INTRIN_VQMOVN;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest) },
		intrinsic,
		{
			il.Const(1, instr->fields[FIELD_esize] * 2),
			il.Const(1, instr->fields[FIELD_src_unsigned] ? 1 : 0),
			il.Const(1, instr->fields[FIELD_dest_unsigned] ? 1 : 0),
			ReadILOperand(il, instr, 1, sourceSize),
		}));
}

static void HalvingVectorAdd(LowLevelILFunction& il, decomp_result* instr)
{
	if (instr->format->operandCount < 3 || !IS_FIELD_PRESENT(instr, FIELD_esize))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	size_t elementSize = instr->fields[FIELD_esize] / 8;
	if (regSize == 0 || elementSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t source1 = GetRegisterOperand(instr, 1);
	uint32_t source2 = GetRegisterOperand(instr, 2);
	if (source1 == armv7::REG_INVALID || source2 == armv7::REG_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
		ARMV7_INTRIN_VHADD,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, IsSignedVectorElement(instr) ? 0 : 1),
			il.Register(GetRegisterSize(instr, 1), source1),
			il.Register(GetRegisterSize(instr, 2), source2),
		}));
}

static void VectorCompareEqual(LowLevelILFunction& il, decomp_result* instr)
{
	if (instr->format->operandCount < 3 || !IS_FIELD_PRESENT(instr, FIELD_esize))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	size_t elementSize = instr->fields[FIELD_esize] / 8;
	if (regSize == 0 || elementSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	ExprId rhs;
	if (instr->format->operands[2].type == OPERAND_FORMAT_ZERO)
	{
		rhs = il.Const(regSize, 0);
	}
	else
	{
		size_t rhsSize = GetRegisterSize(instr, 2);
		if (rhsSize == 0)
		{
			il.AddInstruction(il.Unimplemented());
			return;
		}
		rhs = il.Register(rhsSize, GetRegisterOperand(instr, 2));
	}

	bool isFloat = instr->format->operationFlags & INSTR_FORMAT_FLAG_F32;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
		ARMV7_INTRIN_VCEQ,
		{
			il.Const(1, instr->fields[FIELD_esize]),
			il.Const(1, isFloat ? 1 : 0),
			il.Register(GetRegisterSize(instr, 1), GetRegisterOperand(instr, 1)),
			rhs,
		}));
}

static void VectorCompareGreaterThan(LowLevelILFunction& il, decomp_result* instr)
{
	if (instr->format->operandCount < 3 || !IS_FIELD_PRESENT(instr, FIELD_esize))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	size_t regSize = GetRegisterSize(instr, 0);
	size_t elementSize = instr->fields[FIELD_esize] / 8;
	if (regSize == 0 || elementSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	ExprId rhs;
	if (instr->format->operands[2].type == OPERAND_FORMAT_ZERO)
	{
		rhs = il.Const(regSize, 0);
	}
	else
	{
		size_t rhsSize = GetRegisterSize(instr, 2);
		if (rhsSize == 0)
		{
			il.AddInstruction(il.Unimplemented());
			return;
		}
		rhs = il.Register(rhsSize, GetRegisterOperand(instr, 2));
	}

	bool isUnsigned = IS_FIELD_PRESENT(instr, FIELD_unsigned) && instr->fields[FIELD_unsigned] != 0;
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
		ARMV7_INTRIN_VCGT,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, isUnsigned ? 1 : 0),
			il.Register(GetRegisterSize(instr, 1), GetRegisterOperand(instr, 1)),
			rhs,
		}));
}

static ExprId ReadSignedHalfwordOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, bool top)
{
	if (top)
		return il.ArithShiftRight(4, ReadILOperand(il, instr, operand), il.Const(1, 16));
	return il.SignExtend(4, il.LowPart(2, ReadILOperand(il, instr, operand)));
}

static ExprId SignedHalfProduct32(LowLevelILFunction& il, ExprId lhs, ExprId rhs)
{
	return il.LowPart(4, il.Mult(4, lhs, rhs));
}

static ExprId SignedWordHalfProduct64(LowLevelILFunction& il, ExprId word, ExprId halfword)
{
	return il.Mult(8, il.SignExtend(8, word), il.SignExtend(8, halfword));
}

static void WriteSignedLongHalfwordMultiplyAccumulateOperand(LowLevelILFunction& il, decomp_result* instr, bool nTop, bool mTop)
{
	ExprId source1 = nTop
		? il.ArithShiftRight(4, ReadILOperand(il, instr, 2), il.Const(1, 16))
		: il.SignExtend(4, il.LowPart(2, ReadILOperand(il, instr, 2)));
	ExprId source2 = mTop
		? il.ArithShiftRight(4, ReadILOperand(il, instr, 3), il.Const(1, 16))
		: il.SignExtend(4, il.LowPart(2, ReadILOperand(il, instr, 3)));
	ExprId product = il.Mult(4, source1, source2);

	il.AddInstruction(il.SetRegisterSplit(4, GetRegisterOperand(instr, 1), GetRegisterOperand(instr, 0),
		il.Add(8,
			il.SignExtend(8, product),
			il.RegisterSplit(4,
				GetRegisterOperand(instr, 1),
				GetRegisterOperand(instr, 0)))));
}

static void WriteSignedWordHalfwordMultiplyOperand(LowLevelILFunction& il, decomp_result* instr, bool mTop, bool accumulate)
{
	ExprId product = SignedWordHalfProduct64(il,
		ReadILOperand(il, instr, 1),
		mTop
			? il.ArithShiftRight(4, ReadILOperand(il, instr, 2), il.Const(1, 16))
			: il.SignExtend(4, il.LowPart(2, ReadILOperand(il, instr, 2))));

	if (!accumulate)
	{
		il.AddInstruction(WriteILOperand(il, instr, 0,
			il.LowPart(4, il.ArithShiftRight(8, product, il.Const(1, 16)))));
		return;
	}

	il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
		il.Add(8,
				product,
				il.ShiftLeft(8,
					il.SignExtend(8, ReadILOperand(il, instr, 3)),
					il.Const(1, 16)))));
	il.AddInstruction(WriteILOperand(il, instr, 0,
		il.And(4,
			il.ArithShiftRight(8,
				il.Register(8, LLIL_TEMP(0)),
				il.Const(1, 16)),
			il.Const(4, 0xffffffff))));
}

static ExprId WriteSplitOperands(LowLevelILFunction& il, decomp_result *instr, size_t operandHi, size_t operandLo, ExprId value,
	size_t size = 4, uint32_t flags = 0)
{
	uint32_t regHi = instr->fields[instr->format->operands[operandHi].field0];
	uint32_t regLo = instr->fields[instr->format->operands[operandLo].field0];

	return il.SetRegisterSplit(size, GetRegisterByIndex(regHi), GetRegisterByIndex(regLo), value, flags);
}

static void VfpLoadStoreMultiple(LowLevelILFunction& il, decomp_result* instr, bool load)
{
	const char* prefix = (IS_FIELD_PRESENT(instr, FIELD_single_regs) && instr->fields[FIELD_single_regs]) ? "s" : "d";
	size_t regSize = RegisterSizeFromPrefix(prefix);
	uint32_t baseReg = GetRegisterOperand(instr, 0);
	uint32_t d = instr->fields[FIELD_d];
	uint32_t inc = IS_FIELD_PRESENT(instr, FIELD_inc) ? instr->fields[FIELD_inc] : 1;
	uint32_t regs = instr->fields[FIELD_regs];
	bool increment = IS_FIELD_PRESENT(instr, FIELD_add) ? instr->fields[FIELD_add] != 0
		: ((instr->mnem == armv7::ARMV7_VLDMIA) || (instr->mnem == armv7::ARMV7_VSTMIA));
	size_t totalSize = regs * regSize;

	ExprId base = il.Register(4, baseReg);
	ExprId start = increment ? base : il.Sub(4, base, il.Const(4, totalSize));
	for (uint32_t i = 0; i < regs; ++i)
	{
		if (d + (i * inc) >= 32 && strcmp(prefix, "s") == 0)
			break;
		if (i >= 16 && strcmp(prefix, "d") == 0)
			break;

		uint32_t reg = GetRegisterByIndex((d + i * inc) % 32, prefix);
		ExprId address = i == 0 ? start : il.Add(4, start, il.Const(4, i * regSize));
		if (load)
			il.AddInstruction(il.SetRegister(regSize, reg, il.Load(regSize, address)));
		else
			il.AddInstruction(il.Store(regSize, address, il.Register(regSize, reg)));
	}

	if (IS_FIELD_PRESENT(instr, FIELD_wback) && instr->fields[FIELD_wback])
	{
		ExprId value = increment ? il.Add(4, base, il.Const(4, totalSize)) : il.Sub(4, base, il.Const(4, totalSize));
		il.AddInstruction(il.SetRegister(4, baseReg, value));
	}
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

static bool HasNeonLoadStoreWriteback(decomp_result* instr, size_t operand)
{
	return HasWriteback(instr, operand) || (IS_FIELD_PRESENT(instr, FIELD_wback) && instr->fields[FIELD_wback]);
}

static void StructuredVectorStoreIntrinsic(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic,
	size_t structureCount)
{
	ExprId base = GetMemoryAddress(il, instr, 1, 4, false);
	ExprId sources[4] = {il.Const(8, 0), il.Const(8, 0), il.Const(8, 0), il.Const(8, 0)};
	size_t elementSize = instr->fields[FIELD_ebytes];
	unsigned int d = instr->fields[FIELD_d];
	unsigned int inc = IS_FIELD_PRESENT(instr, FIELD_inc) ? instr->fields[FIELD_inc] : 1;
	bool indexed = instr->format->operands[0].type == OPERAND_FORMAT_REGISTERS_INDEXED;
	size_t sourceRegCount = structureCount;

	if (instr->format->operands[0].type == OPERAND_FORMAT_REGISTERS)
	{
		if (IS_FIELD_PRESENT(instr, FIELD_regs))
			sourceRegCount = instr->fields[FIELD_regs];
	}
	else if (!indexed)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	if ((structureCount == 4 && sourceRegCount != 4) ||
		(structureCount == 2 && sourceRegCount != 2 && sourceRegCount != 4) || elementSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	for (size_t i = 0; i < sourceRegCount && i < 4; ++i)
	{
		int regIdx = (d + i * inc) % 32;
		sources[i] = il.Register(8, GetRegisterByIndex(regIdx, "d"));
	}

	il.AddInstruction(il.Intrinsic({}, intrinsic, {
		base,
		il.Const(1, elementSize * 8),
		il.Const(1, IS_FIELD_PRESENT(instr, FIELD_alignment) ? instr->fields[FIELD_alignment] : 0),
		il.Const(1, indexed ? instr->fields[FIELD_index] : 0xff),
		sources[0],
		sources[1],
		sources[2],
		sources[3],
	}));

	if (HasNeonLoadStoreWriteback(instr, 1))
	{
		size_t totalSize = indexed ? structureCount * elementSize : sourceRegCount * 8;
		uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
		if (IS_FIELD_PRESENT(instr, FIELD_register_index) && instr->fields[FIELD_register_index])
		{
			uint32_t indexReg = GetRegisterByIndex(instr->fields[FIELD_m]);
			il.AddInstruction(il.SetRegister(4, baseReg,
				il.Add(4, il.Register(4, baseReg), il.Register(4, indexReg))));
		}
		else
		{
			il.AddInstruction(il.SetRegister(4, baseReg,
				il.Add(4, il.Register(4, baseReg), il.Const(4, totalSize))));
		}
	}
}

static void StructuredVectorLoadIntrinsic(LowLevelILFunction& il, decomp_result* instr, uint32_t intrinsic,
	size_t structureCount)
{
	ExprId base = GetMemoryAddress(il, instr, 1, 4, false);
	std::vector<RegisterOrFlag> outputs;
	size_t elementSize = 0;
	if (IS_FIELD_PRESENT(instr, FIELD_ebytes))
		elementSize = instr->fields[FIELD_ebytes];
	else if (IS_FIELD_PRESENT(instr, FIELD_size))
		elementSize = 1 << instr->fields[FIELD_size];
	unsigned int d = instr->fields[FIELD_d];
	unsigned int inc = IS_FIELD_PRESENT(instr, FIELD_inc) ? instr->fields[FIELD_inc] : 1;
	bool indexed = instr->format->operands[0].type == OPERAND_FORMAT_REGISTERS_INDEXED;
	size_t outputRegCount = structureCount;

	if (instr->format->operands[0].type == OPERAND_FORMAT_REGISTERS)
	{
		if (IS_FIELD_PRESENT(instr, FIELD_regs_n))
			outputRegCount = instr->fields[FIELD_regs_n];
		else if (IS_FIELD_PRESENT(instr, FIELD_regs))
			outputRegCount = instr->fields[FIELD_regs];
	}
	else if (!indexed)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	if ((structureCount == 4 && outputRegCount != 4) ||
		(structureCount == 2 && outputRegCount != 2 && outputRegCount != 4) || elementSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	for (size_t i = 0; i < outputRegCount && i < 4; ++i)
	{
		int regIdx = (d + i * inc) % 32;
		outputs.push_back(RegisterOrFlag::Register(GetRegisterByIndex(regIdx, "d")));
	}

	il.AddInstruction(il.Intrinsic(outputs, intrinsic, {
		base,
		il.Const(1, elementSize * 8),
		il.Const(1, IS_FIELD_PRESENT(instr, FIELD_alignment) ? instr->fields[FIELD_alignment] : 0),
		il.Const(1, indexed ? instr->fields[FIELD_index] : 0xff),
	}));

	if (HasNeonLoadStoreWriteback(instr, 1))
	{
		size_t totalSize = indexed ? structureCount * elementSize : outputRegCount * 8;
		uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
		bool registerIndex = IS_FIELD_PRESENT(instr, FIELD_register_index) && instr->fields[FIELD_register_index];
		if (!IS_FIELD_PRESENT(instr, FIELD_register_index) && IS_FIELD_PRESENT(instr, FIELD_Rm))
			registerIndex = instr->fields[FIELD_Rm] != 15 && instr->fields[FIELD_Rm] != 13;
		if (registerIndex)
		{
			uint32_t indexReg = GetRegisterByIndex(IS_FIELD_PRESENT(instr, FIELD_m)
				? instr->fields[FIELD_m] : instr->fields[FIELD_Rm]);
			il.AddInstruction(il.SetRegister(4, baseReg,
				il.Add(4, il.Register(4, baseReg), il.Register(4, indexReg))));
		}
		else
		{
			il.AddInstruction(il.SetRegister(4, baseReg,
				il.Add(4, il.Register(4, baseReg), il.Const(4, totalSize))));
		}
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

#define ReadRegisterA(il, instr, reg, align) ReadRegister(il, instr, reg, 4, "", align)
static ExprId GetMemoryAddress(LowLevelILFunction& il, decomp_result* instr, size_t operand, uint32_t size,
	bool canWriteback, uint32_t align)
{
	uint32_t reg, second, t, n;
	switch (instr->format->operands[operand].type)
	{
	case OPERAND_FORMAT_MEMORY_ONE_REG_ALIGNED:
	case OPERAND_FORMAT_MEMORY_ONE_REG:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		return il.Register(4, reg);
	case OPERAND_FORMAT_MEMORY_ONE_REG_IMM:
	case OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = instr->fields[instr->format->operands[operand].field1];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_ONE_REG_NEG_IMM:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = instr->fields[instr->format->operands[operand].field1];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Sub(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second))));
			return il.Register(4, reg);
		}
		return il.Sub(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_ONE_REG_ADD_IMM:
	case OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_ADD_IMM:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = instr->fields[instr->format->operands[operand].field1];
		if (canWriteback && HasWriteback(instr, operand))
		{
			if (instr->fields[FIELD_add])
				il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second))));
			else
				il.AddInstruction(il.SetRegister(4, reg, il.Sub(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second))));
			return il.Register(4, reg);
		}
		if (instr->fields[FIELD_add])
			return il.Add(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second));
		return il.Sub(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_TWO_REG:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field1]);
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegisterA(il, instr, reg, align), il.Register(4, second))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegisterA(il, instr, reg, align), il.Register(4, second));
	case OPERAND_FORMAT_MEMORY_TWO_REG_SHIFT:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field1]);
		t = instr->fields[FIELD_shift_t];
		n = instr->fields[FIELD_shift_n];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegisterA(il, instr, reg, align),
				ShiftedRegister(il, instr, second, t, n))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegisterA(il, instr, reg, align), ShiftedRegister(il, instr, second, t, n));
	case OPERAND_FORMAT_MEMORY_TWO_REG_LSL_ONE:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field1]);
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegisterA(il, instr, reg, align),
				il.ShiftLeft(4, ReadRegister(il, instr, second), il.Const(4, 1)))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegisterA(il, instr, reg, align), il.ShiftLeft(4, ReadRegister(il, instr, second), il.Const(4, 1)));
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
		return il.ConstPointer(4, instr->pc & (align ? ~(align - 1) : ~0));
	case OPERAND_FORMAT_LABEL:
		if (instr->fields[FIELD_add])
			return il.ConstPointer(4, ALIGN4(instr->pc) + instr->fields[FIELD_imm32]);
		return il.ConstPointer(4, ALIGN4(instr->pc) - instr->fields[FIELD_imm32]);
	default:
		return il.Unimplemented();
	}
}

static void AddCoprocStoreIL(LowLevelILFunction& il, decomp_result* instr)
{
	const size_t memOperand = 2;
	bool longTransfer = (instr->mnem == armv7::ARMV7_STCL) || (instr->mnem == armv7::ARMV7_STC2L);
	ExprId address = GetMemoryAddress(il, instr, memOperand, 4, false);

	il.AddInstruction(il.Intrinsic({ },
		ARMV7_INTRIN_COPROC_STORE,
		{
			address,
			il.Const(1, instr->fields[instr->format->operands[0].field0]),
			il.Const(1, instr->fields[instr->format->operands[1].field0]),
			il.Const(1, longTransfer ? 1 : 0),
		}));

	if (HasWriteback(instr, memOperand))
	{
		GetMemoryAddress(il, instr, memOperand, 4, true);
		return;
	}

	if ((instr->format->operandCount > 3)
		&& ((instr->format->operands[3].type == OPERAND_FORMAT_ADD_IMM)
			|| (instr->format->operands[3].type == OPERAND_FORMAT_OPTIONAL_ADD_IMM)))
	{
		uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[memOperand].field0]);
		il.AddInstruction(il.SetRegister(4, baseReg,
			il.Add(4, il.Register(4, baseReg), ReadILOperand(il, instr, 3))));
		return;
	}

	if ((instr->format->operandCount > 3)
		&& (instr->format->operands[3].type == OPERAND_FORMAT_IMM)
		&& (strcmp(instr->format->operands[3].prefix, "#") == 0)
		&& IS_FIELD_PRESENT(instr, FIELD_imm32))
	{
		uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[memOperand].field0]);
		ExprId offset = il.Const(4, instr->fields[FIELD_imm32]);
		ExprId value = instr->fields[FIELD_add] ? il.Add(4, il.Register(4, baseReg), offset)
			: il.Sub(4, il.Register(4, baseReg), offset);
		il.AddInstruction(il.SetRegister(4, baseReg, value));
	}
}

static void AddCoprocLoadIL(LowLevelILFunction& il, decomp_result* instr)
{
	const size_t memOperand = 2;
	bool longTransfer = (instr->mnem == armv7::ARMV7_LDCL) || (instr->mnem == armv7::ARMV7_LDC2L);
	ExprId address = GetMemoryAddress(il, instr, memOperand, 4, false);

	il.AddInstruction(il.Intrinsic({ },
		ARMV7_INTRIN_COPROC_LOAD,
		{
			address,
			il.Const(1, instr->fields[instr->format->operands[0].field0]),
			il.Const(1, instr->fields[instr->format->operands[1].field0]),
			il.Const(1, longTransfer ? 1 : 0),
		}));

	if (HasWriteback(instr, memOperand))
	{
		GetMemoryAddress(il, instr, memOperand, 4, true);
		return;
	}

	if ((instr->format->operandCount > 3)
		&& ((instr->format->operands[3].type == OPERAND_FORMAT_ADD_IMM)
			|| (instr->format->operands[3].type == OPERAND_FORMAT_OPTIONAL_ADD_IMM)))
	{
		uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[memOperand].field0]);
		il.AddInstruction(il.SetRegister(4, baseReg,
			il.Add(4, il.Register(4, baseReg), ReadILOperand(il, instr, 3))));
		return;
	}

	if ((instr->format->operandCount > 3)
		&& (instr->format->operands[3].type == OPERAND_FORMAT_IMM)
		&& (strcmp(instr->format->operands[3].prefix, "#") == 0))
	{
		uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[memOperand].field0]);
		uint32_t offset = instr->fields[instr->format->operands[3].field0] << 2;
		ExprId value = instr->fields[FIELD_add]
			? il.Add(4, il.Register(4, baseReg), il.Const(4, offset))
			: il.Sub(4, il.Register(4, baseReg), il.Const(4, offset));
		il.AddInstruction(il.SetRegister(4, baseReg, value));
	}
}


ExprId GetCondition(LowLevelILFunction& il, uint32_t cond)
{
	switch (cond)
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
		if (IS_FIELD_PRESENT(instr, FIELD_S))
		{
			if (instr->fields[FIELD_S])
				return true;
		}
	}
	return false;
}

static bool IsPCRelativeDataAddress(decomp_result* instr, bool ifThenBlock)
{
	if ((instr->format->operandCount == 3) && (instr->format->operands[1].type == OPERAND_FORMAT_PC)
		&& (instr->format->operands[2].type == OPERAND_FORMAT_IMM) && !WritesToStatus(instr, ifThenBlock))
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
		WriteAddCarryOperand(il, instr, WritesToStatus(instr, ifThenBlock));
		break;
	case armv7::ARMV7_ADCS:
		WriteAddCarryOperand(il, instr, !ifThenBlock);
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
		WriteLogicalOperand(il, instr, WritesToStatus(instr, ifThenBlock), false);
		break;
	case armv7::ARMV7_ANDS:
		WriteLogicalOperand(il, instr, !ifThenBlock, false);
		break;
	case armv7::ARMV7_ASR:
		WriteAsrOperand(il, instr, WritesToStatus(instr, ifThenBlock));
		break;
	case armv7::ARMV7_ASRS:
		WriteAsrOperand(il, instr, !ifThenBlock);
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
		break;
	}
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
		WriteBitClearOperand(il, instr, WritesToStatus(instr, ifThenBlock));
		break;
	case armv7::ARMV7_BICS:
		WriteBitClearOperand(il, instr, !ifThenBlock);
		break;
	case armv7::ARMV7_BKPT:
		il.AddInstruction(il.Breakpoint());
		break;
	case armv7::ARMV7_BL:
	case armv7::ARMV7_BLX:
		il.AddInstruction(il.Call(ReadILOperand(il, instr, 0)));
		break;
	case armv7::ARMV7_BXJ:
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
		il.AddInstruction(WriteILOperand(il, instr, 0,
			il.CountLeadingZeros(4, ReadILOperand(il, instr, 1))));
		break;
	case armv7::ARMV7_CRC32B:
	case armv7::ARMV7_CRC32CB:
	case armv7::ARMV7_CRC32CH:
	case armv7::ARMV7_CRC32CW:
	case armv7::ARMV7_CRC32H:
	case armv7::ARMV7_CRC32W:
	{
		size_t valueSize = GetCrc32ValueSize(instr->mnem);
		ExprId value = ReadILOperand(il, instr, 2);
		if (valueSize < 4)
			value = il.LowPart(valueSize, value);
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			GetCrc32Intrinsic(instr->mnem),
			{
				ReadILOperand(il, instr, 1),
				value,
			}));
		break;
	}
	case armv7::ARMV7_CMP:
		il.AddInstruction(il.Sub(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1), IL_FLAGWRITE_ALL));
		break;
	case armv7::ARMV7_CMN:
		il.AddInstruction(il.Add(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1), IL_FLAGWRITE_ALL));
		break;
	case armv7::ARMV7_CPS:
	{
		uint8_t iflags = 0;
		if (IS_FIELD_PRESENT(instr, FIELD_affectA) && instr->fields[FIELD_affectA])
			iflags |= IFL_A;
		if (IS_FIELD_PRESENT(instr, FIELD_affectI) && instr->fields[FIELD_affectI])
			iflags |= IFL_I;
		if (IS_FIELD_PRESENT(instr, FIELD_affectF) && instr->fields[FIELD_affectF])
			iflags |= IFL_F;

		uint8_t mode = 0;
		if (IS_FIELD_PRESENT(instr, FIELD_changemode) && instr->fields[FIELD_changemode] && IS_FIELD_PRESENT(instr, FIELD_mode))
			mode = instr->fields[FIELD_mode];

		if (IS_FIELD_PRESENT(instr, FIELD_enable) && instr->fields[FIELD_enable])
		{
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_CPSIE, {il.Const(1, iflags), il.Const(1, mode)}));
		}
		else if (IS_FIELD_PRESENT(instr, FIELD_disable) && instr->fields[FIELD_disable])
		{
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_CPSID, {il.Const(1, iflags), il.Const(1, mode)}));
		}
		else
		{
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_CPS, {il.Const(1, mode)}));
		}
		break;
	}
	case armv7::ARMV7_SETEND:
		if (IS_FIELD_PRESENT(instr, FIELD_E))
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_SETEND, {il.Const(1, instr->fields[FIELD_E])}));
		else
			il.AddInstruction(il.Unimplemented());
		break;
	case armv7::ARMV7_CLREX:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_CLREX, {}));
		break;
	case armv7::ARMV7_PLD:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_PLD, {GetMemoryAddress(il, instr, 0, 4)}));
		break;
	case armv7::ARMV7_DBG:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_DBG, {il.Const(1, instr->fields[FIELD_option])}));
		break;
	case armv7::ARMV7_HINT:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_HINT, {ReadILOperand(il, instr, 0, 1)}));
		break;
	case armv7::ARMV7_UNPREDICTABLE:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_UNPREDICTABLE, {}));
		break;
	case armv7::ARMV7_DMB:
		switch (instr->fields[FIELD_barrier_option])
		{
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
		switch (instr->fields[FIELD_barrier_option])
		{
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
		WriteLogicalOperand(il, instr, WritesToStatus(instr, ifThenBlock), true);
		break;
	case armv7::ARMV7_EORS:
		WriteLogicalOperand(il, instr, !ifThenBlock, true);
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
			if (((regs & (1 << armv7::REG_SP)) || ((regs & lrpcBits) == lrpcBits) || !(regs & (regs - 1)) || (HasWriteback(instr, 0) && (regs & (1 << baseReg)))))
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
	case armv7::ARMV7_LDAEX:
	case armv7::ARMV7_LDREX:
		if ((instr->mnem == armv7::ARMV7_LDAEX) || (instr->mnem == armv7::ARMV7_LDREX))
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS,
				{ GetMemoryAddress(il, instr, 1, 4, false), il.Const(1, 4) }));
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
	case armv7::ARMV7_LDAEXB:
	case armv7::ARMV7_LDREXB:
		if ((instr->mnem == armv7::ARMV7_LDAEXB) || (instr->mnem == armv7::ARMV7_LDREXB))
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS,
				{ GetMemoryAddress(il, instr, 1, 4, false), il.Const(1, 1) }));
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
	case armv7::ARMV7_LDAEXH:
	case armv7::ARMV7_LDREXH:
		if ((instr->mnem == armv7::ARMV7_LDAEXH) || (instr->mnem == armv7::ARMV7_LDREXH))
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS,
				{ GetMemoryAddress(il, instr, 1, 4, false), il.Const(1, 2) }));
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
		if (instr->mnem == armv7::ARMV7_LDREXD)
			il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS, { mem, il.Const(1, 8) }));
		if (arch->GetEndianness() == LittleEndian)
		{
				il.AddInstruction(il.SetRegister(4, rt, il.Load(4, mem)));
				il.AddInstruction(il.SetRegister(4, rt2, il.Load(4, il.Add(4, mem, il.Const(4, 4)))));
		}
		else
		{
			il.AddInstruction(il.SetRegister(4, rt2, il.Load(4, mem)));
			il.AddInstruction(il.SetRegister(4, rt, il.Load(4, il.Add(4, mem, il.Const(4, 4)))));
		}

		if (instr->format->operandCount == 4)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[2].field0]);
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 3))));
		}
		break;
	}
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
	case armv7::ARMV7_STC:
	case armv7::ARMV7_STC2:
	case armv7::ARMV7_STCL:
	case armv7::ARMV7_STC2L:
		AddCoprocStoreIL(il, instr);
		break;
	case armv7::ARMV7_LDC:
	case armv7::ARMV7_LDC2:
	case armv7::ARMV7_LDCL:
	case armv7::ARMV7_LDC2L:
		AddCoprocLoadIL(il, instr);
		break;
	case armv7::ARMV7_CDP:
	case armv7::ARMV7_CDP2:
		il.AddInstruction(il.Intrinsic(
			{},
			ARMV7_INTRIN_COPROC_DATAPROCESSING,
			{
				il.Const(1, instr->fields[instr->format->operands[0].field0]),
				il.Const(1, instr->fields[instr->format->operands[1].field0]),
				il.Const(1, instr->fields[instr->format->operands[2].field0]),
				il.Const(1, instr->fields[instr->format->operands[3].field0]),
				il.Const(1, instr->fields[instr->format->operands[4].field0]),
				il.Const(1, instr->fields[instr->format->operands[5].field0]),
			}));
		break;
	case armv7::ARMV7_MCR:
	case armv7::ARMV7_MCR2:
	{
		int dest_reg_field = instr->fields[instr->format->operands[2].field0];
		int dest_reg = GetRegisterByIndex(dest_reg_field, instr->format->operands[2].prefix);

		il.AddInstruction(
			il.Intrinsic({ }, ARMV7_INTRIN_COPROC_SENDONEWORD,
				{
					il.Register(4, dest_reg),
					il.Const(1, instr->fields[instr->format->operands[0].field0]),
					il.Const(1, instr->fields[instr->format->operands[1].field0]),
					il.Const(1, instr->fields[instr->format->operands[3].field0]),
					il.Const(1, instr->fields[instr->format->operands[4].field0]),
					il.Const(1, instr->fields[instr->format->operands[5].field0]),
				}
			)
		);
		break;
	}
	case ARMV7_MCRR:
	case ARMV7_MCRR2:
	{
		int rt = instr->fields[instr->format->operands[2].field0];
		int rt2 = instr->fields[instr->format->operands[3].field0];
		il.AddInstruction(
			il.Intrinsic({ }, ARMV7_INTRIN_COPROC_SENDTWOWORDS,
				{
					il.Register(4, rt2),
					il.Register(4, rt),
					il.Const(1, instr->fields[instr->format->operands[0].field0]),
					il.Const(1, instr->fields[instr->format->operands[1].field0]),
					il.Const(1, instr->fields[instr->format->operands[4].field0]),
				}
			)
		);
		break;
	}
	case armv7::ARMV7_MLA:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Add(4, ReadILOperand(il, instr, 3), il.Mult(4, ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2)))));
		break;
	case armv7::ARMV7_MLS:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Sub(4, ReadILOperand(il, instr, 3), il.Mult(4, ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2)))));
		break;
	case armv7::ARMV7_MOV:
	case armv7::ARMV7_MOVW:
		il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1), 4,
			WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_NZ : 0));
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
	case armv7::ARMV7_MRC:
	case armv7::ARMV7_MRC2:
	{
		auto params = {
			il.Const(1, instr->fields[instr->format->operands[0].field0]), /* cp */
			il.Const(1, instr->fields[instr->format->operands[1].field0]), /* opc1 */
			il.Const(1, instr->fields[instr->format->operands[3].field0]), /* crn */
			il.Const(1, instr->fields[instr->format->operands[4].field0]), /* crm */
			il.Const(1, instr->fields[instr->format->operands[5].field0]), /* opc2 */
		};

		int dest_reg_field = instr->fields[instr->format->operands[2].field0];
		if (dest_reg_field == 15)
		{
			il.AddInstruction(
				il.Intrinsic(
					{
						RegisterOrFlag::Flag(IL_FLAG_N),
						RegisterOrFlag::Flag(IL_FLAG_Z),
						RegisterOrFlag::Flag(IL_FLAG_C),
						RegisterOrFlag::Flag(IL_FLAG_V)
					},
					ARMV7_INTRIN_COPROC_GETONEWORD,
					params
				)
			);
			break;
		}

		int dest_reg = GetRegisterByIndex(dest_reg_field, instr->format->operands[2].prefix);

		il.AddInstruction(
			il.Intrinsic(
				{RegisterOrFlag::Register(dest_reg)}, /* outputs */
				ARMV7_INTRIN_COPROC_GETONEWORD,
				params /* inputs */
			)
		);
		break;
	}

	case ARMV7_MRRC:
	case ARMV7_MRRC2:
	{
		int rt = instr->fields[instr->format->operands[2].field0];
		int rt2 = instr->fields[instr->format->operands[3].field0];

		il.AddInstruction(
			il.Intrinsic(
				{ RegisterOrFlag::Register(rt2), RegisterOrFlag::Register(rt) },
				ARMV7_INTRIN_COPROC_GETTWOWORDS,
				{
					il.Const(1, instr->fields[instr->format->operands[0].field0]),
					il.Const(1, instr->fields[instr->format->operands[1].field0]),
					il.Const(1, instr->fields[instr->format->operands[4].field0]),
				}
			)
		);
		break;
	}

	case armv7::ARMV7_MRS:
	{
		int dest_reg = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0], instr->format->operands[0].prefix);

		int intrinsic_id = ARMV7_INTRIN_MRS;

		il.AddInstruction(
			il.Intrinsic(
				{RegisterOrFlag::Register(dest_reg)}, /* outputs */
				intrinsic_id,
				// {il.Register(4, GetSpecialRegister(il, instr, 1))} /* inputs */
				{il.Const(4, GetSpecialRegister(il, instr, 1))} /* inputs */
			)
		);
		break;
	}
	case armv7::ARMV7_MSR:
	{
		int dest_reg = GetSpecialRegister(il, instr, 0);
		int intrinsic_id = ARMV7_INTRIN_MSR;

		il.AddInstruction(
			il.Intrinsic(
				{}, /* outputs */
				intrinsic_id,
				{
					// il.Register(4, dest_reg),
					il.Const(4, dest_reg),
					ReadILOperand(il, instr, 1)
				} /* inputs */
			)
		);


		/* certain MSR scenarios earn a specialized intrinsic */
		// if (dest_reg == REGS_BASEPRI)
		// 	intrinsic_id = ARM_M_INTRIN_SET_BASEPRI;
		// switch (dest_reg) {
		// 	case REGS_MSP:
		// 	case REGS_PSP:
		// 	case REGS_BASEPRI:
		// 	case REGS_BASEPRI_MAX:
		// 	case REGS_PRIMASK:
		// 	case REGS_FAULTMASK:
		// 	case REGS_CONTROL:
		// 	case REGS_IPSR:
		// 	case REGS_EPSR:
		// 	case REGS_IEPSR:
		// 		il.AddInstruction(
		// 			il.Intrinsic(
		// 				{}, /* outputs */
		// 				intrinsic_id,
		// 				{
		// 					// il.Register(4, dest_reg),
		// 					il.Const(4, dest_reg),
		// 					ReadILOperand(il, instr, 1)
		// 				} /* inputs */
		// 			)
		// 		);
		// 		break;
		// 	default:
		// 		il.AddInstruction(
		// 			il.Intrinsic(
		// 				{RegisterOrFlag::Register(dest_reg)}, /* outputs */
		// 				intrinsic_id,
		// 				{ReadILOperand(il, instr, 1)} /* inputs */
		// 			)
		// 		);
		// }

		break;
	}
	case armv7::ARMV7_MUL:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_NZ : 0)));
		break;
	case armv7::ARMV7_MULS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_NZ)));
		break;
	case armv7::ARMV7_MVN:
		WriteMoveNotOperand(il, instr, WritesToStatus(instr, ifThenBlock));
		break;
	case armv7::ARMV7_MVNS:
		WriteMoveNotOperand(il, instr, !ifThenBlock);
		break;
	case armv7::ARMV7_NOP:
		il.AddInstruction(il.Nop());
		break;
	case ARMV7_ORN:
		il.AddInstruction(WriteArithOperand(il, instr, il.Or(4, ReadArithOperand(il, instr, 0),
			il.Not(4, ReadArithOperand(il, instr, 1)), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_ORR:
		WriteOrOperand(il, instr, WritesToStatus(instr, ifThenBlock));
		break;
	case armv7::ARMV7_ORRS:
		WriteOrOperand(il, instr, !ifThenBlock);
		break;
	case armv7::ARMV7_PKHBT:
		WritePackHalfwordOperand(il, instr, true);
		break;
	case armv7::ARMV7_PKHTB:
		WritePackHalfwordOperand(il, instr, false);
		break;
	case armv7::ARMV7_QADD:
		WriteSaturatingAddSubOperand(il, instr, false);
		break;
	case armv7::ARMV7_QADD16:
		WriteSignedSaturatingParallelAddSubOperand(il, instr, 2, false);
		break;
	case armv7::ARMV7_QADD8:
		WriteSignedSaturatingParallelAddSubOperand(il, instr, 1, false);
		break;
	case armv7::ARMV7_QDADD:
		WriteSaturatingDoubleAddSubOperand(il, instr, false);
		break;
	case armv7::ARMV7_QDSUB:
		WriteSaturatingDoubleAddSubOperand(il, instr, true);
		break;
	case armv7::ARMV7_QSAX:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_QSAX,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_QSUB:
		WriteSaturatingAddSubOperand(il, instr, true);
		break;
	case armv7::ARMV7_QSUB16:
		WriteSignedSaturatingParallelAddSubOperand(il, instr, 2, true);
		break;
	case armv7::ARMV7_QSUB8:
		WriteSignedSaturatingParallelAddSubOperand(il, instr, 1, true);
		break;
	case armv7::ARMV7_POP:
		Pop(il, instr->fields[FIELD_registers]);
		break;
	case armv7::ARMV7_PUSH:
		Push(il, instr->fields[FIELD_registers]);
		break;
	case armv7::ARMV7_RBIT:
		il.AddInstruction(WriteILOperand(il, instr, 0,
			il.ReverseBits(4, ReadILOperand(il, instr, 1))));
		break;
	case armv7::ARMV7_REV:
		il.AddInstruction(WriteILOperand(il, instr, 0,
			il.ByteSwap(4, ReadILOperand(il, instr, 1))));
		break;
	case armv7::ARMV7_REV16:
		il.AddInstruction(WriteILOperand(il, instr, 0,
			il.RotateRight(4, il.ByteSwap(4, ReadILOperand(il, instr, 1)), il.Const(1, 16))));
		break;
	case armv7::ARMV7_REVSH:
		il.AddInstruction(WriteILOperand(il, instr, 0,
			il.SignExtend(4, il.ByteSwap(2, il.LowPart(2, ReadILOperand(il, instr, 1))))));
		break;
	case armv7::ARMV7_ROR:
		WriteRorOperand(il, instr, WritesToStatus(instr, ifThenBlock));
		break;
	case armv7::ARMV7_RORS:
		WriteRorOperand(il, instr, !ifThenBlock);
		break;
	case armv7::ARMV7_RSB:
		il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, ReadArithOperand(il, instr, 1),
			ReadArithOperand(il, instr, 0), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv7::ARMV7_RSBS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, ReadArithOperand(il, instr, 1),
			ReadArithOperand(il, instr, 0), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv7::ARMV7_SASX:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_SASX);
		break;
	case armv7::ARMV7_SADD16:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_SADD16);
		break;
	case armv7::ARMV7_SADD8:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_SADD8);
		break;
	case armv7::ARMV7_SHADD16:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_SHADD16,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_SHADD8:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_SHADD8,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_SHASX:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_SHASX,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_SSAX:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_SSAX);
		break;
	case armv7::ARMV7_SSUB16:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_SSUB16);
		break;
	case armv7::ARMV7_SSUB8:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_SSUB8);
		break;
	case armv7::ARMV7_SHSUB16:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_SHSUB16,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_SHSUB8:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_SHSUB8,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_UASX:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_UASX);
		break;
	case armv7::ARMV7_UHASX:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_UHASX,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_UQADD16:
		WriteUnsignedSaturatingParallelAddSubOperand(il, instr, 2, false);
		break;
	case armv7::ARMV7_UQADD8:
		WriteUnsignedSaturatingParallelAddSubOperand(il, instr, 1, false);
		break;
	case armv7::ARMV7_UQASX:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_UQASX,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_UHADD16:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_UHADD16,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_UHADD8:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_UHADD8,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_UHSUB16:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_UHSUB16,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_UHSUB8:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_UHSUB8,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_UADD8:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_UADD8);
		break;
	case armv7::ARMV7_UADD16:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_UADD16);
		break;
	case armv7::ARMV7_USAX:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_USAX);
		break;
	case armv7::ARMV7_UQSUB16:
		WriteUnsignedSaturatingParallelAddSubOperand(il, instr, 2, true);
		break;
	case armv7::ARMV7_UQSUB8:
		WriteUnsignedSaturatingParallelAddSubOperand(il, instr, 1, true);
		break;
	case armv7::ARMV7_UQSAX:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_UQSAX,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_USAD8:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_USAD8,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_USADA8:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_USADA8,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3) }));
		break;
	case armv7::ARMV7_USUB16:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_USUB16);
		break;
	case armv7::ARMV7_USUB8:
		WriteParallelGEIntrinsic(il, instr, ARMV7_INTRIN_USUB8);
		break;
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
	case ARMV7_YIELD:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_YIELD, {}));
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

		uint32_t targetReg = decBeforeMode ? LLIL_TEMP(0) : baseReg;
		for (int32_t i = 0, slot = 0; i <= regLimit; i++)
		{
			if ((regs >> i) & 1)
			{
				il.AddInstruction(il.Store(4,
					il.Add(4, il.Register(4, targetReg), il.Const(4, 4 * slot++)),
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
	case armv7::ARMV7_STLEX:
	case armv7::ARMV7_STLEXB:
	case armv7::ARMV7_STLEXH:
	case armv7::ARMV7_STREX:
	case armv7::ARMV7_STREXB:
	case armv7::ARMV7_STREXH:
	{
		size_t storeSize = 4;
		if (instr->mnem == armv7::ARMV7_STLEXB || instr->mnem == armv7::ARMV7_STREXB)
			storeSize = 1;
		else if (instr->mnem == armv7::ARMV7_STLEXH || instr->mnem == armv7::ARMV7_STREXH)
			storeSize = 2;

		ExprId address = GetMemoryAddress(il, instr, 2, 4);
		LowLevelILLabel trueCode, falseCode, done;
		uint32_t statusReg = GetRegisterOperand(instr, 0);
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(LLIL_TEMP(0)) },
			ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS,
			{ address, il.Const(1, 4) }));
		il.AddInstruction(il.If(il.CompareEqual(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 1)), trueCode, falseCode));
		il.MarkLabel(trueCode);
		ExprId value = ReadILOperand(il, instr, 1);
		if (storeSize < 4)
			value = il.LowPart(storeSize, value);
		il.AddInstruction(il.Store(storeSize, address, value));
		il.AddInstruction(il.SetRegister(4, statusReg, il.Const(4, 0)));
		il.AddInstruction(il.Goto(done));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.SetRegister(4, statusReg, il.Const(4, 1)));
		il.MarkLabel(done);
		break;
	}
	case armv7::ARMV7_STLEXD:
	case armv7::ARMV7_STREXD:
	{
		ExprId address = GetMemoryAddress(il, instr, 3, 4);
		LowLevelILLabel trueCode, falseCode, done;
		uint32_t statusReg = GetRegisterOperand(instr, 0);
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(LLIL_TEMP(0)) },
			ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS,
			{ address, il.Const(1, 8) }));
		il.AddInstruction(il.If(il.CompareEqual(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 1)), trueCode, falseCode));
		il.MarkLabel(trueCode);

		ExprId value = arch->GetEndianness() == LittleEndian
			? il.RegisterSplit(4, GetRegisterOperand(instr, 2), GetRegisterOperand(instr, 1))
			: il.RegisterSplit(4, GetRegisterOperand(instr, 1), GetRegisterOperand(instr, 2));
		il.AddInstruction(il.Store(8, address, value));
		il.AddInstruction(il.SetRegister(4, statusReg, il.Const(4, 0)));
		il.AddInstruction(il.Goto(done));

		il.MarkLabel(falseCode);
		il.AddInstruction(il.SetRegister(4, statusReg, il.Const(4, 1)));
		il.MarkLabel(done);
		break;
	}
	case armv7::ARMV7_STL:
	case armv7::ARMV7_STR:
	case armv7::ARMV7_STRT:
	// case armv7::ARMV7_STREX:
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
	case armv7::ARMV7_SRS:
	case armv7::ARMV7_SRSDA:
	case armv7::ARMV7_SRSDB:
	case armv7::ARMV7_SRSIA:
	case armv7::ARMV7_SRSIB:
	{
		bool increment = false;
		bool wordhigher = false;
		if (IS_FIELD_PRESENT(instr, FIELD_increment))
			increment = instr->fields[FIELD_increment] != 0;
		else if (IS_FIELD_PRESENT(instr, FIELD_inc))
			increment = instr->fields[FIELD_inc] != 0;
		else
			increment = (instr->mnem == armv7::ARMV7_SRSIA) || (instr->mnem == armv7::ARMV7_SRSIB);

		if (IS_FIELD_PRESENT(instr, FIELD_wordhigher))
			wordhigher = instr->fields[FIELD_wordhigher] != 0;
		else
			wordhigher = (instr->mnem == armv7::ARMV7_SRSDA) || (instr->mnem == armv7::ARMV7_SRSIB);

		il.AddInstruction(il.Intrinsic(
			{},
			ARMV7_INTRIN_SRS,
			{
				il.Const(1, instr->fields[FIELD_mode]),
				il.Const(1, increment ? 1 : 0),
				il.Const(1, wordhigher ? 1 : 0),
				il.Const(1, (IS_FIELD_PRESENT(instr, FIELD_wback) && instr->fields[FIELD_wback]) ? 1 : 0),
			}));
		break;
	}
	case armv7::ARMV7_RFE:
	case armv7::ARMV7_RFEDA:
	case armv7::ARMV7_RFEDB:
	case armv7::ARMV7_RFEIA:
	case armv7::ARMV7_RFEIB:
	{
		bool increment = false;
		bool wordhigher = false;
		if (IS_FIELD_PRESENT(instr, FIELD_increment))
			increment = instr->fields[FIELD_increment] != 0;
		else if (IS_FIELD_PRESENT(instr, FIELD_inc))
			increment = instr->fields[FIELD_inc] != 0;
		else
			increment = (instr->mnem == armv7::ARMV7_RFEIA) || (instr->mnem == armv7::ARMV7_RFEIB);

		if (IS_FIELD_PRESENT(instr, FIELD_wordhigher))
			wordhigher = instr->fields[FIELD_wordhigher] != 0;
		else
			wordhigher = (instr->mnem == armv7::ARMV7_RFEDA) || (instr->mnem == armv7::ARMV7_RFEIB);

		il.AddInstruction(il.Intrinsic(
			{},
			ARMV7_INTRIN_RFE,
			{
				ReadILOperand(il, instr, 0),
				il.Const(1, increment ? 1 : 0),
				il.Const(1, wordhigher ? 1 : 0),
				il.Const(1, (IS_FIELD_PRESENT(instr, FIELD_wback) && instr->fields[FIELD_wback]) ? 1 : 0),
			}));
		break;
	}
	case armv7::ARMV7_STLB:
	case armv7::ARMV7_STRB:
	case armv7::ARMV7_STRBT:
	// case armv7::ARMV7_STREXB:
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
	case armv7::ARMV7_STRHT:
	// case armv7::ARMV7_STREXH:
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
	// case armv7::ARMV7_STREXD:
	{
		ExprId mem;

		mem = GetMemoryAddress(il, instr, 2, 4, instr->format->operandCount != 4);
		if (arch->GetEndianness() == LittleEndian)
		{
			il.AddInstruction(il.Store(4, mem, ReadILOperand(il, instr, 0)));
			il.AddInstruction(il.Store(4, il.Add(4, mem, il.Const(4, 4)), ReadILOperand(il, instr, 1)));
		}
		else
		{
			il.AddInstruction(il.Store(4, mem, ReadILOperand(il, instr, 1)));
			il.AddInstruction(il.Store(4, il.Add(4, mem, il.Const(4, 4)), ReadILOperand(il, instr, 0)));
		}

		if (instr->format->operandCount == 4)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[2].field0]);
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 3))));
		}
		break;
	}
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
	case armv7::ARMV7_SMC:
		il.AddInstruction(il.Intrinsic({}, ARMV7_INTRIN_SMC,
			{il.Const(1, instr->fields[instr->format->operands[0].field0])}));
		break;
	case armv7::ARMV7_SXTAB:
		il.AddInstruction(WriteArithOperand(il, instr, il.Add(4, ReadILOperand(il, instr, 1), il.SignExtend(4, il.LowPart(1, ReadRotatedOperand(il, instr, 2))))));
		break;
	case armv7::ARMV7_SXTAB16:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_SXTAB16,
			{ ReadILOperand(il, instr, 1), ReadRotatedOperand(il, instr, 2) }));
		break;
	case armv7::ARMV7_SXTAH:
		il.AddInstruction(WriteArithOperand(il, instr, il.Add(4, ReadILOperand(il, instr, 1), il.SignExtend(4, il.LowPart(2, ReadRotatedOperand(il, instr, 2))))));
		break;
	case armv7::ARMV7_SXTB:
		il.AddInstruction(WriteArithOperand(il, instr, il.SignExtend(4, il.LowPart(1, ReadRotatedOperand(il, instr, 1)))));
		break;
	case armv7::ARMV7_SXTB16:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_SXTB16,
			{ ReadRotatedOperand(il, instr, 1) }));
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
		WriteTestEquivalenceOperand(il, instr);
		break;
	case armv7::ARMV7_TST:
		WriteTestOperand(il, instr);
		break;
	case armv7::ARMV7_SSAT:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_SSAT,
			{ ReadILOperand(il, instr, 1), ReadShiftedOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_SSAT16:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_SSAT16,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_USAT:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_USAT,
			{ ReadILOperand(il, instr, 1), ReadShiftedOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_USAT16:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_USAT16,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_UBFX:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.And(4, il.LogicalShiftRight(4, ReadILOperand(il, instr, 1),
												 ReadILOperand(il, instr, 2)),
									 il.Const(4, (1 << instr->fields[instr->format->operands[3].field0]) - 1))));
		break;
	case armv7::ARMV7_UDF:
		il.AddInstruction(il.Trap(instr->fields[instr->format->operands[0].field0]));
		break;
	case armv7::ARMV7_UMAAL:
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
					il.Add(8,
						il.ZeroExtend(8, il.Register(4, RdHi)),
						il.ZeroExtend(8, il.Register(4, RdLo)))
				)
			)
		);
		break;
	}
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
		il.AddInstruction(WriteSplitOperands(il, instr, 1, 0, il.MultDoublePrecUnsigned(4, ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3))));
		break;
	case armv7::ARMV7_SMULL:
		il.AddInstruction(WriteSplitOperands(il, instr, 1, 0, il.MultDoublePrecSigned(4, ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3))));
		break;
	case armv7::ARMV7_SMLAD:
	case armv7::ARMV7_SMLADX:
		WriteQFlagIntrinsic(il, instr,
			(instr->mnem == armv7::ARMV7_SMLADX) ? ARMV7_INTRIN_SMLADX : ARMV7_INTRIN_SMLAD,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3) });
		break;
	case armv7::ARMV7_SMUAD:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_SMUAD,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_SMUADX:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_SMUADX,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_SMUSD:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_SMUSD,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_SMUSDX:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_SMUSDX,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2) });
		break;
	case armv7::ARMV7_SMLSD:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_SMLSD,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3) });
		break;
	case armv7::ARMV7_SMLSDX:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_SMLSDX,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3) });
		break;
	case armv7::ARMV7_SMLSLD:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 1)), RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_SMLSLD,
			{ ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3),
				il.RegisterSplit(4, GetRegisterOperand(instr, 1), GetRegisterOperand(instr, 0)) }));
		break;
	case armv7::ARMV7_SMLSLDX:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 1)), RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_SMLSLDX,
			{ ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3),
				il.RegisterSplit(4, GetRegisterOperand(instr, 1), GetRegisterOperand(instr, 0)) }));
		break;
	case armv7::ARMV7_SMLALBB:
		WriteSignedLongHalfwordMultiplyAccumulateOperand(il, instr, false, false);
		break;
	case armv7::ARMV7_SMLALBT:
		WriteSignedLongHalfwordMultiplyAccumulateOperand(il, instr, false, true);
		break;
	case armv7::ARMV7_SMLALTB:
		WriteSignedLongHalfwordMultiplyAccumulateOperand(il, instr, true, false);
		break;
	case armv7::ARMV7_SMLALTT:
		WriteSignedLongHalfwordMultiplyAccumulateOperand(il, instr, true, true);
		break;
	case armv7::ARMV7_SMLAWB:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_SMLAWB,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3) });
		break;
	case armv7::ARMV7_SMLAWT:
		WriteQFlagIntrinsic(il, instr,
			ARMV7_INTRIN_SMLAWT,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3) });
		break;
	case armv7::ARMV7_SMULWB:
		WriteSignedWordHalfwordMultiplyOperand(il, instr, false, false);
		break;
	case armv7::ARMV7_SMULWT:
		WriteSignedWordHalfwordMultiplyOperand(il, instr, true, false);
		break;
	case armv7::ARMV7_SMLAL:
		il.AddInstruction(WriteSplitOperands(il, instr, 1, 0,
			il.Add(8,
				il.MultDoublePrecSigned(4, ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3)),
				il.RegisterSplit(4,
					GetRegisterOperand(instr, 1),
					GetRegisterOperand(instr, 0)))));
		break;
	case armv7::ARMV7_SMLALD:
	case armv7::ARMV7_SMLALDX:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 1)), RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			(instr->mnem == armv7::ARMV7_SMLALDX) ? ARMV7_INTRIN_SMLALDX : ARMV7_INTRIN_SMLALD,
			{ ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3),
				il.RegisterSplit(4, GetRegisterOperand(instr, 1), GetRegisterOperand(instr, 0)) }));
		break;
	case armv7::ARMV7_SMLABB:
	case armv7::ARMV7_SMLABT:
	case armv7::ARMV7_SMLATB:
	case armv7::ARMV7_SMLATT:
	{
		uint32_t intrinsic = ARMV7_INTRIN_SMLABB;
		if (instr->mnem == armv7::ARMV7_SMLABT)
			intrinsic = ARMV7_INTRIN_SMLABT;
		else if (instr->mnem == armv7::ARMV7_SMLATB)
			intrinsic = ARMV7_INTRIN_SMLATB;
		else if (instr->mnem == armv7::ARMV7_SMLATT)
			intrinsic = ARMV7_INTRIN_SMLATT;
		WriteQFlagIntrinsic(il, instr, intrinsic,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3) });
		break;
	}
	case armv7::ARMV7_SMULBB:
		il.AddInstruction(WriteArithOperand(il, instr,
			SignedHalfProduct32(il,
				ReadSignedHalfwordOperand(il, instr, 1, false),
				ReadSignedHalfwordOperand(il, instr, 2, false)),
			IL_FLAGWRITE_NONE));
		break;
	case armv7::ARMV7_SMULBT:
		il.AddInstruction(WriteArithOperand(il, instr,
			SignedHalfProduct32(il,
				ReadSignedHalfwordOperand(il, instr, 1, false),
				ReadSignedHalfwordOperand(il, instr, 2, true)),
			IL_FLAGWRITE_NONE));
		break;
	case armv7::ARMV7_SMULTB:
		il.AddInstruction(WriteArithOperand(il, instr,
			SignedHalfProduct32(il,
				ReadSignedHalfwordOperand(il, instr, 1, true),
				ReadSignedHalfwordOperand(il, instr, 2, false)),
			IL_FLAGWRITE_NONE));
		break;
	case armv7::ARMV7_SMULTT:
		il.AddInstruction(WriteArithOperand(il, instr,
			SignedHalfProduct32(il,
				ReadSignedHalfwordOperand(il, instr, 1, true),
				ReadSignedHalfwordOperand(il, instr, 2, true)),
			IL_FLAGWRITE_NONE));
		break;
	case armv7::ARMV7_SMMUL:
	case armv7::ARMV7_SMMULR:
	{
		ExprId product = il.MultDoublePrecSigned(4, ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2));
		if (instr->mnem == armv7::ARMV7_SMMULR)
			product = il.Add(8, product, il.Const(8, 0x80000000));
		il.AddInstruction(WriteILOperand(il, instr, 0,
			il.LowPart(4,
				il.ArithShiftRight(8,
					product,
					il.Const(1, 32)))));
		break;
	}
	case armv7::ARMV7_SMMLA:
	case armv7::ARMV7_SMMLAR:
	{
		ExprId product = il.MultDoublePrecSigned(4, ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2));
		if (instr->mnem == armv7::ARMV7_SMMLAR)
			product = il.Add(8, product, il.Const(8, 0x80000000));
		ExprId high = il.LowPart(4, il.ArithShiftRight(8, product, il.Const(1, 32)));
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Add(4, high, ReadILOperand(il, instr, 3))));
		break;
	}
	case armv7::ARMV7_SMMLS:
	case armv7::ARMV7_SMMLSR:
	{
		ExprId difference = il.Sub(8,
			il.ShiftLeft(8, ReadILOperand(il, instr, 3), il.Const(1, 32)),
			il.MultDoublePrecSigned(4, ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2)));
		if (instr->mnem == armv7::ARMV7_SMMLSR)
			difference = il.Add(8, difference, il.Const(8, 0x80000000));
		il.AddInstruction(WriteILOperand(il, instr, 0,
			il.LowPart(4, il.ArithShiftRight(8, difference, il.Const(1, 32)))));
		break;
	}
	case armv7::ARMV7_UXTAB:
		il.AddInstruction(WriteArithOperand(il, instr,
			il.Add(4,
				ReadILOperand(il, instr, 1),
				il.ZeroExtend(4, il.LowPart(1, ReadRotatedOperand(il, instr, 2))))));
		break;
	case armv7::ARMV7_UXTAB16:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_UXTAB16,
			{ ReadILOperand(il, instr, 1), ReadRotatedOperand(il, instr, 2) }));
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
	case armv7::ARMV7_UXTB16:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_UXTB16,
			{ ReadRotatedOperand(il, instr, 1) }));
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
	case ARMV7_RRX:
		il.AddInstruction(WriteILOperand(il, instr, 0, ReadShiftedOperand(il, instr, 1)));
		break;
	case ARMV7_SEL:
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			ARMV7_INTRIN_SEL,
			{ ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2), il.Register(4, REGS_APSR_G) }));
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
	switch (instr->mnem)
	{
	case armv7::ARMV7_VABS:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(
				WriteILOperand(il, instr, 0, il.FloatAbs(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1))));
		}
		else
		{
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv7::ARMV7_VADD:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatAdd(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		}
		else
		{
			VectorAddSubtract(il, instr, ARMV7_INTRIN_VADD);
		}
		break;
	case armv7::ARMV7_VBIF:
		VectorBitSelect(il, instr, ARMV7_INTRIN_VBIF);
		break;
	case armv7::ARMV7_VBIT:
		VectorBitSelect(il, instr, ARMV7_INTRIN_VBIT);
		break;
	case armv7::ARMV7_VBSL:
		VectorBitSelect(il, instr, ARMV7_INTRIN_VBSL);
		break;
	case armv7::ARMV7_VCEQ:
		VectorCompareEqual(il, instr);
		break;
	case armv7::ARMV7_VCGT:
		VectorCompareGreaterThan(il, instr);
		break;
	case armv7::ARMV7_VDUP:
		VectorDuplicate(il, instr);
		break;
	case armv7::ARMV7_VAND:
		il.AddInstruction(WriteArithOperand(
			il, instr, il.And(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		break;
	case armv7::ARMV7_VEOR:
		il.AddInstruction(WriteArithOperand(
			il, instr, il.Xor(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		break;
	case armv7::ARMV7_VORR:
		il.AddInstruction(WriteArithOperand(
			il, instr, il.Or(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		break;
	case armv7::ARMV7_VQADD:
		SaturatingVectorAdd(il, instr);
		break;
	case armv7::ARMV7_VABD:
		VectorAbsoluteDifference(il, instr, ARMV7_INTRIN_VABD);
		break;
	case armv7::ARMV7_VABDL:
		VectorAbsoluteDifference(il, instr, ARMV7_INTRIN_VABDL);
		break;
	case armv7::ARMV7_VABA:
		VectorAbsoluteDifferenceAccumulate(il, instr, ARMV7_INTRIN_VABA);
		break;
	case armv7::ARMV7_VABAL:
		VectorAbsoluteDifferenceAccumulate(il, instr, ARMV7_INTRIN_VABAL);
		break;
	case armv7::ARMV7_VADDL:
		VectorWideningAdd(il, instr, ARMV7_INTRIN_VADDL);
		break;
	case armv7::ARMV7_VADDW:
		VectorWideningAdd(il, instr, ARMV7_INTRIN_VADDW);
		break;
	case armv7::ARMV7_VRADDHN:
		VectorRoundingAddNarrow(il, instr);
		break;
	case armv7::ARMV7_VQSHL:
		SaturatingVectorShiftLeft(il, instr, ARMV7_INTRIN_VQSHL);
		break;
	case armv7::ARMV7_VQRSHL:
		SaturatingVectorShiftLeft(il, instr, ARMV7_INTRIN_VQRSHL);
		break;
	case armv7::ARMV7_VQSHRN:
		SaturatingVectorShiftRightNarrow(il, instr, 0);
		break;
	case armv7::ARMV7_VQSHRUN:
		SaturatingVectorShiftRightNarrow(il, instr, ARMV7_INTRIN_VQSHRUN);
		break;
	case armv7::ARMV7_VQRSHRN:
		SaturatingVectorShiftRightNarrow(il, instr, static_cast<uint32_t>(-1));
		break;
	case armv7::ARMV7_VQRSHRUN:
		SaturatingVectorShiftRightNarrow(il, instr, ARMV7_INTRIN_VQRSHRUN);
		break;
	case armv7::ARMV7_VQMOVN:
	case armv7::ARMV7_VQMOVUN:
		SaturatingVectorMoveNarrow(il, instr);
		break;
	case armv7::ARMV7_VRSHR:
		RoundedVectorShift(il, instr, ARMV7_INTRIN_VRSHR);
		break;
	case armv7::ARMV7_VRSHL:
		RoundedVectorShift(il, instr, ARMV7_INTRIN_VRSHL);
		break;
	case armv7::ARMV7_VSRA:
		ShiftRightAccumulateOrInsert(il, instr, ARMV7_INTRIN_VSRA);
		break;
	case armv7::ARMV7_VRSRA:
		ShiftRightAccumulateOrInsert(il, instr, ARMV7_INTRIN_VRSRA);
		break;
	case armv7::ARMV7_VSRI:
		ShiftRightAccumulateOrInsert(il, instr, ARMV7_INTRIN_VSRI);
		break;
	case armv7::ARMV7_VSLI:
		ShiftRightAccumulateOrInsert(il, instr, ARMV7_INTRIN_VSLI);
		break;
	case armv7::ARMV7_VSHL:
		VectorShiftLeft(il, instr);
		break;
	case armv7::ARMV7_VSHLL:
		VectorShiftLeftLong(il, instr);
		break;
	case armv7::ARMV7_VSHR:
		VectorShiftRight(il, instr);
		break;
	case armv7::ARMV7_VTBL:
	case armv7::ARMV7_VTBX:
		VectorTableLookup(il, instr);
		break;
	case armv7::ARMV7_VSUB:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatSub(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		}
		else
		{
			VectorAddSubtract(il, instr, ARMV7_INTRIN_VSUB);
		}
		break;
	case armv7::ARMV7_VFMA:
		// TODO: Find a better way to disambiguate between add and sub variants.
		if (strcmp(instr->format->operation, "vfma.f64") == 0 || strcmp(instr->format->operation, "vfma.f32") == 0)
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatAdd(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 0),
					il.FloatMult(
						GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2)))));
		}
		else if (strcmp(instr->format->operation, "vfms.f64") == 0 || strcmp(instr->format->operation, "vfms.f32") == 0)
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatSub(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 0),
					il.FloatMult(
						GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2)))));
			}
			else
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
	case armv7::ARMV7_VHADD:
		HalvingVectorAdd(il, instr);
		break;
	case armv7::ARMV7_VFNMS:
	case armv7::ARMV7_VNMLS:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			size_t size = GetRegisterSize(instr, 0);
			ExprId product = il.FloatMult(size, ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2));
			if ((strncmp(instr->format->operation, "vfnma", 5) == 0) ||
				(strncmp(instr->format->operation, "vnmla", 5) == 0))
			{
				il.AddInstruction(WriteArithOperand(il, instr,
					il.FloatNeg(size, il.FloatAdd(size, ReadILOperand(il, instr, 0), product))));
			}
			else if ((strncmp(instr->format->operation, "vfnms", 5) == 0) ||
				(strncmp(instr->format->operation, "vnmls", 5) == 0))
			{
				il.AddInstruction(WriteArithOperand(il, instr,
					il.FloatNeg(size, il.FloatSub(size, ReadILOperand(il, instr, 0), product))));
			}
			else
			{
				il.AddInstruction(il.Unimplemented());
			}
			}
			else
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
	case armv7::ARMV7_VMAXNM:
	{
		uint32_t intrinsic = ARMV7_INTRIN_VMAXNM;
		if (strncmp(instr->format->operation, "vminnm", 6) == 0)
			intrinsic = ARMV7_INTRIN_VMINNM;
		else if (strncmp(instr->format->operation, "vmaxnm", 6) != 0)
		{
			il.AddInstruction(il.Unimplemented());
			break;
		}
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
			intrinsic,
			{ ReadILOperand(il, instr, 1, GetRegisterSize(instr, 0)),
				ReadILOperand(il, instr, 2, GetRegisterSize(instr, 0)) }));
		break;
	}
	case armv7::ARMV7_VMAX:
		VectorMaximumMinimum(il, instr, ARMV7_INTRIN_VMAX);
		break;
	case armv7::ARMV7_VMIN:
		VectorMaximumMinimum(il, instr, ARMV7_INTRIN_VMIN);
		break;
	case armv7::ARMV7_VPMAX:
		if (strncmp(instr->format->operation, "vpmin", 5) == 0)
			VectorMaximumMinimum(il, instr, ARMV7_INTRIN_VPMIN);
		else if (strncmp(instr->format->operation, "vpmax", 5) == 0)
			VectorMaximumMinimum(il, instr, ARMV7_INTRIN_VPMAX);
		else
			il.AddInstruction(il.Unimplemented());
		break;
	case armv7::ARMV7_VREV16:
		VectorReverse(il, instr, ARMV7_INTRIN_VREV16);
		break;
	case armv7::ARMV7_VREV32:
		VectorReverse(il, instr, ARMV7_INTRIN_VREV32);
		break;
	case armv7::ARMV7_VREV64:
		VectorReverse(il, instr, ARMV7_INTRIN_VREV64);
		break;
	case armv7::ARMV7_VEXT:
		VectorExtract(il, instr);
		break;
	case armv7::ARMV7_VMLA:
	case armv7::ARMV7_VMLS:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			size_t size = GetRegisterSize(instr, 0);
			ExprId product = il.FloatMult(size, ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2));
			if (strncmp(instr->format->operation, "vmla", 4) == 0)
			{
				il.AddInstruction(WriteArithOperand(il, instr,
					il.FloatAdd(size, ReadILOperand(il, instr, 0), product)));
			}
			else if (strncmp(instr->format->operation, "vmls", 4) == 0)
			{
				il.AddInstruction(WriteArithOperand(il, instr,
					il.FloatSub(size, ReadILOperand(il, instr, 0), product)));
			}
			else
			{
				il.AddInstruction(il.Unimplemented());
			}
		}
		else
		{
			uint32_t intrinsic = (strncmp(instr->format->operation, "vmls", 4) == 0) ? ARMV7_INTRIN_VMLS : ARMV7_INTRIN_VMLA;
			if (!VectorMultiplyAccumulateIntrinsic(il, instr, intrinsic))
				il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv7::ARMV7_VMLAL:
	case armv7::ARMV7_VMLSL:
	{
		uint32_t intrinsic = (strncmp(instr->format->operation, "vmlsl", 5) == 0) ? ARMV7_INTRIN_VMLSL : ARMV7_INTRIN_VMLAL;
		if (!VectorMultiplyAccumulateIntrinsic(il, instr, intrinsic))
			il.AddInstruction(il.Unimplemented());
		break;
	}
	case armv7::ARMV7_VMUL:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatMult(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		}
		else
		{
			if (!VectorMultiplyIntrinsic(il, instr))
				il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv7::ARMV7_VQDMULL:
		if (!VectorSaturatingDoublingMultiplyLongIntrinsic(il, instr))
			il.AddInstruction(il.Unimplemented());
		break;
	case armv7::ARMV7_VNMUL:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatNeg(GetRegisterSize(instr, 0),
					il.FloatMult(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2)))));
		}
		else
		{
			// Non scalar unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv7::ARMV7_VCMP:
		FloatCompare(il, instr);
		break;
	case armv7::ARMV7_VDIV:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatDiv(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		}
		else
		{
			// Non scalar unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv7::ARMV7_VNEG:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(
				WriteArithOperand(il, instr, il.FloatNeg(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1))));
		}
		else
		{
			// Non scalar unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv7::ARMV7_VSQRT:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(
				WriteArithOperand(il, instr, il.FloatSqrt(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1))));
		}
		else
		{
			// Non scalar unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv7::ARMV7_VSEL:
	{
		LowLevelILLabel trueCode, falseCode, done;
		size_t size = GetRegisterSize(instr, 0);
		il.AddInstruction(il.If(GetCondition(il, instr->fields[FIELD_cond]), trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1), size));
		il.AddInstruction(il.Goto(done));
		il.MarkLabel(falseCode);
		il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 2), size));
		il.MarkLabel(done);
		break;
	}
	case armv7::ARMV7_VRINTA:
		if (strncmp(instr->format->operation, "vrinta", 6) == 0)
		{
			il.AddInstruction(il.Intrinsic(
				{ RegisterOrFlag::Register(GetRegisterOperand(instr, 0)) },
				ARMV7_INTRIN_VRINTA,
				{ ReadILOperand(il, instr, 1, GetRegisterSize(instr, 0)) }));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, RoundFloatOperand(il, instr), GetRegisterSize(instr, 0)));
		}
		break;
	case armv7::ARMV7_VRINTR:
		il.AddInstruction(WriteILOperand(il, instr, 0, RoundFloatOperand(il, instr), GetRegisterSize(instr, 0)));
		break;
	case armv7::ARMV7_VMRS:
	{
		int status_reg = GetVfpStatusRegister(instr, 1);
		if (status_reg == REG_INVALID)
		{
			il.AddInstruction(il.Unimplemented());
			break;
		}

		if ((instr->format->operands[0].type == OPERAND_FORMAT_RT_MRC) && (instr->fields[FIELD_Rt_mrc] == 15))
		{
			if (status_reg == REGS_FPSCR)
				il.AddInstruction(il.Nop());
			else
				il.AddInstruction(il.Unimplemented());
			break;
		}

		uint32_t dest_reg = GetRegisterOperand(instr, 0);
		if (dest_reg == REG_INVALID)
		{
			il.AddInstruction(il.Unimplemented());
			break;
		}
		il.AddInstruction(il.Intrinsic(
			{ RegisterOrFlag::Register(dest_reg) },
			ARMV7_INTRIN_VMRS,
			{ il.Const(4, status_reg) }
		));
		break;
	}
	case armv7::ARMV7_VMSR:
	{
		int status_reg = GetVfpStatusRegister(instr, 0);
		uint32_t source_reg = GetRegisterOperand(instr, 1);
		if ((status_reg == REG_INVALID) || (source_reg == REG_INVALID))
		{
			il.AddInstruction(il.Unimplemented());
			break;
		}

		il.AddInstruction(il.Intrinsic(
			{},
			ARMV7_INTRIN_VMSR,
			{ il.Const(4, status_reg), il.Register(GetRegisterSize(instr, 1), source_reg) }
		));
		break;
	}
	case armv7::ARMV7_VCVT:
		if (IS_FIELD_PRESENT(instr, FIELD_to_fixed))
		{
			if (IS_FIELD_PRESENT(instr, FIELD_imm))
			{
				// VCVT (between floating-point and fixed-point, Floating-point)
				/* VCVT<c>.F32.<dt> <Sd>,<Sd>,#<imm> */
				/* VCVT<c>.F64.<dt> <Dd>,<Dd>,#<imm> */
				/* VCVT<c>.<dt> <Sd>,<Sd>,#<imm> */
				/* VCVT<c>.<dt> <Dd>,<Dd>,#<imm> */
				size_t floatSize = GetRegisterSize(instr, 0);
				size_t fixedSize = instr->fields[FIELD_size] / 8;
				bool isUnsigned = instr->fields[FIELD_unsigned];
				uint64_t fractionalBits = instr->fields[FIELD_imm];
				auto fixedSource = [&]() {
					ExprId value = ReadILOperand(il, instr, 1, GetRegisterSize(instr, 1));
					if (fixedSize < GetRegisterSize(instr, 1))
						value = il.LowPart(fixedSize, value);
					return value;
				};

				if (instr->fields[FIELD_to_fixed])
				{
					ExprId scaled = il.FloatMult(floatSize,
						ReadILOperand(il, instr, 1, floatSize),
						FixedPointScale(il, floatSize, fractionalBits));
					ExprId converted = il.FloatToInt(floatSize, il.RoundToInt(floatSize, scaled));
					if (isUnsigned)
						converted = il.ZeroExtend(floatSize, converted);
					il.AddInstruction(WriteILOperand(il, instr, 0, converted, floatSize));
				}
				else
				{
					ExprId converted = isUnsigned
						? il.IntToFloat(floatSize, il.ZeroExtend(floatSize, fixedSource()))
						: il.IntToFloat(floatSize, il.SignExtend(floatSize, fixedSource()));
					il.AddInstruction(WriteILOperand(il, instr, 0,
						il.FloatDiv(floatSize, converted, FixedPointScale(il, floatSize, fractionalBits)), floatSize));
				}
			}
			else if (IS_FIELD_PRESENT(instr, FIELD_fbits))
			{
				// VCVT (between floating-point and fixed-point, Advanced SIMD)
				/* VCVT<c>.<dt> <Dd>,<Dm>,#<fbits> */
				/* VCVT<c>.<dt> <Qd>,<Qm>,#<fbits> */
				// TODO: vector and fixed-point unsupported.
			}
		}
		else if (IS_FIELD_PRESENT(instr, FIELD_half_to_single))
		{
			// VCVT (between half-precision and single-precision, Advanced SIMD)
			/* VCVT<c>.F16.F32 <Dd>,<Qm> */
			/* VCVT<c>.F32.F16 <Qd>,<Dm> */
			// TODO: vector and half-precision unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		else if (IS_FIELD_PRESENT(instr, FIELD_double_to_single))
		{
			// VCVT (between double-precision and single-precision)
			/* VCVT<c>.F64.F32 <Dd>,<Sm> */
			/* VCVT<c>.F32.F64 <Sd>,<Dm> */
			il.AddInstruction(WriteILOperand(
				il, instr, 0, il.FloatConvert(GetRegisterSize(instr, 1), ReadILOperand(il, instr, 1))));
			break;
		}
		else if (IS_FIELD_PRESENT(instr, FIELD_to_integer))
		{
			if (IS_FIELD_PRESENT(instr, FIELD_td))
			{
				// VCVT (between floating-point and integer, Advanced SIMD)
				/* VCVT<c>.<dt> <Dd>,<Dm> */  // instr->fields[FIELD_regs] = 1
				/* VCVT<c>.<dt> <Qd>,<Qm> */  // instr->fields[FIELD_regs] = 2
				switch (instr->fields[FIELD_dt])
				{
				case VFP_DATA_SIZE_S32F32:
				case VFP_DATA_SIZE_U32F32:
					// TODO: iterate over vector components
					// break;
				case VFP_DATA_SIZE_F32S32:
				case VFP_DATA_SIZE_F32U32:
					// TODO: iterate over vector components
					// break;
				default:
					// Invalid
					il.AddInstruction(il.Unimplemented());
				}
			}
			else if (instr->fields[FIELD_to_integer])
			{
				// VCVT, VCVTR (between floating-point and integer, Floating-point)
				// TODO: handle distinction of VCVTR:
				// If R is specified, the operation uses the rounding mode specified by the FPSCR.
				// If R is omitted. the operation uses the Round towards Zero rounding mode.
				// (Note: Binary Ninja does not currently support specifying any particular rounding mode, so it doesn't matter.)
				switch (instr->fields[FIELD_dt])
				{
				case VFP_DATA_SIZE_S32F32:
				case VFP_DATA_SIZE_S32F64:
					/* VCVT<c>.S32.F32 <Sd>,<Sm> */
					/* VCVT<c>.S32.F64 <Sd>,<Dm> */
					/* VCVTR<c>.S32.F32 <Sd>,<Sm> */
					/* VCVTR<c>.S32.F64 <Sd>,<Dm> */
					il.AddInstruction(WriteILOperand(
						il, instr, 0, il.SignExtend(GetRegisterSize(instr, 0),
							il.FloatToInt(GetRegisterSize(instr, 0),
								il.RoundToInt(GetRegisterSize(instr, 0),
									ReadILOperand(il, instr, 1))))));
					break;
				case VFP_DATA_SIZE_U32F32:
				case VFP_DATA_SIZE_U32F64:
					/* VCVT<c>.U32.F32 <Sd>,<Sm> */
					/* VCVT<c>.U32.F64 <Sd>,<Dm> */
					/* VCVTR<c>.U32.F32 <Sd>,<Sm> */
					/* VCVTR<c>.U32.F64 <Sd>,<Dm> */
					il.AddInstruction(WriteILOperand(
						il, instr, 0, il.ZeroExtend(GetRegisterSize(instr, 0),
							il.FloatToInt(GetRegisterSize(instr, 0),
								il.RoundToInt(GetRegisterSize(instr, 0),
									ReadILOperand(il, instr, 1))))));
					break;
				default:
					// Invalid
					il.AddInstruction(il.Unimplemented());
				}
			}
			else
			{
				// VCVT, VCVTR (between floating-point and integer, Floating-point)
				switch (instr->fields[FIELD_dt])
				{
				case VFP_DATA_SIZE_S32:
					/* VCVT<c>.F32.<dt> <Sd>,<Sm> */
					il.AddInstruction(WriteILOperand(
						il, instr, 0, il.IntToFloat(GetRegisterSize(instr, 0),
							il.SignExtend(GetRegisterSize(instr, 0),
								ReadILOperand(il, instr, 1)))));
					break;
				case VFP_DATA_SIZE_U32:
					/* VCVT<c>.F64.<dt> <Dd>,<Sm> */
					il.AddInstruction(WriteILOperand(
						il, instr, 0, il.IntToFloat(GetRegisterSize(instr, 0),
							il.ZeroExtend(GetRegisterSize(instr, 0),
								ReadILOperand(il, instr, 1)))));
					break;
				default:
					// Invalid
					il.AddInstruction(il.Unimplemented());
				}
			}
		}
		else
			il.AddInstruction(il.Unimplemented());
		break;
	case armv7::ARMV7_VMOV:
		if (instr->format->operandCount == 4)
		{
			// s1 <- r2, s2 <- r4
			// r1 <- s0, r7 <- s1
			il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 2)));
			il.AddInstruction(WriteILOperand(il, instr, 1, ReadILOperand(il, instr, 3)));
		}
		else if (instr->format->operandCount == 3)
		{
			if (instr->format->operands[2].type == OPERAND_FORMAT_REG_FP)
			{

				uint32_t RdLo = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
				uint32_t RdHi = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);

				// r3:r2 <- d12
				il.AddInstruction(il.SetRegisterSplit(
					4, RdHi, RdLo, ReadILOperand(il, instr, 2, 8)));
			}
			else
			{
				uint32_t Rm = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
				uint32_t Rn = GetRegisterByIndex(instr->fields[instr->format->operands[2].field0]);

				// d9 <- r1:r0
				il.AddInstruction(WriteILOperand(
					il, instr, 0, il.RegisterSplit(4, Rn, Rm), 8));
			}
		}
		else /* if (instr->format->operandCount == 2) */
		{
			if (instr->format->operands[0].type == OPERAND_FORMAT_REG_INDEX)
			{
				const instruction_operand_format& op = instr->format->operands[0];
				size_t regSize = RegisterSizeFromPrefix(op.prefix);
				uint32_t reg = GetRegisterByIndex(instr->fields[op.field0], op.prefix);
				il.AddInstruction(il.SetRegister(regSize, reg,
					InsertVectorElement(il, instr, 0, ReadILOperand(il, instr, 1), GetRegisterSize(instr, 1))));
			}
			else if (instr->format->operands[1].type == OPERAND_FORMAT_REG_INDEX)
			{
				il.AddInstruction(WriteILOperand(il, instr, 0,
					ReadVectorElement(il, instr, 1, GetRegisterSize(instr, 0))));
			}
			else if (instr->format->operands[1].type == OPERAND_FORMAT_IMM64 && strcmp(instr->format->operands[0].prefix, "q") == 0)
				// Load immediate in high and low
				il.AddInstruction(WriteILOperand(il, instr, 0,
					il.Or(16, ReadILOperand(il, instr, 1),
						il.ShiftLeft(16, ReadILOperand(il, instr, 1), il.Const(8, 64)), 16)));
			else
				// Load immediate or reg -> reg
				// r2 <= s4
				// s12 <- r8
				il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1)));
			// Note: the code below is more exlicit about the logic, but equivalent to the above:
			// if (instr->format->operands[1].type == OPERAND_FORMAT_IMM64)
			// {
			// 	if (strcmp(instr->format->operands[0].prefix, "q") == 0)
			// 		// Load immediate in high and low
			// 		il.AddInstruction(WriteILOperand(il, instr, 0,
			// 			il.Or(16, ReadILOperand(il, instr, 1),
			// 				il.ShiftLeft(16, ReadILOperand(il, instr, 1), il.Const(8, 64)), 16)));
			// 	else
			// 		// Load immediate
			// 		il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1)));
			// }
			// else
			// {
			// 	// r2 <= s4
			// 	// s12 <- r8
			// 	il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1)));
			// }
		}
		break;
	case armv7::ARMV7_VSTM:
	case armv7::ARMV7_VSTMDB:
	case armv7::ARMV7_VSTMIA:
	{
		VfpLoadStoreMultiple(il, instr, false);
		break;
	}
	case armv7::ARMV7_VST1:
	{
		ExprId base = GetMemoryAddress(il, instr, 1, 4, false);
		size_t totalSize = 0;

		if (instr->format->operands[0].type == OPERAND_FORMAT_REGISTERS)
		{
			unsigned int d = instr->fields[FIELD_d];
			unsigned int inc = 1;
			if (IS_FIELD_PRESENT(instr, FIELD_inc))
				inc = instr->fields[FIELD_inc];
			int regs = instr->fields[FIELD_regs];
			for (int i = 0; i < regs; ++i)
			{
				int regIdx = (d + i * inc) % 32;
				size_t offset = i * 8;
				il.AddInstruction(il.Store(8,
					offset == 0 ? base : il.Add(4, base, il.Const(4, offset)),
					il.Register(8, GetRegisterByIndex(regIdx, "d"))));
			}
			totalSize = regs * 8;
		}
		else if (instr->format->operands[0].type == OPERAND_FORMAT_REGISTERS_INDEXED)
		{
			size_t elementSize = instr->fields[FIELD_ebytes];
			unsigned int d = instr->fields[FIELD_d];
			unsigned int inc = 1;
			if (IS_FIELD_PRESENT(instr, FIELD_inc))
				inc = instr->fields[FIELD_inc];
			unsigned int index = instr->fields[FIELD_index];
			int length = instr->fields[FIELD_length];
			for (int i = 0; i < length; ++i)
			{
				int regIdx = (d + i * inc) % 32;
				size_t offset = i * elementSize;
				il.AddInstruction(il.Store(elementSize,
					offset == 0 ? base : il.Add(4, base, il.Const(4, offset)),
					ReadVst1Element(il, GetRegisterByIndex(regIdx, "d"), elementSize, index)));
			}
			totalSize = length * elementSize;
		}
		else
		{
			il.AddInstruction(il.Unimplemented());
			break;
		}

		if (HasNeonLoadStoreWriteback(instr, 1))
		{
			uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			if (IS_FIELD_PRESENT(instr, FIELD_register_index) && instr->fields[FIELD_register_index])
			{
				uint32_t indexReg = GetRegisterByIndex(instr->fields[FIELD_m]);
				il.AddInstruction(il.SetRegister(4, baseReg,
					il.Add(4, il.Register(4, baseReg), il.Register(4, indexReg))));
			}
			else
			{
				il.AddInstruction(il.SetRegister(4, baseReg,
					il.Add(4, il.Register(4, baseReg), il.Const(4, totalSize))));
			}
		}
		break;
	}
	case armv7::ARMV7_VST2:
		StructuredVectorStoreIntrinsic(il, instr, ARMV7_INTRIN_VST2, 2);
		break;
	case armv7::ARMV7_VST4:
		StructuredVectorStoreIntrinsic(il, instr, ARMV7_INTRIN_VST4, 4);
		break;
	case armv7::ARMV7_VLD2:
		StructuredVectorLoadIntrinsic(il, instr, ARMV7_INTRIN_VLD2, 2);
		break;
	case armv7::ARMV7_VLD4:
		StructuredVectorLoadIntrinsic(il, instr, ARMV7_INTRIN_VLD4, 4);
		break;
	case armv7::ARMV7_VLD1:
	{
		ExprId base = GetMemoryAddress(il, instr, 1, 4, false);
		size_t totalSize = 0;

		if (instr->format->operands[0].type == OPERAND_FORMAT_REGISTERS)
		{
			unsigned int d = instr->fields[FIELD_d];
			unsigned int inc = 1;
			if (IS_FIELD_PRESENT(instr, FIELD_inc))
				inc = instr->fields[FIELD_inc];
			int regs = IS_FIELD_PRESENT(instr, FIELD_regs_n) ? instr->fields[FIELD_regs_n] : instr->fields[FIELD_regs];
			for (int i = 0; i < regs; ++i)
			{
				int regIdx = (d + i * inc) % 32;
				size_t offset = i * 8;
				il.AddInstruction(il.SetRegister(8, GetRegisterByIndex(regIdx, "d"),
					il.Load(8, offset == 0 ? base : il.Add(4, base, il.Const(4, offset)))));
			}
			totalSize = regs * 8;
		}
		else if (instr->format->operands[0].type == OPERAND_FORMAT_REGISTERS_INDEXED)
		{
			size_t elementSize = instr->fields[FIELD_ebytes];
			unsigned int d = instr->fields[FIELD_d];
			unsigned int inc = 1;
			if (IS_FIELD_PRESENT(instr, FIELD_inc))
				inc = instr->fields[FIELD_inc];
			unsigned int index = instr->fields[FIELD_index];
			int length = instr->fields[FIELD_length];
			for (int i = 0; i < length; ++i)
			{
				int regIdx = (d + i * inc) % 32;
				size_t offset = i * elementSize;
				uint32_t reg = GetRegisterByIndex(regIdx, "d");
				il.AddInstruction(il.SetRegister(8, reg,
					InsertVld1Element(il, reg,
						il.Load(elementSize, offset == 0 ? base : il.Add(4, base, il.Const(4, offset))),
						elementSize, index)));
			}
			totalSize = length * elementSize;
		}
		else
		{
			il.AddInstruction(il.Unimplemented());
			break;
		}

		if (HasNeonLoadStoreWriteback(instr, 1))
		{
			uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			if (IS_FIELD_PRESENT(instr, FIELD_register_index) && instr->fields[FIELD_register_index])
			{
				uint32_t indexReg = GetRegisterByIndex(instr->fields[FIELD_m]);
				il.AddInstruction(il.SetRegister(4, baseReg,
					il.Add(4, il.Register(4, baseReg), il.Register(4, indexReg))));
			}
			else
			{
				il.AddInstruction(il.SetRegister(4, baseReg,
					il.Add(4, il.Register(4, baseReg), il.Const(4, totalSize))));
			}
		}
		break;
	}
	case armv7::ARMV7_VLDM:
	case armv7::ARMV7_VLDMDB:
	case armv7::ARMV7_VLDMIA:
	{
		VfpLoadStoreMultiple(il, instr, true);
		break;
	}
	case armv7::ARMV7_VPUSH:
	{
		// TODO: Clean this code up...
		const char* prefix = "d";
		if (IS_FIELD_PRESENT(instr, FIELD_single_regs))
		{
			if (instr->fields[FIELD_single_regs] == 1)
			{
				prefix = "s";
			}
		}
		auto regSize = RegisterSizeFromPrefix(prefix);
		unsigned int d = instr->fields[FIELD_d];
		unsigned int inc = 1;
		if (IS_FIELD_PRESENT(instr, FIELD_inc))
			inc = instr->fields[FIELD_inc];
		int regs = instr->fields[FIELD_regs];
		for (int i = 0; i < regs; ++i)
		{
			if (d + (i * inc) >= 32 && strcmp(prefix, "s") == 0)
				break;
			if (i >= 16 && strcmp(prefix, "d") == 0)
				break;
			int regIdx = (d + i * inc) % 32;
			il.AddInstruction(il.Push(regSize, il.Register(regSize, GetRegisterByIndex(regIdx, prefix))));
		}
		break;
	}
	case armv7::ARMV7_VPOP:
	{
		// TODO: Clean this code up...
		const char* prefix = "d";
		if (IS_FIELD_PRESENT(instr, FIELD_single_regs))
		{
			if (instr->fields[FIELD_single_regs] == 1)
			{
				prefix = "s";
			}
		}
		auto regSize = RegisterSizeFromPrefix(prefix);
		unsigned int d = instr->fields[FIELD_d];
		unsigned int inc = 1;
		if (IS_FIELD_PRESENT(instr, FIELD_inc))
			inc = instr->fields[FIELD_inc];
		int regs = instr->fields[FIELD_regs];
		for (int i = 0; i < regs; ++i)
		{
			if (d + (i * inc) >= 32 && strcmp(prefix, "s") == 0)
				break;
			if (i >= 16 && strcmp(prefix, "d") == 0)
				break;
			int regIdx = (d + i * inc) % 32;
			il.AddInstruction(il.SetRegister(regSize, GetRegisterByIndex(regIdx, prefix), il.Pop(regSize)));
		}
		break;
	}
	case armv7::ARMV7_VLDR:
	{
		uint32_t regSize = RegisterSizeFromPrefix(instr->format->operands[1].prefix);
		if (instr->format->operandCount == 3)
		{
			uint32_t reg =
				GetRegisterByIndex(instr->fields[instr->format->operands[1].field0], instr->format->operands[1].prefix);
			il.AddInstruction(
				WriteILOperand(il, instr, 0, il.Load(regSize, GetMemoryAddress(il, instr, 1, regSize, false))));
			il.AddInstruction(
				il.SetRegister(regSize, reg, il.Add(regSize, il.Register(regSize, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0,
				il.Load(regSize,
					GetMemoryAddress(il, instr, 1, 4, true, 4))));
		}
		break;
	}
	case armv7::ARMV7_VSTR:
	{
		uint32_t regSize = RegisterSizeFromPrefix(instr->format->operands[1].prefix);
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0], instr->format->operands[1].prefix);
			il.AddInstruction(
				il.Store(regSize, GetMemoryAddress(il, instr, 1, regSize, false), ReadILOperand(il, instr, 0)));
			il.AddInstruction(
				il.SetRegister(regSize, reg, il.Add(regSize, il.Register(regSize, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(il.Store(regSize, GetMemoryAddress(il, instr, 1, regSize), ReadILOperand(il, instr, 0)));
		}
		break;
	}
	default:
		il.AddInstruction(il.Unimplemented());
		break;
	}
	return true;
}
