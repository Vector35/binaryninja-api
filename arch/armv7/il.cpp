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

static uint32_t GetDmbIntrinsic(DsbOption option)
{
	switch (option)
	{
	case DSB_SY:
		return ARMV7_INTRIN_DMB_SY;
	case DSB_ST:
		return ARMV7_INTRIN_DMB_ST;
	case DSB_ISH:
		return ARMV7_INTRIN_DMB_ISH;
	case DSB_ISHST:
		return ARMV7_INTRIN_DMB_ISHST;
	case DSB_NSH:
		return ARMV7_INTRIN_DMB_NSH;
	case DSB_NSHST:
		return ARMV7_INTRIN_DMB_NSHST;
	case DSB_OSH:
		return ARMV7_INTRIN_DMB_OSH;
	case DSB_OSHST:
		return ARMV7_INTRIN_DMB_OSHST;
	default:
		return 0;
	}
}

static uint32_t GetDsbIntrinsic(DsbOption option)
{
	switch (option)
	{
	case DSB_SY:
		return ARMV7_INTRIN_DSB_SY;
	case DSB_ST:
		return ARMV7_INTRIN_DSB_ST;
	case DSB_ISH:
		return ARMV7_INTRIN_DSB_ISH;
	case DSB_ISHST:
		return ARMV7_INTRIN_DSB_ISHST;
	case DSB_NSH:
		return ARMV7_INTRIN_DSB_NSH;
	case DSB_NSHST:
		return ARMV7_INTRIN_DSB_NSHST;
	case DSB_OSH:
		return ARMV7_INTRIN_DSB_OSH;
	case DSB_OSHST:
		return ARMV7_INTRIN_DSB_OSHST;
	default:
		return 0;
	}
}

static uint32_t GetCrc32Intrinsic(Operation operation)
{
	switch (operation)
	{
	case ARMV7_CRC32B:
		return ARMV7_INTRIN_CRC32B;
	case ARMV7_CRC32CB:
		return ARMV7_INTRIN_CRC32CB;
	case ARMV7_CRC32CH:
		return ARMV7_INTRIN_CRC32CH;
	case ARMV7_CRC32CW:
		return ARMV7_INTRIN_CRC32CW;
	case ARMV7_CRC32H:
		return ARMV7_INTRIN_CRC32H;
	case ARMV7_CRC32W:
		return ARMV7_INTRIN_CRC32W;
	default:
		return 0;
	}
}

static size_t GetCrc32ValueSize(Operation operation)
{
	switch (operation)
	{
	case ARMV7_CRC32B:
	case ARMV7_CRC32CB:
		return 1;
	case ARMV7_CRC32H:
	case ARMV7_CRC32CH:
		return 2;
	case ARMV7_CRC32W:
	case ARMV7_CRC32CW:
		return 4;
	default:
		return 0;
	}
}

static size_t GetDataTypeSize(DataType dataType)
{
	switch (dataType)
	{
	case DT_8:
	case DT_S8:
	case DT_U8:
	case DT_I8:
	case DT_P8:
		return 1;
	case DT_16:
	case DT_S16:
	case DT_U16:
	case DT_I16:
	case DT_F16:
	case DT_P16:
		return 2;
	case DT_32:
	case DT_S32:
	case DT_U32:
	case DT_I32:
	case DT_F32:
	case DT_P32:
		return 4;
	case DT_64:
	case DT_S64:
	case DT_U64:
	case DT_I64:
	case DT_F64:
	case DT_P64:
		return 8;
	default:
		return 0;
	}
}

static bool IsSignedDataType(DataType dataType)
{
	switch (dataType)
	{
	case DT_S8:
	case DT_S16:
	case DT_S32:
	case DT_S64:
	case DT_I8:
	case DT_I16:
	case DT_I32:
	case DT_I64:
		return true;
	default:
		return false;
	}
}

static bool IsUnsignedDataType(DataType dataType)
{
	switch (dataType)
	{
	case DT_U8:
	case DT_U16:
	case DT_U32:
	case DT_U64:
		return true;
	default:
		return false;
	}
}

static ExprId ReadVectorElement(LowLevelILFunction& il, InstructionOperand& op, size_t elementSize, size_t outputSize, bool isSigned)
{
	size_t regSize = get_register_size(op.reg);
	size_t shift = op.imm * elementSize * 8;
	ExprId value = il.Register(regSize, op.reg);
	if (shift != 0)
		value = il.LogicalShiftRight(regSize, value, il.Const(1, shift));
	value = il.LowPart(elementSize, value);
	if (outputSize > elementSize)
		return isSigned ? il.SignExtend(outputSize, value) : il.ZeroExtend(outputSize, value);
	return value;
}

static ExprId ReadVectorElement(LowLevelILFunction& il, Register reg, size_t elementSize, size_t index)
{
	size_t regSize = get_register_size(reg);
	size_t shift = index * elementSize * 8;
	ExprId value = il.Register(regSize, reg);
	if (shift != 0)
		value = il.LogicalShiftRight(regSize, value, il.Const(1, shift));
	return il.LowPart(elementSize, value);
}

static ExprId InsertVectorElement(LowLevelILFunction& il, InstructionOperand& dst, ExprId src, size_t elementSize)
{
	size_t regSize = get_register_size(dst.reg);
	size_t shift = dst.imm * elementSize * 8;
	size_t elementBits = elementSize * 8;
	uint64_t elementMask = (elementBits == 64) ? UINT64_MAX : ((1ULL << elementBits) - 1);
	uint64_t shiftedMask = elementMask << shift;

	ExprId value = il.LowPart(elementSize, src);
	if (regSize > elementSize)
		value = il.ZeroExtend(regSize, value);
	if (shift != 0)
		value = il.ShiftLeft(regSize, value, il.Const(1, shift));

	return il.Or(regSize,
		il.And(regSize, il.Register(regSize, dst.reg), il.Const(regSize, ~shiftedMask)),
		value);
}

static ExprId InsertVectorElement(LowLevelILFunction& il, Register reg, ExprId src, size_t elementSize, size_t index)
{
	size_t regSize = get_register_size(reg);
	size_t shift = index * elementSize * 8;
	size_t elementBits = elementSize * 8;
	uint64_t elementMask = (elementBits == 64) ? UINT64_MAX : ((1ULL << elementBits) - 1);
	uint64_t shiftedMask = elementMask << shift;

	ExprId value = src;
	if (regSize > elementSize)
		value = il.ZeroExtend(regSize, value);
	if (shift != 0)
		value = il.ShiftLeft(regSize, value, il.Const(1, shift));

	return il.Or(regSize,
		il.And(regSize, il.Register(regSize, reg), il.Const(regSize, ~shiftedMask)),
		value);
}

static ExprId LowHalf(LowLevelILFunction& il, ExprId value)
{
	return il.LowPart(2, value);
}

static ExprId SignedHighHalf(LowLevelILFunction& il, ExprId value)
{
	return il.LowPart(2, il.ArithShiftRight(4, value, il.Const(1, 16)));
}

static ExprId SignedHalf(LowLevelILFunction& il, ExprId value, bool high)
{
	return il.SignExtend(4, high ? SignedHighHalf(il, value) : LowHalf(il, value));
}

static ExprId SignedHalfProduct32(LowLevelILFunction& il, ExprId lhs, bool lhsHigh, ExprId rhs, bool rhsHigh)
{
	return il.LowPart(4, il.Mult(4, SignedHalf(il, lhs, lhsHigh), SignedHalf(il, rhs, rhsHigh)));
}

static ExprId SignedHalfProduct64(LowLevelILFunction& il, ExprId lhs, bool lhsHigh, ExprId rhs, bool rhsHigh)
{
	return il.SignExtend(8, il.Mult(4, SignedHalf(il, lhs, lhsHigh), SignedHalf(il, rhs, rhsHigh)));
}

static ExprId SignedWordHalfProduct64(LowLevelILFunction& il, ExprId word, ExprId halfwordSource, bool high)
{
	return il.Mult(8, il.SignExtend(8, word), il.SignExtend(8, SignedHalf(il, halfwordSource, high)));
}

static ExprId UnsignedHighHalf(LowLevelILFunction& il, ExprId value)
{
	return il.LowPart(2, il.LogicalShiftRight(4, value, il.Const(1, 16)));
}

static ExprId PackHalfwords(LowLevelILFunction& il, ExprId low, ExprId high)
{
	return il.Or(4,
		il.ShiftLeft(4, il.ZeroExtend(4, il.LowPart(2, high)), il.Const(1, 16)),
		il.ZeroExtend(4, il.LowPart(2, low)));
}

static ExprId ReadFloatOperand(LowLevelILFunction& il, InstructionOperand& op, size_t size)
{
	switch (op.cls)
	{
	case REG:
		return il.Register(size, op.reg);
	case FIMM32:
		return il.FloatConstRaw(size, op.imm);
	case FIMM64:
		return il.FloatConstRaw(size, op.imm64);
	default:
		return il.Unimplemented();
	}
}

static void FloatCompare(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& lhsOp = instr.operands[0];
	InstructionOperand& rhsOp = instr.operands[1];
	size_t size = get_register_size(lhsOp.reg);
	ExprId lhs = ReadFloatOperand(il, lhsOp, size);
	ExprId rhs = (rhsOp.cls == NONE) ? il.FloatConstRaw(size, 0) : ReadFloatOperand(il, rhsOp, size);

	il.AddInstruction(il.FloatSub(size, lhs, rhs, IL_FLAGWRITE_FLOAT_COMPARE));
}

static ExprId RoundFloatOperand(LowLevelILFunction& il, Instruction& instr, ExprId src, size_t size)
{
	switch (instr.operation)
	{
	case ARMV7_VRINTN:
	case ARMV7_VRINTR:
	case ARMV7_VRINTX:
		return il.RoundToInt(size, src);
	case ARMV7_VRINTP:
		return il.Ceil(size, src);
	case ARMV7_VRINTM:
		return il.Floor(size, src);
	case ARMV7_VRINTZ:
		return il.FloatTrunc(size, src);
	default:
		return il.Unimplemented();
	}
}

static ExprId FixedPointScale(LowLevelILFunction& il, size_t size, uint64_t fractionalBits)
{
	double scale = static_cast<double>(UINT64_C(1) << fractionalBits);
	if (size == 8)
		return il.FloatConstDouble(scale);
	return il.FloatConstSingle(static_cast<float>(scale));
}

static bool GetDoubleRegisterList(Register regList, std::vector<Register>& regs)
{
	for (uint32_t i = 0; i < 32; i++)
	{
		if (((static_cast<uint32_t>(regList) >> i) & 1) != 0)
			regs.push_back(static_cast<Register>(REG_D0 + i));
	}
	return !regs.empty() && regs.size() <= 4;
}

static ExprId VectorTableLookup(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& destOp = instr.operands[0];
	InstructionOperand& tableOp = instr.operands[1];
	InstructionOperand& indicesOp = instr.operands[2];
	if (destOp.cls != REG || tableOp.cls != REG_LIST_DOUBLE || indicesOp.cls != REG)
		return il.Unimplemented();

	std::vector<Register> tableRegs;
	if (!GetDoubleRegisterList(tableOp.reg, tableRegs))
		return il.Unimplemented();

	std::vector<ExprId> inputs;
	inputs.push_back(il.Const(1, tableRegs.size()));
	for (size_t i = 0; i < 4; i++)
	{
		if (i < tableRegs.size())
			inputs.push_back(il.Register(8, tableRegs[i]));
		else
			inputs.push_back(il.Const(8, 0));
	}
	inputs.push_back(il.Register(8, indicesOp.reg));

	bool isVtbl = instr.operation == ARMV7_VTBL;
	if (!isVtbl)
		inputs.push_back(il.Register(8, destOp.reg));

	return il.Intrinsic(
		{ RegisterOrFlag::Register(destOp.reg) },
		isVtbl ? ARMV7_INTRIN_VTBL : ARMV7_INTRIN_VTBX,
		inputs);
}

static void HalvingVectorAdd(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];
	size_t regSize = get_register_size(dst.reg);
	size_t elementSize = GetDataTypeSize(instr.dataType);

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG || regSize == 0 || elementSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		ARMV7_INTRIN_VHADD,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, IsSignedDataType(instr.dataType) ? 0 : 1),
			il.Register(get_register_size(src1.reg), src1.reg),
			il.Register(get_register_size(src2.reg), src2.reg),
		}));
}

static ExprId SaturatingVectorShiftRightNarrow(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src = instr.operands[1];
	InstructionOperand& shift = instr.operands[2];

	if (dst.cls != REG || src.cls != REG || shift.cls != IMM)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t sourceSize = get_register_size(src.reg);
	if (elementSize == 0 || sourceSize == 0)
		return il.Unimplemented();

	bool sourceUnsigned = (instr.operation == ARMV7_VQSHRUN) ? false : !IsSignedDataType(instr.dataType);
	if (instr.operation == ARMV7_VQRSHRUN)
		sourceUnsigned = false;
	bool destinationUnsigned = (instr.operation == ARMV7_VQSHRUN || instr.operation == ARMV7_VQRSHRUN)
		? true
		: sourceUnsigned;
	uint32_t intrinsic = (instr.operation == ARMV7_VQSHRUN) ? ARMV7_INTRIN_VQSHRUN : ARMV7_INTRIN_VQSHRN;
	if (instr.operation == ARMV7_VQRSHRUN)
		intrinsic = ARMV7_INTRIN_VQRSHRUN;
	else if (instr.operation == ARMV7_VQRSHRN)
		intrinsic = ARMV7_INTRIN_VQRSHRN;

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		intrinsic,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, sourceUnsigned ? 1 : 0),
			il.Const(1, destinationUnsigned ? 1 : 0),
			il.Register(sourceSize, src.reg),
			il.Const(sourceSize, shift.imm),
		});
}

static ExprId SaturatingVectorMoveNarrow(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src = instr.operands[1];

	if (dst.cls != REG || src.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t sourceSize = get_register_size(src.reg);
	if (elementSize == 0 || sourceSize == 0)
		return il.Unimplemented();

	bool sourceUnsigned = !IsSignedDataType(instr.dataType);
	bool destinationUnsigned = sourceUnsigned || (instr.operation == ARMV7_VQMOVUN);

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		(instr.operation == ARMV7_VQMOVUN) ? ARMV7_INTRIN_VQMOVUN : ARMV7_INTRIN_VQMOVN,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, sourceUnsigned ? 1 : 0),
			il.Const(1, destinationUnsigned ? 1 : 0),
			il.Register(sourceSize, src.reg),
		});
}

static ExprId RoundedVectorShift(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src = instr.operands[1];
	InstructionOperand& shift = instr.operands[2];

	if (dst.cls != REG || src.cls != REG || (shift.cls != IMM && shift.cls != REG))
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t regSize = get_register_size(dst.reg);
	if (elementSize == 0 || regSize == 0)
		return il.Unimplemented();

	ExprId shiftValue = shift.cls == IMM
		? il.Const(regSize, shift.imm)
		: il.Register(regSize, shift.reg);

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		(instr.operation == ARMV7_VRSHL) ? ARMV7_INTRIN_VRSHL : ARMV7_INTRIN_VRSHR,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, IsSignedDataType(instr.dataType) ? 0 : 1),
			il.Register(regSize, src.reg),
			shiftValue,
		});
}

static ExprId ShiftRightAccumulateOrInsert(LowLevelILFunction& il, Instruction& instr, uint32_t intrinsic)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src = instr.operands[1];
	InstructionOperand& shift = instr.operands[2];

	if (dst.cls != REG || src.cls != REG || shift.cls != IMM)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t regSize = get_register_size(dst.reg);
	if (elementSize == 0 || regSize == 0)
		return il.Unimplemented();

	if (intrinsic == ARMV7_INTRIN_VSRA || intrinsic == ARMV7_INTRIN_VRSRA)
	{
		return il.Intrinsic(
			{ RegisterOrFlag::Register(dst.reg) },
			intrinsic,
			{
				il.Const(1, elementSize * 8),
				il.Const(1, IsSignedDataType(instr.dataType) ? 0 : 1),
				il.Register(regSize, dst.reg),
				il.Register(regSize, src.reg),
				il.Const(regSize, shift.imm),
			});
	}

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		intrinsic,
		{
			il.Const(1, elementSize * 8),
			il.Register(regSize, dst.reg),
			il.Register(regSize, src.reg),
			il.Const(regSize, shift.imm),
		});
}

static ExprId VectorDuplicate(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src = instr.operands[1];

	if (dst.cls != REG || src.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t destSize = get_register_size(dst.reg);
	size_t sourceSize = get_register_size(src.reg);
	if (elementSize == 0 || destSize == 0 || sourceSize == 0)
		return il.Unimplemented();

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		ARMV7_INTRIN_VDUP,
		{
			il.Const(1, elementSize * 8),
			il.Register(sourceSize, src.reg),
			il.Const(1, src.flags.hasElements ? src.imm : 0),
		});
}

static ExprId SaturatingVectorAdd(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t regSize = get_register_size(dst.reg);
	if (elementSize == 0 || regSize == 0)
		return il.Unimplemented();

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		ARMV7_INTRIN_VQADD,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, IsSignedDataType(instr.dataType) ? 0 : 1),
			il.Register(regSize, src1.reg),
			il.Register(regSize, src2.reg),
		});
}

static ExprId VectorAddSubtract(LowLevelILFunction& il, Instruction& instr, uint32_t intrinsic)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t regSize = get_register_size(dst.reg);
	if (elementSize == 0 || regSize == 0)
		return il.Unimplemented();

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		intrinsic,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, IsSignedDataType(instr.dataType) ? 0 : 1),
			il.Register(regSize, src1.reg),
			il.Register(regSize, src2.reg),
		});
}

static void AddParallelGEIntrinsic(
	LowLevelILFunction& il, enum Register dest, uint32_t intrinsic, ExprId source1, ExprId source2)
{
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dest), RegisterOrFlag::Register(REGS_APSR_G) },
		intrinsic,
		{ source1, source2 }));
}

static ExprId QFlagIntrinsic(
	LowLevelILFunction& il, enum Register dest, uint32_t intrinsic, const std::vector<ExprId>& inputs)
{
	return il.Intrinsic(
		{ RegisterOrFlag::Register(dest), RegisterOrFlag::Flag(IL_FLAG_Q) },
		intrinsic,
		inputs);
}

static ExprId SaturatingVectorShiftLeft(LowLevelILFunction& il, Instruction& instr, uint32_t intrinsic)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src = instr.operands[1];
	InstructionOperand& shift = instr.operands[2];

	if (dst.cls != REG || src.cls != REG || shift.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t regSize = get_register_size(dst.reg);
	if (elementSize == 0 || regSize == 0)
		return il.Unimplemented();

	bool isUnsigned = !IsSignedDataType(instr.dataType);
	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		intrinsic,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, isUnsigned ? 1 : 0),
			il.Const(1, isUnsigned ? 1 : 0),
			il.Register(regSize, src.reg),
			il.Register(regSize, shift.reg),
		});
}

static ExprId VectorMaximumMinimum(LowLevelILFunction& il, Instruction& instr, uint32_t intrinsic)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t regSize = get_register_size(dst.reg);
	if (elementSize == 0 || regSize == 0)
		return il.Unimplemented();

	bool isUnsigned = !IsSignedDataType(instr.dataType) && instr.dataType != DT_F32 && instr.dataType != DT_F64;
	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		intrinsic,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, isUnsigned ? 1 : 0),
			il.Register(get_register_size(src1.reg), src1.reg),
			il.Register(get_register_size(src2.reg), src2.reg),
		});
}

static ExprId VectorReverse(LowLevelILFunction& il, Instruction& instr, uint32_t intrinsic)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src = instr.operands[1];

	if (dst.cls != REG || src.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t destSize = get_register_size(dst.reg);
	size_t sourceSize = get_register_size(src.reg);
	if (elementSize == 0 || destSize == 0 || sourceSize == 0)
		return il.Unimplemented();

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		intrinsic,
		{
			il.Const(1, elementSize * 8),
			il.Register(sourceSize, src.reg),
		});
}

static ExprId VectorExtract(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];
	InstructionOperand& index = instr.operands[3];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG || index.cls != IMM)
		return il.Unimplemented();

	size_t destSize = get_register_size(dst.reg);
	size_t source1Size = get_register_size(src1.reg);
	size_t source2Size = get_register_size(src2.reg);
	if (destSize == 0 || source1Size == 0 || source2Size == 0)
		return il.Unimplemented();

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		ARMV7_INTRIN_VEXT,
		{
			il.Const(1, 8),
			il.Register(source1Size, src1.reg),
			il.Register(source2Size, src2.reg),
			il.Const(1, index.imm),
		});
}

static ExprId VectorAbsoluteDifferenceAccumulate(LowLevelILFunction& il, Instruction& instr, uint32_t intrinsic)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t destSize = get_register_size(dst.reg);
	size_t sourceSize = get_register_size(src1.reg);
	if (elementSize == 0 || destSize == 0 || sourceSize == 0)
		return il.Unimplemented();

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		intrinsic,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, IsSignedDataType(instr.dataType) ? 0 : 1),
			il.Register(destSize, dst.reg),
			il.Register(sourceSize, src1.reg),
			il.Register(get_register_size(src2.reg), src2.reg),
		});
}

static ExprId VectorAbsoluteDifference(LowLevelILFunction& il, Instruction& instr, uint32_t intrinsic)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t destSize = get_register_size(dst.reg);
	size_t source1Size = get_register_size(src1.reg);
	size_t source2Size = get_register_size(src2.reg);
	if (elementSize == 0 || destSize == 0 || source1Size == 0 || source2Size == 0)
		return il.Unimplemented();

	bool isUnsigned = !IsSignedDataType(instr.dataType) && instr.dataType != DT_F32 && instr.dataType != DT_F64;
	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		intrinsic,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, isUnsigned ? 1 : 0),
			il.Register(source1Size, src1.reg),
			il.Register(source2Size, src2.reg),
		});
}

static ExprId VectorWideningAdd(LowLevelILFunction& il, Instruction& instr, uint32_t intrinsic)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t destSize = get_register_size(dst.reg);
	size_t source1Size = get_register_size(src1.reg);
	size_t source2Size = get_register_size(src2.reg);
	if (elementSize == 0 || destSize == 0 || source1Size == 0 || source2Size == 0)
		return il.Unimplemented();

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		intrinsic,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, IsSignedDataType(instr.dataType) ? 0 : 1),
			il.Register(source1Size, src1.reg),
			il.Register(source2Size, src2.reg),
		});
}

static ExprId VectorRoundingAddNarrow(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t destSize = get_register_size(dst.reg);
	size_t source1Size = get_register_size(src1.reg);
	size_t source2Size = get_register_size(src2.reg);
	if (elementSize == 0 || destSize == 0 || source1Size == 0 || source2Size == 0)
		return il.Unimplemented();

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		ARMV7_INTRIN_VRADDHN,
		{
			il.Const(1, elementSize * 8),
			il.Register(source1Size, src1.reg),
			il.Register(source2Size, src2.reg),
		});
}

static ExprId VectorMultiply(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t destSize = get_register_size(dst.reg);
	size_t source1Size = get_register_size(src1.reg);
	size_t source2Size = get_register_size(src2.reg);
	if (elementSize == 0 || destSize == 0 || source1Size == 0 || source2Size == 0)
		return il.Unimplemented();

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		ARMV7_INTRIN_VMUL,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, IsUnsignedDataType(instr.dataType) ? 1 : 0),
			il.Register(source1Size, src1.reg),
			il.Register(source2Size, src2.reg),
		});
}

static ExprId VectorMultiplyAccumulateIntrinsic(LowLevelILFunction& il, Instruction& instr, uint32_t intrinsic)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t destSize = get_register_size(dst.reg);
	size_t source1Size = get_register_size(src1.reg);
	size_t source2Size = get_register_size(src2.reg);
	if (elementSize == 0 || destSize == 0 || source1Size == 0 || source2Size == 0)
		return il.Unimplemented();

	std::vector<ExprId> inputs;
	inputs.push_back(il.Const(1, elementSize * 8));
	if ((intrinsic == ARMV7_INTRIN_VMLAL) || (intrinsic == ARMV7_INTRIN_VMLSL))
		inputs.push_back(il.Const(1, IsUnsignedDataType(instr.dataType) ? 1 : 0));
	inputs.push_back(il.Register(destSize, dst.reg));
	inputs.push_back(il.Register(source1Size, src1.reg));
	inputs.push_back(il.Register(source2Size, src2.reg));
	inputs.push_back(il.Const(1, src2.flags.hasElements ? src2.imm : 0xff));

	return il.Intrinsic({ RegisterOrFlag::Register(dst.reg) }, intrinsic, inputs);
}

static ExprId VectorSaturatingDoublingMultiplyLongIntrinsic(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || src2.cls != REG)
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t source1Size = get_register_size(src1.reg);
	size_t source2Size = get_register_size(src2.reg);
	if (elementSize == 0 || source1Size == 0 || source2Size == 0)
		return il.Unimplemented();

	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		ARMV7_INTRIN_VQDMULL,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, IsUnsignedDataType(instr.dataType) ? 1 : 0),
			il.Register(source1Size, src1.reg),
			il.Register(source2Size, src2.reg),
		});
}

static void VectorCompareEqual(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];
	size_t regSize = get_register_size(dst.reg);
	size_t elementSize = GetDataTypeSize(instr.dataType);

	if (dst.cls != REG || src1.cls != REG || (src2.cls != REG && src2.cls != IMM)
		|| regSize == 0 || elementSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	if (src2.cls == IMM && src2.imm != 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	bool isFloat = instr.dataType == DT_F32;
	ExprId rhs = (src2.cls == IMM) ? il.Const(regSize, 0) : il.Register(get_register_size(src2.reg), src2.reg);
	il.AddInstruction(il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		ARMV7_INTRIN_VCEQ,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, isFloat ? 1 : 0),
			il.Register(get_register_size(src1.reg), src1.reg),
			rhs,
		}));
}

static ExprId VectorCompareGreaterThan(LowLevelILFunction& il, Instruction& instr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];

	if (dst.cls != REG || src1.cls != REG || (src2.cls != REG && src2.cls != IMM))
		return il.Unimplemented();

	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t regSize = get_register_size(dst.reg);
	if (elementSize == 0 || regSize == 0)
		return il.Unimplemented();

	if (src2.cls == IMM && src2.imm != 0)
		return il.Unimplemented();

	ExprId rhs = (src2.cls == IMM) ? il.Const(regSize, 0) : il.Register(get_register_size(src2.reg), src2.reg);
	bool isUnsigned = !IsSignedDataType(instr.dataType) && instr.dataType != DT_F32 && instr.dataType != DT_F64;
	return il.Intrinsic(
		{ RegisterOrFlag::Register(dst.reg) },
		ARMV7_INTRIN_VCGT,
		{
			il.Const(1, elementSize * 8),
			il.Const(1, isUnsigned ? 1 : 0),
			il.Register(get_register_size(src1.reg), src1.reg),
			rhs,
		});
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


static ExprId GetRegisterShiftedRegister(LowLevelILFunction& il, Register reg, Register shiftReg, Shift shiftType)
{
	if (shiftType == SHIFT_NONE)
		return il.Register(get_register_size(reg), reg);

	uint32_t regSize = get_register_size(reg);
	uint32_t shiftRegSize = get_register_size(shiftReg);
	switch (shiftType)
	{
		case SHIFT_ASR:
			return il.ArithShiftRight(
				regSize,
				il.Register(regSize, reg),
				il.And(
					shiftRegSize,
					il.Register(shiftRegSize, shiftReg),
					il.Const(shiftRegSize, 0xff)
				));
		case SHIFT_LSL:
			return il.ShiftLeft(
				regSize,
				il.Register(regSize, reg),
				il.And(
					shiftRegSize,
					il.Register(shiftRegSize, shiftReg),
					il.Const(shiftRegSize, 0xff)
				));
		case SHIFT_LSR:
			return il.LogicalShiftRight(
				regSize,
				il.Register(regSize, reg),
				il.And(
					shiftRegSize,
					il.Register(shiftRegSize, shiftReg),
					il.Const(shiftRegSize, 0xff)
				));
		case SHIFT_ROR:
			return il.RotateRight(
				regSize,
				il.Register(regSize, reg),
				il.And(
					shiftRegSize,
					il.Register(shiftRegSize, shiftReg),
					il.Const(shiftRegSize, 0xff)
				));
		case SHIFT_RRX:
			//RRX can only shift 1 at a time
			return il.RotateRightCarry(
				regSize,
				il.Register(regSize, reg),
				il.Const(1, 1),
				il.Flag(IL_FLAG_C)
			);
		default:
			return 0;
	}
}


static ExprId GetShiftedRegister(LowLevelILFunction& il, InstructionOperand& op)
{
	if (op.flags.offsetRegUsed == 1)
		return GetRegisterShiftedRegister(il, op.reg, op.offset, op.shift);
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
			else if (op.flags.offsetRegUsed == 1 && op.imm != 0)
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

static void LogicalOperand(LowLevelILFunction& il, Instruction& instr, bool writeFlags, bool exclusiveOr, size_t addr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];
	size_t size = get_register_size(dst.reg);
	uint32_t flags = writeFlags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE;
	il.AddInstruction(SetRegisterOrBranch(il, dst.reg,
		exclusiveOr
			? il.Xor(size, ReadRegisterOrPointer(il, src1, addr), ReadILOperand(il, src2, addr), flags)
			: il.And(size, ReadRegisterOrPointer(il, src1, addr), ReadILOperand(il, src2, addr), flags)));
}

static void TestOperand(LowLevelILFunction& il, Instruction& instr, size_t addr)
{
	InstructionOperand& src1 = instr.operands[0];
	InstructionOperand& src2 = instr.operands[1];
	size_t size = get_register_size(src1.reg);

	il.AddInstruction(il.And(size, ReadRegisterOrPointer(il, src1, addr), ReadILOperand(il, src2, addr),
		IL_FLAGWRITE_ALL));
}

static void TestEquivalenceOperand(LowLevelILFunction& il, Instruction& instr, size_t addr)
{
	InstructionOperand& src1 = instr.operands[0];
	InstructionOperand& src2 = instr.operands[1];
	size_t size = get_register_size(src1.reg);

	il.AddInstruction(il.Xor(size, ReadRegisterOrPointer(il, src1, addr), ReadILOperand(il, src2, addr),
		IL_FLAGWRITE_CNZ));
}

static void BitClearOperand(LowLevelILFunction& il, Instruction& instr, bool writeFlags, size_t addr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src1 = instr.operands[1];
	InstructionOperand& src2 = instr.operands[2];
	size_t size = get_register_size(dst.reg);
	il.AddInstruction(SetRegisterOrBranch(il, dst.reg,
		il.And(size,
			ReadRegisterOrPointer(il, src1, addr),
			il.Not(size, ReadILOperand(il, src2, addr)),
			writeFlags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE)));
}

static void MoveNotOperand(LowLevelILFunction& il, Instruction& instr, bool writeFlags, size_t addr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src = instr.operands[1];
	size_t size = get_register_size(dst.reg);
	il.AddInstruction(SetRegisterOrBranch(il, dst.reg,
		il.Not(size, ReadILOperand(il, src, addr), writeFlags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE)));
}

static void RotateRightOperand(LowLevelILFunction& il, Instruction& instr, bool writeFlags, size_t addr)
{
	InstructionOperand& dst = instr.operands[0];
	InstructionOperand& src = instr.operands[1];
	InstructionOperand& shift = instr.operands[2];
	size_t size = get_register_size(dst.reg);
	ExprId source = ReadRegisterOrPointer(il, src, addr);
	ExprId shiftValue = il.And(4, ReadILOperand(il, shift, addr), il.Const(4, 0xff));
	il.AddInstruction(SetRegisterOrBranch(il, dst.reg,
		il.RotateRight(size, source, shiftValue, writeFlags ? IL_FLAGWRITE_CNZ : IL_FLAGWRITE_NONE)));
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

	il.AddInstruction(il.Intrinsic({ },
				ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS,
				{ address, il.Const(1, size) }));
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

	il.AddInstruction(il.Intrinsic({ },
				ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS,
				{ address, il.Const(1, 8) }));
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

static void StoreVst1(LowLevelILFunction& il, Instruction& instr, size_t addr)
{
	InstructionOperand& regs = instr.operands[0];
	InstructionOperand& mem = instr.operands[1];
	InstructionOperand& writeback = instr.operands[2];
	uint32_t regMask = (uint32_t)regs.reg;
	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t offset = 0;
	size_t totalSize = 0;
	ExprId base = ReadRegisterOrPointer(il, mem, addr);

	if (regs.cls != REG_LIST_DOUBLE || mem.cls != MEM_ALIGNED || elementSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	for (uint32_t i = 0; i < 32; i++)
	{
		if (((regMask >> i) & 1) == 0)
			continue;

		Register reg = (Register)(REG_D0 + i);
		size_t storeSize = regs.flags.hasElements ? elementSize : get_register_size(reg);
		ExprId address = (offset == 0) ? base : il.Add(4, base, il.Const(4, offset));
		ExprId value = regs.flags.hasElements ? ReadVectorElement(il, reg, elementSize, regs.imm) : il.Register(storeSize, reg);
		il.AddInstruction(il.Store(storeSize, address, value));
		offset += storeSize;
		totalSize += storeSize;
	}

	if (mem.flags.wb)
	{
		il.AddInstruction(il.SetRegister(get_register_size(mem.reg), mem.reg,
			il.Add(get_register_size(mem.reg), base, il.Const(get_register_size(mem.reg), totalSize))));
	}
	else if (writeback.cls == REG)
	{
		il.AddInstruction(il.SetRegister(get_register_size(mem.reg), mem.reg,
			il.Add(get_register_size(mem.reg), base, il.Register(get_register_size(writeback.reg), writeback.reg))));
	}
}

static void StoreStructuredVector(LowLevelILFunction& il, Instruction& instr, size_t addr, uint32_t intrinsic,
	size_t structureCount)
{
	InstructionOperand& regs = instr.operands[0];
	InstructionOperand& mem = instr.operands[1];
	InstructionOperand& writeback = instr.operands[2];
	uint32_t regMask = (uint32_t)regs.reg;
	size_t elementSize = GetDataTypeSize(instr.dataType);
	ExprId sources[4] = {il.Const(8, 0), il.Const(8, 0), il.Const(8, 0), il.Const(8, 0)};
	size_t regCount = 0;
	ExprId base = ReadRegisterOrPointer(il, mem, addr);

	if (regs.cls != REG_LIST_DOUBLE || mem.cls != MEM_ALIGNED || elementSize == 0 || structureCount == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	for (uint32_t i = 0; i < 32 && regCount < 4; i++)
	{
		if (((regMask >> i) & 1) == 0)
			continue;
		Register reg = (Register)(REG_D0 + i);
		sources[regCount++] = il.Register(get_register_size(reg), reg);
	}

	if ((structureCount == 4 && regCount != 4) || (structureCount == 2 && regCount != 2 && regCount != 4))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic({}, intrinsic, {
		base,
		il.Const(1, elementSize * 8),
		il.Const(1, mem.imm),
		il.Const(1, regs.flags.hasElements ? regs.imm : 0xff),
		sources[0],
		sources[1],
		sources[2],
		sources[3],
	}));

	size_t totalSize = regs.flags.hasElements ? structureCount * elementSize : regCount * 8;
	if (mem.flags.wb)
	{
		il.AddInstruction(il.SetRegister(get_register_size(mem.reg), mem.reg,
			il.Add(get_register_size(mem.reg), base, il.Const(get_register_size(mem.reg), totalSize))));
	}
	else if (writeback.cls == REG)
	{
		il.AddInstruction(il.SetRegister(get_register_size(mem.reg), mem.reg,
			il.Add(get_register_size(mem.reg), base, il.Register(get_register_size(writeback.reg), writeback.reg))));
	}
}

static void LoadStructuredVector(LowLevelILFunction& il, Instruction& instr, size_t addr, uint32_t intrinsic,
	size_t structureCount)
{
	InstructionOperand& regs = instr.operands[0];
	InstructionOperand& mem = instr.operands[1];
	InstructionOperand& writeback = instr.operands[2];
	uint32_t regMask = (uint32_t)regs.reg;
	size_t elementSize = GetDataTypeSize(instr.dataType);
	std::vector<RegisterOrFlag> outputs;
	size_t regCount = 0;
	ExprId base = ReadRegisterOrPointer(il, mem, addr);

	if (regs.cls != REG_LIST_DOUBLE || mem.cls != MEM_ALIGNED || elementSize == 0 || structureCount == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	for (uint32_t i = 0; i < 32 && regCount < 4; i++)
	{
		if (((regMask >> i) & 1) == 0)
			continue;
		outputs.push_back(RegisterOrFlag::Register((Register)(REG_D0 + i)));
		regCount++;
	}

	if ((structureCount == 4 && regCount != 4) || (structureCount == 2 && regCount != 2 && regCount != 4))
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	il.AddInstruction(il.Intrinsic(outputs, intrinsic, {
		base,
		il.Const(1, elementSize * 8),
		il.Const(1, mem.imm),
		il.Const(1, regs.flags.hasElements ? regs.imm : 0xff),
	}));

	size_t totalSize = regs.flags.hasElements ? structureCount * elementSize : regCount * 8;
	if (mem.flags.wb)
	{
		il.AddInstruction(il.SetRegister(get_register_size(mem.reg), mem.reg,
			il.Add(get_register_size(mem.reg), base, il.Const(get_register_size(mem.reg), totalSize))));
	}
	else if (writeback.cls == REG)
	{
		il.AddInstruction(il.SetRegister(get_register_size(mem.reg), mem.reg,
			il.Add(get_register_size(mem.reg), base, il.Register(get_register_size(writeback.reg), writeback.reg))));
	}
}

static void StoreVpush(LowLevelILFunction& il, Instruction& instr, size_t addr)
{
	(void) addr;
	InstructionOperand& regs = instr.operands[0];
	uint32_t regMask = (uint32_t)regs.reg;
	Register baseReg;
	size_t regSize;

	if (regs.cls == REG_LIST_SINGLE)
	{
		baseReg = REG_S0;
		regSize = 4;
	}
	else if (regs.cls == REG_LIST_DOUBLE)
	{
		baseReg = REG_D0;
		regSize = 8;
	}
	else
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	for (int32_t i = 31; i >= 0; i--)
	{
		if (((regMask >> i) & 1) == 1)
		{
			Register reg = (Register)(baseReg + i);
			il.AddInstruction(il.Push(regSize, il.Register(regSize, reg)));
		}
	}
}

static void LoadVpop(LowLevelILFunction& il, Instruction& instr, size_t addr)
{
	(void) addr;
	InstructionOperand& regs = instr.operands[0];
	uint32_t regMask = (uint32_t)regs.reg;
	Register baseReg;
	size_t regSize;

	if (regs.cls == REG_LIST_SINGLE)
	{
		baseReg = REG_S0;
		regSize = 4;
	}
	else if (regs.cls == REG_LIST_DOUBLE)
	{
		baseReg = REG_D0;
		regSize = 8;
	}
	else
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	for (uint32_t i = 0; i < 32; i++)
	{
		if (((regMask >> i) & 1) == 1)
		{
			Register reg = (Register)(baseReg + i);
			il.AddInstruction(il.SetRegister(regSize, reg, il.Pop(regSize)));
		}
	}
}

static void VfpLoadStoreMultiple(LowLevelILFunction& il, InstructionOperand& base, InstructionOperand& regs, bool load,
	bool decrementBefore)
{
	uint32_t regMask = (uint32_t)regs.reg;
	Register baseReg;
	size_t regSize;

	if (base.cls != REG)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	if (regs.cls == REG_LIST_SINGLE)
	{
		baseReg = REG_S0;
		regSize = 4;
	}
	else if (regs.cls == REG_LIST_DOUBLE)
	{
		baseReg = REG_D0;
		regSize = 8;
	}
	else
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	uint32_t count = 0;
	for (uint32_t i = 0; i < 32; i++)
	{
		if (((regMask >> i) & 1) == 1)
			count++;
	}
	size_t totalSize = count * regSize;
	ExprId start = decrementBefore ? il.Sub(4, il.Register(4, base.reg), il.Const(4, totalSize)) : il.Register(4, base.reg);

	uint32_t index = 0;
	for (uint32_t i = 0; i < 32; i++)
	{
		if (((regMask >> i) & 1) == 0)
			continue;

		Register reg = (Register)(baseReg + i);
		ExprId address = index == 0 ? start : il.Add(4, start, il.Const(4, index * regSize));
		if (load)
			il.AddInstruction(il.SetRegister(regSize, reg, il.Load(regSize, address)));
		else
			il.AddInstruction(il.Store(regSize, address, il.Register(regSize, reg)));
		index++;
	}

	if (base.flags.wb)
	{
		ExprId newBase = decrementBefore ? il.Sub(4, il.Register(4, base.reg), il.Const(4, totalSize))
			: il.Add(4, il.Register(4, base.reg), il.Const(4, totalSize));
		il.AddInstruction(il.SetRegister(4, base.reg, newBase));
	}
}

static void LoadVld1(LowLevelILFunction& il, Instruction& instr, size_t addr)
{
	InstructionOperand& regs = instr.operands[0];
	InstructionOperand& mem = instr.operands[1];
	InstructionOperand& writeback = instr.operands[2];
	uint32_t regMask = (uint32_t)regs.reg;
	size_t elementSize = GetDataTypeSize(instr.dataType);
	size_t offset = 0;
	size_t totalSize = 0;
	ExprId base = ReadRegisterOrPointer(il, mem, addr);

	if (regs.cls != REG_LIST_DOUBLE || mem.cls != MEM_ALIGNED || elementSize == 0)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	for (uint32_t i = 0; i < 32; i++)
	{
		if (((regMask >> i) & 1) == 0)
			continue;

		Register reg = (Register)(REG_D0 + i);
		size_t loadSize = regs.flags.hasElements ? elementSize : get_register_size(reg);
		ExprId address = (offset == 0) ? base : il.Add(4, base, il.Const(4, offset));
		ExprId value = il.Load(loadSize, address);
		if (regs.flags.hasElements)
			value = InsertVectorElement(il, reg, value, elementSize, regs.imm);
		il.AddInstruction(il.SetRegister(get_register_size(reg), reg, value));
		offset += loadSize;
		totalSize += loadSize;
	}

	if (mem.flags.wb)
	{
		il.AddInstruction(il.SetRegister(get_register_size(mem.reg), mem.reg,
			il.Add(get_register_size(mem.reg), base, il.Const(get_register_size(mem.reg), totalSize))));
	}
	else if (writeback.cls == REG)
	{
		il.AddInstruction(il.SetRegister(get_register_size(mem.reg), mem.reg,
			il.Add(get_register_size(mem.reg), base, il.Register(get_register_size(writeback.reg), writeback.reg))));
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

	LowLevelILLabel trueCode, falseCode, done;
	size_t statusSize = get_register_size(status.reg);
	il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(LLIL_TEMP(0)) },
				ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS,
				{ address, il.Const(1, dstSize) }));
	il.AddInstruction(il.If(il.CompareEqual(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 1)),
				trueCode, falseCode));
	il.MarkLabel(trueCode);

	Store(il, size, src, dst, addr);
	il.AddInstruction(il.SetRegister(statusSize, status.reg, il.Const(statusSize, 0)));
	il.AddInstruction(il.Goto(done));

	il.MarkLabel(falseCode);
	il.AddInstruction(il.SetRegister(statusSize, status.reg, il.Const(statusSize, 1)));
	il.MarkLabel(done);
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

static void CoprocStore(
		LowLevelILFunction& il,
		InstructionOperand& coproc,
		InstructionOperand& coprocReg,
		InstructionOperand& dst,
		bool longTransfer,
		size_t addr)
{
	ExprId address = (dst.cls == MEM_POST_IDX) ? ILREG(dst) : ReadAddress(il, dst, addr);

	il.AddInstruction(il.Intrinsic({ },
		ARMV7_INTRIN_COPROC_STORE,
		{
			address,
			il.Const(1, coproc.reg),
			il.Const(1, coprocReg.reg),
			il.Const(1, longTransfer ? 1 : 0),
		}));

	if (dst.cls == MEM_POST_IDX || dst.cls == MEM_PRE_IDX)
		il.AddInstruction(SetRegisterOrBranch(il, dst.reg, ReadAddress(il, dst, addr)));
}

static void CoprocLoad(
		LowLevelILFunction& il,
		InstructionOperand& coproc,
		InstructionOperand& coprocReg,
		InstructionOperand& src,
		bool longTransfer,
		size_t addr)
{
	ExprId address = (src.cls == MEM_POST_IDX || src.cls == MEM_OPTION) ? ILREG(src) : ReadAddress(il, src, addr);

	il.AddInstruction(il.Intrinsic({ },
		ARMV7_INTRIN_COPROC_LOAD,
		{
			address,
			il.Const(1, coproc.reg),
			il.Const(1, coprocReg.reg),
			il.Const(1, longTransfer ? 1 : 0),
		}));

	if (src.cls == MEM_POST_IDX || src.cls == MEM_PRE_IDX)
		il.AddInstruction(SetRegisterOrBranch(il, src.reg, ReadAddress(il, src, addr)));
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

	LowLevelILLabel trueCode, falseCode, done;
	size_t statusSize = get_register_size(status.reg);
	il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(LLIL_TEMP(0)) },
				ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS,
				{ address, il.Const(1, 8) }));
	il.AddInstruction(il.If(il.CompareEqual(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 1)),
				trueCode, falseCode));
	il.MarkLabel(trueCode);

	StorePair(arch, il, src1, src2, dst, addr);
	il.AddInstruction(il.SetRegister(statusSize, status.reg, il.Const(statusSize, 0)));
	il.AddInstruction(il.Goto(done));

	il.MarkLabel(falseCode);
	il.AddInstruction(il.SetRegister(statusSize, status.reg, il.Const(statusSize, 1)));
	il.MarkLabel(done);
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
	LowLevelILLabel trueLabel, falseLabel, endLabel;
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
		case ARMV7_ANDS:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					LogicalOperand(il, instr, instr.operation == ARMV7_ANDS || instr.setsFlags, false, addr);
				});
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
		case ARMV7_CLREX:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_CLREX, {}));
			break;
		case ARMV7_PLD:
			ConditionExecute(il, instr.cond,
				il.Intrinsic({}, ARMV7_INTRIN_PLD, {ReadILOperand(il, op1, addr, true)})
			);
			break;
		case ARMV7_CRC32B:
		case ARMV7_CRC32CB:
		case ARMV7_CRC32CH:
		case ARMV7_CRC32CW:
		case ARMV7_CRC32H:
		case ARMV7_CRC32W:
		{
			size_t valueSize = GetCrc32ValueSize(instr.operation);
			ExprId value = ReadILOperand(il, op3, addr);
			if (valueSize < 4)
				value = il.LowPart(valueSize, value);
			ConditionExecute(il, instr.cond,
				il.Intrinsic(
					{ RegisterOrFlag::Register(op1.reg) },
					GetCrc32Intrinsic(instr.operation),
					{
						ReadILOperand(il, op2, addr),
						value,
					}
				)
			);
			break;
		}
		case ARMV7_YIELD:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_YIELD, {}));
			break;
		case ARMV7_SEV:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_SEV, {}));
			break;
		case ARMV7_WFE:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_WFE, {}));
			break;
		case ARMV7_WFI:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_WFI, {}));
			break;
		case ARMV7_DBG:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_DBG, {il.Const(1, op1.imm)}));
			break;
		case ARMV7_HINT:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_HINT, {il.Const(1, op1.imm)}));
			break;
		case ARMV7_UNPREDICTABLE:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_UNPREDICTABLE, {}));
			break;
		case ARMV7_CPS:
		case ARMV7_CPSIE:
		case ARMV7_CPSID:
		{
			uint8_t iflags = IFL_NONE;
			uint8_t mode = 0;

			for (size_t i = 0; i < 4; i++)
			{
				if (instr.operands[i].cls == IFLAGS)
					iflags = instr.operands[i].iflag;
				else if (instr.operands[i].cls == IMM)
					mode = instr.operands[i].imm;
			}

			if (instr.operation == ARMV7_CPS)
			{
				ConditionExecute(il, instr.cond,
					il.Intrinsic({}, ARMV7_INTRIN_CPS, {il.Const(1, mode)})
				);
			}
			else
			{
				ConditionExecute(il, instr.cond,
					il.Intrinsic({}, (instr.operation == ARMV7_CPSIE) ? ARMV7_INTRIN_CPSIE : ARMV7_INTRIN_CPSID, {
						il.Const(1, iflags),
						il.Const(1, mode)
					})
				);
			}
			break;
		}
		case ARMV7_SETEND:
			ConditionExecute(il, instr.cond,
				il.Intrinsic({}, ARMV7_INTRIN_SETEND, {il.Const(1, op1.endian)}));
			break;
		case ARMV7_SRS:
		case ARMV7_SRSDA:
		case ARMV7_SRSDB:
		case ARMV7_SRSIA:
		case ARMV7_SRSIB:
		{
			bool increment = (instr.operation == ARMV7_SRSIA) || (instr.operation == ARMV7_SRSIB);
			bool wordhigher = (instr.operation == ARMV7_SRSDA) || (instr.operation == ARMV7_SRSIB);
			ConditionExecute(il, instr.cond,
				il.Intrinsic({}, ARMV7_INTRIN_SRS, {
					il.Const(1, op2.imm),
					il.Const(1, increment ? 1 : 0),
					il.Const(1, wordhigher ? 1 : 0),
					il.Const(1, op1.flags.wb ? 1 : 0),
				})
			);
			break;
		}
		case ARMV7_RFE:
		case ARMV7_RFEDA:
		case ARMV7_RFEDB:
		case ARMV7_RFEIA:
		case ARMV7_RFEIB:
		{
			bool increment = (instr.operation == ARMV7_RFEIA) || (instr.operation == ARMV7_RFEIB);
			bool wordhigher = (instr.operation == ARMV7_RFEDA) || (instr.operation == ARMV7_RFEIB);
			ConditionExecute(il, instr.cond,
				il.Intrinsic({}, ARMV7_INTRIN_RFE, {
					ReadILOperand(il, op1, addr),
					il.Const(1, increment ? 1 : 0),
					il.Const(1, wordhigher ? 1 : 0),
					il.Const(1, op1.flags.wb ? 1 : 0),
				})
			);
			break;
		}
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
		case ARMV7_BICS:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					BitClearOperand(il, instr, instr.operation == ARMV7_BICS || instr.setsFlags, addr);
				});
			break;
		case ARMV7_CLZ:
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				il.AddInstruction(SetRegisterOrBranch(il, op1.reg,
					il.CountLeadingZeros(4, ReadRegisterOrPointer(il, op2, addr))));
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
		case ARMV7_EORS:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					LogicalOperand(il, instr, instr.operation == ARMV7_EORS || instr.setsFlags, true, addr);
				});
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
						ExprId wb = BN_INVALID_OPERAND;
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
		case ARMV7_LDAEX:
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
		case ARMV7_LDAEXH:
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
		case ARMV7_LDAEXB:
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
		case ARMV7_LDAEXD:
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
		case ARMV7_STC:
		case ARMV7_STC2:
		case ARMV7_STCL:
		case ARMV7_STC2L:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					CoprocStore(il, op1, op2, op3,
						(instr.operation == ARMV7_STCL) || (instr.operation == ARMV7_STC2L), addr);
				});
			break;
		case ARMV7_LDC:
		case ARMV7_LDC2:
		case ARMV7_LDCL:
		case ARMV7_LDC2L:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					CoprocLoad(il, op1, op2, op3,
						(instr.operation == ARMV7_LDCL) || (instr.operation == ARMV7_LDC2L), addr);
				});
			break;
		case ARMV7_CDP:
		case ARMV7_CDP2:
		{
			uint32_t opc2 = (op6.cls == IMM) ? op6.imm : 0;
			ConditionExecute(il, instr.cond,
				il.Intrinsic({}, ARMV7_INTRIN_COPROC_DATAPROCESSING,
					{
						il.Const(1, op1.reg),
						il.Const(1, op2.imm),
						il.Const(1, op3.reg),
						il.Const(1, op4.reg),
						il.Const(1, op5.reg),
						il.Const(1, opc2),
					}
				)
			);
			break;
		}
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
		case ARMV7_MRS:
			if (op2.cls != REG_SPEC)
			{
				il.AddInstruction(il.Unimplemented());
				break;
			}
			ConditionExecute(il, instr.cond,
				il.Intrinsic(
					{ RegisterOrFlag::Register(op1.reg) },
					ARMV7_INTRIN_MRS,
					{ il.Const(4, op2.regs) }
				)
			);
			break;
		case ARMV7_MSR:
			if ((op1.cls != REG_SPEC) || ((op2.cls != REG) && (op2.cls != IMM)))
			{
				il.AddInstruction(il.Unimplemented());
				break;
			}
			ConditionExecute(il, instr.cond,
				il.Intrinsic(
					{},
					ARMV7_INTRIN_MSR,
					{ il.Const(4, op1.regs), ReadILOperand(il, op2, addr) }
				)
			);
			break;
		case ARMV7_VMSR:
			if ((op1.cls != REG_SPEC) || (op2.cls != REG))
			{
				il.AddInstruction(il.Unimplemented());
				break;
			}
			ConditionExecute(il, instr.cond,
				il.Intrinsic(
					{},
					ARMV7_INTRIN_VMSR,
					{ il.Const(4, op1.regs), il.Register(get_register_size(op2.reg), op2.reg) }
				)
			);
			break;
		case ARMV7_VMRS:
			if (op2.cls != REG_SPEC)
			{
				il.AddInstruction(il.Unimplemented());
				break;
			}
			if (op1.cls == REG_SPEC)
			{
				if (op1.regs != REGS_APSR_NZCV)
				{
					il.AddInstruction(il.Unimplemented());
					break;
				}
				if (op2.regs != REGS_FPSCR)
				{
					il.AddInstruction(il.Unimplemented());
					break;
				}
				ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t, Instruction&, LowLevelILFunction& il)
					{
						il.AddInstruction(il.Nop());
					});
				break;
			}
			if (op1.cls != REG)
			{
				il.AddInstruction(il.Unimplemented());
				break;
			}
			ConditionExecute(il, instr.cond,
				il.Intrinsic(
					{ RegisterOrFlag::Register(op1.reg) },
					ARMV7_INTRIN_VMRS,
					{ il.Const(4, op2.regs) }
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
		case ARMV7_MVNS:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					MoveNotOperand(il, instr, instr.operation == ARMV7_MVNS || instr.setsFlags, addr);
				});
			break;
		case ARMV7_NOP:
			ConditionExecute(il, instr.cond, il.Nop());
			break;
		case ARMV7_DMB:
		{
			uint32_t intrinsic = GetDmbIntrinsic(op1.dsbOpt);
			if (intrinsic == 0)
				il.AddInstruction(il.Unimplemented());
			else
				ConditionExecute(il, instr.cond, il.Intrinsic({}, intrinsic, {}));
			break;
		}
		case ARMV7_DSB:
		{
			uint32_t intrinsic = GetDsbIntrinsic(op1.dsbOpt);
			if (intrinsic == 0)
				il.AddInstruction(il.Unimplemented());
			else
				ConditionExecute(il, instr.cond, il.Intrinsic({}, intrinsic, {}));
			break;
		}
		case ARMV7_ISB:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_ISB, {}));
			break;
		case ARMV7_ORR:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Or(get_register_size(op1.reg),
					ReadRegisterOrPointer(il, op2, addr),
					ReadILOperand(il, op3, addr), instr.setsFlags ? IL_FLAGWRITE_CNZ : IL_FLAGWRITE_NONE)));
			break;
		case ARMV7_PKHBT:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Or(4,
					il.And(4,
						ReadRegisterOrPointer(il, op2, addr),
						il.Const(4, 0xffff)),
					il.And(4,
						ReadILOperand(il, op3, addr),
						il.Const(4, 0xffff0000))
					)
				));
			break;
		case ARMV7_PKHTB:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Or(4,
					il.And(4,
						ReadRegisterOrPointer(il, op2, addr),
						il.Const(4, 0xffff0000)),
					il.And(4,
						ReadILOperand(il, op3, addr),
						il.Const(4, 0xffff))
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
		case ARMV7_VPUSH:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					StoreVpush(il, instr, addr);
				});
			break;
		case ARMV7_VPOP:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					LoadVpop(il, instr, addr);
				});
			break;
		case ARMV7_VSTM:
		case ARMV7_VSTMIA:
		case ARMV7_VSTMDB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					VfpLoadStoreMultiple(il, op1, op2, false, instr.operation == ARMV7_VSTMDB);
				});
			break;
		case ARMV7_VLDM:
		case ARMV7_VLDMIA:
		case ARMV7_VLDMDB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					VfpLoadStoreMultiple(il, op1, op2, true, instr.operation == ARMV7_VLDMDB);
				});
			break;
		case ARMV7_QADD:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_QADD,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_QADD16:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_QADD16,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_UQADD16:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_UQADD16,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_QADD8:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_QADD8,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_UQADD8:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_UQADD8,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_QDADD:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_QDADD,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_QASX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					ExprId source1 = ReadILOperand(il, op2, addr);
					ExprId source2 = ReadILOperand(il, op3, addr);
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.Sub(4,
							il.SignExtend(4, LowHalf(il, source1)),
							il.SignExtend(4, SignedHighHalf(il, source2))
						)
					));
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
						il.Add(4,
							il.SignExtend(4, SignedHighHalf(il, source1)),
							il.SignExtend(4, LowHalf(il, source2))
						)
					));

					Saturate(il, LLIL_TEMP(2), il.Register(4, LLIL_TEMP(0)), il.Const(4, 0x7fff), true);
					Saturate(il, LLIL_TEMP(3), il.Register(4, LLIL_TEMP(1)), il.Const(4, 0x7fff), true);

					il.AddInstruction(il.SetRegister(4, op1.reg,
						PackHalfwords(il, il.Register(4, LLIL_TEMP(2)), il.Register(4, LLIL_TEMP(3)))
					));
				});
			break;
		case ARMV7_QSAX:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg,
					ARMV7_INTRIN_QSAX,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_UQASX:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg,
					ARMV7_INTRIN_UQASX,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_UQSAX:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg,
					ARMV7_INTRIN_UQSAX,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_QDSUB:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_QDSUB,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_QSUB:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_QSUB,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_QSUB16:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_QSUB16,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_UQSUB16:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_UQSUB16,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_QSUB8:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_QSUB8,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_UQSUB8:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_UQSUB8,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_RBIT:
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				il.AddInstruction(SetRegisterOrBranch(il, op1.reg,
					il.ReverseBits(4, ReadRegisterOrPointer(il, op2, addr))));
			});
			break;
		case ARMV7_REV:
			ConditionExecute(il, instr.cond, il.SetRegister(4, op1.reg,
				il.ByteSwap(4, il.Register(4, op2.reg)),
				flagOperation[instr.setsFlags]));
			break;
		case ARMV7_REV16:
			// A 32-bit register holds two 16-bit lanes, so reversing the bytes within each lane is a
			// full byte reversal rotated by one halfword
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				il.AddInstruction(il.SetRegister(4, op1.reg,
					il.RotateRight(4, il.ByteSwap(4, ReadILOperand(il, op2, addr)), il.Const(1, 16))));
			});
			break;
		case ARMV7_REVSH:
			// Reverse the bytes of the low 16-bit halfword and sign-extend the result to 32 bits
			ConditionExecute(addr, instr.cond, instr, il, [&](size_t, Instruction&, LowLevelILFunction& il){
				il.AddInstruction(il.SetRegister(4, op1.reg,
					il.SignExtend(4, il.ByteSwap(2, il.LowPart(2, ReadILOperand(il, op2, addr))))));
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
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					RotateRightOperand(il, instr, instr.operation == ARMV7_RORS || instr.setsFlags, addr);
				});
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
		case ARMV7_SEL:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t, Instruction&, LowLevelILFunction& il)
				{
					il.AddInstruction(il.Intrinsic(
						{ RegisterOrFlag::Register(op1.reg) },
						ARMV7_INTRIN_SEL,
						{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr), il.Register(4, REGS_APSR_G) }));
				});
			break;
		case ARMV7_SADD16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t, Instruction&, LowLevelILFunction& il)
				{
					AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_SADD16, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
				});
			break;
		case ARMV7_UADD16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t, Instruction&, LowLevelILFunction& il)
				{
					AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_UADD16, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
				});
			break;
		case ARMV7_SADD8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t, Instruction&, LowLevelILFunction& il)
				{
					AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_SADD8, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
				});
			break;
			case ARMV7_UADD8:
				ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t, Instruction&, LowLevelILFunction& il)
					{
						AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_UADD8, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
					});
				break;
			case ARMV7_SASX:
				ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t, Instruction&, LowLevelILFunction& il)
					{
						AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_SASX, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
					});
				break;
			case ARMV7_UASX:
				ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t, Instruction&, LowLevelILFunction& il)
					{
						AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_UASX, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
					});
				break;
			case ARMV7_SHASX:
				ConditionExecute(il, instr.cond,
					il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_SHASX,
						{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
				break;
			case ARMV7_UHASX:
				ConditionExecute(il, instr.cond,
					il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_UHASX,
						{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
				break;
		case ARMV7_SHSAX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
							il.Add(4,
								il.SignExtend(4, LowHalf(il, source1)),
								il.SignExtend(4, SignedHighHalf(il, source2))
							)
						));
						il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
							il.Sub(4,
								il.SignExtend(4, SignedHighHalf(il, source1)),
								il.SignExtend(4, LowHalf(il, source2))
							)
						));
						il.AddInstruction(il.SetRegister(4, op1.reg,
							PackHalfwords(il,
								il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 1)),
								il.ArithShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(1, 1)))
						));
					});
				break;
		case ARMV7_UHSAX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
							il.Add(4,
								il.ZeroExtend(4, LowHalf(il, source1)),
								il.ZeroExtend(4, UnsignedHighHalf(il, source2))
							)
						));
						il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
							il.Sub(4,
								il.ZeroExtend(4, UnsignedHighHalf(il, source1)),
								il.ZeroExtend(4, LowHalf(il, source2))
							)
						));
						il.AddInstruction(il.SetRegister(4, op1.reg,
							PackHalfwords(il,
								il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 1)),
								il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(1, 1)))
						));
					});
				break;
		case ARMV7_SSAX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t, Instruction&, LowLevelILFunction& il)
				{
					AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_SSAX, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
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
									il.ZeroExtend(8, il.Register(4, op2.reg)),
									il.ZeroExtend(8, il.Register(4, op1.reg))
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
		case ARMV7_SSUB16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t, Instruction&, LowLevelILFunction& il)
				{
					AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_SSUB16, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
				});
			break;
		case ARMV7_USUB16:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t, Instruction&, LowLevelILFunction& il)
				{
					AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_USUB16, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
				});
			break;
		case ARMV7_SSUB8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t, Instruction&, LowLevelILFunction& il)
				{
					AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_SSUB8, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
				});
			break;
		case ARMV7_USUB8:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t, Instruction&, LowLevelILFunction& il)
				{
					AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_USUB8, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
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
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_SHADD16, { ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_UHADD16:
			ConditionExecute(il, instr.cond,
				il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_UHADD16,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_SHADD8:
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_SHADD8, { ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
			case ARMV7_UHADD8:
				ConditionExecute(il, instr.cond,
					il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_UHADD8,
						{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
				break;
		case ARMV7_SHSUB16:
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_SHSUB16, { ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_UHSUB16:
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_UHSUB16, { ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_SHSUB8:
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_SHSUB8, { ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_UHSUB8:
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_UHSUB8, { ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_SMLABB:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Add(4,
								SignedHalfProduct32(il, source1, false, source2, false),
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

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Add(4,
								SignedHalfProduct32(il, source1, false, source2, true),
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

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Add(4,
								SignedHalfProduct32(il, source1, true, source2, false),
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

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, op1.reg,
							il.Add(4,
								SignedHalfProduct32(il, source1, true, source2, true),
								ReadILOperand(il, op4, addr)
							)
						));
				});
			break;
		case ARMV7_SMLAD:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_SMLAD,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr) }));
			break;
		case ARMV7_SMLADX:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_SMLADX,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr) }));
			break;
		case ARMV7_SMLAL:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.MultDoublePrecSigned(4, ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr))));
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
		case ARMV7_SMLALBT:
		case ARMV7_SMLALTB:
		case ARMV7_SMLALTT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					bool nTop = instr.operation == ARMV7_SMLALTB || instr.operation == ARMV7_SMLALTT;
					bool mTop = instr.operation == ARMV7_SMLALBT || instr.operation == ARMV7_SMLALTT;
						ExprId source1 = ReadILOperand(il, op3, addr);
						ExprId source2 = ReadILOperand(il, op4, addr);

						il.AddInstruction(il.SetRegisterSplit(4, op2.reg, op1.reg,
							il.Add(8,
								SignedHalfProduct64(il, source1, nTop, source2, mTop),
								il.RegisterSplit(4, op2.reg, op1.reg))));
					});
				break;
		case ARMV7_SMLALD:
			ConditionExecute(il, instr.cond,
				il.Intrinsic({ RegisterOrFlag::Register(op2.reg), RegisterOrFlag::Register(op1.reg) },
					ARMV7_INTRIN_SMLALD,
					{ ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr), il.RegisterSplit(4, op2.reg, op1.reg) }));
			break;
		case ARMV7_SMLALDX:
			ConditionExecute(il, instr.cond,
				il.Intrinsic({ RegisterOrFlag::Register(op2.reg), RegisterOrFlag::Register(op1.reg) },
					ARMV7_INTRIN_SMLALDX,
					{ ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr), il.RegisterSplit(4, op2.reg, op1.reg) }));
			break;
		case ARMV7_SMLAWB:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_SMLAWB,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr) }));
			break;
		case ARMV7_SMLAWT:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_SMLAWT,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr) }));
			break;
		case ARMV7_SMLSD:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_SMLSD,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr) }));
			break;
		case ARMV7_SMLSDX:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_SMLSDX,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr) }));
			break;
		case ARMV7_SMLSLD:
			ConditionExecute(il, instr.cond,
				il.Intrinsic({ RegisterOrFlag::Register(op2.reg), RegisterOrFlag::Register(op1.reg) },
					ARMV7_INTRIN_SMLSLD,
					{ ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr), il.RegisterSplit(4, op2.reg, op1.reg) }));
			break;
		case ARMV7_SMLSLDX:
			ConditionExecute(il, instr.cond,
				il.Intrinsic({ RegisterOrFlag::Register(op2.reg), RegisterOrFlag::Register(op1.reg) },
					ARMV7_INTRIN_SMLSLDX,
					{ ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr), il.RegisterSplit(4, op2.reg, op1.reg) }));
			break;
		case ARMV7_SMMLA:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
						il.LowPart(4,
							il.ArithShiftRight(8,
								il.MultDoublePrecSigned(4, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr)),
								il.Const(1, 32)))));
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
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.Add(8,
							il.MultDoublePrecSigned(4, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr)),
							il.Const(8, 0x80000000))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.Add(4,
							il.LowPart(4,
								il.ArithShiftRight(8,
									il.Register(8, LLIL_TEMP(0)),
									il.Const(1, 32))),
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
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.MultDoublePrecSigned(4, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr))));
						il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1),
							il.ShiftLeft(8, il.SignExtend(8, ReadILOperand(il, op4, addr)), il.Const(1, 32))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.LowPart(4,
							il.ArithShiftRight(8,
								il.Sub(8,
									il.Register(8, LLIL_TEMP(1)),
									il.Register(8, LLIL_TEMP(0))
								),
								il.Const(1, 32)))
					));
				});
			break;
		case ARMV7_SMMLSR:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.MultDoublePrecSigned(4, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr))));
						il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1),
							il.ShiftLeft(8, il.SignExtend(8, ReadILOperand(il, op4, addr)), il.Const(1, 32))));
					il.AddInstruction(il.SetRegister(4, op1.reg,
						il.LowPart(4,
							il.ArithShiftRight(8,
								il.Add(8,
									il.Sub(8,
										il.Register(8, LLIL_TEMP(1)),
										il.Register(8, LLIL_TEMP(0))
									),
									il.Const(8, 0x80000000)
								),
								il.Const(1, 32)))
					));
				});
			break;
		case ARMV7_SMUAD:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_SMUAD,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_SMUADX:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_SMUADX,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_SMMUL:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.MultDoublePrecSigned(4, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr))));
					il.AddInstruction(il.SetRegister(4, op1.reg, il.ArithShiftRight(4, il.Register(8, LLIL_TEMP(0)), il.Const(1, 32))));
				});
			break;
		case ARMV7_SMMULR:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;

					il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.Add(8,
							il.MultDoublePrecSigned(4, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr)),
							il.Const(8, 0x80000000))));
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

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, op1.reg,
								SignedHalfProduct32(il, source1, false, source2, false)
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

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, op1.reg,
								SignedHalfProduct32(il, source1, false, source2, true)
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

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, op1.reg,
								SignedHalfProduct32(il, source1, true, source2, false)
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

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, op1.reg,
								SignedHalfProduct32(il, source1, true, source2, true)
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

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, op1.reg,
							il.LowPart(4, il.ArithShiftRight(8,
								SignedWordHalfProduct64(il, source1, source2, false),
								il.Const(1, 16)))
						));
					});
				break;
		case ARMV7_SMULWT:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;

						ExprId source1 = ReadILOperand(il, op2, addr);
						ExprId source2 = ReadILOperand(il, op3, addr);
						il.AddInstruction(il.SetRegister(4, op1.reg,
							il.LowPart(4, il.ArithShiftRight(8,
								SignedWordHalfProduct64(il, source1, source2, true),
								il.Const(1, 16)))
						));
					});
				break;
		case ARMV7_SMUSD:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_SMUSD,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_SMUSDX:
			ConditionExecute(il, instr.cond,
				QFlagIntrinsic(il, op1.reg, ARMV7_INTRIN_SMUSDX,
					{ ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
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
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
					il.Sub(4,
						il.ShiftLeft(4,
							il.Const(4, 2),
							ReadILOperand(il, op2, addr)
						),
						il.Const(4, 1)
					)
				));

				ExprId source = ReadILOperand(il, op3, addr);
				Saturate(il, LLIL_TEMP(1), il.SignExtend(4, LowHalf(il, source)), il.Register(4, LLIL_TEMP(0)), true);
				Saturate(il, LLIL_TEMP(2), il.SignExtend(4, SignedHighHalf(il, source)), il.Register(4, LLIL_TEMP(0)), true);

				il.AddInstruction(il.SetRegister(4, op1.reg,
					PackHalfwords(il, il.Register(4, LLIL_TEMP(1)), il.Register(4, LLIL_TEMP(2)))
				));
			});
			break;
		case ARMV7_STMDA:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					uint32_t numToLoad = 0;
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
							numToLoad++;
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
							il.AddInstruction(
								il.Store(4,
									il.Register(4, LLIL_TEMP(0)),
									il.Register(get_register_size((enum Register)j), j)
								)
							);
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
					uint32_t numToLoad = 0;
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
							numToLoad++;
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
							il.AddInstruction(
								il.Store(4,
									il.Register(4, LLIL_TEMP(0)),
									il.Register(get_register_size((enum Register)j), j)
								)
							);
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
					uint32_t numToLoad = 0;
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
							numToLoad++;
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
							il.AddInstruction(
								il.Store(4,
									il.Register(4, LLIL_TEMP(0)),
									il.Register(get_register_size((enum Register)j), j)
								)
							);
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
					uint32_t numToLoad = 0;
					for (uint32_t j = 0; j < 15; j++)
					{
						if (((op2.reg >> j) & 1) == 1)
							numToLoad++;
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
							il.AddInstruction(
								il.Store(4,
									il.Register(4, LLIL_TEMP(0)),
									il.Register(get_register_size((enum Register)j), j)
								)
							);
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
		case ARMV7_STLEX:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						StoreExclusive(il, 4, op1, op2, op3, addr);
					});
			break;
		case ARMV7_STREXH:
		case ARMV7_STLEXH:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						(void) instr;
						StoreExclusive(il, 2, op1, op2, op3, addr);
					});
			break;
		case ARMV7_STREXB:
		case ARMV7_STLEXB:
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
		case ARMV7_STLEXD:
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
		case ARMV7_HVC:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_HVC, {il.Const(2, op1.imm)}));
			break;
		case ARMV7_SMC:
			ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV7_INTRIN_SMC, {il.Const(1, op1.imm)}));
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
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_SXTAB16, { ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
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
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_SXTB16, { ReadILOperand(il, op2, addr) }));
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
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					TestEquivalenceOperand(il, instr, addr);
				});
			break;
		case ARMV7_TST:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					TestOperand(il, instr, addr);
				});
			break;
		case ARMV7_UBFX:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.And(get_register_size(op1.reg),
					il.LogicalShiftRight(get_register_size(op2.reg), ReadILOperand(il, op2, addr), il.Const(1, op3.imm)),
					il.Const(get_register_size(op2.reg), BITMASK(op4.imm, 0)))));
			break;
		case ARMV7_USAD8:
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_USAD8, { ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
			break;
		case ARMV7_USADA8:
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_USADA8, { ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr), ReadILOperand(il, op4, addr) }));
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
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
					il.Sub(4,
						il.ShiftLeft(4,
							il.Const(4, 1),
							ReadILOperand(il, op2, addr)
						),
						il.Const(4, 1)
					)
				));

				ExprId source = ReadILOperand(il, op3, addr);
				Saturate(il, LLIL_TEMP(1), il.SignExtend(4, LowHalf(il, source)), il.Register(4, LLIL_TEMP(0)), false);
				Saturate(il, LLIL_TEMP(2), il.SignExtend(4, SignedHighHalf(il, source)), il.Register(4, LLIL_TEMP(0)), false);

				il.AddInstruction(il.SetRegister(4, op1.reg,
					PackHalfwords(il, il.Register(4, LLIL_TEMP(1)), il.Register(4, LLIL_TEMP(2)))
				));
			});
			break;
		case ARMV7_USAX:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t, Instruction&, LowLevelILFunction& il)
				{
					AddParallelGEIntrinsic(il, op1.reg, ARMV7_INTRIN_USAX, ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr));
				});
			break;
		case ARMV7_UXTAB:
			ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
				il.Add(get_register_size(op2.reg), ReadRegisterOrPointer(il, op2, addr),
					il.And(get_register_size(op3.reg),
						GetShiftedRegister(il, op3), il.Const(get_register_size(op3.reg), 0xff)))));
			break;
		case ARMV7_UXTAB16:
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_UXTAB16, { ReadILOperand(il, op2, addr), ReadILOperand(il, op3, addr) }));
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
			ConditionExecute(il, instr.cond, il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, ARMV7_INTRIN_UXTB16, { ReadILOperand(il, op2, addr) }));
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
		case ARMV7_VCVT:
			if (op3.cls == IMM)
			{
				size_t destSize = get_register_size(op1.reg);
				size_t fixedSize = GetDataTypeSize(instr.dataType);
				if (!fixedSize)
					fixedSize = destSize;
				size_t sourceSize = GetDataTypeSize(instr.dataType2);
				if (!sourceSize)
					sourceSize = get_register_size(op2.reg);
				auto source = [&]() {
					ExprId value = il.Register(get_register_size(op2.reg), op2.reg);
					if (sourceSize < get_register_size(op2.reg))
						value = il.LowPart(sourceSize, value);
					return value;
				};
				switch (instr.dataType)
				{
				case DT_S16:
				case DT_S32:
					ConditionExecute(il, instr.cond, il.SetRegister(destSize, op1.reg,
						il.SignExtend(destSize,
							il.FloatToInt(fixedSize,
								il.RoundToInt(sourceSize,
									il.FloatMult(sourceSize,
										source(),
										FixedPointScale(il, sourceSize, op3.imm)))))));
					break;
				case DT_U16:
				case DT_U32:
					ConditionExecute(il, instr.cond, il.SetRegister(destSize, op1.reg,
						il.ZeroExtend(destSize,
							il.FloatToInt(fixedSize,
								il.RoundToInt(sourceSize,
									il.FloatMult(sourceSize,
										source(),
										FixedPointScale(il, sourceSize, op3.imm)))))));
					break;
				case DT_F32:
				case DT_F64:
					switch (instr.dataType2)
					{
					case DT_S16:
					case DT_S32:
						ConditionExecute(il, instr.cond, il.SetRegister(destSize, op1.reg,
							il.FloatDiv(destSize,
								il.IntToFloat(destSize, il.SignExtend(destSize, source())),
								FixedPointScale(il, destSize, op3.imm))));
						break;
					case DT_U16:
					case DT_U32:
						ConditionExecute(il, instr.cond, il.SetRegister(destSize, op1.reg,
							il.FloatDiv(destSize,
								il.IntToFloat(destSize, il.ZeroExtend(destSize, source())),
								FixedPointScale(il, destSize, op3.imm))));
						break;
					default:
						break;
					}
					break;
				default:
					break;
				}
				break;
			}
			switch (instr.dataType)
			{
			// To integer cases
			case DT_S32:
				switch (instr.dataType2)
				{
				case DT_F32:
				case DT_F64:
					ConditionExecute(il, instr.cond, il.SetRegister(get_register_size(op1.reg), op1.reg,
						il.SignExtend(get_register_size(op1.reg),
							il.FloatToInt(get_register_size(op1.reg), il.RoundToInt(get_register_size(op2.reg),
								il.Register(get_register_size(op2.reg), op2.reg))))));
					break;
				default:
					break;
				}
				break;
			case DT_U32:
				switch (instr.dataType2)
				{
				case DT_F32:
				case DT_F64:
					ConditionExecute(il, instr.cond, il.SetRegister(get_register_size(op1.reg), op1.reg,
						il.ZeroExtend(get_register_size(op1.reg),
							il.FloatToInt(get_register_size(op1.reg), il.RoundToInt(get_register_size(op2.reg),
								il.Register(get_register_size(op2.reg), op2.reg))))));
					break;
				default:
					break;
				}
				break;
			// To float from integer cases
			case DT_F32:
			case DT_F64:
				switch (instr.dataType2)
				{
				case DT_S32:
					ConditionExecute(il, instr.cond, il.SetRegister(get_register_size(op1.reg), op1.reg,
						il.IntToFloat(get_register_size(op1.reg),
							il.SignExtend(get_register_size(op1.reg),
								il.Register(get_register_size(op2.reg), op2.reg)))));
					break;
				case DT_U32:
					ConditionExecute(il, instr.cond, il.SetRegister(get_register_size(op1.reg), op1.reg,
						il.IntToFloat(get_register_size(op1.reg),
							il.ZeroExtend(get_register_size(op1.reg),
								il.Register(get_register_size(op2.reg), op2.reg)))));
					break;
				default:
					break;
				}
				break;
			default:
				break;
			}
			break;
		case ARMV7_VADD:
			if (op1.cls != REG || op2.cls != REG || op3.cls != REG)
			{
				ConditionExecute(il, instr.cond, il.Unimplemented());
				break;
			}

			if ((instr.dataType == DT_F32) || (instr.dataType == DT_F64))
			{
				ConditionExecute(il, instr.cond,
					il.SetRegister(get_register_size(op1.reg), op1.reg,
						il.FloatAdd(get_register_size(op1.reg),
							il.Register(get_register_size(op2.reg), op2.reg),
							il.Register(get_register_size(op3.reg), op3.reg)
						)
					)
				);
			}
			else
			{
				ConditionExecute(il, instr.cond, VectorAddSubtract(il, instr, ARMV7_INTRIN_VADD));
			}
			break;
		case ARMV7_VCMP:
		case ARMV7_VCMPE:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					FloatCompare(il, instr);
				});
			break;
		case ARMV7_VCEQ:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					VectorCompareEqual(il, instr);
				});
			break;
		case ARMV7_VCGT:
			ConditionExecute(il, instr.cond, VectorCompareGreaterThan(il, instr));
			break;
		case ARMV7_VAND:
			if (op1.cls != REG || op2.cls != REG || op3.cls != REG)
			{
				ConditionExecute(il, instr.cond, il.Unimplemented());
				break;
			}
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg,
					il.And(get_register_size(op1.reg),
						il.Register(get_register_size(op2.reg), op2.reg),
						il.Register(get_register_size(op3.reg), op3.reg)),
					flagOperation[instr.setsFlags]));
			break;
		case ARMV7_VORR:
			if (op1.cls != REG || op2.cls != REG || op3.cls != REG)
			{
				ConditionExecute(il, instr.cond, il.Unimplemented());
				break;
			}
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg,
					il.Or(get_register_size(op1.reg),
						il.Register(get_register_size(op2.reg), op2.reg),
						il.Register(get_register_size(op3.reg), op3.reg)),
					flagOperation[instr.setsFlags]));
			break;
		case ARMV7_VDUP:
		{
			ConditionExecute(il, instr.cond, VectorDuplicate(il, instr));
			break;
		}
		case ARMV7_VTBL:
		case ARMV7_VTBX:
			ConditionExecute(il, instr.cond, VectorTableLookup(il, instr));
			break;
		case ARMV7_VDIV:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
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
		case ARMV7_VHADD:
			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					HalvingVectorAdd(il, instr);
				});
			break;
		case ARMV7_VSQRT:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;

			ConditionExecute(il, instr.cond,
				il.SetRegister(get_register_size(op1.reg), op1.reg,
					il.FloatSqrt(get_register_size(op1.reg),
						il.Register(get_register_size(op2.reg), op2.reg)
					)
				)
			);
			break;
		case ARMV7_VRINTA:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;
			ConditionExecute(il, instr.cond,
				il.Intrinsic(
					{ RegisterOrFlag::Register(op1.reg) },
					ARMV7_INTRIN_VRINTA,
					{ il.Register(get_register_size(op2.reg), op2.reg) }
				)
			);
			break;
		case ARMV7_VRINTN:
		case ARMV7_VRINTP:
		case ARMV7_VRINTM:
		case ARMV7_VRINTR:
		case ARMV7_VRINTX:
		case ARMV7_VRINTZ:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;
			ConditionExecute(il, instr.cond,
				il.SetRegister(get_register_size(op1.reg), op1.reg,
					RoundFloatOperand(il, instr, il.Register(get_register_size(op2.reg), op2.reg), get_register_size(op1.reg))
				)
			);
			break;
		case ARMV7_VMAXNM:
		case ARMV7_VMINM:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;
			ConditionExecute(il, instr.cond,
				il.Intrinsic(
					{ RegisterOrFlag::Register(op1.reg) },
					(instr.operation == ARMV7_VMAXNM) ? ARMV7_INTRIN_VMAXNM : ARMV7_INTRIN_VMINNM,
					{ il.Register(get_register_size(op2.reg), op2.reg),
						il.Register(get_register_size(op3.reg), op3.reg) }
				)
			);
			break;
		case ARMV7_VMAX:
			ConditionExecute(il, instr.cond, VectorMaximumMinimum(il, instr, ARMV7_INTRIN_VMAX));
			break;
		case ARMV7_VMIN:
			ConditionExecute(il, instr.cond, VectorMaximumMinimum(il, instr, ARMV7_INTRIN_VMIN));
			break;
		case ARMV7_VPMAX:
			ConditionExecute(il, instr.cond, VectorMaximumMinimum(il, instr, ARMV7_INTRIN_VPMAX));
			break;
		case ARMV7_VPMIN:
			ConditionExecute(il, instr.cond, VectorMaximumMinimum(il, instr, ARMV7_INTRIN_VPMIN));
			break;
		case ARMV7_VREV16:
			ConditionExecute(il, instr.cond, VectorReverse(il, instr, ARMV7_INTRIN_VREV16));
			break;
		case ARMV7_VREV32:
			ConditionExecute(il, instr.cond, VectorReverse(il, instr, ARMV7_INTRIN_VREV32));
			break;
		case ARMV7_VREV64:
			ConditionExecute(il, instr.cond, VectorReverse(il, instr, ARMV7_INTRIN_VREV64));
			break;
		case ARMV7_VEXT:
			ConditionExecute(il, instr.cond, VectorExtract(il, instr));
			break;
		case ARMV7_VQSHRN:
		case ARMV7_VQSHRUN:
		case ARMV7_VQRSHRN:
		case ARMV7_VQRSHRUN:
			ConditionExecute(il, instr.cond, SaturatingVectorShiftRightNarrow(il, instr));
			break;
		case ARMV7_VQMOVN:
		case ARMV7_VQMOVUN:
			ConditionExecute(il, instr.cond, SaturatingVectorMoveNarrow(il, instr));
			break;
		case ARMV7_VQADD:
			ConditionExecute(il, instr.cond, SaturatingVectorAdd(il, instr));
			break;
		case ARMV7_VABD:
			ConditionExecute(il, instr.cond,
				VectorAbsoluteDifference(il, instr, ARMV7_INTRIN_VABD));
			break;
		case ARMV7_VABDL:
			ConditionExecute(il, instr.cond,
				VectorAbsoluteDifference(il, instr, ARMV7_INTRIN_VABDL));
			break;
		case ARMV7_VABA:
			ConditionExecute(il, instr.cond,
				VectorAbsoluteDifferenceAccumulate(il, instr, ARMV7_INTRIN_VABA));
			break;
		case ARMV7_VABAL:
			ConditionExecute(il, instr.cond,
				VectorAbsoluteDifferenceAccumulate(il, instr, ARMV7_INTRIN_VABAL));
			break;
		case ARMV7_VADDL:
			ConditionExecute(il, instr.cond,
				VectorWideningAdd(il, instr, ARMV7_INTRIN_VADDL));
			break;
		case ARMV7_VADDW:
			ConditionExecute(il, instr.cond,
				VectorWideningAdd(il, instr, ARMV7_INTRIN_VADDW));
			break;
		case ARMV7_VRADDHN:
			ConditionExecute(il, instr.cond, VectorRoundingAddNarrow(il, instr));
			break;
		case ARMV7_VQSHL:
			ConditionExecute(il, instr.cond, SaturatingVectorShiftLeft(il, instr, ARMV7_INTRIN_VQSHL));
			break;
		case ARMV7_VQRSHL:
			ConditionExecute(il, instr.cond, SaturatingVectorShiftLeft(il, instr, ARMV7_INTRIN_VQRSHL));
			break;
		case ARMV7_VRSHR:
		case ARMV7_VRSHL:
			ConditionExecute(il, instr.cond, RoundedVectorShift(il, instr));
			break;
		case ARMV7_VSRA:
			ConditionExecute(il, instr.cond, ShiftRightAccumulateOrInsert(il, instr, ARMV7_INTRIN_VSRA));
			break;
		case ARMV7_VRSRA:
			ConditionExecute(il, instr.cond, ShiftRightAccumulateOrInsert(il, instr, ARMV7_INTRIN_VRSRA));
			break;
		case ARMV7_VSRI:
			ConditionExecute(il, instr.cond, ShiftRightAccumulateOrInsert(il, instr, ARMV7_INTRIN_VSRI));
			break;
		case ARMV7_VSLI:
			ConditionExecute(il, instr.cond, ShiftRightAccumulateOrInsert(il, instr, ARMV7_INTRIN_VSLI));
			break;
		case ARMV7_VFMA:
		case ARMV7_VFMS:
		{
			if ((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;

			size_t size = get_register_size(op1.reg);
			ExprId product = il.FloatMult(size,
				il.Register(get_register_size(op2.reg), op2.reg),
				il.Register(get_register_size(op3.reg), op3.reg));
			ExprId value = (instr.operation == ARMV7_VFMA)
				? il.FloatAdd(size, il.Register(size, op1.reg), product)
				: il.FloatSub(size, il.Register(size, op1.reg), product);
			ConditionExecute(il, instr.cond, il.SetRegister(size, op1.reg, value));
			break;
		}
		case ARMV7_VMLA:
		case ARMV7_VMLS:
		{
			if ((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
			{
				ConditionExecute(il, instr.cond, VectorMultiplyAccumulateIntrinsic(il, instr,
					(instr.operation == ARMV7_VMLS) ? ARMV7_INTRIN_VMLS : ARMV7_INTRIN_VMLA));
				break;
			}

			if ((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;

			size_t size = get_register_size(op1.reg);
			ExprId product = il.FloatMult(size,
				il.Register(get_register_size(op2.reg), op2.reg),
				il.Register(get_register_size(op3.reg), op3.reg));
			ExprId value = (instr.operation == ARMV7_VMLA)
				? il.FloatAdd(size, il.Register(size, op1.reg), product)
				: il.FloatSub(size, il.Register(size, op1.reg), product);
			ConditionExecute(il, instr.cond,
				il.SetRegister(size, op1.reg, value));
			break;
		}
		case ARMV7_VMLAL:
		case ARMV7_VMLSL:
		{
			ConditionExecute(il, instr.cond, VectorMultiplyAccumulateIntrinsic(il, instr,
				(instr.operation == ARMV7_VMLSL) ? ARMV7_INTRIN_VMLSL : ARMV7_INTRIN_VMLAL));
			break;
		}
		case ARMV7_VFNMA:
		case ARMV7_VFNMS:
		case ARMV7_VNMLA:
		case ARMV7_VNMLS:
		{
			if ((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;

			size_t size = get_register_size(op1.reg);
			ExprId product = il.FloatMult(size,
				il.Register(get_register_size(op2.reg), op2.reg),
				il.Register(get_register_size(op3.reg), op3.reg));
			ExprId value = ((instr.operation == ARMV7_VFNMA) || (instr.operation == ARMV7_VNMLA))
				? il.FloatNeg(size, il.FloatAdd(size, il.Register(size, op1.reg), product))
				: il.FloatNeg(size, il.FloatSub(size, il.Register(size, op1.reg), product));
			ConditionExecute(il, instr.cond,
				il.SetRegister(size, op1.reg, value));
			break;
		}
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
			if (op1.cls == REG && op1.flags.hasElements == 1 && op2.cls == REG && op3.cls == NONE)
			{
				size_t elementSize = GetDataTypeSize(instr.dataType);
				if (elementSize == 0)
				{
					ConditionExecute(il, instr.cond, il.Unimplemented());
					break;
				}
				ConditionExecute(il, instr.cond,
					SetRegisterOrBranch(il, op1.reg,
						InsertVectorElement(il, op1, il.Register(get_register_size(op2.reg), op2.reg), elementSize),
						flagOperation[instr.setsFlags]));
				break;
			}
			if (op1.cls == REG && op2.cls == REG && op2.flags.hasElements == 1 && op3.cls == NONE)
			{
				size_t elementSize = GetDataTypeSize(instr.dataType);
				size_t outputSize = get_register_size(op1.reg);
				if (elementSize == 0)
				{
					ConditionExecute(il, instr.cond, il.Unimplemented());
					break;
				}
				ConditionExecute(il, instr.cond,
					SetRegisterOrBranch(il, op1.reg,
						ReadVectorElement(il, op2, elementSize, outputSize, IsSignedDataType(instr.dataType)),
						flagOperation[instr.setsFlags]));
				break;
			}
			/* VMOV(register) */
			if (op1.cls == REG && op2.cls == REG && op3.cls == REG && op4.cls == NONE)
			{
				if (get_register_size(op1.reg) == (get_register_size(op2.reg) + get_register_size(op3.reg)))
				{
					ConditionExecute(il, instr.cond,
						SetRegisterOrBranch(il, op1.reg,
							il.RegisterSplit(get_register_size(op2.reg), op3.reg, op2.reg),
							flagOperation[instr.setsFlags]));
				}
				else
				{
					ConditionExecute(il, instr.cond,
						il.SetRegisterSplit(get_register_size(op1.reg), op2.reg, op1.reg,
							il.Register(get_register_size(op3.reg), op3.reg),
							flagOperation[instr.setsFlags]));
				}
			}
			else if (op1.cls == REG && op2.cls == REG && op3.cls == NONE)
			{
				ConditionExecute(il, instr.cond,
					SetRegisterOrBranch(il, op1.reg,
						ReadILOperand(il, op2, addr), flagOperation[instr.setsFlags]));
			} else if (op1.cls == REG && (op2.cls == IMM || op2.cls == IMM64 || op2.cls == FIMM32 || op2.cls == FIMM64) && op3.cls == NONE) {
			/* VMOV(immediate) */
				uint64_t imm = (op2.cls == FIMM32) ? op2.imm : op2.imm64;
				if (get_register_size(op1.reg) == 16)
				{
					ConditionExecute(il, instr.cond,
						SetRegisterOrBranch(il, op1.reg,
							il.Or(16, il.Const(8, imm), il.ShiftLeft(16, il.Const(8, imm), il.Const(8, 64))),
								flagOperation[instr.setsFlags]));
				} else
				{
					ConditionExecute(il, instr.cond,
						SetRegisterOrBranch(il, op1.reg,
							il.Const(get_register_size(op1.reg), imm), flagOperation[instr.setsFlags]));
				}
			} else
			{
				ConditionExecute(il, instr.cond, il.Unimplemented());
			}
			break;
		case ARMV7_VQDMULL:
			ConditionExecute(il, instr.cond, VectorSaturatingDoublingMultiplyLongIntrinsic(il, instr));
			break;
		case ARMV7_VMUL:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
			{
				ConditionExecute(il, instr.cond, VectorMultiply(il, instr));
				break;
			}

			if((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
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
		case ARMV7_VNMUL:
			if((instr.dataType != DT_F32) && (instr.dataType != DT_F64))
				break;

			ConditionExecute(il, instr.cond,
				il.SetRegister(get_register_size(op1.reg), op1.reg,
					il.FloatNeg(get_register_size(op1.reg),
						il.FloatMult(get_register_size(op1.reg),
							il.Register(get_register_size(op2.reg), op2.reg),
							il.Register(get_register_size(op3.reg), op3.reg)
						)
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
		case ARMV7_VST1:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						StoreVst1(il, instr, addr);
					});
			break;
		case ARMV7_VST2:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						StoreStructuredVector(il, instr, addr, ARMV7_INTRIN_VST2, 2);
					});
			break;
		case ARMV7_VST4:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						StoreStructuredVector(il, instr, addr, ARMV7_INTRIN_VST4, 4);
					});
			break;
		case ARMV7_VLD2:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						LoadStructuredVector(il, instr, addr, ARMV7_INTRIN_VLD2, 2);
					});
			break;
		case ARMV7_VLD4:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						LoadStructuredVector(il, instr, addr, ARMV7_INTRIN_VLD4, 4);
					});
			break;
		case ARMV7_VLD1:
			ConditionExecute(addrSize, instr.cond, instr, il,
					[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
					{
						(void) addrSize;
						LoadVld1(il, instr, addr);
					});
			break;
		case ARMV7_VSHR:
		{
			size_t elementSize = GetDataTypeSize(instr.dataType);
			size_t size = get_register_size(op1.reg);
			if (op1.cls != REG || op2.cls != REG || op3.cls != IMM || elementSize != size)
			{
				ConditionExecute(il, instr.cond, il.Unimplemented());
				break;
			}

			ExprId value = IsSignedDataType(instr.dataType)
				? il.ArithShiftRight(size, il.Register(size, op2.reg), il.Const(1, op3.imm))
				: il.LogicalShiftRight(size, il.Register(size, op2.reg), il.Const(1, op3.imm));
			ConditionExecute(il, instr.cond,
				SetRegisterOrBranch(il, op1.reg, value, flagOperation[instr.setsFlags]));
			break;
		}
		case ARMV7_VSHL:
		{
			size_t elementSize = GetDataTypeSize(instr.dataType);
			size_t size = get_register_size(op1.reg);
			if (op1.cls != REG || op2.cls != REG || elementSize != size)
			{
				ConditionExecute(il, instr.cond, il.Unimplemented());
				break;
			}

			if (op3.cls == IMM)
			{
				ConditionExecute(il, instr.cond,
					SetRegisterOrBranch(il, op1.reg,
						il.ShiftLeft(size, il.Register(size, op2.reg), il.Const(1, op3.imm)),
						flagOperation[instr.setsFlags]));
				break;
			}

			if (op3.cls != REG || get_register_size(op3.reg) != size)
			{
				ConditionExecute(il, instr.cond, il.Unimplemented());
				break;
			}

			ConditionExecute(addrSize, instr.cond, instr, il,
				[&](size_t addrSize, Instruction& instr, LowLevelILFunction& il)
				{
					(void) addrSize;
					(void) instr;
					LowLevelILLabel rightShift, leftShift, done;
					il.AddInstruction(il.If(
						il.CompareSignedLessThan(size, il.Register(size, op3.reg), il.Const(size, 0)),
						rightShift, leftShift));
					il.MarkLabel(rightShift);
					il.AddInstruction(SetRegisterOrBranch(il, op1.reg,
						IsSignedDataType(instr.dataType)
							? il.ArithShiftRight(size, il.Register(size, op2.reg), il.Neg(size, il.Register(size, op3.reg)))
							: il.LogicalShiftRight(size, il.Register(size, op2.reg), il.Neg(size, il.Register(size, op3.reg))),
						flagOperation[instr.setsFlags]));
					il.AddInstruction(il.Goto(done));
					il.MarkLabel(leftShift);
					il.AddInstruction(SetRegisterOrBranch(il, op1.reg,
						il.ShiftLeft(size, il.Register(size, op2.reg), il.Register(size, op3.reg)),
						flagOperation[instr.setsFlags]));
					il.MarkLabel(done);
				});
			break;
		}
		case ARMV7_VSUB:
			if (op1.cls != REG || op2.cls != REG || op3.cls != REG)
			{
				ConditionExecute(il, instr.cond, il.Unimplemented());
				break;
			}

			if ((instr.dataType == DT_F32) || (instr.dataType == DT_F64))
			{
				ConditionExecute(il, instr.cond,
					il.SetRegister(get_register_size(op1.reg), op1.reg,
						il.FloatSub(get_register_size(op1.reg),
							il.Register(get_register_size(op2.reg), op2.reg),
							il.Register(get_register_size(op3.reg), op3.reg)
						)
					)
				);
			}
			else
			{
				ConditionExecute(il, instr.cond, VectorAddSubtract(il, instr, ARMV7_INTRIN_VSUB));
			}
			break;
		default:
			//printf("Instruction: %s\n", get_operation(instr.operation));
			ConditionExecute(il, instr.cond, il.Unimplemented());
			break;
	}
	return true;
}
