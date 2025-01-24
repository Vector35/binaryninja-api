#include "lowlevelilinstruction.h"
#include <cstring>
#include <inttypes.h>
#include <stdarg.h>

#include "il.h"
#include "neon_intrinsics.h"
#include "sysregs.h"

using namespace BinaryNinja;

#include "il_macros.h"

static uint32_t GetFlagWriteTypeForEffect(FlagEffect e) {
	switch (e) {
	case FLAGEFFECT_SETS:
	case FLAGEFFECT_SETS_NORMAL:
		return IL_FLAG_WRITE_ALL;
	case FLAGEFFECT_SETS_FLOAT:
		return IL_FLAG_WRITE_ALL_FLOAT;
	case FLAGEFFECT_NONE:
	default:
		return 0;
	}
}

static ExprId GetCondition(LowLevelILFunction& il, Condition cond)
{
	switch (cond)
	{
	case COND_EQ:
		return il.FlagGroup(IL_FLAG_GROUP_EQ);
	case COND_NE:
		return il.FlagGroup(IL_FLAG_GROUP_NE);
	case COND_CS:
		return il.FlagGroup(IL_FLAG_GROUP_CS);
	case COND_CC:
		return il.FlagGroup(IL_FLAG_GROUP_CC);
	case COND_MI:
		return il.FlagGroup(IL_FLAG_GROUP_MI);
	case COND_PL:
		return il.FlagGroup(IL_FLAG_GROUP_PL);
	case COND_VS:
		return il.FlagGroup(IL_FLAG_GROUP_VS);
	case COND_VC:
		return il.FlagGroup(IL_FLAG_GROUP_VC);
	case COND_HI:
		return il.FlagGroup(IL_FLAG_GROUP_HI);
	case COND_LS:
		return il.FlagGroup(IL_FLAG_GROUP_LS);
	case COND_GE:
		return il.FlagGroup(IL_FLAG_GROUP_GE);
	case COND_LT:
		return il.FlagGroup(IL_FLAG_GROUP_LT);
	case COND_GT:
		return il.FlagGroup(IL_FLAG_GROUP_GT);
	case COND_LE:
		return il.FlagGroup(IL_FLAG_GROUP_LE);
	case COND_AL:
		return il.Const(0, 1);  // Always branch
	case COND_NV:
	default:
		return il.Const(0, 0);  // Never branch
	}
}

static void GenIfElse(LowLevelILFunction& il, ExprId clause, ExprId trueCase, ExprId falseCase)
{
	if (falseCase)
	{
		LowLevelILLabel trueCode, falseCode, done;
		il.AddInstruction(il.If(clause, trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(trueCase);
		il.AddInstruction(il.Goto(done));
		il.MarkLabel(falseCode);
		il.AddInstruction(falseCase);
		il.AddInstruction(il.Goto(done));
		il.MarkLabel(done);
	}
	else
	{
		LowLevelILLabel trueCode, done;
		il.AddInstruction(il.If(clause, trueCode, done));
		il.MarkLabel(trueCode);
		il.AddInstruction(trueCase);
		il.MarkLabel(done);
	}
	return;
}

ExprId ExtractImmediate(LowLevelILFunction& il, InstructionOperand& operand, int sizeof_imm)
{
	if (operand.operandClass != IMM32 && operand.operandClass != IMM64)
		return il.Unimplemented();

	uint64_t imm = operand.immediate;

	if (operand.shiftValueUsed)
	{
		switch (operand.shiftType)
		{
		case ShiftType_LSL:
			imm = imm << operand.shiftValue;
			break;
		case ShiftType_LSR:
			imm = imm >> operand.shiftValue;
			break;
		case ShiftType_MSL:
			imm = (imm << operand.shiftValue) | ONES(operand.shiftValue);
			break;
		case ShiftType_ASR:
		case ShiftType_ROR:
		case ShiftType_UXTW:
		case ShiftType_SXTW:
		case ShiftType_SXTX:
		case ShiftType_UXTX:
		case ShiftType_SXTB:
		case ShiftType_SXTH:
		case ShiftType_UXTH:
		case ShiftType_UXTB:
		case ShiftType_END:
		default:
			return il.Unimplemented();
		}
	}

	return ILCONST(sizeof_imm, imm & ONES(sizeof_imm * 8));
}

// extractSize can be smaller than the register, generating an LLIL_LOWPART
// resultSize can be larger than the register, generating sign or zero extension
ExprId ExtractRegister(LowLevelILFunction& il, InstructionOperand& operand, size_t regNum,
    size_t extractSize, bool signExtend, size_t resultSize)
{
	size_t opsz = get_register_size(operand.reg[regNum]);

	if (IS_ZERO_REG(operand.reg[regNum]))
	    return il.Const(resultSize, 0);

	ExprId res = 0;

	switch (operand.operandClass)
	{
	case SYS_REG:
		res = il.Register(opsz, operand.sysreg);
		break;
	case REG:
	default:
		res = il.Register(opsz, operand.reg[regNum]);
		break;
	}

	if (extractSize < opsz)
		res = il.LowPart(extractSize, res);

	if (extractSize < resultSize || opsz < extractSize)
	{
		if (signExtend)
			res = il.SignExtend(resultSize, res);
		else
			res = il.ZeroExtend(resultSize, res);
	}

	return res;
}

static ExprId GetFloat(LowLevelILFunction& il, InstructionOperand& operand, int float_sz)
{
	if (operand.operandClass == FIMM32)
	{
		switch (float_sz)
		{
		case 2:
			return il.FloatConstRaw(2, operand.immediate);
		case 4:
			return il.FloatConstSingle(*(float*)&(operand.immediate));
		case 8:
			return il.FloatConstDouble(*(float*)&(operand.immediate));
		default:
			break;
		}
	}
	else if (operand.operandClass == REG)
	{
		return il.FloatConvert(
		    float_sz, ExtractRegister(il, operand, 0, REGSZ_O(operand), false, REGSZ_O(operand)));
	}

	return il.Unimplemented();
}

static ExprId GetShiftedRegister(
    LowLevelILFunction& il, InstructionOperand& operand, size_t regNum, size_t resultSize)
{
	ExprId res;

	// peel off the variants that return early
	switch (operand.shiftType)
	{
	case ShiftType_NONE:
		res = ExtractRegister(il, operand, regNum, REGSZ_O(operand), false, resultSize);
		return res;
	case ShiftType_ASR:
		res = ExtractRegister(il, operand, regNum, REGSZ_O(operand), false, resultSize);
		if (operand.shiftValue)
			res = il.ArithShiftRight(resultSize, res, il.Const(1, operand.shiftValue));
		return res;
	case ShiftType_LSR:
		res = ExtractRegister(il, operand, regNum, REGSZ_O(operand), false, resultSize);
		if (operand.shiftValue)
			res = il.LogicalShiftRight(resultSize, res, il.Const(1, operand.shiftValue));
		return res;
	case ShiftType_ROR:
		res = ExtractRegister(il, operand, regNum, REGSZ_O(operand), false, resultSize);
		if (operand.shiftValue)
			res = il.RotateRight(resultSize, res, il.Const(1, operand.shiftValue));
		return res;
	default:
		break;
	}

	// everything else falls through to maybe be left shifted
	switch (operand.shiftType)
	{
	case ShiftType_LSL:
		res = ExtractRegister(il, operand, regNum, REGSZ_O(operand), false, resultSize);
		break;
	case ShiftType_SXTB:
		res = ExtractRegister(il, operand, regNum, 1, true, resultSize);
		break;
	case ShiftType_SXTH:
		res = ExtractRegister(il, operand, regNum, 2, true, resultSize);
		break;
	case ShiftType_SXTW:
		res = ExtractRegister(il, operand, regNum, 4, true, resultSize);
		break;
	case ShiftType_SXTX:
		res = ExtractRegister(il, operand, regNum, 8, true, resultSize);
		break;
	case ShiftType_UXTB:
		res = ExtractRegister(il, operand, regNum, 1, false, resultSize);
		break;
	case ShiftType_UXTH:
		res = ExtractRegister(il, operand, regNum, 2, false, resultSize);
		break;
	case ShiftType_UXTW:
		res = ExtractRegister(il, operand, regNum, 4, false, resultSize);
		break;
	case ShiftType_UXTX:
		res = ExtractRegister(il, operand, regNum, 8, false, resultSize);
		break;
	default:
		il.AddInstruction(il.Unimplemented());
		return il.Unimplemented();
	}

	if (operand.shiftValue)
		res = il.ShiftLeft(resultSize, res, il.Const(1, operand.shiftValue));

	return res;
}

static ExprId GetILOperandPreOrPostIndex(LowLevelILFunction& il, InstructionOperand& operand)
{
	if (operand.operandClass != MEM_PRE_IDX && operand.operandClass != MEM_POST_IDX)
		return 0;

	if (operand.reg[1] == REG_NONE)
	{
		// ..., [Xn], #imm
		if (IMM_O(operand) == 0)
			return 0;

		return ILSETREG_O(operand, ILADDREG_O(operand, il.Const(REGSZ_O(operand), IMM_O(operand))));
	}
	else
	{
		// ..., [Xn], <Xm>
		return ILSETREG_O(operand, ILADDREG_O(operand, il.Register(8, operand.reg[1])));
	}
}

/* Returns an expression that does any pre-incrementing on an operand, if it exists */
static ExprId GetILOperandPreIndex(LowLevelILFunction& il, InstructionOperand& operand)
{
	if (operand.operandClass != MEM_PRE_IDX)
		return 0;

	return GetILOperandPreOrPostIndex(il, operand);
}

/* Returns an expression that does any post-incrementing on an operand, if it exists */
static ExprId GetILOperandPostIndex(LowLevelILFunction& il, InstructionOperand& operand)
{
	if (operand.operandClass != MEM_POST_IDX)
		return 0;

	return GetILOperandPreOrPostIndex(il, operand);
}

/* Returns an IL expression that reads (and only reads) from the operand.
  It accounts for, but does not generate IL that executes, pre and post indexing.
  The operand class can be overridden.
  An additional offset can be applied, convenient for calculating sequential loads and stores. */
static ExprId GetILOperandEffectiveAddress(LowLevelILFunction& il, InstructionOperand& operand,
    size_t addrSize, OperandClass oclass, size_t extra_offset)
{
	ExprId addr = 0;
	if (oclass == NONE)
		oclass = operand.operandClass;
	switch (oclass)
	{
	case MEM_REG:       // ldr x0, [x1]
	case MEM_POST_IDX:  // ldr w0, [x1], #4
		addr = ILREG_O(operand);
		if (extra_offset)
			addr = il.Add(addrSize, addr, il.Const(addrSize, extra_offset));
		break;
	case MEM_OFFSET:   // ldr w0, [x1, #4]
	case MEM_PRE_IDX:  // ldr w0, [x1, #4]!
		addr = il.Add(addrSize, ILREG_O(operand), il.Const(addrSize, operand.immediate + extra_offset));
		break;
	case MEM_EXTENDED:
		if (operand.shiftType == ShiftType_NONE)
		{
			addr =
			    il.Add(addrSize, ILREG_O(operand), il.Const(addrSize, operand.immediate + extra_offset));
		}
		else if (operand.shiftType == ShiftType_LSL)
		{
			if (extra_offset)
			{
				addr = il.Add(addrSize, ILREG_O(operand),
				    il.Add(addrSize,
				        il.ShiftLeft(addrSize, il.Const(addrSize, operand.immediate),
				            il.Const(1, operand.shiftValue)),
				        il.Const(addrSize, extra_offset)));
			}
			else
			{
				addr = il.Add(addrSize, ILREG_O(operand),
				    il.ShiftLeft(
				        addrSize, il.Const(addrSize, operand.immediate), il.Const(1, operand.shiftValue)));
			}
		}
		else
		{
			// printf("ERROR: dunno how to handle MEM_EXTENDED shiftType %d\n", operand.shiftType);
			ABORT_LIFT;
		}
		break;
	default:
		// printf("ERROR: dunno how to handle operand class %d\n", oclass);
		ABORT_LIFT;
	}
	return addr;
}


static size_t ReadILOperand(LowLevelILFunction& il, InstructionOperand& operand, size_t resultSize)
{
	switch (operand.operandClass)
	{
	case IMM32:
	case IMM64:
		if (operand.shiftType != ShiftType_NONE && operand.shiftValue)
			return il.Const(resultSize, operand.immediate << operand.shiftValue);
		else
			return il.Const(resultSize, operand.immediate);
	case LABEL:
		return il.ConstPointer(8, operand.immediate);
	case REG:
		if (IS_ZERO_REG(operand.reg[0]))
			return il.Const(resultSize, 0);
		return GetShiftedRegister(il, operand, 0, resultSize);
	case MEM_REG:
		return il.Load(resultSize, il.Register(8, operand.reg[0]));
	case MEM_OFFSET:
		if (operand.immediate != 0)
			return il.Load(
			    resultSize, il.Add(8, il.Register(8, operand.reg[0]), il.Const(8, operand.immediate)));
		else
			return il.Load(resultSize, il.Register(8, operand.reg[0]));
	case MEM_EXTENDED:
		return il.Load(resultSize, GetILOperandEffectiveAddress(il, operand, resultSize, NONE, 0));
	case MEM_PRE_IDX:
	case MEM_POST_IDX:
	case MULTI_REG:
	case FIMM32:
		return GetFloat(il, operand, resultSize);
	case NONE:
	default:
		return il.Unimplemented();
	}
}

unsigned v_unpack_lookup_sz[15] = {0, 1, 2, 4, 8, 16, 1, 2, 4, 8, 1, 2, 4, 1, 1};

extern "C" Register* v_unpack_lookup[15][32];

Register v_consolidate_lookup[32][15] = {
    // NONE .q .2d .4s .8h .16b .d .2s .4h .8b .s .2h .4b .h .b
    {REG_V0, REG_V0, REG_V0, REG_V0, REG_V0, REG_V0, REG_V0_D0, REG_V0_D0, REG_V0_D0, REG_V0_D0,
        REG_V0_S0, REG_V0_S0, REG_V0_S0, REG_V0_H0, REG_V0_B0},
    {REG_V1, REG_V1, REG_V1, REG_V1, REG_V1, REG_V1, REG_V1_D0, REG_V1_D0, REG_V1_D0, REG_V1_D0,
        REG_V1_S0, REG_V1_S0, REG_V1_S0, REG_V1_H0, REG_V1_B0},
    {REG_V2, REG_V2, REG_V2, REG_V2, REG_V2, REG_V2, REG_V2_D0, REG_V2_D0, REG_V2_D0, REG_V2_D0,
        REG_V2_S0, REG_V2_S0, REG_V2_S0, REG_V2_H0, REG_V2_B0},
    {REG_V3, REG_V3, REG_V3, REG_V3, REG_V3, REG_V3, REG_V3_D0, REG_V3_D0, REG_V3_D0, REG_V3_D0,
        REG_V3_S0, REG_V3_S0, REG_V3_S0, REG_V3_H0, REG_V3_B0},
    {REG_V4, REG_V4, REG_V4, REG_V4, REG_V4, REG_V4, REG_V4_D0, REG_V4_D0, REG_V4_D0, REG_V4_D0,
        REG_V4_S0, REG_V4_S0, REG_V4_S0, REG_V4_H0, REG_V4_B0},
    {REG_V5, REG_V5, REG_V5, REG_V5, REG_V5, REG_V5, REG_V5_D0, REG_V5_D0, REG_V5_D0, REG_V5_D0,
        REG_V5_S0, REG_V5_S0, REG_V5_S0, REG_V5_H0, REG_V5_B0},
    {REG_V6, REG_V6, REG_V6, REG_V6, REG_V6, REG_V6, REG_V6_D0, REG_V6_D0, REG_V6_D0, REG_V6_D0,
        REG_V6_S0, REG_V6_S0, REG_V6_S0, REG_V6_H0, REG_V6_B0},
    {REG_V7, REG_V7, REG_V7, REG_V7, REG_V7, REG_V7, REG_V7_D0, REG_V7_D0, REG_V7_D0, REG_V7_D0,
        REG_V7_S0, REG_V7_S0, REG_V7_S0, REG_V7_H0, REG_V7_B0},
    {REG_V8, REG_V8, REG_V8, REG_V8, REG_V8, REG_V8, REG_V8_D0, REG_V8_D0, REG_V8_D0, REG_V8_D0,
        REG_V8_S0, REG_V8_S0, REG_V8_S0, REG_V8_H0, REG_V8_B0},
    {REG_V9, REG_V9, REG_V9, REG_V9, REG_V9, REG_V9, REG_V9_D0, REG_V9_D0, REG_V9_D0, REG_V9_D0,
        REG_V9_S0, REG_V9_S0, REG_V9_S0, REG_V9_H0, REG_V9_B0},
    {REG_V10, REG_V10, REG_V10, REG_V10, REG_V10, REG_V10, REG_V10_D0, REG_V10_D0, REG_V10_D0,
        REG_V10_D0, REG_V10_S0, REG_V10_S0, REG_V10_S0, REG_V10_H0, REG_V10_B0},
    {REG_V11, REG_V11, REG_V11, REG_V11, REG_V11, REG_V11, REG_V11_D0, REG_V11_D0, REG_V11_D0,
        REG_V11_D0, REG_V11_S0, REG_V11_S0, REG_V11_S0, REG_V11_H0, REG_V11_B0},
    {REG_V12, REG_V12, REG_V12, REG_V12, REG_V12, REG_V12, REG_V12_D0, REG_V12_D0, REG_V12_D0,
        REG_V12_D0, REG_V12_S0, REG_V12_S0, REG_V12_S0, REG_V12_H0, REG_V12_B0},
    {REG_V13, REG_V13, REG_V13, REG_V13, REG_V13, REG_V13, REG_V13_D0, REG_V13_D0, REG_V13_D0,
        REG_V13_D0, REG_V13_S0, REG_V13_S0, REG_V13_S0, REG_V13_H0, REG_V13_B0},
    {REG_V14, REG_V14, REG_V14, REG_V14, REG_V14, REG_V14, REG_V14_D0, REG_V14_D0, REG_V14_D0,
        REG_V14_D0, REG_V14_S0, REG_V14_S0, REG_V14_S0, REG_V14_H0, REG_V14_B0},
    {REG_V15, REG_V15, REG_V15, REG_V15, REG_V15, REG_V15, REG_V15_D0, REG_V15_D0, REG_V15_D0,
        REG_V15_D0, REG_V15_S0, REG_V15_S0, REG_V15_S0, REG_V15_H0, REG_V15_B0},
    {REG_V16, REG_V16, REG_V16, REG_V16, REG_V16, REG_V16, REG_V16_D0, REG_V16_D0, REG_V16_D0,
        REG_V16_D0, REG_V16_S0, REG_V16_S0, REG_V16_S0, REG_V16_H0, REG_V16_B0},
    {REG_V17, REG_V17, REG_V17, REG_V17, REG_V17, REG_V17, REG_V17_D0, REG_V17_D0, REG_V17_D0,
        REG_V17_D0, REG_V17_S0, REG_V17_S0, REG_V17_S0, REG_V17_H0, REG_V17_B0},
    {REG_V18, REG_V18, REG_V18, REG_V18, REG_V18, REG_V18, REG_V18_D0, REG_V18_D0, REG_V18_D0,
        REG_V18_D0, REG_V18_S0, REG_V18_S0, REG_V18_S0, REG_V18_H0, REG_V18_B0},
    {REG_V19, REG_V19, REG_V19, REG_V19, REG_V19, REG_V19, REG_V19_D0, REG_V19_D0, REG_V19_D0,
        REG_V19_D0, REG_V19_S0, REG_V19_S0, REG_V19_S0, REG_V19_H0, REG_V19_B0},
    {REG_V20, REG_V20, REG_V20, REG_V20, REG_V20, REG_V20, REG_V20_D0, REG_V20_D0, REG_V20_D0,
        REG_V20_D0, REG_V20_S0, REG_V20_S0, REG_V20_S0, REG_V20_H0, REG_V20_B0},
    {REG_V21, REG_V21, REG_V21, REG_V21, REG_V21, REG_V21, REG_V21_D0, REG_V21_D0, REG_V21_D0,
        REG_V21_D0, REG_V21_S0, REG_V21_S0, REG_V21_S0, REG_V21_H0, REG_V21_B0},
    {REG_V22, REG_V22, REG_V22, REG_V22, REG_V22, REG_V22, REG_V22_D0, REG_V22_D0, REG_V22_D0,
        REG_V22_D0, REG_V22_S0, REG_V22_S0, REG_V22_S0, REG_V22_H0, REG_V22_B0},
    {REG_V23, REG_V23, REG_V23, REG_V23, REG_V23, REG_V23, REG_V23_D0, REG_V23_D0, REG_V23_D0,
        REG_V23_D0, REG_V23_S0, REG_V23_S0, REG_V23_S0, REG_V23_H0, REG_V23_B0},
    {REG_V24, REG_V24, REG_V24, REG_V24, REG_V24, REG_V24, REG_V24_D0, REG_V24_D0, REG_V24_D0,
        REG_V24_D0, REG_V24_S0, REG_V24_S0, REG_V24_S0, REG_V24_H0, REG_V24_B0},
    {REG_V25, REG_V25, REG_V25, REG_V25, REG_V25, REG_V25, REG_V25_D0, REG_V25_D0, REG_V25_D0,
        REG_V25_D0, REG_V25_S0, REG_V25_S0, REG_V25_S0, REG_V25_H0, REG_V25_B0},
    {REG_V26, REG_V26, REG_V26, REG_V26, REG_V26, REG_V26, REG_V26_D0, REG_V26_D0, REG_V26_D0,
        REG_V26_D0, REG_V26_S0, REG_V26_S0, REG_V26_S0, REG_V26_H0, REG_V26_B0},
    {REG_V27, REG_V27, REG_V27, REG_V27, REG_V27, REG_V27, REG_V27_D0, REG_V27_D0, REG_V27_D0,
        REG_V27_D0, REG_V27_S0, REG_V27_S0, REG_V27_S0, REG_V27_H0, REG_V27_B0},
    {REG_V28, REG_V28, REG_V28, REG_V28, REG_V28, REG_V28, REG_V28_D0, REG_V28_D0, REG_V28_D0,
        REG_V28_D0, REG_V28_S0, REG_V28_S0, REG_V28_S0, REG_V28_H0, REG_V28_B0},
    {REG_V29, REG_V29, REG_V29, REG_V29, REG_V29, REG_V29, REG_V29_D0, REG_V29_D0, REG_V29_D0,
        REG_V29_D0, REG_V29_S0, REG_V29_S0, REG_V29_S0, REG_V29_H0, REG_V29_B0},
    {REG_V30, REG_V30, REG_V30, REG_V30, REG_V30, REG_V30, REG_V30_D0, REG_V30_D0, REG_V30_D0,
        REG_V30_D0, REG_V30_S0, REG_V30_S0, REG_V30_S0, REG_V30_H0, REG_V30_B0},
    {REG_V31, REG_V31, REG_V31, REG_V31, REG_V31, REG_V31, REG_V31_D0, REG_V31_D0, REG_V31_D0,
        REG_V31_D0, REG_V31_S0, REG_V31_S0, REG_V31_S0, REG_V31_H0, REG_V31_B0},
};

/* v28.d[1] -> REG_V0_D1 */
static Register vector_reg_minimize(InstructionOperand& oper)
{
	if (!IS_ASIMD_O(oper))
		return REG_NONE;

	if (oper.arrSpec == ARRSPEC_NONE)
	{
		if (oper.laneUsed)
			return REG_NONE;  // cannot have lane without an arrangement spec
		return oper.reg[0];
	}

	int vidx = oper.reg[0] - REG_V0;
	if (vidx < 0 || vidx > 31)
		return REG_NONE;

	if (oper.laneUsed)
	{
		switch (oper.arrSpec)
		{
		case ARRSPEC_FULL:
			return oper.reg[0];
		case ARRSPEC_1DOUBLE:
		case ARRSPEC_2DOUBLES:
			if (oper.lane >= 2)
				return REG_NONE;
			return v_unpack_lookup[ARRSPEC_2DOUBLES][vidx][oper.lane];
		case ARRSPEC_1SINGLE:
		case ARRSPEC_2SINGLES:
		case ARRSPEC_4SINGLES:
			if (oper.lane >= 4)
				return REG_NONE;
			return v_unpack_lookup[ARRSPEC_4SINGLES][vidx][oper.lane];
		case ARRSPEC_1HALF:
		case ARRSPEC_2HALVES:
		case ARRSPEC_4HALVES:
		case ARRSPEC_8HALVES:
			if (oper.lane >= 8)
				return REG_NONE;
			return v_unpack_lookup[ARRSPEC_8HALVES][vidx][oper.lane];
		case ARRSPEC_1BYTE:
		case ARRSPEC_4BYTES:
		case ARRSPEC_8BYTES:
		case ARRSPEC_16BYTES:
			if (oper.lane >= 16)
				return REG_NONE;
			return v_unpack_lookup[ARRSPEC_16BYTES][vidx][oper.lane];
		default:
			break;
		}
	}
	else
	{
		switch (oper.arrSpec)
		{
		case ARRSPEC_FULL:
		case ARRSPEC_2DOUBLES:
		case ARRSPEC_4SINGLES:
		case ARRSPEC_8HALVES:
		case ARRSPEC_16BYTES:
			return oper.reg[0];
		case ARRSPEC_1DOUBLE:
		case ARRSPEC_2SINGLES:
		case ARRSPEC_4HALVES:
		case ARRSPEC_8BYTES:
			return v_unpack_lookup[ARRSPEC_2DOUBLES][vidx][0];
		case ARRSPEC_1SINGLE:
		case ARRSPEC_2HALVES:
		case ARRSPEC_4BYTES:
			return v_unpack_lookup[ARRSPEC_4SINGLES][vidx][0];
		case ARRSPEC_1HALF:
			// case ARRSPEC_2BYTE
			return v_unpack_lookup[ARRSPEC_8HALVES][vidx][0];
		case ARRSPEC_1BYTE:
			return v_unpack_lookup[ARRSPEC_16BYTES][vidx][0];
		default:
			break;
		}
	}

	return REG_NONE;
}

/* "promote" the spec to full width so lane can select any */
static ArrangementSpec promote_spec(ArrangementSpec spec)
{
	switch (spec)
	{
	case ARRSPEC_1DOUBLE:
		return ARRSPEC_2DOUBLES;
	case ARRSPEC_1SINGLE:
	case ARRSPEC_2SINGLES:
		return ARRSPEC_4SINGLES;
	case ARRSPEC_1HALF:
	case ARRSPEC_2HALVES:
	case ARRSPEC_4HALVES:
		return ARRSPEC_8HALVES;
	case ARRSPEC_1BYTE:
	case ARRSPEC_4BYTES:
	case ARRSPEC_8BYTES:
		return ARRSPEC_16BYTES;
	default:
		return spec;
	}
}

static int unpack_vector(InstructionOperand& oper, Register* result)
{
	if (oper.operandClass == REG)
	{
		/* register without an arrangement specification is just a register
		  examples: "d18", "d6", "v7" */
		if (oper.arrSpec == ARRSPEC_NONE)
		{
			result[0] = oper.reg[0];
			return 1;
		}

		/* require V register with valid arrangement spec
		  examples: "v17.2s", "v8.4h", "v21.8b" */
		if (oper.reg[0] < REG_V0 || oper.reg[0] > REG_V31)
			return 0;
		if (oper.arrSpec <= ARRSPEC_NONE || oper.arrSpec > ARRSPEC_1BYTE)
			return 0;

		/* lookup, copy result */
		if (oper.laneUsed)
		{
			ArrangementSpec spec = promote_spec(oper.arrSpec);

			int n_lanes = v_unpack_lookup_sz[spec];

			if (oper.lane >= n_lanes)
				return 0;

			// int n = v_unpack_lookup_sz[spec];
			// for (int i = 0; i < n; ++i)
			result[0] = v_unpack_lookup[spec][oper.reg[0] - REG_V0][oper.lane];

			return 1;
		}

		int n = v_unpack_lookup_sz[oper.arrSpec];
		for (int i = 0; i < n; ++i)
			result[i] = v_unpack_lookup[oper.arrSpec][oper.reg[0] - REG_V0][i];
		return n;
	}
	else if (oper.operandClass == MULTI_REG)
	{
		if (oper.laneUsed)
		{
			/* multireg with a lane
			  examples: "ld2 {v17.d, v18.d}[1], [x20]" */

			ArrangementSpec spec = promote_spec(oper.arrSpec);

			int n = 0;
			for (int i = 0; i < 4 && oper.reg[i] != REG_NONE; i++)
			{
				int n_lanes = v_unpack_lookup_sz[spec];
				if (oper.lane >= n_lanes)
					return 0;
				result[i] = v_unpack_lookup[spec][oper.reg[i] - REG_V0][oper.lane];
				n += 1;
			}
			return n;
		}
		else
		{
			/* multireg without a lane
			  examples: "{v0.8b, v1.8b}", "{v8.2s, v9.2s}" */
			if (oper.arrSpec < ARRSPEC_NONE || oper.arrSpec > ARRSPEC_1BYTE)
				return 0;

			int n = 0;
			for (int i = 0; i < 4 && oper.reg[i] != REG_NONE; i++)
			{
				result[i] = v_consolidate_lookup[oper.reg[i] - REG_V0][oper.arrSpec];
				n += 1;
			}
			return n;
		}
	}

	return 0;
}

/* if we have two operands that have the same arrangement spec, instead of treating them as
    distinct sets of registers, see if we can consolidate the set of registers into a single
    larger register. This allows us to easily lift things like 'mov v0.16b, v1.16b' as
    'mov v0, v1' */
static int consolidate_vector(
		InstructionOperand& operand1,
		InstructionOperand& operand2,
		Register *result)
{
	/* make sure both our operand classes are single regs */
	if (operand1.operandClass != REG || operand2.operandClass != REG)
		return 0;

	/* make sure our arrSpec's match. We need this to deal with cases where the arrSpec might
        have different sizes, e.g. 'uxtl v2.2d, v8.2s'.*/
	if (operand1.arrSpec != operand2.arrSpec)
		return 0;

	result[0] = v_consolidate_lookup[operand1.reg[0]-REG_V0][operand1.arrSpec];
	result[1] = v_consolidate_lookup[operand2.reg[0]-REG_V0][operand2.arrSpec];

	return 1;
}

static void LoadStoreOperandPairSize(LowLevelILFunction& il, bool load, size_t load_size, InstructionOperand& operand1,
	InstructionOperand& operand2, InstructionOperand& operand3)
{
	/* do pre-indexing */
	ExprId tmp = GetILOperandPreIndex(il, operand3);
	if (tmp)
		il.AddInstruction(tmp);

	/* compute addresses */
	OperandClass oclass = (operand3.operandClass == MEM_PRE_IDX) ? MEM_REG : operand3.operandClass;
	ExprId addr0 = GetILOperandEffectiveAddress(il, operand3, 8, oclass, 0);
	ExprId addr1 = GetILOperandEffectiveAddress(il, operand3, 8, oclass, load_size);

	/* load/store */
	if (load)
	{
		// We lift this instruction differently if operand1 and operand3 are equal as to not break outlining in the common case,
		//  since outlining does not seem to handle intermediate stores to temporary registers
		// TODO: unify lifting once outlining handles intermediate temporary stores
		if (REG_O(operand1) != REG_O(operand3))
		{
			// {op} X, Y, [Z]
			il.AddInstruction(ILSETREG_O(operand1, il.Load(load_size, addr0)));
			il.AddInstruction(ILSETREG_O(operand2, il.Load(load_size, addr1)));
		}
		else
		{
			// {op} X, Y, [X]
			// Prevent clobbering of source during write to operand1 by storing source in a temporary register
			il.AddInstruction(il.SetRegister(REGSZ_O(operand1), LLIL_TEMP(0), addr1));
			il.AddInstruction(ILSETREG_O(operand1, il.Load(load_size, addr0)));
			il.AddInstruction(ILSETREG_O(operand2, il.Load(load_size, il.Register(load_size, LLIL_TEMP(0)))));
		}
	}
	else
	{
		il.AddInstruction(il.Store(load_size, addr0, ILREG_O(operand1)));
		il.AddInstruction(il.Store(load_size, addr1, ILREG_O(operand2)));
	}

	/* do post-indexing */
	tmp = GetILOperandPostIndex(il, operand3);
	if (tmp)
		il.AddInstruction(tmp);
}


static void LoadStoreOperandPair(LowLevelILFunction& il, bool load, InstructionOperand& operand1,
    InstructionOperand& operand2, InstructionOperand& operand3)
{
	unsigned sz = REGSZ_O(operand1);
	LoadStoreOperandPairSize(il, load, sz, operand1, operand2, operand3);
}


static void LoadStoreVector(
    LowLevelILFunction& il, bool is_load, InstructionOperand& oper0, InstructionOperand& oper1)
{
	/* do pre-indexing */
	ExprId tmp = GetILOperandPreIndex(il, oper1);
	if (tmp)
		il.AddInstruction(tmp);

	Register regs[16];
	int regs_n = unpack_vector(oper0, regs);

	/* if we pre-indexed, base sequential effective addresses off the base register */
	OperandClass oclass = (oper1.operandClass == MEM_PRE_IDX) ? MEM_REG : oper1.operandClass;

	int offset = 0;
	for (int i = 0; i < regs_n; ++i)
	{
		int rsize = get_register_size(regs[i]);
		ExprId eaddr = GetILOperandEffectiveAddress(il, oper1, 8, oclass, offset);

		if (is_load)
			il.AddInstruction(il.SetRegister(rsize, regs[i], il.Load(rsize, eaddr)));
		else
			il.AddInstruction(il.Store(rsize, eaddr, il.Register(rsize, regs[i])));

		offset += rsize;
	}

	/* do post-indexing */
	tmp = GetILOperandPostIndex(il, oper1);
	if (tmp)
		il.AddInstruction(tmp);
}

static void LoadStoreOperand(LowLevelILFunction& il, bool load,
    InstructionOperand& operand1, /* register that gets read/written */
    InstructionOperand& operand2, /* location the read/write occurs */
    int load_store_sz)
{
	if (!load_store_sz)
		load_store_sz = REGSZ_O(operand1);

	ExprId tmp;
	if (load)
	{
		switch (operand2.operandClass)
		{
		case MEM_REG:
			// operand1.reg = [operand2.reg]
			il.AddInstruction(
			    ILSETREG_O(operand1, il.Operand(1, il.Load(load_store_sz, ILREG_O(operand2)))));
			break;
		case MEM_OFFSET:
			if (!load_store_sz)
				load_store_sz = REGSZ_O(operand1);

			// operand1.reg = [operand2.reg + operand2.imm]
			if (IMM_O(operand2) == 0)
				tmp = ILREG_O(operand2);
			else
				tmp = ILADDREG_O(operand2, il.Const(REGSZ_O(operand2), IMM_O(operand2)));

			il.AddInstruction(ILSETREG_O(operand1, il.Operand(1, il.Load(load_store_sz, tmp))));
			break;
		case MEM_PRE_IDX:
			// operand2.reg += operand2.imm
			if (IMM_O(operand2) != 0)
				il.AddInstruction(ILSETREG_O(operand2, il.Add(REGSZ_O(operand2), ILREG_O(operand2),
				                                           il.Const(REGSZ_O(operand2), IMM_O(operand2)))));
			// operand1.reg = [operand2.reg]
			il.AddInstruction(
			    ILSETREG_O(operand1, il.Operand(1, il.Load(load_store_sz, ILREG_O(operand2)))));
			break;
		case MEM_POST_IDX:
			// operand1.reg = [operand2.reg]
			il.AddInstruction(
			    ILSETREG_O(operand1, il.Operand(1, il.Load(load_store_sz, ILREG_O(operand2)))));
			// operand2.reg += operand2.imm
			if (IMM_O(operand2) != 0)
				il.AddInstruction(ILSETREG_O(operand2, il.Add(REGSZ_O(operand2), ILREG_O(operand2),
				                                           il.Const(REGSZ_O(operand2), IMM_O(operand2)))));
			break;
		case MEM_EXTENDED:
			il.AddInstruction(ILSETREG_O(operand1,
			    il.Operand(1, il.Load(load_store_sz,
			                      il.Add(REGSZ_O(operand2), ILREG_O(operand2),
			                          GetShiftedRegister(il, operand2, 1, REGSZ_O(operand2)))))));
			break;
		case LABEL:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.Operand(1, il.Load(load_store_sz, il.ConstPointer(8, IMM_O(operand2))))));
			break;
		case IMM32:
		case IMM64:
			il.AddInstruction(ILSETREG_O(operand1, il.Const(REGSZ_O(operand1), IMM_O(operand2))));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
	}
	else  // store
	{
		switch (operand2.operandClass)
		{
		case MEM_REG:
			il.AddInstruction(
			    il.Operand(1, il.Store(load_store_sz, ILREG_O(operand2), ILREG_O(operand1))));
			break;
		case MEM_OFFSET:
			//[operand2.reg + operand2.immediate] = operand1.reg
			if (IMM_O(operand2) == 0)
				tmp = ILREG_O(operand2);
			else
				tmp = ILADDREG_O(operand2, il.Const(REGSZ_O(operand2), IMM_O(operand2)));

			il.AddInstruction(il.Operand(1, il.Store(load_store_sz, tmp, ILREG_O(operand1))));
			break;
		case MEM_PRE_IDX:
			// operand2.reg = operand2.reg + operand2.immediate
			if (IMM_O(operand2) != 0)
				il.AddInstruction(ILSETREG_O(
				    operand2, ILADDREG_O(operand2, il.Const(REGSZ_O(operand2), IMM_O(operand2)))));
			//[operand2.reg] = operand1.reg
			il.AddInstruction(
			    il.Operand(1, il.Store(load_store_sz, ILREG_O(operand2), ILREG_O(operand1))));
			break;
		case MEM_POST_IDX:
			//[operand2.reg] = operand1.reg
			il.AddInstruction(
			    il.Operand(1, il.Store(load_store_sz, ILREG_O(operand2), ILREG_O(operand1))));
			// operand2.reg = operand2.reg + operand2.immediate
			if (IMM_O(operand2) != 0)
				il.AddInstruction(ILSETREG_O(
				    operand2, ILADDREG_O(operand2, il.Const(REGSZ_O(operand2), IMM_O(operand2)))));
			break;
		case MEM_EXTENDED:
			il.AddInstruction(il.Operand(
			    1, il.Store(load_store_sz,
			           il.Add(REGSZ_O(operand2), il.Register(REGSZ_O(operand2), operand2.reg[0]),
			               GetShiftedRegister(il, operand2, 1, REGSZ_O(operand2))),
			           ILREG_O(operand1))));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
	}
}

static void LoadStoreOperandSize(LowLevelILFunction& il, bool load, bool sign_extend, size_t size,
    InstructionOperand& operand1, InstructionOperand& operand2)
{
	ExprId tmp;
	if (load)
	{
		// LLIL_TEMP registers will be reported to have size 0, so override with size
		size_t extendSize = REGSZ_O(operand1) ? REGSZ_O(operand1) : size;
		switch (operand2.operandClass)
		{
		case MEM_REG:
			// operand1.reg = [operand2.reg]
			tmp = il.Operand(1, il.Load(size, ILREG_O(operand2)));

			if (sign_extend)
				tmp = il.SignExtend(extendSize, tmp);
			else
				tmp = il.ZeroExtend(extendSize, tmp);

			il.AddInstruction(ILSETREG_O(operand1, tmp));
			break;
		case MEM_OFFSET:
			// operand1.reg = [operand2.reg + operand2.imm]
			if (IMM_O(operand2) == 0)
				tmp = ILREG_O(operand2);
			else
				tmp = ILADDREG_O(operand2, il.Const(REGSZ_O(operand2), IMM_O(operand2)));

			tmp = il.Operand(1, il.Load(size, tmp));

			if (sign_extend)
				tmp = il.SignExtend(extendSize, tmp);
			else
				tmp = il.ZeroExtend(extendSize, tmp);

			il.AddInstruction(ILSETREG_O(operand1, tmp));
			break;
		case MEM_PRE_IDX:
			// operand2.reg += operand2.imm
			if (IMM_O(operand2) != 0)
				il.AddInstruction(ILSETREG_O(operand2, il.Add(REGSZ_O(operand2), ILREG_O(operand2),
				                                           il.Const(REGSZ_O(operand2), IMM_O(operand2)))));
			// operand1.reg = [operand2.reg]
			tmp = il.Operand(1, il.Load(size, ILREG_O(operand2)));

			if (sign_extend)
				tmp = il.SignExtend(extendSize, tmp);
			else
				tmp = il.ZeroExtend(extendSize, tmp);

			il.AddInstruction(ILSETREG_O(operand1, tmp));
			break;
		case MEM_POST_IDX:
			// operand1.reg = [operand2.reg]
			tmp = il.Operand(1, il.Load(size, ILREG_O(operand2)));

			if (sign_extend)
				tmp = il.SignExtend(extendSize, tmp);
			else
				tmp = il.ZeroExtend(extendSize, tmp);

			il.AddInstruction(ILSETREG_O(operand1, tmp));
			// operand2.reg += operand2.imm
			if (IMM_O(operand2) != 0)
				il.AddInstruction(ILSETREG_O(operand2, il.Add(REGSZ_O(operand2), ILREG_O(operand2),
				                                           il.Const(REGSZ_O(operand2), IMM_O(operand2)))));
			break;
		case MEM_EXTENDED:
			tmp =
			    il.Operand(1, il.Load(size, il.Add(REGSZ_O(operand2), ILREG_O(operand2),
			                                    GetShiftedRegister(il, operand2, 1, REGSZ_O(operand2)))));

			if (sign_extend)
				tmp = il.SignExtend(extendSize, tmp);
			else
				tmp = il.ZeroExtend(extendSize, tmp);

			il.AddInstruction(ILSETREG_O(operand1, tmp));
			break;
		case LABEL:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.Operand(1, il.Load(size, il.ConstPointer(8, IMM_O(operand2))))));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
	}
	else  // store
	{
		ExprId valToStore = il.Operand(0, ILREG_O(operand1));

		if (size < REGSZ_O(operand1))
			valToStore = il.LowPart(size, valToStore);

		switch (operand2.operandClass)
		{
		case MEM_REG:
			il.AddInstruction(il.Operand(1, il.Store(size, ILREG_O(operand2), valToStore)));
			break;
		case MEM_OFFSET:
			//[operand2.reg + operand2.immediate] = operand1.reg
			if (IMM_O(operand2) == 0)
				tmp = il.Store(size, ILREG_O(operand2), valToStore);
			else
				tmp = il.Store(
				    size, ILADDREG_O(operand2, il.Const(REGSZ_O(operand2), IMM_O(operand2))), valToStore);
			il.AddInstruction(il.Operand(1, tmp));
			break;
		case MEM_PRE_IDX:
			// operand2.reg = operand2.reg + operand2.immediate
			if (IMM_O(operand2) != 0)
				il.AddInstruction(ILSETREG_O(
				    operand2, ILADDREG_O(operand2, il.Const(REGSZ_O(operand2), IMM_O(operand2)))));
			//[operand2.reg] = operand1.reg
			il.AddInstruction(il.Operand(1, il.Store(size, ILREG_O(operand2), valToStore)));
			break;
		case MEM_POST_IDX:
			//[operand2.reg] = operand1.reg
			il.AddInstruction(il.Operand(1, il.Store(size, ILREG_O(operand2), valToStore)));
			// operand2.reg = operand2.reg + operand2.immediate
			if (IMM_O(operand2) != 0)
				il.AddInstruction(ILSETREG_O(
				    operand2, ILADDREG_O(operand2, il.Const(REGSZ_O(operand2), IMM_O(operand2)))));
			break;
		case MEM_EXTENDED:
			il.AddInstruction(il.Operand(
			    1, il.Store(size,
			           il.Add(REGSZ_O(operand2), il.Register(REGSZ_O(operand2), operand2.reg[0]),
			               GetShiftedRegister(il, operand2, 1, REGSZ_O(operand2))),
			           valToStore)));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
	}
}


static size_t DirectJump(
    Architecture* arch, LowLevelILFunction& il, uint64_t target, size_t addrSize)
{
	BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);
	if (label)
		return il.Goto(*label);
	else
		return il.Jump(il.ConstPointer(addrSize, target));

	return 0;
}


static ExprId ExtractBits(
    LowLevelILFunction& il, InstructionOperand& reg, size_t nbits, size_t rightMostBit)
{
// Get N set bits at offset O
#define BITMASK(N, O) (((1LL << nbits) - 1) << O)
	return il.And(REGSZ_O(reg), ILREG_O(reg), il.Const(REGSZ_O(reg), BITMASK(nbits, rightMostBit)));
}

static ExprId ExtractBit(LowLevelILFunction& il, InstructionOperand& reg, size_t bit)
{
	return il.And(REGSZ_O(reg), ILREG_O(reg), il.Const(REGSZ_O(reg), (1 << bit)));
}

static void ConditionalJump(Architecture* arch, LowLevelILFunction& il, size_t cond,
    size_t addrSize, uint64_t t, uint64_t f)
{
	BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
	BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);

	if (trueLabel && falseLabel)
	{
		il.AddInstruction(il.If(cond, *trueLabel, *falseLabel));
		return;
	}

	LowLevelILLabel trueCode, falseCode;

	if (trueLabel)
	{
		il.AddInstruction(il.If(cond, *trueLabel, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
		return;
	}

	if (falseLabel)
	{
		il.AddInstruction(il.If(cond, trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
		return;
	}

	il.AddInstruction(il.If(cond, trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
	il.MarkLabel(falseCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
}


static void ApplyAttributeToLastInstruction(LowLevelILFunction& il, uint32_t attributes)
{
	size_t instrId = il.GetInstructionCount()-1;
	ExprId expr = il.GetIndexForInstruction(instrId);
	il.SetExprAttributes(expr, attributes);
}


enum Arm64Intrinsic operation_to_intrinsic(int operation)
{
	switch (operation)
	{
	case ARM64_AUTDA:
	case ARM64_AUTDZA:
		return ARM64_INTRIN_AUTDA;
	case ARM64_AUTDB:
	case ARM64_AUTDZB:
		return ARM64_INTRIN_AUTDB;
	case ARM64_AUTIA:
	case ARM64_AUTIA1716:
	case ARM64_AUTIASP:
	case ARM64_AUTIAZ:
	case ARM64_AUTIZA:
		return ARM64_INTRIN_AUTIA;
	case ARM64_AUTIB:
	case ARM64_AUTIB1716:
	case ARM64_AUTIBSP:
	case ARM64_AUTIBZ:
	case ARM64_AUTIZB:
		return ARM64_INTRIN_AUTIB;
	case ARM64_PACDA:
	case ARM64_PACDZA:
		return ARM64_INTRIN_PACDA;
	case ARM64_PACDB:
	case ARM64_PACDZB:
		return ARM64_INTRIN_PACDB;
	case ARM64_PACGA:
		return ARM64_INTRIN_PACGA;
	case ARM64_PACIA:
	case ARM64_PACIA1716:
	case ARM64_PACIASP:
	case ARM64_PACIAZ:
	case ARM64_PACIZA:
		return ARM64_INTRIN_PACIA;
	case ARM64_PACIB:
	case ARM64_PACIB1716:
	case ARM64_PACIBSP:
	case ARM64_PACIBZ:
	case ARM64_PACIZB:
		return ARM64_INTRIN_PACIB;
	case ARM64_XPACD:
		return ARM64_INTRIN_XPACD;
	case ARM64_XPACI:
	case ARM64_XPACLRI:
		return ARM64_INTRIN_XPACI;
	default:
		return ARM64_INTRIN_INVALID;
	}
}


bool GetLowLevelILForInstruction(
    Architecture* arch, uint64_t addr, LowLevelILFunction& il, Instruction& instr, size_t addrSize, bool requireAlignment, std::function<bool()> _preferIntrinsics)
{
	bool SetPacAttr = false;

	InstructionOperand& operand1 = instr.operands[0];
	InstructionOperand& operand2 = instr.operands[1];
	InstructionOperand& operand3 = instr.operands[2];
	InstructionOperand& operand4 = instr.operands[3];
	InstructionOperand& operand5 = instr.operands[4];

	const size_t pairedSize = REGSZ_O(operand1) * 2;


	if (requireAlignment && (addr % 4 != 0)) {
		return false;
	}

	int n_instrs_before = il.GetInstructionCount();

	auto preferIntrinsics = [&]() -> bool {
		if (_preferIntrinsics())
		{
			NeonGetLowLevelILForInstruction(arch, addr, il, instr, addrSize);
			return (il.GetInstructionCount() > n_instrs_before);
		}
		return false;
	};

	// printf("%s() operation:%d encoding:%d\n", __func__, instr.operation, instr.encoding);

	LowLevelILLabel trueLabel, falseLabel;
	switch (instr.operation)
	{
	case ARM64_ADD:
	case ARM64_ADDS:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.Add(REGSZ_O(operand1), ILREG_O(operand2),
		                             ReadILOperand(il, operand3, REGSZ_O(operand1)), SETFLAGS)));
		break;
	case ARM64_ADC:
	case ARM64_ADCS:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.AddCarry(REGSZ_O(operand1), ILREG_O(operand2),
		        ReadILOperand(il, operand3, REGSZ_O(operand1)), il.Flag(IL_FLAG_C), SETFLAGS)));
		break;
	case ARM64_AND:
	case ARM64_ANDS:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.And(REGSZ_O(operand1), ILREG_O(operand2),
		                             ReadILOperand(il, operand3, REGSZ_O(operand1)), SETFLAGS)));
		break;
	case ARM64_ADR:
	case ARM64_ADRP:
		il.AddInstruction(ILSETREG_O(operand1, il.ConstPointer(REGSZ_O(operand1), IMM_O(operand2))));
		break;
	case ARM64_ASR:
		il.AddInstruction(ILSETREG_O(operand1, il.ArithShiftRight(REGSZ_O(operand2), ILREG_O(operand2),
		                                           ReadILOperand(il, operand3, REGSZ_O(operand2)))));
		break;
	case ARM64_AESD:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_AESD,
		    {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case ARM64_AESE:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_AESE,
		    {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case ARM64_BTI:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_BTI, {}));
		break;
	case ARM64_B:
		il.AddInstruction(DirectJump(arch, il, IMM_O(operand1), addrSize));
		break;
	case ARM64_B_NE:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_NE), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_EQ:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_EQ), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_CS:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_CS), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_CC:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_CC), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_MI:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_MI), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_PL:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_PL), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_VS:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_VS), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_VC:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_VC), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_HI:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_HI), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_LS:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_LS), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_GE:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_GE), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_LT:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_LT), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_GT:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_GT), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_B_LE:
		ConditionalJump(arch, il, il.FlagGroup(IL_FLAG_GROUP_LE), addrSize, IMM_O(operand1), addr + 4);
		return false;
	case ARM64_BL:
		il.AddInstruction(il.Call(il.ConstPointer(addrSize, IMM_O(operand1))));
		break;
	case ARM64_BLRAA:
	case ARM64_BLRAAZ:
	case ARM64_BLRAB:
	case ARM64_BLRABZ:
		SetPacAttr = true;
	case ARM64_BLR:
		il.AddInstruction(il.Call(ILREG_O(operand1)));
		if (SetPacAttr)
			ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
		break;
	case ARM64_BFC:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.And(REGSZ_O(operand1),
		                  il.Const(REGSZ_O(operand1), ~(ONES(IMM_O(operand3)) << IMM_O(operand2))),
		                  ILREG_O(operand1))));
		break;
	case ARM64_BFI:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Or(REGSZ_O(operand1),
		        il.And(REGSZ_O(operand1),
		            il.Const(REGSZ_O(operand1), ~(ONES(IMM_O(operand4)) << IMM_O(operand3))),
		            ILREG_O(operand1)),
		        il.ShiftLeft(REGSZ_O(operand1),
		            il.And(REGSZ_O(operand1), il.Const(REGSZ_O(operand1), ONES(IMM_O(operand4))),
		                ILREG_O(operand2)),
		            il.Const(1, IMM_O(operand3))))));
		break;
	case ARM64_BFXIL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Or(REGSZ_O(operand1),
		        il.And(REGSZ_O(operand1), ILREG_O(operand1),
		            il.Const(REGSZ_O(operand1), ~ONES(IMM_O(operand4)))),
		        il.LogicalShiftRight(REGSZ_O(operand1),
		            il.And(REGSZ_O(operand1), ILREG_O(operand2),
		                il.Const(REGSZ_O(operand1), ONES(IMM_O(operand4)) << IMM_O(operand3))),
		            il.Const(1, IMM_O(operand3))))));
		break;
	case ARM64_BRAA:
	case ARM64_BRAAZ:
	case ARM64_BRAB:
	case ARM64_BRABZ:
		SetPacAttr = true;
	case ARM64_BR:
		il.AddInstruction(il.Jump(ILREG_O(operand1)));
		if (SetPacAttr)
			ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
		return false;
	case ARM64_BIC:
	case ARM64_BICS:
		switch (instr.encoding) {
		case ENC_BIC_ASIMDIMM_L_HL:
		case ENC_BIC_ASIMDIMM_L_SL:
			il.AddInstruction(ILSETREG_O(operand1,
				il.And(REGSZ_O(operand1), ILREG_O(operand1),
					il.Not(REGSZ_O(operand2), ReadILOperand(il, operand2, REGSZ_O(operand2))), SETFLAGS)));
			break;
		default:
			il.AddInstruction(ILSETREG_O(operand1,
				il.And(REGSZ_O(operand2), ILREG_O(operand2),
					il.Not(REGSZ_O(operand2), ReadILOperand(il, operand3, REGSZ_O(operand2))), SETFLAGS)));
		}
		break;
	// TODO: some representation of the Acquire/Release semantics of the CAS* instructions... attribute?
	case ARM64_CASP:  // these compare-and-swaps can be pairs of 32 bit words or 64 bit doublewords
	case ARM64_CASPA:
	case ARM64_CASPAL:
	case ARM64_CASPL:
	{
		// the ordering of the register pairing depends on the byte order (endianness) of memory
		bool bigEndian = arch->GetEndianness() == BigEndian;
		auto hi1 = bigEndian ? operand1 : operand2;
		auto lo1 = bigEndian ? operand2 : operand1;
		auto hi2 = bigEndian ? operand3 : operand4;
		auto lo2 = bigEndian ? operand4 : operand3;
		il.AddInstruction(il.SetRegister(pairedSize, LLIL_TEMP(0), il.Load(pairedSize, ILREG_O(operand5))));

		GenIfElse(il,
			il.CompareEqual(pairedSize,
				il.RegisterSplit(REGSZ_O(operand1),
					hi1.reg[0], lo1.reg[0]),
				il.Register(pairedSize, LLIL_TEMP(0))),
			il.Store(pairedSize,
				ILREG_O(operand5),
				il.RegisterSplit(REGSZ_O(operand1), hi2.reg[0], lo2.reg[0])),
			0);

		il.AddInstruction(
			il.SetRegisterSplit(pairedSize,
				hi1.reg[0],
				lo1.reg[0],
				il.Register(pairedSize, LLIL_TEMP(0))));
		break;
	}
	case ARM64_CAS:  // these compare-and-swaps can be 32 or 64 bit
	case ARM64_CASA:
	case ARM64_CASAL:
	case ARM64_CASL:
		il.AddInstruction(il.SetRegister(REGSZ_O(operand1), LLIL_TEMP(0), il.Load(REGSZ_O(operand1), ILREG_O(operand3))));

		GenIfElse(il,
			il.CompareEqual(REGSZ_O(operand1), ILREG_O(operand1), il.Register(REGSZ_O(operand1), LLIL_TEMP(0))),
			il.Store(REGSZ_O(operand1), ILREG_O(operand3), ILREG_O(operand2)),
			0);

		il.AddInstruction(ILSETREG_O(operand1, il.Register(REGSZ_O(operand1), LLIL_TEMP(0))));
		break;
	case ARM64_CASAH:  // these compare-and-swaps are 16 bit
	case ARM64_CASALH:
	case ARM64_CASH:
	case ARM64_CASLH:
		il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0), il.Load(2, ILREG_O(operand3))));

		GenIfElse(il,
			il.CompareEqual(REGSZ_O(operand1), ExtractRegister(il, operand1, 0, 2, false, 2), il.Register(2, LLIL_TEMP(0))),
			il.Store(2, ILREG_O(operand3), ExtractRegister(il, operand2, 0, 2, false, 2)),
			0);

		il.AddInstruction(ILSETREG_O(operand1, il.Register(2, LLIL_TEMP(0))));
		break;
	case ARM64_CASAB:  // these compare-and-swaps are 8 bit
	case ARM64_CASALB:
	case ARM64_CASB:
	case ARM64_CASLB:
		il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Load(1, ILREG_O(operand3))));

		GenIfElse(il,
			il.CompareEqual(REGSZ_O(operand1), ExtractRegister(il, operand1, 0, 1, false, 1), il.Register(1, LLIL_TEMP(0))),
			il.Store(1, ILREG_O(operand3), ExtractRegister(il, operand2, 0, 1, false, 1)),
			0);

		il.AddInstruction(ILSETREG_O(operand1, il.Register(1, LLIL_TEMP(0))));
		break;
	case ARM64_CBNZ:
		ConditionalJump(arch, il,
		    il.CompareNotEqual(REGSZ_O(operand1), ILREG_O(operand1), il.Const(REGSZ_O(operand1), 0)),
		    addrSize, IMM_O(operand2), addr + 4);
		return false;
	case ARM64_CBZ:
		ConditionalJump(arch, il,
		    il.CompareEqual(REGSZ_O(operand1), ILREG_O(operand1), il.Const(REGSZ_O(operand1), 0)),
		    addrSize, IMM_O(operand2), addr + 4);
		return false;
	case ARM64_CMN:
		il.AddInstruction(il.Add(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1)), SETFLAGS));
		break;
	case ARM64_CCMN:
	{
		LowLevelILLabel trueCode, falseCode, done;

		il.AddInstruction(il.If(GetCondition(il, operand4.cond), trueCode, falseCode));

		il.MarkLabel(trueCode);
		il.AddInstruction(il.Add(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1)), SETFLAGS));
		il.AddInstruction(il.Goto(done));

		il.MarkLabel(falseCode);
		il.AddInstruction(il.SetFlag(IL_FLAG_N, il.Const(0, (IMM_O(operand3) >> 3) & 1)));
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.Const(0, (IMM_O(operand3) >> 2) & 1)));
		il.AddInstruction(il.SetFlag(IL_FLAG_C, il.Const(0, (IMM_O(operand3) >> 1) & 1)));
		il.AddInstruction(il.SetFlag(IL_FLAG_V, il.Const(0, (IMM_O(operand3) >> 0) & 1)));

		il.AddInstruction(il.Goto(done));

		il.MarkLabel(done);
	}
	break;
	case ARM64_CMP:
		il.AddInstruction(il.Sub(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1)), SETFLAGS));
		break;
	case ARM64_CCMP:
	{
		LowLevelILLabel trueCode, falseCode, done;

		il.AddInstruction(il.If(GetCondition(il, operand4.cond), trueCode, falseCode));

		il.MarkLabel(trueCode);
		il.AddInstruction(il.Sub(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1)), SETFLAGS));
		il.AddInstruction(il.Goto(done));

		il.MarkLabel(falseCode);
		il.AddInstruction(il.SetFlag(IL_FLAG_N, il.Const(0, (IMM_O(operand3) >> 3) & 1)));
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.Const(0, (IMM_O(operand3) >> 2) & 1)));
		il.AddInstruction(il.SetFlag(IL_FLAG_C, il.Const(0, (IMM_O(operand3) >> 1) & 1)));
		il.AddInstruction(il.SetFlag(IL_FLAG_V, il.Const(0, (IMM_O(operand3) >> 0) & 1)));

		il.AddInstruction(il.Goto(done));

		il.MarkLabel(done);
	}
	break;
	case ARM64_CLREX:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_CLREX, {}));
		break;
	case ARM64_CSEL:
	case ARM64_FCSEL:
		GenIfElse(il, GetCondition(il, operand4.cond), ILSETREG_O(operand1, ILREG_O(operand2)),
		    ILSETREG_O(operand1, ILREG_O(operand3)));
		break;
	case ARM64_CSINC:
		GenIfElse(il, GetCondition(il, operand4.cond), ILSETREG_O(operand1, ILREG_O(operand2)),
		    ILSETREG_O(operand1, ILADDREG_O(operand3, il.Const(REGSZ_O(operand1), 1))));
		break;
	case ARM64_CSINV:
		GenIfElse(il, GetCondition(il, operand4.cond), ILSETREG_O(operand1, ILREG_O(operand2)),
		    ILSETREG_O(operand1, il.Not(REGSZ_O(operand1), ILREG_O(operand3))));
		break;
	case ARM64_CSNEG:
		GenIfElse(il, GetCondition(il, operand4.cond), ILSETREG_O(operand1, ILREG_O(operand2)),
		    ILSETREG_O(operand1, il.Neg(REGSZ_O(operand1), ILREG_O(operand3))));
		break;
	case ARM64_CSET:
		il.AddInstruction(
			ILSETREG_O(operand1,
				il.BoolToInt(REGSZ_O(operand1), GetCondition(il, operand2.cond))));
		break;
	case ARM64_CSETM:
		GenIfElse(il, GetCondition(il, operand2.cond),
		    ILSETREG_O(operand1, il.Const(REGSZ_O(operand1), -1)),
		    ILSETREG_O(operand1, il.Const(REGSZ_O(operand1), 0)));
		break;
	case ARM64_CINC:
		GenIfElse(il, GetCondition(il, operand3.cond),
		    ILSETREG_O(operand1, ILADDREG_O(operand2, il.Const(REGSZ_O(operand1), 1))),
		    ILSETREG_O(operand1, ILREG_O(operand2)));
		break;
	case ARM64_CINV:
		GenIfElse(il, GetCondition(il, operand3.cond),
		    ILSETREG_O(operand1, il.Not(REGSZ_O(operand1), ILREG_O(operand2))),
		    ILSETREG_O(operand1, ILREG_O(operand2)));
		break;
	case ARM64_CNEG:
		GenIfElse(il, GetCondition(il, operand3.cond),
		    ILSETREG_O(operand1, il.Neg(REGSZ_O(operand1), ILREG_O(operand2))),
		    ILSETREG_O(operand1, ILREG_O(operand2)));
		break;
	case ARM64_CLZ:
		il.AddInstruction(il.Intrinsic(
		    {RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_CLZ, {ILREG_O(operand2)}));
		break;
	case ARM64_DC:
		il.AddInstruction(
		    il.Intrinsic({}, ARM64_INTRIN_DC, {ILREG_O(operand2)})); /* operand1 is <dc_op> */
		break;
	case ARM64_DMB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_DMB, {}));
		break;
	case ARM64_DSB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_DSB, {}));
		break;
	case ARM64_EON:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Xor(REGSZ_O(operand1), ILREG_O(operand2),
		                  il.Not(REGSZ_O(operand1), ReadILOperand(il, operand3, REGSZ_O(operand1))))));
		break;
	case ARM64_EOR:
		il.AddInstruction(ILSETREG_O(operand1, il.Xor(REGSZ_O(operand1), ILREG_O(operand2),
		                                           ReadILOperand(il, operand3, REGSZ_O(operand1)))));
		break;
	case ARM64_ESB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_ESB, {}));
		break;
	case ARM64_EXTR:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.LogicalShiftRight(pairedSize,
		                             il.Or(pairedSize,
		                                 il.ShiftLeft(pairedSize, ILREG_O(operand2),
		                                     il.Const(1, REGSZ_O(operand1) * 8)),
		                                 ILREG_O(operand3)),
		                             il.Const(1, IMM_O(operand4)))));
		break;
	case ARM64_FABD:
		switch (instr.encoding)
		{
		case ENC_FABD_ASISDSAMEFP16_ONLY:
		case ENC_FABD_ASISDSAME_ONLY:
			il.AddInstruction(ILSETREG_O(operand1,
				il.FloatAbs(REGSZ_O(operand1),
					il.FloatSub(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
			break;
		case ENC_FABD_ASIMDSAMEFP16_ONLY:
		case ENC_FABD_ASIMDSAME_ONLY:
			// covered by intrinsics
			break;
		case ENC_FABD_Z_P_ZZ_:
		default:
			ABORT_LIFT;
		}
		break;
	case ARM64_FABS:
		switch (instr.encoding)
		{
		case ENC_FABS_D_FLOATDP1:
		case ENC_FABS_S_FLOATDP1:
		case ENC_FABS_H_FLOATDP1:
			il.AddInstruction(ILSETREG_O(operand1, il.FloatAbs(REGSZ_O(operand1), ILREG_O(operand2))));
			break;
		case ENC_FABS_ASIMDMISC_R:
		case ENC_FABS_ASIMDMISCFP16_R:
			// covered by intrinsics
			break;
		default:
			ABORT_LIFT;
		}
		break;
	case ARM64_FADD:
		switch (instr.encoding)
		{
		case ENC_FADD_H_FLOATDP2:
		case ENC_FADD_S_FLOATDP2:
		case ENC_FADD_D_FLOATDP2:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.FloatAdd(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
			break;
		case ENC_FADD_ASIMDSAME_ONLY:
		case ENC_FADD_ASIMDSAMEFP16_ONLY:
		{
			if (preferIntrinsics())
				return true;
			Register srcs1[16], srcs2[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src1_n = unpack_vector(operand2, srcs1);
			int src2_n = unpack_vector(operand3, srcs2);
			if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
				ABORT_LIFT;

			int rsize = get_register_size(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(
					dsts[i], il.FloatAdd(rsize, ILREG(srcs1[i]), ILREG(srcs2[i]))));
		}
		break;
		default:
			ABORT_LIFT;
		}
		break;
	case ARM64_FADDP:
		switch (instr.encoding)
		{
		case ENC_FADDP_ASISDPAIR_ONLY_H:
		case ENC_FADDP_ASISDPAIR_ONLY_SD:
		{
			Register srcs[16];
			int src_n = unpack_vector(operand2, srcs);
			if (src_n != 2)
				ABORT_LIFT;
			il.AddInstruction(ILSETREG_O(operand1,
				il.FloatAdd(REGSZ_O(operand1), ILREG(srcs[0]), ILREG(srcs[1]))
			));
			break;
		}
		case ENC_FADDP_ASIMDSAME_ONLY:
		case ENC_FADDP_ASIMDSAMEFP16_ONLY:
		{
			if (preferIntrinsics())
				return true;

			Register srcs1[16], srcs2[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src1_n = unpack_vector(operand2, srcs1);
			int src2_n = unpack_vector(operand3, srcs2);
			if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
				ABORT_LIFT;

			int rsize = get_register_size(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
			{
				auto srcs = i < dst_n / 2 ? srcs1 : srcs2;
				auto index = i % (dst_n / 2);
				il.AddInstruction(il.SetRegister(REGSZ(dsts[i]),
					LLIL_TEMP(i), il.FloatAdd(rsize, ILREG(srcs[2 * index]), ILREG(srcs[2 * index + 1]))));
			}
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(dsts[i], il.Register(REGSZ(dsts[i]), LLIL_TEMP(i))));

			break;
		}
		case ENC_FADDP_Z_P_ZZ_:
			il.AddInstruction(il.Unimplemented());
		default:
			ABORT_LIFT;
		}
		break;
	case ARM64_FCCMP:
	case ARM64_FCCMPE:
	{
		LowLevelILLabel trueCode, falseCode, done;

		il.AddInstruction(il.If(GetCondition(il, operand4.cond), trueCode, falseCode));

		il.MarkLabel(trueCode);
		il.AddInstruction(il.FloatSub(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1)), SETFLAGS));
		il.AddInstruction(il.Goto(done));

		il.MarkLabel(falseCode);
		il.AddInstruction(il.SetFlag(IL_FLAG_N, il.Const(0, (IMM_O(operand3) >> 3) & 1)));
		il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.Const(0, (IMM_O(operand3) >> 2) & 1)));
		il.AddInstruction(il.SetFlag(IL_FLAG_C, il.Const(0, (IMM_O(operand3) >> 1) & 1)));
		il.AddInstruction(il.SetFlag(IL_FLAG_V, il.Const(0, (IMM_O(operand3) >> 0) & 1)));

		il.AddInstruction(il.Goto(done));

		il.MarkLabel(done);
	}
	break;
	case ARM64_FCMP:
	case ARM64_FCMPE:
		il.AddInstruction(il.FloatSub(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1)), SETFLAGS));
		break;
	case ARM64_FSQRT:
		switch (instr.encoding)
		{
		case ENC_FSQRT_D_FLOATDP1:
		case ENC_FSQRT_H_FLOATDP1:
		case ENC_FSQRT_S_FLOATDP1:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.FloatSqrt(REGSZ_O(operand1), ILREG_O(operand2))));
			break;
		case ENC_FSQRT_ASIMDMISCFP16_R:
		case ENC_FSQRT_ASIMDMISC_R:
			// Intrinsics
			break;
		default:
			ABORT_LIFT;
		}
		break;
	case ARM64_FSUB:
		switch (instr.encoding)
		{
		case ENC_FSUB_H_FLOATDP2:
		case ENC_FSUB_S_FLOATDP2:
		case ENC_FSUB_D_FLOATDP2:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.FloatSub(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
			break;
		case ENC_FSUB_ASIMDSAME_ONLY:
		case ENC_FSUB_ASIMDSAMEFP16_ONLY:
		{
			if (preferIntrinsics())
				return true;

			Register srcs[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src_n = unpack_vector(operand2, srcs);
			if ((dst_n != src_n) || dst_n == 0)
				ABORT_LIFT;

			int rsize = get_register_size(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(dsts[i], il.FloatSub(rsize, ILREG(dsts[i]), ILREG(srcs[i]))));
			break;
		}
		default:
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case ARM64_FCVT:
	{
		int float_sz = 0;
		switch (instr.encoding)
		{
		/* non-SVE is straight register-to-register */
		case ENC_FCVT_HS_FLOATDP1:  // convert to half (2-byte)
		case ENC_FCVT_HD_FLOATDP1:
			float_sz = 2;
		case ENC_FCVT_SH_FLOATDP1:  // convert to single (4-byte)
		case ENC_FCVT_SD_FLOATDP1:
			if (!float_sz)
				float_sz = 4;
		case ENC_FCVT_DH_FLOATDP1:  // convert to double (8-byte)
		case ENC_FCVT_DS_FLOATDP1:
			if (!float_sz)
				float_sz = 8;
			il.AddInstruction(ILSETREG_O(operand1, GetFloat(il, operand2, float_sz)));
			break;
		/* future: support SVE versions with predicated execution and z register file */
		default:
			ABORT_LIFT;
		}
		break;
	}
	case ARM64_FDIV:
		switch (instr.encoding)
		{
		case ENC_FDIV_H_FLOATDP2:
		case ENC_FDIV_S_FLOATDP2:
		case ENC_FDIV_D_FLOATDP2:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.FloatDiv(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
			break;
		case ENC_FDIV_ASIMDSAMEFP16_ONLY:
		case ENC_FDIV_ASIMDSAME_ONLY:
		{
			if (preferIntrinsics())
				return true;

			Register srcs1[16], srcs2[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src1_n = unpack_vector(operand2, srcs1);
			int src2_n = unpack_vector(operand3, srcs2);
			if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
				ABORT_LIFT;
			int rsize = get_register_size(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(
					dsts[i], il.FloatDiv(rsize, ILREG(srcs1[i]), ILREG(srcs2[i]))));
			break;
		}
		default:
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case ARM64_FMOV:

		switch (instr.encoding)
		{
		case ENC_FMOV_64VX_FLOAT2INT:
			il.AddInstruction(ILSETREG_O(operand1,
			    il.ZeroExtend(REGSZ_O(operand1), ILREG(vector_reg_minimize(instr.operands[1])))));
			break;
		case ENC_FMOV_V64I_FLOAT2INT:
		{
			Register minreg = vector_reg_minimize(instr.operands[0]);
			il.AddInstruction(il.SetRegister(get_register_size(minreg), minreg,
			    il.Register(REGSZ_O(operand1), instr.operands[1].reg[0])));
			break;
		}
		case ENC_FMOV_32H_FLOAT2INT:
		case ENC_FMOV_32S_FLOAT2INT:
		case ENC_FMOV_64H_FLOAT2INT:
		case ENC_FMOV_64D_FLOAT2INT:
			// <Rd> <- <Vn> (copy from FP register to general register, with no conversion)
			il.AddInstruction(
			    ILSETREG_O(operand1, il.ZeroExtend(REGSZ_O(operand1), ILREG_O(instr.operands[1]))));
			break;
		case ENC_FMOV_D64_FLOAT2INT:
		case ENC_FMOV_H32_FLOAT2INT:
		case ENC_FMOV_H64_FLOAT2INT:
		case ENC_FMOV_S32_FLOAT2INT:
			// <Vd> <- <Rn> (copy from general register to FP register, with no conversion)
			il.AddInstruction(
			    ILSETREG_O(operand1, il.IntToFloat(REGSZ_O(operand1), ILREG_O(instr.operands[1]))));
			break;
		case ENC_FMOV_H_FLOATIMM:
		case ENC_FMOV_S_FLOATIMM:
		case ENC_FMOV_D_FLOATIMM:
		{
			int float_sz = 2;
			if (instr.encoding == ENC_FMOV_S_FLOATIMM)
				float_sz = 4;
			if (instr.encoding == ENC_FMOV_D_FLOATIMM)
				float_sz = 8;
			// Technically, we should use 2 bytes to GetFloat for half-precision registers, but that causes MLIL and HLIL to lift the constant to 0
			il.AddInstruction(ILSETREG_O(operand1, il.FloatConvert(float_sz, GetFloat(il, operand2, float_sz == 2 ? 4 : float_sz))));
			break;
		}
		case ENC_FMOV_H_FLOATDP1:
		case ENC_FMOV_S_FLOATDP1:
		case ENC_FMOV_D_FLOATDP1:
			il.AddInstruction(ILSETREG_O(operand1, ILREG_O(operand2)));
			break;
		case ENC_FMOV_ASIMDIMM_D2_D:
		case ENC_FMOV_ASIMDIMM_H_H:
		case ENC_FMOV_ASIMDIMM_S_S:
		{
			if (preferIntrinsics())
				return true;

			int float_sz = 2;
			if (instr.encoding == ENC_FMOV_ASIMDIMM_S_S)
				float_sz = 4;
			if (instr.encoding == ENC_FMOV_ASIMDIMM_D2_D)
				float_sz = 8;

			Register regs[16];
			int dst_n = unpack_vector(operand1, regs);
			for (int i = 0; i < dst_n; ++i)
				// Technically, we should use 2 bytes to GetFloat for half-precision registers, but that causes MLIL and HLIL to lift the constant to 0
				il.AddInstruction(ILSETREG(regs[i], il.FloatConvert(float_sz, GetFloat(il, operand2, float_sz == 2 ? 4 : float_sz))));
			break;
		}
		default:
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case ARM64_FMUL:
		switch (instr.encoding)
		{
		case ENC_FMUL_H_FLOATDP2:
		case ENC_FMUL_S_FLOATDP2:
		case ENC_FMUL_D_FLOATDP2:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.FloatMult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
			break;
		case ENC_FMUL_ASIMDSAME_ONLY:
		case ENC_FMUL_ASIMDSAMEFP16_ONLY:
		{
			if (preferIntrinsics())
				return true;

			Register srcs1[16], srcs2[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src1_n = unpack_vector(operand2, srcs1);
			int src2_n = unpack_vector(operand3, srcs2);
			if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
				ABORT_LIFT;
			int rsize = get_register_size(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(
					dsts[i], il.FloatMult(rsize, ILREG(srcs1[i]), ILREG(srcs2[i]))));
			break;
		}
		case ENC_FMUL_ASIMDELEM_RH_H:
		case ENC_FMUL_ASIMDELEM_R_SD:
		case ENC_FMUL_ASISDELEM_RH_H:
		case ENC_FMUL_ASISDELEM_R_SD:
		{
			if (preferIntrinsics())
				return true;

			Register srcs1[16], srcs2[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src1_n = unpack_vector(operand2, srcs1);
			int src2_n = unpack_vector(operand3, srcs2);
			if ((dst_n != src1_n) || dst_n == 0 || src2_n != 1)
				ABORT_LIFT;
			int rsize = get_register_size(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(
					dsts[i], il.FloatMult(rsize, ILREG(srcs1[i]), ILREG(srcs2[0]))));
			break;
		}
		default:
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case ARM64_FNEG:
		switch (instr.encoding)
		{
		case ENC_FNEG_D_FLOATDP1:
		case ENC_FNEG_S_FLOATDP1:
		case ENC_FNEG_H_FLOATDP1:
			il.AddInstruction(ILSETREG_O(
				operand1, il.FloatNeg(REGSZ_O(operand1), ILREG_O(operand2))));
			break;
		case ENC_FNEG_ASIMDMISCFP16_R:
		case ENC_FNEG_ASIMDMISC_R:
		{
			if (preferIntrinsics())
				return true;

			Register srcs[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src_n = unpack_vector(operand2, srcs);
			if ((dst_n != src_n) || dst_n == 0)
				ABORT_LIFT;

			int rsize = get_register_size(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(dsts[i], il.FloatNeg(rsize, ILREG(srcs[i]))));
			break;
		}
		default:
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case ARM64_FNMUL:
		il.AddInstruction(ILSETREG_O(operand1,
			il.FloatNeg(REGSZ_O(operand1),
				il.FloatMult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case ARM64_ERET:
	case ARM64_ERETAA:
	case ARM64_ERETAB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_ERET, {}));
		il.AddInstruction(il.Trap(0));
		return false;
	case ARM64_ISB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_ISB, {}));
		break;
	case ARM64_LDAR:
	case ARM64_LDAPR:
	case ARM64_LDAPUR:
		LoadStoreOperand(il, true, instr.operands[0], instr.operands[1], 0);
		break;
	case ARM64_LDARB:
	case ARM64_LDAPRB:
	case ARM64_LDAPURB:
		LoadStoreOperandSize(il, true, false, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDARH:
	case ARM64_LDAPRH:
	case ARM64_LDAPURH:
		LoadStoreOperandSize(il, true, false, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDP:
	case ARM64_LDNP:
		LoadStoreOperandPair(il, true, instr.operands[0], instr.operands[1], instr.operands[2]);
		break;
	case ARM64_LDPSW:
		LoadStoreOperandPairSize(il, true, 4, instr.operands[0], instr.operands[1], instr.operands[2]);
		break;
	case ARM64_LDRAA:
	case ARM64_LDRAB:
		SetPacAttr = true;
	case ARM64_LDR:
	case ARM64_LDUR:
		LoadStoreOperand(il, true, instr.operands[0], instr.operands[1], 0);
		if (SetPacAttr)
			ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
		break;
	case ARM64_LDRB:
	case ARM64_LDURB:
		LoadStoreOperandSize(il, true, false, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRH:
	case ARM64_LDURH:
		LoadStoreOperandSize(il, true, false, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRSB:
	case ARM64_LDURSB:
	case ARM64_LDAPURSB:
		LoadStoreOperandSize(il, true, true, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRSH:
	case ARM64_LDURSH:
	case ARM64_LDAPURSH:
		LoadStoreOperandSize(il, true, true, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRSW:
	case ARM64_LDURSW:
	case ARM64_LDAPURSW:
		LoadStoreOperandSize(il, true, true, 4, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDXR:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDXR, { ILREG_O(operand2) }));
		break;
	case ARM64_LDXRB:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDXRB, { ILREG_O(operand2) }));
		break;
	case ARM64_LDXRH:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDXRH, { ILREG_O(operand2) }));
		break;
	// We don't have a way to specify intrinsic register size, so we explicitly embed the size in the intrinsic name.
	case ARM64_LDAXR:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDAXR, { ILREG_O(operand2) }));
		break;
	case ARM64_LDAXRB:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDAXRB, { ILREG_O(operand2) }));
		break;
	case ARM64_LDAXRH:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDAXRH, { ILREG_O(operand2) }));
		break;
	case ARM64_STXR:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STXR, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case ARM64_STXRB:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STXRB, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case ARM64_STXRH:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STXRH, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case ARM64_STLXR:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STLXR, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case ARM64_STLXRB:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STLXRB, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case ARM64_STLXRH:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STLXRH, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case ARM64_LD1:
		LoadStoreVector(il, true, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDADD:
	case ARM64_LDADDA:
	case ARM64_LDADDL:
	case ARM64_LDADDAL:
	{
		// TODO: represent/annotate (model?) acquire/release memory ordering semantics for all LDADD* instructions

		// I want to do this, but I also don't want to add an #ifdef __clang__
		// InstructionOperand tmp = { .reg = { (Register) LLIL_TEMP(0) } };
		InstructionOperand tmp;
		tmp.reg[0] = (Register) LLIL_TEMP(0);
		LoadStoreOperandSize(il, true, false, REGSZ_O(operand2), tmp, operand3);
		il.AddInstruction(il.Store(REGSZ_O(operand2), ILREG_O(operand3),
		    il.Add(REGSZ_O(operand1),
				ILREG_O(operand1),
				il.ZeroExtend(REGSZ_O(operand2),
					il.Register(REGSZ_O(operand2), LLIL_TEMP(0))))));
		if (!(operand2.reg[0] == REG_XZR || operand2.reg[0] == REG_WZR))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.Register(REGSZ_O(operand2), LLIL_TEMP(0)))));
		break;
	}
	case ARM64_STADD:
	case ARM64_STADDL:
		// STADD* are aliases of the corresponding LDADD*, so group them together
		il.AddInstruction(il.Store(REGSZ_O(operand2), ILREG_O(operand2),
		    il.Add(REGSZ_O(operand1), ILREG_O(operand1), il.Load(REGSZ_O(operand1), ILREG_O(operand2)))));
		break;
	case ARM64_LDADDB:
	case ARM64_LDADDAB:
	case ARM64_LDADDLB:
	case ARM64_LDADDALB:
	{
		// InstructionOperand tmp = { .reg = { (Register) LLIL_TEMP(0) } };
		InstructionOperand tmp;
		tmp.reg[0] = (Register) LLIL_TEMP(0);
		LoadStoreOperandSize(il, true, false, 1, tmp, operand3);
		il.AddInstruction(il.Store(1, ILREG_O(operand3),
		    il.Add(1, il.LowPart(1, ILREG_O(operand1)), il.LowPart(1, il.Register(1, LLIL_TEMP(0))))));
		if (!(operand2.reg[0] == REG_XZR || operand2.reg[0] == REG_WZR))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.LowPart(1, il.Register(1, LLIL_TEMP(0))))));
		break;
	}
	case ARM64_STADDB:
	case ARM64_STADDLB:
		// STADD* are aliases of the corresponding LDADD*, so group them together
		il.AddInstruction(il.Store(1, ILREG_O(operand2),
		    il.Add(1, il.LowPart(1, ILREG_O(operand1)), il.Load(1, ILREG_O(operand2)))));
		break;
	case ARM64_LDADDH:
	case ARM64_LDADDAH:
	case ARM64_LDADDLH:
	case ARM64_LDADDALH:
	{
		// InstructionOperand tmp = { .reg = { (Register) LLIL_TEMP(0) } };
		InstructionOperand tmp;
		tmp.reg[0] = (Register) LLIL_TEMP(0);
		LoadStoreOperandSize(il, true, false, 2, tmp, operand3);
		il.AddInstruction(il.Store(2, ILREG_O(operand3),
		    il.Add(2, il.LowPart(2, ILREG_O(operand1)), il.LowPart(2, il.Register(2, LLIL_TEMP(0))))));
		if (!(operand2.reg[0] == REG_XZR || operand2.reg[0] == REG_WZR))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.LowPart(2, il.Register(2, LLIL_TEMP(0))))));
		break;
	}
	case ARM64_STADDH:
	case ARM64_STADDLH:
		// STADD* are aliases of the corresponding LDADD*, so group them together
		il.AddInstruction(il.Store(2, ILREG_O(operand2),
		    il.Add(2, il.LowPart(2, ILREG_O(operand1)), il.Load(2, ILREG_O(operand2)))));
		break;
	case ARM64_LSL:
		il.AddInstruction(ILSETREG_O(operand1, il.ShiftLeft(REGSZ_O(operand2), ILREG_O(operand2),
		                                           ReadILOperand(il, operand3, REGSZ_O(operand2)))));
		break;
	case ARM64_LSR:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.LogicalShiftRight(REGSZ_O(operand2), ILREG_O(operand2),
		                             ReadILOperand(il, operand3, REGSZ_O(operand2)))));
		break;
	case ARM64_DUP:
	case ARM64_MOV:
	case ARM64_MOVN:
	case ARM64_UMOV:
	case ARM64_INS:
	case ARM64_MOVS:
	{
		bool zero_extend = false;
		switch (instr.encoding)
		{
		case ENC_DUP_ASIMDINS_DR_R:
		{
			// if (preferIntrinsics())
			// 	return true;

			Register regs[16];
			int regs_n = unpack_vector(operand1, regs);
			if (regs_n <= 0)
				ABORT_LIFT;
			int lane_sz = REGSZ(regs[0]);
			for (int i = 0; i < regs_n; ++i)
				il.AddInstruction(ILSETREG(regs[i], ExtractRegister(il, operand2, 0, lane_sz, 0, lane_sz)));
			break;
		}
		case ENC_DUP_ASIMDINS_DV_V:
			// We let the Neon intrinsic lifter take care of this case.
			break;
		case ENC_MOV_UMOV_ASIMDINS_W_W:
		case ENC_MOV_UMOV_ASIMDINS_X_X:
		case ENC_UMOV_ASIMDINS_W_W:
		case ENC_UMOV_ASIMDINS_X_X:
			zero_extend = true;
		case ENC_MOV_DUP_ASISDONE_ONLY:
		case ENC_DUP_ASISDONE_ONLY:
		case ENC_MOV_INS_ASIMDINS_IV_V:
		case ENC_INS_ASIMDINS_IV_V:
		{
			Register srcs[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src_n = unpack_vector(operand2, srcs);
			if ((dst_n != src_n) || dst_n == 0)
				ABORT_LIFT;

			// if (dst_n > 1 && preferIntrinsics())
			// 	return true;

			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(dsts[i], zero_extend
					? il.ZeroExtend(REGSZ(dsts[i]), ILREG(srcs[i]))
						: ILREG(srcs[i])));

			break;
		}
		case ENC_MOV_MOVN_32_MOVEWIDE:
		case ENC_MOV_MOVN_64_MOVEWIDE:
		case ENC_MOVN_32_MOVEWIDE:
		case ENC_MOVN_64_MOVEWIDE:
			il.AddInstruction(ILSETREG_O(operand1,
				ReadILOperand(il, operand2, REGSZ_O(operand1))));
			break;
		case ENC_MOV_INS_ASIMDINS_IR_R:
		case ENC_INS_ASIMDINS_IR_R:
		case ENC_MOV_ORR_32_LOG_IMM:
		case ENC_MOV_ORR_32_LOG_SHIFT:
		case ENC_MOV_ORR_64_LOG_IMM:
		case ENC_MOV_ORR_64_LOG_SHIFT:
		case ENC_MOV_ADD_32_ADDSUB_IMM:
		case ENC_MOV_ADD_64_ADDSUB_IMM:
		case ENC_MOV_ORR_ASIMDSAME_ONLY:
		case ENC_MOV_MOVZ_32_MOVEWIDE:
		case ENC_MOV_MOVZ_64_MOVEWIDE:
		{
			Register regs[16];
			int n = unpack_vector(operand1, regs);

			if (n == 1) {
				il.AddInstruction(ILSETREG(regs[0], ReadILOperand(il, operand2, get_register_size(regs[0]))));
			} else {
				Register cregs[2];
				if (consolidate_vector(operand1, operand2, cregs))
					il.AddInstruction(ILSETREG(cregs[0], ILREG(cregs[1])));
				else
					ABORT_LIFT;
			}
			break;
		}
		default:
			// case ENC_MOVS_ORRS_P_P_PP_Z:
			// il.AddInstruction(il.Unimplemented());
			break;
		}
		break;
	}
	case ARM64_MOVI:
	{
		Register regs[16];
		int n = unpack_vector(operand1, regs);
		for (int i = 0; i < n; ++i)
			il.AddInstruction(ILSETREG(regs[i], ILCONST_O(get_register_size(regs[i]), operand2)));
		break;
	}
	case ARM64_MVN:
	case ARM64_MVNI:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Not(REGSZ_O(operand1), ReadILOperand(il, operand2, REGSZ_O(operand1)))));
		break;
	case ARM64_MOVK:
		// zero the underling register slice
		il.AddInstruction(ILSETREG_O(
		    operand1, il.And(REGSZ_O(operand1), ILREG_O(operand1),
			    il.Const(REGSZ_O(operand1), ~(0xffffULL << operand2.shiftValue)))));
		// mov the immediate into it
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Or(REGSZ_O(operand1), ILREG_O(operand1),
		                  il.Const(REGSZ_O(operand1), IMM_O(operand2) << operand2.shiftValue))));
		break;
	case ARM64_MOVZ:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.Const(REGSZ_O(operand1), IMM_O(operand2) << operand2.shiftValue)));
		break;
	case ARM64_MUL:
		switch (instr.encoding)
		{
			case ENC_MUL_ASIMDSAME_ONLY:
			case ENC_MUL_ASIMDELEM_R:
				break;
			default:
				il.AddInstruction(
					ILSETREG_O(operand1, il.Mult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
		}
		break;
	case ARM64_MADD:
		il.AddInstruction(ILSETREG_O(operand1,
		    ILADDREG_O(operand4, il.Mult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case ARM64_MRS:
	{
		ExprId reg = ILREG_O(operand2);
		const char* name = get_system_register_name((SystemReg)operand2.sysreg);

		if (strlen(name) == 0)
		{
			LogWarn("Unknown system register %d @ 0x%" PRIx64
			        ": S%d_%d_c%d_c%d_%d, using generic system register instead\n",
			    operand2.sysreg, addr, operand2.implspec[0], operand2.implspec[1], operand2.implspec[2],
			    operand2.implspec[3], operand2.implspec[4]);
			reg = il.Register(8, FAKEREG_SYSREG_UNKNOWN);
		}

		il.AddInstruction(
		    il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_MRS, {reg}));
		break;
	}
	case ARM64_MSUB:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Sub(REGSZ_O(operand1), ILREG_O(operand4),
		                  il.Mult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case ARM64_MNEG:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Sub(REGSZ_O(operand1), il.Const(8, 0),
		                  il.Mult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case ARM64_MSR:
	{
		uint32_t dst = operand1.sysreg;
		const char* name = get_system_register_name((SystemReg)dst);

		if (strlen(name) == 0)
		{
			LogWarn("Unknown system register %d @ 0x%" PRIx64
			        ": S%d_%d_c%d_c%d_%d, using generic system register instead\n",
			    dst, addr, operand1.implspec[0], operand1.implspec[1], operand1.implspec[2],
			    operand1.implspec[3], operand1.implspec[4]);
			dst = FAKEREG_SYSREG_UNKNOWN;
		}

		switch (operand2.operandClass)
		{
		case IMM32:
			il.AddInstruction(il.Intrinsic(
			    {RegisterOrFlag::Register(dst)}, ARM64_INTRIN_MSR, {il.Const(4, IMM_O(operand2))}));
			break;
		case REG:
			il.AddInstruction(
			    il.Intrinsic({RegisterOrFlag::Register(dst)}, ARM64_INTRIN_MSR, {ILREG_O(operand2)}));
			break;
		default:
			LogError("unknown MSR operand class: %x\n", operand2.operandClass);
			break;
		}
		break;
	}
	case ARM64_NEG:
	case ARM64_NEGS:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Neg(REGSZ_O(operand1), ReadILOperand(il, instr.operands[1], REGSZ_O(operand1)),
		                  SETFLAGS)));
		break;
	case ARM64_NGC:
	case ARM64_NGCS:
		il.AddInstruction(ILSETREG_O(operand1, il.SubBorrow(REGSZ_O(operand1), il.Const(REGSZ_O(operand1), 0),
		                                           ReadILOperand(il, operand2, REGSZ_O(operand1)),
		                                           il.Not(0, il.Flag(IL_FLAG_C)), SETFLAGS)));
		break;
	case ARM64_NOP:
		il.AddInstruction(il.Nop());
		break;

#ifdef LIFT_PAC_AS_INTRINSIC
	case ARM64_AUTDA:
	case ARM64_AUTDB:
	case ARM64_AUTIA:
	case ARM64_AUTIB:
	case ARM64_PACDA:
	case ARM64_PACDB:
	case ARM64_PACIA:
	case ARM64_PACIB:
		// <Xd> is address, <Xn> is modifier
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))},
		    operation_to_intrinsic(instr.operation), {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case ARM64_PACGA:
		// <Xd> is address, <Xn>, <Xm> are modifiers, keys
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))},
		    operation_to_intrinsic(instr.operation), {ILREG_O(operand2), ILREG_O(operand3)}));
		break;
	case ARM64_AUTIA1716:
	case ARM64_AUTIB1716:
	case ARM64_PACIA1716:
	case ARM64_PACIB1716:
		// x17 is address, x16 is modifier
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X17)},
		    operation_to_intrinsic(instr.operation), {il.Register(8, REG_X17), il.Register(8, REG_X16)}));
		break;
	case ARM64_AUTDZA:
	case ARM64_AUTDZB:
	case ARM64_AUTIZA:
	case ARM64_AUTIZB:
	case ARM64_PACDZA:
	case ARM64_PACDZB:
	case ARM64_PACIZA:
	case ARM64_PACIZB:
		// <Xd> is address, modifier is 0
		il.AddInstruction(il.Intrinsic(
		    {RegisterOrFlag::Register(REG_O(operand1))}, operation_to_intrinsic(instr.operation), {ILREG_O(operand1), il.Const(8, 0)}));
		break;
	case ARM64_XPACI:
	case ARM64_XPACD:
		// <Xd> is address
		il.AddInstruction(il.Intrinsic(
		    {RegisterOrFlag::Register(REG_O(operand1))}, operation_to_intrinsic(instr.operation), {ILREG_O(operand1)}));
		break;
	case ARM64_AUTIAZ:
	case ARM64_AUTIBZ:
	case ARM64_PACIAZ:
	case ARM64_PACIBZ:
		// x30 is address, modifier is 0
		il.AddInstruction(il.Intrinsic(
		    {RegisterOrFlag::Register(REG_X30)}, operation_to_intrinsic(instr.operation), {il.Register(8, REG_X30), il.Const(8, 0)}));
		break;
	case ARM64_XPACLRI:
		// x30 is address
		il.AddInstruction(il.Intrinsic(
		    {RegisterOrFlag::Register(REG_X30)}, operation_to_intrinsic(instr.operation), {il.Register(8, REG_X30)}));
		break;
	case ARM64_AUTIASP:
	case ARM64_AUTIBSP:
	case ARM64_PACIASP:
	case ARM64_PACIBSP:
		// x30 is address, sp is modifier
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X30)},
		    operation_to_intrinsic(instr.operation), {il.Register(8, REG_X30), il.Register(8, REG_SP)}));
		break;
#else
	case ARM64_AUTDA:
	case ARM64_AUTDB:
	case ARM64_AUTIA:
	case ARM64_AUTIB:
	case ARM64_PACDA:
	case ARM64_PACDB:
	case ARM64_PACIA:
	case ARM64_PACIB:
	case ARM64_PACGA:
	case ARM64_AUTIA1716:
	case ARM64_AUTIB1716:
	case ARM64_PACIA1716:
	case ARM64_PACIB1716:
	case ARM64_AUTDZA:
	case ARM64_AUTDZB:
	case ARM64_AUTIZA:
	case ARM64_AUTIZB:
	case ARM64_PACDZA:
	case ARM64_PACDZB:
	case ARM64_PACIZA:
	case ARM64_PACIZB:
	case ARM64_XPACI:
	case ARM64_XPACD:
	case ARM64_AUTIAZ:
	case ARM64_AUTIBZ:
	case ARM64_PACIAZ:
	case ARM64_PACIBZ:
	case ARM64_XPACLRI:
	case ARM64_AUTIASP:
	case ARM64_AUTIBSP:
	case ARM64_PACIASP:
	case ARM64_PACIBSP:
		il.AddInstruction(il.Nop());
		ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
		break;
#endif
	case ARM64_PRFUM:
	case ARM64_PRFM:
		// TODO use the PRFM types when we have a better option than defining 18 different intrinsics to
		// account for:
		// - 3 types {PLD, PLI, PST}
		// - 3 targets {L1, L2, L3}
		// - 2 policies {KEEP, STM}
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_PRFM, {ReadILOperand(il, operand2, 8)}));
		break;
	case ARM64_ORN:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Or(REGSZ_O(operand1), ILREG_O(operand2),
		                  il.Not(REGSZ_O(operand1), ReadILOperand(il, operand3, REGSZ_O(operand1))))));
		break;
	case ARM64_ORR:
	case ARM64_ORRS:
		switch (instr.encoding)
		{
		case ENC_ORR_32_LOG_IMM:
		case ENC_ORR_32_LOG_SHIFT:
		case ENC_ORR_64_LOG_IMM:
		case ENC_ORR_64_LOG_SHIFT:
			il.AddInstruction(
				ILSETREG_O(operand1, il.Or(REGSZ_O(operand1), ILREG_O(operand2),
										ReadILOperand(il, operand3, REGSZ_O(operand1)), SETFLAGS)));
			break;
		case ENC_ORR_ASIMDIMM_L_HL:
		case ENC_ORR_ASIMDIMM_L_SL:
		{
			Register regs[16];
			int n = unpack_vector(operand1, regs);
			for (int i = 0; i < n; ++i)
				il.AddInstruction(ILSETREG(regs[i], ILCONST_O(get_register_size(regs[i]), operand2)));
			break;
		}
		case ENC_ORR_ASIMDSAME_ONLY:
			// Let the neon intrinsic lifter take over.
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
		break;
	case ARM64_PSB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_PSBCSYNC, {}));
		break;
	case ARM64_RETAA:
	case ARM64_RETAB:
		SetPacAttr = true;
	case ARM64_RET:
	{
		ExprId reg = (operand1.operandClass == REG) ? ILREG_O(operand1) : il.Register(8, REG_X30);
		il.AddInstruction(il.Return(reg));
		if (SetPacAttr)
			ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
	}
	break;
	case ARM64_REVB:  // SVE only
	case ARM64_REVH:
	case ARM64_REVW:
		il.AddInstruction(il.Unimplemented());
		break;
	case ARM64_REV16:
	case ARM64_REV32:
	case ARM64_REV64:
	case ARM64_REV:
		switch (instr.encoding) {
		case ENC_REV16_ASIMDMISC_R:
		case ENC_REV32_ASIMDMISC_R:
		case ENC_REV64_ASIMDMISC_R:
			break;
		default:
			if (IS_SVE_O(operand1))
			{
				il.AddInstruction(il.Unimplemented());
				break;
			}
			// if LLIL_BSWAP ever gets added, replace
			il.AddInstruction(il.Intrinsic(
				{RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_REV, {ILREG_O(operand2)}));
		}
		break;
	case ARM64_RBIT:
		switch (instr.encoding) {
		case ENC_RBIT_ASIMDMISC_R:
			break;
		default:
			il.AddInstruction(il.Intrinsic(
				{RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_RBIT, {ILREG_O(operand2)}));
		}
		break;
	case ARM64_ROR:
		il.AddInstruction(ILSETREG_O(operand1, il.RotateRight(REGSZ_O(operand2), ILREG_O(operand2),
		                                           ReadILOperand(il, operand3, REGSZ_O(operand2)))));
		break;
	case ARM64_SBC:
	case ARM64_SBCS:
		il.AddInstruction(ILSETREG_O(operand1, il.SubBorrow(REGSZ_O(operand1), ILREG_O(operand2),
		                                           ReadILOperand(il, operand3, REGSZ_O(operand1)),
		                                           il.Not(0, il.Flag(IL_FLAG_C)), SETFLAGS)));
		break;
	case ARM64_SBFIZ:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.ArithShiftRight(REGSZ_O(operand1),
		                  il.ShiftLeft(REGSZ_O(operand1), ExtractBits(il, operand2, IMM_O(operand4), 0),
		                      il.Const(1, (REGSZ_O(operand1) * 8) - IMM_O(operand4))),
		                  il.Const(1, (REGSZ_O(operand1) * 8) - IMM_O(operand3) - IMM_O(operand4)))));
		break;
	case ARM64_SBFX:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.ArithShiftRight(REGSZ_O(operand1),
		                  il.ShiftLeft(REGSZ_O(operand1),
		                      ExtractBits(il, operand2, IMM_O(operand4), IMM_O(operand3)),
		                      il.Const(1, (REGSZ_O(operand1) * 8) - IMM_O(operand4) - IMM_O(operand3))),
		                  il.Const(1, (REGSZ_O(operand1) * 8) - IMM_O(operand4)))));
		break;
	case ARM64_SCVTF:
	case ARM64_UCVTF:
	{
		bool zero_extend = false;
		switch (instr.encoding)
		{
		// Scalar, float
		case ENC_UCVTF_ASISDMISCFP16_R:
		case ENC_UCVTF_ASISDMISC_R:
			zero_extend = true;
		case ENC_SCVTF_ASISDMISCFP16_R:
		case ENC_SCVTF_ASISDMISC_R:
		{
			il.AddInstruction(ILSETREG_O(
			    operand1, il.IntToFloat(REGSZ_O(operand1),
					zero_extend
					? il.ZeroExtend(REGSZ_O(operand1), ILREG_O(operand2))
					: il.SignExtend(REGSZ_O(operand1), ILREG_O(operand2)))));
			break;
		}
		// Scalar, integer
		case ENC_UCVTF_D32_FLOAT2INT:
		case ENC_UCVTF_D64_FLOAT2INT:
		case ENC_UCVTF_H32_FLOAT2INT:
		case ENC_UCVTF_H64_FLOAT2INT:
		case ENC_UCVTF_S32_FLOAT2INT:
		case ENC_UCVTF_S64_FLOAT2INT:
			zero_extend = true;
		case ENC_SCVTF_D32_FLOAT2INT:
		case ENC_SCVTF_D64_FLOAT2INT:
		case ENC_SCVTF_H32_FLOAT2INT:
		case ENC_SCVTF_H64_FLOAT2INT:
		case ENC_SCVTF_S32_FLOAT2INT:
		case ENC_SCVTF_S64_FLOAT2INT:
		{
			il.AddInstruction(ILSETREG_O(
			    operand1, il.IntToFloat(REGSZ_O(operand1),
					zero_extend
					? il.ZeroExtend(REGSZ_O(operand1), ILREG_O(operand2))
					: il.SignExtend(REGSZ_O(operand1), ILREG_O(operand2)))));
			break;
		}
		// Vector, single-precision and double-precision unsigned
		case ENC_UCVTF_ASIMDMISC_R:
		// Vector, half precision unsigned
		case ENC_UCVTF_ASIMDMISCFP16_R:
			zero_extend = true;
		// Vector, single-precision and double-precision
		case ENC_SCVTF_ASIMDMISC_R:
		// Vector, half precision
		case ENC_SCVTF_ASIMDMISCFP16_R:
		{
			if (preferIntrinsics())
				return true;

			Register cregs[2];
			if (false && consolidate_vector(operand1, operand2, cregs))
				il.AddInstruction(ILSETREG(cregs[0],
					il.IntToFloat(REGSZ(cregs[0]),
						zero_extend
						? il.ZeroExtend(REGSZ(cregs[0]), ILREG(cregs[1]))
						: il.SignExtend(REGSZ(cregs[0]), ILREG(cregs[1])))));
			else
			{
				// SCVTF <Vd>.<T>, <Vn>.<T>
				Register srcs[16], dsts[16];
				int dst_n = unpack_vector(operand1, dsts);
				int src_n = unpack_vector(operand2, srcs);
				if ((dst_n != src_n) || dst_n == 0)
					ABORT_LIFT;

				int rsize = get_register_size(dsts[0]);
				for (int i = 0; i < dst_n; ++i)
					il.AddInstruction(ILSETREG(dsts[i], il.IntToFloat(rsize,
						zero_extend
						? il.ZeroExtend(rsize, ILREG(srcs[i]))
						: il.SignExtend(rsize, ILREG(srcs[i])))));

			}
			break;
		}
		// Scalar, fixed-point (in SIMD&FP register)
		case ENC_SCVTF_ASISDSHF_C:
		case ENC_UCVTF_ASISDSHF_C:
		// Scalar, fixed-point (in GP register) [will fail because no intrinsics]
		case ENC_SCVTF_D32_FLOAT2FIX:
		case ENC_SCVTF_D64_FLOAT2FIX:
		case ENC_SCVTF_H32_FLOAT2FIX:
		case ENC_SCVTF_H64_FLOAT2FIX:
		case ENC_SCVTF_S32_FLOAT2FIX:
		case ENC_SCVTF_S64_FLOAT2FIX:
		case ENC_UCVTF_D32_FLOAT2FIX:
		case ENC_UCVTF_D64_FLOAT2FIX:
		case ENC_UCVTF_H32_FLOAT2FIX:
		case ENC_UCVTF_H64_FLOAT2FIX:
		case ENC_UCVTF_S32_FLOAT2FIX:
		case ENC_UCVTF_S64_FLOAT2FIX:
		// Vector, fixed-point
		case ENC_SCVTF_ASIMDSHF_C:
			// Lift to instrinsics (except there are none)
		case ENC_UCVTF_ASIMDSHF_C:
			// Lift to instrinsics
			break;
		// SVE: Vector, integer
		case ENC_SCVTF_Z_P_Z_H2FP16:
		case ENC_SCVTF_Z_P_Z_W2D:
		case ENC_SCVTF_Z_P_Z_W2FP16:
		case ENC_SCVTF_Z_P_Z_W2S:
		case ENC_SCVTF_Z_P_Z_X2D:
		case ENC_SCVTF_Z_P_Z_X2FP16:
		case ENC_SCVTF_Z_P_Z_X2S:
		case ENC_UCVTF_Z_P_Z_H2FP16:
		case ENC_UCVTF_Z_P_Z_W2D:
		case ENC_UCVTF_Z_P_Z_W2FP16:
		case ENC_UCVTF_Z_P_Z_W2S:
		case ENC_UCVTF_Z_P_Z_X2D:
		case ENC_UCVTF_Z_P_Z_X2FP16:
		case ENC_UCVTF_Z_P_Z_X2S:
			break;
		default:
			break;
		}
		break;
	}
	case ARM64_SDIV:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.DivSigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3))));
		break;
	case ARM64_SEV:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_SEV, {}));
		break;
	case ARM64_SEVL:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_SEVL, {}));
		break;
	case ARM64_SHL:
	{
		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		if ((dst_n != src_n) || dst_n == 0)
			ABORT_LIFT;

		int rsize = get_register_size(dsts[0]);
		for (int i = 0; i < dst_n; ++i)
		{
			il.AddInstruction(il.SetRegister(rsize, dsts[i],
			    il.ShiftLeft(rsize, il.Register(rsize, srcs[i]), il.Const(1, IMM_O(operand3)))));
		}

		break;
	}
	case ARM64_SSHL:
	{
		Register srcs1[16], srcs2[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src1_n = unpack_vector(operand2, srcs1);
		int src2_n = unpack_vector(operand3, srcs2);
		if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
			ABORT_LIFT;

		int rsize = get_register_size(dsts[0]);
		for (int i = 0; i < dst_n; ++i)
		{
			il.AddInstruction(il.SetRegister(rsize, dsts[i],
			    il.ShiftLeft(rsize,
					il.SignExtend(rsize, il.Register(rsize, srcs1[i])),
					il.Register(1, srcs2[i]))));
		}

		break;
	}
	case ARM64_SSHR:
	{
		// Note: we don't lift SRSHR, because it requires rounding the shifted results

		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		if ((dst_n != src_n) || dst_n == 0)
			ABORT_LIFT;

		int rsize = get_register_size(dsts[0]);
		for (int i = 0; i < dst_n; ++i)
		{
			il.AddInstruction(il.SetRegister(rsize, dsts[i],
			    il.ArithShiftRight(rsize, il.Register(rsize, srcs[i]), il.Const(1, IMM_O(operand3)))));
		}

		break;
	}
	case ARM64_SSHLL:
	case ARM64_SSHLL2:
	case ARM64_SXTL:
	case ARM64_SXTL2:
		if ((instr.encoding == ENC_SSHLL_ASIMDSHF_L || instr.encoding == ENC_SXTL_SSHLL_ASIMDSHF_L) && preferIntrinsics())
		{
			// // Not all valid operand combinations have intrinsics and we have to try it here in case it fails
			// NeonGetLowLevelILForInstruction(arch, addr, il, instr, addrSize);
			// LogWarn("NeonGetLowLevelILForInstruction: %d -> %d\n", n_instrs_before, il.GetInstructionCount());
			// if (il.GetInstructionCount() > n_instrs_before)
			// 	return true;
			return true;
		}
	// SHLL{2} is the same as SHLL{2}, except the extension is signed or unsigned "without change of functionality"
	// (The shift amount is the element size, but is still disassembled to the immediate value in the third operand)
	case ARM64_SHLL:
	case ARM64_SHLL2:
	{
		if (preferIntrinsics())
			return true;

		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		// We cannot check that the src and dst counts are the same here
		// because the 2 variants use different count arrange specs, e.g.
		// sxtl2 v0.2d, v1.4s
		// (void) src_n;

		int left_shift = 0;
		if (instr.operation == ARM64_SSHLL || instr.operation == ARM64_SSHLL2 ||
			instr.operation == ARM64_SHLL || instr.operation == ARM64_SHLL2)
			left_shift = IMM_O(operand3);

		int two_variant_offset = 0;
		if (instr.operation == ARM64_SXTL2 || instr.operation == ARM64_SSHLL2 || instr.operation == ARM64_SHLL2)
			two_variant_offset = src_n / 2;

		int dst_size = get_register_size(dsts[0]);
		int src_size = get_register_size(srcs[0]);

		for (int i = 0; i < dst_n; ++i)
			if (left_shift)
				il.AddInstruction(il.SetRegister(dst_size, dsts[i],
					il.ShiftLeft(dst_size,
						il.SignExtend(dst_size,
							il.Register(src_size, srcs[i + two_variant_offset])),
						il.Const(1, left_shift))));
			else
				il.AddInstruction(il.SetRegister(dst_size, dsts[i],
					il.SignExtend(dst_size,
						il.Register(src_size, srcs[i + two_variant_offset]))));

		break;
	}
	case ARM64_ST1:
		LoadStoreVector(il, false, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_STP:
	case ARM64_STNP:
		LoadStoreOperandPair(il, false, instr.operands[0], instr.operands[1], instr.operands[2]);
		break;
	case ARM64_STR:
	case ARM64_STLR:
	case ARM64_STUR:
	case ARM64_STLUR:
		LoadStoreOperand(il, false, instr.operands[0], instr.operands[1], 0);
		break;
	case ARM64_STRB:
	case ARM64_STLRB:
	case ARM64_STURB:
	case ARM64_STLURB:
		LoadStoreOperandSize(il, false, false, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_STRH:
	case ARM64_STLRH:
	case ARM64_STURH:
	case ARM64_STLURH:
		LoadStoreOperandSize(il, false, false, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_SUB:
	case ARM64_SUBS:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Sub(REGSZ_O(operand1), ILREG_O(operand2),
		                  ReadILOperand(il, instr.operands[2], REGSZ_O(operand1)), SETFLAGS)));
		break;
	case ARM64_SVC:
	case ARM64_HVC:
	case ARM64_SMC:
	{
		/* b31,b30==xx of fake register mark transition to ELxx */
		uint32_t el_mark = 0;
		if (instr.operation == ARM64_SVC)
			el_mark = 0x40000000;
		else if (instr.operation == ARM64_HVC)
			el_mark = 0x80000000;
		else if (instr.operation == ARM64_SMC)
			el_mark = 0xC0000000;
		/* b15..b0 of fake register still holds syscall number */
		il.AddInstruction(
		    il.SetRegister(4, FAKEREG_SYSCALL_INFO, il.Const(4, el_mark | IMM_O(operand1))));
		il.AddInstruction(il.SystemCall());
		break;
	}

	case ARM64_SMOV:
	{
		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);
		if ((dst_n != src_n) || dst_n == 0)
			ABORT_LIFT;

		for (int i = 0; i < dst_n; ++i)
			il.AddInstruction(ILSETREG(dsts[i], il.SignExtend(REGSZ(dsts[i]), ILREG(srcs[i]))));
		break;
	}
	case ARM64_SWP: /* word (4) or doubleword (8) */
	case ARM64_SWPA:
	case ARM64_SWPL:
	case ARM64_SWPAL:
		LoadStoreOperand(il, true, operand2, operand3, 0);
		LoadStoreOperand(il, false, operand1, operand3, 0);
		break;
	case ARM64_SWPB: /* byte (1) */
	case ARM64_SWPAB:
	case ARM64_SWPLB:
	case ARM64_SWPALB:
		LoadStoreOperand(il, true, operand2, operand3, 1);
		il.AddInstruction(il.Store(1, ILREG_O(operand3), il.LowPart(1, ILREG_O(operand1))));
		break;
	case ARM64_SWPH: /* half-word (2) */
	case ARM64_SWPAH:
	case ARM64_SWPLH:
	case ARM64_SWPALH:
		LoadStoreOperand(il, true, operand2, operand3, 2);
		il.AddInstruction(il.Store(2, ILREG_O(operand3), il.LowPart(2, ILREG_O(operand1))));
		break;
	case ARM64_SXTB:
		il.AddInstruction(
		    ILSETREG_O(operand1, ExtractRegister(il, operand2, 0, 1, true, REGSZ_O(operand1))));
		break;
	case ARM64_SXTH:
		il.AddInstruction(
		    ILSETREG_O(operand1, ExtractRegister(il, operand2, 0, 2, true, REGSZ_O(operand1))));
		break;
	case ARM64_SXTW:
		il.AddInstruction(
		    ILSETREG_O(operand1, ExtractRegister(il, operand2, 0, 4, true, REGSZ_O(operand1))));
		break;
	case ARM64_TBNZ:
		ConditionalJump(arch, il,
		    il.CompareNotEqual(REGSZ_O(operand1), ExtractBit(il, operand1, IMM_O(operand2)),
		        il.Const(REGSZ_O(operand1), 0)),
		    addrSize, IMM_O(operand3), addr + 4);
		return false;
	case ARM64_TBZ:
		ConditionalJump(arch, il,
		    il.CompareEqual(REGSZ_O(operand1), ExtractBit(il, operand1, IMM_O(operand2)),
		        il.Const(REGSZ_O(operand1), 0)),
		    addrSize, IMM_O(operand3), addr + 4);
		return false;
	case ARM64_TST:
		il.AddInstruction(il.And(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1)), SETFLAGS));
		break;
	case ARM64_UMADDL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Add(REGSZ_O(operand1), ILREG_O(operand4),
		        il.MultDoublePrecUnsigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case ARM64_UMULL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.MultDoublePrecUnsigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
		break;
	case ARM64_UMSUBL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Sub(REGSZ_O(operand1), ILREG_O(operand4),
		        il.MultDoublePrecUnsigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case ARM64_UMNEGL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Sub(REGSZ_O(operand1), il.Const(8, 0),
		        il.MultDoublePrecUnsigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case ARM64_UXTL:
	case ARM64_UXTL2:
	case ARM64_USHLL:
	case ARM64_USHLL2:
	{
		if ((instr.encoding == ENC_USHLL_ASIMDSHF_L || instr.encoding == ENC_UXTL_USHLL_ASIMDSHF_L) && preferIntrinsics())
		{
			// // Not all valid operand combinations have intrinsics and we have to try it here in case it fails
			// NeonGetLowLevelILForInstruction(arch, addr, il, instr, addrSize);
			// LogWarn("NeonGetLowLevelILForInstruction: %d -> %d\n", n_instrs_before, il.GetInstructionCount());
			// if (il.GetInstructionCount() > n_instrs_before)
			// 	return true;
			return true;
		}

		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		// We cannot check that the src and dst counts are the same here
		// because the 2 variants use different count arrange specs, e.g.
		// uxtl2 v0.2d, v1.4s
		(void) src_n;

		int left_shift = 0;
		if (instr.operation == ARM64_USHLL || instr.operation == ARM64_USHLL2)
			left_shift = IMM_O(operand3);

		int two_variant_offset = 0;
		if (instr.operation == ARM64_UXTL2 || instr.operation == ARM64_USHLL2)
			two_variant_offset = src_n / 2;

		int dst_size = get_register_size(dsts[0]);
		int src_size = get_register_size(srcs[0]);

		for (int i = 0; i < dst_n; ++i)
			if (left_shift)
				il.AddInstruction(il.SetRegister(dst_size, dsts[i],
					il.ShiftLeft(dst_size,
						il.ZeroExtend(dst_size,
							il.Register(src_size, srcs[i + two_variant_offset])),
						il.Const(1, left_shift))));
			else
				il.AddInstruction(il.SetRegister(dst_size, dsts[i],
					il.ZeroExtend(dst_size,
						il.Register(src_size, srcs[i + two_variant_offset]))));

		break;
	}
	case ARM64_SMADDL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Add(REGSZ_O(operand1), ILREG_O(operand4),
		        il.MultDoublePrecSigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case ARM64_USHL:
	{
		switch (instr.encoding)
		{
			case ENC_USHL_ASIMDSAME_ONLY:
				if (preferIntrinsics())
					return true;

			case ENC_USHL_ASISDSAME_ONLY:
			default:
			{
				Register srcs1[16], srcs2[16], dsts[16];
				int dst_n = unpack_vector(operand1, dsts);
				int src1_n = unpack_vector(operand2, srcs1);
				int src2_n = unpack_vector(operand3, srcs2);
				if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
					ABORT_LIFT;

				int rsize = get_register_size(dsts[0]);
				for (int i = 0; i < dst_n; ++i)
				{
					il.AddInstruction(il.SetRegister(rsize, dsts[i],
						il.ShiftLeft(rsize,
							il.Register(rsize, srcs1[i]),
							il.Register(1, srcs2[i]))));
				}
			}
		}
		break;
	}
	case ARM64_USHR:
	{
		// Note: we don't lift URSHR, because it requires rounding the shifted results

		if (preferIntrinsics())
			return true;

		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		if ((dst_n != src_n) || dst_n == 0)
			ABORT_LIFT;

		int rsize = get_register_size(dsts[0]);
		for (int i = 0; i < dst_n; ++i)
		{
			il.AddInstruction(il.SetRegister(rsize, dsts[i],
			    il.LogicalShiftRight(rsize, il.Register(rsize, srcs[i]), il.Const(1, IMM_O(operand3)))));
		}

		break;
	}
	case ARM64_SMULL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.MultDoublePrecSigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
		break;
	case ARM64_SMSUBL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Sub(REGSZ_O(operand1), ILREG_O(operand4),
		        il.MultDoublePrecSigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case ARM64_SMNEGL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Sub(REGSZ_O(operand1), il.Const(8, 0),
		        il.MultDoublePrecSigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case ARM64_UMULH:
		il.AddInstruction(ILSETREG_O(operand1,
			il.LowPart(8,
				il.LogicalShiftRight(16,
					il.MultDoublePrecUnsigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)),
					il.Const(1, 64)))));
		break;
	case ARM64_SMULH:
		il.AddInstruction(ILSETREG_O(operand1,
			il.LowPart(8,
				il.LogicalShiftRight(16,
					il.MultDoublePrecSigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)),
					il.Const(1, 64)))));
		break;
	case ARM64_UDIV:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.DivUnsigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3))));
		break;
	case ARM64_UBFIZ:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.ZeroExtend(REGSZ_O(operand1),
		                             il.ShiftLeft(REGSZ_O(operand2),
		                                 il.And(REGSZ_O(operand2), ILREG_O(operand2),
		                                     il.Const(REGSZ_O(operand2), (1LL << IMM_O(operand4)) - 1)),
		                                 il.Const(1, IMM_O(operand3))))));
		break;
	case ARM64_UBFX:
	{
		// ubfx <dst>, <src>, <src_lsb>, <src_len>
		int src_lsb = IMM_O(operand3);
		int src_len = IMM_O(operand4);
		if (src_lsb == 0 && (src_len == 8 || src_len == 16 || src_len == 32 || src_len == 64))
		{
			il.AddInstruction(ILSETREG_O(operand1, il.LowPart(src_len / 8, ILREG_O(operand2))));
		}
		else
		{
			il.AddInstruction(ILSETREG_O(
			    operand1, il.ZeroExtend(REGSZ_O(operand1),
			                  il.And(REGSZ_O(operand2),
			                      il.LogicalShiftRight(
			                          REGSZ_O(operand2), ILREG_O(operand2), il.Const(1, IMM_O(operand3))),
			                      il.Const(REGSZ_O(operand2), (1LL << IMM_O(operand4)) - 1)))));
		}
		break;
	}
	case ARM64_UXTB:
		il.AddInstruction(
		    ILSETREG_O(operand1, ExtractRegister(il, operand2, 0, 1, false, REGSZ_O(operand1))));
		break;
	case ARM64_UXTH:
		il.AddInstruction(
		    ILSETREG_O(operand1, ExtractRegister(il, operand2, 0, 2, false, REGSZ_O(operand1))));
		break;
	case ARM64_WFE:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_WFE, {}));
		break;
	case ARM64_WFI:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_WFI, {}));
		break;
	case ARM64_BRK:
		il.AddInstruction(
		    il.Trap(IMM_O(operand1)));  // FIXME Breakpoint may need a parameter (IMM_O(operand1)));
		return false;
	case ARM64_DGH:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_DGH, {}));
		break;
	case ARM64_TSB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_TSB, {}));
		break;
	case ARM64_CSDB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_CSDB, {}));
		break;
	case ARM64_HINT:
		if ((IMM_O(operand1) & ~0b110) == 0b100000)
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_BTI, {}));
		else
			LogWarn("unknown hint operand: 0x%" PRIx64 "\n", IMM_O(operand1));
		break;
	case ARM64_HLT:
		il.AddInstruction(il.Trap(IMM_O(operand1)));
		return false;
	case ARM64_UDF:
		il.AddInstruction(il.Trap(IMM_O(operand1)));
		return false;
	case ARM64_YIELD:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_YIELD, {}));
		break;
	default:
		break;
	}

	if (il.GetInstructionCount() > n_instrs_before)
		return true;

	NeonGetLowLevelILForInstruction(arch, addr, il, instr, addrSize);
	if (il.GetInstructionCount() > n_instrs_before)
		return true;

	il.AddInstruction(il.Unimplemented());
	return true;
}
