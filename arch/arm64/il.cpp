#include "lowlevelilinstruction.h"
#include <cstring>
#include <inttypes.h>
#include <math.h>
#include <optional>
#include <stdarg.h>

#include "il.h"
#include "acle_intrinsics.h"
#include "system_operations.h"
#include "system_registers.h"
#include "operands.h"

using namespace BinaryNinja;

#include "il_macros.h"

static uint32_t GetFlagWriteTypeForEffect(exarmo_aarch64_flag_effect effect)
{
	if (!effect.writes)
		return 0;

	return effect.float_compare ? IL_FLAG_WRITE_ALL_FLOAT : IL_FLAG_WRITE_ALL;
}

// The IL expression for the condition `operand` names.
static ExprId GetCondition(LowLevelILFunction& il, const exarmo_aarch64_operand& operand)
{
	switch ((exarmo_aarch64_cond)operand.cond)
	{
	case EXARMO_AARCH64_COND_EQ:
		return il.FlagGroup(IL_FLAG_GROUP_EQ);
	case EXARMO_AARCH64_COND_NE:
		return il.FlagGroup(IL_FLAG_GROUP_NE);
	case EXARMO_AARCH64_COND_CS:
		return il.FlagGroup(IL_FLAG_GROUP_CS);
	case EXARMO_AARCH64_COND_CC:
		return il.FlagGroup(IL_FLAG_GROUP_CC);
	case EXARMO_AARCH64_COND_MI:
		return il.FlagGroup(IL_FLAG_GROUP_MI);
	case EXARMO_AARCH64_COND_PL:
		return il.FlagGroup(IL_FLAG_GROUP_PL);
	case EXARMO_AARCH64_COND_VS:
		return il.FlagGroup(IL_FLAG_GROUP_VS);
	case EXARMO_AARCH64_COND_VC:
		return il.FlagGroup(IL_FLAG_GROUP_VC);
	case EXARMO_AARCH64_COND_HI:
		return il.FlagGroup(IL_FLAG_GROUP_HI);
	case EXARMO_AARCH64_COND_LS:
		return il.FlagGroup(IL_FLAG_GROUP_LS);
	case EXARMO_AARCH64_COND_GE:
		return il.FlagGroup(IL_FLAG_GROUP_GE);
	case EXARMO_AARCH64_COND_LT:
		return il.FlagGroup(IL_FLAG_GROUP_LT);
	case EXARMO_AARCH64_COND_GT:
		return il.FlagGroup(IL_FLAG_GROUP_GT);
	case EXARMO_AARCH64_COND_LE:
		return il.FlagGroup(IL_FLAG_GROUP_LE);
	// In ARM's ConditionHolds pseudocode, AL and NV both evaluate true.
	case EXARMO_AARCH64_COND_AL:
	case EXARMO_AARCH64_COND_NV:
		return il.Const(0, 1);
	default:
		return il.Const(0, 0);
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

ExprId ExtractImmediate(LowLevelILFunction& il, exarmo_aarch64_operand& operand, int sizeof_imm)
{
	if (operand.kind != EXARMO_AARCH64_OPERAND_IMM)
		return il.Unimplemented();

	uint64_t imm = operand.imm.value;
	exarmo_aarch64_modifier modifier = operand.imm.modifier;

	if (modifier.present && modifier.amount >= 0)
	{
		switch (modifier.kind)
		{
		case EXARMO_AARCH64_MOD_LSL:
			imm = imm << modifier.amount;
			break;
		case EXARMO_AARCH64_MOD_LSR:
			imm = imm >> modifier.amount;
			break;
		case EXARMO_AARCH64_MOD_MSL:
			imm = (imm << modifier.amount) | ONES(modifier.amount);
			break;
		default:
			return il.Unimplemented();
		}
	}

	return ILCONST(sizeof_imm, imm & ONES(sizeof_imm * 8));
}

// extractSize can be smaller than the register, generating an LLIL_LOWPART
// resultSize can be larger than the register, generating sign or zero extension
ExprId ExtractRegister(LowLevelILFunction& il, exarmo_aarch64_operand& operand, size_t regNum,
    size_t extractSize, bool signExtend, size_t resultSize)
{
	Register reg = OperandRegisterAt(operand, regNum);
	size_t opsz = RegisterSize(reg);

	if (IS_ZERO_REG(reg))
		return il.Const(resultSize, 0);

	ExprId res = il.Register(opsz, reg);

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

// Convert `value` to IEEE half-precision bits, for an immediate exarmo supplies only as a value.
static uint16_t HalfPrecisionBits(double value)
{
	uint64_t bits;
	memcpy(&bits, &value, sizeof(bits));
	uint16_t sign = (uint16_t)((bits >> 48) & 0x8000);
	int64_t exponent = (int64_t)((bits >> 52) & 0x7FF);
	uint64_t mantissa = bits & 0xFFFFFFFFFFFFFull;

	if (exponent == 0x7FF)
		return sign | 0x7C00 | (mantissa ? 0x200 : 0);

	// The double's exponent bias is 1023 and the half's is 15.
	int64_t halfExponent = exponent - 1023 + 15;
	if (exponent == 0 || halfExponent <= 0)
		return sign;
	if (halfExponent >= 0x1F)
		return sign | 0x7C00;

	return (uint16_t)(sign | (halfExponent << 10) | (mantissa >> 42));
}

static ExprId GetFloat(LowLevelILFunction& il, exarmo_aarch64_operand& operand, int float_sz)
{
	if (operand.kind == EXARMO_AARCH64_OPERAND_FP_IMM)
	{
		const exarmo_aarch64_fp_imm& value = operand.fp_imm;
		switch (float_sz)
		{
		case 2:
			return il.FloatConstRaw(2,
			    value.width == 16 ? (uint16_t)value.bits : HalfPrecisionBits(value.value));
		case 4:
			return il.FloatConstSingle((float)value.value);
		case 8:
			return il.FloatConstDouble(value.value);
		default:
			break;
		}
	}
	else if (operand.kind == EXARMO_AARCH64_OPERAND_REG)
	{
		return il.FloatConvert(
		    float_sz, ExtractRegister(il, operand, 0, REGSZ_O(operand), false, REGSZ_O(operand)));
	}

	return il.Unimplemented();
}

// Compute a half-precision fixed-point conversion in single precision, because 2^fbits can exceed
// the half-precision maximum of 65504.
static size_t FixedPointSize(size_t registerSize)
{
	return registerSize < 4 ? 4 : registerSize;
}


// The scale a fixed-point conversion applies, as a floating-point constant of the given width.
// Every shift the encoding allows is a power of two single precision holds exactly.
static ExprId FixedPointScale(LowLevelILFunction& il, size_t size, uint32_t shift)
{
	return size == 4 ? il.FloatConstSingle(ldexpf(1.0f, (int)shift))
	                 : il.FloatConstDouble(ldexp(1.0, (int)shift));
}


static ExprId GetShiftedRegister(
    LowLevelILFunction& il, exarmo_aarch64_operand& operand, size_t regNum, size_t resultSize)
{
	exarmo_aarch64_modifier modifier = OperandModifier(operand);
	uint32_t amount = modifier.amount > 0 ? (uint32_t)modifier.amount : 0;
	ExprId res;

	if (!modifier.present)
		return ExtractRegister(il, operand, regNum, REGSZ_O(operand), false, resultSize);

	// peel off the variants that return early
	switch (modifier.kind)
	{
	case EXARMO_AARCH64_MOD_ASR:
		res = ExtractRegister(il, operand, regNum, REGSZ_O(operand), false, resultSize);
		if (amount)
			res = il.ArithShiftRight(resultSize, res, il.Const(1, amount));
		return res;
	case EXARMO_AARCH64_MOD_LSR:
		res = ExtractRegister(il, operand, regNum, REGSZ_O(operand), false, resultSize);
		if (amount)
			res = il.LogicalShiftRight(resultSize, res, il.Const(1, amount));
		return res;
	case EXARMO_AARCH64_MOD_ROR:
		res = ExtractRegister(il, operand, regNum, REGSZ_O(operand), false, resultSize);
		if (amount)
			res = il.RotateRight(resultSize, res, il.Const(1, amount));
		return res;
	default:
		break;
	}

	// everything else falls through to maybe be left shifted
	switch (modifier.kind)
	{
	case EXARMO_AARCH64_MOD_LSL:
		res = ExtractRegister(il, operand, regNum, REGSZ_O(operand), false, resultSize);
		break;
	case EXARMO_AARCH64_MOD_SXTB:
		res = ExtractRegister(il, operand, regNum, 1, true, resultSize);
		break;
	case EXARMO_AARCH64_MOD_SXTH:
		res = ExtractRegister(il, operand, regNum, 2, true, resultSize);
		break;
	case EXARMO_AARCH64_MOD_SXTW:
		res = ExtractRegister(il, operand, regNum, 4, true, resultSize);
		break;
	case EXARMO_AARCH64_MOD_SXTX:
		res = ExtractRegister(il, operand, regNum, 8, true, resultSize);
		break;
	case EXARMO_AARCH64_MOD_UXTB:
		res = ExtractRegister(il, operand, regNum, 1, false, resultSize);
		break;
	case EXARMO_AARCH64_MOD_UXTH:
		res = ExtractRegister(il, operand, regNum, 2, false, resultSize);
		break;
	case EXARMO_AARCH64_MOD_UXTW:
		res = ExtractRegister(il, operand, regNum, 4, false, resultSize);
		break;
	case EXARMO_AARCH64_MOD_UXTX:
		res = ExtractRegister(il, operand, regNum, 8, false, resultSize);
		break;
	default:
		il.AddInstruction(il.Unimplemented());
		return il.Unimplemented();
	}

	if (amount)
		res = il.ShiftLeft(resultSize, res, il.Const(1, amount));

	return res;
}

// Emit the base register update of a memory operand whose writeback mode is `writeback`.
static void WriteBack(
    LowLevelILFunction& il, exarmo_aarch64_operand& operand, exarmo_aarch64_writeback writeback)
{
	if (operand.kind != EXARMO_AARCH64_OPERAND_MEM || operand.mem.writeback != writeback)
		return;

	const exarmo_aarch64_offset& offset = operand.mem.offset;
	if (offset.kind == EXARMO_AARCH64_OFFSET_REG)
	{
		// ..., [Xn], <Xm>
		il.AddInstruction(
		    ILSETREG_O(operand, ILADDREG_O(operand, il.Register(8, ToRegister(offset.reg)))));
		return;
	}

	// ..., [Xn], #imm and ..., [Xn, #imm]!
	if (offset.kind == EXARMO_AARCH64_OFFSET_IMM && offset.imm)
		il.AddInstruction(ILSETREG_O(operand, ILADDREG_O(operand, il.Const(REGSZ_O(operand), offset.imm))));
}

// The address a memory operand accesses, once any pre-index writeback has been emitted. For both
// indexed forms this is the base register. `extra` reaches elements past the first.
static ExprId AccessAddress(LowLevelILFunction& il, exarmo_aarch64_operand& operand, size_t extra = 0)
{
	const exarmo_aarch64_offset& offset = operand.mem.offset;
	if (offset.kind == EXARMO_AARCH64_OFFSET_VECTOR || offset.mul_vl)
		return il.Unimplemented();

	bool indexed = operand.mem.writeback != EXARMO_AARCH64_WRITEBACK_NONE;
	if (offset.kind == EXARMO_AARCH64_OFFSET_REG && !indexed)
	{
		// [Xn, Xm{, <extend> #amount}]
		ExprId address = il.Add(8, ILREG_O(operand), GetShiftedRegister(il, operand, 1, 8));
		return extra ? il.Add(8, address, il.Const(8, extra)) : address;
	}

	// [Xn], [Xn, #imm] and either indexed form
	int64_t displacement = (int64_t)extra;
	if (offset.kind == EXARMO_AARCH64_OFFSET_IMM && !indexed)
		displacement += offset.imm;

	return displacement ? il.Add(8, ILREG_O(operand), il.Const(8, displacement)) : ILREG_O(operand);
}

static size_t ReadILOperand(
    LowLevelILFunction& il, exarmo_aarch64_operand& operand, size_t resultSize, uint64_t addr)
{
	switch (operand.kind)
	{
	case EXARMO_AARCH64_OPERAND_IMM:
	{
		exarmo_aarch64_modifier modifier = operand.imm.modifier;
		if (modifier.present && modifier.kind == EXARMO_AARCH64_MOD_LSL && modifier.amount > 0)
			return il.Const(resultSize, IMM_O(operand) << modifier.amount);

		return il.Const(resultSize, IMM_O(operand));
	}
	case EXARMO_AARCH64_OPERAND_LABEL:
		return il.ConstPointer(8, LabelTarget(operand, addr));
	case EXARMO_AARCH64_OPERAND_REG:
		if (IS_ZERO_REG(REG_O(operand)))
			return il.Const(resultSize, 0);
		return GetShiftedRegister(il, operand, 0, resultSize);
	case EXARMO_AARCH64_OPERAND_MEM:
		// A writeback is an instruction of its own, which one expression cannot carry.
		if (operand.mem.writeback != EXARMO_AARCH64_WRITEBACK_NONE)
			return il.Unimplemented();

		return il.Load(resultSize, AccessAddress(il, operand));
	case EXARMO_AARCH64_OPERAND_FP_IMM:
		return GetFloat(il, operand, resultSize);
	default:
		return il.Unimplemented();
	}
}

static Register vector_reg_minimize(exarmo_aarch64_operand& oper)
{
	if (!IS_ASIMD_O(oper))
		return REG_NONE;

	exarmo_aarch64_arrangement arrangement = OperandArrangement(oper);
	int32_t lane = OperandLaneIndex(oper);
	if (arrangement.element == EXARMO_AARCH64_ELEMENT_NONE)
	{
		if (lane >= 0)
			return REG_NONE;  // cannot have lane without an arrangement spec
		return REG_O(oper);
	}

	uint32_t number = REG_O(oper) - REG_V0;
	if (number > 31)
		return REG_NONE;

	// An index names one lane of the width written on the register.
	if (lane >= 0)
		return LaneRegister(arrangement.element, number, (uint32_t)lane);

	return ArrangementRegister(arrangement, number);
}

// Write the registers an operand names into `result`, one per lane. Returns the count, or zero if
// it names no vector register.
static int unpack_vector(exarmo_aarch64_operand& oper, Register* result)
{
	exarmo_aarch64_arrangement arrangement = OperandArrangement(oper);
	int32_t lane = OperandLaneIndex(oper);

	if (IS_REG_O(oper))
	{
		Register reg = REG_O(oper);
		/* register without an arrangement specification is just a register
		  examples: "d18", "d6", "v7" */
		if (arrangement.element == EXARMO_AARCH64_ELEMENT_NONE)
		{
			result[0] = reg;
			return 1;
		}

		if (reg < REG_V0 || reg > REG_V31)
			return 0;

		uint32_t number = reg - REG_V0;
		/* a single lane
		  examples: "v0.s[1]", "v17.d[1]" */
		if (lane >= 0)
		{
			result[0] = LaneRegister(arrangement.element, number, lane);
			return result[0] == REG_NONE ? 0 : 1;
		}

		/* each lane of the arrangement
		  examples: "v17.2s", "v8.4h", "v21.8b" */
		uint32_t lanes = ArrangementLanes(arrangement);
		for (uint32_t i = 0; i < lanes; i++)
		{
			result[i] = LaneRegister(arrangement.element, number, i);
			if (result[i] == REG_NONE)
				return 0;
		}

		return (int)lanes;
	}

	if (oper.kind != EXARMO_AARCH64_OPERAND_LIST)
		return 0;

	for (uint8_t i = 0; i < oper.list.len; i++)
	{
		Register reg = OperandRegisterAt(oper, i);
		if (reg < REG_V0 || reg > REG_V31)
			return 0;

		uint32_t number = reg - REG_V0;
		/* each list member's indexed lane, or the span its arrangement covers
		  examples: "ld2 {v17.d, v18.d}[1], [x20]", "{v0.8b, v1.8b}", "{v8.2s, v9.2s}" */
		result[i] = lane >= 0 ? LaneRegister(arrangement.element, number, lane)
		                      : ArrangementRegister(arrangement, number);
		if (result[i] == REG_NONE)
			return 0;
	}

	return oper.list.len;
}

/* if we have two operands that have the same arrangement spec, instead of treating them as
    distinct sets of registers, see if we can consolidate the set of registers into a single
    larger register. This allows us to easily lift things like 'mov v0.16b, v1.16b' as
    'mov v0, v1' */
static int consolidate_vector(
		exarmo_aarch64_operand& operand1,
		exarmo_aarch64_operand& operand2,
		Register *result)
{
	/* make sure both operands are single regs */
	if (!IS_REG_O(operand1) || !IS_REG_O(operand2))
		return 0;

	/* make sure our arrangements match. We need this to deal with cases where the arrangement
        might have different sizes, e.g. 'uxtl v2.2d, v8.2s'.*/
	exarmo_aarch64_arrangement arrangement = OperandArrangement(operand1);
	exarmo_aarch64_arrangement other = OperandArrangement(operand2);
	if (arrangement.element != other.element || arrangement.lanes != other.lanes)
		return 0;

	result[0] = ArrangementRegister(arrangement, REG_O(operand1) - REG_V0);
	result[1] = ArrangementRegister(arrangement, REG_O(operand2) - REG_V0);

	return result[0] != REG_NONE && result[1] != REG_NONE;
}

static void LoadStoreOperandPairSize(LowLevelILFunction& il, bool load, size_t load_size, exarmo_aarch64_operand& operand1,
	exarmo_aarch64_operand& operand2, exarmo_aarch64_operand& operand3)
{
	WriteBack(il, operand3, EXARMO_AARCH64_WRITEBACK_PRE);

	ExprId addr0 = AccessAddress(il, operand3);
	ExprId addr1 = AccessAddress(il, operand3, load_size);

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

	WriteBack(il, operand3, EXARMO_AARCH64_WRITEBACK_POST);
}


static void LoadStoreOperandPair(LowLevelILFunction& il, bool load, exarmo_aarch64_operand& operand1,
    exarmo_aarch64_operand& operand2, exarmo_aarch64_operand& operand3)
{
	unsigned sz = REGSZ_O(operand1);
	LoadStoreOperandPairSize(il, load, sz, operand1, operand2, operand3);
}


// Lift a SYS alias to its intrinsic. Find the operands by kind rather than position because GICR
// puts its register first.
static void LiftSystemOperation(LowLevelILFunction& il, exarmo_aarch64_mnemonic mnemonic,
    exarmo_aarch64_operand* operands, size_t operandCount, uint64_t addr)
{
	const exarmo_aarch64_sysop_def* operation = nullptr;
	for (size_t i = 0; i < operandCount; i++)
	{
		if (operands[i].kind == EXARMO_AARCH64_OPERAND_SYSOP
		    && operands[i].sysop.index < EXARMO_AARCH64_SYSOP_COUNT)
			operation = &exarmo_aarch64_sysops[operands[i].sysop.index];
	}

	// TLBIP takes a register pair with the low half first. An optional register is present only when
	// it isn't XZR.
	exarmo_aarch64_operand* registers[2] = {};
	size_t registerCount = 0;
	for (size_t i = 0; operation && i < operandCount && registerCount < 2; i++)
	{
		if (!IS_REG_O(operands[i]) || operation->reg_use == EXARMO_AARCH64_SYSOP_REG_NONE)
			continue;

		if (operation->reg_use == EXARMO_AARCH64_SYSOP_REG_OPTIONAL && operands[i].reg.reg.num == 31)
			continue;

		registers[registerCount++] = &operands[i];
	}

	// An operation that writes XZR discards its result, so lift it without the register.
	if (registerCount && operation->reg_access == EXARMO_AARCH64_SYSOP_REG_WRITE
	    && IS_ZERO_REG(REG_O(*registers[0])))
		registerCount = 0;

	uint32_t intrinsic =
	    operation ? SysOpIntrinsic(mnemonic, registerCount != 0) : (uint32_t)ARM64_INTRIN_INVALID;
	if (intrinsic == ARM64_INTRIN_INVALID)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	ExprId encoding = il.Const(4, operation->encoding);
	if (!registerCount)
	{
		il.AddInstruction(il.Intrinsic({}, intrinsic, {encoding}));
		return;
	}

	if (operation->reg_access == EXARMO_AARCH64_SYSOP_REG_WRITE)
	{
		il.AddInstruction(
		    il.Intrinsic({RegisterOrFlag::Register(REG_O(*registers[0]))}, intrinsic, {encoding}));
		return;
	}

	if (operation->reg_bits == 128 && registerCount == 2)
	{
		Register low = REG_O(*registers[0]);
		Register high = REG_O(*registers[1]);
		// The pair is XZR twice or two registers, never one of each.
		ExprId value = IS_ZERO_REG(low) ? il.Const(16, 0) : il.RegisterSplit(8, high, low);
		il.AddInstruction(il.Intrinsic({}, intrinsic, {encoding, value}));
		return;
	}

	il.AddInstruction(
	    il.Intrinsic({}, intrinsic, {encoding, ReadILOperand(il, *registers[0], 8, addr)}));
}


static void LoadStoreVector(
    LowLevelILFunction& il, bool is_load, exarmo_aarch64_operand& oper0, exarmo_aarch64_operand& oper1, bool replicate=false)
{
	WriteBack(il, oper1, EXARMO_AARCH64_WRITEBACK_PRE);

	Register regs[16];
	int regs_n = unpack_vector(oper0, regs);

	bool lanes = (OperandLaneIndex(oper0) >= 0);

	exarmo_aarch64_arrangement arrangement = OperandArrangement(oper0);
	if (arrangement.element == EXARMO_AARCH64_ELEMENT_NONE
	    || arrangement.element == EXARMO_AARCH64_ELEMENT_Q)
	{
		// Every register list this lifts is written with elements narrower than a whole register.
		LogWarn("Invalid arrangement specification");
		return;
	}

	int element_size = arrangement.element / 8;
	int element_count = (int)ArrangementLanes(arrangement);

	int offset = 0;
	if (lanes)
		element_count = 1;
	int lane = lanes ? OperandLaneIndex(oper0) : 0;
	int rsize = element_size;
	if (replicate)
		// load first into temp register for replication
		il.AddInstruction(il.SetRegister(rsize, LLIL_TEMP(0), il.Load(rsize, AccessAddress(il, oper1, offset))));
	for (int j = 0; j < element_count; j++)
	{
		for (int i = 0; i < regs_n; ++i)
		{
			// Read each register from the list, because a list can wrap from v31 to v0.
			uint32_t number = OperandRegisterAt(oper0, i) - REG_V0;
			Register reg = LaneRegister(arrangement.element, number, lane + j);

			ExprId eaddr = AccessAddress(il, oper1, offset);
			if (is_load)
				il.AddInstruction(il.SetRegister(rsize, reg, replicate ?
					il.Register(rsize, LLIL_TEMP(0)) // replicate: already loaded
					:
					il.Load(rsize, eaddr))); // single-lane: do the load inline
			else
				il.AddInstruction(il.Store(rsize, eaddr, il.Register(rsize, reg)));
			offset += rsize;
		}
	}

	WriteBack(il, oper1, EXARMO_AARCH64_WRITEBACK_POST);
}

// Emit any pre-index writeback, and return the address a literal or memory operand accesses.
// Returns nullopt for any other operand.
static std::optional<ExprId> BeginAccess(
    LowLevelILFunction& il, exarmo_aarch64_operand& operand, uint64_t addr)
{
	if (operand.kind == EXARMO_AARCH64_OPERAND_LABEL)
		return il.ConstPointer(8, LabelTarget(operand, addr));

	if (operand.kind != EXARMO_AARCH64_OPERAND_MEM)
		return std::nullopt;

	WriteBack(il, operand, EXARMO_AARCH64_WRITEBACK_PRE);
	return AccessAddress(il, operand);
}

static void LoadStoreOperand(LowLevelILFunction& il, bool load,
    exarmo_aarch64_operand& operand1, /* register that gets read/written */
    exarmo_aarch64_operand& operand2, /* location the read/write occurs */
    int load_store_sz, uint64_t addr)
{
	if (!load_store_sz)
		load_store_sz = REGSZ_O(operand1);

	std::optional<ExprId> address = BeginAccess(il, operand2, addr);
	if (!address)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	if (load)
		il.AddInstruction(ILSETREG_O(operand1, il.Operand(1, il.Load(load_store_sz, *address))));
	else
		il.AddInstruction(il.Operand(1, il.Store(load_store_sz, *address, ILREG_O(operand1))));

	WriteBack(il, operand2, EXARMO_AARCH64_WRITEBACK_POST);
}

// Load `reg` from, or store it to, the location operand2 names. `reg` may be an LLIL_TEMP, which a
// lift loads into before working on the value.
static void LoadStoreOperandSize(LowLevelILFunction& il, bool load, bool sign_extend, size_t size,
    Register reg, exarmo_aarch64_operand& operand2, uint64_t addr)
{
	std::optional<ExprId> address = BeginAccess(il, operand2, addr);
	if (!address)
	{
		il.AddInstruction(il.Unimplemented());
		return;
	}

	if (load)
	{
		// LLIL_TEMP registers will be reported to have size 0, so override with size
		size_t extendSize = REGSZ(reg) ? REGSZ(reg) : size;

		ExprId value = il.Operand(1, il.Load(size, *address));
		if (extendSize > size)
			value = sign_extend ? il.SignExtend(extendSize, value) : il.ZeroExtend(extendSize, value);

		il.AddInstruction(ILSETREG(reg, value));
	}
	else
	{
		ExprId value = il.Operand(0, IS_ZERO_REG(reg) ? il.Const(REGSZ(reg), 0) : ILREG(reg));
		if (size < REGSZ(reg))
			value = il.LowPart(size, value);

		il.AddInstruction(il.Operand(1, il.Store(size, *address, value)));
	}

	WriteBack(il, operand2, EXARMO_AARCH64_WRITEBACK_POST);
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
    LowLevelILFunction& il, exarmo_aarch64_operand& reg, size_t nbits, size_t rightMostBit)
{
// Get N set bits at offset O
#define BITMASK(N, O) (((UINT64_C(1) << nbits) - 1) << O)
	return il.And(REGSZ_O(reg), ILREG_O(reg), il.Const(REGSZ_O(reg), BITMASK(nbits, rightMostBit)));
}

static ExprId ExtractBit(LowLevelILFunction& il, exarmo_aarch64_operand& reg, size_t bit)
{
	return il.And(REGSZ_O(reg), ILREG_O(reg), il.Const(REGSZ_O(reg), (UINT64_C(1) << bit)));
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


#ifdef LIFT_PAC_AS_INTRINSIC
static enum Arm64Intrinsic mnemonic_to_intrinsic(exarmo_aarch64_mnemonic mnemonic)
{
	switch (mnemonic)
	{
	case EXARMO_AARCH64_AUTDA:
	case EXARMO_AARCH64_AUTDZA:
		return ARM64_INTRIN_AUTDA;
	case EXARMO_AARCH64_AUTDB:
	case EXARMO_AARCH64_AUTDZB:
		return ARM64_INTRIN_AUTDB;
	case EXARMO_AARCH64_AUTIA:
	case EXARMO_AARCH64_AUTIA1716:
	case EXARMO_AARCH64_AUTIASP:
	case EXARMO_AARCH64_AUTIAZ:
	case EXARMO_AARCH64_AUTIZA:
		return ARM64_INTRIN_AUTIA;
	case EXARMO_AARCH64_AUTIB:
	case EXARMO_AARCH64_AUTIB1716:
	case EXARMO_AARCH64_AUTIBSP:
	case EXARMO_AARCH64_AUTIBZ:
	case EXARMO_AARCH64_AUTIZB:
		return ARM64_INTRIN_AUTIB;
	case EXARMO_AARCH64_AUTIA171615:
	case EXARMO_AARCH64_AUTIASPPC:
	case EXARMO_AARCH64_AUTIASPPCR:
		return ARM64_INTRIN_AUTIA2;
	case EXARMO_AARCH64_AUTIB171615:
	case EXARMO_AARCH64_AUTIBSPPC:
	case EXARMO_AARCH64_AUTIBSPPCR:
		return ARM64_INTRIN_AUTIB2;
	case EXARMO_AARCH64_PACDA:
	case EXARMO_AARCH64_PACDZA:
		return ARM64_INTRIN_PACDA;
	case EXARMO_AARCH64_PACDB:
	case EXARMO_AARCH64_PACDZB:
		return ARM64_INTRIN_PACDB;
	case EXARMO_AARCH64_PACGA:
		return ARM64_INTRIN_PACGA;
	case EXARMO_AARCH64_PACIA:
	case EXARMO_AARCH64_PACIA1716:
	case EXARMO_AARCH64_PACIASP:
	case EXARMO_AARCH64_PACIAZ:
	case EXARMO_AARCH64_PACIZA:
		return ARM64_INTRIN_PACIA;
	case EXARMO_AARCH64_PACIB:
	case EXARMO_AARCH64_PACIB1716:
	case EXARMO_AARCH64_PACIBSP:
	case EXARMO_AARCH64_PACIBZ:
	case EXARMO_AARCH64_PACIZB:
		return ARM64_INTRIN_PACIB;
	case EXARMO_AARCH64_PACIA171615:
	case EXARMO_AARCH64_PACIASPPC:
	case EXARMO_AARCH64_PACNBIASPPC:
		return ARM64_INTRIN_PACIA2;
	case EXARMO_AARCH64_PACIB171615:
	case EXARMO_AARCH64_PACIBSPPC:
	case EXARMO_AARCH64_PACNBIBSPPC:
		return ARM64_INTRIN_PACIB2;
	case EXARMO_AARCH64_XPACD:
		return ARM64_INTRIN_XPACD;
	case EXARMO_AARCH64_XPACI:
	case EXARMO_AARCH64_XPACLRI:
		return ARM64_INTRIN_XPACI;
	default:
		return ARM64_INTRIN_INVALID;
	}
}
#endif


bool GetLowLevelILForInstruction(
    Architecture* arch, uint64_t addr, LowLevelILFunction& il, const exarmo_aarch64_instruction& instr, size_t addrSize, bool requireAlignment, std::function<bool()> _preferIntrinsics)
{
	bool SetPacAttr = false;

	// Mark unused operands EXARMO_AARCH64_OPERAND_OTHER so that a lift reading one falls through.
	exarmo_aarch64_operand operands[EXARMO_AARCH64_MAX_OPERANDS];
	size_t operandCount =
	    exarmo_aarch64_instruction_operands(&instr, operands, EXARMO_AARCH64_MAX_OPERANDS);
	for (size_t i = operandCount; i < EXARMO_AARCH64_MAX_OPERANDS; i++)
		operands[i].kind = EXARMO_AARCH64_OPERAND_OTHER;

	exarmo_aarch64_operand& operand1 = operands[0];
	exarmo_aarch64_operand& operand2 = operands[1];
	exarmo_aarch64_operand& operand3 = operands[2];
	exarmo_aarch64_operand& operand4 = operands[3];
	exarmo_aarch64_operand& operand5 = operands[4];

	exarmo_aarch64_mnemonic mnemonic = exarmo_aarch64_instruction_mnemonic(&instr);
	exarmo_aarch64_encoding encoding = exarmo_aarch64_instruction_encoding(&instr);

	const size_t pairedSize = REGSZ_O(operand1) * 2;


	if (requireAlignment && (addr % 4 != 0)) {
		return false;
	}

	int n_instrs_before = il.GetInstructionCount();

	auto preferIntrinsics = [&]() -> bool {
		if (_preferIntrinsics())
		{
			AcleGetLowLevelILForInstruction(il, instr, operands);
			return (il.GetInstructionCount() > n_instrs_before);
		}
		return false;
	};

	LowLevelILLabel trueLabel, falseLabel;
	switch (mnemonic)
	{
	case EXARMO_AARCH64_ABS:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_Abs32Dp1src:
		case EXARMO_AARCH64_ENC_Abs64Dp1src:
			// FEAT_CSSC scalar absolute value on a general-purpose register
			il.AddInstruction(ILSETREG_O(operand1, il.AbsoluteValue(REGSZ_O(operand2), ILREG_O(operand2))));
			break;
		default:
			// The NEON and SVE forms are per-element absolute values, which have no native scalar
			// representation
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case EXARMO_AARCH64_ADD:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_AddZPZz:
		case EXARMO_AARCH64_ENC_AddZZi:
		case EXARMO_AARCH64_ENC_AddZZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
	case EXARMO_AARCH64_ADDS:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.Add(REGSZ_O(operand1), ILREG_O(operand2),
		                             ReadILOperand(il, operand3, REGSZ_O(operand1), addr), SETFLAGS)));
		break;
	case EXARMO_AARCH64_ADDG:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_ADDG,
			{ILREG_O(operand2), il.Const(REGSZ_O(operand2), IMM_O(operand3)), il.Const(1, IMM_O(operand4))}));
		break;
	case EXARMO_AARCH64_ADDPT:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_AddptZPZz:
		case EXARMO_AARCH64_ENC_AddptZZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		// FEAT_CPA checked pointer addition, lifted as if checking is disabled
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Add(REGSZ_O(operand1), ILREG_O(operand2),
		        ReadILOperand(il, operand3, REGSZ_O(operand1), addr))));
		break;
	case EXARMO_AARCH64_ADC:
	case EXARMO_AARCH64_ADCS:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.AddCarry(REGSZ_O(operand1), ILREG_O(operand2),
		        ReadILOperand(il, operand3, REGSZ_O(operand1), addr), il.Flag(IL_FLAG_C), SETFLAGS)));
		break;
	case EXARMO_AARCH64_AND:
	case EXARMO_AARCH64_ANDS:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_AndPPPpZ:
		case EXARMO_AARCH64_ENC_AndZPZz:
		case EXARMO_AARCH64_ENC_AndZZi:
		case EXARMO_AARCH64_ENC_AndZZz:
		case EXARMO_AARCH64_ENC_AndsPPPpZ:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(
		    ILSETREG_O(operand1, il.And(REGSZ_O(operand1), ILREG_O(operand2),
		                             ReadILOperand(il, operand3, REGSZ_O(operand1), addr), SETFLAGS)));
		break;
	case EXARMO_AARCH64_ADR:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_AdrZAzSdSameScaled:
		case EXARMO_AARCH64_ENC_AdrZAzDS32Scaled:
		case EXARMO_AARCH64_ENC_AdrZAzDU32Scaled:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
	case EXARMO_AARCH64_ADRP:
		il.AddInstruction(ILSETREG_O(operand1, il.ConstPointer(REGSZ_O(operand1), LabelTarget(operand2, addr))));
		break;
	case EXARMO_AARCH64_ASR:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_AsrZPZi:
		case EXARMO_AARCH64_ENC_AsrZPZw:
		case EXARMO_AARCH64_ENC_AsrZPZz:
		case EXARMO_AARCH64_ENC_AsrZZi:
		case EXARMO_AARCH64_ENC_AsrZZw:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(ILSETREG_O(operand1, il.ArithShiftRight(REGSZ_O(operand2), ILREG_O(operand2),
		                                           ReadILOperand(il, operand3, REGSZ_O(operand2), addr))));
		break;
	case EXARMO_AARCH64_AESD:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_AesdZZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_AESD,
		    {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case EXARMO_AARCH64_AESE:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_AeseZZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_AESE,
		    {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case EXARMO_AARCH64_AESIMC:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_AesimcZZ:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_AESIMC,
		    {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case EXARMO_AARCH64_AESMC:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_AesmcZZ:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_AESMC,
		    {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case EXARMO_AARCH64_BTI:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_BTI, {}));
		break;

	// B carries the condition as an operand, so one case covers the unconditional branch and
	// every conditional one. b.al and b.nv branch every time, and jump directly so that the
	// block does not gain an edge nothing takes.
	case EXARMO_AARCH64_B:
	case EXARMO_AARCH64_BC:
	{
		exarmo_aarch64_operand& target = IS_COND_O(operand1) ? operand2 : operand1;
		if (!IS_COND_O(operand1) || operand1.cond == EXARMO_AARCH64_COND_AL
		    || operand1.cond == EXARMO_AARCH64_COND_NV)
		{
			il.AddInstruction(DirectJump(arch, il, LabelTarget(target, addr), addrSize));
			break;
		}

		ConditionalJump(
		    arch, il, GetCondition(il, operand1), addrSize, LabelTarget(target, addr), addr + 4);
		return false;
	}
	case EXARMO_AARCH64_BL:
		il.AddInstruction(il.Call(il.ConstPointer(addrSize, LabelTarget(operand1, addr))));
		break;
	case EXARMO_AARCH64_BLRAA:
	case EXARMO_AARCH64_BLRAAZ:
	case EXARMO_AARCH64_BLRAB:
	case EXARMO_AARCH64_BLRABZ:
		SetPacAttr = true;
	case EXARMO_AARCH64_BLR:
		il.AddInstruction(il.Call(ILREG_O(operand1)));
		if (SetPacAttr)
			ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
		break;
	case EXARMO_AARCH64_BFC:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.And(REGSZ_O(operand1),
		                  il.Const(REGSZ_O(operand1), ~(ONES(IMM_O(operand3)) << IMM_O(operand2))),
		                  ILREG_O(operand1))));
		break;
	case EXARMO_AARCH64_BFI:
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
	case EXARMO_AARCH64_BFXIL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Or(REGSZ_O(operand1),
		        il.And(REGSZ_O(operand1), ILREG_O(operand1),
		            il.Const(REGSZ_O(operand1), ~ONES(IMM_O(operand4)))),
		        il.LogicalShiftRight(REGSZ_O(operand1),
		            il.And(REGSZ_O(operand1), ILREG_O(operand2),
		                il.Const(REGSZ_O(operand1), ONES(IMM_O(operand4)) << IMM_O(operand3))),
		            il.Const(1, IMM_O(operand3))))));
		break;
	case EXARMO_AARCH64_BRAA:
	case EXARMO_AARCH64_BRAAZ:
	case EXARMO_AARCH64_BRAB:
	case EXARMO_AARCH64_BRABZ:
		SetPacAttr = true;
	case EXARMO_AARCH64_BR:
		il.AddInstruction(il.Jump(ILREG_O(operand1)));
		if (SetPacAttr)
			ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
		return false;
	case EXARMO_AARCH64_BIC:
	case EXARMO_AARCH64_BICS:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_BicPPPpZ:
		case EXARMO_AARCH64_ENC_BicZPZz:
		case EXARMO_AARCH64_ENC_BicZZz:
		case EXARMO_AARCH64_ENC_BicsPPPpZ:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		case EXARMO_AARCH64_ENC_BicAsimdimmLHl:
		case EXARMO_AARCH64_ENC_BicAsimdimmLSl:
			il.AddInstruction(ILSETREG_O(operand1,
				il.And(REGSZ_O(operand1), ILREG_O(operand1),
					il.Not(REGSZ_O(operand2), ReadILOperand(il, operand2, REGSZ_O(operand2), addr)), SETFLAGS)));
			break;
		default:
			il.AddInstruction(ILSETREG_O(operand1,
				il.And(REGSZ_O(operand2), ILREG_O(operand2),
					il.Not(REGSZ_O(operand2), ReadILOperand(il, operand3, REGSZ_O(operand2), addr)), SETFLAGS)));
		}
		break;
	// TODO: some representation of the Acquire/Release semantics of the CAS* instructions... attribute?
	case EXARMO_AARCH64_CASP:  // these compare-and-swaps can be pairs of 32 bit words or 64 bit doublewords
	case EXARMO_AARCH64_CASPA:
	case EXARMO_AARCH64_CASPAL:
	case EXARMO_AARCH64_CASPL:
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
					REG_O(hi1), REG_O(lo1)),
				il.Register(pairedSize, LLIL_TEMP(0))),
			il.Store(pairedSize,
				ILREG_O(operand5),
				il.RegisterSplit(REGSZ_O(operand1), REG_O(hi2), REG_O(lo2))),
			0);

		il.AddInstruction(
			il.SetRegisterSplit(pairedSize,
				REG_O(hi1),
				REG_O(lo1),
				il.Register(pairedSize, LLIL_TEMP(0))));
		break;
	}
	case EXARMO_AARCH64_CAS:  // these compare-and-swaps can be 32 or 64 bit
	case EXARMO_AARCH64_CASA:
	case EXARMO_AARCH64_CASAL:
	case EXARMO_AARCH64_CASL:
		il.AddInstruction(il.SetRegister(REGSZ_O(operand1), LLIL_TEMP(0), il.Load(REGSZ_O(operand1), ILREG_O(operand3))));

		GenIfElse(il,
			il.CompareEqual(REGSZ_O(operand1), ILREG_O(operand1), il.Register(REGSZ_O(operand1), LLIL_TEMP(0))),
			il.Store(REGSZ_O(operand1), ILREG_O(operand3), ILREG_O(operand2)),
			0);

		il.AddInstruction(ILSETREG_O(operand1, il.Register(REGSZ_O(operand1), LLIL_TEMP(0))));
		break;
	case EXARMO_AARCH64_CASAH:  // these compare-and-swaps are 16 bit
	case EXARMO_AARCH64_CASALH:
	case EXARMO_AARCH64_CASH:
	case EXARMO_AARCH64_CASLH:
		il.AddInstruction(il.SetRegister(2, LLIL_TEMP(0), il.Load(2, ILREG_O(operand3))));

		GenIfElse(il,
			il.CompareEqual(REGSZ_O(operand1), ExtractRegister(il, operand1, 0, 2, false, 2), il.Register(2, LLIL_TEMP(0))),
			il.Store(2, ILREG_O(operand3), ExtractRegister(il, operand2, 0, 2, false, 2)),
			0);

		il.AddInstruction(ILSETREG_O(operand1, il.Register(2, LLIL_TEMP(0))));
		break;
	case EXARMO_AARCH64_CASAB:  // these compare-and-swaps are 8 bit
	case EXARMO_AARCH64_CASALB:
	case EXARMO_AARCH64_CASB:
	case EXARMO_AARCH64_CASLB:
		il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Load(1, ILREG_O(operand3))));

		GenIfElse(il,
			il.CompareEqual(REGSZ_O(operand1), ExtractRegister(il, operand1, 0, 1, false, 1), il.Register(1, LLIL_TEMP(0))),
			il.Store(1, ILREG_O(operand3), ExtractRegister(il, operand2, 0, 1, false, 1)),
			0);

		il.AddInstruction(ILSETREG_O(operand1, il.Register(1, LLIL_TEMP(0))));
		break;
	case EXARMO_AARCH64_CBNZ:
		ConditionalJump(arch, il,
		    il.CompareNotEqual(REGSZ_O(operand1), ILREG_O(operand1), il.Const(REGSZ_O(operand1), 0)),
		    addrSize, LabelTarget(operand2, addr), addr + 4);
		return false;
	case EXARMO_AARCH64_CBZ:
		ConditionalJump(arch, il,
		    il.CompareEqual(REGSZ_O(operand1), ILREG_O(operand1), il.Const(REGSZ_O(operand1), 0)),
		    addrSize, LabelTarget(operand2, addr), addr + 4);
		return false;
	case EXARMO_AARCH64_CMN:
		il.AddInstruction(il.Add(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1), addr), SETFLAGS));
		break;
	case EXARMO_AARCH64_CCMN:
	{
		LowLevelILLabel trueCode, falseCode, done;

		il.AddInstruction(il.If(GetCondition(il, operand4), trueCode, falseCode));

		il.MarkLabel(trueCode);
		il.AddInstruction(il.Add(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1), addr), SETFLAGS));
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
	case EXARMO_AARCH64_CMP:
		il.AddInstruction(il.Sub(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1), addr), SETFLAGS));
		break;
	case EXARMO_AARCH64_CMPP:
		il.AddInstruction(il.Intrinsic(
			{RegisterOrFlag::Flag(IL_FLAG_N), RegisterOrFlag::Flag(IL_FLAG_Z), RegisterOrFlag::Flag(IL_FLAG_C),
				RegisterOrFlag::Flag(IL_FLAG_V)},
			ARM64_INTRIN_CMPP, {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case EXARMO_AARCH64_CCMP:
	{
		LowLevelILLabel trueCode, falseCode, done;

		il.AddInstruction(il.If(GetCondition(il, operand4), trueCode, falseCode));

		il.MarkLabel(trueCode);
		il.AddInstruction(il.Sub(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1), addr), SETFLAGS));
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
	case EXARMO_AARCH64_CLREX:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_CLREX, {}));
		break;
	case EXARMO_AARCH64_CSEL:
	case EXARMO_AARCH64_FCSEL:
		GenIfElse(il, GetCondition(il, operand4), ILSETREG_O(operand1, ILREG_O(operand2)),
		    ILSETREG_O(operand1, ILREG_O(operand3)));
		break;
	case EXARMO_AARCH64_CSINC:
		GenIfElse(il, GetCondition(il, operand4), ILSETREG_O(operand1, ILREG_O(operand2)),
		    ILSETREG_O(operand1, ILADDREG_O(operand3, il.Const(REGSZ_O(operand1), 1))));
		break;
	case EXARMO_AARCH64_CSINV:
		GenIfElse(il, GetCondition(il, operand4), ILSETREG_O(operand1, ILREG_O(operand2)),
		    ILSETREG_O(operand1, il.Not(REGSZ_O(operand1), ILREG_O(operand3))));
		break;
	case EXARMO_AARCH64_CSNEG:
		GenIfElse(il, GetCondition(il, operand4), ILSETREG_O(operand1, ILREG_O(operand2)),
		    ILSETREG_O(operand1, il.Neg(REGSZ_O(operand1), ILREG_O(operand3))));
		break;
	case EXARMO_AARCH64_CSET:
		il.AddInstruction(
			ILSETREG_O(operand1,
				il.BoolToInt(REGSZ_O(operand1), GetCondition(il, operand2))));
		break;
	case EXARMO_AARCH64_CSETM:
		GenIfElse(il, GetCondition(il, operand2),
		    ILSETREG_O(operand1, il.Const(REGSZ_O(operand1), -1)),
		    ILSETREG_O(operand1, il.Const(REGSZ_O(operand1), 0)));
		break;
	case EXARMO_AARCH64_CINC:
		GenIfElse(il, GetCondition(il, operand3),
		    ILSETREG_O(operand1, ILADDREG_O(operand2, il.Const(REGSZ_O(operand1), 1))),
		    ILSETREG_O(operand1, ILREG_O(operand2)));
		break;
	case EXARMO_AARCH64_CINV:
		GenIfElse(il, GetCondition(il, operand3),
		    ILSETREG_O(operand1, il.Not(REGSZ_O(operand1), ILREG_O(operand2))),
		    ILSETREG_O(operand1, ILREG_O(operand2)));
		break;
	case EXARMO_AARCH64_CNEG:
		GenIfElse(il, GetCondition(il, operand3),
		    ILSETREG_O(operand1, il.Neg(REGSZ_O(operand1), ILREG_O(operand2))),
		    ILSETREG_O(operand1, ILREG_O(operand2)));
		break;
	case EXARMO_AARCH64_CLS:
		il.AddInstruction(ILSETREG_O(operand1, il.CountLeadingSigns(REGSZ_O(operand2), ILREG_O(operand2))));
		break;
	case EXARMO_AARCH64_CLZ:
		il.AddInstruction(ILSETREG_O(operand1, il.CountLeadingZeros(REGSZ_O(operand2), ILREG_O(operand2))));
		break;
	case EXARMO_AARCH64_CNT:
		switch (encoding) {
		case EXARMO_AARCH64_ENC_Cnt32Dp1src:
		case EXARMO_AARCH64_ENC_Cnt64Dp1src:
			// FEAT_CSSC scalar population count on a general-purpose register
			il.AddInstruction(ILSETREG_O(operand1, il.PopulationCount(REGSZ_O(operand2), ILREG_O(operand2))));
			break;
		default:
			// The NEON and SVE forms are per-element population counts, which have no native scalar
			// representation and are lifted as an intrinsic
			il.AddInstruction(
				il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_CNT, {ILREG_O(operand2)}));
		}
		break;
	case EXARMO_AARCH64_CTZ:
		il.AddInstruction(ILSETREG_O(operand1, il.CountTrailingZeros(REGSZ_O(operand2), ILREG_O(operand2))));
		break;
	case EXARMO_AARCH64_DMB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_DMB, {}));
		break;
	case EXARMO_AARCH64_DSB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_DSB, {}));
		break;
	case EXARMO_AARCH64_EON:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Xor(REGSZ_O(operand1), ILREG_O(operand2),
		                  il.Not(REGSZ_O(operand1), ReadILOperand(il, operand3, REGSZ_O(operand1), addr)))));
		break;
	case EXARMO_AARCH64_EOR:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_EorPPPpZ:
		case EXARMO_AARCH64_ENC_EorZPZz:
		case EXARMO_AARCH64_ENC_EorZZi:
		case EXARMO_AARCH64_ENC_EorZZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(ILSETREG_O(operand1, il.Xor(REGSZ_O(operand1), ILREG_O(operand2),
		                                           ReadILOperand(il, operand3, REGSZ_O(operand1), addr))));
		break;
	case EXARMO_AARCH64_ESB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_ESB, {}));
		break;
	case EXARMO_AARCH64_EXTR:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.LogicalShiftRight(pairedSize,
		                             il.Or(pairedSize,
		                                 il.ShiftLeft(pairedSize, ILREG_O(operand2),
		                                     il.Const(1, REGSZ_O(operand1) * 8)),
		                                 ILREG_O(operand3)),
		                             il.Const(1, IMM_O(operand4)))));
		break;
	case EXARMO_AARCH64_FABD:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FabdAsisdsamefp16Only:
		case EXARMO_AARCH64_ENC_FabdAsisdsameOnly:
			il.AddInstruction(ILSETREG_O(operand1,
				il.FloatAbs(REGSZ_O(operand1),
					il.FloatSub(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
			break;
		case EXARMO_AARCH64_ENC_FabdAsimdsamefp16Only:
		case EXARMO_AARCH64_ENC_FabdAsimdsameOnly:
			// covered by intrinsics
			break;
		case EXARMO_AARCH64_ENC_FabdZPZz:
		default:
			ABORT_LIFT;
		}
		break;
	case EXARMO_AARCH64_FABS:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FabsDFloatdp1:
		case EXARMO_AARCH64_ENC_FabsSFloatdp1:
		case EXARMO_AARCH64_ENC_FabsHFloatdp1:
			il.AddInstruction(ILSETREG_O(operand1, il.FloatAbs(REGSZ_O(operand1), ILREG_O(operand2))));
			break;
		case EXARMO_AARCH64_ENC_FabsAsimdmiscR:
		case EXARMO_AARCH64_ENC_FabsAsimdmiscfp16R:
			// covered by intrinsics
			break;
		default:
			ABORT_LIFT;
		}
		break;
	case EXARMO_AARCH64_FADD:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FaddHFloatdp2:
		case EXARMO_AARCH64_ENC_FaddSFloatdp2:
		case EXARMO_AARCH64_ENC_FaddDFloatdp2:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.FloatAdd(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
			break;
		case EXARMO_AARCH64_ENC_FaddAsimdsameOnly:
		case EXARMO_AARCH64_ENC_FaddAsimdsamefp16Only:
		{
			if (preferIntrinsics())
				return true;
			Register srcs1[16], srcs2[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src1_n = unpack_vector(operand2, srcs1);
			int src2_n = unpack_vector(operand3, srcs2);
			if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
				ABORT_LIFT;

			int rsize = RegisterSize(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(
					dsts[i], il.FloatAdd(rsize, ILREG(srcs1[i]), ILREG(srcs2[i]))));
			break;
		}
		default:
			ABORT_LIFT;
		}
		break;
	case EXARMO_AARCH64_FADDP:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FaddpAsisdpairOnlyH:
		case EXARMO_AARCH64_ENC_FaddpAsisdpairOnlySd:
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
		case EXARMO_AARCH64_ENC_FaddpAsimdsameOnly:
		case EXARMO_AARCH64_ENC_FaddpAsimdsamefp16Only:
		{
			if (preferIntrinsics())
				return true;

			Register srcs1[16], srcs2[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src1_n = unpack_vector(operand2, srcs1);
			int src2_n = unpack_vector(operand3, srcs2);
			if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
				ABORT_LIFT;

			int rsize = RegisterSize(dsts[0]);
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
		case EXARMO_AARCH64_ENC_FaddpZPZz:
		default:
			ABORT_LIFT;
		}
		break;
	case EXARMO_AARCH64_FCCMP:
	case EXARMO_AARCH64_FCCMPE:
	{
		LowLevelILLabel trueCode, falseCode, done;

		il.AddInstruction(il.If(GetCondition(il, operand4), trueCode, falseCode));

		il.MarkLabel(trueCode);
		il.AddInstruction(il.FloatSub(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1), addr), SETFLAGS));
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
	case EXARMO_AARCH64_FCMP:
	case EXARMO_AARCH64_FCMPE:
		il.AddInstruction(il.FloatSub(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1), addr), SETFLAGS));
		break;
	case EXARMO_AARCH64_FSQRT:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FsqrtDFloatdp1:
		case EXARMO_AARCH64_ENC_FsqrtHFloatdp1:
		case EXARMO_AARCH64_ENC_FsqrtSFloatdp1:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.FloatSqrt(REGSZ_O(operand1), ILREG_O(operand2))));
			break;
		case EXARMO_AARCH64_ENC_FsqrtAsimdmiscfp16R:
		case EXARMO_AARCH64_ENC_FsqrtAsimdmiscR:
			// Intrinsics
			break;
		default:
			ABORT_LIFT;
		}
		break;
	case EXARMO_AARCH64_FSUB:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FsubHFloatdp2:
		case EXARMO_AARCH64_ENC_FsubSFloatdp2:
		case EXARMO_AARCH64_ENC_FsubDFloatdp2:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.FloatSub(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
			break;
		case EXARMO_AARCH64_ENC_FsubAsimdsameOnly:
		case EXARMO_AARCH64_ENC_FsubAsimdsamefp16Only:
		{
			if (preferIntrinsics())
				return true;

			Register srcs[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src_n = unpack_vector(operand2, srcs);
			if ((dst_n != src_n) || dst_n == 0)
				ABORT_LIFT;

			int rsize = RegisterSize(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(dsts[i], il.FloatSub(rsize, ILREG(dsts[i]), ILREG(srcs[i]))));
			break;
		}
		default:
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case EXARMO_AARCH64_FCVT:
	{
		int float_sz = 0;
		switch (encoding)
		{
		/* non-SVE is straight register-to-register */
		case EXARMO_AARCH64_ENC_FcvtHsFloatdp1:  // convert to half (2-byte)
		case EXARMO_AARCH64_ENC_FcvtHdFloatdp1:
			float_sz = 2;
		case EXARMO_AARCH64_ENC_FcvtShFloatdp1:  // convert to single (4-byte)
		case EXARMO_AARCH64_ENC_FcvtSdFloatdp1:
			if (!float_sz)
				float_sz = 4;
		case EXARMO_AARCH64_ENC_FcvtDhFloatdp1:  // convert to double (8-byte)
		case EXARMO_AARCH64_ENC_FcvtDsFloatdp1:
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
	case EXARMO_AARCH64_FDIV:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FdivHFloatdp2:
		case EXARMO_AARCH64_ENC_FdivSFloatdp2:
		case EXARMO_AARCH64_ENC_FdivDFloatdp2:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.FloatDiv(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
			break;
		case EXARMO_AARCH64_ENC_FdivAsimdsamefp16Only:
		case EXARMO_AARCH64_ENC_FdivAsimdsameOnly:
		{
			if (preferIntrinsics())
				return true;

			Register srcs1[16], srcs2[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src1_n = unpack_vector(operand2, srcs1);
			int src2_n = unpack_vector(operand3, srcs2);
			if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
				ABORT_LIFT;
			int rsize = RegisterSize(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(
					dsts[i], il.FloatDiv(rsize, ILREG(srcs1[i]), ILREG(srcs2[i]))));
			break;
		}
		case EXARMO_AARCH64_ENC_FdivZPZz:
		default:
			ABORT_LIFT;
		}
		break;
	case EXARMO_AARCH64_FMOV:

		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_Fmov64vxFloat2int:
			il.AddInstruction(ILSETREG_O(operand1, ILREG(vector_reg_minimize(operands[1]))));
				
			break;
		case EXARMO_AARCH64_ENC_FmovV64iFloat2int:
		{
			Register minreg = vector_reg_minimize(operands[0]);
			il.AddInstruction(il.SetRegister(RegisterSize(minreg), minreg,
			    il.Register(REGSZ_O(operand1), REG_O(operands[1]))));
			break;
		}
		case EXARMO_AARCH64_ENC_Fmov32hFloat2int:
		case EXARMO_AARCH64_ENC_Fmov32sFloat2int:
		case EXARMO_AARCH64_ENC_Fmov64hFloat2int:
		case EXARMO_AARCH64_ENC_Fmov64dFloat2int:
		{
			bool extend = REGSZ_O(operand1) > REGSZ_O(operands[1]);
			ExprId tmp;

			// <Rd> <- <Vn> (copy from FP register to general register, with no conversion)
			if (extend)
				tmp = ILSETREG_O(operand1, il.ZeroExtend(REGSZ_O(operand1), ILREG_O(operands[1])));
			else
				tmp = ILSETREG_O(operand1, ILREG_O(operands[1]));

			il.AddInstruction(tmp);
			break;
		}
		case EXARMO_AARCH64_ENC_FmovD64Float2int:
		case EXARMO_AARCH64_ENC_FmovH32Float2int:
		case EXARMO_AARCH64_ENC_FmovH64Float2int:
		case EXARMO_AARCH64_ENC_FmovS32Float2int:
			// <Vd> <- <Rn> (copy from general register to FP register, with no conversion)
			il.AddInstruction(
			    ILSETREG_O(operand1, il.IntToFloat(REGSZ_O(operand1), ILREG_O(operands[1]))));
			break;
		case EXARMO_AARCH64_ENC_FmovHFloatimm:
		case EXARMO_AARCH64_ENC_FmovSFloatimm:
		case EXARMO_AARCH64_ENC_FmovDFloatimm:
		{
			int float_sz = 2;
			if (encoding == EXARMO_AARCH64_ENC_FmovSFloatimm)
				float_sz = 4;
			if (encoding == EXARMO_AARCH64_ENC_FmovDFloatimm)
				float_sz = 8;
			// Technically, we should use 2 bytes to GetFloat for half-precision registers, but that causes MLIL and HLIL to lift the constant to 0
			il.AddInstruction(ILSETREG_O(operand1, il.FloatConvert(float_sz, GetFloat(il, operand2, float_sz == 2 ? 4 : float_sz))));
			break;
		}
		case EXARMO_AARCH64_ENC_FmovHFloatdp1:
		case EXARMO_AARCH64_ENC_FmovSFloatdp1:
		case EXARMO_AARCH64_ENC_FmovDFloatdp1:
			il.AddInstruction(ILSETREG_O(operand1, ILREG_O(operand2)));
			break;
		case EXARMO_AARCH64_ENC_FmovAsimdimmD2D:
		case EXARMO_AARCH64_ENC_FmovAsimdimmHH:
		case EXARMO_AARCH64_ENC_FmovAsimdimmSS:
		{
			if (preferIntrinsics())
				return true;

			int float_sz = 2;
			if (encoding == EXARMO_AARCH64_ENC_FmovAsimdimmSS)
				float_sz = 4;
			if (encoding == EXARMO_AARCH64_ENC_FmovAsimdimmD2D)
				float_sz = 8;

			Register regs[16];
			int dst_n = unpack_vector(operand1, regs);
			for (int i = 0; i < dst_n; ++i)
				// Technically, we should use 2 bytes to GetFloat for half-precision registers, but that causes MLIL and HLIL to lift the constant to 0
				il.AddInstruction(ILSETREG(regs[i], il.FloatConvert(float_sz, GetFloat(il, operand2, float_sz == 2 ? 4 : float_sz))));
			break;
		}
		default:
			ABORT_LIFT;
		}
		break;
	case EXARMO_AARCH64_FMUL:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FmulHFloatdp2:
		case EXARMO_AARCH64_ENC_FmulSFloatdp2:
		case EXARMO_AARCH64_ENC_FmulDFloatdp2:
			il.AddInstruction(ILSETREG_O(
			    operand1, il.FloatMult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
			break;
		case EXARMO_AARCH64_ENC_FmulAsimdsameOnly:
		case EXARMO_AARCH64_ENC_FmulAsimdsamefp16Only:
		{
			// TODO: the ACLE table names an intrinsic for this where the hand-written one did not,
			// so preferring intrinsics replaces the per-lane lifting below with an opaque call.
			// Decide whether that is wanted before turning this back on.
			// if (preferIntrinsics())
			// 	return true;

			Register srcs1[16], srcs2[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src1_n = unpack_vector(operand2, srcs1);
			int src2_n = unpack_vector(operand3, srcs2);
			if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
				ABORT_LIFT;
			int rsize = RegisterSize(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(
					dsts[i], il.FloatMult(rsize, ILREG(srcs1[i]), ILREG(srcs2[i]))));
			break;
		}
		case EXARMO_AARCH64_ENC_FmulAsimdelemRhH:
		case EXARMO_AARCH64_ENC_FmulAsimdelemRSd:
		case EXARMO_AARCH64_ENC_FmulAsisdelemRhH:
		case EXARMO_AARCH64_ENC_FmulAsisdelemRSd:
		{
			// TODO: the ACLE table names an intrinsic for this where the hand-written one did not,
			// so preferring intrinsics replaces the per-lane lifting below with an opaque call.
			// Decide whether that is wanted before turning this back on.
			// if (preferIntrinsics())
			// 	return true;

			Register srcs1[16], srcs2[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src1_n = unpack_vector(operand2, srcs1);
			int src2_n = unpack_vector(operand3, srcs2);
			if ((dst_n != src1_n) || dst_n == 0 || src2_n != 1)
				ABORT_LIFT;
			int rsize = RegisterSize(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(
					dsts[i], il.FloatMult(rsize, ILREG(srcs1[i]), ILREG(srcs2[0]))));
			break;
		}
		default:
			ABORT_LIFT;
		}
		break;
	case EXARMO_AARCH64_FNEG:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FnegDFloatdp1:
		case EXARMO_AARCH64_ENC_FnegSFloatdp1:
		case EXARMO_AARCH64_ENC_FnegHFloatdp1:
			il.AddInstruction(ILSETREG_O(
				operand1, il.FloatNeg(REGSZ_O(operand1), ILREG_O(operand2))));
			break;
		case EXARMO_AARCH64_ENC_FnegAsimdmiscfp16R:
		case EXARMO_AARCH64_ENC_FnegAsimdmiscR:
		{
			if (preferIntrinsics())
				return true;

			Register srcs[16], dsts[16];
			int dst_n = unpack_vector(operand1, dsts);
			int src_n = unpack_vector(operand2, srcs);
			if ((dst_n != src_n) || dst_n == 0)
				ABORT_LIFT;

			int rsize = RegisterSize(dsts[0]);
			for (int i = 0; i < dst_n; ++i)
				il.AddInstruction(ILSETREG(dsts[i], il.FloatNeg(rsize, ILREG(srcs[i]))));
			break;
		}
		default:
			ABORT_LIFT;
		}
		break;
	case EXARMO_AARCH64_FNMUL:
		il.AddInstruction(ILSETREG_O(operand1,
			il.FloatNeg(REGSZ_O(operand1),
				il.FloatMult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case EXARMO_AARCH64_ERET:
	case EXARMO_AARCH64_ERETAA:
	case EXARMO_AARCH64_ERETAB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_ERET, {}));
		il.AddInstruction(il.Trap(0));
		return false;
	case EXARMO_AARCH64_GMI:
		il.AddInstruction(il.Intrinsic(
			{RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_GMI, {ILREG_O(operand2), ILREG_O(operand3)}));
		break;
	case EXARMO_AARCH64_IRG:
		// `irg x0, x1` writes no Xm, which the decode reports as XZR and so reads as zero.
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_IRG,
			{
				ILREG_O(operand2),
				ILREG_O(operand3),
			}));
		break;
	case EXARMO_AARCH64_ISB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_ISB, {}));
		break;
	case EXARMO_AARCH64_LDAR:
	case EXARMO_AARCH64_LDAPR:
	case EXARMO_AARCH64_LDAPUR:
		LoadStoreOperand(il, true, operands[0], operands[1], 0, addr);
		break;
	case EXARMO_AARCH64_LDARB:
	case EXARMO_AARCH64_LDAPRB:
	case EXARMO_AARCH64_LDAPURB:
		LoadStoreOperandSize(il, true, false, 1, REG_O(operands[0]), operands[1], addr);
		break;
	case EXARMO_AARCH64_LDARH:
	case EXARMO_AARCH64_LDAPRH:
	case EXARMO_AARCH64_LDAPURH:
		LoadStoreOperandSize(il, true, false, 2, REG_O(operands[0]), operands[1], addr);
		break;
	case EXARMO_AARCH64_LDP:
	case EXARMO_AARCH64_LDNP:
		LoadStoreOperandPair(il, true, operands[0], operands[1], operands[2]);
		break;
	case EXARMO_AARCH64_LDPSW:
		LoadStoreOperandPairSize(il, true, 4, operands[0], operands[1], operands[2]);
		break;
	case EXARMO_AARCH64_LDRAA:
	case EXARMO_AARCH64_LDRAB:
		SetPacAttr = true;
	case EXARMO_AARCH64_LDR:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_LdrPBi:
		case EXARMO_AARCH64_ENC_LdrZBi:
		case EXARMO_AARCH64_ENC_LdrZaRi:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
	case EXARMO_AARCH64_LDUR:
		LoadStoreOperand(il, true, operands[0], operands[1], 0, addr);
		if (SetPacAttr)
			ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
		break;
	case EXARMO_AARCH64_LDG:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_LDG,
			{AccessAddress(il, operand2)}));
		break;
	case EXARMO_AARCH64_LDGM:
		il.AddInstruction(
			il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_LDGM, {ILREG_O(operand2)}));
		break;
	case EXARMO_AARCH64_LDRB:
	case EXARMO_AARCH64_LDURB:
		LoadStoreOperandSize(il, true, false, 1, REG_O(operands[0]), operands[1], addr);
		break;
	case EXARMO_AARCH64_LDRH:
	case EXARMO_AARCH64_LDURH:
		LoadStoreOperandSize(il, true, false, 2, REG_O(operands[0]), operands[1], addr);
		break;
	case EXARMO_AARCH64_LDRSB:
	case EXARMO_AARCH64_LDURSB:
	case EXARMO_AARCH64_LDAPURSB:
		LoadStoreOperandSize(il, true, true, 1, REG_O(operands[0]), operands[1], addr);
		break;
	case EXARMO_AARCH64_LDRSH:
	case EXARMO_AARCH64_LDURSH:
	case EXARMO_AARCH64_LDAPURSH:
		LoadStoreOperandSize(il, true, true, 2, REG_O(operands[0]), operands[1], addr);
		break;
	case EXARMO_AARCH64_LDRSW:
	case EXARMO_AARCH64_LDURSW:
	case EXARMO_AARCH64_LDAPURSW:
		LoadStoreOperandSize(il, true, true, 4, REG_O(operands[0]), operands[1], addr);
		break;
	case EXARMO_AARCH64_LDXR:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDXR, { ILREG_O(operand2) }));
		break;
	case EXARMO_AARCH64_LDXRB:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDXRB, { ILREG_O(operand2) }));
		break;
	case EXARMO_AARCH64_LDXRH:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDXRH, { ILREG_O(operand2) }));
		break;
	// We don't have a way to specify intrinsic register size, so we explicitly embed the size in the intrinsic name.
	case EXARMO_AARCH64_LDXP:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)), RegisterOrFlag::Register(REG_O(operand2)) }, ARM64_INTRIN_LDXP, { ILREG_O(operand3) }));
		break;
	case EXARMO_AARCH64_LDAXR:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDAXR, { ILREG_O(operand2) }));
		break;
	case EXARMO_AARCH64_LDAXRB:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDAXRB, { ILREG_O(operand2) }));
		break;
	case EXARMO_AARCH64_LDAXRH:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_LDAXRH, { ILREG_O(operand2) }));
		break;
	case EXARMO_AARCH64_STXR:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STXR, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case EXARMO_AARCH64_STXRB:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STXRB, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case EXARMO_AARCH64_STXRH:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STXRH, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case EXARMO_AARCH64_STXP:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STXP, { ILREG_O(operand2), ILREG_O(operand3), ILREG_O(operand4) }));
		break;
	case EXARMO_AARCH64_STLXR:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STLXR, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case EXARMO_AARCH64_STLXRB:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STLXRB, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case EXARMO_AARCH64_STLXRH:
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(REG_O(operand1)) }, ARM64_INTRIN_STLXRH, { ILREG_O(operand2), ILREG_O(operand3) }));
		break;
	case EXARMO_AARCH64_LD1R:
	case EXARMO_AARCH64_LD2R:
	case EXARMO_AARCH64_LD3R:
	case EXARMO_AARCH64_LD4R:
		if (true || !preferIntrinsics())  // For now, forcibly disable intrinsics (they are incomplete, and this could help dataflow)
			LoadStoreVector(il, true, operands[0], operands[1], true);
		break;
	case EXARMO_AARCH64_LD1:
	case EXARMO_AARCH64_LD2:
	case EXARMO_AARCH64_LD3:
	case EXARMO_AARCH64_LD4:
		if (true || !preferIntrinsics())  // For now, forcibly disable intrinsics (they are incomplete, and this could help dataflow)
			LoadStoreVector(il, true, operands[0], operands[1]);
		break;
	case EXARMO_AARCH64_LDADD:
	case EXARMO_AARCH64_LDADDA:
	case EXARMO_AARCH64_LDADDL:
	case EXARMO_AARCH64_LDADDAL:
	{
		// TODO: represent/annotate (model?) acquire/release memory ordering semantics for all LDADD* instructions

		LoadStoreOperandSize(il, true, false, REGSZ_O(operand2), (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(REGSZ_O(operand2), ILREG_O(operand3),
		    il.Add(REGSZ_O(operand1),
				ILREG_O(operand1),
				il.ZeroExtend(REGSZ_O(operand2),
					il.Register(REGSZ_O(operand2), LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.Register(REGSZ_O(operand2), LLIL_TEMP(0)))));
		break;
	}
	case EXARMO_AARCH64_STADD:
	case EXARMO_AARCH64_STADDL:
		// STADD* are aliases of the corresponding LDADD*, so group them together
		il.AddInstruction(il.Store(REGSZ_O(operand2), ILREG_O(operand2),
		    il.Add(REGSZ_O(operand1), ILREG_O(operand1), il.Load(REGSZ_O(operand1), ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDADDB:
	case EXARMO_AARCH64_LDADDAB:
	case EXARMO_AARCH64_LDADDLB:
	case EXARMO_AARCH64_LDADDALB:
	{
		LoadStoreOperandSize(il, true, false, 1, (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(1, ILREG_O(operand3),
		    il.Add(1, il.LowPart(1, ILREG_O(operand1)), il.LowPart(1, il.Register(1, LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.LowPart(1, il.Register(1, LLIL_TEMP(0))))));
		break;
	}
	case EXARMO_AARCH64_STADDB:
	case EXARMO_AARCH64_STADDLB:
		// STADD* are aliases of the corresponding LDADD*, so group them together
		il.AddInstruction(il.Store(1, ILREG_O(operand2),
		    il.Add(1, il.LowPart(1, ILREG_O(operand1)), il.Load(1, ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDADDH:
	case EXARMO_AARCH64_LDADDAH:
	case EXARMO_AARCH64_LDADDLH:
	case EXARMO_AARCH64_LDADDALH:
	{
		LoadStoreOperandSize(il, true, false, 2, (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(2, ILREG_O(operand3),
		    il.Add(2, il.LowPart(2, ILREG_O(operand1)), il.LowPart(2, il.Register(2, LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.LowPart(2, il.Register(2, LLIL_TEMP(0))))));
		break;
	}
	case EXARMO_AARCH64_STADDH:
	case EXARMO_AARCH64_STADDLH:
		// STADD* are aliases of the corresponding LDADD*, so group them together
		il.AddInstruction(il.Store(2, ILREG_O(operand2),
		    il.Add(2, il.LowPart(2, ILREG_O(operand1)), il.Load(2, ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDCLR:
	case EXARMO_AARCH64_LDCLRA:
	case EXARMO_AARCH64_LDCLRL:
	case EXARMO_AARCH64_LDCLRAL:
	{
		// TODO: represent/annotate (model?) acquire/release memory ordering semantics for all LDCLR* instructions

		LoadStoreOperandSize(il, true, false, REGSZ_O(operand2), (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(REGSZ_O(operand2), ILREG_O(operand3),
		    il.And(REGSZ_O(operand1),
				il.Not(REGSZ_O(operand1), ILREG_O(operand1)),
				il.ZeroExtend(REGSZ_O(operand2),
					il.Register(REGSZ_O(operand2), LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.Register(REGSZ_O(operand2), LLIL_TEMP(0)))));
		break;
	}
	case EXARMO_AARCH64_STCLR:
	case EXARMO_AARCH64_STCLRL:
		// STCLR* are aliases of the corresponding LDCLR*, so group them together
		il.AddInstruction(il.Store(REGSZ_O(operand2), ILREG_O(operand2),
			il.And(REGSZ_O(operand1),
				il.Not(REGSZ_O(operand1), ILREG_O(operand1)),
				il.Load(REGSZ_O(operand1), ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDCLRB:
	case EXARMO_AARCH64_LDCLRAB:
	case EXARMO_AARCH64_LDCLRLB:
	case EXARMO_AARCH64_LDCLRALB:
	{
		LoadStoreOperandSize(il, true, false, 1, (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(1, ILREG_O(operand3),
		    il.And(1, il.Not(1, il.LowPart(1, ILREG_O(operand1))), il.LowPart(1, il.Register(1, LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.LowPart(1, il.Register(1, LLIL_TEMP(0))))));
		break;
	}
	case EXARMO_AARCH64_STCLRB:
	case EXARMO_AARCH64_STCLRLB:
		// STCLR* are aliases of the corresponding LDCLR*, so group them together
		il.AddInstruction(il.Store(1, ILREG_O(operand2),
		    il.And(1, il.Not(1, il.LowPart(1, ILREG_O(operand1))), il.Load(1, ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDCLRH:
	case EXARMO_AARCH64_LDCLRAH:
	case EXARMO_AARCH64_LDCLRLH:
	case EXARMO_AARCH64_LDCLRALH:
	{
		LoadStoreOperandSize(il, true, false, 2, (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(2, ILREG_O(operand3),
		    il.And(2, il.Not(2, il.LowPart(2, ILREG_O(operand1))), il.LowPart(2, il.Register(2, LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.LowPart(2, il.Register(2, LLIL_TEMP(0))))));
		break;
	}
	case EXARMO_AARCH64_STCLRH:
	case EXARMO_AARCH64_STCLRLH:
		// STCLR* are aliases of the corresponding LDCLR*, so group them together
		il.AddInstruction(il.Store(2, ILREG_O(operand2),
		    il.And(2, il.Not(2, il.LowPart(2, ILREG_O(operand1))), il.Load(2, ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDEOR:
	case EXARMO_AARCH64_LDEORA:
	case EXARMO_AARCH64_LDEORL:
	case EXARMO_AARCH64_LDEORAL:
	{
		// TODO: represent/annotate (model?) acquire/release memory ordering semantics for all LDEOR* instructions

		LoadStoreOperandSize(il, true, false, REGSZ_O(operand2), (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(REGSZ_O(operand2), ILREG_O(operand3),
		    il.Xor(REGSZ_O(operand1),
				ILREG_O(operand1),
				il.ZeroExtend(REGSZ_O(operand2),
					il.Register(REGSZ_O(operand2), LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.Register(REGSZ_O(operand2), LLIL_TEMP(0)))));
		break;
	}
	case EXARMO_AARCH64_STEOR:
	case EXARMO_AARCH64_STEORL:
		// STEOR* are aliases of the corresponding LDEOR*, so group them together
		il.AddInstruction(il.Store(REGSZ_O(operand2), ILREG_O(operand2),
		    il.Xor(REGSZ_O(operand1), ILREG_O(operand1), il.Load(REGSZ_O(operand1), ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDEORB:
	case EXARMO_AARCH64_LDEORAB:
	case EXARMO_AARCH64_LDEORLB:
	case EXARMO_AARCH64_LDEORALB:
	{
		LoadStoreOperandSize(il, true, false, 1, (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(1, ILREG_O(operand3),
		    il.Xor(1, il.LowPart(1, ILREG_O(operand1)), il.LowPart(1, il.Register(1, LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.LowPart(1, il.Register(1, LLIL_TEMP(0))))));
		break;
	}
	case EXARMO_AARCH64_STEORB:
	case EXARMO_AARCH64_STEORLB:
		// STEOR* are aliases of the corresponding LDEOR*, so group them together
		il.AddInstruction(il.Store(1, ILREG_O(operand2),
		    il.Xor(1, il.LowPart(1, ILREG_O(operand1)), il.Load(1, ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDEORH:
	case EXARMO_AARCH64_LDEORAH:
	case EXARMO_AARCH64_LDEORLH:
	case EXARMO_AARCH64_LDEORALH:
	{
		LoadStoreOperandSize(il, true, false, 2, (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(2, ILREG_O(operand3),
		    il.Xor(2, il.LowPart(2, ILREG_O(operand1)), il.LowPart(2, il.Register(2, LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.LowPart(2, il.Register(2, LLIL_TEMP(0))))));
		break;
	}
	case EXARMO_AARCH64_STEORH:
	case EXARMO_AARCH64_STEORLH:
		// STEOR* are aliases of the corresponding LDEOR*, so group them together
		il.AddInstruction(il.Store(2, ILREG_O(operand2),
		    il.Xor(2, il.LowPart(2, ILREG_O(operand1)), il.Load(2, ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDSET:
	case EXARMO_AARCH64_LDSETA:
	case EXARMO_AARCH64_LDSETL:
	case EXARMO_AARCH64_LDSETAL:
	{
		// TODO: represent/annotate (model?) acquire/release memory ordering semantics for all LDSET* instructions

		LoadStoreOperandSize(il, true, false, REGSZ_O(operand2), (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(REGSZ_O(operand2), ILREG_O(operand3),
		    il.Or(REGSZ_O(operand1),
				ILREG_O(operand1),
				il.ZeroExtend(REGSZ_O(operand2),
					il.Register(REGSZ_O(operand2), LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.Register(REGSZ_O(operand2), LLIL_TEMP(0)))));
		break;
	}
	case EXARMO_AARCH64_STSET:
	case EXARMO_AARCH64_STSETL:
		// STSET* are aliases of the corresponding LDSET*, so group them together
		il.AddInstruction(il.Store(REGSZ_O(operand2), ILREG_O(operand2),
		    il.Or(REGSZ_O(operand1), ILREG_O(operand1), il.Load(REGSZ_O(operand1), ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDSETB:
	case EXARMO_AARCH64_LDSETAB:
	case EXARMO_AARCH64_LDSETLB:
	case EXARMO_AARCH64_LDSETALB:
	{
		LoadStoreOperandSize(il, true, false, 1, (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(1, ILREG_O(operand3),
		    il.Or(1, il.LowPart(1, ILREG_O(operand1)), il.LowPart(1, il.Register(1, LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.LowPart(1, il.Register(1, LLIL_TEMP(0))))));
		break;
	}
	case EXARMO_AARCH64_STSETB:
	case EXARMO_AARCH64_STSETLB:
		// STSET* are aliases of the corresponding LDSET*, so group them together
		il.AddInstruction(il.Store(1, ILREG_O(operand2),
		    il.Or(1, il.LowPart(1, ILREG_O(operand1)), il.Load(1, ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LDSETH:
	case EXARMO_AARCH64_LDSETAH:
	case EXARMO_AARCH64_LDSETLH:
	case EXARMO_AARCH64_LDSETALH:
	{
		LoadStoreOperandSize(il, true, false, 2, (Register)LLIL_TEMP(0), operand3, addr);
		il.AddInstruction(il.Store(2, ILREG_O(operand3),
		    il.Or(2, il.LowPart(2, ILREG_O(operand1)), il.LowPart(2, il.Register(2, LLIL_TEMP(0))))));
		if (!IS_ZERO_REG(REG_O(operand2)))
			il.AddInstruction(ILSETREG_O(operand2,
				il.ZeroExtend(REGSZ_O(operand2),
					il.LowPart(2, il.Register(2, LLIL_TEMP(0))))));
		break;
	}
	case EXARMO_AARCH64_STSETH:
	case EXARMO_AARCH64_STSETLH:
		// STSET* are aliases of the corresponding LDSET*, so group them together
		il.AddInstruction(il.Store(2, ILREG_O(operand2),
		    il.Or(2, il.LowPart(2, ILREG_O(operand1)), il.Load(2, ILREG_O(operand2)))));
		break;
	case EXARMO_AARCH64_LSL:
		il.AddInstruction(ILSETREG_O(operand1, il.ShiftLeft(REGSZ_O(operand2), ILREG_O(operand2),
		                                           ReadILOperand(il, operand3, REGSZ_O(operand2), addr))));
		break;
	case EXARMO_AARCH64_LSR:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.LogicalShiftRight(REGSZ_O(operand2), ILREG_O(operand2),
		                             ReadILOperand(il, operand3, REGSZ_O(operand2), addr))));
		break;
	case EXARMO_AARCH64_MOV:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_MovzPPPAndPPPpZ:
		case EXARMO_AARCH64_ENC_MovZOICpyZOI:
		case EXARMO_AARCH64_ENC_MovZPICpyZPI:
		case EXARMO_AARCH64_ENC_MovZPRCpyZPR:
		case EXARMO_AARCH64_ENC_MovZPVCpyZPV:
		case EXARMO_AARCH64_ENC_MovZIDupZI:
		case EXARMO_AARCH64_ENC_MovZRDupZR:
		case EXARMO_AARCH64_ENC_MovZVDupZZi:
		case EXARMO_AARCH64_ENC_MovZZiDupZZi:
		case EXARMO_AARCH64_ENC_MovZMDupmZI:
		case EXARMO_AARCH64_ENC_MovMz2ZaB1MovaMz2ZaB1:
		case EXARMO_AARCH64_ENC_MovMz2ZaH1MovaMz2ZaH1:
		case EXARMO_AARCH64_ENC_MovMz2ZaW1MovaMz2ZaW1:
		case EXARMO_AARCH64_ENC_MovMz2ZaD1MovaMz2ZaD1:
		case EXARMO_AARCH64_ENC_MovMz4ZaB1MovaMz4ZaB1:
		case EXARMO_AARCH64_ENC_MovMz4ZaH1MovaMz4ZaH1:
		case EXARMO_AARCH64_ENC_MovMz4ZaW1MovaMz4ZaW1:
		case EXARMO_AARCH64_ENC_MovMz4ZaD1MovaMz4ZaD1:
		case EXARMO_AARCH64_ENC_MovMzZa21MovaMzZa21:
		case EXARMO_AARCH64_ENC_MovMzZa41MovaMzZa41:
		case EXARMO_AARCH64_ENC_MovZPRzaBMovaZPRzaB:
		case EXARMO_AARCH64_ENC_MovZPRzaHMovaZPRzaH:
		case EXARMO_AARCH64_ENC_MovZPRzaWMovaZPRzaW:
		case EXARMO_AARCH64_ENC_MovZPRzaDMovaZPRzaD:
		case EXARMO_AARCH64_ENC_MovZPRzaQMovaZPRzaQ:
		case EXARMO_AARCH64_ENC_MovZa2ZB1MovaZa2ZB1:
		case EXARMO_AARCH64_ENC_MovZa2ZH1MovaZa2ZH1:
		case EXARMO_AARCH64_ENC_MovZa2ZW1MovaZa2ZW1:
		case EXARMO_AARCH64_ENC_MovZa2ZD1MovaZa2ZD1:
		case EXARMO_AARCH64_ENC_MovZa4ZB1MovaZa4ZB1:
		case EXARMO_AARCH64_ENC_MovZa4ZH1MovaZa4ZH1:
		case EXARMO_AARCH64_ENC_MovZa4ZW1MovaZa4ZW1:
		case EXARMO_AARCH64_ENC_MovZa4ZD1MovaZa4ZD1:
		case EXARMO_AARCH64_ENC_MovZaMz21MovaZaMz21:
		case EXARMO_AARCH64_ENC_MovZaMz41MovaZaMz41:
		case EXARMO_AARCH64_ENC_MovZaPRzBMovaZaPRzB:
		case EXARMO_AARCH64_ENC_MovZaPRzHMovaZaPRzH:
		case EXARMO_AARCH64_ENC_MovZaPRzWMovaZaPRzW:
		case EXARMO_AARCH64_ENC_MovZaPRzDMovaZaPRzD:
		case EXARMO_AARCH64_ENC_MovZaPRzQMovaZaPRzQ:
		case EXARMO_AARCH64_ENC_MovPPOrrPPPpZ:
		case EXARMO_AARCH64_ENC_MovZZOrrZZz:
		case EXARMO_AARCH64_ENC_MovmPPPSelPPPp:
		case EXARMO_AARCH64_ENC_MovZPZSelZPZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
	case EXARMO_AARCH64_DUP:
	case EXARMO_AARCH64_MOVN:
	case EXARMO_AARCH64_UMOV:
	case EXARMO_AARCH64_INS:
	case EXARMO_AARCH64_MOVS:
	{
		bool zero_extend = false;
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_DupAsimdinsDrR:
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
		case EXARMO_AARCH64_ENC_DupAsimdinsDvV:
			// Lifted as its ACLE intrinsic.
			break;
		case EXARMO_AARCH64_ENC_MovUmovAsimdinsWW:
		case EXARMO_AARCH64_ENC_MovUmovAsimdinsXX:
		case EXARMO_AARCH64_ENC_UmovAsimdinsWW:
		case EXARMO_AARCH64_ENC_UmovAsimdinsXX:
			zero_extend = true;
		case EXARMO_AARCH64_ENC_MovDupAsisdoneOnly:
		case EXARMO_AARCH64_ENC_DupAsisdoneOnly:
		case EXARMO_AARCH64_ENC_MovInsAsimdinsIvV:
		case EXARMO_AARCH64_ENC_InsAsimdinsIvV:
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
		case EXARMO_AARCH64_ENC_MovMovn32Movewide:
		case EXARMO_AARCH64_ENC_MovMovn64Movewide:
		case EXARMO_AARCH64_ENC_Movn32Movewide:
		case EXARMO_AARCH64_ENC_Movn64Movewide:
			il.AddInstruction(ILSETREG_O(operand1,
				ReadILOperand(il, operand2, REGSZ_O(operand1), addr)));
			break;
		case EXARMO_AARCH64_ENC_MovInsAsimdinsIrR:
		case EXARMO_AARCH64_ENC_InsAsimdinsIrR:
		case EXARMO_AARCH64_ENC_MovOrr32LogImm:
		case EXARMO_AARCH64_ENC_MovOrr32LogShift:
		case EXARMO_AARCH64_ENC_MovOrr64LogImm:
		case EXARMO_AARCH64_ENC_MovOrr64LogShift:
		case EXARMO_AARCH64_ENC_MovAdd32AddsubImm:
		case EXARMO_AARCH64_ENC_MovAdd64AddsubImm:
		case EXARMO_AARCH64_ENC_MovOrrAsimdsameOnly:
		case EXARMO_AARCH64_ENC_MovMovz32Movewide:
		case EXARMO_AARCH64_ENC_MovMovz64Movewide:
		{
			Register regs[16];
			int n = unpack_vector(operand1, regs);

			if (n == 1) {
				il.AddInstruction(ILSETREG(regs[0], ReadILOperand(il, operand2, RegisterSize(regs[0]), addr)));
			} else {
				Register cregs[2];
				if (consolidate_vector(operand1, operand2, cregs))
					il.AddInstruction(ILSETREG(cregs[0], ILREG(cregs[1])));
				else
					ABORT_LIFT;
			}
			break;
		}
		case EXARMO_AARCH64_ENC_PselPPpi:
		case EXARMO_AARCH64_ENC_DupZI:
		case EXARMO_AARCH64_ENC_DupZR:
		case EXARMO_AARCH64_ENC_DupZZi:
		default:
			break;
		}
		break;
	}
	case EXARMO_AARCH64_MOVI:
	{
		Register regs[16];
		int n = unpack_vector(operand1, regs);
		for (int i = 0; i < n; ++i)
			il.AddInstruction(ILSETREG(regs[i], ILCONST_O(RegisterSize(regs[i]), operand2)));
		break;
	}
	case EXARMO_AARCH64_MVN:
	case EXARMO_AARCH64_MVNI:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Not(REGSZ_O(operand1), ReadILOperand(il, operand2, REGSZ_O(operand1), addr))));
		break;
	case EXARMO_AARCH64_MOVK:
		// zero the underling register slice
		il.AddInstruction(ILSETREG_O(
		    operand1, il.And(REGSZ_O(operand1), ILREG_O(operand1),
			    il.Const(REGSZ_O(operand1), ~(0xffffULL << OperandModifier(operand2).amount)))));
		// mov the immediate into it
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Or(REGSZ_O(operand1), ILREG_O(operand1),
		                  il.Const(REGSZ_O(operand1), IMM_O(operand2) << OperandModifier(operand2).amount))));
		break;
	case EXARMO_AARCH64_MOVZ:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.Const(REGSZ_O(operand1), IMM_O(operand2) << OperandModifier(operand2).amount)));
		break;
	case EXARMO_AARCH64_MUL:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_MulZPZz:
		case EXARMO_AARCH64_ENC_MulZZi:
		case EXARMO_AARCH64_ENC_MulZZz:
		case EXARMO_AARCH64_ENC_MulZZziH:
		case EXARMO_AARCH64_ENC_MulZZziS:
		case EXARMO_AARCH64_ENC_MulZZziD:
		case EXARMO_AARCH64_ENC_MulAsimdsameOnly:
		case EXARMO_AARCH64_ENC_MulAsimdelemR:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default:
			il.AddInstruction(
				ILSETREG_O(operand1, il.Mult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3))));
		}
		break;
	case EXARMO_AARCH64_MADD:
	case EXARMO_AARCH64_MADDPT:  // FEAT_CPA checked multiply-add, lifted as if checking is disabled
		il.AddInstruction(ILSETREG_O(operand1,
		    ILADDREG_O(operand4, il.Mult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case EXARMO_AARCH64_MRS:
	{
		SystemRegister sysreg = ToSystemRegister(operand2.sysreg);
		uint32_t reg = sysreg.Value();

		if (SystemRegisterName(sysreg).empty())
		{
			LogDebug("MSR Unknown system register %d @ 0x%" PRIx64
					": S%d_%d_c%d_c%d_%d",
				reg, addr, operand2.sysreg.op0, operand2.sysreg.op1, operand2.sysreg.crn,
				operand2.sysreg.crm, operand2.sysreg.op2);
		}

		if (IS_ZERO_REG(REG_O(operand1))) {
			il.AddInstruction(
			    il.Intrinsic({}, ARM64_INTRIN_MRS, {il.Const(4, reg)}));
		} else {
			il.AddInstruction(
			    il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_MRS, {il.Const(4, reg)}));
		}
		break;
	}
	case EXARMO_AARCH64_MSUB:
	case EXARMO_AARCH64_MSUBPT:  // FEAT_CPA checked multiply-subtract, lifted as if checking is disabled
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Sub(REGSZ_O(operand1), ILREG_O(operand4),
		                  il.Mult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case EXARMO_AARCH64_MNEG:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Sub(REGSZ_O(operand1), il.Const(8, 0),
		                  il.Mult(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case EXARMO_AARCH64_MSR:
	{
		// MSR (immediate) writes a PSTATE field, which has no register number. Pass the field's
		// encoding.
		if (operand1.kind == EXARMO_AARCH64_OPERAND_SYSOP)
		{
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_MSR_IMM,
			    {il.Const(4, SystemOperationNumber(operand1)),
			        il.Const(4, IMM_O(operand2))}));
			break;
		}

		uint32_t dst = ToSystemRegister(operand1.sysreg).Value();

		if (SystemRegisterName(SystemRegister(dst)).empty())
		{
			LogDebug("MSR Unknown system register %d @ 0x%" PRIx64 ": S%d_%d_c%d_c%d_%d", dst, addr,
			    operand1.sysreg.op0, operand1.sysreg.op1, operand1.sysreg.crn, operand1.sysreg.crm,
			    operand1.sysreg.op2);
		}

		switch (operand2.kind)
		{
		case EXARMO_AARCH64_OPERAND_REG:
			il.AddInstruction( il.Intrinsic({}, ARM64_INTRIN_MSR, {il.Const(4, dst), ILREG_O(operand2)}));
			break;
		default:
			LogError("unknown MSR operand kind: %x\n", operand2.kind);
			break;
		}
		break;
	}
	case EXARMO_AARCH64_NEG:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_NegAsisdmiscR:
		case EXARMO_AARCH64_ENC_NegAsimdmiscR:
		case EXARMO_AARCH64_ENC_NegZPZM:
		case EXARMO_AARCH64_ENC_NegZPZZ:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
	case EXARMO_AARCH64_NEGS:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Neg(REGSZ_O(operand1), ReadILOperand(il, operands[1], REGSZ_O(operand1), addr),
		                  SETFLAGS)));
		break;
	case EXARMO_AARCH64_NGC:
	case EXARMO_AARCH64_NGCS:
		il.AddInstruction(ILSETREG_O(operand1, il.SubBorrow(REGSZ_O(operand1), il.Const(REGSZ_O(operand1), 0),
		                                           ReadILOperand(il, operand2, REGSZ_O(operand1), addr),
		                                           il.Not(0, il.Flag(IL_FLAG_C)), SETFLAGS)));
		break;
	case EXARMO_AARCH64_NOP:
		il.AddInstruction(il.Nop());
		break;

#ifdef LIFT_PAC_AS_INTRINSIC
	case EXARMO_AARCH64_AUTDA:
	case EXARMO_AARCH64_AUTDB:
	case EXARMO_AARCH64_AUTIA:
	case EXARMO_AARCH64_AUTIB:
	case EXARMO_AARCH64_PACDA:
	case EXARMO_AARCH64_PACDB:
	case EXARMO_AARCH64_PACIA:
	case EXARMO_AARCH64_PACIB:
		// <Xd> is address, <Xn> is modifier
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))},
		    mnemonic_to_intrinsic(mnemonic), {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case EXARMO_AARCH64_PACGA:
		// <Xd> is address, <Xn>, <Xm> are modifiers, keys
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))},
		    mnemonic_to_intrinsic(mnemonic), {ILREG_O(operand2), ILREG_O(operand3)}));
		break;
	case EXARMO_AARCH64_AUTIA1716:
	case EXARMO_AARCH64_AUTIB1716:
	case EXARMO_AARCH64_PACIA1716:
	case EXARMO_AARCH64_PACIB1716:
		// x17 is address, x16 is modifier
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X17)},
		    mnemonic_to_intrinsic(mnemonic), {il.Register(8, REG_X17), il.Register(8, REG_X16)}));
		break;
	case EXARMO_AARCH64_AUTDZA:
	case EXARMO_AARCH64_AUTDZB:
	case EXARMO_AARCH64_AUTIZA:
	case EXARMO_AARCH64_AUTIZB:
	case EXARMO_AARCH64_PACDZA:
	case EXARMO_AARCH64_PACDZB:
	case EXARMO_AARCH64_PACIZA:
	case EXARMO_AARCH64_PACIZB:
		// <Xd> is address, modifier is 0
		il.AddInstruction(il.Intrinsic(
		    {RegisterOrFlag::Register(REG_O(operand1))}, mnemonic_to_intrinsic(mnemonic), {ILREG_O(operand1), il.Const(8, 0)}));
		break;
	case EXARMO_AARCH64_XPACI:
	case EXARMO_AARCH64_XPACD:
		// <Xd> is address
		il.AddInstruction(il.Intrinsic(
		    {RegisterOrFlag::Register(REG_O(operand1))}, mnemonic_to_intrinsic(mnemonic), {ILREG_O(operand1)}));
		break;
	case EXARMO_AARCH64_AUTIAZ:
	case EXARMO_AARCH64_AUTIBZ:
	case EXARMO_AARCH64_PACIAZ:
	case EXARMO_AARCH64_PACIBZ:
		// x30 is address, modifier is 0
		il.AddInstruction(il.Intrinsic(
		    {RegisterOrFlag::Register(REG_X30)}, mnemonic_to_intrinsic(mnemonic), {il.Register(8, REG_X30), il.Const(8, 0)}));
		break;
	case EXARMO_AARCH64_XPACLRI:
		// x30 is address
		il.AddInstruction(il.Intrinsic(
		    {RegisterOrFlag::Register(REG_X30)}, mnemonic_to_intrinsic(mnemonic), {il.Register(8, REG_X30)}));
		break;
	case EXARMO_AARCH64_AUTIASP:
	case EXARMO_AARCH64_AUTIBSP:
	case EXARMO_AARCH64_PACIASP:
	case EXARMO_AARCH64_PACIBSP:
		// x30 is address, sp is modifier
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X30)},
		    mnemonic_to_intrinsic(mnemonic), {il.Register(8, REG_X30), il.Register(8, REG_SP)}));
		break;
	case EXARMO_AARCH64_AUTIA171615:
	case EXARMO_AARCH64_AUTIB171615:
	case EXARMO_AARCH64_PACIA171615:
	case EXARMO_AARCH64_PACIB171615:
		// x17 is address, x16 and x15 are the modifiers
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X17)},
		    mnemonic_to_intrinsic(mnemonic),
		    {il.Register(8, REG_X17), il.Register(8, REG_X16), il.Register(8, REG_X15)}));
		break;
	case EXARMO_AARCH64_PACIASPPC:
	case EXARMO_AARCH64_PACIBSPPC:
	case EXARMO_AARCH64_PACNBIASPPC:
	case EXARMO_AARCH64_PACNBIBSPPC:
		// x30 is address, sp and this instruction's own address are the modifiers
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X30)},
		    mnemonic_to_intrinsic(mnemonic),
		    {il.Register(8, REG_X30), il.Register(8, REG_SP), il.ConstPointer(addrSize, addr)}));
		break;
	case EXARMO_AARCH64_AUTIASPPCR:
	case EXARMO_AARCH64_AUTIBSPPCR:
		// x30 is address, sp and <Xn> are the modifiers
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X30)},
		    mnemonic_to_intrinsic(mnemonic),
		    {il.Register(8, REG_X30), il.Register(8, REG_SP), ILREG_O(operand1)}));
		break;
	case EXARMO_AARCH64_AUTIASPPC:
	case EXARMO_AARCH64_AUTIBSPPC:
		// x30 is address, sp and <label> are the modifiers
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X30)},
		    mnemonic_to_intrinsic(mnemonic),
		    {il.Register(8, REG_X30), il.Register(8, REG_SP), il.ConstPointer(addrSize, LabelTarget(operand1, addr))}));
		break;
#else
	case EXARMO_AARCH64_AUTDA:
	case EXARMO_AARCH64_AUTDB:
	case EXARMO_AARCH64_AUTIA:
	case EXARMO_AARCH64_AUTIB:
	case EXARMO_AARCH64_PACDA:
	case EXARMO_AARCH64_PACDB:
	case EXARMO_AARCH64_PACIA:
	case EXARMO_AARCH64_PACIB:
	case EXARMO_AARCH64_PACGA:
	case EXARMO_AARCH64_AUTIA1716:
	case EXARMO_AARCH64_AUTIB1716:
	case EXARMO_AARCH64_PACIA1716:
	case EXARMO_AARCH64_PACIB1716:
	case EXARMO_AARCH64_AUTDZA:
	case EXARMO_AARCH64_AUTDZB:
	case EXARMO_AARCH64_AUTIZA:
	case EXARMO_AARCH64_AUTIZB:
	case EXARMO_AARCH64_PACDZA:
	case EXARMO_AARCH64_PACDZB:
	case EXARMO_AARCH64_PACIZA:
	case EXARMO_AARCH64_PACIZB:
	case EXARMO_AARCH64_XPACI:
	case EXARMO_AARCH64_XPACD:
	case EXARMO_AARCH64_AUTIAZ:
	case EXARMO_AARCH64_AUTIBZ:
	case EXARMO_AARCH64_PACIAZ:
	case EXARMO_AARCH64_PACIBZ:
	case EXARMO_AARCH64_XPACLRI:
	case EXARMO_AARCH64_AUTIASP:
	case EXARMO_AARCH64_AUTIBSP:
	case EXARMO_AARCH64_PACIASP:
	case EXARMO_AARCH64_PACIBSP:
	case EXARMO_AARCH64_AUTIA171615:
	case EXARMO_AARCH64_AUTIB171615:
	case EXARMO_AARCH64_PACIA171615:
	case EXARMO_AARCH64_PACIB171615:
	case EXARMO_AARCH64_AUTIASPPC:
	case EXARMO_AARCH64_AUTIBSPPC:
	case EXARMO_AARCH64_AUTIASPPCR:
	case EXARMO_AARCH64_AUTIBSPPCR:
	case EXARMO_AARCH64_PACIASPPC:
	case EXARMO_AARCH64_PACIBSPPC:
	case EXARMO_AARCH64_PACNBIASPPC:
	case EXARMO_AARCH64_PACNBIBSPPC:
		il.AddInstruction(il.Nop());
		ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
		break;
#endif
	case EXARMO_AARCH64_PRFUM:
	case EXARMO_AARCH64_PRFM:
		// TODO use the PRFM types when we have a better option than defining 18 different intrinsics to
		// account for:
		// - 3 types {PLD, PLI, PST}
		// - 3 targets {L1, L2, L3}
		// - 2 policies {KEEP, STM}
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_PRFM, {ReadILOperand(il, operand2, 8, addr)}));
		break;
	case EXARMO_AARCH64_ORN:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_OrnPPPpZ:
			if (!preferIntrinsics())
					il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Or(REGSZ_O(operand1), ILREG_O(operand2),
		                  il.Not(REGSZ_O(operand1), ReadILOperand(il, operand3, REGSZ_O(operand1), addr)))));
		break;
	case EXARMO_AARCH64_ORR:
	case EXARMO_AARCH64_ORRS:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_Orr32LogImm:
		case EXARMO_AARCH64_ENC_Orr32LogShift:
		case EXARMO_AARCH64_ENC_Orr64LogImm:
		case EXARMO_AARCH64_ENC_Orr64LogShift:
			il.AddInstruction(
				ILSETREG_O(operand1, il.Or(REGSZ_O(operand1), ILREG_O(operand2),
										ReadILOperand(il, operand3, REGSZ_O(operand1), addr), SETFLAGS)));
			break;
		case EXARMO_AARCH64_ENC_OrrAsimdimmLHl:
		case EXARMO_AARCH64_ENC_OrrAsimdimmLSl:
		{
			Register regs[16];
			int n = unpack_vector(operand1, regs);
			for (int i = 0; i < n; ++i)
				il.AddInstruction(ILSETREG(regs[i], ILCONST_O(RegisterSize(regs[i]), operand2)));
			break;
		}
		case EXARMO_AARCH64_ENC_OrrAsimdsameOnly:
			// Lifted as its ACLE intrinsic.
			break;
		case EXARMO_AARCH64_ENC_OrrPPPpZ:
		case EXARMO_AARCH64_ENC_OrrZPZz:
		case EXARMO_AARCH64_ENC_OrrZZi:
		case EXARMO_AARCH64_ENC_OrrZZz:
		default:
			ABORT_LIFT;
		}
		break;
	case EXARMO_AARCH64_PSB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_PSBCSYNC, {}));
		break;
	case EXARMO_AARCH64_RETAASPPC:
	case EXARMO_AARCH64_RETABSPPC:
	case EXARMO_AARCH64_RETAASPPCR:
	case EXARMO_AARCH64_RETABSPPCR:
		// Unlike RET, the operand here is an authentication modifier. These always
		// return to x30.
		il.AddInstruction(il.Return(il.Register(8, REG_X30)));
		ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
		break;
	case EXARMO_AARCH64_RETAA:
	case EXARMO_AARCH64_RETAB:
		SetPacAttr = true;
	case EXARMO_AARCH64_RET:
	{
		ExprId reg = (IS_REG_O(operand1)) ? ILREG_O(operand1) : il.Register(8, REG_X30);
		il.AddInstruction(il.Return(reg));
		if (SetPacAttr)
			ApplyAttributeToLastInstruction(il, SrcInstructionUsesPointerAuth);
	}
	break;
	case EXARMO_AARCH64_REVB:  // SVE only
	case EXARMO_AARCH64_REVH:
	case EXARMO_AARCH64_REVW:
		il.AddInstruction(il.Unimplemented());
		break;
	case EXARMO_AARCH64_REV16:
		switch (encoding) {
		case EXARMO_AARCH64_ENC_Rev16AsimdmiscR:
			break;
		default:
			if (IS_SVE_O(operand1))
			{
				il.AddInstruction(il.Unimplemented());
				break;
			}
			if (REGSZ_O(operand1) == 4)
			{
				// A 32-bit register holds two 16-bit lanes, so reversing the bytes within each lane is
				// a full byte reversal rotated by one halfword
				il.AddInstruction(ILSETREG_O(operand1,
					il.RotateRight(4, il.ByteSwap(4, ILREG_O(operand2)), il.Const(1, 16))));
			}
			else
			{
				// A 64-bit register holds four 16-bit lanes; reversing the bytes within each lane has
				// no native representation and is lifted as an intrinsic
				il.AddInstruction(il.Intrinsic(
					{RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_REV16, {ILREG_O(operand2)}));
			}
		}
		break;
	case EXARMO_AARCH64_REV32:
		switch (encoding) {
		case EXARMO_AARCH64_ENC_Rev32AsimdmiscR:
			break;
		default:
			if (IS_SVE_O(operand1))
			{
				il.AddInstruction(il.Unimplemented());
				break;
			}
			// REV32 reverses bytes within each 32-bit lane; a 64-bit register holds two such lanes,
			// so it is a full byte reversal rotated by one word
			il.AddInstruction(ILSETREG_O(operand1,
				il.RotateRight(8, il.ByteSwap(8, ILREG_O(operand2)), il.Const(1, 32))));
		}
		break;
	case EXARMO_AARCH64_REV64:
	case EXARMO_AARCH64_REV:
		switch (encoding) {
		case EXARMO_AARCH64_ENC_Rev64AsimdmiscR:
			break;
		default:
			if (IS_SVE_O(operand1))
			{
				il.AddInstruction(il.Unimplemented());
				break;
			}
			il.AddInstruction(ILSETREG_O(operand1, il.ByteSwap(REGSZ_O(operand2), ILREG_O(operand2))));
		}
		break;
	case EXARMO_AARCH64_RBIT:
		switch (encoding) {
		case EXARMO_AARCH64_ENC_RbitAsimdmiscR:
			break;
		default:
			il.AddInstruction(ILSETREG_O(operand1, il.ReverseBits(REGSZ_O(operand2), ILREG_O(operand2))));
		}
		break;
	case EXARMO_AARCH64_ROR:
		il.AddInstruction(ILSETREG_O(operand1, il.RotateRight(REGSZ_O(operand2), ILREG_O(operand2),
		                                           ReadILOperand(il, operand3, REGSZ_O(operand2), addr))));
		break;
	case EXARMO_AARCH64_SBC:
	case EXARMO_AARCH64_SBCS:
		il.AddInstruction(ILSETREG_O(operand1, il.SubBorrow(REGSZ_O(operand1), ILREG_O(operand2),
		                                           ReadILOperand(il, operand3, REGSZ_O(operand1), addr),
		                                           il.Not(0, il.Flag(IL_FLAG_C)), SETFLAGS)));
		break;
	case EXARMO_AARCH64_SBFIZ:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.ArithShiftRight(REGSZ_O(operand1),
		                  il.ShiftLeft(REGSZ_O(operand1), ExtractBits(il, operand2, IMM_O(operand4), 0),
		                      il.Const(1, (REGSZ_O(operand1) * 8) - IMM_O(operand4))),
		                  il.Const(1, (REGSZ_O(operand1) * 8) - IMM_O(operand3) - IMM_O(operand4)))));
		break;
	case EXARMO_AARCH64_SBFX:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.ArithShiftRight(REGSZ_O(operand1),
		                  il.ShiftLeft(REGSZ_O(operand1),
		                      ExtractBits(il, operand2, IMM_O(operand4), IMM_O(operand3)),
		                      il.Const(1, (REGSZ_O(operand1) * 8) - IMM_O(operand4) - IMM_O(operand3))),
		                  il.Const(1, (REGSZ_O(operand1) * 8) - IMM_O(operand4)))));
		break;
	// Lift the forms that write a general register directly in IL. The forms that write a vector
	// register fall through to the ACLE lift.
	case EXARMO_AARCH64_FCVTZS:
	case EXARMO_AARCH64_FCVTZU:
	case EXARMO_AARCH64_FCVTMS:
	case EXARMO_AARCH64_FCVTMU:
	case EXARMO_AARCH64_FCVTNS:
	case EXARMO_AARCH64_FCVTNU:
	case EXARMO_AARCH64_FCVTPS:
	case EXARMO_AARCH64_FCVTPU:
	{
		if (!IS_REG_O(operand1) || !(IS_W_REG(REG_O(operand1)) || IS_X_REG(REG_O(operand1))))
			break;

		size_t sourceSize = REGSZ_O(operand2);
		size_t size = FixedPointSize(sourceSize);
		ExprId value = ILREG_O(operand2);
		if (size != sourceSize)
			value = il.FloatConvert(size, value);

		// A third operand is the shift scaling the value before it is truncated.
		if (operandCount > 2)
		{
			value = il.FloatMult(
			    size, value, FixedPointScale(il, size, (uint32_t)IMM_O(operand3)));
		}

		switch (mnemonic)
		{
		case EXARMO_AARCH64_FCVTMS:
		case EXARMO_AARCH64_FCVTMU:
			value = il.Floor(size, value);
			break;
		case EXARMO_AARCH64_FCVTPS:
		case EXARMO_AARCH64_FCVTPU:
			value = il.Ceil(size, value);
			break;
		case EXARMO_AARCH64_FCVTNS:
		case EXARMO_AARCH64_FCVTNU:
			value = il.RoundToInt(size, value);
			break;
		// FCVTZS and FCVTZU round toward zero, which is what the truncation already does.
		default:
			break;
		}

		il.AddInstruction(ILSETREG_O(operand1, il.FloatToInt(REGSZ_O(operand1), value)));
		break;
	}
	// FCVTAS and FCVTAU round ties away from zero, but RoundToInt rounds ties to even.
	case EXARMO_AARCH64_FCVTAS:
	case EXARMO_AARCH64_FCVTAU:
	// FMAX and FMIN return NaN if either input is NaN, and FMAXNM and FMINNM return the number. No
	// IL operation matches either.
	case EXARMO_AARCH64_FMAX:
	case EXARMO_AARCH64_FMIN:
	case EXARMO_AARCH64_FMAXNM:
	case EXARMO_AARCH64_FMINNM:
	{
		if (!IS_REG_O(operand1) || IS_ASIMD_O(operand1))
			break;

		// ACLE covers every scalar FCVTAS and FCVTAU form and the half and double forms of FMAX and
		// friends. That leaves single precision to the plugin's intrinsics.
		if (AcleGetLowLevelILForInstruction(il, instr, operands))
			break;

		if (mnemonic == EXARMO_AARCH64_FCVTAS || mnemonic == EXARMO_AARCH64_FCVTAU
		    || REGSZ_O(operand1) != 4)
			ABORT_LIFT;

		uint32_t intrinsic;
		switch (mnemonic)
		{
		case EXARMO_AARCH64_FMAX:
			intrinsic = ARM64_INTRIN_FMAX;
			break;
		case EXARMO_AARCH64_FMIN:
			intrinsic = ARM64_INTRIN_FMIN;
			break;
		case EXARMO_AARCH64_FMAXNM:
			intrinsic = ARM64_INTRIN_FMAXNM;
			break;
		default:
			intrinsic = ARM64_INTRIN_FMINNM;
			break;
		}

		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, intrinsic,
		    {ILREG_O(operand2), ILREG_O(operand3)}));
		break;
	}
	// ACLE covers the half, double and vector forms. For single precision, lift FRINTZ, FRINTM and
	// FRINTP as IL, and the other roundings and FMADD and FMSUB as the plugin's intrinsics.
	case EXARMO_AARCH64_FRINTA:
	case EXARMO_AARCH64_FRINTI:
	case EXARMO_AARCH64_FRINTM:
	case EXARMO_AARCH64_FRINTP:
	case EXARMO_AARCH64_FRINTX:
	case EXARMO_AARCH64_FRINTZ:
	case EXARMO_AARCH64_FRINT32X:
	case EXARMO_AARCH64_FRINT32Z:
	case EXARMO_AARCH64_FRINT64X:
	case EXARMO_AARCH64_FRINT64Z:
	case EXARMO_AARCH64_FMADD:
	case EXARMO_AARCH64_FMSUB:
	{
		uint32_t intrinsic = ARM64_INTRIN_INVALID;
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FrintmSFloatdp1:
			il.AddInstruction(ILSETREG_O(operand1, il.Floor(4, ILREG_O(operand2))));
			break;
		case EXARMO_AARCH64_ENC_FrintpSFloatdp1:
			il.AddInstruction(ILSETREG_O(operand1, il.Ceil(4, ILREG_O(operand2))));
			break;
		case EXARMO_AARCH64_ENC_FrintzSFloatdp1:
			il.AddInstruction(ILSETREG_O(operand1, il.FloatTrunc(4, ILREG_O(operand2))));
			break;
		case EXARMO_AARCH64_ENC_FrintaSFloatdp1:
			intrinsic = ARM64_INTRIN_FRINTA;
			break;
		case EXARMO_AARCH64_ENC_FrintiSFloatdp1:
			intrinsic = ARM64_INTRIN_FRINTI;
			break;
		case EXARMO_AARCH64_ENC_FrintxSFloatdp1:
			intrinsic = ARM64_INTRIN_FRINTX;
			break;
		case EXARMO_AARCH64_ENC_Frint32xSFloatdp1:
			intrinsic = ARM64_INTRIN_FRINT32X;
			break;
		case EXARMO_AARCH64_ENC_Frint32zSFloatdp1:
			intrinsic = ARM64_INTRIN_FRINT32Z;
			break;
		case EXARMO_AARCH64_ENC_Frint64xSFloatdp1:
			intrinsic = ARM64_INTRIN_FRINT64X;
			break;
		case EXARMO_AARCH64_ENC_Frint64zSFloatdp1:
			intrinsic = ARM64_INTRIN_FRINT64Z;
			break;
		case EXARMO_AARCH64_ENC_FmaddSFloatdp3:
			intrinsic = ARM64_INTRIN_FMADD;
			break;
		case EXARMO_AARCH64_ENC_FmsubSFloatdp3:
			intrinsic = ARM64_INTRIN_FMSUB;
			break;
		default:
			break;
		}

		if (intrinsic == ARM64_INTRIN_FMADD || intrinsic == ARM64_INTRIN_FMSUB)
		{
			// In ACLE's vfma order, the addend and then the two factors
			il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, intrinsic,
			    {ILREG_O(operand4), ILREG_O(operand2), ILREG_O(operand3)}));
		}
		else if (intrinsic != ARM64_INTRIN_INVALID)
		{
			il.AddInstruction(
			    il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, intrinsic, {ILREG_O(operand2)}));
		}
		break;
	}
	// ACLE has no intrinsic for scalar FMAXP and friends on two halves. Lift them as the two-operand
	// half intrinsic, such as vmaxh_f16, applied to the two lanes.
	case EXARMO_AARCH64_FMAXP:
	case EXARMO_AARCH64_FMINP:
	case EXARMO_AARCH64_FMAXNMP:
	case EXARMO_AARCH64_FMINNMP:
	{
		const char* name;
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_FmaxpAsisdpairOnlyH:
			name = "vmaxh_f16";
			break;
		case EXARMO_AARCH64_ENC_FminpAsisdpairOnlyH:
			name = "vminh_f16";
			break;
		case EXARMO_AARCH64_ENC_FmaxnmpAsisdpairOnlyH:
			name = "vmaxnmh_f16";
			break;
		case EXARMO_AARCH64_ENC_FminnmpAsisdpairOnlyH:
			name = "vminnmh_f16";
			break;
		default:
			name = nullptr;
			break;
		}

		if (!name)
			break;

		uint32_t intrinsic = AcleIntrinsicNamed(name);
		Register lanes[16];
		if (intrinsic == ARM64_INTRIN_INVALID || unpack_vector(operand2, lanes) != 2)
			ABORT_LIFT;

		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, intrinsic,
		    {ILREG(lanes[0]), ILREG(lanes[1])}));
		break;
	}
	case EXARMO_AARCH64_SCVTF:
	case EXARMO_AARCH64_UCVTF:
	{
		bool zero_extend = false;
		switch (encoding)
		{
		// Scalar, float
		case EXARMO_AARCH64_ENC_UcvtfAsisdmiscfp16R:
		case EXARMO_AARCH64_ENC_UcvtfAsisdmiscR:
			zero_extend = true;
		case EXARMO_AARCH64_ENC_ScvtfAsisdmiscfp16R:
		case EXARMO_AARCH64_ENC_ScvtfAsisdmiscR:
		{
			il.AddInstruction(ILSETREG_O(
			    operand1, il.IntToFloat(REGSZ_O(operand1),
					zero_extend
					? il.ZeroExtend(REGSZ_O(operand1), ILREG_O(operand2))
					: il.SignExtend(REGSZ_O(operand1), ILREG_O(operand2)))));
			break;
		}
		// Scalar, integer
		case EXARMO_AARCH64_ENC_UcvtfD32Float2int:
		case EXARMO_AARCH64_ENC_UcvtfD64Float2int:
		case EXARMO_AARCH64_ENC_UcvtfH32Float2int:
		case EXARMO_AARCH64_ENC_UcvtfH64Float2int:
		case EXARMO_AARCH64_ENC_UcvtfS32Float2int:
		case EXARMO_AARCH64_ENC_UcvtfS64Float2int:
			zero_extend = true;
		case EXARMO_AARCH64_ENC_ScvtfD32Float2int:
		case EXARMO_AARCH64_ENC_ScvtfD64Float2int:
		case EXARMO_AARCH64_ENC_ScvtfH32Float2int:
		case EXARMO_AARCH64_ENC_ScvtfH64Float2int:
		case EXARMO_AARCH64_ENC_ScvtfS32Float2int:
		case EXARMO_AARCH64_ENC_ScvtfS64Float2int:
		{
			il.AddInstruction(ILSETREG_O(
			    operand1, il.IntToFloat(REGSZ_O(operand1),
					zero_extend
					? il.ZeroExtend(REGSZ_O(operand1), ILREG_O(operand2))
					: il.SignExtend(REGSZ_O(operand1), ILREG_O(operand2)))));
			break;
		}
		// Vector, single-precision and double-precision unsigned
		case EXARMO_AARCH64_ENC_UcvtfAsimdmiscR:
		// Vector, half precision unsigned
		case EXARMO_AARCH64_ENC_UcvtfAsimdmiscfp16R:
			zero_extend = true;
		// Vector, single-precision and double-precision
		case EXARMO_AARCH64_ENC_ScvtfAsimdmiscR:
		// Vector, half precision
		case EXARMO_AARCH64_ENC_ScvtfAsimdmiscfp16R:
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

				int rsize = RegisterSize(dsts[0]);
				for (int i = 0; i < dst_n; ++i)
					il.AddInstruction(ILSETREG(dsts[i], il.IntToFloat(rsize,
						zero_extend
						? il.ZeroExtend(rsize, ILREG(srcs[i]))
						: il.SignExtend(rsize, ILREG(srcs[i])))));

			}
			break;
		}
		// Scalar, fixed-point (in GP register). The value is the integer scaled down by the
		// shift the instruction writes.
		case EXARMO_AARCH64_ENC_UcvtfD32Float2fix:
		case EXARMO_AARCH64_ENC_UcvtfD64Float2fix:
		case EXARMO_AARCH64_ENC_UcvtfH32Float2fix:
		case EXARMO_AARCH64_ENC_UcvtfH64Float2fix:
		case EXARMO_AARCH64_ENC_UcvtfS32Float2fix:
		case EXARMO_AARCH64_ENC_UcvtfS64Float2fix:
			zero_extend = true;
		case EXARMO_AARCH64_ENC_ScvtfD32Float2fix:
		case EXARMO_AARCH64_ENC_ScvtfD64Float2fix:
		case EXARMO_AARCH64_ENC_ScvtfH32Float2fix:
		case EXARMO_AARCH64_ENC_ScvtfH64Float2fix:
		case EXARMO_AARCH64_ENC_ScvtfS32Float2fix:
		case EXARMO_AARCH64_ENC_ScvtfS64Float2fix:
		{
			size_t destSize = REGSZ_O(operand1);
			size_t size = FixedPointSize(destSize);

			// IntToFloat treats its operand as signed, so zero-extend an unsigned 32-bit source first.
			ExprId source = ILREG_O(operand2);
			if (zero_extend && REGSZ_O(operand2) < 8)
				source = il.ZeroExtend(8, source);

			ExprId value = il.FloatDiv(size, il.IntToFloat(size, source),
			    FixedPointScale(il, size, (uint32_t)IMM_O(operand3)));
			if (size != destSize)
				value = il.FloatConvert(destSize, value);

			il.AddInstruction(ILSETREG_O(operand1, value));
			break;
		}
		// Scalar, fixed-point (in SIMD&FP register)
		case EXARMO_AARCH64_ENC_ScvtfAsisdshfC:
		case EXARMO_AARCH64_ENC_UcvtfAsisdshfC:
		// Vector, fixed-point
		case EXARMO_AARCH64_ENC_ScvtfAsimdshfC:
			// Lift to instrinsics (except there are none)
		case EXARMO_AARCH64_ENC_UcvtfAsimdshfC:
			// Lift to instrinsics
			break;
		// SVE: Vector, integer
		case EXARMO_AARCH64_ENC_ScvtfZPZH2fp16:
		case EXARMO_AARCH64_ENC_ScvtfZPZW2d:
		case EXARMO_AARCH64_ENC_ScvtfZPZW2fp16:
		case EXARMO_AARCH64_ENC_ScvtfZPZW2s:
		case EXARMO_AARCH64_ENC_ScvtfZPZX2d:
		case EXARMO_AARCH64_ENC_ScvtfZPZX2fp16:
		case EXARMO_AARCH64_ENC_ScvtfZPZX2s:
		case EXARMO_AARCH64_ENC_UcvtfZPZH2fp16:
		case EXARMO_AARCH64_ENC_UcvtfZPZW2d:
		case EXARMO_AARCH64_ENC_UcvtfZPZW2fp16:
		case EXARMO_AARCH64_ENC_UcvtfZPZW2s:
		case EXARMO_AARCH64_ENC_UcvtfZPZX2d:
		case EXARMO_AARCH64_ENC_UcvtfZPZX2fp16:
		case EXARMO_AARCH64_ENC_UcvtfZPZX2s:
			ABORT_LIFT;
		default:
			break;
		}
		break;
	}
	case EXARMO_AARCH64_SDIV:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.DivSigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3))));
		break;
	case EXARMO_AARCH64_SEV:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_SEV, {}));
		break;
	case EXARMO_AARCH64_SEVL:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_SEVL, {}));
		break;
	case EXARMO_AARCH64_SHL:
	{
		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		if ((dst_n != src_n) || dst_n == 0)
			ABORT_LIFT;

		int rsize = RegisterSize(dsts[0]);
		for (int i = 0; i < dst_n; ++i)
		{
			il.AddInstruction(il.SetRegister(rsize, dsts[i],
			    il.ShiftLeft(rsize, il.Register(rsize, srcs[i]), il.Const(1, IMM_O(operand3)))));
		}

		break;
	}
	case EXARMO_AARCH64_SSHL:
	{
		Register srcs1[16], srcs2[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src1_n = unpack_vector(operand2, srcs1);
		int src2_n = unpack_vector(operand3, srcs2);
		if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
			ABORT_LIFT;

		int rsize = RegisterSize(dsts[0]);
		for (int i = 0; i < dst_n; ++i)
		{
			il.AddInstruction(il.SetRegister(rsize, dsts[i],
			    il.ShiftLeft(rsize,
					il.SignExtend(rsize, il.Register(rsize, srcs1[i])),
					il.Register(1, srcs2[i]))));
		}

		break;
	}
	case EXARMO_AARCH64_SSHR:
	{
		// Note: we don't lift SRSHR, because it requires rounding the shifted results

		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		if ((dst_n != src_n) || dst_n == 0)
			ABORT_LIFT;

		int rsize = RegisterSize(dsts[0]);
		for (int i = 0; i < dst_n; ++i)
		{
			il.AddInstruction(il.SetRegister(rsize, dsts[i],
			    il.ArithShiftRight(rsize, il.Register(rsize, srcs[i]), il.Const(1, IMM_O(operand3)))));
		}

		break;
	}
	case EXARMO_AARCH64_SSHLL:
	case EXARMO_AARCH64_SSHLL2:
	case EXARMO_AARCH64_SXTL:
	case EXARMO_AARCH64_SXTL2:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_SshllAsimdshfL:
		case EXARMO_AARCH64_ENC_SshllAsimdshfL2:
		case EXARMO_AARCH64_ENC_SxtlSshllAsimdshfL:
		case EXARMO_AARCH64_ENC_SxtlSshllAsimdshfL2:
			if (preferIntrinsics())
				return true;
		default:
			break;
		}
	// SHLL{2} is the same as SHLL{2}, except the extension is signed or unsigned "without change of functionality"
	// (The shift amount is the element size, but is still disassembled to the immediate value in the third operand)
	case EXARMO_AARCH64_SHLL:
	case EXARMO_AARCH64_SHLL2:
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
		if (mnemonic == EXARMO_AARCH64_SSHLL || mnemonic == EXARMO_AARCH64_SSHLL2 ||
			mnemonic == EXARMO_AARCH64_SHLL || mnemonic == EXARMO_AARCH64_SHLL2)
			left_shift = IMM_O(operand3);

		int two_variant_offset = 0;
		if (mnemonic == EXARMO_AARCH64_SXTL2 || mnemonic == EXARMO_AARCH64_SSHLL2 || mnemonic == EXARMO_AARCH64_SHLL2)
			two_variant_offset = src_n / 2;

		int dst_size = RegisterSize(dsts[0]);
		int src_size = RegisterSize(srcs[0]);

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
	case EXARMO_AARCH64_ST1:
	case EXARMO_AARCH64_ST2:
	case EXARMO_AARCH64_ST3:
	case EXARMO_AARCH64_ST4:
		if (true || !preferIntrinsics())  // For now, forcibly disable intrinsics (they are incomplete, and this could help dataflow)
			LoadStoreVector(il, false, operands[0], operands[1]);
		break;
	case EXARMO_AARCH64_STP:
	case EXARMO_AARCH64_STNP:
		LoadStoreOperandPair(il, false, operands[0], operands[1], operands[2]);
		break;
	case EXARMO_AARCH64_ST2G:
		WriteBack(il, operand2, EXARMO_AARCH64_WRITEBACK_PRE);
		il.AddInstruction(
			il.Intrinsic({}, ARM64_INTRIN_ST2G, {ILREG_O(operand1), AccessAddress(il, operand2)}));
		WriteBack(il, operand2, EXARMO_AARCH64_WRITEBACK_POST);
		break;
	case EXARMO_AARCH64_STG:
		WriteBack(il, operand2, EXARMO_AARCH64_WRITEBACK_PRE);
		il.AddInstruction(
			il.Intrinsic({}, ARM64_INTRIN_STG, {ILREG_O(operand1), AccessAddress(il, operand2)}));
		WriteBack(il, operand2, EXARMO_AARCH64_WRITEBACK_POST);
		break;
	case EXARMO_AARCH64_STGM:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_STGM, {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case EXARMO_AARCH64_STGP:
		WriteBack(il, operand3, EXARMO_AARCH64_WRITEBACK_PRE);
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_STGP,
			{ILREG_O(operand1), ILREG_O(operand2), AccessAddress(il, operand3)}));
		WriteBack(il, operand3, EXARMO_AARCH64_WRITEBACK_POST);
		break;
	case EXARMO_AARCH64_STZ2G:
		WriteBack(il, operand2, EXARMO_AARCH64_WRITEBACK_PRE);
		il.AddInstruction(
			il.Intrinsic({}, ARM64_INTRIN_STZ2G, {ILREG_O(operand1), AccessAddress(il, operand2)}));
		WriteBack(il, operand2, EXARMO_AARCH64_WRITEBACK_POST);
		break;
	case EXARMO_AARCH64_STZG:
		WriteBack(il, operand2, EXARMO_AARCH64_WRITEBACK_PRE);
		il.AddInstruction(
			il.Intrinsic({}, ARM64_INTRIN_STZG, {ILREG_O(operand1), AccessAddress(il, operand2)}));
		WriteBack(il, operand2, EXARMO_AARCH64_WRITEBACK_POST);
		break;
	case EXARMO_AARCH64_STZGM:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_STZGM, {ILREG_O(operand1), ILREG_O(operand2)}));
		break;
	case EXARMO_AARCH64_STR:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_StrPBi:
		case EXARMO_AARCH64_ENC_StrZBi:
		case EXARMO_AARCH64_ENC_StrZaRi:
			if (!preferIntrinsics())
					il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
	case EXARMO_AARCH64_STLR:
	case EXARMO_AARCH64_STUR:
	case EXARMO_AARCH64_STLUR:
		LoadStoreOperand(il, false, operands[0], operands[1], 0, addr);
		break;
	case EXARMO_AARCH64_STRB:
	case EXARMO_AARCH64_STLRB:
	case EXARMO_AARCH64_STURB:
	case EXARMO_AARCH64_STLURB:
		LoadStoreOperandSize(il, false, false, 1, REG_O(operands[0]), operands[1], addr);
		break;
	case EXARMO_AARCH64_STRH:
	case EXARMO_AARCH64_STLRH:
	case EXARMO_AARCH64_STURH:
	case EXARMO_AARCH64_STLURH:
		LoadStoreOperandSize(il, false, false, 2, REG_O(operands[0]), operands[1], addr);
		break;
	case EXARMO_AARCH64_SUB:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_SubZPZz:
		case EXARMO_AARCH64_ENC_SubZZi:
		case EXARMO_AARCH64_ENC_SubZZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
	case EXARMO_AARCH64_SUBS:
		il.AddInstruction(ILSETREG_O(
		    operand1, il.Sub(REGSZ_O(operand1), ILREG_O(operand2),
		                  ReadILOperand(il, operands[2], REGSZ_O(operand1), addr), SETFLAGS)));
		break;
	case EXARMO_AARCH64_SUBG:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_SUBG,
			{ILREG_O(operand2), il.Const(REGSZ_O(operand2), IMM_O(operand3)), il.Const(1, IMM_O(operand4))}));
		break;
	case EXARMO_AARCH64_SUBPT:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_SubptZPZz:
		case EXARMO_AARCH64_ENC_SubptZZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		// FEAT_CPA checked pointer subtraction, lifted as if checking is disabled
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Sub(REGSZ_O(operand1), ILREG_O(operand2),
		        ReadILOperand(il, operand3, REGSZ_O(operand1), addr))));
		break;
	case EXARMO_AARCH64_SUBP:
		il.AddInstruction(il.Intrinsic(
			{RegisterOrFlag::Register(REG_O(operand1))}, ARM64_INTRIN_SUBP, {ILREG_O(operand2), ILREG_O(operand3)}));
		break;
	case EXARMO_AARCH64_SUBPS:
		il.AddInstruction(il.Intrinsic(
			{RegisterOrFlag::Register(REG_O(operand1)), RegisterOrFlag::Flag(IL_FLAG_N),
				RegisterOrFlag::Flag(IL_FLAG_Z), RegisterOrFlag::Flag(IL_FLAG_C), RegisterOrFlag::Flag(IL_FLAG_V)},
			ARM64_INTRIN_SUBPS, {ILREG_O(operand2), ILREG_O(operand3)}));
		break;
	case EXARMO_AARCH64_SVC:
	case EXARMO_AARCH64_HVC:
	case EXARMO_AARCH64_SMC:
	{
		/* b31,b30==xx of fake register mark transition to ELxx */
		uint32_t el_mark = 0;
		if (mnemonic == EXARMO_AARCH64_SVC)
			el_mark = 0x40000000;
		else if (mnemonic == EXARMO_AARCH64_HVC)
			el_mark = 0x80000000;
		else if (mnemonic == EXARMO_AARCH64_SMC)
			el_mark = 0xC0000000;
		/* b15..b0 of fake register still holds syscall number */
		il.AddInstruction(
		    il.SetRegister(4, FAKEREG_SYSCALL_INFO, il.Const(4, el_mark | IMM_O(operand1))));
		il.AddInstruction(il.SystemCall());
		break;
	}

	case EXARMO_AARCH64_SMOV:
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
	case EXARMO_AARCH64_SWP: /* word (4) or doubleword (8) */
	case EXARMO_AARCH64_SWPA:
	case EXARMO_AARCH64_SWPL:
	case EXARMO_AARCH64_SWPAL:
		LoadStoreOperand(il, true, operand2, operand3, 0, addr);
		LoadStoreOperand(il, false, operand1, operand3, 0, addr);
		break;
	case EXARMO_AARCH64_SWPB: /* byte (1) */
	case EXARMO_AARCH64_SWPAB:
	case EXARMO_AARCH64_SWPLB:
	case EXARMO_AARCH64_SWPALB:
		LoadStoreOperand(il, true, operand2, operand3, 1, addr);
		il.AddInstruction(il.Store(1, ILREG_O(operand3), il.LowPart(1, ILREG_O(operand1))));
		break;
	case EXARMO_AARCH64_SWPH: /* half-word (2) */
	case EXARMO_AARCH64_SWPAH:
	case EXARMO_AARCH64_SWPLH:
	case EXARMO_AARCH64_SWPALH:
		LoadStoreOperand(il, true, operand2, operand3, 2, addr);
		il.AddInstruction(il.Store(2, ILREG_O(operand3), il.LowPart(2, ILREG_O(operand1))));
		break;
	case EXARMO_AARCH64_SXTB:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_SxtbZPZM:
		case EXARMO_AARCH64_ENC_SxtbZPZZ:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(
		    ILSETREG_O(operand1, ExtractRegister(il, operand2, 0, 1, true, REGSZ_O(operand1))));
		break;
	case EXARMO_AARCH64_SXTH:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_SxthZPZM:
		case EXARMO_AARCH64_ENC_SxthZPZZ:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(
		    ILSETREG_O(operand1, ExtractRegister(il, operand2, 0, 2, true, REGSZ_O(operand1))));
		break;
	case EXARMO_AARCH64_SXTW:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_SxtwZPZM:
		case EXARMO_AARCH64_ENC_SxtwZPZZ:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(
		    ILSETREG_O(operand1, ExtractRegister(il, operand2, 0, 4, true, REGSZ_O(operand1))));
		break;
	case EXARMO_AARCH64_TBNZ:
		ConditionalJump(arch, il,
		    il.CompareNotEqual(REGSZ_O(operand1), ExtractBit(il, operand1, IMM_O(operand2)),
		        il.Const(REGSZ_O(operand1), 0)),
		    addrSize, LabelTarget(operand3, addr), addr + 4);
		return false;
	case EXARMO_AARCH64_TBZ:
		ConditionalJump(arch, il,
		    il.CompareEqual(REGSZ_O(operand1), ExtractBit(il, operand1, IMM_O(operand2)),
		        il.Const(REGSZ_O(operand1), 0)),
		    addrSize, LabelTarget(operand3, addr), addr + 4);
		return false;
	case EXARMO_AARCH64_TST:
		il.AddInstruction(il.And(REGSZ_O(operand1), ILREG_O(operand1),
		    ReadILOperand(il, operand2, REGSZ_O(operand1), addr), SETFLAGS));
		break;
	// An operation arrives as plain SYS when its alias requires Rt to be XZR and the encoding has
	// another register. That is CONSTRAINED UNPREDICTABLE, and this lifts it as if Rt were XZR.
	case EXARMO_AARCH64_SYS:
	{
		uint32_t op1 = (uint32_t)IMM_O(operand1);
		uint32_t crn = (uint32_t)IMM_O(operand2);
		uint32_t crm = (uint32_t)IMM_O(operand3);
		uint32_t op2 = (uint32_t)IMM_O(operand4);
		exarmo_aarch64_sysop_def named;
		if (!SystemOperationAt(op1, crn, crm, op2, named))
		{
			il.AddInstruction(il.Unimplemented());
			break;
		}

		uint32_t intrinsic = SysOpIntrinsic(named.instruction, false);
		if (intrinsic == ARM64_INTRIN_INVALID)
		{
			il.AddInstruction(il.Unimplemented());
			break;
		}

		il.AddInstruction(il.Intrinsic({}, intrinsic, {il.Const(4, named.encoding)}));
		break;
	}
	// The SYS aliases in exarmo's system operation table.
	case EXARMO_AARCH64_AT:
	case EXARMO_AARCH64_BRB:
	case EXARMO_AARCH64_CFP:
	case EXARMO_AARCH64_COSP:
	case EXARMO_AARCH64_CPP:
	case EXARMO_AARCH64_DC:
	case EXARMO_AARCH64_DVP:
	case EXARMO_AARCH64_GIC:
	case EXARMO_AARCH64_GICR:
	case EXARMO_AARCH64_GSB:
	case EXARMO_AARCH64_IC:
	case EXARMO_AARCH64_PLBI:
	case EXARMO_AARCH64_TLBI:
	case EXARMO_AARCH64_TLBIP:
		LiftSystemOperation(il, mnemonic, operands, operandCount, addr);
		break;
	case EXARMO_AARCH64_UMADDL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Add(REGSZ_O(operand1), ILREG_O(operand4),
		        il.MultDoublePrecUnsigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case EXARMO_AARCH64_UMULL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.MultDoublePrecUnsigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3))));
		break;
	case EXARMO_AARCH64_UMSUBL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Sub(REGSZ_O(operand1), ILREG_O(operand4),
		        il.MultDoublePrecUnsigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case EXARMO_AARCH64_UMNEGL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Sub(REGSZ_O(operand1), il.Const(8, 0),
		        il.MultDoublePrecUnsigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case EXARMO_AARCH64_UXTL:
	case EXARMO_AARCH64_UXTL2:
	case EXARMO_AARCH64_USHLL:
	case EXARMO_AARCH64_USHLL2:
	{
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_UshllAsimdshfL:
		case EXARMO_AARCH64_ENC_UshllAsimdshfL2:
		case EXARMO_AARCH64_ENC_UxtlUshllAsimdshfL:
		case EXARMO_AARCH64_ENC_UxtlUshllAsimdshfL2:
			if (preferIntrinsics())
				return true;
		default:
			break;
		}

		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		// We cannot check that the src and dst counts are the same here
		// because the 2 variants use different count arrange specs, e.g.
		// uxtl2 v0.2d, v1.4s
		(void) src_n;

		int left_shift = 0;
		if (mnemonic == EXARMO_AARCH64_USHLL || mnemonic == EXARMO_AARCH64_USHLL2)
			left_shift = IMM_O(operand3);

		int two_variant_offset = 0;
		if (mnemonic == EXARMO_AARCH64_UXTL2 || mnemonic == EXARMO_AARCH64_USHLL2)
			two_variant_offset = src_n / 2;

		int dst_size = RegisterSize(dsts[0]);
		int src_size = RegisterSize(srcs[0]);

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
	case EXARMO_AARCH64_SMADDL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Add(REGSZ_O(operand1), ILREG_O(operand4),
		        il.MultDoublePrecSigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case EXARMO_AARCH64_USHL:
	{
		switch (encoding)
		{
			case EXARMO_AARCH64_ENC_UshlAsimdsameOnly:
				if (preferIntrinsics())
					return true;

			case EXARMO_AARCH64_ENC_UshlAsisdsameOnly:
			default:
			{
				Register srcs1[16], srcs2[16], dsts[16];
				int dst_n = unpack_vector(operand1, dsts);
				int src1_n = unpack_vector(operand2, srcs1);
				int src2_n = unpack_vector(operand3, srcs2);
				if ((dst_n != src1_n) || (src1_n != src2_n) || dst_n == 0)
					ABORT_LIFT;

				int rsize = RegisterSize(dsts[0]);
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
	case EXARMO_AARCH64_USHR:
	{
		// Note: we don't lift URSHR, because it requires rounding the shifted results

		// TODO: the ACLE table names an intrinsic for this where the hand-written one did not,
		// so preferring intrinsics replaces the per-lane lifting below with an opaque call.
		// Decide whether that is wanted before turning this back on.
		// if (preferIntrinsics())
		// 	return true;

		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		if ((dst_n != src_n) || dst_n == 0)
			ABORT_LIFT;

		int rsize = RegisterSize(dsts[0]);
		for (int i = 0; i < dst_n; ++i)
		{
			il.AddInstruction(il.SetRegister(rsize, dsts[i],
			    il.LogicalShiftRight(rsize, il.Register(rsize, srcs[i]), il.Const(1, IMM_O(operand3)))));
		}

		break;
	}
	case EXARMO_AARCH64_SMULL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.MultDoublePrecSigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3))));
		break;
	case EXARMO_AARCH64_SMSUBL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Sub(REGSZ_O(operand1), ILREG_O(operand4),
		        il.MultDoublePrecSigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case EXARMO_AARCH64_SMNEGL:
		il.AddInstruction(ILSETREG_O(operand1,
		    il.Neg(REGSZ_O(operand1),
		        il.MultDoublePrecSigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3)))));
		break;
	case EXARMO_AARCH64_UMULH:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_UmulhZZz:
		case EXARMO_AARCH64_ENC_UmulhZPZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default:
			break;
		}

		il.AddInstruction(ILSETREG_O(operand1,
			il.LowPart(8,
				il.LogicalShiftRight(16,
					il.MultDoublePrecUnsigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)),
					il.Const(1, 64)))));
		break;
	case EXARMO_AARCH64_SMULH:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_SmulhZZz:
		case EXARMO_AARCH64_ENC_SmulhZPZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(ILSETREG_O(operand1,
			il.SignExtend(8,
				il.LowPart(8,
					il.LogicalShiftRight(16,
						il.MultDoublePrecSigned(REGSZ_O(operand1), ILREG_O(operand2), ILREG_O(operand3)),
						il.Const(1, 64))))));
		break;
	case EXARMO_AARCH64_SMAX:
	{
		ExprId op2 = ILREG_O(operand2);
		ExprId op3;

		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_Smax32MinmaxImm:
		case EXARMO_AARCH64_ENC_Smax64MinmaxImm:
			op3 = il.Const(REGSZ_O(operand2), IMM_O(operand3));
			break;
		case EXARMO_AARCH64_ENC_Smax32Dp2src:
		case EXARMO_AARCH64_ENC_Smax64Dp2src:
			op3 = ILREG_O(operand3);
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			return true;
		}

		il.AddInstruction(ILSETREG_O(operand1, il.MaxSigned(REGSZ_O(operand2), op2, op3)));
		break;
	}
	case EXARMO_AARCH64_SMIN:
	{
		ExprId op2 = ILREG_O(operand2);
		ExprId op3;

		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_Smin32MinmaxImm:
		case EXARMO_AARCH64_ENC_Smin64MinmaxImm:
			op3 = il.Const(REGSZ_O(operand2), IMM_O(operand3));
			break;
		case EXARMO_AARCH64_ENC_Smin32Dp2src:
		case EXARMO_AARCH64_ENC_Smin64Dp2src:
			op3 = ILREG_O(operand3);
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			return true;
		}

		il.AddInstruction(ILSETREG_O(operand1, il.MinSigned(REGSZ_O(operand2), op2, op3)));
		break;
	}
	case EXARMO_AARCH64_UDIV:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_UdivZPZz:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(ILSETREG_O(
		    operand1, il.DivUnsigned(REGSZ_O(operand2), ILREG_O(operand2), ILREG_O(operand3))));
		break;
	case EXARMO_AARCH64_UMAX:
	{
		ExprId op2 = ILREG_O(operand2);
		ExprId op3;

		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_Umax32uMinmaxImm:
		case EXARMO_AARCH64_ENC_Umax64uMinmaxImm:
			op3 = il.Const(REGSZ_O(operand2), IMM_O(operand3));
			break;
		case EXARMO_AARCH64_ENC_Umax32Dp2src:
		case EXARMO_AARCH64_ENC_Umax64Dp2src:
			op3 = ILREG_O(operand3);
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			return true;
		}

		il.AddInstruction(ILSETREG_O(operand1, il.MaxUnsigned(REGSZ_O(operand2), op2, op3)));
		break;
	}
	case EXARMO_AARCH64_UMIN:
	{
		ExprId op2 = ILREG_O(operand2);
		ExprId op3;

		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_Umin32uMinmaxImm:
		case EXARMO_AARCH64_ENC_Umin64uMinmaxImm:
			op3 = il.Const(REGSZ_O(operand2), IMM_O(operand3));
			break;
		case EXARMO_AARCH64_ENC_Umin32Dp2src:
		case EXARMO_AARCH64_ENC_Umin64Dp2src:
			op3 = ILREG_O(operand3);
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			return true;
		}

		il.AddInstruction(ILSETREG_O(operand1, il.MinUnsigned(REGSZ_O(operand2), op2, op3)));
		break;
	}
	case EXARMO_AARCH64_UBFIZ:
		il.AddInstruction(
		    ILSETREG_O(operand1, il.ShiftLeft(REGSZ_O(operand2),
                                                il.And(REGSZ_O(operand2),
                                                    ILREG_O(operand2),
                                                    il.Const(REGSZ_O(operand2), (1LL << IMM_O(operand4)) - 1)),
                                                il.Const(1, IMM_O(operand3)))));
		break;
	case EXARMO_AARCH64_UBFX:
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
			il.AddInstruction(ILSETREG_O(operand1, il.And(REGSZ_O(operand2),
                                                    il.LogicalShiftRight(REGSZ_O(operand2),
                                                        ILREG_O(operand2),
                                                        il.Const(1, IMM_O(operand3))),
                                                    il.Const(REGSZ_O(operand2), (1LL << IMM_O(operand4)) - 1))));
		}
		break;
	}
	case EXARMO_AARCH64_UXTB:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_UxtbZPZM:
		case EXARMO_AARCH64_ENC_UxtbZPZZ:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(
		    ILSETREG_O(operand1, ExtractRegister(il, operand2, 0, 1, false, REGSZ_O(operand1))));
		break;
	case EXARMO_AARCH64_UXTH:
		switch (encoding)
		{
		case EXARMO_AARCH64_ENC_UxthZPZM:
		case EXARMO_AARCH64_ENC_UxthZPZZ:
			if (!preferIntrinsics())
				il.AddInstruction(il.Unimplemented());
			return true;
		default: break;
		}
		il.AddInstruction(
		    ILSETREG_O(operand1, ExtractRegister(il, operand2, 0, 2, false, REGSZ_O(operand1))));
		break;
	case EXARMO_AARCH64_WFE:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_WFE, {}));
		break;
	case EXARMO_AARCH64_WFI:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_WFI, {}));
		break;
	case EXARMO_AARCH64_BRK:
		il.AddInstruction(
		    il.Trap(IMM_O(operand1)));  // FIXME Breakpoint may need a parameter (IMM_O(operand1)));
		return false;
	case EXARMO_AARCH64_DGH:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_DGH, {}));
		break;
	case EXARMO_AARCH64_TSB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_TSB, {}));
		break;
	case EXARMO_AARCH64_CSDB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_CSDB, {}));
		break;
	case EXARMO_AARCH64_PACM:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_PACM, {}));
		break;
	case EXARMO_AARCH64_HINT:
		if ((IMM_O(operand1) & ~0b110) == 0b100000)
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_BTI, {}));
		break;
	case EXARMO_AARCH64_HLT:
		il.AddInstruction(il.Trap(IMM_O(operand1)));
		return false;
	case EXARMO_AARCH64_UDF:
		il.AddInstruction(il.Trap(IMM_O(operand1)));
		return false;
	case EXARMO_AARCH64_YIELD:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_YIELD, {}));
		break;
	default:
		break;
	}

	if (il.GetInstructionCount() > n_instrs_before)
		return true;

	AcleGetLowLevelILForInstruction(il, instr, operands);
	if (il.GetInstructionCount() > n_instrs_before)
		return true;

	il.AddInstruction(il.Unimplemented());
	return true;
}
