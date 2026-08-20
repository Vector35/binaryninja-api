#include "il.h"

#include "mips.h"

using namespace BinaryNinja;
using namespace mips;

#define INVALID_EXPRID ((uint32_t)-1)

#define INVALID_OPERATION \
				default: \
					LogWarn("Invalid operation"); \
					il.AddInstruction(il.Unimplemented()); \
					return false

typedef enum {
	ZeroExtend,
	SignExtend,
} ExtendType;

static ExprId SetRegisterOrNop(LowLevelILFunction& il,
		size_t size,
		size_t registerSize,
		uint32_t reg,
		ExprId expr,
		ExtendType extend = SignExtend)
{
	if (reg == REG_ZERO)
		return il.Nop();
	else
	{
		if (size < registerSize)
		{
			switch (extend)
			{
			case ZeroExtend:
				expr = il.ZeroExtend(registerSize, expr);
				break;
			case SignExtend:
				expr = il.SignExtend(registerSize, expr);
				break;
			}
		}
		return il.SetRegister(registerSize, reg, expr);
	}
}


static void ConditionExecute(LowLevelILFunction& il, ExprId cond, ExprId trueCase, ExprId falseCase=INVALID_EXPRID)
{
	LowLevelILLabel trueCode, falseCode, done;

	if (falseCase == INVALID_EXPRID)
		il.AddInstruction(il.If(cond, trueCode, done));
	else
		il.AddInstruction(il.If(cond, trueCode, falseCode));

	il.MarkLabel(trueCode);
	il.AddInstruction(trueCase);
	il.AddInstruction(il.Goto(done));

	if (falseCase != INVALID_EXPRID)
	{
		il.MarkLabel(falseCode);
		il.AddInstruction(falseCase);
		il.AddInstruction(il.Goto(done));
	}
	il.MarkLabel(done);
	return;
}

static void SaturatingAddSub(LowLevelILFunction& il, Instruction& instr, bool saturate, bool signedFlag, size_t bytes, bool subtract=false)
{
	// Perform saturating addition by applying the optimizations from https://web.archive.org/web/20190213215419/https://locklessinc.com/articles/sat_arithmetic/
	// TODO: optimize signed case by applying above link
	InstructionOperand& op1 = instr.operands[0];  // rd
	InstructionOperand& op2 = instr.operands[1];  // rs
	InstructionOperand& op3 = instr.operands[2];  // rt

	auto signExtend = signedFlag ? SignExtend : ZeroExtend;


	// Simple case: if either rs or rt is $zero, then it's equivalent to a 128-bit move
	if (op3.reg == REG_ZERO)
	{
		// (If both are, then it's a 128-bit clear)
		if (op2.reg == REG_ZERO)
			il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Const(16, 0), signExtend));
		else
			il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, op2.reg), signExtend));
		return;
	}
	else if (op2.reg == REG_ZERO)
	{
		if (!subtract)
		{
			il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, op3.reg), signExtend));
			return;
		}
		else
		{
			// This cannot be done by a single negation, so let the code below handle it
		}
	}
	// else
	{
		// Mask of the appropriate size for the pieces of rs and rd
		const uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - (8 * bytes));

		// Perform the appropriate number of piecewise additions, saturating if needed, then combine into the rd register
		for (int i = 0; i < 16 / bytes; i++)
		{
			// How much to shift the piece
			size_t shift = i * 8 * bytes;
			ExprId rs_shifted = il.Register(16, op2.reg);
			ExprId rt_shifted = il.Register(16, op3.reg);

			// Only need to shift if it's not the lowest-order piece
			if (i > 0)
			{
				rs_shifted = il.LogicalShiftRight( 16, rs_shifted, il.Const(1, shift));
				rt_shifted = il.LogicalShiftRight( 16, rt_shifted, il.Const(1, shift));
			}

			// Mask the (shifted) piece to the appropriate size
			rs_shifted = il.And(bytes, rs_shifted, il.Const(128, mask));
			rt_shifted = il.And(bytes, rt_shifted, il.Const(128, mask));

			ExprId sum = 0;

			if (!saturate)
			{
				// Non-saturating add/sub is just add/sub ignoring overflows (sign is actually irrelevant)
				if (!subtract)
					sum = il.And(bytes, il.Add(bytes, rs_shifted, rt_shifted), il.Const(bytes, mask));
				else
					sum = il.And(bytes, il.Sub(bytes, rs_shifted, rt_shifted), il.Const(bytes, mask));
			}
			else
			{
				if (signedFlag)
				{
					rs_shifted = il.SignExtend(2 * bytes, rs_shifted);
					rt_shifted = il.SignExtend(2 * bytes, rt_shifted);
				}
				else
				{
					rs_shifted = il.ZeroExtend(2 * bytes, rs_shifted);
					rt_shifted = il.ZeroExtend(2 * bytes, rt_shifted);

					// For the unsigned case, we need to use the shifted and masked rs sub-value more than once so save it in temp0
					il.AddInstruction(il.SetRegister(2 * bytes, LLIL_TEMP(0), rs_shifted));
					rs_shifted = il.Register(2 * bytes, LLIL_TEMP(0));
				}
				// This is an n-byte add, but if the sum is greater than 0xFFFFFFFF >> (32 - 8*n), the result is 0xFFFFFFFF >> (4-n)
				// (Saturation for the signed case is more complicated, but the initial addition is the same)
				// So we do a 2n-byte add and saturate the result if necessary
				ExprId add_sub = 0;
				if (!subtract)
					add_sub = il.Add(2 * bytes,
						rs_shifted,
						rt_shifted);
				else
					add_sub = il.Sub(2 * bytes,
						rs_shifted,
						rt_shifted);
				il.AddInstruction(il.SetRegister(2 * bytes,
					LLIL_TEMP(1),
						add_sub));

				if (!signedFlag)
				{
					if (!subtract)
					{
						ExprId comparison = il.CompareUnsignedLessThan(bytes,
						  il.Register(bytes, LLIL_TEMP(1)),
						  il.Register(bytes, LLIL_TEMP(0)));
						sum = il.Or(bytes,
							il.Register(bytes, LLIL_TEMP(1)),
							il.Neg(bytes,
								il.BoolToInt(bytes,
									comparison)));
					}
					else
					{
						ExprId comparison = il.CompareUnsignedLessEqual(bytes,
						  il.Register(bytes, LLIL_TEMP(1)),
						  il.Register(bytes, LLIL_TEMP(0)));
						sum = il.And(bytes,
							il.Register(bytes, LLIL_TEMP(1)),
							il.Neg(bytes,
								il.BoolToInt(bytes,
									comparison)));
					}
				}
				else
				{
					uint64_t clamp_overflow = 0x7FFFFFFF >> (32 - (8 * bytes));
					uint64_t clamp_under_lower_bound = 0x100000000 >> (32 - (8 * bytes));
					uint64_t clamp_under_upper_bound = 0x180000000 >> (32 - (8 * bytes));
					// uint64_t clamp4 = 0x80000000 >> (32 - (8 * bytes));  // clamp3 - clamp2
					uint64_t clamp_underflow = clamp_under_upper_bound - clamp_under_lower_bound;

					// Note: the Operation definition shows the overflow check before the underflow check, but
					// that would mean an underflow would be detected as an overflow, and the underflow clamp
					// would never be applied. So we do the underflow check first, under the assumption the
					// reference manual is incorrect but the implementation in hardware would be correct.

					auto comparison_underflow = il.And(1,
							il.CompareSignedGreaterThan(2 * bytes,
							   il.Register(2 * bytes, LLIL_TEMP(1)),
							   il.Const(2 * bytes, clamp_under_lower_bound)),
							il.CompareSignedLessThan(bytes,
							   il.Register(2 * bytes, LLIL_TEMP(1)),
							   il.Const(2 * bytes, clamp_under_upper_bound)));
					auto comparison_overflow = il.CompareSignedGreaterThan(bytes,
					   il.Register(2 * bytes, LLIL_TEMP(1)),
					   il.Const(2 * bytes, clamp_overflow));

					LowLevelILLabel trueCase1, trueCase2, falseCase1, falseCase2, done;
					il.AddInstruction(il.If(comparison_underflow, trueCase1, falseCase1));

					il.MarkLabel(trueCase1);
					il.AddInstruction(il.SetRegister(bytes, LLIL_TEMP(1), il.Const(bytes, clamp_underflow)));
					il.AddInstruction(il.Goto(done));

					il.MarkLabel(falseCase1);
					il.AddInstruction(il.If(comparison_overflow, trueCase2, done));

					il.MarkLabel(trueCase2);
					il.AddInstruction(il.SetRegister(bytes, LLIL_TEMP(1), il.Const(bytes, clamp_overflow)));

					il.MarkLabel(done);

					sum = il.Register(bytes, LLIL_TEMP(1));

				}
			}

			auto shifted_sum = i == 0 ? sum : il.ShiftLeft(16, sum, il.Const(1, shift));
			if (i == 0)
			{
				il.AddInstruction(il.SetRegister(16, op1.reg, shifted_sum));
			}
			else
			{
				il.AddInstruction(il.SetRegister(16, op1.reg, il.Or(16, il.Register(16, op1.reg), shifted_sum)));
			}
		}
	}
}

static void ParallelMinMax(LowLevelILFunction& il, Instruction& instr, size_t bytes, bool max=false)
{
	// Perform saturating addition by applying the optimizations from https://web.archive.org/web/20190213215419/https://locklessinc.com/articles/sat_arithmetic/
	// TODO: optimize signed case by applying above link
	InstructionOperand& op1 = instr.operands[0];  // rd
	InstructionOperand& op2 = instr.operands[1];  // rs
	InstructionOperand& op3 = instr.operands[2];  // rt

	// Simple case: if either rs or rt is $zero, then it's equivalent to a 128-bit move
	if (op3.reg == REG_ZERO && op2.reg == REG_ZERO)
		il.AddInstruction(il.SetRegister(16, op1.reg, il.Const(16, 0)));
	else
	{
		// Mask of the appropriate size for the pieces of rs and rd
		const uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - (8 * bytes));

		// Perform the appropriate number of piecewise additions, saturating if needed, then combine into the rd register
		for (int i = 0; i < 16 / bytes; i++)
		{
			// How much to shift the piece
			size_t shift = i * 8 * bytes;
			ExprId rs_shifted = op2.reg != REG_ZERO ? il.Register(16, op2.reg) : il.Const(bytes, 0);
			ExprId rt_shifted = op3.reg != REG_ZERO ? il.Register(16, op3.reg) : il.Const(bytes, 0);

			// Only need to shift if it's not the lowest-order piece
			if (i > 0)
			{
				if (op2.reg != REG_ZERO)
					rs_shifted = il.LogicalShiftRight( 16, rs_shifted, il.Const(1, shift));
				if (op3.reg != REG_ZERO)
					rt_shifted = il.LogicalShiftRight( 16, rt_shifted, il.Const(1, shift));
			}

			// Mask the (shifted) piece to the appropriate size
			if (op2.reg != REG_ZERO)
				rs_shifted = il.And(bytes, rs_shifted, il.Const(128, mask));
			if (op3.reg != REG_ZERO)
				rt_shifted = il.And(bytes, rt_shifted, il.Const(128, mask));

			if (i == 0)
				il.AddInstruction(il.SetRegister(16, LLIL_TEMP(2), il.Const(bytes, 0)));

			ExprId lhs = op2.reg != REG_ZERO ? il.Register(bytes, LLIL_TEMP(0)) : il.Const(bytes, 0);
			ExprId rhs = op3.reg != REG_ZERO ? il.Register(bytes, LLIL_TEMP(1)) : il.Const(bytes, 0);
			// if (op2.reg != REG_ZERO)
				il.AddInstruction(il.SetRegister(bytes, LLIL_TEMP(0), rs_shifted));
			// if (op3.reg != REG_ZERO)
				il.AddInstruction(il.SetRegister(bytes, LLIL_TEMP(1), rt_shifted));
			if (!max)
				ConditionExecute(il,
					il.CompareSignedLessThan(bytes,
						lhs, rhs),
						il.SetRegister(bytes, LLIL_TEMP(1), lhs));
			else
				ConditionExecute(il,
					il.CompareSignedGreaterThan(bytes,
						lhs, rhs),
						il.SetRegister(bytes, LLIL_TEMP(1), lhs));
			ExprId sum = il.Register(bytes, LLIL_TEMP(1));

			auto shifted_sum = i == 0 ? sum : il.ShiftLeft(16, sum, il.Const(1, shift));
			if (i == 0)
			{
				il.AddInstruction(il.SetRegister(16, LLIL_TEMP(2), shifted_sum));
			}
			else
			{
				il.AddInstruction(il.SetRegister(16, LLIL_TEMP(2), il.Or(16, il.Register(16, LLIL_TEMP(2)), shifted_sum)));
			}
		}
		il.AddInstruction(il.SetRegister(16, op1.reg, il.Register(16, LLIL_TEMP(2))));
	}
}

static size_t GetILOperandMemoryAddress(LowLevelILFunction& il, InstructionOperand& operand, size_t addrSize, int32_t delta=0)
{
	size_t offset = 0;
	if (operand.reg == REG_ZERO)
		return il.ConstPointer(addrSize, operand.immediate + (int64_t)delta);

	if (operand.operandClass == MEM_IMM)
	{
		if (operand.immediate + (uint64_t)((int64_t)delta) >= 0x80000000)
			offset = il.Sub(addrSize,
					il.Register(addrSize, operand.reg),
					il.Const(addrSize, -((int32_t)operand.immediate + delta)));
		else
			offset = il.Add(addrSize,
						il.Register(addrSize, operand.reg),
						il.Const(addrSize, operand.immediate + delta));
	}
	else if (operand.operandClass == MEM_REG)
	{
		if (operand.immediate + (uint64_t)((int64_t)delta) >= 0x80000000)
			offset = il.Sub(addrSize,
						il.Register(addrSize, operand.reg),
						il.Register(addrSize, -((int32_t)operand.immediate + delta)));
		else
			offset = il.Add(addrSize,
						il.Register(addrSize, operand.reg),
						il.Register(addrSize, operand.immediate + delta));
	}
	return offset;
}


static size_t ReadILOperand(LowLevelILFunction& il,
	const Instruction& instr,
	size_t i,
	size_t registerSize,
	size_t opSize = SIZE_MAX,
	bool isAddress = false)
{
	if (opSize == SIZE_MAX)
	{
		opSize = registerSize;
	}
	InstructionOperand operand = instr.operands[i - 1];
	switch (operand.operandClass)
	{
	case NONE:
		return il.Undefined();
	case IMM:
		if (isAddress)
			return il.Operand(i - 1, il.ConstPointer(registerSize, operand.immediate));
		return il.Operand(i - 1, il.Const(opSize, operand.immediate));
	case MEM_REG:
	case MEM_IMM:
		return il.Operand(i - 1, il.Load(opSize, GetILOperandMemoryAddress(il, operand, registerSize)));
	default:
		if (operand.reg == REG_ZERO)
			return il.Operand(i - 1, il.Const(opSize, 0));
		return il.Operand(i - 1, il.Register(opSize, operand.reg));
	}
}


static size_t WriteILOperand(LowLevelILFunction& il, Instruction& instr, size_t i, size_t addrSize, size_t value)
{
	InstructionOperand& operand = instr.operands[i - 1];
	switch (operand.operandClass)
	{
	case NONE:
	case IMM:
		return il.Undefined();
	case MEM_IMM:
	case MEM_REG:
		return il.Operand(i - 1, il.Store(addrSize, GetILOperandMemoryAddress(il, operand, addrSize), value));
	default:
		return il.Operand(i - 1, SetRegisterOrNop(il, addrSize, addrSize, operand.reg, value));
	}
}


static size_t DirectJump(Architecture* arch, LowLevelILFunction& il, uint64_t target, size_t addrSize)
{
	BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);
	if (label)
		return il.Goto(*label);
	else
		return il.Jump(il.ConstPointer(addrSize, target));
}


static void ConditionalJump(Architecture* arch, LowLevelILFunction& il, size_t cond, size_t addrSize, uint64_t t, uint64_t f)
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

ExprId GetConditionForInstruction(LowLevelILFunction& il, Instruction& instr, std::function<size_t(InstructionOperand&)> registerSize)
{
	InstructionOperand& op1 = instr.operands[0];
	InstructionOperand& op2 = instr.operands[1];
	InstructionOperand& op3 = instr.operands[2];
	InstructionOperand& op4 = instr.operands[3];
	(void) op3;
	(void) op4;
	switch (instr.operation)
	{
	case MIPS_BEQ:
	case MIPS_BEQL:
		return il.CompareEqual(registerSize(op1), ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2)));
	case MIPS_BNE:
	case MIPS_BNEL:
		return il.CompareNotEqual(registerSize(op1), ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2)));
	case MIPS_BEQZ:
		return il.CompareEqual(registerSize(op1), ReadILOperand(il, instr, 1, registerSize(op1)), il.Const(registerSize(op1), 0));
	case MIPS_BNEZ:
		return il.CompareNotEqual(registerSize(op1), ReadILOperand(il, instr, 1, registerSize(op1)), il.Const(registerSize(op1), 0));
	case MIPS_BGEZ:
	case MIPS_BGEZL:
	case MIPS_BGEZAL:
	case MIPS_BGEZALL:
		return il.CompareSignedGreaterEqual(registerSize(op1), ReadILOperand(il, instr, 1, registerSize(op1)), il.Const(registerSize(op1), 0));
	case MIPS_BGTZ:
	case MIPS_BGTZL:
		return il.CompareSignedGreaterThan(registerSize(op1), ReadILOperand(il, instr, 1, registerSize(op1)), il.Const(registerSize(op1), 0));
	case MIPS_BLEZ:
	case MIPS_BLEZL:
		return il.CompareSignedLessEqual(registerSize(op1), ReadILOperand(il, instr, 1, registerSize(op1)), il.Const(registerSize(op1), 0));
	case MIPS_BLTZ:
	case MIPS_BLTZL:
	case MIPS_BLTZAL:
	case MIPS_BLTZALL:
		return il.CompareSignedLessThan(registerSize(op1), ReadILOperand(il, instr, 1, registerSize(op1)), il.Const(registerSize(op1), 0));
	case MIPS_BC1F:
	case MIPS_BC1FL:
		if (instr.operands[0].operandClass == FLAG)
			return il.Not(0, il.Flag(instr.operands[0].reg));
		return il.Not(0, il.Flag(FPCCREG_FCC0));
	case MIPS_BC1T:
	case MIPS_BC1TL:
		if (instr.operands[0].operandClass == FLAG)
			return il.Flag(instr.operands[0].reg);
		return il.Flag(FPCCREG_FCC0);
	case MIPS_BC0F:
	case MIPS_BC0FL:
		return il.Not(0, il.Flag(CCREG_COC0));
	case MIPS_BC0T:
	case MIPS_BC0TL:
		return il.Flag(CCREG_COC0);
	case MIPS_BC2F:
	case MIPS_BC2FL:
		return il.Not(0, il.Flag(CCREG_COC2));
	case MIPS_BC2T:
	case MIPS_BC2TL:
		return il.Flag(CCREG_COC2);
	case CNMIPS_BBIT0:
		return il.CompareEqual(registerSize(op1),
			il.And(registerSize(op1),
				ReadILOperand(il, instr, 1, registerSize(op1)),
				il.Const(registerSize(op1), 1 << instr.operands[1].immediate)
			),
			il.Const(registerSize(op1), 0)
		);
	case CNMIPS_BBIT032:
		return il.CompareEqual(registerSize(op1),
			il.And(registerSize(op1),
				ReadILOperand(il, instr, 1, registerSize(op1)),
				il.Const(registerSize(op1), ((uint64_t)1) << (instr.operands[1].immediate + 32))
			),
			il.Const(registerSize(op1), 0)
		);
	case CNMIPS_BBIT1:
		return il.CompareNotEqual(registerSize(op1),
			il.And(registerSize(op1),
				ReadILOperand(il, instr, 1, registerSize(op1)),
				il.Const(registerSize(op1), 1 << instr.operands[1].immediate)
			),
			il.Const(registerSize(op1), 0)
		);
	case CNMIPS_BBIT132:
		return il.CompareNotEqual(registerSize(op1),
			il.And(registerSize(op1),
				ReadILOperand(il, instr, 1, registerSize(op1)),
				il.Const(registerSize(op1), ((uint64_t)1) << (instr.operands[1].immediate + 32))
			),
			il.Const(registerSize(op1), 0)
		);

	default:
		LogError("Missing conditional: %d", instr.operation);
		return il.Unimplemented();
	}
}

static bool IsCop0ImplementationDefined(uint32_t reg, uint64_t sel)
{
	switch (reg)
	{
		case 9:
			switch (sel)
			{
				case 6:
				case 7: return true;
				default: return false;
			}
			break;
		case 11:
			switch (sel)
			{
				case 6:
				case 7: return true;
				default: return false;
			}
			break;
		case 16:
			switch (sel)
			{
				case 6:
				case 7: return true;
				default: return false;
			}
			break;
		case 22: return true;
		default: return false;
	}
}

// Get the IL Register for a given cop0 register/selector pair.
// Returns REG_ZERO for unsupported/unimplemented values.
static Reg GetCop0Register(uint32_t reg, uint64_t sel)
{
	switch (reg)
	{
		case 0:
			switch (sel)
			{
				case 0: return REG_INDEX;
				case 1: return REG_MVP_CONTROL;
				case 2: return REG_MVP_CONF0;
				case 3: return REG_MVP_CONF1;
			}
			break;
		case 1:
			switch (sel)
			{
				case 0: return REG_RANDOM;
				case 1: return REG_VPE_CONTROL;
				case 2: return REG_VPE_CONF0;
				case 3: return REG_VPE_CONF1;
				case 4: return REG_YQ_MASK;
				case 5: return REG_VPE_SCHEDULE;
				case 6: return REG_VPE_SCHE_FBACK;
				case 7: return REG_VPE_OPT;
			}
			break;
		case 2:
			switch (sel)
			{
				case 0: return REG_ENTRY_LO0;
				case 1: return REG_TC_STATUS;
				case 2: return REG_TC_BIND;
				case 3: return REG_TC_RESTART;
				case 4: return REG_TC_HALT;
				case 5: return REG_TC_CONTEXT;
				case 6: return REG_TC_SCHEDULE;
				case 7: return REG_TC_SCHE_FBACK;
			}
			break;
		case 3:
			switch (sel)
			{
				case 0: return REG_ENTRY_LO1;
			}
			break;
		case 4:
			switch (sel)
			{
				case 0: return REG_CONTEXT;
				case 1: return REG_CONTEXT_CONFIG;
			}
			break;
		case 5:
			switch (sel)
			{
				case 0: return REG_PAGE_MASK;
				case 1: return REG_PAGE_GRAIN;
			}
			break;
		case 6:
			switch (sel)
			{
				case 0: return REG_WIRED;
				case 1: return REG_SRS_CONF0;
				case 2: return REG_SRS_CONF1;
				case 3: return REG_SRS_CONF2;
				case 4: return REG_SRS_CONF3;
				case 5: return REG_SRS_CONF4;
			}
			break;
		case 7:
			switch (sel)
			{
				case 0: return REG_HWR_ENA;
			}
			break;
		case 8:
			switch (sel)
			{
				case 0: return REG_BAD_VADDR;
			}
			break;
		case 9:
			switch (sel)
			{
				case 0: return REG_COUNT;
			}
			break;
		case 10:
			switch (sel)
			{
				case 0: return REG_ENTRY_HI;
			}
			break;
		case 11:
			switch (sel)
			{
				case 0: return REG_COMPARE;
			}
			break;
		case 12:
			switch (sel)
			{
				case 0: return REG_STATUS;
				case 1: return REG_INT_CTL;
				case 2: return REG_SRS_CTL;
				case 3: return REG_SRS_MAP;
			}
			break;
		case 13:
			switch (sel)
			{
				case 0: return REG_CAUSE;
			}
			break;
		case 14:
			switch (sel)
			{
				case 0: return REG_EPC;
			}
			break;
		case 15:
			switch (sel)
			{
				case 0: return REG_PR_ID;
				case 1: return REG_EBASE;
			}
			break;
		case 16:
			switch (sel)
			{
				case 0: return REG_CONFIG;
				case 1: return REG_CONFIG1;
				case 2: return REG_CONFIG2;
				case 3: return REG_CONFIG3;
			}
			break;
		case 17:
			switch (sel)
			{
				case 0: return REG_LLADDR;
			}
			break;
		case 20:
			switch (sel)
			{
				case 0: return REG_XCONTEXT;
			}
			break;
		case 23:
			switch (sel)
			{
				case 0: return REG_DEBUG;
				case 1: return REG_TRACE_CONTROL;
				case 2: return REG_TRACE_CONTROL2;
				case 3: return REG_USER_TRACE_DATA;
				case 4: return REG_TRACE_BPC;
			}
			break;
		case 24:
			switch (sel)
			{
				case 0: return REG_DEPC;
			}
			break;
		case 26:
			switch (sel)
			{
				case 0: return REG_ERR_CTL;
			}
			break;
		case 27:
			switch (sel)
			{
				case 0: return REG_CACHE_ERR0;
				case 1: return REG_CACHE_ERR1;
				case 2: return REG_CACHE_ERR2;
				case 3: return REG_CACHE_ERR3;
			}
			break;
		case 30:
			switch (sel)
			{
				case 0: return REG_ERROR_EPC;
			}
			break;
		case 31:
			switch (sel)
			{
				case 0: return REG_DESAVE;
			}
			break;
	}
	return REG_ZERO;
}

static Reg GetCaviumCop0Register(uint32_t reg, uint64_t sel)
{
	switch (reg)
	{
		case 9:
			switch (sel)
			{
				case 6: return CNREG0_CVM_COUNT;
				case 7: return CNREG0_CVM_CTL;
				default: return REG_ZERO;
			}
			break;

		case 11:
			switch (sel)
			{
				case 6: return CNREG0_POWTHROTTLE;
				case 7: return CNREG0_CVM_MEM_CTL;
				default: return REG_ZERO;
			}
			break;
		case 22:
			switch (sel)
			{
				case 0: return CNREG0_MULTICORE_DBG;
				default: return REG_ZERO;
			}
			break;

		default: return REG_ZERO;
	}
}

static Reg GetCaviumCop2Register(uint32_t reg)
{
	switch (reg)
	{
		case 0x0040: return CNREG2_0040_HSH_DAT0;
		case 0x0041: return CNREG2_0041_HSH_DAT1;
		case 0x0042: return CNREG2_0042_HSH_DAT2;
		case 0x0043: return CNREG2_0043_HSH_DAT3;
		case 0x0044: return CNREG2_0044_HSH_DAT4;
		case 0x0045: return CNREG2_0045_HSH_DAT5;
		case 0x0046: return CNREG2_0046_HSH_DAT6;
		case 0x0048: return CNREG2_0048_HSH_IV0;
		case 0x0049: return CNREG2_0049_HSH_IV1;
		case 0x004a: return CNREG2_004A_HSH_IV2;
		case 0x004b: return CNREG2_004B_HSH_IV3;
		case 0x0050: return CNREG2_0050_SHA3_DAT24;
		case 0x0051: return CNREG2_0051_SHA3_DAT15_RD;
		case 0x0058: return CNREG2_0058_GFM_MUL_REFLECT0;
		case 0x0059: return CNREG2_0059_GFM_MUL_REFLECT1;
		case 0x005a: return CNREG2_005A_GFM_RESINP_REFLECT0;
		case 0x005b: return CNREG2_005B_GFM_RESINP_REFLECT1;
		case 0x005c: return CNREG2_005C_GFM_XOR0_REFLECT;
		case 0x0080: return CNREG2_0080_3DES_KEY0;
		case 0x0081: return CNREG2_0081_3DES_KEY1;
		case 0x0082: return CNREG2_0082_3DES_KEY2;
		case 0x0084: return CNREG2_0084_3DES_IV;
		case 0x0088: return CNREG2_0088_3DES_RESULT_RD;
		case 0x0098: return CNREG2_0098_3DES_RESULT_WR;
		case 0x0100: return CNREG2_0100_AES_RESULT0;
		case 0x0101: return CNREG2_0101_AES_RESULT1;
		case 0x0102: return CNREG2_0102_AES_IV0;
		case 0x0103: return CNREG2_0103_AES_IV1;
		case 0x0104: return CNREG2_0104_AES_KEY0;
		case 0x0105: return CNREG2_0105_AES_KEY1;
		case 0x0106: return CNREG2_0106_AES_KEY2;
		case 0x0107: return CNREG2_0107_AES_KEY3;
		case 0x0108: return CNREG2_0108_AES_ENC_CBC0;
		case 0x010a: return CNREG2_010A_AES_ENC0;
		case 0x010c: return CNREG2_010C_AES_DEC_CBC0;
		case 0x010e: return CNREG2_010E_AES_DEC0;
		case 0x0110: return CNREG2_0110_AES_KEYLENGTH;
		case 0x0111: return CNREG2_0111_AES_DAT0;
		case 0x0115: return CNREG2_0115_CAMELLIA_FL;
		case 0x0116: return CNREG2_0116_CAMELLIA_FLINV;
		case 0x0200: return CNREG2_0200_CRC_POLYNOMIAL;
		case 0x0201: return CNREG2_0201_CRC_IV;
		case 0x0202: return CNREG2_0202_CRC_LEN;
		case 0x0203: return CNREG2_0203_CRC_IV_REFLECT_RD;
		case 0x0204: return CNREG2_0204_CRC_BYTE;
		case 0x0205: return CNREG2_0205_CRC_HALF;
		case 0x0206: return CNREG2_0206_CRC_WORD;
		case 0x0211: return CNREG2_0211_CRC_IV_REFLECT_WR;
		case 0x0214: return CNREG2_0214_CRC_BYTE_REFLECT;
		case 0x0215: return CNREG2_0215_CRC_HALF_REFLECT;
		case 0x0216: return CNREG2_0216_CRC_WORD_REFLECT;
		case 0x0240: return CNREG2_0240_HSH_DATW0;
		case 0x0241: return CNREG2_0241_HSH_DATW1;
		case 0x0242: return CNREG2_0242_HSH_DATW2;
		case 0x0243: return CNREG2_0243_HSH_DATW3;
		case 0x0244: return CNREG2_0244_HSH_DATW4;
		case 0x0245: return CNREG2_0245_HSH_DATW5;
		case 0x0246: return CNREG2_0246_HSH_DATW6;
		case 0x0247: return CNREG2_0247_HSH_DATW7;
		case 0x0248: return CNREG2_0248_HSH_DATW8;
		case 0x0249: return CNREG2_0249_HSH_DATW9;
		case 0x024a: return CNREG2_024A_HSH_DATW10;
		case 0x024b: return CNREG2_024B_HSH_DATW11;
		case 0x024c: return CNREG2_024C_HSH_DATW12;
		case 0x024d: return CNREG2_024D_HSH_DATW13;
		case 0x024e: return CNREG2_024E_HSH_DATW14;
		case 0x024f: return CNREG2_024F_SHA3_DAT15_RD;
		case 0x0250: return CNREG2_0250_HSH_IVW0;
		case 0x0251: return CNREG2_0251_HSH_IVW1;
		case 0x0252: return CNREG2_0252_HSH_IVW2;
		case 0x0253: return CNREG2_0253_HSH_IVW3;
		case 0x0254: return CNREG2_0254_HSH_IVW4;
		case 0x0255: return CNREG2_0255_HSH_IVW5;
		case 0x0256: return CNREG2_0256_HSH_IVW6;
		case 0x0257: return CNREG2_0257_HSH_IVW7;
		case 0x0258: return CNREG2_0258_GFM_MUL0;
		case 0x0259: return CNREG2_0259_GFM_MUL1;
		case 0x025a: return CNREG2_025A_GFM_RESINP0;
		case 0x025b: return CNREG2_025B_GFM_RESINP1;
		case 0x025c: return CNREG2_025C_GFM_XOR0;
		case 0x025e: return CNREG2_025E_GFM_POLY;
		case 0x02c0: return CNREG2_02C0_SHA3_XORDAT0;
		case 0x02c1: return CNREG2_02C1_SHA3_XORDAT1;
		case 0x02c2: return CNREG2_02C2_SHA3_XORDAT2;
		case 0x02c3: return CNREG2_02C3_SHA3_XORDAT3;
		case 0x02c4: return CNREG2_02C4_SHA3_XORDAT4;
		case 0x02c5: return CNREG2_02C5_SHA3_XORDAT5;
		case 0x02c6: return CNREG2_02C6_SHA3_XORDAT6;
		case 0x02c7: return CNREG2_02C7_SHA3_XORDAT7;
		case 0x02c8: return CNREG2_02C8_SHA3_XORDAT8;
		case 0x02c9: return CNREG2_02C9_SHA3_XORDAT9;
		case 0x02ca: return CNREG2_02CA_SHA3_XORDAT10;
		case 0x02cb: return CNREG2_02CB_SHA3_XORDAT11;
		case 0x02cc: return CNREG2_02CC_SHA3_XORDAT12;
		case 0x02cd: return CNREG2_02CD_SHA3_XORDAT13;
		case 0x02ce: return CNREG2_02CE_SHA3_XORDAT14;
		case 0x02cf: return CNREG2_02CF_SHA3_XORDAT15;
		case 0x02d0: return CNREG2_02D0_SHA3_XORDAT16;
		case 0x02d1: return CNREG2_02D1_SHA3_XORDAT17;
		case 0x0400: return CNREG2_0400_LLM_READ_ADDR0;
		case 0x0401: return CNREG2_0401_LLM_WRITE_ADDR_INTERNAL0;
		case 0x0402: return CNREG2_0402_LLM_DATA0;
		case 0x0404: return CNREG2_0404_LLM_READ64_ADDR0;
		case 0x0405: return CNREG2_0405_LLM_WRITE64_ADDR_INTERNAL0;
		case 0x0408: return CNREG2_0408_LLM_READ_ADDR1;
		case 0x0409: return CNREG2_0409_LLM_WRITE_ADDR_INTERNAL1;
		case 0x040a: return CNREG2_040a_LLM_DATA1;
		case 0x040c: return CNREG2_040c_LLM_READ64_ADDR1;
		case 0x040d: return CNREG2_040d_LLM_WRITE64_ADDR_INTERNAL1;
		case 0x1202: return CNREG2_1202_CRC_LEN;
		case 0x1207: return CNREG2_1207_CRC_DWORD;
		case 0x1208: return CNREG2_1208_CRC_VAR;
		case 0x1217: return CNREG2_1217_CRC_DWORD_REFLECT;
		case 0x1218: return CNREG2_1218_CRC_VAR_REFLECT;
		case 0x3109: return CNREG2_3109_AES_ENC_CBC1;
		case 0x310b: return CNREG2_310B_AES_ENC1;
		case 0x310d: return CNREG2_310D_AES_DEC_CBC1;
		case 0x310f: return CNREG2_310F_AES_DEC1;
		case 0x3114: return CNREG2_3114_CAMELLIA_ROUND;
		case 0x3119: return CNREG2_3119_SMS4_ENC_CBC1;
		case 0x311b: return CNREG2_311B_SMS4_ENC1;
		case 0x311d: return CNREG2_311D_SMS4_DEC_CBC1;
		case 0x311f: return CNREG2_311F_SMS4_DEC1;
		case 0x4052: return CNREG2_4052_SHA3_STARTOP;
		case 0x4047: return CNREG2_4047_HSH_STARTMD5;
		case 0x404d: return CNREG2_404D_SNOW3G_START;
		case 0x4055: return CNREG2_4055_ZUC_START;
		case 0x4056: return CNREG2_4056_ZUC_MORE;
		case 0x405d: return CNREG2_405D_GFM_XORMUL1_REFLECT;
		case 0x404e: return CNREG2_404E_SNOW3G_MORE;
		case 0x404f: return CNREG2_404F_HSH_STARTSHA256;
		case 0x4057: return CNREG2_4057_HSH_STARTSHA;
		case 0x4088: return CNREG2_4088_3DES_ENC_CBC;
		case 0x4089: return CNREG2_4089_KAS_ENC_CBC;
		case 0x408a: return CNREG2_408A_3DES_ENC;
		case 0x408b: return CNREG2_408B_KAS_ENC;
		case 0x408c: return CNREG2_408C_3DES_DEC_CBC;
		case 0x408e: return CNREG2_408E_3DES_DEC;
		case 0x4200: return CNREG2_4200_CRC_POLYNOMIAL_WR;
		case 0x4210: return CNREG2_4210_CRC_POLYNOMIAL_REFLECT;
		case 0x424f: return CNREG2_424F_HSH_STARTSHA512;
		case 0x425d: return CNREG2_425D_GFM_XORMUL1;

		default: return REG_ZERO;
	}
}

static ExprId MoveFromCoprocessor(unsigned cop, LowLevelILFunction& il, size_t loadSize, uint32_t outReg, uint32_t reg, uint64_t sel, uint32_t decomposeFlags)
{
	if (cop == 0)
	{
		Reg copReg = GetCop0Register(reg, sel);
		if (copReg == REG_ZERO && IsCop0ImplementationDefined(reg, sel))
		{
			if ((decomposeFlags & DECOMPOSE_FLAGS_CAVIUM) != 0)
			{
				copReg = GetCaviumCop0Register(reg, sel);
			}
		}

		if (copReg != REG_ZERO)
		{
			return il.Intrinsic(
					{RegisterOrFlag::Register(outReg)},
					loadSize == 4 ? MIPS_INTRIN_MFC0 : MIPS_INTRIN_DMFC0,
					{il.Register(loadSize, copReg)});

		}
	}
	else if (cop == 2)
	{
		if ((decomposeFlags & DECOMPOSE_FLAGS_CAVIUM) != 0)
		{
			Reg cop2Reg = GetCaviumCop2Register(reg);
			if (cop2Reg != REG_ZERO)
			{
				return il.Intrinsic(
					{RegisterOrFlag::Register(outReg)},
					loadSize == 4 ? MIPS_INTRIN_MFC2 : MIPS_INTRIN_DMFC2,
					{il.Register(loadSize, cop2Reg)});
			}
		}
	}

	return il.Intrinsic(
			{RegisterOrFlag::Register(outReg)},
			loadSize == 4 ? MIPS_INTRIN_MFC_UNIMPLEMENTED : MIPS_INTRIN_DMFC_UNIMPLEMENTED,
			{il.Const(4, cop), il.Const(4, reg), il.Const(4, sel)});
}

static ExprId MoveToCoprocessor(unsigned cop, LowLevelILFunction& il, size_t storeSize, uint32_t reg, uint64_t sel, ExprId srcExpr, uint32_t decomposeFlags)
{
	if (cop == 0)
	{
		Reg copReg = GetCop0Register(reg, sel);
		if (copReg == REG_ZERO && IsCop0ImplementationDefined(reg, sel))
		{
			if ((decomposeFlags & DECOMPOSE_FLAGS_CAVIUM) != 0)
			{
				copReg = GetCaviumCop0Register(reg, sel);
			}
		}

		if (copReg != REG_ZERO)
		{
			return il.Intrinsic(
					{},
					storeSize == 4 ? MIPS_INTRIN_MTC0 : MIPS_INTRIN_DMTC0,
					{il.Register(storeSize, copReg), srcExpr});
		}
	}
	else if (cop == 2)
	{
		if ((decomposeFlags & DECOMPOSE_FLAGS_CAVIUM) != 0)
		{
			Reg cop2Reg = GetCaviumCop2Register(reg);
			if (cop2Reg != REG_ZERO)
			{
				return il.Intrinsic(
						{},
						storeSize == 4 ? MIPS_INTRIN_MTC2 : MIPS_INTRIN_DMTC2,
						{il.Register(storeSize, cop2Reg), srcExpr});
			}
		}
	}

	return il.Intrinsic(
			{},
			storeSize == 4 ? MIPS_INTRIN_MTC_UNIMPLEMENTED : MIPS_INTRIN_DMTC_UNIMPLEMENTED,
			{il.Const(4, cop), il.Const(4, reg), il.Const(4, sel), srcExpr});
}

static ExprId SimpleIntrinsic(LowLevelILFunction& il, MipsIntrinsic intrinsic)
{
	return il.Intrinsic({}, intrinsic, {});
}

// returns 256-bit value of [0:64] || [regHi] || [regMid] || [regLo]
static ExprId Concat3to256(LowLevelILFunction& il, uint32_t regHi, uint32_t regMid, uint32_t regLo)
{
	return il.Or(0x20,
		il.ShiftLeft(0x20, il.ZeroExtend(0x20, il.Register(8, regHi)), il.Const(4, 0x80)),
		il.Or(0x20,
			il.ShiftLeft(0x20, il.ZeroExtend(0x20, il.Register(8, regMid)), il.Const(4, 0x40)),
			il.ZeroExtend(0x20, il.Register(8, regLo))
		)
	);
}

static void SignExtendHiLo(LowLevelILFunction& il, size_t registerSize)
{
	if (registerSize == 8)
	{
		il.AddInstruction(il.SetRegister(8, REG_HI,
			il.SignExtend(8, il.LowPart(4, il.Register(registerSize, REG_HI)))
		));

		il.AddInstruction(il.SetRegister(8, REG_LO,
			il.SignExtend(8, il.LowPart(4, il.Register(registerSize, REG_LO)))
		));
	}
}

#define DEFINE_HILO1(op) \
	auto hi = REG_HI; \
	auto lo = REG_LO; \
	if (instr.operation == op) \
	{ \
		hi = REG_HI1; \
		lo = REG_LO1; \
	}

bool GetLowLevelILForInstruction(Architecture* arch, uint64_t addr, LowLevelILFunction& il, Instruction& instr, size_t addrSize, uint32_t decomposeFlags, MipsVersion version)
{
	LowLevelILLabel trueLabel, falseLabel, doneLabel, dirFlagSet, dirFlagClear, dirFlagDone;
	InstructionOperand& op1 = instr.operands[0];
	InstructionOperand& op2 = instr.operands[1];
	InstructionOperand& op3 = instr.operands[2];
	InstructionOperand& op4 = instr.operands[3];
	LowLevelILLabel trueCode, falseCode, again;
	size_t bytes = 4;
	bool signedFlag = false;
	ExtendType extendType = SignExtend;
	bool saturate = false;
	auto registerSize = [=](const InstructionOperand& op) -> size_t const
	{
		return get_register_width(Reg(op.reg), version);
	};
	BNEndianness endian = arch->GetEndianness();
	switch (instr.operation)
	{
	case MIPS_ADDIU:
		if (version == MIPS_R5900 && op1.reg == REG_SP)
		{
			il.AddInstruction(il.SetRegister(4, op1.reg,
			il.Add(4,
				ReadILOperand(il, instr, 2, registerSize(op2), 4),
				ReadILOperand(il, instr, 3, registerSize(op3), 4))));
			break;
		}
	case MIPS_ADDU:
		extendType = ZeroExtend;
	case MIPS_ADD:
	case MIPS_ADDI:
		if (op2.reg == REG_ZERO)
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, ReadILOperand(il, instr, 3, registerSize(op3), 4), extendType));
		else
			il.AddInstruction(
				SetRegisterOrNop(il, 4, registerSize(op1), op1.reg,
					il.Add(4,
						ReadILOperand(il, instr, 2, registerSize(op2), 4),
						ReadILOperand(il, instr, 3, registerSize(op3), 4)), extendType));
		break;
	case MIPS_DADDU:
	case MIPS_DADDIU:
		extendType = ZeroExtend;
	case MIPS_DADD:
	case MIPS_DADDI:
		if (op2.reg == REG_ZERO)
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, ReadILOperand(il, instr, 3, registerSize(op3)), extendType));
		else
			il.AddInstruction(
				SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
					il.Add(8,
						ReadILOperand(il, instr, 2, registerSize(op2)),
						ReadILOperand(il, instr, 3, registerSize(op3))), extendType));
		break;
	case MIPS_SUBU:
		extendType = ZeroExtend;
	case MIPS_SUB:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg,
							il.Sub(4,
								ReadILOperand(il, instr, 2, registerSize(op2), 4),
								ReadILOperand(il, instr, 3, registerSize(op3), 4)), extendType));
		break;
	case MIPS_DSUBU:
		extendType = ZeroExtend;
	case MIPS_DSUB:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
							il.Sub(8,
								ReadILOperand(il, instr, 2, registerSize(op2), 8),
								ReadILOperand(il, instr, 3, registerSize(op3), 8)), extendType));
		break;
	case MIPS_AND:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op2), registerSize(op1), op1.reg,
							il.And(registerSize(op2),
								ReadILOperand(il, instr, 2, registerSize(op2)),
								ReadILOperand(il, instr, 3, registerSize(op3))), ZeroExtend));
		break;
	case MIPS_ANDI:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op2), registerSize(op1), op1.reg,
							il.And(registerSize(op2),
								ReadILOperand(il, instr, 2, registerSize(op2)),
								il.Operand(1, il.Const(4, 0x0000ffff & op3.immediate))), ZeroExtend));
		break;
	case MIPS_DIV:
		il.AddInstruction(il.SetRegister(get_register_width(REG_LO, version), REG_LO,
							il.DivSigned(4,
								ReadILOperand(il, instr, 1, 4, 4),
								ReadILOperand(il, instr, 2, 4, 4))));
		il.AddInstruction(il.SetRegister(get_register_width(REG_HI, version), REG_HI,
								il.ModSigned(4,
									ReadILOperand(il, instr, 1, 4, 4),
									ReadILOperand(il, instr, 2, 4, 4))));
		SignExtendHiLo(il, 4);
		break;
	case MIPS_DIV1:
		il.AddInstruction(il.SetRegister(8, REG_LO1,
			il.SignExtend(8,
				il.DivSigned(4,
					ReadILOperand(il, instr, 1, 4, 4),
					ReadILOperand(il, instr, 2, 4, 4)))));
		il.AddInstruction(il.SetRegister(8, REG_HI1,
			il.SignExtend(8,
				il.ModSigned(4,
					ReadILOperand(il, instr, 1, 4, 4),
					ReadILOperand(il, instr, 2, 4, 4)))));
		break;
	case MIPS_DIVU1:
	case MIPS_DIVU:
	{
		DEFINE_HILO1(MIPS_DIVU1);
		il.AddInstruction(il.SetRegister(get_register_width(lo, version), lo,
								il.DivUnsigned(4,
									ReadILOperand(il, instr, 1, 4, 4),
									ReadILOperand(il, instr, 2, 4, 4))));
		il.AddInstruction(il.SetRegister(get_register_width(hi, version), hi,
								il.ModUnsigned(4,
									ReadILOperand(il, instr, 1, 4, 4),
									ReadILOperand(il, instr, 2, 4, 4))));
		if (lo == REG_LO)
			SignExtendHiLo(il, registerSize(op1));
		break;
	}
	case MIPS_DDIV:
		il.AddInstruction(il.SetRegister(get_register_width(REG_LO, version), REG_LO,
							il.DivSigned(8,
								ReadILOperand(il, instr, 1, registerSize(op1), 8),
								ReadILOperand(il, instr, 2, registerSize(op2), 8))));
		il.AddInstruction(il.SetRegister(get_register_width(REG_HI, version), REG_HI,
								il.ModSigned(8,
									ReadILOperand(il, instr, 1, registerSize(op1), 8),
									ReadILOperand(il, instr, 2, registerSize(op2), 8))));
		break;
	case MIPS_DDIVU:
		il.AddInstruction(il.SetRegister(get_register_width(REG_LO, version), REG_LO,
								il.DivUnsigned(8,
									ReadILOperand(il, instr, 1, registerSize(op1), 8),
									ReadILOperand(il, instr, 2, registerSize(op2), 8))));
		il.AddInstruction(il.SetRegister(get_register_width(REG_HI, version), REG_HI,
								il.ModUnsigned(8,
									ReadILOperand(il, instr, 1, registerSize(op1), 8),
									ReadILOperand(il, instr, 2, registerSize(op2), 8))));
		break;
	case MIPS_MUL:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg,
							il.Mult(4,
								ReadILOperand(il, instr, 2, registerSize(op2), 4),
								ReadILOperand(il, instr, 3, registerSize(op3), 4))));
		break;
	case MIPS_XOR:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg,
							il.Xor(registerSize(op2),
								ReadILOperand(il, instr, 2, registerSize(op2)),
								ReadILOperand(il, instr, 3, registerSize(op3))), ZeroExtend));
		break;
	case MIPS_XORI:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg,
								il.Xor(registerSize(op2),
									ReadILOperand(il, instr, 2, registerSize(op2)),
									il.Operand(1,il.Const(registerSize(op2), 0x0000ffff & op3.immediate))), ZeroExtend));
		break;
	case MIPS_B:
	case MIPS_J:
		il.AddInstruction(DirectJump(arch, il, op1.immediate, addrSize));
		break;
	case MIPS_JAL:
	case MIPS_BAL:
		if (op1.immediate == (addr + 8)) // Get PC construct
			il.AddInstruction(il.SetRegister(addrSize, REG_RA, il.ConstPointer(addrSize ,addr + 8)));
		else
			il.AddInstruction(il.Call(il.ConstPointer(addrSize, op1.immediate)));
		break;

	case MIPS_BEQ:
	case MIPS_BNE:
	case MIPS_BEQL: //Branch likely
	case MIPS_BNEL:
		ConditionalJump(arch, il, GetConditionForInstruction(il, instr, registerSize), addrSize, op3.immediate, addr + 8);
		return false;

	case MIPS_BEQZ:
	case MIPS_BGEZ:
	case MIPS_BGTZ:
	case MIPS_BLEZ:
	case MIPS_BLTZ:
	case MIPS_BNEZ:
	case MIPS_BGEZL: //Branch likely
	case MIPS_BGTZL:
	case MIPS_BLEZL:
	case MIPS_BLTZL:
		ConditionalJump(arch, il, GetConditionForInstruction(il, instr, registerSize), addrSize, op2.immediate, addr + 8);
		return false;

	case MIPS_BC1F:
	case MIPS_BC1FL:
		if (op1.operandClass == FLAG)
			ConditionalJump(arch, il, il.Not(0, il.Flag(op1.reg)), addrSize, op2.immediate, addr + 8);
		else
			ConditionalJump(arch, il, il.Not(0, il.Flag(FPCCREG_FCC0)), addrSize, op1.immediate, addr + 8);
		return false;

	case MIPS_BC1T:
	case MIPS_BC1TL:
		if (op1.operandClass == FLAG)
			ConditionalJump(arch, il, il.Flag(op1.reg), addrSize, op2.immediate, addr + 8);
		else
			ConditionalJump(arch, il, il.Flag(FPCCREG_FCC0), addrSize, op1.immediate, addr + 8);
		return false;

	case MIPS_BC2F:
	case MIPS_BC2FL:
		if (op1.operandClass == FLAG)
			ConditionalJump(arch, il, il.Not(0, il.Flag(op1.reg)), addrSize, op2.immediate, addr + 8);
		else
			ConditionalJump(arch, il, il.Not(0, il.Flag(CCREG_COC2)), addrSize, op1.immediate, addr + 8);
		return false;

	case MIPS_BC2T:
	case MIPS_BC2TL:
		if (op1.operandClass == FLAG)
			ConditionalJump(arch, il, il.Flag(op1.reg), addrSize, op2.immediate, addr + 8);
		else
			ConditionalJump(arch, il, il.Flag(CCREG_COC2), addrSize, op1.immediate, addr + 8);
		return false;

	case MIPS_BC0F:
	case MIPS_BC0FL:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag(true, CCREG_COC0)}, MIPS_INTRIN_COP0_CONDITION, {}));
		ConditionalJump(arch, il, GetConditionForInstruction(il, instr, registerSize), addrSize, op1.immediate, addr + 8);
		return false;

	case MIPS_BC0T:
	case MIPS_BC0TL:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag(true, CCREG_COC0)}, MIPS_INTRIN_COP0_CONDITION, {}));
		ConditionalJump(arch, il, GetConditionForInstruction(il, instr, registerSize), addrSize, op1.immediate, addr + 8);
		return false;

	case MIPS_BGEZAL:
	case MIPS_BLTZAL:
		il.AddInstruction(il.If(GetConditionForInstruction(il, instr, registerSize), trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Call(ReadILOperand(il, instr, 2, registerSize(op2))));
		il.MarkLabel(falseCode);
		break;

	case MIPS_BREAK:
		il.AddInstruction(il.Breakpoint());
		break;
	case MIPS_CLO:
		//count leading ones
		//algorithm is as follows
		//
		//tmp0 = 0;
		//again:
		//if (((op2 << tmp) & 0x80000000) != 0)
		//{
		//   tmp0 += 1;
		//   goto again;
		//}
		//
		il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Const(4,0)));
		il.MarkLabel(again);
		il.AddInstruction(il.If(il.CompareNotEqual(4,
				il.And(4, il.ShiftLeft(4, ReadILOperand(il, instr, 2, registerSize(op2), 4), il.Register(1, LLIL_TEMP(0))), il.Const(4, 0x80000000)),
				il.Const(4,0)), trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Add(1, il.Const(1,1), il.Register(1, LLIL_TEMP(0)))));
		il.AddInstruction(il.Goto(again));
		il.MarkLabel(falseCode);
		break;
	case MIPS_DCLO:
		//count leading ones
		//algorithm is as follows
		//
		//tmp0 = 0;
		//again:
		//if (((op2 << tmp) & 0x80000000_00000000) != 0)
		//{
		//   tmp0 += 1;
		//   goto again;
		//}
		//
		il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Const(4,0)));
		il.MarkLabel(again);
		il.AddInstruction(il.If(il.CompareNotEqual(8,
				il.And(8, il.ShiftLeft(8, ReadILOperand(il, instr, 2, registerSize(op2), 8), il.Register(1, LLIL_TEMP(0))), il.Const(8, 0x8000000000000000)),
				il.Const(8,0)), trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Add(1, il.Const(1,1), il.Register(1, LLIL_TEMP(0)))));
		il.AddInstruction(il.Goto(again));
		il.MarkLabel(falseCode);
		break;
	case MIPS_CLZ:
		//count leading zeroes
		//algorithm is as follows
		//
		//tmp0 = 0;
		//again:
		//if (((op2 << tmp) & 0x80000000) == 0)
		//{
		//   tmp0 += 1;
		//   goto again;
		//}
		//
		il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Const(4,0)));
		il.MarkLabel(again);
		il.AddInstruction(il.If(il.CompareEqual(4,
				il.And(4, il.ShiftLeft(4, ReadILOperand(il, instr, 2, registerSize(op2), 4), il.Register(1, LLIL_TEMP(0))), il.Const(4, 0x80000000)),
				il.Const(4,0)), trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Add(1, il.Const(1,1), il.Register(1, LLIL_TEMP(0)))));
		il.AddInstruction(il.Goto(again));
		il.MarkLabel(falseCode);
		break;
	case MIPS_DCLZ:
		//count leading zeroes
		//algorithm is as follows
		//
		//tmp0 = 0;
		//again:
		//if (((op2 << tmp) & 0x80000000_00000000) == 0)
		//{
		//   tmp0 += 1;
		//   goto again;
		//}
		//
		il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Const(4,0)));
		il.MarkLabel(again);
		il.AddInstruction(il.If(il.CompareEqual(8,
				il.And(8, il.ShiftLeft(8, ReadILOperand(il, instr, 2, registerSize(op2), 8), il.Register(1, LLIL_TEMP(0))), il.Const(8, 0x8000000000000000)),
				il.Const(8,0)), trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Add(1, il.Const(1,1), il.Register(1, LLIL_TEMP(0)))));
		il.AddInstruction(il.Goto(again));
		il.MarkLabel(falseCode);
		break;
	case MIPS_JALR:
	case MIPS_JALR_HB:
	{
		uint32_t operand = 1;
		if (instr.operands[1].operandClass != NONE)
		{
			operand = 2;
		}
		if (operand == 2 && op1.reg == REG_ZERO && op2.reg == REG_RA)
			il.AddInstruction(il.Return(il.Register(addrSize, REG_RA)));
		else
			il.AddInstruction(il.Call(ReadILOperand(il, instr, operand, registerSize(instr.operands[operand]), addrSize, true)));
	}
		break;
	case MIPS_JR:
	case MIPS_JR_HB:
		if (op1.reg == REG_RA)
			il.AddInstruction(il.Return(ReadILOperand(il, instr, 1, registerSize(op1), addrSize)));
		else
			il.AddInstruction(il.Jump(ReadILOperand(il, instr, 1, registerSize(op1), addrSize)));
		return false;
	case MIPS_ERET:
		il.AddInstruction(il.Return(il.Register(addrSize, REG_ERROR_EPC)));
		break;
	case MIPS_LBUX:
	case MIPS_LBU:
		il.AddInstruction(SetRegisterOrNop(il, 1, registerSize(op1), op1.reg, ReadILOperand(il, instr, 2, registerSize(op2), 1), ZeroExtend));
		break;
	case MIPS_LB:
		il.AddInstruction(SetRegisterOrNop(il, 1, registerSize(op1), op1.reg, ReadILOperand(il, instr, 2, registerSize(op2), 1), SignExtend));
		break;
	case MIPS_MFHI:
		il.AddInstruction(SetRegisterOrNop(il, get_register_width(REG_HI, version), registerSize(op1), op1.reg, il.Register(get_register_width(REG_HI, version), REG_HI)));
		break;
	case MIPS_MFHI1:
		il.AddInstruction(SetRegisterOrNop(il, get_register_width(REG_HI1, version), registerSize(op1), op1.reg, il.Register(get_register_width(REG_HI1, version), REG_HI1)));
		break;
	case MIPS_MFLO:
		il.AddInstruction(SetRegisterOrNop(il, get_register_width(REG_LO, version), registerSize(op1), op1.reg, il.Register(get_register_width(REG_LO, version), REG_LO)));
		break;
	case MIPS_MFLO1:
		il.AddInstruction(SetRegisterOrNop(il, get_register_width(REG_LO1, version), registerSize(op1), op1.reg, il.Register(get_register_width(REG_LO1, version), REG_LO1)));
		break;
	case MIPS_MTHI:
		il.AddInstruction(il.SetRegister(get_register_width(REG_HI, version), REG_HI, ReadILOperand(il, instr, 1, registerSize(op1))));
		break;
	case MIPS_MTHI1:
		il.AddInstruction(il.SetRegister(get_register_width(REG_HI1, version), REG_HI1, ReadILOperand(il, instr, 1, registerSize(op1))));
		break;
	case MIPS_MTLO:
		il.AddInstruction(il.SetRegister(get_register_width(REG_LO, version), REG_LO, ReadILOperand(il, instr, 1, registerSize(op1))));
		break;
	case MIPS_MTLO1:
		il.AddInstruction(il.SetRegister(get_register_width(REG_LO1, version), REG_LO1, ReadILOperand(il, instr, 1, registerSize(op1))));
		break;
	case MIPS_DMFC0:
		il.AddInstruction(MoveFromCoprocessor(0, il, 8, op1.reg, op2.immediate, op3.immediate, decomposeFlags));
		break;
	case MIPS_MFC0:
		il.AddInstruction(MoveFromCoprocessor(0, il, 4, op1.reg, op2.immediate, op3.immediate, decomposeFlags));
		break;
	case MIPS_MFC1:
		if (version == MIPS_R5900)
		{
			il.AddInstruction(
				SetRegisterOrNop(il, 4, 8, op1.reg, il.Register(4, op2.reg)));
			break;
		}
		else
			il.AddInstruction(MoveFromCoprocessor(1, il, 4, op1.reg, op2.immediate, op3.immediate, decomposeFlags));
		break;
	case MIPS_DMFC2:
		il.AddInstruction(MoveFromCoprocessor(2, il, 8, op1.reg, op2.immediate, 0, decomposeFlags));
		break;
	case MIPS_MFC2:
		il.AddInstruction(MoveFromCoprocessor(2, il, 4, op1.reg, op2.immediate, 0, decomposeFlags));
		break;
	case MIPS_DMTC0:
		il.AddInstruction(MoveToCoprocessor(0, il, 8, op2.immediate, op3.immediate, ReadILOperand(il, instr, 1, registerSize(op1)), decomposeFlags));
		break;
	case MIPS_MTC0:
		il.AddInstruction(MoveToCoprocessor(0, il, 4, op2.immediate, op3.immediate, ReadILOperand(il, instr, 1, registerSize(op1)), decomposeFlags));
		break;
	case MIPS_MTC1:
		if (version == MIPS_R5900)
		{
			il.AddInstruction(
				il.SetRegister(4, op2.reg,
					op1.reg == REG_ZERO ? il.Const(4, 0) : il.Register(4, op1.reg)));
			break;
		}
		else
			il.AddInstruction(MoveToCoprocessor(1, il, 4, op2.immediate, op3.immediate, ReadILOperand(il, instr, 1, registerSize(op1)), decomposeFlags));
		break;
	case MIPS_DMTC2:
		il.AddInstruction(MoveToCoprocessor(2, il, 8, op2.immediate, 0, ReadILOperand(il, instr, 1, registerSize(op1)), decomposeFlags));
		break;
	case MIPS_MTC2:
		il.AddInstruction(MoveToCoprocessor(2, il, 4, op2.immediate, 0, ReadILOperand(il, instr, 1, registerSize(op1)), decomposeFlags));
		break;
	case MIPS_MOVE:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, ReadILOperand(il, instr, 2, registerSize(op2))));
		break;
	case MIPS_MOVN:
		il.AddInstruction(il.If(il.CompareNotEqual(registerSize(op3), ReadILOperand(il, instr, 3, registerSize(op3)), il.Const(registerSize(op3), 0)), trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, ReadILOperand(il, instr, 2, registerSize(op2))));
		il.MarkLabel(falseCode);
		break;
	case MIPS_MOVZ:
		il.AddInstruction(il.If(il.CompareEqual(registerSize(op3), ReadILOperand(il, instr, 3, registerSize(op3)), il.Const(registerSize(op3), 0)), trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, ReadILOperand(il, instr, 2, registerSize(op2))));
		il.MarkLabel(falseCode);
		break;
	case MIPS_MSUB:
		//(HI,LO) = (HI,LO) - (GPR[rs] x GPR[rt])
		//
		//tmp0 = REG_HI << 32 | REG_LO
		//(HI,LO) = tmp0 - (op1 * op2)
		il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
				il.Or(8, il.ShiftLeft(8, il.Register(4, REG_HI), il.Const(1, 32)), il.ZeroExtend(8, il.Register(4, REG_LO)))));
		il.AddInstruction(il.SetRegisterSplit(4, REG_HI, REG_LO,
				il.Sub(8, il.Register(8, LLIL_TEMP(0)),
				il.MultDoublePrecSigned(4, ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2))))));

		SignExtendHiLo(il, registerSize(op1));
		break;
	case MIPS_MSUBU:
		//(HI,LO) = (HI,LO) - (GPR[rs] x GPR[rt])
		//
		//tmp0 = REG_HI << 32 | REG_LO
		//(HI,LO) = tmp0 - (op1 * op2)
		il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
				il.Or(8, il.ShiftLeft(8, il.Register(4, REG_HI), il.Const(1, 32)), il.ZeroExtend(8, il.Register(4, REG_LO)))));
		il.AddInstruction(il.SetRegisterSplit(4, REG_HI, REG_LO,
				il.Sub(8, il.Register(8, LLIL_TEMP(0)),
				il.MultDoublePrecUnsigned(4, ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2))))));

		SignExtendHiLo(il, registerSize(op1));
		break;
	case MIPS_MULT1:
	case MIPS_MULT:
		if (version == MIPS_R5900 && instr.numOperands == 3) {
			DEFINE_HILO1(MIPS_MULT1);
			il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
					il.MultDoublePrecSigned(4,
						ReadILOperand(il, instr, 2, 4, 4),
						ReadILOperand(il, instr, 3, 4, 4))));
			il.AddInstruction(il.SetRegisterSplit(4, hi, lo, il.Register(8, LLIL_TEMP(0))));
			if (lo == REG_LO)
				SignExtendHiLo(il, 4);
			auto rd = op1.reg;
			if (rd != REG_ZERO)
				il.AddInstruction(SetRegisterOrNop(il, 4, 8, rd, il.Register(4, LLIL_TEMP(0))));
		}
		else
		{
			DEFINE_HILO1(MIPS_MADD1);
			il.AddInstruction(il.SetRegisterSplit(4, hi, lo,
					il.MultDoublePrecSigned(8,
						ReadILOperand(il, instr, 1, 4, 4),
						ReadILOperand(il, instr, 2, 4, 4))));
			if (lo == REG_LO)
				SignExtendHiLo(il, 4);
		}
		break;
	case MIPS_MULTU1:
	case MIPS_MULTU:
		if (version == MIPS_R5900 && instr.numOperands == 3) {
			DEFINE_HILO1(MIPS_MULTU1);

			il.AddInstruction(il.SetRegisterSplit(4, hi, lo,
				il.MultDoublePrecUnsigned(4,
					ReadILOperand(il, instr, 2, 4),
					ReadILOperand(il, instr, 3, 4))));
			if (lo == REG_LO)
				SignExtendHiLo(il, 4);
			auto rd = op1.reg;
			if (rd != REG_ZERO)
				il.AddInstruction(SetRegisterOrNop(il, 4, 8, rd, il.Register(get_register_width(lo, version), lo)));
		}
		else
		{
			DEFINE_HILO1(MIPS_MULTU1);
			il.AddInstruction(il.SetRegisterSplit(4, hi, lo,
				il.MultDoublePrecUnsigned(4,
					ReadILOperand(il, instr, 1, 4),
					ReadILOperand(il, instr, 2, 4))));
			if (lo == REG_LO)
				SignExtendHiLo(il, 4);
		}
		break;
	case MIPS_DMULT:
		il.AddInstruction(il.SetRegisterSplit(8, REG_HI, REG_LO, il.MultDoublePrecSigned(8, ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2)))));
		break;
	case MIPS_DMULTU:
		il.AddInstruction(il.SetRegisterSplit(8, REG_HI, REG_LO, il.MultDoublePrecUnsigned(8, ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2)))));
		break;
	case MIPS_NEGU:
		// Also, turns out neg and negu are both pseudo instructions for sub/subu
	case MIPS_NEG:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg,
								il.Neg(4, ReadILOperand(il, instr, 2, registerSize(op2)))));
		break;
	case MIPS_NOT:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op2), registerSize(op1), op1.reg,
								il.Not(registerSize(op2), ReadILOperand(il, instr, 2, registerSize(op2)))));
		break;
	case MIPS_NOR:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op2), registerSize(op1), op1.reg,
								il.Not(registerSize(op2), il.Or(registerSize(op2), ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3))))));
		break;
	case MIPS_OR:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op2), registerSize(op1), op1.reg,
								il.Or(registerSize(op2), ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3)))));
		break;
	case MIPS_ORI:
		if (op2.reg == REG_ZERO)
			il.AddInstruction(il.SetRegister(registerSize(op1), op1.reg, il.Operand(1, il.Const(4, 0x0000ffff & op3.immediate))));
		else
			il.AddInstruction(SetRegisterOrNop(il, registerSize(op2), registerSize(op1), op1.reg,
							il.Or(registerSize(op2),
								ReadILOperand(il, instr, 2, registerSize(op2)),
								il.Operand(1, il.Const(4, 0x0000ffff & op3.immediate)))));
		break;
	case MIPS_RDHWR:
	{
		MipsIntrinsic intrinsic;
		switch (op2.immediate)
		{
		case 0: intrinsic = MIPS_INTRIN_HWR0; break;
		case 1: intrinsic = MIPS_INTRIN_HWR1; break;
		case 2: intrinsic = MIPS_INTRIN_HWR2; break;
		case 3: intrinsic = MIPS_INTRIN_HWR3; break;
		default: intrinsic = MIPS_INTRIN_HWR_UNKNOWN;
		}

		if (intrinsic != MIPS_INTRIN_HWR_UNKNOWN)
		{
			il.AddInstruction(
				il.Intrinsic({RegisterOrFlag::Register(op1.reg)}, intrinsic, {})
			);
		}
		else
		{
			il.AddInstruction(
				il.Intrinsic({RegisterOrFlag::Register(op1.reg)}, MIPS_INTRIN_HWR_UNKNOWN, {il.Const(1, op2.immediate)})
			);
		}
		break;
	}
	case MIPS_SW:
		il.AddInstruction(il.Store(4, GetILOperandMemoryAddress(il, op2, addrSize), ReadILOperand(il, instr, 1, registerSize(op1), 4)));
		break;
	case MIPS_SWL:
	{
		int32_t delta = endian == LittleEndian ? -3 : 0;
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(LLIL_TEMP(0)) }, MIPS_INTRIN_GET_LEFT_PART32, { ReadILOperand(il, instr, 1, registerSize(op1), 4) }));
		il.AddInstruction(il.Store(4,
			GetILOperandMemoryAddress(il, op2, addrSize, delta),
			il.Register(4, LLIL_TEMP(0))
		));

		break;
	}

	case MIPS_SDL:
	{
		int32_t delta = endian == LittleEndian ? -7 : 0;
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(LLIL_TEMP(0)) }, MIPS_INTRIN_GET_LEFT_PART64, { ReadILOperand(il, instr, 1, registerSize(op1), 8) }));
		il.AddInstruction(il.Store(8,
			GetILOperandMemoryAddress(il, op2, addrSize, delta),
			il.Register(8, LLIL_TEMP(0))
		));

		break;
	}
	case MIPS_SWR:
	{
		int32_t delta = endian == BigEndian ? -3 : 0;
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(LLIL_TEMP(0)) }, MIPS_INTRIN_GET_RIGHT_PART32, { ReadILOperand(il, instr, 1, registerSize(op1), 4) }));
		il.AddInstruction(il.Store(4,
			GetILOperandMemoryAddress(il, op2, addrSize, delta),
			il.Register(4, LLIL_TEMP(0))
		));

		break;
	}

	case MIPS_SDR:
	{
		int32_t delta = endian == BigEndian ? -7 : 0;
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(LLIL_TEMP(0)) }, MIPS_INTRIN_GET_RIGHT_PART64, { ReadILOperand(il, instr, 1, registerSize(op1), 8) }));
		il.AddInstruction(il.Store(8,
			GetILOperandMemoryAddress(il, op2, addrSize, delta),
			il.Register(8, LLIL_TEMP(0))
		));

		break;
	}

	case MIPS_SC:
	{
		LowLevelILLabel trueCode, falseCode, doneCode;
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(LLIL_TEMP(0)) }, MIPS_INTRIN_LLBIT_CHECK, {}));
		il.AddInstruction(il.If(il.CompareEqual(0, il.Register(0, LLIL_TEMP(0)), il.Const(0, 1)),
								trueCode, falseCode));
		il.MarkLabel(trueCode);

		il.AddInstruction(il.Store(4, GetILOperandMemoryAddress(il, op2, addrSize), ReadILOperand(il, instr, 1, registerSize(op1), 4)));
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, il.Const(0, 1)));
		il.AddInstruction(il.Goto(doneCode));

		il.MarkLabel(falseCode);
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, il.Const(0, 0)));

		il.MarkLabel(doneCode);
		break;
	}
	case MIPS_SD:
		il.AddInstruction(il.Store(8, GetILOperandMemoryAddress(il, op2, addrSize), ReadILOperand(il, instr, 1, registerSize(op1))));
		break;
	case MIPS_SQ:
		// Technically, the store address should be automagically aligned by masking off the low 4 bits...
		// il.AddInstruction(il.Store(16,
		// 	il.And(addrSize, il.Const(addrSize, ~0x0F), GetILOperandMemoryAddress(il, op2, addrSize)),
		// 	ReadILOperand(il, instr, 1, 16)));
		// ...but that makes the IL ugly, so don't bother:
		il.AddInstruction(il.Store(16, GetILOperandMemoryAddress(il, op2, addrSize), ReadILOperand(il, instr, 1, 16)));
		break;
	case MIPS_SCD:
	{
		LowLevelILLabel trueCode, falseCode, doneCode;
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(LLIL_TEMP(0)) }, MIPS_INTRIN_LLBIT_CHECK, {}));
		il.AddInstruction(il.If(il.CompareEqual(0, il.Register(0, LLIL_TEMP(0)), il.Const(0, 1)),
								trueCode, falseCode));
		il.MarkLabel(trueCode);

		il.AddInstruction(il.Store(8, GetILOperandMemoryAddress(il, op2, addrSize), ReadILOperand(il, instr, 1, registerSize(op1), 4)));
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, il.Const(0, 1)));
		il.AddInstruction(il.Goto(doneCode));

		il.MarkLabel(falseCode);
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, il.Const(0, 0)));

		il.MarkLabel(doneCode);
		break;
	}
	case MIPS_SWC1:
		if (version == MIPS_R5900)
		{
			il.AddInstruction(
				il.Store(4, GetILOperandMemoryAddress(il, op2, addrSize),
					il.Register(4, op1.reg)));
		}
		else
		{
			il.AddInstruction(MoveFromCoprocessor(1, il, 4, LLIL_TEMP(0), op1.immediate, 0, decomposeFlags));
			il.AddInstruction(WriteILOperand(il, instr, 1, addrSize, il.Register(4, LLIL_TEMP(0))));
		}
		break;
	case MIPS_SDC1:
		il.AddInstruction(
			il.Store(4, GetILOperandMemoryAddress(il, op2, addrSize),
				il.LowPart(4, il.Register(8, op1.reg))));
		il.AddInstruction(
			il.Store(4, GetILOperandMemoryAddress(il, op2, addrSize, 4),
				il.LogicalShiftRight(4, il.Register(8, op1.reg), il.Const(4, 32))));
		break;
	case MIPS_SDXC1:
		il.AddInstruction(
			il.Store(4, GetILOperandMemoryAddress(il, op2, addrSize),
				il.LowPart(4, il.Register(8, op1.reg))));
		il.AddInstruction(
			il.Store(4, il.Add(addrSize, GetILOperandMemoryAddress(il, op2, addrSize), il.Const(addrSize, 4)),
				il.LogicalShiftRight(4, il.Register(8, op1.reg), il.Const(4, 32))));
		break;
	case MIPS_SWXC1:
		il.AddInstruction(
			il.Store(4, GetILOperandMemoryAddress(il, op2, addrSize),
				il.Register(4, op1.reg)));
		break;
	case MIPS_SWC2:
		il.AddInstruction(MoveFromCoprocessor(2, il, 4, LLIL_TEMP(0), op1.immediate, 0, decomposeFlags));
		il.AddInstruction(WriteILOperand(il, instr, 1, addrSize, il.Register(4, LLIL_TEMP(0))));
		break;
	case MIPS_SDC2:
		il.AddInstruction(MoveFromCoprocessor(2, il, 8, LLIL_TEMP(0), op1.immediate, 0, decomposeFlags));
		il.AddInstruction(WriteILOperand(il, instr, 1, addrSize, il.Register(8, LLIL_TEMP(0))));
		break;
	case MIPS_SWC3:
		il.AddInstruction(MoveFromCoprocessor(3, il, 4, LLIL_TEMP(0), op1.immediate, 0, decomposeFlags));
		il.AddInstruction(WriteILOperand(il, instr, 1, addrSize, il.Register(4, LLIL_TEMP(0))));
		break;
	case MIPS_SDC3:
		il.AddInstruction(MoveFromCoprocessor(3, il, 8, LLIL_TEMP(0), op1.immediate, 0, decomposeFlags));
		il.AddInstruction(WriteILOperand(il, instr, 1, addrSize, il.Register(8, LLIL_TEMP(0))));
		break;
	case MIPS_SYSCALL:
		il.AddInstruction(il.SystemCall());
		break;
	case MIPS_EXT:
		//op1 = op4.imm bits in op2.reg at bit offset op3.imm
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg,
					il.And(registerSize(op1),
						il.LogicalShiftRight(registerSize(op1),
							ReadILOperand(il, instr, 2, registerSize(op2)),
							il.Const(1, op3.immediate)
						),
						il.Const(registerSize(op1), (1<<op4.immediate)-1)
					)));
		break;
	case MIPS_DEXT:
	case MIPS_DEXTM:
	case MIPS_DEXTU:
		//op1 = op4.imm bits in op2.reg at bit offset op3.imm
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
					il.And(8,
						il.LogicalShiftRight(8,
							ReadILOperand(il, instr, 2, registerSize(op2)),
							il.Const(1, op3.immediate)
						),
						il.Const(8, (((uint64_t)1)<<op4.immediate)-1)
					)));
		break;
	case MIPS_INS:
		// recall: pos = op3, size = op4
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg,
					il.Or(registerSize(op1),
						il.And(registerSize(op1),
							ReadILOperand(il, instr, 1, registerSize(op1)),
							il.Const(registerSize(op1), ~(((1<<op4.immediate)-1)<<op3.immediate))
						),
						il.ShiftLeft(registerSize(op1),
							il.And(registerSize(op1),
								ReadILOperand(il, instr, 2, registerSize(op2)),
								il.Const(registerSize(op1), (1<<op4.immediate)-1)
							),
							il.Const(registerSize(op1), op3.immediate)
						)
					)));
		break;
	case MIPS_DINS:
	case MIPS_DINSM:
	case MIPS_DINSU:
		// recall: pos = op3, size = op4
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg,
					il.Or(registerSize(op1),
						il.And(registerSize(op1),
							ReadILOperand(il, instr, 1, registerSize(op1)),
							il.Const(registerSize(op1), ~(((((uint64_t)1)<<op4.immediate)-1)<<op3.immediate))
						),
						il.ShiftLeft(registerSize(op1),
							il.And(registerSize(op1),
								ReadILOperand(il, instr, 2, registerSize(op2)),
								il.Const(registerSize(op1), (((uint64_t)1)<<op4.immediate)-1)
							),
							il.Const(registerSize(op1), op3.immediate)
						)
					)));
		break;
	case MIPS_LUI:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, il.Const(4, op2.immediate << 16)));
		break;
	case MIPS_LI:
	case MIPS_LW:
	case MIPS_LWX:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, ReadILOperand(il, instr, 2, registerSize(op2), 4)));
		break;
	case MIPS_LWU:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, il.ZeroExtend(8, ReadILOperand(il, instr, 2, registerSize(op2), 4))));
		break;
	case MIPS_LD:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, ReadILOperand(il, instr, 2, registerSize(op2))));
		break;
	case MIPS_LQ:
		il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, ReadILOperand(il, instr, 2, addrSize, 16)));
		break;
	case MIPS_LWL:
	{
		int32_t delta = endian == LittleEndian ? -3 : 0;
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, MIPS_INTRIN_SET_LEFT_PART32,
			{
				il.Load(4, GetILOperandMemoryAddress(il, op2, addrSize, delta))
			}
		));

		break;
	}
	case MIPS_LDL:
	{
		int32_t delta = endian == LittleEndian ? -7 : 0;
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, MIPS_INTRIN_SET_LEFT_PART64,
			{
				il.Load(8, GetILOperandMemoryAddress(il, op2, addrSize, delta))
			}
		));

		break;
	}
	case MIPS_LWR:
	{
		int32_t delta = endian == BigEndian ? -3 : 0;
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, MIPS_INTRIN_SET_RIGHT_PART32,
			{
				il.Load(4, GetILOperandMemoryAddress(il, op2, addrSize, delta))
			}
		));

		break;
	}
	case MIPS_LDR:
	{
		int32_t delta = endian == BigEndian ? -7 : 0;
		il.AddInstruction(il.Intrinsic({ RegisterOrFlag::Register(op1.reg) }, MIPS_INTRIN_SET_RIGHT_PART64,
			{
				il.Load(8, GetILOperandMemoryAddress(il, op2, addrSize, delta))
			}
		));

		break;
	}
	case MIPS_LL:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, ReadILOperand(il, instr, 2, registerSize(op2), 4)));
		il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_LLBIT_SET, {il.Const(0, 1)}));
		break;
	case MIPS_LLD:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, ReadILOperand(il, instr, 2, registerSize(op2))));
		il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_LLBIT_SET, {il.Const(0, 1)}));
		break;
	case MIPS_SRA:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, il.ArithShiftRight(4, ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3)))));
		break;
	case MIPS_SRAV:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, il.ArithShiftRight(4, ReadILOperand(il, instr, 2, registerSize(op2)), il.And(4, ReadILOperand(il, instr, 3, registerSize(op3)), il.Const(4, 0x1f)))));
		break;
	case MIPS_SLT:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, il.BoolToInt(registerSize(op1),
			il.CompareSignedLessThan(registerSize(op2), ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3))))));
		break;
	case MIPS_SLTI:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, il.BoolToInt(registerSize(op1),
			il.CompareSignedLessThan(registerSize(op2), ReadILOperand(il, instr, 2, registerSize(op2)), il.Const(registerSize(op2), op3.immediate)))));
		break;
	case MIPS_SLTIU:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, il.BoolToInt(registerSize(op1),
			il.CompareUnsignedLessThan(registerSize(op2), ReadILOperand(il, instr, 2, registerSize(op2)),
				il.Const(registerSize(op2), op3.immediate))), ZeroExtend));
		break;
	case MIPS_SLTU:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), registerSize(op1), op1.reg, il.BoolToInt(registerSize(op1),
			il.CompareUnsignedLessThan(registerSize(op2), ReadILOperand(il, instr, 2, registerSize(op2)),
				ReadILOperand(il, instr, 3, registerSize(op3)))), ZeroExtend));
		break;
	case MIPS_SLL:
		// SLL is unique in that the input doesn't have to be sign extended, and the
		// preferred way to sign extend the lower 32 bits of an register is to shift
		// it left by 0
		if ((version == MIPS_R5900 || version == MIPS_64) && op2.reg != REG_ZERO)
		{
			if (op3.immediate == 0)
			{
				il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg,
					il.SignExtend(8,
						il.LowPart(4,
							ReadILOperand(il, instr, 2, 8)))));
			}
			else
			{
				il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg,
					il.ShiftLeft(registerSize(op1),
						il.SignExtend(registerSize(op1),
							il.LowPart(4, ReadILOperand(il, instr, 2, registerSize(op2)))),
						ReadILOperand(il, instr, 3, registerSize(op2)))));
			}
		}
		else
		{
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg,
				il.ShiftLeft(4,
					ReadILOperand(il, instr, 2, registerSize(op2)),
					ReadILOperand(il, instr, 3, registerSize(op2)))));
		}
		break;
	case MIPS_SLLV:
		il.AddInstruction(SetRegisterOrNop(il, registerSize(op2), registerSize(op1), op1.reg,
			il.ShiftLeft(registerSize(op2),
				ReadILOperand(il, instr, 2, registerSize(op2)),
				il.And(4,
					ReadILOperand(il, instr, 3, registerSize(op3)),
					il.Const(4, 0x1f)))));
		break;
	case MIPS_DSLL32:
		op3.immediate += 32;
		// fall through
	case MIPS_DSLL:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
			il.ShiftLeft(8,
				ReadILOperand(il, instr, 2, registerSize(op2)),
				ReadILOperand(il, instr, 3, registerSize(op3)))));
		break;
	case MIPS_DSLLV:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
			il.ShiftLeft(8,
				ReadILOperand(il, instr, 2, registerSize(op2)),
				il.And(8,
					ReadILOperand(il, instr, 3, registerSize(op3)),
					il.Const(8, 0x3f)))));
		break;
	case MIPS_DSRL32:
		op3.immediate += 32;
		// fall through
	case MIPS_DSRL:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, il.LogicalShiftRight(8, ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3)))));
		break;
	case MIPS_DSRLV:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, il.LogicalShiftRight(8, ReadILOperand(il, instr, 2, registerSize(op2)), il.And(8, ReadILOperand(il, instr, 3, registerSize(op3)), il.Const(8, 0x3f)))));
		break;
	case MIPS_DSRA32:
		op3.immediate += 32;
		// fall through
	case MIPS_DSRA:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, il.ArithShiftRight(8, ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3)))));
		break;
	case MIPS_DSRAV:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, il.ArithShiftRight(8, ReadILOperand(il, instr, 2, registerSize(op2)), il.And(8, ReadILOperand(il, instr, 3, registerSize(op3)), il.Const(8, 0x3f)))));
		break;
	case MIPS_SB:
		il.AddInstruction(il.Store(1,
			GetILOperandMemoryAddress(il, op2, addrSize),
			il.LowPart(1,
				ReadILOperand(il, instr, 1, registerSize(op1)))));
		break;
	case MIPS_TRAP:
		il.AddInstruction(il.Trap(0));
		break;
	case MIPS_TEQI:
	case MIPS_TEQ:
		ConditionExecute(il, il.CompareEqual(4, ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2))),il.Trap(0));
		break;
	case MIPS_TNE:
	case MIPS_TNEI:
		ConditionExecute(il, il.CompareNotEqual(4, ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2))),il.Trap(0));
		break;
	case MIPS_TGE:
	case MIPS_TGEI:
		ConditionExecute(il, il.CompareSignedGreaterEqual(4, ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2))),il.Trap(0));
		break;
	case MIPS_TGEIU:
	case MIPS_TGEU:
		ConditionExecute(il, il.CompareUnsignedGreaterEqual(4, ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2))),il.Trap(0));
		break;
	case MIPS_TLT:
	case MIPS_TLTI:
		ConditionExecute(il, il.CompareSignedLessThan(4, ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2))),il.Trap(0));
		break;
	case MIPS_TLTIU:
	case MIPS_TLTU:
		ConditionExecute(il, il.CompareUnsignedLessThan(4, ReadILOperand(il, instr, 1, registerSize(op1)), ReadILOperand(il, instr, 2, registerSize(op2))),il.Trap(0));
		break;
	case MIPS_LH:
	case MIPS_LHX:
	case MIPS_LHI:
		il.AddInstruction(SetRegisterOrNop(il, 2, registerSize(op1), op1.reg,
			ReadILOperand(il, instr, 2, registerSize(op2), 2), SignExtend));
		break;
	case MIPS_LHU:
		il.AddInstruction(SetRegisterOrNop(il, 2, registerSize(op1), op1.reg,
				ReadILOperand(il, instr, 2, registerSize(op2), 2),
				ZeroExtend));
		break;
	case MIPS_MADD1:
	case MIPS_MADD:
		if (version == MIPS_R5900 && instr.numOperands == 3) {
			DEFINE_HILO1(MIPS_MADD1);
			il.AddInstruction(il.SetRegisterSplit(4, hi, lo,
				il.Add(8,
					il.RegisterSplit(4, hi, lo),
					il.MultDoublePrecSigned(8,
						ReadILOperand(il, instr, 2, 4, 4),
						ReadILOperand(il, instr, 3, 4, 4)
					)
				)
			));
			if (lo == REG_LO)
				SignExtendHiLo(il, 4);
			auto rd = op1.reg;
			if (rd != REG_ZERO)
				il.AddInstruction(SetRegisterOrNop(il, 4, 8, rd, il.Register(get_register_width(lo, version), lo)));
		}
		else
		{
			DEFINE_HILO1(MIPS_MADD1);
			il.AddInstruction(il.SetRegisterSplit(4, hi, lo,
				il.Add(8,
					il.RegisterSplit(4, hi, lo),
					il.MultDoublePrecSigned(4,
						ReadILOperand(il, instr, 1, 4, 4),
						ReadILOperand(il, instr, 2, 4, 4)
					)
				)
			));
			if (lo == REG_LO)
				SignExtendHiLo(il, 4);
		}
		break;
	case MIPS_MADDU1:
	case MIPS_MADDU:
		if (version == MIPS_R5900 && instr.numOperands == 3) {
			DEFINE_HILO1(MIPS_MADDU1);
			il.AddInstruction(il.SetRegisterSplit(4, hi, lo,
				il.Add(8,
					il.RegisterSplit(4, hi, lo),
					il.MultDoublePrecUnsigned(4,
						ReadILOperand(il, instr, 2, 4, 4),
						ReadILOperand(il, instr, 3, 4, 4)
					))));
			if (lo == REG_LO)
				SignExtendHiLo(il, 4);
			auto rd = op1.reg;
			if (rd != REG_ZERO)
				il.AddInstruction(SetRegisterOrNop(il, 4, 8, rd, il.Register(get_register_width(lo, version), lo), ZeroExtend));
		}
		else {
			DEFINE_HILO1(MIPS_MADDU1);
			il.AddInstruction(il.SetRegisterSplit(4, hi, lo,
			il.Add(8,
				il.RegisterSplit(4, hi, lo),
				il.MultDoublePrecUnsigned(4,
					ReadILOperand(il, instr, 1, 4, 4),
					ReadILOperand(il, instr, 2, 4, 4)
				))));
			if (lo == REG_LO)
				SignExtendHiLo(il, 4);
		}
		break;
	case MIPS_DROTR32:
		op3.immediate += 32;
		// fall through
	case MIPS_DROTR:
	case MIPS_DROTRV:
		il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, il.RotateRight(8, ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3)))));
		break;
	case MIPS_ROTR:
	case MIPS_ROTRV:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, il.RotateRight(4, ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3)))));
		break;
	case MIPS_SDBBP:
		il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_SDBBP, { il.Const(1, op1.immediate )}));
		break;
	case MIPS_SEB:
		il.AddInstruction(SetRegisterOrNop(il, 1, registerSize(op1), op1.reg, il.LowPart(1, ReadILOperand(il, instr, 2, registerSize(op2))), SignExtend));
		break;
	case MIPS_SEH:
		il.AddInstruction(SetRegisterOrNop(il, 2, registerSize(op1), op1.reg, il.LowPart(2, ReadILOperand(il, instr, 2, registerSize(op2))), SignExtend));
		break;
	case MIPS_SH:
		il.AddInstruction(il.Store(2, GetILOperandMemoryAddress(il, op2, addrSize), il.LowPart(2, ReadILOperand(il, instr, 1, registerSize(op1)))));
		break;
	case MIPS_SRL:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, il.LogicalShiftRight(4, ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3)))));
		break;
	case MIPS_SRLV:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, il.LogicalShiftRight(4, ReadILOperand(il, instr, 2, registerSize(op2)), il.And(4, ReadILOperand(il, instr, 3, registerSize(op3)), il.Const(4, 0x1f)))));
		break;
	case MIPS_SSNOP:
	case MIPS_NOP:
		il.AddInstruction(il.Nop());
		break;
	case MIPS_WSBH:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op1.reg)}, MIPS_INTRIN_WSBH, {ReadILOperand(il, instr, 2, registerSize(op2))}));
		break;
	case MIPS_DSBH:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op1.reg)}, MIPS_INTRIN_DSBH, {ReadILOperand(il, instr, 2, registerSize(op2))}));
		break;
	case MIPS_DSHD:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op1.reg)}, MIPS_INTRIN_DSHD, {ReadILOperand(il, instr, 2, registerSize(op2))}));
		break;
	case MIPS_BGEZALL:
	case MIPS_BLTZALL:
		break;
	case MIPS_NEG_S:
		il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatNeg(4, il.Register(4, op2.reg))));
		break;
	case MIPS_ABS_S:
	case MIPS_ABS_D:
		il.AddInstruction(il.SetRegister(registerSize(op1), op1.reg, il.FloatAbs(registerSize(op2), il.Register(registerSize(op2), op2.reg))));
		break;
	case MIPS_MOV_S:
		il.AddInstruction(il.SetRegister(registerSize(op1), op1.reg, il.Register(registerSize(op2), op2.reg)));
		break;
	case MIPS_ADD_S:
		il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatAdd(4, il.Register(4, op2.reg), il.Register(4, op3.reg))));
		break;
	case MIPS_ADD_D:
		if (registerSize(op1) < 8)
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
			   il.FloatAdd(8, il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
				   il.RegisterSplit(4, op3.reg + 1, op3.reg))));
		else
			il.AddInstruction(il.SetRegister(registerSize(op1), op1.reg, il.FloatAdd(registerSize(op2), il.Register(registerSize(op2), op2.reg), il.Register(registerSize(op3), op3.reg))));
		break;
	case MIPS_SUB_S:
		il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatSub(4, il.Register(4, op2.reg), il.Register(4, op3.reg))));
		break;
	case MIPS_SUB_D:
		if (registerSize(op1) < 8)
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatSub(8, il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg + 1, op3.reg))));
		else
			il.AddInstruction(il.SetRegister(registerSize(op1), op1.reg, il.FloatSub(registerSize(op2),
				il.Register(registerSize(op2), op2.reg), il.Register(registerSize(op3), op3.reg))));
		break;
	case MIPS_MUL_S:
		il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatMult(4, il.Register(4, op2.reg), il.Register(4, op3.reg))));
		break;
	case MIPS_MUL_D:
		if (registerSize(op1) < 8)
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatMult(8, il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg + 1, op3.reg))));
		else
			il.AddInstruction(il.SetRegister(registerSize(op1), op1.reg, il.FloatMult(registerSize(op2),
				il.Register(registerSize(op2), op2.reg), il.Register(registerSize(op3), op3.reg))));
		break;
	case MIPS_DIV_S:
		il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatDiv(4, il.Register(4, op2.reg), il.Register(4, op3.reg))));
		break;
	case MIPS_DIV_D:
		if (registerSize(op1) < 8)
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatDiv(8, il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg + 1, op3.reg))));
		else
			il.AddInstruction(il.SetRegister(registerSize(op1), op1.reg, il.FloatDiv(registerSize(op2),
				il.Register(registerSize(op2), op2.reg), il.Register(registerSize(op3), op3.reg))));
		break;
	case MIPS_SQRT_S:
		il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatSqrt(4, il.Register(4, op2.reg))));
		break;
	case MIPS_SQRT_D:
		if (registerSize(op1) < 8)
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatSqrt(8, il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
		else
			il.AddInstruction(il.SetRegister(registerSize(op1), op1.reg, il.FloatSqrt(registerSize(op2),
				il.Register(registerSize(op2), op2.reg), il.Register(registerSize(op3), op3.reg))));
		break;
	case MIPS_CVT_S_W:
		il.AddInstruction(il.SetRegister(4, op1.reg, il.IntToFloat(4, ReadILOperand(il, instr, 2, 4))));
		break;
	case MIPS_CVT_D_W:
		if (registerSize(op2) < 8)
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.IntToFloat(8, ReadILOperand(il, instr, 2, 4))));
		else
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, il.IntToFloat(8, il.Register(4, op2.reg))));
		break;
	case MIPS_CVT_W_S:
		il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, il.FloatToInt(4, il.Register(4, op2.reg))));
		break;
	case MIPS_CVT_W_D:
		if (registerSize(op2) < 8)
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, il.FloatToInt(4,
				il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
		else
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize(op1), op1.reg, il.FloatToInt(4, il.Register(registerSize(op2), op2.reg))));
		break;
	case MIPS_CVT_D_S:
		if (registerSize(op2) < 8)
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatConvert(8, il.Register(4, op2.reg))));
		else
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, il.FloatConvert(8, il.Register(4, op2.reg))));
		break;
	case MIPS_CVT_S_D:
		if (registerSize(op2) < 8)
			il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatConvert(4,
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
		else
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, il.FloatConvert(4, il.Register(registerSize(op2), op2.reg))));
		break;
	case MIPS_C_F_S:
	case MIPS_C_F_D:
	case MIPS_C_SF_S:
	case MIPS_C_SF_D:
		if (op1.operandClass == FLAG)
		{
			il.AddInstruction(il.SetFlag(op1.reg, il.Const(0, 0)));
		}
		else
		{
			il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.Const(0, 0)));
		}
		break;
	case MIPS_C_EQ_S:
	case MIPS_C_SEQ_S:
		if (op1.operandClass == FLAG)
		{
			il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareEqual(4,
				il.Register(4, op2.reg), il.Register(4, op3.reg))));
		}
		else
		{
			il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareEqual(4,
				il.Register(4, op1.reg), il.Register(4, op2.reg))));
		}
		break;
	case MIPS_C_EQ_D:
	case MIPS_C_SEQ_D:
		if (op1.operandClass == FLAG)
		{
			if (registerSize(op2) < 8)
				il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareEqual(8,
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg | 1, op3.reg & (~1)))));
			else
				il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareEqual(8,
					il.Register(8, op2.reg), il.Register(8, op3.reg))));
		}
		else
		{
			if (registerSize(op2) < 8)
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareEqual(8,
					il.RegisterSplit(4, op1.reg | 1, op1.reg & (~1)),
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
			else
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareEqual(8,
					il.Register(8, op1.reg), il.Register(8, op2.reg))));
		}
		break;
	case MIPS_C_LE_S:
			if (op1.operandClass == FLAG)
			{
				il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareLessEqual(4,
					il.Register(4, op2.reg), il.Register(4, op3.reg))));
			}
			else
			{
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareLessEqual(4,
					il.Register(4, op1.reg), il.Register(4, op2.reg))));
			}
			break;
		case MIPS_C_LE_D:
			if (op1.operandClass == FLAG)
			{
				if (registerSize(op2) < 8)
					il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareLessEqual(8,
						il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
						il.RegisterSplit(4, op3.reg | 1, op3.reg & (~1)))));
				else
					il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareLessEqual(8,
						il.Register(8, op2.reg), il.Register(8, op3.reg))));
			}
			else
			{
				if (registerSize(op2) < 8)
					il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareLessEqual(8,
						il.RegisterSplit(4, op1.reg | 1, op1.reg & (~1)),
						il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
				else
					il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareLessEqual(8,
						il.Register(8, op1.reg), il.Register(8, op2.reg))));
			}
			break;
		case MIPS_C_LT_S:
			if (op1.operandClass == FLAG)
			{
				il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareLessThan(4,
					il.Register(4, op2.reg), il.Register(4, op3.reg))));
			}
			else
			{
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareLessThan(4,
					il.Register(4, op1.reg), il.Register(4, op2.reg))));
			}
			break;
		case MIPS_C_LT_D:
			if (op1.operandClass == FLAG)
			{
				if (registerSize(op2) < 8)
					il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareLessThan(8,
						il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
						il.RegisterSplit(4, op3.reg | 1, op3.reg & (~1)))));
				else
					il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareLessThan(8,
						il.Register(8, op2.reg), il.Register(8, op3.reg))));
			}
			else
			{
				if (registerSize(op2) < 8)
					il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareLessThan(8,
						il.RegisterSplit(4, op1.reg | 1, op1.reg & (~1)),
						il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
				else
					il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareLessThan(8,
						il.Register(8, op1.reg), il.Register(8, op2.reg))));
			}
			break;
		case MIPS_C_UN_S:
			if (op1.operandClass == FLAG)
			{
				il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareUnordered(4,
					il.Register(4, op2.reg), il.Register(4, op3.reg))));
			}
			else
			{
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareUnordered(4,
					il.Register(4, op1.reg), il.Register(4, op2.reg))));
			}
			break;
		case MIPS_C_UN_D:
			if (op1.operandClass == FLAG)
			{
				if (registerSize(op2) < 8)
					il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareUnordered(8,
						il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
						il.RegisterSplit(4, op3.reg | 1, op3.reg & (~1)))));
				else
					il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareUnordered(8,
						il.Register(8, op2.reg), il.Register(8, op3.reg))));
			}
			else
			{
				if (registerSize(op2) < 8)
					il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareUnordered(8,
						il.RegisterSplit(4, op1.reg | 1, op1.reg & (~1)),
						il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
				else
					il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareUnordered(8,
						il.Register(8, op1.reg), il.Register(8, op2.reg))));
			}
			break;
		case MIPS_C_NGE_S:
			if (op1.operandClass == FLAG)
			{
				il.AddInstruction(il.SetFlag(op1.reg, il.Not(4, il.FloatCompareGreaterEqual(4,
					il.Register(4, op2.reg), il.Register(4, op3.reg)))));
			}
			else
			{
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.Not(4, il.FloatCompareGreaterEqual(4,
					il.Register(4, op1.reg), il.Register(4, op2.reg)))));
			}
			break;
		case MIPS_C_NGE_D:
			if (op1.operandClass == FLAG)
			{
				if (registerSize(op2) < 8)
					il.AddInstruction(il.SetFlag(op1.reg, il.Not(8, il.FloatCompareGreaterEqual(8,
						il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
						il.RegisterSplit(4, op3.reg | 1, op3.reg & (~1))))));
				else
					il.AddInstruction(il.SetFlag(op1.reg, il.Not(8, il.FloatCompareGreaterEqual(8,
						il.Register(8, op2.reg), il.Register(8, op3.reg)))));
			}
			else
			{
				if (registerSize(op2) < 8)
					il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.Not(8, il.FloatCompareGreaterEqual(8,
						il.RegisterSplit(4, op1.reg | 1, op1.reg & (~1)),
						il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1))))));
				else
					il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.Not(8, il.FloatCompareGreaterEqual(8,
						il.Register(8, op1.reg), il.Register(8, op2.reg)))));
			}
			break;
		case MIPS_C_NGT_S:
			if (op1.operandClass == FLAG)
			{
				il.AddInstruction(il.SetFlag(op1.reg, il.Not(4, il.FloatCompareGreaterThan(4,
					il.Register(4, op2.reg), il.Register(4, op3.reg)))));
			}
			else
			{
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.Not(4, il.FloatCompareGreaterThan(4,
					il.Register(4, op1.reg), il.Register(4, op2.reg)))));
			}
			break;
		case MIPS_C_NGT_D:
			if (op1.operandClass == FLAG)
			{
				if (registerSize(op2) < 8)
					il.AddInstruction(il.SetFlag(op1.reg, il.Not(8, il.FloatCompareGreaterThan(8,
						il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
						il.RegisterSplit(4, op3.reg | 1, op3.reg & (~1))))));
				else
					il.AddInstruction(il.SetFlag(op1.reg, il.Not(8, il.FloatCompareGreaterThan(8,
						il.Register(8, op2.reg), il.Register(8, op3.reg)))));
			}
			else
			{
				if (registerSize(op2) < 8)
					il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.Not(8, il.FloatCompareGreaterEqual(8,
						il.RegisterSplit(4, op1.reg | 1, op1.reg & (~1)),
						il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1))))));
				else
					il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.Not(8, il.FloatCompareGreaterEqual(8,
						il.Register(8, op1.reg), il.Register(8, op2.reg)))));
			}
			break;
		case MIPS_SYNC:
		{
			uint64_t stype = 0;
			if (op1.operandClass != NONE)
			{
				stype = op1.immediate;
			}

			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_SYNC, {il.Const(1, stype)}));
			break;
		}

		case MIPS_SYNCI:
			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_SYNCI, { GetILOperandMemoryAddress(il, op1, addrSize) }));
			break;

		case MIPS_DI:
			il.AddInstruction(SimpleIntrinsic(il, MIPS_INTRIN_DI));
			break;

		case MIPS_EHB:
			il.AddInstruction(SimpleIntrinsic(il, MIPS_INTRIN_EHB));
			break;

		case MIPS_EI:
			il.AddInstruction(SimpleIntrinsic(il, MIPS_INTRIN_EI));
			break;

		case MIPS_PAUSE:
			il.AddInstruction(SimpleIntrinsic(il, MIPS_INTRIN_PAUSE));
			break;

		case MIPS_WAIT:
			il.AddInstruction(SimpleIntrinsic(il, MIPS_INTRIN_WAIT));
			break;

		case MIPS_PREF:
			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_PREFETCH, {il.Const(1, op1.immediate), GetILOperandMemoryAddress(il, op2, addrSize)}));
			break;

		case MIPS_CACHE:
			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_CACHE, {il.Const(1, op1.immediate), GetILOperandMemoryAddress(il, op2, addrSize)}));
			break;

		case MIPS_TLBP:
			il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_INDEX)}, MIPS_INTRIN_TLBSEARCH, {il.Register(addrSize, REG_ENTRY_HI)}));
			break;
		case MIPS_TLBR:
			il.AddInstruction(il.Intrinsic({
				RegisterOrFlag::Register(REG_PAGE_MASK),
				RegisterOrFlag::Register(REG_ENTRY_HI),
				RegisterOrFlag::Register(REG_ENTRY_LO1),
				RegisterOrFlag::Register(REG_ENTRY_LO0)
			}, MIPS_INTRIN_TLBGET, { il.Register(addrSize, REG_INDEX) }));
			break;
		case MIPS_TLBWI:
			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_TLBSET, {
				il.Register(addrSize, REG_INDEX),
				il.Register(addrSize, REG_PAGE_MASK),
				il.Register(addrSize, REG_ENTRY_HI),
				il.Register(addrSize, REG_ENTRY_LO1),
				il.Register(addrSize, REG_ENTRY_LO0)
			}));
			break;
		case MIPS_TLBWR:
			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_TLBSET, {
				il.Register(addrSize, REG_RANDOM),
				il.Register(addrSize, REG_PAGE_MASK),
				il.Register(addrSize, REG_ENTRY_HI),
				il.Register(addrSize, REG_ENTRY_LO1),
				il.Register(addrSize, REG_ENTRY_LO0)
			}));
			break;

		case MIPS_TLBINV:
			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_TLBINV, {
				il.Register(addrSize, REG_INDEX),
				il.Register(addrSize, REG_ENTRY_HI)
			}));
			break;

		case MIPS_TLBINVF:
			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_TLBINVF, {
				il.Register(addrSize, REG_INDEX),
			}));
			break;

		case CNMIPS_BADDU:
			il.AddInstruction(SetRegisterOrNop(il, 1, registerSize(op1), op1.reg,
					il.Add(1,
						il.LowPart(1, ReadILOperand(il, instr, 2, registerSize(op2), 8)),
						il.LowPart(1, ReadILOperand(il, instr, 3, registerSize(op3), 8))
					), ZeroExtend));
			break;

		case CNMIPS_BBIT0:
		case CNMIPS_BBIT032:
		case CNMIPS_BBIT1:
		case CNMIPS_BBIT132:
			ConditionalJump(arch, il, GetConditionForInstruction(il, instr, registerSize), addrSize, op3.immediate, addr + 8);
			break;

		case CNMIPS_CINS:
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
				il.ShiftLeft(8,
					il.And(8,
						ReadILOperand(il, instr, 2, registerSize(op2)),
						il.Const(8, (((uint64_t)1) << (op4.immediate + 1)) - 1)),
					il.Const(8, op3.immediate)
				)
			));
			break;

		case CNMIPS_CINS32:
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
				il.ShiftLeft(8,
					il.And(8,
						ReadILOperand(il, instr, 2, registerSize(op2)),
						il.Const(8, (((uint64_t)1) << (op4.immediate + 1)) - 1)),
					il.Const(8, op3.immediate + 32)
				)
			));
			break;

		case CNMIPS_DMUL:
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
								il.Mult(8,
									ReadILOperand(il, instr, 2, registerSize(op2), 8),
									ReadILOperand(il, instr, 3, registerSize(op3), 8))));
			break;

		case CNMIPS_EXTS:
			// recall: p = op3.immediate, lenm1 = op4.immediate
			if (op3.immediate == 0 && op4.immediate == 7)
			{
				il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
					il.SignExtend(8, il.LowPart(1, ReadILOperand(il, instr, 2, registerSize(op2), 1)))  // XXX: 1 => registerSize
				));
			}
			else if (op3.immediate == 0 && op4.immediate == 0xf)
			{
				il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
					il.SignExtend(8, il.LowPart(2, ReadILOperand(il, instr, 2, registerSize(op2), 2)))  // XXX: 2 => registerSize
				));
			}
			else if (op3.immediate == 0 && op4.immediate == 0x1f)
			{
				il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
					il.SignExtend(8, il.LowPart(4, ReadILOperand(il, instr, 2, registerSize(op2), 4)))  // XXX: 4 => registerSize
				));
			}
			else
			{
				il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
					il.ArithShiftRight(8,
						il.ShiftLeft(8,
							ReadILOperand(il, instr, 2, registerSize(op2), 8),
							il.Const(8, 63 - (op3.immediate + op4.immediate))
						),
						il.Const(8, 63 - op4.immediate)
					)
				));
			}
			break;

		case CNMIPS_EXTS32:
			// recall: p = op3.immediate, lenm1 = op4.immediate
			if (op3.immediate + op4.immediate + 32 > 63)
			{
				il.AddInstruction(il.Undefined());
			}
			else
			{
				il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg,
					il.ArithShiftRight(8,
						il.ShiftLeft(8,
							ReadILOperand(il, instr, 2, registerSize(op2), 8),
							il.Const(8, 63 - (32 + op3.immediate + op4.immediate))
						),
						il.Const(8, 63 - op4.immediate)
					)
				));
			}
			break;

		case CNMIPS_POP:
			il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op1.reg)}, CNMIPS_INTRIN_POP, {ReadILOperand(il, instr, 2, registerSize(op2))}));
			break;
		case CNMIPS_DPOP:
			il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op1.reg)}, CNMIPS_INTRIN_DPOP, {ReadILOperand(il, instr, 2, registerSize(op2))}));
			break;
		case CNMIPS_MTM0:
			il.AddInstruction(il.SetRegister(registerSize(op1), CNREG_MPL0, ReadILOperand(il, instr, 1, registerSize(op1))));
			break;
		case CNMIPS_MTM1:
			il.AddInstruction(il.SetRegister(registerSize(op1), CNREG_MPL1, ReadILOperand(il, instr, 1, registerSize(op1))));
			break;
		case CNMIPS_MTM2:
			il.AddInstruction(il.SetRegister(registerSize(op1), CNREG_MPL2, ReadILOperand(il, instr, 1, registerSize(op1))));
			break;
		case CNMIPS_MTP0:
			il.AddInstruction(il.SetRegister(registerSize(op1), CNREG_P0, ReadILOperand(il, instr, 1, registerSize(op1))));
			break;
		case CNMIPS_MTP1:
			il.AddInstruction(il.SetRegister(8, CNREG_P1, ReadILOperand(il, instr, 1, 8)));
			break;
		case CNMIPS_MTP2:
			il.AddInstruction(il.SetRegister(8, CNREG_P2, ReadILOperand(il, instr, 1, 8)));
			break;
		case CNMIPS_RDHWR:
		{
			MipsIntrinsic intrinsic;
			switch (op2.immediate)
			{
				case 30: intrinsic = CNMIPS_INTRIN_HWR30; break;
				case 31: intrinsic = CNMIPS_INTRIN_HWR31; break;
				default: intrinsic = MIPS_INTRIN_HWR_UNKNOWN;
			}

			if (intrinsic != MIPS_INTRIN_HWR_UNKNOWN)
			{
				il.AddInstruction(
					il.Intrinsic({RegisterOrFlag::Register(op1.reg)}, intrinsic, {})
				);
			}
			else
			{
				il.AddInstruction(
					il.Intrinsic({RegisterOrFlag::Register(op1.reg)}, MIPS_INTRIN_HWR_UNKNOWN, {il.Const(1, op2.immediate)})
				);
			}
			break;
		}
		case CNMIPS_SAA:
			il.AddInstruction(
				il.Store(4,
					GetILOperandMemoryAddress(il, op2, addrSize),
					il.Add(4,
						il.Load(4, GetILOperandMemoryAddress(il, op2, addrSize)),
						ReadILOperand(il, instr, 1, registerSize(op1), 4)
					)
				)
			);
			break;

		case CNMIPS_SAAD:
			il.AddInstruction(
				il.Store(8,
					GetILOperandMemoryAddress(il, op2, addrSize),
					il.Add(8,
						il.Load(8, GetILOperandMemoryAddress(il, op2, addrSize)),
						ReadILOperand(il, instr, 1, registerSize(op1), 8)
					)
				)
			);
			break;

		case CNMIPS_SEQ:
			il.AddInstruction(SetRegisterOrNop(il, 1, registerSize(op1), op1.reg, il.BoolToInt(1,
				il.CompareEqual(registerSize(op2), ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3))))));
			break;

		case CNMIPS_SEQI:
			il.AddInstruction(SetRegisterOrNop(il, 1, registerSize(op1), op1.reg, il.BoolToInt(1,
				il.CompareEqual(registerSize(op2), ReadILOperand(il, instr, 2, registerSize(op2)), il.Const(registerSize(op2), op3.immediate)))));
			break;

		case CNMIPS_SNE:
			il.AddInstruction(SetRegisterOrNop(il, 1, registerSize(op1), op1.reg, il.BoolToInt(1,
				il.CompareNotEqual(registerSize(op2), ReadILOperand(il, instr, 2, registerSize(op2)), ReadILOperand(il, instr, 3, registerSize(op3))))));
			break;

		case CNMIPS_SNEI:
			il.AddInstruction(SetRegisterOrNop(il, 1, registerSize(op1), op1.reg, il.BoolToInt(1,
				il.CompareNotEqual(1, ReadILOperand(il, instr, 2, registerSize(op2)), il.Const(registerSize(op2), op3.immediate)))));
			break;

		case CNMIPS_SYNCIOBDMA:
			il.AddInstruction(SimpleIntrinsic(il, CNMIPS_INTRIN_SYNCIOBDMA));
			break;

		case CNMIPS_SYNCS:
			il.AddInstruction(SimpleIntrinsic(il, CNMIPS_INTRIN_SYNCS));
			break;

		case CNMIPS_SYNCW:
			il.AddInstruction(SimpleIntrinsic(il, CNMIPS_INTRIN_SYNCW));
			break;

		case CNMIPS_SYNCWS:
			il.AddInstruction(SimpleIntrinsic(il, CNMIPS_INTRIN_SYNCWS));
			break;

		case CNMIPS_V3MULU:
			// description of this behemoth of an instruction:
			//
			//    ([0:64] || P2 || P1 || P0)
			//  + ([0:192]            || rt)
			//  + (rs x (MPL2 || MPL1 || MPL0))
			//  ------------------------------
			//    (P2 || P1 || P0 || rd)
			//
			// register splits IL operations work with 2 registers, and
			// considering Px registers as subregisters of a massive
			// product register would also introduce complications (for example,
			// note that P0 is in bits 63..0 in the first summand, but then
			// occupies bits 127..64 of the total sum), so the simplest way forward
			// seems to be to do shifts...
			il.AddInstruction(il.SetRegister(0x20, LLIL_TEMP(0),
				il.Add(0x20,
					// [0:64] || P2 || P1 || P0
					Concat3to256(il, CNREG_P2, CNREG_P1, CNREG_P0),
					il.Add(0x20,
						// [0:192] || rt
						il.ZeroExtend(0x20, ReadILOperand(il, instr, 3, 8)),

						// rs x (MPL2 || MPL1 || MPL0)
						il.Mult(0x20,
							il.ZeroExtend(0x20, ReadILOperand(il, instr, 2, 8)),
							Concat3to256(il, CNREG_MPL2, CNREG_MPL1, CNREG_MPL0)
						)
					)
				)
			));

			il.AddInstruction(il.SetRegister(8, CNREG_P2,
				il.LowPart(8, il.LogicalShiftRight(0x20, il.Register(0x20, LLIL_TEMP(0)), il.Const(4, 0xc0)))
			));

			il.AddInstruction(il.SetRegister(8, CNREG_P1,
				il.LowPart(8, il.LogicalShiftRight(0x20, il.Register(0x20, LLIL_TEMP(0)), il.Const(4, 0x80)))
			));

			il.AddInstruction(il.SetRegister(8, CNREG_P0,
				il.LowPart(8, il.LogicalShiftRight(0x20, il.Register(0x20, LLIL_TEMP(0)), il.Const(4, 0x40)))
			));

			il.AddInstruction(SetRegisterOrNop(il, 8, 8, op1.reg, il.LowPart(8, il.Register(0x20, LLIL_TEMP(0)))));

			break;

		case MIPS_MTSAB:
		{
			ExprId shiftAmount;
			if (op1.reg == REG_ZERO)
			{
				shiftAmount = il.Const(4,(op2.immediate & 0xF) << 3);
			}
			else
			{
				auto gprValue = il.Register(4, op1.reg);
				auto gprLS4 = il.And(4, gprValue, il.Const(4, 0xF));
				ExprId xorResult;
				if (op2.immediate & 0xF)
				{
 					// Extract least-significant 4 bits of immediate value
					// auto immLS4 = il.And(4, il.Const(4, op2.immediate), il.Const(4, 0xF));
					auto immLS4 = il.Const(4, op2.immediate & 0xF);

					// Perform XOR operation between GPR[rs][3:0] and immediate[3:0]
					xorResult = il.Xor(4, gprLS4, immLS4);
				}
				else
					xorResult = gprLS4;

				// Multiply result by 8 (equivalent to left shift by 3)
				shiftAmount = il.ShiftLeft(4, xorResult, il.Const(4, 3));
			}

			// Write the result to the SA register
			il.AddInstruction(il.SetRegister(4, R5900_SA, shiftAmount));

			break;
		}
		case MIPS_MTSAH:
		{
			auto rsVal = il.And(4, il.Register(4, op1.reg), il.Const(4, 0b111));
			auto immVal = il.Const(4, op2.immediate & 0b111);

			// Perform XOR
			auto xorVal = il.Xor(4, rsVal, immVal);

			// Multiply by 16
			auto shiftAmount = il.Mult(4, xorVal, il.Const(4, 16));

			// Set the SA register
			il.AddInstruction(il.SetRegister(4, R5900_SA, shiftAmount));

			break;
		}
		case MIPS_QFSRV:
		{
			if (op2.reg == REG_ZERO)
			{
				if (op3.reg == REG_ZERO)
					il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Const(16, 0)));
				else
					il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg,
						il.LogicalShiftRight(16,
							il.Register(16, op3.reg),
							il.Register(1, R5900_SA))));
			}
			else if (op3.reg == REG_ZERO)
				il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg,
					il.ShiftLeft(16,
						il.Register(16, op2.reg),
						il.Register(1, R5900_SA))));
			else
				il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg,
					il.Or(16,
						il.ShiftLeft(16,
							il.Register(16, op2.reg),
							il.Register(1, R5900_SA)),
						il.LogicalShiftRight(16,
							il.Register(16, op3.reg),
							il.Register(1, R5900_SA)))));
			break;
		}
		case MIPS_PADDSB:
			signedFlag = true;
		case MIPS_PADDUB:
			saturate = true;
		case MIPS_PADDB:
		{
			SaturatingAddSub(il, instr, saturate, signedFlag, 1);
			break;
		}
		case MIPS_PADDSH:
			signedFlag = true;
		case MIPS_PADDUH:
			saturate = true;
		case MIPS_PADDH:
		{
			SaturatingAddSub(il, instr, saturate, signedFlag, 2);
			break;
		}
		case MIPS_PADDSW:
			signedFlag = true;
		case MIPS_PADDUW:
			saturate = true;
		case MIPS_PADDW:
		{
			SaturatingAddSub(il, instr, saturate, signedFlag, 4);
			break;
		}
		case MIPS_PSUBSB:
			signedFlag = true;
		case MIPS_PSUBUB:
			saturate = true;
		case MIPS_PSUBB:
		{
			SaturatingAddSub(il, instr, saturate, signedFlag, 1, true);
			break;
		}
		case MIPS_PSUBSH:
			signedFlag = true;
		case MIPS_PSUBUH:
			saturate = true;
		case MIPS_PSUBH:
		{
			SaturatingAddSub(il, instr, saturate, signedFlag, 2, true);
			break;
		}
		case MIPS_PSUBSW:
			signedFlag = true;
		case MIPS_PSUBUW:
			saturate = true;
		case MIPS_PSUBW:
		{
			SaturatingAddSub(il, instr, saturate, signedFlag, 4, true);
			break;
		}

		case MIPS_PCPYUD:
		{
			// TODO: this really requires indexed vector registers
			// il.AddInstruction(il.Unimplemented());
			if (op3.reg == REG_ZERO)
			{
				if (op2.reg == REG_ZERO)
				{
					il.AddInstruction(il.SetRegister(16, op1.reg, il.Const(16, 0)));
				}
				else
				{
					il.AddInstruction(il.SetRegister(16, op1.reg,
					   il.LogicalShiftRight(16,
						   il.Register(16, op2.reg),
						   il.Const(1, 64))));
				}
			}
			else if (op2.reg == REG_ZERO)
			{
				il.AddInstruction(il.SetRegister(16, op1.reg,
					il.And(16, il.Register(16, op3.reg),
						il.ShiftLeft(16, il.Const(8, 0xFFFFFFFFFFFFFFFF), il.Const(1, 64)))));
			}
			else
			{
				il.AddInstruction(il.SetRegister(16, op1.reg,
				   il.Or(16,
					   il.LogicalShiftRight(16,
						   il.Register(16, op2.reg),
						   il.Const(1, 64)),
						   il.And(16, il.Register(16, op3.reg),
							   il.ShiftLeft(16, il.Const(8, 0xFFFFFFFFFFFFFFFF), il.Const(1, 64))))));
			}
			break;
		}
		case MIPS_PCPYLD:
		{
			il.AddInstruction(il.SetRegister(16, op1.reg,
				il.Or(16,
					il.ShiftLeft(16,
						il.Register(16, op2.reg),
						il.Const(1, 64)),
				il.LowPart(8, il.Register(16, op3.reg)))));
			break;
		}
		case MIPS_PCPYH:
		{
			il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0), il.Register(2, op2.reg)));
			il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1), il.LogicalShiftRight(2, il.Register(16, op2.reg), il.Const(1, 64))));
			for (int i = 0; i < 4; i++)
			{
				il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
					il.Or(8,
						il.Register(8, LLIL_TEMP(0)),
						il.ShiftLeft(8,
							il.Register(8, LLIL_TEMP(0)),
							il.Const(1, 16)))));
				il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1),
					il.Or(8,
						il.Register(8, LLIL_TEMP(1)),
						il.ShiftLeft(8,
							il.Register(8, LLIL_TEMP(1)),
							il.Const(1, 16)))));
			}
			il.AddInstruction(il.SetRegister(16, op1.reg,
				il.Or(16, il.Register(8, LLIL_TEMP(0)), il.ShiftLeft(16, il.Register(8, LLIL_TEMP(1)), il.Const(1, 64)))));
			break;
		}
		case MIPS_PAND:
		{
			il.AddInstruction(il.SetRegister(16, op1.reg,
				il.And(16,
					il.Register(16, op2.reg),
					il.Register(16, op3.reg))));
			break;
		}
		case MIPS_PXOR:
		{
			il.AddInstruction(il.SetRegister(16, op1.reg,
				il.Xor(16,
					il.Register(16, op2.reg),
					il.Register(16, op3.reg))));
			break;
		}
		case MIPS_POR:
		{
			il.AddInstruction(il.SetRegister(16, op1.reg,
				il.Xor(16,
					il.Register(16, op2.reg),
					il.Register(16, op3.reg))));
			break;
		}
		case MIPS_PNOR:
		{
			if (op2.reg == REG_ZERO)
			{
				if (op3.reg == REG_ZERO)
					il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Const(16, -1), ZeroExtend));
				else
					il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Not(16, il.Register(16, op3.reg)), ZeroExtend));
			}
			else if (op3.reg == REG_ZERO)
				il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Not(16, il.Register(16, op2.reg)), ZeroExtend));
			else
				il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg,
					il.Not(16,
						il.Or(16,
							il.Register(16, op2.reg),
							il.Register(16, op3.reg))), ZeroExtend));
			break;
		}
		case MIPS_PMINH:
			bytes = 2;
		case MIPS_PMINW:
		{
			ParallelMinMax(il, instr, bytes);
			break;
		}
		case MIPS_PMAXH:
			bytes = 2;
		case MIPS_PMAXW:
		{
			ParallelMinMax(il, instr, bytes, true);
			break;
		}
		case MIPS_PROT3W:
		{
			il.AddInstruction(il.SetRegister(16,
				LLIL_TEMP(0),
					il.ShiftLeft(16, il.LogicalShiftRight(16, il.Register(16, op2.reg), il.Const(1, 96)), il.Const(1, 96))));
			il.AddInstruction(il.SetRegister(16,
				LLIL_TEMP(0),
				il.Or(16,
					il.Register(16, LLIL_TEMP(0)),
					il.ShiftLeft(16, il.And(16, il.Register(16, op2.reg), il.Const(4, 0xFFFFFFFF)), il.Const(1, 64)))));
			il.AddInstruction(il.SetRegister(16,
				LLIL_TEMP(0),
				il.Or(16,
					il.Register(16, LLIL_TEMP(0)),
					il.ShiftLeft(16, il.And(16, il.LogicalShiftRight(16, il.Register(16, op2.reg), il.Const(1, 64)), il.Const(4, 0xFFFFFFFF)), il.Const(1, 32)))));
			il.AddInstruction(il.SetRegister(16,
				LLIL_TEMP(0),
				il.Or(16,
					il.Register(16, LLIL_TEMP(0)),
					il.And(16, il.LogicalShiftRight(16, il.Register(16, op2.reg), il.Const(1, 32)), il.Const(4, 0xFFFFFFFF)))));
			il.AddInstruction(il.SetRegister(16, op1.reg, il.Register(16, LLIL_TEMP(0))));
			break;
		}

		case MIPS_LWXC1:
			il.AddInstruction(
				il.SetRegister(4, op1.reg,
				il.Load(4	, GetILOperandMemoryAddress(il, op2, addrSize))));
			break;
		case MIPS_LDXC1:
		case MIPS_LUXC1:
			// TODO: For LUXC1, this needs verification that it really does the right thing with unaligned addresses in both endiannesses
			il.AddInstruction(
				il.SetRegister(8, op1.reg,
				il.Load(8, GetILOperandMemoryAddress(il, op2, addrSize))));
			break;
		case MIPS_ADDR:
		case MIPS_LLO:
		case MIPS_LWC1:
			il.AddInstruction(
				il.SetRegister(4, op1.reg,
				il.Load(4, GetILOperandMemoryAddress(il, op2, addrSize))));
			break;
		case MIPS_LWC2:
		case MIPS_LWC3:
			il.AddInstruction(MoveToCoprocessor(instr.operation == MIPS_LWC2 ? 2 : 3, il, 4, op1.reg, op1.immediate,
				ReadILOperand(il, instr, 2, registerSize(op2)), decomposeFlags));
			break;
		case MIPS_LDC1:
		case MIPS_LDC2:
		case MIPS_LDC3:
		{
			unsigned cop = 0;
			switch (instr.operation)
			{
				case MIPS_LDC1: cop = 1; break;
				case MIPS_LDC2: cop = 2; break;
				case MIPS_LDC3: cop = 3; break;
				// default: il.Fail("Unhandled LDC1/2/3 instruction");
				default: break;
			}
			if (version == MIPS_R5900 && instr.operation == MIPS_LDC1)
				il.AddInstruction(
					il.SetRegister(8, op1.reg,
					il.Load(8, GetILOperandMemoryAddress(il, op2, addrSize))));
			else
				il.AddInstruction(MoveToCoprocessor(cop, il, 8, op1.reg, op1.immediate,
					ReadILOperand(il, instr, 2, registerSize(op2)), decomposeFlags));
			break;
		}
		case MIPS_MFSA:
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize(op1), op1.reg, il.Register(8, R5900_SA), ZeroExtend));
			break;
		case MIPS_MTSA:
			il.AddInstruction(SetRegisterOrNop(il, registerSize(op1), 8, R5900_SA, il.Register(8, op1.reg), ZeroExtend));
			break;

		case MIPS_ADDA_S:
			if (version == MIPS_R5900)
			{
				il.AddInstruction(il.SetRegister(4, REG_VACC, il.FloatAdd(4, il.Register(4, op1.reg), il.Register(4, op2.reg))));
				break;
			}
		case MIPS_SUBA_S:
			if (version == MIPS_R5900)
			{
				il.AddInstruction(il.SetRegister(4, REG_VACC, il.FloatSub(4, il.Register(4, op1.reg), il.Register(4, op2.reg))));
				break;
			}
		case MIPS_MULA_S:
			if (version == MIPS_R5900)
			{
				il.AddInstruction(il.SetRegister(4, REG_VACC, il.FloatMult(4, il.Register(4, op1.reg), il.Register(4, op2.reg))));
				break;
			}
		case MIPS_MADDA_S:
			if (version == MIPS_R5900)
			{
				il.AddInstruction(il.SetRegister(4, REG_VACC,
				il.FloatAdd(4, il.Register(4, REG_VACC),
						il.FloatMult(4, il.Register(4, op1.reg), il.Register(4, op2.reg)))));
				break;
			}
		case MIPS_MSUBA_S:
			if (version == MIPS_R5900)
			{
				il.AddInstruction(il.SetRegister(4, REG_VACC,
				il.FloatAdd(4, il.Register(4, REG_VACC),
						il.FloatMult(4, il.Register(4, op1.reg), il.Register(4, op2.reg)))));
				break;
			}
		case MIPS_MADD_S:
			if (version == MIPS_R5900)
			{
				il.AddInstruction(il.SetRegister(4, op1.reg,
				il.FloatAdd(4, il.Register(4, REG_VACC),
						il.FloatMult(4, il.Register(4, op2.reg), il.Register(4, op3.reg)))));
				break;
			}
		case MIPS_MSUB_S:
			if (version == MIPS_R5900)
			{
				il.AddInstruction(il.SetRegister(4, op1.reg,
				il.FloatAdd(4, il.Register(4, REG_VACC),
						il.FloatMult(4, il.Register(4, op2.reg), il.Register(4, op3.reg)))));
				break;
			}

		case MIPS_LQC2:
			if (version == MIPS_R5900)
			{
				auto reg = op1.reg;
				if (op2.operandClass == V_REG && reg < REG_VF0)
					reg += REG_VF0;
				il.AddInstruction(il.SetRegister(16, reg,
					ReadILOperand(il, instr, 2, addrSize, 16)));
				break;
			}
		case MIPS_SQC2:
			if (version == MIPS_R5900)
			{
				auto reg = op1.reg;
				if (op2.operandClass == V_REG && reg < REG_VF0)
					reg += REG_VF0;
				il.AddInstruction(
					WriteILOperand(il, instr, 2, 16, il.Register(16, reg)));
				break;
			}
		case MIPS_QMFC2:
		case MIPS_QMFC2_I:
			if (version == MIPS_R5900)
			{
				auto reg = op2.reg;
				if (op2.operandClass == V_REG && reg < REG_VF0)
					reg += REG_VF0;
				il.AddInstruction(
					SetRegisterOrNop(il,16, 16, op1.reg, il.Register(16, reg)));
				break;
			}
		case MIPS_QMTC2:
		case MIPS_QMTC2_I:
			if (version == MIPS_R5900)
			{
				auto reg = op2.reg;
				if (op2.operandClass == V_REG && reg < REG_VF0)
					reg += REG_VF0;
				il.AddInstruction(
					il.SetRegister(16, reg, il.Register(16, op1.reg)));
				break;
			}

		case MIPS_PEXTLW:
		case MIPS_PEXTLH:
		case MIPS_PEXTLB:
		{
			switch (instr.operation)
			{
			case MIPS_PEXTLW: bytes = 4; break;
			case MIPS_PEXTLH: bytes = 2; break;
			case MIPS_PEXTLB: bytes = 1; break;
			default: bytes = 0;
			}
			if (bytes == 0)
			{
				il.AddInstruction((il.Unimplemented()));
				break;
			}
			const uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - (8 * bytes));
			for (int i = 0; i < 8 / bytes; i++)
			{
				if (op2.reg != REG_ZERO)
				{
					if (i == 0)
						il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
							il.ShiftLeft(16,
								il.And(2 * bytes,
									il.Register(16, op2.reg),
									il.Const(8, mask)),
								il.Const(1, 2 * bytes))));
					else
						il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
							il.Or(16, il.Register(16, LLIL_TEMP(0)),
								il.ShiftLeft(16,
									il.And(2 * bytes,
										il.LogicalShiftRight(16,
											il.Register(16, op2.reg),
											il.Const(1, i * (bytes * 8))), il.Const(bytes, mask)),
									il.Const(1, i * (16 * bytes + 1))))));
				}
				if (op3.reg != REG_ZERO)
				{
					if (i == 0)
						il.AddInstruction(il.SetRegister(16, LLIL_TEMP(1),
								il.And(2 * bytes,
									il.Register(16, op3.reg),
									il.Const(bytes, mask))));
					else
						il.AddInstruction(il.SetRegister(16, LLIL_TEMP(1),
							il.Or(16, il.Register(16, LLIL_TEMP(1)),
								il.ShiftLeft(16,
									il.And(2 * bytes,
										il.LogicalShiftRight(16,
											il.Register(16, op3.reg),
											il.Const(1, i * (bytes * 8))), il.Const(bytes, mask)),
									il.Const(1, i * (16 * bytes))))));
				}
			}
			if (op2.reg == REG_ZERO)
			{
				if (op3.reg == REG_ZERO)
					il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Const(16, 0)));
				else
					il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, LLIL_TEMP(1))));
			}
			else if (op3.reg == REG_ZERO)
					il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, LLIL_TEMP(0))));
			else
				il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Or(16, il.Register(16, LLIL_TEMP(0)), il.Register(16, LLIL_TEMP(1)))));
			break;
		}
		case MIPS_PEXTUW:
		case MIPS_PEXTUH:
		case MIPS_PEXTUB:
		{
			switch (instr.operation)
			{
			case MIPS_PEXTUW: bytes = 4; break;
			case MIPS_PEXTUH: bytes = 2; break;
			case MIPS_PEXTUB: bytes = 1; break;
			default: bytes = 0;
			}
			if (bytes == 0)
			{
				il.AddInstruction((il.Unimplemented()));
				break;
			}
			const uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - (8 * bytes));
			for (int i = 0; i < 8 / bytes; i++)
			{
				if (op2.reg != REG_ZERO)
				{
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
						il.Or(16, il.Register(16, LLIL_TEMP(0)),
							il.ShiftLeft(16,
								il.And(2 * bytes,
									il.LogicalShiftRight(16,
										il.Register(16, op2.reg),
										il.Const(1, 64 + i * (bytes * 8))), il.Const(bytes, mask)),
								il.Const(1, i * (16 * bytes + 1))))));
				}
				if (op3.reg != REG_ZERO)
				{
					if (i == 0)
						il.AddInstruction(il.SetRegister(16, LLIL_TEMP(1),
							il.And(2 * bytes,
								il.LogicalShiftRight(16, il.Register(16, op3.reg), il.Const(1, 64)),
									il.Const(bytes, mask))));
					else
						il.AddInstruction(il.SetRegister(16, LLIL_TEMP(1),
							il.Or(16, il.Register(16, LLIL_TEMP(1)),
								il.ShiftLeft(16,
									il.And(2 * bytes,
										il.LogicalShiftRight(16,
											il.Register(16, op3.reg),
											il.Const(1, 64 + i * (bytes * 8))), il.Const(bytes, mask)),
									il.Const(1, i * (16 * bytes))))));
				}
			}
			if (op2.reg == REG_ZERO)
			{
				if (op3.reg == REG_ZERO)
					il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Const(16, 0)));
				else
					il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, LLIL_TEMP(1))));
			}
			else if (op3.reg == REG_ZERO)
					il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, LLIL_TEMP(0))));
			else
				il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Or(16, il.Register(16, LLIL_TEMP(0)), il.Register(16, LLIL_TEMP(1)))));
			break;
		}
		case MIPS_PPACW:
		case MIPS_PPACH:
		case MIPS_PPACB:
		{
			switch (instr.operation)
			{
			case MIPS_PPACW: bytes = 4; break;
			case MIPS_PPACH: bytes = 2; break;
			case MIPS_PPACB: bytes = 1; break;
			default: bytes = 0;
			}
			if (bytes == 0)
			{
				il.AddInstruction((il.Unimplemented()));
				break;
			}
			const uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - (8 * bytes));
			for (int i = 0; i < 8 / bytes; i++)
			{
				if (i == 0)
				{
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
						il.Or(16,
							il.ShiftLeft(16,
								il.And(16,
									il.Register(16, op2.reg),
									il.Const(bytes, mask)),
								il.Const(1, i * bytes * 8 + 64)),
							il.And(16,
								il.Register(16, op3.reg),
								il.Const(bytes, mask)))));
				}
				else
				{
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
					il.Or(16,
						il.Register(16, LLIL_TEMP(0)),
						il.Or(16,
							il.ShiftLeft(16,
								il.And(16,
									il.LogicalShiftRight(16,
										il.Register(16, op2.reg),
										il.Const(1, 2 * i * (bytes * 8))),
									il.Const(bytes, mask)),
								il.Const(1, i * bytes * 8 + 64)),
							il.ShiftLeft(16,
								il.And(16,
									il.LogicalShiftRight(16,
										il.Register(16, op3.reg),
										il.Const(1, 2 * i * (bytes * 8))),
									il.Const(bytes, mask)),
								il.Const(1, i * bytes * 8))))));
				}
			}
			il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, LLIL_TEMP(0))));
			break;
		}

		case MIPS_PSRLH:
			bytes = 2;
		case MIPS_PSRLW:
		{
			if (bytes == 0)
			{
				il.AddInstruction((il.Unimplemented()));
				break;
			}
			const uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - (8 * bytes));
			const uint64_t shift_amount = op3.immediate;
			for (int i = 0; i < 16 / bytes; i++)
			{
				if (i == 0)
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
						il.And(16,
							il.LogicalShiftRight(16,
								il.Register(16, op2.reg),
								il.Const(1, i * 16 + shift_amount)),
							il.Const(16, mask))));
				else
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
						il.Or(16, il.Register(16, LLIL_TEMP(0)),
							il.ShiftLeft(16,
								il.And(16,
									il.LogicalShiftRight(16,
										il.Register(16, op2.reg),
										il.Const(1, i * 16 + shift_amount)),
									il.Const(16, mask)),
								il.Const(1, i * 16)))));
			}
			il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, LLIL_TEMP(0))));
			break;
		}

		case MIPS_PSRAH:
			bytes = 2;
		case MIPS_PSRAW:
		{
			if (bytes == 0)
			{
				il.AddInstruction((il.Unimplemented()));
				break;
			}
			const uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - (8 * bytes));
			const uint64_t shift_amount = op3.immediate;
			for (int i = 0; i < 16 / bytes; i++)
			{
				if (i == 0)
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
						il.SignExtend(bytes,
							il.And(16,
								il.ArithShiftRight(16,
									il.Register(16, op2.reg),
									il.Const(1, i * 16 + shift_amount)),
								il.Const(16, mask)))));
				else
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
						il.Or(16, il.Register(16, LLIL_TEMP(0)),
							il.ShiftLeft(16,
								il.SignExtend(bytes,
									il.And(16,
										il.ArithShiftRight(16,
											il.Register(16, op2.reg),
											il.Const(1, i * 16 + shift_amount)),
										il.Const(16, mask))),
									il.Const(1, i * 16)))));
			}
			il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, LLIL_TEMP(0))));
			break;
		}

		case MIPS_PSLLH:
			bytes = 2;
		case MIPS_PSLLW:
		{
			if (bytes == 0)
			{
				il.AddInstruction((il.Unimplemented()));
				break;
			}
			const uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - (8 * bytes));
			const uint64_t shift_amount = op3.immediate;
			for (int i = 0; i < 16 / bytes; i++)
			{
				if (i == 0)
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
						il.ShiftLeft(16,
							il.And(16,
								il.Register(16, op2.reg),
								il.Const(16, mask)),
							il.Const(1, shift_amount))));
				else
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
						il.Or(16, il.Register(16, LLIL_TEMP(0)),
							il.ShiftLeft(16,
								il.And(16,
									il.LogicalShiftRight(16,
										il.Register(16, op2.reg),
										il.Const(1, i * 16)),
									il.Const(16, mask)),
								il.Const(1, i * 16 + shift_amount)))));
			}
			il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, LLIL_TEMP(0))));
			break;
		}

		case MIPS_PCGTB:
		case MIPS_PCGTH:
		case MIPS_PCGTW:
		{
			if (op2.reg == REG_ZERO && op3.reg == REG_ZERO)
			{
				il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Const(16, 0)));
                break;
			}
			switch (instr.operation)
			{
			case MIPS_PCGTW: bytes = 4; break;
			case MIPS_PCGTH: bytes = 2; break;
			case MIPS_PCGTB: bytes = 1; break;
			default: bytes = 0;
			}
			if (bytes == 0)
			{
				il.AddInstruction((il.Unimplemented()));
				break;
			}
			const uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - (8 * bytes));
			for (int i = 0; i < 16 / bytes; i++)
			{
				if (i == 0)
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
						il.BoolToInt(bytes,
							il.CompareSignedGreaterThan(bytes,
								op2.reg == REG_ZERO ?
								il.Const(bytes, 0) :
								il.And(bytes,
									il.Register(16, op2.reg),
									il.Const(bytes, mask)),
								op3.reg == REG_ZERO ?
								il.Const(bytes, 0) :
								il.And(bytes,
									il.Register(16, op3.reg),
									il.Const(bytes, mask))))));
				else
					il.AddInstruction(il.SetRegister(16, LLIL_TEMP(0),
						il.Or(16, il.Register(16, LLIL_TEMP(0)),
							il.ShiftLeft(16,
								il.BoolToInt(bytes,
									il.CompareSignedGreaterThan(bytes,
										op2.reg == REG_ZERO ?
										il.Const(bytes, 0) :
										il.And(bytes,
											il.LogicalShiftRight(16,
												il.Register(16, op2.reg),
												il.Const(1, i * bytes * 8)),
											il.Const(bytes, mask)),
										op3.reg == REG_ZERO ?
										il.Const(bytes, 0) :
										il.And(bytes,
											il.LogicalShiftRight(16,
												il.Register(16, op3.reg),
												il.Const(1, i * bytes * 8)),
											il.Const(bytes, mask)))),
								il.Const(1, i * bytes * 8)))));
			}
			il.AddInstruction(SetRegisterOrNop(il, 16, 16, op1.reg, il.Register(16, LLIL_TEMP(0))));
			break;
		}

		// case MIPS_PEXCH:
		case MIPS_PEXCW:
		{
			il.AddInstruction(il.SetRegister(16, op1.reg,
				il.Or(16,
					il.Xor(16, il.Register(16, op2.reg),
						il.And(16, il.Register(16, op2.reg),
							il.ShiftLeft(16, il.Const(16, 0xFFFFFFFFFFFFFFFF), il.Const(16, 32)))),
					il.Or(16,
						il.ShiftLeft(16,
							il.And(16, il.LogicalShiftRight(64, il.Register(16, op2.reg), il.Const(16, 64)),
								il.Const(16, 0xFFFFFFFF)),
							il.Const(16, 32)),
						il.ShiftLeft(16,
							il.And(16, il.LogicalShiftRight(64, il.Register(16, op2.reg), il.Const(16, 32)),
								il.Const(16, 0xFFFFFFFF)),
							il.Const(16, 64))
						))));
			break;
		}
		case MIPS_PEXEW:
		{
			il.AddInstruction(il.SetRegister(16, op1.reg,
				il.Or(16,
					il.Xor(16, il.Register(16, op2.reg),
						il.And(16, il.Register(16, op2.reg),
							il.ShiftLeft(16, il.Const(16, 0xFFFFFFFFFFFFFFFF), il.Const(16, 32)))),
					il.Or(16,
						il.ShiftLeft(16,
							il.And(16, il.LogicalShiftRight(64, il.Register(16, op2.reg), il.Const(16, 64)),
								il.Const(16, 0xFFFFFFFF)),
							il.Const(16, 32)),
						il.ShiftLeft(16,
							il.And(16, il.LogicalShiftRight(64, il.Register(16, op2.reg), il.Const(16, 32)),
								il.Const(16, 0xFFFFFFFF)),
							il.Const(16, 64))
						))));
			break;
		}
		case MIPS_PEXT5:
		{
			for (int i = 0; i < 4; i++)
			{
				int shift = i * 32;
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(i),
					il.And(4,
						il.LogicalShiftRight(16,
							il.Register(16, op2.reg),
							il.Const(1, shift)),
						il.Const(2, 0xFFFF))));
				il.AddInstruction(il.SetRegister(4, LLIL_TEMP(i),
					il.ShiftLeft(16,
					il.Or(4,
					il.Or(4,
						il.ShiftLeft(4, il.And(4, il.Register(4, LLIL_TEMP(i)), il.Const(4, 1 << 15)), il.Const(1, 31-15)),
						il.ShiftLeft(4, il.And(4, il.Register(4, LLIL_TEMP(i)), il.Const(4, 0x1f << 10)), il.Const(1, 19-10))),
					il.Or(4,
						il.ShiftLeft(4, il.And(4, il.Register(4, LLIL_TEMP(i)), il.Const(4, 0x1f << 5)), il.Const(1, 11-5)),
						il.ShiftLeft(4, il.And(4, il.Register(4, LLIL_TEMP(i)), il.Const(4, 0x1f)), il.Const(1, 3)))),
						il.Const(1, shift))));

			}
			il.AddInstruction(il.SetRegister(16, op1.reg,
				il.Or(16,
					il.Or(16, il.Register(16, LLIL_TEMP(0)), il.Register(16, LLIL_TEMP(1))),
					il.Or(16, il.Register(16, LLIL_TEMP(2)), il.Register(16, LLIL_TEMP(3))))));

			break;
		}
		case MIPS_PHMADH:
		{
			for (int i = 0; i < 4; i++)
			{
				if (i == 0)
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(i),
						il.Add(4,
							il.Mult(4,
								il.And(4, il.Register(16, op2.reg), il.Const(2, 0xFFFF)),
								il.And(4, il.Register(16, op3.reg), il.Const(2, 0xFFFF))),
							il.Mult(4,
								il.And(4, il.LogicalShiftRight(16, il.Register(16, op2.reg), il.Const(1, i * 32 + 16)), il.Const(2, 0xFFFF)),
								il.And(4, il.LogicalShiftRight(16, il.Register(16, op3.reg), il.Const(1, i * 32 + 16)), il.Const(2, 0xFFFF)))
	                    )));
				else
					il.AddInstruction(il.SetRegister(4, LLIL_TEMP(i),
						il.Add(4,
							il.Mult(4,
								il.And(4, il.LogicalShiftRight(16, il.Register(16, op2.reg), il.Const(1, i * 32)), il.Const(2, 0xFFFF)),
								il.And(4, il.LogicalShiftRight(16, il.Register(16, op3.reg), il.Const(1, i * 32)), il.Const(2, 0xFFFF))),
							il.Mult(4,
								il.And(4, il.LogicalShiftRight(16, il.Register(16, op2.reg), il.Const(1, i * 32 + 16)), il.Const(2, 0xFFFF)),
								il.And(4, il.LogicalShiftRight(16, il.Register(16, op3.reg), il.Const(1, i * 32 + 16)), il.Const(2, 0xFFFF)))
	                    )));
			}
			il.AddInstruction(il.SetRegister(16, REG_LO, il.Or(16,
				il.LowPart(4, il.Register(4, LLIL_TEMP(0))),
				il.ShiftLeft(16, il.LowPart(4, il.Register(4, LLIL_TEMP(2))), il.Const(1, 64)))));
			il.AddInstruction(il.SetRegister(16, REG_HI, il.Or(16,
				il.LowPart(4, il.Register(4, LLIL_TEMP(1))),
				il.ShiftLeft(16, il.LowPart(4, il.Register(4, LLIL_TEMP(3))), il.Const(1, 64)))));
			il.AddInstruction(il.SetRegister(16, op1.reg,
				il.Or(16,
					il.Or(16,
						il.LowPart(4, il.Register(4, LLIL_TEMP(0))),
						il.ShiftLeft(4, il.LowPart(4, il.Register(4, LLIL_TEMP(1))), il.Const(1, 32))),
					il.Or(16,
						il.ShiftLeft(4, il.LowPart(4, il.Register(4, LLIL_TEMP(2))), il.Const(1, 64)),
						il.ShiftLeft(4, il.LowPart(4, il.Register(4, LLIL_TEMP(3))), il.Const(1, 96))))));
			break;
		}

		case MIPS_CTC1:
		case MIPS_CTC2:
			if (version == MIPS_R5900)
			{
				il.AddInstruction(il.SetRegister(4, op2.reg, il.Register(4, op1.reg)));
				break;
			}
		case MIPS_CFC1:
		case MIPS_CFC2:
			if (version == MIPS_R5900)
			{
				il.AddInstruction(il.SetRegister(4, op1.reg, il.Register(4, op2.reg)));
				break;
			}

		case MIPS_MFHC1:
		case MIPS_MFHC2:
		case MIPS_MOVT:
		case MIPS_MULR:

		//unimplemented system functions
		case MIPS_BC1ANY2:
		case MIPS_BC1ANY4:
		case MIPS_C2:
		case MIPS_COP2:
		case MIPS_COP3:
		case MIPS_DERET:
		case MIPS_DRET:
		case MIPS_JALX: //Special instruction for switching to MIPS32/microMIPS32/MIPS16e
		case MIPS_MTHC1:
		case MIPS_MTHC2:
		case MIPS_PREFX:
		case MIPS_WRPGPR:
		case MIPS_RDPGPR:
		case MIPS_SUXC1:
		// Floating point instructions
		case MIPS_RSQRT_D:
		case MIPS_RSQRT_S:
			if (version == MIPS_R5900)
			{
				il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatDiv(4, il.Register(4, op3.reg), il.FloatSqrt(4, il.Register(4, op3.reg)))));
                break;
			}
		case MIPS_RSQRT:
		case MIPS_RSQRT1:
		case MIPS_RSQRT2:
		case MIPS_RECIP1:
		case MIPS_RECIP2:
		case MIPS_RECIP:
		case MIPS_NMADD_D:
		case MIPS_NMADD_PS:
		case MIPS_NMADD_S:
		case MIPS_NMSUB_D:
		case MIPS_NMSUB_PS:
		case MIPS_NMSUB_S:
		case MIPS_MADD_D:
		case MIPS_MADD_PS:
		case MIPS_MADDF_D:
		case MIPS_MADDF_S:
		// Unimplemented R5900 instructions
		case MIPS_DSLRV:
		case MIPS_PMFHL:
		case MIPS_PMTHL:
		case MIPS_PPAC5:
		case MIPS_PABSW:
		case MIPS_PCEQW:
		case MIPS_PADSBH:
		case MIPS_PABSH:
		case MIPS_PCEQH:
		case MIPS_PCEQB:
		case MIPS_PMADDW:
		case MIPS_PSLLVW:
		case MIPS_PSRLVW:
		case MIPS_PMSUBW:
		case MIPS_PMFHI:
		case MIPS_PMFLO:
		case MIPS_PINTH:
		case MIPS_PMULTW:
		case MIPS_PDIVW:
		case MIPS_PMADDH:
		case MIPS_PMSUBH:
		case MIPS_PHMSBH:
		case MIPS_PEXEH:
		case MIPS_PREVH:
		case MIPS_PMULTH:
		case MIPS_PDIVBW:
		case MIPS_PMADDUW:
		case MIPS_PSRAVW:
		case MIPS_PMTHI:
		case MIPS_PMTLO:
		case MIPS_PINTEH:
		case MIPS_PMULTUW:
		case MIPS_PDIVUW:
			il.AddInstruction(il.Unimplemented());
			break;

		case MIPS_MAX_S:
		{
			ConditionExecute(il,
				il.FloatCompareGreaterEqual(4, il.Register(4, op2.reg), il.Register(4, op3.reg)),
				il.SetRegister(4, op1.reg, il.Register(4, op2.reg)),
				il.SetRegister(4, op1.reg, il.Register(4, op3.reg)));
			break;
		}
		case MIPS_MIN_S:
		{
			ConditionExecute(il,
				il.FloatCompareLessEqual(4, il.Register(4, op2.reg), il.Register(4, op3.reg)),
				il.SetRegister(4, op1.reg, il.Register(4, op2.reg)),
				il.SetRegister(4, op1.reg, il.Register(4, op3.reg)));
			break;
		}


		// R5900 VPU0 (macro) instructions
		case MIPS_VNOP:
			il.AddInstruction(il.Nop());
			break;
		case MIPS_VWAITQ:
			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VWAITQ, {}));
			break;

		case MIPS_VMR32:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.Register(4, op3.reg + REG_VF0_Y)));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.Register(4, op3.reg + REG_VF0_Z)));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.Register(4, op3.reg + REG_VF0_W)));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.Register(4, op3.reg + REG_VF0_X)));
			break;
		}
		case MIPS_VABS:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatAbs(4, il.Register(4, op3.reg + REG_VF0_Y))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatAbs(4, il.Register(4, op3.reg + REG_VF0_Z))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatAbs(4, il.Register(4, op3.reg + REG_VF0_W))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatAbs(4, il.Register(4, op3.reg + REG_VF0_X))));
			break;
		}
		case MIPS_VMOVE:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.Register(4, op3.reg + REG_VF0_X)));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.Register(4, op3.reg + REG_VF0_Y)));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.Register(4, op3.reg + REG_VF0_Z)));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.Register(4, op3.reg + REG_VF0_W)));
			break;
		}
		case MIPS_VMFIR:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.SignExtend(4,il.Register(2, op3.reg))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.SignExtend(4,il.Register(2, op3.reg))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.SignExtend(4,il.Register(2, op3.reg))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.SignExtend(4,il.Register(2, op3.reg))));
			break;
		}
		case MIPS_VMTIR:
		{
			il.AddInstruction(il.SetRegister(2, op1.reg, il.Register(4, op2.reg + REG_VF0_X + (op2.immediate - 1) * 33)));
			break;
		}

		case MIPS_VADD:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W))));
			break;
		}
		case MIPS_VADDA:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W))));
			break;
		}
		case MIPS_VADDAx:
		case MIPS_VADDAy:
		case MIPS_VADDAz:
		case MIPS_VADDAw:
		{
			unsigned char dest = op1.reg;
			auto bc = REG_VF0_X + (op4.immediate - 1) * 33;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + bc))));
			break;
		}
		case MIPS_VADDx:
		case MIPS_VADDy:
		case MIPS_VADDz:
		case MIPS_VADDw:
		{
			unsigned char dest = op1.reg;
			auto bc = REG_VF0_X + (op4.immediate - 1) * 33;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + bc))));
			break;
		}
		case MIPS_VADDq:
		case MIPS_VADDi:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatAdd(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg))));
			break;
		}

		// VSUB
		case MIPS_VSUB:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W))));
			break;
		}
		case MIPS_VSUBA:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W))));
			break;
		}
		case MIPS_VSUBAx:
		case MIPS_VSUBAy:
		case MIPS_VSUBAz:
		case MIPS_VSUBAw:
		{
			unsigned char dest = op1.reg;
			auto bc = REG_VF0_X + (op4.immediate - 1) * 33;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + bc))));
			break;
		}
		case MIPS_VSUBx:
		case MIPS_VSUBy:
		case MIPS_VSUBz:
		case MIPS_VSUBw:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg))));
			break;
		}
		case MIPS_VSUBq:
		case MIPS_VSUBi:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatSub(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg))));
			break;
		}

		// VMUL
		case MIPS_VMUL:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W))));
			break;
		}
		case MIPS_VMULA:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W))));
			break;
		}
		case MIPS_VMULAx:
		case MIPS_VMULAy:
		case MIPS_VMULAz:
		case MIPS_VMULAw:
		{
			unsigned char dest = op1.reg;
			auto bc = REG_VF0_X + (op4.immediate - 1) * 33;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + bc))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + bc))));
			break;
		}
		case MIPS_VMULAq:
		case MIPS_VMULAi:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg))));
			break;
		}

		case MIPS_VMULx:
		case MIPS_VMULy:
		case MIPS_VMULz:
		case MIPS_VMULw:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg))));
			break;
		}
		case MIPS_VMULq:
		case MIPS_VMULi:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg))));
			break;
		}

		case MIPS_VMADD:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatAdd(4, il.Register(4, REG_VACC_X), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatAdd(4, il.Register(4, REG_VACC_Y), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatAdd(4, il.Register(4, REG_VACC_Z), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatAdd(4, il.Register(4, REG_VACC_W), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W)))));
			break;
		}
		case MIPS_VMADDA:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_X - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_Y - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_Z - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_W - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W)))));
			break;
		}
		case MIPS_VMSUB:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatSub(4, il.Register(4, REG_VACC_X), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatSub(4, il.Register(4, REG_VACC_Y), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatSub(4, il.Register(4, REG_VACC_Z), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatSub(4, il.Register(4, REG_VACC_W), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W)))));
			break;
		}
		case MIPS_VMSUBA:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_X - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_Y - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_Z - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_W - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W)))));
			break;
		}
		case MIPS_VMADDAx:
		case MIPS_VMADDAy:
		case MIPS_VMADDAz:
		case MIPS_VMADDAw:
		{
			unsigned char dest = op1.reg;
			auto bc = REG_VF0_X + (op4.immediate - 1) * 33;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_X - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_Y - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_Z - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_W - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + bc)))));
			break;
		}
		case MIPS_VMSUBAx:
		case MIPS_VMSUBAy:
		case MIPS_VMSUBAz:
		case MIPS_VMSUBAw:
		{
			unsigned char dest = op1.reg;
			auto bc = REG_VF0_X + (op4.immediate - 1) * 33;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_X - REG_VACC, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_X - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Y - REG_VACC, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_Y - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_Z - REG_VACC, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_Z - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VACC_W - REG_VACC, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_W - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + bc)))));
			break;
		}
		case MIPS_VMADDx:
		case MIPS_VMADDy:
		case MIPS_VMADDz:
		case MIPS_VMADDw:
		{
			unsigned char dest = op1.reg;
			auto bc = REG_VF0_X + (op4.immediate - 1) * 33;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatAdd(4, il.Register(4, REG_VACC_X), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatAdd(4, il.Register(4, REG_VACC_Y), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatAdd(4, il.Register(4, REG_VACC_Z), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatAdd(4, il.Register(4, REG_VACC_W), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + bc)))));
			break;
		}
		case MIPS_VMSUBx:
		case MIPS_VMSUBy:
		case MIPS_VMSUBz:
		case MIPS_VMSUBw:
		{
			unsigned char dest = op1.reg;
			auto bc = REG_VF0_X + (op4.immediate - 1) * 33;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatSub(4, il.Register(4, REG_VACC_X), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatSub(4, il.Register(4, REG_VACC_Y), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatSub(4, il.Register(4, REG_VACC_Z), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + bc)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatSub(4, il.Register(4, REG_VACC_W), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + bc)))));
			break;
		}
		case MIPS_VMADDq:
		case MIPS_VMADDi:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_X - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_Y - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_Z - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatAdd(4, il.Register(4, op2.reg + REG_VACC_W - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg)))));
			break;
		}
		case MIPS_VMSUBq:
		case MIPS_VMSUBi:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_X - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_Y - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_Z - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatSub(4, il.Register(4, op2.reg + REG_VACC_W - REG_VACC), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg)))));
			break;
		}
		case MIPS_VDIV:
		{
			il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatDiv(4, il.Register(4, op2.reg + REG_VF0_X + (op2.immediate) * 33), il.Register(4, op3.reg + REG_VF0_X + (op3.immediate) * 33))));
			break;
		}

		case MIPS_VSQRT:
		{
			il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatSqrt(4, il.Register(4, op2.reg + REG_VF0_X + (op2.immediate) * 33))));
			break;
		}
		case MIPS_VRSQRT:
		{
			il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatDiv(4, il.Register(4, op2.reg + REG_VF0_X + (op2.immediate) * 33), il.FloatSqrt(4, il.Register(4, op3.reg + REG_VF0_X + (op3.immediate) * 33)))));
			break;
		}

		// VF[fd]x = ACCx - VF[fs]y × VF[ft]z
		// VF[fd]y = ACCy - VF[fs]z × VF[ft]x
		// VF[fd]z = ACCz - VF[fs]x × VF[ft]y
		case MIPS_VOPMSUB:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatSub(4, il.Register(4, REG_VACC_X), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Z)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatSub(4, il.Register(4, REG_VACC_Y), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_X)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatSub(4, il.Register(4, REG_VACC_Z), il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_Y)))));
			break;
		}
		// ACCx = VF[fs]y × VF[ft]z
		// ACCy = VF[fs]z × VF[ft]x
		// ACCz = VF[fs]x × VF[ft]y
		case MIPS_VOPMULA:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, REG_VACC_X, il.FloatMult(4, il.Register(4, op2.reg + REG_VF0_Y), il.Register(4, op3.reg + REG_VF0_Z))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, REG_VACC_Y, il.FloatMult(4, il.Register(4, op2.reg + REG_VF0_Z), il.Register(4, op3.reg + REG_VF0_X))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, REG_VACC_Z, il.FloatMult(4, il.Register(4, op2.reg + REG_VF0_X), il.Register(4, op3.reg + REG_VF0_Y))));
			break;
		}

		case MIPS_VILWR:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op2.reg)}, MIPS_INTRIN_R5900_VU_MEM_LOAD, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 0)}));
			if (dest & (1 << 2))
				il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op2.reg)}, MIPS_INTRIN_R5900_VU_MEM_LOAD, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 1)}));
			if (dest & (1 << 1))
				il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op2.reg)}, MIPS_INTRIN_R5900_VU_MEM_LOAD, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 2)}));
			if (dest & (1 << 0))
				il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op2.reg)}, MIPS_INTRIN_R5900_VU_MEM_LOAD, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 3)}));
			break;
		}

		case MIPS_VISWR:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VU_MEM_STORE, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 0), il.Register(4, op2.reg)}));
			if (dest & (1 << 2))
				il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VU_MEM_STORE, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 1), il.Register(4, op2.reg)}));
			if (dest & (1 << 1))
				il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VU_MEM_STORE, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 2), il.Register(4, op2.reg)}));
			if (dest & (1 << 0))
				il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VU_MEM_STORE, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 3), il.Register(4, op2.reg)}));
			break;
		}

		case MIPS_VLQI:
		case MIPS_VLQD:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op2.reg + REG_VF0_X)}, MIPS_INTRIN_R5900_VU_MEM_LOAD, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 0)}));
			if (dest & (1 << 2))
				il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op2.reg + REG_VF0_Y)}, MIPS_INTRIN_R5900_VU_MEM_LOAD, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 1)}));
			if (dest & (1 << 1))
				il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op2.reg + REG_VF0_Z)}, MIPS_INTRIN_R5900_VU_MEM_LOAD, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 2)}));
			if (dest & (1 << 0))
				il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op2.reg + REG_VF0_W)}, MIPS_INTRIN_R5900_VU_MEM_LOAD, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 3)}));
			il.AddInstruction(il.SetRegister(2, op3.reg, il.Add(2, il.Register(2, op3.reg), il.Const(2, op1.immediate))));
			break;
		}

		case MIPS_VSQI:
		case MIPS_VSQD:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VU_MEM_STORE, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 0), il.Register(4, op2.reg + REG_VF0_X)}));
			if (dest & (1 << 2))
				il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VU_MEM_STORE, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 1), il.Register(4, op2.reg + REG_VF0_Y)}));
			if (dest & (1 << 1))
				il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VU_MEM_STORE, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 2), il.Register(4, op2.reg + REG_VF0_Z)}));
			if (dest & (1 << 0))
				il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VU_MEM_STORE, {il.Mult(4, il.Register(4, op3.reg), il.Const(4, 16)), il.Const(2, 3), il.Register(4, op2.reg + REG_VF0_W)}));
			il.AddInstruction(il.SetRegister(2, op3.reg, il.Add(2, il.Register(2, op3.reg), il.Const(2, op1.immediate))));
			break;
		}

		case MIPS_VCALLMS:
		{
			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VU0_CALLMS, {il.Const(4, op1.immediate << 3)}));
			break;
		}
		case MIPS_VCALLMSR:
		{
			il.AddInstruction(il.Intrinsic({}, MIPS_INTRIN_R5900_VU0_CALLMSR, {}));
			break;
		}

		case MIPS_VIADD:
		case MIPS_VIADDI:
		{
			il.AddInstruction(il.SetRegister(2, op1.reg, il.Add(2, il.Register(2, op2.reg), ReadILOperand(il, instr, 3, 2, 1))));
            break;
		}
		case MIPS_VFTOI0:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatToInt(4, il.Register(4, op3.reg + REG_VF0_X))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatToInt(4, il.Register(4, op3.reg + REG_VF0_Y))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatToInt(4, il.Register(4, op3.reg + REG_VF0_Z))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatToInt(4, il.Register(4, op3.reg + REG_VF0_W))));
			break;
		}
		case MIPS_VITOF0:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.IntToFloat(4, il.Register(4, op3.reg + REG_VF0_X))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.IntToFloat(4, il.Register(4, op3.reg + REG_VF0_Y))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.IntToFloat(4, il.Register(4, op3.reg + REG_VF0_Z))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.IntToFloat(4, il.Register(4, op3.reg + REG_VF0_W))));
			break;
		}
		case MIPS_VFTOI15:
		case MIPS_VFTOI12:
		case MIPS_VFTOI4:
		{
			int shift = 4;
			switch (instr.operation)
			{
				case MIPS_VFTOI15: shift = 15; break;
                case MIPS_VFTOI12: shift = 12; break;
                case MIPS_VFTOI4: shift = 4; break;
				default: shift = 0;
			}
			if (shift == 0)
			{
				il.AddInstruction((il.Unimplemented()));
				break;
			}
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.RoundToInt(4, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_X), il.FloatConstSingle(1 << shift)))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.RoundToInt(4, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Y), il.FloatConstSingle(1 << shift)))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.RoundToInt(4, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_Z), il.FloatConstSingle(1 << shift)))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.RoundToInt(4, il.FloatMult(4, il.Register(4, op3.reg + REG_VF0_W), il.FloatConstSingle(1 << shift)))));
			break;
		}
		case MIPS_VITOF15:
		case MIPS_VITOF12:
		case MIPS_VITOF4:
		{
			int shift = 4;
			switch (instr.operation)
			{
				case MIPS_VITOF15: shift = 15; break;
                case MIPS_VITOF12: shift = 12; break;
                case MIPS_VITOF4: shift = 4; break;
			default: shift = 0;
			}
			if (shift == 0)
			{
				il.AddInstruction((il.Unimplemented()));
				break;
			}
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_X, il.FloatDiv(4, il.Register(4, op3.reg + REG_VF0_X), il.FloatConstSingle(1 << shift))));
			if (dest & (1 << 2))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Y, il.FloatDiv(4, il.Register(4, op3.reg + REG_VF0_Y), il.FloatConstSingle(1 << shift))));
			if (dest & (1 << 1))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_Z, il.FloatDiv(4, il.Register(4, op3.reg + REG_VF0_Z), il.FloatConstSingle(1 << shift))));
			if (dest & (1 << 0))
				il.AddInstruction(il.SetRegister(4, op2.reg + REG_VF0_W, il.FloatDiv(4, il.Register(4, op3.reg + REG_VF0_W), il.FloatConstSingle(1 << shift))));
			break;
		}
		case MIPS_VIOR:
		{
			il.AddInstruction(il.SetRegister(2, op1.reg, il.Or(2, il.Register(2, op2.reg), il.Register(2, op3.reg))));
			break;
		}
		case MIPS_VMINI:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				ConditionExecute(il,
					il.FloatCompareLessThan(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X)),
					il.SetRegister(4, op2.reg + REG_VF0_X, il.Register(4, op3.reg + REG_VF0_X)),

					il.SetRegister(4, op2.reg + REG_VF0_X, il.Register(4, op4.reg + REG_VF0_X)));
			if (dest & (1 << 2))
				ConditionExecute(il,
					il.FloatCompareLessThan(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y)),
					il.SetRegister(4, op2.reg + REG_VF0_Y, il.Register(4, op3.reg + REG_VF0_Y)),

					il.SetRegister(4, op2.reg + REG_VF0_Y, il.Register(4, op4.reg + REG_VF0_Y)));
			if (dest & (1 << 1))
				ConditionExecute(il,
					il.FloatCompareLessThan(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z)),
					il.SetRegister(4, op2.reg + REG_VF0_Z, il.Register(4, op3.reg + REG_VF0_Z)),

					il.SetRegister(4, op2.reg + REG_VF0_Z, il.Register(4, op4.reg + REG_VF0_Z)));
			if (dest & (1 << 0))
				ConditionExecute(il,
					il.FloatCompareLessThan(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W)),
					il.SetRegister(4, op2.reg + REG_VF0_W, il.Register(4, op3.reg + REG_VF0_W)),

					il.SetRegister(4, op2.reg + REG_VF0_W, il.Register(4, op4.reg + REG_VF0_W)));
			break;
		}
		case MIPS_VMINIx:
		case MIPS_VMINIy:
		case MIPS_VMINIz:
		case MIPS_VMINIw:
		{
			unsigned char dest = op1.reg;
			auto bc = REG_VF0_X + (op4.immediate - 1) * 33;
			if (dest & (1 << 3))
				ConditionExecute(il,
					il.FloatCompareLessThan(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + bc)),
					il.SetRegister(4, op2.reg + REG_VF0_X, il.Register(4, op3.reg + REG_VF0_X)),

					il.SetRegister(4, op2.reg + REG_VF0_X, il.Register(4, op4.reg + bc)));
			if (dest & (1 << 2))
				ConditionExecute(il,
					il.FloatCompareLessThan(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + bc)),
					il.SetRegister(4, op2.reg + REG_VF0_Y, il.Register(4, op3.reg + REG_VF0_Y)),

					il.SetRegister(4, op2.reg + REG_VF0_Y, il.Register(4, op4.reg + bc)));
			if (dest & (1 << 1))
				ConditionExecute(il,
					il.FloatCompareLessThan(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + bc)),
					il.SetRegister(4, op2.reg + REG_VF0_Z, il.Register(4, op3.reg + REG_VF0_Z)),

					il.SetRegister(4, op2.reg + REG_VF0_Z, il.Register(4, op4.reg + bc)));
			if (dest & (1 << 0))
				ConditionExecute(il,
					il.FloatCompareLessThan(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + bc)),
					il.SetRegister(4, op2.reg + REG_VF0_W, il.Register(4, op3.reg + REG_VF0_W)),

					il.SetRegister(4, op2.reg + REG_VF0_W, il.Register(4, op4.reg + bc)));
			break;
		}
		case MIPS_VMAX:
		{
			unsigned char dest = op1.reg;
			if (dest & (1 << 3))
				ConditionExecute(il,
					il.FloatCompareGreaterThan(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + REG_VF0_X)),
					il.SetRegister(4, op2.reg + REG_VF0_X, il.Register(4, op3.reg + REG_VF0_X)),

					il.SetRegister(4, op2.reg + REG_VF0_X, il.Register(4, op4.reg + REG_VF0_X)));
			if (dest & (1 << 2))
				ConditionExecute(il,
					il.FloatCompareGreaterThan(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + REG_VF0_Y)),
					il.SetRegister(4, op2.reg + REG_VF0_Y, il.Register(4, op3.reg + REG_VF0_Y)),

					il.SetRegister(4, op2.reg + REG_VF0_Y, il.Register(4, op4.reg + REG_VF0_Y)));
			if (dest & (1 << 1))
				ConditionExecute(il,
					il.FloatCompareGreaterThan(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + REG_VF0_Z)),
					il.SetRegister(4, op2.reg + REG_VF0_Z, il.Register(4, op3.reg + REG_VF0_Z)),

					il.SetRegister(4, op2.reg + REG_VF0_Z, il.Register(4, op4.reg + REG_VF0_Z)));
			if (dest & (1 << 0))
				ConditionExecute(il,
					il.FloatCompareGreaterThan(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + REG_VF0_W)),
					il.SetRegister(4, op2.reg + REG_VF0_W, il.Register(4, op3.reg + REG_VF0_W)),

					il.SetRegister(4, op2.reg + REG_VF0_W, il.Register(4, op4.reg + REG_VF0_W)));
			break;
		}
		case MIPS_VMAXx:
		case MIPS_VMAXy:
		case MIPS_VMAXz:
		case MIPS_VMAXw:
		{
			unsigned char dest = op1.reg;
			auto bc = REG_VF0_X + (op4.immediate - 1) * 33;
			if (dest & (1 << 3))
				ConditionExecute(il,
					il.FloatCompareGreaterThan(4, il.Register(4, op3.reg + REG_VF0_X), il.Register(4, op4.reg + bc)),
					il.SetRegister(4, op2.reg + REG_VF0_X, il.Register(4, op3.reg + REG_VF0_X)),

					il.SetRegister(4, op2.reg + REG_VF0_X, il.Register(4, op4.reg + bc)));
			if (dest & (1 << 2))
				ConditionExecute(il,
					il.FloatCompareGreaterThan(4, il.Register(4, op3.reg + REG_VF0_Y), il.Register(4, op4.reg + bc)),
					il.SetRegister(4, op2.reg + REG_VF0_Y, il.Register(4, op3.reg + REG_VF0_Y)),

					il.SetRegister(4, op2.reg + REG_VF0_Y, il.Register(4, op4.reg + bc)));
			if (dest & (1 << 1))
				ConditionExecute(il,
					il.FloatCompareGreaterThan(4, il.Register(4, op3.reg + REG_VF0_Z), il.Register(4, op4.reg + bc)),
					il.SetRegister(4, op2.reg + REG_VF0_Z, il.Register(4, op3.reg + REG_VF0_Z)),

					il.SetRegister(4, op2.reg + REG_VF0_Z, il.Register(4, op4.reg + bc)));
			if (dest & (1 << 0))
				ConditionExecute(il,
					il.FloatCompareGreaterThan(4, il.Register(4, op3.reg + REG_VF0_W), il.Register(4, op4.reg + bc)),
					il.SetRegister(4, op2.reg + REG_VF0_W, il.Register(4, op3.reg + REG_VF0_W)),

					il.SetRegister(4, op2.reg + REG_VF0_W, il.Register(4, op4.reg + bc)));
			break;
		}

		// instructions that are just internal placeholders for other
		// decode tables; these will never be implemented because they're
		// not real instructions
		case MIPS_BSHFL:
		case MIPS_COP0:
		case MIPS_COP1:
		case MIPS_COP1X:
		case MIPS_MMI0:
		case MIPS_MMI1:
		case MIPS_MMI2:
		case MIPS_MMI3:
			il.AddInstruction(il.Undefined());
			break;

		default:
			il.AddInstruction(il.Unimplemented());
			break;
	}
	return true;
}
