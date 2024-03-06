#include "il.h"

using namespace BinaryNinja;
using namespace mips;

#define INVALID_EXPRID ((uint32_t)-1)

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


static size_t GetILOperandMemoryAddress(LowLevelILFunction& il, InstructionOperand& operand, size_t addrSize)
{
	size_t offset = 0;
	if (operand.reg == REG_ZERO)
		return il.ConstPointer(addrSize, operand.immediate);

	if (operand.operandClass == MEM_IMM)
	{
		if (operand.immediate  >= 0x80000000)
			offset = il.Sub(addrSize,
					il.Register(addrSize, operand.reg),
					il.Const(addrSize, -(int32_t)operand.immediate));
		else
			offset = il.Add(addrSize,
						il.Register(addrSize, operand.reg),
						il.Const(addrSize, operand.immediate));
	}
	else if (operand.operandClass == MEM_REG)
	{
		if (operand.immediate  >= 0x80000000)
			offset = il.Sub(addrSize,
						il.Register(addrSize, operand.reg),
						il.Register(addrSize, -(int32_t)operand.immediate));
		else
			offset = il.Add(addrSize,
						il.Register(addrSize, operand.reg),
						il.Register(addrSize, operand.immediate));
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
	if (opSize == SIZE_MAX) {
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

ExprId GetConditionForInstruction(LowLevelILFunction& il, Instruction& instr, size_t registerSize)
{
	switch (instr.operation)
	{
	case MIPS_BEQ:
	case MIPS_BEQL:
		return il.CompareEqual(registerSize, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize));
	case MIPS_BNE:
	case MIPS_BNEL:
		return il.CompareNotEqual(registerSize, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize));
	case MIPS_BEQZ:
		return il.CompareEqual(registerSize, ReadILOperand(il, instr, 1, registerSize), il.Const(registerSize, 0));
	case MIPS_BGEZ:
	case MIPS_BGEZL:
	case MIPS_BGEZAL:
		return il.CompareSignedGreaterEqual(registerSize, ReadILOperand(il, instr, 1, registerSize), il.Const(registerSize, 0));
	case MIPS_BGTZ:
	case MIPS_BGTZL:
		return il.CompareSignedGreaterThan(registerSize, ReadILOperand(il, instr, 1, registerSize), il.Const(registerSize, 0));
	case MIPS_BLEZ:
	case MIPS_BLEZL:
		return il.CompareSignedLessEqual(registerSize, ReadILOperand(il, instr, 1, registerSize), il.Const(registerSize, 0));
	case MIPS_BLTZ:
	case MIPS_BLTZL:
	case MIPS_BLTZAL:
		return il.CompareSignedLessThan(registerSize, ReadILOperand(il, instr, 1, registerSize), il.Const(registerSize, 0));
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
	default:
		LogError("Missing conditional: %d", instr.operation);
		return il.Unimplemented();
	}
}

// Get the IL Register for a given cop0 register/selector pair.
// Returns REG_ZERO for unsupported/unimplemented values.
static Reg GetCop0Register(uint32_t reg, uint64_t sel)
{
	switch (reg) {
		case 0:
			switch (sel) {
				case 0: return REG_INDEX;
				case 1: return REG_MVP_CONTROL;
				case 2: return REG_MVP_CONF0;
				case 3: return REG_MVP_CONF1;
			}
			break;
		case 1:
			switch (sel) {
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
			switch (sel) {
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
			switch (sel) {
				case 0: return REG_ENTRY_LO1;
			}
			break;
		case 4:
			switch (sel) {
				case 0: return REG_CONTEXT;
				case 1: return REG_CONTEXT_CONFIG;
			}
			break;
		case 5:
			switch (sel) {
				case 0: return REG_PAGE_MASK;
				case 1: return REG_PAGE_GRAIN;
			}
			break;
		case 6:
			switch (sel) {
				case 0: return REG_WIRED;
				case 1: return REG_SRS_CONF0;
				case 2: return REG_SRS_CONF1;
				case 3: return REG_SRS_CONF2;
				case 4: return REG_SRS_CONF3;
				case 5: return REG_SRS_CONF4;
			}
			break;
		case 7:
			switch (sel) {
				case 0: return REG_HWR_ENA;
			}
			break;
		case 8:
			switch (sel) {
				case 0: return REG_BAD_VADDR;
			}
			break;
		case 9:
			switch (sel) {
				case 0: return REG_COUNT;
			}
			break;
		case 10:
			switch (sel) {
				case 0: return REG_ENTRY_HI;
			}
			break;
		case 11:
			switch (sel) {
				case 0: return REG_COMPARE;
			}
			break;
		case 12:
			switch (sel) {
				case 0: return REG_STATUS;
				case 1: return REG_INT_CTL;
				case 2: return REG_SRS_CTL;
				case 3: return REG_SRS_MAP;
			}
			break;
		case 13:
			switch (sel) {
				case 0: return REG_CAUSE;
			}
			break;
		case 14:
			switch (sel) {
				case 0: return REG_EPC;
			}
			break;
		case 15:
			switch (sel) {
				case 0: return REG_PR_ID;
				case 1: return REG_EBASE;
			}
			break;
		case 16:
			switch (sel) {
				case 0: return REG_CONFIG;
				case 1: return REG_CONFIG1;
				case 2: return REG_CONFIG2;
				case 3: return REG_CONFIG3;
			}
			break;
		case 17:
			switch (sel) {
				case 0: return REG_LLADDR;
			}
			break;
		case 20:
			switch (sel) {
				case 0: return REG_XCONTEXT;
			}
			break;
		case 23:
			switch (sel) {
				case 0: return REG_DEBUG;
				case 1: return REG_TRACE_CONTROL;
				case 2: return REG_TRACE_CONTROL2;
				case 3: return REG_USER_TRACE_DATA;
				case 4: return REG_TRACE_BPC;
			}
			break;
		case 24:
			switch (sel) {
				case 0: return REG_DEPC;
			}
			break;
		case 26:
			switch (sel) {
				case 0: return REG_ERR_CTL;
			}
			break;
		case 27:
			switch (sel) {
				case 0: return REG_CACHE_ERR0;
				case 1: return REG_CACHE_ERR1;
				case 2: return REG_CACHE_ERR2;
				case 3: return REG_CACHE_ERR3;
			}
			break;
		case 30:
			switch (sel) {
				case 0: return REG_ERROR_EPC;
			}
			break;
		case 31:
			switch (sel) {
				case 0: return REG_DESAVE;
			}
			break;
	}
	return REG_ZERO;
}

static ExprId MoveFromCoprocessor(unsigned cop, LowLevelILFunction& il, size_t loadSize, uint32_t outReg, uint32_t reg, uint64_t sel)
{
	if (cop == 0) {
		Reg copReg = GetCop0Register(reg, sel);
		switch (copReg) {
			case REG_ZERO: /* Unimplemented coprocessor register */
				break;
			default:
				return il.Intrinsic(
						{RegisterOrFlag::Register(outReg)},
						loadSize == 4 ? MIPS_INTRIN_MFC0 : MIPS_INTRIN_DMFC0,
						{il.Register(loadSize, copReg)});
		}
	}

	return il.Intrinsic(
			{RegisterOrFlag::Register(outReg)},
			loadSize == 4 ? MIPS_INTRIN_MFC_UNIMPLEMENTED : MIPS_INTRIN_DMFC_UNIMPLEMENTED,
			{il.Const(4, cop), il.Const(4, reg), il.Const(4, sel)});
}

static ExprId MoveToCoprocessor(unsigned cop, LowLevelILFunction& il, size_t storeSize, uint32_t reg, uint64_t sel, ExprId srcExpr)
{
	if (cop == 0) {
		Reg copReg = GetCop0Register(reg, sel);
		switch (copReg) {
			case REG_ZERO: /* Unimplemented coprocessor register */
				break;
			default:
				return il.Intrinsic(
						{},
						storeSize == 4 ? MIPS_INTRIN_MTC0 : MIPS_INTRIN_DMTC0,
						{il.Register(storeSize, copReg), srcExpr});
		}
	}

	return il.Intrinsic(
			{},
			storeSize == 4 ? MIPS_INTRIN_MTC_UNIMPLEMENTED : MIPS_INTRIN_DMTC_UNIMPLEMENTED,
			{il.Const(4, cop), il.Const(4, reg), il.Const(4, sel), srcExpr});
}

bool GetLowLevelILForInstruction(Architecture* arch, uint64_t addr, LowLevelILFunction& il, Instruction& instr, size_t addrSize)
{
	LowLevelILLabel trueLabel, falseLabel, doneLabel, dirFlagSet, dirFlagClear, dirFlagDone;
	InstructionOperand& op1 = instr.operands[0];
	InstructionOperand& op2 = instr.operands[1];
	InstructionOperand& op3 = instr.operands[2];
	InstructionOperand& op4 = instr.operands[3];
	LowLevelILLabel trueCode, falseCode, again;
	size_t registerSize = addrSize;
	switch (instr.operation)
	{
		case MIPS_ADD:
		case MIPS_ADDU:
		case MIPS_ADDI:
		case MIPS_ADDIU:
			if (op2.reg == REG_ZERO)
				il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, ReadILOperand(il, instr, 3, registerSize, 4)));
			else
				il.AddInstruction(
					SetRegisterOrNop(il, 4, registerSize, op1.reg,
						il.Add(4,
							ReadILOperand(il, instr, 2, registerSize, 4),
							ReadILOperand(il, instr, 3, registerSize, 4))));
			break;
		case MIPS_DADD:
		case MIPS_DADDU:
		case MIPS_DADDI:
		case MIPS_DADDIU:
			if (op2.reg == REG_ZERO)
				il.AddInstruction(SetRegisterOrNop(il, 8, registerSize, op1.reg, ReadILOperand(il, instr, 3, registerSize)));
			else
				il.AddInstruction(
					SetRegisterOrNop(il, 8, registerSize, op1.reg,
						il.Add(8,
							ReadILOperand(il, instr, 2, registerSize),
							ReadILOperand(il, instr, 3, registerSize))));
			break;
		case MIPS_SUB:
		case MIPS_SUBU:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
								il.Sub(4,
									ReadILOperand(il, instr, 2, registerSize, 4),
									ReadILOperand(il, instr, 3, registerSize, 4))));
			break;
		case MIPS_AND:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg,
								il.And(4,
									ReadILOperand(il, instr, 2, registerSize),
									ReadILOperand(il, instr, 3, registerSize))));
			break;
		case MIPS_ANDI:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg,
								il.And(4,
									ReadILOperand(il, instr, 2, registerSize),
									il.Operand(1, il.Const(4, 0x0000ffff & op3.immediate)))));
			break;
		case MIPS_DIV:
			il.AddInstruction(il.SetRegister(4, REG_LO,
								il.DivSigned(4,
									ReadILOperand(il, instr, 1, registerSize, 4),
									ReadILOperand(il, instr, 2, registerSize, 4))));
			il.AddInstruction(il.SetRegister(4, REG_HI,
									il.ModSigned(4,
										ReadILOperand(il, instr, 1, registerSize, 4),
										ReadILOperand(il, instr, 2, registerSize, 4))));
			break;
		case MIPS_DIVU:
			il.AddInstruction(il.SetRegister(4, REG_LO,
									il.DivUnsigned(4,
										ReadILOperand(il, instr, 1, registerSize, 4),
										ReadILOperand(il, instr, 2, registerSize, 4))));
			il.AddInstruction(il.SetRegister(4, REG_HI,
									il.ModUnsigned(4,
										ReadILOperand(il, instr, 1, registerSize, 4),
										ReadILOperand(il, instr, 2, registerSize, 4))));
			break;
		case MIPS_MUL:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
								il.Mult(4,
									ReadILOperand(il, instr, 2, registerSize, 4),
									ReadILOperand(il, instr, 3, registerSize, 4))));
			break;
		case MIPS_XOR:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
								il.Xor(4,
									ReadILOperand(il, instr, 2, registerSize),
									ReadILOperand(il, instr, 3, registerSize))));
			break;
		case MIPS_XORI:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
									il.Xor(4,
										ReadILOperand(il, instr, 2, registerSize, 4),
										il.Operand(1,il.Const(4, 0x0000ffff & op3.immediate)))));
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
				il.AddInstruction(il.Call(il.ConstPointer(4, op1.immediate)));
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

		case MIPS_BGEZAL:
		case MIPS_BLTZAL:
			il.AddInstruction(il.If(GetConditionForInstruction(il, instr, registerSize), trueCode, falseCode));
			il.MarkLabel(trueCode);
			il.AddInstruction(il.Call(ReadILOperand(il, instr, 2, registerSize)));
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
					il.And(4, il.ShiftLeft(4, ReadILOperand(il, instr, 2, registerSize, 4), il.Register(1, LLIL_TEMP(0))), il.Const(4, 0x80000000)),
					il.Const(4,0)), trueCode, falseCode));
			il.MarkLabel(trueCode);
			il.AddInstruction(il.SetRegister(1, LLIL_TEMP(0), il.Add(1, il.Const(1,1), il.Register(1, LLIL_TEMP(0)))));
			il.AddInstruction(il.Goto(again));
			il.MarkLabel(falseCode);
			break;
		case MIPS_CLZ:
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
			il.AddInstruction(il.If(il.CompareEqual(4,
					il.And(4, il.ShiftLeft(4, ReadILOperand(il, instr, 2, registerSize, 4), il.Register(1, LLIL_TEMP(0))), il.Const(4, 0x80000000)),
					il.Const(4,0)), trueCode, falseCode));
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
				il.AddInstruction(il.Call(ReadILOperand(il, instr, operand, registerSize, addrSize, true)));
			}
			break;
		case MIPS_JR:
		case MIPS_JR_HB:
			if (op1.reg == REG_RA)
				il.AddInstruction(il.Return(ReadILOperand(il, instr, 1, registerSize)));
			else
				il.AddInstruction(il.Jump(ReadILOperand(il, instr, 1, registerSize)));
			return false;
		case MIPS_ERET:
			il.AddInstruction(il.Return(il.Register(registerSize, REG_ERROR_EPC)));
			break;
		case MIPS_LBUX:
		case MIPS_LBU:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, il.ZeroExtend(registerSize, ReadILOperand(il, instr, 2, registerSize, 1))));
			break;
		case MIPS_LB:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, il.SignExtend(registerSize, ReadILOperand(il, instr, 2, registerSize, 1))));
			break;
		case MIPS_MFHI:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, il.Register(registerSize, REG_HI)));
			break;
		case MIPS_MFLO:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, il.Register(registerSize, REG_LO)));
			break;
		case MIPS_MTHI:
			il.AddInstruction(il.SetRegister(registerSize, REG_HI, ReadILOperand(il, instr, 1, registerSize)));
			break;
		case MIPS_MTLO:
			il.AddInstruction(il.SetRegister(registerSize, REG_LO, ReadILOperand(il, instr, 1, registerSize)));
			break;
		case MIPS_DMFC0:
			il.AddInstruction(MoveFromCoprocessor(0, il, 8, op1.reg, op2.immediate, op3.immediate));
			break;
		case MIPS_MFC0:
			il.AddInstruction(MoveFromCoprocessor(0, il, 4, op1.reg, op2.immediate, op3.immediate));
			break;
		case MIPS_MFC1:
			il.AddInstruction(MoveFromCoprocessor(1, il, 4, op1.reg, op2.immediate, op3.immediate));
			break;
		case MIPS_MFC2:
			il.AddInstruction(MoveFromCoprocessor(2, il, 4, op1.reg, op2.immediate, op3.immediate));
			break;
		case MIPS_DMTC0:
			il.AddInstruction(MoveToCoprocessor(0, il, 8, op2.immediate, op3.immediate, ReadILOperand(il, instr, 1, registerSize)));
			break;
		case MIPS_MTC0:
			il.AddInstruction(MoveToCoprocessor(0, il, 4, op2.immediate, op3.immediate, ReadILOperand(il, instr, 1, registerSize)));
			break;
		case MIPS_MTC1:
			il.AddInstruction(MoveToCoprocessor(1, il, 4, op2.immediate, op3.immediate, ReadILOperand(il, instr, 1, registerSize)));
			break;
		case MIPS_MTC2:
			il.AddInstruction(MoveToCoprocessor(2, il, 4, op2.immediate, op3.immediate, ReadILOperand(il, instr, 1, registerSize)));
			break;
		case MIPS_MOVE:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, ReadILOperand(il, instr, 2, registerSize)));
			break;
		case MIPS_MOVN:
			il.AddInstruction(il.If(il.CompareNotEqual(registerSize, ReadILOperand(il, instr, 3, registerSize), il.Const(registerSize, 0)), trueCode, falseCode));
			il.MarkLabel(trueCode);
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, ReadILOperand(il, instr, 2, registerSize)));
			il.MarkLabel(falseCode);
			break;
		case MIPS_MOVZ:
			il.AddInstruction(il.If(il.CompareEqual(registerSize, ReadILOperand(il, instr, 3, registerSize), il.Const(registerSize, 0)), trueCode, falseCode));
			il.MarkLabel(trueCode);
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, ReadILOperand(il, instr, 2, registerSize)));
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
					il.MultDoublePrecSigned(4, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize)))));
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
					il.MultDoublePrecUnsigned(8, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize)))));
			break;
		case MIPS_MULT:
			il.AddInstruction(il.SetRegisterSplit(4, REG_HI, REG_LO, il.MultDoublePrecSigned(8, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize))));
			break;
		case MIPS_MULTU:
			il.AddInstruction(il.SetRegisterSplit(4, REG_HI, REG_LO, il.MultDoublePrecUnsigned(8, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize))));
			break;
		case MIPS_NEG:
		case MIPS_NEGU:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
									il.Neg(4, ReadILOperand(il, instr, 2, registerSize))));
			break;
		case MIPS_NOT:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
									il.Not(4, ReadILOperand(il, instr, 2, registerSize))));
			break;
		case MIPS_NOR:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
									il.Not(4, il.Or(4, ReadILOperand(il, instr, 2, registerSize), ReadILOperand(il, instr, 3, registerSize)))));
			break;
		case MIPS_OR:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
									il.Or(4, ReadILOperand(il, instr, 2, registerSize), ReadILOperand(il, instr, 3, registerSize))));
			break;
		case MIPS_ORI:
			if (op2.reg == REG_ZERO)
				il.AddInstruction(il.SetRegister(4, op1.reg, il.Operand(1, il.Const(4, 0x0000ffff & op3.immediate))));
			else
				il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
								il.Or(4,
									ReadILOperand(il, instr, 2, registerSize),
									il.Operand(1, il.Const(4, 0x0000ffff & op3.immediate)))));
			break;
		case MIPS_RDHWR:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.Unimplemented()));
			break;
		case MIPS_SW:
			il.AddInstruction(il.Store(4, GetILOperandMemoryAddress(il, op2, addrSize), ReadILOperand(il, instr, 1, registerSize, 4)));
			break;
		case MIPS_SD:
			il.AddInstruction(il.Store(8, GetILOperandMemoryAddress(il, op2, addrSize), ReadILOperand(il, instr, 1, registerSize)));
			break;
		case MIPS_SWC1:
			il.AddInstruction(MoveFromCoprocessor(1, il, 4, LLIL_TEMP(0), op1.immediate, 0));
			il.AddInstruction(WriteILOperand(il, instr, 1, addrSize, il.Register(4, LLIL_TEMP(0))));
			break;
		case MIPS_SWC2:
			il.AddInstruction(MoveFromCoprocessor(2, il, 4, LLIL_TEMP(0), op1.immediate, 0));
			il.AddInstruction(WriteILOperand(il, instr, 1, addrSize, il.Register(4, LLIL_TEMP(0))));
			break;
		case MIPS_SWC3:
			il.AddInstruction(MoveFromCoprocessor(3, il, 4, LLIL_TEMP(0), op1.immediate, 0));
			il.AddInstruction(WriteILOperand(il, instr, 1, addrSize, il.Register(4, LLIL_TEMP(0))));
			break;
		case MIPS_SWL:
			il.AddInstruction(il.Store(2,
				GetILOperandMemoryAddress(il, op2, addrSize),
				il.LogicalShiftRight(4, ReadILOperand(il, instr, 1, registerSize, 4), il.Const(1, 16))));
			break;
		case MIPS_SWR:
			il.AddInstruction(il.Store(2,
				il.Sub(4, GetILOperandMemoryAddress(il, op2, addrSize), il.Const(4, 1)),
				il.And(4, ReadILOperand(il, instr, 1, registerSize, 4), il.Const(4, 0xffff))));
			break;
		case MIPS_SYSCALL:
			il.AddInstruction(il.SystemCall());
			break;
		case MIPS_EXT:
			//op1 = op4.imm bits in op2.reg at bit offset op3.imm
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg,
						il.And(registerSize,
							il.Const(registerSize, (1<<op4.immediate)-1),
							il.ShiftLeft(registerSize, ReadILOperand(il, instr, 2, registerSize),
								il.Const(1, op3.immediate)))));
			break;
		case MIPS_INS:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg,
						il.Or(registerSize,
							il.And(registerSize,
								il.Const(registerSize, ((1<<op4.immediate)-1)<<op3.immediate),
								ReadILOperand(il, instr, 1, registerSize)),
							il.And(registerSize,
								il.Const(registerSize, (1<<op4.immediate)-1),
								ReadILOperand(il, instr, 2, registerSize)))));
			break;
		case MIPS_LUI:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.Const(4, op2.immediate << 16)));
			break;
		case MIPS_LI:
		case MIPS_LW:
		case MIPS_LWX:
		case MIPS_LL: // TODO: Atomic access primitives
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, ReadILOperand(il, instr, 2, registerSize, 4)));
			break;
		case MIPS_LD:
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize, op1.reg, ReadILOperand(il, instr, 2, registerSize)));
			break;
		case MIPS_SRA:
		case MIPS_SRAV:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.ArithShiftRight(4, ReadILOperand(il, instr, 2, registerSize), ReadILOperand(il, instr, 3, registerSize))));
			break;
		case MIPS_SLT:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, il.BoolToInt(registerSize,
				il.CompareSignedLessThan(registerSize, ReadILOperand(il, instr, 2, registerSize), ReadILOperand(il, instr, 3, registerSize)))));
			break;
		case MIPS_SLTI:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, il.BoolToInt(registerSize,
				il.CompareSignedLessThan(registerSize, ReadILOperand(il, instr, 2, registerSize), il.Const(registerSize, op3.immediate)))));
			break;
		case MIPS_SLTIU:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, il.BoolToInt(registerSize,
				il.CompareUnsignedLessThan(registerSize, ReadILOperand(il, instr, 2, registerSize), il.Const(registerSize, op3.immediate)))));
			break;
		case MIPS_SLTU:
			il.AddInstruction(SetRegisterOrNop(il, registerSize, registerSize, op1.reg, il.BoolToInt(registerSize,
				il.CompareUnsignedLessThan(registerSize, ReadILOperand(il, instr, 2, registerSize), ReadILOperand(il, instr, 3, registerSize)))));
			break;
		case MIPS_SLL:
		case MIPS_SLLV:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.ShiftLeft(4, ReadILOperand(il, instr, 2, registerSize), ReadILOperand(il, instr, 3, registerSize))));
			break;
		case MIPS_DSLL:
		case MIPS_DSLL32:
			if (registerSize != 8) {
				il.AddInstruction(il.Unimplemented());
				break;
			}
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize, op1.reg, il.ShiftLeft(8, ReadILOperand(il, instr, 2, registerSize), ReadILOperand(il, instr, 3, registerSize))));
			break;
		case MIPS_DSRL:
		case MIPS_DSRL32:
			if (registerSize != 8) {
				il.AddInstruction(il.Unimplemented());
				break;
			}
			il.AddInstruction(SetRegisterOrNop(il, 8, registerSize, op1.reg, il.LogicalShiftRight(8, ReadILOperand(il, instr, 2, registerSize), ReadILOperand(il, instr, 3, registerSize))));
			break;
		case MIPS_SB:
			il.AddInstruction(il.Store(1, GetILOperandMemoryAddress(il, op2, addrSize), il.LowPart(1, ReadILOperand(il, instr, 1, registerSize))));
			break;
		case MIPS_TRAP:
			il.AddInstruction(il.Trap(0));
			break;
		case MIPS_TEQI:
		case MIPS_TEQ:
			ConditionExecute(il, il.CompareEqual(4, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize)),il.Trap(0));
			break;
		case MIPS_TNE:
		case MIPS_TNEI:
			ConditionExecute(il, il.CompareNotEqual(4, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize)),il.Trap(0));
			break;
		case MIPS_TGE:
		case MIPS_TGEI:
			ConditionExecute(il, il.CompareSignedGreaterEqual(4, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize)),il.Trap(0));
			break;
		case MIPS_TGEIU:
		case MIPS_TGEU:
			ConditionExecute(il, il.CompareUnsignedGreaterEqual(4, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize)),il.Trap(0));
			break;
		case MIPS_TLT:
		case MIPS_TLTI:
			ConditionExecute(il, il.CompareSignedLessThan(4, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize)),il.Trap(0));
			break;
		case MIPS_TLTIU:
		case MIPS_TLTU:
			ConditionExecute(il, il.CompareUnsignedLessThan(4, ReadILOperand(il, instr, 1, registerSize), ReadILOperand(il, instr, 2, registerSize)),il.Trap(0));
			break;
		case MIPS_LH:
		case MIPS_LHX:
		case MIPS_LHI:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.SignExtend(4, ReadILOperand(il, instr, 2, registerSize, 2))));
			break;
		case MIPS_LHU:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.ZeroExtend(4, ReadILOperand(il, instr, 2, registerSize, 2))));
			break;
		case MIPS_LWR:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
						il.And(4,
							il.Const(4, 0xffff0000),
							il.Register(4, op1.reg))));
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
						il.Or(4,
							ReadILOperand(il, instr, 2, registerSize, 2),
							il.Register(4, op1.reg))));
			break;
		case MIPS_LWL:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
						il.And(4,
							il.Const(4, 0xffff),
							il.Register(4, op1.reg))));
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg,
						il.Or(4,
							il.ShiftLeft(4,
								ReadILOperand(il, instr, 2, registerSize, 2),
								il.Const(1, 16)),
							il.Register(4, op1.reg))));
			break;
		case MIPS_MADD:
			il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.MultDoublePrecSigned(8,
							ReadILOperand(il, instr, 1, registerSize, 4),
							ReadILOperand(il, instr, 2, registerSize, 4))));
			il.AddInstruction(il.SetRegister(4, REG_LO,
						il.Add(4,
							il.Register(4, REG_LO),
							il.LowPart(4, il.Register(8, LLIL_TEMP(0))))));
			il.AddInstruction(il.SetRegister(4, REG_HI,
						il.Add(4,
							il.Register(4, REG_HI),
							il.LogicalShiftRight(4,
								il.Register(8, LLIL_TEMP(0)),
								il.Const(1, 16)))));
			break;
		case MIPS_MADDU:
			il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
						il.MultDoublePrecUnsigned(8,
							ReadILOperand(il, instr, 1, registerSize, 4),
							ReadILOperand(il, instr, 2, registerSize, 4))));
			il.AddInstruction(il.SetRegister(4, REG_LO,
						il.Add(4,
							il.Register(4, REG_LO),
							il.LowPart(4, il.Register(8, LLIL_TEMP(0))))));
			il.AddInstruction(il.SetRegister(4, REG_HI,
						il.Add(4,
							il.Register(4, REG_HI),
							il.LogicalShiftRight(4,
								il.Register(8, LLIL_TEMP(0)),
								il.Const(1, 16)))));
			break;
		case MIPS_ROTR:
		case MIPS_ROTRV:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.RotateRight(4, ReadILOperand(il, instr, 2, registerSize), ReadILOperand(il, instr, 3, registerSize))));
			break;
		case MIPS_SC:
			il.AddInstruction(il.UnimplementedMemoryRef(4, ReadILOperand(il, instr, 2, registerSize)));
			break;
		case MIPS_SDBBP:
			il.AddInstruction(il.Unimplemented());
			break;
		case MIPS_SEB:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.SignExtend(4, il.LowPart(1, ReadILOperand(il, instr, 2, registerSize)))));
			break;
		case MIPS_SEH:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.SignExtend(4, il.LowPart(2, ReadILOperand(il, instr, 2, registerSize)))));
			break;
		case MIPS_SH:
			il.AddInstruction(il.Store(2, GetILOperandMemoryAddress(il, op2, addrSize), il.LowPart(2, ReadILOperand(il, instr, 1, registerSize))));
			break;
		case MIPS_SRL:
		case MIPS_SRLV:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.LogicalShiftRight(4, ReadILOperand(il, instr, 2, registerSize), ReadILOperand(il, instr, 3, registerSize))));
			break;
		case MIPS_SSNOP:
		case MIPS_NOP:
			il.AddInstruction(il.Nop());
			break;
		case MIPS_WSBH:
			il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(op1.reg)}, MIPS_INTRIN_WSBH, {ReadILOperand(il, instr, 2, registerSize)}));
			break;
		case MIPS_BGEZALL:
		case MIPS_BLTZALL:
			break;
		case MIPS_ADD_S:
			il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatAdd(4, il.Register(4, op2.reg), il.Register(4, op3.reg))));
			break;
		case MIPS_ADD_D:
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatAdd(8, il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg + 1, op3.reg))));
			break;
		case MIPS_SUB_S:
			il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatSub(4, il.Register(4, op2.reg), il.Register(4, op3.reg))));
			break;
		case MIPS_SUB_D:
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatSub(8, il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg + 1, op3.reg))));
			break;
		case MIPS_MUL_S:
			il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatMult(4, il.Register(4, op2.reg), il.Register(4, op3.reg))));
			break;
		case MIPS_MUL_D:
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatMult(8, il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg + 1, op3.reg))));
			break;
		case MIPS_DIV_S:
			il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatDiv(4, il.Register(4, op2.reg), il.Register(4, op3.reg))));
			break;
		case MIPS_DIV_D:
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatDiv(8, il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg + 1, op3.reg))));
			break;
		case MIPS_SQRT_S:
			il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatSqrt(4, il.Register(4, op2.reg))));
			break;
		case MIPS_SQRT_D:
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatSqrt(8, il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
			break;
		case MIPS_CVT_S_W:
			il.AddInstruction(il.SetRegister(4, op1.reg, il.IntToFloat(4, ReadILOperand(il, instr, 2, registerSize))));
			break;
		case MIPS_CVT_D_W:
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.IntToFloat(8, ReadILOperand(il, instr, 2, registerSize))));
			break;
		case MIPS_CVT_W_S:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.FloatToInt(4, il.Register(4, op2.reg))));
			break;
		case MIPS_CVT_W_D:
			il.AddInstruction(SetRegisterOrNop(il, 4, registerSize, op1.reg, il.FloatToInt(4,
				il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
			break;
		case MIPS_CVT_D_S:
			il.AddInstruction(il.SetRegisterSplit(4, op1.reg | 1, op1.reg & (~1),
				il.FloatConvert(8, il.Register(4, op2.reg))));
			break;
		case MIPS_CVT_S_D:
			il.AddInstruction(il.SetRegister(4, op1.reg, il.FloatConvert(4,
				il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
			break;
		case MIPS_C_EQ_S:
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
			if (op1.operandClass == FLAG)
			{
				il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareEqual(8,
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg | 1, op3.reg & (~1)))));
			}
			else
			{
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareEqual(8,
					il.RegisterSplit(4, op1.reg | 1, op1.reg & (~1)),
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
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
				il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareLessEqual(8,
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg | 1, op3.reg & (~1)))));
			}
			else
			{
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareLessEqual(8,
					il.RegisterSplit(4, op1.reg | 1, op1.reg & (~1)),
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
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
				il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareLessThan(8,
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg | 1, op3.reg & (~1)))));
			}
			else
			{
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareLessThan(8,
					il.RegisterSplit(4, op1.reg | 1, op1.reg & (~1)),
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
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
				il.AddInstruction(il.SetFlag(op1.reg, il.FloatCompareUnordered(8,
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)),
					il.RegisterSplit(4, op3.reg | 1, op3.reg & (~1)))));
			}
			else
			{
				il.AddInstruction(il.SetFlag(FPCCREG_FCC0, il.FloatCompareUnordered(8,
					il.RegisterSplit(4, op1.reg | 1, op1.reg & (~1)),
					il.RegisterSplit(4, op2.reg | 1, op2.reg & (~1)))));
			}
			break;
		case MIPS_ADDR:
		case MIPS_DSLLV:
		case MIPS_DSRA32:
		case MIPS_DSRA:
		case MIPS_DSRAV:
		case MIPS_DSLV:
		case MIPS_DSUB:
		case MIPS_DSUBU:
		case MIPS_LDL:
		case MIPS_LDR:
		case MIPS_LDXC1:
		case MIPS_LLD:
		case MIPS_LLO:
		case MIPS_LUXC1:
		case MIPS_LWC1:
		case MIPS_LWC2:
		case MIPS_LWC3:
		case MIPS_LWU:
		case MIPS_LWXC1:
		case MIPS_MFHC1:
		case MIPS_MFHC2:
		case MIPS_MOVT:
		case MIPS_MULR:
		case MIPS_SCD:
		case MIPS_SDC1:
		case MIPS_SDC2:
		case MIPS_SDC3:
		case MIPS_SDL:
		case MIPS_SDR:
		case MIPS_SDXC1:
		case MIPS_LDC1:
		case MIPS_LDC2:
		case MIPS_LDC3:

		//unimplemented system functions
		case MIPS_BC1ANY2:
		case MIPS_BC1ANY4:
		case MIPS_BSHFL:
		case MIPS_C2:
		case MIPS_CFC1:
		case MIPS_CFC2:
		case MIPS_COP0:
		case MIPS_COP1:
		case MIPS_COP1X:
		case MIPS_COP2:
		case MIPS_COP3:
		case MIPS_CTC1:
		case MIPS_CTC2:
		case MIPS_DERET:
		case MIPS_DI:
		case MIPS_DMULT:
		case MIPS_DMULTU:
		case MIPS_DRET:
		case MIPS_EHB:
		case MIPS_EI:
		case MIPS_JALX: //Special instruction for switching to MIPS32/microMIPS32/MIPS16e
		case MIPS_MTHC1:
		case MIPS_MTHC2:
		case MIPS_PAUSE:
		case MIPS_PREF:
		case MIPS_PREFX:
		case MIPS_SYNC:
		case MIPS_SYNCI:
		case MIPS_TLBP:
		case MIPS_TLBR:
		case MIPS_TLBWI:
		case MIPS_TLBWR:
		case MIPS_WAIT:
		case MIPS_WRPGPR:
		case MIPS_RDPGPR:
		case MIPS_RECIP1:
		case MIPS_RECIP2:
		case MIPS_RECIP:
		case MIPS_SUXC1:
		case MIPS_SWXC1:
			il.AddInstruction(il.Unimplemented());
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
	}
	return true;
}
