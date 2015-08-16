#include "binaryninjaapi.h"

using namespace BinaryNinja;


LowLevelILLabel::LowLevelILLabel()
{
	BNLowLevelILInitLabel(this);
}


LowLevelILFunction::LowLevelILFunction()
{
	m_func = BNCreateLowLevelILFunction();
}


LowLevelILFunction::LowLevelILFunction(BNLowLevelILFunction* func): m_func(func)
{
}


LowLevelILFunction::~LowLevelILFunction()
{
	BNFreeLowLevelILFunction(m_func);
}


uint64_t LowLevelILFunction::GetCurrentAddress() const
{
	return BNLowLevelILGetCurrentAddress(m_func);
}


void LowLevelILFunction::SetCurrentAddress(uint64_t addr)
{
	BNLowLevelILSetCurrentAddress(m_func, addr);
}


ExprId LowLevelILFunction::AddExpr(BNLowLevelILOperation operation, size_t size, uint32_t flags,
                                   ExprId a, ExprId b, ExprId c, ExprId d)
{
	return BNLowLevelILAddExpr(m_func, operation, size, flags, a, b, c, d);
}


ExprId LowLevelILFunction::AddInstruction(size_t expr)
{
	return BNLowLevelILAddInstruction(m_func, expr);
}


ExprId LowLevelILFunction::Nop()
{
	return AddExpr(LLIL_NOP, 0, 0);
}


ExprId LowLevelILFunction::SetRegister(size_t size, uint32_t reg, ExprId val)
{
	return AddExpr(LLIL_SET_REG, size, 0, reg, val);
}


ExprId LowLevelILFunction::SetRegisterSplit(size_t size, uint32_t high, uint32_t low, ExprId val)
{
	return AddExpr(LLIL_SET_REG_SPLIT, size, 0, high, low, val);
}


ExprId LowLevelILFunction::SetFlag(uint32_t flag, ExprId val)
{
	return AddExpr(LLIL_SET_FLAG, 0, 0, flag, val);
}


ExprId LowLevelILFunction::Load(size_t size, ExprId addr)
{
	return AddExpr(LLIL_LOAD, size, 0, addr);
}


ExprId LowLevelILFunction::Store(size_t size, ExprId addr, ExprId val)
{
	return AddExpr(LLIL_STORE, size, 0, addr, val);
}


ExprId LowLevelILFunction::Push(size_t size, ExprId val)
{
	return AddExpr(LLIL_PUSH, size, 0, val);
}


ExprId LowLevelILFunction::Pop(size_t size)
{
	return AddExpr(LLIL_POP, size, 0);
}


ExprId LowLevelILFunction::Register(size_t size, uint32_t reg)
{
	return AddExpr(LLIL_REG, size, 0, reg);
}


ExprId LowLevelILFunction::Const(size_t size, uint64_t val)
{
	return AddExpr(LLIL_CONST, size, 0, val);
}


ExprId LowLevelILFunction::Flag(uint32_t reg)
{
	return AddExpr(LLIL_FLAG, 0, 0, reg);
}


ExprId LowLevelILFunction::Add(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_ADD, size, flags, a, b);
}


ExprId LowLevelILFunction::AddCarry(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_ADC, size, flags, a, b);
}


ExprId LowLevelILFunction::Sub(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_SUB, size, flags, a, b);
}


ExprId LowLevelILFunction::SubBorrow(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_SBB, size, flags, a, b);
}


ExprId LowLevelILFunction::And(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_AND, size, flags, a, b);
}


ExprId LowLevelILFunction::Or(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_OR, size, flags, a, b);
}


ExprId LowLevelILFunction::Xor(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_XOR, size, flags, a, b);
}


ExprId LowLevelILFunction::ShiftLeft(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_LSL, size, flags, a, b);
}


ExprId LowLevelILFunction::LogicalShiftRight(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_LSR, size, flags, a, b);
}


ExprId LowLevelILFunction::ArithShiftRight(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_ASR, size, flags, a, b);
}


ExprId LowLevelILFunction::RotateLeft(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_ROL, size, flags, a, b);
}


ExprId LowLevelILFunction::RotateLeftCarry(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_RLC, size, flags, a, b);
}


ExprId LowLevelILFunction::RotateRight(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_ROR, size, flags, a, b);
}


ExprId LowLevelILFunction::RotateRightCarry(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_RRC, size, flags, a, b);
}


ExprId LowLevelILFunction::Mult(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_MUL, size, flags, a, b);
}


ExprId LowLevelILFunction::MultDoublePrecUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_MULU_DP, size, flags, a, b);
}


ExprId LowLevelILFunction::MultDoublePrecSigned(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_MULS_DP, size, flags, a, b);
}


ExprId LowLevelILFunction::DivUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_DIVU, size, flags, a, b);
}


ExprId LowLevelILFunction::DivDoublePrecUnsigned(size_t size, ExprId high, ExprId low, ExprId div, uint32_t flags)
{
	return AddExpr(LLIL_DIVU_DP, size, flags, high, low, div);
}


ExprId LowLevelILFunction::DivSigned(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_DIVS, size, flags, a, b);
}


ExprId LowLevelILFunction::DivDoublePrecSigned(size_t size, ExprId high, ExprId low, ExprId div, uint32_t flags)
{
	return AddExpr(LLIL_DIVS_DP, size, flags, high, low, div);
}


ExprId LowLevelILFunction::ModUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_MODU, size, flags, a, b);
}


ExprId LowLevelILFunction::ModDoublePrecUnsigned(size_t size, ExprId high, ExprId low, ExprId div, uint32_t flags)
{
	return AddExpr(LLIL_MODU_DP, size, flags, high, low, div);
}


ExprId LowLevelILFunction::ModSigned(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_MODS, size, flags, a, b);
}


ExprId LowLevelILFunction::ModDoublePrecSigned(size_t size, ExprId high, ExprId low, ExprId div, uint32_t flags)
{
	return AddExpr(LLIL_MODS_DP, size, flags, high, low, div);
}


ExprId LowLevelILFunction::Neg(size_t size, ExprId a, uint32_t flags)
{
	return AddExpr(LLIL_NEG, size, flags, a);
}


ExprId LowLevelILFunction::Not(size_t size, ExprId a, uint32_t flags)
{
	return AddExpr(LLIL_NOT, size, flags, a);
}


ExprId LowLevelILFunction::SignExtend(size_t size, ExprId a)
{
	return AddExpr(LLIL_SX, size, 0, a);
}


ExprId LowLevelILFunction::ZeroExtend(size_t size, ExprId a)
{
	return AddExpr(LLIL_ZX, size, 0, a);
}


ExprId LowLevelILFunction::Jump(ExprId dest)
{
	return AddExpr(LLIL_JUMP, 0, 0, dest);
}


ExprId LowLevelILFunction::Call(ExprId dest)
{
	return AddExpr(LLIL_CALL, 0, 0, dest);
}


ExprId LowLevelILFunction::Return(size_t dest)
{
	return AddExpr(LLIL_RET, 0, 0, dest);
}


ExprId LowLevelILFunction::NoReturn()
{
	return AddExpr(LLIL_NORET, 0, 0);
}


ExprId LowLevelILFunction::FlagCondition(BNLowLevelILFlagCondition cond)
{
	return AddExpr(LLIL_FLAG_COND, 0, 0, (ExprId)cond);
}


ExprId LowLevelILFunction::CompareEqual(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_CMP_E, size, 0, a, b);
}


ExprId LowLevelILFunction::CompareNotEqual(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_CMP_NE, size, 0, a, b);
}


ExprId LowLevelILFunction::CompareSignedLessThan(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_CMP_SLT, size, 0, a, b);
}


ExprId LowLevelILFunction::CompareUnsignedLessThan(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_CMP_ULT, size, 0, a, b);
}


ExprId LowLevelILFunction::CompareSignedLessEqual(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_CMP_SLE, size, 0, a, b);
}


ExprId LowLevelILFunction::CompareUnsignedLessEqual(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_CMP_ULE, size, 0, a, b);
}


ExprId LowLevelILFunction::CompareSignedGreaterEqual(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_CMP_SGE, size, 0, a, b);
}


ExprId LowLevelILFunction::CompareUnsignedGreaterEqual(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_CMP_UGE, size, 0, a, b);
}


ExprId LowLevelILFunction::CompareSignedGreaterThan(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_CMP_SGT, size, 0, a, b);
}


ExprId LowLevelILFunction::CompareUnsignedGreaterThan(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_CMP_UGT, size, 0, a, b);
}


ExprId LowLevelILFunction::SystemCall()
{
	return AddExpr(LLIL_SYSCALL, 0, 0);
}


ExprId LowLevelILFunction::Breakpoint()
{
	return AddExpr(LLIL_BP, 0, 0);
}


ExprId LowLevelILFunction::Trap(uint32_t num)
{
	return AddExpr(LLIL_TRAP, 0, 0, num);
}


ExprId LowLevelILFunction::Undefined()
{
	return AddExpr(LLIL_UNDEF, 0, 0);
}


ExprId LowLevelILFunction::Unimplemented()
{
	return AddExpr(LLIL_UNIMPL, 0, 0);
}


ExprId LowLevelILFunction::UnimplementedMemoryRef(size_t size, ExprId addr)
{
	return AddExpr(LLIL_UNIMPL_MEM, size, 0, addr);
}


ExprId LowLevelILFunction::Goto(BNLowLevelILLabel& label)
{
	return BNLowLevelILGoto(m_func, &label);
}


ExprId LowLevelILFunction::If(ExprId operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f)
{
	return BNLowLevelILIf(m_func, operand, &t, &f);
}


void LowLevelILFunction::MarkLabel(BNLowLevelILLabel& label)
{
	BNLowLevelILMarkLabel(m_func, &label);
}


BNLowLevelILInstruction LowLevelILFunction::operator[](size_t i) const
{
	return BNGetLowLevelILByIndex(m_func, i);
}


size_t LowLevelILFunction::GetIndexForInstruction(size_t i) const
{
	return BNGetLowLevelILIndexForInstruction(m_func, i);
}


size_t LowLevelILFunction::GetInstructionCount() const
{
	return BNGetLowLevelILInstructionCount(m_func);
}


void LowLevelILFunction::AddLabelForAddress(Architecture* arch, ExprId addr)
{
	BNAddLowLevelILLabelForAddress(m_func, arch->GetArchitectureObject(), addr);
}


BNLowLevelILLabel* LowLevelILFunction::GetLabelForAddress(Architecture* arch, ExprId addr)
{
	return BNGetLowLevelILLabelForAddress(m_func, arch->GetArchitectureObject(), addr);
}


void LowLevelILFunction::Finalize()
{
	BNFinalizeLowLevelILFunction(m_func);
}
