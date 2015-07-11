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


size_t LowLevelILFunction::AddExpr(BNLowLevelILOperation operation, size_t size, uint32_t flags,
                                   uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
	return BNLowLevelILAddExpr(m_func, operation, size, flags, a, b, c, d);
}


size_t LowLevelILFunction::AddInstruction(size_t expr)
{
	return BNLowLevelILAddInstruction(m_func, expr);
}


size_t LowLevelILFunction::Nop()
{
	return AddExpr(LLIL_NOP, 0, 0);
}


size_t LowLevelILFunction::SetRegister(size_t size, uint32_t reg, uint64_t val)
{
	return AddExpr(LLIL_SET_REG, size, 0, reg, val);
}


size_t LowLevelILFunction::SetRegisterSplit(size_t size, uint32_t high, uint32_t low, uint64_t val)
{
	return AddExpr(LLIL_SET_REG_SPLIT, size, 0, high, low, val);
}


size_t LowLevelILFunction::SetFlag(uint32_t flag, uint64_t val)
{
	return AddExpr(LLIL_SET_FLAG, 0, 0, flag, val);
}


size_t LowLevelILFunction::Load(size_t size, uint64_t addr)
{
	return AddExpr(LLIL_LOAD, size, 0, addr);
}


size_t LowLevelILFunction::Store(size_t size, uint64_t addr, uint64_t val)
{
	return AddExpr(LLIL_STORE, size, 0, addr, val);
}


size_t LowLevelILFunction::Push(size_t size, uint64_t val)
{
	return AddExpr(LLIL_PUSH, size, 0, val);
}


size_t LowLevelILFunction::Pop(size_t size)
{
	return AddExpr(LLIL_POP, size, 0);
}


size_t LowLevelILFunction::Register(size_t size, uint32_t reg)
{
	return AddExpr(LLIL_REG, size, 0, reg);
}


size_t LowLevelILFunction::Const(size_t size, uint64_t val)
{
	return AddExpr(LLIL_CONST, size, 0, val);
}


size_t LowLevelILFunction::Flag(uint32_t reg)
{
	return AddExpr(LLIL_FLAG, 0, 0, reg);
}


size_t LowLevelILFunction::Add(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_ADD, size, flags, a, b);
}


size_t LowLevelILFunction::AddCarry(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_ADC, size, flags, a, b);
}


size_t LowLevelILFunction::Sub(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_SUB, size, flags, a, b);
}


size_t LowLevelILFunction::SubBorrow(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_SBB, size, flags, a, b);
}


size_t LowLevelILFunction::And(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_AND, size, flags, a, b);
}


size_t LowLevelILFunction::Or(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_OR, size, flags, a, b);
}


size_t LowLevelILFunction::Xor(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_XOR, size, flags, a, b);
}


size_t LowLevelILFunction::ShiftLeft(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_LSL, size, flags, a, b);
}


size_t LowLevelILFunction::LogicalShiftRight(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_LSR, size, flags, a, b);
}


size_t LowLevelILFunction::ArithShiftRight(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_ASR, size, flags, a, b);
}


size_t LowLevelILFunction::RotateLeft(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_ROL, size, flags, a, b);
}


size_t LowLevelILFunction::RotateLeftCarry(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_RLC, size, flags, a, b);
}


size_t LowLevelILFunction::RotateRight(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_ROR, size, flags, a, b);
}


size_t LowLevelILFunction::RotateRightCarry(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_RRC, size, flags, a, b);
}


size_t LowLevelILFunction::Mult(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_MUL, size, flags, a, b);
}


size_t LowLevelILFunction::MultDoublePrecUnsigned(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_MULU_DP, size, flags, a, b);
}


size_t LowLevelILFunction::MultDoublePrecSigned(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_MULS_DP, size, flags, a, b);
}


size_t LowLevelILFunction::DivUnsigned(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_DIVU, size, flags, a, b);
}


size_t LowLevelILFunction::DivDoublePrecUnsigned(size_t size, uint64_t high, uint64_t low, uint64_t div, uint32_t flags)
{
	return AddExpr(LLIL_DIVU_DP, size, flags, high, low, div);
}


size_t LowLevelILFunction::DivSigned(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_DIVS, size, flags, a, b);
}


size_t LowLevelILFunction::DivDoublePrecSigned(size_t size, uint64_t high, uint64_t low, uint64_t div, uint32_t flags)
{
	return AddExpr(LLIL_DIVS_DP, size, flags, high, low, div);
}


size_t LowLevelILFunction::ModUnsigned(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_MODU, size, flags, a, b);
}


size_t LowLevelILFunction::ModDoublePrecUnsigned(size_t size, uint64_t high, uint64_t low, uint64_t div, uint32_t flags)
{
	return AddExpr(LLIL_MODU_DP, size, flags, high, low, div);
}


size_t LowLevelILFunction::ModSigned(size_t size, uint64_t a, uint64_t b, uint32_t flags)
{
	return AddExpr(LLIL_MODS, size, flags, a, b);
}


size_t LowLevelILFunction::ModDoublePrecSigned(size_t size, uint64_t high, uint64_t low, uint64_t div, uint32_t flags)
{
	return AddExpr(LLIL_MODS_DP, size, flags, high, low, div);
}


size_t LowLevelILFunction::Neg(size_t size, uint64_t a, uint32_t flags)
{
	return AddExpr(LLIL_NEG, size, flags, a);
}


size_t LowLevelILFunction::Not(size_t size, uint64_t a, uint32_t flags)
{
	return AddExpr(LLIL_NOT, size, flags, a);
}


size_t LowLevelILFunction::SignExtend(size_t size, uint64_t a)
{
	return AddExpr(LLIL_SX, size, 0, a);
}


size_t LowLevelILFunction::ZeroExtend(size_t size, uint64_t a)
{
	return AddExpr(LLIL_ZX, size, 0, a);
}


size_t LowLevelILFunction::Jump(uint64_t dest)
{
	return AddExpr(LLIL_JUMP, 0, 0, dest);
}


size_t LowLevelILFunction::Call(uint64_t dest)
{
	return AddExpr(LLIL_CALL, 0, 0, dest);
}


size_t LowLevelILFunction::Return(size_t dest)
{
	return AddExpr(LLIL_RET, 0, 0, dest);
}


size_t LowLevelILFunction::FlagCondition(BNLowLevelILFlagCondition cond)
{
	return AddExpr(LLIL_FLAG_COND, 0, 0, (uint64_t)cond);
}


size_t LowLevelILFunction::CompareEqual(size_t size, uint64_t a, uint64_t b)
{
	return AddExpr(LLIL_CMP_E, size, 0, a, b);
}


size_t LowLevelILFunction::CompareNotEqual(size_t size, uint64_t a, uint64_t b)
{
	return AddExpr(LLIL_CMP_NE, size, 0, a, b);
}


size_t LowLevelILFunction::CompareSignedLessThan(size_t size, uint64_t a, uint64_t b)
{
	return AddExpr(LLIL_CMP_SLT, size, 0, a, b);
}


size_t LowLevelILFunction::CompareUnsignedLessThan(size_t size, uint64_t a, uint64_t b)
{
	return AddExpr(LLIL_CMP_ULT, size, 0, a, b);
}


size_t LowLevelILFunction::CompareSignedLessEqual(size_t size, uint64_t a, uint64_t b)
{
	return AddExpr(LLIL_CMP_SLE, size, 0, a, b);
}


size_t LowLevelILFunction::CompareUnsignedLessEqual(size_t size, uint64_t a, uint64_t b)
{
	return AddExpr(LLIL_CMP_ULE, size, 0, a, b);
}


size_t LowLevelILFunction::CompareSignedGreaterEqual(size_t size, uint64_t a, uint64_t b)
{
	return AddExpr(LLIL_CMP_SGE, size, 0, a, b);
}


size_t LowLevelILFunction::CompareUnsignedGreaterEqual(size_t size, uint64_t a, uint64_t b)
{
	return AddExpr(LLIL_CMP_UGE, size, 0, a, b);
}


size_t LowLevelILFunction::CompareSignedGreaterThan(size_t size, uint64_t a, uint64_t b)
{
	return AddExpr(LLIL_CMP_SGT, size, 0, a, b);
}


size_t LowLevelILFunction::CompareUnsignedGreaterThan(size_t size, uint64_t a, uint64_t b)
{
	return AddExpr(LLIL_CMP_UGT, size, 0, a, b);
}


size_t LowLevelILFunction::SystemCall()
{
	return AddExpr(LLIL_SYSCALL, 0, 0);
}


size_t LowLevelILFunction::Breakpoint()
{
	return AddExpr(LLIL_BP, 0, 0);
}


size_t LowLevelILFunction::Undefined()
{
	return AddExpr(LLIL_UNDEF, 0, 0);
}


size_t LowLevelILFunction::Unimplemented()
{
	return AddExpr(LLIL_UNIMPL, 0, 0);
}


size_t LowLevelILFunction::UnimplementedMemoryRef(size_t size, uint64_t addr)
{
	return AddExpr(LLIL_UNIMPL_MEM, size, 0, addr);
}


size_t LowLevelILFunction::Goto(BNLowLevelILLabel& label)
{
	return BNLowLevelILGoto(m_func, &label);
}


size_t LowLevelILFunction::If(uint64_t operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f)
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


void LowLevelILFunction::AddLabelForAddress(Architecture* arch, uint64_t addr)
{
	BNAddLowLevelILLabelForAddress(m_func, arch->GetArchitectureObject(), addr);
}


BNLowLevelILLabel* LowLevelILFunction::GetLabelForAddress(Architecture* arch, uint64_t addr)
{
	return BNGetLowLevelILLabelForAddress(m_func, arch->GetArchitectureObject(), addr);
}


void LowLevelILFunction::Finalize()
{
	BNFinalizeLowLevelILFunction(m_func);
}
