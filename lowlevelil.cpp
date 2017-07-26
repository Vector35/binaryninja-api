// Copyright (c) 2015-2017 Vector 35 LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


LowLevelILLabel::LowLevelILLabel()
{
	BNLowLevelILInitLabel(this);
}


LowLevelILFunction::LowLevelILFunction(Architecture* arch, Function* func)
{
	m_object = BNCreateLowLevelILFunction(arch->GetObject(), func ? func->GetObject() : nullptr);
}


LowLevelILFunction::LowLevelILFunction(BNLowLevelILFunction* func)
{
	m_object = func;
}


uint64_t LowLevelILFunction::GetCurrentAddress() const
{
	return BNLowLevelILGetCurrentAddress(m_object);
}


void LowLevelILFunction::SetCurrentAddress(Architecture* arch, uint64_t addr)
{
	BNLowLevelILSetCurrentAddress(m_object, arch ? arch->GetObject() : nullptr, addr);
}


size_t LowLevelILFunction::GetInstructionStart(Architecture* arch, uint64_t addr)
{
	return BNLowLevelILGetInstructionStart(m_object, arch ? arch->GetObject() : nullptr, addr);
}


void LowLevelILFunction::ClearIndirectBranches()
{
	BNLowLevelILClearIndirectBranches(m_object);
}


void LowLevelILFunction::SetIndirectBranches(const vector<ArchAndAddr>& branches)
{
	BNArchitectureAndAddress* branchList = new BNArchitectureAndAddress[branches.size()];
	for (size_t i = 0; i < branches.size(); i++)
	{
		branchList[i].arch = branches[i].arch->GetObject();
		branchList[i].address = branches[i].address;
	}
	BNLowLevelILSetIndirectBranches(m_object, branchList, branches.size());
	delete[] branchList;
}


ExprId LowLevelILFunction::AddExpr(BNLowLevelILOperation operation, size_t size, uint32_t flags,
                                   ExprId a, ExprId b, ExprId c, ExprId d)
{
	return BNLowLevelILAddExpr(m_object, operation, size, flags, a, b, c, d);
}


ExprId LowLevelILFunction::AddInstruction(size_t expr)
{
	return BNLowLevelILAddInstruction(m_object, expr);
}


ExprId LowLevelILFunction::Nop()
{
	return AddExpr(LLIL_NOP, 0, 0);
}


ExprId LowLevelILFunction::SetRegister(size_t size, uint32_t reg, ExprId val, uint32_t flags)
{
	return AddExpr(LLIL_SET_REG, size, flags, reg, val);
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


ExprId LowLevelILFunction::ConstPointer(size_t size, uint64_t val)
{
	return AddExpr(LLIL_CONST_PTR, size, 0, val);
}


ExprId LowLevelILFunction::Flag(uint32_t reg)
{
	return AddExpr(LLIL_FLAG, 0, 0, reg);
}


ExprId LowLevelILFunction::FlagBit(size_t size, uint32_t flag, uint32_t bitIndex)
{
	return AddExpr(LLIL_FLAG_BIT, size, 0, flag, bitIndex);
}


ExprId LowLevelILFunction::Add(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_ADD, size, flags, a, b);
}


ExprId LowLevelILFunction::AddCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags)
{
	return AddExpr(LLIL_ADC, size, flags, a, b, carry);
}


ExprId LowLevelILFunction::Sub(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_SUB, size, flags, a, b);
}


ExprId LowLevelILFunction::SubBorrow(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags)
{
	return AddExpr(LLIL_SBB, size, flags, a, b, carry);
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


ExprId LowLevelILFunction::RotateLeftCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags)
{
	return AddExpr(LLIL_RLC, size, flags, a, b, carry);
}


ExprId LowLevelILFunction::RotateRight(size_t size, ExprId a, ExprId b, uint32_t flags)
{
	return AddExpr(LLIL_ROR, size, flags, a, b);
}


ExprId LowLevelILFunction::RotateRightCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags)
{
	return AddExpr(LLIL_RRC, size, flags, a, b, carry);
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


ExprId LowLevelILFunction::SignExtend(size_t size, ExprId a, uint32_t flags)
{
	return AddExpr(LLIL_SX, size, flags, a);
}


ExprId LowLevelILFunction::ZeroExtend(size_t size, ExprId a, uint32_t flags)
{
	return AddExpr(LLIL_ZX, size, flags, a);
}


ExprId LowLevelILFunction::LowPart(size_t size, ExprId a, uint32_t flags)
{
	return AddExpr(LLIL_LOW_PART, size, flags, a);
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


ExprId LowLevelILFunction::TestBit(size_t size, ExprId a, ExprId b)
{
	return AddExpr(LLIL_TEST_BIT, size, 0, a, b);
}


ExprId LowLevelILFunction::BoolToInt(size_t size, ExprId a)
{
	return AddExpr(LLIL_BOOL_TO_INT, size, 0, a);
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
	return BNLowLevelILGoto(m_object, &label);
}


ExprId LowLevelILFunction::If(ExprId operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f)
{
	return BNLowLevelILIf(m_object, operand, &t, &f);
}


void LowLevelILFunction::MarkLabel(BNLowLevelILLabel& label)
{
	BNLowLevelILMarkLabel(m_object, &label);
}


vector<uint64_t> LowLevelILFunction::GetOperandList(ExprId expr, size_t listOperand)
{
	size_t count;
	uint64_t* operands = BNLowLevelILGetOperandList(m_object, expr, listOperand, &count);
	vector<uint64_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(operands[i]);
	BNLowLevelILFreeOperandList(operands);
	return result;
}


ExprId LowLevelILFunction::AddLabelList(const vector<BNLowLevelILLabel*>& labels)
{
	BNLowLevelILLabel** labelList = new BNLowLevelILLabel*[labels.size()];
	for (size_t i = 0; i < labels.size(); i++)
		labelList[i] = labels[i];
	ExprId result = (ExprId)BNLowLevelILAddLabelList(m_object, labelList, labels.size());
	delete[] labelList;
	return result;
}


ExprId LowLevelILFunction::AddOperandList(const vector<ExprId> operands)
{
	uint64_t* operandList = new uint64_t[operands.size()];
	for (size_t i = 0; i < operands.size(); i++)
		operandList[i] = operands[i];
	ExprId result = (ExprId)BNLowLevelILAddOperandList(m_object, operandList, operands.size());
	delete[] operandList;
	return result;
}


ExprId LowLevelILFunction::GetExprForRegisterOrConstant(const BNRegisterOrConstant& operand, size_t size)
{
	if (operand.constant)
		return AddExpr(LLIL_CONST, size, 0, operand.value);
	return AddExpr(LLIL_REG, size, 0, operand.reg);
}


ExprId LowLevelILFunction::GetNegExprForRegisterOrConstant(const BNRegisterOrConstant& operand, size_t size)
{
	if (operand.constant)
		return AddExpr(LLIL_CONST, size, 0, -(int64_t)operand.value);
	return AddExpr(LLIL_NEG, size, 0, AddExpr(LLIL_REG, size, 0, operand.reg));
}


ExprId LowLevelILFunction::GetExprForFlagOrConstant(const BNRegisterOrConstant& operand)
{
	if (operand.constant)
		return AddExpr(LLIL_CONST, 0, 0, operand.value);
	return AddExpr(LLIL_FLAG, 0, 0, operand.reg);
}


ExprId LowLevelILFunction::GetExprForRegisterOrConstantOperation(BNLowLevelILOperation op, size_t size,
	BNRegisterOrConstant* operands, size_t operandCount)
{
	if (operandCount == 0)
		return AddExpr(op, size, 0);
	if (operandCount == 1)
		return AddExpr(op, size, 0, GetExprForRegisterOrConstant(operands[0], size));
	if (operandCount == 2)
	{
		return AddExpr(op, size, 0, GetExprForRegisterOrConstant(operands[0], size),
			GetExprForRegisterOrConstant(operands[1], size));
	}
	if (operandCount == 3)
	{
		if ((op == LLIL_ADC) || (op == LLIL_SBB) || (op == LLIL_RLC) || (op == LLIL_RRC))
		{
			return AddExpr(op, size, 0, GetExprForRegisterOrConstant(operands[0], size),
				GetExprForRegisterOrConstant(operands[1], size), GetExprForFlagOrConstant(operands[2]));
		}
		return AddExpr(op, size, 0, GetExprForRegisterOrConstant(operands[0], size),
			GetExprForRegisterOrConstant(operands[1], size), GetExprForRegisterOrConstant(operands[2], size));
	}
	return AddExpr(op, size, 0, GetExprForRegisterOrConstant(operands[0], size),
		GetExprForRegisterOrConstant(operands[1], size), GetExprForRegisterOrConstant(operands[2], size),
		GetExprForRegisterOrConstant(operands[3], size));
}


ExprId LowLevelILFunction::Operand(uint32_t n, ExprId expr)
{
	BNLowLevelILSetExprSourceOperand(m_object, expr, n);
	return expr;
}


BNLowLevelILInstruction LowLevelILFunction::operator[](size_t i) const
{
	return BNGetLowLevelILByIndex(m_object, i);
}


size_t LowLevelILFunction::GetIndexForInstruction(size_t i) const
{
	return BNGetLowLevelILIndexForInstruction(m_object, i);
}


size_t LowLevelILFunction::GetInstructionCount() const
{
	return BNGetLowLevelILInstructionCount(m_object);
}


size_t LowLevelILFunction::GetExprCount() const
{
	return BNGetLowLevelILExprCount(m_object);
}


void LowLevelILFunction::AddLabelForAddress(Architecture* arch, ExprId addr)
{
	BNAddLowLevelILLabelForAddress(m_object, arch->GetObject(), addr);
}


BNLowLevelILLabel* LowLevelILFunction::GetLabelForAddress(Architecture* arch, ExprId addr)
{
	return BNGetLowLevelILLabelForAddress(m_object, arch->GetObject(), addr);
}


void LowLevelILFunction::Finalize()
{
	BNFinalizeLowLevelILFunction(m_object);
}


bool LowLevelILFunction::GetExprText(Architecture* arch, ExprId expr, vector<InstructionTextToken>& tokens)
{
	size_t count;
	BNInstructionTextToken* list;
	if (!BNGetLowLevelILExprText(m_object, arch->GetObject(), expr, &list, &count))
		return false;

	tokens.clear();
	for (size_t i = 0; i < count; i++)
	{
		InstructionTextToken token;
		token.type = list[i].type;
		token.text = list[i].text;
		token.value = list[i].value;
		token.size = list[i].size;
		token.operand = list[i].operand;
		token.context = list[i].context;
		token.confidence = list[i].confidence;
		token.address = list[i].address;
		tokens.push_back(token);
	}

	BNFreeInstructionText(list, count);
	return true;
}


bool LowLevelILFunction::GetInstructionText(Function* func, Architecture* arch, size_t instr,
	vector<InstructionTextToken>& tokens)
{
	size_t count;
	BNInstructionTextToken* list;
	if (!BNGetLowLevelILInstructionText(m_object, func ? func->GetObject() : nullptr, arch->GetObject(),
		instr, &list, &count))
		return false;

	tokens.clear();
	for (size_t i = 0; i < count; i++)
	{
		InstructionTextToken token;
		token.type = list[i].type;
		token.text = list[i].text;
		token.value = list[i].value;
		token.size = list[i].size;
		token.operand = list[i].operand;
		token.context = list[i].context;
		token.confidence = list[i].confidence;
		token.address = list[i].address;
		tokens.push_back(token);
	}

	BNFreeInstructionText(list, count);
	return true;
}


uint32_t LowLevelILFunction::GetTemporaryRegisterCount()
{
	return BNGetLowLevelILTemporaryRegisterCount(m_object);
}


uint32_t LowLevelILFunction::GetTemporaryFlagCount()
{
	return BNGetLowLevelILTemporaryFlagCount(m_object);
}


vector<Ref<BasicBlock>> LowLevelILFunction::GetBasicBlocks() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetLowLevelILBasicBlockList(m_object, &count);

	vector<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


Ref<LowLevelILFunction> LowLevelILFunction::GetSSAForm() const
{
	BNLowLevelILFunction* func = BNGetLowLevelILSSAForm(m_object);
	if (!func)
		return nullptr;
	return new LowLevelILFunction(func);
}


Ref<LowLevelILFunction> LowLevelILFunction::GetNonSSAForm() const
{
	BNLowLevelILFunction* func = BNGetLowLevelILNonSSAForm(m_object);
	if (!func)
		return nullptr;
	return new LowLevelILFunction(func);
}


size_t LowLevelILFunction::GetSSAInstructionIndex(size_t instr) const
{
	return BNGetLowLevelILSSAInstructionIndex(m_object, instr);
}


size_t LowLevelILFunction::GetNonSSAInstructionIndex(size_t instr) const
{
	return BNGetLowLevelILNonSSAInstructionIndex(m_object, instr);
}


size_t LowLevelILFunction::GetSSAExprIndex(size_t expr) const
{
	return BNGetLowLevelILSSAExprIndex(m_object, expr);
}


size_t LowLevelILFunction::GetNonSSAExprIndex(size_t expr) const
{
	return BNGetLowLevelILNonSSAExprIndex(m_object, expr);
}


size_t LowLevelILFunction::GetSSARegisterDefinition(uint32_t reg, size_t version) const
{
	return BNGetLowLevelILSSARegisterDefinition(m_object, reg, version);
}


size_t LowLevelILFunction::GetSSAFlagDefinition(uint32_t flag, size_t version) const
{
	return BNGetLowLevelILSSAFlagDefinition(m_object, flag, version);
}


size_t LowLevelILFunction::GetSSAMemoryDefinition(size_t version) const
{
	return BNGetLowLevelILSSAMemoryDefinition(m_object, version);
}


set<size_t> LowLevelILFunction::GetSSARegisterUses(uint32_t reg, size_t version) const
{
	size_t count;
	size_t* instrs = BNGetLowLevelILSSARegisterUses(m_object, reg, version, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


set<size_t> LowLevelILFunction::GetSSAFlagUses(uint32_t flag, size_t version) const
{
	size_t count;
	size_t* instrs = BNGetLowLevelILSSAFlagUses(m_object, flag, version, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


set<size_t> LowLevelILFunction::GetSSAMemoryUses(size_t version) const
{
	size_t count;
	size_t* instrs = BNGetLowLevelILSSAMemoryUses(m_object, version, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


RegisterValue LowLevelILFunction::GetSSARegisterValue(uint32_t reg, size_t version)
{
	BNRegisterValue value = BNGetLowLevelILSSARegisterValue(m_object, reg, version);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetSSAFlagValue(uint32_t flag, size_t version)
{
	BNRegisterValue value = BNGetLowLevelILSSAFlagValue(m_object, flag, version);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetExprValue(size_t expr)
{
	BNRegisterValue value = BNGetLowLevelILExprValue(m_object, expr);
	return RegisterValue::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleExprValues(size_t expr)
{
	BNPossibleValueSet value = BNGetLowLevelILPossibleExprValues(m_object, expr);
	return PossibleValueSet::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetRegisterValueAtInstruction(uint32_t reg, size_t instr)
{
	BNRegisterValue value = BNGetLowLevelILRegisterValueAtInstruction(m_object, reg, instr);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetRegisterValueAfterInstruction(uint32_t reg, size_t instr)
{
	BNRegisterValue value = BNGetLowLevelILRegisterValueAfterInstruction(m_object, reg, instr);
	return RegisterValue::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleRegisterValuesAtInstruction(uint32_t reg, size_t instr)
{
	BNPossibleValueSet value = BNGetLowLevelILPossibleRegisterValuesAtInstruction(m_object, reg, instr);
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleRegisterValuesAfterInstruction(uint32_t reg, size_t instr)
{
	BNPossibleValueSet value = BNGetLowLevelILPossibleRegisterValuesAfterInstruction(m_object, reg, instr);
	return PossibleValueSet::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetFlagValueAtInstruction(uint32_t flag, size_t instr)
{
	BNRegisterValue value = BNGetLowLevelILFlagValueAtInstruction(m_object, flag, instr);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetFlagValueAfterInstruction(uint32_t flag, size_t instr)
{
	BNRegisterValue value = BNGetLowLevelILFlagValueAfterInstruction(m_object, flag, instr);
	return RegisterValue::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleFlagValuesAtInstruction(uint32_t flag, size_t instr)
{
	BNPossibleValueSet value = BNGetLowLevelILPossibleFlagValuesAtInstruction(m_object, flag, instr);
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleFlagValuesAfterInstruction(uint32_t flag, size_t instr)
{
	BNPossibleValueSet value = BNGetLowLevelILPossibleFlagValuesAfterInstruction(m_object, flag, instr);
	return PossibleValueSet::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetStackContentsAtInstruction(int32_t offset, size_t len, size_t instr)
{
	BNRegisterValue value = BNGetLowLevelILStackContentsAtInstruction(m_object, offset, len, instr);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr)
{
	BNRegisterValue value = BNGetLowLevelILStackContentsAfterInstruction(m_object, offset, len, instr);
	return RegisterValue::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleStackContentsAtInstruction(int32_t offset, size_t len, size_t instr)
{
	BNPossibleValueSet value = BNGetLowLevelILPossibleStackContentsAtInstruction(m_object, offset, len, instr);
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr)
{
	BNPossibleValueSet value = BNGetLowLevelILPossibleStackContentsAfterInstruction(m_object, offset, len, instr);
	return PossibleValueSet::FromAPIObject(value);
}


Ref<MediumLevelILFunction> LowLevelILFunction::GetMediumLevelIL() const
{
	BNMediumLevelILFunction* func = BNGetMediumLevelILForLowLevelIL(m_object);
	if (!func)
		return nullptr;
	return new MediumLevelILFunction(func);
}


Ref<MediumLevelILFunction> LowLevelILFunction::GetMappedMediumLevelIL() const
{
	BNMediumLevelILFunction* func = BNGetMappedMediumLevelIL(m_object);
	if (!func)
		return nullptr;
	return new MediumLevelILFunction(func);
}


size_t LowLevelILFunction::GetMediumLevelILInstructionIndex(size_t instr) const
{
	return BNGetMediumLevelILInstructionIndex(m_object, instr);
}


size_t LowLevelILFunction::GetMediumLevelILExprIndex(size_t expr) const
{
	return BNGetMediumLevelILExprIndex(m_object, expr);
}


size_t LowLevelILFunction::GetMappedMediumLevelILInstructionIndex(size_t instr) const
{
	return BNGetMappedMediumLevelILInstructionIndex(m_object, instr);
}


size_t LowLevelILFunction::GetMappedMediumLevelILExprIndex(size_t expr) const
{
	return BNGetMappedMediumLevelILExprIndex(m_object, expr);
}
