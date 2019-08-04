// Copyright (c) 2015-2019 Vector 35 Inc
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
#include "lowlevelilinstruction.h"

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


Ref<Function> LowLevelILFunction::GetFunction() const
{
	BNFunction* func = BNGetLowLevelILOwnerFunction(m_object);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<Architecture> LowLevelILFunction::GetArchitecture() const
{
	Ref<Function> func = GetFunction();
	if (!func)
		return nullptr;
	return func->GetArchitecture();
}


void LowLevelILFunction::PrepareToCopyFunction(LowLevelILFunction* func)
{
	BNPrepareToCopyLowLevelILFunction(m_object, func->GetObject());
}


void LowLevelILFunction::PrepareToCopyBlock(BasicBlock* block)
{
	BNPrepareToCopyLowLevelILBasicBlock(m_object, block->GetObject());
}


BNLowLevelILLabel* LowLevelILFunction::GetLabelForSourceInstruction(size_t i)
{
	return BNGetLabelForLowLevelILSourceInstruction(m_object, i);
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


ExprId LowLevelILFunction::AddExprWithLocation(BNLowLevelILOperation operation, uint64_t addr,
	uint32_t sourceOperand, size_t size, uint32_t flags, ExprId a, ExprId b, ExprId c, ExprId d)
{
	return BNLowLevelILAddExprWithLocation(m_object, addr, sourceOperand, operation, size, flags, a, b, c, d);
}


ExprId LowLevelILFunction::AddExprWithLocation(BNLowLevelILOperation operation, const ILSourceLocation& loc,
	size_t size, uint32_t flags, ExprId a, ExprId b, ExprId c, ExprId d)
{
	if (loc.valid)
	{
		return BNLowLevelILAddExprWithLocation(m_object, loc.address, loc.sourceOperand, operation,
			size, flags, a, b, c, d);
	}
	return BNLowLevelILAddExpr(m_object, operation, size, flags, a, b, c, d);
}


ExprId LowLevelILFunction::AddInstruction(size_t expr)
{
	return BNLowLevelILAddInstruction(m_object, expr);
}


ExprId LowLevelILFunction::Goto(BNLowLevelILLabel& label, const ILSourceLocation& loc)
{
	if (loc.valid)
		return BNLowLevelILGotoWithLocation(m_object, &label, loc.address, loc.sourceOperand);
	return BNLowLevelILGoto(m_object, &label);
}


ExprId LowLevelILFunction::If(ExprId operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f,
	const ILSourceLocation& loc)
{
	if (loc.valid)
		return BNLowLevelILIfWithLocation(m_object, operand, &t, &f, loc.address, loc.sourceOperand);
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
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(operands[i]);
	BNLowLevelILFreeOperandList(operands);
	return result;
}


ExprId LowLevelILFunction::AddLabelMap(const map<uint64_t, BNLowLevelILLabel*>& labels)
{
	uint64_t* valueList = new uint64_t[labels.size()];
	BNLowLevelILLabel** labelList = new BNLowLevelILLabel*[labels.size()];
	size_t i = 0;
	for (auto& j : labels)
	{
		valueList[i] = j.first;
		labelList[i] = j.second;
		i++;
	}
	ExprId result = (ExprId)BNLowLevelILAddLabelMap(m_object, valueList, labelList, labels.size());
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


ExprId LowLevelILFunction::AddIndexList(const vector<size_t> operands)
{
	uint64_t* operandList = new uint64_t[operands.size()];
	for (size_t i = 0; i < operands.size(); i++)
		operandList[i] = operands[i];
	ExprId result = (ExprId)BNLowLevelILAddOperandList(m_object, operandList, operands.size());
	delete[] operandList;
	return result;
}


ExprId LowLevelILFunction::AddRegisterOrFlagList(const vector<RegisterOrFlag>& regs)
{
	uint64_t* operandList = new uint64_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		operandList[i] = regs[i].ToIdentifier();
	ExprId result = (ExprId)BNLowLevelILAddOperandList(m_object, operandList, regs.size());
	delete[] operandList;
	return result;
}


ExprId LowLevelILFunction::AddSSARegisterList(const vector<SSARegister>& regs)
{
	uint64_t* operandList = new uint64_t[regs.size() * 2];
	for (size_t i = 0; i < regs.size(); i++)
	{
		operandList[i * 2] = regs[i].reg;
		operandList[(i * 2) + 1] = regs[i].version;
	}
	ExprId result = (ExprId)BNLowLevelILAddOperandList(m_object, operandList, regs.size() * 2);
	delete[] operandList;
	return result;
}


ExprId LowLevelILFunction::AddSSARegisterStackList(const vector<SSARegisterStack>& regStacks)
{
	uint64_t* operandList = new uint64_t[regStacks.size() * 2];
	for (size_t i = 0; i < regStacks.size(); i++)
	{
		operandList[i * 2] = regStacks[i].regStack;
		operandList[(i * 2) + 1] = regStacks[i].version;
	}
	ExprId result = (ExprId)BNLowLevelILAddOperandList(m_object, operandList, regStacks.size() * 2);
	delete[] operandList;
	return result;
}


ExprId LowLevelILFunction::AddSSAFlagList(const vector<SSAFlag>& flags)
{
	uint64_t* operandList = new uint64_t[flags.size() * 2];
	for (size_t i = 0; i < flags.size(); i++)
	{
		operandList[i * 2] = flags[i].flag;
		operandList[(i * 2) + 1] = flags[i].version;
	}
	ExprId result = (ExprId)BNLowLevelILAddOperandList(m_object, operandList, flags.size() * 2);
	delete[] operandList;
	return result;
}


ExprId LowLevelILFunction::AddSSARegisterOrFlagList(const vector<SSARegisterOrFlag>& regs)
{
	uint64_t* operandList = new uint64_t[regs.size() * 2];
	for (size_t i = 0; i < regs.size(); i++)
	{
		operandList[i * 2] = regs[i].regOrFlag.ToIdentifier();
		operandList[(i * 2) + 1] = regs[i].version;
	}
	ExprId result = (ExprId)BNLowLevelILAddOperandList(m_object, operandList, regs.size() * 2);
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
	{
		if (op == LLIL_SET_REG)
			return GetExprForRegisterOrConstant(operands[0], size);
		return AddExpr(op, size, 0, GetExprForRegisterOrConstant(operands[0], size));
	}
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


BNLowLevelILInstruction LowLevelILFunction::GetRawExpr(size_t i) const
{
	return BNGetLowLevelILByIndex(m_object, i);
}


LowLevelILInstruction LowLevelILFunction::operator[](size_t i)
{
	return GetInstruction(i);
}


LowLevelILInstruction LowLevelILFunction::GetInstruction(size_t i)
{
	size_t expr = GetIndexForInstruction(i);
	return LowLevelILInstruction(this, GetRawExpr(expr), expr, i);
}


LowLevelILInstruction LowLevelILFunction::GetExpr(size_t i)
{
	return LowLevelILInstruction(this, GetRawExpr(i), i, GetInstructionForExpr(i));
}


size_t LowLevelILFunction::GetIndexForInstruction(size_t i) const
{
	return BNGetLowLevelILIndexForInstruction(m_object, i);
}


size_t LowLevelILFunction::GetInstructionForExpr(size_t expr) const
{
	return BNGetLowLevelILInstructionForExpr(m_object, expr);
}


size_t LowLevelILFunction::GetInstructionCount() const
{
	return BNGetLowLevelILInstructionCount(m_object);
}


size_t LowLevelILFunction::GetExprCount() const
{
	return BNGetLowLevelILExprCount(m_object);
}


void LowLevelILFunction::UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value)
{
	BNUpdateLowLevelILOperand(m_object, i, operandIndex, value);
}


void LowLevelILFunction::ReplaceExpr(size_t expr, size_t newExpr)
{
	BNReplaceLowLevelILExpr(m_object, expr, newExpr);
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

	tokens = InstructionTextToken::ConvertAndFreeInstructionTextTokenList(list, count);
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

	tokens = InstructionTextToken::ConvertAndFreeInstructionTextTokenList(list, count);
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
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


Ref<BasicBlock> LowLevelILFunction::GetBasicBlockForInstruction(size_t i) const
{
	BNBasicBlock* block = BNGetLowLevelILBasicBlockForInstruction(m_object, i);
	if (!block)
		return nullptr;
	return new BasicBlock(block);
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


size_t LowLevelILFunction::GetSSARegisterDefinition(const SSARegister& reg) const
{
	return BNGetLowLevelILSSARegisterDefinition(m_object, reg.reg, reg.version);
}


size_t LowLevelILFunction::GetSSAFlagDefinition(const SSAFlag& flag) const
{
	return BNGetLowLevelILSSAFlagDefinition(m_object, flag.flag, flag.version);
}


size_t LowLevelILFunction::GetSSAMemoryDefinition(size_t version) const
{
	return BNGetLowLevelILSSAMemoryDefinition(m_object, version);
}


set<size_t> LowLevelILFunction::GetSSARegisterUses(const SSARegister& reg) const
{
	size_t count;
	size_t* instrs = BNGetLowLevelILSSARegisterUses(m_object, reg.reg, reg.version, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
}


set<size_t> LowLevelILFunction::GetSSAFlagUses(const SSAFlag& flag) const
{
	size_t count;
	size_t* instrs = BNGetLowLevelILSSAFlagUses(m_object, flag.flag, flag.version, &count);

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


RegisterValue LowLevelILFunction::GetSSARegisterValue(const SSARegister& reg)
{
	BNRegisterValue value = BNGetLowLevelILSSARegisterValue(m_object, reg.reg, reg.version);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetSSAFlagValue(const SSAFlag& flag)
{
	BNRegisterValue value = BNGetLowLevelILSSAFlagValue(m_object, flag.flag, flag.version);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetExprValue(size_t expr)
{
	BNRegisterValue value = BNGetLowLevelILExprValue(m_object, expr);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue LowLevelILFunction::GetExprValue(const LowLevelILInstruction& expr)
{
	return GetExprValue(expr.exprIndex);
}


PossibleValueSet LowLevelILFunction::GetPossibleExprValues(size_t expr, const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value = BNGetLowLevelILPossibleExprValues(m_object, expr, optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleExprValues(const LowLevelILInstruction& expr,
	const set<BNDataFlowQueryOption>& options)
{
	return GetPossibleExprValues(expr.exprIndex, options);
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


PossibleValueSet LowLevelILFunction::GetPossibleRegisterValuesAtInstruction(uint32_t reg, size_t instr,
	const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value = BNGetLowLevelILPossibleRegisterValuesAtInstruction(m_object, reg, instr,
		optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleRegisterValuesAfterInstruction(uint32_t reg, size_t instr,
	const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value = BNGetLowLevelILPossibleRegisterValuesAfterInstruction(m_object, reg, instr,
		optionArray, options.size());
	delete[] optionArray;
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


PossibleValueSet LowLevelILFunction::GetPossibleFlagValuesAtInstruction(uint32_t flag, size_t instr,
	const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value = BNGetLowLevelILPossibleFlagValuesAtInstruction(m_object, flag, instr,
		optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleFlagValuesAfterInstruction(uint32_t flag, size_t instr,
	const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value = BNGetLowLevelILPossibleFlagValuesAfterInstruction(m_object, flag, instr,
		optionArray, options.size());
	delete[] optionArray;
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


PossibleValueSet LowLevelILFunction::GetPossibleStackContentsAtInstruction(int32_t offset, size_t len, size_t instr,
	const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value = BNGetLowLevelILPossibleStackContentsAtInstruction(m_object, offset, len, instr,
		optionArray, options.size());
	delete[] optionArray;
	return PossibleValueSet::FromAPIObject(value);
}


PossibleValueSet LowLevelILFunction::GetPossibleStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr,
	const set<BNDataFlowQueryOption>& options)
{
	BNDataFlowQueryOption* optionArray = new BNDataFlowQueryOption[options.size()];
	size_t idx = 0;
	for (auto i : options)
		optionArray[idx++] = i;
	BNPossibleValueSet value = BNGetLowLevelILPossibleStackContentsAfterInstruction(m_object, offset, len, instr,
		optionArray, options.size());
	delete[] optionArray;
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


Ref<FlowGraph> LowLevelILFunction::CreateFunctionGraph(DisassemblySettings* settings)
{
	BNFlowGraph* graph = BNCreateLowLevelILFunctionGraph(m_object, settings ? settings->GetObject() : nullptr);
	return new CoreFlowGraph(graph);
}
