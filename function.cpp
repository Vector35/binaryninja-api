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


Variable::Variable()
{
	type = RegisterVariableSourceType;
	index = 0;
	storage = 0;
}


Variable::Variable(BNVariableSourceType t, uint32_t i, uint64_t s)
{
	type = t;
	index = i;
	storage = s;
}


Variable::Variable(const BNVariable& var)
{
	type = var.type;
	index = var.index;
	storage = var.storage;
}


Variable& Variable::operator=(const Variable& var)
{
	type = var.type;
	index = var.index;
	storage = var.storage;
	return *this;
}


bool Variable::operator==(const Variable& var) const
{
	if (type != var.type)
		return false;
	if (index != var.index)
		return false;
	return storage == var.storage;
}


bool Variable::operator!=(const Variable& var) const
{
	return !((*this) == var);
}


bool Variable::operator<(const Variable& var) const
{
	return ToIdentifier() < var.ToIdentifier();
}


uint64_t Variable::ToIdentifier() const
{
	return BNToVariableIdentifier(this);
}


Variable Variable::FromIdentifier(uint64_t id)
{
	return BNFromVariableIdentifier(id);
}


RegisterValue::RegisterValue(): state(UndeterminedValue), value(0)
{
}


BNRegisterValue RegisterValue::ToAPIObject()
{
	BNRegisterValue result;
	result.state = state;
	result.value = value;
	return result;
}


Function::Function(BNFunction* func)
{
	m_object = func;
	m_advancedAnalysisRequests = 0;
}


Function::~Function()
{
	if (m_advancedAnalysisRequests > 0)
		BNReleaseAdvancedFunctionAnalysisDataMultiple(m_object, (size_t)m_advancedAnalysisRequests);
}


Ref<Platform> Function::GetPlatform() const
{
	return new Platform(BNGetFunctionPlatform(m_object));
}


Ref<Architecture> Function::GetArchitecture() const
{
	return new CoreArchitecture(BNGetFunctionArchitecture(m_object));
}


uint64_t Function::GetStart() const
{
	return BNGetFunctionStart(m_object);
}


Ref<Symbol> Function::GetSymbol() const
{
	return new Symbol(BNGetFunctionSymbol(m_object));
}


bool Function::WasAutomaticallyDiscovered() const
{
	return BNWasFunctionAutomaticallyDiscovered(m_object);
}


Confidence<bool> Function::CanReturn() const
{
	BNBoolWithConfidence bc = BNCanFunctionReturn(m_object);
	return Confidence<bool>(bc.value, bc.confidence);
}


bool Function::HasExplicitlyDefinedType() const
{
	return BNFunctionHasExplicitlyDefinedType(m_object);
}


bool Function::NeedsUpdate() const
{
	return BNIsFunctionUpdateNeeded(m_object);
}


vector<Ref<BasicBlock>> Function::GetBasicBlocks() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetFunctionBasicBlockList(m_object, &count);

	vector<Ref<BasicBlock>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


Ref<BasicBlock> Function::GetBasicBlockAtAddress(Architecture* arch, uint64_t addr) const
{
	BNBasicBlock* block = BNGetFunctionBasicBlockAtAddress(m_object, arch->GetObject(), addr);
	if (!block)
		return nullptr;
	return new BasicBlock(block);
}


void Function::MarkRecentUse()
{
	BNMarkFunctionAsRecentlyUsed(m_object);
}


string Function::GetComment() const
{
	char* comment = BNGetFunctionComment(m_object);
	string result = comment;
	BNFreeString(comment);
	return result;
}


string Function::GetCommentForAddress(uint64_t addr) const
{
	char* comment = BNGetCommentForAddress(m_object, addr);
	string result = comment;
	BNFreeString(comment);
	return result;
}


vector<uint64_t> Function::GetCommentedAddresses() const
{
	size_t count;
	uint64_t* addrs = BNGetCommentedAddresses(m_object, &count);
	vector<uint64_t> result;
	result.insert(result.end(), addrs, &addrs[count]);
	BNFreeAddressList(addrs);
	return result;
}


void Function::SetComment(const string& comment)
{
	BNSetFunctionComment(m_object, comment.c_str());
}


void Function::SetCommentForAddress(uint64_t addr, const string& comment)
{
	BNSetCommentForAddress(m_object, addr, comment.c_str());
}


Ref<LowLevelILFunction> Function::GetLowLevelIL() const
{
	return new LowLevelILFunction(BNGetFunctionLowLevelIL(m_object));
}


size_t Function::GetLowLevelILForInstruction(Architecture* arch, uint64_t addr)
{
	return BNGetLowLevelILForInstruction(m_object, arch->GetObject(), addr);
}


vector<size_t> Function::GetLowLevelILExitsForInstruction(Architecture* arch, uint64_t addr)
{
	size_t count;
	size_t* exits = BNGetLowLevelILExitsForInstruction(m_object, arch->GetObject(), addr, &count);

	vector<size_t> result;
	result.insert(result.end(), exits, &exits[count]);

	BNFreeILInstructionList(exits);
	return result;
}


RegisterValue RegisterValue::FromAPIObject(const BNRegisterValue& value)
{
	RegisterValue result;
	result.state = value.state;
	result.value = value.value;
	return result;
}


PossibleValueSet PossibleValueSet::FromAPIObject(BNPossibleValueSet& value)
{
	PossibleValueSet result;
	result.state = value.state;
	result.value = value.value;
	if (value.state == LookupTableValue)
	{
		for (size_t i = 0; i < value.count; i++)
		{
			LookupTableEntry entry;
			entry.fromValues.insert(entry.fromValues.end(), &value.table[i].fromValues[0],
				&value.table[i].fromValues[value.table[i].fromCount]);
			entry.toValue = value.table[i].toValue;
			result.table.push_back(entry);
		}
	}
	else if ((value.state == SignedRangeValue) || (value.state == UnsignedRangeValue))
	{
		for (size_t i = 0; i < value.count; i++)
			result.ranges.push_back(value.ranges[i]);
	}
	else if ((value.state == InSetOfValues) || (value.state == NotInSetOfValues))
	{
		for (size_t i = 0; i < value.count; i++)
			result.valueSet.insert(value.valueSet[i]);
	}
	BNFreePossibleValueSet(&value);
	return result;
}


RegisterValue Function::GetRegisterValueAtInstruction(Architecture* arch, uint64_t addr, uint32_t reg)
{
	BNRegisterValue value = BNGetRegisterValueAtInstruction(m_object, arch->GetObject(), addr, reg);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue Function::GetRegisterValueAfterInstruction(Architecture* arch, uint64_t addr, uint32_t reg)
{
	BNRegisterValue value = BNGetRegisterValueAfterInstruction(m_object, arch->GetObject(), addr, reg);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue Function::GetStackContentsAtInstruction(Architecture* arch, uint64_t addr, int64_t offset, size_t size)
{
	BNRegisterValue value = BNGetStackContentsAtInstruction(m_object, arch->GetObject(), addr, offset, size);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue Function::GetStackContentsAfterInstruction(Architecture* arch, uint64_t addr, int64_t offset, size_t size)
{
	BNRegisterValue value = BNGetStackContentsAfterInstruction(m_object, arch->GetObject(), addr, offset, size);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue Function::GetParameterValueAtInstruction(Architecture* arch, uint64_t addr, Type* functionType, size_t i)
{
	BNRegisterValue value = BNGetParameterValueAtInstruction(m_object, arch->GetObject(), addr,
		functionType ? functionType->GetObject() : nullptr, i);
	return RegisterValue::FromAPIObject(value);
}


RegisterValue Function::GetParameterValueAtLowLevelILInstruction(size_t instr, Type* functionType, size_t i)
{
	BNRegisterValue value = BNGetParameterValueAtLowLevelILInstruction(m_object, instr,
		functionType ? functionType->GetObject() : nullptr, i);
	return RegisterValue::FromAPIObject(value);
}


vector<uint32_t> Function::GetRegistersReadByInstruction(Architecture* arch, uint64_t addr)
{
	size_t count;
	uint32_t* regs = BNGetRegistersReadByInstruction(m_object, arch->GetObject(), addr, &count);

	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);

	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> Function::GetRegistersWrittenByInstruction(Architecture* arch, uint64_t addr)
{
	size_t count;
	uint32_t* regs = BNGetRegistersWrittenByInstruction(m_object, arch->GetObject(), addr, &count);

	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);

	BNFreeRegisterList(regs);
	return result;
}


vector<StackVariableReference> Function::GetStackVariablesReferencedByInstruction(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNStackVariableReference* refs = BNGetStackVariablesReferencedByInstruction(m_object, arch->GetObject(), addr, &count);

	vector<StackVariableReference> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		StackVariableReference ref;
		ref.sourceOperand = refs[i].sourceOperand;
		ref.type = Confidence<Ref<Type>>(refs[i].type ? new Type(BNNewTypeReference(refs[i].type)) : nullptr,
			refs[i].typeConfidence);
		ref.name = refs[i].name;
		ref.var = Variable::FromIdentifier(refs[i].varIdentifier);
		ref.referencedOffset = refs[i].referencedOffset;
		ref.size = refs[i].size;
		result.push_back(ref);
	}

	BNFreeStackVariableReferenceList(refs, count);
	return result;
}


vector<BNConstantReference> Function::GetConstantsReferencedByInstruction(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNConstantReference* refs = BNGetConstantsReferencedByInstruction(m_object, arch->GetObject(), addr, &count);

	vector<BNConstantReference> result;
	result.insert(result.end(), &refs[0], &refs[count]);

	BNFreeConstantReferenceList(refs);
	return result;
}


Ref<LowLevelILFunction> Function::GetLiftedIL() const
{
	return new LowLevelILFunction(BNGetFunctionLiftedIL(m_object));
}


size_t Function::GetLiftedILForInstruction(Architecture* arch, uint64_t addr)
{
	return BNGetLiftedILForInstruction(m_object, arch->GetObject(), addr);
}


set<size_t> Function::GetLiftedILFlagUsesForDefinition(size_t i, uint32_t flag)
{
	size_t count;
	size_t* instrs = BNGetLiftedILFlagUsesForDefinition(m_object, i, flag, &count);

	set<size_t> result;
	result.insert(&instrs[0], &instrs[count]);
	BNFreeILInstructionList(instrs);
	return result;
}


set<size_t> Function::GetLiftedILFlagDefinitionsForUse(size_t i, uint32_t flag)
{
	size_t count;
	size_t* instrs = BNGetLiftedILFlagDefinitionsForUse(m_object, i, flag, &count);

	set<size_t> result;
	result.insert(&instrs[0], &instrs[count]);
	BNFreeILInstructionList(instrs);
	return result;
}


set<uint32_t> Function::GetFlagsReadByLiftedILInstruction(size_t i)
{
	size_t count;
	uint32_t* flags = BNGetFlagsReadByLiftedILInstruction(m_object, i, &count);

	set<uint32_t> result;
	result.insert(&flags[0], &flags[count]);
	BNFreeRegisterList(flags);
	return result;
}


set<uint32_t> Function::GetFlagsWrittenByLiftedILInstruction(size_t i)
{
	size_t count;
	uint32_t* flags = BNGetFlagsWrittenByLiftedILInstruction(m_object, i, &count);

	set<uint32_t> result;
	result.insert(&flags[0], &flags[count]);
	BNFreeRegisterList(flags);
	return result;
}


Ref<MediumLevelILFunction> Function::GetMediumLevelIL() const
{
	return new MediumLevelILFunction(BNGetFunctionMediumLevelIL(m_object));
}


Ref<Type> Function::GetType() const
{
	return new Type(BNGetFunctionType(m_object));
}


Confidence<Ref<Type>> Function::GetReturnType() const
{
	BNTypeWithConfidence tc = BNGetFunctionReturnType(m_object);
	Ref<Type> type = tc.type ? new Type(tc.type) : nullptr;
	return Confidence<Ref<Type>>(type, tc.confidence);
}


Confidence<vector<uint32_t>> Function::GetReturnRegisters() const
{
	BNRegisterSetWithConfidence regs = BNGetFunctionReturnRegisters(m_object);
	vector<uint32_t> regList;
	for (size_t i = 0; i < regs.count; i++)
		regList.push_back(regs.regs[i]);
	Confidence<vector<uint32_t>> result(regList, regs.confidence);
	BNFreeRegisterSet(&regs);
	return result;
}


Confidence<Ref<CallingConvention>> Function::GetCallingConvention() const
{
	BNCallingConventionWithConfidence cc = BNGetFunctionCallingConvention(m_object);
	Ref<CallingConvention> convention = cc.convention ? new CoreCallingConvention(cc.convention) : nullptr;
	return Confidence<Ref<CallingConvention>>(convention, cc.confidence);
}


Confidence<vector<Variable>> Function::GetParameterVariables() const
{
	BNParameterVariablesWithConfidence vars = BNGetFunctionParameterVariables(m_object);
	vector<Variable> varList;
	varList.reserve(vars.count);
	for (size_t i = 0; i < vars.count; i++)
		varList.emplace_back(vars.vars[i].type, vars.vars[i].index, vars.vars[i].storage);
	Confidence<vector<Variable>> result(varList, vars.confidence);
	BNFreeParameterVariables(&vars);
	return result;
}


Confidence<bool> Function::HasVariableArguments() const
{
	BNBoolWithConfidence bc = BNFunctionHasVariableArguments(m_object);
	return Confidence<bool>(bc.value, bc.confidence);
}


Confidence<size_t> Function::GetStackAdjustment() const
{
	BNSizeWithConfidence sc = BNGetFunctionStackAdjustment(m_object);
	return Confidence<size_t>(sc.value, sc.confidence);
}


map<uint32_t, Confidence<int32_t>> Function::GetRegisterStackAdjustments() const
{
	size_t count;
	BNRegisterStackAdjustment* regStackAdjust = BNGetFunctionRegisterStackAdjustments(m_object, &count);
	map<uint32_t, Confidence<int32_t>> result;
	for (size_t i = 0; i < count; i++)
		result[regStackAdjust[i].regStack] = Confidence<int32_t>(regStackAdjust[i].adjustment, regStackAdjust[i].confidence);
	BNFreeRegisterStackAdjustments(regStackAdjust);
	return result;
}


Confidence<set<uint32_t>> Function::GetClobberedRegisters() const
{
	BNRegisterSetWithConfidence regs = BNGetFunctionClobberedRegisters(m_object);
	set<uint32_t> regSet;
	for (size_t i = 0; i < regs.count; i++)
		regSet.insert(regs.regs[i]);
	Confidence<set<uint32_t>> result(regSet, regs.confidence);
	BNFreeRegisterSet(&regs);
	return result;
}


void Function::SetAutoType(Type* type)
{
	BNSetFunctionAutoType(m_object, type->GetObject());
}


void Function::SetAutoReturnType(const Confidence<Ref<Type>>& type)
{
	BNTypeWithConfidence tc;
	tc.type = type ? type->GetObject() : nullptr;
	tc.confidence = type.GetConfidence();
	BNSetAutoFunctionReturnType(m_object, &tc);
}


void Function::SetAutoReturnRegisters(const Confidence<std::vector<uint32_t>>& returnRegs)
{
	BNRegisterSetWithConfidence regs;
	regs.regs = new uint32_t[returnRegs.GetValue().size()];
	regs.count = returnRegs.GetValue().size();
	for (size_t i = 0; i < regs.count; i++)
		regs.regs[i] = returnRegs.GetValue()[i];
	regs.confidence = returnRegs.GetConfidence();
	BNSetAutoFunctionReturnRegisters(m_object, &regs);
	delete[] regs.regs;
}


void Function::SetAutoCallingConvention(const Confidence<Ref<CallingConvention>>& convention)
{
	BNCallingConventionWithConfidence cc;
	cc.convention = convention ? convention->GetObject() : nullptr;
	cc.confidence = convention.GetConfidence();
	BNSetAutoFunctionCallingConvention(m_object, &cc);
}


void Function::SetAutoParameterVariables(const Confidence<vector<Variable>>& vars)
{
	BNParameterVariablesWithConfidence varConf;
	varConf.vars = new BNVariable[vars->size()];
	varConf.count = vars->size();
	size_t i = 0;
	for (auto it = vars->begin(); it != vars->end(); ++it, ++i)
	{
		varConf.vars[i].type = it->type;
		varConf.vars[i].index = it->index;
		varConf.vars[i].storage = it->storage;
	}
	varConf.confidence = vars.GetConfidence();

	BNSetAutoFunctionParameterVariables(m_object, &varConf);
	delete[] varConf.vars;
}


void Function::SetAutoHasVariableArguments(const Confidence<bool>& varArgs)
{
	BNBoolWithConfidence bc;
	bc.value = varArgs.GetValue();
	bc.confidence = varArgs.GetConfidence();
	BNSetAutoFunctionHasVariableArguments(m_object, &bc);
}


void Function::SetAutoCanReturn(const Confidence<bool>& returns)
{
	BNBoolWithConfidence bc;
	bc.value = returns.GetValue();
	bc.confidence = returns.GetConfidence();
	BNSetAutoFunctionCanReturn(m_object, &bc);
}


void Function::SetAutoStackAdjustment(const Confidence<size_t>& stackAdjust)
{
	BNSizeWithConfidence sc;
	sc.value = stackAdjust.GetValue();
	sc.confidence = stackAdjust.GetConfidence();
	BNSetAutoFunctionStackAdjustment(m_object, &sc);
}


void Function::SetAutoRegisterStackAdjustments(const map<uint32_t, Confidence<int32_t>>& regStackAdjust)
{
	BNRegisterStackAdjustment* adjust = new BNRegisterStackAdjustment[regStackAdjust.size()];
	size_t i = 0;
	for (auto& j : regStackAdjust)
	{
		adjust[i].regStack = j.first;
		adjust[i].adjustment = j.second.GetValue();
		adjust[i].confidence = j.second.GetConfidence();
		i++;
	}
	BNSetAutoFunctionRegisterStackAdjustments(m_object, adjust, regStackAdjust.size());
	delete[] adjust;
}


void Function::SetAutoClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered)
{
	BNRegisterSetWithConfidence regs;
	regs.regs = new uint32_t[clobbered->size()];
	regs.count = clobbered->size();

	size_t i = 0;
	for (auto it = clobbered->begin(); it != clobbered->end(); ++it, ++i)
		regs.regs[i] = *it;
	regs.confidence = clobbered.GetConfidence();
	BNSetAutoFunctionClobberedRegisters(m_object, &regs);
	delete[] regs.regs;
}


void Function::SetUserType(Type* type)
{
	BNSetFunctionUserType(m_object, type->GetObject());
}


void Function::SetReturnType(const Confidence<Ref<Type>>& type)
{
	BNTypeWithConfidence tc;
	tc.type = type ? type->GetObject() : nullptr;
	tc.confidence = type.GetConfidence();
	BNSetUserFunctionReturnType(m_object, &tc);
}


void Function::SetReturnRegisters(const Confidence<std::vector<uint32_t>>& returnRegs)
{
	BNRegisterSetWithConfidence regs;
	regs.regs = new uint32_t[returnRegs.GetValue().size()];
	regs.count = returnRegs.GetValue().size();
	for (size_t i = 0; i < regs.count; i++)
		regs.regs[i] = returnRegs.GetValue()[i];
	regs.confidence = returnRegs.GetConfidence();
	BNSetUserFunctionReturnRegisters(m_object, &regs);
	delete[] regs.regs;
}


void Function::SetCallingConvention(const Confidence<Ref<CallingConvention>>& convention)
{
	BNCallingConventionWithConfidence cc;
	cc.convention = convention ? convention->GetObject() : nullptr;
	cc.confidence = convention.GetConfidence();
	BNSetUserFunctionCallingConvention(m_object, &cc);
}


void Function::SetParameterVariables(const Confidence<vector<Variable>>& vars)
{
	BNParameterVariablesWithConfidence varConf;
	varConf.vars = new BNVariable[vars->size()];
	varConf.count = vars->size();
	size_t i = 0;
	for (auto it = vars->begin(); it != vars->end(); ++it, ++i)
	{
		varConf.vars[i].type = it->type;
		varConf.vars[i].index = it->index;
		varConf.vars[i].storage = it->storage;
	}
	varConf.confidence = vars.GetConfidence();

	BNSetUserFunctionParameterVariables(m_object, &varConf);
	delete[] varConf.vars;
}


void Function::SetHasVariableArguments(const Confidence<bool>& varArgs)
{
	BNBoolWithConfidence bc;
	bc.value = varArgs.GetValue();
	bc.confidence = varArgs.GetConfidence();
	BNSetUserFunctionHasVariableArguments(m_object, &bc);
}


void Function::SetCanReturn(const Confidence<bool>& returns)
{
	BNBoolWithConfidence bc;
	bc.value = returns.GetValue();
	bc.confidence = returns.GetConfidence();
	BNSetUserFunctionCanReturn(m_object, &bc);
}


void Function::SetStackAdjustment(const Confidence<size_t>& stackAdjust)
{
	BNSizeWithConfidence sc;
	sc.value = stackAdjust.GetValue();
	sc.confidence = stackAdjust.GetConfidence();
	BNSetUserFunctionStackAdjustment(m_object, &sc);
}


void Function::SetRegisterStackAdjustments(const map<uint32_t, Confidence<int32_t>>& regStackAdjust)
{
	BNRegisterStackAdjustment* adjust = new BNRegisterStackAdjustment[regStackAdjust.size()];
	size_t i = 0;
	for (auto& j : regStackAdjust)
	{
		adjust[i].regStack = j.first;
		adjust[i].adjustment = j.second.GetValue();
		adjust[i].confidence = j.second.GetConfidence();
		i++;
	}
	BNSetUserFunctionRegisterStackAdjustments(m_object, adjust, regStackAdjust.size());
	delete[] adjust;
}


void Function::SetClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered)
{
	BNRegisterSetWithConfidence regs;
	regs.regs = new uint32_t[clobbered->size()];
	regs.count = clobbered->size();
	size_t i = 0;
	for (auto it = clobbered->begin(); it != clobbered->end(); ++it, ++i)
		regs.regs[i] = *it;
	regs.confidence = clobbered.GetConfidence();
	BNSetUserFunctionClobberedRegisters(m_object, &regs);
	delete[] regs.regs;
}


void Function::ApplyImportedTypes(Symbol* sym)
{
	BNApplyImportedTypes(m_object, sym->GetObject());
}


void Function::ApplyAutoDiscoveredType(Type* type)
{
	BNApplyAutoDiscoveredFunctionType(m_object, type->GetObject());
}


Ref<FunctionGraph> Function::CreateFunctionGraph()
{
	BNFunctionGraph* graph = BNCreateFunctionGraph(m_object);
	return new FunctionGraph(graph);
}


map<int64_t, vector<VariableNameAndType>> Function::GetStackLayout()
{
	size_t count;
	BNVariableNameAndType* vars = BNGetStackLayout(m_object, &count);

	map<int64_t, vector<VariableNameAndType>> result;
	for (size_t i = 0; i < count; i++)
	{
		VariableNameAndType var;
		var.name = vars[i].name;
		var.type = Confidence<Ref<Type>>(new Type(BNNewTypeReference(vars[i].type)), vars[i].typeConfidence);
		var.var = vars[i].var;
		var.autoDefined = vars[i].autoDefined;
		result[vars[i].var.storage].push_back(var);
	}

	BNFreeVariableNameAndTypeList(vars, count);
	return result;
}


void Function::CreateAutoStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const string& name)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNCreateAutoStackVariable(m_object, offset, &tc, name.c_str());
}


void Function::CreateUserStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const string& name)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNCreateUserStackVariable(m_object, offset, &tc, name.c_str());
}


void Function::DeleteAutoStackVariable(int64_t offset)
{
	BNDeleteAutoStackVariable(m_object, offset);
}


void Function::DeleteUserStackVariable(int64_t offset)
{
	BNDeleteUserStackVariable(m_object, offset);
}


bool Function::GetStackVariableAtFrameOffset(Architecture* arch, uint64_t addr,
	int64_t offset, VariableNameAndType& result)
{
	BNVariableNameAndType var;
	if (!BNGetStackVariableAtFrameOffset(m_object, arch->GetObject(), addr, offset, &var))
		return false;

	result.type = Confidence<Ref<Type>>(new Type(BNNewTypeReference(var.type)), var.typeConfidence);
	result.name = var.name;
	result.var = var.var;
	result.autoDefined = var.autoDefined;

	BNFreeVariableNameAndType(&var);
	return true;
}


map<Variable, VariableNameAndType> Function::GetVariables()
{
	size_t count;
	BNVariableNameAndType* vars = BNGetFunctionVariables(m_object, &count);

	map<Variable, VariableNameAndType> result;
	for (size_t i = 0; i < count; i++)
	{
		VariableNameAndType var;
		var.name = vars[i].name;
		var.type = Confidence<Ref<Type>>(new Type(BNNewTypeReference(vars[i].type)), vars[i].typeConfidence);
		var.var = vars[i].var;
		var.autoDefined = vars[i].autoDefined;
		result[vars[i].var] = var;
	}

	BNFreeVariableNameAndTypeList(vars, count);
	return result;
}


void Function::CreateAutoVariable(const Variable& var, const Confidence<Ref<Type>>& type,
	const string& name, bool ignoreDisjointUses)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNCreateAutoVariable(m_object, &var, &tc, name.c_str(), ignoreDisjointUses);
}


void Function::CreateUserVariable(const Variable& var, const Confidence<Ref<Type>>& type,
	const string& name, bool ignoreDisjointUses)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNCreateUserVariable(m_object, &var, &tc, name.c_str(), ignoreDisjointUses);
}


void Function::DeleteAutoVariable(const Variable& var)
{
	BNDeleteAutoVariable(m_object, &var);
}


void Function::DeleteUserVariable(const Variable& var)
{
	BNDeleteUserVariable(m_object, &var);
}


Confidence<Ref<Type>> Function::GetVariableType(const Variable& var)
{
	BNTypeWithConfidence type = BNGetVariableType(m_object, &var);
	if (!type.type)
		return nullptr;
	return Confidence<Ref<Type>>(new Type(type.type), type.confidence);
}


string Function::GetVariableName(const Variable& var)
{
	char* name = BNGetVariableName(m_object, &var);
	string result = name;
	BNFreeString(name);
	return result;
}


void Function::SetAutoIndirectBranches(Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches)
{
	BNArchitectureAndAddress* branchList = new BNArchitectureAndAddress[branches.size()];
	for (size_t i = 0; i < branches.size(); i++)
	{
		branchList[i].arch = branches[i].arch->GetObject();
		branchList[i].address = branches[i].address;
	}
	BNSetAutoIndirectBranches(m_object, sourceArch->GetObject(), source, branchList, branches.size());
	delete[] branchList;
}


void Function::SetUserIndirectBranches(Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches)
{
	BNArchitectureAndAddress* branchList = new BNArchitectureAndAddress[branches.size()];
	for (size_t i = 0; i < branches.size(); i++)
	{
		branchList[i].arch = branches[i].arch->GetObject();
		branchList[i].address = branches[i].address;
	}
	BNSetUserIndirectBranches(m_object, sourceArch->GetObject(), source, branchList, branches.size());
	delete[] branchList;
}


vector<IndirectBranchInfo> Function::GetIndirectBranches()
{
	size_t count;
	BNIndirectBranchInfo* branches = BNGetIndirectBranches(m_object, &count);

	vector<IndirectBranchInfo> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		IndirectBranchInfo b;
		b.sourceArch = new CoreArchitecture(branches[i].sourceArch);
		b.sourceAddr = branches[i].sourceAddr;
		b.destArch = new CoreArchitecture(branches[i].destArch);
		b.destAddr = branches[i].destAddr;
		b.autoDefined = branches[i].autoDefined;
		result.push_back(b);
	}

	BNFreeIndirectBranchList(branches);
	return result;
}


vector<IndirectBranchInfo> Function::GetIndirectBranchesAt(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNIndirectBranchInfo* branches = BNGetIndirectBranchesAt(m_object, arch->GetObject(), addr, &count);

	vector<IndirectBranchInfo> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		IndirectBranchInfo b;
		b.sourceArch = new CoreArchitecture(branches[i].sourceArch);
		b.sourceAddr = branches[i].sourceAddr;
		b.destArch = new CoreArchitecture(branches[i].destArch);
		b.destAddr = branches[i].destAddr;
		b.autoDefined = branches[i].autoDefined;
		result.push_back(b);
	}

	BNFreeIndirectBranchList(branches);
	return result;
}


void Function::SetAutoCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<size_t>& adjust)
{
	BNSetAutoCallStackAdjustment(m_object, arch->GetObject(), addr, adjust.GetValue(), adjust.GetConfidence());
}


void Function::SetAutoCallRegisterStackAdjustment(Architecture* arch, uint64_t addr,
	const map<uint32_t, Confidence<int32_t>>& adjust)
{
	BNRegisterStackAdjustment* values = new BNRegisterStackAdjustment[adjust.size()];
	size_t i = 0;
	for (auto& j : adjust)
	{
		values[i].regStack = j.first;
		values[i].adjustment = j.second.GetValue();
		values[i].confidence = j.second.GetConfidence();
		i++;
	}
	BNSetAutoCallRegisterStackAdjustment(m_object, arch->GetObject(), addr, values, adjust.size());
	delete[] values;
}


void Function::SetAutoCallRegisterStackAdjustment(Architecture* arch, uint64_t addr, uint32_t regStack,
	const Confidence<int32_t>& adjust)
{
	BNSetAutoCallRegisterStackAdjustmentForRegisterStack(m_object, arch->GetObject(), addr, regStack,
		adjust.GetValue(), adjust.GetConfidence());
}


void Function::SetUserCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<size_t>& adjust)
{
	BNSetUserCallStackAdjustment(m_object, arch->GetObject(), addr, adjust.GetValue(), adjust.GetConfidence());
}


void Function::SetUserCallRegisterStackAdjustment(Architecture* arch, uint64_t addr,
	const map<uint32_t, Confidence<int32_t>>& adjust)
{
	BNRegisterStackAdjustment* values = new BNRegisterStackAdjustment[adjust.size()];
	size_t i = 0;
	for (auto& j : adjust)
	{
		values[i].regStack = j.first;
		values[i].adjustment = j.second.GetValue();
		values[i].confidence = j.second.GetConfidence();
		i++;
	}
	BNSetUserCallRegisterStackAdjustment(m_object, arch->GetObject(), addr, values, adjust.size());
	delete[] values;
}


void Function::SetUserCallRegisterStackAdjustment(Architecture* arch, uint64_t addr, uint32_t regStack,
	const Confidence<int32_t>& adjust)
{
	BNSetUserCallRegisterStackAdjustmentForRegisterStack(m_object, arch->GetObject(), addr, regStack,
		adjust.GetValue(), adjust.GetConfidence());
}


Confidence<size_t> Function::GetCallStackAdjustment(Architecture* arch, uint64_t addr)
{
	BNSizeWithConfidence result = BNGetCallStackAdjustment(m_object, arch->GetObject(), addr);
	return Confidence<size_t>(result.value, result.confidence);
}


map<uint32_t, Confidence<int32_t>> Function::GetCallRegisterStackAdjustment(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNRegisterStackAdjustment* adjust = BNGetCallRegisterStackAdjustment(m_object, arch->GetObject(), addr, &count);

	map<uint32_t, Confidence<int32_t>> result;
	for (size_t i = 0; i < count; i++)
		result[adjust[i].regStack] = Confidence<int32_t>(adjust[i].adjustment, adjust[i].confidence);
	BNFreeRegisterStackAdjustments(adjust);
	return result;
}


Confidence<int32_t> Function::GetCallRegisterStackAdjustment(Architecture* arch, uint64_t addr, uint32_t regStack)
{
	BNRegisterStackAdjustment result = BNGetCallRegisterStackAdjustmentForRegisterStack(m_object,
		arch->GetObject(), addr, regStack);
	return Confidence<int32_t>(result.adjustment, result.confidence);
}


vector<vector<InstructionTextToken>> Function::GetBlockAnnotations(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNInstructionTextLine* lines = BNGetFunctionBlockAnnotations(m_object, arch->GetObject(), addr, &count);

	vector<vector<InstructionTextToken>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		vector<InstructionTextToken> line;
		line.reserve(lines[i].count);
		for (size_t j = 0; j < lines[i].count; j++)
		{
			InstructionTextToken token;
			token.type = lines[i].tokens[j].type;
			token.text = lines[i].tokens[j].text;
			token.value = lines[i].tokens[j].value;
			token.size = lines[i].tokens[j].size;
			token.operand = lines[i].tokens[j].operand;
			token.context = lines[i].tokens[j].context;
			token.confidence = lines[i].tokens[j].confidence;
			token.address = lines[i].tokens[j].address;
			line.push_back(token);
		}
		result.push_back(line);
	}

	BNFreeInstructionTextLines(lines, count);
	return result;
}


BNIntegerDisplayType Function::GetIntegerConstantDisplayType(Architecture* arch, uint64_t instrAddr, uint64_t value,
	size_t operand)
{
	return BNGetIntegerConstantDisplayType(m_object, arch->GetObject(), instrAddr, value, operand);
}


void Function::SetIntegerConstantDisplayType(Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand,
	BNIntegerDisplayType type)
{
	BNSetIntegerConstantDisplayType(m_object, arch->GetObject(), instrAddr, value, operand, type);
}


BNHighlightColor Function::GetInstructionHighlight(Architecture* arch, uint64_t addr)
{
	return BNGetInstructionHighlight(m_object, arch->GetObject(), addr);
}


void Function::SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightColor color)
{
	BNSetAutoInstructionHighlight(m_object, arch->GetObject(), addr, color);
}


void Function::SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
	uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = StandardHighlightColor;
	hc.color = color;
	hc.mixColor = NoHighlightColor;
	hc.mix = 0;
	hc.r = 0;
	hc.g = 0;
	hc.b = 0;
	hc.alpha = alpha;
	SetAutoInstructionHighlight(arch, addr, hc);
}


void Function::SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
	BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = MixedHighlightColor;
	hc.color = color;
	hc.mixColor = mixColor;
	hc.mix = mix;
	hc.r = 0;
	hc.g = 0;
	hc.b = 0;
	hc.alpha = alpha;
	SetAutoInstructionHighlight(arch, addr, hc);
}


void Function::SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, uint8_t r, uint8_t g, uint8_t b,
	uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = CustomHighlightColor;
	hc.color = NoHighlightColor;
	hc.mixColor = NoHighlightColor;
	hc.mix = 0;
	hc.r = r;
	hc.g = g;
	hc.b = b;
	hc.alpha = alpha;
	SetAutoInstructionHighlight(arch, addr, hc);
}


void Function::SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightColor color)
{
	BNSetUserInstructionHighlight(m_object, arch->GetObject(), addr, color);
}


void Function::SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
	uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = StandardHighlightColor;
	hc.color = color;
	hc.mixColor = NoHighlightColor;
	hc.mix = 0;
	hc.r = 0;
	hc.g = 0;
	hc.b = 0;
	hc.alpha = alpha;
	SetUserInstructionHighlight(arch, addr, hc);
}


void Function::SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
	BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = MixedHighlightColor;
	hc.color = color;
	hc.mixColor = mixColor;
	hc.mix = mix;
	hc.r = 0;
	hc.g = 0;
	hc.b = 0;
	hc.alpha = alpha;
	SetUserInstructionHighlight(arch, addr, hc);
}


void Function::SetUserInstructionHighlight(Architecture* arch, uint64_t addr, uint8_t r, uint8_t g, uint8_t b,
	uint8_t alpha)
{
	BNHighlightColor hc;
	hc.style = CustomHighlightColor;
	hc.color = NoHighlightColor;
	hc.mixColor = NoHighlightColor;
	hc.mix = 0;
	hc.r = r;
	hc.g = g;
	hc.b = b;
	hc.alpha = alpha;
	SetUserInstructionHighlight(arch, addr, hc);
}


Confidence<RegisterValue> Function::GetGlobalPointerValue() const
{
	BNRegisterValueWithConfidence value = BNGetFunctionGlobalPointerValue(m_object);
	return Confidence<RegisterValue>(RegisterValue::FromAPIObject(value.value), value.confidence);
}


Confidence<RegisterValue> Function::GetRegisterValueAtExit(uint32_t reg) const
{
	BNRegisterValueWithConfidence value = BNGetFunctionRegisterValueAtExit(m_object, reg);
	return Confidence<RegisterValue>(RegisterValue::FromAPIObject(value.value), value.confidence);
}


void Function::Reanalyze()
{
	BNReanalyzeFunction(m_object);
}


void Function::RequestAdvancedAnalysisData()
{
	BNRequestAdvancedFunctionAnalysisData(m_object);
#ifdef WIN32
	InterlockedIncrement((LONG*)&m_advancedAnalysisRequests);
#else
	__sync_fetch_and_add(&m_advancedAnalysisRequests, 1);
#endif
}


void Function::ReleaseAdvancedAnalysisData()
{
	BNReleaseAdvancedFunctionAnalysisData(m_object);
#ifdef WIN32
	InterlockedDecrement((LONG*)&m_advancedAnalysisRequests);
#else
	__sync_fetch_and_add(&m_advancedAnalysisRequests, -1);
#endif
}


map<string, double> Function::GetAnalysisPerformanceInfo()
{
	size_t count;
	BNPerformanceInfo* info = BNGetFunctionAnalysisPerformanceInfo(m_object, &count);

	map<string, double> result;
	for (size_t i = 0; i < count; i++)
		result[info[i].name] = info[i].seconds;
	BNFreeAnalysisPerformanceInfo(info, count);
	return result;
}


vector<DisassemblyTextLine> Function::GetTypeTokens(DisassemblySettings* settings)
{
	size_t count;
	BNDisassemblyTextLine* lines = BNGetFunctionTypeTokens(m_object,
		settings ? settings->GetObject() : nullptr, &count);

	vector<DisassemblyTextLine> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DisassemblyTextLine line;
		line.addr = lines[i].addr;
		line.tokens.reserve(lines[i].count);
		for (size_t j = 0; j < lines[i].count; j++)
		{
			InstructionTextToken token;
			token.type = lines[i].tokens[j].type;
			token.text = lines[i].tokens[j].text;
			token.value = lines[i].tokens[j].value;
			token.size = lines[i].tokens[j].size;
			token.operand = lines[i].tokens[j].operand;
			token.context = lines[i].tokens[j].context;
			token.confidence = lines[i].tokens[j].confidence;
			token.address = lines[i].tokens[j].address;
			line.tokens.push_back(token);
		}
		result.push_back(line);
	}

	BNFreeDisassemblyTextLines(lines, count);
	return result;
}


AdvancedFunctionAnalysisDataRequestor::AdvancedFunctionAnalysisDataRequestor(Function* func): m_func(func)
{
	if (m_func)
		m_func->RequestAdvancedAnalysisData();
}


AdvancedFunctionAnalysisDataRequestor::AdvancedFunctionAnalysisDataRequestor(const AdvancedFunctionAnalysisDataRequestor& req)
{
	m_func = req.m_func;
	if (m_func)
		m_func->RequestAdvancedAnalysisData();
}


AdvancedFunctionAnalysisDataRequestor::~AdvancedFunctionAnalysisDataRequestor()
{
	if (m_func)
		m_func->ReleaseAdvancedAnalysisData();
}


AdvancedFunctionAnalysisDataRequestor& AdvancedFunctionAnalysisDataRequestor::operator=(
	const AdvancedFunctionAnalysisDataRequestor& req)
{
	SetFunction(req.m_func);
	return *this;
}


void AdvancedFunctionAnalysisDataRequestor::SetFunction(Function* func)
{
	if (m_func)
		m_func->ReleaseAdvancedAnalysisData();

	m_func = func;

	if (m_func)
		m_func->RequestAdvancedAnalysisData();
}
