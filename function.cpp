// Copyright (c) 2015-2022 Vector 35 Inc
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
#include "mediumlevelilinstruction.h"
#include <cstring>

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


Variable::Variable(const Variable& var)
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


RegisterValue::RegisterValue(): state(UndeterminedValue), value(0), offset(0)
{
}


bool RegisterValue::IsConstant() const
{
	return (state == ConstantValue) || (state == ConstantPointerValue);
}


BNRegisterValue RegisterValue::ToAPIObject()
{
	BNRegisterValue result;
	result.state = state;
	result.value = value;
	result.offset = offset;
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


Ref<BinaryView> Function::GetView() const
{
	return new BinaryView(BNGetFunctionData(m_object));
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


bool Function::HasUserAnnotations() const
{
	return BNFunctionHasUserAnnotations(m_object);
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


vector<ReferenceSource> Function::GetCallSites() const
{
	size_t count;
	BNReferenceSource* refs = BNGetFunctionCallSites(m_object, &count);

	vector<ReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		ReferenceSource src;
		src.func = new Function(BNNewFunctionReference(refs[i].func));
		src.arch = new CoreArchitecture(refs[i].arch);
		src.addr = refs[i].addr;
		result.push_back(src);
	}

	BNFreeCodeReferences(refs, count);
	return result;
}


void Function::AddUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr)
{
	BNAddUserCodeReference(m_object, fromArch->GetObject(), fromAddr, toAddr);
}


void Function::RemoveUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr)
{
	BNRemoveUserCodeReference(m_object, fromArch->GetObject(), fromAddr, toAddr);
}


void Function::AddUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNAddUserTypeReference(m_object, fromArch->GetObject(), fromAddr, &nameObj);
}


void Function::RemoveUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNRemoveUserTypeReference(m_object, fromArch->GetObject(), fromAddr, &nameObj);
}


void Function::AddUserTypeFieldReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name, uint64_t offset, size_t size)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNAddUserTypeFieldReference(m_object, fromArch->GetObject(), fromAddr, &nameObj, offset,
		size);
}


void Function::RemoveUserTypeFieldReference(Architecture* fromArch, uint64_t fromAddr,
	const QualifiedName& name, uint64_t offset, size_t size)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNRemoveUserTypeFieldReference(m_object, fromArch->GetObject(), fromAddr, &nameObj,
		offset, size);
}


Ref<LowLevelILFunction> Function::GetLowLevelIL() const
{
	return new LowLevelILFunction(BNGetFunctionLowLevelIL(m_object));
}


Ref<LowLevelILFunction> Function::GetLowLevelILIfAvailable() const
{
	BNLowLevelILFunction* function = BNGetFunctionLowLevelILIfAvailable(m_object);
	if (!function)
		return nullptr;
	return new LowLevelILFunction(function);
}


size_t Function::GetLowLevelILForInstruction(Architecture* arch, uint64_t addr)
{
	return BNGetLowLevelILForInstruction(m_object, arch->GetObject(), addr);
}


set<size_t> Function::GetLowLevelILInstructionsForAddress(Architecture* arch, uint64_t addr)
{
	size_t count;
	size_t* instrs = BNGetLowLevelILInstructionsForAddress(m_object, arch->GetObject(), addr, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
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
	result.offset = value.offset;
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

	result.count = value.count;
	BNFreePossibleValueSet(&value);
	return result;
}


BNPossibleValueSet PossibleValueSet::ToAPIObject ()
{
	BNPossibleValueSet result;
	result.state = state;
	result.value = value;
	result.offset = offset;
	result.count = 0;

	if ((state == SignedRangeValue) || (state == UnsignedRangeValue))
	{
		result.ranges = new BNValueRange[ranges.size()];
		result.count = ranges.size();
		for (size_t i = 0; i < ranges.size(); i++)
			result.ranges[i] = ranges[i];
	}
	else
	{
		result.ranges = nullptr;
	}

	if (state == LookupTableValue)
	{
		result.table = new BNLookupTableEntry[table.size()];
		result.count = table.size();
		for (size_t i = 0; i < table.size(); i++)
		{
			result.table[i].fromValues = new int64_t[table[i].fromValues.size()];
			memcpy(result.table[i].fromValues, &table[i].fromValues[0], sizeof(int64_t) *
				table[i].fromValues.size());
			result.table[i].fromCount = table[i].fromValues.size();
			result.table[i].toValue = table[i].toValue;
		}
	}
	else
	{
		result.table = nullptr;
	}

	if ((state == InSetOfValues) || (state == NotInSetOfValues))
	{
		result.valueSet = new int64_t[valueSet.size()];
		result.count = valueSet.size();
		size_t i = 0;
		for (auto j : valueSet)
			result.valueSet[i++] = j;
	}
	else
	{
		result.valueSet = nullptr;
	}

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


Ref<LowLevelILFunction> Function::GetLiftedILIfAvailable() const
{
	BNLowLevelILFunction* function = BNGetFunctionLiftedILIfAvailable(m_object);
	if (!function)
		return nullptr;
	return new LowLevelILFunction(function);
}


size_t Function::GetLiftedILForInstruction(Architecture* arch, uint64_t addr)
{
	return BNGetLiftedILForInstruction(m_object, arch->GetObject(), addr);
}


set<size_t> Function::GetLiftedILInstructionsForAddress(Architecture* arch, uint64_t addr)
{
	size_t count;
	size_t* instrs = BNGetLiftedILInstructionsForAddress(m_object, arch->GetObject(), addr, &count);

	set<size_t> result;
	for (size_t i = 0; i < count; i++)
		result.insert(instrs[i]);

	BNFreeILInstructionList(instrs);
	return result;
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


Ref<MediumLevelILFunction> Function::GetMediumLevelILIfAvailable() const
{
	BNMediumLevelILFunction* function = BNGetFunctionMediumLevelILIfAvailable(m_object);
	if (!function)
		return nullptr;
	return new MediumLevelILFunction(function);
}


Ref<HighLevelILFunction> Function::GetHighLevelIL() const
{
	return new HighLevelILFunction(BNGetFunctionHighLevelIL(m_object));
}


Ref<HighLevelILFunction> Function::GetHighLevelILIfAvailable() const
{
	BNHighLevelILFunction* function = BNGetFunctionHighLevelILIfAvailable(m_object);
	if (!function)
		return nullptr;
	return new HighLevelILFunction(function);
}


Ref<LanguageRepresentationFunction> Function::GetLanguageRepresentation() const
{
	return new LanguageRepresentationFunction(BNGetFunctionLanguageRepresentation(m_object));
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


Confidence<int64_t> Function::GetStackAdjustment() const
{
	BNOffsetWithConfidence oc = BNGetFunctionStackAdjustment(m_object);
	return Confidence<int64_t>(oc.value, oc.confidence);
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


void Function::SetAutoStackAdjustment(const Confidence<int64_t>& stackAdjust)
{
	BNOffsetWithConfidence oc;
	oc.value = stackAdjust.GetValue();
	oc.confidence = stackAdjust.GetConfidence();
	BNSetAutoFunctionStackAdjustment(m_object, &oc);
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


void Function::SetStackAdjustment(const Confidence<int64_t>& stackAdjust)
{
	BNOffsetWithConfidence oc;
	oc.value = stackAdjust.GetValue();
	oc.confidence = stackAdjust.GetConfidence();
	BNSetUserFunctionStackAdjustment(m_object, &oc);
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


void Function::ApplyImportedTypes(Symbol* sym, Ref<Type> type)
{
	BNApplyImportedTypes(m_object, sym->GetObject(), type ? type->GetObject() : nullptr);
}


void Function::ApplyAutoDiscoveredType(Type* type)
{
	BNApplyAutoDiscoveredFunctionType(m_object, type->GetObject());
}


Ref<FlowGraph> Function::CreateFunctionGraph(BNFunctionGraphType type, DisassemblySettings* settings)
{
	BNFlowGraph* graph = BNCreateFunctionGraph(m_object, type, settings ? settings->GetObject() : nullptr);
	return new CoreFlowGraph(graph);
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
	for (size_t i = 0; i < count; ++i)
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


set<Variable> Function::GetMediumLevelILVariables()
{
	Ref<MediumLevelILFunction> mlil = this->GetMediumLevelIL();
	if (!mlil)
		return {};

	size_t count;
	BNVariable* vars = BNGetMediumLevelILVariables(mlil->GetObject(), &count);

	set<Variable> result;
	for (size_t i = 0; i < count; ++i)
		result.emplace(vars[i]);

	BNFreeVariableList(vars);
	return result;
}


set<Variable> Function::GetMediumLevelILAliasedVariables()
{
	Ref<MediumLevelILFunction> mlil = this->GetMediumLevelIL();
	if (!mlil)
		return {};

	size_t count;
	BNVariable* vars = BNGetMediumLevelILAliasedVariables(mlil->GetObject(), &count);

	set<Variable> result;
	for (size_t i = 0; i < count; ++i)
		result.emplace(vars[i]);

	BNFreeVariableList(vars);
	return result;
}


set<SSAVariable> Function::GetMediumLevelILSSAVariables()
{
	Ref<MediumLevelILFunction> mlil = this->GetMediumLevelIL();
	if (!mlil)
		return {};

	size_t count;
	BNVariable* vars = BNGetMediumLevelILVariables(mlil->GetObject(), &count);

	set<SSAVariable> result;
	for (size_t i = 0; i < count; ++i)
	{
		size_t versionCount;
		size_t* versions = BNGetMediumLevelILVariableSSAVersions(mlil->GetObject(), &vars[i], &versionCount);
		for (size_t j = 0; j < versionCount; ++j)
			result.emplace(vars[i], versions[j]);
		BNFreeILInstructionList(versions);
	}

	BNFreeVariableList(vars);
	return result;
}


set<Variable> Function::GetHighLevelILVariables()
{
	Ref<HighLevelILFunction> hlil = this->GetHighLevelIL();
	if (!hlil)
		return {};

	size_t count;
	BNVariable* vars = BNGetHighLevelILVariables(hlil->GetObject(), &count);

	set<Variable> result;
	for (size_t i = 0; i < count; ++i)
		result.emplace(vars[i]);

	BNFreeVariableList(vars);
	return result;
}


set<Variable> Function::GetHighLevelILAliasedVariables()
{
	Ref<HighLevelILFunction> hlil = this->GetHighLevelIL();
	if (!hlil)
		return {};

	size_t count;
	BNVariable* vars = BNGetHighLevelILAliasedVariables(hlil->GetObject(), &count);

	set<Variable> result;
	for (size_t i = 0; i < count; ++i)
		result.emplace(vars[i]);

	BNFreeVariableList(vars);
	return result;
}


set<SSAVariable> Function::GetHighLevelILSSAVariables()
{
	Ref<HighLevelILFunction> hlil = this->GetHighLevelIL();
	if (!hlil)
		return {};

	size_t count;
	BNVariable* vars = BNGetHighLevelILVariables(hlil->GetObject(), &count);

	set<SSAVariable> result;
	for (size_t i = 0; i < count; ++i)
	{
		size_t versionCount;
		size_t* versions = BNGetHighLevelILVariableSSAVersions(hlil->GetObject(), &vars[i], &versionCount);
		for (size_t j = 0; j < versionCount; ++j)
			result.emplace(vars[i], versions[j]);
		BNFreeILInstructionList(versions);
	}

	BNFreeVariableList(vars);
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


void Function::DeleteUserVariable(const Variable& var)
{
	BNDeleteUserVariable(m_object, &var);
}


bool Function::IsVariableUserDefinded(const Variable& var)
{
	return BNIsVariableUserDefined(m_object, &var);
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


vector<uint64_t> Function::GetUnresolvedIndirectBranches()
{
	size_t count;
	uint64_t* addrs = BNGetUnresolvedIndirectBranches(m_object, &count);
	vector<uint64_t> result;
	result.insert(result.end(), addrs, &addrs[count]);
	BNFreeAddressList(addrs);
	return result;
}


bool Function::HasUnresolvedIndirectBranches()
{
	return BNHasUnresolvedIndirectBranches(m_object);
}


void Function::SetAutoCallTypeAdjustment(Architecture* arch, uint64_t addr, const Confidence<Ref<Type>>& adjust)
{
	BNTypeWithConfidence apiObject;
	apiObject.type = adjust ? adjust->GetObject() : nullptr;
	apiObject.confidence = adjust.GetConfidence();
	BNSetAutoCallTypeAdjustment(m_object, arch->GetObject(), addr, adjust ? &apiObject : nullptr);
}


void Function::SetAutoCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<int64_t>& adjust)
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


void Function::SetUserCallTypeAdjustment(Architecture* arch, uint64_t addr, const Confidence<Ref<Type>>& adjust)
{
	BNTypeWithConfidence apiObject;
	apiObject.type = adjust ? adjust->GetObject() : nullptr;
	apiObject.confidence = adjust.GetConfidence();
	BNSetUserCallTypeAdjustment(m_object, arch->GetObject(), addr, adjust ? &apiObject : nullptr);
}


void Function::SetUserCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<int64_t>& adjust)
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


Confidence<Ref<Type>> Function::GetCallTypeAdjustment(Architecture* arch, uint64_t addr)
{
	BNTypeWithConfidence result = BNGetCallTypeAdjustment(m_object, arch->GetObject(), addr);
	return Confidence<Ref<Type>>(result.type ? new Type(result.type) : nullptr, result.confidence);
}


Confidence<int64_t> Function::GetCallStackAdjustment(Architecture* arch, uint64_t addr)
{
	BNOffsetWithConfidence result = BNGetCallStackAdjustment(m_object, arch->GetObject(), addr);
	return Confidence<int64_t>(result.value, result.confidence);
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


bool Function::IsCallInstruction(Architecture* arch, uint64_t addr)
{
	return BNIsCallInstruction(m_object, arch->GetObject(), addr);
}


vector<vector<InstructionTextToken>> Function::GetBlockAnnotations(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNInstructionTextLine* lines = BNGetFunctionBlockAnnotations(m_object, arch->GetObject(), addr, &count);

	vector<vector<InstructionTextToken>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(InstructionTextToken::ConvertInstructionTextTokenList(lines[i].tokens, lines[i].count));

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


std::vector<TagReference> Function::GetAllTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetFunctionAllTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> Function::GetTagReferencesOfType(Ref<TagType> tagType)
{
	size_t count;
	BNTagReference* refs = BNGetFunctionTagReferencesOfType(m_object, tagType->GetObject(), &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> Function::GetAddressTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetAddressTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> Function::GetAutoAddressTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetAutoAddressTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> Function::GetUserAddressTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetUserAddressTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<Ref<Tag>> Function::GetAddressTags(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNTag** tags = BNGetAddressTags(m_object, arch->GetObject(), addr, &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> Function::GetAutoAddressTags(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNTag** tags = BNGetAutoAddressTags(m_object, arch->GetObject(), addr, &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> Function::GetUserAddressTags(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNTag** tags = BNGetUserAddressTags(m_object, arch->GetObject(), addr, &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> Function::GetAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType)
{
	size_t count;
	BNTag** tags = BNGetAddressTagsOfType(m_object, arch->GetObject(), addr, tagType->GetObject(), &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> Function::GetAutoAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType)
{
	size_t count;
	BNTag** tags = BNGetAutoAddressTagsOfType(m_object, arch->GetObject(), addr, tagType->GetObject(), &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> Function::GetUserAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType)
{
	size_t count;
	BNTag** tags = BNGetUserAddressTagsOfType(m_object, arch->GetObject(), addr, tagType->GetObject(), &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<TagReference> Function::GetAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end)
{
	size_t count;
	BNTagReference* refs = BNGetAddressTagsInRange(m_object, arch->GetObject(), start, end, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> Function::GetAutoAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end)
{
	size_t count;
	BNTagReference* refs = BNGetAutoAddressTagsInRange(m_object, arch->GetObject(), start, end, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> Function::GetUserAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end)
{
	size_t count;
	BNTagReference* refs = BNGetUserAddressTagsInRange(m_object, arch->GetObject(), start, end, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


void Function::AddAutoAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag)
{
	BNAddAutoAddressTag(m_object, arch->GetObject(), addr, tag->GetObject());
}


void Function::RemoveAutoAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag)
{
	BNRemoveAutoAddressTag(m_object, arch->GetObject(), addr, tag->GetObject());
}


void Function::RemoveAutoAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType)
{
	BNRemoveAutoAddressTagsOfType(m_object, arch->GetObject(), addr, tagType->GetObject());
}


void Function::AddUserAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag)
{
	BNAddUserAddressTag(m_object, arch->GetObject(), addr, tag->GetObject());
}


void Function::RemoveUserAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag)
{
	BNRemoveUserAddressTag(m_object, arch->GetObject(), addr, tag->GetObject());
}


void Function::RemoveUserAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType)
{
	BNRemoveUserAddressTagsOfType(m_object, arch->GetObject(), addr, tagType->GetObject());
}


std::vector<TagReference> Function::GetFunctionTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetFunctionTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> Function::GetAutoFunctionTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetAutoFunctionTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> Function::GetUserFunctionTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetUserFunctionTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<Ref<Tag>> Function::GetFunctionTags()
{
	size_t count;
	BNTag** tags = BNGetFunctionTags(m_object, &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> Function::GetAutoFunctionTags()
{
	size_t count;
	BNTag** tags = BNGetAutoFunctionTags(m_object, &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> Function::GetUserFunctionTags()
{
	size_t count;
	BNTag** tags = BNGetUserFunctionTags(m_object, &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> Function::GetFunctionTagsOfType(Ref<TagType> tagType)
{
	size_t count;
	BNTag** tags = BNGetFunctionTagsOfType(m_object, tagType->GetObject(), &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> Function::GetAutoFunctionTagsOfType(Ref<TagType> tagType)
{
	size_t count;
	BNTag** tags = BNGetAutoFunctionTagsOfType(m_object, tagType->GetObject(), &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> Function::GetUserFunctionTagsOfType(Ref<TagType> tagType)
{
	size_t count;
	BNTag** tags = BNGetUserFunctionTagsOfType(m_object, tagType->GetObject(), &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


void Function::AddAutoFunctionTag(Ref<Tag> tag)
{
	BNAddAutoFunctionTag(m_object, tag->GetObject());
}


void Function::RemoveAutoFunctionTag(Ref<Tag> tag)
{
	BNRemoveAutoFunctionTag(m_object, tag->GetObject());
}


void Function::RemoveAutoFunctionTagsOfType(Ref<TagType> tagType)
{
	BNRemoveAutoFunctionTagsOfType(m_object, tagType->GetObject());
}


void Function::AddUserFunctionTag(Ref<Tag> tag)
{
	BNAddUserFunctionTag(m_object, tag->GetObject());
}


void Function::RemoveUserFunctionTag(Ref<Tag> tag)
{
	BNRemoveUserFunctionTag(m_object, tag->GetObject());
}


void Function::RemoveUserFunctionTagsOfType(Ref<TagType> tagType)
{
	BNRemoveUserFunctionTagsOfType(m_object, tagType->GetObject());
}


Ref<Tag> Function::CreateAutoAddressTag(Architecture* arch, uint64_t addr, const std::string& tagTypeName, const std::string& data, bool unique)
{
	Ref<TagType> tagType = GetView()->GetTagTypeByName(tagTypeName);
	if (!tagType)
		return nullptr;

	return CreateAutoAddressTag(arch, addr, tagType, data, unique);
}


Ref<Tag> Function::CreateAutoAddressTag(Architecture* arch, uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique)
{
	if (unique)
	{
		auto tags = GetAddressTags(arch, addr);
		for (const auto& tag : tags)
		{
			if (tag->GetType() == tagType && tag->GetData() == data)
				return nullptr;
		}
	}

	Ref<Tag> tag = new Tag(tagType, data);
	GetView()->AddTag(tag);

	AddAutoAddressTag(arch, addr, tag);
	return tag;
}


Ref<Tag> Function::CreateUserAddressTag(Architecture* arch, uint64_t addr, const std::string& tagTypeName, const std::string& data, bool unique)
{
	Ref<TagType> tagType = GetView()->GetTagTypeByName(tagTypeName);
	if (!tagType)
		return nullptr;

	return CreateUserAddressTag(arch, addr, tagType, data, unique);
}


Ref<Tag> Function::CreateUserAddressTag(Architecture* arch, uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique)
{
	if (unique)
	{
		auto tags = GetAddressTags(arch, addr);
		for (const auto& tag : tags)
		{
			if (tag->GetType() == tagType && tag->GetData() == data)
				return nullptr;
		}
	}
	Ref<Tag> tag = new Tag(tagType, data);
	GetView()->AddTag(tag);

	AddUserAddressTag(arch, addr, tag);
	return tag;
}


Ref<Tag> Function::CreateAutoFunctionTag(const std::string& tagTypeName, const std::string& data, bool unique)
{
	Ref<TagType> tagType = GetView()->GetTagTypeByName(tagTypeName);
	if (!tagType)
		return nullptr;

	return CreateAutoFunctionTag(tagType, data, unique);
}


Ref<Tag> Function::CreateAutoFunctionTag(Ref<TagType> tagType, const std::string& data, bool unique)
{
	if (unique)
	{
		auto tags = GetFunctionTags();
		for (const auto& tag : tags)
		{
			if (tag->GetType() == tagType && tag->GetData() == data)
				return nullptr;
		}
	}

	Ref<Tag> tag = new Tag(tagType, data);
	GetView()->AddTag(tag);

	AddAutoFunctionTag(tag);
	return tag;
}


Ref<Tag> Function::CreateUserFunctionTag(const std::string& tagTypeName, const std::string& data, bool unique)
{
	Ref<TagType> tagType = GetView()->GetTagTypeByName(tagTypeName);
	if (!tagType)
		return nullptr;

	return CreateUserFunctionTag(tagType, data, unique);
}


Ref<Tag> Function::CreateUserFunctionTag(Ref<TagType> tagType, const std::string& data, bool unique)
{
	if (unique)
	{
		auto tags = GetFunctionTags();
		for (const auto& tag : tags)
		{
			if (tag->GetType() == tagType && tag->GetData() == data)
				return nullptr;
		}
	}

	Ref<Tag> tag = new Tag(tagType, data);
	GetView()->AddTag(tag);

	AddUserFunctionTag(tag);
	return tag;
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


Ref<Workflow> Function::GetWorkflow() const
{
	BNWorkflow* workflow = BNGetWorkflowForFunction(m_object);
	if (!workflow)
		return nullptr;
	return new Workflow(workflow);
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
		line.instrIndex = lines[i].instrIndex;
		line.highlight = lines[i].highlight;
		line.tokens = InstructionTextToken::ConvertInstructionTextTokenList(lines[i].tokens, lines[i].count);
		line.tags = Tag::ConvertTagList(lines[i].tags, lines[i].tagCount);
		result.push_back(line);
	}

	BNFreeDisassemblyTextLines(lines, count);
	return result;
}


bool Function::IsFunctionTooLarge()
{
	return BNIsFunctionTooLarge(m_object);
}


bool Function::IsAnalysisSkipped()
{
	return BNIsFunctionAnalysisSkipped(m_object);
}


BNAnalysisSkipReason Function::GetAnalysisSkipReason()
{
	return BNGetAnalysisSkipReason(m_object);
}


BNFunctionAnalysisSkipOverride Function::GetAnalysisSkipOverride()
{
	return BNGetFunctionAnalysisSkipOverride(m_object);
}


void Function::SetAnalysisSkipOverride(BNFunctionAnalysisSkipOverride skip)
{
	BNSetFunctionAnalysisSkipOverride(m_object, skip);
}


Ref<FlowGraph> Function::GetUnresolvedStackAdjustmentGraph()
{
	BNFlowGraph* graph = BNGetUnresolvedStackAdjustmentGraph(m_object);
	if (!graph)
		return nullptr;
	return new CoreFlowGraph(graph);
}


void Function::SetUserVariableValue(const Variable& var, uint64_t defAddr, PossibleValueSet& value)
{
	Ref<MediumLevelILFunction> mlil = GetMediumLevelIL();
	const set<size_t>& varDefs = mlil->GetVariableDefinitions(var);
	if (varDefs.size() == 0)
	{
		LogError("Could not get definition for Variable");
		return;
	}
	bool found = false;
	for (auto& site : varDefs)
	{
		const MediumLevelILInstruction& instr = mlil->GetInstruction(site);
		if (instr.address == defAddr)
		{
			found = true;
			break;
		}
	}
	if (!found)
	{
		LogError("Could not find definition for variable at given address");
	}
	auto defSite = BNArchitectureAndAddress();
	defSite.arch = GetArchitecture()->m_object;
	defSite.address = defAddr;

	auto var_data = BNVariable();
	var_data.type = var.type;
	var_data.index = var.index;
	var_data.storage = var.storage;

	auto valueObj = value.ToAPIObject();

	BNSetUserVariableValue(m_object, &var_data, &defSite, &valueObj);
}


void Function::ClearUserVariableValue(const Variable& var, uint64_t defAddr)
{
	Ref<MediumLevelILFunction> mlil = GetMediumLevelIL();
	const set<size_t>& varDefs = mlil->GetVariableDefinitions(var);
	if (varDefs.size() == 0)
	{
		LogError("Could not get definition for Variable");
		return;
	}
	bool found = false;
	for (auto& site : varDefs)
	{
		const MediumLevelILInstruction& instr = mlil->GetInstruction(site);
		if (instr.address == defAddr)
		{
			found = true;
			break;
		}
	}
	if (!found)
	{
		LogError("Could not find definition for variable at given address");
	}
	auto defSite = BNArchitectureAndAddress();
	defSite.arch = GetArchitecture()->m_object;
	defSite.address = defAddr;

	auto var_data = BNVariable();
	var_data.type = var.type;
	var_data.index = var.index;
	var_data.storage = var.storage;

	BNClearUserVariableValue(m_object, &var_data, &defSite);
}


map<Variable, map<ArchAndAddr, PossibleValueSet>> Function::GetAllUserVariableValues()
{
	size_t count;
	map<Variable, map<ArchAndAddr, PossibleValueSet>> result;
	BNUserVariableValue* var_values = BNGetAllUserVariableValues(m_object, &count);

	for (size_t i = 0; i < count; i++)
	{
		Variable var(var_values[i].var);
		Architecture* arch = new CoreArchitecture(var_values[i].defSite.arch);
		uint64_t address = var_values[i].defSite.address;
		ArchAndAddr defSite(arch, address);
		PossibleValueSet value = PossibleValueSet::FromAPIObject(var_values[i].value);
		result[var][defSite] = value;
	}

	BNFreeUserVariableValues(var_values);
	return result;
}


void Function::ClearAllUserVariableValues()
{
	const map<Variable, map<ArchAndAddr, PossibleValueSet>>& allValues = GetAllUserVariableValues();
	for (auto& valuePair : allValues)
	{
		for (auto& valMap : valuePair.second)
		{
			ClearUserVariableValue(valuePair.first, valMap.first.address);
		}
	}
}


void Function::RequestDebugReport(const string& name)
{
	BNRequestFunctionDebugReport(m_object, name.c_str());
}


string Function::GetGotoLabelName(uint64_t labelId)
{
	char* name = BNGetGotoLabelName(m_object, labelId);
	string result = name;
	BNFreeString(name);
	return result;
}


void Function::SetGotoLabelName(uint64_t labelId, const std::string& name)
{
	BNSetUserGotoLabelName(m_object, labelId, name.c_str());
}


BNDeadStoreElimination Function::GetVariableDeadStoreElimination(const Variable& var)
{
	BNVariable varData;
	varData.type = var.type;
	varData.index = var.index;
	varData.storage = var.storage;
	return BNGetFunctionVariableDeadStoreElimination(m_object, &varData);
}


void Function::SetVariableDeadStoreElimination(const Variable& var, BNDeadStoreElimination mode)
{
	BNVariable varData;
	varData.type = var.type;
	varData.index = var.index;
	varData.storage = var.storage;
	BNSetFunctionVariableDeadStoreElimination(m_object, &varData, mode);
}


vector<ILReferenceSource> Function::GetMediumLevelILVariableReferences(const Variable& var)
{
	size_t count;

	BNVariable varData;
	varData.type = var.type;
	varData.index = var.index;
	varData.storage = var.storage;

	BNILReferenceSource* refs = BNGetMediumLevelILVariableReferences(m_object, &varData, &count);

	vector<ILReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		ILReferenceSource src;
		src.func = new Function(BNNewFunctionReference(refs[i].func));
		src.arch = new CoreArchitecture(refs[i].arch);
		src.addr = refs[i].addr;
		src.type = refs[i].type;
		src.exprId = refs[i].exprId;
		result.push_back(src);
	}

	BNFreeILReferences(refs, count);
	return result;
}


vector<VariableReferenceSource> Function::GetMediumLevelILVariableReferencesFrom(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNVariableReferenceSource* refs = BNGetMediumLevelILVariableReferencesFrom(m_object, arch->GetObject(), addr, &count);

	vector<VariableReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		VariableReferenceSource src;
		src.var.index = refs[i].var.index;
		src.var.storage = refs[i].var.storage;
		src.var.type = refs[i].var.type;

		src.source.func = new Function(BNNewFunctionReference(refs[i].source.func));
		src.source.arch = new CoreArchitecture(refs[i].source.arch);
		src.source.addr = refs[i].source.addr;
		src.source.type = refs[i].source.type;
		src.source.exprId = refs[i].source.exprId;

		result.push_back(src);
	}

	BNFreeVariableReferenceSourceList(refs, count);
	return result;
}


vector<VariableReferenceSource> Function::GetMediumLevelILVariableReferencesInRange(Architecture* arch, uint64_t addr, uint64_t len)
{
	size_t count;
	BNVariableReferenceSource* refs = BNGetMediumLevelILVariableReferencesInRange(m_object, arch->GetObject(), addr, len, &count);

	vector<VariableReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		VariableReferenceSource src;
		src.var.index = refs[i].var.index;
		src.var.storage = refs[i].var.storage;
		src.var.type = refs[i].var.type;

		src.source.func = new Function(BNNewFunctionReference(refs[i].source.func));
		src.source.arch = new CoreArchitecture(refs[i].source.arch);
		src.source.addr = refs[i].source.addr;
		src.source.type = refs[i].source.type;
		src.source.exprId = refs[i].source.exprId;

		result.push_back(src);
	}

	BNFreeVariableReferenceSourceList(refs, count);
	return result;
}


vector<ILReferenceSource> Function::GetHighLevelILVariableReferences(const Variable& var)
{
	size_t count;

	BNVariable varData;
	varData.type = var.type;
	varData.index = var.index;
	varData.storage = var.storage;

	BNILReferenceSource* refs = BNGetHighLevelILVariableReferences(m_object, &varData, &count);

	vector<ILReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		ILReferenceSource src;
		src.func = new Function(BNNewFunctionReference(refs[i].func));
		src.arch = new CoreArchitecture(refs[i].arch);
		src.addr = refs[i].addr;
		src.type = refs[i].type;
		src.exprId = refs[i].exprId;
		result.push_back(src);
	}

	BNFreeILReferences(refs, count);
	return result;
}


vector<VariableReferenceSource> Function::GetHighLevelILVariableReferencesFrom(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNVariableReferenceSource* refs = BNGetHighLevelILVariableReferencesFrom(m_object, arch->GetObject(), addr, &count);

	vector<VariableReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		VariableReferenceSource src;
		src.var.index = refs[i].var.index;
		src.var.storage = refs[i].var.storage;
		src.var.type = refs[i].var.type;

		src.source.func = new Function(BNNewFunctionReference(refs[i].source.func));
		src.source.arch = new CoreArchitecture(refs[i].source.arch);
		src.source.addr = refs[i].source.addr;
		src.source.type = refs[i].source.type;
		src.source.exprId = refs[i].source.exprId;

		result.push_back(src);
	}

	BNFreeVariableReferenceSourceList(refs, count);
	return result;
}


vector<VariableReferenceSource> Function::GetHighLevelILVariableReferencesInRange(Architecture* arch, uint64_t addr, uint64_t len)
{
	size_t count;
	BNVariableReferenceSource* refs = BNGetHighLevelILVariableReferencesInRange(m_object, arch->GetObject(), addr, len, &count);

	vector<VariableReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		VariableReferenceSource src;
		src.var.index = refs[i].var.index;
		src.var.storage = refs[i].var.storage;
		src.var.type = refs[i].var.type;

		src.source.func = new Function(BNNewFunctionReference(refs[i].source.func));
		src.source.arch = new CoreArchitecture(refs[i].source.arch);
		src.source.addr = refs[i].source.addr;
		src.source.type = refs[i].source.type;
		src.source.exprId = refs[i].source.exprId;

		result.push_back(src);
	}

	BNFreeVariableReferenceSourceList(refs, count);
	return result;
}


uint64_t Function::GetHighestAddress()
{
	return BNGetFunctionHighestAddress(m_object);
}


uint64_t Function::GetLowestAddress()
{
	return BNGetFunctionLowestAddress(m_object);
}


std::vector<BNAddressRange> Function::GetAddressRanges()
{
	size_t count;
	BNAddressRange* ranges = BNGetFunctionAddressRanges(m_object, &count);

	std::vector<BNAddressRange> result;
	copy(&ranges[0], &ranges[count], back_inserter(result));
	BNFreeAddressRanges(ranges);
	return result;
}


bool Function::GetInstructionContainingAddress(Architecture* arch,
	uint64_t addr, uint64_t* start)
{
	return BNGetInstructionContainingAddress(m_object, arch->GetObject(), addr, start);
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
