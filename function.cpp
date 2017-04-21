// Copyright (c) 2015-2016 Vector 35 LLC
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


bool Function::CanReturn() const
{
	return BNCanFunctionReturn(m_object);
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


RegisterValue RegisterValue::FromAPIObject(BNRegisterValue& value)
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
	for (size_t i = 0; i < count; i++)
	{
		StackVariableReference ref;
		ref.sourceOperand = refs[i].sourceOperand;
		ref.type = refs[i].type ? new Type(BNNewTypeReference(refs[i].type)) : nullptr;
		ref.name = refs[i].name;
		ref.startingOffset = refs[i].startingOffset;
		ref.referencedOffset = refs[i].referencedOffset;
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


void Function::SetAutoType(Type* type)
{
	BNSetFunctionAutoType(m_object, type->GetObject());
}


void Function::SetUserType(Type* type)
{
	BNSetFunctionUserType(m_object, type->GetObject());
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
		var.type = new Type(BNNewTypeReference(vars[i].type));
		var.var = vars[i].var;
		var.autoDefined = vars[i].autoDefined;
		result[vars[i].var.storage].push_back(var);
	}

	BNFreeVariableList(vars, count);
	return result;
}


void Function::CreateAutoStackVariable(int64_t offset, Ref<Type> type, const string& name)
{
	BNCreateAutoStackVariable(m_object, offset, type->GetObject(), name.c_str());
}


void Function::CreateUserStackVariable(int64_t offset, Ref<Type> type, const string& name)
{
	BNCreateUserStackVariable(m_object, offset, type->GetObject(), name.c_str());
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

	result.type = new Type(BNNewTypeReference(var.type));
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
		var.type = new Type(BNNewTypeReference(vars[i].type));
		var.var = vars[i].var;
		var.autoDefined = vars[i].autoDefined;
		result[vars[i].var] = var;
	}

	BNFreeVariableList(vars, count);
	return result;
}


void Function::CreateAutoVariable(const Variable& var, Ref<Type> type, const string& name, bool ignoreDisjointUses)
{
	BNCreateAutoVariable(m_object, &var, type->GetObject(), name.c_str(), ignoreDisjointUses);
}


void Function::CreateUserVariable(const Variable& var, Ref<Type> type, const string& name, bool ignoreDisjointUses)
{
	BNCreateUserVariable(m_object, &var, type->GetObject(), name.c_str(), ignoreDisjointUses);
}


void Function::DeleteAutoVariable(const Variable& var)
{
	BNDeleteAutoVariable(m_object, &var);
}


void Function::DeleteUserVariable(const Variable& var)
{
	BNDeleteAutoVariable(m_object, &var);
}


Ref<Type> Function::GetVariableType(const Variable& var)
{
	BNType* type = BNGetVariableType(m_object, &var);
	if (!type)
		return nullptr;
	return new Type(type);
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


vector<vector<InstructionTextToken>> Function::GetBlockAnnotations(Architecture* arch, uint64_t addr)
{
	size_t count;
	BNInstructionTextLine* lines = BNGetFunctionBlockAnnotations(m_object, arch->GetObject(), addr, &count);

	vector<vector<InstructionTextToken>> result;
	for (size_t i = 0; i < count; i++)
	{
		vector<InstructionTextToken> line;
		for (size_t j = 0; j < lines[i].count; j++)
		{
			InstructionTextToken token;
			token.type = lines[i].tokens[j].type;
			token.text = lines[i].tokens[j].text;
			token.value = lines[i].tokens[j].value;
			token.size = lines[i].tokens[j].size;
			token.operand = lines[i].tokens[j].operand;
			token.context = lines[i].tokens[j].context;
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
