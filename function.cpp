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


Function::Function(BNFunction* func)
{
	m_object = func;
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


vector<Ref<BasicBlock>> Function::GetLowLevelILBasicBlocks() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetFunctionLowLevelILBasicBlockList(m_object, &count);

	vector<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
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

	BNFreeLowLevelILInstructionList(exits);
	return result;
}


BNRegisterValue Function::GetRegisterValueAtInstruction(Architecture* arch, uint64_t addr, uint32_t reg)
{
	return BNGetRegisterValueAtInstruction(m_object, arch->GetObject(), addr, reg);
}


BNRegisterValue Function::GetRegisterValueAfterInstruction(Architecture* arch, uint64_t addr, uint32_t reg)
{
	return BNGetRegisterValueAfterInstruction(m_object, arch->GetObject(), addr, reg);
}


BNRegisterValue Function::GetRegisterValueAtLowLevelILInstruction(size_t i, uint32_t reg)
{
	return BNGetRegisterValueAtLowLevelILInstruction(m_object, i, reg);
}


BNRegisterValue Function::GetRegisterValueAfterLowLevelILInstruction(size_t i, uint32_t reg)
{
	return BNGetRegisterValueAfterLowLevelILInstruction(m_object, i, reg);
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


Ref<Type> Function::GetType() const
{
	return new Type(BNGetFunctionType(m_object));
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


map<int64_t, StackVariable> Function::GetStackLayout()
{
	size_t count;
	BNStackVariable* vars = BNGetStackLayout(m_object, &count);

	map<int64_t, StackVariable> result;
	for (size_t i = 0; i < count; i++)
	{
		StackVariable var;
		var.name = vars[i].name;
		var.type = new Type(BNNewTypeReference(vars[i].type));
		var.offset = vars[i].offset;
		var.autoDefined = vars[i].autoDefined;
		result[vars[i].offset] = var;
	}

	BNFreeStackLayout(vars, count);
	return result;
}


void Function::CreateAutoStackVariable(int64_t offset, Type* type, const string& name)
{
	BNCreateAutoStackVariable(m_object, offset, type->GetObject(), name.c_str());
}


void Function::CreateUserStackVariable(int64_t offset, Type* type, const string& name)
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


bool Function::GetStackVariableAtFrameOffset(int64_t offset, StackVariable& result)
{
	BNStackVariable var;
	if (!BNGetStackVariableAtFrameOffset(m_object, offset, &var))
		return false;

	result.type = new Type(BNNewTypeReference(var.type));
	result.name = var.name;
	result.offset = var.offset;
	result.autoDefined = var.autoDefined;

	BNFreeStackVariable(&var);
	return true;
}
