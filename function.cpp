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


Ref<Type> Function::GetType() const
{
	return new Type(BNGetFunctionType(m_object));
}


void Function::ApplyImportedTypes(Symbol* sym)
{
	BNApplyImportedTypes(m_object, sym->GetObject());
}


Ref<FunctionGraph> Function::CreateFunctionGraph()
{
	BNFunctionGraph* graph = BNCreateFunctionGraph(m_object);
	return new FunctionGraph(graph);
}
