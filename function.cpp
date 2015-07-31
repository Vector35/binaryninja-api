#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


Function::Function(BNFunction* func): m_func(func)
{
}


Function::~Function()
{
	BNFreeFunction(m_func);
}


Ref<Architecture> Function::GetArchitecture() const
{
	return new CoreArchitecture(BNGetFunctionArchitecture(m_func));
}


uint64_t Function::GetStart() const
{
	return BNGetFunctionStart(m_func);
}


Ref<Symbol> Function::GetSymbol() const
{
	return new Symbol(BNGetFunctionSymbol(m_func));
}


bool Function::WasAutomaticallyDiscovered() const
{
	return BNWasFunctionAutomaticallyDiscovered(m_func);
}


bool Function::CanReturn() const
{
	return BNCanFunctionReturn(m_func);
}


vector<Ref<BasicBlock>> Function::GetBasicBlocks() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetFunctionBasicBlockList(m_func, &count);

	vector<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


void Function::MarkRecentUse()
{
	BNMarkFunctionAsRecentlyUsed(m_func);
}


string Function::GetCommentForAddress(uint64_t addr) const
{
	char* comment = BNGetCommentForAddress(m_func, addr);
	string result = comment;
	BNFreeString(comment);
	return result;
}


vector<uint64_t> Function::GetCommentedAddresses() const
{
	size_t count;
	uint64_t* addrs = BNGetCommentedAddresses(m_func, &count);
	vector<uint64_t> result;
	result.insert(result.end(), addrs, &addrs[count]);
	BNFreeAddressList(addrs);
	return result;
}


void Function::SetCommentForAddress(uint64_t addr, const string& comment)
{
	BNSetCommentForAddress(m_func, addr, comment.c_str());
}


Ref<LowLevelILFunction> Function::GetLowLevelIL() const
{
	return new LowLevelILFunction(BNGetFunctionLowLevelIL(m_func));
}


vector<Ref<BasicBlock>> Function::GetLowLevelILBasicBlocks() const
{
	size_t count;
	BNBasicBlock** blocks = BNGetFunctionLowLevelILBasicBlockList(m_func, &count);

	vector<Ref<BasicBlock>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


size_t Function::GetLowLevelILForInstruction(Architecture* arch, uint64_t addr)
{
	return BNGetLowLevelILForInstruction(m_func, arch->GetArchitectureObject(), addr);
}


vector<size_t> Function::GetLowLevelILExitsForInstruction(Architecture* arch, uint64_t addr)
{
	size_t count;
	size_t* exits = BNGetLowLevelILExitsForInstruction(m_func, arch->GetArchitectureObject(), addr, &count);

	vector<size_t> result;
	result.insert(result.end(), exits, &exits[count]);

	BNFreeLowLevelILInstructionList(exits);
	return result;
}


BNRegisterValue Function::GetRegisterValueAtInstruction(Architecture* arch, uint64_t addr, uint32_t reg)
{
	return BNGetRegisterValueAtInstruction(m_func, arch->GetArchitectureObject(), addr, reg);
}


BNRegisterValue Function::GetRegisterValueAfterInstruction(Architecture* arch, uint64_t addr, uint32_t reg)
{
	return BNGetRegisterValueAfterInstruction(m_func, arch->GetArchitectureObject(), addr, reg);
}


BNRegisterValue Function::GetRegisterValueAtLowLevelILInstruction(size_t i, uint32_t reg)
{
	return BNGetRegisterValueAtLowLevelILInstruction(m_func, i, reg);
}


BNRegisterValue Function::GetRegisterValueAfterLowLevelILInstruction(size_t i, uint32_t reg)
{
	return BNGetRegisterValueAfterLowLevelILInstruction(m_func, i, reg);
}


vector<uint32_t> Function::GetRegistersReadByInstruction(Architecture* arch, uint64_t addr)
{
	size_t count;
	uint32_t* regs = BNGetRegistersReadByInstruction(m_func, arch->GetArchitectureObject(), addr, &count);

	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);

	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> Function::GetRegistersWrittenByInstruction(Architecture* arch, uint64_t addr)
{
	size_t count;
	uint32_t* regs = BNGetRegistersWrittenByInstruction(m_func, arch->GetArchitectureObject(), addr, &count);

	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);

	BNFreeRegisterList(regs);
	return result;
}


Ref<Type> Function::GetType() const
{
	return new Type(BNGetFunctionType(m_func));
}


Ref<FunctionGraph> Function::CreateFunctionGraph()
{
	BNFunctionGraph* graph = BNCreateFunctionGraph(m_func);
	return new FunctionGraph(graph);
}
