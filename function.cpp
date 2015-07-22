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


Ref<FunctionGraph> Function::CreateFunctionGraph()
{
	BNFunctionGraph* graph = BNCreateFunctionGraph(m_func);
	return new FunctionGraph(graph);
}
