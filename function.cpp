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
