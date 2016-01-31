#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


BasicBlock::BasicBlock(BNBasicBlock* block)
{
	m_object = block;
}


Ref<Function> BasicBlock::GetFunction() const
{
	return new Function(BNGetBasicBlockFunction(m_object));
}


Ref<Architecture> BasicBlock::GetArchitecture() const
{
	return new CoreArchitecture(BNGetBasicBlockArchitecture(m_object));
}


uint64_t BasicBlock::GetStart() const
{
	return BNGetBasicBlockStart(m_object);
}


uint64_t BasicBlock::GetEnd() const
{
	return BNGetBasicBlockEnd(m_object);
}


uint64_t BasicBlock::GetLength() const
{
	return BNGetBasicBlockLength(m_object);
}


vector<BasicBlockEdge> BasicBlock::GetOutgoingEdges() const
{
	size_t count;
	BNBasicBlockEdge* array = BNGetBasicBlockOutgoingEdges(m_object, &count);

	vector<BasicBlockEdge> result;
	for (size_t i = 0; i < count; i++)
	{
		BasicBlockEdge edge;
		edge.type = array[i].type;
		edge.target = array[i].target;
		edge.arch = array[i].arch ? new CoreArchitecture(array[i].arch) : nullptr;
		result.push_back(edge);
	}

	BNFreeBasicBlockOutgoingEdgeList(array);
	return result;
}


bool BasicBlock::HasUndeterminedOutgoingEdges() const
{
	return BNBasicBlockHasUndeterminedOutgoingEdges(m_object);
}


void BasicBlock::MarkRecentUse()
{
	BNMarkBasicBlockAsRecentlyUsed(m_object);
}
