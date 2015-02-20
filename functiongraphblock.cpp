#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


FunctionGraphBlock::FunctionGraphBlock(BNFunctionGraphBlock* block): m_block(block)
{
}


FunctionGraphBlock::~FunctionGraphBlock()
{
	BNFreeFunctionGraphBlock(m_block);
}


int FunctionGraphBlock::GetX() const
{
	return BNGetFunctionGraphBlockX(m_block);
}


int FunctionGraphBlock::GetY() const
{
	return BNGetFunctionGraphBlockY(m_block);
}


int FunctionGraphBlock::GetWidth() const
{
	return BNGetFunctionGraphBlockWidth(m_block);
}


int FunctionGraphBlock::GetHeight() const
{
	return BNGetFunctionGraphBlockHeight(m_block);
}


vector<FunctionGraphTextLine> FunctionGraphBlock::GetLines() const
{
	size_t count;
	BNFunctionGraphTextLine* lines = BNGetFunctionGraphBlockLines(m_block, &count);

	vector<FunctionGraphTextLine> result;
	for (size_t i = 0; i < count; i++)
	{
		FunctionGraphTextLine line;
		line.addr = lines[i].addr;
		for (size_t j = 0; j < lines[i].count; j++)
		{
			InstructionTextToken token;
			token.type = lines[i].tokens[j].type;
			token.text = lines[i].tokens[j].text;
			token.value = lines[i].tokens[j].value;
			line.tokens.push_back(token);
		}
		result.push_back(line);
	}

	BNFreeFunctionGraphBlockLines(lines, count);
	return result;
}


vector<BNBasicBlockEdge> FunctionGraphBlock::GetOutgoingEdges() const
{
	size_t count;
	BNBasicBlockEdge* edges = BNGetFunctionGraphBlockOutgoingEdges(m_block, &count);

	vector<BNBasicBlockEdge> result;
	result.insert(result.begin(), &edges[0], &edges[count]);

	BNFreeFunctionGraphBlockOutgoingEdgeList(edges);
	return result;
}
