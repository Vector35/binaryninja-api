#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


FunctionGraphBlock::FunctionGraphBlock(BNFunctionGraphBlock* block)
{
	m_object = block;
}


Ref<Architecture> FunctionGraphBlock::GetArchitecture() const
{
	return new CoreArchitecture(BNGetFunctionGraphBlockArchitecture(m_object));
}


uint64_t FunctionGraphBlock::GetStart() const
{
	return BNGetFunctionGraphBlockStart(m_object);
}


uint64_t FunctionGraphBlock::GetEnd() const
{
	return BNGetFunctionGraphBlockEnd(m_object);
}


int FunctionGraphBlock::GetX() const
{
	return BNGetFunctionGraphBlockX(m_object);
}


int FunctionGraphBlock::GetY() const
{
	return BNGetFunctionGraphBlockY(m_object);
}


int FunctionGraphBlock::GetWidth() const
{
	return BNGetFunctionGraphBlockWidth(m_object);
}


int FunctionGraphBlock::GetHeight() const
{
	return BNGetFunctionGraphBlockHeight(m_object);
}


vector<FunctionGraphTextLine> FunctionGraphBlock::GetLines() const
{
	size_t count;
	BNFunctionGraphTextLine* lines = BNGetFunctionGraphBlockLines(m_object, &count);

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


vector<FunctionGraphEdge> FunctionGraphBlock::GetOutgoingEdges() const
{
	size_t count;
	BNFunctionGraphEdge* edges = BNGetFunctionGraphBlockOutgoingEdges(m_object, &count);

	vector<FunctionGraphEdge> result;
	for (size_t i = 0; i < count; i++)
	{
		FunctionGraphEdge edge;
		edge.type = edges[i].type;
		edge.target = edges[i].target;
		edge.arch = edges[i].arch ? new CoreArchitecture(edges[i].arch) : nullptr;
		edge.points.insert(edge.points.begin(), &edges[i].points[0], &edges[i].points[edges[i].pointCount]);
		result.push_back(edge);
	}

	BNFreeFunctionGraphBlockOutgoingEdgeList(edges, count);
	return result;
}
