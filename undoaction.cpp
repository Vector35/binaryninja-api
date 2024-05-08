// Copyright (c) 2015-2024 Vector 35 Inc
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
#include <cstring>
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace Json;
using namespace std;


UndoAction::UndoAction(BNUndoAction* action)
{
	m_object = action;
}


std::string UndoAction::GetSummaryText()
{
	char* summary = BNUndoActionGetSummaryText(m_object);
	std::string result = summary;
	BNFreeString(summary);
	return result;
}


vector<InstructionTextToken> UndoAction::GetSummary()
{
	size_t count = 0;
	BNInstructionTextToken* result = BNUndoActionGetSummary(m_object, &count);
	vector<InstructionTextToken> newTokens;
	return InstructionTextToken::ConvertAndFreeInstructionTextTokenList(result, count);
}


UndoEntry::UndoEntry(BNUndoEntry* entry)
{
	m_object = entry;
}


std::string UndoEntry::GetId()
{
	char* id = BNUndoEntryGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


std::vector<Ref<UndoAction>> UndoEntry::GetActions()
{
	size_t count;

	BNUndoAction** actions = BNUndoEntryGetActions(m_object, &count);
	std::vector<Ref<UndoAction>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new UndoAction(BNNewUndoActionReference(actions[i])));
	}

	BNFreeUndoActionList(actions, count);
	return result;
}


uint64_t UndoEntry::GetTimestamp()
{
	return BNUndoEntryGetTimestamp(m_object);
}
