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

#include "binaryninjaapi.h"
#include "ffi.h"


std::string BinaryNinja::Unicode::UTF16ToUTF8(const uint8_t* utf16, const size_t len)
{
	char* value = BNUnicodeUTF16ToUTF8(utf16, len);
	std::string result(value);
	BNFreeString(value);
	return result;
}


std::string BinaryNinja::Unicode::UTF32ToUTF8(const uint8_t* utf32)
{
	char* value = BNUnicodeUTF32ToUTF8(utf32);
	std::string result(value);
	BNFreeString(value);
	return result;
}


bool BinaryNinja::Unicode::GetBlockRange(const std::string& name, std::pair<uint32_t, uint32_t>& range)
{
	return BNUnicodeGetBlockRange(name.c_str(), &range.first, &range.second);
}


std::vector<std::vector<std::pair<uint32_t, uint32_t>>> BinaryNinja::Unicode::GetBlocksForNames(const std::vector<std::string>& names)
{
	char** nameList;
	size_t nameCount;
	AllocApiStringList(names, &nameList, &nameCount);

	uint32_t** blockStarts;
	uint32_t** blockEnds;
	size_t* blockCounts;
	size_t blockListCounts;
	BNUnicodeGetBlocksForNames(nameList, nameCount, &blockStarts, &blockEnds, &blockCounts, &blockListCounts);

	FreeApiStringList(nameList, nameCount);

	std::vector<std::vector<std::pair<uint32_t, uint32_t>>> result;
	for (size_t i = 0; i < blockListCounts; i ++)
	{
		std::vector<std::pair<uint32_t, uint32_t>> blockList;
		for (size_t j = 0; j < blockCounts[i]; j ++)
		{
			blockList.push_back(std::make_pair(blockStarts[i][j], blockEnds[i][j]));
		}
		result.push_back(std::move(blockList));
	}

	BNFreeUnicodeBlockList(blockStarts, blockEnds, blockCounts, blockListCounts);
	return result;
}


std::vector<std::string> BinaryNinja::Unicode::GetBlockNames()
{
	char** names;
	size_t count;
	BNUnicodeGetBlockNames(&names, &count);
	auto result = ParseStringList(names, count);
	BNFreeStringList(names, count);
	return result;
}


std::map<std::string, std::pair<uint32_t, uint32_t>> BinaryNinja::Unicode::GetBlockRanges()
{
	char** names;
	uint32_t* rangeStarts;
	uint32_t* rangeEnds;
	size_t count;
	BNUnicodeGetBlockRanges(&names, &rangeStarts, &rangeEnds, &count);

	std::map<std::string, std::pair<uint32_t, uint32_t>> result;
	for (size_t i = 0; i < count; i ++)
	{
		std::string name = names[i];
		result.insert({name, std::make_pair(rangeStarts[i], rangeEnds[i])});
	}

	BNFreeStringList(names, count);
	BNFreeUnicodeRangeList(rangeStarts, rangeEnds);

	return result;
}


std::string BinaryNinja::Unicode::GetUTF8String(
	const std::vector<std::vector<std::pair<uint32_t, uint32_t>>>& unicodeBlocks,
	const uint8_t* data,
	const size_t offset,
	const size_t dataLen
)
{
	std::vector<std::vector<uint32_t>> starts;
	std::vector<std::vector<uint32_t>> ends;

	for (size_t i = 0; i < unicodeBlocks.size(); i ++)
	{
		std::vector<uint32_t> blockStarts;
		std::vector<uint32_t> blockEnds;
		for (size_t j = 0; j < unicodeBlocks[i].size(); j ++)
		{
			blockStarts.push_back(unicodeBlocks[i][j].first);
			blockEnds.push_back(unicodeBlocks[i][j].second);
		}
		starts.push_back(blockStarts);
		ends.push_back(blockEnds);
	}

	std::vector<uint32_t*> startPtrs;
	std::vector<uint32_t*> endPtrs;
	std::vector<size_t> counts;
	for (size_t i = 0; i < unicodeBlocks.size(); i ++)
	{
		startPtrs.push_back(starts[i].data());
		endPtrs.push_back(ends[i].data());
		counts.push_back(starts[i].size());
	}

	char* value = BNUnicodeGetUTF8String(startPtrs.data(), endPtrs.data(), counts.data(), unicodeBlocks.size(), data, offset, dataLen);
	std::string result(value);
	BNFreeString(value);
	return result;
}


std::string BinaryNinja::Unicode::ToEscapedString(
	const std::vector<std::vector<std::pair<uint32_t, uint32_t>>>& unicodeBlocks,
	bool utf8Enabled,
	const void* data,
	const size_t dataLen
)
{
	std::vector<std::vector<uint32_t>> starts;
	std::vector<std::vector<uint32_t>> ends;

	for (size_t i = 0; i < unicodeBlocks.size(); i ++)
	{
		std::vector<uint32_t> blockStarts;
		std::vector<uint32_t> blockEnds;
		for (size_t j = 0; j < unicodeBlocks[i].size(); j ++)
		{
			blockStarts.push_back(unicodeBlocks[i][j].first);
			blockEnds.push_back(unicodeBlocks[i][j].second);
		}
		starts.push_back(blockStarts);
		ends.push_back(blockEnds);
	}

	std::vector<uint32_t*> startPtrs;
	std::vector<uint32_t*> endPtrs;
	std::vector<size_t> counts;
	for (size_t i = 0; i < unicodeBlocks.size(); i ++)
	{
		startPtrs.push_back(starts[i].data());
		endPtrs.push_back(ends[i].data());
		counts.push_back(starts[i].size());
	}

	char* value = BNUnicodeToEscapedString(startPtrs.data(), endPtrs.data(), counts.data(), unicodeBlocks.size(), utf8Enabled, data, dataLen);
	std::string result(value);
	BNFreeString(value);
	return result;
}

