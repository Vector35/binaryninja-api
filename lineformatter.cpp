// Copyright (c) 2024 Vector 35 Inc
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

using namespace BinaryNinja;
using namespace std;


LineFormatterSettings LineFormatterSettings::GetDefault(DisassemblySettings* settings, HighLevelILFunction* func)
{
	BNLineFormatterSettings* apiObj =
		BNGetDefaultLineFormatterSettings(settings ? settings->GetObject() : nullptr, func->GetObject());
	LineFormatterSettings result = FromAPIObject(apiObj);
	BNFreeLineFormatterSettings(apiObj);
	return result;
}


LineFormatterSettings LineFormatterSettings::GetLanguageRepresentationSettings(
	DisassemblySettings* settings, LanguageRepresentationFunction* func)
{
	BNLineFormatterSettings* apiObj =
		BNGetLanguageRepresentationLineFormatterSettings(settings ? settings->GetObject() : nullptr, func->GetObject());
	LineFormatterSettings result = FromAPIObject(apiObj);
	BNFreeLineFormatterSettings(apiObj);
	return result;
}


LineFormatterSettings LineFormatterSettings::FromAPIObject(const BNLineFormatterSettings* settings)
{
	LineFormatterSettings result;
	result.highLevelIL = new HighLevelILFunction(BNNewHighLevelILFunctionReference(settings->highLevelIL));
	result.desiredLineLength = settings->desiredLineLength;
	result.minimumContentLength = settings->minimumContentLength;
	result.tabWidth = settings->tabWidth;
	result.languageName = settings->languageName;
	result.commentStartString = settings->commentStartString;
	result.commentEndString = settings->commentEndString;
	result.annotationStartString = settings->annotationStartString;
	result.annotationEndString = settings->annotationEndString;
	return result;
}


BNLineFormatterSettings LineFormatterSettings::ToAPIObject() const
{
	BNLineFormatterSettings result;
	result.highLevelIL = highLevelIL->GetObject();
	result.desiredLineLength = desiredLineLength;
	result.minimumContentLength = minimumContentLength;
	result.tabWidth = tabWidth;
	result.languageName = (char*)languageName.c_str();
	result.commentStartString = (char*)commentStartString.c_str();
	result.commentEndString = (char*)commentEndString.c_str();
	result.annotationStartString = (char*)annotationStartString.c_str();
	result.annotationEndString = (char*)annotationEndString.c_str();
	return result;
}


LineFormatter::LineFormatter(const string& name) : m_nameForRegister(name) {}


LineFormatter::LineFormatter(BNLineFormatter* formatter)
{
	m_object = formatter;
}


void LineFormatter::Register(LineFormatter* formatter)
{
	BNCustomLineFormatter cb;
	cb.context = formatter;
	cb.formatLines = FormatLinesCallback;
	cb.freeLines = FreeLinesCallback;

	formatter->AddRefForRegistration();
	formatter->m_object = BNRegisterLineFormatter(formatter->m_nameForRegister.c_str(), &cb);
}


BNDisassemblyTextLine* LineFormatter::FormatLinesCallback(void* ctxt, BNDisassemblyTextLine* inLines, size_t inCount,
	const BNLineFormatterSettings* settings, size_t* outCount)
{
	LineFormatter* formatter = (LineFormatter*)ctxt;

	vector<DisassemblyTextLine> input = ParseAPIObjectList<DisassemblyTextLine>(inLines, inCount);
	vector<DisassemblyTextLine> outLines =
		formatter->FormatLines(input, LineFormatterSettings::FromAPIObject(settings));
	return AllocAPIObjectList<DisassemblyTextLine>(outLines, outCount);
}


void LineFormatter::FreeLinesCallback(void*, BNDisassemblyTextLine* lines, size_t count)
{
	FreeAPIObjectList<DisassemblyTextLine>(lines, count);
}


vector<Ref<LineFormatter>> LineFormatter::GetList()
{
	size_t count;
	BNLineFormatter** list = BNGetLineFormatterList(&count);
	vector<Ref<LineFormatter>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreLineFormatter(list[i]));
	BNFreeLineFormatterList(list);
	return result;
}


Ref<LineFormatter> LineFormatter::GetByName(const string& name)
{
	BNLineFormatter* result = BNGetLineFormatterByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreLineFormatter(result);
}


Ref<LineFormatter> LineFormatter::GetDefault()
{
	BNLineFormatter* result = BNGetDefaultLineFormatter();
	if (!result)
		return nullptr;
	return new CoreLineFormatter(result);
}


CoreLineFormatter::CoreLineFormatter(BNLineFormatter* formatter) : LineFormatter(formatter) {}


vector<DisassemblyTextLine> CoreLineFormatter::FormatLines(
	const vector<DisassemblyTextLine>& lines, const LineFormatterSettings& settings)
{
	size_t inCount = 0;
	BNDisassemblyTextLine* inLines = AllocAPIObjectList<DisassemblyTextLine>(lines, &inCount);
	size_t outCount = 0;
	BNLineFormatterSettings apiSettings = settings.ToAPIObject();
	BNDisassemblyTextLine* outLines = BNFormatLines(m_object, inLines, inCount, &apiSettings, &outCount);

	vector<DisassemblyTextLine> result = ParseAPIObjectList<DisassemblyTextLine>(outLines, outCount);
	FreeAPIObjectList<DisassemblyTextLine>(inLines, inCount);
	BNFreeDisassemblyTextLines(outLines, outCount);
	return result;
}
