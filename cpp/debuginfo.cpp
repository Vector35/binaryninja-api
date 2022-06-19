// Copyright (c) 2015-2022 Vector 35 Inc
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


#include "debuginfo.hpp"
#include "core/architecture.h"
#include "platform.hpp"
#include "type.hpp"
#include "getobject.hpp"
#include "callingconvention.hpp"
#include "datavariable.hpp"
#include "core/datavariable.h"
#include "nameandtype.hpp"

using namespace BinaryNinja;
using namespace std;


///////////////
// DebugInfo //
///////////////

DebugFunctionInfo::DebugFunctionInfo(std::string shortName, std::string fullName, std::string rawName, uint64_t address,
	Ref<Type> returnType, std::vector<std::tuple<std::string, Ref<Type>>> parameters, bool variableParameters,
	Ref<CallingConvention> callingConvention, Ref<Platform> platform) :
	shortName(shortName),
	fullName(fullName), rawName(rawName), address(address), returnType(returnType), parameters(parameters),
	variableParameters(variableParameters), callingConvention(callingConvention), platform(platform)
{}


DebugInfo::DebugInfo(BNDebugInfo* debugInfo)
{
	m_object = debugInfo;
}


vector<NameAndType> DebugInfo::GetTypes(const string& parserName)
{
	size_t count;
	BNNameAndType* nameAndTypes =
	    BNGetDebugTypes(m_object, parserName.size() == 0 ? nullptr : parserName.c_str(), &count);

	vector<NameAndType> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(nameAndTypes[i].name,
		    Confidence<Ref<Type>>(new Type(BNNewTypeReference(nameAndTypes[i].type)), nameAndTypes[i].typeConfidence));
	}

	BNFreeDebugTypes(nameAndTypes, count);
	return result;
}


vector<DebugFunctionInfo> DebugInfo::GetFunctions(const string& parserName)
{
	size_t count;
	BNDebugFunctionInfo* functions =
	    BNGetDebugFunctions(m_object, parserName.size() == 0 ? nullptr : parserName.c_str(), &count);

	vector<DebugFunctionInfo> result;
	for (size_t i = 0; i < count; ++i)
	{
		vector<tuple<string, Ref<Type>>> parameters;
		for (size_t j = 0; j < functions[i].parameterCount; ++j)
			parameters.emplace_back(
			    functions[i].parameterNames[j], new Type(BNNewTypeReference(functions[i].parameterTypes[j])));

		result.emplace_back(functions[i].shortName ? functions[i].shortName : "",
		    functions[i].fullName ? functions[i].fullName : "", functions[i].rawName ? functions[i].rawName : "",
		    functions[i].address,
		    functions[i].returnType ? new Type(BNNewTypeReference(functions[i].returnType)) : nullptr, parameters,
		    functions[i].variableParameters,
		    functions[i].callingConvention ?
                new CoreCallingConvention(BNNewCallingConventionReference(functions[i].callingConvention)) :
                nullptr,
		    functions[i].platform ? new Platform(BNNewPlatformReference(functions[i].platform)) : nullptr);
	}

	BNFreeDebugFunctions(functions, count);
	return result;
}


vector<DataVariableAndName> DebugInfo::GetDataVariables(const string& parserName)
{
	size_t count;
	BNDataVariableAndName* variableAndNames =
	    BNGetDebugDataVariables(m_object, parserName.size() == 0 ? nullptr : parserName.c_str(), &count);

	vector<DataVariableAndName> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(variableAndNames[i].address,
		    Confidence(new Type(BNNewTypeReference(variableAndNames[i].type)), variableAndNames[i].typeConfidence),
		    variableAndNames[i].autoDiscovered, variableAndNames[i].name);
	}

	BNFreeDataVariablesAndName(variableAndNames, count);
	return result;
}


bool DebugInfo::AddType(const string& name, Ref<Type> type)
{
	return BNAddDebugType(m_object, name.c_str(), type->GetObject());
}


bool DebugInfo::AddFunction(const DebugFunctionInfo& function)
{
	BNDebugFunctionInfo* input = new BNDebugFunctionInfo();

	input->shortName = function.shortName.size() ? BNAllocString(function.shortName.c_str()) : nullptr;
	input->fullName = function.fullName.size() ? BNAllocString(function.fullName.c_str()) : nullptr;
	input->rawName = function.rawName.size() ? BNAllocString(function.rawName.c_str()) : nullptr;
	input->address = function.address;
	input->returnType = function.returnType ? function.returnType->GetObject() : nullptr;
	input->variableParameters = function.variableParameters;
	input->callingConvention = function.callingConvention ? function.callingConvention->GetObject() : nullptr;
	input->platform = function.platform ? function.platform->GetObject() : nullptr;

	size_t parameterCount = function.parameters.size();
	input->parameterCount = parameterCount;
	input->parameterNames = new char*[parameterCount];
	input->parameterTypes = new BNType*[parameterCount];
	for (size_t i = 0; i < parameterCount; ++i)
	{
		input->parameterNames[i] = BNAllocString(std::get<0>(function.parameters[i]).c_str());
		input->parameterTypes[i] = std::get<1>(function.parameters[i])->GetObject();
	}

	bool result = BNAddDebugFunction(m_object, input);

	BNFreeString(input->shortName);
	BNFreeString(input->fullName);
	BNFreeString(input->rawName);

	for (size_t i = 0; i < parameterCount; ++i)
		BNFreeString(input->parameterNames[i]);

	return result;
}


bool DebugInfo::AddDataVariable(uint64_t address, Ref<Type> type, const string& name)
{
	if (name.size() == 0)
		return BNAddDebugDataVariable(m_object, address, type->GetObject(), nullptr);
	return BNAddDebugDataVariable(m_object, address, type->GetObject(), name.c_str());
}


/////////////////////
// DebugInfoParser //
/////////////////////


DebugInfoParser::DebugInfoParser(BNDebugInfoParser* parser)
{
	m_object = parser;
}


Ref<DebugInfoParser> DebugInfoParser::GetByName(const string& name)
{
	BNDebugInfoParser* parser = BNGetDebugInfoParserByName(name.c_str());
	if (parser)
		return new DebugInfoParser(BNNewDebugInfoParserReference(parser));
	return nullptr;
}


vector<Ref<DebugInfoParser>> DebugInfoParser::GetList()
{
	size_t count = 0;
	BNDebugInfoParser** parsers = BNGetDebugInfoParsers(&count);

	vector<Ref<DebugInfoParser>> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(new DebugInfoParser(BNNewDebugInfoParserReference(parsers[i])));
	}

	BNFreeDebugInfoParserList(parsers, count);
	return result;
}


vector<Ref<DebugInfoParser>> DebugInfoParser::GetListForView(const Ref<BinaryView> data)
{
	size_t count = 0;
	BNDebugInfoParser** parsers = BNGetDebugInfoParsersForView(BinaryNinja::GetView(data), &count);

	vector<Ref<DebugInfoParser>> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(new DebugInfoParser(BNNewDebugInfoParserReference(parsers[i])));
	}

	BNFreeDebugInfoParserList(parsers, count);
	return result;
}


string DebugInfoParser::GetName() const
{
	return BNGetDebugInfoParserName(m_object);
}


Ref<DebugInfo> DebugInfoParser::Parse(Ref<BinaryView> view, Ref<DebugInfo> existingDebugInfo) const
{
	if (existingDebugInfo)
		return new DebugInfo(
		    BNNewDebugInfoReference(BNParseDebugInfo(m_object, BinaryNinja::GetView(view), existingDebugInfo->GetObject())));
	return new DebugInfo(BNParseDebugInfo(m_object, BinaryNinja::GetView(view), nullptr));
}


bool DebugInfoParser::IsValidForView(const Ref<BinaryView> view) const
{
	return BNIsDebugInfoParserValidForView(m_object, BinaryNinja::GetView(view));
}


//////////////////////////////
// Plugin registration APIs //
//////////////////////////////


bool CustomDebugInfoParser::IsValidCallback(void* ctxt, BNBinaryView* view)
{
	CustomDebugInfoParser* parser = (CustomDebugInfoParser*)ctxt;
	return parser->IsValid(CreateNewView(view));
}


void CustomDebugInfoParser::ParseCallback(void* ctxt, BNDebugInfo* debugInfo, BNBinaryView* view)
{
	CustomDebugInfoParser* parser = (CustomDebugInfoParser*)ctxt;
	parser->ParseInfo(new DebugInfo(debugInfo), CreateNewView(view));
}


CustomDebugInfoParser::CustomDebugInfoParser(const string& name) :
    DebugInfoParser(
        BNNewDebugInfoParserReference(BNRegisterDebugInfoParser(name.c_str(), IsValidCallback, ParseCallback, this)))
{}
