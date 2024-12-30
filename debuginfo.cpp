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


// TODO : Documentation


#include "binaryninjaapi.h"
using namespace BinaryNinja;
using namespace std;


///////////////
// DebugInfo //
///////////////


DebugInfo::DebugInfo(BNDebugInfo* debugInfo)
{
	m_object = debugInfo;
}


vector<string> DebugInfo::GetParsers() const
{
	size_t count;
	char** parsers = BNGetDebugParserNames(m_object, &count);

	vector<string> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(parsers[i]);
	}
	BNFreeStringList(parsers, count);

	return result;
}


TypeContainer DebugInfo::GetTypeContainer(const std::string& parserName)
{
	return TypeContainer(BNGetDebugInfoTypeContainer(m_object, parserName.c_str()));
}


vector<NameAndType> DebugInfo::GetTypes(const string& parserName) const
{
	size_t count;
	BNNameAndType* nameAndTypes =
	    BNGetDebugTypes(m_object, parserName.size() == 0 ? nullptr : parserName.c_str(), &count);

	if (nameAndTypes == nullptr)
		return {};

	vector<NameAndType> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(nameAndTypes[i].name,
		    Confidence<Ref<Type>>(new Type(BNNewTypeReference(nameAndTypes[i].type)), nameAndTypes[i].typeConfidence));
	}

	BNFreeDebugTypes(nameAndTypes, count);
	return result;
}


vector<DebugFunctionInfo> DebugInfo::GetFunctions(const string& parserName) const
{
	size_t count;
	BNDebugFunctionInfo* functions =
	    BNGetDebugFunctions(m_object, parserName.size() == 0 ? nullptr : parserName.c_str(), &count);

	if (functions == nullptr)
		return {};

	vector<DebugFunctionInfo> result;
	for (size_t i = 0; i < count; ++i)
	{
		vector<string> components;
		for (size_t componentN = 0; componentN < functions[i].componentN; ++componentN)
			components.emplace_back(functions[i].components[componentN]);

		vector<VariableNameAndType> localVariables;
		for (size_t localVariableN = 0; localVariableN < functions[i].localVariableN; ++localVariableN)
		{
			auto& bnVar = functions[i].localVariables[localVariableN];

			VariableNameAndType vnt;
			vnt.var = bnVar.var;
			vnt.name = bnVar.name;
			vnt.autoDefined = bnVar.autoDefined;
			vnt.type = Confidence<Ref<Type>>(new Type(BNNewTypeReference(bnVar.type)), bnVar.typeConfidence);
			localVariables.push_back(vnt);
		}

		result.emplace_back(functions[i].shortName ? functions[i].shortName : "",
		    functions[i].fullName ? functions[i].fullName : "", functions[i].rawName ? functions[i].rawName : "",
		    functions[i].address,
		    functions[i].type ? new Type(BNNewTypeReference(functions[i].type)) : nullptr,
		    functions[i].platform ? new CorePlatform(BNNewPlatformReference(functions[i].platform)) : nullptr,
			components, localVariables);
	}

	BNFreeDebugFunctions(functions, count);
	return result;
}


vector<DataVariableAndName> DebugInfo::GetDataVariables(const string& parserName) const
{
	size_t count;
	BNDataVariableAndName* variablesAndName =
	    BNGetDebugDataVariables(m_object, parserName.size() == 0 ? nullptr : parserName.c_str(), &count);

	if (variablesAndName == nullptr)
		return {};

	vector<DataVariableAndName> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(variablesAndName[i].address,
		    Confidence(new Type(BNNewTypeReference(variablesAndName[i].type)), variablesAndName[i].typeConfidence),
		    variablesAndName[i].autoDiscovered, variablesAndName[i].name);
	}

	BNFreeDataVariablesAndName(variablesAndName, count);
	return result;
}


// May return nullptr
Ref<Type> DebugInfo::GetTypeByName(const string& parserName, const string& name) const
{
	BNType* result = BNGetDebugTypeByName(m_object, parserName.c_str(), name.c_str());
	if (result)
		return Ref<Type>(new Type(result));
	return nullptr;
}


optional<tuple<uint64_t, Ref<Type>>> DebugInfo::GetDataVariableByName(
	const string& parserName, const string& name) const
{
	BNDataVariableAndName* result = BNGetDebugDataVariableByName(m_object, parserName.c_str(), name.c_str());
	if (result)
	{
		BNFreeString(result->name);
		return {{result->address, Ref<Type>(new Type(result->type))}};
	}
	return {};
}


optional<tuple<string, Ref<Type>>> DebugInfo::GetDataVariableByAddress(
	const string& parserName, const uint64_t address) const
{
	BNDataVariableAndName* nameAndVar = BNGetDebugDataVariableByAddress(m_object, parserName.c_str(), address);
	if (nameAndVar)
	{
		const tuple<string, Ref<Type>> result = {nameAndVar->name, Ref<Type>(new Type(nameAndVar->type))};
		BNFreeString(nameAndVar->name);
		return {result};
	}
	return {};
}


// The tuple is (DebugInfoParserName, type)
vector<tuple<string, Ref<Type>>> DebugInfo::GetTypesByName(const string& name) const
{
	size_t count;
	BNNameAndType* namesAndTypes = BNGetDebugTypesByName(m_object, name.c_str(), &count);

	if (namesAndTypes == nullptr)
		return {};

	vector<tuple<string, Ref<Type>>> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(namesAndTypes[i].name, Ref<Type>(new Type(BNNewTypeReference(namesAndTypes[i].type))));
	}

	BNFreeNameAndTypeList(namesAndTypes, count);
	return result;
}


// The tuple is (DebugInfoParserName, address, type)
vector<tuple<string, uint64_t, Ref<Type>>> DebugInfo::GetDataVariablesByName(const string& name) const
{
	size_t count;
	BNDataVariableAndName* variablesAndName = BNGetDebugDataVariablesByName(m_object, name.c_str(), &count);

	if (variablesAndName == nullptr)
		return {};

	vector<tuple<string, uint64_t, Ref<Type>>> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(variablesAndName[i].name, variablesAndName[i].address,
			Ref<Type>(new Type(BNNewTypeReference(variablesAndName[i].type))));
	}

	BNFreeDataVariablesAndName(variablesAndName, count);
	return result;
}


// The tuple is (DebugInfoParserName, TypeName, type)
vector<tuple<string, string, Ref<Type>>> DebugInfo::GetDataVariablesByAddress(const uint64_t address) const
{
	size_t count;
	BNDataVariableAndNameAndDebugParser* variablesAndName = BNGetDebugDataVariablesByAddress(m_object, address, &count);

	if (variablesAndName == nullptr)
		return {};

	vector<tuple<string, string, Ref<Type>>> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.emplace_back(variablesAndName[i].parser, variablesAndName[i].name,
			Ref<Type>(new Type(BNNewTypeReference(variablesAndName[i].type))));
	}

	BNFreeDataVariableAndNameAndDebugParserList(variablesAndName, count);
	return result;
}


bool DebugInfo::RemoveParserInfo(const string& parserName)
{
	return BNRemoveDebugParserInfo(m_object, parserName.c_str());
}


bool DebugInfo::RemoveParserTypes(const string& parserName)
{
	return BNRemoveDebugParserTypes(m_object, parserName.c_str());
}


bool DebugInfo::RemoveParserFunctions(const string& parserName)
{
	return BNRemoveDebugParserFunctions(m_object, parserName.c_str());
}


bool DebugInfo::RemoveParserDataVariables(const string& parserName)
{
	return BNRemoveDebugParserDataVariables(m_object, parserName.c_str());
}


bool DebugInfo::RemoveTypeByName(const string& parserName, const string& name)
{
	return BNRemoveDebugTypeByName(m_object, parserName.c_str(), name.c_str());
}


bool DebugInfo::RemoveFunctionByIndex(const string& parserName, const size_t index)
{
	return BNRemoveDebugFunctionByIndex(m_object, parserName.c_str(), index);
}


bool DebugInfo::RemoveDataVariableByAddress(const string& parserName, const uint64_t address)
{
	return BNRemoveDebugDataVariableByAddress(m_object, parserName.c_str(), address);
}


bool DebugInfo::AddType(const string& name, Ref<Type> type, const vector<string>& components)
{
	const char** const componentArray = new const char*[components.size()];
	for (size_t i = 0; i < components.size(); ++i)
		componentArray[i] = components[i].c_str();
	bool result = BNAddDebugType(m_object, name.c_str(), type->GetObject(), componentArray, components.size());
	delete[] componentArray;
	return result;
}


bool DebugInfo::AddFunction(const DebugFunctionInfo& function)
{
	char** components = new char*[function.components.size()];
	for (size_t i = 0; i < function.components.size(); ++i)
		components[i] = (char*)function.components[i].c_str();

	BNVariableNameAndType* localVariables = new BNVariableNameAndType[function.localVariables.size()];
	for (size_t i = 0; i < function.localVariables.size(); i++)
	{
		auto v = function.localVariables[i];
		localVariables[i].var = v.var;
		localVariables[i].type = v.type.GetValue()->m_object;
		localVariables[i].typeConfidence = v.type.GetConfidence();
		localVariables[i].name = (char*)v.name.c_str();
		localVariables[i].autoDefined = v.autoDefined;
	}

	BNDebugFunctionInfo input;

	input.shortName = function.shortName.size() ? BNAllocString(function.shortName.c_str()) : nullptr;
	input.fullName = function.fullName.size() ? BNAllocString(function.fullName.c_str()) : nullptr;
	input.rawName = function.rawName.size() ? BNAllocString(function.rawName.c_str()) : nullptr;
	input.address = function.address;
	input.type = function.type ? function.type->GetObject() : nullptr;
	input.platform = function.platform ? function.platform->GetObject() : nullptr;
	input.components = components;
	input.componentN = function.components.size();
	input.localVariables = localVariables;
	input.localVariableN = function.localVariables.size();

	bool result = BNAddDebugFunction(m_object, &input);

	BNFreeString(input.shortName);
	BNFreeString(input.fullName);
	BNFreeString(input.rawName);
	delete[] components;
	delete[] localVariables;
	return result;
}


bool DebugInfo::AddDataVariable(uint64_t address, Ref<Type> type, const string& name, const vector<string>& components)
{
	const char** const componentArray = new const char*[components.size()];
	for (size_t i = 0; i < components.size(); ++i)
		componentArray[i] = components[i].c_str();
	if (name.size() == 0)
		return BNAddDebugDataVariable(m_object, address, type->GetObject(), nullptr, componentArray, components.size());
	return BNAddDebugDataVariable(m_object, address, type->GetObject(), name.c_str(), componentArray, components.size());
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
	BNDebugInfoParser** parsers = BNGetDebugInfoParsersForView(data->GetObject(), &count);

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


Ref<DebugInfo> DebugInfoParser::Parse(Ref<BinaryView> view, Ref<BinaryView> debugFile, Ref<DebugInfo> existingDebugInfo,
	std::function<bool(size_t, size_t)> progress) const
{
	ProgressContext ctxt;
	if (progress)
		ctxt.callback = progress;
	else
		ctxt.callback = [=](size_t, size_t) { return true; };

	BNDebugInfo* info = nullptr;
	if (existingDebugInfo)
	{
		info = BNParseDebugInfo(m_object, view->GetObject(), debugFile->GetObject(), existingDebugInfo->GetObject(),
			ProgressCallback, &ctxt);
		if (!info)
			return nullptr;
		info = BNNewDebugInfoReference(info);
	}
	else
	{
		info = BNParseDebugInfo(m_object, view->GetObject(), debugFile->GetObject(), nullptr, ProgressCallback, &ctxt);
		if (!info)
			return nullptr;
	}
	return new DebugInfo(info);
}


bool DebugInfoParser::IsValidForView(const Ref<BinaryView> view) const
{
	return BNIsDebugInfoParserValidForView(m_object, view->GetObject());
}


//////////////////////////////
// Plugin registration APIs //
//////////////////////////////


bool CustomDebugInfoParser::IsValidCallback(void* ctxt, BNBinaryView* view)
{
	CustomDebugInfoParser* parser = (CustomDebugInfoParser*)ctxt;
	return parser->IsValid(new BinaryView(view));
}


bool CustomDebugInfoParser::ParseCallback(void* ctxt, BNDebugInfo* debugInfo, BNBinaryView* view,
	BNBinaryView* debugFile, BNProgressFunction progress, void* progressCtxt)
{
	CustomDebugInfoParser* parser = (CustomDebugInfoParser*)ctxt;
	return parser->ParseInfo(new DebugInfo(debugInfo), new BinaryView(view), new BinaryView(debugFile),
		[=](size_t cur, size_t max) { return progress(progressCtxt, cur, max); });
}


CustomDebugInfoParser::CustomDebugInfoParser(const string& name) :
    DebugInfoParser(
        BNNewDebugInfoParserReference(BNRegisterDebugInfoParser(name.c_str(), IsValidCallback, ParseCallback, this)))
{}
