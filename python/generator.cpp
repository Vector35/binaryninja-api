// Copyright (c) 2015-2026 Vector 35 Inc
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

#include <stdio.h>
#include <inttypes.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


map<string, string> g_pythonKeywordReplacements = {
    {"False", "False_"},
    {"True", "True_"},
    {"None", "None_"},
    {"and", "and_"},
    {"as", "as_"},
    {"assert", "assert_"},
    {"async", "async_"},
    {"await", "await_"},
    {"break", "break_"},
    {"class", "class_"},
    {"continue", "continue_"},
    {"def", "def_"},
    {"del", "del_"},
    {"elif", "elif_"},
    {"else", "else_"},
    {"except", "except_"},
    {"finally", "finally_"},
    {"for", "for_"},
    {"from", "from_"},
    {"global", "global_"},
    {"if", "if_"},
    {"import", "import_"},
    {"in", "in_"},
    {"is", "is_"},
    {"lambda", "lambda_"},
    {"nonlocal", "nonlocal_"},
    {"not", "not_"},
    {"or", "or_"},
    {"pass", "pass_"},
    {"raise", "raise_"},
    {"return", "return_"},
    {"try", "try_"},
    {"while", "while_"},
    {"with", "with_"},
    {"yield", "yield_"},
};


string PythonEnumName(string name)
{
	if (name.size() > 2 && name.substr(0, 2) == "BN")
		return name.substr(2);
	return name;
}


void OutputType(FILE* out, Type* type, bool isReturnType = false, bool isCallback = false, bool isTypeHint = false)
{
	switch (type->GetClass())
	{
	case BoolTypeClass:
		fprintf(out, "ctypes.c_bool");
		break;
	case IntegerTypeClass:
		switch (type->GetWidth())
		{
		case 1:
			if (type->IsSigned())
				fprintf(out, "ctypes.c_byte");
			else
				fprintf(out, "ctypes.c_ubyte");
			break;
		case 2:
			if (type->IsSigned())
				fprintf(out, "ctypes.c_short");
			else
				fprintf(out, "ctypes.c_ushort");
			break;
		case 4:
			if (type->IsSigned())
				fprintf(out, "ctypes.c_int");
			else
				fprintf(out, "ctypes.c_uint");
			break;
		default:
			if (type->IsSigned())
				fprintf(out, "ctypes.c_longlong");
			else
				fprintf(out, "ctypes.c_ulonglong");
			break;
		}
		break;
	case FloatTypeClass:
		if (type->GetWidth() == 4)
			fprintf(out, "ctypes.c_float");
		else
			fprintf(out, "ctypes.c_double");
		break;
	case NamedTypeReferenceClass:
		if (type->GetNamedTypeReference()->GetTypeReferenceClass() == EnumNamedTypeClass)
		{
			string name = PythonEnumName(type->GetNamedTypeReference()->GetName().GetString());
			fprintf(out, "%sEnum", name.c_str());
		}
		else
		{
			fprintf(out, "%s", type->GetNamedTypeReference()->GetName().GetString().c_str());
		}
		break;
	case PointerTypeClass:
		if (isCallback || (type->GetChildType()->GetClass() == VoidTypeClass))
		{
			fprintf(out, "ctypes.c_void_p");
			break;
		}
		else if ((type->GetChildType()->GetClass() == IntegerTypeClass) && (type->GetChildType()->GetWidth() == 1)
		         && (type->GetChildType()->IsSigned()))
		{
			if (isTypeHint)
				fprintf(out, "ctypes._Pointer[ctypes.c_byte]");
			else if (isReturnType)
				fprintf(out, "ctypes.POINTER(ctypes.c_byte)");
			else
				fprintf(out, "ctypes.c_char_p");
			break;
		}
		else if (type->GetChildType()->GetClass() == FunctionTypeClass)
		{
			if (isTypeHint)
				fprintf(out, "ctypes.CFUNCTYPE[");
			else
				fprintf(out, "ctypes.CFUNCTYPE(");
			OutputType(out, type->GetChildType()->GetChildType().GetValue(), true, true, isTypeHint);
			for (auto& i : type->GetChildType()->GetParameters())
			{
				fprintf(out, ", ");
				OutputType(out, i.type.GetValue(), false, false, isTypeHint);
			}

			if (isTypeHint)
				fprintf(out, "]");
			else
				fprintf(out, ")");
			break;
		}
		if (isTypeHint)
			fprintf(out, "ctypes._Pointer[");
		else
			fprintf(out, "ctypes.POINTER(");

		OutputType(out, type->GetChildType().GetValue(), false, false, isTypeHint);

		if (isTypeHint)
			fprintf(out, "]");
		else
			fprintf(out, ")");
		break;
	case ArrayTypeClass:
		OutputType(out, type->GetChildType().GetValue(), false, false, isTypeHint);
		fprintf(out, " * %" PRId64, type->GetElementCount());
		break;
	default:
		fprintf(out, "None");
		break;
	}
}


void OutputSwizzledType(FILE* out, Type* type, bool isTypeHint = false)
{
	switch (type->GetClass())
	{
	case BoolTypeClass:
		fprintf(out, "bool");
		break;
	case IntegerTypeClass:
		fprintf(out, "int");
		break;
	case FloatTypeClass:
		fprintf(out, "float");
		break;
	case NamedTypeReferenceClass:
		if (type->GetNamedTypeReference()->GetTypeReferenceClass() == EnumNamedTypeClass)
		{
			string name = PythonEnumName(type->GetNamedTypeReference()->GetName().GetString());
			fprintf(out, "%s", name.c_str());
		}
		else
		{
			fprintf(out, "%s", type->GetNamedTypeReference()->GetName().GetString().c_str());
		}
		break;
	case PointerTypeClass:
		if (type->GetChildType()->GetClass() == VoidTypeClass)
		{
			fprintf(out, "Optional[ctypes.c_void_p]");
			break;
		}
		else if ((type->GetChildType()->GetClass() == IntegerTypeClass) && (type->GetChildType()->GetWidth() == 1)
		         && (type->GetChildType()->IsSigned()))
		{
			fprintf(out, "Optional[str]");
			break;
		}
		else if (type->GetChildType()->GetClass() == FunctionTypeClass)
		{
			if (isTypeHint)
				fprintf(out, "ctypes.CFUNCTYPE[");
			else
				fprintf(out, "ctypes.CFUNCTYPE(");
			OutputType(out, type->GetChildType()->GetChildType().GetValue(), true, true, isTypeHint);
			for (auto& i : type->GetChildType()->GetParameters())
			{
				fprintf(out, ", ");
				OutputType(out, i.type.GetValue(), false, false, isTypeHint);
			}
			if (isTypeHint)
				fprintf(out, "]");
			else
				fprintf(out, ")");

			break;
		}
		if (isTypeHint)
			fprintf(out, "ctypes._Pointer[");
		else
			fprintf(out, "ctypes.POINTER(");
		OutputType(out, type->GetChildType().GetValue(), false, false, isTypeHint);
		if (isTypeHint)
			fprintf(out, "]");
		else
			fprintf(out, ")");
		break;
	case ArrayTypeClass:
		OutputType(out, type->GetChildType().GetValue(), false, false, isTypeHint);
		fprintf(out, " * %" PRId64, type->GetElementCount());
		break;
	default:
		fprintf(out, "None");
		break;
	}
}


void CollectNamedTypeReferences(Type* type, set<QualifiedName>& names)
{
	switch (type->GetClass())
	{
	case NamedTypeReferenceClass:
		names.insert(type->GetNamedTypeReference()->GetName());
		break;
	case PointerTypeClass:
	case ArrayTypeClass:
		CollectNamedTypeReferences(type->GetChildType().GetValue(), names);
		break;
	case FunctionTypeClass:
		CollectNamedTypeReferences(type->GetChildType().GetValue(), names);
		for (auto& param : type->GetParameters())
			CollectNamedTypeReferences(param.type.GetValue(), names);
		break;
	case StructureTypeClass:
		for (auto& member : type->GetStructure()->GetMembers())
			CollectNamedTypeReferences(member.type.GetValue(), names);
		break;
	default:
		break;
	}
}


// Returns the names the core bindings define for the core type `name`.
vector<string> CoreBindingNames(const string& name, Type* type)
{
	switch (type->GetClass())
	{
	case StructureTypeClass:
	case NamedTypeReferenceClass:
		return {name, name + "Handle"};
	case EnumerationTypeClass:
		return {PythonEnumName(name) + "Enum"};
	case BoolTypeClass:
	case IntegerTypeClass:
	case FloatTypeClass:
	case ArrayTypeClass:
		return {name};
	case PointerTypeClass:
		if (type->GetChildType()->GetClass() == FunctionTypeClass)
			return {name};
		return {};
	default:
		return {};
	}
}


static const string g_templateBindingsMarker = "# @@GENERATED_BINDINGS@@";


bool ReadTemplate(const char* path, string& prologue, string& epilogue)
{
	ifstream file(path, ios::binary);
	if (!file)
		return false;

	string contents((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
	size_t marker = contents.find(g_templateBindingsMarker);
	if (marker == string::npos)
	{
		prologue = std::move(contents);
		epilogue.clear();
		return true;
	}

	size_t lineEnd = contents.find('\n', marker);
	prologue = contents.substr(0, marker);
	epilogue = lineEnd == string::npos ? string() : contents.substr(lineEnd + 1);
	return true;
}


int main(int argc, char* argv[])
{
	const char* usage = "Usage: generator <header> <output> <template> <output_enum> [--core-header <core_header>]\n";
	if (argc < 5)
	{
		fprintf(stderr, "%s", usage);
		return 1;
	}

	const char* coreHeader = nullptr;
	for (int i = 5; i < argc; i++)
	{
		if (string(argv[i]) == "--core-header" && i + 1 < argc)
		{
			coreHeader = argv[++i];
			continue;
		}

		fprintf(stderr, "%s", usage);
		return 1;
	}

	string prologue, epilogue;
	if (!ReadTemplate(argv[3], prologue, epilogue))
	{
		fprintf(stderr, "Failed to read template %s\n", argv[3]);
		return 1;
	}

	// Parse API header to get type and function information
	map<QualifiedName, Ref<Type>> types, vars, funcs;
	string errors;
	auto arch = new CoreArchitecture(BNGetNativeTypeParserArchitecture());

	// Enable ephemeral settings
	Settings::Instance()->LoadSettingsFile("");
	Settings::Instance()->Set("analysis.types.parserName", "ClangTypeParser");
	Ref<Platform> platform = arch->GetStandalonePlatform();
	vector<string> includeDirs;
	if (coreHeader)
		includeDirs.push_back(filesystem::path(coreHeader).parent_path().string());
	bool ok = platform->ParseTypesFromSourceFile(argv[1], types, vars, funcs, errors, includeDirs);

	if (!ok) {
		fprintf(stderr, "Errors: %s\n", errors.c_str());
		return 1;
	}

	map<QualifiedName, Ref<Type>> coreTypes;
	if (coreHeader)
	{
		map<QualifiedName, Ref<Type>> coreVars, coreFuncs;
		if (!platform->ParseTypesFromSourceFile(coreHeader, coreTypes, coreVars, coreFuncs, errors))
		{
			fprintf(stderr, "Errors: %s\n", errors.c_str());
			return 1;
		}

		erase_if(types, [&](const auto& i) { return coreTypes.count(i.first) != 0; });
		erase_if(funcs, [&](const auto& i) { return coreFuncs.count(i.first) != 0; });
	}

	FILE* out = fopen(argv[2], "w");
	FILE* enums = fopen(argv[4], "w");

	fprintf(enums, "import enum\n");

	fputs(prologue.c_str(), out);

	if (coreHeader)
	{
		set<QualifiedName> referencedTypes;
		for (auto& i : types)
			CollectNamedTypeReferences(i.second, referencedTypes);
		for (auto& i : funcs)
			CollectNamedTypeReferences(i.second, referencedTypes);

		fprintf(out, "# Core definitions\n");
		fprintf(out, "from binaryninja._binaryninjacore import BNFreeString\n");
		for (auto& name : referencedTypes)
		{
			auto coreType = coreTypes.find(name);
			if (coreType == coreTypes.end() || name.size() != 1)
				continue;

			for (auto& bindingName : CoreBindingNames(name[0], coreType->second))
				fprintf(out, "from binaryninja._binaryninjacore import %s\n", bindingName.c_str());
			if (coreType->second->GetClass() == EnumerationTypeClass)
				fprintf(enums, "from binaryninja.enums import %s\n", PythonEnumName(name[0]).c_str());
		}
		fprintf(out, "\n");
	}

	// Create type objects
	fprintf(out, "# Type definitions\n");
	for (auto& i : types)
	{
		string name;
		if (i.first.size() != 1)
			continue;
		name = i.first[0];
		if (i.second->GetClass() == StructureTypeClass)
		{
			fprintf(out, "class %s(ctypes.Structure):\n", name.c_str());

			// python uses str's, C uses byte-arrays
			bool stringField = false;
			for (auto& arg : i.second->GetStructure()->GetMembers())
			{
				if ((arg.type->GetClass() == PointerTypeClass) && (arg.type->GetChildType()->GetWidth() == 1)
				    && (arg.type->GetChildType()->IsSigned()))
				{
					fprintf(out, "\t@property\n\tdef %s(self):\n\t\treturn pyNativeStr(self._%s)\n", arg.name.c_str(),
					    arg.name.c_str());
					fprintf(out, "\t@%s.setter\n\tdef %s(self, value):\n\t\tself._%s = cstr(value)\n", arg.name.c_str(),
					    arg.name.c_str(), arg.name.c_str());
					stringField = true;
				}
			}

			if (!stringField)
				fprintf(out, "\tpass\n");

			fprintf(out, "\n\n%sHandle = ctypes.POINTER(%s)\n\n\n", name.c_str(), name.c_str());
		}
		else if (i.second->GetClass() == EnumerationTypeClass)
		{
			name = PythonEnumName(name);

			const char* ctypesType = nullptr;
			switch (i.second->GetWidth())
			{
			case 1:
				ctypesType = i.second->IsSigned() ? "ctypes.c_int8" : "ctypes.c_uint8";
				break;
			case 2:
				ctypesType = i.second->IsSigned() ? "ctypes.c_int16" : "ctypes.c_uint16";
				break;
			case 4:
				ctypesType = i.second->IsSigned() ? "ctypes.c_int32" : "ctypes.c_uint32";
				break;
			default:
				ctypesType = i.second->IsSigned() ? "ctypes.c_int64" : "ctypes.c_uint64";
				break;
			}
			fprintf(out, "%sEnum = %s\n", name.c_str(), ctypesType);

			if (i.second->GetAttribute("options").has_value())
				fprintf(enums, "\n\nclass %s(enum.IntFlag):\n", name.c_str());
			else
				fprintf(enums, "\n\nclass %s(enum.IntEnum):\n", name.c_str());

			for (auto& j : i.second->GetEnumeration()->GetMembers())
			{
				if (i.second->IsSigned())
				{
					fprintf(enums, "\t%s = %" PRId64 "\n", j.name.c_str(), (int64_t)BNSignExtend(j.value, i.second->GetWidth(), 8));
				}
				else
				{
					fprintf(enums, "\t%s = %" PRIu64 "\n", j.name.c_str(), j.value);
				}
			}
		}
		else if ((i.second->GetClass() == BoolTypeClass) || (i.second->GetClass() == IntegerTypeClass)
		         || (i.second->GetClass() == FloatTypeClass) || (i.second->GetClass() == ArrayTypeClass))
		{
			fprintf(out, "%s = ", name.c_str());
			OutputType(out, i.second);
			fprintf(out, "\n");
		}
	}

	// Function pointer types can refer to structure handles, so they follow the structure declarations.
	fprintf(out, "\n# Function pointer definitions\n");
	for (auto& i : types)
	{
		if (i.first.size() != 1)
			continue;
		if (i.second->GetClass() != PointerTypeClass || i.second->GetChildType()->GetClass() != FunctionTypeClass)
			continue;
		fprintf(out, "%s = ", i.first[0].c_str());
		OutputType(out, i.second);
		fprintf(out, "\n");
	}

	fprintf(out, "\n# Structure definitions\n");
	set<QualifiedName> structsToProcess;
	set<QualifiedName> finishedStructs;
	// Only structures and aliases are defined by this loop. Any other type, including a core type, is already defined.
	auto isIncomplete = [&](const QualifiedName& name) {
		auto type = types.find(name);
		if (type == types.end() || finishedStructs.count(name) != 0)
			return false;
		if (type->second->GetClass() == NamedTypeReferenceClass)
			return true;
		return type->second->GetClass() == StructureTypeClass && !type->second->GetStructure()->GetMembers().empty();
	};
	for (auto& i : types)
		structsToProcess.insert(i.first);
	while (structsToProcess.size() != 0)
	{
		set<QualifiedName> currentStructList = structsToProcess;
		structsToProcess.clear();
		bool processedSome = false;
		for (auto& i : currentStructList)
		{
			string name;
			if (i.size() != 1)
				continue;
			Ref<Type> type = types[i];
			name = i[0];
			if ((type->GetClass() == StructureTypeClass) && (type->GetStructure()->GetMembers().size() != 0))
			{
				bool requiresDependency = false;
				for (auto& j : type->GetStructure()->GetMembers())
				{
					if ((j.type->GetClass() == NamedTypeReferenceClass)
					    && isIncomplete(j.type->GetNamedTypeReference()->GetName()))
					{
						// This structure needs another structure that isn't fully defined yet, need to wait
						// for the dependencies to be defined
						structsToProcess.insert(i);
						requiresDependency = true;
						break;
					}
				}

				if (requiresDependency)
					continue;
				fprintf(out, "%s._fields_ = [\n", name.c_str());
				for (auto& j : type->GetStructure()->GetMembers())
				{
					// To help the python->C wrappers
					if ((j.type->GetClass() == PointerTypeClass) && (j.type->GetChildType()->GetWidth() == 1)
					    && (j.type->GetChildType()->IsSigned()))
					{
						fprintf(out, "\t\t(\"_%s\", ", j.name.c_str());
					}
					else
						fprintf(out, "\t\t(\"%s\", ", j.name.c_str());
					OutputType(out, j.type.GetValue());
					fprintf(out, "),\n");
				}
				fprintf(out, "\t]\n");
				finishedStructs.insert(i);
				processedSome = true;
			}
			else if (type->GetClass() == NamedTypeReferenceClass)
			{
				if (isIncomplete(type->GetNamedTypeReference()->GetName()))
				{
					structsToProcess.insert(i);
					continue;
				}

				fprintf(out, "%s = %s\n", name.c_str(), type->GetNamedTypeReference()->GetName().GetString().c_str());
				fprintf(out, "%sHandle = %sHandle\n", name.c_str(),
				    type->GetNamedTypeReference()->GetName().GetString().c_str());
				finishedStructs.insert(i);
				processedSome = true;
			}
		}

		if (!processedSome && !structsToProcess.empty())
		{
			fprintf(stderr, "Detected dependency cycle in structures\n");
			for (auto& i : structsToProcess)
				fprintf(stderr, "%s\n", i.GetString().c_str());
			return 1;
		}
	}

	fprintf(out, "\n# Function definitions\n");
	for (auto& i : funcs)
	{
		string name;
		if (i.first.size() != 1)
			continue;
		name = i.first[0];

		// Check for a string result, these will be automatically wrapped to free the string
		// memory and return a Python string
		bool stringResult = i.second->GetChildType()->GetClass() == PointerTypeClass
		                    && i.second->GetChildType()->GetChildType()->GetClass() == IntegerTypeClass
		                    && i.second->GetChildType()->GetChildType()->GetWidth() == 1
		                    && i.second->GetChildType()->GetChildType()->IsSigned();
		// Pointer returns will be automatically wrapped to return None on null pointer
		bool pointerResult = (i.second->GetChildType()->GetClass() == PointerTypeClass);
		// Enum returns will automatically cast to the enum type
		bool enumResult = (i.second->GetChildType()->GetClass() == NamedTypeReferenceClass
		                   && i.second->GetChildType()->GetNamedTypeReference()->GetTypeReferenceClass() == EnumNamedTypeClass);

		// From python -> C python3 requires str -> str.encode('charmap')
		bool swizzleArgs = true;
		if (name == "BNFreeString" || name == "BNFreeParseError")
			swizzleArgs = false;

		bool callbackConvention = false;
		if (name == "BNAllocString")
		{
			// Don't perform automatic wrapping of string allocation, and return a void
			// pointer so that callback functions (which is the only valid use of BNAllocString)
			// can properly return the result
			stringResult = false;
			callbackConvention = true;
		}

		string funcName = string("_") + name;

		fprintf(out, "# -------------------------------------------------------\n");
		fprintf(out, "# %s\n\n", funcName.c_str());
		fprintf(out, "%s = core.%s\n", funcName.c_str(), name.c_str());
		fprintf(out, "%s.restype = ", funcName.c_str());
		OutputType(out, i.second->GetChildType().GetValue(), true, callbackConvention);
		fprintf(out, "\n");
		if (!i.second->HasVariableArguments())
		{
			fprintf(out, "%s.argtypes = [\n", funcName.c_str());
			for (auto& j : i.second->GetParameters())
			{
				fprintf(out, "\t\t");
				if (name == "BNFreeString" || name == "BNFreeParseError")
				{
					// These expect a pointer to a string allocated by the core, so do not use
					// a c_char_p here, as that would be allocated by the Python runtime.  This can
					// be enforced by outputting like a return value.
					OutputType(out, j.type.GetValue(), true);
				}
				else
				{
					OutputType(out, j.type.GetValue());
				}
				fprintf(out, ",\n");
			}
			fprintf(out, "\t]");
		}
		else
		{
			// As of writing this, only BNLog's have variable instruction lengths, but in an attempt not to break in the
			// future:
			if (funcName.compare(0, 6, "_BNLog") == 0)
			{
				if (funcName != "_BNLog")
				{
					fprintf(out, "def %s(*args):\n", name.c_str());
					fprintf(out, "\treturn %s(*[cstr(arg) for arg in args])\n\n", funcName.c_str());
					continue;
				}
				else
				{
					fprintf(out, "def %s(level, *args):\n", name.c_str());
					fprintf(out, "\treturn %s(level, *[cstr(arg) for arg in args])\n\n", funcName.c_str());
					continue;
				}
			}
		}
		fprintf(out, "\n\n\n# noinspection PyPep8Naming\n");
		fprintf(out, "def %s(", name.c_str());
		if (!i.second->HasVariableArguments())
		{
			size_t argN = 0;
			for (auto& arg : i.second->GetParameters())
			{
				string argName = arg.name;
				if (g_pythonKeywordReplacements.find(argName) != g_pythonKeywordReplacements.end())
					argName = g_pythonKeywordReplacements[argName];

				if (argName.empty())
					argName = "arg" + to_string(argN);

				if (argN > 0)
					fprintf(out, ", ");
				fprintf(out, "\n\t\t");
				fprintf(out, "%s: '", argName.c_str());
				if (swizzleArgs)
					OutputSwizzledType(out, arg.type.GetValue(), true);
				else
					OutputType(out, arg.type.GetValue(), false, false, true);
				fprintf(out, "'");
				argN++;
			}
		}
		fprintf(out, "\n\t\t) -> ");
		if (stringResult || pointerResult)
			fprintf(out, "Optional['");
		OutputSwizzledType(out, i.second->GetChildType().GetValue(), true);
		if (stringResult || pointerResult)
			fprintf(out, "']");
		fprintf(out, ":\n");

		string stringArgFuncCall = funcName + "(";
		size_t argN = 0;
		for (auto& arg : i.second->GetParameters())
		{
			string argName = arg.name;
			if (g_pythonKeywordReplacements.find(argName) != g_pythonKeywordReplacements.end())
				argName = g_pythonKeywordReplacements[argName];

			if (argName.empty())
				argName = "arg" + to_string(argN);

			if (swizzleArgs && (arg.type->GetClass() == PointerTypeClass)
			    && (arg.type->GetChildType()->GetClass() == IntegerTypeClass)
			    && (arg.type->GetChildType()->GetWidth() == 1) && (arg.type->GetChildType()->IsSigned()))
			{
				stringArgFuncCall += string("cstr(") + argName + "), ";
			}
			else
			{
				stringArgFuncCall += argName + ", ";
			}
			argN++;
		}
		if (argN > 0)
			stringArgFuncCall = stringArgFuncCall.substr(0, stringArgFuncCall.size() - 2);
		stringArgFuncCall += ")";

		if (stringResult)
		{
			// Emit wrapper to get Python string and free native memory
			fprintf(out, "\tresult = ");
			fprintf(out, "%s\n", stringArgFuncCall.c_str());
			fprintf(out, "\tcasted = ctypes.cast(result, ctypes.c_char_p).value\n");
			fprintf(out, "\tif casted is None:\n");
			fprintf(out, "\t\treturn None\n");
			fprintf(out, "\tstring = str(pyNativeStr(casted))\n");
			fprintf(out, "\tBNFreeString(result)\n");
			fprintf(out, "\treturn string\n");
		}
		else if (pointerResult)
		{
			// Emit wrapper to return None on null pointer
			fprintf(out, "\tresult = ");
			fprintf(out, "%s\n", stringArgFuncCall.c_str());
			fprintf(out, "\tif not result:\n");
			fprintf(out, "\t\treturn None\n");
			fprintf(out, "\treturn result\n");
		}
		else if (enumResult)
		{
			// Emit wrapper to cast result to enum type
			fprintf(out, "\treturn ");
			OutputSwizzledType(out, i.second->GetChildType().GetValue());
			fprintf(out, "(%s)", stringArgFuncCall.c_str());
		}
		else
		{
			fprintf(out, "\treturn ");
			fprintf(out, "%s\n", stringArgFuncCall.c_str());
		}
		fprintf(out, "\n\n");
	}

	fprintf(out, "\n# Helper functions\n");
	fprintf(out, "def handle_of_type(value, handle_type):\n");
	fprintf(out, "\tif isinstance(value, ctypes.POINTER(handle_type)) or isinstance(value, ctypes.c_void_p):\n");
	fprintf(out, "\t\treturn ctypes.cast(value, ctypes.POINTER(handle_type))\n");
	fprintf(out, "\traise ValueError('expected pointer to %%s' %% str(handle_type))\n");

	fputs(epilogue.c_str(), out);

	fclose(out);
	fclose(enums);
	return 0;
}
