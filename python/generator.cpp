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

#include <stdio.h>
#include <inttypes.h>
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


void OutputType(FILE* out, Type* type, bool isReturnType = false, bool isCallback = false)
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
			string name = type->GetNamedTypeReference()->GetName().GetString();
			if (name.size() > 2 && name.substr(0, 2) == "BN")
				name = name.substr(2);
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
			if (isReturnType)
				fprintf(out, "ctypes.POINTER(ctypes.c_byte)");
			else
				fprintf(out, "ctypes.c_char_p");
			break;
		}
		else if (type->GetChildType()->GetClass() == FunctionTypeClass)
		{
			fprintf(out, "ctypes.CFUNCTYPE(");
			OutputType(out, type->GetChildType()->GetChildType(), true, true);
			for (auto& i : type->GetChildType()->GetParameters())
			{
				fprintf(out, ", ");
				OutputType(out, i.type);
			}
			fprintf(out, ")");
			break;
		}
		fprintf(out, "ctypes.POINTER(");
		OutputType(out, type->GetChildType());
		fprintf(out, ")");
		break;
	case ArrayTypeClass:
		OutputType(out, type->GetChildType());
		fprintf(out, " * %" PRId64, type->GetElementCount());
		break;
	default:
		fprintf(out, "None");
		break;
	}
}


void OutputSwizzledType(FILE* out, Type* type, bool outputCType = false)
{
	switch (type->GetClass())
	{
	case BoolTypeClass:
			fprintf(out, outputCType ? "ctypes.c_bool": "bool");
		break;
	case IntegerTypeClass:
		if (!outputCType)
		{
			fprintf(out, "int");
		}
		else
		{
			std::string formattedInt = "ctypes.c_";
			if (!type->IsSigned())
				formattedInt += "u";
			formattedInt += "int";
			formattedInt += std::to_string(type->GetWidth()*8);
			fprintf(out, formattedInt.c_str());
		}
		break;
	case FloatTypeClass:
		fprintf(out, outputCType ? "ctypes.c_float" : "float");
		break;
	case NamedTypeReferenceClass:
		if (type->GetNamedTypeReference()->GetTypeReferenceClass() == EnumNamedTypeClass)
		{
			string name = type->GetNamedTypeReference()->GetName().GetString();
			if (name.size() > 2 && name.substr(0, 2) == "BN")
				name = name.substr(2);
			fprintf(out, "%sEnum", name.c_str());
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
			fprintf(out, outputCType ? "ctypes.c_char_p" : "str");
			break;
		}
		else if (type->GetChildType()->GetClass() == FunctionTypeClass)
		{
			fprintf(out, "Callable[[");
			for (auto& i : type->GetChildType()->GetParameters())
			{
				OutputSwizzledType(out, i.type);
				fprintf(out, ", ");
			}
			fprintf(out, "], ");
			OutputType(out, type->GetChildType()->GetChildType(), true, true);
			fprintf(out, "]");
			break;
		}
		fprintf(out, "ctypes.pointer[");
		OutputSwizzledType(out, type->GetChildType(), true);
		fprintf(out, "]");
		break;
	case ArrayTypeClass:
		OutputSwizzledType(out, type->GetChildType());
		fprintf(out, " * %" PRId64, type->GetElementCount());
		break;
	default:
		fprintf(out, "None");
		break;
	}
}


int main(int argc, char* argv[])
{
	if (argc < 4)
	{
		fprintf(stderr, "Usage: generator <header> <output> <output_enum>\n");
		return 1;
	}

	// Parse API header to get type and function information
	map<QualifiedName, Ref<Type>> types, vars, funcs;
	string errors;
	auto arch = new CoreArchitecture(BNGetNativeTypeParserArchitecture());

	string oldParser;
	if (Settings::Instance()->Contains("analysis.types.parserNamer"))
		oldParser = Settings::Instance()->Get<string>("analysis.types.parserNamer");
	Settings::Instance()->Set("analysis.types.parserName", "CoreTypeParser");

	bool ok = arch->GetStandalonePlatform()->ParseTypesFromSourceFile(argv[1], types, vars, funcs, errors);

	if (!oldParser.empty())
		Settings::Instance()->Set("analysis.types.parserName", oldParser);
	else
		Settings::Instance()->Reset("analysis.types.parserName");

	if (!errors.empty())
		fprintf(stderr, "Errors: %s\n", errors.c_str());

	if (!ok)
		return 1;

	string outFileName = argv[2];
	string typeStubFileName = outFileName + "i";
	printf("Type stubs: %s\n", typeStubFileName.c_str());
	FILE* out = fopen(outFileName.c_str(), "w");
	FILE* enums = fopen(argv[3], "w");
	FILE* typeStubFile = fopen(typeStubFileName.c_str(), "w");


	fprintf(out, "import ctypes, os\n\n");
	fprintf(out, "from typing import Optional, AnyStr, Callable");
	fprintf(enums, "import enum");
	fprintf(typeStubFile, "import ctypes\n");
	fprintf(typeStubFile, "from typing import Optional, Callable\n\n");

	fprintf(out, "# Load core module\n");
	fprintf(out, "import platform\n");
	fprintf(out, "core = None\n");
	fprintf(out, "_base_path = None\n");
	fprintf(out, "core_platform = platform.system()\n");
	fprintf(out, "if core_platform == \"Darwin\":\n");
	fprintf(out, "\t_base_path = os.path.join(os.path.dirname(__file__), \"..\", \"..\", \"..\", \"MacOS\")\n");
	fprintf(out, "\tcore = ctypes.CDLL(os.path.join(_base_path, \"libbinaryninjacore.dylib\"))\n\n");
	fprintf(out, "elif core_platform == \"Linux\":\n");
	fprintf(out, "\t_base_path = os.path.join(os.path.dirname(__file__), \"..\", \"..\")\n");
	fprintf(out, "\tcore = ctypes.CDLL(os.path.join(_base_path, \"libbinaryninjacore.so.1\"))\n\n");
	fprintf(out, "elif (core_platform == \"Windows\") or (core_platform.find(\"CYGWIN_NT\") == 0):\n");
	fprintf(out, "\t_base_path = os.path.join(os.path.dirname(__file__), \"..\", \"..\")\n");
	fprintf(out, "\tcore = ctypes.CDLL(os.path.join(_base_path, \"binaryninjacore.dll\"))\n");
	fprintf(out, "else:\n");
	fprintf(out, "\traise Exception(\"OS not supported\")\n\n\n");

	fprintf(out, "def cstr(var: Optional[AnyStr]) -> Optional[bytes]:\n");
	fprintf(out, "	if var is None:\n");
	fprintf(out, "		return None\n");
	fprintf(out, "	if isinstance(var, bytes):\n");
	fprintf(out, "		return var\n");
	fprintf(out, "	return var.encode(\"utf-8\")\n\n\n");

	fprintf(out, "def pyNativeStr(arg: Optional[AnyStr]) -> str:\n");
	fprintf(out, "	if arg is None:\n");
	fprintf(out, "		return ''\n");
	fprintf(out, "	if isinstance(arg, str):\n");
	fprintf(out, "		return arg\n");
	fprintf(out, "	else:\n");
	fprintf(out, "		return arg.decode('utf8')\n\n\n");

	fprintf(out, "def free_string(value:ctypes.c_char_p) -> None:\n");
	fprintf(out, "	BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))\n\n");

	// Create type objects
	fprintf(out, "# Type definitions\n");
	fprintf(typeStubFile, "# Type definitions\n");
	for (auto& i : types)
	{
		string name;
		if (i.first.size() != 1)
			continue;
		name = i.first[0];
		if (i.second->GetClass() == StructureTypeClass)
		{
			fprintf(typeStubFile, "class %s(ctypes.Structure): ...\n", name.c_str());

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
			if (name.size() > 2 && name.substr(0, 2) == "BN")
				name = name.substr(2);

			fprintf(typeStubFile, "%sEnum = ctypes.c_int\n", name.c_str());
			fprintf(out, "%sEnum = ctypes.c_int\n", name.c_str());

			fprintf(enums, "\n\nclass %s(enum.IntEnum):\n", name.c_str());
			for (auto& j : i.second->GetEnumeration()->GetMembers())
			{
				fprintf(enums, "\t%s = %" PRId64 "\n", j.name.c_str(), j.value);
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

	fprintf(out, "\n# Structure definitions\n");
	set<QualifiedName> structsToProcess;
	set<QualifiedName> finishedStructs;
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
					    && (types[j.type->GetNamedTypeReference()->GetName()]->GetClass() == StructureTypeClass)
					    && (finishedStructs.count(j.type->GetNamedTypeReference()->GetName()) == 0))
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
					OutputType(out, j.type);
					fprintf(out, "),\n");
				}
				fprintf(out, "\t]\n");
				finishedStructs.insert(i);
				processedSome = true;
			}
			else if (type->GetClass() == NamedTypeReferenceClass)
			{
				fprintf(out, "%s = %s\n", name.c_str(), type->GetNamedTypeReference()->GetName().GetString().c_str());
				fprintf(out, "%sHandle = %sHandle\n", name.c_str(),
				    type->GetNamedTypeReference()->GetName().GetString().c_str());
				finishedStructs.insert(i);
				processedSome = true;
			}
		}

		if (!processedSome)
		{
			fprintf(stderr, "Detected dependency cycle in structures\n");
			for (auto& i : structsToProcess)
				fprintf(stderr, "%s\n", i.GetString().c_str());
			return 1;
		}
	}

	fprintf(out, "\n# Function definitions\n");
	fprintf(typeStubFile, "\n# Function definitions\n");
	for (auto& i : funcs)
	{
		string name;
		if (i.first.size() != 1)
			continue;
		name = i.first[0];

		// Check for a string result, these will be automatically wrapped to free the string
		// memory and return a Python string
		bool stringResult = (i.second->GetChildType()->GetClass() == PointerTypeClass)
		                    && (i.second->GetChildType()->GetChildType()->GetWidth() == 1)
		                    && (i.second->GetChildType()->GetChildType()->IsSigned());
		// Pointer returns will be automatically wrapped to return None on null pointer
		bool pointerResult = (i.second->GetChildType()->GetClass() == PointerTypeClass);

		// From python -> C python3 requires str -> str.encode('charmap')
		bool swizzleArgs = true;
		if (name == "BNFreeString" || name == "BNRustFreeString")
			swizzleArgs = false;

		// Rust-allocated strings are deallocated differently
		bool rustFFI = name.rfind("BNRust", 0) == 0;

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

		// TODO: output to type stub file
		fprintf(out, "# -------------------------------------------------------\n");
		fprintf(out, "# %s\n\n", funcName.c_str());
		fprintf(out, "%s = core.%s\n", funcName.c_str(), name.c_str());
		fprintf(out, "%s.restype = ", funcName.c_str());
		OutputType(out, i.second->GetChildType(), true, callbackConvention);

		
		fprintf(typeStubFile, "def %s(", funcName.c_str());

		fprintf(out, "\n");
		if (!i.second->HasVariableArguments())
		{
			fprintf(out, "%s.argtypes = [\n", funcName.c_str());
			size_t argNum = 0;
			for (auto& j : i.second->GetParameters())
			{
				fprintf(out, "\t\t");
				if (name == "BNFreeString" || name == "BNRustFreeString")
				{
					// BNFreeString expects a pointer to a string allocated by the core, so do not use
					// a c_char_p here, as that would be allocated by the Python runtime.  This can
					// be enforced by outputting like a return value.
					OutputType(out, j.type, true);
				}
				else
				{
					OutputType(out, j.type);
				}
				fprintf(typeStubFile, "arg%ld: '", argNum++);
				OutputSwizzledType(typeStubFile, j.type);
				fprintf(typeStubFile, "'");
				fprintf(out, ",\n");
				// TODO: trailing comma might break type stubs?
				fprintf(typeStubFile, ", ");
			}
			fprintf(out, "\t]");

		fprintf(typeStubFile, ") -> '");
		OutputSwizzledType(typeStubFile, i.second->GetChildType(), true);
		fprintf(typeStubFile, "': ...\n");
		}
		else
		{
			// As of writing this, only BNLog's have variable instruction lengths, but in an attempt not to break in the
			// future:
			if (funcName.compare(0, 6, "_BNLog") == 0)
			{
				if (funcName != "_BNLog")
				{
					fprintf(typeStubFile, "*args");
					fprintf(typeStubFile, ") -> '");
					OutputSwizzledType(typeStubFile, i.second->GetChildType(), true);
					fprintf(typeStubFile, "': ...\n");

					fprintf(out, "def %s(*args):\n", name.c_str());
					fprintf(out, "\treturn %s(*[cstr(arg) for arg in args])\n\n", funcName.c_str());
					continue;
				}
				else
				{
					fprintf(typeStubFile, "level, *args");
					fprintf(typeStubFile, ") -> '");
					OutputSwizzledType(typeStubFile, i.second->GetChildType(), true);
					fprintf(typeStubFile, "': ...\n");

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
					OutputSwizzledType(out, arg.type);
				else
					OutputType(out, arg.type);
				fprintf(out, "'");

				argN++;
			}
		}
		fprintf(out, "\n\t\t) -> '");
		if (pointerResult && !stringResult)
			fprintf(out, "Optional[");
		OutputSwizzledType(out, i.second->GetChildType());
		if (pointerResult && !stringResult)
			fprintf(out, "]");
		fprintf(out, "':\n");

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
			fprintf(out, "\tstring = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))\n");
			if (rustFFI)
				fprintf(out, "\tBNRustFreeString(result)\n");
			else
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
		else
		{
			fprintf(out, "\treturn ");
			fprintf(out, "%s\n", stringArgFuncCall.c_str());
		}
		fprintf(out, "\n\n");
	}

	fprintf(out, "max_confidence = %d\n\n", BN_FULL_CONFIDENCE);

	fprintf(out, "\n# Helper functions\n");
	fprintf(out, "def handle_of_type(value, handle_type):\n");
	fprintf(out, "\tif isinstance(value, ctypes.POINTER(handle_type)) or isinstance(value, ctypes.c_void_p):\n");
	fprintf(out, "\t\treturn ctypes.cast(value, ctypes.POINTER(handle_type))\n");
	fprintf(out, "\traise ValueError('expected pointer to %%s' %% str(handle_type))\n");

	fprintf(out, "\n# Set path for core plugins\n");
	fprintf(out, "BNSetBundledPluginDirectory(os.path.join(_base_path, \"plugins\"))\n");

	fclose(out);
	fclose(enums);
	fclose(typeStubFile);
	return 0;
}
