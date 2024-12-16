/*
Copyright 2020-2024 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/



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
			if (name.size() > 16 && name.substr(0, 11) == "_BNDebugger")
				name = name.substr(3);
			else if (name.size() > 15 && name.substr(0, 10) == "BNDebugger")
				name = name.substr(2);
			else if (name.size() > 15 && name.substr(0, 7) == "BNDebug")
				name = name.substr(2);
			else if (name.size() > 2 && name.substr(0, 2) == "BN")
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
		else if ((type->GetChildType()->GetClass() == IntegerTypeClass) &&
				 (type->GetChildType()->GetWidth() == 1) && (type->GetChildType()->IsSigned()))
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


void OutputSwizzledType(FILE* out, Type* type)
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
			string name = type->GetNamedTypeReference()->GetName().GetString();
			if (name.size() > 16 && name.substr(0, 11) == "_BNDebugger")
				name = name.substr(3);
			else if (name.size() > 15 && name.substr(0, 10) == "BNDebugger")
				name = name.substr(2);
			else if (name.size() > 15 && name.substr(0, 7) == "BNDebug")
				name = name.substr(2);
			else if (name.size() > 2 && name.substr(0, 2) == "BN")
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
		else if ((type->GetChildType()->GetClass() == IntegerTypeClass) &&
			(type->GetChildType()->GetWidth() == 1) && (type->GetChildType()->IsSigned()))
		{
			fprintf(out, "Optional[str]");
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


int main(int argc, char* argv[])
{
	if (argc < 5)
	{
		fprintf(stderr, "Usage: generator <header> <output> <output_template> <output_enum>\n");
		return 1;
	}

	// Parse API header to get type and function information
	map<QualifiedName, Ref<Type>> types, vars, funcs;
	string errors;
	auto arch = new CoreArchitecture(BNGetNativeTypeParserArchitecture());

	// Enable ephemeral settings
	Settings::Instance()->LoadSettingsFile("");
	Settings::Instance()->Set("analysis.types.parserName", "ClangTypeParser");
	bool ok = arch->GetStandalonePlatform()->ParseTypesFromSourceFile(argv[1], types, vars, funcs, errors);

	if (!ok)
	{
		fprintf(stderr, "Errors: %s\n", errors.c_str());
		return 1;
	}

	FILE* out = fopen(argv[2], "w");
	FILE* out_template = fopen(argv[3], "r");
	FILE* enums = fopen(argv[4], "w");

	fprintf(enums, "import enum\n");

	// Copy the content of the template to the output file
	int c;
	while((c = fgetc(out_template)) != EOF)
		fputc(c, out);

	// Create type objects
	fprintf(out, "# Type definitions\n");
	for (auto& i : types)
	{
		string name;
		if (i.first.size() != 1)
			continue;
		name = i.first[0];
		if (name == "BNBinaryView")
		{
			fprintf(out, "from binaryninja._binaryninjacore import BNBinaryView, BNBinaryViewHandle\n");
			continue;
		}
		if (i.second->GetClass() == StructureTypeClass)
		{
			fprintf(out, "class %s(ctypes.Structure):\n", name.c_str());

			// python uses str's, C uses byte-arrays
			bool stringField = false;
			for (auto& arg : i.second->GetStructure()->GetMembers())
			{
				if ((arg.type->GetClass() == PointerTypeClass) &&
					(arg.type->GetChildType()->GetWidth() == 1) &&
					(arg.type->GetChildType()->IsSigned()))
					{
						fprintf(out, "\t@property\n\tdef %s(self):\n\t\treturn pyNativeStr(self._%s)\n", arg.name.c_str(), arg.name.c_str());
						fprintf(out, "\t@%s.setter\n\tdef %s(self, value):\n\t\tself._%s = cstr(value)\n", arg.name.c_str(), arg.name.c_str(), arg.name.c_str());
						stringField = true;
					}
			}

			if (!stringField)
				fprintf(out, "\tpass\n");

			fprintf(out, "%sHandle = ctypes.POINTER(%s)\n", name.c_str(), name.c_str());
		}
		else if (i.second->GetClass() == EnumerationTypeClass)
		{
			bool isBNAPIEnum = false;
			if (name.size() > 16 && name.substr(0, 11) == "_BNDebugger")
				name = name.substr(3);
			else if (name.size() > 15 && name.substr(0, 10) == "BNDebugger")
				name = name.substr(2);
			else if (name.size() > 15 && name.substr(0, 7) == "BNDebug")
				name = name.substr(2);
			else if (name.size() > 2 && name.substr(0, 2) == "BN")
			{
				name = name.substr(2);
				isBNAPIEnum = false;
			}
			else
				continue;

			if (isBNAPIEnum)
			{
				fprintf(out, "from binaryninja._binaryninjacore import %sEnum\n", name.c_str());
				continue;
			}

			fprintf(out, "%sEnum = ctypes.c_int\n", name.c_str());

			fprintf(enums, "\n\nclass %s(enum.IntEnum):\n", name.c_str());
			for (auto& j : i.second->GetEnumeration()->GetMembers())
			{
				fprintf(enums, "\t%s = %" PRId64 "\n", j.name.c_str(), j.value);
			}
		}
		else if ((i.second->GetClass() == BoolTypeClass) || (i.second->GetClass() == IntegerTypeClass) ||
				 (i.second->GetClass() == FloatTypeClass) || (i.second->GetClass() == ArrayTypeClass))
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
					if ((j.type->GetClass() == NamedTypeReferenceClass) &&
						(types[j.type->GetNamedTypeReference()->GetName()]->GetClass() == StructureTypeClass) &&
						(finishedStructs.count(j.type->GetNamedTypeReference()->GetName()) == 0))
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
					if ((j.type->GetClass() == PointerTypeClass) &&
						(j.type->GetChildType()->GetWidth() == 1) &&
						(j.type->GetChildType()->IsSigned()))
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
				if (type->GetNamedTypeReference()->GetTypeReferenceClass() == StructNamedTypeClass)
				{
					fprintf(out, "%s = %s\n", name.c_str(), type->GetNamedTypeReference()->GetName().GetString().c_str());
					fprintf(out, "%sHandle = %sHandle\n", name.c_str(), type->GetNamedTypeReference()->GetName().GetString().c_str());
				}
				else if (type->GetNamedTypeReference()->GetTypeReferenceClass() == EnumNamedTypeClass)
				{
					fprintf(out, "%s = ctypes.c_int\n", name.c_str());
				}
				finishedStructs.insert(i);
				processedSome = true;
			}
		}

		if (!processedSome && structsToProcess.size() != 0)
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
		bool stringResult = (i.second->GetChildType()->GetClass() == PointerTypeClass) &&
			(i.second->GetChildType()->GetChildType()->GetWidth() == 1) &&
			(i.second->GetChildType()->GetChildType()->IsSigned());
		// Pointer returns will be automatically wrapped to return None on null pointer
		bool pointerResult = (i.second->GetChildType()->GetClass() == PointerTypeClass);

		// From python -> C python3 requires str -> str.encode('charmap')
		bool swizzleArgs = true;
		if (name == "BNFreeString")
			swizzleArgs = false;

		bool callbackConvention = false;
		if (name == "BNAllocString")
		{
			// Don't perform automatic wrapping of string allocation, and return a void
			// pointer so that callback functions (which is the only valid use of BNDebuggerAllocString)
			// can properly return the result
			stringResult = false;
			callbackConvention = true;
			swizzleArgs = false;
		}

		string funcName = string("_") + name;

		fprintf(out, "# -------------------------------------------------------\n");
		fprintf(out, "# %s\n\n", funcName.c_str());
		fprintf(out, "%s = core.%s\n", funcName.c_str(), name.c_str());
		fprintf(out, "%s.restype = ", funcName.c_str());
		OutputType(out, i.second->GetChildType(), true, callbackConvention);
		fprintf(out, "\n");
		if (!i.second->HasVariableArguments())
		{
			fprintf(out, "%s.argtypes = [\n", funcName.c_str());
			for (auto& j : i.second->GetParameters())
			{
				fprintf(out, "\t\t");
				if (name == "BNFreeString")
				{
					// BNDebuggerFreeString expects a pointer to a string allocated by the core, so do not use
					// a c_char_p here, as that would be allocated by the Python runtime.  This can
					// be enforced by outputting like a return value.
					OutputType(out, j.type, true);
				}
				else
				{
					OutputType(out, j.type);
				}
				fprintf(out, ",\n");
			}
			fprintf(out, "\t]");
		}
		else
		{
			// As of writing this, only BNLog's have variable instruction lengths, but in an attempt not to break in the future:
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
			for (auto& arg: i.second->GetParameters())
			{
				string argName = arg.name;
				if (g_pythonKeywordReplacements.find(argName) != g_pythonKeywordReplacements.end())
					argName = g_pythonKeywordReplacements[argName];

				if (argName.empty())
					argName = "arg" + to_string(argN);

				if (argN > 0)
					fprintf(out, ", ");
				fprintf(out, "\n\t\t");
				fprintf(out, "%s: ", argName.c_str());
				if (swizzleArgs)
					OutputSwizzledType(out, arg.type);
				else
					OutputType(out, arg.type);
				argN ++;
			}
		}
		fprintf(out, "\n\t\t) -> ");
		if (swizzleArgs)
		{
			if (stringResult || pointerResult)
				fprintf(out, "Optional[");
			OutputSwizzledType(out, i.second->GetChildType());
			if (stringResult || pointerResult)
				fprintf(out, "]");
		}
		else
		{
			OutputType(out, i.second->GetChildType());
		}
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

			if (swizzleArgs && (arg.type->GetClass() == PointerTypeClass) &&
				(arg.type->GetChildType()->GetClass() == IntegerTypeClass) &&
				(arg.type->GetChildType()->GetWidth() == 1) &&
				(arg.type->GetChildType()->IsSigned()))
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
			stringArgFuncCall = stringArgFuncCall.substr(0, stringArgFuncCall.size()-2);
		stringArgFuncCall += ")";

		if (stringResult)
		{
			// Emit wrapper to get Python string and free native memory
			fprintf(out, "\tresult = ");
			fprintf(out, "%s\n", stringArgFuncCall.c_str());
			fprintf(out, "\tif not result:\n");
			fprintf(out, "\t\treturn None\n");
			fprintf(out, "\tstring = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))\n");
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

	fprintf(out, "\n# Helper functions\n");
	fprintf(out, "def handle_of_type(value, handle_type):\n");
	fprintf(out, "\tif isinstance(value, ctypes.POINTER(handle_type)) or isinstance(value, ctypes.c_void_p):\n");
	fprintf(out, "\t\treturn ctypes.cast(value, ctypes.POINTER(handle_type))\n");
	fprintf(out, "\traise ValueError('expected pointer to %%s' %% str(handle_type))\n");

	fclose(out);
	fclose(enums);
	return 0;
}
