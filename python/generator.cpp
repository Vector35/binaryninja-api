// Copyright (c) 2015-2019 Vector 35 Inc
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


class GeneratorArchitecture: public Architecture
{
public:
	GeneratorArchitecture(): Architecture("generator")
	{
	}

	virtual bool GetInstructionInfo(const uint8_t*, uint64_t, size_t, InstructionInfo&) override
	{
		return false;
	}

	virtual bool GetInstructionText(const uint8_t*, uint64_t, size_t&, vector<InstructionTextToken>&) override
	{
		return false;
	}

	virtual BNEndianness GetEndianness() const override
	{
		return LittleEndian;
	}

	virtual size_t GetAddressSize() const override
	{
		return 8;
	}
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
		if (type->GetNamedTypeReference()->GetTypeClass() == EnumNamedTypeClass)
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


int main(int argc, char* argv[])
{
	if (argc < 4)
	{
		fprintf(stderr, "Usage: generator <header> <output> <output_enum>\n");
		return 1;
	}

	Architecture::Register(new GeneratorArchitecture());

	// Parse API header to get type and function information
	map<QualifiedName, Ref<Type>> types, vars, funcs;
	string errors;
	auto arch = Architecture::GetByName("generator");
	if (!arch)
	{
		printf("ERROR: License file validation failed (most likely)\n");
		return 1;
	}

	bool ok = arch->GetStandalonePlatform()->ParseTypesFromSourceFile(argv[1], types, vars, funcs, errors);
	fprintf(stderr, "Errors: %s\n", errors.c_str());
	if (!ok)
		return 1;

	FILE* out = fopen(argv[2], "w");
	FILE* enums = fopen(argv[3], "w");

	fprintf(out, "from __future__ import absolute_import\n");
	fprintf(out, "import ctypes, os\n\n");
	fprintf(enums, "import enum");

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
	fprintf(out, "elif core_platform == \"Windows\":\n");
	fprintf(out, "\t_base_path = os.path.join(os.path.dirname(__file__), \"..\", \"..\")\n");
	fprintf(out, "\tcore = ctypes.CDLL(os.path.join(_base_path, \"binaryninjacore.dll\"))\n");
	fprintf(out, "else:\n");
	fprintf(out, "\traise Exception(\"OS not supported\")\n\n\n");

	fprintf(out, "from binaryninja import cstr, pyNativeStr\n\n\n");

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
		}
		else if (i.second->GetClass() == EnumerationTypeClass)
		{
			if (name.size() > 2 && name.substr(0, 2) == "BN")
				name = name.substr(2);

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
		bool stringArgument = false;
		for (auto& arg : i.second->GetParameters())
		{
			if ((arg.type->GetClass() == PointerTypeClass) &&
				(arg.type->GetChildType()->GetWidth() == 1) &&
				(arg.type->GetChildType()->IsSigned()))
				{
					stringArgument = true;
					break;
				}
		}
		if (name == "BNFreeString")
			stringArgument = false;

		bool callbackConvention = false;
		if (name == "BNAllocString")
		{
			// Don't perform automatic wrapping of string allocation, and return a void
			// pointer so that callback functions (which is the only valid use of BNAllocString)
			// can properly return the result
			stringResult = false;
			callbackConvention = true;
		}

		string funcName = name;
		if (stringResult || pointerResult || stringArgument)
			funcName = string("_") + funcName;

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
					// BNFreeString expects a pointer to a string allocated by the core, so do not use
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
			fprintf(out, "\t]\n");
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

		if (stringResult)
		{
			// Emit wrapper to get Python string and free native memory
			fprintf(out, "def %s(*args):\n", name.c_str());
			if (stringArgument)
			{
				fprintf(out, "\tresult = %s(", funcName.c_str());
				string stringArgFuncCall = "";
				size_t argN = 0;
				for (auto& arg : i.second->GetParameters())
				{
					if ((arg.type->GetClass() == PointerTypeClass) &&
						(arg.type->GetChildType()->GetWidth() == 1) &&
						(arg.type->GetChildType()->IsSigned()))
						{
							stringArgFuncCall += "cstr(args[" + to_string(argN) + "]), ";
						}
					else
						stringArgFuncCall += "args[" + to_string(argN) + "], ";
					argN++;
				}
				stringArgFuncCall = stringArgFuncCall.substr(0, stringArgFuncCall.size()-2);
				stringArgFuncCall += ")\n";
				fprintf(out, "%s", stringArgFuncCall.c_str());
			}
			else
				fprintf(out, "\tresult = %s(*args)\n", funcName.c_str());
			fprintf(out, "\tstring = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))\n");
			fprintf(out, "\tBNFreeString(result)\n");
			fprintf(out, "\treturn string\n");
		}
		else if (pointerResult)
		{
			// Emit wrapper to return None on null pointer
			fprintf(out, "def %s(*args):\n", name.c_str());
			if (stringArgument)
			{
				fprintf(out, "\tresult = %s(", funcName.c_str());
				string stringArgFuncCall = "";
				size_t argN = 0;
				for (auto& arg : i.second->GetParameters())
				{
					if ((arg.type->GetClass() == PointerTypeClass) &&
						(arg.type->GetChildType()->GetWidth() == 1) &&
						(arg.type->GetChildType()->IsSigned()))
						{
							stringArgFuncCall += "cstr(args[" + to_string(argN) + "]), ";
						}
					else
						stringArgFuncCall += "args[" + to_string(argN) + "], ";
					argN++;
				}
				stringArgFuncCall = stringArgFuncCall.substr(0, stringArgFuncCall.size()-2);
				stringArgFuncCall += ")\n";
				fprintf(out, "%s", stringArgFuncCall.c_str());
			}
			else
				fprintf(out, "\tresult = %s(*args)\n", funcName.c_str());
			fprintf(out, "\tif not result:\n");
			fprintf(out, "\t\treturn None\n");
			fprintf(out, "\treturn result\n");
		}
		else if (stringArgument)
		{
			fprintf(out, "def %s(*args):\n", name.c_str());
			{
				fprintf(out, "\treturn %s(", funcName.c_str());
				string stringArgFuncCall = "";
				size_t argN = 0;
				for (auto& arg : i.second->GetParameters())
				{
					if ((arg.type->GetClass() == PointerTypeClass) &&
						(arg.type->GetChildType()->GetWidth() == 1) &&
						(arg.type->GetChildType()->IsSigned()))
						{
							stringArgFuncCall += "cstr(args[" + to_string(argN) + "]), ";
						}
					else
						stringArgFuncCall += "args[" + to_string(argN) + "], ";
					argN++;
				}
				stringArgFuncCall = stringArgFuncCall.substr(0, stringArgFuncCall.size()-2);
				stringArgFuncCall += ")\n";
				fprintf(out, "%s", stringArgFuncCall.c_str());
			}
		}
		fprintf(out, "\n");
	}

	fprintf(out, "\n# Helper functions\n");
	fprintf(out, "def handle_of_type(value, handle_type):\n");
	fprintf(out, "\tif isinstance(value, ctypes.POINTER(handle_type)) or isinstance(value, ctypes.c_void_p):\n");
	fprintf(out, "\t\treturn ctypes.cast(value, ctypes.POINTER(handle_type))\n");
	fprintf(out, "\traise ValueError('expected pointer to %%s' %% str(handle_type))\n");

	// The following method is addapted from python/enum/__init__.py, lines 25-36
	fprintf(out, "\ntry:\n");
	fprintf(out, "\tbasestring\n");
	fprintf(out, "\tunicode\n");
	fprintf(out, "except NameError:\n");
	fprintf(out, "\t# In Python 2 basestring is the ancestor of both str and unicode\n");
	fprintf(out, "\t# in Python 3 it's just str, but was missing in 3.1\n");
	fprintf(out, "\t# In Python 3 unicode no longer exists (it's just str)\n");
	fprintf(out, "\tbasestring = str\n");
	fprintf(out, "\tunicode = str\n");

	fprintf(out, "\n# Set path for core plugins\n");
	fprintf(out, "BNSetBundledPluginDirectory(os.path.join(_base_path, \"plugins\"))\n");

	fclose(out);
	fclose(enums);
	return 0;
}
