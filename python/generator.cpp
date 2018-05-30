// Copyright (c) 2015-2017 Vector 35 LLC
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
			else {
				fprintf(out, "compatstring");
				// fprintf(out, "ctypes.c_char_p");
			}
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
	fprintf(stderr, "Errors: %s", errors.c_str());
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
	fprintf(out, "ctypes.set_conversion_mode('utf-8', 'strict')\n");
	fprintf(out, "if platform.system() == \"Darwin\":\n");
	fprintf(out, "\t_base_path = os.path.join(os.path.dirname(__file__), \"..\", \"..\", \"..\", \"MacOS\")\n");
	fprintf(out, "\tcore = ctypes.CDLL(os.path.join(_base_path, \"libbinaryninjacore.dylib\"))\n\n");
	fprintf(out, "elif platform.system() == \"Linux\":\n");
	fprintf(out, "\t_base_path = os.path.join(os.path.dirname(__file__), \"..\", \"..\")\n");
	fprintf(out, "\tcore = ctypes.CDLL(os.path.join(_base_path, \"libbinaryninjacore.so.1\"))\n\n");
	fprintf(out, "elif platform.system() == \"Windows\":\n");
	fprintf(out, "\t_base_path = os.path.join(os.path.dirname(__file__), \"..\", \"..\")\n");
	fprintf(out, "\tcore = ctypes.CDLL(os.path.join(_base_path, \"binaryninjacore.dll\"))\n");
	fprintf(out, "else:\n");
	fprintf(out, "\traise Exception(\"OS not supported\")\n\n");
	// fprintf(out, "class compatstring(ctypes.c_char_p):\n");
	// fprintf(out, "\tdef __init__(self, value=None):\n");
	// fprintf(out, "\t\tsuper(compatstring, self).__init__()\n");
	// fprintf(out, "\t\tif value is not None:\n");
	// fprintf(out, "\t\t\tself.value = value\n");
	// fprintf(out, "\t@classmethod\n");
	// fprintf(out, "\tdef from_param(cls, value):\n");
	// fprintf(out, "\t\tif not isinstance(value, bytes):\n");
	// fprintf(out, "\t\t\treturn super(compatstring, cls).from_param(value.encode('utf8'))\n");
	// fprintf(out, "\t\treturn super(compatstring, cls).from_param(value)\n\n");
	// fprintf(out, "\t@property\n");
	// fprintf(out, "\tdef value(self, value):\n");
	// fprintf(out, "\t\tif not isinstance(value, bytes):\n");
	// fprintf(out, "\t\t\treturn super(compatstring, cls).from_param(value.encode('utf8'))\n");
	// fprintf(out, "\t\treturn super(compatstring, cls).from_param(value)\n\n");
	fprintf(out, "class compatstring(ctypes.c_char_p):\n");
	fprintf(out, "	@classmethod\n");
	fprintf(out, "	def from_param(cls, obj):\n");
	fprintf(out, "		if (obj is not None) and (not isinstance(obj, cls)):\n");
	fprintf(out, "			if not isinstance(obj, basestring):\n");
	fprintf(out, "				raise TypeError('parameter must be a string type instance')\n");
	fprintf(out, "			if not isinstance(obj, unicode):\n");
	fprintf(out, "				obj = unicode(obj)\n");
	fprintf(out, "			obj = obj.encode('utf-8')\n");
	fprintf(out, "		return ctypes.c_char_p.from_param(obj)\n");
	fprintf(out, "\n");
	fprintf(out, "	def decode(self):\n");
	fprintf(out, "		if self.value is None:\n");
	fprintf(out, "			return None\n");
	fprintf(out, "		return self.value.decode('utf-8')\n");
	fprintf(out, "	@property\n");
	fprintf(out, "	def value(self, c_void_p=ctypes.c_void_p):\n");
	fprintf(out, "		addr = c_void_p.from_buffer(self).value\n");
	fprintf(out, "		return \n");

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
		if (stringResult || pointerResult)
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

		if (stringResult)
		{
			// Emit wrapper to get Python string and free native memory
			fprintf(out, "def %s(*args):\n", name.c_str());
			fprintf(out, "\tresult = %s(*args)\n", funcName.c_str());
			fprintf(out, "\tstring = ctypes.cast(result, ctypes.c_char_p).value\n");
			fprintf(out, "\tBNFreeString(result)\n");
			fprintf(out, "\treturn string\n");
		}
		else if (pointerResult)
		{
			// Emit wrapper to return None on null pointer
			fprintf(out, "def %s(*args):\n", name.c_str());
			fprintf(out, "\tresult = %s(*args)\n", funcName.c_str());
			fprintf(out, "\tif not result:\n");
			fprintf(out, "\t\treturn None\n");
			fprintf(out, "\treturn result\n");
		}
	}

	fprintf(out, "\n# Helper functions\n");
	fprintf(out, "def handle_of_type(value, handle_type):\n");
	fprintf(out, "\tif isinstance(value, ctypes.POINTER(handle_type)) or isinstance(value, ctypes.c_void_p):\n");
	fprintf(out, "\t\treturn ctypes.cast(value, ctypes.POINTER(handle_type))\n");
	fprintf(out, "\traise ValueError('expected pointer to %%s' %% str(handle_type))\n");

	fprintf(out, "\n# Set path for core plugins\n");
	fprintf(out, "BNSetBundledPluginDirectory(os.path.join(_base_path, \"plugins\"))\n");

	fclose(out);
	fclose(enums);
	return 0;
}
