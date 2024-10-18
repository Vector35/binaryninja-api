// Copyright 2016-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Includes snippets from LLVM, which is under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.

#include "binaryninjaapi.h"
#include "demangle_msvc.h"
#include <memory>

using namespace BinaryNinja;
using namespace std;

#define MAX_DEMANGLE_LENGTH 4096

Demangle::Reader::Reader(string data)
{
	m_data = data;
	//Check for non-ascii characters
	for (auto a : m_data)
	{
		if (a < 0x20 || a > 0x7e)
			throw DemangleException();
	}
}


string Demangle::Reader::PeekString(size_t count)
{
	if (count > Length())
		throw DemangleException();
	return m_data.substr(0, count);
}


char Demangle::Reader::Peek()
{
	if (1 > Length())
		throw DemangleException();
	return (char)m_data[0];
}


const char* Demangle::Reader::GetRaw()
{
	return m_data.c_str();
}


char Demangle::Reader::Read()
{
	if (1 > Length())
		throw DemangleException();
	char out = m_data[0];
	m_data = m_data.substr(1);
	return out;
}


string Demangle::Reader::ReadString(size_t count)
{
	if (count > Length())
		throw DemangleException();
	string out = m_data.substr(0, count);
	m_data = m_data.substr(count + 1);
	return out;
}


string Demangle::Reader::ReadUntil(char sentinal)
{
	size_t pos = m_data.find_first_of(sentinal);
	if (pos == string::npos)
		throw DemangleException();
	return ReadString(pos);
}


void Demangle::Reader::Consume(size_t count)
{
	if (count > Length())
		throw DemangleException();
	m_data = m_data.substr(count);
}


size_t Demangle::Reader::Length()
{
	return m_data.length();
}


const TypeBuilder& Demangle::BackrefList::GetTypeBackref(size_t reference)
{
	if (reference < typeList.size())
		return typeList[reference];
	// LogDebug("type: %llx - : %d/%d\n", this, typeList.size(), reference);
	throw DemangleException(string("Backref too large " + std::to_string(reference)));
}


string Demangle::BackrefList::GetStringBackref(size_t reference)
{
	// LogDebug("type: %llx - ref: %d\n", this, reference);
	if (reference < nameList.size())
		return nameList[reference];
	LogDebug("type: %p - Backref too large: %zu/%zu\n", this, nameList.size(), reference);
	throw DemangleException(string("Backref too large " + std::to_string(reference)));
}


void Demangle::BackrefList::PushTypeBackref(TypeBuilder t)
{
	// LogDebug("this: %llx - TypeBackref: %lld  %s\n", this, nameList.size(), t.GetString().c_str());
	if (typeList.size() <= 9)
		typeList.push_back(t);
}


void Demangle::BackrefList::PushStringBackref(string& s)
{
	if (s.size() > MAX_DEMANGLE_LENGTH)
		throw DemangleException();
	LogDebug("this: %p - Backref: %zu - %s\n", this, nameList.size(), s.c_str());
	for (const auto& name : nameList)
		if (name == s)
			return;
	nameList.push_back(s);
}


void Demangle::BackrefList::PushFrontStringBackref(string& s)
{
	if (s.size() > MAX_DEMANGLE_LENGTH)
		throw DemangleException();
	// LogDebug("this: %llx - F-Backref: %lld - %s\n", this, nameList.size(), s.c_str());
	nameList.insert(nameList.begin(), s);
}


Demangle::Demangle(Architecture* arch, string mangledName) :
	reader(mangledName),
	m_arch(arch),
	m_platform(nullptr),
	m_view(nullptr)
{
	m_logger = LogRegistry::CreateLogger("MSVCDemangle");
	m_logger->ResetIndent();
}


Demangle::Demangle(Ref<Platform> platform, string mangledName) :
	reader(mangledName),
	m_arch(platform->GetArchitecture()),
	m_platform(platform),
	m_view(nullptr)
{
	m_logger = LogRegistry::CreateLogger("MSVCDemangle");
	m_logger->ResetIndent();
}


Demangle::Demangle(Ref<BinaryView> view, string mangledName) :
	reader(mangledName),
	m_view(view)
{
	m_platform = view->GetDefaultPlatform();
	if (!m_platform)
		throw DemangleException();
	m_arch = m_platform->GetArchitecture();
	m_logger = LogRegistry::CreateLogger("MSVCDemangle");
	m_logger->ResetIndent();
}


TypeBuilder Demangle::DemangleVarType(BackrefList& varList, bool isReturn, QualifiedName& name)
{
	m_logger->LogDebug("%s: '%s' - %lu\n", __FUNCTION__, reader.GetRaw(), varList.nameList.size());
	TypeBuilder newType;
	bool _const = false, _volatile = false, isMember = false; //TODO: use this info, _signed = false;
	BNReferenceType refType;
	BNTypeClass typeClass = IntegerTypeClass;
	BNStructureVariant structType;
	QualifiedName varName;
	QualifiedName typeName;
	BNNameType classFunctionType;

	size_t width;
	char elm = reader.Read();
	switch (elm)
	{
	case 'A':
		typeClass = PointerTypeClass;
		refType = ReferenceReferenceType;
		_const = false;
		_volatile = false;
		break;
	case 'B':
		typeClass = PointerTypeClass;
		refType = ReferenceReferenceType;
		_const = false;
		_volatile = true;
		break;
	case 'C': return TypeBuilder::IntegerType(1, true);
	case 'D': return TypeBuilder::IntegerType(1, true);
	case 'E': return TypeBuilder::IntegerType(1, false);
	case 'F': return TypeBuilder::IntegerType(2, true);
	case 'G': return TypeBuilder::IntegerType(2, false);
	case 'H': return TypeBuilder::IntegerType(4, true);
	case 'I': return TypeBuilder::IntegerType(4, false);
	case 'J': return TypeBuilder::IntegerType(4, true, "long");
	case 'K': return TypeBuilder::IntegerType(4, false, "unsigned long");
	case 'M': return TypeBuilder::FloatType(4);
	case 'N': return TypeBuilder::FloatType(8);
	case 'O': return TypeBuilder::FloatType(10, "long double");
	case 'P': // *
		typeClass = PointerTypeClass;
		refType = PointerReferenceType;
		_const = false;
		_volatile = false;
		break;
	case 'Q': // const *
		typeClass = PointerTypeClass;
		refType = PointerReferenceType;
		_const = true;
		_volatile = false;
		break;
	case 'R': // volatile *
		typeClass = PointerTypeClass;
		refType = PointerReferenceType;
		_const = false;
		_volatile = true;
		break;
	case 'S': // const volatile *
		typeClass = PointerTypeClass;
		refType = PointerReferenceType;
		_const = true;
		_volatile = true;
		break;
	case 'T': typeClass = StructureTypeClass; structType = UnionStructureType;  break;
	case 'U': typeClass = StructureTypeClass; structType = StructStructureType; break;
	case 'V': typeClass = StructureTypeClass; structType = ClassStructureType;  break;
	case 'W':
		typeClass = EnumerationTypeClass;
		switch (reader.Read())
		{
		case '0': width = 1; /* TODO: use these _signed = true;  */ break;
		case '1': width = 1; /* TODO: use these _signed = false; */ break;
		case '2': width = 2; /* TODO: use these _signed = true;  */ break;
		case '3': width = 2; /* TODO: use these _signed = false; */ break;
		case '4': width = 4; /* TODO: use these _signed = true;  */ break;
		case '5': width = 4; /* TODO: use these _signed = false; */ break;
		case '6': width = 4; /* TODO: use these _signed = true;  */ break;
		case '7': width = 4; /* TODO: use these _signed = false; */ break;
		default: throw DemangleException();
		}
		break;
	case 'X': return TypeBuilder::VoidType(); break;
	case 'Y':
		throw DemangleException(); //TODO: handle cointerfaces
	case 'Z': return TypeBuilder::VarArgsType(); break;
	case '_':
		switch (reader.Read())
		{
		case 'D': newType = TypeBuilder::IntegerType(1, true); break;
		case 'E': newType = TypeBuilder::IntegerType(1, false); break;
		case 'F': newType = TypeBuilder::IntegerType(2, true); break;
		case 'G': newType = TypeBuilder::IntegerType(2, false); break;
		case 'H': newType = TypeBuilder::IntegerType(4, true); break;
		case 'I': newType = TypeBuilder::IntegerType(4, false); break;
		case 'J': newType = TypeBuilder::IntegerType(8, true); break;
		case 'K': newType = TypeBuilder::IntegerType(8, false); break;
		case 'L': newType = TypeBuilder::IntegerType(16, true); break;
		case 'M': newType = TypeBuilder::IntegerType(16, false); break;
		case 'N': newType = TypeBuilder::BoolType(); break;
		case 'O':
		{
			QualifiedName name;
			m_logger->Indent();
			auto childType = DemangleVarType(varList, false, name);
			m_logger->Dedent();
			newType = TypeBuilder::ArrayType(childType.Finalize(), 0);
			break;
		}
		case 'S': newType = TypeBuilder::IntegerType(2, true, "char16_t"); break;
		case 'U': newType = TypeBuilder::IntegerType(4, true, "char32_t"); break;
		case 'W': newType = TypeBuilder::IntegerType(2, false, "wchar_t"); break;
		case 'X': typeClass = StructureTypeClass; structType = ClassStructureType; break; //Coclass
		case 'Y': typeClass = StructureTypeClass; structType = ClassStructureType; break; //Cointerface
		default:
			throw DemangleException();
		}
		break;
	case '$':
		if (reader.PeekString(2) == "$Q") // &&
		{
			reader.Consume(2);
			typeClass = PointerTypeClass;
			refType = RValueReferenceType;
			_const = false;
			_volatile = false;
		}
		else if (reader.PeekString(2) == "$R") // && volatile
		{
			reader.Consume(2);
			typeClass = PointerTypeClass;
			refType = RValueReferenceType;
			_const = false;
			_volatile = true;
		}
		else if (reader.PeekString(2) == "$A")
		{
			reader.Consume(2);
			char num = reader.Read();
			if (num == 8)
				return DemangleFunction(NoNameType, true,  varList);
			if (num == '6' || num == '7')
				return DemangleFunction(NoNameType, false, varList);
			throw DemangleException();
		}
		else if (reader.PeekString(2) == "$C")
		{
			reader.Consume(2);
			DemangleModifiers(_const, _volatile, isMember);
			QualifiedName name;
			m_logger->Indent();
			newType = DemangleVarType(varList, false, name);
			m_logger->Dedent();
			newType.SetConst(_const);
			newType.SetVolatile(_volatile);
			return newType;
		}
		else if (reader.PeekString(2) == "$T")
		{
			reader.Consume(2);
			return TypeBuilder::ValueType("std::nullptr");
		}
		else if (reader.Peek() == '0')
		{
			reader.Consume();
			int64_t value;
			DemangleNumber(value);
			return TypeBuilder::ValueType(to_string(value));
		}
		else if (reader.Peek() == '1')
		{
			reader.Consume();
			auto context = DemangleSymbol();
			return TypeBuilder::PointerType(m_arch, context.type.Finalize());
		}
		else
			throw DemangleException();
		break;
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		//Make a copy of the item in the backref list. Exit early since we don't want this added to the backref list.
		m_logger->LogDebug("Backref %u %lu", elm - '0', varList.typeList.size());
		return varList.GetTypeBackref(elm - '0');
	default:
		throw DemangleException();
	}

	switch (typeClass)
	{
	case PointerTypeClass:
	{
		switch (reader.Peek())
		{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
			throw DemangleException();
		case '6':
		{
			if (refType != PointerReferenceType) //No references to functions
			{
				throw DemangleException();
			}
			reader.Consume();
			auto childType = DemangleFunction(NoNameType, false, varList);
			newType = TypeBuilder::PointerType(m_arch,
			                                   childType.Finalize(),
			                                   _const,
			                                   _volatile,
			                                   refType);
			break;
		}
		case '7': //Function pointer
		case '9': //Class Function pointer
		{
			if (refType != PointerReferenceType) //No references to functions
			{
				throw DemangleException();
			}
			reader.Consume();
			auto childType = DemangleFunction(NoNameType, true, varList);
			newType = TypeBuilder::PointerType(m_arch,
			                                   childType.Finalize(),
			                                   _const,
			                                   _volatile,
			                                   refType);
			break;
		}
		case '8': //Named class function pointer
		{
			if (refType != PointerReferenceType) //No references to functions
			{
				throw DemangleException();
			}
			reader.Consume();
			DemangleName(name, classFunctionType, varList);
			name.push_back("");
			auto childType = DemangleFunction(NoNameType, true, varList);
			newType = TypeBuilder::PointerType(m_arch,
			                                   childType.Finalize(),
			                                   _const,
			                                   _volatile,
			                                   refType);
			break;
		}
		default:  // Non-numeric
		{
			m_logger->LogDebug("Demangle pointer subtype: '%s'\n", reader.GetRaw());
			TypeBuilder child;
			bool _const2 = false, _volatile2 = false, isMember = false;
			auto suffix = DemanglePointerSuffix();
			DemangleModifiers(_const2, _volatile2, isMember);
			if (reader.Peek() == 'Y') //Multi-dimentional array
			{
				m_logger->LogDebug("Demangle multi-dimentional array");
				int64_t nDimentions;
				reader.Consume();
				DemangleNumber(nDimentions);
				vector<uint64_t> elementList;
				while (nDimentions--)
				{
					int64_t element = 0;
					DemangleNumber(element);
					elementList.push_back(element);
				}
				QualifiedName name;
				m_logger->Indent();
				child = DemangleVarType(varList, false, name);
				m_logger->Dedent();

				for (auto i = elementList.rbegin(); i != elementList.rend(); i++)
				{
					child = TypeBuilder::ArrayType(child.Finalize(), *i);
				}
			}
			else
			{
				QualifiedName name;
				m_logger->Indent();
				child = DemangleVarType(varList, true, name);
				m_logger->Dedent();
			}

			child.SetConst(_const2);
			child.SetVolatile(_volatile2);
			newType = TypeBuilder::PointerType(m_arch,
			                                   child.Finalize(),
			                                   _const,
			                                   _volatile,
			                                   refType);

			newType.SetPointerSuffix(suffix);
			m_logger->LogDebug("Name: %s\n", newType.GetString().c_str());
			break;
		}
		}
		break;
	}
	case EnumerationTypeClass:
		m_logger->LogDebug("Demangle enumeration\n");
		m_logger->Indent();
		DemangleName(typeName, classFunctionType, varList);
		m_logger->Dedent();
		newType = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(EnumNamedTypeClass, typeName),
		                                 width, width);
		break;
	case StructureTypeClass:
		m_logger->LogDebug("Demangle structure\n");
		m_logger->Indent();
		DemangleName(typeName, classFunctionType, varList);
		m_logger->Dedent();
		switch (structType)
		{
		case ClassStructureType:
			newType = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
				ClassNamedTypeClass, typeName));
			break;
		case StructStructureType:
			newType = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
				StructNamedTypeClass, typeName));
			break;
		case UnionStructureType:
			newType = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
				UnionNamedTypeClass, typeName));
			break;
		default:
			newType = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
				UnknownNamedTypeClass, typeName));
			break;
		}
		break;
	default:
		break;
	}
	if (!isReturn)
	{
		varList.PushTypeBackref(newType);
	}
	return newType;
}


void Demangle::DemangleNumber(int64_t& num)
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	num = 0;
	int mult = 1;
	if (reader.Peek() == '?')
	{
		mult = -1;
		reader.Consume();
	}

	//The number is decimal 1-10
	if (reader.Peek() >= '0' && reader.Peek() <= '9')
	{
		num = mult * (reader.Read() + 1 - '0');
		return;
	}
	else
	{
		//The number is hexidecimal
		string strnum = reader.ReadUntil('@');
		for (auto a : strnum)
		{
			num *= 16;
			if (a >= 'A' && a <= 'P')
				num += a - 'A';
			else
				throw DemangleException();
		}
		num *= mult;
		return;
	}
}


void Demangle::DemangleChar(char& ch)
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	// Basic char is just the char
	if (reader.Peek() != '?')
	{
		ch = reader.Peek();
		reader.Consume();
		return;
	}
	reader.Consume();

	// Hex char is ?$XX for 2 hex digits XX
	if (reader.Peek() == '$')
	{
		m_logger->LogDebug("%s: Hex digit '%s'\n", __FUNCTION__, reader.GetRaw());

		reader.Consume();
		char c1 = reader.Peek();
		reader.Consume();
		char c2 = reader.Peek();
		reader.Consume();

		if (c1 < 'A' || c1 > 'P')
			throw DemangleException("Invalid character");
		if (c2 < 'A' || c2 > 'P')
			throw DemangleException("Invalid character");

		uint8_t b1 = c1 - 'A';
		uint8_t b2 = c2 - 'A';

		ch = (char)((b1 << 4) | b2);
		return;
	}

	m_logger->LogDebug("%s: Table lookup '%s'\n", __FUNCTION__, reader.GetRaw());

	// Otherwise it's a lookup based on some big table
	// Thanks, LLVM!
	switch (reader.Peek())
	{
	case '0': ch = ','; reader.Consume(); return;
	case '1': ch = '/'; reader.Consume(); return;
	case '2': ch = '\\'; reader.Consume(); return;
	case '3': ch = ':'; reader.Consume(); return;
	case '4': ch = '.'; reader.Consume(); return;
	case '5': ch = ' '; reader.Consume(); return;
	case '6': ch = '\n'; reader.Consume(); return;
	case '7': ch = '\t'; reader.Consume(); return;
	case '8': ch = '\''; reader.Consume(); return;
	case '9': ch = '-'; reader.Consume(); return;
	case 'a': ch = '\xE1'; reader.Consume(); return;
	case 'b': ch = '\xE2'; reader.Consume(); return;
	case 'c': ch = '\xE3'; reader.Consume(); return;
	case 'd': ch = '\xE4'; reader.Consume(); return;
	case 'e': ch = '\xE5'; reader.Consume(); return;
	case 'f': ch = '\xE6'; reader.Consume(); return;
	case 'g': ch = '\xE7'; reader.Consume(); return;
	case 'h': ch = '\xE8'; reader.Consume(); return;
	case 'i': ch = '\xE9'; reader.Consume(); return;
	case 'j': ch = '\xEA'; reader.Consume(); return;
	case 'k': ch = '\xEB'; reader.Consume(); return;
	case 'l': ch = '\xEC'; reader.Consume(); return;
	case 'm': ch = '\xED'; reader.Consume(); return;
	case 'n': ch = '\xEE'; reader.Consume(); return;
	case 'o': ch = '\xEF'; reader.Consume(); return;
	case 'p': ch = '\xF0'; reader.Consume(); return;
	case 'q': ch = '\xF1'; reader.Consume(); return;
	case 'r': ch = '\xF2'; reader.Consume(); return;
	case 's': ch = '\xF3'; reader.Consume(); return;
	case 't': ch = '\xF4'; reader.Consume(); return;
	case 'u': ch = '\xF5'; reader.Consume(); return;
	case 'v': ch = '\xF6'; reader.Consume(); return;
	case 'w': ch = '\xF7'; reader.Consume(); return;
	case 'x': ch = '\xF8'; reader.Consume(); return;
	case 'y': ch = '\xF9'; reader.Consume(); return;
	case 'z': ch = '\xFA'; reader.Consume(); return;
	case 'A': ch = '\xC1'; reader.Consume(); return;
	case 'B': ch = '\xC2'; reader.Consume(); return;
	case 'C': ch = '\xC3'; reader.Consume(); return;
	case 'D': ch = '\xC4'; reader.Consume(); return;
	case 'E': ch = '\xC5'; reader.Consume(); return;
	case 'F': ch = '\xC6'; reader.Consume(); return;
	case 'G': ch = '\xC7'; reader.Consume(); return;
	case 'H': ch = '\xC8'; reader.Consume(); return;
	case 'I': ch = '\xC9'; reader.Consume(); return;
	case 'J': ch = '\xCA'; reader.Consume(); return;
	case 'K': ch = '\xCB'; reader.Consume(); return;
	case 'L': ch = '\xCC'; reader.Consume(); return;
	case 'M': ch = '\xCD'; reader.Consume(); return;
	case 'N': ch = '\xCE'; reader.Consume(); return;
	case 'O': ch = '\xCF'; reader.Consume(); return;
	case 'P': ch = '\xD0'; reader.Consume(); return;
	case 'Q': ch = '\xD1'; reader.Consume(); return;
	case 'R': ch = '\xD2'; reader.Consume(); return;
	case 'S': ch = '\xD3'; reader.Consume(); return;
	case 'T': ch = '\xD4'; reader.Consume(); return;
	case 'U': ch = '\xD5'; reader.Consume(); return;
	case 'V': ch = '\xD6'; reader.Consume(); return;
	case 'W': ch = '\xD7'; reader.Consume(); return;
	case 'X': ch = '\xD8'; reader.Consume(); return;
	case 'Y': ch = '\xD9'; reader.Consume(); return;
	case 'Z': ch = '\xDA'; reader.Consume(); return;
	default:
		throw DemangleException("Unknown character");
	}
}


void Demangle::DemangleWideChar(uint16_t& wch)
{
	char c1, c2;
	DemangleChar(c1);
	DemangleChar(c2);

	wch = (uint16_t)(((uint16_t)c1 << 8) | (uint16_t)c2);
}


void Demangle::DemangleVariableList(vector<FunctionParameter>& paramList, BackrefList& varList)
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	bool _const = false, _volatile = false, isMember = false;
	set<BNPointerSuffix> suffix;
	for (size_t i = 0; reader.Peek() != 'Z'; i++)
	{
		bool hasModifiers = false;
		if (reader.Peek() == '@')
		{
			reader.Consume();
			break;
		}
		else if (reader.Peek() == '?')
		{
			reader.Consume();
			suffix = DemanglePointerSuffix();
			DemangleModifiers(_const, _volatile, isMember);
			hasModifiers = true;
		}

		FunctionParameter vt;
		QualifiedName name;
		m_logger->LogDebug("Argument %d: %s", i, reader.GetRaw());
		m_logger->Indent();
		TypeBuilder type = DemangleVarType(varList, false, name);
		m_logger->Dedent();
		if (hasModifiers)
		{
			type.SetConst(_const);
			type.SetVolatile(_volatile);
			type.SetPointerSuffix(suffix);
		}
		vt.name = name.GetString();
		vt.type = type.Finalize();
		vt.defaultLocation = true;

		paramList.push_back(vt);
		m_logger->LogDebug("Argument %zu: '%s' - '%s'\n", i, vt.type->GetString().c_str(), reader.GetRaw());
	}
	if (reader.Peek() == 'Z')
		reader.Consume();
	m_logger->LogDebug("%s: done '%s'\n", __FUNCTION__, reader.GetRaw());
}


Demangle::NameType Demangle::GetNameType()
{
	if (reader.Peek() == '?')
	{
		reader.Consume();
		if (reader.Peek()== '?')
		{
			reader.Consume();
			return GetNameType();
		}
		else if (reader.Peek() == '$')
		{
			reader.Consume();
			return NameTemplate;
		}
		else if (reader.Peek() == '0')
		{
			reader.Consume();
			return NameConstructor;
		}
		else if (reader.Peek() == '1')
		{
			reader.Consume();
			return NameDestructor;
		}
		else if (reader.Peek() == 'B')
		{
			reader.Consume();
			return NameReturn;
		}
		else if (reader.PeekString(2) == "_R")
		{
			reader.Consume(2);
			return NameRtti;
		}
			// else if (reader.PeekString(3) == "__E")
			// {
			// 	reader.Consume(2);
			// 	return NameDynamicInitializer;
			// }
		else
		{
			return NameLookup;
		}
	}
	else if (reader.Peek() >= '0' && reader.Peek() <= '9')
	{
		return NameBackref;
	}
	return NameString;
}


void Demangle::DemangleNameTypeString(string& out)
{
	out = reader.ReadUntil('@');
}


void Demangle::DemangleNameTypeRtti(BNNameType& classFunctionType,
                                    BackrefList& nameBackrefList,
                                    string& out)
{
	TypeBuilder rtti;
	switch (reader.Read())
	{
	case '0':
	{
		if (reader.Peek() != '?')
			throw DemangleException();
		reader.Consume();

		bool _const = false, _volatile = false, isMember = false;
		auto suffix = DemanglePointerSuffix();
		DemangleModifiers(_const, _volatile, isMember);

		QualifiedName name;
		m_logger->Indent();
		rtti = DemangleVarType(nameBackrefList, false, name);
		m_logger->Dedent();
		rtti.SetConst(_const);
		rtti.SetVolatile(_volatile);
		rtti.SetPointerSuffix(suffix);
		out = rtti.GetString() + " `RTTI Type Descriptor' ";
		classFunctionType = RttiTypeDescriptor;
		break;
	}
	case '1':
		out = "`RTTI Base Class Descriptor at (";
		for (int i = 0; i < 4; i++)
		{
			int64_t num = 0;
			DemangleNumber(num);
			if (i > 0)
			{
				out += ",";
			}
			out += to_string(num);
		}
		out += ")'";
		classFunctionType = RttiBaseClassDescriptor;
		break;
	case '2':
		out = "`RTTI Base Class Array'";
		classFunctionType = RttiBaseClassArray;
		break;
	case '3':
		out = "`RTTI Class Hierarchy Descriptor'";
		classFunctionType = RttiClassHierarchyDescriptor;
		break;
	case '4':
		out = "`RTTI Complete Object Locator'";
		classFunctionType = RttiCompleteObjectLocator;
		break;
	default: throw DemangleException();
	}
}


void Demangle::DemangleTypeNameLookup(string& out, BNNameType& functionType)
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	switch (reader.Read())
	{
	case '?': functionType = NoNameType; break;
	case '2': functionType = OperatorNewNameType; break;
	case '3': functionType = OperatorDeleteNameType; break;
	case '4': functionType = OperatorAssignNameType; break;
	case '5': functionType = OperatorRightShiftNameType; break;
	case '6': functionType = OperatorLeftShiftNameType; break;
	case '7': functionType = OperatorNotNameType; break;
	case '8': functionType = OperatorEqualNameType; break;
	case '9': functionType = OperatorNotEqualNameType; break;
	case 'A': functionType = OperatorArrayNameType; break;
	case 'C': functionType = OperatorArrowNameType; break;
	case 'D': functionType = OperatorStarNameType; break;
	case 'E': functionType = OperatorIncrementNameType; break;
	case 'F': functionType = OperatorDecrementNameType; break;
	case 'G': functionType = OperatorMinusNameType; break;
	case 'H': functionType = OperatorPlusNameType; break;
	case 'I': functionType = OperatorBitAndNameType; break;
	case 'J': functionType = OperatorArrowStarNameType; break;
	case 'K': functionType = OperatorDivideNameType; break;
	case 'L': functionType = OperatorModulusNameType; break;
	case 'M': functionType = OperatorLessThanNameType; break;
	case 'N': functionType = OperatorLessThanEqualNameType; break;
	case 'O': functionType = OperatorGreaterThanNameType; break;
	case 'P': functionType = OperatorGreaterThanEqualNameType; break;
	case 'Q': functionType = OperatorCommaNameType; break;
	case 'R': functionType = OperatorParenthesesNameType; break;
	case 'S': functionType = OperatorTildeNameType; break;
	case 'T': functionType = OperatorXorNameType; break;
	case 'U': functionType = OperatorBitOrNameType; break;
	case 'V': functionType = OperatorLogicalAndNameType; break;
	case 'W': functionType = OperatorLogicalOrNameType; break;
	case 'X': functionType = OperatorStarEqualNameType; break;
	case 'Y': functionType = OperatorPlusEqualNameType; break;
	case 'Z': functionType = OperatorMinusEqualNameType; break;
	case '_':
	{
		m_logger->LogDebug(" %s: '%s'\n", __FUNCTION__, reader.GetRaw());
		switch (reader.Read())
		{
		case '0': functionType = OperatorDivideEqualNameType; break;
		case '1': functionType = OperatorModulusEqualNameType; break;
		case '2': functionType = OperatorRightShiftEqualNameType; break;
		case '3': functionType = OperatorLeftShiftEqualNameType; break;
		case '4': functionType = OperatorAndEqualNameType; break;
		case '5': functionType = OperatorOrEqualNameType; break;
		case '6': functionType = OperatorXorEqualNameType; break;
		case '7': functionType = VFTableNameType; break;
		case '8': functionType = VBTableNameType; break;
		case '9': functionType = VCallNameType; break;
		case 'A': functionType = TypeofNameType; break;
		case 'B': functionType = LocalStaticGuardNameType; break;
		case 'C': functionType = StringNameType; break;
		case 'D': functionType = VBaseDestructorNameType; break;
		case 'E': functionType = VectorDeletingDestructorNameType; break;
		case 'F': functionType = DefaultConstructorClosureNameType; break;
		case 'G': functionType = ScalarDeletingDestructorNameType; break;
		case 'H': functionType = VectorConstructorIteratorNameType; break;
		case 'I': functionType = VectorDestructorIteratorNameType; break;
		case 'J': functionType = VectorVBaseConstructorIteratorNameType; break;
		case 'K': functionType = VirtualDisplacementMapNameType; break;
		case 'L': functionType = EHVectorConstructorIteratorNameType; break;
		case 'M': functionType = EHVectorDestructorIteratorNameType; break;
		case 'N': functionType = EHVectorVBaseConstructorIteratorNameType; break;
		case 'O': functionType = CopyConstructorClosureNameType; break;
		case 'P': functionType = UDTReturningNameType; break;
		case 'S': functionType = LocalVFTableNameType; break;
		case 'T': functionType = LocalVFTableConstructorClosureNameType; break;
		case 'U': functionType = OperatorNewArrayNameType; break;
		case 'V': functionType = OperatorDeleteArrayNameType; break;
		case 'X': functionType = PlacementDeleteClosureNameType; break;
		case 'Y': functionType = PlacementDeleteClosureArrayNameType; break;
		case 'Q': // Fallthrough
		case 'W': // Fallthrough
		case 'Z': functionType = NoNameType; break;
		case '_':
			m_logger->LogDebug("  %s: '%s'\n", __FUNCTION__, reader.GetRaw());
			switch (reader.Read())
			{
			case 'A': functionType = ManagedVectorConstructorIteratorNameType; break;
			case 'B': functionType = ManagedVectorDestructorIteratorNameType; break;
			case 'C': functionType = EHVectorCopyConstructorIteratorNameType; break;
			case 'D': functionType = EHVectorVBaseConstructorIteratorNameType; break;
			case 'E': functionType = DynamicInitializerNameType; break;
			case 'F': functionType = DynamicAtExitDestructorNameType; break;
			case 'G': functionType = VectorCopyConstructorIteratorNameType; break;
			case 'H': functionType = VectorVBaseCopyConstructorIteratorNameType; break;
			case 'I': functionType = ManagedVectorCopyConstructorIteratorNameType; break;
			case 'J': functionType = LocalStaticGuardNameType; break;
			case 'K': functionType = UserDefinedLiteralOperatorNameType; break;
			default: throw DemangleException("Demangle Lookup Failed"); // fall through
			}
			break;
		default:
			throw DemangleException("Demangle Lookup Failed");
		}
		break;
	}
	default: throw DemangleException("Demangle Lookup Failed");
	}
	out = Type::GetNameTypeString(functionType);
}


string Demangle::DemangleTemplateInstantiationName(BackrefList& nameBackrefList)
{
	string out;
	BackrefList templateBackref;
	reader.Consume(2);
	m_logger->LogDebug("DemangleTemplateInstantiationName: '%s'\n", reader.GetRaw());
	if (reader.Peek() >= '0' && reader.Peek() <= '9')
	{
		out = nameBackrefList.GetStringBackref(reader.Read() - '0');
	}
	else
	{
		DemangleNameTypeString(out);
	}
	nameBackrefList.PushStringBackref(out);
	return out;
}


string Demangle::DemangleTemplateParams(vector<FunctionParameter>& params, BackrefList& nameBackrefList, string& out)
{
	m_logger->Indent();
	DemangleVariableList(params, nameBackrefList);
	m_logger->Dedent();
	m_logger->LogDebug("VariableList done\n");
	out += "<";
	for (size_t i = 0; i < params.size(); i++)
	{
		if (i == 0)
		{
			out += params[i].type->GetString();
		}
		else
		{
			out += "," + params[i].type->GetString();
		}
	}
	if (out[out.size()-1] == '>')
		out += " "; //Be c++03 compliant where we can
	out += ">";

	nameBackrefList.PushStringBackref(out);
	return out;
}

// void Demangle::DemangleInitFiniStub(bool destructor, QualifiedName& nameList, BackrefList& nameBackrefList, BNNameType& classFunctionType)
// {
// 	bool isStatic = false;
// 	if (reader.Peek() == '?')
// 	{
// 		reader.Consume();
// 		isStatic = true;
// 	}
// 	string out = DemangleUnqualifiedSymbolName(nameList, nameBackrefList, classFunctionType);
// }


string Demangle::DemangleUnqualifiedSymbolName(QualifiedName& nameList, BackrefList& nameBackrefList, BNNameType& classFunctionType)
{
	string out;
	if (reader.PeekString(2) == "?$")
	{
		reader.Consume(2);
		out = DemangleTemplateInstantiationName(nameBackrefList);
		nameList.insert(nameList.begin(), out);
	}
	else if (reader.Peek() == '?')
	{
		reader.Consume();
		DemangleTypeNameLookup(out, classFunctionType);
	}
	else if (reader.Peek() >= '0' && reader.Peek() <= '9')
	{
		out = nameBackrefList.GetStringBackref(reader.Read() - '0');
	}
	else
	{
		DemangleNameTypeString(out);
	}
	return out;
}


TypeBuilder Demangle::DemangleString()
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	// ??_C@_<length><crc32>@<name>
	if (reader.Peek() != '_')
	{
		throw DemangleException("Invalid mangled string name");
	}
	reader.Consume();

	// Wide char flag (1 yes / 0 no)
	bool isWideChar = false;
	switch (reader.Peek())
	{
	case '1':
		isWideChar = true;
		break;
	case '0':
		break;
	default:
		throw DemangleException("Invalid mangled string name");
	}
	reader.Consume();

	// Length is just a number

	int64_t lengthRaw;
	DemangleNumber(lengthRaw);
	if (lengthRaw < 0)
	{
		throw DemangleException("Invalid mangled string name");
	}
	uint64_t length = (uint64_t)lengthRaw;

	m_logger->LogDebug("%s: Before CRC32 '%s'\n", __FUNCTION__, reader.GetRaw());

	// CRC32 (ignored)
	while (reader.Peek() != '@')
	{
		// Usually 8 bytes but I've seen it be 7 for some ungodly reason
		reader.Consume();
	}

	reader.Consume();

	bool truncated = false;
	string name = "";
	TypeBuilder type;

	// String bytes
	if (isWideChar)
	{
		m_logger->LogDebug("%s: Wide string '%s'\n", __FUNCTION__, reader.GetRaw());
		string utf8name;
		truncated = (length > 64);
		while (reader.Peek() != '@')
		{
			uint16_t wch;
			DemangleWideChar(wch);

			uint8_t chs[2];
			chs[0] = wch & 0xFF;
			chs[1] = wch >> 8;

			// TODO: This is actually UCS2 but we don't have an easy decoder for that
			utf8name += Unicode::UTF16ToUTF8(&chs[0], 2);
		}
		reader.Consume();

		name = Unicode::ToEscapedString(Unicode::GetBlocksForNames({}), false, utf8name.data(), utf8name.size());
		type = Type::ArrayType(Type::WideCharType(2), length / 2);
	}
	else
	{
		m_logger->LogDebug("%s: Non-wide string '%s'\n", __FUNCTION__, reader.GetRaw());
		uint64_t numNulls = 0;
		size_t endNulls = 0;
		vector<uint8_t> chars;
		while (reader.Peek() != '@')
		{
			char ch;
			DemangleChar(ch);
			if (ch == 0)
			{
				numNulls++;
				endNulls++;
			}
			else
			{
				endNulls = 0;
			}
			chars.push_back(ch);
		}
		reader.Consume();

		if (length > (uint64_t)chars.size() + 1)
		{
			truncated = true;
		}

		// Now time to guess encoding
		if (chars.size() % 1 != 0)
		{
			m_logger->LogDebug("%s: Looks like UTF8 '%s'\n", __FUNCTION__, reader.GetRaw());
			name = Unicode::ToEscapedString(Unicode::GetBlocksForNames({}), false, chars.data(), chars.size() - endNulls);
			type = Type::ArrayType(Type::IntegerType(1, true), length);
		}
		else
		{
			if (chars.size() % 4 == 0 && numNulls > length * 2 / 3)
			{
				m_logger->LogDebug("%s: Looks like UTF32 '%s'\n", __FUNCTION__, reader.GetRaw());
				string utf8name;
				for (size_t i = 0; i < chars.size() - endNulls; i += 4)
				{
					utf8name += Unicode::UTF32ToUTF8(chars.data() + i);
				}
				name = Unicode::ToEscapedString(Unicode::GetBlocksForNames({}), false, utf8name.data(), utf8name.size());
				type = Type::ArrayType(Type::WideCharType(4), length / 4);
			}
			else if (numNulls > length / 3)
			{
				m_logger->LogDebug("%s: Looks like UTF16 '%s'\n", __FUNCTION__, reader.GetRaw());
				string utf8name;
				for (size_t i = 0; i < chars.size() - endNulls; i += 2)
				{
					utf8name += Unicode::UTF16ToUTF8(chars.data() + i, 2);
				}
				name = Unicode::ToEscapedString(Unicode::GetBlocksForNames({}), false, utf8name.data(), utf8name.size());
				type = Type::ArrayType(Type::WideCharType(2), length / 2);
			}
			else
			{
				m_logger->LogDebug("%s: Looks like UTF8 '%s'\n", __FUNCTION__, reader.GetRaw());

				name = Unicode::ToEscapedString(Unicode::GetBlocksForNames({}), false, chars.data(), chars.size() - endNulls);
				type = Type::ArrayType(Type::IntegerType(1, true), length);
			}
		}
	}
	if (truncated)
	{
		name += "...";
	}
	m_varName.push_back(name);
	return type;
}


TypeBuilder Demangle::DemangleTypeInfoName()
{
	if (reader.Read() != '?')
		throw DemangleException("Unknown raw name type");
	bool _const = false;
	bool _volatile = false;
	bool isMember = false;
	DemangleModifiers(_const, _volatile, isMember);

	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());

	QualifiedName name;
	TypeBuilder type = DemangleVarType(m_backrefList, false, name);
	type.SetConst(_const);
	type.SetVolatile(_volatile);

	switch (type.GetClass())
	{
	case NamedTypeReferenceClass:
		m_varName = type.GetNamedTypeReference()->GetName();
		return type;
	default:
		throw DemangleException("Unexpected type of RTTI Type Name");
	}
}


void Demangle::DemangleName(QualifiedName& nameList,
                            BNNameType& classFunctionType,
                            BackrefList& nameBackrefList)
{
	string out;
	BNNameType functionType;
	BNNameType dummyFunctionType;
	vector<FunctionParameter> params;
	while(1)
	{
		m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
		switch (GetNameType())
		{
		case NameString:
			m_logger->LogDebug("Demangle String\n");
			DemangleNameTypeString(out);
			nameList.insert(nameList.begin(), out);
			m_logger->LogDebug("Pushing backref NameString %s", out.c_str());
			nameBackrefList.PushStringBackref(out);
			m_logger->LogDebug("nameList.front(): %s\n", nameList.front().c_str());
			m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
			break;
		case NameLookup:
			m_logger->LogDebug("Demangle Lookup\n");
			DemangleTypeNameLookup(out, functionType);
			classFunctionType = functionType;
			nameList.insert(nameList.begin(), out);
			break;
		case NameBackref:
			m_logger->LogDebug("Demangle Backref");
			out = nameBackrefList.GetStringBackref(reader.Read() - '0');
			m_logger->LogDebug("Demangle Backref: %s", out.c_str());
			nameList.insert(nameList.begin(), out);
			break;
		case NameTemplate:
		{
			m_logger->LogDebug("Demangle Template: '%s'\n", reader.GetRaw());
			BackrefList templateBackref;
			out = DemangleUnqualifiedSymbolName(nameList, templateBackref, functionType);
			m_logger->LogDebug("Pushing backref NameTemplate %s", out.c_str());
			templateBackref.PushStringBackref(out);
			m_logger->LogDebug("Demangling Template variables %s\n", reader.GetRaw());
			DemangleTemplateParams(params, templateBackref, out);
			nameList.insert(nameList.begin(), out);
			nameBackrefList.PushStringBackref(out);
			break;
		}
		case NameConstructor:
			m_logger->LogDebug("NameConstructor\n");
			classFunctionType = ConstructorNameType;
			DemangleName(nameList, dummyFunctionType, nameBackrefList);
			if (nameList.size() == 0)
				throw DemangleException();
			nameList.push_back(nameList[nameList.size()-1]);
			return;
		case NameDestructor:
			classFunctionType = ConstructorNameType;
			m_logger->LogDebug("NameDestructor\n");
			DemangleName(nameList, dummyFunctionType, nameBackrefList);
			if (nameList.size() == 0)
				throw DemangleException();
			nameList.push_back("~" + nameList[nameList.size()-1]);
			return;
		case NameRtti:
			m_logger->LogDebug("NameRtti\n");
			DemangleNameTypeRtti(classFunctionType, nameBackrefList, out);
			nameList.insert(nameList.begin(), out);
			break;
			// case NameDynamicInitializer:
			// 	m_logger->LogDebug("NameDynamicInitializer\n");
			// 	DemangleInitFiniStub(false);
			// 	break;
			// case NameDynamicAtExitDestructor:
			// 	m_logger->LogDebug("NameDynamicAtExitDestructor\n");
			// 	DemangleInitFiniStub(false);
			// 	break;
		case NameReturn:
			m_logger->LogDebug("NameReturn\n");
			classFunctionType = OperatorReturnTypeNameType;
			if (reader.PeekString(2) == "?$")
			{
				out = DemangleTemplateInstantiationName(nameBackrefList);
				DemangleTemplateParams(params, nameBackrefList, out);
			}
			else
			{
				DemangleNameTypeString(out);
				nameBackrefList.PushStringBackref(out);
			}
			nameList.insert(nameList.begin(), out);
			break;
		default:
			throw DemangleException();
		}
		if (nameList.StringSize() > MAX_DEMANGLE_LENGTH)
			throw DemangleException();
		if (reader.Peek() == '@')
		{
			reader.Consume();
			return;
		}
	}
}

Ref<CallingConvention> Demangle::GetCallingConventionForType(BNCallingConventionName ccName)
{
	string name;
	switch (ccName)
	{
	case NoCallingConvention: name = ""; break;
	case CdeclCallingConvention: name = "cdecl"; break;
	case PascalCallingConvention: name = "pascal"; break;
	case ThisCallCallingConvention: name = "thiscall"; break;
	case STDCallCallingConvention: name = "stdcall"; break;
	case FastcallCallingConvention: name = "fastcall"; break;
	case CLRCallCallingConvention: name = "clrcall"; break;
	case EabiCallCallingConvention: name = "eabi"; break;
	case VectorCallCallingConvention: name = "vectorcall"; break;
	case SwiftCallingConvention: name = "swiftcall"; break;
	case SwiftAsyncCallingConvention: name = "swiftasync"; break;
	default: break;
	}

	if (m_platform)
	{
		for (const auto& cc : m_platform->GetCallingConventions())
		{
			if (cc->GetName() == name)
				return cc;
		}
	}

	for (const auto& cc : m_arch->GetCallingConventions())
	{
		if (cc->GetName() == name)
			return cc;
	}
	return nullptr;
}

BNCallingConventionName Demangle::DemangleCallingConvention()
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	switch (reader.Read())
	{
	case 'A': //Exported function
	case 'B': return CdeclCallingConvention;
	case 'C': //Exported function
	case 'D': return PascalCallingConvention;
	case 'E': //Exported function
	case 'F': return ThisCallCallingConvention;
	case 'G': //Exported function
	case 'H': return STDCallCallingConvention;
	case 'I': //Exported function
	case 'J': return FastcallCallingConvention;
	case 'K': //Exported function
	case 'L': return NoCallingConvention;
	case 'M': //Exported function
	case 'N': return CLRCallCallingConvention;
	case 'O': //Exported function
	case 'P': return EabiCallCallingConvention;
	case 'Q': return VectorCallCallingConvention;
	case 'S': return SwiftCallingConvention;
	case 'W': return SwiftAsyncCallingConvention;
	default:throw DemangleException();
	}
}

set<BNPointerSuffix> Demangle::DemanglePointerSuffix()
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	set<BNPointerSuffix> suffix;
	if (reader.Peek() == '@')
		return suffix;

	char elm = reader.Peek();
	for (int i = 0; i < 5; i++, elm = reader.Peek())
	{
		if (elm == 'E')
			suffix.insert(suffix.end(), Ptr64Suffix);
		else if (elm == 'F')
			suffix.insert(suffix.end(), UnalignedSuffix);
		else if (elm == 'G')
			suffix.insert(suffix.end(), ReferenceSuffix);
		else if (elm == 'H')
			suffix.insert(suffix.end(), LvalueSuffix);
		else if (elm == 'I')
			suffix.insert(suffix.end(), RestrictSuffix);
		else
			break;
		reader.Consume(1);
	}
	return suffix;
}

void Demangle::DemangleModifiers(bool& _const, bool& _volatile, bool &isMember)
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	if (reader.Peek() == '@')
		return;

	_const = false;
	_volatile = false;
	isMember = false;
	char elm = reader.Read();
	switch (elm)
	{
	case 'A': break;
	case 'B': _const = true; break;
	case 'J': _const = true; break;
	case 'C': _volatile = true; break;
	case 'G': _volatile = true; break;
	case 'K': _volatile = true; break;
	case 'D': _const = true; _volatile = true; break;
	case 'H': _const = true; _volatile = true; break;
	case 'L': _const = true; _volatile = true; break;
	case '6': break;
	case '7': break;
	case 'M': break;
	case 'N': break;
	case 'O': _volatile = true; break;
	case 'P': _volatile = true; _const = true; break;
	case 'Q': isMember = true; break;
	case 'U': break;
	case 'Y': break;
	case 'R': _const = true; isMember = true; break;
	case 'V': _const = true; break;
	case 'Z': _const = true; break;
	case 'S': _volatile = true; isMember = true; break;
	case 'W': _volatile = true; break;
	case '0': _volatile = true; break;
	case 'T': _const = true; _volatile = true; isMember = true; break;
	case 'X': _const = true; _volatile = true; break;
	case '1': _const = true; _volatile = true; break;
	case '8': break;
	case '9': break;
	case '2': break;
	case '3': _const = true; break;
	case '4': _volatile = true; break;
	case '5': _const = true; _volatile = true; break;
	case '_':
		elm = reader.Read();
		if (elm == 'A' || elm == 'B')
		{
			//For unhandled "member" and "based" parameters
			break;
		}
		else if (elm == 'C' || elm == 'D')
		{
			//For unhandled "member" and "based" parameters
			break;
		}
		else
		{
			throw DemangleException();
		}
		break;
	default: throw DemangleException();
	}
	return;
}


TypeBuilder Demangle::DemangleFunction(BNNameType classFunctionType, bool pointerSuffix, BackrefList& nameBackrefList, int funcClass)
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	bool _const = false, _volatile = false, isMember = false;
	set<BNPointerSuffix> suffix;
	TypeBuilder returnType;
	BNCallingConventionName cc;

	//Demangle adjustor which we don't do anything with for now
	if ((funcClass & StaticThunkFunctionClass) == StaticThunkFunctionClass)
	{
		int64_t adjustor;
		DemangleNumber(adjustor);
		m_varName.back() += "`adjustor{" + to_string(adjustor) + "}'";
	}
	else if ((funcClass & VirtualThunkFunctionClass) == VirtualThunkFunctionClass)
	{
		if ((funcClass & VirtualThunkExFunctionClass) == VirtualThunkExFunctionClass)
		{
			int64_t vbptrOffset;
			int64_t vbOffsetOffset;
			int64_t vtorDispOffset;
			int64_t staticOffset;
			DemangleNumber(vbptrOffset);
			DemangleNumber(vbOffsetOffset);
			DemangleNumber(vtorDispOffset);
			DemangleNumber(staticOffset);
			m_varName.back() += "`vtordispex{" + to_string(vbptrOffset) + ", " + to_string(vbOffsetOffset) + ", " + to_string(vtorDispOffset) + ", " + to_string(staticOffset) + "}'";
		}
		else
		{
			int64_t vtorDispOffset;
			int64_t staticOffset;
			DemangleNumber(vtorDispOffset);
			DemangleNumber(staticOffset);
			m_varName.back() += "`vtordisp{" + to_string(vtorDispOffset) + ", " + to_string(staticOffset) + "}'";
		}
	}

	if (pointerSuffix)
	{
		suffix = DemanglePointerSuffix();
		DemangleModifiers(_const, _volatile, isMember);
	}
	if (reader.Peek() == '?')
		reader.Consume();
	cc = DemangleCallingConvention();
	bool shouldHaveReturnType = true;
	if (reader.Peek() == '@')
	{
		//No return type
		shouldHaveReturnType = false;
		reader.Consume();
		m_logger->LogDebug("Function has no return type %s", reader.GetRaw());
	}
	else
	{
		//Demangle function return type
		bool return_const = false, return_volatile = false, isMember = false;
		set<BNPointerSuffix> return_suffix;
		bool hasModifiers = false;
		//Check for modifiers before return type
		if (reader.Peek() == '?')
		{
			reader.Consume(1);
			return_suffix = DemanglePointerSuffix();
			DemangleModifiers(return_const, return_volatile, isMember);
			hasModifiers = true;
		}

		QualifiedName name;
		m_logger->LogDebug("Demangle function return type %s", reader.GetRaw());
		m_logger->Indent();
		returnType = DemangleVarType(nameBackrefList, true, name);
		m_logger->LogDebug("Return type: %s", returnType.GetString().c_str());
		m_logger->Dedent();
		if (hasModifiers)
		{
			returnType.SetConst(return_const);
			returnType.SetVolatile(return_volatile);
			returnType.SetPointerSuffix(return_suffix);
		}
	}
	if (reader.Peek() == '@')
		reader.Consume();

	m_logger->LogDebug("\tDemangle Function Parameters %s", reader.GetRaw());
	vector<FunctionParameter> params;
	bool needsThisPtr = false;
	if (cc == ThisCallCallingConvention)
	{
		needsThisPtr = true;
	}
	if (funcClass != NoneFunctionClass)
	{
		if ((funcClass & VirtualFunctionClass) == VirtualFunctionClass
		    || (funcClass & StaticThunkFunctionClass) == StaticThunkFunctionClass
		    || (funcClass & VirtualThunkFunctionClass) == VirtualThunkFunctionClass)
		{
			needsThisPtr = true;
		}
		else if ((funcClass & StaticFunctionClass) != StaticFunctionClass
		         && (funcClass & GlobalFunctionClass) != GlobalFunctionClass)
		{
			needsThisPtr = true;
		}
	}

	if (needsThisPtr)
	{
		// Insert implicit "this" parameter for thiscall
		// TODO: Replace this with calling convention / platform callbacks to insert thisptr (ask rss)
		QualifiedName thisName = m_varName;
		if (thisName.size() > 0)
			thisName.erase(thisName.end() - 1);
		params.push_back(FunctionParameter("this", Type::PointerType(m_arch, Type::NamedType(thisName, Type::VoidType())), true, {}));
	}

	DemangleVariableList(params, m_backrefList);

	if (params.size() >= 1 && params.back().type->GetClass() == VoidTypeClass)
		params.pop_back();

	// TODO: fix calling convention
	TypeBuilder newType = TypeBuilder::FunctionType(shouldHaveReturnType ? returnType.Finalize() : Type::VoidType(), nullptr, params);
	newType.SetConst(_const);
	newType.SetVolatile(_volatile);
	newType.SetPointerSuffix(suffix);
	newType.SetNameType(classFunctionType);
	newType.SetCallingConventionName(cc);
	auto convention = GetCallingConventionForType(cc);
	if (convention)
		newType.SetCallingConvention(convention);

	m_logger->LogDebug("Successfully Created Function Type!\n");
	return newType;
}


TypeBuilder Demangle::DemangleData()
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	bool _const = false, _volatile = false, isMember = false;
	QualifiedName name;
	m_logger->Indent();
	TypeBuilder newType = DemangleVarType(m_backrefList, false, name);
	m_logger->Dedent();
	auto suffix = DemanglePointerSuffix();
	DemangleModifiers(_const, _volatile, isMember);
	newType.SetConst(_const);
	newType.SetVolatile(_volatile);
	newType.SetPointerSuffix(suffix);
	return newType;
}


TypeBuilder Demangle::DemanagleRTTI(BNNameType nameType)
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	bool _const = false, _volatile = false, isMember = false;
	if (reader.Length() > 0)
		DemangleModifiers(_const, _volatile, isMember);
	QualifiedName typeName = m_varName;
	m_logger->LogDebug("new struct type\n");
	TypeBuilder newType = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
		StructNamedTypeClass, typeName));
	newType.SetNameType(nameType);
	newType.SetConst(_const);
	newType.SetVolatile(_volatile);
	m_logger->LogDebug("log: %s\n", newType.GetString().c_str());
	return newType;
}


TypeBuilder Demangle::DemangleVTable()
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	bool _const = false, _volatile = false, isMember = false;
	DemangleModifiers(_const, _volatile, isMember);
	TypeBuilder newType = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
		StructNamedTypeClass, m_varName));
	if (reader.Peek() != '@')
	{
		QualifiedName typeName;
		BNNameType classFunctionType = NoNameType;
		DemangleName(typeName, classFunctionType, m_backrefList);
		string suffix = m_varName.back();
		m_varName.back() += "{for `" + typeName.GetString() + "'}";

		typeName.push_back(suffix);
		newType = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
			StructNamedTypeClass, typeName));
	}
	newType.SetConst(_const);
	newType.SetVolatile(_volatile);
	newType.SetNameType(VFTableNameType);
	return newType;
}



Demangle::DemangleContext Demangle::DemangleSymbol()
{
	m_logger->LogDebug("%s: '%s'\n", __FUNCTION__, reader.GetRaw());
	m_logger->Indent();
	BNNameType classFunctionType = NoNameType;
	QualifiedName varName;

	if (reader.Peek() == '.')
	{
		reader.Consume();

		return { DemangleTypeInfoName(), NoAccess, NoScope };
	}

	if (reader.Read() != '?')
	{
		throw DemangleException();
	}

	DemangleName(varName, classFunctionType, m_backrefList);
	m_logger->LogDebug("Done demangling Name: '%s' - '%s'", varName.GetString().c_str(), reader.GetRaw());
	m_varName = varName;

	DemangleContext context;

	if (classFunctionType == StringNameType)
	{
		context = { DemangleString(), NoAccess, NoScope };
		return context;
	}

	char funcType = reader.Read();
	switch(funcType)
	{
	case '0': context = {DemangleData(),                      PrivateAccess,   StaticScope }; break;
	case '1': context = {DemangleData(),                      ProtectedAccess, StaticScope }; break;
	case '2': context = {DemangleData(),                      PublicAccess,    StaticScope }; break;
	case '3': context = {DemangleData(),                      NoAccess,        NoScope     }; break;
	case '4': context = {DemangleData(),                      NoAccess,        NoScope     }; break;
	case '5': context = {DemangleVTable(),                    NoAccess,        NoScope     }; break;
	case '6': context = {DemangleVTable(),                    NoAccess,        NoScope     }; break;
	case '7': context = {DemangleVTable(),                    NoAccess,        NoScope     }; break;
	case '8': context = {DemanagleRTTI(classFunctionType),    NoAccess,        NoScope     }; break;
	case '9': context = {DemanagleRTTI(classFunctionType),    NoAccess,        NoScope     }; break;
	case 'A': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PrivateFunctionClass),                              PrivateAccess,   NoScope     }; break;
	case 'B': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PrivateFunctionClass),                              PrivateAccess,   NoScope     }; break;
	case 'C': context = {DemangleFunction(classFunctionType, false, m_backrefList, PrivateFunctionClass | StaticFunctionClass),        PrivateAccess,   StaticScope }; break;
	case 'D': context = {DemangleFunction(classFunctionType, false, m_backrefList, PrivateFunctionClass | StaticFunctionClass),        PrivateAccess,   StaticScope }; break;
	case 'E': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PrivateFunctionClass | VirtualFunctionClass),       PrivateAccess,   VirtualScope}; break;
	case 'F': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PrivateFunctionClass | VirtualFunctionClass),       PrivateAccess,   VirtualScope}; break;
	case 'G': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PrivateFunctionClass | StaticThunkFunctionClass),   PrivateAccess,   ThunkScope  }; break;
	case 'H': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PrivateFunctionClass | StaticThunkFunctionClass),   PrivateAccess,   ThunkScope  }; break;
	case 'I': context = {DemangleFunction(classFunctionType, true,  m_backrefList, ProtectedFunctionClass),                            ProtectedAccess, NoScope     }; break;
	case 'J': context = {DemangleFunction(classFunctionType, true,  m_backrefList, ProtectedFunctionClass),                            ProtectedAccess, NoScope     }; break;
	case 'K': context = {DemangleFunction(classFunctionType, false, m_backrefList, ProtectedFunctionClass | StaticFunctionClass),      ProtectedAccess, StaticScope }; break;
	case 'L': context = {DemangleFunction(classFunctionType, false, m_backrefList, ProtectedFunctionClass | StaticFunctionClass),      ProtectedAccess, StaticScope }; break;
	case 'M': context = {DemangleFunction(classFunctionType, true,  m_backrefList, ProtectedFunctionClass | VirtualFunctionClass),     ProtectedAccess, VirtualScope}; break;
	case 'N': context = {DemangleFunction(classFunctionType, true,  m_backrefList, ProtectedFunctionClass | VirtualFunctionClass),     ProtectedAccess, VirtualScope}; break;
	case 'O': context = {DemangleFunction(classFunctionType, true,  m_backrefList, ProtectedFunctionClass | StaticThunkFunctionClass), ProtectedAccess, ThunkScope  }; break;
	case 'P': context = {DemangleFunction(classFunctionType, true,  m_backrefList, ProtectedFunctionClass | StaticThunkFunctionClass), ProtectedAccess, ThunkScope  }; break;
	case 'Q': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PublicFunctionClass),                               PublicAccess,    NoScope     }; break;
	case 'R': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PublicFunctionClass),                               PublicAccess,    NoScope     }; break;
	case 'S': context = {DemangleFunction(classFunctionType, false, m_backrefList, PublicFunctionClass | StaticFunctionClass),         PublicAccess,    StaticScope }; break;
	case 'T': context = {DemangleFunction(classFunctionType, false, m_backrefList, PublicFunctionClass | StaticFunctionClass),         PublicAccess,    StaticScope }; break;
	case 'U': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PublicFunctionClass | VirtualFunctionClass),        PublicAccess,    VirtualScope}; break;
	case 'V': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PublicFunctionClass | VirtualFunctionClass),        PublicAccess,    VirtualScope}; break;
	case 'W': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PublicFunctionClass | StaticThunkFunctionClass),    PublicAccess,    ThunkScope  }; break;
	case 'X': context = {DemangleFunction(classFunctionType, true,  m_backrefList, PublicFunctionClass | StaticThunkFunctionClass),    PublicAccess,    ThunkScope  }; break;
	case 'Y': context = {DemangleFunction(classFunctionType, false, m_backrefList, GlobalFunctionClass),                               NoAccess,        NoScope     }; break;
	case 'Z': context = {DemangleFunction(classFunctionType, false, m_backrefList, GlobalFunctionClass),                               NoAccess,        NoScope     }; break;
	case '$':
	{
		int funcClass = VirtualThunkFunctionClass;
		if (reader.Peek() == 'R')
		{
			reader.Consume();
			funcClass |= VirtualThunkExFunctionClass;
		}
		char thunkType = reader.Read();
		switch (thunkType)
		{
		case '0': context = {DemangleFunction(classFunctionType, true, m_backrefList, funcClass | VirtualFunctionClass | PrivateFunctionClass),   PrivateAccess,   ThunkScope}; break;
		case '1': context = {DemangleFunction(classFunctionType, true, m_backrefList, funcClass | VirtualFunctionClass | PrivateFunctionClass),   PrivateAccess,   ThunkScope}; break;
		case '2': context = {DemangleFunction(classFunctionType, true, m_backrefList, funcClass | VirtualFunctionClass | ProtectedFunctionClass), ProtectedAccess, ThunkScope}; break;
		case '3': context = {DemangleFunction(classFunctionType, true, m_backrefList, funcClass | VirtualFunctionClass | ProtectedFunctionClass), ProtectedAccess, ThunkScope}; break;
		case '4': context = {DemangleFunction(classFunctionType, true, m_backrefList, funcClass | VirtualFunctionClass | PublicFunctionClass),    PublicAccess,    ThunkScope}; break;
		case '5': context = {DemangleFunction(classFunctionType, true, m_backrefList, funcClass | VirtualFunctionClass | PublicFunctionClass),    PublicAccess,    ThunkScope}; break;
		default: throw DemangleException("Unknown virtual thunk type " + string(1, thunkType));
		}
		break;
	}
	default:  throw DemangleException("Unknown function type " + string(1, funcType));
	}
	return context;
}

bool Demangle::DemangleMS(Architecture* arch, const string& mangledName, Ref<Type>& outType,
                          QualifiedName& outVarName, const Ref<BinaryView>& view)
{
	outType = nullptr;
	if (mangledName.empty() || (mangledName[0] != '?' && mangledName[0] != '.'))
		return false;
	return DemangleMS(arch, mangledName, outType, outVarName);
}

bool Demangle::DemangleMS(Architecture* arch, const string& mangledName, Ref<Type>& outType,
                          QualifiedName& outVarName, BinaryView* view)
{
	outType = nullptr;
	if (mangledName.empty() || (mangledName[0] != '?' && mangledName[0] != '.'))
		return false;
	return DemangleMS(arch, mangledName, outType, outVarName);
}

bool Demangle::DemangleMS(Architecture* arch, const string& mangledName, Ref<Type>& outType,
                          QualifiedName& outVarName)
{
	outType = nullptr;
	if (mangledName.empty() || (mangledName[0] != '?' && mangledName[0] != '.'))
		return false;
	try
	{
		Demangle demangle(arch, mangledName);
		// For now we're throwing away MemberScope and MemberAccess
		outType = demangle.DemangleSymbol().type.Finalize();
		outVarName = demangle.GetVarName();

	}
	catch (DemangleException &e)
	{
		LogDebug("Demangling Failed '%s' '%s;", mangledName.c_str(), e.what());
		return false;
	}
	return true;
}


bool Demangle::DemangleMS(const string& mangledName, Ref<Type>& outType,
                          QualifiedName& outVarName, const Ref<BinaryView>& view)
{
	outType = nullptr;
	if (mangledName.empty() || (mangledName[0] != '?' && mangledName[0] != '.'))
		return false;
	try
	{
		Demangle demangle(view, mangledName);
		// For now we're throwing away MemberScope and MemberAccess
		outType = demangle.DemangleSymbol().type.Finalize();
		outVarName = demangle.GetVarName();

	}
	catch (DemangleException &e)
	{
		LogDebug("Demangling Failed '%s' '%s;", mangledName.c_str(), e.what());
		return false;
	}
	return true;
}


class MSDemangler: public Demangler
{
public:
	MSDemangler(): Demangler("MS")
	{
	}
	~MSDemangler() override {}

	virtual bool IsMangledString(const string& name) override
	{
		return name[0] == '?';
	}

	virtual bool Demangle(Ref<Architecture> arch, const string& name, Ref<Type>& outType, QualifiedName& outVarName,
	                      Ref<BinaryView> view) override
	{
		if (view)
			return Demangle::DemangleMS(arch, name, outType, outVarName, view);
		return Demangle::DemangleMS(arch, name, outType, outVarName);
	}
};


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_EDITION
	bool DemangleMSVCPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		static MSDemangler* demangler = new MSDemangler();
		Demangler::Register(demangler);
		return true;
	}
}
