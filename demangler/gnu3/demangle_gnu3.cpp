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

#include "demangle_gnu3.h"
#include <stdarg.h>
#include <algorithm>
#include <memory>


#ifdef BINARYNINJACORE_LIBRARY
using namespace BinaryNinjaCore;
#define GetClass GetTypeClass
#else
using namespace BinaryNinja;
using namespace std;
#endif


#define MAX_DEMANGLE_LENGTH    4096
#define hash(x,y) (64 * x + y)

#undef GNUDEMANGLE_DEBUG
#ifdef GNUDEMANGLE_DEBUG  // This makes it not thread safe!
static string _indent = "";
#define indent() _indent += " ";
#define dedent() do {if (_indent.size() > 0) _indent = _indent.substr(1);}while(0);

void MyLogDebug(string fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(0, DebugLog, (_indent + fmt).c_str(), args);
	va_end(args);
}
#else
#define indent()
#define dedent()
void MyLogDebug(string fmt, ...)
{ (void)fmt; }
#endif

static inline void rtrim(string &s)
{
	s.erase(find_if(s.rbegin(), s.rend(), [](int c) { return !isspace(c); }).base(), s.end());
}


static string GetTemplateString(vector<FunctionParameter> args)
{
	string name = "<";
	for (size_t i = 0; i < args.size(); i++)
	{
		if (i != 0)
		{
			name += ", ";
		}

		name += args[i].name;
	}
	rtrim(name);
	if (name.back() == '>')
		name += " "; //Be c++03 compliant where we can
	name += ">";
	return name;
}


static void ExtendTypeName(TypeBuilder& type, const string& extend)
{
	QualifiedName qn = type.GetTypeName();
	if (qn.StringSize() + extend.size() > MAX_DEMANGLE_LENGTH)
		throw DemangleException("Detected adversarial mangled string");
	if (qn.size() > 0)
		qn.back() += extend;
	else
		qn.push_back(extend);

	// This type might not be an NTR (Vector35/binaryninja-api#6261)
	if (type.GetClass() == NamedTypeReferenceClass)
	{
		type.SetNamedTypeReference(
			NamedTypeReference::GenerateAutoDemangledTypeReference(type.GetNamedTypeReference()->GetTypeReferenceClass(), qn)
		);
	}
}


static TypeBuilder CreateUnknownType(const QualifiedName& s)
{
	return TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(UnknownNamedTypeClass, s));
}


static TypeBuilder CreateUnknownType(const string& s)
{
	return TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(UnknownNamedTypeClass, {s}));
}

DemangleGNU3::Reader::Reader(const string& data): m_data(data), m_offset(0)
{}


string DemangleGNU3::Reader::PeekString(size_t count)
{
	if (count > Length())
		return "\0";
	return m_data.substr(m_offset, count);
}


char DemangleGNU3::Reader::Peek()
{
	if (1 > Length())
		return '\0';
	return (char)m_data[m_offset];
}


bool DemangleGNU3::Reader::NextIsOneOf(const string& list)
{
	char elm = Peek();
	for (auto a : list)
	{
		if (a == elm)
			return true;
	}
	return false;
}


string DemangleGNU3::Reader::GetRaw()
{
	return m_data.substr(m_offset);
}


char DemangleGNU3::Reader::Read()
{
	if (1 > Length())
		throw DemangleException();
	return m_data[m_offset++];
}


string DemangleGNU3::Reader::ReadString(size_t count)
{
	if (count > Length())
		throw DemangleException();

	const string out = m_data.substr(m_offset, count);
	m_offset += count;
	return out;
}


string DemangleGNU3::Reader::ReadUntil(char sentinal)
{
	size_t pos = m_data.find_first_of(sentinal, m_offset);
	if (pos == string::npos)
		throw DemangleException();
	return ReadString(pos);
}


void DemangleGNU3::Reader::UnRead(size_t count)
{
	if (count <= m_offset)
		m_offset -= count;
}


void DemangleGNU3::Reader::Consume(size_t count)
{
	if (count > Length())
		throw DemangleException();
	m_offset += count;
}


size_t DemangleGNU3::Reader::Length() const
{
	return m_data.length() - m_offset;
}


DemangleGNU3::DemangleGNU3(Architecture* arch, const string& mangledName) :
	m_reader(mangledName),
	m_arch(arch),
	m_isParameter(false),
	m_shouldDeleteReader(true),
	m_topLevel(true),
	m_isOperatorOverload(false)
{
	MyLogDebug("%s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
}


void DemangleGNU3::PushTemplateType(TypeBuilder type)
{
	m_templateSubstitute.push_back(type);
}


const TypeBuilder& DemangleGNU3::GetTemplateType(size_t ref)
{
	if (ref >= m_templateSubstitute.size())
	{
		// PrintTables();
		throw DemangleException();
	}
	return m_templateSubstitute[ref];
}


void DemangleGNU3::PushType(TypeBuilder type)
{
	m_substitute.push_back(type);
}


const TypeBuilder& DemangleGNU3::GetType(size_t ref)
{
	if (ref >= m_substitute.size())
	{
		// PrintTables();
		throw DemangleException();
	}
	return m_substitute[ref];
}


void DemangleGNU3::PrintTables()
{
	LogDebug("Substitution Table\n");
	for (int i = 0; (size_t)i < m_substitute.size(); i++)
	{
		LogDebug("[%d] %s\n", i-1, GetType(i).GetString().c_str());
	}

	LogDebug("Template Table\n");
	for (int i = 0; (size_t)i < m_templateSubstitute.size(); i++)
	{
		LogDebug("[%d] %s\n", i-1, GetTemplateType(i).GetString().c_str());
	}
}


void DemangleGNU3::DemangleCVQualifiers(bool& cnst, bool& vltl, bool& rstrct)
{
	cnst = false; vltl = false; rstrct = false;
	//[<cv-qualifier>]
	while (1)
	{
		switch (m_reader.Peek())
		{
		case 'r': rstrct = true; break;
		case 'V': vltl = true; break;
		case 'K': cnst = true; break;
		default: return;
		}
		m_reader.Consume(1);
	}
}


string DemangleGNU3::DemangleSourceName()
{
	indent();
	MyLogDebug("%s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	m_lastName = m_reader.ReadString(DemangleNumber());
	dedent();
	return m_lastName;
}


TypeBuilder DemangleGNU3::DemangleFunction(bool cnst, bool vltl)
{
	indent();
	MyLogDebug("%s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	bool old_isparam;
	if (m_reader.Peek() == 'Y')
	{
		// TODO: This function is external, should we do anything with that info?
		m_reader.Consume();
	}

	TypeBuilder retType = DemangleType();

	vector<FunctionParameter> params;
	old_isparam = m_isParameter;
	m_isParameter = true;
	m_functionSubstitute.push_back({});
	int i = 0;
	while (m_reader.Peek() != 'E')
	{
		TypeBuilder param = DemangleType();
		if (param.GetClass() == VoidTypeClass)
			continue;
		MyLogDebug("Var_%d - %s\n", i++, param.GetString().c_str());
		m_functionSubstitute.back().push_back(param);
		params.push_back({"", param.Finalize(), true, Variable()});
	}
	m_reader.Consume();
	m_functionSubstitute.pop_back();
	m_isParameter = old_isparam;
	TypeBuilder newType = TypeBuilder::FunctionType(retType.Finalize(), nullptr, params);
	PushType(newType);

	newType.SetConst(cnst);
	newType.SetVolatile(vltl);

	if (cnst || vltl)
		PushType(newType);
	MyLogDebug("After %s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	dedent();
	return newType;
}


const TypeBuilder& DemangleGNU3::DemangleTemplateSubstitution()
{
	indent();
	MyLogDebug("%s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	size_t number = 0;
	char elm = m_reader.Peek();
	if (elm == '_')
	{
		number = 0;
	}
	else if (isdigit(elm))
	{
		m_reader.Consume();
		number = elm - '0' + 1;
	}
	else if (isupper(elm))
	{
		m_reader.Consume();
		number = elm - 'A' + 11;
	}
	else
	{
		throw DemangleException();
	}

	if (m_reader.Read() != '_')
	{
		throw DemangleException();
	}
	dedent();
	return GetTemplateType(number);
}


TypeBuilder DemangleGNU3::DemangleType()
{
	indent();
	MyLogDebug("%s : %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	TypeBuilder type;
	bool cnst = false, vltl = false, rstrct = false;
	bool substitute = false;
	QualifiedName name;

	DemangleCVQualifiers(cnst, vltl, rstrct);

	if (cnst || vltl || rstrct)
	{
		type = DemangleType();
		if (cnst)
			type.SetConst(true);
		if (vltl)
			type.SetVolatile(true);
		if (rstrct)
			type.SetPointerSuffix({RestrictSuffix});
		PushType(type);
		return type;
	}

	switch(m_reader.Read())
	{
	case 'S':
	{
		if (isdigit(m_reader.Peek()) || m_reader.Peek() == '_' || isupper(m_reader.Peek()))
		{
			type = DemangleSubstitution();
			if (m_reader.Peek() == 'I')
			{
				m_reader.Consume();
				vector<FunctionParameter> args;
				DemangleTemplateArgs(args);
				ExtendTypeName(type, GetTemplateString(args));
				type.SetHasTemplateArguments(true);
				substitute = true;
			}
		}
		else
		{
			if (m_reader.Peek() == 't')
			{
				m_reader.Consume(1);
				type = DemangleUnqualifiedName();
				QualifiedName qn = type.GetTypeName();
				qn.insert(qn.begin(), "std");
				type.SetTypeName(qn);
				substitute = true;
			}
			else
			{
				type = DemangleSubstitution();
			}
			if (m_reader.Peek() == 'I')
			{
				m_reader.Consume();
				if (substitute)
					PushType(type);
				vector<FunctionParameter> args;
				DemangleTemplateArgs(args);
				ExtendTypeName(type, GetTemplateString(args));
				type.SetHasTemplateArguments(true);
				substitute = true;
			}
		}
		break;
	}
	case 'T':
	{
		/*  <class-enum-type> ::= <name>     # non-dependent type name, dependent type name, or dependent typename-specifier
		                      ::= Ts <name>  # dependent elaborated type specifier using 'struct' or 'class'
		                      ::= Tu <name>  # dependent elaborated type specifier using 'union'
		                      ::= Te <name>  # dependent elaborated type specifier using 'enum'
		*/
		if (m_reader.Peek() == 's')
		{
			m_reader.Consume();
			type = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
				StructNamedTypeClass, {DemangleSourceName()}));
			break;
		}
		else if (m_reader.Peek() == 'u')
		{
			m_reader.Consume();
			type = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
				UnionNamedTypeClass, {DemangleSourceName()}));
			break;
		}
		else if (m_reader.Peek() == 'e')
		{
			m_reader.Consume();
			type = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
				EnumNamedTypeClass, {DemangleSourceName()}),
				m_arch->GetDefaultIntegerSize(), m_arch->GetDefaultIntegerSize());
			break;
		}

		//Template Substitution
		type = DemangleTemplateSubstitution();
		substitute = true;
		if (m_reader.Peek() == 'I')
		{
			m_reader.Consume();
			if (substitute)
				PushType(type);
			vector<FunctionParameter> args;
			DemangleTemplateArgs(args);
			ExtendTypeName(type, GetTemplateString(args));
			type.SetHasTemplateArguments(true);
		}
		break;
	}
	case 'P':
		type = TypeBuilder::PointerType(m_arch, DemangleType().Finalize(), cnst, vltl, PointerReferenceType);
		substitute = true;
		break;
	case 'R':
		type = TypeBuilder::PointerType(m_arch, DemangleType().Finalize(), cnst, vltl, ReferenceReferenceType);
		substitute = true;
		break;
	case 'O':
		type = TypeBuilder::PointerType(m_arch, DemangleType().Finalize(), cnst, vltl, RValueReferenceType);
		substitute = true;
		break;
	case 'C': //TODO:complex
	case 'G': //TODO:imaginary
	case 'U': //TODO:vendor extended type
		throw DemangleException();
	case 'v': type = TypeBuilder::VoidType(); break;
	case 'w': type = TypeBuilder::IntegerType(4, false, "wchar_t"); break; //TODO: verify
	case 'b': type = TypeBuilder::BoolType(); break;
	case 'c': type = TypeBuilder::IntegerType(1, true); break;
	case 'a': type = TypeBuilder::IntegerType(1, true); break;
	case 'h': type = TypeBuilder::IntegerType(1, false); break;
	case 's': type = TypeBuilder::IntegerType(2, true); break;
	case 't': type = TypeBuilder::IntegerType(2, false); break;
	case 'i': type = TypeBuilder::IntegerType(4, true); break;
	case 'j': type = TypeBuilder::IntegerType(4, false); break;
	case 'l': type = TypeBuilder::IntegerType(m_arch->GetAddressSize(), true); break; //long
	case 'm': type = TypeBuilder::IntegerType(m_arch->GetAddressSize(), false); break; //ulong
	case 'x': type = TypeBuilder::IntegerType(8, true); break;
	case 'y': type = TypeBuilder::IntegerType(8, false); break;
	case 'n': type = TypeBuilder::IntegerType(16, true); break;
	case 'o': type = TypeBuilder::IntegerType(16, false); break;
	case 'f': type = TypeBuilder::FloatType(4); break;
	case 'd': type = TypeBuilder::FloatType(8); break;
	case 'e': type = TypeBuilder::FloatType(10); break;
	case 'g': type = TypeBuilder::FloatType(16); break;
	case 'z': type = TypeBuilder::VarArgsType(); break;
	case 'M': // TODO: Make into pointer to function member
	{
		TypeBuilder name = DemangleType();
		TypeBuilder member = DemangleType();
		string fullName = member.GetStringBeforeName() + "(" + name.GetString() + "::*)" + member.GetStringAfterName();
		//member.SetScope(NonStaticScope);
		//TypeBuilder ptr = TypeBuilder::PointerType(m_arch, member, cnst, vltl);
		//QualifiedName qn({name.GetString(), "*"});
		type = CreateUnknownType(fullName);
		break;
	}
	case 'F': type = DemangleFunction(cnst, vltl); break;
	case 'D':
		switch (m_reader.Read())
		{
		case 'd': type = TypeBuilder::FloatType(8); break;
		case 'e': type = TypeBuilder::FloatType(16); break;
		case 'f': type = TypeBuilder::FloatType(4); break;
		case 'h': type = TypeBuilder::FloatType(2); break;
		case 'i': type = TypeBuilder::IntegerType(4, true, "char32_t"); break;
		case 's': type = TypeBuilder::IntegerType(2, true, "char16_t"); break;
		case 'a': type = CreateUnknownType("auto"); break; //auto type
		case 'c': type = CreateUnknownType("decltype(auto)"); break; //decltype(auto)
		case 'n':
		{
			static const QualifiedName stdNullptrTName(vector<string>{"std", "nullptr_t"});
			type = CreateUnknownType(stdNullptrTName);
			break;
		}
		case 'p': type = DemangleType(); break;
		case 't':
		case 'T':
			type = CreateUnknownType(DemangleExpression());
			if (m_reader.Read() != 'E')
				throw DemangleException();
			break;
		case 'v':
		{
			// vector of size
			uint64_t size = DemangleNumber();
			if (m_reader.Read() != '_')
				throw DemangleException();
			type = TypeBuilder::ArrayType(DemangleType().Finalize(), size);
			break;
		}
		default:
			MyLogDebug("Unsupported type: %s:'%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
			throw DemangleException();
		}
		break;
	case 'N':
		type = DemangleNestedName();
		substitute = true;
		break;
	case 'A':
		//  <array-type> ::= A <positive dimension number> _ <element type>
		//               ::= A [<dimension expression>] _ <element type>
		if (isdigit(m_reader.Peek()))
		{
			//<positive dimension number> _ <element type>
			uint64_t size = DemangleNumber();
			if (m_reader.Read() != '_')
				throw DemangleException();
			type = TypeBuilder::ArrayType(DemangleType().Finalize(), size);
		}
		else
		{
			//[<dimension expression>] _ <element type>
			//Since our type system doesn't support expressions as dimensions
			//we instead demangle this as just a string.
			string dimension = "[]";
			if (m_reader.Peek() != '_')
			{
				dimension = "[" + DemangleExpression() + "]";
			}
			if (m_reader.Read() != '_')
				throw DemangleException();

			const string typeString = DemangleType().GetString() + dimension;
			type = CreateUnknownType(typeString);
		}
		substitute = true;
		break;
	default:
	{
		m_reader.UnRead();

		type = DemangleName();
		auto nameList = type.GetTypeName();
		if (nameList.size() < 1)
			throw DemangleException();
		m_lastName = nameList.back();
		substitute = true;

		if (m_reader.Peek() == 'I')
		{
			substitute = false;
			m_reader.Consume();
			PushType(type);
			vector<FunctionParameter> args;
			DemangleTemplateArgs(args);
			ExtendTypeName(type, GetTemplateString(args));
			type.SetHasTemplateArguments(true);
			PushType(type);
		}
	}
	}

	if (substitute)
		PushType(type);

	dedent();
	return type;
}


TypeBuilder DemangleGNU3::DemangleSubstitution()
{
	static const QualifiedName stdAllocatorName(vector<string>{"std", "allocator"});
	static const QualifiedName stdBasicStringName(vector<string>{"std", "basic_string"});
	static const QualifiedName stdIostreamName(vector<string>{"std", "iostream"});
	static const QualifiedName stdIstreamName(vector<string>{"std", "istream"});
	static const QualifiedName stdOstreamName(vector<string>{"std", "ostream"});
	static const QualifiedName stdStringName(vector<string>{"std", "string"});
	static const QualifiedName stdName(vector<string>{"std"});

	indent()
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	char elm;
	elm = m_reader.Read();
	QualifiedName name;
	size_t number = 0;
	switch (elm)
	{
	case 'a': name = stdAllocatorName; break;
	case 'b': name = stdBasicStringName; break;
	case 'd': name = stdIostreamName; break;
	case 'i': name = stdIstreamName; break;
	case 'o': name = stdOstreamName; break;
	case 's': name = stdStringName; break;
	case 't': name = stdName; break;
	default:
		if (elm == '_')
		{
			m_reader.UnRead(1);
			number = 0;
		}
		else if (isdigit(elm))
		{
			number = elm - '0' + 1;
		}
		else if (isupper(elm))
		{
			number = elm - 'A' + 11;
		}
		else
		{
			// PrintTables();
			throw DemangleException();
		}

		if (m_reader.Read() != '_')
		{
			throw DemangleException();
		}

		dedent();
		return GetType(number);
	}
	m_lastName = name.back();
	dedent();
	return CreateUnknownType(name);
}

string DemangleGNU3::DemangleNumberAsString()
{
	bool negativeFactor = false;
	if ( m_reader.Peek() == 'n')
	{
		negativeFactor = true;
		m_reader.Consume();
	}

	string number;
	while (isdigit(m_reader.Peek()))
	{
		number += m_reader.ReadString(1);
	}
	return (negativeFactor?"-":"") + number;
}

// number ::= [n] <decimal>
int64_t DemangleGNU3::DemangleNumber()
{
	return std::stol(DemangleNumberAsString().c_str());
}


string DemangleGNU3::DemangleInitializer()
{
	string out;
	if (m_reader.ReadString(2) != "pi")
		throw DemangleException();
	out += "(";
	while (m_reader.Peek() != 'E')
		out += DemangleExpression();
	m_reader.Consume();
	out += ")";
	return out;
}

static int8_t HexToDec(char c)
{
	if (isdigit(c))
	{
		return c - '0';
	}
	else if(islower(c) && c <= 'f')
	{
		return c - 'a' + 10;
	}
	return -1;
}

string DemangleGNU3::DemanglePrimaryExpression()
{
	indent();
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	char elm1 = '\0';
	string out;
	QualifiedName tmpList;
	string valueString;
	float f; double d; long double ld;
	bool oldTopLevel;
	//expr-primary
	if (m_reader.PeekString(2) == "_Z")
	{
		m_reader.Consume(2);
		oldTopLevel = m_topLevel;
		m_topLevel = false;
		TypeBuilder t = DemangleSymbol(tmpList);
		m_topLevel = oldTopLevel;
		out += t.GetStringBeforeName();
		out += tmpList.GetString();
		out += t.GetStringAfterName();
		dedent()
		return out;
	}
	switch (m_reader.Read())
	{
	case 'b':
		elm1 = m_reader.Read();
		if (elm1 == '0')
			out += "false";
		else if (elm1 == '1')
			out += "true";
		else
			throw DemangleException();
		break;
	case 'd': //double
		valueString = m_reader.ReadString(8);

		for (size_t i = 0; i < valueString.size(); i+=2)
		{
			((unsigned char*)&d)[i/2] = (HexToDec(valueString[i]) << 16) + HexToDec(valueString[i+1]);
		}
		out += to_string(d);
		break;
	case 'e': //long double
		valueString = m_reader.ReadString(10);

		for (size_t i = 0; i < valueString.size(); i+=2)
		{
			((unsigned char*)&ld)[i/2] = (HexToDec(valueString[i]) << 16) + HexToDec(valueString[i+1]);
		}
		out += to_string(ld);
		break;
	case 'f': //float
		valueString = m_reader.ReadString(4);

		for (size_t i = 0; i < valueString.size(); i+=2)
		{
			((unsigned char*)&f)[i/2] = (HexToDec(valueString[i]) << 16) + HexToDec(valueString[i+1]);
		}
		out += to_string(f);
		break;
	case 'g': //float_128
		valueString = m_reader.ReadString(16); //We read 16 but then just throw away

		for (size_t i = 0; i < 10; i+=2)
		{
			((unsigned char*)&ld)[i/2] = (HexToDec(valueString[i]) << 16) + HexToDec(valueString[i+1]);
		}
		out += to_string(ld);
		break;
	case 'l': out = DemangleNumberAsString() + "l"; break;  //long
	case 'x': out = DemangleNumberAsString() + "ll"; break;  //long long
	case 's': out = "(short)" + DemangleNumberAsString(); break; //short
	case 'n': out = "(__uint128)" + DemangleNumberAsString() + "ull"; break;  //__int128
	case 'i': out = DemangleNumberAsString(); break;       // int
	case 'm': out = DemangleNumberAsString() + "ul"; break;  //unsigned long
	case 't': out = "(unsigned short)" + DemangleNumberAsString(); break; //unsigned short
	case 'y': out = DemangleNumberAsString() + "ull"; break;  //unsigned long long
	case 'j': out = DemangleNumberAsString() + "u"; break; // unsigned int
		break;
	default:
		m_reader.UnRead(1);
		out = "(" + DemangleTypeString() + ")" + DemangleNumberAsString();
		break;
	}
	if (m_reader.Read() != 'E')
		throw DemangleException();

	dedent();
	return out;
}


string DemangleGNU3::DemangleUnarySuffixExpression(const string& op)
{
	return "(" + DemangleExpression() + ")" + op;
}


string DemangleGNU3::DemangleUnaryPrefixExpression(const string& op)
{
	return op + "(" + DemangleExpression() + ")";
}


string DemangleGNU3::DemangleBinaryExpression(const string& op)
{
	indent();
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	const string lhs = "(" + DemangleExpression() + ")";
	const string rhs = "(" + DemangleExpression() + ")";
	dedent();
	if (op == ".")
		return lhs + op + rhs;
	return lhs + " " + op + " " + rhs;
}


string DemangleGNU3::DemangleUnaryPrefixType(const string& op)
{
	return op + "(" + DemangleTypeString() + ")";
}


string DemangleGNU3::DemangleTypeString()
{
	return DemangleType().GetString();
}


string DemangleGNU3::DemangleExpressionList()
{
	indent();
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	string expr;
	bool first = true;
	m_functionSubstitute.push_back({});
	while (m_reader.Peek() != 'E')
	{
		if (!first)
			expr += ", ";
		const string e = DemangleExpression();
		expr += e;
		m_functionSubstitute.back().push_back(CreateUnknownType(e));
		first = false;
	}
	m_functionSubstitute.pop_back();
	m_reader.Consume();
	dedent();
	return expr;
}

static string GetOperator(char elm1, char elm2)
{
	switch (hash(elm1, elm2))
	{
	case hash('d','c'): return "dynamic_cast";
	case hash('s','c'): return "static_cast";
	case hash('c','c'): return "const_cast";
	case hash('r','c'): return "reinterpret_cast";
	case hash('t','i'): return "typeid";
	case hash('t','e'): return "typeid";
	case hash('s','t'): return "sizeof";
	case hash('s','z'): return "sizeof";
	case hash('a','t'): return "alignof";
	case hash('a','z'): return "alignof";
	case hash('n','x'): return "noexcept";
	case hash('s','Z'): return "sizeof...";
	case hash('s','P'): return "sizeof...";
	case hash('s','p'): return "";
	case hash('t','w'): return "throw";
	case hash('t','r'): return "throw";
	case hash('l','s'): return "<<";  // <<
	case hash('r','s'): return ">>";  // >>
	case hash('a','S'): return "=";   // =
	case hash('n','t'): return "!";   // !
	case hash('e','q'): return "==";  // ==
	case hash('n','e'): return "!=";  // !=
	case hash('i','x'): return "[]";  // []
	case hash('d','t'): return ".";   // .
	case hash('p','t'): return "->";  // ->
	case hash('m','l'): return "*";   // *
	case hash('p','p'): return "++";  // ++ (postfix in <expression> context)
	case hash('m','m'): return "--";  // -- (postfix in <expression> context)
	case hash('n','g'): return "-";   // - (unary)
	case hash('m','i'): return "-";   // -
	case hash('p','s'): return "+";   // + (unary)
	case hash('p','l'): return "+";   // +
	case hash('a','d'): return "&";   // & (unary)
	case hash('a','n'): return "&";   // &
	case hash('p','m'): return "->*"; // ->*
	case hash('d','v'): return "/";   // /
	case hash('r','m'): return "%";   // %
	case hash('l','t'): return "<";   // <
	case hash('l','e'): return "<=";  // <=
	case hash('g','t'): return ">";   // >
	case hash('g','e'): return ">=";  // >=
	case hash('c','m'): return ",";   // ,
	case hash('c','l'): return "()";  // ()
	case hash('c','o'): return "~";   // ~
	case hash('e','o'): return "^";   // ^
	case hash('o','r'): return "|";   // |
	case hash('a','a'): return "&&";  // &&
	case hash('o','o'): return "||";  // ||
	case hash('d','e'): return "*";   // * (unary)
	case hash('m','L'): return "*=";  // *=
	case hash('p','L'): return "+=";  // +=
	case hash('m','I'): return "-=";  // -=
	case hash('d','V'): return "/=";  // /=
	case hash('r','M'): return "%=";  // %=
	case hash('r','S'): return ">>="; // >>=
	case hash('l','S'): return "<<="; // <<=
	case hash('a','N'): return "&=";  // &=
	case hash('o','R'): return "|=";  // |=
	case hash('e','O'): return "^=";  // ^=
	case hash('d','l'): return "delete";   // delete
	case hash('d','a'): return "delete[]"; // delete[]
	case hash('n','w'): return "new";      // new
	case hash('n','a'): return "new[]";    // new []
	default: return "";
	}
}

static BNNameType GetNameType(char elm1, char elm2)
{
	switch (hash(elm1, elm2))
	{
	case hash('n','t'): return OperatorNotNameType;              // !
	case hash('n','g'): return OperatorMinusNameType;       // - (unary)
	case hash('p','s'): return OperatorPlusNameType;        // + (unary)
	case hash('a','d'): return OperatorBitAndNameType;      // & (unary)
	case hash('d','e'): return OperatorStarNameType;        // * (unary)
	case hash('i','x'): return OperatorArrayNameType;            // []
	case hash('p','p'): return OperatorIncrementNameType;        // ++ (postfix in <expression> context)
	case hash('m','m'): return OperatorDecrementNameType;        // -- (postfix in <expression> context)
	case hash('l','s'): return OperatorLeftShiftNameType;        // <<
	case hash('r','s'): return OperatorRightShiftNameType;       // >>
	case hash('a','S'): return OperatorAssignNameType;           // =
	case hash('e','q'): return OperatorEqualNameType;            // ==
	case hash('n','e'): return OperatorNotEqualNameType;         // !=
	case hash('p','t'): return OperatorArrowNameType;            // ->
	case hash('m','l'): return OperatorStarNameType;             // *
	case hash('m','i'): return OperatorMinusNameType;            // -
	case hash('p','l'): return OperatorPlusNameType;             // +
	case hash('a','n'): return OperatorBitAndNameType;           // &
	case hash('p','m'): return OperatorArrowStarNameType;        // ->*
	case hash('d','v'): return OperatorDivideNameType;           // /
	case hash('r','m'): return OperatorModulusNameType;          // %
	case hash('l','t'): return OperatorLessThanNameType;         // <
	case hash('l','e'): return OperatorLessThanEqualNameType;    // <=
	case hash('g','t'): return OperatorGreaterThanNameType;      // >
	case hash('g','e'): return OperatorGreaterThanEqualNameType; // >=
	case hash('c','m'): return OperatorCommaNameType;           // ,
	case hash('c','l'): return OperatorParenthesesNameType;     // ()
	case hash('c','o'): return OperatorTildeNameType;           // ~
	case hash('e','o'): return OperatorXorNameType;             // ^
	case hash('o','r'): return OperatorBitOrNameType;           // |
	case hash('a','a'): return OperatorLogicalAndNameType;      // &&
	case hash('o','o'): return OperatorLogicalOrNameType;       // ||
	case hash('m','L'): return OperatorStarEqualNameType;       // *=
	case hash('p','L'): return OperatorPlusEqualNameType;       // +=
	case hash('m','I'): return OperatorMinusEqualNameType;      // -=
	case hash('d','V'): return OperatorDivideEqualNameType;     // /=
	case hash('r','M'): return OperatorModulusEqualNameType;    // %=
	case hash('r','S'): return OperatorRightShiftEqualNameType; // >>=
	case hash('l','S'): return OperatorLeftShiftEqualNameType;  // <<=
	case hash('a','N'): return OperatorAndEqualNameType;        // &=
	case hash('o','R'): return OperatorOrEqualNameType;         // |=
	case hash('e','O'): return OperatorXorEqualNameType;        // ^=
	case hash('d','l'): return OperatorDeleteNameType;          // delete
	case hash('d','a'): return OperatorDeleteArrayNameType;     // delete[]
	case hash('n','w'): return OperatorNewNameType;             // new
	case hash('n','a'): return OperatorNewArrayNameType;        // new []
	case hash('C','1'): return ConstructorNameType;
	case hash('C','2'): return ConstructorNameType;
	case hash('C','3'): return ConstructorNameType;
	case hash('C','4'): return ConstructorNameType;
	case hash('C','5'): return ConstructorNameType;
	case hash('D','0'): return DestructorNameType;
	case hash('D','1'): return DestructorNameType;
	case hash('D','2'): return DestructorNameType;
	case hash('D','3'): return DestructorNameType;
	case hash('D','4'): return DestructorNameType;
	case hash('D','5'): return DestructorNameType;
	default:
		return NoNameType;
	}
}

TypeBuilder DemangleGNU3::DemangleUnqualifiedName()
{
	indent()
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());

	TypeBuilder outType;
	char elm1 = m_reader.Read();
	char elm2 = m_reader.Read();
	switch (hash(elm1, elm2))
	{
	case hash('n','t'): // !
	case hash('n','g'): // - (unary)
	case hash('p','s'): // + (unary)
	case hash('a','d'): // & (unary)
	case hash('d','e'): // * (unary)
	case hash('i','x'): // []
	case hash('p','p'): // ++ (postfix in <expression> context)
	case hash('m','m'): // -- (postfix in <expression> context)
	case hash('l','s'): // <<
	case hash('r','s'): // >>
	case hash('a','S'): // =
	case hash('e','q'): // ==
	case hash('n','e'): // !=
	case hash('p','t'): // ->
	case hash('d','t'): // .
	case hash('m','l'): // *
	case hash('m','i'): // -
	case hash('p','l'): // +
	case hash('a','n'): // &
	case hash('p','m'): // ->*
	case hash('d','v'): // /
	case hash('r','m'): // %
	case hash('l','t'): // <
	case hash('l','e'): // <=
	case hash('g','t'): // >
	case hash('g','e'): // >=
	case hash('c','m'): // ,
	case hash('c','l'): // ()
	case hash('c','o'): // ~
	case hash('e','o'): // ^
	case hash('o','r'): // |
	case hash('a','a'): // &&
	case hash('o','o'): // ||
	case hash('m','L'): // *=
	case hash('p','L'): // +=
	case hash('m','I'): // -=
	case hash('d','V'): // /=
	case hash('r','M'): // %=
	case hash('r','S'): // >>=
	case hash('l','S'): // <<=
	case hash('a','N'): // &=
	case hash('o','R'): // |=
	case hash('e','O'): // ^=
		outType = CreateUnknownType("operator" + GetOperator(elm1, elm2));
		outType.SetNameType(GetNameType(elm1, elm2));
		break;
	case hash('t','i'):
	case hash('t','e'):
	case hash('s','t'):
	case hash('s','z'):
	case hash('a','t'):
	case hash('a','z'):
	case hash('n','x'):
	case hash('s','Z'):
	case hash('s','P'):
	case hash('s','p'):
	case hash('d','l'): // delete
	case hash('d','a'): // delete[]
	case hash('n','w'): // new
	case hash('n','a'): // new []
		outType = CreateUnknownType("operator " + GetOperator(elm1, elm2));
		outType.SetNameType(GetNameType(elm1, elm2));
		break;
	case hash('v','0'):
	case hash('v','1'):
	case hash('v','2'):
	case hash('v','3'):
	case hash('v','4'):
	case hash('v','5'):
	case hash('v','6'):
	case hash('v','7'):
	case hash('v','8'):
	case hash('v','9'):
		//TODO: Unsupported vendor extended types
		throw DemangleException();
	case hash('C','1'): //Construtor
	case hash('C','2'):
	case hash('C','3'):
	case hash('C','4'):
	case hash('C','5'):
		outType = CreateUnknownType(m_lastName);
		outType.SetNameType(ConstructorNameType);
		break;
	case hash('D','0'): //Destructor
	case hash('D','1'):
	case hash('D','2'):
	case hash('D','3'):
	case hash('D','4'):
	case hash('D','5'):
		outType = CreateUnknownType("~" + m_lastName);
		outType.SetNameType(DestructorNameType);
		break;
	case hash('D','t'):
	case hash('D','T'):
		outType = CreateUnknownType(DemangleExpression());
		// if (m_reader.Read() != 'E')
		// 	throw DemangleException();
		break;
	case hash('U','l'): //Lambda
	{
		string name;
		name = "'lambda";
		vector<TypeBuilder> params;
		do
		{
			TypeBuilder param = DemangleType();
			if (param.GetClass() == VoidTypeClass)
				break;
			params.push_back(std::move(param));
		}while (m_reader.Peek() != 'E');
		m_reader.Consume();

		if (isdigit(m_reader.Peek()))
		{
			name += DemangleNumberAsString();
		}
		if (m_reader.Read() != '_')
			throw DemangleException();

		name += "'(";
		for (size_t i = 0; i < params.size(); i++)
		{
			if (i != 0)
				name += ", ";
			name += params[i].GetString();
		}
		name += ")";
		m_lastName = name;
		outType = CreateUnknownType(name);
		break;
	}
	case hash('U','t'):
	{
		string name;
		name = "'unnamed";

		if (isdigit(m_reader.Peek()))
		{
			name += DemangleNumberAsString();
		}
		name += "\'";

		if (m_reader.Read() != '_')
			throw DemangleException();

		m_lastName = name;
		outType = CreateUnknownType(name);
		break;
	}
	case hash('c','v'): //type (expression)
		outType = CreateUnknownType("operator " + DemangleType().GetString());
		break;
	default:
		m_reader.UnRead(2);
		if (isdigit(m_reader.Peek()) || m_reader.Read() == 'L')
		{
			string name = DemangleSourceName();
			if (name.size() > 11 && name.substr(0, 11) == "_GLOBAL__N_")
				name = "(anonymous namespace)";
			outType = CreateUnknownType(name);
		}
		else
		{
			throw DemangleException();
		}
	}
	dedent();
	return outType;
}


QualifiedName DemangleGNU3::DemangleBaseUnresolvedName()
{
	// <base-unresolved-name> ::= <simple-id>                                # unresolved name
	//                        ::= on <operator-name>                         # unresolved operator-function-id
	//                        ::= on <operator-name> <template-args>         # unresolved operator template-id
	//                        ::= dn <destructor-name>                       # destructor or pseudo-destructor;
	//                                                                       # e.g. ~X or ~X<N-1>

	indent()
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	QualifiedName out;
	if (m_reader.Length() > 1)
	{
		const string str = m_reader.PeekString(2);
		if (str == "on")
		{
			out.push_back(GetOperator(m_reader.Read(), m_reader.Read()));
			if (m_reader.Peek() == 'I')
			{
				m_reader.Consume();
				vector<FunctionParameter> args;
				DemangleTemplateArgs(args);
				out.back() += GetTemplateString(args);
				PushType(CreateUnknownType(out));
			}
		}
		else if (str == "dn")
		{
			string name = DemangleUnresolvedType().GetString();
			if (name.empty())
				out.push_back("~" + DemangleSourceName());
			else
				out.push_back("~" + name);
		}
		else
		{
			// <simple-id>
			out.push_back(DemangleSourceName());
			if (m_reader.Peek() == 'I')
			{
				m_reader.Consume();
				vector<FunctionParameter> args;
				DemangleTemplateArgs(args);
				out.back() += GetTemplateString(args);
			}
		}
	}
	dedent();
	return out;
}


TypeBuilder DemangleGNU3::DemangleUnresolvedType()
{
	indent();
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	//<unresolved-type> ::= <template-param> [ <template-args> ]            # T:: or T<X,Y>::
	//                  ::= <decltype>                                      # decltype(p)::
	//                  ::= <substitution>
	TypeBuilder type;
	if (m_reader.Peek() == 'T')
	{
		m_reader.Consume();
		type = DemangleTemplateSubstitution();
		if (m_reader.Peek() == 'I')
		{
			PushType(type);
			m_reader.Consume();
			vector<FunctionParameter> args;
			DemangleTemplateArgs(args);
			ExtendTypeName(type, GetTemplateString(args));
			type.SetHasTemplateArguments(true);
			PushType(type);
		}
	}
	else if (m_reader.Length() > 2 && (m_reader.PeekString(2) == "Dt" || m_reader.PeekString(2) == "DT"))
	{
		const string name = "decltype(" + DemangleExpression() + ")";
		type = CreateUnknownType(name);
	}
	else if (m_reader.Peek() == 'S')
	{
		m_reader.Consume();
		type = DemangleSubstitution();
	}
	else
	{
		throw DemangleException();
	}
	dedent();
	return type;
}


string DemangleGNU3::DemangleExpression()
{
	MyLogDebug("%s: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	/*
	<expression> ::= <unary operator-name> <expression>
	               ::= <binary operator-name> <expression> <expression>
	               ::= <ternary operator-name> <expression> <expression> <expression>
	               ::= pp_ <expression>                                     # prefix ++
	               ::= mm_ <expression>                                     # prefix --
	               ::= cl <expression>+ E                                   # expression (expr-list), call
	               ::= cv <type> <expression>                               # type (expression), conversion with one argument
	               ::= cv <type> _ <expression>* E                          # type (expr-list), conversion with other than one argument
	               ::= tl <type> <expression>* E                            # type {expr-list}, conversion with braced-init-list argument
	               ::= il <expression> E                                    # {expr-list}, braced-init-list in any other context
	               ::= [gs] nw <expression>* _ <type> E                     # new (expr-list) type
	               ::= [gs] nw <expression>* _ <type> <initializer>         # new (expr-list) type (init)
	               ::= [gs] na <expression>* _ <type> E                     # new[] (expr-list) type
	               ::= [gs] na <expression>* _ <type> <initializer>         # new[] (expr-list) type (init)
	               ::= [gs] dl <expression>                                 # delete expression
	               ::= [gs] da <expression>                                 # delete[] expression
	               ::= dc <type> <expression>                               # dynamic_cast<type> (expression)
	               ::= sc <type> <expression>                               # static_cast<type> (expression)
	               ::= cc <type> <expression>                               # const_cast<type> (expression)
	               ::= rc <type> <expression>                               # reinterpret_cast<type> (expression)
	               ::= ti <type>                                            # typeid (type)
	               ::= te <expression>                                      # typeid (expression)
	               ::= st <type>                                            # sizeof (type)
	               ::= sz <expression>                                      # sizeof (expression)
	               ::= at <type>                                            # alignof (type)
	               ::= az <expression>                                      # alignof (expression)
	               ::= nx <expression>                                      # noexcept (expression)
	               ::= <template-param>
	               ::= <function-param>
	               ::= dt <expression> <unresolved-name>                    # expr.name
	               ::= pt <expression> <unresolved-name>                    # expr->name
	               ::= ds <expression> <expression>                         # expr.*expr
	               ::= sZ <template-param>                                  # sizeof...(T), size of a template parameter pack
	               ::= sZ <function-param>                                  # sizeof...(parameter), size of a function parameter pack
	               ::= sP <template-arg>* E                                 # sizeof...(T), size of a captured template parameter pack from an alias template
	               ::= sp <expression>                                      # expression..., pack expansion
	               ::= tw <expression>                                      # throw expression
	               ::= tr                                                   # throw with no operand (rethrow)
	               ::= <unresolved-name>                                    # f(p), N::f(p), ::f(p),
	                                                                        # freestanding dependent name (e.g., T::x),
	                                                                        # objectless nonstatic member reference
	               ::= <expr-primary>
	*/
	char elm1 = '\0', elm2 = '\0';
	string gs, out;
	elm1 = m_reader.Read();
	if (elm1 == 'L')
	{
		out = DemanglePrimaryExpression();
		return out;
	}
	else if (elm1 == 'T') //<template-param>
	{
		return DemangleTemplateSubstitution().GetString();
	}

	elm2 = m_reader.Read();
	if (hash(elm1, elm2) == hash('g', 's'))
	{
		elm1 = m_reader.Read();
		elm2 = m_reader.Read();
		switch (hash(elm1, elm2))
		{
		case hash('s','r'):
		case hash('n','w'):
		case hash('n','a'):
		case hash('d','l'):
		case hash('d','a'): break;
		default:
			throw DemangleException();
		}
		gs = "::";
	}

	switch (hash(elm1, elm2))
	{
	case hash('d','c'):
	case hash('s','c'):
	case hash('c','c'):
	case hash('r','c'):
		return GetOperator(elm1, elm2) + "<" + DemangleTypeString() + ">(" + DemangleExpression() + ")";
	case hash('t','i'):
	case hash('t','e'):
	case hash('s','t'):
	case hash('s','z'):
	case hash('a','t'):
	case hash('a','z'):
	case hash('n','x'):
		return GetOperator(elm1, elm2) + "(" + DemangleTypeString() + ")";
	case hash('s','Z'):
		return GetOperator(elm1, elm2) + "(" + DemangleTypeString() + ")";
	case hash('s','P'):
	{
		vector<FunctionParameter> args;
		DemangleTemplateArgs(args);
		return "sizeof...(" + GetTemplateString(args) + ")...";
	}
	case hash('s','p'):
		return "(" + DemangleExpression() + ")...";
	case hash('t','w'):
		return GetOperator(elm1, elm2) + DemangleExpression();
	case hash('t','r'):
		return GetOperator(elm1, elm2); //rethrow
	case hash('n','t'): // !
	case hash('n','g'): // - (unary)
	case hash('p','s'): // + (unary)
	case hash('a','d'): // & (unary)
	case hash('d','e'): // * (unary)
		return DemangleUnaryPrefixExpression(GetOperator(elm1, elm2));
	case hash('i','x'): // []
	case hash('p','p'): // ++ (postfix in <expression> context)
	case hash('m','m'): // -- (postfix in <expression> context)
		return DemangleUnarySuffixExpression(GetOperator(elm1, elm2));
	case hash('l','s'): // <<
	case hash('r','s'): // >>
	case hash('a','S'): // =
	case hash('e','q'): // ==
	case hash('n','e'): // !=
	case hash('d','t'): // .
	case hash('p','t'): // ->
	case hash('m','l'): // *
	case hash('m','i'): // -
	case hash('p','l'): // +
	case hash('a','n'): // &
	case hash('p','m'): // ->*
	case hash('d','v'): // /
	case hash('r','m'): // %
	case hash('l','t'): // <
	case hash('l','e'): // <=
	case hash('g','t'): // >
	case hash('g','e'): // >=
	case hash('c','m'): // ,
	case hash('c','o'): // ~
	case hash('e','o'): // ^
	case hash('o','r'): // |
	case hash('a','a'): // &&
	case hash('o','o'): // ||
	case hash('m','L'): // *=
	case hash('p','L'): // +=
	case hash('m','I'): // -=
	case hash('d','V'): // /=
	case hash('r','M'): // %=
	case hash('r','S'): // >>=
	case hash('l','S'): // <<=
	case hash('a','N'): // &=
	case hash('o','R'): // |=
	case hash('e','O'): // ^=
		return DemangleBinaryExpression(GetOperator(elm1, elm2));
	case hash('d','l'): // delete
	case hash('d','a'): // delete[]
	case hash('n','w'): // new
	case hash('n','a'): // new []
		return gs + DemangleUnaryPrefixType(GetOperator(elm1, elm2));
	case hash('q','u'): // ternary
		return DemangleExpression() + "?" +
		       DemangleExpression() + ":" +
		       DemangleExpression();
	case hash('c','l'): // ()
		return "(" + DemangleExpressionList() + ")";
	case hash('c','v'): //type (expression)
	{
		TypeBuilder type = DemangleType();
		out = type.GetString();
		if (m_reader.Peek() == '_')
			out += " (" + DemangleExpressionList() + ")";
		else
			out += " (" + DemangleExpression() + ")";
		return out;
	}
	case hash('t','l'): //type {expression}
		return DemangleTypeString() + " {" + DemangleExpressionList() + "}";
	case hash('i', 'l'): //{expr-list}, braced-init-list in any other context
		out = DemangleExpression();
		if (m_reader.Read() != 'E')
			throw DemangleException();
		return out;
	case hash('f','p'):
	case hash('f','L'):
	{
		//<function-param> ::= fp <CV> _                         # L == 0, first parameter
		//                 ::= fp <CV> <prm-2 num> _             # L == 0, second and later parameters
		//                 ::= fL <L-1 num> p <CV> _             # L  > 0, first parameter
		//                 ::= fL <L-1 num> p <CV> <prm-2 num> _ # L  > 0, second and later parameters

		bool cnst = false, vltl = false, rstrct = false;
		TypeBuilder type;
		int64_t listNumber = 0;
		int64_t elementNum = 0;
		char elm;
		if (m_functionSubstitute.size() == 0)
			throw DemangleException();

		if (elm2 == 'L')
		{
			listNumber = DemangleNumber() + 1;
			if (listNumber < 0 ||
			    (uint64_t)listNumber >= (uint64_t)m_functionSubstitute.size() ||
			    m_reader.Read() != 'p')
				throw DemangleException();
		}
		DemangleCVQualifiers(cnst, vltl, rstrct);
		elm = m_reader.Peek();
		if (elm == '_')
		{
			m_reader.Consume(1);
			if ((size_t)elementNum >= m_functionSubstitute[listNumber].size())
			{
				throw DemangleException();
			}
			type = m_functionSubstitute[listNumber][elementNum];
		}
		else if (isdigit(elm) || isupper(elm))
		{
			elementNum = DemangleNumber() + 1;
			if (m_reader.Read() != '_' ||
			    elementNum < 0 ||
			    (size_t)elementNum >= m_functionSubstitute[listNumber].size())
			{
				throw DemangleException();
			}
			type = m_functionSubstitute[listNumber][elementNum];
		}
		else
		{
			throw DemangleException();
		}
		out = type.GetString();
		break;
	}
	case hash('s','r'):
		/*
		<unresolved-name> ::=
		                  ::=   <unresolved-type> <base-unresolved-name>                  # T::x / decltype(p)::x
		                  ::= N <unresolved-type> <unresolved-qualifier-level>+ E <base-unresolved-name>
		                                                                                    # T::N::x /decltype(p)::N::x
		                  ::=                     <unresolved-qualifier-level>+ E <base-unresolved-name>
		                                                            # A::x, N::y, A<T>::z; "gs" means leading "::"

		<unresolved-type> ::= <template-param> [ <template-args> ]            # T:: or T<X,Y>::
		                  ::= <decltype>                                      # decltype(p)::
		                  ::= <substitution>

		<unresolved-qualifier-level> ::= <simple-id>
		<base-unresolved-name> ::= <simple-id>                                # unresolved name
		                       ::= on <operator-name>                         # unresolved operator-function-id
		                       ::= on <operator-name> <template-args>         # unresolved operator template-id
		                       ::= dn <destructor-name>                       # destructor or pseudo-destructor;
		                                                                      # e.g. ~X or ~X<N-1>
		*/
		if (m_reader.Peek() == 'N')
		{
			m_reader.Consume();
			out += DemangleUnresolvedType().GetString() + "::";
			do
			{
				out += DemangleSourceName();
				PushType(TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
					UnknownNamedTypeClass, out)));
				if (m_reader.Peek() == 'I')
				{
					vector<FunctionParameter> args;
					m_reader.Consume();
					//<tmplate-args>
					DemangleTemplateArgs(args);
					out += GetTemplateString(args);
				}
				out += "::";
			}while (m_reader.Peek() != 'E');
			m_reader.Consume();

			out += DemangleBaseUnresolvedName().GetString();
			return out;
		}
		if (isdigit(m_reader.Peek()))
		{
			do
			{
				out += DemangleSourceName();
				if (m_reader.Peek() == 'I')
				{
					vector<FunctionParameter> args;
					m_reader.Consume();
					//<tmplate-args>
					DemangleTemplateArgs(args);
					out += GetTemplateString(args);
				}
				out += "::";
			}while (m_reader.Peek() != 'E');
			m_reader.Consume();
			out += DemangleBaseUnresolvedName().GetString();
			return out;
		}
		else
		{
			out += DemangleUnresolvedType().GetString() + "::";
			out += DemangleBaseUnresolvedName().GetString();
		}
		return out;
	default:
		m_reader.UnRead(2);
		out = DemangleSourceName();
		if (m_reader.Peek() == 'I')
		{
			vector<FunctionParameter> args;
			m_reader.Consume();
			//<tmplate-args>
			DemangleTemplateArgs(args);
			out += GetTemplateString(args);
		}
		break;
	}
	return out;
}


void DemangleGNU3::DemangleTemplateArgs(vector<FunctionParameter>& args)
{
	indent();
	MyLogDebug("%s:: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	TypeBuilder tmp;
	bool tmpValid = false;
	string expr;
	bool topLevel;
	const string lastName = m_lastName;
	while (m_reader.Peek() != 'E')
	{
		switch (m_reader.Read())
		{
		case 'L':
			expr = DemanglePrimaryExpression();
			args.push_back({expr, nullptr, true, Variable()});
			tmp = CreateUnknownType(expr);
			tmpValid = true;
			break;
		case 'X':
			args.push_back({DemangleExpression(), nullptr, true, Variable()});
			if (m_reader.Read() != 'E')
				throw DemangleException();
			break;
		case 'J':
			DemangleTemplateArgs(args);
			break;
		default:
			m_reader.UnRead();
			topLevel = m_topLevel;
			m_topLevel = false;
			tmp = DemangleType();
			m_topLevel = topLevel;
			args.push_back({tmp.GetString(), nullptr, true, Variable()});
			tmpValid = true;
		}
		if (m_topLevel && tmpValid)
		{
			MyLogDebug("Adding template ref: %s\n", tmp.GetString().c_str());
			PushTemplateType(tmp);
		}
	}
	m_reader.Consume();
	m_lastName = lastName;
	dedent();
	return;
}


TypeBuilder DemangleGNU3::DemangleNestedName()
{
	/*
	This can be either a qualified name like: "foo::bar::bas"
	or it can be a qualified type like: "foo::bar::bas & const" thus we return either
	a name or a type.

	<nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E
	              ::= N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <template-args> E

	<prefix> ::= <unqualified-name>                 # global class or namespace
	         ::= <prefix> <unqualified-name>        # nested class or namespace
	         ::= <template-prefix> <template-args>  # class template specialization
	         ::= <template-param>                   # template type parameter
	         ::= <decltype>                         # decltype qualifier
	         ::= <prefix> <data-member-prefix>      # initializer of a data member
	         ::= <substitution>

	<template-prefix> ::= <template unqualified-name>           # global template
	                  ::= <prefix> <template unqualified-name>  # nested template
	                  ::= <template-param>                      # template template parameter
	                  ::= <substitution>

	<unqualified-name> ::= <operator-name>
	                   ::= <ctor-dtor-name>
	                   ::= <source-name>
	                   ::= <unnamed-type-name>

	<source-name> ::= <positive length number> <identifier>
	<identifier>  ::= <unqualified source code identifier>
	*/

	indent();
	MyLogDebug("%s:: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	TypeBuilder type = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(
		UnknownNamedTypeClass, QualifiedName()));
	bool cnst = false, vltl = false, rstrct = false;
	bool ref = false;
	bool rvalueRef = false;
	bool substitute = true;
	TypeBuilder newType;
	bool base = false;
	bool isTemplate = false;
	bool hasB = false;
	//[<CV-qualifiers>]
	DemangleCVQualifiers(cnst, vltl, rstrct);

	//[<ref-qualifier>]
	if (m_reader.Peek() == 'R')
	{
		m_reader.Consume();
		ref = true;
	}
	else if (m_reader.Peek() == 'O')
	{
		m_reader.Consume();
		ref = true;
		rvalueRef = true;
	}

	while (m_reader.Peek() != 'E')
	{
		if (m_reader.Peek() == 'B')
		{
			hasB = true;
			break;
		}
		isTemplate = false;
		substitute = true;
		size_t startSize = m_templateSubstitute.size();
		switch (m_reader.Read())
		{
		case 'S': //<substitution>
			newType = DemangleSubstitution();
			substitute = false;
			break;
		case 'T': //<template-param>
			newType = DemangleTemplateSubstitution();
			break;
		case 'I': //<template-prefix> <template-args>
		{
			if (!base)
				throw DemangleException();
			vector<FunctionParameter> args;
			DemangleTemplateArgs(args);
			ExtendTypeName(type, GetTemplateString(args));
			type.SetHasTemplateArguments(true);
			isTemplate = true;
			break;
		}
		default:  //<unqualified-name> || <decltype>
			m_reader.UnRead(1);
			newType = DemangleUnqualifiedName();
			break;
		}

		base = true;
		if (!isTemplate)
		{
			type.SetNameType(newType.GetNameType());
			QualifiedName newName = type.GetTypeName() + newType.GetTypeName();
			if (newName.StringSize() > MAX_DEMANGLE_LENGTH)
				throw DemangleException("Detected adversarial mangled string");
			type.SetNamedTypeReference(
				NamedTypeReference::GenerateAutoDemangledTypeReference(type.GetNamedTypeReference()->GetTypeReferenceClass(), newName)
			);
			type.SetHasTemplateArguments(false);
		}
		if (substitute && m_reader.Peek() != 'E')
		{
			//Those template arguments were not the primary arguments so clear them from the sub listType
			while (m_templateSubstitute.size() > startSize)
			{
				m_templateSubstitute.pop_back();
			}
			PushType(type);
		}
		MyLogDebug("%s:: '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	}
	if (!hasB)
		m_reader.Consume();

	if (cnst || vltl || rstrct)
	{
		type.SetConst(cnst);
		type.SetVolatile(vltl);
		if (rstrct)
			type.AddPointerSuffix(RestrictSuffix);
	}

	if (ref)
	{
		type.AddPointerSuffix(rvalueRef?LvalueSuffix:ReferenceSuffix);
		PushType(type);
	}
	dedent();
	return type;
}


TypeBuilder DemangleGNU3::DemangleLocalName()
{
	indent();
	MyLogDebug("%s '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	TypeBuilder type;
	QualifiedName varName;
	bool oldTopLevel = m_topLevel;
	m_topLevel = false;
	type = DemangleSymbol(varName);
	m_topLevel = oldTopLevel;

	if (varName.size() > 0)
		varName.back() += (type.GetStringAfterName());
	else
		varName.push_back(type.GetString());

	if (m_reader.Peek() != 's')
	{
		//<entity name>
		TypeBuilder tmpType = DemangleName();
		type = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(UnknownNamedTypeClass, varName));
		QualifiedName newName = type.GetTypeName() + tmpType.GetTypeName();
		if (newName.StringSize() > MAX_DEMANGLE_LENGTH)
			throw DemangleException("Detected adversarial mangled string");
		type.SetTypeName(newName);
		type.SetConst(tmpType.IsConst());
		type.SetVolatile(tmpType.IsVolatile());
		type.SetPointerSuffix(tmpType.GetPointerSuffix());
	}
	else
	{
		m_reader.Consume();
		type = TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(UnknownNamedTypeClass, varName));
	}
	// [<discriminator>]
	//TODO: What do we do with discriminators?
	if (m_reader.Peek() == '_')
	{
		m_reader.Consume();
		if (m_reader.Peek() == '_')
		{
			m_reader.Consume();
			DemangleNumberAsString();
			if (m_reader.Read() != '_')
				throw DemangleException();
		}
		else
		{
			DemangleNumberAsString();
		}
	}
	dedent();
	return type;
}


TypeBuilder DemangleGNU3::DemangleName()
{
	indent();
	MyLogDebug("%s '%s'\n", __FUNCTION__, m_reader.GetRaw().c_str());
	/*
	<name> ::= <nested-name>
	       ::= <unscoped-name>
	       ::= <unscoped-template-name> <template-args>
	       ::= <local-name>	# See Scope Encoding below

	<unscoped-name> ::= <unqualified-name>
	                ::= St <unqualified-name>   # ::std::

	<unscoped-template-name> ::= <unscoped-name>
	                         ::= <substitution>
	*/
	TypeBuilder type;
	bool substitute = false;
	switch (m_reader.Read())
	{
	case 'S':
		if (m_reader.Peek() == 't')
		{
			m_reader.Consume(1);
			type = DemangleUnqualifiedName();
			QualifiedName qn = type.GetTypeName();
			qn.insert(qn.begin(), "std");
			type.SetTypeName(qn);
			substitute = true;
		}
		else
		{
			type = DemangleSubstitution();
		}

		if (m_reader.Peek() == 'I')
		{
			m_reader.Consume();
			if (substitute)
				PushType(type);
			vector<FunctionParameter> args;
			DemangleTemplateArgs(args);
			ExtendTypeName(type, GetTemplateString(args));
			type.SetHasTemplateArguments(true);
		}
		break;
	case 'N': //<nested-name>
		type = DemangleNestedName();
		break;
	case 'Z': //<local-name>
		type = DemangleLocalName();
		break;
	default: //<unscoped-name> | <substitution>
		/*
		<unscoped-name> ::= <unqualified-name>
		                ::= St <unqualified-name>   # ::std::
		<unscoped-template-name> ::= <unscoped-name>
		                         ::= <substitution>
		*/
		m_reader.UnRead();
		if (m_reader.Peek() == 'L')
			m_reader.Consume();
		type = DemangleUnqualifiedName();
		if (m_reader.Peek() == 'I')
		{
			PushType(type);
			//<unscoped-template-name>
			vector<FunctionParameter> args;
			m_reader.Consume();
			//<tmplate-args>
			DemangleTemplateArgs(args);
			LogDebug("Typename: %s", type.GetTypeName()[0].c_str());
			ExtendTypeName(type, GetTemplateString(args));
			LogDebug("Typename: %s", type.GetTypeName()[0].c_str());
			type.SetHasTemplateArguments(true);
		}
	}
	dedent();
	return type;
}


TypeBuilder DemangleGNU3::DemangleSymbol(QualifiedName& varName)
{
	indent();
	MyLogDebug("%s: %s\n", __FUNCTION__, m_reader.GetRaw().c_str());
	TypeBuilder returnType;
	bool isReturnTypeUnknown = false;
	TypeBuilder type;
	vector<FunctionParameter> params;
	bool cnst = false, vltl = false, rstrct = false;
	bool oldTopLevel;
	QualifiedName name;

	/*
	<encoding> ::= <function name> <bare-function-type>
	           ::= <data name>
	           ::= <special-name>
	*/
	//<special-name>
	switch (m_reader.Peek())
	{
	case 'G':
		m_reader.Consume();
		switch (m_reader.Read())
		{
		case 'A': //TODO hidden alias
			LogWarn("Unsupported demangle type: hidden alias\n");
			throw DemangleException();
		case 'R': //TODO reference temporaries
			LogWarn("Unsupported demangle type: reference temporary\n");
			throw DemangleException();
		case 'T': //TODO transaction clones
			LogWarn("Unsupported demangle type: transaction clone\n");
			throw DemangleException();
		case 'V':
		{
			TypeBuilder t = DemangleSymbol(name);
			varName.push_back("guard_variable_for_" + t.GetTypeAndName(name));
			type = TypeBuilder::IntegerType(1, false);
			if (m_reader.Length() == 0)
				return type;
			//function parameters
			string paramList;
			paramList += "(";
			bool first = true;
			do
			{
				if (m_reader.Peek() == 'v')
				{
					m_reader.Consume();
					break;
				}
				if (!first)
					paramList += ", ";
				paramList += DemangleTypeString();
			}while (m_reader.Peek() != 'E');
			m_reader.Consume();
			varName.back() += paramList + ")";
			varName.push_back(DemangleSourceName());
			return type;
		}
		default:
			throw DemangleException();
		}
	case 'T':
		/*
		<special-name> ::= TV <type>	# virtual table
		               ::= TT <type>	# VTT structure (construction vtable index)
		               ::= TI <type>	# typeinfo structure
		               ::= TS <type>	# typeinfo name (null-terminated byte string)
		               ::= T <call-offset> <base encoding>
		                   # base is the nominal target function of thunk
		<call-offset>  ::= h <nv-offset> _
		               ::= v <v-offset> _
		<nv-offset>    ::= <offset number> # non-virtual base override
		<v-offset>     ::= <offset number> _ <virtual offset number>
		                   # virtual base override, with vcall offset
		*/
		m_reader.Consume();
		switch (m_reader.Read())
		{
		case 'c':
			LogWarn("Unsupported: 'virtual function covariant override thunk'\n");
			throw DemangleException();
		case 'C':
		{
			TypeBuilder t = DemangleType();
			DemangleNumberAsString();
			if (m_reader.Read() != '_')
				throw DemangleException();

			return TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(UnknownNamedTypeClass,
						{"construction_vtable_for_" + DemangleTypeString() + "-in-" + t.GetString()}));
		}
		case 'D':
			LogWarn("Unsupported: 'typeinfo common proxy'\n");
			throw DemangleException();
		case 'F':
			LogWarn("Unsupported: 'typeinfo fn'\n");
			throw DemangleException();
		case 'h': //TODO: Convert to whatever the actual type is!
		{
			DemangleNumberAsString();
			if (m_reader.Read() != '_')
				throw DemangleException();
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			TypeBuilder t = DemangleSymbol(name);
			m_topLevel = oldTopLevel;
			return TypeBuilder::NamedType(
					NamedTypeReference::GenerateAutoDemangledTypeReference(UnknownNamedTypeClass,
							{"non-virtual_thunk_to_" + name.GetString() + t.GetStringAfterName()}));
		}
		case 'H':
			LogWarn("Unsupported: 'TLS init function'\n");
			throw DemangleException();
		case 'I':
			return TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(StructNamedTypeClass,
				{"typeinfo_for_" + DemangleTypeString()}));
		case 'J':
			LogWarn("Unsupported: 'java class'\n");
			throw DemangleException();
		case 'S':
		{
			TypeBuilder t = DemangleType();
			varName = vector<string>{"typeinfo_name_for_" + t.GetString()};
			return TypeBuilder::ArrayType(Type::IntegerType(1, true), 0);
		}
		case 'T': //VTT
		{
			TypeBuilder t = DemangleType();
			return TypeBuilder::NamedType(NamedTypeReference::GenerateAutoDemangledTypeReference(StructNamedTypeClass,
				{"VTT_for_" + t.GetString()}));
		}
		case 'v':  //TODO: Convert to whatever the actual type is!
		{
			DemangleNumberAsString();
			if (m_reader.Read() != '_')
				throw DemangleException();
			DemangleNumberAsString();
			if (m_reader.Read() != '_')
				throw DemangleException();
			oldTopLevel = m_topLevel;
			m_topLevel = false;
			TypeBuilder t = DemangleSymbol(name);
			m_topLevel = oldTopLevel;
			return TypeBuilder::NamedType(
						NamedTypeReference::GenerateAutoDemangledTypeReference(UnknownNamedTypeClass,
							{"virtual_thunk_to_" + name.GetString() + t.GetStringAfterName()}));
		}
		case 'V': //Vtable
			return TypeBuilder::NamedType(
					NamedTypeReference::GenerateAutoDemangledTypeReference(StructNamedTypeClass,
						{"vtable_for_" + DemangleTypeString()}));
		case 'W':
			MyLogDebug("Unsupported: 'TLS wrapper function'\n");
			throw DemangleException();
		default:
			throw DemangleException();
		}
	default: break;
	}

	//<function name> or <data name>
	type = DemangleName();
	if (m_reader.Length() == 0)
	{
		return type;
	}

	if (m_reader.Peek() == 'E')
	{
		m_reader.Consume();
		return type;
	}

	varName = type.GetTypeName();
	cnst = type.IsConst();
	vltl = type.IsVolatile();
	set<BNPointerSuffix> suffix = type.GetPointerSuffix();
	if (m_reader.Peek() == 'J')
	{
		m_reader.Consume();
		// TODO: If we get here we have a return type. What can we do with this info?
	}
	if (m_reader.Peek() == 'B')
	{
		m_reader.Consume();
		TypeBuilder t = DemangleUnqualifiedName();

		if (t.GetString() == "cxx11")
		{
			static const QualifiedName stdCxx11StringName(vector<string>{"std", "cxx11", "string"});
			returnType = CreateUnknownType(stdCxx11StringName);
		}
	}
	else if (m_isOperatorOverload ||
		type.GetNameType() == ConstructorNameType ||
		type.GetNameType() == DestructorNameType)
	{
		returnType = TypeBuilder::VoidType();
	}
	else if (m_isParameter || type.HasTemplateArguments())
	{
		returnType = DemangleType();
	}
	else
	{
		isReturnTypeUnknown = true;
		returnType = TypeBuilder::IntegerType(m_arch->GetAddressSize(), true);
	}

	m_functionSubstitute.push_back({});
	for (size_t i = 0; m_reader.Length() > 0; i++)
	{
		if (m_reader.Peek() == 'E')
		{
			m_reader.Consume();
			break;
		}
		if (m_reader.Peek() == '.')
		{
			// Extension, consume the rest
			string ext = m_reader.ReadString(m_reader.Length());

			if (ext == ".eh") ext = "exception handler";
			else if (ext == ".eh_frame") ext = "exception handler frame";
			else if (ext == ".eh_frame_hdr") ext = "exception handler frame header";
			else if (ext == ".debug_frame") ext = "debug frame";
			varName.back() += ext;
			break;
		}

		m_isParameter = true;
		MyLogDebug("Var_%d: %s\n", i, m_reader.GetRaw().c_str());
		if (m_reader.PeekString(2) == "@@")
			break;
		TypeBuilder param = DemangleType();
		if (param.GetClass() == VoidTypeClass)
		{
			if (m_reader.Peek() == 'E')
			{
				m_reader.Consume();
				break;
			}
			break;
		}
		m_functionSubstitute.back().push_back(param);
		params.push_back({"", param.Finalize(), true, Variable()});
		if (param.GetClass() == VarArgsTypeClass)
		{
			if (m_reader.Peek() == 'E')
			{
				m_reader.Consume();
			}

			break;
		}
	}

	m_functionSubstitute.pop_back();
	m_isParameter = false;
	type = TypeBuilder::FunctionType(returnType.Finalize()->
		WithConfidence(isReturnTypeUnknown ? BN_MINIMUM_CONFIDENCE : BN_DEFAULT_CONFIDENCE), nullptr, params);

	type.SetPointerSuffix(suffix);
	type.SetConst(cnst);
	type.SetVolatile(vltl);
	if (rstrct)
		type.SetPointerSuffix({RestrictSuffix});

	// PrintTables();
	MyLogDebug("Done: %s%s%s\n", type.GetStringBeforeName().c_str(), varName.GetString().c_str(),
		type.GetStringAfterName().c_str());

	dedent();
	return type;
}


bool DemangleGNU3::IsGNU3MangledString(const string& name)
{
	string headerless = name;
	string header;
	if (DemangleGlobalHeader(headerless, header))
		return true;

	if (!headerless.compare(0, 2, "_Z") || !headerless.compare(0, 3, "__Z"))
		return true;

	return false;
}


bool DemangleGNU3::DemangleGlobalHeader(string& name, string& header)
{
	size_t strippedCount = 0;
	string encoded = name;
	while (encoded[0] == '_')
	{
		encoded.erase(0, 1);
		strippedCount ++;
	}

	if (strippedCount == 0)
		return false;

	static const vector<pair<string, string>> headers = {
		{"GLOBAL__sub_I_", "(static initializer)"},
		{"GLOBAL__I_", "(global initializer)"},
		{"GLOBAL__D_", "(global destructor)"},
	};

	for (auto& i: headers)
	{
		if (encoded.size() > i.first.size() && encoded.substr(0, i.first.size()) == i.first)
		{
			name = name.substr(i.first.size() + strippedCount);
			header = i.second;
			return true;
		}
	}

	return false;
}


bool DemangleGNU3::DemangleStringGNU3(Architecture* arch, const string& name, Ref<Type>& outType, QualifiedName& outVarName, const Ref<BinaryView>& view)
{
	return DemangleStringGNU3(arch, name, outType, outVarName);
}


bool DemangleGNU3::DemangleStringGNU3(Architecture* arch, const string& name, Ref<Type>& outType, QualifiedName& outVarName, BinaryView* view)
{
	return DemangleStringGNU3(arch, name, outType, outVarName);
}


bool DemangleGNU3::DemangleStringGNU3(Architecture* arch, const string& name, Ref<Type>& outType, QualifiedName& outVarName)
{
	string encoding = name;
	string header;
	bool foundHeader = DemangleGlobalHeader(encoding, header);

	if (!encoding.compare(0, 2, "_Z"))
		encoding = encoding.substr(2);
	else if (!encoding.compare(0, 3, "__Z"))
		encoding = encoding.substr(3);
	else if (foundHeader && !header.empty())
	{
		// Some variable constructors/destructors are __GLOBAL__I_name
		// And there are even __GLOBAL__sub_I_file_name.cpp
		outVarName.clear();
		outVarName.push_back(header);
		outVarName.push_back(encoding);
		outType = CreateUnknownType(outVarName).Finalize();
		return true;
	}
	else
		return false;

	DemangleGNU3 demangle(arch, encoding);
	try
	{
		outType = demangle.DemangleSymbol(outVarName).Finalize();

		if (outVarName.size() == 0)
		{
			if (outType->GetClass() == NamedTypeReferenceClass && outType->GetNamedTypeReference()->GetTypeReferenceClass() == UnknownNamedTypeClass)
			{
				outVarName = outType->GetTypeName();
				outType = nullptr;
			}
			else if (outType->GetClass() == NamedTypeReferenceClass)
			{
				auto typeName = outType->GetTypeName();
				if (typeName.size() > 0)
					outVarName = "_" + typeName[typeName.size() - 1];
			}
		}

		if (foundHeader && !header.empty())
		{
			outVarName.insert(outVarName.begin(), header);
		}
	}
	catch (std::exception&)
	{
		return false;
	}
	return true;
}


class GNU3Demangler: public Demangler
{
public:
	GNU3Demangler(): Demangler("GNU3")
	{
	}
	~GNU3Demangler() override {}

	virtual bool IsMangledString(const string& name) override
	{
		return DemangleGNU3::IsGNU3MangledString(name);
	}

#ifdef BINARYNINJACORE_LIBRARY
	virtual bool Demangle(Architecture* arch, const string& name, Ref<Type>& outType, QualifiedName& outVarName,
	                      BinaryView* view) override
#else
	virtual bool Demangle(Ref<Architecture> arch, const string& name, Ref<Type>& outType, QualifiedName& outVarName,
	                      Ref<BinaryView> view) override
#endif
	{
		if (view)
			return DemangleGNU3::DemangleStringGNU3(arch, name, outType, outVarName, view);
		return DemangleGNU3::DemangleStringGNU3(arch, name, outType, outVarName);
	}
};


extern "C"
{
#ifndef BINARYNINJACORE_LIBRARY
	BN_DECLARE_CORE_ABI_VERSION
#endif

#ifdef BINARYNINJACORE_LIBRARY
	bool DemangleGNU3PluginInit()
#elif defined(DEMO_EDITION)
	bool DemangleGNU3PluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		static GNU3Demangler* demangler = new GNU3Demangler();
		Demangler::Register(demangler);
		return true;
	}
}
