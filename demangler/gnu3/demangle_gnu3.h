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

#pragma once
#include <stdexcept>
#include <exception>

// XXX: Compiled directly into the core for performance reasons
// Will still work fine compiled independently, just at about a
// 50-100% performance penalty due to FFI overhead
#ifdef BINARYNINJACORE_LIBRARY
#include "qualifiedname.h"
#include "type.h"
#include "architecture.h"
#include "binaryview.h"
#include "demangle.h"
#define BN BinaryNinjaCore
#define _STD_STRING BinaryNinjaCore::string
#define _STD_VECTOR BinaryNinjaCore::vector
#else
#include "binaryninjaapi.h"
#define BN BinaryNinja
#define _STD_STRING std::string
#define _STD_VECTOR std::vector
#endif

class DemangleException: public std::exception
{
	_STD_STRING m_message;
public:
	DemangleException(_STD_STRING msg="Attempt to read beyond bounds or missing expected character"): m_message(msg){}
	virtual const char* what() const noexcept { return m_message.c_str(); }
};

class DemangleGNU3
{
	class Reader
	{
	public:
		Reader(const _STD_STRING& data);
		_STD_STRING PeekString(size_t count=1);
		char Peek();
		bool NextIsOneOf(const _STD_STRING& list);
		_STD_STRING GetRaw();
		char Read();
		_STD_STRING ReadString(size_t count=1);
		_STD_STRING ReadUntil(char sentinal);
		void Consume(size_t count=1);
		size_t Length() const;
		void UnRead(size_t count=1);
	private:
		_STD_STRING m_data;
		size_t m_offset;
	};

	class SubstitutionList
	{
		_STD_VECTOR<BN::TypeBuilder> m_typeList;
	public:
		SubstitutionList();
		~SubstitutionList();
		void PushType(BN::TypeBuilder t);
		void PopType();
		const BN::TypeBuilder& GetType(size_t reference) const;
		void PrintSubstitutionTable() const;
		size_t Size() const { return m_typeList.size(); }
		void Clear() { m_typeList.clear(); }
	};

	BN::QualifiedName m_varName;
	Reader m_reader;
	BN::Architecture* m_arch;
	_STD_VECTOR<BN::TypeBuilder> m_substitute;
	_STD_VECTOR<BN::TypeBuilder> m_templateSubstitute;
	_STD_VECTOR<_STD_VECTOR<BN::TypeBuilder>> m_functionSubstitute;
	_STD_STRING m_lastName;
	BNNameType m_nameType;
	bool m_localType;
	bool m_hasReturnType;
	bool m_isParameter;
	bool m_shouldDeleteReader;
	bool m_topLevel;
	bool m_isOperatorOverload;
	enum SymbolType { Function, FunctionWithReturn, Data, VTable, Rtti, Name};
	BN::QualifiedName DemangleBaseUnresolvedName();
	BN::TypeBuilder DemangleUnresolvedType();
	_STD_STRING DemangleUnarySuffixExpression(const _STD_STRING& op);
	_STD_STRING DemangleUnaryPrefixExpression(const _STD_STRING& op);
	_STD_STRING DemangleBinaryExpression(const _STD_STRING& op);
	_STD_STRING DemangleUnaryPrefixType(const _STD_STRING& op);
	_STD_STRING DemangleTypeString();
	_STD_STRING DemangleExpressionList();
	BN::TypeBuilder DemangleUnqualifiedName();
	_STD_STRING DemangleSourceName();
	_STD_STRING DemangleNumberAsString();
	_STD_STRING DemangleInitializer();
	_STD_STRING DemangleExpression();
	_STD_STRING DemanglePrimaryExpression();
	BN::TypeBuilder DemangleName();
	BN::TypeBuilder DemangleLocalName();

	void DemangleCVQualifiers(bool& cnst, bool& vltl, bool& rstrct);
	BN::TypeBuilder DemangleSubstitution();
	const BN::TypeBuilder& DemangleTemplateSubstitution();
	void DemangleTemplateArgs(_STD_VECTOR<BN::FunctionParameter>& args);
	bool DemangleEncoding(BN::Type** type, BN::QualifiedName& outName);
	BN::TypeBuilder DemangleFunction(bool cnst, bool vltl);
	BN::TypeBuilder DemangleType();
	int64_t DemangleNumber();
	BN::TypeBuilder DemangleNestedName();
	void PushTemplateType(BN::TypeBuilder type);
	const BN::TypeBuilder& GetTemplateType(size_t ref);
	void PushType(BN::TypeBuilder type);
	const BN::TypeBuilder& GetType(size_t ref);
	static bool DemangleGlobalHeader(_STD_STRING& name, _STD_STRING& header);

public:
	DemangleGNU3(BN::Architecture* arch, const _STD_STRING& mangledName);
	BN::TypeBuilder DemangleSymbol(BN::QualifiedName& varName);
	BN::QualifiedName GetVarName() const { return m_varName; }
	static bool IsGNU3MangledString(const _STD_STRING& name);

	// Tread lightly on this landmine; a BinaryView* will be converted to a bool; use an explicit (BN::Ref<BN::BinaryView>)view cast
	static bool DemangleStringGNU3(BN::Architecture* arch, const _STD_STRING& name, BN::Ref<BN::Type>& outType, BN::QualifiedName& outVarName, const BN::Ref<BN::BinaryView>& view);
	static bool DemangleStringGNU3(BN::Architecture* arch, const _STD_STRING& name, BN::Ref<BN::Type>& outType, BN::QualifiedName& outVarName, BN::BinaryView* view);
	static bool DemangleStringGNU3(BN::Architecture* arch, const _STD_STRING& name, BN::Ref<BN::Type>& outType, BN::QualifiedName& outVarName);
	void PrintTables();
};
