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
#include "binaryninjaapi.h"


class DemangleException: public std::exception
{
	std::string m_message;
public:
	DemangleException(std::string msg="Attempt to read beyond bounds or missing expected character"): m_message(msg){}
	virtual const char* what() const noexcept { return m_message.c_str(); }
};

class DemangleGNU3
{
	class Reader
	{
	public:
		Reader(const std::string& data);
		std::string PeekString(size_t count=1);
		char Peek();
		bool NextIsOneOf(const std::string& list);
		std::string GetRaw();
		char Read();
		std::string ReadString(size_t count=1);
		std::string ReadUntil(char sentinal);
		void Consume(size_t count=1);
		size_t Length() const;
		void UnRead(size_t count=1);
	private:
		std::string m_data;
		size_t m_offset;
	};

	class SubstitutionList
	{
		std::vector<BinaryNinja::TypeBuilder> m_typeList;
	public:
		SubstitutionList();
		~SubstitutionList();
		void PushType(BinaryNinja::TypeBuilder t);
		void PopType();
		const BinaryNinja::TypeBuilder& GetType(size_t reference) const;
		void PrintSubstitutionTable() const;
		size_t Size() const { return m_typeList.size(); }
		void Clear() { m_typeList.clear(); }
	};

	BinaryNinja::QualifiedName m_varName;
	Reader m_reader;
	BinaryNinja::Architecture* m_arch;
	std::vector<BinaryNinja::TypeBuilder> m_substitute;
	std::vector<BinaryNinja::TypeBuilder> m_templateSubstitute;
	std::vector<std::vector<BinaryNinja::TypeBuilder>> m_functionSubstitute;
	std::string m_lastName;
	BNNameType m_nameType;
	bool m_localType;
	bool m_hasReturnType;
	bool m_isParameter;
	bool m_shouldDeleteReader;
	bool m_topLevel;
	bool m_isOperatorOverload;
	enum SymbolType { Function, FunctionWithReturn, Data, VTable, Rtti, Name};
	BinaryNinja::QualifiedName DemangleBaseUnresolvedName();
	BinaryNinja::TypeBuilder DemangleUnresolvedType();
	std::string DemangleUnarySuffixExpression(const std::string& op);
	std::string DemangleUnaryPrefixExpression(const std::string& op);
	std::string DemangleBinaryExpression(const std::string& op);
	std::string DemangleUnaryPrefixType(const std::string& op);
	std::string DemangleTypeString();
	std::string DemangleExpressionList();
	BinaryNinja::TypeBuilder DemangleUnqualifiedName();
	std::string DemangleSourceName();
	std::string DemangleNumberAsString();
	std::string DemangleInitializer();
	std::string DemangleExpression();
	std::string DemanglePrimaryExpression();
	BinaryNinja::TypeBuilder DemangleName();
	BinaryNinja::TypeBuilder DemangleLocalName();

	void DemangleCVQualifiers(bool& cnst, bool& vltl, bool& rstrct);
	BinaryNinja::TypeBuilder DemangleSubstitution();
	const BinaryNinja::TypeBuilder& DemangleTemplateSubstitution();
	void DemangleTemplateArgs(std::vector<BinaryNinja::FunctionParameter>& args);
	bool DemangleEncoding(BinaryNinja::Type** type, BinaryNinja::QualifiedName& outName);
	BinaryNinja::TypeBuilder DemangleFunction(bool cnst, bool vltl);
	BinaryNinja::TypeBuilder DemangleType();
	int64_t DemangleNumber();
	BinaryNinja::TypeBuilder DemangleNestedName();
	void PushTemplateType(BinaryNinja::TypeBuilder type);
	const BinaryNinja::TypeBuilder& GetTemplateType(size_t ref);
	void PushType(BinaryNinja::TypeBuilder type);
	const BinaryNinja::TypeBuilder& GetType(size_t ref);
	static bool DemangleGlobalHeader(std::string& name, std::string& header);

public:
	DemangleGNU3(BinaryNinja::Architecture* arch, const std::string& mangledName);
	BinaryNinja::TypeBuilder DemangleSymbol(BinaryNinja::QualifiedName& varName);
	BinaryNinja::QualifiedName GetVarName() const { return m_varName; }
	static bool IsGNU3MangledString(const std::string& name);

	// Tread lightly on this landmine; a BinaryView* will be converted to a bool; use an explicit (BinaryNinja::Ref<BinaryNinja::BinaryView>)view cast
	static bool DemangleStringGNU3(BinaryNinja::Architecture* arch, const std::string& name, BinaryNinja::Ref<BinaryNinja::Type>& outType, BinaryNinja::QualifiedName& outVarName, const BinaryNinja::Ref<BinaryNinja::BinaryView>& view);
	static bool DemangleStringGNU3(BinaryNinja::Architecture* arch, const std::string& name, BinaryNinja::Ref<BinaryNinja::Type>& outType, BinaryNinja::QualifiedName& outVarName, BinaryNinja::BinaryView* view);
	static bool DemangleStringGNU3(BinaryNinja::Architecture* arch, const std::string& name, BinaryNinja::Ref<BinaryNinja::Type>& outType, BinaryNinja::QualifiedName& outVarName);
	void PrintTables();
};
