// Copyright 2016-2026 Vector 35 Inc.
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

#include "demangled_type_node.h"

class DemangleException: public std::exception
{
	_STD_STRING m_message;
public:
	DemangleException(_STD_STRING msg="Attempt to read beyond bounds or missing expected character"): m_message(msg){}
	virtual const char* what() const noexcept { return m_message.c_str(); }
};

class DemangleGNU3Reader
{
public:
	DemangleGNU3Reader(const _STD_STRING& data);
	void Reset(const _STD_STRING& data);
	_STD_STRING PeekString(size_t count=1);
#ifdef GNUDEMANGLE_DEBUG
	_STD_STRING GetRaw();
#endif
	_STD_STRING ReadString(size_t count=1);

	size_t Length() const { return m_data.length() - m_offset; }

	char Peek()
	{
		if (1 > Length())
			return '\0';
		return (char)m_data[m_offset];
	}

	char Read()
	{
		if (1 > Length())
			throw DemangleException();
		return m_data[m_offset++];
	}

	void Consume(size_t count=1)
	{
		if (count > Length())
			throw DemangleException();
		m_offset += count;
	}

	void UnRead(size_t count=1)
	{
		if (count <= m_offset)
			m_offset -= count;
	}

private:
	_STD_STRING m_data;
	size_t m_offset;
};


class DemangleGNU3
{
	using ParamList = _STD_VECTOR<DemangledTypeNode::Param>;
	using NodeRef = DemangledTypeNode::NodeRef;
	using NodeRefList = _STD_VECTOR<NodeRef>;

	DemangleGNU3Reader m_reader;
	BN::Ref<BN::Platform> m_platform;
	NodeRefList m_substitute;
	NodeRefList m_templateSubstitute;
	_STD_VECTOR<NodeRefList> m_functionSubstitute;
	NodeRef m_lastTypeRef;
	_STD_STRING m_lastName;
	BNNameType m_nameType;
	bool m_localType;
	bool m_hasReturnType;
	bool m_isParameter;
	bool m_shouldDeleteReader;
	bool m_topLevel;
	bool m_isOperatorOverload;
	bool m_parsingLambdaParams;
	size_t m_lambdaTemplateParamBase;
	// Forward template reference support (for cv conversion operator types).
	// When m_permitForwardTemplateRefs is true, DemangleTemplateSubstitution()
	// returns a shared placeholder node instead of throwing for out-of-bounds
	// template params. m_pendingForwardRefs records those nodes so that
	// ResolveForwardTemplateRefs() can replace their contents once args are known.
	bool m_permitForwardTemplateRefs;
	bool m_inLocalName;
	size_t m_nestingDepth;
	struct ForwardRef
	{
		size_t index;
		NodeRef typeRef;
	};
	_STD_VECTOR<ForwardRef> m_pendingForwardRefs;
	class NestingGuard
	{
		DemangleGNU3& m_demangler;
	public:
		NestingGuard(DemangleGNU3& demangler);
		~NestingGuard();
	};
	void ResolveForwardTemplateRefs(DemangledTypeNode& type, const ParamList& args);
	enum SymbolType { Function, FunctionWithReturn, Data, VTable, Rtti, Name};
	StringList DemangleBaseUnresolvedName();
	DemangledTypeNode DemangleUnresolvedType();
	_STD_STRING DemangleUnarySuffixExpression(const _STD_STRING& op);
	_STD_STRING DemangleUnaryPrefixExpression(const _STD_STRING& op);
	_STD_STRING DemangleBinaryExpression(const _STD_STRING& op);
	_STD_STRING DemangleUnaryPrefixType(const _STD_STRING& op);
	_STD_STRING DemangleTypeString();
	_STD_STRING DemangleExpressionList();
	DemangledTypeNode DemangleUnqualifiedName();
	_STD_STRING DemangleSourceName();
	_STD_STRING DemangleNumberAsString();
	_STD_STRING DemangleExpression();
	_STD_STRING DemanglePrimaryExpression();
	DemangledTypeNode DemangleName();
	DemangledTypeNode DemangleLocalName();

	void DemangleCVQualifiers(bool& cnst, bool& vltl, bool& rstrct);
	DemangledTypeNode DemangleSubstitution(NodeRef* outTypeRef = nullptr);
	DemangledTypeNode DemangleTemplateSubstitution(NodeRef* outTypeRef = nullptr);
	bool DemangleTemplateArg(ParamList& args, bool* hadNonTypeArg = nullptr);
	void DemangleTemplateArgs(ParamList& args, bool* hadNonTypeArg = nullptr);
	DemangledTypeNode DemangleFunction(bool cnst, bool vltl);
	DemangledTypeNode DemangleType();
	int64_t DemangleNumber();
	DemangledTypeNode DemangleNestedName(bool* allTypeTemplateArgs = nullptr, bool pushBareTemplatePrefix = true);
	NodeRef PushTemplateType(NodeRef type);
	NodeRef PushTemplateType(const DemangledTypeNode& type);
	NodeRef PushTemplateType(DemangledTypeNode&& type);
	NodeRef PushType(NodeRef type);
	NodeRef PushType(const DemangledTypeNode& type);
	NodeRef PushType(DemangledTypeNode&& type);
	NodeRef GetTypeRef(size_t ref);
	const DemangledTypeNode& GetType(size_t ref);

	DemangledTypeNode CreateUnknownType(const StringList& s);
	DemangledTypeNode CreateUnknownType(const _STD_STRING& s);
	static void ExtendTypeName(DemangledTypeNode& type, const _STD_STRING& extend);
	static void ApplyTemplateArgs(DemangledTypeNode& type, ParamList args);
	static void AppendTypeName(DemangledTypeNode& type, const DemangledTypeNode& extend);
	static _STD_STRING LastTypeNameSegmentBase(const DemangledTypeNode& type);
	static bool LastTypeNameSegmentHasTemplateArguments(const DemangledTypeNode& type);

#ifdef GNUDEMANGLE_DEBUG
	const DemangledTypeNode& GetTemplateType(size_t ref);
	void PrintTables();
#endif

public:
	DemangleGNU3(BN::Platform* platform, const _STD_STRING& mangledName);
	void Reset(BN::Platform* platform, const _STD_STRING& mangledName);
	DemangledTypeNode DemangleSymbol(StringList& varName);
};


class DemangleGNU3Static
{
public:
	static bool IsGNU3MangledString(const _STD_STRING& name);
	static bool DemangleGlobalHeader(_STD_STRING& name, _STD_STRING& header);

	static bool DemangleStringGNU3(BN::Platform* platform, const _STD_STRING& name, BN::Ref<BN::Type>& outType, BN::QualifiedName& outVarName);
	static bool DemangleStringGNU3(BN::Architecture* arch, const _STD_STRING& name, BN::Ref<BN::Type>& outType, BN::QualifiedName& outVarName);
};
