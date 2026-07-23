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
#include <functional>
#include <string_view>
#include <utility>

// Compiled directly into the core for performance reasons. It also works when
// compiled independently, but benchmarks after the DemangledTypeNode and
// template simplifier refactors showed approximately 25% better performance
// when compiled directly into the core instead of through the FFI.
#ifdef BINARYNINJACORE_LIBRARY
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

#include "demangler/demangled_reader.h"


class DemangleGNU3
{
public:
	using ParamList = _STD_VECTOR<DemangledTypeNode::Param>;
	using TypeNodeRef = DemangledTypeNode::NodeRef;
private:
	struct NodeRef
	{
		TypeNodeRef type;
		std::shared_ptr<ParamList> templatePack;
		bool emptyTemplatePack = false;
		bool templatePackExpansion = false;

		NodeRef() = default;
		NodeRef(std::nullptr_t) {}
		NodeRef(TypeNodeRef typeRef): type(std::move(typeRef)) {}

		static NodeRef EmptyTemplatePack()
		{
			NodeRef ref;
			ref.emptyTemplatePack = true;
			return ref;
		}

		static NodeRef TemplateParamPack(ParamList args)
		{
			NodeRef ref;
			ref.templatePack = std::make_shared<ParamList>(std::move(args));
			ref.emptyTemplatePack = ref.templatePack->empty();
			for (auto& arg : *ref.templatePack)
			{
				if (arg.type)
				{
					ref.type = arg.type;
					break;
				}
			}
			return ref;
		}

		static NodeRef TemplateParamPackExpansion(ParamList args)
		{
			NodeRef ref = TemplateParamPack(std::move(args));
			ref.templatePackExpansion = true;
			return ref;
		}

		explicit operator bool() const { return type != nullptr; }
		[[nodiscard]] bool IsTemplateParamPack() const { return templatePack != nullptr; }
		[[nodiscard]] bool IsTemplateParamPackExpansion() const { return templatePackExpansion; }
		DemangledTypeNode& operator*() const { return *type; }
		DemangledTypeNode* operator->() const { return type.get(); }
		operator TypeNodeRef() const { return type; }
	};
	using NodeRefList = _STD_VECTOR<NodeRef>;

	static constexpr size_t MAX_DEMANGLE_NODE_LENGTH = 8192;
	static constexpr size_t MAX_DEMANGLE_NESTING_DEPTH = 1024;
	_STD_STRING m_mangledName;
	DemangleReader m_reader{m_mangledName, MAX_DEMANGLE_NODE_LENGTH, false};
	std::reference_wrapper<BN::Platform> m_platform;
	NodeRefList m_substitute;
	NodeRefList m_templateSubstitute;
	_STD_VECTOR<NodeRefList> m_functionSubstitute;
	NodeRef m_lastTypeRef;
	_STD_STRING m_lastName;
	bool m_isParameter;
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
	using NestingGuard = DemangleNestingGuard<MAX_DEMANGLE_NESTING_DEPTH>;
	void ResolveForwardTemplateRefs(DemangledTypeNode& type, const ParamList& args);
	enum SymbolType { Function, FunctionWithReturn, Data, VTable, Rtti, Name};
	StringList DemangleBaseUnresolvedName();
	DemangledTypeNode DemangleUnresolvedType();
	_STD_STRING DemangleUnarySuffixExpression(std::string_view op);
	_STD_STRING DemangleUnaryPrefixExpression(std::string_view op, DemangledTypeNode* outNode = nullptr);
	_STD_STRING DemangleBinaryExpression(std::string_view op, DemangledTypeNode* outNode = nullptr);
	_STD_STRING DemangleUnaryPrefixType(std::string_view op);
	_STD_STRING DemangleTypeString();
	_STD_STRING DemangleExpressionList();
	DemangledTypeNode DemangleUnqualifiedName();
	std::string_view DemangleSourceName();
	_STD_STRING DemangleNumberAsString();
	_STD_STRING DemangleExpression(DemangledTypeNode* outNode = nullptr);
	_STD_STRING DemanglePrimaryExpression();
	NodeRef DemangleTemplateSubstitutionEntry(NodeRef* outTypeRef = nullptr);
	bool TryDemangleTemplateParamExpressionPackExpansion(_STD_STRING& expr, bool& emptyPack);
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
	void PushEmptyTemplateParamSubstitution();
	NodeRef PushType(const DemangledTypeNode& type);
	NodeRef PushType(DemangledTypeNode&& type);
	NodeRef GetTypeRef(size_t ref);
	const DemangledTypeNode& GetType(size_t ref);
	bool AppendTemplateParamPackExpansion(ParamList& params, const NodeRef& expansion, bool functionParameter);

#ifdef GNUDEMANGLE_DEBUG
	const DemangledTypeNode& GetTemplateType(size_t ref);
	void PrintTables();
#endif

public:
	DemangleGNU3(BN::Platform& platform, _STD_STRING mangledName);
	void Reset(BN::Platform& platform, _STD_STRING mangledName);
	DemangledTypeNode DemangleSymbol(StringList& varName, bool simplifyTemplates = false);
};


class DemangleGNU3Static
{
public:
	static bool IsGNU3MangledString(std::string_view name);
	static bool DemangleGlobalHeader(_STD_STRING& name, _STD_STRING& header);
};
