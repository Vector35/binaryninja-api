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
#include "unicode.h"
#define BN BinaryNinjaCore
#define _STD_STRING BinaryNinjaCore::string
#define _STD_VECTOR BinaryNinjaCore::vector
#define _STD_SET BinaryNinjaCore::set
#else
#include "binaryninjaapi.h"
#define BN BinaryNinja
#define _STD_STRING std::string
#define _STD_VECTOR std::vector
#define _STD_SET std::set
#endif

class DemangleException: public std::exception
{
	_STD_STRING m_message;
public:
	DemangleException(_STD_STRING msg="Attempt to read beyond bounds or missing expected character"): m_message(msg){}
	virtual const char* what() const noexcept { return m_message.c_str(); }
};


class Demangle
{
	enum NameType
	{
		NameEmpty,
		NameString,
		NameLookup,
		NameBackref,
		NameTemplate,
		NameConstructor,
		NameDestructor,
		NameRtti,
		NameReturn,
		NameDynamicInitializer,
		NameDynamicAtExitDestructor,
		NameLocalStaticThreadGuard,
		NameLocalVftable
	};

	enum FunctionClass
	{
		NoneFunctionClass           = 0,
		PrivateFunctionClass        = 1 << 0,
		ProtectedFunctionClass      = 1 << 1,
		PublicFunctionClass         = 1 << 2,
		GlobalFunctionClass         = 1 << 3,
		StaticFunctionClass         = 1 << 4,
		VirtualFunctionClass        = 1 << 5,
		FriendFunctionClass         = 1 << 6,
		StaticThunkFunctionClass    = 1 << 7,
		VirtualThunkFunctionClass   = 1 << 8,
		VirtualThunkExFunctionClass = 1 << 9,
	};

	class Reader
	{
	public:
		Reader(_STD_STRING data);
		_STD_STRING PeekString(size_t count=1);
		char Peek();
		const char* GetRaw();
		char Read();
		_STD_STRING ReadString(size_t count=1);
		_STD_STRING ReadUntil(char sentinal);
		void Consume(size_t count=1);
		size_t Length();
	private:
		_STD_STRING m_data;
	};

	class BackrefList
	{
	public:
		_STD_VECTOR<BN::TypeBuilder> typeList;
		_STD_VECTOR<_STD_STRING> nameList;
		const BN::TypeBuilder& GetTypeBackref(size_t reference);
		_STD_STRING GetStringBackref(size_t reference);
		void PushTypeBackref(BN::TypeBuilder t);
		void PushStringBackref(_STD_STRING& s);
		void PushFrontStringBackref(_STD_STRING& s);
	};

	Reader reader;
	BackrefList m_backrefList;
	BN::Architecture* m_arch;
	BN::Ref<BN::Platform> m_platform;
	BN::Ref<BN::BinaryView> m_view;
	BN::QualifiedName m_varName;
	BN::Ref<BN::Logger> m_logger;

	NameType GetNameType();
	BN::TypeBuilder DemangleVarType(BackrefList& varList, bool isReturn, BN::QualifiedName& name);
	void DemangleNumber(int64_t& num);
	void DemangleChar(char& ch);
	void DemangleWideChar(uint16_t& wch);
	void DemangleModifiers(bool& _const, bool& _volatile, bool& isMember);
	_STD_SET<BNPointerSuffix> DemanglePointerSuffix();
	void DemangleVariableList(_STD_VECTOR<BN::FunctionParameter>& paramList, BackrefList& varList);
	void DemangleNameTypeRtti(BNNameType& classFunctionType,
	                          BackrefList& nameBackrefList,
	                          _STD_STRING& out,
	                          _STD_STRING& rttiTypeName);
	void DemangleTypeNameLookup(_STD_STRING& out, BNNameType& functionType);
	void DemangleNameTypeString(_STD_STRING& out);
	void DemangleNameTypeBackref(_STD_STRING& out, const _STD_VECTOR<_STD_STRING>& backrefList);
	void DemangleName(BN::QualifiedName& nameList,
	                  BNNameType& classFunctionType,
	                  BackrefList& nameBackrefList);
	BN::Ref<BN::CallingConvention> GetCallingConventionForType(BNCallingConventionName ccName);
	BNCallingConventionName DemangleCallingConvention();
	BN::TypeBuilder DemangleFunction(BNNameType classFunctionType, bool pointerSuffix, BackrefList& varList, int funcClass = NoneFunctionClass);
	BN::TypeBuilder DemangleData();
	void DemangleNameTypeRtti(BNNameType& classFunctionType,
	                          BackrefList& nameBackrefList,
	                          _STD_STRING& out);
	BN::TypeBuilder DemangleVTable();
	BN::TypeBuilder DemanagleRTTI(BNNameType classFunctionType);
	_STD_STRING DemangleTemplateInstantiationName(BackrefList& nameBackrefList);
	_STD_STRING DemangleTemplateParams(_STD_VECTOR<BN::FunctionParameter>& params, BackrefList& nameBackrefList, _STD_STRING& out);
	_STD_STRING DemangleUnqualifiedSymbolName(BN::QualifiedName& nameList, BackrefList& nameBackrefList, BNNameType& classFunctionType);
	BN::TypeBuilder DemangleString();
	BN::TypeBuilder DemangleTypeInfoName();

public:
	struct DemangleContext
	{
		BN::TypeBuilder type;
		BNMemberAccess access;
		BNMemberScope scope;
	};
	Demangle(BN::Architecture* arch, _STD_STRING mangledName);
	Demangle(BN::Ref<BN::BinaryView> view, _STD_STRING mangledName);
	Demangle(BN::Ref<BN::Platform> platform, _STD_STRING mangledName);
	DemangleContext DemangleSymbol();
	BN::QualifiedName GetVarName() const { return m_varName; }

	// Be careful not to accidentally implicitly cast a BinaryView* to a bool
	static bool DemangleMS(BN::Architecture* arch, const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName, const BN::Ref<BN::BinaryView>& view);
	static bool DemangleMS(BN::Architecture* arch, const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName, BN::BinaryView* view);
	static bool DemangleMS(BN::Architecture* arch, const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName);

	static bool DemangleMS(const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName, const BN::Ref<BN::BinaryView>& view);
	static bool DemangleMS(const _STD_STRING& mangledName, BN::Ref<BN::Type>& outType,
	                       BN::QualifiedName& outVarName, BN::BinaryView* view);
};

