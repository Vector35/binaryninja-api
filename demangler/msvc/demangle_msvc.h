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
#include <string>
#include <vector>
#include <set>
#include "binaryninjaapi.h"


class DemangleException: public std::exception
{
	std::string m_message;
public:
	DemangleException(std::string msg="Attempt to read beyond bounds or missing expected character"): m_message(msg){}
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
		Reader(std::string data);
		std::string PeekString(size_t count=1);
		char Peek();
		const char* GetRaw();
		char Read();
		std::string ReadString(size_t count=1);
		std::string ReadUntil(char sentinal);
		void Consume(size_t count=1);
		size_t Length();
	private:
		std::string m_data;
	};

	class BackrefList
	{
	public:
		std::vector<BinaryNinja::TypeBuilder> typeList;
		std::vector<std::string> nameList;
		const BinaryNinja::TypeBuilder& GetTypeBackref(size_t reference);
		std::string GetStringBackref(size_t reference);
		void PushTypeBackref(BinaryNinja::TypeBuilder t);
		void PushStringBackref(std::string& s);
		void PushFrontStringBackref(std::string& s);
	};

	Reader reader;
	BackrefList m_backrefList;
	BinaryNinja::Architecture* m_arch;
	BinaryNinja::Ref<BinaryNinja::Platform> m_platform;
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	BinaryNinja::QualifiedName m_varName;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;

	NameType GetNameType();
	BinaryNinja::TypeBuilder DemangleVarType(BackrefList& varList, bool isReturn, BinaryNinja::QualifiedName& name);
	void DemangleNumber(int64_t& num);
	void DemangleChar(char& ch);
	void DemangleWideChar(uint16_t& wch);
	void DemangleModifiers(bool& _const, bool& _volatile, bool& isMember);
	std::set<BNPointerSuffix> DemanglePointerSuffix();
	void DemangleVariableList(std::vector<BinaryNinja::FunctionParameter>& paramList, BackrefList& varList);
	void DemangleNameTypeRtti(BNNameType& classFunctionType,
	                          BackrefList& nameBackrefList,
	                          std::string& out,
	                          std::string& rttiTypeName);
	void DemangleTypeNameLookup(std::string& out, BNNameType& functionType);
	void DemangleNameTypeString(std::string& out);
	void DemangleNameTypeBackref(std::string& out, const std::vector<std::string>& backrefList);
	void DemangleName(BinaryNinja::QualifiedName& nameList,
	                  BNNameType& classFunctionType,
	                  BackrefList& nameBackrefList);
	BinaryNinja::Ref<BinaryNinja::CallingConvention> GetCallingConventionForType(BNCallingConventionName ccName);
	BNCallingConventionName DemangleCallingConvention();
	BinaryNinja::TypeBuilder DemangleFunction(BNNameType classFunctionType, bool pointerSuffix, BackrefList& varList, int funcClass = NoneFunctionClass);
	BinaryNinja::TypeBuilder DemangleData();
	void DemangleNameTypeRtti(BNNameType& classFunctionType,
	                          BackrefList& nameBackrefList,
	                          std::string& out);
	BinaryNinja::TypeBuilder DemangleVTable();
	BinaryNinja::TypeBuilder DemanagleRTTI(BNNameType classFunctionType);
	std::string DemangleTemplateInstantiationName(BackrefList& nameBackrefList);
	std::string DemangleTemplateParams(std::vector<BinaryNinja::FunctionParameter>& params, BackrefList& nameBackrefList, std::string& out);
	std::string DemangleUnqualifiedSymbolName(BinaryNinja::QualifiedName& nameList, BackrefList& nameBackrefList, BNNameType& classFunctionType);
	BinaryNinja::TypeBuilder DemangleString();
	BinaryNinja::TypeBuilder DemangleTypeInfoName();

public:
	struct DemangleContext
	{
		BinaryNinja::TypeBuilder type;
		BNMemberAccess access;
		BNMemberScope scope;
	};
	Demangle(BinaryNinja::Architecture* arch, std::string mangledName);
	Demangle(BinaryNinja::Ref<BinaryNinja::BinaryView> view, std::string mangledName);
	Demangle(BinaryNinja::Ref<BinaryNinja::Platform> platform, std::string mangledName);
	DemangleContext DemangleSymbol();
	BinaryNinja::QualifiedName GetVarName() const { return m_varName; }

	// Be careful not to accidentally implicitly cast a BinaryView* to a bool
	static bool DemangleMS(BinaryNinja::Architecture* arch, const std::string& mangledName, BinaryNinja::Ref<BinaryNinja::Type>& outType,
	                       BinaryNinja::QualifiedName& outVarName, const BinaryNinja::Ref<BinaryNinja::BinaryView>& view);
	static bool DemangleMS(BinaryNinja::Architecture* arch, const std::string& mangledName, BinaryNinja::Ref<BinaryNinja::Type>& outType,
	                       BinaryNinja::QualifiedName& outVarName, BinaryNinja::BinaryView* view);
	static bool DemangleMS(BinaryNinja::Architecture* arch, const std::string& mangledName, BinaryNinja::Ref<BinaryNinja::Type>& outType,
	                       BinaryNinja::QualifiedName& outVarName);

	static bool DemangleMS(const std::string& mangledName, BinaryNinja::Ref<BinaryNinja::Type>& outType,
	                       BinaryNinja::QualifiedName& outVarName, const BinaryNinja::Ref<BinaryNinja::BinaryView>& view);
	static bool DemangleMS(const std::string& mangledName, BinaryNinja::Ref<BinaryNinja::Type>& outType,
	                       BinaryNinja::QualifiedName& outVarName, BinaryNinja::BinaryView* view);
};

