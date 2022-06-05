#pragma once

#include <vector>
#include <string>

#include "debuginfo.h"
#include "refcount.hpp"

namespace BinaryNinja {
	class NameAndType;
	class DebugFunctionInfo;
	class DataVariableAndName;
	class BinaryView;
	class Type;
	class CallingConvention;
	class Platform;

	class DebugInfo : public CoreRefCountObject<BNDebugInfo, BNNewDebugInfoReference, BNFreeDebugInfoReference>
	{
	  public:
		DebugInfo(BNDebugInfo* debugInfo);

		std::vector<NameAndType> GetTypes(const std::string& parserName = "");
		std::vector<DebugFunctionInfo> GetFunctions(const std::string& parserName = "");
		std::vector<DataVariableAndName> GetDataVariables(const std::string& parserName = "");

		bool AddType(const std::string& name, Ref<Type> type);
		bool AddFunction(const DebugFunctionInfo& function);
		bool AddDataVariable(uint64_t address, Ref<Type> type, const std::string& name = "");
	};

	class DebugInfoParser :
		public CoreRefCountObject<BNDebugInfoParser, BNNewDebugInfoParserReference, BNFreeDebugInfoParserReference>
	{
	  public:
		DebugInfoParser(BNDebugInfoParser* parser);

		static Ref<DebugInfoParser> GetByName(const std::string& name);
		static std::vector<Ref<DebugInfoParser>> GetList();
		static std::vector<Ref<DebugInfoParser>> GetListForView(const Ref<BinaryView> data);

		std::string GetName() const;
		Ref<DebugInfo> Parse(Ref<BinaryView> view, Ref<DebugInfo> existingDebugInfo = nullptr) const;

		bool IsValidForView(const Ref<BinaryView> view) const;
	};

	class CustomDebugInfoParser : public DebugInfoParser
	{
		static bool IsValidCallback(void* ctxt, BNBinaryView* view);
		static void ParseCallback(void* ctxt, BNDebugInfo* debugInfo, BNBinaryView* view);
		BNDebugInfoParser* Register(const std::string& name);

	  public:
		CustomDebugInfoParser(const std::string& name);
		virtual ~CustomDebugInfoParser() {}

		virtual bool IsValid(Ref<BinaryView>) = 0;
		virtual void ParseInfo(Ref<DebugInfo>, Ref<BinaryView>) = 0;
	};

	struct DebugFunctionInfo
	{
		std::string shortName;
		std::string fullName;
		std::string rawName;
		uint64_t address;
		Ref<Type> returnType;
		std::vector<std::tuple<std::string, Ref<Type>>> parameters;
		bool variableParameters;
		Ref<CallingConvention> callingConvention;
		Ref<Platform> platform;

		DebugFunctionInfo(std::string shortName, std::string fullName, std::string rawName, uint64_t address,
		    Ref<Type> returnType, std::vector<std::tuple<std::string, Ref<Type>>> parameters, bool variableParameters,
		    Ref<CallingConvention> callingConvention, Ref<Platform> platform);
	};
}