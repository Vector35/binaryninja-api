#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace BinaryNinja
{
	class BinaryView;
	struct DataVariableAndName;
	struct NameAndType;
	class Platform;
	class Type;
	class TypeContainer;
	struct VariableNameAndType;

	/*!
		\ingroup debuginfo
	*/
	struct DebugFunctionInfo
	{
		std::string shortName;
		std::string fullName;
		std::string rawName;
		uint64_t address;
		Ref<Type> type;
		Ref<Platform> platform;
		std::vector<std::string> components;
		std::vector<VariableNameAndType> localVariables;

		DebugFunctionInfo(std::string shortName, std::string fullName, std::string rawName, uint64_t address,
		    Ref<Type> type, Ref<Platform> platform, const std::vector<std::string>& components,
			const std::vector<VariableNameAndType>& localVariables) :
		    shortName(shortName), fullName(fullName), rawName(rawName),
		    address(address), platform(platform), components(components),
			localVariables(localVariables)
		{}
	};

	/*!
		\ingroup debuginfo
	*/
	class DebugInfo : public CoreRefCountObject<BNDebugInfo, BNNewDebugInfoReference, BNFreeDebugInfoReference>
	{
	  public:
		DebugInfo(BNDebugInfo* debugInfo);

		std::vector<std::string> GetParsers() const;

		/*! Type Container for all types in the DebugInfo that resulted from the parse of
			the given parser.
			\param parserName Name of parser
			\return Type Container for types from that parser
		 */
		TypeContainer GetTypeContainer(const std::string& parserName);

		std::vector<NameAndType> GetTypes(const std::string& parserName = "") const;
		std::vector<DebugFunctionInfo> GetFunctions(const std::string& parserName = "") const;
		std::vector<DataVariableAndName> GetDataVariables(const std::string& parserName = "") const;

		Ref<Type> GetTypeByName(const std::string& parserName, const std::string& name) const;
		std::optional<std::tuple<uint64_t, Ref<Type>>> GetDataVariableByName(
			const std::string& parserName, const std::string& name) const;
		std::optional<std::tuple<std::string, Ref<Type>>> GetDataVariableByAddress(
			const std::string& parserName, const uint64_t address) const;

		std::vector<std::tuple<std::string, Ref<Type>>> GetTypesByName(const std::string& name) const;
		std::vector<std::tuple<std::string, uint64_t, Ref<Type>>> GetDataVariablesByName(const std::string& name) const;
		std::vector<std::tuple<std::string, std::string, Ref<Type>>> GetDataVariablesByAddress(
			const uint64_t address) const;

		bool RemoveParserInfo(const std::string& parserName);
		bool RemoveParserTypes(const std::string& parserName);
		bool RemoveParserFunctions(const std::string& parserName);
		bool RemoveParserDataVariables(const std::string& parserName);

		bool RemoveTypeByName(const std::string& parserName, const std::string& name);
		bool RemoveFunctionByIndex(const std::string& parserName, const size_t index);
		bool RemoveDataVariableByAddress(const std::string& parserName, const uint64_t address);

		bool AddType(const std::string& name, Ref<Type> type, const std::vector<std::string>& components = {});
		bool AddFunction(const DebugFunctionInfo& function);
		bool AddDataVariable(uint64_t address, Ref<Type> type, const std::string& name = "", const std::vector<std::string>& components = {});
	};

	/*!
		\ingroup debuginfo
	*/
	class DebugInfoParser :
	    public CoreRefCountObject<BNDebugInfoParser, BNNewDebugInfoParserReference, BNFreeDebugInfoParserReference>
	{
	  public:
		DebugInfoParser(BNDebugInfoParser* parser);

		static Ref<DebugInfoParser> GetByName(const std::string& name);
		static std::vector<Ref<DebugInfoParser>> GetList();
		static std::vector<Ref<DebugInfoParser>> GetListForView(const Ref<BinaryView> data);

		std::string GetName() const;
		Ref<DebugInfo> Parse(Ref<BinaryView> view, Ref<BinaryView> debugView, Ref<DebugInfo> existingDebugInfo = nullptr, std::function<bool(size_t, size_t)> progress = {}) const;

		bool IsValidForView(const Ref<BinaryView> view) const;
	};

	/*!
		\ingroup debuginfo
	*/
	class CustomDebugInfoParser : public DebugInfoParser
	{
		static bool IsValidCallback(void* ctxt, BNBinaryView* view);
		static bool ParseCallback(void* ctxt, BNDebugInfo* debugInfo, BNBinaryView* view, BNBinaryView* debugFile, bool (*progress)(void*, size_t, size_t), void* progressCtxt);
		BNDebugInfoParser* Register(const std::string& name);

	  public:
		CustomDebugInfoParser(const std::string& name);
		virtual ~CustomDebugInfoParser() {}

		virtual bool IsValid(Ref<BinaryView>) = 0;
		virtual bool ParseInfo(
			Ref<DebugInfo>, Ref<BinaryView>, Ref<BinaryView>, std::function<bool(size_t, size_t)>) = 0;
	};

}
