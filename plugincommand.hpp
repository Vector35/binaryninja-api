#pragma once
#include <string>
#include <functional>

#include "refcount.hpp"
#include "plugincommand.h"

namespace BinaryNinja {
	class BinaryView;
	class Function;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class HighLevelILFunction;
	class LowLevelILInstruction;
	class MediumLevelILInstruction;
	class HighLevelILInstruction;

	struct PluginCommandContext
	{
		Ref<BinaryView> binaryView;
		uint64_t address, length;
		size_t instrIndex;
		Ref<Function> function;
		Ref<LowLevelILFunction> lowLevelILFunction;
		Ref<MediumLevelILFunction> mediumLevelILFunction;
		Ref<HighLevelILFunction> highLevelILFunction;

		PluginCommandContext();
	};

	class HighLevelILInstruction;
	class PluginCommand
	{
		BNPluginCommand m_command;

		struct RegisteredDefaultCommand
		{
			std::function<void(BinaryView*)> action;
			std::function<bool(BinaryView*)> isValid;
		};

		struct RegisteredAddressCommand
		{
			std::function<void(BinaryView*, uint64_t)> action;
			std::function<bool(BinaryView*, uint64_t)> isValid;
		};

		struct RegisteredRangeCommand
		{
			std::function<void(BinaryView*, uint64_t, uint64_t)> action;
			std::function<bool(BinaryView*, uint64_t, uint64_t)> isValid;
		};

		struct RegisteredFunctionCommand
		{
			std::function<void(BinaryView*, Function*)> action;
			std::function<bool(BinaryView*, Function*)> isValid;
		};

		struct RegisteredLowLevelILFunctionCommand
		{
			std::function<void(BinaryView*, LowLevelILFunction*)> action;
			std::function<bool(BinaryView*, LowLevelILFunction*)> isValid;
		};

		struct RegisteredLowLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const LowLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const LowLevelILInstruction&)> isValid;
		};

		struct RegisteredMediumLevelILFunctionCommand
		{
			std::function<void(BinaryView*, MediumLevelILFunction*)> action;
			std::function<bool(BinaryView*, MediumLevelILFunction*)> isValid;
		};

		struct RegisteredMediumLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const MediumLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const MediumLevelILInstruction&)> isValid;
		};

		struct RegisteredHighLevelILFunctionCommand
		{
			std::function<void(BinaryView*, HighLevelILFunction*)> action;
			std::function<bool(BinaryView*, HighLevelILFunction*)> isValid;
		};

		struct RegisteredHighLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const HighLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const HighLevelILInstruction&)> isValid;
		};

		static void DefaultPluginCommandActionCallback(void* ctxt, BNBinaryView* view);
		static void AddressPluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static void RangePluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static void FunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view, BNFunction* func);
		static void LowLevelILFunctionPluginCommandActionCallback(
			void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		static void LowLevelILInstructionPluginCommandActionCallback(
			void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		static void MediumLevelILFunctionPluginCommandActionCallback(
			void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		static void MediumLevelILInstructionPluginCommandActionCallback(
			void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		static void HighLevelILFunctionPluginCommandActionCallback(
			void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		static void HighLevelILInstructionPluginCommandActionCallback(
			void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

		static bool DefaultPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view);
		static bool AddressPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static bool RangePluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static bool FunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, BNFunction* func);
		static bool LowLevelILFunctionPluginCommandIsValidCallback(
			void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		static bool LowLevelILInstructionPluginCommandIsValidCallback(
			void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		static bool MediumLevelILFunctionPluginCommandIsValidCallback(
			void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		static bool MediumLevelILInstructionPluginCommandIsValidCallback(
			void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		static bool HighLevelILFunctionPluginCommandIsValidCallback(
			void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		static bool HighLevelILInstructionPluginCommandIsValidCallback(
			void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

	  public:
		PluginCommand(const BNPluginCommand& cmd);
		PluginCommand(const PluginCommand& cmd);
		~PluginCommand();

		PluginCommand& operator=(const PluginCommand& cmd);

		static void Register(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view)>& action);
		static void Register(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view)>& action, const std::function<bool(BinaryView* view)>& isValid);
		static void RegisterForAddress(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, uint64_t addr)>& action);
		static void RegisterForAddress(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, uint64_t addr)>& action,
			const std::function<bool(BinaryView* view, uint64_t addr)>& isValid);
		static void RegisterForRange(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action);
		static void RegisterForRange(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action,
			const std::function<bool(BinaryView* view, uint64_t addr, uint64_t len)>& isValid);
		static void RegisterForFunction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, Function* func)>& action);
		static void RegisterForFunction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, Function* func)>& action,
			const std::function<bool(BinaryView* view, Function* func)>& isValid);
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action);
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action,
			const std::function<bool(BinaryView* view, LowLevelILFunction* func)>& isValid);
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action);
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action,
			const std::function<bool(BinaryView* view, const LowLevelILInstruction& instr)>& isValid);
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action);
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action,
			const std::function<bool(BinaryView* view, MediumLevelILFunction* func)>& isValid);
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action);
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action,
			const std::function<bool(BinaryView* view, const MediumLevelILInstruction& instr)>& isValid);
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action);
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action,
			const std::function<bool(BinaryView* view, HighLevelILFunction* func)>& isValid);
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action);
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action,
			const std::function<bool(BinaryView* view, const HighLevelILInstruction& instr)>& isValid);

		static std::vector<PluginCommand> GetList();
		static std::vector<PluginCommand> GetValidList(const PluginCommandContext& ctxt);

		std::string GetName() const { return m_command.name; }
		std::string GetDescription() const { return m_command.description; }
		BNPluginCommandType GetType() const { return m_command.type; }
		const BNPluginCommand* GetObject() const { return &m_command; }

		bool IsValid(const PluginCommandContext& ctxt) const;
		void Execute(const PluginCommandContext& ctxt) const;
	};
}