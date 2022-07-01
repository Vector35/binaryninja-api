#pragma once
#include "binaryninjacore/callingconvention.h"
#include "refcount.hpp"
#include "registervalue.hpp"

namespace BinaryNinja {
	class Architecture;
	class Function;
	struct Variable;

	class CallingConvention :
		public CoreRefCountObject<BNCallingConvention, BNNewCallingConventionReference, BNFreeCallingConvention>
	{
	  protected:
		CallingConvention(BNCallingConvention* cc);
		CallingConvention(Architecture* arch, const std::string& name);

		static void FreeCallback(void* ctxt);

		static uint32_t* GetCallerSavedRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetCalleeSavedRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetIntegerArgumentRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetFloatArgumentRegistersCallback(void* ctxt, size_t* count);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs);

		static bool AreArgumentRegistersSharedIndexCallback(void* ctxt);
		static bool AreArgumentRegistersUsedForVarArgsCallback(void* ctxt);
		static bool IsStackReservedForArgumentRegistersCallback(void* ctxt);
		static bool IsStackAdjustedOnReturnCallback(void* ctxt);
		static bool IsEligibleForHeuristicsCallback(void* ctxt);

		static uint32_t GetIntegerReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetHighIntegerReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetFloatReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetGlobalPointerRegisterCallback(void* ctxt);

		static uint32_t* GetImplicitlyDefinedRegistersCallback(void* ctxt, size_t* count);
		static void GetIncomingRegisterValueCallback(
			void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);
		static void GetIncomingFlagValueCallback(void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);

		static void GetIncomingVariableForParameterVariableCallback(
			void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result);
		static void GetParameterVariableForIncomingVariableCallback(
			void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result);

	  public:
		Ref<Architecture> GetArchitecture() const;
		std::string GetName() const;

		virtual std::vector<uint32_t> GetCallerSavedRegisters();
		virtual std::vector<uint32_t> GetCalleeSavedRegisters();

		virtual std::vector<uint32_t> GetIntegerArgumentRegisters();
		virtual std::vector<uint32_t> GetFloatArgumentRegisters();
		virtual bool AreArgumentRegistersSharedIndex();
		virtual bool AreArgumentRegistersUsedForVarArgs();
		virtual bool IsStackReservedForArgumentRegisters();
		virtual bool IsStackAdjustedOnReturn();
		virtual bool IsEligibleForHeuristics();

		virtual uint32_t GetIntegerReturnValueRegister() = 0;
		virtual uint32_t GetHighIntegerReturnValueRegister();
		virtual uint32_t GetFloatReturnValueRegister();
		virtual uint32_t GetGlobalPointerRegister();

		virtual std::vector<uint32_t> GetImplicitlyDefinedRegisters();
		virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func);
		virtual RegisterValue GetIncomingFlagValue(uint32_t flag, Function* func);

		virtual Variable GetIncomingVariableForParameterVariable(const Variable& var, Function* func);
		virtual Variable GetParameterVariableForIncomingVariable(const Variable& var, Function* func);
	};

	class CoreCallingConvention : public CallingConvention
	{
	  public:
		CoreCallingConvention(BNCallingConvention* cc);

		virtual std::vector<uint32_t> GetCallerSavedRegisters() override;
		virtual std::vector<uint32_t> GetCalleeSavedRegisters() override;

		virtual std::vector<uint32_t> GetIntegerArgumentRegisters() override;
		virtual std::vector<uint32_t> GetFloatArgumentRegisters() override;
		virtual bool AreArgumentRegistersSharedIndex() override;
		virtual bool AreArgumentRegistersUsedForVarArgs() override;
		virtual bool IsStackReservedForArgumentRegisters() override;
		virtual bool IsStackAdjustedOnReturn() override;
		virtual bool IsEligibleForHeuristics() override;

		virtual uint32_t GetIntegerReturnValueRegister() override;
		virtual uint32_t GetHighIntegerReturnValueRegister() override;
		virtual uint32_t GetFloatReturnValueRegister() override;
		virtual uint32_t GetGlobalPointerRegister() override;

		virtual std::vector<uint32_t> GetImplicitlyDefinedRegisters() override;
		virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func) override;
		virtual RegisterValue GetIncomingFlagValue(uint32_t flag, Function* func) override;

		virtual Variable GetIncomingVariableForParameterVariable(const Variable& var, Function* func) override;
		virtual Variable GetParameterVariableForIncomingVariable(const Variable& var, Function* func) override;
	};
}