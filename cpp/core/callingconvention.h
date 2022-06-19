#pragma once
#include "core/binaryninja_defs.h"
#include "core/registervalue.h"

extern "C" {
	struct BNArchitecture;
	struct BNCallingConvention;
	struct BNFunction;
	struct BNVariable;

	struct BNCustomCallingConvention
	{
		void* context;

		void (*freeObject)(void* ctxt);

		uint32_t* (*getCallerSavedRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getCalleeSavedRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getIntegerArgumentRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getFloatArgumentRegisters)(void* ctxt, size_t* count);
		void (*freeRegisterList)(void* ctxt, uint32_t* regs);

		bool (*areArgumentRegistersSharedIndex)(void* ctxt);
		bool (*isStackReservedForArgumentRegisters)(void* ctxt);
		bool (*isStackAdjustedOnReturn)(void* ctxt);
		bool (*isEligibleForHeuristics)(void* ctxt);

		uint32_t (*getIntegerReturnValueRegister)(void* ctxt);
		uint32_t (*getHighIntegerReturnValueRegister)(void* ctxt);
		uint32_t (*getFloatReturnValueRegister)(void* ctxt);
		uint32_t (*getGlobalPointerRegister)(void* ctxt);

		uint32_t* (*getImplicitlyDefinedRegisters)(void* ctxt, size_t* count);
		void (*getIncomingRegisterValue)(void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);
		void (*getIncomingFlagValue)(void* ctxt, uint32_t flag, BNFunction* func, BNRegisterValue* result);

		void (*getIncomingVariableForParameterVariable)(
		    void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result);
		void (*getParameterVariableForIncomingVariable)(
		    void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result);

		bool (*areArgumentRegistersUsedForVarArgs)(void* ctxt);
	};

	// Calling conventions
	BINARYNINJACOREAPI BNCallingConvention* BNCreateCallingConvention(
		BNArchitecture* arch, const char* name, BNCustomCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);
	BINARYNINJACOREAPI BNCallingConvention* BNNewCallingConventionReference(BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNFreeCallingConvention(BNCallingConvention* cc);

	BINARYNINJACOREAPI void BNFreeCallingConventionList(BNCallingConvention** list, size_t count);

	BINARYNINJACOREAPI BNArchitecture* BNGetCallingConventionArchitecture(BNCallingConvention* cc);
	BINARYNINJACOREAPI char* BNGetCallingConventionName(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t* BNGetCallerSavedRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetCalleeSavedRegisters(BNCallingConvention* cc, size_t* count);

	BINARYNINJACOREAPI uint32_t* BNGetIntegerArgumentRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetFloatArgumentRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI bool BNAreArgumentRegistersSharedIndex(BNCallingConvention* cc);
	BINARYNINJACOREAPI bool BNAreArgumentRegistersUsedForVarArgs(BNCallingConvention* cc);
	BINARYNINJACOREAPI bool BNIsStackReservedForArgumentRegisters(BNCallingConvention* cc);
	BINARYNINJACOREAPI bool BNIsStackAdjustedOnReturn(BNCallingConvention* cc);
	BINARYNINJACOREAPI bool BNIsEligibleForHeuristics(BNCallingConvention* cc);

	BINARYNINJACOREAPI uint32_t BNGetIntegerReturnValueRegister(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t BNGetHighIntegerReturnValueRegister(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t BNGetFloatReturnValueRegister(BNCallingConvention* cc);
	BINARYNINJACOREAPI uint32_t BNGetGlobalPointerRegister(BNCallingConvention* cc);

	BINARYNINJACOREAPI uint32_t* BNGetImplicitlyDefinedRegisters(BNCallingConvention* cc, size_t* count);
	BINARYNINJACOREAPI BNRegisterValue BNGetIncomingRegisterValue(
		BNCallingConvention* cc, uint32_t reg, BNFunction* func);
	BINARYNINJACOREAPI BNRegisterValue BNGetIncomingFlagValue(BNCallingConvention* cc, uint32_t reg, BNFunction* func);

	BINARYNINJACOREAPI BNVariable BNGetIncomingVariableForParameterVariable(
		BNCallingConvention* cc, const BNVariable* var, BNFunction* func);
	BINARYNINJACOREAPI BNVariable BNGetParameterVariableForIncomingVariable(
		BNCallingConvention* cc, const BNVariable* var, BNFunction* func);
	BINARYNINJACOREAPI BNVariable BNGetDefaultIncomingVariableForParameterVariable(
		BNCallingConvention* cc, const BNVariable* var);
	BINARYNINJACOREAPI BNVariable BNGetDefaultParameterVariableForIncomingVariable(
		BNCallingConvention* cc, const BNVariable* var);

}