#pragma once
#include "binaryninja_defs.h"

extern "C" {
    struct BNBinaryView;
    struct BNLowLevelILFunction;
    struct BNMediumLevelILFunction;
    struct BNHighLevelILFunction;

	enum BNPluginCommandType
	{
		DefaultPluginCommand,
		AddressPluginCommand,
		RangePluginCommand,
		FunctionPluginCommand,
		LowLevelILFunctionPluginCommand,
		LowLevelILInstructionPluginCommand,
		MediumLevelILFunctionPluginCommand,
		MediumLevelILInstructionPluginCommand,
		HighLevelILFunctionPluginCommand,
		HighLevelILInstructionPluginCommand
	};

	struct BNPluginCommand
	{
		char* name;
		char* description;
		BNPluginCommandType type;
		void* context;

		void (*defaultCommand)(void* ctxt, BNBinaryView* view);
		void (*addressCommand)(void* ctxt, BNBinaryView* view, uint64_t addr);
		void (*rangeCommand)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		void (*functionCommand)(void* ctxt, BNBinaryView* view, BNFunction* func);
		void (*lowLevelILFunctionCommand)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		void (*lowLevelILInstructionCommand)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		void (*mediumLevelILFunctionCommand)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		void (*mediumLevelILInstructionCommand)(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		void (*highLevelILFunctionCommand)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		void (*highLevelILInstructionCommand)(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

		bool (*defaultIsValid)(void* ctxt, BNBinaryView* view);
		bool (*addressIsValid)(void* ctxt, BNBinaryView* view, uint64_t addr);
		bool (*rangeIsValid)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		bool (*functionIsValid)(void* ctxt, BNBinaryView* view, BNFunction* func);
		bool (*lowLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		bool (*lowLevelILInstructionIsValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		bool (*mediumLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		bool (*mediumLevelILInstructionIsValid)(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		bool (*highLevelILFunctionIsValid)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		bool (*highLevelILInstructionIsValid)(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);
	};

	BINARYNINJACOREAPI BNPluginCommand* BNGetAllPluginCommands(size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommands(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForAddress(
	    BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForRange(
	    BNBinaryView* view, uint64_t addr, uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForFunction(
	    BNBinaryView* view, BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForLowLevelILFunction(
	    BNBinaryView* view, BNLowLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForLowLevelILInstruction(
	    BNBinaryView* view, BNLowLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForMediumLevelILFunction(
	    BNBinaryView* view, BNMediumLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForMediumLevelILInstruction(
	    BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForHighLevelILFunction(
	    BNBinaryView* view, BNHighLevelILFunction* func, size_t* count);
	BINARYNINJACOREAPI BNPluginCommand* BNGetValidPluginCommandsForHighLevelILInstruction(
	    BNBinaryView* view, BNHighLevelILFunction* func, size_t instr, size_t* count);
	BINARYNINJACOREAPI void BNFreePluginCommandList(BNPluginCommand* commands);

	// Plugin commands
	BINARYNINJACOREAPI void BNRegisterPluginCommand(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view), bool (*isValid)(void* ctxt, BNBinaryView* view), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForAddress(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, uint64_t addr),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, uint64_t addr), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForRange(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForFunction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNFunction* func),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForLowLevelILFunction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForLowLevelILInstruction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForMediumLevelILFunction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForMediumLevelILInstruction(const char* name,
	    const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForHighLevelILFunction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func), void* context);
	BINARYNINJACOREAPI void BNRegisterPluginCommandForHighLevelILInstruction(const char* name, const char* description,
	    void (*action)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr),
	    bool (*isValid)(void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr), void* context);
}