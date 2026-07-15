/*
Copyright 2020-2026 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

// The Binary Ninja type parser (used to generate the Python bindings) defines
// BN_TYPE_PARSER and supplies its own fixed-width integer types, so skip the system
// headers in that mode to avoid depending on the parser's clang include search paths.
#ifndef BN_TYPE_PARSER
#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#else
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#endif
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __GNUC__
	#ifdef EMULATOR_LIBRARY
		#define EMULATOR_FFI_API __attribute__((visibility("default")))
	#else  // EMULATOR_LIBRARY
		#define EMULATOR_FFI_API
	#endif  // EMULATOR_LIBRARY
#else       // __GNUC__
	#ifdef _MSC_VER
		#ifdef EMULATOR_LIBRARY
			#define EMULATOR_FFI_API __declspec(dllexport)
		#else  // EMULATOR_LIBRARY
			#define EMULATOR_FFI_API __declspec(dllimport)
		#endif  // EMULATOR_LIBRARY
	#else  // _MSC_VER
		#define EMULATOR_FFI_API
	#endif  // _MSC_VER
#endif      // __GNUC__

	// Opaque handles owned by this plugin
	typedef struct BNILEmulator BNILEmulator;
	typedef struct BNLLILEmulator BNLLILEmulator;

	// Binary Ninja core handles used by the emulator API (defined by binaryninjacore.h)
	typedef struct BNBinaryView BNBinaryView;
	typedef struct BNLowLevelILFunction BNLowLevelILFunction;

	enum BNILEmulatorStopReason
	{
		ILEmulatorRunning = 0,
		ILEmulatorBreakpoint,
		ILEmulatorInstructionLimit,
		ILEmulatorHalt,
		ILEmulatorError,
		ILEmulatorCallHook,
		ILEmulatorSyscallHook,
		ILEmulatorUndefinedBehavior,
		ILEmulatorUnimplemented,
		ILEmulatorUserRequestedStop
	};

	struct BNEmulatorMemoryRegion
	{
		uint64_t start;
		uint64_t size;
		char* name;
	};

	struct BNEmulatorCallStackEntry
	{
		uint64_t functionAddress;
		uint64_t returnAddress;
	};

	// IL Emulator — creation/lifecycle
	EMULATOR_FFI_API BNLLILEmulator* BNCreateLLILEmulatorForView(BNBinaryView* view);
	EMULATOR_FFI_API BNLLILEmulator* BNCreateLLILEmulator(BNLowLevelILFunction* il, BNBinaryView* view);
	EMULATOR_FFI_API BNLLILEmulator* BNNewLLILEmulatorReference(BNLLILEmulator* emu);
	EMULATOR_FFI_API void BNFreeLLILEmulator(BNLLILEmulator* emu);
	EMULATOR_FFI_API BNILEmulator* BNLLILEmulatorGetBase(BNLLILEmulator* emu);
	EMULATOR_FFI_API bool BNLLILEmulatorSetEntryPoint(BNLLILEmulator* emu, uint64_t addr);
	EMULATOR_FFI_API void BNLLILEmulatorSetEntryPointForIL(BNLLILEmulator* emu,
		BNLowLevelILFunction* il, size_t instrIndex);
	EMULATOR_FFI_API void BNLLILEmulatorSetArgument(BNLLILEmulator* emu, size_t index, const uint8_t* buf, size_t bufLen);
	EMULATOR_FFI_API void BNLLILEmulatorSetArguments(BNLLILEmulator* emu, const uint64_t* values, size_t count);

	// IL Emulator — execution control (shared)
	EMULATOR_FFI_API BNILEmulatorStopReason BNILEmulatorRun(BNILEmulator* emu);
	EMULATOR_FFI_API BNILEmulatorStopReason BNILEmulatorStep(BNILEmulator* emu);
	EMULATOR_FFI_API BNILEmulatorStopReason BNILEmulatorStepN(BNILEmulator* emu, size_t n);

	// IL Emulator — state (shared)
	EMULATOR_FFI_API size_t BNILEmulatorGetInstructionIndex(BNILEmulator* emu);
	EMULATOR_FFI_API void BNILEmulatorSetInstructionIndex(BNILEmulator* emu, size_t index);
	EMULATOR_FFI_API uint64_t BNILEmulatorGetCurrentAddress(BNILEmulator* emu);
	EMULATOR_FFI_API BNILEmulatorStopReason BNILEmulatorGetStopReason(BNILEmulator* emu);
	EMULATOR_FFI_API char* BNILEmulatorGetStopMessage(BNILEmulator* emu);

	// IL Emulator — memory (shared)
	EMULATOR_FFI_API size_t BNILEmulatorReadMemory(BNILEmulator* emu, void* dest, uint64_t addr, size_t len);
	EMULATOR_FFI_API size_t BNILEmulatorWriteMemory(BNILEmulator* emu, uint64_t addr, const void* src, size_t len);
	EMULATOR_FFI_API void BNILEmulatorMapMemory(BNILEmulator* emu, uint64_t addr, const void* data, size_t len);
	EMULATOR_FFI_API void BNILEmulatorMapMemoryZero(BNILEmulator* emu, uint64_t addr, size_t len);
	EMULATOR_FFI_API void BNILEmulatorMapMemoryNamed(BNILEmulator* emu, uint64_t addr, const void* data, size_t len, const char* name);
	EMULATOR_FFI_API void BNILEmulatorMapMemoryZeroNamed(BNILEmulator* emu, uint64_t addr, size_t len, const char* name);

	// IL Emulator — breakpoints (shared, by address)
	EMULATOR_FFI_API void BNILEmulatorAddBreakpoint(BNILEmulator* emu, uint64_t addr);
	EMULATOR_FFI_API void BNILEmulatorRemoveBreakpoint(BNILEmulator* emu, uint64_t addr);
	EMULATOR_FFI_API void BNILEmulatorClearBreakpoints(BNILEmulator* emu);

	// IL Emulator — limits (shared)
	EMULATOR_FFI_API void BNILEmulatorSetMaxInstructions(BNILEmulator* emu, size_t max);
	EMULATOR_FFI_API size_t BNILEmulatorGetInstructionsExecuted(BNILEmulator* emu);

	// IL Emulator — hooks (shared)
	EMULATOR_FFI_API void BNILEmulatorSetCallHook(BNILEmulator* emu, void* ctxt,
		bool (*callback)(void* ctxt, BNILEmulator* emu, uint64_t target));
	EMULATOR_FFI_API void BNILEmulatorSetSyscallHook(BNILEmulator* emu, void* ctxt,
		bool (*callback)(void* ctxt, BNILEmulator* emu));
	EMULATOR_FFI_API void BNILEmulatorSetMemoryReadHook(BNILEmulator* emu, void* ctxt,
		bool (*callback)(void* ctxt, BNILEmulator* emu, uint64_t addr, size_t size, uint8_t* outBuf, size_t bufLen));
	EMULATOR_FFI_API void BNILEmulatorSetMemoryWriteHook(BNILEmulator* emu, void* ctxt,
		bool (*callback)(void* ctxt, BNILEmulator* emu, uint64_t addr, size_t size, const uint8_t* buf, size_t bufLen));
	EMULATOR_FFI_API void BNILEmulatorSetPreInstructionHook(BNILEmulator* emu, void* ctxt,
		bool (*callback)(void* ctxt, BNILEmulator* emu, size_t instrIndex));
	EMULATOR_FFI_API void BNILEmulatorSetStdoutCallback(BNILEmulator* emu, void* ctxt,
		void (*callback)(void* ctxt, BNILEmulator* emu, const char* data, size_t len));
	EMULATOR_FFI_API void BNILEmulatorSetStdinCallback(BNILEmulator* emu, void* ctxt,
		size_t (*callback)(void* ctxt, BNILEmulator* emu, char* buf, size_t maxLen));
	EMULATOR_FFI_API void BNILEmulatorRequestStop(BNILEmulator* emu);
	EMULATOR_FFI_API void BNILEmulatorReset(BNILEmulator* emu);

	// LLIL Emulator — register/flag access (byte-buffer API; values are 64-byte little-endian)
	EMULATOR_FFI_API void BNLLILEmulatorGetRegister(BNLLILEmulator* emu, uint32_t reg, uint8_t* outBuf, size_t bufLen);
	EMULATOR_FFI_API void BNLLILEmulatorSetRegister(BNLLILEmulator* emu, uint32_t reg, const uint8_t* buf, size_t bufLen);
	EMULATOR_FFI_API void BNLLILEmulatorGetTempRegister(BNLLILEmulator* emu, uint32_t index, uint8_t* outBuf, size_t bufLen);
	EMULATOR_FFI_API void BNLLILEmulatorSetTempRegister(BNLLILEmulator* emu, uint32_t index, const uint8_t* buf, size_t bufLen);
	EMULATOR_FFI_API size_t BNLLILEmulatorGetAllTempRegisters(
		BNLLILEmulator* emu, uint32_t* outIndices, uint8_t* outValues, size_t maxCount);
	EMULATOR_FFI_API uint8_t BNLLILEmulatorGetFlag(BNLLILEmulator* emu, uint32_t flag);
	EMULATOR_FFI_API void BNLLILEmulatorSetFlag(BNLLILEmulator* emu, uint32_t flag, uint8_t value);

	// LLIL Emulator — intrinsic hook.
	// The callback receives output buffers outValues/outRegs with capacity maxCount entries;
	// it must write at most maxCount pairs and set *outCount to the number written.
	EMULATOR_FFI_API void BNLLILEmulatorSetIntrinsicHook(BNLLILEmulator* emu, void* ctxt,
		bool (*callback)(void* ctxt, BNLLILEmulator* emu, uint32_t intrinsic,
			const uint64_t* params, size_t paramCount,
			uint64_t* outValues, uint32_t* outRegs, size_t maxCount, size_t* outCount));

	// LLIL Emulator — call stack
	EMULATOR_FFI_API size_t BNLLILEmulatorGetCallStackDepth(BNLLILEmulator* emu);
	EMULATOR_FFI_API BNEmulatorCallStackEntry* BNLLILEmulatorGetCallStack(BNLLILEmulator* emu, size_t* count);
	EMULATOR_FFI_API void BNLLILEmulatorFreeCallStack(BNEmulatorCallStackEntry* entries);

	// LLIL Emulator — stepping
	EMULATOR_FFI_API BNILEmulatorStopReason BNLLILEmulatorStepOver(BNLLILEmulator* emu);

	// IL Emulator — memory regions
	EMULATOR_FFI_API BNEmulatorMemoryRegion* BNILEmulatorGetMappedRegions(BNILEmulator* emu, size_t* count);
	EMULATOR_FFI_API void BNFreeEmulatorMemoryRegions(BNEmulatorMemoryRegion* regions, size_t count);

	// LLIL Emulator — built-in libc stubs
	EMULATOR_FFI_API void BNLLILEmulatorSetBuiltinLibcStubsEnabled(BNLLILEmulator* emu, bool enabled);
	EMULATOR_FFI_API bool BNLLILEmulatorIsBuiltinLibcStubsEnabled(BNLLILEmulator* emu);
	EMULATOR_FFI_API void BNLLILEmulatorSetLogLibcCalls(BNLLILEmulator* emu, bool enabled);
	EMULATOR_FFI_API bool BNLLILEmulatorIsLogLibcCalls(BNLLILEmulator* emu);
	EMULATOR_FFI_API void BNLLILEmulatorSetNopUnknownExternals(BNLLILEmulator* emu, bool enabled);
	EMULATOR_FFI_API bool BNLLILEmulatorIsNopUnknownExternals(BNLLILEmulator* emu);

	// LLIL Emulator — state serialization
	EMULATOR_FFI_API char* BNLLILEmulatorSaveState(BNLLILEmulator* emu);
	EMULATOR_FFI_API bool BNLLILEmulatorLoadState(BNLLILEmulator* emu, const char* json);

#ifdef __cplusplus
}
#endif
