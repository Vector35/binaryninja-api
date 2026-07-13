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

#include "binaryninjaapi.h"
#include "ffi.h"
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace BinaryNinja
{
	/*!
		\ingroup emulator
	*/
	class LLILEmulator :
	    public CoreRefCountObject<BNLLILEmulator, BNNewLLILEmulatorReference, BNFreeLLILEmulator>
	{
		// Stored hooks (prevent dangling captures)
		std::function<bool(LLILEmulator*, uint64_t)> m_callHook;
		std::function<bool(LLILEmulator*)> m_syscallHook;
		std::function<bool(LLILEmulator*, uint64_t, size_t, intx::uint512&)> m_memoryReadHook;
		std::function<bool(LLILEmulator*, uint64_t, size_t, const intx::uint512&)> m_memoryWriteHook;
		std::function<bool(LLILEmulator*, size_t)> m_preInstructionHook;
		std::function<bool(LLILEmulator*, uint32_t, const std::vector<uint64_t>&,
			std::vector<std::pair<uint32_t, uint64_t>>&)> m_intrinsicHook;
		std::function<void(LLILEmulator*, const std::string&)> m_stdoutCallback;
		std::function<size_t(LLILEmulator*, char*, size_t)> m_stdinCallback;

		// Static C bridge callbacks
		static bool CallHookCallback(void* ctxt, BNILEmulator* emu, uint64_t target);
		static bool SyscallHookCallback(void* ctxt, BNILEmulator* emu);
		static bool MemoryReadHookCallback(void* ctxt, BNILEmulator* emu,
			uint64_t addr, size_t size, uint8_t* outBuf, size_t bufLen);
		static bool MemoryWriteHookCallback(void* ctxt, BNILEmulator* emu,
			uint64_t addr, size_t size, const uint8_t* buf, size_t bufLen);
		static bool PreInstructionHookCallback(void* ctxt, BNILEmulator* emu, size_t instrIndex);
		static bool IntrinsicHookCallback(void* ctxt, BNLLILEmulator* emu,
			uint32_t intrinsic, const uint64_t* params, size_t paramCount,
			uint64_t* outValues, uint32_t* outRegs, size_t* outCount);
		static void StdoutCallbackBridge(void* ctxt, BNILEmulator* emu, const char* data, size_t len);
		static size_t StdinCallbackBridge(void* ctxt, BNILEmulator* emu, char* buf, size_t maxLen);

	  public:
		LLILEmulator(Ref<BinaryView> view);
		LLILEmulator(Ref<LowLevelILFunction> il, Ref<BinaryView> view);
		LLILEmulator(BNLLILEmulator* emu);

		bool SetEntryPoint(uint64_t addr);
		void SetEntryPoint(Ref<LowLevelILFunction> il, size_t instrIndex);

		// Argument setup (uses default calling convention)
		void SetArgument(size_t index, const intx::uint512& value);
		void SetArguments(const std::vector<uint64_t>& values);

		// Execution
		BNILEmulatorStopReason Run();
		BNILEmulatorStopReason Step();
		BNILEmulatorStopReason StepN(size_t n);
		BNILEmulatorStopReason StepOver();
		void RequestStop();

		// State
		size_t GetInstructionIndex() const;
		void SetInstructionIndex(size_t index);
		uint64_t GetCurrentAddress() const;
		BNILEmulatorStopReason GetStopReason() const;
		std::string GetStopMessage() const;

		// Memory
		size_t ReadMemory(void* dest, uint64_t addr, size_t len) const;
		size_t WriteMemory(uint64_t addr, const void* src, size_t len);
		void MapMemory(uint64_t addr, const void* data, size_t len, const std::string& name = "");
		void MapMemory(uint64_t addr, size_t len, const std::string& name = "");

		// Breakpoints (by address)
		void AddBreakpoint(uint64_t addr);
		void RemoveBreakpoint(uint64_t addr);
		void ClearBreakpoints();

		// Limits
		void SetMaxInstructions(size_t max);
		size_t GetInstructionsExecuted() const;

		// Hooks
		void SetCallHook(const std::function<bool(LLILEmulator*, uint64_t)>& hook);
		void SetSyscallHook(const std::function<bool(LLILEmulator*)>& hook);
		void SetMemoryReadHook(const std::function<bool(LLILEmulator*, uint64_t, size_t, intx::uint512&)>& hook);
		void SetMemoryWriteHook(const std::function<bool(LLILEmulator*, uint64_t, size_t, const intx::uint512&)>& hook);
		void SetPreInstructionHook(const std::function<bool(LLILEmulator*, size_t)>& hook);
		void SetIntrinsicHook(const std::function<bool(LLILEmulator*, uint32_t,
			const std::vector<uint64_t>&, std::vector<std::pair<uint32_t, uint64_t>>&)>& hook);
		void SetStdoutCallback(const std::function<void(LLILEmulator*, const std::string&)>& cb);
		void SetStdinCallback(const std::function<size_t(LLILEmulator*, char*, size_t)>& cb);

		// Register / flag / temp access
		intx::uint512 GetRegister(uint32_t reg) const;
		void SetRegister(uint32_t reg, const intx::uint512& value);
		intx::uint512 GetTempRegister(uint32_t index) const;
		void SetTempRegister(uint32_t index, const intx::uint512& value);
		std::unordered_map<uint32_t, intx::uint512> GetAllTempRegisters() const;
		uint8_t GetFlag(uint32_t flag) const;
		void SetFlag(uint32_t flag, uint8_t value);

		// Cross-function state
		size_t GetCallStackDepth() const;

		struct CallStackEntry
		{
			uint64_t functionAddress;
			uint64_t returnAddress;
		};
		std::vector<CallStackEntry> GetCallStack() const;

		// Memory regions
		struct MappedRegion
		{
			uint64_t start;
			uint64_t size;
			std::string name;
		};
		std::vector<MappedRegion> GetMappedRegions() const;

		// Built-in libc stub settings
		void SetBuiltinLibcStubsEnabled(bool enabled);
		bool IsBuiltinLibcStubsEnabled() const;
		void SetLogLibcCalls(bool enabled);
		bool IsLogLibcCalls() const;
		void SetNopUnknownExternals(bool enabled);
		bool IsNopUnknownExternals() const;

		// Reset
		void Reset();

		// State serialization
		std::string SaveState() const;
		bool LoadState(const std::string& json);
	};
}  // namespace BinaryNinja
