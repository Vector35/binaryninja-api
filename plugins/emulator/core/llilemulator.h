#pragma once

#include "ilemulator.h"
#include "lowlevelilinstruction.h"

DECLARE_EMULATOR_API_OBJECT(BNLLILEmulator, LLILEmulator);

namespace BinaryNinjaEmulator
{
	class LLILEmulator : public ILEmulator
	{
		IMPLEMENT_EMULATOR_API_OBJECT(BNLLILEmulator)

		BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
		BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> m_il;
		BinaryNinja::Ref<BinaryNinja::Architecture> m_arch;

		// LLIL-specific state
		std::unordered_map<uint32_t, intx::uint512> m_registers;
		std::unordered_map<uint32_t, intx::uint512> m_tempRegisters;
		std::unordered_map<uint32_t, uint8_t> m_flags;

		// Call stack for cross-function emulation
		struct CallFrame
		{
			BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> il;
			BinaryNinja::Ref<BinaryNinja::Architecture> arch;
			size_t returnIndex;  // instruction index to resume in caller
			std::unordered_map<uint32_t, intx::uint512> tempRegisters;  // saved caller temps
		};
		std::vector<CallFrame> m_callStack;

		using IntrinsicHook = std::function<bool(
			LLILEmulator* emu, uint32_t intrinsic,
			const std::vector<uint64_t>& params,
			std::vector<std::pair<uint32_t, uint64_t>>& outputs)>;
		IntrinsicHook m_intrinsicHook;

		// Arithmetic context for flag computation (non-lifted LLIL)
		struct ArithmeticContext
		{
			intx::uint512 left;
			intx::uint512 right;
			intx::uint512 result;
			size_t size;
			BNLowLevelILOperation operation;
			bool valid;
		};
		ArithmeticContext m_lastArithmetic {};

		// Built-in libc stub settings
		bool m_builtinLibcStubs = true;
		bool m_logLibcCalls = true;
		bool m_nopUnknownExternals = false;

		// Heap allocator state for malloc/free/etc.
		static constexpr uint64_t HEAP_BASE = 0x40000000;
		static constexpr size_t HEAP_SIZE = 16 * 1024 * 1024;  // 16MB
		uint64_t m_heapBumpPtr = HEAP_BASE;
		bool m_heapMapped = false;
		std::unordered_map<uint64_t, size_t> m_heapAllocations;

		// Core dispatch
		intx::uint512 EvalExpr(const BinaryNinja::LowLevelILInstruction& expr);
		void ExecuteCurrentInstruction() override;
		size_t GetInstructionCount() const override;
		uint64_t GetCurrentInstructionAddress() const override;
		BNEndianness GetEndianness() const override;

		// Helpers
		static intx::uint512 MaskToSize(const intx::uint512& value, size_t size);
		static intx::uint512 SignExtend(const intx::uint512& value, size_t fromSize, size_t toSize);
		void Push(const intx::uint512& value, size_t size);
		intx::uint512 Pop(size_t size);
		intx::uint512 EvalFlagCondition(BNLowLevelILFlagCondition cond, uint32_t semClass);
		void WriteFlags(uint32_t flagWriteType);
		uint8_t ComputeFlagForRole(BNFlagRole role) const;

		// Cross-function call support
		bool EnterFunction(uint64_t addr, size_t returnIndex);
		bool ReturnToCaller();
		uint64_t GetNativeReturnAddress() const;

		// Built-in libc stub helpers
		uint64_t ReadArgument(size_t index);
		void WriteReturnValue(uint64_t value);
		intx::uint512 ReadArgumentWide(size_t index);
		void WriteReturnValueWide(const intx::uint512& value);
		std::string ResolveCallTargetName(uint64_t addr);
		static std::string NormalizeLibcName(const std::string& name);
		bool HandleBuiltinCall(uint64_t dest);
		bool HandleUnknownCall(uint64_t dest);
		void EnsureHeapMapped();

		// Stub implementations
		using StubFn = bool (LLILEmulator::*)(uint64_t dest);
		static const std::unordered_map<std::string, StubFn>& GetStubTable();
		bool StubMemcpy(uint64_t dest);
		bool StubMemset(uint64_t dest);
		bool StubMemmove(uint64_t dest);
		bool StubStrlen(uint64_t dest);
		bool StubStrcmp(uint64_t dest);
		bool StubStrncmp(uint64_t dest);
		bool StubStrcpy(uint64_t dest);
		bool StubStrncpy(uint64_t dest);
		bool StubMalloc(uint64_t dest);
		bool StubFree(uint64_t dest);
		bool StubCalloc(uint64_t dest);
		bool StubRealloc(uint64_t dest);
		bool StubVirtualAlloc(uint64_t dest);
		bool StubVirtualFree(uint64_t dest);
		bool StubVirtualProtect(uint64_t dest);
		bool StubHeapAlloc(uint64_t dest);
		bool StubHeapFree(uint64_t dest);
		bool StubLstrcpyA(uint64_t dest);
		bool StubLstrcpyW(uint64_t dest);
		bool StubLstrcmpA(uint64_t dest);
		bool StubLstrcmpW(uint64_t dest);
		bool StubLstrlenA(uint64_t dest);
		bool StubLstrlenW(uint64_t dest);
		bool StubMultiByteToWideChar(uint64_t dest);
		bool StubWideCharToMultiByte(uint64_t dest);

		// printf family stubs
		std::string FormatPrintf(size_t fmtArgIndex, size_t firstVarArgIndex);
		bool StubPutchar(uint64_t dest);
		bool StubPuts(uint64_t dest);
		bool StubPrintf(uint64_t dest);
		bool StubSprintf(uint64_t dest);
		bool StubSnprintf(uint64_t dest);
		bool StubFprintf(uint64_t dest);

		// stdin stubs
		bool StubGetchar(uint64_t dest);
		bool StubGets(uint64_t dest);
		bool StubFgets(uint64_t dest);
		bool StubFread(uint64_t dest);

	public:
		LLILEmulator(BinaryNinja::BinaryView* backingView);
		LLILEmulator(BinaryNinja::LowLevelILFunction* il, BinaryNinja::BinaryView* backingView);

		bool SetEntryPoint(uint64_t addr);
		void SetEntryPoint(BinaryNinja::LowLevelILFunction* il, size_t instrIndex);

		// Argument setup (uses default calling convention)
		void SetArgument(size_t index, const intx::uint512& value);
		void SetArguments(const std::vector<uint64_t>& values);

		// LLIL-specific state access
		intx::uint512 GetRegister(uint32_t reg) const;
		void SetRegister(uint32_t reg, const intx::uint512& value);
		intx::uint512 GetTempRegister(uint32_t index) const;
		void SetTempRegister(uint32_t index, const intx::uint512& value);
		const std::unordered_map<uint32_t, intx::uint512>& GetAllTempRegisters() const;
		uint8_t GetFlag(uint32_t flag) const;
		void SetFlag(uint32_t flag, uint8_t value);

		void SetIntrinsicHook(IntrinsicHook hook);

		BinaryNinja::LowLevelILFunction* GetFunction() const;
		BinaryNinja::Architecture* GetArchitecture() const;
		size_t GetCallStackDepth() const;

		struct CallStackEntry
		{
			uint64_t functionAddress;
			uint64_t returnAddress;
		};
		std::vector<CallStackEntry> GetCallStack() const;

		ILEmulatorStopReason StepOver();

		// Built-in libc stub settings
		void SetBuiltinLibcStubsEnabled(bool enabled);
		bool IsBuiltinLibcStubsEnabled() const;
		void SetLogLibcCalls(bool enabled);
		bool IsLogLibcCalls() const;
		void SetNopUnknownExternals(bool enabled);
		bool IsNopUnknownExternals() const;

		void Reset() override;

		// State serialization
		std::string SaveState() const;
		bool LoadState(const std::string& json, BinaryNinja::BinaryView* view);
		BinaryNinja::BinaryView* GetView() const { return m_view; }
	};
}
