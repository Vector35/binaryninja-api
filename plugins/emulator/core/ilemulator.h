#pragma once

#include "binaryninjaapi.h"
#include "vendor/intx/intx.hpp"
#include "ffi_global.h"
#include "refcountobject.h"
#include <atomic>
#include <set>
#include <functional>
#include <string>
#include <vector>

DECLARE_EMULATOR_API_OBJECT(BNILEmulator, ILEmulator);

namespace BinaryNinjaEmulator
{
	enum class ILEmulatorStopReason : uint8_t
	{
		Running = 0,
		Breakpoint,
		InstructionLimit,
		Halt,
		Error,
		CallHook,
		SyscallHook,
		UndefinedBehavior,
		Unimplemented,
		UserRequestedStop
	};

	class EmulatorMemory
	{
		struct Segment
		{
			uint64_t start;
			std::vector<uint8_t> data;
			std::string name;

			uint64_t End() const { return start + data.size(); }
			bool Contains(uint64_t addr) const { return addr >= start && addr < End(); }
		};

		std::vector<Segment> m_segments;

		// Find the segment containing addr, or nullptr
		Segment* FindSegment(uint64_t addr);
		const Segment* FindSegment(uint64_t addr) const;

		// Find the lowest-start segment whose start > addr, or nullptr
		const Segment* FindNextSegment(uint64_t addr) const;

		// True if [addr, addr + len) intersects any existing segment.
		bool OverlapsExisting(uint64_t addr, size_t len) const;

	public:
		EmulatorMemory() = default;

		bool ReadValue(uint64_t addr, size_t size, BNEndianness endian, intx::uint512& result);
		bool WriteValue(uint64_t addr, const intx::uint512& value, size_t size, BNEndianness endian);
		size_t Read(void* dest, uint64_t addr, size_t len);
		size_t Write(uint64_t addr, const void* src, size_t len);

		// Map a region of memory with the given data
		void Map(uint64_t addr, const void* data, size_t len, const std::string& name = "");

		// Map a zero-filled region
		void Map(uint64_t addr, size_t len, const std::string& name = "");

		struct MappedRegion
		{
			uint64_t start;
			uint64_t size;
			std::string name;
		};
		std::vector<MappedRegion> GetMappedRegions() const;

		void Reset();
	};

	class ILEmulator : public EmuRefCountObject
	{
		IMPLEMENT_EMULATOR_API_OBJECT(BNILEmulator)

	protected:
		EmulatorMemory m_memory;
		std::function<bool(ILEmulator*, uint64_t)> m_callHook;
		std::function<bool(ILEmulator*)> m_syscallHook;
		std::function<bool(ILEmulator*, uint64_t, size_t, intx::uint512&)> m_memoryReadHook;
		std::function<bool(ILEmulator*, uint64_t, size_t, const intx::uint512&)> m_memoryWriteHook;
		std::function<bool(ILEmulator*, size_t)> m_preInstructionHook;
		std::function<void(ILEmulator*, const char*, size_t)> m_stdoutCallback;
		std::function<size_t(ILEmulator*, char*, size_t)> m_stdinCallback;
		std::set<uint64_t> m_breakpoints;
		size_t m_maxInstructions = 0;
		size_t m_instructionsExecuted = 0;
		size_t m_instrIndex = 0;
		uint64_t m_currentAddress = 0;
		ILEmulatorStopReason m_stopReason = ILEmulatorStopReason::Running;
		std::string m_stopMessage;
		std::atomic<bool> m_stopRequested {false};

		// Executes the instruction at m_instrIndex and must leave m_instrIndex pointing at
		// the next instruction to execute — advancing past the instruction for fall-through,
		// or setting the branch/call/return target. The driver loops never move the index
		// themselves: only the implementation knows whether an instruction transferred
		// control (comparing indices is ambiguous, since a call or return can land on the
		// same numeric index in a different function).
		virtual void ExecuteCurrentInstruction() = 0;
		virtual size_t GetInstructionCount() const = 0;
		virtual uint64_t GetCurrentInstructionAddress() const = 0;

		// Halts with "ran off end of IL" and returns true when the current instruction
		// index is past the end of the current function's IL.
		bool CheckEndOfIL();
		// Executes the current instruction via ExecuteCurrentInstruction. Returns false
		// when execution cannot continue (end of IL, or a stop condition was raised by
		// the instruction).
		bool StepOnce();

		intx::uint512 ReadMemoryValue(uint64_t addr, size_t size);
		void WriteMemoryValue(uint64_t addr, const intx::uint512& value, size_t size);
		virtual BNEndianness GetEndianness() const = 0;

		// Wide-integer helpers shared by IL emulators. These operate purely on intx::uint512
		// values and byte sizes with no dependence on a specific IL, so they live here for
		// reuse across emulator implementations.
		static intx::uint512 MaskToSize(const intx::uint512& value, size_t size);
		static intx::uint512 SignExtend(const intx::uint512& value, size_t fromSize, size_t toSize);
		// Signed-integer helpers that operate directly on the wide value, so operands wider
		// than 8 bytes are handled correctly (and INT_MIN / -1 does not trap as it would on
		// native signed division).
		static bool IsNegative(const intx::uint512& value, size_t size);
		static bool SignedLess(const intx::uint512& a, const intx::uint512& b, size_t size);
		static intx::uint512 SignedDivideOrModulo(
			const intx::uint512& a, const intx::uint512& b, size_t size, bool modulo);
		// Generalized signed divide/modulo where the dividend, divisor and result may have
		// different widths (used by the double-precision divide/modulo ops).
		static intx::uint512 SignedDivideOrModuloWide(
			const intx::uint512& dividend, size_t dividendSize,
			const intx::uint512& divisor, size_t divisorSize,
			size_t resultSize, bool modulo);

		// Stdout/stdin helpers for stubs
		void EmitStdout(const std::string& data);
		void EmitStdout(const char* data, size_t len);
		size_t RequestStdin(char* buf, size_t maxLen);

	public:
		ILEmulator();
		virtual ~ILEmulator();

		// Execution control
		ILEmulatorStopReason Run();
		ILEmulatorStopReason Step();
		ILEmulatorStopReason StepN(size_t n);

		// State
		size_t GetInstructionIndex() const;
		virtual void SetInstructionIndex(size_t index);
		uint64_t GetCurrentAddress() const;
		ILEmulatorStopReason GetStopReason() const;
		const std::string& GetStopMessage() const;

		// Memory
		EmulatorMemory& GetMemory();
		size_t ReadMemory(void* dest, uint64_t addr, size_t len);
		size_t WriteMemory(uint64_t addr, const void* src, size_t len);
		void MapMemory(uint64_t addr, const void* data, size_t len, const std::string& name = "");
		void MapMemory(uint64_t addr, size_t len, const std::string& name = "");
		std::vector<EmulatorMemory::MappedRegion> GetMappedRegions() const;

		// Breakpoints (by address)
		void AddBreakpoint(uint64_t addr);
		void RemoveBreakpoint(uint64_t addr);
		void ClearBreakpoints();

		// Limits
		void SetMaxInstructions(size_t max);
		size_t GetInstructionsExecuted() const;

		// Hooks
		void SetCallHook(std::function<bool(ILEmulator*, uint64_t)> hook);
		void SetSyscallHook(std::function<bool(ILEmulator*)> hook);
		void SetMemoryReadHook(std::function<bool(ILEmulator*, uint64_t, size_t, intx::uint512&)> hook);
		void SetMemoryWriteHook(std::function<bool(ILEmulator*, uint64_t, size_t, const intx::uint512&)> hook);
		void SetPreInstructionHook(std::function<bool(ILEmulator*, size_t)> hook);
		void SetStdoutCallback(std::function<void(ILEmulator*, const char*, size_t)> cb);
		void SetStdinCallback(std::function<size_t(ILEmulator*, char*, size_t)> cb);

		void SetStopReason(ILEmulatorStopReason reason, const std::string& msg = "");
		void RequestStop();
		virtual void Reset();
	};
}
