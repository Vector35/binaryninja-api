#include "ilemulator.h"
#include "../api/ffi.h"

using namespace std;
using namespace BinaryNinja;
using namespace BinaryNinjaEmulator;


// ============================================================================
// EmulatorMemory
// ============================================================================

EmulatorMemory::Segment* EmulatorMemory::FindSegment(uint64_t addr)
{
	for (auto& seg : m_segments)
		if (seg.Contains(addr))
			return &seg;
	return nullptr;
}


const EmulatorMemory::Segment* EmulatorMemory::FindSegment(uint64_t addr) const
{
	for (auto& seg : m_segments)
		if (seg.Contains(addr))
			return &seg;
	return nullptr;
}


const EmulatorMemory::Segment* EmulatorMemory::FindNextSegment(uint64_t addr) const
{
	const Segment* best = nullptr;
	for (auto& seg : m_segments)
	{
		if (seg.start > addr)
		{
			if (!best || seg.start < best->start)
				best = &seg;
		}
	}
	return best;
}


bool EmulatorMemory::ReadValue(uint64_t addr, size_t size, BNEndianness endian, intx::uint512& result)
{
	if (size == 0 || size > 64)
		return false;

	uint8_t buf[64];
	if (Read(buf, addr, size) != size)
		return false;

	result = 0;
	if (endian == LittleEndian)
	{
		// Build uint512 from little-endian bytes
		for (size_t i = size; i > 0; i--)
			result = (result << 8) | buf[i - 1];
	}
	else
	{
		for (size_t i = 0; i < size; i++)
			result = (result << 8) | buf[i];
	}
	return true;
}


bool EmulatorMemory::WriteValue(uint64_t addr, const intx::uint512& value, size_t size, BNEndianness endian)
{
	if (size == 0 || size > 64)
		return false;

	uint8_t buf[64];
	// Extract bytes from uint512 — work on a copy we can shift
	intx::uint512 tmp = value;
	if (endian == LittleEndian)
	{
		for (size_t i = 0; i < size; i++)
		{
			buf[i] = static_cast<uint8_t>(tmp);
			tmp >>= 8;
		}
	}
	else
	{
		for (size_t i = size; i > 0; i--)
		{
			buf[i - 1] = static_cast<uint8_t>(tmp);
			tmp >>= 8;
		}
	}
	return Write(addr, buf, size) == size;
}


size_t EmulatorMemory::Read(void* dest, uint64_t addr, size_t len)
{
	uint8_t* out = (uint8_t*)dest;
	size_t totalRead = 0;

	while (totalRead < len)
	{
		uint64_t cur = addr + totalRead;
		const Segment* seg = FindSegment(cur);
		if (seg)
		{
			size_t offset = (size_t)(cur - seg->start);
			size_t avail = seg->data.size() - offset;
			size_t chunkSize = std::min(len - totalRead, avail);
			memcpy(out + totalRead, seg->data.data() + offset, chunkSize);
			totalRead += chunkSize;
		}
		else
		{
			// Unmapped region — zero-fill up to the next adjacent segment or end of request.
			// On real hardware this would fault, but we silently return zeros.
			const Segment* next = FindNextSegment(cur);
			size_t remaining = len - totalRead;
			// Distance from the cursor to the next mapped segment; if it falls within the
			// bytes still to read, only skip up to it. Computed relative to `cur` (not
			// addr + len, which can overflow for high addresses).
			size_t skipSize = remaining;
			if (next && next->start > cur)
			{
				uint64_t gap = next->start - cur;
				if (gap < remaining)
					skipSize = static_cast<size_t>(gap);
			}
			memset(out + totalRead, 0, skipSize);
			totalRead += skipSize;
		}
	}
	return totalRead;
}


size_t EmulatorMemory::Write(uint64_t addr, const void* src, size_t len)
{
	const uint8_t* in = (const uint8_t*)src;
	size_t totalWritten = 0;

	while (totalWritten < len)
	{
		uint64_t cur = addr + totalWritten;
		Segment* seg = FindSegment(cur);
		if (seg)
		{
			size_t offset = (size_t)(cur - seg->start);
			size_t avail = seg->data.size() - offset;
			size_t chunkSize = std::min(len - totalWritten, avail);
			memcpy(seg->data.data() + offset, in + totalWritten, chunkSize);
			totalWritten += chunkSize;
		}
		else
		{
			// Unmapped region — skip to the next adjacent segment or end of request.
			// On real hardware this would fault, but we silently discard the data.
			const Segment* next = FindNextSegment(cur);
			size_t remaining = len - totalWritten;
			// Distance from the cursor to the next mapped segment; if it falls within the
			// bytes still to write, only skip up to it. Computed relative to `cur` (not
			// addr + len, which can overflow for high addresses).
			size_t skipSize = remaining;
			if (next && next->start > cur)
			{
				uint64_t gap = next->start - cur;
				if (gap < remaining)
					skipSize = static_cast<size_t>(gap);
			}
			totalWritten += skipSize;
		}
	}
	return totalWritten;
}


bool EmulatorMemory::OverlapsExisting(uint64_t addr, size_t len) const
{
	if (len == 0)
		return false;
	uint64_t end = addr + len;
	for (auto& seg : m_segments)
	{
		// Intersection of [addr, end) and [seg.start, seg.End()); handles end wraparound.
		if (addr < seg.End() && seg.start < end)
			return true;
	}
	return false;
}


void EmulatorMemory::Map(uint64_t addr, const void* data, size_t len, const std::string& name)
{
	if (len == 0)
		return;
	if (OverlapsExisting(addr, len))
	{
		LogWarn("Emulator: refusing to map region '%s' at 0x%llx (size 0x%zx): "
			"overlaps an already-mapped region", name.c_str(), (unsigned long long)addr, len);
		return;
	}
	Segment seg;
	seg.start = addr;
	try
	{
		seg.data.assign((const uint8_t*)data, (const uint8_t*)data + len);
	}
	catch (const std::exception& e)
	{
		// Do not let an allocation failure for a caller-controlled length escape across the
		// extern "C" ABI boundary (that would be undefined behavior).
		LogWarn("Emulator: failed to map region '%s' at 0x%llx (size 0x%zx): %s",
			name.c_str(), (unsigned long long)addr, len, e.what());
		return;
	}
	seg.name = name;
	m_segments.push_back(std::move(seg));
}


void EmulatorMemory::Map(uint64_t addr, size_t len, const std::string& name)
{
	if (len == 0)
		return;
	if (OverlapsExisting(addr, len))
	{
		LogWarn("Emulator: refusing to map region '%s' at 0x%llx (size 0x%zx): "
			"overlaps an already-mapped region", name.c_str(), (unsigned long long)addr, len);
		return;
	}
	Segment seg;
	seg.start = addr;
	try
	{
		seg.data.resize(len, 0);
	}
	catch (const std::exception& e)
	{
		// Do not let an allocation failure for a caller-controlled length escape across the
		// extern "C" ABI boundary (that would be undefined behavior).
		LogWarn("Emulator: failed to map region '%s' at 0x%llx (size 0x%zx): %s",
			name.c_str(), (unsigned long long)addr, len, e.what());
		return;
	}
	seg.name = name;
	m_segments.push_back(std::move(seg));
}


std::vector<EmulatorMemory::MappedRegion> EmulatorMemory::GetMappedRegions() const
{
	std::vector<MappedRegion> result;
	result.reserve(m_segments.size());
	for (auto& seg : m_segments)
		result.push_back({seg.start, seg.data.size(), seg.name});
	return result;
}


void EmulatorMemory::Reset()
{
	m_segments.clear();
}


// ============================================================================
// ILEmulator
// ============================================================================

ILEmulator::ILEmulator()
{
	INIT_EMULATOR_API_OBJECT();
}


ILEmulator::~ILEmulator() {}


ILEmulatorStopReason ILEmulator::Run()
{
	m_stopReason = ILEmulatorStopReason::Running;
	m_stopMessage.clear();
	m_stopRequested.store(false, std::memory_order_relaxed);

	// Remember the address we're resuming from so we skip the breakpoint on the
	// very first instruction (avoids re-hitting the same breakpoint on resume).
	// If we loop back to this address later, the breakpoint will fire normally.
	uint64_t resumeAddress = GetCurrentInstructionAddress();
	bool firstInstruction = true;

	while (m_stopReason == ILEmulatorStopReason::Running)
	{
		if (m_stopRequested.load(std::memory_order_relaxed))
		{
			SetStopReason(ILEmulatorStopReason::UserRequestedStop, "user requested stop");
			break;
		}

		if (m_maxInstructions > 0 && m_instructionsExecuted >= m_maxInstructions)
		{
			SetStopReason(ILEmulatorStopReason::InstructionLimit, "instruction limit reached");
			break;
		}

		if (m_instrIndex >= GetInstructionCount())
		{
			SetStopReason(ILEmulatorStopReason::Halt, "ran off end of IL");
			break;
		}

		m_currentAddress = GetCurrentInstructionAddress();

		bool skipBreakpoint = firstInstruction && m_currentAddress == resumeAddress;
		firstInstruction = false;

		if (m_breakpoints.count(m_currentAddress) && !skipBreakpoint)
		{
			SetStopReason(ILEmulatorStopReason::Breakpoint);
			break;
		}

		if (m_preInstructionHook && !m_preInstructionHook(this, m_instrIndex))
		{
			SetStopReason(ILEmulatorStopReason::Halt, "pre-instruction hook stopped execution");
			break;
		}

		size_t prevIndex = m_instrIndex;
		ExecuteCurrentInstruction();
		m_instructionsExecuted++;

		// If ExecuteCurrentInstruction didn't change the index, advance to next
		if (m_instrIndex == prevIndex && m_stopReason == ILEmulatorStopReason::Running)
			m_instrIndex++;
	}
	return m_stopReason;
}


ILEmulatorStopReason ILEmulator::Step()
{
	return StepN(1);
}


ILEmulatorStopReason ILEmulator::StepN(size_t n)
{
	m_stopReason = ILEmulatorStopReason::Running;
	m_stopMessage.clear();
	m_stopRequested.store(false, std::memory_order_relaxed);

	for (size_t i = 0; i < n && m_stopReason == ILEmulatorStopReason::Running; i++)
	{
		if (m_instrIndex >= GetInstructionCount())
		{
			SetStopReason(ILEmulatorStopReason::Halt, "ran off end of IL");
			break;
		}

		size_t prevIndex = m_instrIndex;
		ExecuteCurrentInstruction();
		m_instructionsExecuted++;

		if (m_instrIndex == prevIndex && m_stopReason == ILEmulatorStopReason::Running)
			m_instrIndex++;
	}

	m_currentAddress = GetCurrentInstructionAddress();

	if (m_stopReason == ILEmulatorStopReason::Running)
		SetStopReason(ILEmulatorStopReason::Halt);

	return m_stopReason;
}


size_t ILEmulator::GetInstructionIndex() const
{
	return m_instrIndex;
}


void ILEmulator::SetInstructionIndex(size_t index)
{
	m_instrIndex = index;
}


uint64_t ILEmulator::GetCurrentAddress() const
{
	return m_currentAddress;
}


ILEmulatorStopReason ILEmulator::GetStopReason() const
{
	return m_stopReason;
}


const std::string& ILEmulator::GetStopMessage() const
{
	return m_stopMessage;
}


EmulatorMemory& ILEmulator::GetMemory()
{
	return m_memory;
}


size_t ILEmulator::ReadMemory(void* dest, uint64_t addr, size_t len)
{
	return m_memory.Read(dest, addr, len);
}


size_t ILEmulator::WriteMemory(uint64_t addr, const void* src, size_t len)
{
	return m_memory.Write(addr, src, len);
}


void ILEmulator::MapMemory(uint64_t addr, const void* data, size_t len, const std::string& name)
{
	m_memory.Map(addr, data, len, name);
}


void ILEmulator::MapMemory(uint64_t addr, size_t len, const std::string& name)
{
	m_memory.Map(addr, len, name);
}


std::vector<EmulatorMemory::MappedRegion> ILEmulator::GetMappedRegions() const
{
	return m_memory.GetMappedRegions();
}


intx::uint512 ILEmulator::ReadMemoryValue(uint64_t addr, size_t size)
{
	if (m_memoryReadHook)
	{
		intx::uint512 value;
		if (m_memoryReadHook(this, addr, size, value))
			return value;
	}

	intx::uint512 result = 0;
	if (!m_memory.ReadValue(addr, size, GetEndianness(), result))
	{
		SetStopReason(ILEmulatorStopReason::Error,
			fmt::format("failed to read {} bytes at 0x{:x}", size, addr));
		return 0;
	}
	return result;
}


void ILEmulator::WriteMemoryValue(uint64_t addr, const intx::uint512& value, size_t size)
{
	if (m_memoryWriteHook)
	{
		if (m_memoryWriteHook(this, addr, size, value))
			return;
	}

	if (!m_memory.WriteValue(addr, value, size, GetEndianness()))
	{
		SetStopReason(ILEmulatorStopReason::Error,
			fmt::format("failed to write {} bytes at 0x{:x}", size, addr));
	}
}


intx::uint512 ILEmulator::MaskToSize(const intx::uint512& value, size_t size)
{
	if (size >= 64)
		return value;
	if (size == 0)
		return 0;
	intx::uint512 mask = (intx::uint512(1) << (size * 8)) - 1;
	return value & mask;
}


intx::uint512 ILEmulator::SignExtend(const intx::uint512& value, size_t fromSize, size_t toSize)
{
	if (fromSize >= toSize || fromSize == 0)
		return value;

	intx::uint512 signBit = intx::uint512(1) << (fromSize * 8 - 1);
	intx::uint512 result = MaskToSize(value, fromSize);
	if (result & signBit)
	{
		// Set all bits from fromSize*8 up to toSize*8
		intx::uint512 fromMask = (intx::uint512(1) << (fromSize * 8)) - 1;
		intx::uint512 toMask = (toSize >= 64) ? ~intx::uint512(0) : (intx::uint512(1) << (toSize * 8)) - 1;
		result |= toMask & ~fromMask;
	}
	return MaskToSize(result, toSize);
}


bool ILEmulator::IsNegative(const intx::uint512& value, size_t size)
{
	if (size == 0 || size > 64)
		return false;
	intx::uint512 signBit = intx::uint512(1) << (size * 8 - 1);
	return (MaskToSize(value, size) & signBit) != 0;
}


bool ILEmulator::SignedLess(const intx::uint512& a, const intx::uint512& b, size_t size)
{
	bool an = IsNegative(a, size);
	bool bn = IsNegative(b, size);
	if (an != bn)
		return an;  // negative < non-negative
	// Same sign: the unsigned comparison of the masked values gives the correct order.
	return MaskToSize(a, size) < MaskToSize(b, size);
}


intx::uint512 ILEmulator::SignedDivideOrModuloWide(
	const intx::uint512& dividend, size_t dividendSize,
	const intx::uint512& divisor, size_t divisorSize,
	size_t resultSize, bool modulo)
{
	// Work with magnitudes as unsigned wide integers, then reapply the sign. This is correct
	// for operands of any width up to 64 bytes and, unlike native signed division, does not
	// trap on INT_MIN / -1 (which wraps to INT_MIN for divide and 0 for modulo). The dividend,
	// divisor and result may have different widths (the double-precision ops divide a
	// double-width dividend by a single-width divisor to produce a single-width result).
	intx::uint512 am = MaskToSize(dividend, dividendSize);
	intx::uint512 bm = MaskToSize(divisor, divisorSize);
	bool an = IsNegative(am, dividendSize);
	bool bn = IsNegative(bm, divisorSize);
	intx::uint512 au = an ? MaskToSize(~am + 1, dividendSize) : am;
	intx::uint512 bu = bn ? MaskToSize(~bm + 1, divisorSize) : bm;
	intx::uint512 result = modulo ? (au % bu) : (au / bu);
	bool resultNeg = modulo ? an : (an != bn);
	if (resultNeg)
		result = MaskToSize(~result + 1, resultSize);
	return MaskToSize(result, resultSize);
}


intx::uint512 ILEmulator::SignedDivideOrModulo(
	const intx::uint512& a, const intx::uint512& b, size_t size, bool modulo)
{
	return SignedDivideOrModuloWide(a, size, b, size, size, modulo);
}


void ILEmulator::AddBreakpoint(uint64_t addr)
{
	m_breakpoints.insert(addr);
}


void ILEmulator::RemoveBreakpoint(uint64_t addr)
{
	m_breakpoints.erase(addr);
}


void ILEmulator::ClearBreakpoints()
{
	m_breakpoints.clear();
}


void ILEmulator::SetMaxInstructions(size_t max)
{
	m_maxInstructions = max;
}


size_t ILEmulator::GetInstructionsExecuted() const
{
	return m_instructionsExecuted;
}


void ILEmulator::SetCallHook(std::function<bool(ILEmulator*, uint64_t)> hook)
{
	m_callHook = std::move(hook);
}


void ILEmulator::SetSyscallHook(std::function<bool(ILEmulator*)> hook)
{
	m_syscallHook = std::move(hook);
}


void ILEmulator::SetMemoryReadHook(std::function<bool(ILEmulator*, uint64_t, size_t, intx::uint512&)> hook)
{
	m_memoryReadHook = std::move(hook);
}


void ILEmulator::SetMemoryWriteHook(std::function<bool(ILEmulator*, uint64_t, size_t, const intx::uint512&)> hook)
{
	m_memoryWriteHook = std::move(hook);
}


void ILEmulator::SetPreInstructionHook(std::function<bool(ILEmulator*, size_t)> hook)
{
	m_preInstructionHook = std::move(hook);
}


void ILEmulator::SetStdoutCallback(std::function<void(ILEmulator*, const char*, size_t)> cb)
{
	m_stdoutCallback = std::move(cb);
}


void ILEmulator::SetStdinCallback(std::function<size_t(ILEmulator*, char*, size_t)> cb)
{
	m_stdinCallback = std::move(cb);
}


void ILEmulator::EmitStdout(const std::string& data)
{
	if (m_stdoutCallback && !data.empty())
		m_stdoutCallback(this, data.data(), data.size());
}


void ILEmulator::EmitStdout(const char* data, size_t len)
{
	if (m_stdoutCallback && len > 0)
		m_stdoutCallback(this, data, len);
}


size_t ILEmulator::RequestStdin(char* buf, size_t maxLen)
{
	if (m_stdinCallback)
		return m_stdinCallback(this, buf, maxLen);
	return 0;
}


void ILEmulator::SetStopReason(ILEmulatorStopReason reason, const std::string& msg)
{
	m_stopReason = reason;
	m_stopMessage = msg;
}


void ILEmulator::RequestStop()
{
	m_stopRequested.store(true, std::memory_order_relaxed);
}


void ILEmulator::Reset()
{
	m_memory.Reset();
	m_breakpoints.clear();
	m_instructionsExecuted = 0;
	m_instrIndex = 0;
	m_currentAddress = 0;
	m_stopReason = ILEmulatorStopReason::Running;
	m_stopMessage.clear();
}


// ============================================================================
// C API — Shared ILEmulator functions
// ============================================================================

BNILEmulatorStopReason BNILEmulatorRun(BNILEmulator* emu)
{
	return (BNILEmulatorStopReason)emu->object->Run();
}


BNILEmulatorStopReason BNILEmulatorStep(BNILEmulator* emu)
{
	return (BNILEmulatorStopReason)emu->object->Step();
}


BNILEmulatorStopReason BNILEmulatorStepN(BNILEmulator* emu, size_t n)
{
	return (BNILEmulatorStopReason)emu->object->StepN(n);
}


size_t BNILEmulatorGetInstructionIndex(BNILEmulator* emu)
{
	return emu->object->GetInstructionIndex();
}


void BNILEmulatorSetInstructionIndex(BNILEmulator* emu, size_t index)
{
	emu->object->SetInstructionIndex(index);
}


uint64_t BNILEmulatorGetCurrentAddress(BNILEmulator* emu)
{
	return emu->object->GetCurrentAddress();
}


BNILEmulatorStopReason BNILEmulatorGetStopReason(BNILEmulator* emu)
{
	return (BNILEmulatorStopReason)emu->object->GetStopReason();
}


char* BNILEmulatorGetStopMessage(BNILEmulator* emu)
{
	return BNAllocString(emu->object->GetStopMessage().c_str());
}


size_t BNILEmulatorReadMemory(BNILEmulator* emu, void* dest, uint64_t addr, size_t len)
{
	return emu->object->ReadMemory(dest, addr, len);
}


size_t BNILEmulatorWriteMemory(BNILEmulator* emu, uint64_t addr, const void* src, size_t len)
{
	return emu->object->WriteMemory(addr, src, len);
}


void BNILEmulatorAddBreakpoint(BNILEmulator* emu, uint64_t addr)
{
	emu->object->AddBreakpoint(addr);
}


void BNILEmulatorRemoveBreakpoint(BNILEmulator* emu, uint64_t addr)
{
	emu->object->RemoveBreakpoint(addr);
}


void BNILEmulatorClearBreakpoints(BNILEmulator* emu)
{
	emu->object->ClearBreakpoints();
}


void BNILEmulatorSetMaxInstructions(BNILEmulator* emu, size_t max)
{
	emu->object->SetMaxInstructions(max);
}


size_t BNILEmulatorGetInstructionsExecuted(BNILEmulator* emu)
{
	return emu->object->GetInstructionsExecuted();
}


void BNILEmulatorSetCallHook(BNILEmulator* emu, void* ctxt, bool (*callback)(void*, BNILEmulator*, uint64_t))
{
	if (callback)
	{
		emu->object->SetCallHook([ctxt, callback](ILEmulator* e, uint64_t target) -> bool {
			return callback(ctxt, e->GetAPIObject(), target);
		});
	}
	else
	{
		emu->object->SetCallHook(nullptr);
	}
}


void BNILEmulatorSetSyscallHook(BNILEmulator* emu, void* ctxt, bool (*callback)(void*, BNILEmulator*))
{
	if (callback)
	{
		emu->object->SetSyscallHook([ctxt, callback](ILEmulator* e) -> bool {
			return callback(ctxt, e->GetAPIObject());
		});
	}
	else
	{
		emu->object->SetSyscallHook(nullptr);
	}
}


void BNILEmulatorSetMemoryReadHook(BNILEmulator* emu, void* ctxt,
	bool (*callback)(void*, BNILEmulator*, uint64_t, size_t, uint8_t*, size_t))
{
	if (callback)
	{
		emu->object->SetMemoryReadHook(
			[ctxt, callback](ILEmulator* e, uint64_t addr, size_t size, intx::uint512& value) -> bool {
				uint8_t buf[64] = {};
				if (!callback(ctxt, e->GetAPIObject(), addr, size, buf, sizeof(buf)))
					return false;
				// Convert little-endian buf to uint512
				value = 0;
				for (size_t i = sizeof(buf); i > 0; i--)
					value = (value << 8) | buf[i - 1];
				return true;
			});
	}
	else
	{
		emu->object->SetMemoryReadHook(nullptr);
	}
}


void BNILEmulatorSetMemoryWriteHook(BNILEmulator* emu, void* ctxt,
	bool (*callback)(void*, BNILEmulator*, uint64_t, size_t, const uint8_t*, size_t))
{
	if (callback)
	{
		emu->object->SetMemoryWriteHook(
			[ctxt, callback](ILEmulator* e, uint64_t addr, size_t size, const intx::uint512& value) -> bool {
				// Convert uint512 to little-endian byte buffer
				uint8_t buf[64];
				intx::uint512 tmp = value;
				for (size_t i = 0; i < 64; i++)
				{
					buf[i] = static_cast<uint8_t>(tmp);
					tmp >>= 8;
				}
				return callback(ctxt, e->GetAPIObject(), addr, size, buf, sizeof(buf));
			});
	}
	else
	{
		emu->object->SetMemoryWriteHook(nullptr);
	}
}


void BNILEmulatorSetPreInstructionHook(BNILEmulator* emu, void* ctxt,
	bool (*callback)(void*, BNILEmulator*, size_t))
{
	if (callback)
	{
		emu->object->SetPreInstructionHook(
			[ctxt, callback](ILEmulator* e, size_t instrIndex) -> bool {
				return callback(ctxt, e->GetAPIObject(), instrIndex);
			});
	}
	else
	{
		emu->object->SetPreInstructionHook(nullptr);
	}
}


void BNILEmulatorSetStdoutCallback(BNILEmulator* emu, void* ctxt,
	void (*callback)(void*, BNILEmulator*, const char*, size_t))
{
	if (callback)
	{
		emu->object->SetStdoutCallback(
			[ctxt, callback](ILEmulator* e, const char* data, size_t len) {
				callback(ctxt, e->GetAPIObject(), data, len);
			});
	}
	else
	{
		emu->object->SetStdoutCallback(nullptr);
	}
}


void BNILEmulatorSetStdinCallback(BNILEmulator* emu, void* ctxt,
	size_t (*callback)(void*, BNILEmulator*, void*, size_t))
{
	if (callback)
	{
		emu->object->SetStdinCallback(
			[ctxt, callback](ILEmulator* e, char* buf, size_t maxLen) -> size_t {
				return callback(ctxt, e->GetAPIObject(), buf, maxLen);
			});
	}
	else
	{
		emu->object->SetStdinCallback(nullptr);
	}
}


void BNILEmulatorMapMemory(BNILEmulator* emu, uint64_t addr, const void* data, size_t len)
{
	emu->object->MapMemory(addr, data, len);
}


void BNILEmulatorMapMemoryZero(BNILEmulator* emu, uint64_t addr, size_t len)
{
	emu->object->MapMemory(addr, len);
}


void BNILEmulatorMapMemoryNamed(BNILEmulator* emu, uint64_t addr, const void* data, size_t len, const char* name)
{
	emu->object->MapMemory(addr, data, len, name ? name : "");
}


void BNILEmulatorMapMemoryZeroNamed(BNILEmulator* emu, uint64_t addr, size_t len, const char* name)
{
	emu->object->MapMemory(addr, len, name ? name : "");
}


void BNILEmulatorRequestStop(BNILEmulator* emu)
{
	emu->object->RequestStop();
}


void BNILEmulatorReset(BNILEmulator* emu)
{
	emu->object->Reset();
}


BNEmulatorMemoryRegion* BNILEmulatorGetMappedRegions(BNILEmulator* emu, size_t* count)
{
	auto regions = emu->object->GetMappedRegions();
	*count = regions.size();
	if (regions.empty())
		return nullptr;

	auto* result = new BNEmulatorMemoryRegion[regions.size()];
	for (size_t i = 0; i < regions.size(); i++)
	{
		result[i].start = regions[i].start;
		result[i].size = regions[i].size;
		result[i].name = BNAllocString(regions[i].name.c_str());
	}
	return result;
}


void BNFreeEmulatorMemoryRegions(BNEmulatorMemoryRegion* regions, size_t count)
{
	for (size_t i = 0; i < count; i++)
		BNFreeString(regions[i].name);
	delete[] regions;
}
