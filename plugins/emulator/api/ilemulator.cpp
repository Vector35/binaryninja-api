// Copyright (c) 2015-2026 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "binaryninjaapi.h"
#include "ffi.h"
#include "emulatorapi.h"

using namespace BinaryNinja;


LLILEmulator::LLILEmulator(Ref<BinaryView> view)
{
	m_object = BNCreateLLILEmulatorForView(view->GetObject());
}


LLILEmulator::LLILEmulator(Ref<LowLevelILFunction> il, Ref<BinaryView> view)
{
	m_object = BNCreateLLILEmulator(il->GetObject(), view->GetObject());
}


LLILEmulator::LLILEmulator(BNLLILEmulator* emu)
{
	m_object = emu;
}


bool LLILEmulator::SetEntryPoint(uint64_t addr)
{
	return BNLLILEmulatorSetEntryPoint(m_object, addr);
}


void LLILEmulator::SetEntryPoint(Ref<LowLevelILFunction> il, size_t instrIndex)
{
	BNLLILEmulatorSetEntryPointForIL(m_object, il->GetObject(), instrIndex);
}


static void ApiUint512ToBytes(const intx::uint512& value, uint8_t* buf, size_t bufLen)
{
	intx::uint512 tmp = value;
	size_t n = std::min(bufLen, (size_t)64);
	for (size_t i = 0; i < n; i++)
	{
		buf[i] = static_cast<uint8_t>(tmp);
		tmp >>= 8;
	}
	for (size_t i = n; i < bufLen; i++)
		buf[i] = 0;
}


static intx::uint512 ApiBytesToUint512(const uint8_t* buf, size_t bufLen)
{
	intx::uint512 result = 0;
	size_t n = std::min(bufLen, (size_t)64);
	for (size_t i = n; i > 0; i--)
		result = (result << 8) | buf[i - 1];
	return result;
}


void LLILEmulator::SetArgument(size_t index, const intx::uint512& value)
{
	uint8_t buf[64];
	ApiUint512ToBytes(value, buf, sizeof(buf));
	BNLLILEmulatorSetArgument(m_object, index, buf, sizeof(buf));
}


void LLILEmulator::SetArguments(const std::vector<uint64_t>& values)
{
	BNLLILEmulatorSetArguments(m_object, values.data(), values.size());
}


// ─── Execution ───────────────────────────────────────────────────────────────

BNILEmulatorStopReason LLILEmulator::Run()
{
	return BNILEmulatorRun(BNLLILEmulatorGetBase(m_object));
}


BNILEmulatorStopReason LLILEmulator::Step()
{
	return BNILEmulatorStep(BNLLILEmulatorGetBase(m_object));
}


BNILEmulatorStopReason LLILEmulator::StepN(size_t n)
{
	return BNILEmulatorStepN(BNLLILEmulatorGetBase(m_object), n);
}


BNILEmulatorStopReason LLILEmulator::StepOver()
{
	return BNLLILEmulatorStepOver(m_object);
}


void LLILEmulator::RequestStop()
{
	BNILEmulatorRequestStop(BNLLILEmulatorGetBase(m_object));
}


// ─── State ───────────────────────────────────────────────────────────────────

size_t LLILEmulator::GetInstructionIndex() const
{
	return BNILEmulatorGetInstructionIndex(BNLLILEmulatorGetBase(m_object));
}


void LLILEmulator::SetInstructionIndex(size_t index)
{
	BNILEmulatorSetInstructionIndex(BNLLILEmulatorGetBase(m_object), index);
}


uint64_t LLILEmulator::GetCurrentAddress() const
{
	return BNILEmulatorGetCurrentAddress(BNLLILEmulatorGetBase(m_object));
}


BNILEmulatorStopReason LLILEmulator::GetStopReason() const
{
	return BNILEmulatorGetStopReason(BNLLILEmulatorGetBase(m_object));
}


std::string LLILEmulator::GetStopMessage() const
{
	char* msg = BNILEmulatorGetStopMessage(BNLLILEmulatorGetBase(m_object));
	std::string result(msg);
	BNFreeString(msg);
	return result;
}


// ─── Memory ──────────────────────────────────────────────────────────────────

size_t LLILEmulator::ReadMemory(void* dest, uint64_t addr, size_t len) const
{
	return BNILEmulatorReadMemory(BNLLILEmulatorGetBase(m_object), dest, addr, len);
}


size_t LLILEmulator::WriteMemory(uint64_t addr, const void* src, size_t len)
{
	return BNILEmulatorWriteMemory(BNLLILEmulatorGetBase(m_object), addr, src, len);
}


void LLILEmulator::MapMemory(uint64_t addr, const void* data, size_t len, const std::string& name)
{
	if (name.empty())
		BNILEmulatorMapMemory(BNLLILEmulatorGetBase(m_object), addr, data, len);
	else
		BNILEmulatorMapMemoryNamed(BNLLILEmulatorGetBase(m_object), addr, data, len, name.c_str());
}


void LLILEmulator::MapMemory(uint64_t addr, size_t len, const std::string& name)
{
	if (name.empty())
		BNILEmulatorMapMemoryZero(BNLLILEmulatorGetBase(m_object), addr, len);
	else
		BNILEmulatorMapMemoryZeroNamed(BNLLILEmulatorGetBase(m_object), addr, len, name.c_str());
}


// ─── Breakpoints ─────────────────────────────────────────────────────────────

void LLILEmulator::AddBreakpoint(uint64_t addr)
{
	BNILEmulatorAddBreakpoint(BNLLILEmulatorGetBase(m_object), addr);
}


void LLILEmulator::RemoveBreakpoint(uint64_t addr)
{
	BNILEmulatorRemoveBreakpoint(BNLLILEmulatorGetBase(m_object), addr);
}


void LLILEmulator::ClearBreakpoints()
{
	BNILEmulatorClearBreakpoints(BNLLILEmulatorGetBase(m_object));
}


// ─── Limits ──────────────────────────────────────────────────────────────────

void LLILEmulator::SetMaxInstructions(size_t max)
{
	BNILEmulatorSetMaxInstructions(BNLLILEmulatorGetBase(m_object), max);
}


size_t LLILEmulator::GetInstructionsExecuted() const
{
	return BNILEmulatorGetInstructionsExecuted(BNLLILEmulatorGetBase(m_object));
}


// ─── Hook bridge callbacks ───────────────────────────────────────────────────

bool LLILEmulator::CallHookCallback(void* ctxt, BNILEmulator*, uint64_t target)
{
	LLILEmulator* self = (LLILEmulator*)ctxt;
	return self->m_callHook(self, target);
}


bool LLILEmulator::SyscallHookCallback(void* ctxt, BNILEmulator*)
{
	LLILEmulator* self = (LLILEmulator*)ctxt;
	return self->m_syscallHook(self);
}


bool LLILEmulator::MemoryReadHookCallback(
	void* ctxt, BNILEmulator*, uint64_t addr, size_t size, uint8_t* outBuf, size_t bufLen)
{
	LLILEmulator* self = (LLILEmulator*)ctxt;
	intx::uint512 value;
	if (!self->m_memoryReadHook(self, addr, size, value))
		return false;
	ApiUint512ToBytes(value, outBuf, bufLen);
	return true;
}


bool LLILEmulator::MemoryWriteHookCallback(
	void* ctxt, BNILEmulator*, uint64_t addr, size_t size, const uint8_t* buf, size_t bufLen)
{
	LLILEmulator* self = (LLILEmulator*)ctxt;
	intx::uint512 value = ApiBytesToUint512(buf, bufLen);
	return self->m_memoryWriteHook(self, addr, size, value);
}


bool LLILEmulator::PreInstructionHookCallback(void* ctxt, BNILEmulator*, size_t instrIndex)
{
	LLILEmulator* self = (LLILEmulator*)ctxt;
	return self->m_preInstructionHook(self, instrIndex);
}


bool LLILEmulator::IntrinsicHookCallback(void* ctxt, BNLLILEmulator*,
	uint32_t intrinsic, const uint64_t* params, size_t paramCount,
	uint64_t* outValues, uint32_t* outRegs, size_t* outCount)
{
	LLILEmulator* self = (LLILEmulator*)ctxt;
	std::vector<uint64_t> paramVec(params, params + paramCount);
	std::vector<std::pair<uint32_t, uint64_t>> outputs;

	bool result = self->m_intrinsicHook(self, intrinsic, paramVec, outputs);

	size_t count = outputs.size();
	if (outCount)
		*outCount = count;
	for (size_t i = 0; i < count; i++)
	{
		if (outRegs)
			outRegs[i] = outputs[i].first;
		if (outValues)
			outValues[i] = outputs[i].second;
	}
	return result;
}


void LLILEmulator::StdoutCallbackBridge(void* ctxt, BNILEmulator*, const char* data, size_t len)
{
	LLILEmulator* self = (LLILEmulator*)ctxt;
	self->m_stdoutCallback(self, std::string(data, len));
}


size_t LLILEmulator::StdinCallbackBridge(void* ctxt, BNILEmulator*, char* buf, size_t maxLen)
{
	LLILEmulator* self = (LLILEmulator*)ctxt;
	return self->m_stdinCallback(self, buf, maxLen);
}


// ─── Hook setters ────────────────────────────────────────────────────────────

void LLILEmulator::SetCallHook(const std::function<bool(LLILEmulator*, uint64_t)>& hook)
{
	m_callHook = hook;
	BNILEmulatorSetCallHook(BNLLILEmulatorGetBase(m_object),
		hook ? (void*)this : nullptr,
		hook ? CallHookCallback : nullptr);
}


void LLILEmulator::SetSyscallHook(const std::function<bool(LLILEmulator*)>& hook)
{
	m_syscallHook = hook;
	BNILEmulatorSetSyscallHook(BNLLILEmulatorGetBase(m_object),
		hook ? (void*)this : nullptr,
		hook ? SyscallHookCallback : nullptr);
}


void LLILEmulator::SetMemoryReadHook(
	const std::function<bool(LLILEmulator*, uint64_t, size_t, intx::uint512&)>& hook)
{
	m_memoryReadHook = hook;
	BNILEmulatorSetMemoryReadHook(BNLLILEmulatorGetBase(m_object),
		hook ? (void*)this : nullptr,
		hook ? MemoryReadHookCallback : nullptr);
}


void LLILEmulator::SetMemoryWriteHook(
	const std::function<bool(LLILEmulator*, uint64_t, size_t, const intx::uint512&)>& hook)
{
	m_memoryWriteHook = hook;
	BNILEmulatorSetMemoryWriteHook(BNLLILEmulatorGetBase(m_object),
		hook ? (void*)this : nullptr,
		hook ? MemoryWriteHookCallback : nullptr);
}


void LLILEmulator::SetPreInstructionHook(const std::function<bool(LLILEmulator*, size_t)>& hook)
{
	m_preInstructionHook = hook;
	BNILEmulatorSetPreInstructionHook(BNLLILEmulatorGetBase(m_object),
		hook ? (void*)this : nullptr,
		hook ? PreInstructionHookCallback : nullptr);
}


void LLILEmulator::SetIntrinsicHook(const std::function<bool(LLILEmulator*, uint32_t,
	const std::vector<uint64_t>&, std::vector<std::pair<uint32_t, uint64_t>>&)>& hook)
{
	m_intrinsicHook = hook;
	BNLLILEmulatorSetIntrinsicHook(m_object,
		hook ? (void*)this : nullptr,
		hook ? IntrinsicHookCallback : nullptr);
}


void LLILEmulator::SetStdoutCallback(const std::function<void(LLILEmulator*, const std::string&)>& cb)
{
	m_stdoutCallback = cb;
	BNILEmulatorSetStdoutCallback(BNLLILEmulatorGetBase(m_object),
		cb ? (void*)this : nullptr,
		cb ? StdoutCallbackBridge : nullptr);
}


void LLILEmulator::SetStdinCallback(const std::function<size_t(LLILEmulator*, char*, size_t)>& cb)
{
	m_stdinCallback = cb;
	BNILEmulatorSetStdinCallback(BNLLILEmulatorGetBase(m_object),
		cb ? (void*)this : nullptr,
		cb ? StdinCallbackBridge : nullptr);
}


// ─── Register / flag / temp access ──────────────────────────────────────────

intx::uint512 LLILEmulator::GetRegister(uint32_t reg) const
{
	uint8_t buf[64] = {};
	BNLLILEmulatorGetRegister(m_object, reg, buf, sizeof(buf));
	return ApiBytesToUint512(buf, sizeof(buf));
}


void LLILEmulator::SetRegister(uint32_t reg, const intx::uint512& value)
{
	uint8_t buf[64];
	ApiUint512ToBytes(value, buf, sizeof(buf));
	BNLLILEmulatorSetRegister(m_object, reg, buf, sizeof(buf));
}


intx::uint512 LLILEmulator::GetTempRegister(uint32_t index) const
{
	uint8_t buf[64] = {};
	BNLLILEmulatorGetTempRegister(m_object, index, buf, sizeof(buf));
	return ApiBytesToUint512(buf, sizeof(buf));
}


void LLILEmulator::SetTempRegister(uint32_t index, const intx::uint512& value)
{
	uint8_t buf[64];
	ApiUint512ToBytes(value, buf, sizeof(buf));
	BNLLILEmulatorSetTempRegister(m_object, index, buf, sizeof(buf));
}


std::unordered_map<uint32_t, intx::uint512> LLILEmulator::GetAllTempRegisters() const
{
	// Query count first, then fetch
	size_t count = BNLLILEmulatorGetAllTempRegisters(m_object, nullptr, nullptr, 0);
	std::unordered_map<uint32_t, intx::uint512> result;
	if (count == 0)
		return result;
	std::vector<uint32_t> indices(count);
	std::vector<uint8_t> values(count * 64);
	count = BNLLILEmulatorGetAllTempRegisters(m_object, indices.data(), values.data(), count);
	for (size_t i = 0; i < count; i++)
		result[indices[i]] = ApiBytesToUint512(values.data() + i * 64, 64);
	return result;
}


uint8_t LLILEmulator::GetFlag(uint32_t flag) const
{
	return BNLLILEmulatorGetFlag(m_object, flag);
}


void LLILEmulator::SetFlag(uint32_t flag, uint8_t value)
{
	BNLLILEmulatorSetFlag(m_object, flag, value);
}


// ─── Cross-function state ────────────────────────────────────────────────────

size_t LLILEmulator::GetCallStackDepth() const
{
	return BNLLILEmulatorGetCallStackDepth(m_object);
}


std::vector<LLILEmulator::CallStackEntry> LLILEmulator::GetCallStack() const
{
	size_t count = 0;
	BNEmulatorCallStackEntry* entries = BNLLILEmulatorGetCallStack(m_object, &count);
	std::vector<CallStackEntry> result;
	if (entries)
	{
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
			result.push_back({entries[i].functionAddress, entries[i].returnAddress});
		BNLLILEmulatorFreeCallStack(entries);
	}
	return result;
}


std::vector<LLILEmulator::MappedRegion> LLILEmulator::GetMappedRegions() const
{
	size_t count = 0;
	BNEmulatorMemoryRegion* regions = BNILEmulatorGetMappedRegions(BNLLILEmulatorGetBase(m_object), &count);
	std::vector<MappedRegion> result;
	if (regions)
	{
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
			result.push_back({regions[i].start, regions[i].size, regions[i].name ? regions[i].name : ""});
		BNFreeEmulatorMemoryRegions(regions, count);
	}
	return result;
}


// ─── Built-in libc stub settings ─────────────────────────────────────────────

void LLILEmulator::SetBuiltinLibcStubsEnabled(bool enabled)
{
	BNLLILEmulatorSetBuiltinLibcStubsEnabled(m_object, enabled);
}


bool LLILEmulator::IsBuiltinLibcStubsEnabled() const
{
	return BNLLILEmulatorIsBuiltinLibcStubsEnabled(m_object);
}


void LLILEmulator::SetLogLibcCalls(bool enabled)
{
	BNLLILEmulatorSetLogLibcCalls(m_object, enabled);
}


bool LLILEmulator::IsLogLibcCalls() const
{
	return BNLLILEmulatorIsLogLibcCalls(m_object);
}


void LLILEmulator::SetNopUnknownExternals(bool enabled)
{
	BNLLILEmulatorSetNopUnknownExternals(m_object, enabled);
}


bool LLILEmulator::IsNopUnknownExternals() const
{
	return BNLLILEmulatorIsNopUnknownExternals(m_object);
}


// ─── Reset ───────────────────────────────────────────────────────────────────

void LLILEmulator::Reset()
{
	BNILEmulatorReset(BNLLILEmulatorGetBase(m_object));
}


// ─── State serialization ─────────────────────────────────────────────────────

std::string LLILEmulator::SaveState() const
{
	char* json = BNLLILEmulatorSaveState(m_object);
	if (!json)
		return {};
	std::string result(json);
	BNFreeString(json);
	return result;
}


bool LLILEmulator::LoadState(const std::string& json)
{
	return BNLLILEmulatorLoadState(m_object, json.c_str());
}
