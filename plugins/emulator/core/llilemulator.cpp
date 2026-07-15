#include "llilemulator.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "../api/ffi.h"

using namespace std;
using namespace BinaryNinja;
using namespace BinaryNinjaEmulator;


// ============================================================================
// LLILEmulator
// ============================================================================

LLILEmulator::LLILEmulator(BinaryView* backingView) :
	m_view(backingView), m_il(nullptr), m_arch(nullptr)
{
	if (m_view)
		m_arch = m_view->GetDefaultArchitecture();
	Ref<Settings> settings = Settings::Instance();
	m_builtinLibcStubs = settings->Get<bool>("emulator.builtinLibcStubs");
	m_logLibcCalls = settings->Get<bool>("emulator.logLibcCalls");
	INIT_EMULATOR_API_OBJECT();
}


LLILEmulator::LLILEmulator(LowLevelILFunction* il, BinaryView* backingView) :
	m_view(backingView), m_il(il), m_arch(il->GetArchitecture())
{
	Ref<Settings> settings = Settings::Instance();
	m_builtinLibcStubs = settings->Get<bool>("emulator.builtinLibcStubs");
	m_logLibcCalls = settings->Get<bool>("emulator.logLibcCalls");
	INIT_EMULATOR_API_OBJECT();
}


bool LLILEmulator::SetEntryPoint(uint64_t addr)
{
	if (!m_view)
		return false;

	Ref<Function> func = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), addr);
	if (!func)
		return false;

	Ref<LowLevelILFunction> targetIL = func->GetLowLevelIL();
	if (!targetIL || targetIL->GetInstructionCount() == 0)
		return false;

	m_il = targetIL;
	m_arch = targetIL->GetArchitecture();
	m_instrIndex = 0;
	m_currentAddress = GetCurrentInstructionAddress();
	m_callStack.clear();
	return true;
}


void LLILEmulator::SetEntryPoint(LowLevelILFunction* il, size_t instrIndex)
{
	m_il = il;
	m_arch = il->GetArchitecture();
	m_instrIndex = instrIndex;
	m_currentAddress = GetCurrentInstructionAddress();
	m_callStack.clear();
}


void LLILEmulator::SetArgument(size_t index, const intx::uint512& value)
{
	if (!m_view || !m_arch)
		return;

	Ref<Platform> platform = m_view->GetDefaultPlatform();
	if (!platform)
		return;

	Ref<CallingConvention> cc = platform->GetDefaultCallingConvention();
	if (!cc)
		return;

	auto argRegs = cc->GetIntegerArgumentRegisters();
	if (index < argRegs.size())
	{
		SetRegister(argRegs[index], value);
		return;
	}

	// Stack argument
	size_t addrSize = m_arch->GetAddressSize();
	uint32_t sp = m_arch->GetStackPointerRegister();
	uint64_t spVal = static_cast<uint64_t>(GetRegister(sp));
	size_t stackIndex = index - argRegs.size();
	WriteMemoryValue(spVal + stackIndex * addrSize, value, addrSize);
}


void LLILEmulator::SetArguments(const std::vector<uint64_t>& values)
{
	for (size_t i = 0; i < values.size(); i++)
		SetArgument(i, values[i]);
}


intx::uint512 LLILEmulator::MaskToSize(const intx::uint512& value, size_t size)
{
	if (size >= 64)
		return value;
	if (size == 0)
		return 0;
	intx::uint512 mask = (intx::uint512(1) << (size * 8)) - 1;
	return value & mask;
}


intx::uint512 LLILEmulator::SignExtend(const intx::uint512& value, size_t fromSize, size_t toSize)
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


bool LLILEmulator::IsNegative(const intx::uint512& value, size_t size)
{
	if (size == 0 || size > 64)
		return false;
	intx::uint512 signBit = intx::uint512(1) << (size * 8 - 1);
	return (MaskToSize(value, size) & signBit) != 0;
}


bool LLILEmulator::SignedLess(const intx::uint512& a, const intx::uint512& b, size_t size)
{
	bool an = IsNegative(a, size);
	bool bn = IsNegative(b, size);
	if (an != bn)
		return an;  // negative < non-negative
	// Same sign: the unsigned comparison of the masked values gives the correct order.
	return MaskToSize(a, size) < MaskToSize(b, size);
}


intx::uint512 LLILEmulator::SignedDivideOrModulo(
	const intx::uint512& a, const intx::uint512& b, size_t size, bool modulo)
{
	// Work with magnitudes as unsigned wide integers, then reapply the sign. This is correct
	// for operands of any width up to 64 bytes and, unlike native signed division, does not
	// trap on INT_MIN / -1 (which wraps to INT_MIN for divide and 0 for modulo).
	intx::uint512 am = MaskToSize(a, size);
	intx::uint512 bm = MaskToSize(b, size);
	bool an = IsNegative(am, size);
	bool bn = IsNegative(bm, size);
	intx::uint512 au = an ? MaskToSize(~am + 1, size) : am;
	intx::uint512 bu = bn ? MaskToSize(~bm + 1, size) : bm;
	intx::uint512 result = modulo ? (au % bu) : (au / bu);
	bool resultNeg = modulo ? an : (an != bn);
	if (resultNeg)
		result = MaskToSize(~result + 1, size);
	return MaskToSize(result, size);
}


BNEndianness LLILEmulator::GetEndianness() const
{
	if (m_arch)
		return m_arch->GetEndianness();
	return LittleEndian;
}


size_t LLILEmulator::GetInstructionCount() const
{
	if (m_il)
		return m_il->GetInstructionCount();
	return 0;
}


uint64_t LLILEmulator::GetCurrentInstructionAddress() const
{
	if (m_il && m_instrIndex < m_il->GetInstructionCount())
		return m_il->GetInstruction(m_instrIndex).address;
	return m_currentAddress;
}


intx::uint512 LLILEmulator::GetRegister(uint32_t reg) const
{
	BNRegisterInfo info = m_arch->GetRegisterInfo(reg);
	auto it = m_registers.find(info.fullWidthRegister);
	intx::uint512 fullValue = (it != m_registers.end()) ? it->second : intx::uint512(0);

	if (reg == info.fullWidthRegister)
		return fullValue;

	intx::uint512 extracted = (fullValue >> (info.offset * 8));
	return MaskToSize(extracted, info.size);
}


void LLILEmulator::SetRegister(uint32_t reg, const intx::uint512& value)
{
	BNRegisterInfo info = m_arch->GetRegisterInfo(reg);

	if (reg == info.fullWidthRegister)
	{
		m_registers[reg] = value;
		return;
	}

	intx::uint512 existing = 0;
	auto it = m_registers.find(info.fullWidthRegister);
	if (it != m_registers.end())
		existing = it->second;

	intx::uint512 masked = MaskToSize(value, info.size);

	switch (info.extend)
	{
	case ZeroExtendToFullWidth:
		m_registers[info.fullWidthRegister] = masked << (info.offset * 8);
		break;
	case SignExtendToFullWidth:
	{
		intx::uint512 signExtended = SignExtend(masked, info.size, m_arch->GetRegisterInfo(info.fullWidthRegister).size);
		m_registers[info.fullWidthRegister] = signExtended;
		break;
	}
	case NoExtend:
	default:
	{
		size_t bitOffset = info.offset * 8;
		size_t bitWidth = info.size * 8;
		intx::uint512 mask = ((intx::uint512(1) << bitWidth) - 1) << bitOffset;
		existing &= ~mask;
		existing |= (masked << bitOffset);
		m_registers[info.fullWidthRegister] = existing;
		break;
	}
	}
}


intx::uint512 LLILEmulator::GetTempRegister(uint32_t index) const
{
	auto it = m_tempRegisters.find(index);
	return (it != m_tempRegisters.end()) ? it->second : intx::uint512(0);
}


void LLILEmulator::SetTempRegister(uint32_t index, const intx::uint512& value)
{
	m_tempRegisters[index] = value;
}


const std::unordered_map<uint32_t, intx::uint512>& LLILEmulator::GetAllTempRegisters() const
{
	return m_tempRegisters;
}


uint8_t LLILEmulator::GetFlag(uint32_t flag) const
{
	auto it = m_flags.find(flag);
	return (it != m_flags.end()) ? it->second : 0;
}


void LLILEmulator::SetFlag(uint32_t flag, uint8_t value)
{
	m_flags[flag] = value ? 1 : 0;
}


void LLILEmulator::SetIntrinsicHook(IntrinsicHook hook)
{
	m_intrinsicHook = std::move(hook);
}


LowLevelILFunction* LLILEmulator::GetFunction() const
{
	return m_il;
}


Architecture* LLILEmulator::GetArchitecture() const
{
	return m_arch;
}


void LLILEmulator::Push(const intx::uint512& value, size_t size)
{
	uint32_t sp = m_arch->GetStackPointerRegister();
	uint64_t spVal = static_cast<uint64_t>(GetRegister(sp));
	spVal -= size;
	SetRegister(sp, intx::uint512(spVal));
	WriteMemoryValue(spVal, value, size);
}


intx::uint512 LLILEmulator::Pop(size_t size)
{
	uint32_t sp = m_arch->GetStackPointerRegister();
	uint64_t spVal = static_cast<uint64_t>(GetRegister(sp));
	intx::uint512 value = ReadMemoryValue(spVal, size);
	spVal += size;
	SetRegister(sp, intx::uint512(spVal));
	return value;
}


size_t LLILEmulator::GetCallStackDepth() const
{
	return m_callStack.size();
}


std::vector<LLILEmulator::CallStackEntry> LLILEmulator::GetCallStack() const
{
	std::vector<CallStackEntry> result;

	// Frame 0 (current): the function currently executing
	if (m_il)
	{
		Ref<Function> curFunc = m_il->GetFunction();
		uint64_t funcAddr = curFunc ? curFunc->GetStart() : 0;
		uint64_t pc = GetCurrentInstructionAddress();
		result.push_back({funcAddr, pc});
	}

	// Parent frames: walk the call stack from most recent to oldest
	for (auto it = m_callStack.rbegin(); it != m_callStack.rend(); ++it)
	{
		uint64_t funcAddr = 0;
		uint64_t returnAddr = 0;

		if (it->il)
		{
			Ref<Function> func = it->il->GetFunction();
			funcAddr = func ? func->GetStart() : 0;

			if (it->returnIndex < it->il->GetInstructionCount())
				returnAddr = it->il->GetInstruction(it->returnIndex).address;
		}

		result.push_back({funcAddr, returnAddr});
	}

	return result;
}


ILEmulatorStopReason LLILEmulator::StepOver()
{
	size_t targetDepth = m_callStack.size();

	m_stopReason = ILEmulatorStopReason::Running;
	m_stopMessage.clear();
	m_stopRequested.store(false, std::memory_order_relaxed);

	if (m_instrIndex >= GetInstructionCount())
	{
		SetStopReason(ILEmulatorStopReason::Halt, "ran off end of IL");
		return m_stopReason;
	}

	// Execute one instruction
	size_t prevIndex = m_instrIndex;
	ExecuteCurrentInstruction();
	m_instructionsExecuted++;
	if (m_instrIndex == prevIndex && m_stopReason == ILEmulatorStopReason::Running)
		m_instrIndex++;

	// If we didn't enter a deeper function, we're done
	if (m_callStack.size() <= targetDepth || m_stopReason != ILEmulatorStopReason::Running)
	{
		m_currentAddress = GetCurrentInstructionAddress();
		if (m_stopReason == ILEmulatorStopReason::Running)
			SetStopReason(ILEmulatorStopReason::Halt);
		return m_stopReason;
	}

	// Entered a function — run until we return to the original depth.
	// Respect breakpoints and other stop conditions inside the callee,
	// matching standard debugger step-over semantics.
	while (m_stopReason == ILEmulatorStopReason::Running)
	{
		if (m_callStack.size() <= targetDepth)
			break;

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

		if (m_breakpoints.count(m_currentAddress))
		{
			SetStopReason(ILEmulatorStopReason::Breakpoint);
			break;
		}

		if (m_preInstructionHook && !m_preInstructionHook(this, m_instrIndex))
		{
			SetStopReason(ILEmulatorStopReason::Halt, "pre-instruction hook stopped execution");
			break;
		}

		prevIndex = m_instrIndex;
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


bool LLILEmulator::EnterFunction(uint64_t addr, size_t returnIndex)
{
	if (!m_view)
		return false;

	// Resolve address to a Function
	Ref<Function> func = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), addr);
	if (!func)
		return false;

	Ref<LowLevelILFunction> targetIL = func->GetLowLevelIL();
	if (!targetIL)
		return false;

	size_t entryInstr = targetIL->GetInstructionStart(targetIL->GetArchitecture(), addr);
	if (entryInstr >= targetIL->GetInstructionCount())
		return false;

	// Save current context (including temp registers, which are per-function)
	m_callStack.push_back({m_il, m_arch, returnIndex, std::move(m_tempRegisters)});
	m_tempRegisters.clear();

	// Switch to callee
	m_il = targetIL;
	m_arch = targetIL->GetArchitecture();
	m_instrIndex = entryInstr;

	return true;
}


bool LLILEmulator::ReturnToCaller()
{
	if (m_callStack.empty())
		return false;

	CallFrame& frame = m_callStack.back();
	m_il = frame.il;
	m_arch = frame.arch;
	m_instrIndex = frame.returnIndex;
	m_tempRegisters = std::move(frame.tempRegisters);
	m_callStack.pop_back();

	return true;
}


uint64_t LLILEmulator::GetNativeReturnAddress() const
{
	if (!m_il || m_instrIndex >= m_il->GetInstructionCount())
		return 0;

	uint64_t callAddr = m_il->GetInstruction(m_instrIndex).address;

	// Use the architecture to get the native instruction length
	if (m_view && m_arch)
	{
		uint8_t buf[16];
		size_t bytesRead = m_view->Read(buf, callAddr, sizeof(buf));
		if (bytesRead > 0)
		{
			InstructionInfo info;
			if (m_arch->GetInstructionInfo(buf, callAddr, bytesRead, info) && info.length > 0)
				return callAddr + info.length;
		}
	}

	// Fallback: use the next LLIL instruction's address
	if (m_instrIndex + 1 < m_il->GetInstructionCount())
		return m_il->GetInstruction(m_instrIndex + 1).address;

	return callAddr;
}


void LLILEmulator::Reset()
{
	ILEmulator::Reset();
	m_registers.clear();
	m_tempRegisters.clear();
	m_flags.clear();
	m_callStack.clear();
	m_heapBumpPtr = HEAP_BASE;
	m_heapMapped = false;
	m_heapAllocations.clear();
}

// ============================================================================
// State serialization helpers
// ============================================================================

static std::string Uint512ToHexString(const intx::uint512& value)
{
	// Extract 64 bytes little-endian, find last non-zero byte for compact output
	uint8_t bytes[64];
	intx::uint512 tmp = value;
	for (int i = 0; i < 64; i++)
	{
		bytes[i] = static_cast<uint8_t>(tmp);
		tmp >>= 8;
	}
	// Find last significant byte
	int last = 63;
	while (last > 0 && bytes[last] == 0)
		last--;

	// Build hex string (big-endian display, like normal hex)
	std::string result = "0x";
	for (int i = last; i >= 0; i--)
		result += fmt::format("{:02x}", bytes[i]);
	return result;
}


static intx::uint512 HexStringToUint512(const std::string& hex)
{
	intx::uint512 result = 0;
	const char* p = hex.c_str();
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
		p += 2;

	while (*p)
	{
		uint8_t nibble;
		if (*p >= '0' && *p <= '9')
			nibble = *p - '0';
		else if (*p >= 'a' && *p <= 'f')
			nibble = *p - 'a' + 10;
		else if (*p >= 'A' && *p <= 'F')
			nibble = *p - 'A' + 10;
		else
			break;
		result = (result << 4) | intx::uint512(nibble);
		p++;
	}
	return result;
}


static void AddUint64Member(rapidjson::Value& obj, const char* key, uint64_t value,
	rapidjson::Document::AllocatorType& alloc)
{
	auto hexStr = fmt::format("0x{:x}", value);
	obj.AddMember(rapidjson::Value(key, alloc), rapidjson::Value(hexStr.c_str(), alloc), alloc);
}


std::string LLILEmulator::SaveState() const
{
	rapidjson::Document doc(rapidjson::kObjectType);
	auto& alloc = doc.GetAllocator();

	doc.AddMember("version", 1, alloc);

	// Instruction state
	doc.AddMember("instrIndex", (uint64_t)m_instrIndex, alloc);
	AddUint64Member(doc, "currentAddress", m_currentAddress, alloc);
	doc.AddMember("instructionsExecuted", (uint64_t)m_instructionsExecuted, alloc);

	// Registers
	{
		rapidjson::Value regs(rapidjson::kObjectType);
		for (auto& [regId, value] : m_registers)
		{
			auto key = fmt::format("{}", regId);
			auto hexVal = Uint512ToHexString(value);
			regs.AddMember(rapidjson::Value(key.c_str(), alloc), rapidjson::Value(hexVal.c_str(), alloc), alloc);
		}
		doc.AddMember("registers", regs, alloc);
	}

	// Temp registers
	{
		rapidjson::Value temps(rapidjson::kObjectType);
		for (auto& [index, value] : m_tempRegisters)
		{
			auto key = fmt::format("{}", index);
			auto hexVal = Uint512ToHexString(value);
			temps.AddMember(rapidjson::Value(key.c_str(), alloc), rapidjson::Value(hexVal.c_str(), alloc), alloc);
		}
		doc.AddMember("tempRegisters", temps, alloc);
	}

	// Flags
	{
		rapidjson::Value flags(rapidjson::kObjectType);
		for (auto& [flagId, value] : m_flags)
		{
			auto key = fmt::format("{}", flagId);
			rapidjson::Value keyVal(key.c_str(), alloc);
			rapidjson::Value valVal((int)value);
			flags.AddMember(keyVal, valVal, alloc);
		}
		doc.AddMember("flags", flags, alloc);
	}

	// Memory segments
	{
		rapidjson::Value memory(rapidjson::kArrayType);
		auto regions = m_memory.GetMappedRegions();
		for (auto& region : regions)
		{
			rapidjson::Value seg(rapidjson::kObjectType);
			AddUint64Member(seg, "start", region.start, alloc);
			AddUint64Member(seg, "size", region.size, alloc);
			seg.AddMember("name", rapidjson::Value(region.name.c_str(), alloc), alloc);

			// Read the data and base64 encode
			std::vector<uint8_t> data(region.size);
			const_cast<EmulatorMemory&>(m_memory).Read(data.data(), region.start, region.size);
			DataBuffer buf(data.data(), data.size());
			auto b64 = buf.ToBase64();
			seg.AddMember("data", rapidjson::Value(b64.c_str(), alloc), alloc);

			memory.PushBack(seg, alloc);
		}
		doc.AddMember("memory", memory, alloc);
	}

	// Breakpoints
	{
		rapidjson::Value bps(rapidjson::kArrayType);
		for (auto addr : m_breakpoints)
		{
			auto hexAddr = fmt::format("0x{:x}", addr);
			bps.PushBack(rapidjson::Value(hexAddr.c_str(), alloc), alloc);
		}
		doc.AddMember("breakpoints", bps, alloc);
	}

	// Heap state
	{
		rapidjson::Value heap(rapidjson::kObjectType);
		AddUint64Member(heap, "bumpPtr", m_heapBumpPtr, alloc);
		heap.AddMember("mapped", m_heapMapped, alloc);

		rapidjson::Value allocations(rapidjson::kObjectType);
		for (auto& [addr, size] : m_heapAllocations)
		{
			auto key = fmt::format("0x{:x}", addr);
			rapidjson::Value keyVal(key.c_str(), alloc);
			rapidjson::Value sizeVal((uint64_t)size);
			allocations.AddMember(keyVal, sizeVal, alloc);
		}
		heap.AddMember("allocations", allocations, alloc);
		doc.AddMember("heap", heap, alloc);
	}

	// Call stack
	{
		rapidjson::Value stack(rapidjson::kArrayType);
		for (auto& frame : m_callStack)
		{
			rapidjson::Value f(rapidjson::kObjectType);
			// Store function start address (resolve back on load)
			uint64_t funcAddr = 0;
			if (frame.il)
			{
				auto func = frame.il->GetFunction();
				if (func)
					funcAddr = func->GetStart();
			}
			AddUint64Member(f, "funcAddr", funcAddr, alloc);
			f.AddMember("returnIndex", (uint64_t)frame.returnIndex, alloc);

			rapidjson::Value temps(rapidjson::kObjectType);
			for (auto& [index, value] : frame.tempRegisters)
			{
				auto key = fmt::format("{}", index);
				auto hexVal = Uint512ToHexString(value);
				temps.AddMember(rapidjson::Value(key.c_str(), alloc), rapidjson::Value(hexVal.c_str(), alloc), alloc);
			}
			f.AddMember("temps", temps, alloc);
			stack.PushBack(f, alloc);
		}
		doc.AddMember("callStack", stack, alloc);
	}

	// Settings
	{
		rapidjson::Value settings(rapidjson::kObjectType);
		settings.AddMember("builtinLibcStubs", m_builtinLibcStubs, alloc);
		settings.AddMember("logLibcCalls", m_logLibcCalls, alloc);
		settings.AddMember("nopUnknownExternals", m_nopUnknownExternals, alloc);
		doc.AddMember("settings", settings, alloc);
	}

	// Stop state
	doc.AddMember("stopReason", (int)m_stopReason, alloc);
	doc.AddMember("stopMessage", rapidjson::Value(m_stopMessage.c_str(), alloc), alloc);

	// Serialize to string
	rapidjson::StringBuffer sb;
	rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
	doc.Accept(writer);
	return std::string(sb.GetString(), sb.GetSize());
}


bool LLILEmulator::LoadState(const std::string& json, BinaryView* view)
{
	rapidjson::Document doc;
	doc.Parse(json.c_str());
	if (doc.HasParseError() || !doc.IsObject())
		return false;

	if (!doc.HasMember("version") || doc["version"].GetInt() != 1)
		return false;

	// Instruction state
	if (doc.HasMember("instrIndex"))
		m_instrIndex = doc["instrIndex"].GetUint64();
	if (doc.HasMember("currentAddress"))
		m_currentAddress = strtoull(doc["currentAddress"].GetString() + 2, nullptr, 16);
	if (doc.HasMember("instructionsExecuted"))
		m_instructionsExecuted = doc["instructionsExecuted"].GetUint64();

	// Registers
	m_registers.clear();
	if (doc.HasMember("registers") && doc["registers"].IsObject())
	{
		for (auto it = doc["registers"].MemberBegin(); it != doc["registers"].MemberEnd(); ++it)
		{
			uint32_t regId = std::stoul(it->name.GetString());
			m_registers[regId] = HexStringToUint512(it->value.GetString());
		}
	}

	// Temp registers
	m_tempRegisters.clear();
	if (doc.HasMember("tempRegisters") && doc["tempRegisters"].IsObject())
	{
		for (auto it = doc["tempRegisters"].MemberBegin(); it != doc["tempRegisters"].MemberEnd(); ++it)
		{
			uint32_t index = std::stoul(it->name.GetString());
			m_tempRegisters[index] = HexStringToUint512(it->value.GetString());
		}
	}

	// Flags
	m_flags.clear();
	if (doc.HasMember("flags") && doc["flags"].IsObject())
	{
		for (auto it = doc["flags"].MemberBegin(); it != doc["flags"].MemberEnd(); ++it)
		{
			uint32_t flagId = std::stoul(it->name.GetString());
			m_flags[flagId] = (uint8_t)it->value.GetInt();
		}
	}

	// Memory
	m_memory.Reset();
	if (doc.HasMember("memory") && doc["memory"].IsArray())
	{
		for (auto& seg : doc["memory"].GetArray())
		{
			if (!seg.IsObject() || !seg.HasMember("start") || !seg.HasMember("data"))
				continue;

			uint64_t start = strtoull(seg["start"].GetString() + 2, nullptr, 16);
			std::string name = seg.HasMember("name") ? seg["name"].GetString() : "";
			string b64 = seg["data"].GetString();
			DataBuffer data = DataBuffer::FromBase64(b64);
			m_memory.Map(start, data.GetData(), data.GetLength(), name);
		}
	}

	// Breakpoints
	m_breakpoints.clear();
	if (doc.HasMember("breakpoints") && doc["breakpoints"].IsArray())
	{
		for (auto& bp : doc["breakpoints"].GetArray())
		{
			if (bp.IsString())
				m_breakpoints.insert(strtoull(bp.GetString() + 2, nullptr, 16));
		}
	}

	// Heap state
	if (doc.HasMember("heap") && doc["heap"].IsObject())
	{
		auto& heap = doc["heap"];
		if (heap.HasMember("bumpPtr"))
			m_heapBumpPtr = strtoull(heap["bumpPtr"].GetString() + 2, nullptr, 16);
		if (heap.HasMember("mapped"))
			m_heapMapped = heap["mapped"].GetBool();

		m_heapAllocations.clear();
		if (heap.HasMember("allocations") && heap["allocations"].IsObject())
		{
			for (auto it = heap["allocations"].MemberBegin(); it != heap["allocations"].MemberEnd(); ++it)
			{
				uint64_t addr = strtoull(it->name.GetString() + 2, nullptr, 16);
				m_heapAllocations[addr] = it->value.GetUint64();
			}
		}
	}

	// Call stack
	m_callStack.clear();
	if (doc.HasMember("callStack") && doc["callStack"].IsArray() && view)
	{
		for (auto& frame : doc["callStack"].GetArray())
		{
			if (!frame.IsObject())
				continue;

			CallFrame cf;
			cf.arch = nullptr;

			if (frame.HasMember("funcAddr"))
			{
				uint64_t funcAddr = strtoull(frame["funcAddr"].GetString() + 2, nullptr, 16);
				auto func = view->GetAnalysisFunction(view->GetDefaultPlatform(), funcAddr);
				if (func)
				{
					cf.il = func->GetLowLevelIL();
					cf.arch = func->GetArchitecture();
				}
			}

			cf.returnIndex = frame.HasMember("returnIndex") ? frame["returnIndex"].GetUint64() : 0;

			if (frame.HasMember("temps") && frame["temps"].IsObject())
			{
				for (auto it = frame["temps"].MemberBegin(); it != frame["temps"].MemberEnd(); ++it)
				{
					uint32_t index = std::stoul(it->name.GetString());
					cf.tempRegisters[index] = HexStringToUint512(it->value.GetString());
				}
			}

			m_callStack.push_back(std::move(cf));
		}
	}

	// Resolve current function IL from the entry in the call stack or from the current address
	if (view)
	{
		auto func = view->GetAnalysisFunction(view->GetDefaultPlatform(), m_currentAddress);
		if (func)
		{
			m_il = func->GetLowLevelIL();
			m_arch = func->GetArchitecture();
		}
	}

	// Settings
	if (doc.HasMember("settings") && doc["settings"].IsObject())
	{
		auto& settings = doc["settings"];
		if (settings.HasMember("builtinLibcStubs"))
			m_builtinLibcStubs = settings["builtinLibcStubs"].GetBool();
		if (settings.HasMember("logLibcCalls"))
			m_logLibcCalls = settings["logLibcCalls"].GetBool();
		if (settings.HasMember("nopUnknownExternals"))
			m_nopUnknownExternals = settings["nopUnknownExternals"].GetBool();
	}

	// Stop state
	if (doc.HasMember("stopReason"))
		m_stopReason = (ILEmulatorStopReason)doc["stopReason"].GetInt();
	if (doc.HasMember("stopMessage"))
		m_stopMessage = doc["stopMessage"].GetString();

	m_view = view;

	return true;
}


// ============================================================================
// EvalExpr — Expression evaluation
// ============================================================================

intx::uint512 LLILEmulator::EvalExpr(const LowLevelILInstruction& expr)
{
	if (m_stopReason != ILEmulatorStopReason::Running)
		return 0;

	size_t sz = expr.size;

	switch (expr.operation)
	{
	// --- Constants ---
	case LLIL_CONST:
	case LLIL_CONST_PTR:
		return MaskToSize(intx::uint512((uint64_t)expr.GetRawOperandAsInteger(0)), sz);

	case LLIL_EXTERN_PTR:
		return MaskToSize(intx::uint512((uint64_t)(expr.GetRawOperandAsInteger(0) + expr.GetRawOperandAsInteger(1))), sz);

	case LLIL_FLOAT_CONST:
		return intx::uint512((uint64_t)expr.GetRawOperandAsInteger(0));

	// --- Registers ---
	case LLIL_REG:
	{
		uint32_t reg = expr.GetRawOperandAsRegister(0);
		if (LLIL_REG_IS_TEMP(reg))
			return MaskToSize(GetTempRegister(LLIL_GET_TEMP_REG_INDEX(reg)), sz);
		return MaskToSize(GetRegister(reg), sz);
	}

	case LLIL_REG_SPLIT:
	{
		uint32_t hi = expr.GetRawOperandAsRegister(0);
		uint32_t lo = expr.GetRawOperandAsRegister(1);
		intx::uint512 hiVal = LLIL_REG_IS_TEMP(hi)
			? GetTempRegister(LLIL_GET_TEMP_REG_INDEX(hi)) : GetRegister(hi);
		intx::uint512 loVal = LLIL_REG_IS_TEMP(lo)
			? GetTempRegister(LLIL_GET_TEMP_REG_INDEX(lo)) : GetRegister(lo);
		size_t loSize = LLIL_REG_IS_TEMP(lo) ? sz / 2 : m_arch->GetRegisterInfo(lo).size;
		return MaskToSize((hiVal << (loSize * 8)) | loVal, sz);
	}

	case LLIL_FLAG:
		return intx::uint512(GetFlag(expr.GetRawOperandAsRegister(0)));

	case LLIL_FLAG_BIT:
	{
		uint8_t flagVal = GetFlag(expr.GetRawOperandAsRegister(0));
		size_t bitIndex = expr.GetRawOperandAsIndex(1);
		return intx::uint512((flagVal >> bitIndex) & 1);
	}

	// --- Two-operand arithmetic ---
	// Convention: operands are masked to the operation size `sz` up front, and the same
	// masked values are used both for the computation and for the flag context recorded in
	// m_lastArithmetic. (Double-precision ops below intentionally use sz/2-wide operands
	// producing an sz-wide result, which is why they mask differently.)
	case LLIL_ADD:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		intx::uint512 result = MaskToSize(left + right, sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_ADD, true};
		return result;
	}

	case LLIL_SUB:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		intx::uint512 result = MaskToSize(left - right, sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_SUB, true};
		return result;
	}

	case LLIL_AND:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		intx::uint512 result = MaskToSize(left & right, sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_AND, true};
		return result;
	}

	case LLIL_OR:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		intx::uint512 result = MaskToSize(left | right, sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_OR, true};
		return result;
	}

	case LLIL_XOR:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		intx::uint512 result = MaskToSize(left ^ right, sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_XOR, true};
		return result;
	}

	case LLIL_LSL:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		size_t shiftAmt = static_cast<uint64_t>(right) & (sz * 8 - 1);
		intx::uint512 result = MaskToSize(left << shiftAmt, sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_LSL, true};
		return result;
	}

	case LLIL_LSR:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		size_t shiftAmt = static_cast<uint64_t>(right) & (sz * 8 - 1);
		intx::uint512 result = MaskToSize(left >> shiftAmt, sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_LSR, true};
		return result;
	}

	case LLIL_ASR:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		intx::uint512 maskedLeft = MaskToSize(left, sz);
		// Sign-extend to full 512 bits, then arithmetic shift right
		intx::uint512 extended = SignExtend(maskedLeft, sz, 64);
		size_t shiftAmt = static_cast<uint64_t>(right) & (sz * 8 - 1);
		// Logical shift on the sign-extended value, then mask back
		intx::uint512 result = MaskToSize(extended >> shiftAmt, sz);
		m_lastArithmetic = {maskedLeft, right, result, sz, LLIL_ASR, true};
		return result;
	}

	case LLIL_ROL:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		size_t bits = sz * 8;
		size_t shift = static_cast<size_t>(static_cast<uint64_t>(right) % bits);
		intx::uint512 result = (shift == 0) ? left : MaskToSize((left << shift) | (left >> (bits - shift)), sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_ROL, true};
		return result;
	}

	case LLIL_ROR:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		size_t bits = sz * 8;
		size_t shift = static_cast<size_t>(static_cast<uint64_t>(right) % bits);
		intx::uint512 result = (shift == 0) ? left : MaskToSize((left >> shift) | (left << (bits - shift)), sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_ROR, true};
		return result;
	}

	case LLIL_MUL:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		intx::uint512 result = MaskToSize(left * right, sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_MUL, true};
		return result;
	}

	// --- With carry ---
	case LLIL_ADC:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		intx::uint512 carry = EvalExpr(expr.GetRawOperandAsExpr(2));
		intx::uint512 result = MaskToSize(left + right + (carry & 1), sz);
		m_lastArithmetic = {MaskToSize(left, sz), MaskToSize(right + (carry & 1), sz), result, sz, LLIL_ADC, true};
		return result;
	}

	case LLIL_SBB:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		intx::uint512 carry = EvalExpr(expr.GetRawOperandAsExpr(2));
		intx::uint512 result = MaskToSize(left - right - (carry & 1), sz);
		m_lastArithmetic = {MaskToSize(left, sz), MaskToSize(right + (carry & 1), sz), result, sz, LLIL_SBB, true};
		return result;
	}

	case LLIL_RLC:
	{
		// Rotate left through carry: rotate the (bits + 1)-bit quantity {carry : value},
		// with carry as the most-significant bit.
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		intx::uint512 carry = EvalExpr(expr.GetRawOperandAsExpr(2)) & 1;
		size_t bits = sz * 8;
		size_t width = bits + 1;
		size_t shift = static_cast<size_t>(static_cast<uint64_t>(right) % width);
		intx::uint512 extended = left | (carry << bits);
		intx::uint512 rotated = (shift == 0) ? extended : ((extended << shift) | (extended >> (width - shift)));
		intx::uint512 result = MaskToSize(rotated, sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_RLC, true};
		return result;
	}

	case LLIL_RRC:
	{
		// Rotate right through carry: rotate the (bits + 1)-bit quantity {carry : value},
		// with carry as the most-significant bit.
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		intx::uint512 carry = EvalExpr(expr.GetRawOperandAsExpr(2)) & 1;
		size_t bits = sz * 8;
		size_t width = bits + 1;
		size_t shift = static_cast<size_t>(static_cast<uint64_t>(right) % width);
		intx::uint512 extended = left | (carry << bits);
		intx::uint512 rotated = (shift == 0) ? extended : ((extended >> shift) | (extended << (width - shift)));
		intx::uint512 result = MaskToSize(rotated, sz);
		m_lastArithmetic = {left, right, result, sz, LLIL_RRC, true};
		return result;
	}

	// --- Division ---
	case LLIL_DIVU:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		if (right == 0)
		{
			SetStopReason(ILEmulatorStopReason::Error, "division by zero");
			return 0;
		}
		return MaskToSize(left / right, sz);
	}

	case LLIL_DIVS:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		if (MaskToSize(right, sz) == 0)
		{
			SetStopReason(ILEmulatorStopReason::Error, "division by zero");
			return 0;
		}
		return SignedDivideOrModulo(left, right, sz, false);
	}

	case LLIL_MODU:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		if (right == 0)
		{
			SetStopReason(ILEmulatorStopReason::Error, "modulo by zero");
			return 0;
		}
		return MaskToSize(left % right, sz);
	}

	case LLIL_MODS:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		if (MaskToSize(right, sz) == 0)
		{
			SetStopReason(ILEmulatorStopReason::Error, "modulo by zero");
			return 0;
		}
		return SignedDivideOrModulo(left, right, sz, true);
	}

	// --- Double-precision ---
	case LLIL_MULU_DP:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz / 2);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz / 2);
		return MaskToSize(left * right, sz);
	}

	case LLIL_MULS_DP:
	{
		// Signed multiply double-precision: sign-extend each sz/2-byte operand to the full
		// wide value, then multiply as two's-complement. The low sz bytes of the product are
		// correct regardless of sign, and this handles operands wider than 8 bytes.
		intx::uint512 l = SignExtend(EvalExpr(expr.GetRawOperandAsExpr(0)), sz / 2, 64);
		intx::uint512 r = SignExtend(EvalExpr(expr.GetRawOperandAsExpr(1)), sz / 2, 64);
		return MaskToSize(l * r, sz);
	}

	case LLIL_DIVU_DP:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz / 2);
		if (right == 0)
		{
			SetStopReason(ILEmulatorStopReason::Error, "division by zero");
			return 0;
		}
		return MaskToSize(left / right, sz / 2);
	}

	case LLIL_DIVS_DP:
	{
		int64_t left = static_cast<int64_t>(static_cast<uint64_t>(SignExtend(EvalExpr(expr.GetRawOperandAsExpr(0)), sz, 8)));
		int64_t right = static_cast<int64_t>(static_cast<uint64_t>(SignExtend(EvalExpr(expr.GetRawOperandAsExpr(1)), sz / 2, 8)));
		if (right == 0)
		{
			SetStopReason(ILEmulatorStopReason::Error, "division by zero");
			return 0;
		}
		return MaskToSize(intx::uint512(static_cast<uint64_t>(left / right)), sz / 2);
	}

	case LLIL_MODU_DP:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz / 2);
		if (right == 0)
		{
			SetStopReason(ILEmulatorStopReason::Error, "modulo by zero");
			return 0;
		}
		return MaskToSize(left % right, sz / 2);
	}

	case LLIL_MODS_DP:
	{
		int64_t left = static_cast<int64_t>(static_cast<uint64_t>(SignExtend(EvalExpr(expr.GetRawOperandAsExpr(0)), sz, 8)));
		int64_t right = static_cast<int64_t>(static_cast<uint64_t>(SignExtend(EvalExpr(expr.GetRawOperandAsExpr(1)), sz / 2, 8)));
		if (right == 0)
		{
			SetStopReason(ILEmulatorStopReason::Error, "modulo by zero");
			return 0;
		}
		return MaskToSize(intx::uint512(static_cast<uint64_t>(left % right)), sz / 2);
	}

	// --- Unary ---
	case LLIL_NEG:
	{
		intx::uint512 val = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 result = MaskToSize(~val + 1, sz);
		m_lastArithmetic = {intx::uint512(0), val, result, sz, LLIL_NEG, true};
		return result;
	}

	case LLIL_NOT:
	{
		intx::uint512 val = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 result = MaskToSize(~val, sz);
		m_lastArithmetic = {val, intx::uint512(0), result, sz, LLIL_NOT, true};
		return result;
	}

	case LLIL_SX:
	{
		LowLevelILInstruction src = expr.GetRawOperandAsExpr(0);
		intx::uint512 val = EvalExpr(src);
		return MaskToSize(SignExtend(val, src.size, sz), sz);
	}

	case LLIL_ZX:
	{
		LowLevelILInstruction src = expr.GetRawOperandAsExpr(0);
		return MaskToSize(EvalExpr(src), sz);
	}

	case LLIL_LOW_PART:
		return MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);

	// --- Bit operations ---
	case LLIL_BSWAP:
	{
		// Reverse the byte order of the sz-byte value.
		intx::uint512 val = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 result(0);
		for (size_t i = 0; i < sz; i++)
		{
			intx::uint512 byte = (val >> (8 * i)) & intx::uint512(0xff);
			result |= byte << (8 * (sz - 1 - i));
		}
		return result;
	}

	case LLIL_POPCNT:
	{
		intx::uint512 val = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		uint64_t count = 0;
		for (size_t i = 0; i < sz * 8; i++)
			if (((val >> i) & intx::uint512(1)) != 0)
				count++;
		return intx::uint512(count);
	}

	case LLIL_CLZ:
	{
		// Count leading zero bits; clz(0) == 8 * size.
		intx::uint512 val = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		size_t bits = sz * 8;
		uint64_t count = 0;
		for (size_t i = bits; i-- > 0;)
		{
			if (((val >> i) & intx::uint512(1)) != 0)
				break;
			count++;
		}
		return intx::uint512(count);
	}

	case LLIL_CTZ:
	{
		// Count trailing zero bits; ctz(0) == 8 * size.
		intx::uint512 val = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		size_t bits = sz * 8;
		uint64_t count = 0;
		for (size_t i = 0; i < bits; i++)
		{
			if (((val >> i) & intx::uint512(1)) != 0)
				break;
			count++;
		}
		return intx::uint512(count);
	}

	case LLIL_RBIT:
	{
		// Reverse the bit order of the sz-byte value.
		intx::uint512 val = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		size_t bits = sz * 8;
		intx::uint512 result(0);
		for (size_t i = 0; i < bits; i++)
			if (((val >> i) & intx::uint512(1)) != 0)
				result |= intx::uint512(1) << (bits - 1 - i);
		return result;
	}

	case LLIL_CLS:
	{
		// Count leading sign bits: number of bits below the sign bit that match it.
		intx::uint512 val = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		size_t bits = sz * 8;
		intx::uint512 sign = (val >> (bits - 1)) & intx::uint512(1);
		uint64_t count = 0;
		for (size_t i = bits - 1; i-- > 0;)
		{
			if (((val >> i) & intx::uint512(1)) != sign)
				break;
			count++;
		}
		return intx::uint512(count);
	}

	case LLIL_ABS:
	{
		// Signed absolute value; abs(INT_MIN) == INT_MIN.
		intx::uint512 val = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		size_t bits = sz * 8;
		bool neg = ((val >> (bits - 1)) & intx::uint512(1)) != 0;
		return neg ? MaskToSize(~val + 1, sz) : val;
	}

	case LLIL_MINS:
	case LLIL_MAXS:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		// leftWins for MINS when left <= right, for MAXS when left >= right (i.e. !(left < right))
		bool leftWins = (expr.operation == LLIL_MINS) ? !SignedLess(right, left, sz)
		                                              : !SignedLess(left, right, sz);
		return leftWins ? left : right;
	}

	case LLIL_MINU:
	case LLIL_MAXU:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		bool leftWins = (expr.operation == LLIL_MINU) ? (left <= right) : (left >= right);
		return leftWins ? left : right;
	}

	// --- Comparisons ---
	case LLIL_CMP_E:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		return MaskToSize(left, sz) == MaskToSize(right, sz) ? intx::uint512(1) : intx::uint512(0);
	}

	case LLIL_CMP_NE:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		return MaskToSize(left, sz) != MaskToSize(right, sz) ? intx::uint512(1) : intx::uint512(0);
	}

	case LLIL_CMP_SLT:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		return SignedLess(left, right, sz) ? intx::uint512(1) : intx::uint512(0);
	}

	case LLIL_CMP_ULT:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		return left < right ? intx::uint512(1) : intx::uint512(0);
	}

	case LLIL_CMP_SLE:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		return !SignedLess(right, left, sz) ? intx::uint512(1) : intx::uint512(0);
	}

	case LLIL_CMP_ULE:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		return left <= right ? intx::uint512(1) : intx::uint512(0);
	}

	case LLIL_CMP_SGE:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		return !SignedLess(left, right, sz) ? intx::uint512(1) : intx::uint512(0);
	}

	case LLIL_CMP_UGE:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		return left >= right ? intx::uint512(1) : intx::uint512(0);
	}

	case LLIL_CMP_SGT:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		return SignedLess(right, left, sz) ? intx::uint512(1) : intx::uint512(0);
	}

	case LLIL_CMP_UGT:
	{
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		return left > right ? intx::uint512(1) : intx::uint512(0);
	}

	// --- Memory ---
	case LLIL_LOAD:
	{
		uint64_t addr = static_cast<uint64_t>(EvalExpr(expr.GetRawOperandAsExpr(0)));
		return ReadMemoryValue(addr, sz);
	}

	case LLIL_POP:
		return Pop(sz);

	// --- Misc ---
	case LLIL_BOOL_TO_INT:
		return EvalExpr(expr.GetRawOperandAsExpr(0)) != 0 ? intx::uint512(1) : intx::uint512(0);

	case LLIL_TEST_BIT:
	{
		intx::uint512 left = EvalExpr(expr.GetRawOperandAsExpr(0));
		intx::uint512 right = EvalExpr(expr.GetRawOperandAsExpr(1));
		return (left & right) != 0 ? intx::uint512(1) : intx::uint512(0);
	}

	case LLIL_ADD_OVERFLOW:
	{
		// Signed overflow flag: set when both operands share a sign and the result's sign
		// differs from them (not the unsigned carry-out).
		intx::uint512 left = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(0)), sz);
		intx::uint512 right = MaskToSize(EvalExpr(expr.GetRawOperandAsExpr(1)), sz);
		intx::uint512 result = MaskToSize(left + right, sz);
		intx::uint512 signBit = intx::uint512(1) << (sz * 8 - 1);
		bool overflow = ((left ^ result) & (right ^ result) & signBit) != 0;
		return overflow ? intx::uint512(1) : intx::uint512(0);
	}

	// --- Flag conditions (Lifted IL) ---
	case LLIL_FLAG_COND:
	{
		BNLowLevelILFlagCondition cond = expr.GetRawOperandAsFlagCondition(0);
		uint32_t semClass = expr.GetRawOperandAsRegister(1);
		return EvalFlagCondition(cond, semClass);
	}

	case LLIL_FLAG_GROUP:
	{
		uint32_t semGroup = expr.GetRawOperandAsRegister(0);
		auto condMap = m_arch->GetFlagConditionsForSemanticFlagGroup(semGroup);
		if (!condMap.empty())
			return EvalFlagCondition(condMap.begin()->second, condMap.begin()->first);
		SetStopReason(ILEmulatorStopReason::Unimplemented,
			fmt::format("unknown flag group {}", semGroup));
		return 0;
	}

	case LLIL_UNDEF:
		return 0;

	case LLIL_UNIMPL:
		SetStopReason(ILEmulatorStopReason::Unimplemented,
			fmt::format("unimplemented IL expression at 0x{:x}", expr.address));
		return 0;

	case LLIL_UNIMPL_MEM:
		SetStopReason(ILEmulatorStopReason::Unimplemented,
			fmt::format("unimplemented memory IL expression at 0x{:x}", expr.address));
		return 0;

	default:
		SetStopReason(ILEmulatorStopReason::Unimplemented,
			fmt::format("unhandled IL expression operation {} at 0x{:x}",
				(int)expr.operation, expr.address));
		return 0;
	}
}


// ============================================================================
// Flag condition evaluation
// ============================================================================

intx::uint512 LLILEmulator::EvalFlagCondition(BNLowLevelILFlagCondition cond, uint32_t semClass)
{
	auto requiredFlags = m_arch->GetFlagsRequiredForFlagCondition(cond, semClass);

	uint8_t z = 0, s = 0, c = 0, o = 0;
	for (uint32_t flag : requiredFlags)
	{
		uint8_t val = GetFlag(flag);
		BNFlagRole role = m_arch->GetFlagRole(flag, semClass);
		switch (role)
		{
		case ZeroFlagRole:
			z = val;
			break;
		case NegativeSignFlagRole:
			s = val;
			break;
		case PositiveSignFlagRole:
			s = val ? 0 : 1;
			break;
		case CarryFlagRole:
		case CarryFlagWithInvertedSubtractRole:
			c = val;
			break;
		case OverflowFlagRole:
			o = val;
			break;
		default:
			break;
		}
	}

	switch (cond)
	{
	case LLFC_E:   return z ? 1 : 0;
	case LLFC_NE:  return z ? 0 : 1;
	case LLFC_SLT: return (s != o) ? 1 : 0;
	case LLFC_ULT: return c ? 1 : 0;
	case LLFC_SLE: return (z || (s != o)) ? 1 : 0;
	case LLFC_ULE: return (c || z) ? 1 : 0;
	case LLFC_SGE: return (s == o) ? 1 : 0;
	case LLFC_UGE: return c ? 0 : 1;
	case LLFC_SGT: return (!z && (s == o)) ? 1 : 0;
	case LLFC_UGT: return (!c && !z) ? 1 : 0;
	case LLFC_NEG: return s ? 1 : 0;
	case LLFC_POS: return s ? 0 : 1;
	case LLFC_O:   return o ? 1 : 0;
	case LLFC_NO:  return o ? 0 : 1;
	default:
		SetStopReason(ILEmulatorStopReason::Unimplemented,
			fmt::format("unhandled flag condition {}", (int)cond));
		return 0;
	}
}


// ============================================================================
// Flag computation for non-lifted LLIL (flag write types on SET_REG)
// ============================================================================

uint8_t LLILEmulator::ComputeFlagForRole(BNFlagRole role) const
{
	const auto& ctx = m_lastArithmetic;
	intx::uint512 signBit = (ctx.size > 0 && ctx.size <= 64) ? (intx::uint512(1) << (ctx.size * 8 - 1)) : intx::uint512(0);
	bool isAdd = (ctx.operation == LLIL_ADD || ctx.operation == LLIL_ADC);
	bool isSub = (ctx.operation == LLIL_SUB || ctx.operation == LLIL_SBB || ctx.operation == LLIL_NEG);

	switch (role)
	{
	case ZeroFlagRole:
		return ctx.result == 0 ? 1 : 0;

	case NegativeSignFlagRole:
		return (ctx.result & signBit) != 0 ? 1 : 0;

	case PositiveSignFlagRole:
		return (ctx.result & signBit) != 0 ? 0 : 1;

	case CarryFlagRole:
		if (isAdd)
			return ctx.result < ctx.left ? 1 : 0;
		if (isSub)
			return ctx.left < ctx.right ? 1 : 0;
		return 0;

	case CarryFlagWithInvertedSubtractRole:
		if (isSub)
			return ctx.left >= ctx.right ? 1 : 0;
		if (isAdd)
			return ctx.result < ctx.left ? 1 : 0;
		return 0;

	case OverflowFlagRole:
		if (isAdd)
		{
			// Overflow if both operands same sign but result different sign
			return (uint8_t)(((~(ctx.left ^ ctx.right)) & (ctx.left ^ ctx.result) & signBit) != 0 ? 1 : 0);
		}
		if (isSub)
		{
			// Overflow if operands different sign and result differs from left
			return (uint8_t)((((ctx.left ^ ctx.right)) & (ctx.left ^ ctx.result) & signBit) != 0 ? 1 : 0);
		}
		return 0;

	case HalfCarryFlagRole:
		if (isAdd)
			return ((ctx.left & intx::uint512(0xf)) + (ctx.right & intx::uint512(0xf))) > intx::uint512(0xf) ? 1 : 0;
		if (isSub)
			return (ctx.left & intx::uint512(0xf)) < (ctx.right & intx::uint512(0xf)) ? 1 : 0;
		return 0;

	case EvenParityFlagRole:
	{
		uint8_t byte = static_cast<uint8_t>(ctx.result);
		byte ^= byte >> 4;
		byte ^= byte >> 2;
		byte ^= byte >> 1;
		return (byte & 1) ? 0 : 1;
	}

	case OddParityFlagRole:
	{
		uint8_t byte = static_cast<uint8_t>(ctx.result);
		byte ^= byte >> 4;
		byte ^= byte >> 2;
		byte ^= byte >> 1;
		return byte & 1;
	}

	default:
		return 0;
	}
}


void LLILEmulator::WriteFlags(uint32_t flagWriteType)
{
	if (!m_lastArithmetic.valid)
		return;

	auto flagsWritten = m_arch->GetFlagsWrittenByFlagWriteType(flagWriteType);
	uint32_t semClass = m_arch->GetSemanticClassForFlagWriteType(flagWriteType);

	for (uint32_t flag : flagsWritten)
	{
		BNFlagRole role = m_arch->GetFlagRole(flag, semClass);
		SetFlag(flag, ComputeFlagForRole(role));
	}
}


// ============================================================================
// ExecInstruction — Side effects
// ============================================================================

void LLILEmulator::ExecuteCurrentInstruction()
{
	LowLevelILInstruction instr = m_il->GetInstruction(m_instrIndex);
	m_currentAddress = instr.address;

	switch (instr.operation)
	{
	case LLIL_NOP:
		break;

	case LLIL_SET_REG:
	{
		uint32_t reg = instr.GetRawOperandAsRegister(0);
		m_lastArithmetic.valid = false;
		intx::uint512 val = EvalExpr(instr.GetRawOperandAsExpr(1));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;
		if (LLIL_REG_IS_TEMP(reg))
			SetTempRegister(LLIL_GET_TEMP_REG_INDEX(reg), val);
		else
			SetRegister(reg, val);
		if (instr.flags != 0)
			WriteFlags(instr.flags);
		break;
	}

	case LLIL_SET_REG_SPLIT:
	{
		uint32_t hi = instr.GetRawOperandAsRegister(0);
		uint32_t lo = instr.GetRawOperandAsRegister(1);
		m_lastArithmetic.valid = false;
		intx::uint512 val = EvalExpr(instr.GetRawOperandAsExpr(2));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;

		size_t loSize;
		if (LLIL_REG_IS_TEMP(lo))
		{
			loSize = instr.size / 2;
			SetTempRegister(LLIL_GET_TEMP_REG_INDEX(lo), MaskToSize(val, loSize));
		}
		else
		{
			BNRegisterInfo loInfo = m_arch->GetRegisterInfo(lo);
			loSize = loInfo.size;
			SetRegister(lo, MaskToSize(val, loSize));
		}

		intx::uint512 hiVal = val >> (loSize * 8);
		if (LLIL_REG_IS_TEMP(hi))
			SetTempRegister(LLIL_GET_TEMP_REG_INDEX(hi), hiVal);
		else
			SetRegister(hi, hiVal);

		if (instr.flags != 0)
			WriteFlags(instr.flags);
		break;
	}

	case LLIL_SET_FLAG:
	{
		uint32_t flag = instr.GetRawOperandAsRegister(0);
		intx::uint512 val = EvalExpr(instr.GetRawOperandAsExpr(1));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;
		SetFlag(flag, static_cast<uint8_t>(static_cast<uint64_t>(val) & 1));
		break;
	}

	case LLIL_STORE:
	{
		uint64_t addr = static_cast<uint64_t>(EvalExpr(instr.GetRawOperandAsExpr(0)));
		intx::uint512 val = EvalExpr(instr.GetRawOperandAsExpr(1));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;
		WriteMemoryValue(addr, val, instr.size);
		break;
	}

	case LLIL_PUSH:
	{
		intx::uint512 val = EvalExpr(instr.GetRawOperandAsExpr(0));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;
		Push(val, instr.size);
		break;
	}

	case LLIL_GOTO:
	{
		size_t target = instr.GetRawOperandAsIndex(0);
		m_instrIndex = target;
		return;
	}

	case LLIL_IF:
	{
		intx::uint512 cond = EvalExpr(instr.GetRawOperandAsExpr(0));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;
		size_t target = (cond != 0) ? instr.GetRawOperandAsIndex(1) : instr.GetRawOperandAsIndex(2);
		m_instrIndex = target;
		return;
	}

	case LLIL_JUMP:
	{
		uint64_t dest = static_cast<uint64_t>(EvalExpr(instr.GetRawOperandAsExpr(0)));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;

		size_t target = m_il->GetInstructionStart(m_arch, dest);
		if (target >= m_il->GetInstructionCount())
		{
			SetStopReason(ILEmulatorStopReason::Error,
				fmt::format("jump to unmapped address 0x{:x}", dest));
			return;
		}
		m_instrIndex = target;
		return;
	}

	case LLIL_JUMP_TO:
	{
		uint64_t dest = static_cast<uint64_t>(EvalExpr(instr.GetRawOperandAsExpr(0)));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;

		size_t target = m_il->GetInstructionStart(m_arch, dest);
		if (target >= m_il->GetInstructionCount())
		{
			SetStopReason(ILEmulatorStopReason::Error,
				fmt::format("jump_to unmapped address 0x{:x}", dest));
			return;
		}
		m_instrIndex = target;
		return;
	}

	case LLIL_CALL:
	{
		uint64_t dest = static_cast<uint64_t>(EvalExpr(instr.GetRawOperandAsExpr(0)));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;

		// 1) Try built-in stubs first
		if (m_builtinLibcStubs && HandleBuiltinCall(dest))
			break;

		// 2) Let the hook handle it (e.g., stub a library call)
		if (m_callHook && m_callHook(this, dest))
			break;

		// 3) Try to enter the callee's LLIL
		{
			// Compute return address before EnterFunction changes m_il/m_arch
			uint64_t returnAddr = GetNativeReturnAddress();
			size_t addrSize = m_arch->GetAddressSize();
			uint32_t lr = m_arch->GetLinkRegister();

			if (EnterFunction(dest, m_instrIndex + 1))
			{
				if (lr != BN_INVALID_REGISTER)
					SetRegister(lr, intx::uint512(returnAddr));
				else
					Push(intx::uint512(returnAddr), addrSize);
				return;
			}
		}

		// 4) Treat unknown external calls as no-op if enabled
		if (HandleUnknownCall(dest))
			break;

		// 5) Cannot resolve — stop
		SetStopReason(ILEmulatorStopReason::CallHook,
			fmt::format("call to 0x{:x}", dest));
		return;
	}

	case LLIL_CALL_STACK_ADJUST:
	{
		uint64_t dest = static_cast<uint64_t>(EvalExpr(instr.GetRawOperandAsExpr(0)));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;

		if (m_builtinLibcStubs && HandleBuiltinCall(dest))
		{
			int64_t adj = (int64_t)instr.GetRawOperandAsInteger(1);
			uint32_t sp = m_arch->GetStackPointerRegister();
			uint64_t spVal = static_cast<uint64_t>(GetRegister(sp));
			SetRegister(sp, intx::uint512(spVal + (uint64_t)adj));
			break;
		}

		if (m_callHook && m_callHook(this, dest))
		{
			int64_t adj = (int64_t)instr.GetRawOperandAsInteger(1);
			uint32_t sp = m_arch->GetStackPointerRegister();
			uint64_t spVal = static_cast<uint64_t>(GetRegister(sp));
			SetRegister(sp, intx::uint512(spVal + (uint64_t)adj));
			break;
		}

		{
			uint64_t returnAddr = GetNativeReturnAddress();
			size_t addrSize = m_arch->GetAddressSize();
			uint32_t lr = m_arch->GetLinkRegister();

			if (EnterFunction(dest, m_instrIndex + 1))
			{
				if (lr != BN_INVALID_REGISTER)
					SetRegister(lr, intx::uint512(returnAddr));
				else
					Push(intx::uint512(returnAddr), addrSize);
				return;
			}
		}

		if (HandleUnknownCall(dest))
		{
			int64_t adj = (int64_t)instr.GetRawOperandAsInteger(1);
			uint32_t sp = m_arch->GetStackPointerRegister();
			uint64_t spVal = static_cast<uint64_t>(GetRegister(sp));
			SetRegister(sp, intx::uint512(spVal + (uint64_t)adj));
			break;
		}

		SetStopReason(ILEmulatorStopReason::CallHook,
			fmt::format("call to 0x{:x}", dest));
		return;
	}

	case LLIL_TAILCALL:
	{
		uint64_t dest = static_cast<uint64_t>(EvalExpr(instr.GetRawOperandAsExpr(0)));
		if (m_stopReason != ILEmulatorStopReason::Running)
			return;

		if (m_builtinLibcStubs && HandleBuiltinCall(dest))
			break;

		if (m_callHook && m_callHook(this, dest))
			break;

		// Tailcall: don't push a frame, replace current function
		if (m_view)
		{
			Ref<Function> func = m_view->GetAnalysisFunction(
				m_view->GetDefaultPlatform(), dest);
			if (func)
			{
				Ref<LowLevelILFunction> targetIL = func->GetLowLevelIL();
				if (targetIL)
				{
					size_t entry = targetIL->GetInstructionStart(
						targetIL->GetArchitecture(), dest);
					if (entry < targetIL->GetInstructionCount())
					{
						m_il = targetIL;
						m_arch = targetIL->GetArchitecture();
						m_instrIndex = entry;
						return;
					}
				}
			}
		}

		if (HandleUnknownCall(dest))
			break;

		SetStopReason(ILEmulatorStopReason::CallHook,
			fmt::format("tailcall to 0x{:x}", dest));
		return;
	}

	case LLIL_RET:
	{
		// Evaluate the return address expression for side effects
		// (pops RA from stack on x86, reads LR on ARM — no-op)
		EvalExpr(instr.GetRawOperandAsExpr(0));

		if (ReturnToCaller())
			return;

		// Top-level return — halt
		SetStopReason(ILEmulatorStopReason::Halt, "return");
		return;
	}

	case LLIL_NORET:
		SetStopReason(ILEmulatorStopReason::Halt, "noreturn");
		return;

	case LLIL_SYSCALL:
	{
		if (m_syscallHook)
		{
			if (m_syscallHook(this))
				break;
		}
		SetStopReason(ILEmulatorStopReason::SyscallHook, "syscall");
		return;
	}

	case LLIL_BP:
		SetStopReason(ILEmulatorStopReason::Halt, "breakpoint instruction");
		return;

	case LLIL_TRAP:
		SetStopReason(ILEmulatorStopReason::Halt,
			fmt::format("trap {}", instr.GetRawOperandAsInteger(0)));
		return;

	case LLIL_INTRINSIC:
	{
		if (m_intrinsicHook)
		{
			uint32_t intrinsic = instr.GetRawOperandAsRegister(2);
			LowLevelILInstruction paramExpr = instr.GetRawOperandAsExpr(3);
			LowLevelILInstructionList paramList = paramExpr.GetRawOperandAsExprList(0);
			std::vector<uint64_t> params;
			for (auto& p : paramList)
			{
				params.push_back(static_cast<uint64_t>(EvalExpr(p)));
				if (m_stopReason != ILEmulatorStopReason::Running)
					return;
			}

			std::vector<std::pair<uint32_t, uint64_t>> outputs;
			if (m_intrinsicHook(this, intrinsic, params, outputs))
			{
				for (auto& [reg, val] : outputs)
					SetRegister(reg, intx::uint512(val));
				break;
			}
		}

		SetStopReason(ILEmulatorStopReason::Unimplemented,
			fmt::format("intrinsic at 0x{:x}", instr.address));
		return;
	}

	case LLIL_UNDEF:
		SetStopReason(ILEmulatorStopReason::UndefinedBehavior,
			fmt::format("undefined behavior at 0x{:x}", instr.address));
		return;

	case LLIL_UNIMPL:
		SetStopReason(ILEmulatorStopReason::Unimplemented,
			fmt::format("unimplemented instruction at 0x{:x}", instr.address));
		return;

	case LLIL_UNIMPL_MEM:
		SetStopReason(ILEmulatorStopReason::Unimplemented,
			fmt::format("unimplemented memory instruction at 0x{:x}", instr.address));
		return;

	default:
		SetStopReason(ILEmulatorStopReason::Unimplemented,
			fmt::format("unhandled IL instruction operation {} at 0x{:x}",
				(int)instr.operation, instr.address));
		return;
	}
}


// ============================================================================
// Built-in libc stub settings
// ============================================================================

void LLILEmulator::SetBuiltinLibcStubsEnabled(bool enabled)
{
	m_builtinLibcStubs = enabled;
}


bool LLILEmulator::IsBuiltinLibcStubsEnabled() const
{
	return m_builtinLibcStubs;
}


void LLILEmulator::SetLogLibcCalls(bool enabled)
{
	m_logLibcCalls = enabled;
}


bool LLILEmulator::IsLogLibcCalls() const
{
	return m_logLibcCalls;
}


void LLILEmulator::SetNopUnknownExternals(bool enabled)
{
	m_nopUnknownExternals = enabled;
}


bool LLILEmulator::IsNopUnknownExternals() const
{
	return m_nopUnknownExternals;
}


// ============================================================================
// Built-in libc stub helpers
// ============================================================================

void LLILEmulator::EnsureHeapMapped()
{
	if (!m_heapMapped)
	{
		MapMemory(HEAP_BASE, HEAP_SIZE, "heap");
		m_heapMapped = true;
	}
}


uint64_t LLILEmulator::ReadArgument(size_t index)
{
	if (!m_view)
		return 0;

	Ref<Platform> platform = m_view->GetDefaultPlatform();
	if (!platform)
		return 0;

	Ref<CallingConvention> cc = platform->GetDefaultCallingConvention();
	if (!cc)
		return 0;

	auto argRegs = cc->GetIntegerArgumentRegisters();
	size_t addrSize = m_arch->GetAddressSize();

	if (index < argRegs.size())
		return static_cast<uint64_t>(GetRegister(argRegs[index]));

	// Stack argument: read from SP + (index - argRegs.size()) * addrSize
	uint32_t sp = m_arch->GetStackPointerRegister();
	uint64_t spVal = static_cast<uint64_t>(GetRegister(sp));
	size_t stackIndex = index - argRegs.size();
	return static_cast<uint64_t>(ReadMemoryValue(spVal + stackIndex * addrSize, addrSize));
}


void LLILEmulator::WriteReturnValue(uint64_t value)
{
	if (!m_view)
		return;

	Ref<Platform> platform = m_view->GetDefaultPlatform();
	if (!platform)
		return;

	Ref<CallingConvention> cc = platform->GetDefaultCallingConvention();
	if (!cc)
		return;

	uint32_t retReg = cc->GetIntegerReturnValueRegister();
	SetRegister(retReg, intx::uint512(value));
}


std::string LLILEmulator::ResolveCallTargetName(uint64_t addr)
{
	if (!m_view)
		return "";

	Ref<Symbol> sym = m_view->GetSymbolByAddress(addr);
	if (!sym)
		return "";

	BNSymbolType type = sym->GetType();
	if (type == ImportedFunctionSymbol || type == FunctionSymbol
		|| type == LibraryFunctionSymbol || type == ExternalSymbol)
		return std::string(sym->GetShortName());

	return "";
}


std::string LLILEmulator::NormalizeLibcName(const std::string& name)
{
	std::string result = name;

	// Strip leading underscore (macOS/Mach-O convention)
	if (result.size() > 1 && result[0] == '_')
		result = result.substr(1);

	// Strip j_ prefix (PLT/thunk convention)
	if (result.size() > 2 && result.substr(0, 2) == "j_")
		result = result.substr(2);

	return result;
}


const std::unordered_map<std::string, LLILEmulator::StubFn>& LLILEmulator::GetStubTable()
{
	static const std::unordered_map<std::string, StubFn> table = {
		// C library memory functions
		{"memcpy", &LLILEmulator::StubMemcpy},
		{"memset", &LLILEmulator::StubMemset},
		{"memmove", &LLILEmulator::StubMemmove},
		// C library string functions
		{"strlen", &LLILEmulator::StubStrlen},
		{"strcmp", &LLILEmulator::StubStrcmp},
		{"strncmp", &LLILEmulator::StubStrncmp},
		{"strcpy", &LLILEmulator::StubStrcpy},
		{"strncpy", &LLILEmulator::StubStrncpy},
		// C library allocation
		{"malloc", &LLILEmulator::StubMalloc},
		{"free", &LLILEmulator::StubFree},
		{"calloc", &LLILEmulator::StubCalloc},
		{"realloc", &LLILEmulator::StubRealloc},
		// Windows API - virtual memory
		{"VirtualAlloc", &LLILEmulator::StubVirtualAlloc},
		{"VirtualFree", &LLILEmulator::StubVirtualFree},
		{"VirtualProtect", &LLILEmulator::StubVirtualProtect},
		// Windows API - heap
		{"HeapAlloc", &LLILEmulator::StubHeapAlloc},
		{"HeapFree", &LLILEmulator::StubHeapFree},
		// Windows API - string
		{"lstrcpyA", &LLILEmulator::StubLstrcpyA},
		{"lstrcpyW", &LLILEmulator::StubLstrcpyW},
		{"lstrcmpA", &LLILEmulator::StubLstrcmpA},
		{"lstrcmpW", &LLILEmulator::StubLstrcmpW},
		{"lstrlenA", &LLILEmulator::StubLstrlenA},
		{"lstrlenW", &LLILEmulator::StubLstrlenW},
		// Windows API - conversion
		{"MultiByteToWideChar", &LLILEmulator::StubMultiByteToWideChar},
		{"WideCharToMultiByte", &LLILEmulator::StubWideCharToMultiByte},
		// C library printf family
		{"putchar", &LLILEmulator::StubPutchar},
		{"puts", &LLILEmulator::StubPuts},
		{"printf", &LLILEmulator::StubPrintf},
		{"sprintf", &LLILEmulator::StubSprintf},
		{"snprintf", &LLILEmulator::StubSnprintf},
		{"fprintf", &LLILEmulator::StubFprintf},
		// glibc fortified variants
		{"__printf_chk", &LLILEmulator::StubPrintf},
		{"__sprintf_chk", &LLILEmulator::StubSprintf},
		{"__snprintf_chk", &LLILEmulator::StubSnprintf},
		{"__fprintf_chk", &LLILEmulator::StubFprintf},
		// C library stdin
		{"getchar", &LLILEmulator::StubGetchar},
		{"gets", &LLILEmulator::StubGets},
		{"fgets", &LLILEmulator::StubFgets},
		{"fread", &LLILEmulator::StubFread},
	};
	return table;
}


bool LLILEmulator::HandleBuiltinCall(uint64_t dest)
{
	std::string name = ResolveCallTargetName(dest);
	if (name.empty())
		return false;

	std::string normalized = NormalizeLibcName(name);

	auto& table = GetStubTable();
	auto it = table.find(normalized);
	if (it == table.end())
		return false;

	return (this->*(it->second))(dest);
}


bool LLILEmulator::HandleUnknownCall(uint64_t dest)
{
	if (!m_nopUnknownExternals)
		return false;

	std::string name = ResolveCallTargetName(dest);
	if (name.empty())
		return false;

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: unhandled call to %s (0x%" PRIx64 "), returning 0", name.c_str(), dest);

	WriteReturnValue(0);
	return true;
}


// ============================================================================
// Built-in libc stub implementations
// ============================================================================

static constexpr size_t MEM_OP_LIMIT = 16 * 1024 * 1024;  // 16MB
static constexpr size_t STR_OP_LIMIT = 1 * 1024 * 1024;   // 1MB


bool LLILEmulator::StubMemcpy(uint64_t)
{
	uint64_t destAddr = ReadArgument(0);
	uint64_t srcAddr = ReadArgument(1);
	uint64_t n = ReadArgument(2);

	if (n > MEM_OP_LIMIT)
		n = MEM_OP_LIMIT;

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub memcpy(dest=0x%" PRIx64 ", src=0x%" PRIx64 ", n=0x%" PRIx64 ")", destAddr, srcAddr, n);

	if (n > 0)
	{
		std::vector<uint8_t> buf(n);
		m_memory.Read(buf.data(), srcAddr, n);
		m_memory.Write(destAddr, buf.data(), n);
	}

	WriteReturnValue(destAddr);
	return true;
}


bool LLILEmulator::StubMemset(uint64_t)
{
	uint64_t s = ReadArgument(0);
	uint64_t c = ReadArgument(1);
	uint64_t n = ReadArgument(2);

	if (n > MEM_OP_LIMIT)
		n = MEM_OP_LIMIT;

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub memset(s=0x%" PRIx64 ", c=0x%" PRIx64 ", n=0x%" PRIx64 ")", s, c, n);

	if (n > 0)
	{
		std::vector<uint8_t> buf(n, (uint8_t)(c & 0xFF));
		m_memory.Write(s, buf.data(), n);
	}

	WriteReturnValue(s);
	return true;
}


bool LLILEmulator::StubMemmove(uint64_t)
{
	uint64_t destAddr = ReadArgument(0);
	uint64_t srcAddr = ReadArgument(1);
	uint64_t n = ReadArgument(2);

	if (n > MEM_OP_LIMIT)
		n = MEM_OP_LIMIT;

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub memmove(dest=0x%" PRIx64 ", src=0x%" PRIx64 ", n=0x%" PRIx64 ")", destAddr, srcAddr, n);

	if (n > 0)
	{
		std::vector<uint8_t> buf(n);
		m_memory.Read(buf.data(), srcAddr, n);
		m_memory.Write(destAddr, buf.data(), n);
	}

	WriteReturnValue(destAddr);
	return true;
}


bool LLILEmulator::StubStrlen(uint64_t)
{
	uint64_t s = ReadArgument(0);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub strlen(s=0x%" PRIx64 ")", s);

	uint64_t len = 0;
	uint8_t byte;
	while (len < STR_OP_LIMIT)
	{
		if (m_memory.Read(&byte, s + len, 1) != 1 || byte == 0)
			break;
		len++;
	}

	WriteReturnValue(len);
	return true;
}


bool LLILEmulator::StubStrcmp(uint64_t)
{
	uint64_t s1 = ReadArgument(0);
	uint64_t s2 = ReadArgument(1);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub strcmp(s1=0x%" PRIx64 ", s2=0x%" PRIx64 ")", s1, s2);

	int result = 0;
	for (size_t i = 0; i < STR_OP_LIMIT; i++)
	{
		uint8_t c1 = 0, c2 = 0;
		m_memory.Read(&c1, s1 + i, 1);
		m_memory.Read(&c2, s2 + i, 1);
		if (c1 != c2)
		{
			result = (int)c1 - (int)c2;
			break;
		}
		if (c1 == 0)
			break;
	}

	WriteReturnValue((uint64_t)(int64_t)result);
	return true;
}


bool LLILEmulator::StubStrncmp(uint64_t)
{
	uint64_t s1 = ReadArgument(0);
	uint64_t s2 = ReadArgument(1);
	uint64_t n = ReadArgument(2);

	if (n > STR_OP_LIMIT)
		n = STR_OP_LIMIT;

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub strncmp(s1=0x%" PRIx64 ", s2=0x%" PRIx64 ", n=0x%" PRIx64 ")", s1, s2, n);

	int result = 0;
	for (uint64_t i = 0; i < n; i++)
	{
		uint8_t c1 = 0, c2 = 0;
		m_memory.Read(&c1, s1 + i, 1);
		m_memory.Read(&c2, s2 + i, 1);
		if (c1 != c2)
		{
			result = (int)c1 - (int)c2;
			break;
		}
		if (c1 == 0)
			break;
	}

	WriteReturnValue((uint64_t)(int64_t)result);
	return true;
}


bool LLILEmulator::StubStrcpy(uint64_t)
{
	uint64_t destAddr = ReadArgument(0);
	uint64_t srcAddr = ReadArgument(1);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub strcpy(dest=0x%" PRIx64 ", src=0x%" PRIx64 ")", destAddr, srcAddr);

	for (size_t i = 0; i < STR_OP_LIMIT; i++)
	{
		uint8_t byte = 0;
		m_memory.Read(&byte, srcAddr + i, 1);
		m_memory.Write(destAddr + i, &byte, 1);
		if (byte == 0)
			break;
	}

	WriteReturnValue(destAddr);
	return true;
}


bool LLILEmulator::StubStrncpy(uint64_t)
{
	uint64_t destAddr = ReadArgument(0);
	uint64_t srcAddr = ReadArgument(1);
	uint64_t n = ReadArgument(2);

	if (n > STR_OP_LIMIT)
		n = STR_OP_LIMIT;

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub strncpy(dest=0x%" PRIx64 ", src=0x%" PRIx64 ", n=0x%" PRIx64 ")", destAddr, srcAddr, n);

	bool hitNull = false;
	for (uint64_t i = 0; i < n; i++)
	{
		uint8_t byte = 0;
		if (!hitNull)
		{
			m_memory.Read(&byte, srcAddr + i, 1);
			if (byte == 0)
				hitNull = true;
		}
		m_memory.Write(destAddr + i, &byte, 1);
	}

	WriteReturnValue(destAddr);
	return true;
}


bool LLILEmulator::StubMalloc(uint64_t)
{
	uint64_t size = ReadArgument(0);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub malloc(size=0x%" PRIx64 ")", size);

	EnsureHeapMapped();

	// 16-byte align
	uint64_t aligned = (m_heapBumpPtr + 15) & ~(uint64_t)15;
	if (aligned + size > HEAP_BASE + HEAP_SIZE || size > HEAP_SIZE)
	{
		WriteReturnValue(0);
		return true;
	}

	m_heapBumpPtr = aligned + size;
	m_heapAllocations[aligned] = (size_t)size;
	WriteReturnValue(aligned);
	return true;
}


bool LLILEmulator::StubFree(uint64_t)
{
	uint64_t ptr = ReadArgument(0);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub free(ptr=0x%" PRIx64 ")", ptr);

	m_heapAllocations.erase(ptr);
	WriteReturnValue(0);
	return true;
}


bool LLILEmulator::StubCalloc(uint64_t)
{
	uint64_t nmemb = ReadArgument(0);
	uint64_t size = ReadArgument(1);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub calloc(nmemb=0x%" PRIx64 ", size=0x%" PRIx64 ")", nmemb, size);

	// Check for multiplication overflow
	if (size != 0 && nmemb > UINT64_MAX / size)
	{
		WriteReturnValue(0);
		return true;
	}
	uint64_t total = nmemb * size;

	EnsureHeapMapped();

	uint64_t aligned = (m_heapBumpPtr + 15) & ~(uint64_t)15;
	if (aligned + total > HEAP_BASE + HEAP_SIZE || total > HEAP_SIZE)
	{
		WriteReturnValue(0);
		return true;
	}

	// Zero-fill (heap is already zero-mapped, but be explicit)
	std::vector<uint8_t> zeros(total, 0);
	m_memory.Write(aligned, zeros.data(), total);

	m_heapBumpPtr = aligned + total;
	m_heapAllocations[aligned] = (size_t)total;
	WriteReturnValue(aligned);
	return true;
}


bool LLILEmulator::StubRealloc(uint64_t)
{
	uint64_t ptr = ReadArgument(0);
	uint64_t newSize = ReadArgument(1);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub realloc(ptr=0x%" PRIx64 ", size=0x%" PRIx64 ")", ptr, newSize);

	if (ptr == 0)
	{
		// realloc(NULL, size) == malloc(size)
		EnsureHeapMapped();
		uint64_t aligned = (m_heapBumpPtr + 15) & ~(uint64_t)15;
		if (aligned + newSize > HEAP_BASE + HEAP_SIZE || newSize > HEAP_SIZE)
		{
			WriteReturnValue(0);
			return true;
		}
		m_heapBumpPtr = aligned + newSize;
		m_heapAllocations[aligned] = (size_t)newSize;
		WriteReturnValue(aligned);
		return true;
	}

	EnsureHeapMapped();

	uint64_t aligned = (m_heapBumpPtr + 15) & ~(uint64_t)15;
	if (aligned + newSize > HEAP_BASE + HEAP_SIZE || newSize > HEAP_SIZE)
	{
		WriteReturnValue(0);
		return true;
	}

	// Copy old data
	size_t oldSize = 0;
	auto it = m_heapAllocations.find(ptr);
	if (it != m_heapAllocations.end())
		oldSize = it->second;

	size_t copySize = (oldSize < (size_t)newSize) ? oldSize : (size_t)newSize;
	if (copySize > 0)
	{
		std::vector<uint8_t> buf(copySize);
		m_memory.Read(buf.data(), ptr, copySize);
		m_memory.Write(aligned, buf.data(), copySize);
	}

	m_heapAllocations.erase(ptr);
	m_heapBumpPtr = aligned + newSize;
	m_heapAllocations[aligned] = (size_t)newSize;
	WriteReturnValue(aligned);
	return true;
}


// ============================================================================
// Windows API stubs
// ============================================================================

bool LLILEmulator::StubVirtualAlloc(uint64_t)
{
	uint64_t addr = ReadArgument(0);
	uint64_t size = ReadArgument(1);
	// uint64_t type = ReadArgument(2);  // MEM_COMMIT, etc.
	// uint64_t protect = ReadArgument(3);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub VirtualAlloc(addr=0x%" PRIx64 ", size=0x%" PRIx64 ")", addr, size);

	EnsureHeapMapped();

	(void)addr;  // Ignore address hint

	uint64_t aligned = (m_heapBumpPtr + 15) & ~(uint64_t)15;
	if (aligned + size > HEAP_BASE + HEAP_SIZE || size > HEAP_SIZE)
	{
		WriteReturnValue(0);
		return true;
	}

	// Zero-fill
	std::vector<uint8_t> zeros(size, 0);
	m_memory.Write(aligned, zeros.data(), size);

	m_heapBumpPtr = aligned + size;
	m_heapAllocations[aligned] = (size_t)size;
	WriteReturnValue(aligned);
	return true;
}


bool LLILEmulator::StubVirtualFree(uint64_t)
{
	uint64_t addr = ReadArgument(0);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub VirtualFree(addr=0x%" PRIx64 ")", addr);

	m_heapAllocations.erase(addr);
	WriteReturnValue(1);  // TRUE
	return true;
}


bool LLILEmulator::StubVirtualProtect(uint64_t)
{
	uint64_t addr = ReadArgument(0);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub VirtualProtect(addr=0x%" PRIx64 ")", addr);

	WriteReturnValue(1);  // TRUE
	return true;
}


bool LLILEmulator::StubHeapAlloc(uint64_t)
{
	// uint64_t hHeap = ReadArgument(0);
	uint64_t flags = ReadArgument(1);
	uint64_t size = ReadArgument(2);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub HeapAlloc(flags=0x%" PRIx64 ", size=0x%" PRIx64 ")", flags, size);

	EnsureHeapMapped();

	uint64_t aligned = (m_heapBumpPtr + 15) & ~(uint64_t)15;
	if (aligned + size > HEAP_BASE + HEAP_SIZE || size > HEAP_SIZE)
	{
		WriteReturnValue(0);
		return true;
	}

	// HEAP_ZERO_MEMORY = 0x00000008
	if (flags & 0x8)
	{
		std::vector<uint8_t> zeros(size, 0);
		m_memory.Write(aligned, zeros.data(), size);
	}

	m_heapBumpPtr = aligned + size;
	m_heapAllocations[aligned] = (size_t)size;
	WriteReturnValue(aligned);
	return true;
}


bool LLILEmulator::StubHeapFree(uint64_t)
{
	// uint64_t hHeap = ReadArgument(0);
	// uint64_t flags = ReadArgument(1);
	uint64_t ptr = ReadArgument(2);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub HeapFree(ptr=0x%" PRIx64 ")", ptr);

	m_heapAllocations.erase(ptr);
	WriteReturnValue(1);  // TRUE
	return true;
}


bool LLILEmulator::StubLstrcpyA(uint64_t dest)
{
	if (m_logLibcCalls)
	{
		uint64_t d = ReadArgument(0);
		uint64_t s = ReadArgument(1);
		LogInfo("BNIL Emulator: stub lstrcpyA(dest=0x%" PRIx64 ", src=0x%" PRIx64 ")", d, s);
	}
	bool savedLog = m_logLibcCalls;
	m_logLibcCalls = false;
	bool result = StubStrcpy(dest);
	m_logLibcCalls = savedLog;
	return result;
}


bool LLILEmulator::StubLstrcpyW(uint64_t)
{
	uint64_t destAddr = ReadArgument(0);
	uint64_t srcAddr = ReadArgument(1);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub lstrcpyW(dest=0x%" PRIx64 ", src=0x%" PRIx64 ")", destAddr, srcAddr);

	for (size_t i = 0; i < STR_OP_LIMIT; i++)
	{
		uint8_t wchar[2] = {0, 0};
		m_memory.Read(wchar, srcAddr + i * 2, 2);
		m_memory.Write(destAddr + i * 2, wchar, 2);
		if (wchar[0] == 0 && wchar[1] == 0)
			break;
	}

	WriteReturnValue(destAddr);
	return true;
}


bool LLILEmulator::StubLstrcmpA(uint64_t dest)
{
	if (m_logLibcCalls)
	{
		uint64_t s1 = ReadArgument(0);
		uint64_t s2 = ReadArgument(1);
		LogInfo("BNIL Emulator: stub lstrcmpA(s1=0x%" PRIx64 ", s2=0x%" PRIx64 ")", s1, s2);
	}
	bool savedLog = m_logLibcCalls;
	m_logLibcCalls = false;
	bool result = StubStrcmp(dest);
	m_logLibcCalls = savedLog;
	return result;
}


bool LLILEmulator::StubLstrcmpW(uint64_t)
{
	uint64_t s1 = ReadArgument(0);
	uint64_t s2 = ReadArgument(1);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub lstrcmpW(s1=0x%" PRIx64 ", s2=0x%" PRIx64 ")", s1, s2);

	int result = 0;
	for (size_t i = 0; i < STR_OP_LIMIT; i++)
	{
		uint8_t w1[2] = {0, 0}, w2[2] = {0, 0};
		m_memory.Read(w1, s1 + i * 2, 2);
		m_memory.Read(w2, s2 + i * 2, 2);
		uint16_t c1 = (uint16_t)w1[0] | ((uint16_t)w1[1] << 8);
		uint16_t c2 = (uint16_t)w2[0] | ((uint16_t)w2[1] << 8);
		if (c1 != c2)
		{
			result = (int)c1 - (int)c2;
			break;
		}
		if (c1 == 0)
			break;
	}

	WriteReturnValue((uint64_t)(int64_t)result);
	return true;
}


bool LLILEmulator::StubLstrlenA(uint64_t dest)
{
	if (m_logLibcCalls)
	{
		uint64_t s = ReadArgument(0);
		LogInfo("BNIL Emulator: stub lstrlenA(s=0x%" PRIx64 ")", s);
	}
	bool savedLog = m_logLibcCalls;
	m_logLibcCalls = false;
	bool result = StubStrlen(dest);
	m_logLibcCalls = savedLog;
	return result;
}


bool LLILEmulator::StubLstrlenW(uint64_t)
{
	uint64_t s = ReadArgument(0);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub lstrlenW(s=0x%" PRIx64 ")", s);

	uint64_t len = 0;
	while (len < STR_OP_LIMIT)
	{
		uint8_t wchar[2] = {0, 0};
		if (m_memory.Read(wchar, s + len * 2, 2) != 2)
			break;
		if (wchar[0] == 0 && wchar[1] == 0)
			break;
		len++;
	}

	WriteReturnValue(len);
	return true;
}


bool LLILEmulator::StubMultiByteToWideChar(uint64_t)
{
	// uint64_t codePage = ReadArgument(0);
	// uint64_t flags = ReadArgument(1);
	uint64_t mbStr = ReadArgument(2);
	int64_t mbLen = (int64_t)ReadArgument(3);
	uint64_t wcStr = ReadArgument(4);
	int64_t wcLen = (int64_t)ReadArgument(5);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub MultiByteToWideChar(mb=0x%" PRIx64 ", mbLen=%" PRId64 ", wc=0x%" PRIx64 ", wcLen=%" PRId64 ")",
			mbStr, mbLen, wcStr, wcLen);

	// Determine source length
	size_t srcLen;
	if (mbLen == -1)
	{
		// null-terminated
		srcLen = 0;
		uint8_t byte;
		while (srcLen < STR_OP_LIMIT)
		{
			if (m_memory.Read(&byte, mbStr + srcLen, 1) != 1 || byte == 0)
			{
				srcLen++;  // include null
				break;
			}
			srcLen++;
		}
	}
	else
	{
		srcLen = (size_t)mbLen;
		if (srcLen > STR_OP_LIMIT)
			srcLen = STR_OP_LIMIT;
	}

	if (wcLen == 0)
	{
		// Query mode: return required size
		WriteReturnValue((uint64_t)srcLen);
		return true;
	}

	size_t copyLen = srcLen;
	if (copyLen > (size_t)wcLen)
		copyLen = (size_t)wcLen;

	// Simple ASCII -> UTF16LE copy
	for (size_t i = 0; i < copyLen; i++)
	{
		uint8_t byte = 0;
		m_memory.Read(&byte, mbStr + i, 1);
		uint8_t wchar[2] = {byte, 0};
		m_memory.Write(wcStr + i * 2, wchar, 2);
	}

	WriteReturnValue((uint64_t)copyLen);
	return true;
}


bool LLILEmulator::StubWideCharToMultiByte(uint64_t)
{
	// uint64_t codePage = ReadArgument(0);
	// uint64_t flags = ReadArgument(1);
	uint64_t wcStr = ReadArgument(2);
	int64_t wcLen = (int64_t)ReadArgument(3);
	uint64_t mbStr = ReadArgument(4);
	int64_t mbLen = (int64_t)ReadArgument(5);
	// uint64_t defaultChar = ReadArgument(6);
	// uint64_t usedDefaultChar = ReadArgument(7);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub WideCharToMultiByte(wc=0x%" PRIx64 ", wcLen=%" PRId64 ", mb=0x%" PRIx64 ", mbLen=%" PRId64 ")",
			wcStr, wcLen, mbStr, mbLen);

	// Determine source length (in wide chars)
	size_t srcLen;
	if (wcLen == -1)
	{
		srcLen = 0;
		while (srcLen < STR_OP_LIMIT)
		{
			uint8_t wchar[2] = {0, 0};
			if (m_memory.Read(wchar, wcStr + srcLen * 2, 2) != 2)
				break;
			srcLen++;
			if (wchar[0] == 0 && wchar[1] == 0)
				break;
		}
	}
	else
	{
		srcLen = (size_t)wcLen;
		if (srcLen > STR_OP_LIMIT)
			srcLen = STR_OP_LIMIT;
	}

	if (mbLen == 0)
	{
		// Query mode
		WriteReturnValue((uint64_t)srcLen);
		return true;
	}

	size_t copyLen = srcLen;
	if (copyLen > (size_t)mbLen)
		copyLen = (size_t)mbLen;

	// Simple UTF16LE -> ASCII copy (take low byte)
	for (size_t i = 0; i < copyLen; i++)
	{
		uint8_t wchar[2] = {0, 0};
		m_memory.Read(wchar, wcStr + i * 2, 2);
		uint8_t byte = wchar[0];  // Take low byte (ASCII)
		m_memory.Write(mbStr + i, &byte, 1);
	}

	WriteReturnValue((uint64_t)copyLen);
	return true;
}


// ============================================================================
// printf family stubs
// ============================================================================

// Escape a string for log display: \n, \r, \t, \0, and non-printable bytes shown as \xNN.
static std::string EscapeForLog(const std::string& s)
{
	std::string out;
	out.reserve(s.size());
	for (unsigned char c : s)
	{
		switch (c)
		{
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		case '\0': out += "\\0"; break;
		case '\\': out += "\\\\"; break;
		default:
			if (c >= 0x20 && c < 0x7f)
				out += (char)c;
			else
			{
				char buf[5];
				snprintf(buf, sizeof(buf), "\\x%02x", c);
				out += buf;
			}
			break;
		}
	}
	return out;
}


static constexpr size_t PRINTF_FMT_LIMIT = 4096;
static constexpr size_t PRINTF_OUTPUT_LIMIT = 65536;
static constexpr int PRINTF_WIDTH_PRECISION_MAX = 256;
static constexpr size_t PRINTF_SPECIFIER_BUF = 512;


std::string LLILEmulator::FormatPrintf(size_t fmtArgIndex, size_t firstVarArgIndex)
{
	uint64_t fmtPtr = ReadArgument(fmtArgIndex);

	// Read format string from emulated memory
	std::string fmt;
	fmt.reserve(256);
	for (size_t i = 0; i < PRINTF_FMT_LIMIT; i++)
	{
		uint8_t byte = 0;
		if (m_memory.Read(&byte, fmtPtr + i, 1) != 1 || byte == 0)
			break;
		fmt.push_back((char)byte);
	}

	std::string output;
	output.reserve(256);
	size_t argIndex = firstVarArgIndex;
	size_t pos = 0;

	while (pos < fmt.size() && output.size() < PRINTF_OUTPUT_LIMIT)
	{
		if (fmt[pos] != '%')
		{
			output.push_back(fmt[pos++]);
			continue;
		}
		pos++;  // skip '%'

		if (pos >= fmt.size())
			break;

		// Handle %%
		if (fmt[pos] == '%')
		{
			output.push_back('%');
			pos++;
			continue;
		}

		// Parse specifier: % [flags] [width] [.precision] [length] conversion
		std::string specFmt = "%";

		// Flags
		while (pos < fmt.size())
		{
			char c = fmt[pos];
			if (c == '-' || c == '+' || c == ' ' || c == '#' || c == '0')
			{
				specFmt.push_back(c);
				pos++;
			}
			else
				break;
		}

		// Width
		int width = 0;
		if (pos < fmt.size() && fmt[pos] == '*')
		{
			width = (int)(int64_t)ReadArgument(argIndex++);
			if (width < 0)
				width = -width;  // negative width means left-justify
			if (width > PRINTF_WIDTH_PRECISION_MAX)
				width = PRINTF_WIDTH_PRECISION_MAX;
			specFmt += std::to_string(width);
			pos++;
		}
		else
		{
			while (pos < fmt.size() && fmt[pos] >= '0' && fmt[pos] <= '9')
			{
				width = width * 10 + (fmt[pos] - '0');
				pos++;
			}
			if (width > PRINTF_WIDTH_PRECISION_MAX)
				width = PRINTF_WIDTH_PRECISION_MAX;
			if (width > 0)
				specFmt += std::to_string(width);
		}

		// Precision
		int precision = -1;
		if (pos < fmt.size() && fmt[pos] == '.')
		{
			pos++;
			precision = 0;
			if (pos < fmt.size() && fmt[pos] == '*')
			{
				precision = (int)(int64_t)ReadArgument(argIndex++);
				if (precision < 0)
					precision = 0;
				if (precision > PRINTF_WIDTH_PRECISION_MAX)
					precision = PRINTF_WIDTH_PRECISION_MAX;
				pos++;
			}
			else
			{
				while (pos < fmt.size() && fmt[pos] >= '0' && fmt[pos] <= '9')
				{
					precision = precision * 10 + (fmt[pos] - '0');
					pos++;
				}
				if (precision > PRINTF_WIDTH_PRECISION_MAX)
					precision = PRINTF_WIDTH_PRECISION_MAX;
			}
			specFmt += "." + std::to_string(precision);
		}

		// Length modifier
		std::string lengthMod;
		if (pos < fmt.size())
		{
			char c = fmt[pos];
			if (c == 'h')
			{
				pos++;
				if (pos < fmt.size() && fmt[pos] == 'h')
				{
					lengthMod = "hh";
					pos++;
				}
				else
					lengthMod = "h";
			}
			else if (c == 'l')
			{
				pos++;
				if (pos < fmt.size() && fmt[pos] == 'l')
				{
					lengthMod = "ll";
					pos++;
				}
				else
					lengthMod = "l";
			}
			else if (c == 'z' || c == 'j' || c == 't' || c == 'L')
			{
				lengthMod.push_back(c);
				pos++;
			}
		}

		// Conversion
		if (pos >= fmt.size())
			break;

		char conv = fmt[pos++];

		// %n: reject
		if (conv == 'n')
		{
			LogWarn("BNIL Emulator: printf %%n rejected (attempted write via format string)");
			argIndex++;  // consume the argument
			continue;
		}

		// Read the argument value
		uint64_t argVal = ReadArgument(argIndex++);

		char specBuf[PRINTF_SPECIFIER_BUF];

		switch (conv)
		{
		case 'd':
		case 'i':
		{
			// Use ll to handle all integer sizes uniformly
			std::string finalFmt = specFmt + "ll" + conv;
			snprintf(specBuf, sizeof(specBuf), finalFmt.c_str(), (long long)(int64_t)argVal);
			output += specBuf;
			break;
		}
		case 'u':
		case 'o':
		case 'x':
		case 'X':
		{
			std::string finalFmt = specFmt + "ll" + conv;
			snprintf(specBuf, sizeof(specBuf), finalFmt.c_str(), (unsigned long long)argVal);
			output += specBuf;
			break;
		}
		case 'c':
		{
			std::string finalFmt = specFmt + "c";
			snprintf(specBuf, sizeof(specBuf), finalFmt.c_str(), (int)(argVal & 0xFF));
			output += specBuf;
			break;
		}
		case 's':
		{
			// Read string from emulated memory
			size_t maxRead = STR_OP_LIMIT;
			if (precision >= 0 && (size_t)precision < maxRead)
				maxRead = (size_t)precision;

			std::string strVal;
			strVal.reserve(256);
			for (size_t i = 0; i < maxRead; i++)
			{
				uint8_t byte = 0;
				if (m_memory.Read(&byte, argVal + i, 1) != 1 || byte == 0)
					break;
				strVal.push_back((char)byte);
			}

			// Format with %.*s using known length for safety
			std::string finalFmt = specFmt + ".*s";
			snprintf(specBuf, sizeof(specBuf), finalFmt.c_str(), (int)strVal.size(), strVal.c_str());
			output += specBuf;
			break;
		}
		case 'p':
		{
			snprintf(specBuf, sizeof(specBuf), "0x%llx", (unsigned long long)argVal);
			output += specBuf;
			break;
		}
		default:
			// Unsupported conversion
			output += "<unsupported:%" + std::string(1, conv) + ">";
			break;
		}

		// Check total output limit
		if (output.size() >= PRINTF_OUTPUT_LIMIT)
		{
			output.resize(PRINTF_OUTPUT_LIMIT);
			output += "[...]";
			break;
		}
	}

	return output;
}


bool LLILEmulator::StubPutchar(uint64_t)
{
	// putchar(c) — writes a single character, returns the character written
	uint64_t c = ReadArgument(0);
	char ch = (char)(c & 0xFF);

	EmitStdout(&ch, 1);

	if (m_logLibcCalls)
	{
		std::string s(1, ch);
		LogInfo("BNIL Emulator: stub putchar -> '%s'", EscapeForLog(s).c_str());
	}

	WriteReturnValue(c & 0xFF);
	return true;
}


bool LLILEmulator::StubPuts(uint64_t)
{
	// puts(s) — prints string followed by newline, returns non-negative on success
	uint64_t sPtr = ReadArgument(0);
	std::string s;
	char c;
	while (m_memory.Read(&c, sPtr + s.size(), 1) == 1 && c != '\0' && s.size() < PRINTF_OUTPUT_LIMIT)
		s += c;

	EmitStdout(s + "\n");

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub puts -> \"%s\"", EscapeForLog(s).c_str());

	WriteReturnValue(1);  // non-negative = success
	return true;
}


bool LLILEmulator::StubPrintf(uint64_t)
{
	// printf(fmt, ...)
	std::string result = FormatPrintf(0, 1);

	EmitStdout(result);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub printf -> \"%s\"", EscapeForLog(result).c_str());

	WriteReturnValue((uint64_t)result.size());
	return true;
}


bool LLILEmulator::StubSprintf(uint64_t)
{
	// sprintf(dest, fmt, ...)
	uint64_t destAddr = ReadArgument(0);
	std::string result = FormatPrintf(1, 2);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub sprintf(dest=0x%" PRIx64 ") -> \"%s\"", destAddr, EscapeForLog(result).c_str());

	// Write result + null terminator to emulated memory
	m_memory.Write(destAddr, result.data(), result.size());
	uint8_t nul = 0;
	m_memory.Write(destAddr + result.size(), &nul, 1);

	WriteReturnValue((uint64_t)result.size());
	return true;
}


bool LLILEmulator::StubSnprintf(uint64_t)
{
	// snprintf(dest, n, fmt, ...)
	uint64_t destAddr = ReadArgument(0);
	uint64_t n = ReadArgument(1);
	std::string result = FormatPrintf(2, 3);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub snprintf(dest=0x%" PRIx64 ", n=%" PRIu64 ") -> \"%s\"", destAddr, n, EscapeForLog(result).c_str());

	// Write min(len, n-1) bytes + null terminator
	if (n > 0)
	{
		size_t writeLen = result.size();
		if (writeLen >= (size_t)n)
			writeLen = (size_t)n - 1;
		if (writeLen > 0)
			m_memory.Write(destAddr, result.data(), writeLen);
		uint8_t nul = 0;
		m_memory.Write(destAddr + writeLen, &nul, 1);
	}

	// Return untruncated length (per C standard)
	WriteReturnValue((uint64_t)result.size());
	return true;
}


bool LLILEmulator::StubFprintf(uint64_t)
{
	// fprintf(stream, fmt, ...) — stream is ignored, treated as stdout
	std::string result = FormatPrintf(1, 2);

	EmitStdout(result);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub fprintf -> \"%s\"", EscapeForLog(result).c_str());

	WriteReturnValue((uint64_t)result.size());
	return true;
}


// ─── Stdin stubs ─────────────────────────────────────────────────────────────

bool LLILEmulator::StubGetchar(uint64_t)
{
	// getchar() — reads one character from stdin, returns char or EOF (-1)
	char ch;
	size_t n = RequestStdin(&ch, 1);
	if (n == 0)
	{
		if (m_logLibcCalls)
			LogInfo("BNIL Emulator: stub getchar -> EOF");
		WriteReturnValue((uint64_t)-1);  // EOF
		return true;
	}

	if (m_logLibcCalls)
	{
		std::string s(1, ch);
		LogInfo("BNIL Emulator: stub getchar -> '%s'", EscapeForLog(s).c_str());
	}

	WriteReturnValue((uint64_t)(unsigned char)ch);
	return true;
}


bool LLILEmulator::StubGets(uint64_t)
{
	// gets(buf) — reads until newline or EOF into buf (deprecated, no size limit)
	uint64_t bufAddr = ReadArgument(0);
	std::string line;
	char ch;
	bool gotAny = false;

	while (line.size() < PRINTF_OUTPUT_LIMIT)
	{
		size_t n = RequestStdin(&ch, 1);
		if (n == 0)
			break;  // EOF
		gotAny = true;
		if (ch == '\n')
			break;
		line += ch;
	}

	if (!gotAny)
	{
		if (m_logLibcCalls)
			LogInfo("BNIL Emulator: stub gets -> NULL (EOF)");
		WriteReturnValue(0);
		return true;
	}

	// Write to buffer + null terminator
	if (!line.empty())
		m_memory.Write(bufAddr, line.data(), line.size());
	uint8_t nul = 0;
	m_memory.Write(bufAddr + line.size(), &nul, 1);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub gets -> \"%s\"", EscapeForLog(line).c_str());

	WriteReturnValue(bufAddr);
	return true;
}


bool LLILEmulator::StubFgets(uint64_t)
{
	// fgets(buf, n, stream) — reads up to n-1 chars until newline or EOF
	uint64_t bufAddr = ReadArgument(0);
	uint64_t n = ReadArgument(1);
	// arg 2 (stream) is ignored — always treated as stdin

	if (n <= 1)
	{
		if (n == 1)
		{
			uint8_t nul = 0;
			m_memory.Write(bufAddr, &nul, 1);
		}
		WriteReturnValue(bufAddr);
		return true;
	}

	std::string line;
	char ch;
	size_t maxRead = (size_t)(n - 1);

	while (line.size() < maxRead)
	{
		size_t nr = RequestStdin(&ch, 1);
		if (nr == 0)
			break;  // EOF
		line += ch;
		if (ch == '\n')
			break;
	}

	if (line.empty())
	{
		// EOF with no data — return NULL
		if (m_logLibcCalls)
			LogInfo("BNIL Emulator: stub fgets -> NULL (EOF)");
		WriteReturnValue(0);
		return true;
	}

	// Write to buffer + null terminator
	m_memory.Write(bufAddr, line.data(), line.size());
	uint8_t nul = 0;
	m_memory.Write(bufAddr + line.size(), &nul, 1);

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub fgets -> \"%s\"", EscapeForLog(line).c_str());

	WriteReturnValue(bufAddr);
	return true;
}


bool LLILEmulator::StubFread(uint64_t)
{
	// fread(buf, size, count, stream) — reads size*count bytes
	uint64_t bufAddr = ReadArgument(0);
	uint64_t elemSize = ReadArgument(1);
	uint64_t elemCount = ReadArgument(2);
	// arg 3 (stream) is ignored — always treated as stdin

	size_t totalBytes = (size_t)(elemSize * elemCount);
	if (totalBytes == 0)
	{
		WriteReturnValue(0);
		return true;
	}

	// Read in chunks to avoid huge stack allocations
	size_t totalRead = 0;
	constexpr size_t CHUNK = 4096;
	char chunk[CHUNK];

	while (totalRead < totalBytes)
	{
		size_t want = std::min(CHUNK, totalBytes - totalRead);
		size_t got = RequestStdin(chunk, want);
		if (got == 0)
			break;  // EOF
		m_memory.Write(bufAddr + totalRead, chunk, got);
		totalRead += got;
		if (got < want)
			break;  // short read
	}

	size_t itemsRead = elemSize > 0 ? totalRead / (size_t)elemSize : 0;

	if (m_logLibcCalls)
		LogInfo("BNIL Emulator: stub fread(size=%" PRIu64 ", count=%" PRIu64 ") -> %zu items",
			elemSize, elemCount, itemsRead);

	WriteReturnValue((uint64_t)itemsRead);
	return true;
}


// ============================================================================
// C API — LLIL Emulator
// ============================================================================

BNLLILEmulator* BNCreateLLILEmulatorForView(BNBinaryView* view)
{
	return EMU_API_OBJECT_REF(new LLILEmulator(new BinaryView(BNNewViewReference(view))));
}


BNLLILEmulator* BNCreateLLILEmulator(BNLowLevelILFunction* il, BNBinaryView* view)
{
	return EMU_API_OBJECT_REF(new LLILEmulator(new LowLevelILFunction(BNNewLowLevelILFunctionReference(il)), new BinaryView(BNNewViewReference(view))));
}


BNLLILEmulator* BNNewLLILEmulatorReference(BNLLILEmulator* emu)
{
	return EMU_API_OBJECT_NEW_REF(emu);
}


void BNFreeLLILEmulator(BNLLILEmulator* emu)
{
	EMU_API_OBJECT_FREE(emu);
}


BNILEmulator* BNLLILEmulatorGetBase(BNLLILEmulator* emu)
{
	return emu->object->ILEmulator::GetAPIObject();
}


static void Uint512ToBytes(const intx::uint512& value, uint8_t* buf, size_t bufLen)
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


static intx::uint512 BytesToUint512(const uint8_t* buf, size_t bufLen)
{
	intx::uint512 result = 0;
	size_t n = std::min(bufLen, (size_t)64);
	for (size_t i = n; i > 0; i--)
		result = (result << 8) | buf[i - 1];
	return result;
}


void BNLLILEmulatorGetRegister(BNLLILEmulator* emu, uint32_t reg, uint8_t* outBuf, size_t bufLen)
{
	intx::uint512 value = emu->object->GetRegister(reg);
	Uint512ToBytes(value, outBuf, bufLen);
}


void BNLLILEmulatorSetRegister(BNLLILEmulator* emu, uint32_t reg, const uint8_t* buf, size_t bufLen)
{
	emu->object->SetRegister(reg, BytesToUint512(buf, bufLen));
}


void BNLLILEmulatorGetTempRegister(BNLLILEmulator* emu, uint32_t index, uint8_t* outBuf, size_t bufLen)
{
	intx::uint512 value = emu->object->GetTempRegister(index);
	Uint512ToBytes(value, outBuf, bufLen);
}


void BNLLILEmulatorSetTempRegister(BNLLILEmulator* emu, uint32_t index, const uint8_t* buf, size_t bufLen)
{
	emu->object->SetTempRegister(index, BytesToUint512(buf, bufLen));
}


size_t BNLLILEmulatorGetAllTempRegisters(
	BNLLILEmulator* emu, uint32_t* outIndices, uint8_t* outValues, size_t maxCount)
{
	auto& temps = emu->object->GetAllTempRegisters();
	if (!outIndices || !outValues)
		return temps.size();
	size_t count = 0;
	for (auto& [index, value] : temps)
	{
		if (count >= maxCount)
			break;
		outIndices[count] = index;
		Uint512ToBytes(value, outValues + count * 64, 64);
		count++;
	}
	return count;
}


uint8_t BNLLILEmulatorGetFlag(BNLLILEmulator* emu, uint32_t flag)
{
	return emu->object->GetFlag(flag);
}


void BNLLILEmulatorSetFlag(BNLLILEmulator* emu, uint32_t flag, uint8_t value)
{
	emu->object->SetFlag(flag, value);
}


void BNLLILEmulatorSetIntrinsicHook(BNLLILEmulator* emu, void* ctxt,
	bool (*callback)(void*, BNLLILEmulator*, uint32_t, const uint64_t*, size_t, uint64_t*, uint32_t*, size_t*))
{
	if (callback)
	{
		emu->object->SetIntrinsicHook(
			[ctxt, callback, emu](LLILEmulator* e, uint32_t intrinsic,
				const std::vector<uint64_t>& params,
				std::vector<std::pair<uint32_t, uint64_t>>& outputs) -> bool {
				size_t outCount = 0;
				uint64_t outValues[64];
				uint32_t outRegs[64];
				bool result = callback(ctxt, emu, intrinsic,
					params.data(), params.size(), outValues, outRegs, &outCount);
				if (result)
				{
					for (size_t i = 0; i < outCount && i < 64; i++)
						outputs.push_back({outRegs[i], outValues[i]});
				}
				return result;
			});
	}
	else
	{
		emu->object->SetIntrinsicHook(nullptr);
	}
}


bool BNLLILEmulatorSetEntryPoint(BNLLILEmulator* emu, uint64_t addr)
{
	return emu->object->SetEntryPoint(addr);
}


void BNLLILEmulatorSetEntryPointForIL(BNLLILEmulator* emu, BNLowLevelILFunction* il, size_t instrIndex)
{
	emu->object->SetEntryPoint(new LowLevelILFunction(BNNewLowLevelILFunctionReference(il)), instrIndex);
}


void BNLLILEmulatorSetArgument(BNLLILEmulator* emu, size_t index, const uint8_t* buf, size_t bufLen)
{
	emu->object->SetArgument(index, BytesToUint512(buf, bufLen));
}


void BNLLILEmulatorSetArguments(BNLLILEmulator* emu, const uint64_t* values, size_t count)
{
	std::vector<uint64_t> v(values, values + count);
	emu->object->SetArguments(v);
}


size_t BNLLILEmulatorGetCallStackDepth(BNLLILEmulator* emu)
{
	return emu->object->GetCallStackDepth();
}


BNILEmulatorStopReason BNLLILEmulatorStepOver(BNLLILEmulator* emu)
{
	return (BNILEmulatorStopReason)emu->object->StepOver();
}


void BNLLILEmulatorSetBuiltinLibcStubsEnabled(BNLLILEmulator* emu, bool enabled)
{
	emu->object->SetBuiltinLibcStubsEnabled(enabled);
}


bool BNLLILEmulatorIsBuiltinLibcStubsEnabled(BNLLILEmulator* emu)
{
	return emu->object->IsBuiltinLibcStubsEnabled();
}


void BNLLILEmulatorSetLogLibcCalls(BNLLILEmulator* emu, bool enabled)
{
	emu->object->SetLogLibcCalls(enabled);
}


bool BNLLILEmulatorIsLogLibcCalls(BNLLILEmulator* emu)
{
	return emu->object->IsLogLibcCalls();
}


void BNLLILEmulatorSetNopUnknownExternals(BNLLILEmulator* emu, bool enabled)
{
	emu->object->SetNopUnknownExternals(enabled);
}


bool BNLLILEmulatorIsNopUnknownExternals(BNLLILEmulator* emu)
{
	return emu->object->IsNopUnknownExternals();
}


BNEmulatorCallStackEntry* BNLLILEmulatorGetCallStack(BNLLILEmulator* emu, size_t* count)
{
	auto frames = emu->object->GetCallStack();
	*count = frames.size();
	if (frames.empty())
		return nullptr;

	auto* result = new BNEmulatorCallStackEntry[frames.size()];
	for (size_t i = 0; i < frames.size(); i++)
	{
		result[i].functionAddress = frames[i].functionAddress;
		result[i].returnAddress = frames[i].returnAddress;
	}
	return result;
}


void BNLLILEmulatorFreeCallStack(BNEmulatorCallStackEntry* entries)
{
	delete[] entries;
}


char* BNLLILEmulatorSaveState(BNLLILEmulator* emu)
{
	auto json = emu->object->SaveState();
	return BNAllocString(json.c_str());
}


bool BNLLILEmulatorLoadState(BNLLILEmulator* emu, const char* json)
{
	return emu->object->LoadState(json, emu->object->GetView());
}
