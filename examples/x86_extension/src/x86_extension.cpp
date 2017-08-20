#define _CRT_SECURE_NO_WARNINGS
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "binaryninjaapi.h"
#include "asmx86/asmx86.h"

using namespace BinaryNinja;
using namespace std;
using namespace asmx86;

// This is a wrapper for the x86 architecture. Its useful for extending and improving
// the existing core x86 architecture.
class x86ArchitectureExtension: public Architecture
{
	Architecture* m_arch;
public:
	x86ArchitectureExtension() : Architecture("x86_extension")
	{
		m_arch = new CoreArchitecture(BNGetArchitectureByName("x86"));
	}

	virtual size_t GetAddressSize() const override
	{
		return 4;
	}

	virtual BNEndianness GetEndianness() const override
	{
		return LittleEndian;
	}

	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override
	{
		return m_arch->GetInstructionInfo(data, addr, maxLen, result);
	}

	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
		return m_arch->GetInstructionText(data, addr, len, result);
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		Instruction instr;
		if (!asmx86::Disassemble32(data, addr, len, &instr))
		{
			il.AddInstruction(il.Undefined());
			return false;
		}
		if (instr.operation == CPUID)
		{
			// The default implementation of CPUID doesn't set registers to constant values
			// Here we'll emulate a Intel(R) Core(TM) i5-6267U CPU @ 2.90GHz with _eax set to 1
			il.AddInstruction(il.Register(4, REG_EAX)); // Reference the register so we know it is read
			il.AddInstruction(il.SetRegister(4, REG_EAX, il.Const(4, 0x000406e3)));
			il.AddInstruction(il.SetRegister(4, REG_EBX, il.Const(4, 0x03100800)));
			il.AddInstruction(il.SetRegister(4, REG_ECX, il.Const(4, 0x7ffafbbf)));
			il.AddInstruction(il.SetRegister(4, REG_EDX, il.Const(4, 0xbfebfbff)));
			len = instr.length;
			return true;
		}
		return m_arch->GetInstructionLowLevelIL(data, addr, len, il);
	}

	virtual size_t GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override
	{
		return m_arch->GetFlagWriteLowLevelIL(op,size, flagWriteType, flag, operands, operandCount, il);
	}

	virtual string GetRegisterName(uint32_t reg) override
	{
		return m_arch->GetRegisterName(reg);
	}

	virtual string GetFlagName(uint32_t flag) override
	{
		return m_arch->GetFlagName(flag);
	}

	virtual vector<uint32_t> GetAllFlags() override
	{
		return m_arch->GetAllFlags();
	}

	virtual string GetFlagWriteTypeName(uint32_t flags) override
	{
		return m_arch->GetFlagWriteTypeName(flags);
	}

	virtual vector<uint32_t> GetAllFlagWriteTypes() override
	{
		return m_arch->GetAllFlagWriteTypes();
	}

	virtual BNFlagRole GetFlagRole(uint32_t flag) override
	{
		return m_arch->GetFlagRole(flag);
	}

	virtual vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond) override
	{
		return m_arch->GetFlagsRequiredForFlagCondition(cond);
	}

	virtual vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override
	{
		return m_arch->GetFlagsWrittenByFlagWriteType(writeType);
	}

	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		return m_arch->IsNeverBranchPatchAvailable(data, addr, len);
	}

	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		return m_arch->IsAlwaysBranchPatchAvailable(data, addr, len);
	}

	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		return m_arch->IsInvertBranchPatchAvailable(data, addr, len);
	}

	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		return m_arch->IsSkipAndReturnZeroPatchAvailable(data, addr, len);
	}

	virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		return m_arch->IsSkipAndReturnValuePatchAvailable(data, addr, len);
	}

	virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len) override
	{
		return m_arch->ConvertToNop(data, addr, len);
	}

	virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		return m_arch->AlwaysBranch(data, addr, len);
	}

	virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		return m_arch->InvertBranch(data, addr, len);
	}

	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override
	{
		return m_arch->SkipAndReturnValue(data, addr, len, value);
	}

	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
		return m_arch->GetFullWidthRegisters();
	}

	virtual vector<uint32_t> GetGlobalRegisters() override
	{
		return m_arch->GetGlobalRegisters();
	}

	virtual vector<uint32_t> GetAllRegisters() override
	{
		return m_arch->GetAllRegisters();
	}

	virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override
	{
		return m_arch->GetRegisterInfo(reg);
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		return m_arch->GetStackPointerRegister();
	}

	virtual bool Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors) override
	{
		return m_arch->Assemble(code, addr, result, errors);
	}
};


extern "C"
{
	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		Architecture* x86ext = new x86ArchitectureExtension();
		Architecture::Register(x86ext);

		// Register the architectures with the binary format parsers so that they know when to use
		// these architectures for disassembling an executable file
		BinaryViewType::RegisterArchitecture("ELF", 3, LittleEndian, x86ext);
		BinaryViewType::RegisterArchitecture("PE", 0x14c, LittleEndian, x86ext);
		BinaryViewType::RegisterArchitecture("Mach-O", 0x00000007, LittleEndian, x86ext);
		x86ext->SetBinaryViewTypeConstant("ELF", "R_COPY", 5);
		x86ext->SetBinaryViewTypeConstant("ELF", "R_JUMP_SLOT", 7);
		return true;
	}
}
