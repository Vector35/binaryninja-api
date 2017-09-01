#define _CRT_SECURE_NO_WARNINGS
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "binaryninjaapi.h"
#include "asmx86/asmx86.h"

using namespace BinaryNinja;
using namespace std;
using namespace asmx86;


#define IL_FLAG_C 0
#define IL_FLAG_P 2
#define IL_FLAG_A 4
#define IL_FLAG_Z 6
#define IL_FLAG_S 7
#define IL_FLAG_D 10
#define IL_FLAG_O 11

#define IL_FLAGWRITE_ALL     1
#define IL_FLAGWRITE_NOCARRY 2
#define IL_FLAGWRITE_CO      3

#define REG_FSBASE 0x100
#define REG_GSBASE 0x101

#define TRAP_DIV       0
#define TRAP_ICEBP     1
#define TRAP_NMI       2
#define TRAP_BP        3
#define TRAP_OVERFLOW  4
#define TRAP_BOUND     5
#define TRAP_ILL       6
#define TRAP_NOT_AVAIL 7
#define TRAP_DOUBLE    8
#define TRAP_TSS       10
#define TRAP_NO_SEG    11
#define TRAP_STACK     12
#define TRAP_GPF       13
#define TRAP_PAGE      14
#define TRAP_FPU       16
#define TRAP_ALIGN     17
#define TRAP_MCE       18
#define TRAP_SIMD      19

static uint8_t GetShiftCountForScale(uint8_t scale)
{
	switch (scale)
	{
	case 2:
		return 1;
	case 4:
		return 2;
	case 8:
		return 3;
	default:
		return 0;
	}
}


static uint32_t GetStackPointer(size_t addrSize)
{
	switch (addrSize)
	{
	case 2:
		return REG_SP;
	case 4:
		return REG_ESP;
	default:
		return REG_RSP;
	}
}


static uint32_t GetFramePointer(size_t addrSize)
{
	switch (addrSize)
	{
	case 2:
		return REG_BP;
	case 4:
		return REG_EBP;
	default:
		return REG_RBP;
	}
}


static uint32_t GetCountRegister(size_t addrSize)
{
	switch (addrSize)
	{
	case 2:
		return REG_CX;
	case 4:
		return REG_ECX;
	default:
		return REG_RCX;
	}
}


static size_t GetILOperandMemoryAddress(LowLevelILFunction& il, InstructionOperand& operand, size_t i, size_t addrSize)
{
	size_t offset;
	if (operand.operand != MEM)
		offset = il.Operand(i, il.Undefined());
	else if ((operand.components[0] == NONE) && (operand.components[1] == NONE) && operand.relative)
		offset = il.Operand(i, il.ConstPointer(addrSize, operand.immediate));
	else if ((operand.components[0] == NONE) && (operand.components[1] == NONE))
		offset = il.Operand(i, il.Const(addrSize, operand.immediate));
	else if ((operand.components[1] == NONE) && (operand.immediate == 0))
		offset = il.Operand(i, il.Register(addrSize, operand.components[0]));
	else if (operand.components[1] == NONE)
	{
		offset = il.Operand(i, il.Add(addrSize, il.Register(addrSize, operand.components[0]),
			il.Const(addrSize, operand.immediate)));
	}
	else if ((operand.components[0] == NONE) && (operand.scale == 1) && (operand.immediate == 0))
		offset = il.Operand(i, il.Register(addrSize, operand.components[1]));
	else if ((operand.components[0] == NONE) && (operand.scale == 1))
	{
		offset = il.Operand(i, il.Add(addrSize, il.Register(addrSize, operand.components[1]),
			il.Const(addrSize, operand.immediate)));
	}
	else if ((operand.components[0] == NONE) && (operand.immediate == 0))
	{
		offset = il.Operand(i, il.ShiftLeft(addrSize, il.Register(addrSize, operand.components[1]),
			il.Const(1, GetShiftCountForScale(operand.scale))));
	}
	else if (operand.components[0] == NONE)
	{
		offset = il.Operand(i, il.Add(addrSize, il.ShiftLeft(addrSize, il.Register(addrSize, operand.components[1]),
			il.Const(1, GetShiftCountForScale(operand.scale))), il.Const(addrSize, operand.immediate)));
	}
	else if ((operand.scale == 1) && (operand.immediate == 0))
	{
		offset = il.Operand(i, il.Add(addrSize, il.Register(addrSize, operand.components[0]),
			il.Register(addrSize, operand.components[1])));
	}
	else if (operand.scale == 1)
	{
		offset = il.Operand(i, il.Add(addrSize, il.Add(addrSize, il.Register(addrSize, operand.components[0]),
			il.Register(addrSize, operand.components[1])), il.Const(addrSize, operand.immediate)));
	}
	else if (operand.immediate == 0)
	{
		offset = il.Operand(i, il.Add(addrSize, il.Register(addrSize, operand.components[0]),
			il.ShiftLeft(addrSize, il.Register(addrSize, operand.components[1]),
			il.Const(1, GetShiftCountForScale(operand.scale)))));
	}
	else
	{
		offset = il.Operand(i, il.Add(addrSize, il.Add(addrSize, il.Register(addrSize, operand.components[0]),
			il.ShiftLeft(addrSize, il.Register(addrSize, operand.components[1]),
			il.Const(1, GetShiftCountForScale(operand.scale)))), il.Const(addrSize, operand.immediate)));
	}

	if (operand.segment == SEG_FS)
		return il.Operand(i, il.Add(addrSize, il.Register(addrSize, REG_FSBASE), offset));
	if (operand.segment == SEG_GS)
		return il.Operand(i, il.Add(addrSize, il.Register(addrSize, REG_GSBASE), offset));
	return offset;
}


static size_t ReadILOperand(LowLevelILFunction& il, Instruction& instr, size_t i, size_t addrSize, bool isAddress = false)
{
	InstructionOperand& operand = instr.operands[i];
	switch (operand.operand)
	{
	case NONE:
		return il.Undefined();
	case IMM:
		if (isAddress)
			return il.Operand(i, il.ConstPointer(operand.size, operand.immediate));
		else
			return il.Operand(i, il.Const(operand.size, operand.immediate));
	case MEM:
		return il.Operand(i, il.Load(operand.size, GetILOperandMemoryAddress(il, operand, i, addrSize)));
	default:
		return il.Operand(i, il.Register(operand.size, operand.operand));
	}
}


static size_t WriteILOperand(LowLevelILFunction& il, Instruction& instr, size_t i, size_t addrSize, size_t value)
{
	InstructionOperand& operand = instr.operands[i];
	switch (operand.operand)
	{
	case NONE:
	case IMM:
		return il.Undefined();
	case MEM:
		return il.Operand(i, il.Store(operand.size, GetILOperandMemoryAddress(il, operand, i, addrSize), value));
	default:
		return il.Operand(i, il.SetRegister(operand.size, operand.operand, value));
	}
}


static size_t DirectJump(Architecture* arch, LowLevelILFunction& il, uint64_t target, size_t addrSize)
{
	BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);
	if (label)
		return il.Goto(*label);
	else
		return il.Jump(il.ConstPointer(addrSize, target));
}


static void ConditionalJump(Architecture* arch, LowLevelILFunction& il, size_t cond, size_t addrSize, uint64_t t, uint64_t f)
{
	BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
	BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);

	if (trueLabel && falseLabel)
	{
		il.AddInstruction(il.If(cond, *trueLabel, *falseLabel));
		return;
	}

	LowLevelILLabel trueCode, falseCode;

	if (trueLabel)
	{
		il.AddInstruction(il.If(cond, *trueLabel, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
		return;
	}

	if (falseLabel)
	{
		il.AddInstruction(il.If(cond, trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
		return;
	}

	il.AddInstruction(il.If(cond, trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
	il.MarkLabel(falseCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
}


static void DirFlagIf(size_t addrSize,
	LowLevelILFunction& il,
	std::function<void (size_t addrSize, LowLevelILFunction& il)> addPreTestIl,
	std::function<void (size_t addrSize, LowLevelILFunction& il)> addDirFlagSetIl,
	std::function<void (size_t addrSize, LowLevelILFunction& il)> addDirFlagClearIl)
{
	LowLevelILLabel dirFlagSet, dirFlagClear, dirFlagDone;

	addPreTestIl(addrSize, il);

	il.AddInstruction(il.If(il.Flag(IL_FLAG_D), dirFlagSet, dirFlagClear));
	il.MarkLabel(dirFlagSet);

	addDirFlagSetIl(addrSize, il);

	il.AddInstruction(il.Goto(dirFlagDone));
	il.MarkLabel(dirFlagClear);

	addDirFlagClearIl(addrSize, il);

	il.AddInstruction(il.Goto(dirFlagDone));
	il.MarkLabel(dirFlagDone);
}


static void Repeat(size_t addrSize,
	Instruction& instr,
	LowLevelILFunction& il,
	std::function<void (size_t addrSize, LowLevelILFunction& il)> addil)
{
	LowLevelILLabel trueLabel, falseLabel, doneLabel;
	if (instr.flags & X86_FLAG_ANY_REP)
	{
		il.AddInstruction(il.Goto(trueLabel));
		il.MarkLabel(trueLabel);
		il.AddInstruction(il.If(il.CompareEqual(addrSize, il.Register(addrSize, GetCountRegister(addrSize)),
												il.Const(addrSize, 0)), doneLabel, falseLabel));
		il.MarkLabel(falseLabel);
	}

	addil(addrSize, il);

	if (instr.flags & X86_FLAG_ANY_REP)
	{
		il.AddInstruction(il.SetRegister(addrSize, GetCountRegister(addrSize),
											il.Sub(addrSize, il.Register(addrSize, GetCountRegister(addrSize)),
												il.Const(addrSize, 1))));
		if (instr.flags & X86_FLAG_REPE)
			il.AddInstruction(il.If(il.FlagCondition(LLFC_E), trueLabel, doneLabel));
		else if (instr.flags & X86_FLAG_REPNE)
			il.AddInstruction(il.If(il.FlagCondition(LLFC_NE), trueLabel, doneLabel));
		else
			il.AddInstruction(il.Goto(trueLabel));
		il.MarkLabel(doneLabel);
	}
}

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
