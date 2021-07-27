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
class x86ArchitectureExtension: public ArchitectureHook
{
public:
	x86ArchitectureExtension(Architecture* x86) : ArchitectureHook(x86)
	{
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LiftingContext& context, LowLevelILFunction& il) override
	{
		Instruction instr;
		if (asmx86::Disassemble32(data, addr, len, &instr))
		{
			switch (instr.operation)
			{
			case CPUID:
				// The default implementation of CPUID doesn't set registers to constant values
				// Here we'll emulate a Intel(R) Core(TM) i5-6267U CPU @ 2.90GHz with _eax set to 1
				il.AddInstruction(il.Register(4, REG_EAX)); // Reference the register so we know it is read
				il.AddInstruction(il.SetRegister(4, REG_EAX, il.Const(4, 0x000406e3)));
				il.AddInstruction(il.SetRegister(4, REG_EBX, il.Const(4, 0x03100800)));
				il.AddInstruction(il.SetRegister(4, REG_ECX, il.Const(4, 0x7ffafbbf)));
				il.AddInstruction(il.SetRegister(4, REG_EDX, il.Const(4, 0xbfebfbff)));
				len = instr.length;
				return true;
			default:
				break;
			}
		}
		return ArchitectureHook::GetInstructionLowLevelIL(data, addr, len, context, il);
	}
};


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		// Make sure we load after the original x86 plugin loads
		AddRequiredPluginDependency("arch_x86");
	}

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		Architecture* x86ext = new x86ArchitectureExtension(Architecture::GetByName("x86"));
		Architecture::Register(x86ext);
		return true;
	}
}
