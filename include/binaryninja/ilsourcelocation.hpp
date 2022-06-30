#pragma once

#include "binaryninjacore/lowlevelil.h"
#include "binaryninjacore/mediumlevelil.h"
#include "binaryninjacore/highlevelil.h"

struct BNLowLevelILInstruction;
struct BNMediumLevelILInstruction;
struct BNHighLevelILInstruction;

namespace BinaryNinja {
	struct ILSourceLocation
	{
		uint64_t address;
		uint32_t sourceOperand;
		bool valid;

		ILSourceLocation();
		ILSourceLocation(uint64_t addr, uint32_t operand);
		ILSourceLocation(const BNLowLevelILInstruction& instr);
		ILSourceLocation(const BNMediumLevelILInstruction& instr);
		ILSourceLocation(const BNHighLevelILInstruction& instr);
	};
}