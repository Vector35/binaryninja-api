#include "ilsourcelocation.hpp"
#include "lowlevelil.h"

ILSourceLocation::ILSourceLocation()
	: valid(false)
{}

ILSourceLocation::ILSourceLocation(uint64_t addr, uint32_t operand)
	: address(addr), sourceOperand(operand), valid(true)
{}

ILSourceLocation::ILSourceLocation(const BNLowLevelILInstruction& instr)
	: address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
{}

ILSourceLocation::ILSourceLocation(const BNMediumLevelILInstruction& instr)
	: address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
{}

ILSourceLocation::ILSourceLocation(const BNHighLevelILInstruction& instr)
	: address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
{}
