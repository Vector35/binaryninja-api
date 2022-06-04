#pragma once

namespace BinaryNinja {
	struct BNLowLevelILInstruction;
	struct BNMediumLevelILInstruction;
	struct BNHighLevelILInstruction;
	struct ILSourceLocation
	{
		uint64_t address;
		uint32_t sourceOperand;
		bool valid;

		ILSourceLocation() : valid(false) {}

		ILSourceLocation(uint64_t addr, uint32_t operand) : address(addr), sourceOperand(operand), valid(true) {}

		ILSourceLocation(const BNLowLevelILInstruction& instr) :
			address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{}

		ILSourceLocation(const BNMediumLevelILInstruction& instr) :
			address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{}

		ILSourceLocation(const BNHighLevelILInstruction& instr) :
			address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{}
	};
}