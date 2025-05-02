
#pragma once

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

class LowLevelILVerifier
{
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
	BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> m_il;
	BinaryNinja::Ref<BinaryNinja::Architecture> m_arch;

	bool CheckExprSize(const BinaryNinja::LowLevelILInstruction& expr, std::optional<size_t> requiredSize);
	bool CheckInstrSize(const BinaryNinja::LowLevelILInstruction& instr);

	bool CheckExprOperands(const BinaryNinja::LowLevelILInstruction& expr);

public:
	LowLevelILVerifier(BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> function);
	bool Verify();
};
