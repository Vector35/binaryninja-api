
#pragma once

#include "binaryninjaapi.h"
#include "lift_check.h"
#include "lowlevelilinstruction.h"

class LowLevelILVerifier: public ILVerifier
{
protected:
	BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> m_il;
	BinaryNinja::Ref<BinaryNinja::Architecture> m_arch;

	LowLevelILVerifier(BNFunctionGraphType graphType, BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> function);

	bool GetTemporaryRegisterSize(const BinaryNinja::LowLevelILInstruction& expr, uint32_t reg, size_t& outSize);

	void CheckExprSize(const BinaryNinja::LowLevelILInstruction& expr, std::optional<size_t> requiredSize);
	void CheckInstrSize(const BinaryNinja::LowLevelILInstruction& instr);

	void CheckExprOperands(const BinaryNinja::LowLevelILInstruction& expr);

public:
	explicit LowLevelILVerifier(BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> function);
	void Verify() override;
};

