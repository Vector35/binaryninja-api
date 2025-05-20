
#pragma once

#include "binaryninjaapi.h"
#include "lift_check.h"
#include "mediumlevelilinstruction.h"

class MediumLevelILVerifier: public ILVerifier
{
protected:
	BinaryNinja::Ref<BinaryNinja::MediumLevelILFunction> m_il;
	BinaryNinja::Ref<BinaryNinja::Architecture> m_arch;

	MediumLevelILVerifier(BNFunctionGraphType graphType, BinaryNinja::Ref<BinaryNinja::MediumLevelILFunction> function);

	void CheckExprSize(const BinaryNinja::MediumLevelILInstruction& expr, std::optional<size_t> requiredSize);
	void CheckInstrSize(const BinaryNinja::MediumLevelILInstruction& instr);

	void CheckExprOperands(const BinaryNinja::MediumLevelILInstruction& expr);

public:
	explicit MediumLevelILVerifier(BinaryNinja::Ref<BinaryNinja::MediumLevelILFunction> function);
	void Verify() override;
};

