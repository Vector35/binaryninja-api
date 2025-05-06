
#pragma once

#include "binaryninjaapi.h"
#include "lift_check.h"
#include "lowlevelilinstruction.h"

class LowLevelILVerifier: public ILVerifier
{
protected:
	BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> m_il;
	BinaryNinja::Ref<BinaryNinja::Architecture> m_arch;

	struct TempRegisterInfo
	{
		size_t reg;
		size_t width;
		size_t seenExpr;
	};

	std::unordered_map<size_t, TempRegisterInfo> m_tempRegSizes;

	LowLevelILVerifier(BNFunctionGraphType graphType, BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> function);

	void CheckExprSize(const BinaryNinja::LowLevelILInstruction& expr, std::optional<size_t> requiredSize);
	void CheckInstrSize(const BinaryNinja::LowLevelILInstruction& instr);

	void CheckExprOperands(const BinaryNinja::LowLevelILInstruction& expr);

public:
	explicit LowLevelILVerifier(BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> function);
	void Verify() override;
};

