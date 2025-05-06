
#pragma once

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "llil_lift_check.h"

class LiftedILVerifier : public LowLevelILVerifier
{
	size_t GetTreePopCount(const BinaryNinja::LowLevelILInstruction& expr);
	size_t GetTreeFlagWriteCount(const BinaryNinja::LowLevelILInstruction& expr);

public:
	explicit LiftedILVerifier(BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> function);
	virtual void Verify() override;
};
