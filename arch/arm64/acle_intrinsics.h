#pragma once

#include "binaryninjaapi.h"
#include "system_operations.h"

#include "exarmo/aarch64.h"

#include <string>
#include <string_view>
#include <vector>

// Lift instructions to the intrinsics Arm's C Language Extensions (ACLE) define. exarmo supplies
// each intrinsic's name and types, which intrinsic an instruction implements, and which operand
// supplies each argument.

constexpr uint32_t AcleIntrinsicBase = SysOpIntrinsicEnd;
constexpr uint32_t AcleIntrinsicEnd = AcleIntrinsicBase + EXARMO_AARCH64_INTRINSIC_COUNT;

inline bool IsAcleIntrinsic(uint32_t intrinsic)
{
	return intrinsic >= AcleIntrinsicBase && intrinsic < AcleIntrinsicEnd;
}

std::string AcleIntrinsicName(uint32_t intrinsic);
std::vector<BinaryNinja::NameAndType> AcleIntrinsicInputs(uint32_t intrinsic);
std::vector<BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>>> AcleIntrinsicOutputs(
    uint32_t intrinsic);

// Look up an ACLE intrinsic by name, for an instruction exarmo maps to none. Returns
// ARM64_INTRIN_INVALID if no intrinsic has the name.
uint32_t AcleIntrinsicNamed(std::string_view name);

// Lift the instruction as the intrinsic it implements, where exarmo names one. False where it
// names none, leaving the caller to lift the instruction itself.
bool AcleGetLowLevelILForInstruction(BinaryNinja::LowLevelILFunction& il,
    const exarmo_aarch64_instruction& instr, exarmo_aarch64_operand* operands);
