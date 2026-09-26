#pragma once

#include "binaryninjaapi.h"
#include "il.h"

#include "exarmo/aarch64.h"

#include <stdint.h>
#include <string>
#include <vector>

// AT, DC, IC, TLBI and similar instructions are SYS aliases that select an operation from a
// per-instruction table. Their intrinsic names come from exarmo's table.

// Each instruction gets two intrinsics, one taking only the operation and one also taking the
// register. An intrinsic's argument list is fixed, but whether an operation takes a register varies.
constexpr uint32_t SysOpIntrinsicsPerInstruction = 2;
constexpr uint32_t SysOpIntrinsicBase = ARM64_INTRIN_NORMAL_END;
constexpr uint32_t SysOpIntrinsicCount =
    EXARMO_AARCH64_SYSOP_INSTRUCTION_COUNT * SysOpIntrinsicsPerInstruction;
constexpr uint32_t SysOpIntrinsicEnd = SysOpIntrinsicBase + SysOpIntrinsicCount;

inline bool IsSysOpIntrinsic(uint32_t intrinsic)
{
	return intrinsic >= SysOpIntrinsicBase && intrinsic < SysOpIntrinsicEnd;
}

// The intrinsic an instruction lifts to, with or without the register. Returns
// ARM64_INTRIN_INVALID for an instruction not in exarmo's system operation table.
uint32_t SysOpIntrinsic(exarmo_aarch64_mnemonic instruction, bool withRegister);

// The system operation intrinsics that some lift can produce, in id order. A variant that no
// operation of its instruction can reach is left out.
const std::vector<uint32_t>& SysOpLiftedIntrinsics();

// The instruction's mnemonic prefixed with `__`.
std::string SysOpIntrinsicName(uint32_t intrinsic);

// The operation, followed by the source register for an intrinsic that takes one. The register is
// as wide as the transfer, which is 128 bits for TLBIP.
std::vector<BinaryNinja::NameAndType> SysOpIntrinsicInputs(
    BinaryNinja::Architecture* arch, uint32_t intrinsic);

// The destination register, for an intrinsic whose instruction writes one, as GICR does. Empty
// otherwise.
std::vector<BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>>> SysOpIntrinsicOutputs(
    uint32_t intrinsic);

// The operations of one instruction, as an enumeration a lifted intrinsic takes. Each member's
// value is the operation's op1:CRn:CRm:op2 encoding.
BinaryNinja::Ref<BinaryNinja::Enumeration> SystemOperationEnumeration(
    exarmo_aarch64_mnemonic instruction);

// The PSTATE fields MSR (immediate) sets, as an enumeration valued by each field's encoding.
BinaryNinja::Ref<BinaryNinja::Enumeration> PstateFieldEnumeration();

// Find the operation SYS encodes with these fields. Returns false if none matches. TLBI and TLBIP
// share 240 encodings at CRn 8 and 9, so `out.instruction` may name either. Rely only on its name
// and encoding.
bool SystemOperationAt(
    uint32_t op1, uint32_t crn, uint32_t crm, uint32_t op2, exarmo_aarch64_sysop_def& out);

// The encoding of the system operation or PSTATE field an operand names, matching the values of
// SystemOperationEnumeration and PstateFieldEnumeration. Zero for any other operand. The operand's
// own field can't be used because its layout differs between instructions and, for PSTATE fields,
// includes MSR's immediate.
uint32_t SystemOperationNumber(const exarmo_aarch64_operand& operand);
