// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#include <binaryninjaapi.h>

#include <cstdint>

#include "conditions.h"
#include "instructions.h"
#include "util.h"

namespace BN = BinaryNinja;

namespace C166 {
bool Calla::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
                 BN::InstructionInfo& result) {
  const auto code = GetConditionCode(data, length);
  const auto target = GetTarget(data, addr, length);

  if (code == Conditions::CC_UC)
    result.AddBranch(CallDestination, target);
  else {
    result.AddBranch(
        TrueBranch,
        target);  // TODO: Figure out how to model as CallDestination
    result.AddBranch(FalseBranch, addr + length);
  }

  result.length = length;
  return true;
}

bool Calli::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
                 BN::InstructionInfo& result) {
  if (const auto code = GetConditionCode(data, length);
      code == Conditions::CC_UC)
    result.AddBranch(UnresolvedBranch);
  else {
    BN::LogDebug("[I] 0x%lx: Unhandled CALLI variant", addr);
    return false;
  }

  result.length = length;
  return true;
}

bool Callr::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
                 BN::InstructionInfo& result) {
  result.AddBranch(CallDestination, GetTarget(data, addr, length));
  result.length = length;
  return true;
}

bool Calls::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
                 BN::InstructionInfo& result) {
  result.AddBranch(CallDestination, GetTarget(data, length));
  result.length = length;
  return true;
}

bool Jb::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
              BN::InstructionInfo& result) {
  const auto target = GetTarget(data, addr, length);

  result.AddBranch(TrueBranch, target);
  result.AddBranch(FalseBranch, addr + length);

  result.length = length;
  return true;
}

bool Jbc::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
               BN::InstructionInfo& result) {
  const auto target = GetTarget(data, addr, length);

  result.AddBranch(TrueBranch, target);
  result.AddBranch(FalseBranch, addr + length);

  result.length = length;
  return true;
}

bool Jmpa::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
                BN::InstructionInfo& result) {
  const auto code = GetConditionCode(data, length);
  const auto target = GetTarget(data, addr, length);

  if (code == Conditions::CC_UC)
    result.AddBranch(UnconditionalBranch, target);
  else {
    result.AddBranch(TrueBranch, target);
    result.AddBranch(FalseBranch, addr + length);
  }

  result.length = length;
  return true;
}

bool Jmpi::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
                BN::InstructionInfo& result) {
  if (const auto code = Instruction::GetData4High(data, length);
      code == Conditions::CC_UC)
    result.AddBranch(UnresolvedBranch);
  else {
    BN::LogDebug("0x%lx: Jmpi::%s -- unhandled conditional code", addr,
                 __func__);
    return false;
  }

  result.length = length;
  return true;
}

bool Jmpr::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
                BN::InstructionInfo& result) {
  const auto target = GetTarget(data, addr, length);

  if (GetConditionCode(data, length) == Conditions::CC_UC)
    result.AddBranch(UnconditionalBranch, target);
  else {
    result.AddBranch(TrueBranch, target);
    result.AddBranch(FalseBranch, addr + length);
  }

  result.length = length;
  return true;
}

bool Jmps::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
                BN::InstructionInfo& result) {
  const auto target = GetTarget(data, length);
  result.AddBranch(UnconditionalBranch, target);
  result.length = length;
  return true;
}

bool Jnb::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
               BN::InstructionInfo& result) {
  const auto target = GetTarget(data, addr, length);

  result.AddBranch(TrueBranch, target);
  result.AddBranch(FalseBranch, addr + length);

  result.length = length;
  return true;
}

bool Jnbs::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
                BN::InstructionInfo& result) {
  const auto target = GetTarget(data, addr, length);

  result.AddBranch(TrueBranch, target);
  result.AddBranch(FalseBranch, addr + length);

  result.length = length;
  return true;
}

bool Trap::Info(const uint8_t* data, const uint64_t addr, const size_t maxLen,
                BN::InstructionInfo& result) {
  result.AddBranch(CallDestination, GetTarget(data, addr));
  result.length = length;
  return true;
}
}  // namespace C166
