// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#ifndef ARCHITECTURE_H
#define ARCHITECTURE_H

#include <binaryninjaapi.h>

namespace BN = BinaryNinja;

namespace C166 {
class C166Architecture : public BN::Architecture {
 protected:
  static BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset,
                                     size_t size, bool zeroExtend = false);

 public:
  explicit C166Architecture(const std::string& name);
  [[nodiscard]] size_t GetAddressSize() const override;
  [[nodiscard]] size_t GetDefaultIntegerSize() const override;
  [[nodiscard]] BNEndianness GetEndianness() const override;
  [[nodiscard]] size_t GetMaxInstructionLength() const override;
  [[nodiscard]] size_t GetInstructionAlignment() const override;
  std::vector<uint32_t> GetAllRegisters() override;
  std::vector<uint32_t> GetFullWidthRegisters() override;
  std::vector<uint32_t> GetGlobalRegisters() override;
  BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
  std::string GetRegisterName(uint32_t reg) override;
  std::vector<uint32_t> GetAllFlags() override;
  std::string GetFlagName(uint32_t flag) override;
  std::vector<uint32_t> GetAllFlagWriteTypes() override;
  BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass) override;
  std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t flags) override;
  std::string GetFlagWriteTypeName(uint32_t flags) override;
  std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
      BNLowLevelILFlagCondition cond, uint32_t semClass) override;

  bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen,
                          BN::InstructionInfo& result) override;
  bool GetInstructionText(
      const uint8_t* data, uint64_t addr, size_t& len,
      std::vector<BN::InstructionTextToken>& result) override;
  bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len,
                                BN::LowLevelILFunction& il) override;

  uint32_t GetStackPointerRegister() override = 0;
};
}  // namespace C166

#endif  // ARCHITECTURE_H
