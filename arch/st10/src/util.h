// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#ifndef SRC_UTIL_H_
#define SRC_UTIL_H_

#include <binaryninjaapi.h>

#include <cstdint>
#include <string>
#include <vector>

namespace BN = BinaryNinja;

namespace C166 {

enum ExtState {
  ExtNone = 0x0,
  ExtRegister = 0x1,
  ExtSegment = 0x2,
  ExtPage = 0x4,
  ExtAtomic = 0x8,
};

class InstructionState {
 public:
  uint8_t ext_state;
  uint8_t num_insns;
  uint32_t pag10;
  uint32_t seg8;

  InstructionState();
};

class Instruction {
  static uint32_t GetBitoffRamAddress(uint8_t value);
  static uint32_t GetBitoffSfrAddress(uint8_t value, bool extr);
  static uint32_t GetRegSfrAddress(uint8_t value, bool extr);
  static bool GetConstantRegister(uint32_t mem, uint16_t &value);
  static uint32_t TranslateSfrRegister(uint32_t reg);
  static const char *GetSfrRegisterName(uint32_t reg);

 public:
  // Indirect Addressing Expressions (using EXTS)
  static BN::ExprId GetIndAddrExpr_Exts_Rw(BN::LowLevelILFunction &il,
                                           uint32_t seg8, uint32_t Rw);
  static BN::ExprId GetIndAddrExpr_Exts_Rw_data16(BN::LowLevelILFunction &il,
                                                  uint32_t seg8, uint32_t Rw,
                                                  uint16_t data16);
  // Indirect Addressing Expressions (using EXTP)
  static BN::ExprId GetIndAddrExpr_Extp_Rw(BN::LowLevelILFunction &il,
                                           uint32_t pag10, uint32_t Rw);
  static BN::ExprId GetIndAddrExpr_Extp_Rw_data16(BN::LowLevelILFunction &il,
                                                  uint32_t pag10, uint32_t Rw,
                                                  uint16_t data16);
  // Indirect Addressing Expressions (using DPP registers by default)
  static BN::ExprId GetIndAddrExpr_Rw(BN::LowLevelILFunction &il, uint32_t Rw);
  static BN::ExprId GetIndAddrExpr_Rw_data16(BN::LowLevelILFunction &il,
                                             uint32_t Rw, uint16_t data16);

  static void SetExtpPag10(uint64_t addr, uint16_t pag10, uint8_t num_insns);
  static void SetExtsSeg8(uint64_t addr, uint16_t seg8, uint8_t num_insns);
  static void SetExtr(uint64_t addr, uint8_t num_insns);
  static bool ShouldUseExtr(uint64_t addr);
  static bool ShouldUseExts(uint64_t addr, uint32_t *seg8);
  static bool ShouldUseExtp(uint64_t addr, uint32_t *pag10);
  static void writeStateMapToFile(std::string filename);
  static void loadStateMapFromFile(std::string filename);
  static size_t SerializeStateMap(uint8_t *buf, size_t size);
  static bool DeserializeStateMap(const uint8_t *buf, size_t size);
  static size_t SizeOfStateMap();

  static InstructionState GetInstructionState(uint64_t addr);

  static const char *ConditionCodeToString(uint8_t code);
  static uint8_t GetBitPosition(const uint8_t *data, size_t len);
  static BNLowLevelILFlagCondition GetFlagCondition(uint8_t code);
  static uint32_t GetMem(uint64_t addr, const uint8_t *data, size_t len);
  static uint8_t GetOpSeg(const uint8_t *data, size_t len);
  static uint8_t GetData3(const uint8_t *data, size_t len);
  static uint8_t GetData4High(const uint8_t *data, size_t len);
  static uint8_t GetData4Low(const uint8_t *data, size_t len);
  static uint8_t GetData8High(const uint8_t *data, size_t len);
  static uint8_t GetData8Low(const uint8_t *data, size_t len);
  static uint16_t GetData16(const uint8_t *data, size_t len);
  static uint8_t GetIndirectIndex(const uint8_t *data, size_t len);
  static uint16_t GetOpCaddr(const uint8_t *data, size_t len);
  static uint8_t GetRegShortAddr(const uint8_t *data, size_t len);
  static bool JumpDirect(BN::Architecture *arch, BN::LowLevelILFunction &il,
                         uint32_t target);
  static bool JumpIndirect(BN::Architecture *arch, BN::LowLevelILFunction &il,
                           uint32_t rid, uint32_t addr);
  static bool LiftOpMemReg(
      uint64_t addr, const uint8_t *data, size_t len, size_t width,
      uint32_t flags, bool store, BN::LowLevelILFunction &il,
      const std::function<
          BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                     const BN::ILSourceLocation &loc)> &operation);
  static bool LiftOpRegData(
      uint64_t addr, const uint8_t *data, size_t len, size_t width,
      uint32_t flags, bool store, BN::LowLevelILFunction &il,
      const std::function<
          BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                     const BN::ILSourceLocation &loc)> &operation);
  static bool LiftOpRegMem(
      uint64_t addr, const uint8_t *data, size_t len, size_t width,
      uint32_t flags, bool store, BN::LowLevelILFunction &il,
      const std::function<
          BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                     const BN::ILSourceLocation &loc)> &operation);
  static bool LiftOpRnRm(
      const uint8_t *data, size_t len, size_t width, uint32_t flags, bool store,
      BN::LowLevelILFunction &il,
      const std::function<
          BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                     const BN::ILSourceLocation &loc)> &operation);
  static bool LiftOpRnRwiData3(
      uint64_t addr, const uint8_t *data, size_t len, size_t width,
      uint32_t flags, bool store, BN::LowLevelILFunction &il,
      const std::function<
          BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                     const BN::ILSourceLocation &loc)> &operation);
  static int8_t SignExtend(uint8_t data);
  static bool TextOpMemReg(uint64_t addr, const uint8_t *data, size_t len,
                           size_t width,
                           std::vector<BN::InstructionTextToken> &result,
                           const std::string &instr);
  static bool TextOpRegData(uint64_t addr, const uint8_t *data, size_t len,
                            size_t width,
                            std::vector<BN::InstructionTextToken> &result,
                            const std::string &instr);
  static bool TextOpRegMem(uint64_t addr, const uint8_t *data, size_t len,
                           size_t width,
                           std::vector<BN::InstructionTextToken> &result,
                           const std::string &instr);
  static bool TextOpRnRm(const uint8_t *data, size_t len, size_t width,
                         std::vector<BN::InstructionTextToken> &result,
                         const std::string &instr);
  static bool TextOpRnRwiData3(const uint8_t *data, size_t len, size_t width,
                               std::vector<BN::InstructionTextToken> &result,
                               const std::string &instr);
  static uint32_t TranslateBitOff(uint64_t addr, uint32_t bitoff);
  static uint32_t TranslateMem(uint32_t mem);
  static uint32_t TranslateReg(uint64_t addr, uint32_t reg);
  static bool IsRegister(uint32_t reg, size_t width = 2);
  static std::vector<uint32_t> GetSfrRegisters();
  static BN::ExprId ReadRegisterOrMemory(BN::LowLevelILFunction &il,
                                          uint32_t operand, size_t width);
  static BN::ExprId WriteRegisterOrMemory(BN::LowLevelILFunction &il,
                                           uint32_t operand, size_t width,
                                           BN::ExprId value, uint32_t flags);
  static void AddRegisterOrAddressToken(
      std::vector<BN::InstructionTextToken> &result, uint32_t operand,
      size_t width);
  static const char *RegToStr(uint32_t rid);
  static BN::ExprId ElideReg(BN::LowLevelILFunction &il, uint32_t reg,
                             int width);
};
}  // namespace C166

#endif  // SRC_UTIL_H_
