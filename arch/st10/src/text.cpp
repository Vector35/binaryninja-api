// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#include <binaryninjaapi.h>

#include <cstdint>
#include <cstdio>
#include <vector>

#include "instructions.h"
#include "opcodes.h"
#include "util.h"

#define ITEXT(m)                            \
  result.emplace_back(InstructionToken, m); \
  result.emplace_back(TextToken, " ");

namespace BN = BinaryNinja;

namespace C166 {

bool Add::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
               size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::ADD_RWN_RWM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 2, result, "add");
    case Opcodes::ADD_RWN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 2, result, "add");
    case Opcodes::ADD_REG_DATA16:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 2, result, "add");
    case Opcodes::ADD_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 2, result, "add");
    case Opcodes::ADD_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 2, result, "add");
    default:
      BN::LogError("0x%lx: Add::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Addb::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
                size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::ADDB_RBN_RBM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 1, result, "addb");
    case Opcodes::ADDB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 1, result, "addb");
    case Opcodes::ADDB_REG_DATA8:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 1, result, "addb");
    case Opcodes::ADDB_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 1, result, "addb");
    case Opcodes::ADDB_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 1, result, "addb");
    default:
      BN::LogError("0x%lx: Addb::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Addc::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
                size_t& len, std::vector<BN::InstructionTextToken>& result) {
  // TODO: Handle carry
  switch (op) {
    case Opcodes::ADDC_RWN_RWM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 2, result, "addc");
    case Opcodes::ADDC_RWN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 2, result, "addc");
    case Opcodes::ADDC_REG_DATA16:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 2, result, "addc");
    case Opcodes::ADDC_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 2, result, "addc");
    case Opcodes::ADDC_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 2, result, "addc");
    default:
      BN::LogError("0x%lx: Addc::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Addcb::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
                 size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::ADDCB_RBN_RBM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 1, result, "addcb");
    case Opcodes::ADDCB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 1, result, "addcb");
    case Opcodes::ADDCB_REG_DATA8:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 1, result, "addcb");
    case Opcodes::ADDCB_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 1, result, "addcb");
    case Opcodes::ADDCB_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 1, result, "addcb");
    default:
      BN::LogError("0x%lx: Addcb::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool And::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
               size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::AND_RWN_RWM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 2, result, "and");
    case Opcodes::AND_RWN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 2, result, "and");
    case Opcodes::AND_REG_DATA16:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 2, result, "and");
    case Opcodes::AND_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 2, result, "and");
    case Opcodes::AND_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 2, result, "and");
    default:
      BN::LogError("0x%lx: And::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Andb::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
                size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::ANDB_RBN_RBM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 1, result, "andb");
    case Opcodes::ANDB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 1, result, "andb");
    case Opcodes::ANDB_REG_DATA8:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 1, result, "andb");
    case Opcodes::ANDB_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 1, result, "andb");
    case Opcodes::ANDB_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 1, result, "andb");
    default:
      BN::LogError("0x%lx: Andb::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Ashr::TextxAC(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  ITEXT("ashr")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  len = length;
  return true;
}

bool Ashr::TextxBC(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, length);
  const auto data4 = Instruction::GetData4High(data, length);

  ITEXT("ashr")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  std::snprintf(buf, sizeof(buf), "%d", data4);
  result.emplace_back(IntegerToken, buf, data4);

  len = length;
  return true;
}

bool Band::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const auto zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  const uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  const uint8_t zpos = *(data + 3) & 0xFu;

  ITEXT("band")

  if (zaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(zaddr));
    result.emplace_back(RegisterToken, buf, zaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", zaddr);
    result.emplace_back(PossibleAddressToken, buf, zaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", zpos);
  result.emplace_back(IntegerToken, buf, zpos);

  result.emplace_back(OperandSeparatorToken, ", ");

  if (qaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(qaddr));
    result.emplace_back(RegisterToken, buf, qaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", qaddr);
    result.emplace_back(PossibleAddressToken, buf, qaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", qpos);
  result.emplace_back(IntegerToken, buf, qpos);

  len = length;
  return true;
}

bool Bclr::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto bitpos = Instruction::GetBitPosition(data, length);
  const auto bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));

  ITEXT("bclr")

  if (bitaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(bitaddr));
    result.emplace_back(RegisterToken, buf, bitaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", bitaddr);
    result.emplace_back(PossibleAddressToken, buf, bitaddr);
  }
  result.emplace_back(TextToken, ".");

  std::snprintf(buf, sizeof(buf), "%u", bitpos);
  result.emplace_back(IntegerToken, buf, bitpos);

  len = length;
  return true;
}

bool Bcmp::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  auto qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  auto zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  uint8_t zpos = *(data + 3) & 0xFu;

  ITEXT("bcmp")

  if (zaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(zaddr));
    result.emplace_back(RegisterToken, buf, zaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", zaddr);
    result.emplace_back(PossibleAddressToken, buf, zaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", zpos);
  result.emplace_back(IntegerToken, buf, zpos);

  result.emplace_back(OperandSeparatorToken, ", ");

  if (qaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(qaddr));
    result.emplace_back(RegisterToken, buf, qaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", qaddr);
    result.emplace_back(PossibleAddressToken, buf, qaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", qpos);
  result.emplace_back(IntegerToken, buf, qpos);

  len = length;
  return true;
}

bool Bfldh::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto bitoff = Instruction::TranslateBitOff(addr, *(data + 1));
  uint8_t data8 = *(data + 2);
  uint8_t mask8 = *(data + 3);

  ITEXT("bfldh")

  if (bitoff <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(bitoff));
    result.emplace_back(RegisterToken, buf, bitoff);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", bitoff);
    result.emplace_back(PossibleAddressToken, buf, bitoff);
  }
  result.emplace_back(OperandSeparatorToken, ", #");

  std::snprintf(buf, sizeof(buf), "0x%x", mask8);
  result.emplace_back(IntegerToken, buf, mask8, 1);
  result.emplace_back(OperandSeparatorToken, ", #");

  std::snprintf(buf, sizeof(buf), "0x%x", data8);
  result.emplace_back(IntegerToken, buf, data8, 1);

  len = length;
  return true;
}

bool Bfldl::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto bitoff = Instruction::TranslateBitOff(addr, *(data + 1));
  uint8_t mask8 = *(data + 2);
  uint8_t data8 = *(data + 3);

  ITEXT("bfldl")

  if (bitoff <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(bitoff));
    result.emplace_back(RegisterToken, buf, bitoff);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", bitoff);
    result.emplace_back(PossibleAddressToken, buf, bitoff);
  }
  result.emplace_back(OperandSeparatorToken, ", #");

  std::snprintf(buf, sizeof(buf), "0x%x", mask8);
  result.emplace_back(IntegerToken, buf, mask8, 1);
  result.emplace_back(OperandSeparatorToken, ", #");

  std::snprintf(buf, sizeof(buf), "0x%x", data8);
  result.emplace_back(IntegerToken, buf, data8, 1);

  len = length;
  return true;
}

bool Bmov::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  auto qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  auto zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  uint8_t zpos = *(data + 3) & 0xFu;

  ITEXT("bmov")

  if (zaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(zaddr));
    result.emplace_back(RegisterToken, buf, zaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", zaddr);
    result.emplace_back(PossibleAddressToken, buf, zaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", zpos);
  result.emplace_back(IntegerToken, buf, zpos);
  result.emplace_back(OperandSeparatorToken, ", ");

  if (qaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(qaddr));
    result.emplace_back(RegisterToken, buf, qaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", qaddr);
    result.emplace_back(PossibleAddressToken, buf, qaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", qpos);
  result.emplace_back(IntegerToken, buf, qpos);

  len = length;
  return true;
}

bool Bmovn::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  auto qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  auto zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  uint8_t zpos = *(data + 3) & 0xFu;

  ITEXT("bmovn")

  if (zaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(zaddr));
    result.emplace_back(RegisterToken, buf, zaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", zaddr);
    result.emplace_back(PossibleAddressToken, buf, zaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", zpos);
  result.emplace_back(IntegerToken, buf, zpos);
  result.emplace_back(OperandSeparatorToken, ", ");

  if (qaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(qaddr));
    result.emplace_back(RegisterToken, buf, qaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", qaddr);
    result.emplace_back(PossibleAddressToken, buf, qaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", qpos);
  result.emplace_back(IntegerToken, buf, qpos);

  len = length;
  return true;
}

bool Bor::Text(const uint8_t* data, const uint64_t addr, size_t& len,
               std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  auto qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  auto zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  uint8_t zpos = *(data + 3) & 0xFu;

  ITEXT("bor")

  if (zaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(zaddr));
    result.emplace_back(RegisterToken, buf, zaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", zaddr);
    result.emplace_back(PossibleAddressToken, buf, zaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", zpos);
  result.emplace_back(IntegerToken, buf, zpos);
  result.emplace_back(OperandSeparatorToken, ", ");

  if (qaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(qaddr));
    result.emplace_back(RegisterToken, buf, qaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", qaddr);
    result.emplace_back(PossibleAddressToken, buf, qaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", qpos);
  result.emplace_back(IntegerToken, buf, qpos);

  len = length;
  return true;
}

bool Bxor::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  auto qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  auto zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  uint8_t zpos = *(data + 3) & 0xFu;

  ITEXT("bxor")

  if (zaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(zaddr));
    result.emplace_back(RegisterToken, buf, zaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", zaddr);
    result.emplace_back(PossibleAddressToken, buf, zaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", zpos);
  result.emplace_back(IntegerToken, buf, zpos);
  result.emplace_back(OperandSeparatorToken, ", ");

  if (qaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(qaddr));
    result.emplace_back(RegisterToken, buf, qaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", qaddr);
    result.emplace_back(PossibleAddressToken, buf, qaddr);
  }
  result.emplace_back(TextToken, ".");
  std::snprintf(buf, sizeof(buf), "%u", qpos);
  result.emplace_back(IntegerToken, buf, qpos);

  len = length;
  return true;
}

bool Bset::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  auto bitpos = Instruction::GetBitPosition(data, length);
  auto bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));

  ITEXT("bset")

  if (bitaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(bitaddr));
    result.emplace_back(RegisterToken, buf, bitaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", bitaddr);
    result.emplace_back(PossibleAddressToken, buf, bitaddr);
  }
  result.emplace_back(TextToken, ".");

  std::snprintf(buf, sizeof(buf), "%u", bitpos);
  result.emplace_back(IntegerToken, buf, bitpos);

  len = length;
  return true;
}

bool Calla::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const char* const code =
      Instruction::ConditionCodeToString(Calla::GetConditionCode(data, length));
  auto target = Calla::GetTarget(data, addr, length);

  ITEXT("calla")

  std::snprintf(buf, sizeof(buf), "%s", code);
  result.emplace_back(TextToken, buf);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", target);
  result.emplace_back(RegisterToken, buf, target);

  len = length;
  return true;
}

bool Calli::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const char* const code =
      Instruction::ConditionCodeToString(GetConditionCode(data, length));
  const auto rwn = Instruction::GetData4Low(data, length);

  ITEXT("calli")

  std::snprintf(buf, sizeof(buf), "%s", code);
  result.emplace_back(TextToken, buf);
  result.emplace_back(OperandSeparatorToken, ", [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(TextToken, "]");

  len = length;
  return true;
}

bool Callr::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto target = Callr::GetTarget(data, addr, length);

  ITEXT("callr")

  std::snprintf(buf, sizeof(buf), "0x%x", target);
  result.emplace_back(PossibleAddressToken, buf, target, sizeof(target));

  len = length;
  return true;
}

bool Calls::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  uint8_t seg = Instruction::GetOpSeg(data, length);
  uint16_t caddr = Instruction::GetOpCaddr(data, length);

  ITEXT("calls")

  std::snprintf(buf, sizeof(buf), "0x%x", seg);
  result.emplace_back(IntegerToken, buf, seg, 1);
  result.emplace_back(OperandSeparatorToken, ", ");
  std::snprintf(buf, sizeof(buf), "0x%x", caddr);
  result.emplace_back(IntegerToken, buf, caddr, 2);

  len = length;
  return true;
}

bool Cmp::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
               size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::CMP_RWN_RWM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 2, result, "cmp");
    case Opcodes::CMP_RWN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 2, result, "cmp");
    case Opcodes::CMP_REG_DATA16:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 2, result, "cmp");
    case Opcodes::CMP_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 2, result, "cmp");
    default:
      BN::LogError("0x%lx: Cmp::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Cmpb::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
                size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::CMPB_RBN_RBM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 1, result, "cmpb");
    case Opcodes::CMPB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 1, result, "cmpb");
    case Opcodes::CMPB_REG_DATA8:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 1, result, "cmpb");
    case Opcodes::CMPB_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 1, result, "cmpb");
    default:
      BN::LogError("0x%lx: Cmpb::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Cmpd1::TextxA0(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto data4 = Instruction::GetData4High(data, 2);
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpd1")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  snprintf(buf, sizeof(buf), "0x%x", data4);
  result.emplace_back(IntegerToken, buf, data4);

  len = 2;
  return true;
}

bool Cmpd1::TextxA2(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpd1")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = 4;
  return true;
}

bool Cmpd1::TextxA6(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto data16 = Instruction::GetData16(data, 4);
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpd1")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  snprintf(buf, sizeof(buf), "0x%x", data16);
  result.emplace_back(IntegerToken, buf, data16);

  len = 4;
  return true;
}

bool Cmpd2::TextxB0(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto data4 = Instruction::GetData4High(data, 2);
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpd2")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  snprintf(buf, sizeof(buf), "0x%x", data4);
  result.emplace_back(IntegerToken, buf, data4);

  len = 2;
  return true;
}

bool Cmpd2::TextxB2(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpd2")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = 4;
  return true;
}

bool Cmpd2::TextxB6(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto data16 = Instruction::GetData16(data, 4);
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpd2")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  snprintf(buf, sizeof(buf), "0x%x", data16);
  result.emplace_back(IntegerToken, buf, data16);

  len = 4;
  return true;
}

bool Cmpi1::Textx80(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto data4 = Instruction::GetData4High(data, 2);
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpi1")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  snprintf(buf, sizeof(buf), "0x%x", data4);
  result.emplace_back(IntegerToken, buf, data4);

  len = 2;
  return true;
}

bool Cmpi1::Textx82(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpi1")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = 4;
  return true;
}

bool Cmpi1::Textx86(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto data16 = Instruction::GetData16(data, 4);
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpi1")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  snprintf(buf, sizeof(buf), "0x%x", data16);
  result.emplace_back(IntegerToken, buf, data16);

  len = 4;
  return true;
}

bool Cmpi2::Textx90(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto data4 = Instruction::GetData4High(data, 2);
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpi2")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  snprintf(buf, sizeof(buf), "0x%x", data4);
  result.emplace_back(IntegerToken, buf, data4);

  len = 2;
  return true;
}

bool Cmpi2::Textx92(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpi2")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = 4;
  return true;
}

bool Cmpi2::Textx96(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto data16 = Instruction::GetData16(data, 4);
  const auto rwn = Instruction::GetData4Low(data, 2);

  ITEXT("cmpi2")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  snprintf(buf, sizeof(buf), "0x%x", data16);
  result.emplace_back(IntegerToken, buf, data16);

  len = 4;
  return true;
}

bool Cpl::Text(const uint8_t* data, const uint64_t addr, size_t& len,
               std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);

  ITEXT("cpl")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  len = length;
  return true;
}

bool Cplb::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rbn = Instruction::GetData4High(data, length) + 16;

  ITEXT("cplb")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbn));
  result.emplace_back(RegisterToken, buf, rbn);

  len = length;
  return true;
}

bool Diswdt::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "diswdt");
  len = length;
  return true;
}

bool Div::Text(const uint8_t* data, const uint64_t addr, size_t& len,
               std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);

  ITEXT("div")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  len = length;
  return true;
}

bool Divl::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);

  ITEXT("divl")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  len = length;
  return true;
}

bool Divlu::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);

  ITEXT("divlu")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  len = length;
  return true;
}

bool Divu::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);

  ITEXT("divu")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  len = length;
  return true;
}

bool Einit::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "einit");
  len = length;
  return true;
}

bool ExtrAtomic::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto instr = *(const uint16_t*)data;
  uint8_t scode = (instr & (0b11u << 14u)) >> 14u;
  uint8_t count = ((instr & (0b11u << 12u)) >> 12u) + 1u;

  if (scode == 0b10) {
    ITEXT("extr")
  } else if (scode == 0b00) {
    ITEXT("atomic")
  } else {
    BN::LogError("0x%lx: Malformed %s instruction (invalid subopcode)", addr,
                 "ExtrAtomic");
    return false;
  }
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "%d", count);
  result.emplace_back(IntegerToken, buf, count, 1);

  len = length;
  return true;
}

bool Extprs::TextxD7(const uint8_t* data, const uint64_t addr, size_t& len,
                     std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const uint16_t instr = *(const uint16_t*)data;
  const char* const mnemonic = Extprs::GetInstruction(data, addr, 4);
  uint16_t pag_seg = Instruction::GetData16(data, 4);
  uint8_t count = ((instr & (0b11u << 12u)) >> 12u) + 1;

  ITEXT(mnemonic)

  std::snprintf(buf, sizeof(buf), "0x%x", pag_seg);
  result.emplace_back(IntegerToken, buf, pag_seg, 2);
  result.emplace_back(OperandSeparatorToken, ", ");
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "%d", count);
  result.emplace_back(IntegerToken, buf, count, 1);

  len = 4;
  return true;
}

bool Extprs::TextxDC(const uint8_t* data, const uint64_t addr, size_t& len,
                     std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const uint16_t instr = *(const uint16_t*)data;
  const char* const mnemonic = Extprs::GetInstruction(data, addr, 4);
  const auto rwm = Instruction::GetData4Low(data, 2);
  uint8_t count = ((instr & (0b11u << 12u)) >> 12u) + 1;

  ITEXT(mnemonic)

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(OperandSeparatorToken, ", ");
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "%d", count);
  result.emplace_back(IntegerToken, buf, count, 1);

  len = 2;
  return true;
}

bool Idle::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "idle");
  len = length;
  return true;
}

bool Jb::Text(const uint8_t* data, const uint64_t addr, size_t& len,
              std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto target = Jb::GetTarget(data, addr, length);
  const auto bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const auto bitpos = (*(data + 3) & (0xFu << 4u)) >> 4u;

  ITEXT("jb")

  if (bitaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(bitaddr));
    result.emplace_back(RegisterToken, buf, bitaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", bitaddr);
    result.emplace_back(PossibleAddressToken, buf, bitaddr);
  }
  std::snprintf(buf, sizeof(buf), ".");
  result.emplace_back(TextToken, buf);
  std::snprintf(buf, sizeof(buf), "%d", bitpos);
  result.emplace_back(IntegerToken, buf, bitpos);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", target);
  result.emplace_back(PossibleAddressToken, buf, target, sizeof(target));

  len = length;
  return true;
}

bool Jbc::Text(const uint8_t* data, const uint64_t addr, size_t& len,
               std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto target = Jbc::GetTarget(data, addr, length);
  const auto bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const auto bitpos = (*(data + 3) & (0xFu << 4u)) >> 4u;

  ITEXT("jbc")

  if (bitaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(bitaddr));
    result.emplace_back(RegisterToken, buf, bitaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", bitaddr);
    result.emplace_back(PossibleAddressToken, buf, bitaddr);
  }
  std::snprintf(buf, sizeof(buf), ".");
  result.emplace_back(TextToken, buf);
  std::snprintf(buf, sizeof(buf), "%d", bitpos);
  result.emplace_back(IntegerToken, buf, bitpos);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", target);
  result.emplace_back(PossibleAddressToken, buf, target, sizeof(target));

  len = length;
  return true;
}

bool Jmpa::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const char* const code =
      Instruction::ConditionCodeToString(Jmpa::GetConditionCode(data, length));
  auto target = Jmpa::GetTarget(data, addr, length);

  ITEXT("jmpa")

  std::snprintf(buf, sizeof(buf), "%s", code);
  result.emplace_back(TextToken, buf);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", target);
  result.emplace_back(RegisterToken, buf, target);

  len = length;
  return true;
}

bool Jmpi::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const char* const code = Instruction::ConditionCodeToString(
      Instruction::GetData4High(data, length));
  const auto rwn = Instruction::GetData4Low(data, length);

  ITEXT("jmpi")

  std::snprintf(buf, sizeof(buf), "%s", code);
  result.emplace_back(TextToken, buf);
  result.emplace_back(OperandSeparatorToken, ", [");
  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(TextToken, "]");

  len = length;
  return true;
}

bool Jmpr::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const char* const code =
      Instruction::ConditionCodeToString(Jmpr::GetConditionCode(data, length));
  const auto target = Jmpr::GetTarget(data, addr, length);

  ITEXT("jmpr")

  std::snprintf(buf, sizeof(buf), "%s", code);
  result.emplace_back(TextToken, buf);
  result.emplace_back(OperandSeparatorToken, ", ");
  std::snprintf(buf, sizeof(buf), "0x%x", target);
  result.emplace_back(PossibleAddressToken, buf, target, sizeof(target));

  len = length;
  return true;
}

bool Jmps::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  uint8_t seg = Instruction::GetOpSeg(data, length);
  uint16_t caddr = Instruction::GetOpCaddr(data, length);

  ITEXT("jmps")

  std::snprintf(buf, sizeof(buf), "0x%x", seg);
  result.emplace_back(IntegerToken, buf, seg, 1);
  result.emplace_back(OperandSeparatorToken, ", ");
  std::snprintf(buf, sizeof(buf), "0x%x", caddr);
  result.emplace_back(IntegerToken, buf, caddr, 2);

  len = length;
  return true;
}

bool Jnb::Text(const uint8_t* data, const uint64_t addr, size_t& len,
               std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto target = Jnb::GetTarget(data, addr, length);
  const auto bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const auto bitpos = (*(data + 3) & (0xFu << 4u)) >> 4u;

  ITEXT("jnb")

  if (bitaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(bitaddr));
    result.emplace_back(RegisterToken, buf, bitaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", bitaddr);
    result.emplace_back(PossibleAddressToken, buf, bitaddr);
  }
  std::snprintf(buf, sizeof(buf), ".");
  result.emplace_back(TextToken, buf);
  std::snprintf(buf, sizeof(buf), "%d", bitpos);
  result.emplace_back(IntegerToken, buf, bitpos);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", target);
  result.emplace_back(PossibleAddressToken, buf, target, sizeof(target));

  len = length;
  return true;
}

bool Jnbs::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto target = Jnbs::GetTarget(data, addr, length);
  const auto bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const auto bitpos = (*(data + 3) & (0xFu << 4u)) >> 4u;

  ITEXT("jnbs")

  if (bitaddr <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(bitaddr));
    result.emplace_back(RegisterToken, buf, bitaddr);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", bitaddr);
    result.emplace_back(PossibleAddressToken, buf, bitaddr);
  }
  std::snprintf(buf, sizeof(buf), ".");
  result.emplace_back(TextToken, buf);
  std::snprintf(buf, sizeof(buf), "%d", bitpos);
  result.emplace_back(IntegerToken, buf, bitpos);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", target);
  result.emplace_back(PossibleAddressToken, buf, target, sizeof(target));

  len = length;
  return true;
}

bool Mov::Textx84(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  result.emplace_back(InstructionToken, "mov");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, "], ");

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = 4;
  return true;
}

bool Mov::Textx88(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  result.emplace_back(InstructionToken, "mov");
  result.emplace_back(TextToken, " [-");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  result.emplace_back(OperandSeparatorToken, "], ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  len = 2;
  return true;
}

bool Mov::Textx94(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  ITEXT("mov")

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);
  result.emplace_back(OperandSeparatorToken, ", [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(TextToken, "]");

  len = 4;
  return true;
}

bool Mov::Textx98(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  ITEXT("mov")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  result.emplace_back(OperandSeparatorToken, ", [");
  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(TextToken, "+]");

  len = 2;
  return true;
}

bool Mov::TextxA8(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  ITEXT("mov")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", [");
  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(TextToken, "]");

  len = 2;
  return true;
}

bool Mov::TextxB8(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  result.emplace_back(InstructionToken, "mov");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(OperandSeparatorToken, "], ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  len = 2;
  return true;
}

bool Mov::TextxC4(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);
  const auto data16 = Instruction::GetData16(data, 4);

  result.emplace_back(InstructionToken, "mov");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(OperandSeparatorToken, "+#");
  std::snprintf(buf, sizeof(buf), "0x%x", data16);
  result.emplace_back(RegisterToken, buf, data16);
  result.emplace_back(OperandSeparatorToken, "], ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  len = 4;
  return true;
}

bool Mov::TextxC8(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  result.emplace_back(InstructionToken, "mov");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, "], [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(TextToken, "]");

  len = 2;
  return true;
}

bool Mov::TextxD4(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);
  const auto data16 = Instruction::GetData16(data, 4);

  ITEXT("mov")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  result.emplace_back(OperandSeparatorToken, ", [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  result.emplace_back(OperandSeparatorToken, "+#");

  std::snprintf(buf, sizeof(buf), "0x%x", data16);
  result.emplace_back(RegisterToken, buf, data16);
  result.emplace_back(TextToken, "]");

  len = 4;
  return true;
}

bool Mov::TextxD8(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  result.emplace_back(InstructionToken, "mov");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, "+], [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(TextToken, "]");

  len = 2;
  return true;
}

bool Mov::TextxE0(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, 2);
  uint16_t data4 = Instruction::GetData4High(data, 2);

  ITEXT("mov")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "0x%x", data4);
  result.emplace_back(IntegerToken, buf, data4, 1);

  len = 2;
  return true;
}

bool Mov::TextxE6(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));
  const auto data16 = Instruction::GetData16(data, 4);

  ITEXT("mov")

  if (reg <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "0x%x", data16);
  result.emplace_back(IntegerToken, buf, data16, 2);

  len = 4;
  return true;
}

bool Mov::TextxE8(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  result.emplace_back(InstructionToken, "mov");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, "], [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(TextToken, "+]");

  len = 2;
  return true;
}

bool Mov::TextxF0(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  ITEXT("mov")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");
  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  len = 2;
  return true;
}

bool Mov::TextxF2(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  ITEXT("mov")

  if (reg <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = 4;
  return true;
}

/* MOV mem, reg     F6 RR MM MM */
bool Mov::TextxF6(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));

  ITEXT("mov")

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);
  result.emplace_back(OperandSeparatorToken, ", ");
  if (reg <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  len = 4;
  return true;
}

bool Movb::Textx89(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);

  result.emplace_back(InstructionToken, "mov");
  result.emplace_back(TextToken, " [-");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  result.emplace_back(OperandSeparatorToken, "], ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbn));
  result.emplace_back(RegisterToken, buf, rbn);

  len = 2;
  return true;
}

bool Movb::Textx99(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);

  ITEXT("movb")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbn));
  result.emplace_back(RegisterToken, buf, rbn);

  result.emplace_back(OperandSeparatorToken, ", [");
  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(TextToken, "+]");

  len = 2;
  return true;
}

bool Movb::TextxA4(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  result.emplace_back(InstructionToken, "movb");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, "], ");

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = 4;
  return true;
}

bool Movb::TextxB4(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  ITEXT("movb")

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);
  result.emplace_back(OperandSeparatorToken, ", [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(TextToken, "]");

  len = 4;
  return true;
}

bool Movb::TextxA9(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);

  ITEXT("movb")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbn));
  result.emplace_back(RegisterToken, buf, rbn);
  result.emplace_back(OperandSeparatorToken, ", [");
  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(TextToken, "]");

  len = 2;
  return true;
}

bool Movb::TextxB9(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);

  result.emplace_back(InstructionToken, "movb");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(OperandSeparatorToken, "], ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbn));
  result.emplace_back(RegisterToken, buf, rbn);

  len = 2;
  return true;
}

bool Movb::TextxC9(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  result.emplace_back(InstructionToken, "movb");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, "], [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(TextToken, "]");

  len = 2;
  return true;
}

bool Movb::TextxD9(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  result.emplace_back(InstructionToken, "movb");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, "+], [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(TextToken, "]");

  len = 2;
  return true;
}

bool Movb::TextxE4(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);
  const auto data16 = Instruction::GetData16(data, 4);

  result.emplace_back(InstructionToken, "movb");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(OperandSeparatorToken, "+#");
  std::snprintf(buf, sizeof(buf), "0x%x", data16);
  result.emplace_back(RegisterToken, buf, data16);
  result.emplace_back(OperandSeparatorToken, "], ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbn));
  result.emplace_back(RegisterToken, buf, rbn);

  len = 4;
  return true;
}

bool Movb::TextxE9(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  result.emplace_back(InstructionToken, "movb");
  result.emplace_back(TextToken, " [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, "], [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);
  result.emplace_back(TextToken, "+]");

  len = 2;
  return true;
}

bool Movb::TextxE1(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rbn = Instruction::GetData4Low(data, 2) + 16;
  const auto data4 = Instruction::GetData4High(data, 2);

  ITEXT("movb")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbn));
  result.emplace_back(RegisterToken, buf, rbn);
  result.emplace_back(OperandSeparatorToken, ", ");
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "0x%x", data4);
  result.emplace_back(IntegerToken, buf, data4, 1);

  len = 2;
  return true;
}

bool Movb::TextxE7(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));
  uint16_t data8 = Instruction::GetData8Low(data, 4);

  ITEXT("movb")

  if (reg <= 0xF) {
    reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "0x%x", data8);
  result.emplace_back(IntegerToken, buf, data8, 1);

  len = 4;
  return true;
}

bool Movb::TextxF1(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rbm = Instruction::GetData4Low(data, 2) + 16;

  ITEXT("movb")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbn));
  result.emplace_back(RegisterToken, buf, rbn);
  result.emplace_back(OperandSeparatorToken, ", ");
  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbm));
  result.emplace_back(RegisterToken, buf, rbm);

  len = 2;
  return true;
}

bool Movb::TextxF3(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  ITEXT("movb")

  if (reg <= 0xF) {
    reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = 4;
  return true;
}

bool Movb::TextxF4(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);
  const auto data16 = Instruction::GetData16(data, 4);

  ITEXT("movb")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbn));
  result.emplace_back(RegisterToken, buf, rbn);

  result.emplace_back(OperandSeparatorToken, ", [");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  result.emplace_back(OperandSeparatorToken, "+#");

  std::snprintf(buf, sizeof(buf), "0x%x", data16);
  result.emplace_back(RegisterToken, buf, data16);
  result.emplace_back(TextToken, "]");

  len = 4;
  return true;
}

bool Movb::TextxF7(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));

  ITEXT("movb")

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);
  result.emplace_back(OperandSeparatorToken, ", ");
  if (reg <= 0xF) {
    reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  len = 4;
  return true;
}

bool Movbs::TextxD0(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto rbm = Instruction::GetData4High(data, 2) + 16;

  ITEXT("movbs")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbm));
  result.emplace_back(RegisterToken, buf, rbm);

  len = 2;
  return true;
}

bool Movbs::TextxD2(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  ITEXT("movbs")

  if (reg <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = 4;
  return true;
}

bool Movbs::TextxD5(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));

  ITEXT("movbs")

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);
  result.emplace_back(OperandSeparatorToken, ", ");
  if (reg <= 0xF) {
    reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  len = 4;
  return true;
}

bool Movbz::TextxC0(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto rbm = Instruction::GetData4High(data, 2) + 16;

  ITEXT("movbz")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbm));
  result.emplace_back(RegisterToken, buf, rbm);

  len = 2;
  return true;
}

bool Movbz::TextxC2(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  ITEXT("movbz")

  if (reg <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = 4;
  return true;
}

bool Movbz::TextxC5(const uint8_t* data, const uint64_t addr, size_t& len,
                    std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));

  ITEXT("movbz")

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);
  result.emplace_back(OperandSeparatorToken, ", ");
  if (reg <= 0xF) {
    reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  len = 4;
  return true;
}

bool Mul::Text(const uint8_t* data, const uint64_t addr, size_t& len,
               std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  ITEXT("mul")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  len = length;
  return true;
}

bool Mulu::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  ITEXT("mulu")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  len = length;
  return true;
}

bool Neg::Text(const uint8_t* data, const uint64_t addr, size_t& len,
               std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);

  ITEXT("neg")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);

  len = length;
  return true;
}

bool Negb::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rbn = Instruction::GetData4High(data, length) + 16;

  ITEXT("negb")

  snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rbn));
  result.emplace_back(RegisterToken, buf, rbn);

  len = length;
  return true;
}

bool Nop::Text(const uint8_t* data, const uint64_t addr, size_t& len,
               std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "nop");
  len = length;
  return true;
}

bool Or::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
              size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::OR_RWN_RWM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 2, result, "or");
    case Opcodes::OR_RWN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 2, result, "or");
    case Opcodes::OR_REG_DATA16:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 2, result, "or");
    case Opcodes::OR_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 2, result, "or");
    case Opcodes::OR_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 2, result, "or");
    default:
      BN::LogError("0x%lx: Or::%s received invalid opcode 0x%x", addr, __func__,
                   op);
      return false;
  }
}

bool Orb::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
               size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::ORB_RBN_RBM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 1, result, "orb");
    case Opcodes::ORB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 1, result, "orb");
    case Opcodes::ORB_REG_DATA8:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 1, result, "orb");
    case Opcodes::ORB_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 1, result, "orb");
    case Opcodes::ORB_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 1, result, "orb");
    default:
      BN::LogError("0x%lx: Orb::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Pop::Text(const uint8_t* data, const uint64_t addr, size_t& len,
               std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto reg = Instruction::TranslateReg(
      addr, Instruction::GetRegShortAddr(data, length));

  ITEXT("pop")

  if (reg <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }

  len = length;
  return true;
}

bool Prior::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  ITEXT("prior")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  len = length;
  return true;
}

bool Push::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto reg = Instruction::TranslateReg(
      addr, Instruction::GetRegShortAddr(data, length));

  ITEXT("push")

  if (reg <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }

  len = length;
  return true;
}

bool Pwrdn::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                 std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "pwrdn");
  len = length;
  return true;
}

bool Ret::Text(const uint8_t* data, const uint64_t addr, size_t& len,
               std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "ret");
  len = length;
  return true;
}

bool Reti::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "reti");
  len = length;
  return true;
}

bool Retp::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "retp");
  len = length;
  return true;
}

bool Rets::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "rets");
  len = length;
  return true;
}

bool Rol::Textx0C(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  ITEXT("rol")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  len = length;
  return true;
}

bool Rol::Textx1C(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, length);
  const auto data4 = Instruction::GetData4High(data, length);

  ITEXT("rol")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  std::snprintf(buf, sizeof(buf), "%d", data4);
  result.emplace_back(IntegerToken, buf, data4);

  len = length;
  return true;
}

bool Ror::Textx2C(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  ITEXT("ror")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  len = length;
  return true;
}

bool Ror::Textx3C(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, length);
  const auto data4 = Instruction::GetData4High(data, length);

  ITEXT("ror")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  std::snprintf(buf, sizeof(buf), "%d", data4);
  result.emplace_back(IntegerToken, buf, data4);

  len = length;
  return true;
}

bool Scxt::TextxC6(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto reg = Instruction::TranslateReg(
      addr, Instruction::GetRegShortAddr(data, length));
  const auto data16 = Instruction::GetData16(data, length);

  ITEXT("scxt")

  if (reg <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "0x%x", data16);
  result.emplace_back(IntegerToken, buf, data16, 2);

  len = length;
  return true;
}

bool Scxt::TextxD6(const uint8_t* data, const uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto reg = Instruction::TranslateReg(
      addr, Instruction::GetRegShortAddr(data, length));
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, length));

  ITEXT("scxt")

  if (reg <= 0xF) {
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  len = length;
  return true;
}

bool Shl::Textx4C(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  ITEXT("shl")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  len = length;
  return true;
}

bool Shl::Textx5C(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, length);
  const auto data4 = Instruction::GetData4High(data, length);

  ITEXT("shl")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  std::snprintf(buf, sizeof(buf), "%d", data4);
  result.emplace_back(IntegerToken, buf, data4);

  len = length;
  return true;
}

bool Shr::Textx6C(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  ITEXT("shr")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwm));
  result.emplace_back(RegisterToken, buf, rwm);

  len = length;
  return true;
}

bool Shr::Textx7C(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  const auto rwn = Instruction::GetData4Low(data, length);
  const auto data4 = Instruction::GetData4High(data, length);

  ITEXT("shr")

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwn));
  result.emplace_back(RegisterToken, buf, rwn);
  result.emplace_back(OperandSeparatorToken, ", #");

  std::snprintf(buf, sizeof(buf), "%d", data4);
  result.emplace_back(IntegerToken, buf, data4);

  len = length;
  return true;
}

bool Srst::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "srst");
  len = length;
  return true;
}

bool Srvwdt::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                  std::vector<BN::InstructionTextToken>& result) {
  result.emplace_back(InstructionToken, "srvwdt");
  len = length;
  return true;
}

bool Sub::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
               size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::SUB_RWN_RWM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 2, result, "sub");
    case Opcodes::SUB_RWN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 2, result, "sub");
    case Opcodes::SUB_REG_DATA16:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 2, result, "sub");
    case Opcodes::SUB_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 2, result, "sub");
    case Opcodes::SUB_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 2, result, "sub");
    default:
      BN::LogError("0x%lx: Sub::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Subb::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
                size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::SUBB_RBN_RBM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 1, result, "subb");
    case Opcodes::SUBB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 1, result, "subb");
    case Opcodes::SUBB_REG_DATA8:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 1, result, "subb");
    case Opcodes::SUBB_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 1, result, "subb");
    case Opcodes::SUBB_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 1, result, "subb");
    default:
      BN::LogError("0x%lx: Subb::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Subc::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
                size_t& len, std::vector<BN::InstructionTextToken>& result) {
  // TODO: Handle carry
  switch (op) {
    case Opcodes::SUBC_RWN_RWM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 2, result, "subc");
    case Opcodes::SUBC_RWN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 2, result, "subc");
    case Opcodes::SUBC_REG_DATA16:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 2, result, "subc");
    case Opcodes::SUBC_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 2, result, "subc");
    case Opcodes::SUBC_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 2, result, "subc");
    default:
      BN::LogError("0x%lx: Subc::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Subcb::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
                 size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::SUBCB_RBN_RBM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 1, result, "subcb");
    case Opcodes::SUBCB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 1, result, "subcb");
    case Opcodes::SUBCB_REG_DATA8:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 1, result, "subcb");
    case Opcodes::SUBCB_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 1, result, "subcb");
    case Opcodes::SUBCB_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 1, result, "subcb");
    default:
      BN::LogError("0x%lx: Subcb::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Trap::Text(const uint8_t* data, const uint64_t addr, size_t& len,
                std::vector<BN::InstructionTextToken>& result) {
  char buf[32];
  uint8_t trap7 = Trap::GetTrap7(data);

  ITEXT("trap")

  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "0x%x", trap7);
  result.emplace_back(IntegerToken, buf, trap7);

  len = length;
  return true;
}

bool Xor::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
               size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::XOR_RWN_RWM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 2, result, "xor");
    case Opcodes::XOR_RWN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 2, result, "xor");
    case Opcodes::XOR_REG_DATA16:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 2, result, "xor");
    case Opcodes::XOR_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 2, result, "xor");
    case Opcodes::XOR_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 2, result, "xor");
    default:
      BN::LogError("0x%lx: Xor::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Xorb::Text(const uint8_t op, const uint8_t* data, const uint64_t addr,
                size_t& len, std::vector<BN::InstructionTextToken>& result) {
  switch (op) {
    case Opcodes::XORB_RBN_RBM:
      len = 2;
      return Instruction::TextOpRnRm(data, len, 1, result, "xorb");
    case Opcodes::XORB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::TextOpRnRwiData3(data, len, 1, result, "xorb");
    case Opcodes::XORB_REG_DATA8:
      len = 4;
      return Instruction::TextOpRegData(addr, data, len, 1, result, "xorb");
    case Opcodes::XORB_REG_MEM:
      len = 4;
      return Instruction::TextOpRegMem(addr, data, len, 1, result, "xorb");
    case Opcodes::XORB_MEM_REG:
      len = 4;
      return Instruction::TextOpMemReg(addr, data, len, 1, result, "xorb");
    default:
      BN::LogError("0x%lx: Xorb::%s received invalid opcode 0x%x", addr,
                   __func__, op);
      return false;
  }
}
}  // namespace C166
