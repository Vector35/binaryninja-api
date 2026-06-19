// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#include "architecture.h"

#include <binaryninjaapi.h>

#include <cinttypes>
#include <cstring>
#include <string>
#include <vector>

#include "flags.h"
#include "instructions.h"
#include "opcodes.h"
#include "registers.h"
#include "util.h"

namespace BN = BinaryNinja;

namespace C166 {
static std::vector<uint32_t> GetDppRegisters() {
  return std::vector<uint32_t>{Registers::DPP0, Registers::DPP1,
                               Registers::DPP2, Registers::DPP3};
}

static void AppendUnique(std::vector<uint32_t>& regs,
                         const std::vector<uint32_t>& extraRegs) {
  for (const auto reg : extraRegs) {
    bool found = false;
    for (const auto existingReg : regs) {
      if (existingReg == reg) {
        found = true;
        break;
      }
    }
    if (!found) regs.push_back(reg);
  }
}

C166Architecture::C166Architecture(const std::string& name)
    : Architecture(name) {}

BNRegisterInfo C166Architecture::RegisterInfo(const uint32_t fullWidthReg,
                                              const size_t offset,
                                              const size_t size,
                                              const bool zeroExtend) {
  BNRegisterInfo result;
  result.fullWidthRegister = fullWidthReg;
  result.offset = offset;
  result.size = size;
  result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
  return result;
}

[[nodiscard]] size_t C166Architecture::GetAddressSize() const { return 3; }

[[nodiscard]] BNEndianness C166Architecture::GetEndianness() const {
  return LittleEndian;
}

[[nodiscard]] size_t C166Architecture::GetDefaultIntegerSize() const {
  return 2;
}

[[nodiscard]] size_t C166Architecture::GetInstructionAlignment() const {
  return 2;
}

[[nodiscard]] size_t C166Architecture::GetMaxInstructionLength() const {
  return 4;
}

std::vector<uint32_t> C166Architecture::GetAllRegisters() {
  std::vector<uint32_t> regs{
      Registers::R0,  Registers::R1,        Registers::R2,      Registers::R3,
      Registers::R4,  Registers::R5,        Registers::R6,      Registers::R7,
      Registers::R8,  Registers::R9,        Registers::R10,     Registers::R11,
      Registers::R12, Registers::R13,       Registers::R14,     Registers::R15,
      Registers::RL0, Registers::RH0,       Registers::RL1,     Registers::RH1,
      Registers::RL2, Registers::RH2,       Registers::RL3,     Registers::RH3,
      Registers::RL4, Registers::RH4,       Registers::RL5,     Registers::RH5,
      Registers::RL6, Registers::RH6,       Registers::RL7,     Registers::RH7,
      Registers::CSP, Registers::CPUCON1,   Registers::CPUCON2, Registers::PSW,
      Registers::CP,  Registers::VIRTUAL_LR, Registers::DPP0,   Registers::DPP1,
      Registers::DPP2, Registers::DPP3};
  AppendUnique(regs, Instruction::GetSfrRegisters());
  return regs;
}

std::vector<uint32_t> C166Architecture::GetFullWidthRegisters() {
  std::vector<uint32_t> regs{
      Registers::R0,  Registers::R1,        Registers::R2,      Registers::R3,
      Registers::R4,  Registers::R5,        Registers::R6,      Registers::R7,
      Registers::R8,  Registers::R9,        Registers::R10,     Registers::R11,
      Registers::R12, Registers::R13,       Registers::R14,     Registers::R15,
      Registers::CSP, Registers::CPUCON1,   Registers::CPUCON2, Registers::PSW,
      Registers::CP,  Registers::VIRTUAL_LR, Registers::DPP0,   Registers::DPP1,
      Registers::DPP2, Registers::DPP3};
  AppendUnique(regs, Instruction::GetSfrRegisters());
  return regs;
}

std::vector<uint32_t> C166Architecture::GetGlobalRegisters() {
  std::vector<uint32_t> regs{Registers::CSP, Registers::CPUCON1,
    Registers::CPUCON2, Registers::PSW, Registers::CP, Registers::VIRTUAL_LR};
  AppendUnique(regs, Instruction::GetSfrRegisters());
  return regs;
}

BNRegisterInfo C166Architecture::GetRegisterInfo(const uint32_t rid) {
  switch (rid) {
    case Registers::R0:
      return RegisterInfo(Registers::R0, 0, 2);
    case Registers::RL0:
      return RegisterInfo(Registers::R0, 0, 1);
    case Registers::RH0:
      return RegisterInfo(Registers::R0, 1, 1);
    case Registers::R1:
      return RegisterInfo(Registers::R1, 0, 2);
    case Registers::RL1:
      return RegisterInfo(Registers::R1, 0, 1);
    case Registers::RH1:
      return RegisterInfo(Registers::R1, 1, 1);
    case Registers::R2:
      return RegisterInfo(Registers::R2, 0, 2);
    case Registers::RL2:
      return RegisterInfo(Registers::R2, 0, 1);
    case Registers::RH2:
      return RegisterInfo(Registers::R2, 1, 1);
    case Registers::R3:
      return RegisterInfo(Registers::R3, 0, 2);
    case Registers::RL3:
      return RegisterInfo(Registers::R3, 0, 1);
    case Registers::RH3:
      return RegisterInfo(Registers::R3, 1, 1);
    case Registers::R4:
      return RegisterInfo(Registers::R4, 0, 2);
    case Registers::RL4:
      return RegisterInfo(Registers::R4, 0, 1);
    case Registers::RH4:
      return RegisterInfo(Registers::R4, 1, 1);
    case Registers::R5:
      return RegisterInfo(Registers::R5, 0, 2);
    case Registers::RL5:
      return RegisterInfo(Registers::R5, 0, 1);
    case Registers::RH5:
      return RegisterInfo(Registers::R5, 1, 1);
    case Registers::R6:
      return RegisterInfo(Registers::R6, 0, 2);
    case Registers::RL6:
      return RegisterInfo(Registers::R6, 0, 1);
    case Registers::RH6:
      return RegisterInfo(Registers::R6, 1, 1);
    case Registers::R7:
      return RegisterInfo(Registers::R7, 0, 2);
    case Registers::RL7:
      return RegisterInfo(Registers::R7, 0, 1);
    case Registers::RH7:
      return RegisterInfo(Registers::R7, 1, 1);
    case Registers::R8:
      return RegisterInfo(Registers::R8, 0, 2);
    case Registers::R9:
      return RegisterInfo(Registers::R9, 0, 2);
    case Registers::R10:
      return RegisterInfo(Registers::R10, 0, 2);
    case Registers::R11:
      return RegisterInfo(Registers::R11, 0, 2);
    case Registers::R12:
      return RegisterInfo(Registers::R12, 0, 2);
    case Registers::R13:
      return RegisterInfo(Registers::R13, 0, 2);
    case Registers::R14:
      return RegisterInfo(Registers::R14, 0, 2);
    case Registers::R15:
      return RegisterInfo(Registers::R15, 0, 2);
    case Registers::CSP:
      return RegisterInfo(Registers::CSP, 0, 2);
    case Registers::CPUCON1:
      return RegisterInfo(Registers::CPUCON1, 0, 2);
    case Registers::CPUCON2:
      return RegisterInfo(Registers::CPUCON2, 0, 2);
    case Registers::PSW:
      return RegisterInfo(Registers::PSW, 0, 2);
    case Registers::CP:
      return RegisterInfo(Registers::CP, 0, 2);
    case Registers::VIRTUAL_LR:
      return RegisterInfo(Registers::VIRTUAL_LR, 0, 2);
    case Registers::DPP0:
      return RegisterInfo(Registers::DPP0, 0, 2);
    case Registers::DPP1:
      return RegisterInfo(Registers::DPP1, 0, 2);
    case Registers::DPP2:
      return RegisterInfo(Registers::DPP2, 0, 2);
    case Registers::DPP3:
      return RegisterInfo(Registers::DPP3, 0, 2);
    default:
      if (Instruction::IsRegister(rid, 2)) return RegisterInfo(rid, 0, 2);
      return RegisterInfo(0, 0, 0);
  }
}

std::string C166Architecture::GetRegisterName(uint32_t rid) {
  const char* result = Instruction::RegToStr(rid);
  if (result == nullptr) result = "";
  return result;
}

std::vector<uint32_t> C166Architecture::GetAllFlags() {
  return std::vector<uint32_t>{Flags::FLAG_NEGATIVE, Flags::FLAG_CARRY,
                               Flags::FLAG_OVERFLOW, Flags::FLAG_ZERO,
                               Flags::FLAG_E};
}

std::string C166Architecture::GetFlagName(const uint32_t flag) {
  switch (flag) {
    case Flags::FLAG_NEGATIVE:
      return "n";
    case Flags::FLAG_CARRY:
      return "c";
    case Flags::FLAG_OVERFLOW:
      return "v";
    case Flags::FLAG_ZERO:
      return "z";
    case Flags::FLAG_E:
      return "e";
    default:
      BN::LogError("%s: Invalid id: %u", __func__, flag);
      return "?F?";
  }
}

std::vector<uint32_t> C166Architecture::GetAllFlagWriteTypes() {
  return std::vector<uint32_t>{Flags::WRITE_ALL, Flags::WRITE_Z,
                               Flags::WRITE_EZN};
}

std::string C166Architecture::GetFlagWriteTypeName(const uint32_t wtype) {
  switch (wtype) {
    case Flags::WRITE_ALL:
      return "*";
    case Flags::WRITE_Z:
      return "z";
    case Flags::WRITE_EZN:
      return "ezn";
    default:
      BN::LogError("%s: Invalid id: %u", __func__, wtype);
      return "?W?";
  }
}

std::vector<uint32_t> C166Architecture::GetFlagsWrittenByFlagWriteType(
    uint32_t wtype) {
  switch (wtype) {
    case Flags::WRITE_ALL:
      return std::vector<uint32_t>{Flags::FLAG_NEGATIVE, Flags::FLAG_CARRY,
                                   Flags::FLAG_OVERFLOW, Flags::FLAG_ZERO,
                                   Flags::FLAG_E};
    case Flags::WRITE_Z:
      return std::vector<uint32_t>{Flags::FLAG_ZERO};
    case Flags::WRITE_EZN:
      return std::vector<uint32_t>{Flags::FLAG_E, Flags::FLAG_ZERO,
                                   Flags::FLAG_NEGATIVE};
    default:
      BN::LogError("%s: Invalid write type id: %u", __func__, wtype);
      return {};
  }
}

// TODO: Learn about semantic flag classes
BNFlagRole C166Architecture::GetFlagRole(const uint32_t flag,
                                         uint32_t sem_class) {
  switch (flag) {
    case Flags::FLAG_NEGATIVE:
      return NegativeSignFlagRole;
    case Flags::FLAG_CARRY:
      return CarryFlagRole;
    case Flags::FLAG_OVERFLOW:
      return OverflowFlagRole;
    case Flags::FLAG_ZERO:
      return ZeroFlagRole;
    case Flags::FLAG_E:
      return SpecialFlagRole;
    default:
      BN::LogError("%s: Invalid id: %u", __func__, flag);
      return SpecialFlagRole;
  }
}

std::vector<uint32_t> C166Architecture::GetFlagsRequiredForFlagCondition(
    const BNLowLevelILFlagCondition cond, uint32_t) {
  switch (cond) {
    case LLFC_E:
    case LLFC_NE:
      return std::vector<uint32_t>{Flags::FLAG_ZERO};
    case LLFC_O:
    case LLFC_NO:
      return std::vector<uint32_t>{Flags::FLAG_OVERFLOW};
    case LLFC_NEG:
    case LLFC_POS:
      return std::vector<uint32_t>{Flags::FLAG_NEGATIVE};
    case LLFC_ULT:
    case LLFC_UGE:
      return std::vector<uint32_t>{Flags::FLAG_CARRY};
    case LLFC_ULE:
    case LLFC_UGT:
      return std::vector<uint32_t>{Flags::FLAG_CARRY, Flags::FLAG_ZERO};
    case LLFC_SLT:
    case LLFC_SGE:
      return std::vector<uint32_t>{Flags::FLAG_NEGATIVE, Flags::FLAG_OVERFLOW};
    case LLFC_SLE:
    case LLFC_SGT:
      return std::vector<uint32_t>{Flags::FLAG_ZERO, Flags::FLAG_NEGATIVE,
                                   Flags::FLAG_OVERFLOW};
    case LLFC_FE:
    case LLFC_FNE:
    case LLFC_FLT:
    case LLFC_FLE:
    case LLFC_FGE:
    case LLFC_FGT:
    case LLFC_FO:
    case LLFC_FUO:
    default:
      return {};
  }
}

bool C166Architecture::GetInstructionInfo(const uint8_t* data,
                                          const uint64_t addr,
                                          const size_t maxLen,
                                          BN::InstructionInfo& result) {
  const auto wdata = (const uint16_t*)data;
  const uint16_t raw = *wdata;

  switch (raw & 0xFFu) {
    /* 2-byte non-branching instructions */
    case Opcodes::ADD_RWN_RWM:
    case Opcodes::ADD_RWN_RWI_DATA3:
    case Opcodes::ADDB_RBN_RBM:
    case Opcodes::ADDB_RBN_RWI_DATA3:
    case Opcodes::ADDC_RWN_RWM:
    case Opcodes::ADDC_RWN_RWI_DATA3:
    case Opcodes::ADDCB_RBN_RBM:
    case Opcodes::ADDCB_RBN_RWI_DATA3:
    case Opcodes::AND_RWN_RWM:
    case Opcodes::AND_RWN_RWI_DATA3:
    case Opcodes::ANDB_RBN_RBM:
    case Opcodes::ANDB_RBN_RWI_DATA3:
    case Opcodes::ASHR_RWN_RWM:
    case Opcodes::ASHR_RWN_DATA4:
    case Opcodes::BCLR_0:
    case Opcodes::BCLR_1:
    case Opcodes::BCLR_2:
    case Opcodes::BCLR_3:
    case Opcodes::BCLR_4:
    case Opcodes::BCLR_5:
    case Opcodes::BCLR_6:
    case Opcodes::BCLR_7:
    case Opcodes::BCLR_8:
    case Opcodes::BCLR_9:
    case Opcodes::BCLR_A:
    case Opcodes::BCLR_B:
    case Opcodes::BCLR_C:
    case Opcodes::BCLR_D:
    case Opcodes::BCLR_E:
    case Opcodes::BCLR_F:
    case Opcodes::BSET_0:
    case Opcodes::BSET_1:
    case Opcodes::BSET_2:
    case Opcodes::BSET_3:
    case Opcodes::BSET_4:
    case Opcodes::BSET_5:
    case Opcodes::BSET_6:
    case Opcodes::BSET_7:
    case Opcodes::BSET_8:
    case Opcodes::BSET_9:
    case Opcodes::BSET_A:
    case Opcodes::BSET_B:
    case Opcodes::BSET_C:
    case Opcodes::BSET_D:
    case Opcodes::BSET_E:
    case Opcodes::BSET_F:
    case Opcodes::CMP_RWN_RWM:
    case Opcodes::CMP_RWN_RWI_DATA3:
    case Opcodes::CMPB_RBN_RBM:
    case Opcodes::CMPB_RBN_RWI_DATA3:
    case Opcodes::CMPD1_RWN_DATA4:
    case Opcodes::CMPD2_RWN_DATA4:
    case Opcodes::CMPI1_RWN_DATA4:
    case Opcodes::CMPI2_RWN_DATA4:
    case Opcodes::CPL:
    case Opcodes::CPLB:
    case Opcodes::DIV:
    case Opcodes::DIVL:
    case Opcodes::DIVLU:
    case Opcodes::DIVU:
    case Opcodes::EXTPRS_RWM_COUNT:
    case Opcodes::EXTR_ATOMIC:
    case Opcodes::MOV_RWN_RWM:
    case Opcodes::MOV_RWN_DATA4:
    case Opcodes::MOV_RWN_REF_RWM:
    case Opcodes::MOV_RWN_REF_POST_INC_RWM:
    case Opcodes::MOV_REF_RWM_RWN:
    case Opcodes::MOV_REF_PRE_DEC_RWM_RWN:
    case Opcodes::MOV_REF_RWN_REF_RWM:
    case Opcodes::MOV_REF_POST_INC_RWN_REF_RWM:
    case Opcodes::MOV_REF_RWN_REF_POST_INC_RWM:
    case Opcodes::MOVB_RBN_RBM:
    case Opcodes::MOVB_RBN_DATA4:
    case Opcodes::MOVB_RBN_REF_RWM:
    case Opcodes::MOVB_RBN_REF_POST_INC_RWM:
    case Opcodes::MOVB_REF_RWM_RBN:
    case Opcodes::MOVB_REF_PRE_DEC_RWM_RBN:
    case Opcodes::MOVB_REF_RWN_REF_RWM:
    case Opcodes::MOVB_REF_POST_INC_RWN_REF_RWM:
    case Opcodes::MOVB_REF_RWN_REF_POST_INC_RWM:
    case Opcodes::MOVBS_RWN_RBM:
    case Opcodes::MOVBZ_RWN_RBM:
    case Opcodes::MUL:
    case Opcodes::MULU:
    case Opcodes::NEG:
    case Opcodes::NEGB:
    case Opcodes::NOP:
    case Opcodes::OR_RWN_RWM:
    case Opcodes::OR_RWN_RWI_DATA3:
    case Opcodes::ORB_RBN_RBM:
    case Opcodes::ORB_RBN_RWI_DATA3:
    case Opcodes::POP:
    case Opcodes::PRIOR:
    case Opcodes::PUSH:
    case Opcodes::SHL_RWN_RWM:
    case Opcodes::SHL_RWN_DATA4:
    case Opcodes::SHR_RWN_RWM:
    case Opcodes::SHR_RWN_DATA4:
    case Opcodes::SUB_RWN_RWM:
    case Opcodes::SUB_RWN_RWI_DATA3:
    case Opcodes::SUBB_RBN_RBM:
    case Opcodes::SUBB_RBN_RWI_DATA3:
    case Opcodes::SUBC_RWN_RWM:
    case Opcodes::SUBC_RWN_RWI_DATA3:
    case Opcodes::SUBCB_RBN_RBM:
    case Opcodes::SUBCB_RBN_RWI_DATA3:
    case Opcodes::XOR_RWN_RWM:
    case Opcodes::XOR_RWN_RWI_DATA3:
    case Opcodes::XORB_RBN_RBM:
    case Opcodes::XORB_RBN_RWI_DATA3:
      result.length = 2;
      return true;

    /* 4-byte non-branching instructions */
    case Opcodes::ADD_REG_MEM:
    case Opcodes::ADD_MEM_REG:
    case Opcodes::ADD_REG_DATA16:
    case Opcodes::ADDB_REG_MEM:
    case Opcodes::ADDB_MEM_REG:
    case Opcodes::ADDB_REG_DATA8:
    case Opcodes::ADDC_REG_MEM:
    case Opcodes::ADDC_MEM_REG:
    case Opcodes::ADDC_REG_DATA16:
    case Opcodes::ADDCB_REG_MEM:
    case Opcodes::ADDCB_MEM_REG:
    case Opcodes::ADDCB_REG_DATA8:
    case Opcodes::AND_REG_MEM:
    case Opcodes::AND_MEM_REG:
    case Opcodes::AND_REG_DATA16:
    case Opcodes::ANDB_REG_MEM:
    case Opcodes::ANDB_MEM_REG:
    case Opcodes::ANDB_REG_DATA8:
    case Opcodes::BAND:
    case Opcodes::BCMP:
    case Opcodes::BFLDH:
    case Opcodes::BFLDL:
    case Opcodes::BMOV:
    case Opcodes::BMOVN:
    case Opcodes::BOR:
    case Opcodes::BXOR:
    case Opcodes::CMP_REG_MEM:
    case Opcodes::CMP_REG_DATA16:
    case Opcodes::CMPB_REG_MEM:
    case Opcodes::CMPB_REG_DATA8:
    case Opcodes::CMPD1_RWN_MEM:
    case Opcodes::CMPD1_RWN_DATA16:
    case Opcodes::CMPD2_RWN_MEM:
    case Opcodes::CMPD2_RWN_DATA16:
    case Opcodes::CMPI1_RWN_MEM:
    case Opcodes::CMPI1_RWN_DATA16:
    case Opcodes::CMPI2_RWN_MEM:
    case Opcodes::CMPI2_RWN_DATA16:
    case Opcodes::DISWDT:
    case Opcodes::EINIT:
    case Opcodes::EXTPRS_PAG_SEG_COUNT:
    case Opcodes::IDLE:
    case Opcodes::MOV_REG_DATA16:
    case Opcodes::MOV_RWN_REF_RWM_DATA16:
    case Opcodes::MOV_REF_RWM_DATA16_RWN:
    case Opcodes::MOV_REF_RWN_MEM:
    case Opcodes::MOV_MEM_REF_RWN:
    case Opcodes::MOV_REG_MEM:
    case Opcodes::MOV_MEM_REG:
    case Opcodes::MOVB_REG_DATA8:
    case Opcodes::MOVB_RBN_REF_RWM_DATA16:
    case Opcodes::MOVB_REF_RWM_DATA16_RBN:
    case Opcodes::MOVB_REF_RWN_MEM:
    case Opcodes::MOVB_MEM_REF_RWN:
    case Opcodes::MOVB_REG_MEM:
    case Opcodes::MOVB_MEM_REG:
    case Opcodes::MOVBS_REG_MEM:
    case Opcodes::MOVBS_MEM_REG:
    case Opcodes::MOVBZ_REG_MEM:
    case Opcodes::MOVBZ_MEM_REG:
    case Opcodes::OR_REG_DATA16:
    case Opcodes::OR_REG_MEM:
    case Opcodes::OR_MEM_REG:
    case Opcodes::ORB_REG_DATA8:
    case Opcodes::ORB_REG_MEM:
    case Opcodes::ORB_MEM_REG:
    case Opcodes::PWRDN:
    case Opcodes::ROL_RWN_RWM:
    case Opcodes::ROL_RWN_DATA4:
    case Opcodes::ROR_RWN_RWM:
    case Opcodes::ROR_RWN_DATA4:
    case Opcodes::SCXT_REG_DATA16:
    case Opcodes::SCXT_REG_MEM:
    case Opcodes::SRST:
    case Opcodes::SRVWDT:
    case Opcodes::SUB_REG_DATA16:
    case Opcodes::SUB_REG_MEM:
    case Opcodes::SUB_MEM_REG:
    case Opcodes::SUBB_REG_DATA8:
    case Opcodes::SUBB_REG_MEM:
    case Opcodes::SUBB_MEM_REG:
    case Opcodes::SUBC_REG_DATA16:
    case Opcodes::SUBC_REG_MEM:
    case Opcodes::SUBC_MEM_REG:
    case Opcodes::SUBCB_REG_DATA8:
    case Opcodes::SUBCB_REG_MEM:
    case Opcodes::SUBCB_MEM_REG:
    case Opcodes::XOR_REG_DATA16:
    case Opcodes::XOR_REG_MEM:
    case Opcodes::XOR_MEM_REG:
    case Opcodes::XORB_REG_DATA8:
    case Opcodes::XORB_REG_MEM:
    case Opcodes::XORB_MEM_REG:
      result.length = 4;
      return true;

    /* Branching instructions */
    case Opcodes::CALLA:
      return Calla::Info(data, addr, maxLen, result);
    case Opcodes::CALLI:
      return Calli::Info(data, addr, maxLen, result);
    case Opcodes::CALLR:
      return Callr::Info(data, addr, maxLen, result);
    case Opcodes::CALLS:
      return Calls::Info(data, addr, maxLen, result);
    case Opcodes::JB:
      return Jb::Info(data, addr, maxLen, result);
    case Opcodes::JBC:
      return Jbc::Info(data, addr, maxLen, result);
    case Opcodes::JMPI:
      return Jmpi::Info(data, addr, maxLen, result);
    case Opcodes::JMPA:
      return Jmpa::Info(data, addr, maxLen, result);
    case Opcodes::JMPR_UC:
    case Opcodes::JMPR_NET:
    case Opcodes::JMPR_Z:
    case Opcodes::JMPR_NZ:
    case Opcodes::JMPR_V:
    case Opcodes::JMPR_NV:
    case Opcodes::JMPR_N:
    case Opcodes::JMPR_NN:
    case Opcodes::JMPR_ULT:
    case Opcodes::JMPR_SGT:
    case Opcodes::JMPR_UGE:
    case Opcodes::JMPR_SLE:
    case Opcodes::JMPR_SLT:
    case Opcodes::JMPR_SGE:
    case Opcodes::JMPR_UGT:
    case Opcodes::JMPR_ULE:
      return Jmpr::Info(data, addr, maxLen, result);
    case Opcodes::JMPS:
      return Jmps::Info(data, addr, maxLen, result);
    case Opcodes::JNB:
      return Jnb::Info(data, addr, maxLen, result);
    case Opcodes::JNBS:
      return Jnbs::Info(data, addr, maxLen, result);
    case Opcodes::PCALL:
      return false;
    case Opcodes::RET:
    case Opcodes::RETP:
    case Opcodes::RETS:
    case Opcodes::RETI:
      result.AddBranch(FunctionReturn);
      result.length = 2;
      return true;
    case Opcodes::TRAP:
      return Trap::Info(data, addr, maxLen, result);
    default:
      return false;
  }
}

bool C166Architecture::GetInstructionLowLevelIL(const uint8_t* data,
                                                uint64_t addr, size_t& len,
                                                BN::LowLevelILFunction& il) {
  switch (const uint16_t op = (*(const uint16_t*)data) & 0xFFu) {
    /* 2-byte non-branching instructions */
    case Opcodes::ADD_RWN_RWM:
    case Opcodes::ADD_RWN_RWI_DATA3:
      return Add::Lift(op, data, addr, len, il);
    case Opcodes::ADDB_RBN_RBM:
    case Opcodes::ADDB_RBN_RWI_DATA3:
      return Addb::Lift(op, data, addr, len, il);
    case Opcodes::ADDC_RWN_RWM:
    case Opcodes::ADDC_RWN_RWI_DATA3:
      return Addc::Lift(op, data, addr, len, il);
    case Opcodes::ADDCB_RBN_RBM:
    case Opcodes::ADDCB_RBN_RWI_DATA3:
      return Addcb::Lift(op, data, addr, len, il);
    case Opcodes::AND_RWN_RWM:
    case Opcodes::AND_RWN_RWI_DATA3:
      return And::Lift(op, data, addr, len, il);
    case Opcodes::ANDB_RBN_RBM:
    case Opcodes::ANDB_RBN_RWI_DATA3:
      return Andb::Lift(op, data, addr, len, il);
    case Opcodes::ASHR_RWN_RWM:
      return Ashr::LiftxAC(data, addr, len, il);
    case Opcodes::ASHR_RWN_DATA4:
      return Ashr::LiftxBC(data, addr, len, il);
    case Opcodes::BCLR_0:
    case Opcodes::BCLR_1:
    case Opcodes::BCLR_2:
    case Opcodes::BCLR_3:
    case Opcodes::BCLR_4:
    case Opcodes::BCLR_5:
    case Opcodes::BCLR_6:
    case Opcodes::BCLR_7:
    case Opcodes::BCLR_8:
    case Opcodes::BCLR_9:
    case Opcodes::BCLR_A:
    case Opcodes::BCLR_B:
    case Opcodes::BCLR_C:
    case Opcodes::BCLR_D:
    case Opcodes::BCLR_E:
    case Opcodes::BCLR_F:
      return Bclr::Lift(data, addr, len, il);
    case Opcodes::BSET_0:
    case Opcodes::BSET_1:
    case Opcodes::BSET_2:
    case Opcodes::BSET_3:
    case Opcodes::BSET_4:
    case Opcodes::BSET_5:
    case Opcodes::BSET_6:
    case Opcodes::BSET_7:
    case Opcodes::BSET_8:
    case Opcodes::BSET_9:
    case Opcodes::BSET_A:
    case Opcodes::BSET_B:
    case Opcodes::BSET_C:
    case Opcodes::BSET_D:
    case Opcodes::BSET_E:
    case Opcodes::BSET_F:
      return Bset::Lift(data, addr, len, il);
    case Opcodes::CMP_RWN_RWM:
    case Opcodes::CMP_RWN_RWI_DATA3:
      return Cmp::Lift(op, data, addr, len, il);
    case Opcodes::CMPB_RBN_RWI_DATA3:
    case Opcodes::CMPB_RBN_RBM:
      return Cmpb::Lift(op, data, addr, len, il);
    case Opcodes::CMPD1_RWN_DATA4:
      return Cmpd1::LiftxA0(data, addr, len, il);
    case Opcodes::CMPD2_RWN_DATA4:
      return Cmpd2::LiftxB0(data, addr, len, il);
    case Opcodes::CMPI1_RWN_DATA4:
      return Cmpi1::Liftx80(data, addr, len, il);
    case Opcodes::CMPI2_RWN_DATA4:
      return Cmpi2::Liftx90(data, addr, len, il);
    case Opcodes::CPL:
      return Cpl::Lift(data, addr, len, il);
    case Opcodes::CPLB:
      return Cplb::Lift(data, addr, len, il);
    case Opcodes::DIV:
      return Div::Lift(data, addr, len, il);
    case Opcodes::DIVL:
      return Divl::Lift(data, addr, len, il);
    case Opcodes::DIVLU:
      return Divlu::Lift(data, addr, len, il);
    case Opcodes::DIVU:
      return Divu::Lift(data, addr, len, il);
    case Opcodes::EXTPRS_RWM_COUNT:
      return Extprs::LiftxDC(data, addr, len, il);
    case Opcodes::EXTR_ATOMIC:
      return ExtrAtomic::Lift(data, addr, len, il);
    case Opcodes::MOV_RWN_RWM:
      return Mov::LiftxF0(data, addr, len, il);
    case Opcodes::MOV_RWN_DATA4:
      return Mov::LiftxE0(data, addr, len, il);
    case Opcodes::MOV_RWN_REF_RWM:
      return Mov::LiftxA8(data, addr, len, il);
    case Opcodes::MOV_RWN_REF_POST_INC_RWM:
      return Mov::Liftx98(data, addr, len, il);
    case Opcodes::MOV_REF_RWM_RWN:
      return Mov::LiftxB8(data, addr, len, il);
    case Opcodes::MOV_REF_PRE_DEC_RWM_RWN:
      return Mov::Liftx88(data, addr, len, il);
    case Opcodes::MOV_REF_RWN_REF_RWM:
      return Mov::LiftxC8(data, addr, len, il);
    case Opcodes::MOV_REF_POST_INC_RWN_REF_RWM:
      return Mov::LiftxD8(data, addr, len, il);
    case Opcodes::MOV_REF_RWN_REF_POST_INC_RWM:
      return Mov::LiftxE8(data, addr, len, il);
    case Opcodes::MOVB_RBN_RBM:
      return Movb::LiftxF1(data, addr, len, il);
    case Opcodes::MOVB_RBN_DATA4:
      return Movb::LiftxE1(data, addr, len, il);
    case Opcodes::MOVB_RBN_REF_RWM:
      return Movb::LiftxA9(data, addr, len, il);
    case Opcodes::MOVB_RBN_REF_POST_INC_RWM:
      return Movb::Liftx99(data, addr, len, il);
    case Opcodes::MOVB_REF_RWM_RBN:
      return Movb::LiftxB9(data, addr, len, il);
    case Opcodes::MOVB_REF_PRE_DEC_RWM_RBN:
      return Movb::Liftx89(data, addr, len, il);
    case Opcodes::MOVB_REF_RWN_REF_RWM:
      return Movb::LiftxC9(data, addr, len, il);
    case Opcodes::MOVB_REF_POST_INC_RWN_REF_RWM:
      return Movb::LiftxD9(data, addr, len, il);
    case Opcodes::MOVB_REF_RWN_REF_POST_INC_RWM:
      return Movb::LiftxE9(data, addr, len, il);
    case Opcodes::MOVBS_RWN_RBM:
      return Movbs::LiftxD0(data, addr, len, il);
    case Opcodes::MOVBZ_RWN_RBM:
      return Movbz::LiftxC0(data, addr, len, il);
    case Opcodes::MUL:
      return Mul::Lift(data, addr, len, il);
    case Opcodes::MULU:
      return Mulu::Lift(data, addr, len, il);
    case Opcodes::NEG:
      return Neg::Lift(data, addr, len, il);
    case Opcodes::NEGB:
      return Negb::Lift(data, addr, len, il);
    case Opcodes::NOP:
      return Nop::Lift(data, addr, len, il);
    case Opcodes::OR_RWN_RWM:
    case Opcodes::OR_RWN_RWI_DATA3:
      return Or::Lift(op, data, addr, len, il);
    case Opcodes::ORB_RBN_RBM:
    case Opcodes::ORB_RBN_RWI_DATA3:
      return Orb::Lift(op, data, addr, len, il);
    case Opcodes::POP:
      return Pop::Lift(data, addr, len, il);
    case Opcodes::PRIOR:
      return Prior::Lift(data, addr, len, il);
    case Opcodes::PUSH:
      return Push::Lift(data, addr, len, il);
    case Opcodes::SHL_RWN_RWM:
      return Shl::Liftx4C(data, addr, len, il);
    case Opcodes::SHL_RWN_DATA4:
      return Shl::Liftx5C(data, addr, len, il);
    case Opcodes::SHR_RWN_RWM:
      return Shr::Liftx6C(data, addr, len, il);
    case Opcodes::SHR_RWN_DATA4:
      return Shr::Liftx7C(data, addr, len, il);
    case Opcodes::SUB_RWN_RWM:
    case Opcodes::SUB_RWN_RWI_DATA3:
      return Sub::Lift(op, data, addr, len, il);
    case Opcodes::SUBB_RBN_RBM:
    case Opcodes::SUBB_RBN_RWI_DATA3:
      return Subb::Lift(op, data, addr, len, il);
    case Opcodes::SUBC_RWN_RWM:
    case Opcodes::SUBC_RWN_RWI_DATA3:
      return Subc::Lift(op, data, addr, len, il);
    case Opcodes::SUBCB_RBN_RBM:
    case Opcodes::SUBCB_RBN_RWI_DATA3:
      return Subcb::Lift(op, data, addr, len, il);
    case Opcodes::XOR_RWN_RWM:
    case Opcodes::XOR_RWN_RWI_DATA3:
      return Xor::Lift(op, data, addr, len, il);
    case Opcodes::XORB_RBN_RBM:
    case Opcodes::XORB_RBN_RWI_DATA3:
      return Xorb::Lift(op, data, addr, len, il);

    /* 4-byte non-branching instructions */
    case Opcodes::ADD_REG_MEM:
    case Opcodes::ADD_MEM_REG:
    case Opcodes::ADD_REG_DATA16:
      return Add::Lift(op, data, addr, len, il);
    case Opcodes::ADDB_REG_MEM:
    case Opcodes::ADDB_MEM_REG:
    case Opcodes::ADDB_REG_DATA8:
      return Addb::Lift(op, data, addr, len, il);
    case Opcodes::ADDC_REG_MEM:
    case Opcodes::ADDC_MEM_REG:
    case Opcodes::ADDC_REG_DATA16:
      return Addc::Lift(op, data, addr, len, il);
    case Opcodes::ADDCB_REG_MEM:
    case Opcodes::ADDCB_MEM_REG:
    case Opcodes::ADDCB_REG_DATA8:
      return Addcb::Lift(op, data, addr, len, il);
    case Opcodes::AND_REG_MEM:
    case Opcodes::AND_MEM_REG:
    case Opcodes::AND_REG_DATA16:
      return And::Lift(op, data, addr, len, il);
    case Opcodes::ANDB_REG_MEM:
    case Opcodes::ANDB_MEM_REG:
    case Opcodes::ANDB_REG_DATA8:
      return Andb::Lift(op, data, addr, len, il);
    case Opcodes::BAND:
      return Band::Lift(data, addr, len, il);
    case Opcodes::BCMP:
      return Bcmp::Lift(data, addr, len, il);
    case Opcodes::BFLDH:
      return Bfldh::Lift(data, addr, len, il);
    case Opcodes::BFLDL:
      return Bfldl::Lift(data, addr, len, il);
    case Opcodes::BMOV:
      return Bmov::Lift(data, addr, len, il);
    case Opcodes::BMOVN:
      return Bmovn::Lift(data, addr, len, il);
    case Opcodes::BOR:
      return Bor::Lift(data, addr, len, il);
    case Opcodes::BXOR:
      return Bxor::Lift(data, addr, len, il);
    case Opcodes::CMP_REG_DATA16:
    case Opcodes::CMP_REG_MEM:
      return Cmp::Lift(op, data, addr, len, il);
    case Opcodes::CMPB_REG_DATA8:
    case Opcodes::CMPB_REG_MEM:
      return Cmpb::Lift(op, data, addr, len, il);
    case Opcodes::CMPD1_RWN_MEM:
      return Cmpd1::LiftxA2(data, addr, len, il);
    case Opcodes::CMPD1_RWN_DATA16:
      return Cmpd1::LiftxA6(data, addr, len, il);
    case Opcodes::CMPD2_RWN_MEM:
      return Cmpd2::LiftxB2(data, addr, len, il);
    case Opcodes::CMPD2_RWN_DATA16:
      return Cmpd2::LiftxB6(data, addr, len, il);
    case Opcodes::CMPI1_RWN_MEM:
      return Cmpi1::Liftx82(data, addr, len, il);
    case Opcodes::CMPI1_RWN_DATA16:
      return Cmpi1::Liftx86(data, addr, len, il);
    case Opcodes::CMPI2_RWN_MEM:
      return Cmpi2::Liftx92(data, addr, len, il);
    case Opcodes::CMPI2_RWN_DATA16:
      return Cmpi2::Liftx96(data, addr, len, il);
    case Opcodes::DISWDT:
      return Diswdt::Lift(data, addr, len, il);
    case Opcodes::EINIT:
      return Einit::Lift(data, addr, len, il);
    case Opcodes::EXTPRS_PAG_SEG_COUNT:
      return Extprs::LiftxD7(data, addr, len, il);
    case Opcodes::IDLE:
      return Idle::Lift(data, addr, len, il);
    case Opcodes::MOV_REG_DATA16:
      return Mov::LiftxE6(data, addr, len, il);
    case Opcodes::MOV_RWN_REF_RWM_DATA16:
      return Mov::LiftxD4(data, addr, len, il);
    case Opcodes::MOV_REF_RWM_DATA16_RWN:
      return Mov::LiftxC4(data, addr, len, il);
    case Opcodes::MOV_REF_RWN_MEM:
      return Mov::Liftx84(data, addr, len, il);
    case Opcodes::MOV_MEM_REF_RWN:
      return Mov::Liftx94(data, addr, len, il);
    case Opcodes::MOV_REG_MEM:
      return Mov::LiftxF2(data, addr, len, il);
    case Opcodes::MOV_MEM_REG:
      return Mov::LiftxF6(data, addr, len, il);
    case Opcodes::MOVB_REG_DATA8:
      return Movb::LiftxE7(data, addr, len, il);
    case Opcodes::MOVB_RBN_REF_RWM_DATA16:
      return Movb::LiftxF4(data, addr, len, il);
    case Opcodes::MOVB_REF_RWM_DATA16_RBN:
      return Movb::LiftxE4(data, addr, len, il);
    case Opcodes::MOVB_REF_RWN_MEM:
      return Movb::LiftxA4(data, addr, len, il);
    case Opcodes::MOVB_MEM_REF_RWN:
      return Movb::LiftxB4(data, addr, len, il);
    case Opcodes::MOVB_REG_MEM:
      return Movb::LiftxF3(data, addr, len, il);
    case Opcodes::MOVB_MEM_REG:
      return Movb::LiftxF7(data, addr, len, il);
    case Opcodes::MOVBS_REG_MEM:
      return Movbs::LiftxD2(data, addr, len, il);
    case Opcodes::MOVBS_MEM_REG:
      return Movbs::LiftxD5(data, addr, len, il);
    case Opcodes::MOVBZ_REG_MEM:
      return Movbz::LiftxC2(data, addr, len, il);
    case Opcodes::MOVBZ_MEM_REG:
      return Movbz::LiftxC5(data, addr, len, il);
    case Opcodes::OR_REG_DATA16:
    case Opcodes::OR_REG_MEM:
    case Opcodes::OR_MEM_REG:
      return Or::Lift(op, data, addr, len, il);
    case Opcodes::ORB_REG_DATA8:
    case Opcodes::ORB_REG_MEM:
    case Opcodes::ORB_MEM_REG:
      return Orb::Lift(op, data, addr, len, il);
    case Opcodes::PWRDN:
      return Pwrdn::Lift(data, addr, len, il);
    case Opcodes::ROL_RWN_RWM:
      return Rol::Liftx0C(data, addr, len, il);
    case Opcodes::ROL_RWN_DATA4:
      return Rol::Liftx1C(data, addr, len, il);
    case Opcodes::ROR_RWN_RWM:
      return Ror::Liftx2C(data, addr, len, il);
    case Opcodes::ROR_RWN_DATA4:
      return Ror::Liftx3C(data, addr, len, il);
    case Opcodes::SCXT_REG_DATA16:
      return Scxt::LiftxC6(data, addr, len, il);
    case Opcodes::SCXT_REG_MEM:
      return Scxt::LiftxD6(data, addr, len, il);
    case Opcodes::SRST:
      return Srst::Lift(data, addr, len, il);
    case Opcodes::SRVWDT:
      return Srvwdt::Lift(data, addr, len, il);
    case Opcodes::SUB_REG_DATA16:
    case Opcodes::SUB_REG_MEM:
    case Opcodes::SUB_MEM_REG:
      return Sub::Lift(op, data, addr, len, il);
    case Opcodes::SUBB_REG_DATA8:
    case Opcodes::SUBB_REG_MEM:
    case Opcodes::SUBB_MEM_REG:
      return Subb::Lift(op, data, addr, len, il);
    case Opcodes::SUBC_REG_DATA16:
    case Opcodes::SUBC_REG_MEM:
    case Opcodes::SUBC_MEM_REG:
      return Subc::Lift(op, data, addr, len, il);
    case Opcodes::SUBCB_REG_DATA8:
    case Opcodes::SUBCB_REG_MEM:
    case Opcodes::SUBCB_MEM_REG:
      return Subcb::Lift(op, data, addr, len, il);
    case Opcodes::XOR_REG_DATA16:
    case Opcodes::XOR_REG_MEM:
    case Opcodes::XOR_MEM_REG:
      return Xor::Lift(op, data, addr, len, il);
    case Opcodes::XORB_REG_DATA8:
    case Opcodes::XORB_REG_MEM:
    case Opcodes::XORB_MEM_REG:
      return Xorb::Lift(op, data, addr, len, il);

    /* Branching instructions */
    case Opcodes::CALLA:
      return Calla::Lift(this, data, addr, len, il);
    case Opcodes::CALLI:
      return Calli::Lift(this, data, addr, len, il);
    case Opcodes::CALLR:
      return Callr::Lift(this, data, addr, len, il);
    case Opcodes::CALLS:
      return Calls::Lift(this, data, addr, len, il);
    case Opcodes::JB:
      return Jb::Lift(this, data, addr, len, il);
    case Opcodes::JBC:
      return Jbc::Lift(this, data, addr, len, il);
    case Opcodes::JMPI:
      return Jmpi::Lift(this, data, addr, len, il);
    case Opcodes::JMPA:
      return Jmpa::Lift(this, data, addr, len, il);
    case Opcodes::JMPR_UC:
    case Opcodes::JMPR_NET:
    case Opcodes::JMPR_Z:
    case Opcodes::JMPR_NZ:
    case Opcodes::JMPR_V:
    case Opcodes::JMPR_NV:
    case Opcodes::JMPR_N:
    case Opcodes::JMPR_NN:
    case Opcodes::JMPR_ULT:
    case Opcodes::JMPR_SGT:
    case Opcodes::JMPR_UGE:
    case Opcodes::JMPR_SLE:
    case Opcodes::JMPR_SLT:
    case Opcodes::JMPR_SGE:
    case Opcodes::JMPR_UGT:
    case Opcodes::JMPR_ULE:
      return Jmpr::Lift(this, data, addr, len, il);
    case Opcodes::JMPS:
      return Jmps::Lift(this, data, addr, len, il);
    case Opcodes::JNB:
      return Jnb::Lift(this, data, addr, len, il);
    case Opcodes::JNBS:
      return Jnbs::Lift(this, data, addr, len, il);
    case Opcodes::PCALL:
      // TODO: BRANCH
      return false;
    case Opcodes::RET:
      return Ret::Lift(data, addr, len, il);
    case Opcodes::RETP:
      return Retp::Lift(data, addr, len, il);
    case Opcodes::RETS:
      return Rets::Lift(data, addr, len, il);
    case Opcodes::RETI:
      return Reti::Lift(data, addr, len, il);
    case Opcodes::TRAP:
      return Trap::Lift(data, addr, len, il);
    default:
      return false;
  }
}

bool C166Architecture::GetInstructionText(
    const uint8_t* data, uint64_t addr, size_t& len,
    std::vector<BN::InstructionTextToken>& result) {
  switch (const uint16_t op = (*(const uint16_t*)data) & 0xFFu) {
    /* 2-byte non-branching instructions */
    case Opcodes::ADD_RWN_RWM:
    case Opcodes::ADD_RWN_RWI_DATA3:
      return Add::Text(op, data, addr, len, result);
    case Opcodes::ADDB_RBN_RBM:
    case Opcodes::ADDB_RBN_RWI_DATA3:
      return Addb::Text(op, data, addr, len, result);
    case Opcodes::ADDC_RWN_RWM:
    case Opcodes::ADDC_RWN_RWI_DATA3:
      return Addc::Text(op, data, addr, len, result);
    case Opcodes::ADDCB_RBN_RBM:
    case Opcodes::ADDCB_RBN_RWI_DATA3:
      return Addcb::Text(op, data, addr, len, result);
    case Opcodes::AND_RWN_RWM:
    case Opcodes::AND_RWN_RWI_DATA3:
      return And::Text(op, data, addr, len, result);
    case Opcodes::ANDB_RBN_RBM:
    case Opcodes::ANDB_RBN_RWI_DATA3:
      return Andb::Text(op, data, addr, len, result);
    case Opcodes::ASHR_RWN_RWM:
      return Ashr::TextxAC(data, addr, len, result);
    case Opcodes::ASHR_RWN_DATA4:
      return Ashr::TextxBC(data, addr, len, result);
    case Opcodes::BCLR_0:
    case Opcodes::BCLR_1:
    case Opcodes::BCLR_2:
    case Opcodes::BCLR_3:
    case Opcodes::BCLR_4:
    case Opcodes::BCLR_5:
    case Opcodes::BCLR_6:
    case Opcodes::BCLR_7:
    case Opcodes::BCLR_8:
    case Opcodes::BCLR_9:
    case Opcodes::BCLR_A:
    case Opcodes::BCLR_B:
    case Opcodes::BCLR_C:
    case Opcodes::BCLR_D:
    case Opcodes::BCLR_E:
    case Opcodes::BCLR_F:
      return Bclr::Text(data, addr, len, result);
    case Opcodes::BSET_0:
    case Opcodes::BSET_1:
    case Opcodes::BSET_2:
    case Opcodes::BSET_3:
    case Opcodes::BSET_4:
    case Opcodes::BSET_5:
    case Opcodes::BSET_6:
    case Opcodes::BSET_7:
    case Opcodes::BSET_8:
    case Opcodes::BSET_9:
    case Opcodes::BSET_A:
    case Opcodes::BSET_B:
    case Opcodes::BSET_C:
    case Opcodes::BSET_D:
    case Opcodes::BSET_E:
    case Opcodes::BSET_F:
      return Bset::Text(data, addr, len, result);
    case Opcodes::CMP_RWN_RWM:
    case Opcodes::CMP_RWN_RWI_DATA3:
      return Cmp::Text(op, data, addr, len, result);
    case Opcodes::CMPB_RBN_RBM:
    case Opcodes::CMPB_RBN_RWI_DATA3:
      return Cmpb::Text(op, data, addr, len, result);
    case Opcodes::CMPD1_RWN_DATA4:
      return Cmpd1::TextxA0(data, addr, len, result);
    case Opcodes::CMPD2_RWN_DATA4:
      return Cmpd2::TextxB0(data, addr, len, result);
    case Opcodes::CMPI1_RWN_DATA4:
      return Cmpi1::Textx80(data, addr, len, result);
    case Opcodes::CMPI2_RWN_DATA4:
      return Cmpi2::Textx90(data, addr, len, result);
    case Opcodes::CPL:
      return Cpl::Text(data, addr, len, result);
    case Opcodes::CPLB:
      return Cplb::Text(data, addr, len, result);
    case Opcodes::DIV:
      return Div::Text(data, addr, len, result);
    case Opcodes::DIVL:
      return Divl::Text(data, addr, len, result);
    case Opcodes::DIVLU:
      return Divlu::Text(data, addr, len, result);
    case Opcodes::DIVU:
      return Divu::Text(data, addr, len, result);
    case Opcodes::EXTPRS_PAG_SEG_COUNT:
      return Extprs::TextxD7(data, addr, len, result);
    case Opcodes::EXTR_ATOMIC:
      return ExtrAtomic::Text(data, addr, len, result);
    case Opcodes::MOV_RWN_RWM:
      return Mov::TextxF0(data, addr, len, result);
    case Opcodes::MOV_RWN_DATA4:
      return Mov::TextxE0(data, addr, len, result);
    case Opcodes::MOV_RWN_REF_RWM:
      return Mov::TextxA8(data, addr, len, result);
    case Opcodes::MOV_RWN_REF_POST_INC_RWM:
      return Mov::Textx98(data, addr, len, result);
    case Opcodes::MOV_REF_RWM_RWN:
      return Mov::TextxB8(data, addr, len, result);
    case Opcodes::MOV_REF_PRE_DEC_RWM_RWN:
      return Mov::Textx88(data, addr, len, result);
    case Opcodes::MOV_REF_RWN_REF_RWM:
      return Mov::TextxC8(data, addr, len, result);
    case Opcodes::MOV_REF_POST_INC_RWN_REF_RWM:
      return Mov::TextxD8(data, addr, len, result);
    case Opcodes::MOV_REF_RWN_REF_POST_INC_RWM:
      return Mov::TextxE8(data, addr, len, result);
    case Opcodes::MOVB_RBN_RBM:
      return Movb::TextxF1(data, addr, len, result);
    case Opcodes::MOVB_RBN_DATA4:
      return Movb::TextxE1(data, addr, len, result);
    case Opcodes::MOVB_RBN_REF_RWM:
      return Movb::TextxA9(data, addr, len, result);
    case Opcodes::MOVB_RBN_REF_POST_INC_RWM:
      return Movb::Textx99(data, addr, len, result);
    case Opcodes::MOVB_REF_RWM_RBN:
      return Movb::TextxB9(data, addr, len, result);
    case Opcodes::MOVB_REF_PRE_DEC_RWM_RBN:
      return Movb::Textx89(data, addr, len, result);
    case Opcodes::MOVB_REF_RWN_REF_RWM:
      return Movb::TextxC9(data, addr, len, result);
    case Opcodes::MOVB_REF_POST_INC_RWN_REF_RWM:
      return Movb::TextxD9(data, addr, len, result);
    case Opcodes::MOVB_REF_RWN_REF_POST_INC_RWM:
      return Movb::TextxE9(data, addr, len, result);
    case Opcodes::MOVBS_RWN_RBM:
      return Movbs::TextxD0(data, addr, len, result);
    case Opcodes::MOVBZ_RWN_RBM:
      return Movbz::TextxC0(data, addr, len, result);
    case Opcodes::MUL:
      return Mul::Text(data, addr, len, result);
    case Opcodes::MULU:
      return Mulu::Text(data, addr, len, result);
    case Opcodes::NEG:
      return Neg::Text(data, addr, len, result);
    case Opcodes::NEGB:
      return Negb::Text(data, addr, len, result);
    case Opcodes::NOP:
      return Nop::Text(data, addr, len, result);
    case Opcodes::OR_RWN_RWM:
    case Opcodes::OR_RWN_RWI_DATA3:
      return Or::Text(op, data, addr, len, result);
    case Opcodes::ORB_RBN_RBM:
    case Opcodes::ORB_RBN_RWI_DATA3:
      return Orb::Text(op, data, addr, len, result);
    case Opcodes::POP:
      return Pop::Text(data, addr, len, result);
    case Opcodes::PRIOR:
      return Prior::Text(data, addr, len, result);
    case Opcodes::PUSH:
      return Push::Text(data, addr, len, result);
    case Opcodes::SHL_RWN_RWM:
      return Shl::Textx4C(data, addr, len, result);
    case Opcodes::SHL_RWN_DATA4:
      return Shl::Textx5C(data, addr, len, result);
    case Opcodes::SHR_RWN_RWM:
      return Shr::Textx6C(data, addr, len, result);
    case Opcodes::SHR_RWN_DATA4:
      return Shr::Textx7C(data, addr, len, result);
    case Opcodes::SUB_RWN_RWM:
    case Opcodes::SUB_RWN_RWI_DATA3:
      return Sub::Text(op, data, addr, len, result);
    case Opcodes::SUBB_RBN_RBM:
    case Opcodes::SUBB_RBN_RWI_DATA3:
      return Subb::Text(op, data, addr, len, result);
    case Opcodes::SUBC_RWN_RWM:
    case Opcodes::SUBC_RWN_RWI_DATA3:
      return Subc::Text(op, data, addr, len, result);
    case Opcodes::SUBCB_RBN_RBM:
    case Opcodes::SUBCB_RBN_RWI_DATA3:
      return Subcb::Text(op, data, addr, len, result);
    case Opcodes::XOR_RWN_RWM:
    case Opcodes::XOR_RWN_RWI_DATA3:
      return Xor::Text(op, data, addr, len, result);
    case Opcodes::XORB_RBN_RBM:
    case Opcodes::XORB_RBN_RWI_DATA3:
      return Xorb::Text(op, data, addr, len, result);

    /* 4-byte non-branching instructions */
    case Opcodes::ADD_REG_DATA16:
    case Opcodes::ADD_REG_MEM:
    case Opcodes::ADD_MEM_REG:
      return Add::Text(op, data, addr, len, result);
    case Opcodes::ADDB_REG_MEM:
    case Opcodes::ADDB_MEM_REG:
    case Opcodes::ADDB_REG_DATA8:
      return Addb::Text(op, data, addr, len, result);
    case Opcodes::ADDC_REG_DATA16:
    case Opcodes::ADDC_REG_MEM:
    case Opcodes::ADDC_MEM_REG:
      return Addc::Text(op, data, addr, len, result);
    case Opcodes::ADDCB_REG_MEM:
    case Opcodes::ADDCB_MEM_REG:
    case Opcodes::ADDCB_REG_DATA8:
      return Addcb::Text(op, data, addr, len, result);
    case Opcodes::AND_REG_DATA16:
    case Opcodes::AND_REG_MEM:
    case Opcodes::AND_MEM_REG:
      return And::Text(op, data, addr, len, result);
    case Opcodes::ANDB_REG_MEM:
    case Opcodes::ANDB_MEM_REG:
    case Opcodes::ANDB_REG_DATA8:
      return Andb::Text(op, data, addr, len, result);
    case Opcodes::BAND:
      return Band::Text(data, addr, len, result);
    case Opcodes::BCMP:
      return Bcmp::Text(data, addr, len, result);
    case Opcodes::BFLDH:
      return Bfldh::Text(data, addr, len, result);
    case Opcodes::BFLDL:
      return Bfldl::Text(data, addr, len, result);
    case Opcodes::BMOV:
      return Bmov::Text(data, addr, len, result);
    case Opcodes::BMOVN:
      return Bmovn::Text(data, addr, len, result);
    case Opcodes::BOR:
      return Bor::Text(data, addr, len, result);
    case Opcodes::BXOR:
      return Bxor::Text(data, addr, len, result);
    case Opcodes::CMP_REG_DATA16:
    case Opcodes::CMP_REG_MEM:
      return Cmp::Text(op, data, addr, len, result);
    case Opcodes::CMPB_REG_DATA8:
    case Opcodes::CMPB_REG_MEM:
      return Cmpb::Text(op, data, addr, len, result);
    case Opcodes::CMPD1_RWN_MEM:
      return Cmpd1::TextxA2(data, addr, len, result);
    case Opcodes::CMPD1_RWN_DATA16:
      return Cmpd1::TextxA6(data, addr, len, result);
    case Opcodes::CMPD2_RWN_MEM:
      return Cmpd2::TextxB2(data, addr, len, result);
    case Opcodes::CMPD2_RWN_DATA16:
      return Cmpd2::TextxB6(data, addr, len, result);
    case Opcodes::CMPI1_RWN_MEM:
      return Cmpi1::Textx82(data, addr, len, result);
    case Opcodes::CMPI1_RWN_DATA16:
      return Cmpi1::Textx86(data, addr, len, result);
    case Opcodes::CMPI2_RWN_MEM:
      return Cmpi2::Textx92(data, addr, len, result);
    case Opcodes::CMPI2_RWN_DATA16:
      return Cmpi2::Textx96(data, addr, len, result);
    case Opcodes::DISWDT:
      return Diswdt::Text(data, addr, len, result);
    case Opcodes::EINIT:
      return Einit::Text(data, addr, len, result);
    case Opcodes::EXTPRS_RWM_COUNT:
      return Extprs::TextxDC(data, addr, len, result);
    case Opcodes::IDLE:
      return Idle::Text(data, addr, len, result);
    case Opcodes::MOV_REG_DATA16:
      return Mov::TextxE6(data, addr, len, result);
    case Opcodes::MOV_RWN_REF_RWM_DATA16:
      return Mov::TextxD4(data, addr, len, result);
    case Opcodes::MOV_REF_RWM_DATA16_RWN:
      return Mov::TextxC4(data, addr, len, result);
    case Opcodes::MOV_REF_RWN_MEM:
      return Mov::Textx84(data, addr, len, result);
    case Opcodes::MOV_MEM_REF_RWN:
      return Mov::Textx94(data, addr, len, result);
    case Opcodes::MOV_REG_MEM:
      return Mov::TextxF2(data, addr, len, result);
    case Opcodes::MOV_MEM_REG:
      return Mov::TextxF6(data, addr, len, result);
    case Opcodes::MOVB_REG_DATA8:
      return Movb::TextxE7(data, addr, len, result);
    case Opcodes::MOVB_RBN_REF_RWM_DATA16:
      return Movb::TextxF4(data, addr, len, result);
    case Opcodes::MOVB_REF_RWM_DATA16_RBN:
      return Movb::TextxE4(data, addr, len, result);
    case Opcodes::MOVB_REF_RWN_MEM:
      return Movb::TextxA4(data, addr, len, result);
    case Opcodes::MOVB_MEM_REF_RWN:
      return Movb::TextxB4(data, addr, len, result);
    case Opcodes::MOVB_REG_MEM:
      return Movb::TextxF3(data, addr, len, result);
    case Opcodes::MOVB_MEM_REG:
      return Movb::TextxF7(data, addr, len, result);
    case Opcodes::MOVBS_REG_MEM:
      return Movbs::TextxD2(data, addr, len, result);
    case Opcodes::MOVBS_MEM_REG:
      return Movbs::TextxD5(data, addr, len, result);
    case Opcodes::MOVBZ_REG_MEM:
      return Movbz::TextxC2(data, addr, len, result);
    case Opcodes::MOVBZ_MEM_REG:
      return Movbz::TextxC5(data, addr, len, result);
    case Opcodes::OR_REG_DATA16:
    case Opcodes::OR_REG_MEM:
    case Opcodes::OR_MEM_REG:
      return Or::Text(op, data, addr, len, result);
    case Opcodes::ORB_REG_DATA8:
    case Opcodes::ORB_REG_MEM:
    case Opcodes::ORB_MEM_REG:
      return Orb::Text(op, data, addr, len, result);
    case Opcodes::PWRDN:
      return Pwrdn::Text(data, addr, len, result);
    case Opcodes::ROL_RWN_RWM:
      return Rol::Textx0C(data, addr, len, result);
    case Opcodes::ROL_RWN_DATA4:
      return Rol::Textx1C(data, addr, len, result);
    case Opcodes::ROR_RWN_RWM:
      return Ror::Textx2C(data, addr, len, result);
    case Opcodes::ROR_RWN_DATA4:
      return Ror::Textx3C(data, addr, len, result);
    case Opcodes::SCXT_REG_DATA16:
      return Scxt::TextxC6(data, addr, len, result);
    case Opcodes::SCXT_REG_MEM:
      return Scxt::TextxD6(data, addr, len, result);
    case Opcodes::SRST:
      return Srst::Text(data, addr, len, result);
    case Opcodes::SRVWDT:
      return Srvwdt::Text(data, addr, len, result);
    case Opcodes::SUB_REG_DATA16:
    case Opcodes::SUB_REG_MEM:
    case Opcodes::SUB_MEM_REG:
      return Sub::Text(op, data, addr, len, result);
    case Opcodes::SUBB_REG_DATA8:
    case Opcodes::SUBB_REG_MEM:
    case Opcodes::SUBB_MEM_REG:
      return Subb::Text(op, data, addr, len, result);
    case Opcodes::SUBC_REG_DATA16:
    case Opcodes::SUBC_REG_MEM:
    case Opcodes::SUBC_MEM_REG:
      return Subc::Text(op, data, addr, len, result);
    case Opcodes::SUBCB_REG_DATA8:
    case Opcodes::SUBCB_REG_MEM:
    case Opcodes::SUBCB_MEM_REG:
      return Subcb::Text(op, data, addr, len, result);
    case Opcodes::XOR_REG_DATA16:
    case Opcodes::XOR_REG_MEM:
    case Opcodes::XOR_MEM_REG:
      return Xor::Text(op, data, addr, len, result);
    case Opcodes::XORB_REG_DATA8:
    case Opcodes::XORB_REG_MEM:
    case Opcodes::XORB_MEM_REG:
      return Xorb::Text(op, data, addr, len, result);

    /* Branching instructions */
    case Opcodes::CALLA:
      return Calla::Text(data, addr, len, result);
    case Opcodes::CALLI:
      return Calli::Text(data, addr, len, result);
    case Opcodes::CALLR:
      return Callr::Text(data, addr, len, result);
    case Opcodes::CALLS:
      return Calls::Text(data, addr, len, result);
    case Opcodes::JB:
      return Jb::Text(data, addr, len, result);
    case Opcodes::JBC:
      return Jbc::Text(data, addr, len, result);
    case Opcodes::JMPI:
      return Jmpi::Text(data, addr, len, result);
    case Opcodes::JMPA:
      return Jmpa::Text(data, addr, len, result);
    case Opcodes::JMPR_UC:
    case Opcodes::JMPR_NET:
    case Opcodes::JMPR_Z:
    case Opcodes::JMPR_NZ:
    case Opcodes::JMPR_V:
    case Opcodes::JMPR_NV:
    case Opcodes::JMPR_N:
    case Opcodes::JMPR_NN:
    case Opcodes::JMPR_ULT:
    case Opcodes::JMPR_SGT:
    case Opcodes::JMPR_UGE:
    case Opcodes::JMPR_SLE:
    case Opcodes::JMPR_SLT:
    case Opcodes::JMPR_SGE:
    case Opcodes::JMPR_UGT:
    case Opcodes::JMPR_ULE:
      return Jmpr::Text(data, addr, len, result);
    case Opcodes::JMPS:
      return Jmps::Text(data, addr, len, result);
    case Opcodes::JNB:
      return Jnb::Text(data, addr, len, result);
    case Opcodes::JNBS:
      return Jnbs::Text(data, addr, len, result);
    case Opcodes::PCALL:
      return false;
    case Opcodes::RET:
      return Ret::Text(data, addr, len, result);
    case Opcodes::RETP:
      return Retp::Text(data, addr, len, result);
    case Opcodes::RETS:
      return Rets::Text(data, addr, len, result);
    case Opcodes::RETI:
      return Reti::Text(data, addr, len, result);
    case Opcodes::TRAP:
      return Trap::Text(data, addr, len, result);
    default:
      return false;
  }
}

class C166TCArchitecture final : public C166Architecture {
 public:
  explicit C166TCArchitecture(const std::string& name)
      : C166Architecture(name) {}

  uint32_t GetStackPointerRegister() override { return Registers::R0; }
};

class C166TVXArchitecture : public C166Architecture {
 public:
  explicit C166TVXArchitecture(const std::string& name)
      : C166Architecture(name) {}

  uint32_t GetStackPointerRegister() override { return Registers::R15; }
};

class C166V2Architecture final : public C166Architecture {
 public:
  explicit C166V2Architecture(const std::string& name)
      : C166Architecture(name) {}

  uint32_t GetStackPointerRegister() override { return Registers::R0; }

  uint32_t GetLinkRegister() override { return Registers::VIRTUAL_LR; }
};

class TaskingVXCallingConvention final : public BN::CallingConvention {
 public:
  explicit TaskingVXCallingConvention(BN::Architecture* arch)
      : CallingConvention(arch, "c166-vx") {}

  std::vector<uint32_t> GetIntegerArgumentRegisters() override {
    return std::vector<uint32_t>{
        Registers::R2,
        Registers::R3,
        Registers::R4,
        Registers::R5,
    };
  }

  std::vector<uint32_t> GetCalleeSavedRegisters() override {
    return std::vector<uint32_t>{Registers::R0, Registers::RL0, Registers::RH0,
                                 Registers::R1, Registers::RL1, Registers::RH1,
                                 Registers::R6, Registers::RL6, Registers::RH6,
                                 Registers::R7, Registers::RL7, Registers::RH7,
                                 Registers::R8, Registers::R9,  Registers::R10};
  }

  std::vector<uint32_t> GetCallerSavedRegisters() override {
    return std::vector<uint32_t>{};
  }

  uint32_t GetIntegerReturnValueRegister() override { return Registers::R2; }

  std::vector<uint32_t> GetGlobalPointerRegisters() override {
    return GetDppRegisters();
  }
};

class TaskingClassicCallingConvention final : public BN::CallingConvention {
 public:
  explicit TaskingClassicCallingConvention(BN::Architecture* arch)
      : CallingConvention(arch, "c166-classic") {}

  std::vector<uint32_t> GetIntegerArgumentRegisters() override {
    return std::vector<uint32_t>{Registers::R12, Registers::R13, Registers::R14,
                                 Registers::R15};
  }

  std::vector<uint32_t> GetCalleeSavedRegisters() override {
    return std::vector<uint32_t>{Registers::R6, Registers::RL6, Registers::RH6,
                                 Registers::R7, Registers::RL7, Registers::RH7,
                                 Registers::R8, Registers::R9,  Registers::R10};
  }

  std::vector<uint32_t> GetCallerSavedRegisters() override {
    return std::vector<uint32_t>{};
  }

  uint32_t GetIntegerReturnValueRegister() override { return Registers::R4; }

  uint32_t GetHighIntegerReturnValueRegister() override {
    return Registers::R5;
  }

  std::vector<uint32_t> GetGlobalPointerRegisters() override {
    return GetDppRegisters();
  }
};

class TaskingV2CallingConvention : public BN::CallingConvention {
 public:
  explicit TaskingV2CallingConvention(BN::Architecture* arch)
      : CallingConvention(arch, "c166-v2") {}

  std::vector<uint32_t> GetIntegerArgumentRegisters() override {
    return std::vector<uint32_t>{
        Registers::R8,  Registers::R9,  Registers::R10,
        Registers::R11, Registers::R12,
    };
  }

  std::vector<uint32_t> GetCalleeSavedRegisters() override {
    return std::vector<uint32_t>{
        Registers::R13,
        Registers::R14,
        Registers::R15,
    };
  }

  std::vector<uint32_t> GetCallerSavedRegisters() override {
    return std::vector<uint32_t>{};
  }

  uint32_t GetIntegerReturnValueRegister() override { return Registers::R4; }

  uint32_t GetHighIntegerReturnValueRegister() override {
    return Registers::R5;
  }

  bool IsStackReservedForArgumentRegisters() override { return true; }

  std::vector<uint32_t> GetGlobalPointerRegisters() override {
    return GetDppRegisters();
  }
};

void apply_extp_pag10(BinaryNinja::BinaryView* view, uint64_t start,
                      uint64_t length) {
  int64_t pag10;

  BN::GetIntegerInput(pag10, std::string("Enter EXTP #pag10 value"),
                      std::string("EXTP: pag10"));

  // Try to apply to all 2-byte addresses in the specified (highlighted range)
  for (uint64_t a = start; a < (start + length);) {
    BN::LogInfo("Apply EXTP to address: 0x%" PRIx64, a);
    Instruction::SetExtpPag10(a, pag10, 0);
    a += 2;
  }

  view->Reanalyze();
}

void apply_exts_seg8(BinaryNinja::BinaryView* view, uint64_t start,
                     uint64_t length) {
  int64_t seg8;

  BN::GetIntegerInput(seg8, std::string("Enter EXTS #seg8 value"),
                      std::string("EXTS: seg8"));

  // Try to apply to all 2-byte addresses in the specified (highlighted range)
  for (uint64_t a = start; a < (start + length);) {
    BN::LogInfo("Apply EXTS to address: 0x%" PRIx64, a);
    Instruction::SetExtsSeg8(a, seg8, 0);
    a += 2;
  }

  view->Reanalyze();
}

void apply_extr(BinaryNinja::BinaryView* view, uint64_t start,
                uint64_t length) {
  // Try to apply to all 2-byte addresses in the specified (highlighted range)
  for (uint64_t a = start; a < (start + length);) {
    BN::LogInfo("Apply EXTR to address: 0x%" PRIx64, a);
    Instruction::SetExtr(a, 0);
    a += 2;
  }

  view->Reanalyze();
}

bool func_is_valid(BinaryNinja::BinaryView* view, uint64_t start,
                   uint64_t length) {
  return true;
}

void save_state_map(const BinaryNinja::BinaryView* view) {
  const size_t buffer_size = Instruction::SizeOfStateMap();
  auto* buffer = (uint8_t*)malloc(buffer_size);
  Instruction::SerializeStateMap(buffer, buffer_size);

  BNMetadata* state_metadata = BNCreateMetadataRawData(buffer, buffer_size);
  free(buffer);

  BNBinaryViewStoreMetadata(view->m_object, "c166_state", state_metadata,
                            false);
}

void load_state_map(BinaryNinja::BinaryView* view) {
  BNMetadata* state_metadata =
      BNBinaryViewQueryMetadata(view->m_object, "c166_state");
  if (state_metadata == nullptr) {
    BN::LogInfo("No metadata found");
    return;
  }

  if (!BNMetadataIsRaw(state_metadata)) {
    BN::LogInfo("Wrong type for C166 state metadata");
    return;
  }

  size_t size;
  const uint8_t* data = BNMetadataGetRaw(state_metadata, &size);

  Instruction::DeserializeStateMap(data, size);

  view->Reanalyze();
}
}  // namespace C166

extern "C" {
BN_DECLARE_CORE_ABI_VERSION
BINARYNINJAPLUGIN bool CorePluginInit() {
  // Tasking C166/ST10 VX Series
  BN::Architecture* C166TVX = new C166::C166TVXArchitecture("c166tvx");
  BN::Architecture::Register(C166TVX);

  BN::Ref<BN::CallingConvention> cc =
      new C166::TaskingVXCallingConvention(C166TVX);
  C166TVX->RegisterCallingConvention(cc);
  C166TVX->SetDefaultCallingConvention(cc);

  // Tasking C166/ST10 Classic Series
  BN::Architecture* C166TC = new C166::C166TCArchitecture("c166tc");
  BN::Architecture::Register(C166TC);

  cc = new C166::TaskingClassicCallingConvention(C166TC);
  C166TC->RegisterCallingConvention(cc);
  C166TC->SetDefaultCallingConvention(cc);

  // Tasking C166/ST10 V2 Series
  BN::Architecture* C166V2 = new C166::C166V2Architecture("c166v2");
  BN::Architecture::Register(C166V2);

  cc = new C166::TaskingV2CallingConvention(C166V2);
  C166V2->RegisterCallingConvention(cc);
  C166V2->SetDefaultCallingConvention(cc);

  // Register plugin commands to support manual identification of EXT values
  // for instruction lifting
  BN::PluginCommand::RegisterForRange(
      "C166 Architecture\\Apply EXTP #pag10",
      "Highlight a range of instructions to apply EXTP #pag10 value to.",
      &C166::apply_extp_pag10, &C166::func_is_valid);

  BN::PluginCommand::RegisterForRange(
      "C166 Architecture\\Apply EXTS #seg8",
      "Highlight a range of instructions to apply EXTS #seg8 value to.",
      &C166::apply_exts_seg8, &C166::func_is_valid);

  BN::PluginCommand::RegisterForRange(
      "C166 Architecture\\Apply EXTR",
      "Highlight a range of instructions to apply EXTR to.", &C166::apply_extr,
      &C166::func_is_valid);

  BN::PluginCommand::Register(
      "C166 Architecture\\Save C166 StateMap",
      "Saves manual modifications to instruction addressing modes.",
      &C166::save_state_map);

  BN::PluginCommand::Register(
      "C166 Architecture\\Load C166 StateMap",
      "Load manual modifications to instruction addressing modes.",
      &C166::load_state_map);

  return true;
}
}
