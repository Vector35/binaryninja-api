// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#include "util.h"

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "conditions.h"
#include "instructions.h"
#include "registers.h"
#include "sfr.h"

namespace BN = BinaryNinja;

#define ITEXT(m)                            \
  result.emplace_back(InstructionToken, m); \
  result.emplace_back(TextToken, " ");

namespace C166 {

// Maintain a "global" (map/hashtable) of {address: state} pairings.
// State will be an object that can be extended to include any relevant
// per-instruction (at a given address)
//     data that can have an effect on the instruction operation (lifting) or
//     disassembly (text).
std::unordered_map<uint64_t, InstructionState> StateMap;
std::mutex StateMapMutex;
uint32_t default_dpp[4] = {0x0000, 0x0001, 0x0002, 0x0003};  // Reset Value(s)

// Default Constructor
InstructionState::InstructionState() {
  ext_state = ExtNone;
  pag10 = 0x0;
  seg8 = 0x0;
  num_insns = 0;
  dpp[0] = default_dpp[0];
  dpp[1] = default_dpp[1];
  dpp[2] = default_dpp[2];
  dpp[3] = default_dpp[3];
}

void Instruction::SetDefaultDpps(uint16_t dpp0, uint16_t dpp1, uint16_t dpp2,
                                 uint16_t dpp3) {
  default_dpp[0] = dpp0;
  default_dpp[1] = dpp1;
  default_dpp[2] = dpp2;
  default_dpp[3] = dpp3;
}

void Instruction::GetDefaultDpps(uint32_t* dpps) {
  dpps[0] = default_dpp[0];
  dpps[1] = default_dpp[1];
  dpps[2] = default_dpp[2];
  dpps[3] = default_dpp[3];
}

// Assumes DPP usage implies no EXT sequence active.
void Instruction::SetDpps(uint64_t addr, uint16_t dpp0, uint16_t dpp1,
                          uint16_t dpp2, uint16_t dpp3) {
  // BN::LogInfo("util.cpp: SetDpps: addr=0x%" PRIx64, addr);
  std::lock_guard<std::mutex> guard(StateMapMutex);

  auto it = StateMap.find(addr);
  if (it != StateMap.end()) {
    StateMap[addr].ext_state = ExtNoneCustomDpps;
    StateMap[addr].dpp[0] = dpp0;
    StateMap[addr].dpp[1] = dpp1;
    StateMap[addr].dpp[2] = dpp2;
    StateMap[addr].dpp[3] = dpp3;
  } else {
    // Insert new element
    InstructionState new_insn_state;
    new_insn_state.ext_state = ExtNoneCustomDpps;
    new_insn_state.dpp[0] = dpp0;
    new_insn_state.dpp[1] = dpp1;
    new_insn_state.dpp[2] = dpp2;
    new_insn_state.dpp[3] = dpp3;
    StateMap[addr] = new_insn_state;
  }
}

// Sets DPP values in a range if no EXT sequence detected.
void Instruction::SetDppsRange(uint64_t start, uint64_t end, uint16_t dpp0,
                               uint16_t dpp1, uint16_t dpp2, uint16_t dpp3) {
  std::lock_guard<std::mutex> guard(StateMapMutex);

  for (auto addr = start; addr <= end; addr += 2) {
    auto it = StateMap.find(addr);
    if (it != StateMap.end()) {
      // Only overwrite if no EXT sequence is active
      if (it->second.ext_state == ExtNoneCustomDpps ||
          it->second.ext_state == ExtNone) {
        it->second.ext_state = ExtNoneCustomDpps;
        it->second.dpp[0] = dpp0;
        it->second.dpp[1] = dpp1;
        it->second.dpp[2] = dpp2;
        it->second.dpp[3] = dpp3;
      }
    } else {
      // Address not in map, insert new element
      InstructionState new_insn_state;
      new_insn_state.ext_state = ExtNoneCustomDpps;
      new_insn_state.dpp[0] = dpp0;
      new_insn_state.dpp[1] = dpp1;
      new_insn_state.dpp[2] = dpp2;
      new_insn_state.dpp[3] = dpp3;
      StateMap[addr] = new_insn_state;
    }
  }
}

void Instruction::SetExtpPag10(uint64_t addr, uint16_t pag10,
                               uint8_t num_insns) {
  // BN::LogInfo("util.cpp: SetExtpPagSeg: addr=0x%" PRIx64 ", pag10=0x%hx", addr,
  // pag10);
  std::lock_guard<std::mutex> guard(StateMapMutex);

  auto it = StateMap.find(addr);
  if (it != StateMap.end()) {
    StateMap[addr].ext_state |= ExtPage;
    StateMap[addr].pag10 = pag10;
    StateMap[addr].num_insns = num_insns;
  } else {
    // Insert new element
    InstructionState new_insn_state;
    new_insn_state.ext_state = ExtPage;
    new_insn_state.pag10 = pag10;
    new_insn_state.num_insns = num_insns;
    StateMap[addr] = new_insn_state;
  }
}

void Instruction::SetExtsSeg8(uint64_t addr, uint16_t seg8, uint8_t num_insns) {
  // BN::LogInfo("util.cpp: SetExtsSeg8: addr=0x%" PRIx64 ", seg8=0x%hx", addr, seg8);
  std::lock_guard<std::mutex> guard(StateMapMutex);

  auto it = StateMap.find(addr);
  if (it != StateMap.end()) {
    StateMap[addr].ext_state |= ExtSegment;
    StateMap[addr].seg8 = seg8;
    StateMap[addr].num_insns = num_insns;
  } else {
    // Insert new element
    InstructionState new_insn_state;
    new_insn_state.ext_state = ExtSegment;
    new_insn_state.seg8 = seg8;
    new_insn_state.num_insns = num_insns;
    StateMap[addr] = new_insn_state;
  }
}

void Instruction::SetExtr(uint64_t addr, uint8_t num_insns) {
  // BN::LogInfo("util.cpp: SetExtr: addr=0x%" PRIx64, addr);
  std::lock_guard<std::mutex> guard(StateMapMutex);

  if (const auto it = StateMap.find(addr); it != StateMap.end()) {
    StateMap[addr].ext_state |= ExtRegister;
    StateMap[addr].num_insns = num_insns;
  } else {
    // Insert new element
    InstructionState new_insn_state;
    new_insn_state.ext_state = ExtRegister;
    new_insn_state.num_insns = num_insns;

    StateMap[addr] = new_insn_state;
  }
}

bool Instruction::ShouldUseExtr(const uint64_t addr) {
  std::lock_guard<std::mutex> guard(StateMapMutex);
  bool use_extr = false;

  // If there's an entry containing extra state information for this address,
  // use it.
  auto it = StateMap.find(addr);
  if (it != StateMap.end()) {
    if (StateMap[addr].ext_state & ExtRegister) {
      use_extr = true;
    }
  }

  return use_extr;
}

bool Instruction::ShouldUseExts(const uint64_t addr, uint32_t* seg8) {
  std::lock_guard<std::mutex> guard(StateMapMutex);
  bool use_exts = false;

  // If there's an entry containing extra state information for this address,
  // use it.
  if (const auto it = StateMap.find(addr); it != StateMap.end()) {
    if (StateMap[addr].ext_state & ExtSegment) {
      use_exts = true;
      *seg8 = StateMap[addr].seg8;
    }
  }

  return use_exts;
}

bool Instruction::ShouldUseExtp(const uint64_t addr, uint32_t* pag10) {
  std::lock_guard<std::mutex> guard(StateMapMutex);
  bool use_extp = false;

  // If there's an entry containing extra state information for this address,
  // use it.
  if (const auto it = StateMap.find(addr); it != StateMap.end()) {
    if (StateMap[addr].ext_state & ExtPage) {
      use_extp = true;
      *pag10 = StateMap[addr].pag10;
    }
  }

  return use_extp;
}

bool Instruction::ShouldUseCustomDpps(const uint64_t addr, uint32_t* dpps) {
  std::lock_guard<std::mutex> guard(StateMapMutex);
  bool use_custom_dpps = false;

  // If there's an entry containing extra state information for this address,
  // use it.
  if (const auto it = StateMap.find(addr); it != StateMap.end()) {
    if (StateMap[addr].ext_state & ExtNoneCustomDpps) {
      use_custom_dpps = true;
      dpps[0] = StateMap[addr].dpp[0];
      dpps[1] = StateMap[addr].dpp[1];
      dpps[2] = StateMap[addr].dpp[2];
      dpps[3] = StateMap[addr].dpp[3];
    }
  }

  return use_custom_dpps;
}

InstructionState Instruction::GetInstructionState(const uint64_t addr) {
  std::lock_guard<std::mutex> guard(StateMapMutex);

  if (StateMap.find(addr) == StateMap.end()) {
    InstructionState empty = {};
    return empty;
  } else {
    return StateMap[addr];
  }
}

size_t Instruction::SerializeStateMap(uint8_t* buf, size_t size) {
  std::lock_guard<std::mutex> guard(StateMapMutex);

  uint64_t elem_count = StateMap.size();
  uint64_t elem_size = (sizeof(uint64_t) + sizeof(InstructionState));

  if (size < elem_count * elem_size) {
    return 0;
  }

  uint8_t* head = buf;
  for (auto elem : StateMap) {
    std::memcpy(head, &elem.first, sizeof(elem.first));
    head += sizeof(elem.first);
    std::memcpy(head, &elem.second, sizeof(elem.second));
    head += sizeof(elem.second);
  }

  return head - buf;
}

bool Instruction::DeserializeStateMap(const uint8_t* buf, size_t size) {
  std::lock_guard<std::mutex> guard(StateMapMutex);

  if (size % (sizeof(uint64_t) + sizeof(InstructionState)) != 0) {
    return false;
  }

  StateMap.clear();

  for (const uint8_t* head = buf; head < buf + size;
       head += sizeof(uint64_t) + sizeof(InstructionState)) {
    uint64_t addr;
    memcpy(&addr, head, sizeof(addr));

    InstructionState state;
    memcpy(&state, head + sizeof(addr), sizeof(state));

    StateMap[addr] = state;
  }

  return true;
}

size_t Instruction::SizeOfStateMap() {
  uint64_t elem_count = StateMap.size();
  uint64_t elem_size = (sizeof(uint64_t) + sizeof(InstructionState));
  return elem_count * elem_size;
}

/*
 * Indirect Addressing (EXTS) Expressions
 */

// exts; [Rw]
BN::ExprId Instruction::GetIndAddrExpr_Exts_Rw(BN::LowLevelILFunction& il,
                                               uint32_t seg8, uint32_t Rw) {
  const BN::ExprId IndAddrSeg8 =
      il.ShiftLeft(3, il.Const(3, seg8), il.Const(2, 16));
  const BN::ExprId IndAddr = il.Or(3, IndAddrSeg8, il.Register(2, Rw));
  return IndAddr;
}
// exts; [Rw + #data16]
BN::ExprId Instruction::GetIndAddrExpr_Exts_Rw_data16(
    BN::LowLevelILFunction& il, uint32_t seg8, uint32_t Rw, uint16_t data16) {
  const BN::ExprId IndAddrSeg8 =
      il.ShiftLeft(3, il.Const(3, seg8), il.Const(2, 16));
  const BN::ExprId IndAddrOff =
      il.And(2, il.Add(2, il.Register(2, Rw), il.Const(2, data16)),
             il.Const(2, 0xFFFF));
  BN::ExprId IndAddr = il.Or(3, IndAddrSeg8, IndAddrOff);
  return IndAddr;
}

/*
 * Indirect Addressing (EXTP) Expressions
 */

// extp; [Rw]
BN::ExprId Instruction::GetIndAddrExpr_Extp_Rw(BN::LowLevelILFunction& il,
                                               uint32_t pag10, uint32_t Rw) {
  const BN::ExprId IndAddrPag10 =
      il.ShiftLeft(3, il.Const(3, pag10), il.Const(2, 14));
  const BN::ExprId IndAddr = il.Or(
      3, IndAddrPag10, il.And(2, il.Register(2, Rw), il.Const(2, 0x3FFF)));
  return IndAddr;
}

// extp; [Rw + #data16]
BN::ExprId Instruction::GetIndAddrExpr_Extp_Rw_data16(
    BN::LowLevelILFunction& il, uint32_t pag10, uint32_t Rw, uint16_t data16) {
  const BN::ExprId IndAddrPag10 =
      il.ShiftLeft(3, il.Const(3, pag10), il.Const(2, 14));
  const BN::ExprId IndAddrOff =
      il.And(2, il.Add(2, il.Register(2, Rw), il.Const(2, data16)),
             il.Const(2, 0xFFFF));
  const BN::ExprId IndAddr = il.Or(3, IndAddrPag10, IndAddrOff);
  return IndAddr;
}

/*
 * Indirect Addressing (DPP) Expressions
 */

// [Rw]
BN::ExprId Instruction::GetIndAddrExpr_Rw(BN::LowLevelILFunction& il,
                                          uint32_t Rw) {
  const BN::ExprId Ind = il.Register(2, Rw);
  const BN::ExprId DppIndex = il.LogicalShiftRight(
      2, il.And(2, il.Const(2, 0xC000), Ind), il.Const(2, 14));
  const BN::ExprId DppAddr = il.Add(3, il.ConstPointer(2, Sfr::DPP0),
                                    il.ShiftLeft(2, DppIndex, il.Const(2, 1)));
  const BN::ExprId IndAddrUpper =
      il.ShiftLeft(3, il.Load(2, DppAddr), il.Const(2, 14));
  const BN::ExprId IndAddrLower = il.And(2, Ind, il.Const(2, 0x3FFF));
  const BN::ExprId IndAddr = il.Or(3, IndAddrUpper, IndAddrLower);
  return IndAddr;
}

BN::ExprId Instruction::GetIndAddrExpr_Rw_data16(BN::LowLevelILFunction& il,
                                                 uint32_t Rw, uint16_t data16) {
  const BN::ExprId Ind =
      il.And(2, il.Add(2, il.Const(2, data16), il.Register(2, Rw)),
             il.Const(2, 0xFFFF));
  const BN::ExprId DppIndex = il.LogicalShiftRight(
      2, il.And(2, il.Const(2, 0xC000), Ind), il.Const(2, 14));
  const BN::ExprId DppAddr = il.Add(3, il.ConstPointer(2, 0xFE00),
                                    il.ShiftLeft(2, DppIndex, il.Const(2, 1)));
  const BN::ExprId IndAddrUpper =
      il.ShiftLeft(3, il.Load(2, DppAddr), il.Const(2, 14));
  const BN::ExprId IndAddrLower = il.And(2, Ind, il.Const(2, 0x3FFF));
  const BN::ExprId IndAddr = il.Or(3, IndAddrUpper, IndAddrLower);
  return IndAddr;
}

const char* Instruction::ConditionCodeToString(const uint8_t code) {
  switch (code) {
    case Conditions::CC_UC:
      return "cc_uc";
    case Conditions::CC_Z:
      return "cc_z";
    case Conditions::CC_NZ:
      return "cc_nz";
    case Conditions::CC_V:
      return "cc_v";
    case Conditions::CC_NV:
      return "cc_nv";
    case Conditions::CC_N:
      return "cc_n";
    case Conditions::CC_NN:
      return "cc_nn";
    case Conditions::CC_ULT:
      return "cc_ult";
    case Conditions::CC_ULE:
      return "cc_ule";
    case Conditions::CC_UGE:
      return "cc_uge";
    case Conditions::CC_UGT:
      return "cc_ugt";
    case Conditions::CC_SLT:
      return "cc_slt";
    case Conditions::CC_SLE:
      return "cc_sle";
    case Conditions::CC_SGE:
      return "cc_sge";
    case Conditions::CC_SGT:
      return "cc_sgt";
    case Conditions::CC_NET:
      return "cc_net";
    default:
      BN::LogDebug("Invalid condition code");
      return "?!?";
  }
}

uint8_t Instruction::GetBitPosition(const uint8_t* data, size_t len) {
  return (*data & (0xFu << 4u)) >> 4u;
}

uint32_t Instruction::GetBitoffRamAddress(const uint8_t value) {
  return 0xFD00 + 2 * value;
}

uint32_t Instruction::GetBitoffSfrAddress(const uint8_t value, bool extr) {
  uint32_t base = (extr) ? 0xF100 : 0xFF00;
  return base + 2 * (value & 0x7Fu);
}

uint16_t Instruction::GetData16(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1);
}

uint8_t Instruction::GetData3(const uint8_t* data, const size_t len) {
  return *(data + 1) & 0b111u;
}

uint8_t Instruction::GetData4High(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  switch (len) {
    case 2:
      return (*wdata & (0b1111u << ((4 * len) + 4))) >> ((4 * len) + 4);
    case 4:
      return (*(wdata + 1) & (0b1111u << ((4 * len) + 4))) >> ((4 * len) + 4);
    default:
      BN::LogError("GetData4High -- Invalid len parameter: %zu", len);
      return 0;
  }
}

uint8_t Instruction::GetData4Low(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  switch (len) {
    case 2:
      return (*wdata & (0b1111u << (4 * len))) >> (4 * len);
    case 4:
      return (*(wdata + 1) & (0b1111u << (4 * len))) >> (4 * len);
    default:
      BN::LogError("GetData4Low -- Invalid len parameter: %zu", len);
      return 0;
  }
}

uint8_t Instruction::GetData8High(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return (*(wdata + 1) & (0xFFu << 8u)) >> 8u;
}

uint8_t Instruction::GetData8Low(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1) & 0xFFu;
}

BNLowLevelILFlagCondition Instruction::GetFlagCondition(const uint8_t code) {
  switch (code) {
    case Conditions::CC_Z:
      return LLFC_E;
    case Conditions::CC_NZ:
      return LLFC_NE;
    case Conditions::CC_V:
      return LLFC_O;
    case Conditions::CC_NV:
      return LLFC_NO;
    case Conditions::CC_N:
      return LLFC_NEG;
    case Conditions::CC_NN:
      return LLFC_POS;
    case Conditions::CC_ULT:
      return LLFC_ULT;
    case Conditions::CC_ULE:
      return LLFC_ULE;
    case Conditions::CC_UGE:
      return LLFC_UGE;
    case Conditions::CC_UGT:
      return LLFC_UGT;
    case Conditions::CC_SLT:
      return LLFC_SLT;
    case Conditions::CC_SLE:
      return LLFC_SLE;
    case Conditions::CC_SGE:
      return LLFC_SGE;
    case Conditions::CC_SGT:
      return LLFC_SGT;
    case Conditions::CC_NET:  // TODO: Special flag? Not end of table?!?
    case Conditions::CC_UC:
    default:
      BN::LogDebug("Invalid flag condition code");
      return LLFC_E;  // TODO: Better return value?
  }
}

uint8_t Instruction::GetIndirectIndex(const uint8_t* data, size_t len) {
  return *(data + 1) & 0b11u;
}

uint32_t Instruction::GetMem(const uint64_t addr, const uint8_t* data,
                             const size_t len) {
  std::lock_guard<std::mutex> guard(StateMapMutex);

  const auto wdata = (const uint16_t*)data;
  uint32_t mem = (*(wdata + 1) & (0xFFFFu));
  uint32_t dpp_index = (mem & 0xC000) >> 14;
  uint32_t offset;

  // If there's an entry containing extra state information for this address,
  // use it.
  auto it = StateMap.find(addr);
  if (it != StateMap.end()) {
    if (StateMap[addr].ext_state & ExtPage) {  // EXTP Overrides DPP
      offset = mem & 0x3FFF;
      return (StateMap[addr].pag10 << 14) | offset;
    } else if (StateMap[addr].ext_state & ExtSegment) {  // EXTS Overrides DPP
      return (StateMap[addr].seg8 << 16) | mem;
    } else if (StateMap[addr].ext_state & ExtNoneCustomDpps) {  // Use DPP
      offset = mem & 0x3FFF;
      return (StateMap[addr].dpp[dpp_index] << 14) | offset;
    }
  }

  offset = mem & 0x3FFF;
  return (default_dpp[dpp_index] << 14) | offset;
}

uint16_t Instruction::GetOpCaddr(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1);
}

uint8_t Instruction::GetOpSeg(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return (*wdata & (0xFFu << 8u)) >> 8u;
}

uint32_t Instruction::GetRegSfrAddress(const uint8_t value, bool extr) {
  uint32_t base = (extr) ? 0xF000 : 0xFE00;
  return base + 2 * value;
}

uint8_t Instruction::GetRegShortAddr(const uint8_t* data, const size_t len) {
  return *(data + 1);
}

bool Instruction::JumpDirect(BN::Architecture* arch, BN::LowLevelILFunction& il,
                             uint32_t target) {
  BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);

  if (label)
    il.AddInstruction(il.Goto(*label));
  else
    il.AddInstruction(il.Jump(il.ConstPointer(3, target)));

  return true;
}

bool Instruction::JumpIndirect(BN::Architecture* arch,
                               BN::LowLevelILFunction& il, uint32_t rid,
                               uint32_t addr) {
  BN::ExprId csp = il.And(3, il.Const(3, addr), il.Const(3, 0xFF0000));
  BN::ExprId target = il.Or(3, csp, il.ZeroExtend(3, il.Register(2, rid)));
  il.AddInstruction(il.Jump(target));
  return true;
}

bool Instruction::LiftOpMemReg(
    const uint64_t addr, const uint8_t* data, size_t len, size_t width,
    uint32_t flags, bool store, BN::LowLevelILFunction& il,
    const std::function<
        BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                   const BN::ILSourceLocation& loc)>& operation) {
  uint32_t mem = Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));

  BN::ExprId op2;
  if (reg <= 0xF) {
    if (width == 1) reg += 16;
    op2 = il.Register(width, reg);
  } else {
    op2 = Instruction::ElideReg(il, reg, width);
  }

  if (store)
    il.AddInstruction(
        il.Store(width, il.ConstPointer(3, mem),
                 operation(width, il.Load(width, il.ConstPointer(3, mem)), op2,
                           flags, BN::ILSourceLocation())));
  else
    operation(width, il.Load(width, il.ConstPointer(3, mem)), op2, flags,
              BN::ILSourceLocation());

  return true;
}

bool Instruction::LiftOpRegData(
    const uint64_t addr, const uint8_t* data, size_t len, size_t width,
    uint32_t flags, bool store, BN::LowLevelILFunction& il,
    const std::function<
        BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                   const BN::ILSourceLocation& loc)>& operation) {
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));

  unsigned int ndata;
  switch (width) {
    case 1:
      ndata = Instruction::GetData8Low(data, len);  // TODO: Verify
      break;
    case 2:
      ndata = Instruction::GetData16(data, len);
      break;
    default:
      BN::LogError("Instruction::%s received invalid width: %zu", __func__,
                   width);
      return false;
  }

  if (reg <= 0xF) {
    if (width == 1) reg += 16;
    if (store)
      il.AddInstruction(il.SetRegister(
          width, reg,
          operation(width, il.Register(width, reg), il.Const(width, ndata),
                    flags, BN::ILSourceLocation())));
    else
      il.AddInstruction(operation(width, il.Register(width, reg),
                                  il.Const(width, ndata), flags,
                                  BN::ILSourceLocation()));
  } else {
    if (store)
      il.AddInstruction(il.Store(
          width, il.ConstPointer(3, reg),
          operation(width, il.Load(width, il.ConstPointer(3, reg)),
                    il.Const(width, ndata), flags, BN::ILSourceLocation())));
    else
      il.AddInstruction(
          operation(width, il.Load(width, il.ConstPointer(3, reg)),
                    il.Const(width, ndata), flags, BN::ILSourceLocation()));
  }

  return true;
}

bool Instruction::LiftOpRegMem(
    const uint64_t addr, const uint8_t* data, size_t len, size_t width,
    uint32_t flags, bool store, BN::LowLevelILFunction& il,
    const std::function<
        BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                   const BN::ILSourceLocation& loc)>& operation) {
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));
  uint32_t mem = Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  if (reg <= 0xF) {
    if (width == 1) reg += 16;
    if (store)
      il.AddInstruction(
          il.SetRegister(width, reg,
                         operation(width, il.Register(width, reg),
                                   il.Load(width, il.ConstPointer(3, mem)),
                                   flags, BN::ILSourceLocation())));
    else
      il.AddInstruction(operation(width, il.Register(width, reg),
                                  il.Load(width, il.ConstPointer(3, mem)),
                                  flags, BN::ILSourceLocation()));
  } else {
    if (store)
      il.AddInstruction(
          il.Store(width, il.ConstPointer(3, reg),
                   operation(width, il.Load(width, il.ConstPointer(3, reg)),
                             il.Load(width, il.ConstPointer(3, mem)), flags,
                             BN::ILSourceLocation())));
    else
      il.AddInstruction(operation(width,
                                  il.Load(width, il.ConstPointer(3, reg)),
                                  il.Load(width, il.ConstPointer(3, mem)),
                                  flags, BN::ILSourceLocation()));
  }

  return true;
}

bool Instruction::LiftOpRnRm(
    const uint8_t* data, const size_t len, const size_t width,
    const uint32_t flags, bool store, BN::LowLevelILFunction& il,
    const std::function<
        BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                   const BN::ILSourceLocation& loc)>& operation) {
  uint32_t rn = Instruction::GetData4High(data, 2);
  uint32_t rm = Instruction::GetData4Low(data, 2);

  if (width == 1) {
    rn += 16;
    rm += 16;
  }

  if (store)
    il.AddInstruction(il.SetRegister(
        width, rn,
        operation(width, il.Register(width, rn), il.Register(width, rm), flags,
                  BN::ILSourceLocation())));
  else
    il.AddInstruction(operation(width, il.Register(width, rn),
                                il.Register(width, rm), flags,
                                BN::ILSourceLocation()));

  return true;
}

bool Instruction::LiftOpRnRwiData3(
    const uint64_t addr, const uint8_t* data, const size_t len,
    const size_t width, const uint32_t flags, bool store,
    BN::LowLevelILFunction& il,
    const std::function<
        BN::ExprId(size_t size, BN::ExprId a, BN::ExprId b, uint32_t flags,
                   const BN::ILSourceLocation& loc)>& operation) {
  uint32_t rn = Instruction::GetData4High(data, 2);
  uint8_t scode = ((*(data + 1) & 0xCu) >> 2u);
  uint32_t rwi = Instruction::GetIndirectIndex(data, 2);
  uint8_t data3 = Instruction::GetData3(data, 2);

  if (width == 1) rn += 16;

  BN::ExprId src = 0, post = 0;  // TODO: Is 0 the best initial value?
  switch (scode) {
    case 0b11:  // Rw_n, [Rw_i+]
      post = il.SetRegister(2, rwi,
                            il.Add(2, il.Register(2, rwi), il.Const(2, 2)));
    case 0b10:  // Rw_n, [Rw_i]
    {
      BN::ExprId SrcIndAddr;
      uint32_t seg8, pag10;
      if (Instruction::ShouldUseExts(addr, &seg8)) {
        SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwi);
      } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
        SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwi);
      } else {
        SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwi);
      }
      src = il.Load(width, SrcIndAddr);
    } break;
    case 0b00:
    case 0b01:  // Rw_n, #data3
      src = il.Const(1, data3);
      break;
    default:
      BN::LogError("%s: Invalid sub-opcode: 0x%x", __func__, scode);
      return false;
  }

  if (store)
    il.AddInstruction(
        il.SetRegister(width, rn,
                       operation(width, il.Register(width, rn), src, flags,
                                 BN::ILSourceLocation())));
  else
    il.AddInstruction(operation(width, il.Register(width, rn), src, flags,
                                BN::ILSourceLocation()));

  if (post) il.AddInstruction(post);

  return true;
}

int8_t Instruction::SignExtend(uint8_t data) {
  if ((data >> 7u) & 1u) data |= 0x80u;
  return (int8_t)data;
}

bool Instruction::TextOpMemReg(const uint64_t addr, const uint8_t* data,
                               size_t len, size_t width,
                               std::vector<BN::InstructionTextToken>& result,
                               const std::string& instr) {
  char buf[32];
  uint32_t mem = Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));

  ITEXT(instr)

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  result.emplace_back(OperandSeparatorToken, ", ");

  if (reg <= 0xF) {
    if (width == 1) reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }

  return true;
}

bool Instruction::TextOpRegData(const uint64_t addr, const uint8_t* data,
                                size_t len, size_t width,
                                std::vector<BN::InstructionTextToken>& result,
                                const std::string& instr) {
  char buf[32];
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));

  unsigned int ndata;
  switch (width) {
    case 1:
      ndata = Instruction::GetData8Low(data, len);  // TODO: Verify
      break;
    case 2:
      ndata = Instruction::GetData16(data, len);
      break;
    default:
      BN::LogError("Instruction::%s received invalid width: %zu", __func__,
                   width);
      return false;
  }

  ITEXT(instr)

  if (reg <= 0xF) {
    if (width == 1) reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");
  result.emplace_back(TextToken, "#");
  std::snprintf(buf, sizeof(buf), "0x%x", ndata);
  result.emplace_back(IntegerToken, buf, ndata, width);

  return true;
}

bool Instruction::TextOpRegMem(const uint64_t addr, const uint8_t* data,
                               size_t len, size_t width,
                               std::vector<BN::InstructionTextToken>& result,
                               const std::string& instr) {
  char buf[32];
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, 4));
  uint32_t mem = Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  ITEXT(instr)

  if (reg <= 0xF) {
    if (width == 1) reg += 16;
    std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(reg));
    result.emplace_back(RegisterToken, buf, reg);
  } else {
    std::snprintf(buf, sizeof(buf), "0x%x", reg);
    result.emplace_back(PossibleAddressToken, buf, reg);
  }
  result.emplace_back(OperandSeparatorToken, ", ");

  std::snprintf(buf, sizeof(buf), "0x%x", mem);
  result.emplace_back(PossibleAddressToken, buf, mem);

  return true;
}

bool Instruction::TextOpRnRm(const uint8_t* data, const size_t len,
                             const size_t width,
                             std::vector<BN::InstructionTextToken>& result,
                             const std::string& instr) {
  char buf[32];
  uint32_t rn = Instruction::GetData4High(data, 2);
  uint32_t rm = Instruction::GetData4Low(data, 2);

  if (width == 1) {
    rn += 16;
    rm += 16;
  }

  ITEXT(instr)

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rn));
  result.emplace_back(RegisterToken, buf, rn);
  result.emplace_back(OperandSeparatorToken, ", ");
  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rm));
  result.emplace_back(RegisterToken, buf, rm);

  return true;
}

bool Instruction::TextOpRnRwiData3(
    const uint8_t* data, size_t len, size_t width,
    std::vector<BN::InstructionTextToken>& result, const std::string& instr) {
  char buf[32];
  uint32_t rn = Instruction::GetData4High(data, 2);
  uint8_t scode = ((*(data + 1) & 0xCu) >> 2u);
  uint32_t rwi = Instruction::GetIndirectIndex(data, 2);
  uint8_t data3 = Instruction::GetData3(data, 2);

  ITEXT(instr)

  if (width == 1) rn += 16;

  std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rn));
  result.emplace_back(RegisterToken, buf, rn);

  switch (scode) {
    case 0b10:
      result.emplace_back(OperandSeparatorToken, ", [");
      std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwi));
      result.emplace_back(RegisterToken, buf, rwi);
      result.emplace_back(TextToken, "]");
      return true;
    case 0b11:
      result.emplace_back(OperandSeparatorToken, ", [");
      std::snprintf(buf, sizeof(buf), "%s", Instruction::RegToStr(rwi));
      result.emplace_back(RegisterToken, buf, rwi);
      result.emplace_back(TextToken, "+]");
      return true;
    case 0b00:
    case 0b01:
      result.emplace_back(OperandSeparatorToken, ", ");
      result.emplace_back(TextToken, "#");
      std::snprintf(buf, sizeof(buf), "0x%x", data3);
      result.emplace_back(IntegerToken, buf, data3, 1);
      return true;
    default:
      BN::LogError("%s: Invalid sub-opcode.", __func__);
      return false;
  }
}

uint32_t Instruction::TranslateBitOff(const uint64_t addr,
                                      const uint32_t bitoff) {
  if (bitoff <= 0x7F) {
    return GetBitoffRamAddress(bitoff);
  } else if (bitoff <= 0xEF)
    return GetBitoffSfrAddress(bitoff, ShouldUseExtr(addr));
  else {
    return bitoff & 0xFu;
  }
}

uint32_t Instruction::TranslateMem(const uint32_t mem) { return mem; }

uint32_t Instruction::TranslateReg(const uint64_t addr, const uint32_t reg) {
  if (reg <= 0xEF) {
    return GetRegSfrAddress(reg, ShouldUseExtr(addr));
  } else {
    return reg & 0xFu;
  }
}

const char* Instruction::RegToStr(const uint32_t rid) {
  switch (rid) {
    /* Full-Width GPRs + Stack Pointer */
    case Registers::R0:
      return "r0";
    case Registers::R1:
      return "r1";
    case Registers::R2:
      return "r2";
    case Registers::R3:
      return "r3";
    case Registers::R4:
      return "r4";
    case Registers::R5:
      return "r5";
    case Registers::R6:
      return "r6";
    case Registers::R7:
      return "r7";
    case Registers::R8:
      return "r8";
    case Registers::R9:
      return "r9";
    case Registers::R10:
      return "r10";
    case Registers::R11:
      return "r11";
    case Registers::R12:
      return "r12";
    case Registers::R13:
      return "r13";
    case Registers::R14:
      return "r14";
    case Registers::R15:  // Stack Pointer
      return "r15";
    case Registers::RL0:
      return "rl0";
    case Registers::RH0:
      return "rh0";
    case Registers::RL1:
      return "rl1";
    case Registers::RH1:
      return "rh1";
    case Registers::RL2:
      return "rl2";
    case Registers::RH2:
      return "rh2";
    case Registers::RL3:
      return "rl3";
    case Registers::RH3:
      return "rh3";
    case Registers::RL4:
      return "rl4";
    case Registers::RH4:
      return "rh4";
    case Registers::RL5:
      return "rl5";
    case Registers::RH5:
      return "rh5";
    case Registers::RL6:
      return "rl6";
    case Registers::RH6:
      return "rh6";
    case Registers::RL7:
      return "rl7";
    case Registers::RH7:
      return "rh7";
    case Registers::CSP:
      return "csp";
    case Registers::CPUCON1:
      return "cpucon1";
    case Registers::CPUCON2:
      return "cpucon2";
    case Registers::PSW:
      return "psw";
    case Registers::CP:
      return "cp";
    default:
      return nullptr;
  }
}

bool Instruction::GetConstantRegister(uint32_t reg, uint16_t& value) {
  switch (reg) {
    case 0xFF1C:  // ZEROS
      value = 0x0;
      return true;
    case 0xFF1E:  // ONES
      value = 0xFFFF;
      return true;
    default:
      return false;
  }
}

BN::ExprId Instruction::ElideReg(BN::LowLevelILFunction& il, const uint32_t reg,
                                 const int width) {
  if (uint16_t constant = 0; GetConstantRegister(reg, constant)) {
    return il.Const(width, constant);
  } else {
    return il.Load(width, il.ConstPointer(3, reg));
  }
}

uint32_t Calla::GetConditionCode(const uint8_t* data, const size_t len) {
  return (*(data + 1) & 0xF0u) >> 4u;
}

uint32_t Calli::GetConditionCode(const uint8_t* data, const size_t len) {
  return (*(data + 1) & 0xF0u) >> 4u;
}

uint8_t Callr::GetRelativeOffset(const uint8_t* data, const size_t len) {
  return *(data + 1) & 0xFFu;
}

uint32_t Callr::GetTarget(const uint8_t* data, const uint64_t addr,
                          const size_t len) {
  return addr +
         Instruction::SignExtend(Callr::GetRelativeOffset(data, len)) * 2 + 2;
}

uint32_t Calla::GetTarget(const uint8_t* data, const uint64_t addr,
                          const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return (addr & (0xFFu << 16u)) + *(wdata + 1);
}

uint32_t Calls::GetTarget(const uint8_t* data, const size_t len) {
  const uint8_t seg = Instruction::GetOpSeg(data, len);
  const uint16_t caddr = Instruction::GetOpCaddr(data, len);
  return (static_cast<uint32_t>(seg) << 16u) | caddr;
}

const char* Extprs::GetInstruction(const uint8_t* data, uint64_t addr,
                                   const size_t len) {
  const uint16_t instr = *(const uint16_t*)data;
  const auto scode = (instr & (0b11u << 14u)) >> 14u;
  switch (scode) {
    case 0b00:
      return "exts";
    case 0b01:
      return "extp";
    default:
      BN::LogDebug("0x%" PRIx64 ": Encountered unimplemented extended instruction",
                   addr);
      return "UNIMPLEMENTED_EXT";
  }
}

uint8_t Jb::GetRelativeOffset(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1) & 0xFFu;
}

uint32_t Jb::GetTarget(const uint8_t* data, const uint64_t addr,
                       const size_t len) {
  return addr + Instruction::SignExtend(Jb::GetRelativeOffset(data, len)) * 2 +
         length;
}

uint8_t Jbc::GetRelativeOffset(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1) & 0xFFu;
}

uint32_t Jbc::GetTarget(const uint8_t* data, const uint64_t addr,
                        const size_t len) {
  return addr + Instruction::SignExtend(Jbc::GetRelativeOffset(data, len)) * 2 +
         length;
}

uint32_t Jmpa::GetConditionCode(const uint8_t* data, const size_t len) {
  return (*(data + 1) & 0xF0u) >> 4u;
}

uint32_t Jmpa::GetTarget(const uint8_t* data, const uint64_t addr,
                         const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return (addr & (0xFFu << 16u)) + *(wdata + 1);
}

uint32_t Jmpr::GetConditionCode(const uint8_t* data, const size_t len) {
  return (*data & 0xF0u) >> 4u;
}

uint8_t Jmpr::GetRelativeOffset(const uint8_t* data, const size_t len) {
  return *(data + 1) & 0xFFu;
}

uint32_t Jmpr::GetTarget(const uint8_t* data, const uint64_t addr,
                         const size_t len) {
  return addr +
         Instruction::SignExtend(Jmpr::GetRelativeOffset(data, len)) * 2 + 2;
}

uint32_t Jmps::GetTarget(const uint8_t* data, const size_t len) {
  const uint8_t seg = Instruction::GetOpSeg(data, len);
  const uint16_t caddr = Instruction::GetOpCaddr(data, len);
  return ((uint32_t)seg << 16u) | caddr;
}

uint8_t Jnb::GetRelativeOffset(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1) & 0xFFu;
}

uint32_t Jnb::GetTarget(const uint8_t* data, const uint64_t addr,
                        const size_t len) {
  return addr + Instruction::SignExtend(Jnb::GetRelativeOffset(data, len)) * 2 +
         length;
}

uint8_t Jnbs::GetRelativeOffset(const uint8_t* data, const size_t len) {
  const auto wdata = (const uint16_t*)data;
  return *(wdata + 1) & 0xFFu;
}

uint32_t Jnbs::GetTarget(const uint8_t* data, const uint64_t addr,
                         const size_t len) {
  return addr +
         Instruction::SignExtend(Jnbs::GetRelativeOffset(data, len)) * 2 +
         length;
}

uint32_t Trap::GetTarget(const uint8_t* data, const uint64_t addr) {
  const uint8_t trap7 = Trap::GetTrap7(data);
  return (addr & (0xFFu << 16u)) + (trap7 * 4);
}

uint8_t Trap::GetTrap7(const uint8_t* data) {
  return (*(data + 1) & (0b1111111u << 1u)) >> 1u;
}
}  // namespace C166
