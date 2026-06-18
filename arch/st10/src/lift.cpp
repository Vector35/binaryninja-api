// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>

#include <cstdint>
#include <vector>

#include "conditions.h"
#include "instructions.h"
#include "opcodes.h"
#include "registers.h"
#include "sfr.h"
#include "util.h"

// Enable nice function signature printing in windows for logs
#ifdef _MSC_VER
    #define __PRETTY_FUNCTION__ __FUNCSIG__
#endif

namespace BN = BinaryNinja;

// Ref: https://clang.llvm.org/extra/clang-tidy/checks/modernize/avoid-bind.html
#define IL_OP(m)                                                        \
  [&il](auto &&_1, auto &&_2, auto &&_3, auto &&_4, auto &&_5) {        \
    return il.m(                                                        \
        std::forward<decltype(_1)>(_1), std::forward<decltype(_2)>(_2), \
        std::forward<decltype(_3)>(_3), std::forward<decltype(_4)>(_4), \
        std::forward<decltype(_5)>(_5));                                \
  }
#define NO_RETURN(length)           \
  il.AddInstruction(il.NoReturn()); \
  len = length;                     \
  return true
#define NO_OPERATION(length)   \
  il.AddInstruction(il.Nop()); \
  len = length;                \
  return true
#define UNIMPLEMENTED(length)            \
  il.AddInstruction(il.Unimplemented()); \
  len = length;                          \
  return true
#define STACK_RETURN(length)                                           \
  il.AddInstruction(il.Return(il.Register(3, Registers::VIRTUAL_LR))); \
  len = length;                                                        \
  return true

namespace C166 {

static void UpdateExtSequence(const uint64_t addr, const size_t len) {
  uint32_t pag10, seg8;
  if (Instruction::ShouldUseExts(addr, &seg8)) {
    InstructionState curState = Instruction::GetInstructionState(addr);
    if (curState.num_insns > 0) {
      Instruction::SetExtsSeg8(addr + len, curState.seg8,
                               curState.num_insns - 1);
    }
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    InstructionState curState = Instruction::GetInstructionState(addr);
    if (curState.num_insns > 0) {
      Instruction::SetExtpPag10(addr + len, curState.pag10,
                                curState.num_insns - 1);
    }
  } else if (Instruction::ShouldUseExtr(addr)) {
    InstructionState curState = Instruction::GetInstructionState(addr);
    if (curState.num_insns > 0) {
      Instruction::SetExtr(addr + len, curState.num_insns - 1);
    }
  }
}

bool Add::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
               size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::ADD_RWN_RWM:
      len = 2;
      return Instruction::LiftOpRnRm(data, len, 2, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADD_RWN_RWI_DATA3:
      len = 2;
      return Instruction::LiftOpRnRwiData3(addr, data, len, 2, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADD_REG_DATA16:
      len = 4;
      return Instruction::LiftOpRegData(addr, data, len, 2, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADD_REG_MEM:
      len = 4;
      return Instruction::LiftOpRegMem(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADD_MEM_REG:
      len = 4;
      return Instruction::LiftOpMemReg(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Add));
    default:
      BN::LogError("0x%lx: Add::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Addb::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
                size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::ADDB_RBN_RBM:
      len = 2;
      return Instruction::LiftOpRnRm(data, len, 1, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::LiftOpRnRwiData3(addr, data, len, 1, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDB_REG_DATA8:
      len = 4;
      return Instruction::LiftOpRegData(addr, data, len, 1, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDB_REG_MEM:
      len = 4;
      return Instruction::LiftOpRegMem(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDB_MEM_REG:
      len = 4;
      return Instruction::LiftOpMemReg(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Add));
    default:
      BN::LogError("0x%lx: Add::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Addc::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
                size_t &len, BN::LowLevelILFunction &il) {
  // TODO: Handle carry
  switch (op) {
    case Opcodes::ADDC_RWN_RWM:
      len = 2;
      return Instruction::LiftOpRnRm(data, len, 2, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDC_RWN_RWI_DATA3:
      len = 2;
      return Instruction::LiftOpRnRwiData3(addr, data, len, 2, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDC_REG_DATA16:
      len = 4;
      return Instruction::LiftOpRegData(addr, data, len, 2, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDC_REG_MEM:
      len = 4;
      return Instruction::LiftOpRegMem(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDC_MEM_REG:
      len = 4;
      return Instruction::LiftOpMemReg(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Add));
    default:
      BN::LogError("0x%lx: Addc::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Addcb::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
                 size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::ADDCB_RBN_RBM:
      len = 2;
      return Instruction::LiftOpRnRm(data, len, 1, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDCB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::LiftOpRnRwiData3(addr, data, len, 1, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDCB_REG_DATA8:
      len = 4;
      return Instruction::LiftOpRegData(addr, data, len, 1, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDCB_REG_MEM:
      len = 4;
      return Instruction::LiftOpRegMem(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Add));
    case Opcodes::ADDCB_MEM_REG:
      len = 4;
      return Instruction::LiftOpMemReg(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Add));
    default:
      BN::LogError("0x%lx: Addcb::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool And::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
               size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::AND_RWN_RWM:
      len = 2;
      return Instruction::LiftOpRnRm(data, len, 2, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::And));
    case Opcodes::AND_RWN_RWI_DATA3:
      len = 2;
      return Instruction::LiftOpRnRwiData3(addr, data, len, 2, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::And));
    case Opcodes::AND_REG_DATA16:
      len = 4;
      return Instruction::LiftOpRegData(addr, data, len, 2, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::And));
    case Opcodes::AND_REG_MEM:
      len = 4;
      return Instruction::LiftOpRegMem(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::And));
    case Opcodes::AND_MEM_REG:
      len = 4;
      return Instruction::LiftOpMemReg(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::And));
    default:
      BN::LogError("0x%lx: And::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Andb::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
                size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::ANDB_RBN_RBM:
      len = 2;
      return Instruction::LiftOpRnRm(data, len, 1, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::And));
    case Opcodes::ANDB_RBN_RWI_DATA3:
      len = 2;
      return Instruction::LiftOpRnRwiData3(addr, data, len, 1, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::And));
    case Opcodes::ANDB_REG_DATA8:
      len = 4;
      return Instruction::LiftOpRegData(addr, data, len, 1, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::And));
    case Opcodes::ANDB_REG_MEM:
      len = 4;
      return Instruction::LiftOpRegMem(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::And));
    case Opcodes::ANDB_MEM_REG:
      len = 4;
      return Instruction::LiftOpMemReg(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::And));
    default:
      BN::LogError("0x%lx: Andb::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Ashr::LiftxAC(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  il.AddInstruction(il.SetRegister(
      2, rwn, il.ArithShiftRight(2, il.Register(2, rwn), il.Register(2, rwm)),
      flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Ashr::LiftxBC(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, length);
  const auto data4 = Instruction::GetData4High(data, length);

  il.AddInstruction(il.SetRegister(
      2, rwn, il.ArithShiftRight(2, il.Register(2, rwn), il.Const(1, data4)),
      flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Band::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  const uint32_t qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const uint32_t zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  const uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  const uint8_t zpos = *(data + 3) & 0xFu;

  BN::ExprId qq, zz;

  if (zaddr <= 0xF) {
    zz = il.Register(2, zaddr);
  } else {
    zz = il.Load(2, il.ConstPointer(3, zaddr));
  }

  if (qaddr <= 0xF) {
    qq = il.Register(2, qaddr);
  } else {
    qq = il.Load(2, il.ConstPointer(3, qaddr));
  }

  BN::ExprId zz_bit = il.LogicalShiftRight(2, zz, il.Const(2, zpos));
  zz_bit = il.And(2, zz_bit, il.Const(2, 1));

  BN::ExprId qq_bit = il.LogicalShiftRight(2, qq, il.Const(2, qpos));
  qq_bit = il.And(2, qq_bit, il.Const(2, 1));

  BN::ExprId res_bit =
      il.ShiftLeft(2, il.And(2, qq_bit, zz_bit), il.Const(2, zpos));
  BN::ExprId res_masked = il.And(2, zz, il.Const(2, ~(0b1u << zpos)));
  BN::ExprId result = il.Or(2, res_bit, res_masked);

  BN::ExprId instr;
  if (zaddr <= 0xF) {
    instr = il.SetRegister(2, zaddr, result, flags);
  } else {
    instr = il.Store(2, il.ConstPointer(3, zaddr), result, flags);
  }

  il.AddInstruction(instr);

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Bclr::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  uint8_t bitpos = Instruction::GetBitPosition(data, length);
  uint32_t bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));

  if (bitaddr <= 0xF) {
    il.AddInstruction(il.SetRegister(
        2, bitaddr,
        il.And(2, il.Register(2, bitaddr), il.Const(2, ~(0b1u << bitpos)))));
  } else {
    il.AddInstruction(
        il.Store(2, il.ConstPointer(3, bitaddr),
                 il.And(2, il.Load(2, il.ConstPointer(3, bitaddr)),
                        il.Const(2, ~(0b1u << bitpos)))));
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Bcmp::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  const uint32_t qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const uint32_t zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  const uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  const uint8_t zpos = *(data + 3) & 0xFu;

  BN::ExprId qq, zz;

  if (zaddr <= 0xF) {
    zz = il.Register(2, zaddr);
    if (qaddr <= 0xF) {  // reg <- reg
      qq = il.Register(2, qaddr);
    } else {  // reg <- mem
      qq = il.Load(2, il.ConstPointer(3, qaddr));
    }

    qq = il.LogicalShiftRight(2, qq, il.Const(2, qpos));
    qq = il.And(2, qq, il.Const(2, 0x0001));

    zz = il.LogicalShiftRight(2, zz, il.Const(2, zpos));
    zz = il.And(2, zz, il.Const(2, 0x0001));
  } else {
    zz = il.Load(2, il.ConstPointer(3, zaddr));
    if (qaddr <= 0xF) {  // mem <- reg
      qq = il.Register(2, qaddr);
    } else {  // mem <- mem
      qq = il.Load(2, il.ConstPointer(3, qaddr));
    }

    qq = il.LogicalShiftRight(2, qq, il.Const(2, qpos));
    qq = il.And(2, qq, il.Const(2, 0x0001));

    zz = il.LogicalShiftRight(2, zz, il.Const(2, zpos));
    zz = il.And(2, zz, il.Const(2, 0x0001));
  }

  il.AddInstruction(il.SetFlag(Flags::FLAG_E, il.Const(2, 0)));
  il.AddInstruction(il.SetFlag(Flags::FLAG_ZERO, il.Not(2, il.Or(2, qq, zz))));
  il.AddInstruction(il.SetFlag(Flags::FLAG_OVERFLOW, il.Or(2, qq, zz)));
  il.AddInstruction(il.SetFlag(Flags::FLAG_CARRY, il.And(2, qq, zz)));
  il.AddInstruction(il.SetFlag(Flags::FLAG_NEGATIVE, il.Xor(2, qq, zz)));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Bfldh::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                 BN::LowLevelILFunction &il) {  // TODO: Fully implement
  char buf[32];
  uint32_t bitoff = Instruction::TranslateBitOff(addr, *(data + 1));
  uint8_t data8 = *(data + 2);
  uint8_t mask8 = *(data + 3);

  if (bitoff < 0xF) {
    il.Unimplemented();  // TODO: Reference byte register (+17)
  } else {
    il.UnimplementedMemoryRef(
        1, il.ConstPointer(3, bitoff + 1));  // TODO: Verify offset
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Bfldl::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                 BN::LowLevelILFunction &il) {  // TODO: Fully implement
  char buf[32];
  uint32_t bitoff = Instruction::TranslateBitOff(addr, *(data + 1));
  uint8_t mask8 = *(data + 2);
  uint8_t data8 = *(data + 3);

  if (bitoff < 0xF) {
    il.Unimplemented();  // TODO: Reference byte register (+16)
  } else {
    il.UnimplementedMemoryRef(
        1, il.ConstPointer(3, bitoff));  // TODO: Verify (non-)offset
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Bmov::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  const uint32_t qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const uint32_t zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  const uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  const uint8_t zpos = *(data + 3) & 0xFu;

  BN::ExprId qq, zz;

  if (zaddr <= 0xF) {
    zz = il.Register(2, zaddr);
  } else {
    zz = il.Load(2, il.ConstPointer(3, zaddr));
  }

  if (qaddr <= 0xF) {
    qq = il.Register(2, qaddr);
  } else {
    qq = il.Load(2, il.ConstPointer(3, qaddr));
  }

  BN::ExprId qq_bit = il.LogicalShiftRight(2, qq, il.Const(2, qpos));
  qq_bit = il.And(2, qq_bit, il.Const(2, 1));

  BN::ExprId res_bit = il.ShiftLeft(2, qq_bit, il.Const(2, zpos));
  BN::ExprId res_masked = il.And(2, zz, il.Const(2, ~(0b1u << zpos)));
  BN::ExprId result = il.Or(2, res_bit, res_masked);

  BN::ExprId instr;
  if (zaddr <= 0xF) {
    instr = il.SetRegister(2, zaddr, result, flags);
  } else {
    instr = il.Store(2, il.ConstPointer(3, zaddr), result, flags);
  }

  il.AddInstruction(instr);

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Bmovn::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                 BN::LowLevelILFunction &il) {
  const uint32_t qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const uint32_t zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  const uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  const uint8_t zpos = *(data + 3) & 0xFu;

  BN::ExprId qq, zz;

  if (zaddr <= 0xF) {
    zz = il.Register(2, zaddr);
  } else {
    zz = il.Load(2, il.ConstPointer(3, zaddr));
  }

  if (qaddr <= 0xF) {
    qq = il.Register(2, qaddr);
  } else {
    qq = il.Load(2, il.ConstPointer(3, qaddr));
  }

  BN::ExprId qq_bit = il.Not(2, il.LogicalShiftRight(2, qq, il.Const(2, qpos)));
  qq_bit = il.And(2, qq_bit, il.Const(2, 1));

  BN::ExprId res_bit = il.ShiftLeft(2, qq_bit, il.Const(2, zpos));
  BN::ExprId res_masked = il.And(2, zz, il.Const(2, ~(0b1u << zpos)));
  BN::ExprId result = il.Or(2, res_bit, res_masked);

  BN::ExprId instr;
  if (zaddr <= 0xF) {
    instr = il.SetRegister(2, zaddr, result, flags);
  } else {
    instr = il.Store(2, il.ConstPointer(3, zaddr), result, flags);
  }

  il.AddInstruction(instr);

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Bor::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
               BN::LowLevelILFunction &il) {
  const uint32_t qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const uint32_t zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  const uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  const uint8_t zpos = *(data + 3) & 0xFu;

  BN::ExprId qq, zz;

  if (zaddr <= 0xF) {
    zz = il.Register(2, zaddr);
  } else {
    zz = il.Load(2, il.ConstPointer(3, zaddr));
  }

  if (qaddr <= 0xF) {
    qq = il.Register(2, qaddr);
  } else {
    qq = il.Load(2, il.ConstPointer(3, qaddr));
  }

  BN::ExprId zz_bit = il.LogicalShiftRight(2, zz, il.Const(2, zpos));
  zz_bit = il.And(2, zz_bit, il.Const(2, 1));

  BN::ExprId qq_bit = il.LogicalShiftRight(2, qq, il.Const(2, qpos));
  qq_bit = il.And(2, qq_bit, il.Const(2, 1));

  BN::ExprId res_bit =
      il.ShiftLeft(2, il.Or(2, qq_bit, zz_bit), il.Const(2, zpos));
  BN::ExprId res_masked = il.And(2, zz, il.Const(2, ~(0b1u << zpos)));
  BN::ExprId result = il.Or(2, res_bit, res_masked);

  BN::ExprId instr;
  if (zaddr <= 0xF) {
    instr = il.SetRegister(2, zaddr, result, flags);
  } else {
    instr = il.Store(2, il.ConstPointer(3, zaddr), result, flags);
  }

  il.AddInstruction(instr);

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Bxor::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  const uint32_t qaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const uint32_t zaddr = Instruction::TranslateBitOff(addr, *(data + 2));
  const uint8_t qpos = (*(data + 3) & (0xFu << 4u)) >> 4u;
  const uint8_t zpos = *(data + 3) & 0xFu;

  BN::ExprId qq, zz;

  if (zaddr <= 0xF) {
    zz = il.Register(2, zaddr);
  } else {
    zz = il.Load(2, il.ConstPointer(3, zaddr));
  }

  if (qaddr <= 0xF) {
    qq = il.Register(2, qaddr);
  } else {
    qq = il.Load(2, il.ConstPointer(3, qaddr));
  }

  BN::ExprId zz_bit = il.LogicalShiftRight(2, zz, il.Const(2, zpos));
  zz_bit = il.And(2, zz_bit, il.Const(2, 1));

  BN::ExprId qq_bit = il.LogicalShiftRight(2, qq, il.Const(2, qpos));
  qq_bit = il.And(2, qq_bit, il.Const(2, 1));

  BN::ExprId res_bit =
      il.ShiftLeft(2, il.Xor(2, qq_bit, zz_bit), il.Const(2, zpos));
  BN::ExprId res_masked = il.And(2, zz, il.Const(2, ~(0b1u << zpos)));
  BN::ExprId result = il.Or(2, res_bit, res_masked);

  BN::ExprId instr;
  if (zaddr <= 0xF) {
    instr = il.SetRegister(2, zaddr, result, flags);
  } else {
    instr = il.Store(2, il.ConstPointer(3, zaddr), result, flags);
  }

  il.AddInstruction(instr);

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Bset::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  uint8_t bitpos = Instruction::GetBitPosition(data, length);
  uint32_t bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));

  if (bitaddr <= 0xF) {
    il.AddInstruction(il.SetRegister(
        2, bitaddr,
        il.Or(2, il.Register(2, bitaddr), il.Const(2, 0b1u << bitpos))));
  } else {
    il.AddInstruction(il.Store(2, il.ConstPointer(3, bitaddr),
                               il.Or(2, il.Load(2, il.ConstPointer(3, bitaddr)),
                                     il.Const(2, 0b1u << bitpos))));
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Calla::Lift(BN::Architecture *arch, const uint8_t *data,
                 const uint64_t addr, size_t &len, BN::LowLevelILFunction &il) {
  const auto code = GetConditionCode(data, length);
  const auto target = GetTarget(data, addr, length);

  if (code == Conditions::CC_UC) {
    il.AddInstruction(
        il.Call(il.ConstPointer(3, GetTarget(data, addr, length))));
  } else {
    BN::ExprId condition =
        il.FlagCondition(Instruction::GetFlagCondition(code));
    BNLowLevelILLabel *t = il.GetLabelForAddress(arch, target);
    BNLowLevelILLabel *f = il.GetLabelForAddress(arch, addr + length);

    if (!t || !f) {  // This should never happen!
      BN::LogDebug("0x%lx: Calla::%s Failed to find true/false labels!", addr,
                   __func__);
      return false;
    }
    il.AddInstruction(il.If(condition, *t, *f));
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Calli::Lift(BN::Architecture *arch, const uint8_t *data,
                 const uint64_t addr, size_t &len, BN::LowLevelILFunction &il) {
  const auto code = GetConditionCode(data, length);
  const auto rwn = Instruction::GetData4Low(data, length);

  if (code == Conditions::CC_UC) {
    il.AddInstruction(il.Call(il.Register(2, rwn)));
  } else {
    BN::LogDebug("[L] 0x%lx: Unhandled Calli variant", addr);
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Callr::Lift(BN::Architecture *arch, const uint8_t *data,
                 const uint64_t addr, size_t &len, BN::LowLevelILFunction &il) {
  il.AddInstruction(il.Call(il.ConstPointer(3, GetTarget(data, addr, length))));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Calls::Lift(BN::Architecture *arch, const uint8_t *data,
                 const uint64_t addr, size_t &len, BN::LowLevelILFunction &il) {
  il.AddInstruction(il.Call(il.ConstPointer(3, GetTarget(data, length))));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmp::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
               size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::CMP_RWN_RWM:
      len = 2;
      UpdateExtSequence(addr, len);
      return Instruction::LiftOpRnRm(data, len, 2, flags, false, il,
                                     IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::CMP_RWN_RWI_DATA3:
      len = 2;
      UpdateExtSequence(addr, len);
      return Instruction::LiftOpRnRwiData3(addr, data, len, 2, flags, false, il,
                                           IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::CMP_REG_DATA16:
      len = 4;
      UpdateExtSequence(addr, len);
      return Instruction::LiftOpRegData(addr, data, len, 2, flags, false, il,
                                        IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::CMP_REG_MEM:
      len = 4;
      UpdateExtSequence(addr, len);
      return Instruction::LiftOpRegMem(addr, data, len, 2, flags, false, il,
                                       IL_OP(BN::LowLevelILFunction::Sub));
    default:
      BN::LogError("0x%lx: Cmp::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Cmpb::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
                size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::CMPB_RBN_RBM:
      len = 2;
      UpdateExtSequence(addr, len);
      return Instruction::LiftOpRnRm(data, len, 1, flags, false, il,
                                     IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::CMPB_RBN_RWI_DATA3:
      len = 2;
      UpdateExtSequence(addr, len);
      return Instruction::LiftOpRnRwiData3(addr, data, len, 1, flags, false, il,
                                           IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::CMPB_REG_DATA8:
      len = 4;
      UpdateExtSequence(addr, len);
      return Instruction::LiftOpRegData(addr, data, len, 1, flags, false, il,
                                        IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::CMPB_REG_MEM:
      len = 4;
      UpdateExtSequence(addr, len);
      return Instruction::LiftOpRegMem(addr, data, len, 1, flags, false, il,
                                       IL_OP(BN::LowLevelILFunction::Sub));
    default:
      BN::LogError("0x%lx: Cmpb::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Cmpd1::LiftxA0(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto data4 = Instruction::GetData4High(data, 2);
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn), il.Const(2, data4), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Sub(2, il.Register(2, rwn), il.Const(2, 1))));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpd1::LiftxA2(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn),
                           il.Load(2, il.ConstPointer(3, mem)), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Sub(2, il.Register(2, rwn), il.Const(2, 1))));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpd1::LiftxA6(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const uint32_t data16 = Instruction::GetData16(data, 4);
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn), il.Const(2, data16), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Sub(2, il.Register(2, rwn), il.Const(2, 1))));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpd2::LiftxB0(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto data4 = Instruction::GetData4High(data, 2);
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn), il.Const(2, data4), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Sub(2, il.Register(2, rwn), il.Const(2, 2))));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpd2::LiftxB2(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn),
                           il.Load(2, il.ConstPointer(3, mem)), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Sub(2, il.Register(2, rwn), il.Const(2, 1))));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpd2::LiftxB6(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const uint32_t data16 = Instruction::GetData16(data, 4);
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn), il.Const(2, data16), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Sub(2, il.Register(2, rwn), il.Const(2, 2))));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpi1::Liftx80(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto data4 = Instruction::GetData4High(data, 2);
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn), il.Const(2, data4), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Add(2, il.Register(2, rwn), il.Const(2, 1))));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpi1::Liftx82(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn),
                           il.Load(2, il.ConstPointer(3, mem)), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Add(2, il.Register(2, rwn), il.Const(2, 1))));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpi1::Liftx86(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const uint32_t data16 = Instruction::GetData16(data, 4);
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn), il.Const(2, data16), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Add(2, il.Register(2, rwn), il.Const(2, 1))));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpi2::Liftx90(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto data4 = Instruction::GetData4High(data, 2);
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn), il.Const(2, data4), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Add(2, il.Register(2, rwn), il.Const(2, 2))));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpi2::Liftx92(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn),
                           il.Load(2, il.ConstPointer(3, mem)), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Add(2, il.Register(2, rwn), il.Const(2, 1))));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cmpi2::Liftx96(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const uint32_t data16 = Instruction::GetData16(data, 4);
  const auto rwn = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.Sub(2, il.Register(2, rwn), il.Const(2, data16), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Add(2, il.Register(2, rwn), il.Const(2, 2))));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cpl::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
               BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);

  il.AddInstruction(il.Not(2, il.Register(2, rwn), flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Cplb::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  const uint32_t rbn = Instruction::GetData4High(data, length) + 16;

  il.AddInstruction(il.Not(1, il.Register(1, rbn), flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Diswdt::Lift(const uint8_t *data, uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  UNIMPLEMENTED(length);
}

bool Div::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
               BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);

  const auto div = il.DivDoublePrecSigned(
      2, il.Load(2, il.ConstPointer(3, Sfr::MDL)), il.Register(2, rwn), flags);
  const auto mod = il.ModDoublePrecSigned(
      2, il.Load(2, il.ConstPointer(3, Sfr::MDL)), il.Register(2, rwn), flags);

  il.AddInstruction(il.Store(2, il.ConstPointer(3, Sfr::MDL), div));
  il.AddInstruction(il.Store(2, il.ConstPointer(3, Sfr::MDH), mod));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Divl::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);

  const auto div = il.DivDoublePrecSigned(
      2, il.Load(4, il.ConstPointer(3, Sfr::MD)), il.Register(2, rwn), flags);
  const auto mod = il.ModDoublePrecSigned(
      2, il.Load(4, il.ConstPointer(3, Sfr::MD)), il.Register(2, rwn), flags);

  il.AddInstruction(il.Store(2, il.ConstPointer(3, Sfr::MDL), div));
  il.AddInstruction(il.Store(2, il.ConstPointer(3, Sfr::MDH), mod));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Divlu::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                 BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);

  const auto div = il.DivDoublePrecUnsigned(
      2, il.Load(4, il.ConstPointer(3, Sfr::MD)), il.Register(2, rwn), flags);
  const auto mod = il.ModDoublePrecUnsigned(
      2, il.Load(4, il.ConstPointer(3, Sfr::MD)), il.Register(2, rwn), flags);

  il.AddInstruction(il.Store(2, il.ConstPointer(3, Sfr::MDL), div));
  il.AddInstruction(il.Store(2, il.ConstPointer(3, Sfr::MDH), mod));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Divu::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);

  auto div = il.DivDoublePrecUnsigned(
      2, il.Load(2, il.ConstPointer(3, Sfr::MDL)), il.Register(2, rwn), flags);
  auto mod = il.ModDoublePrecUnsigned(
      2, il.Load(2, il.ConstPointer(3, Sfr::MDL)), il.Register(2, rwn), flags);

  il.AddInstruction(il.Store(2, il.ConstPointer(3, Sfr::MDL), div));
  il.AddInstruction(il.Store(2, il.ConstPointer(3, Sfr::MDH), mod));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Einit::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                 BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  UNIMPLEMENTED(length);
}

bool ExtrAtomic::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                      BN::LowLevelILFunction &il) {
  // EXTR/ATOMIC
  uint8_t num_insns = ((data[1] & 0b00110000) >> 4) + 1;
  Instruction::SetExtr(addr + length, num_insns - 1);

  UNIMPLEMENTED(length);
}

bool Extprs::LiftxD7(const uint8_t *data, const uint64_t addr, size_t &len,
                     BN::LowLevelILFunction &il) {
  uint8_t num_insns = ((data[1] & 0b00110000) >> 4) + 1;
  if ((data[1] & 0b11000000) == 0b00000000) {
    // EXTS
    uint16_t seg8 = data[2];
    Instruction::SetExtsSeg8(addr + 4, seg8, num_insns - 1);
  } else if ((data[1] & 0b11000000) == 0b01000000) {
    // EXTP
    uint16_t pag10 = ((data[3] & 0b11) << 8) | data[2];
    Instruction::SetExtpPag10(addr + 4, pag10, num_insns - 1);
  } else if ((data[1] & 0b11000000) == 0b10000000) {
    // TODO: EXTSR
  } else {
    // TODO: EXTPR
  }

  UNIMPLEMENTED(4);
}

bool Extprs::LiftxDC(const uint8_t *data, const uint64_t addr, size_t &len,
                     BN::LowLevelILFunction &il) {
  // TODO: EXTP
  UNIMPLEMENTED(2);
}

bool Idle::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  UNIMPLEMENTED(length);
}

bool Jb::Lift(BN::Architecture *arch, const uint8_t *data, const uint64_t addr,
              size_t &len, BN::LowLevelILFunction &il) {
  const auto target = GetTarget(data, addr, length);
  const uint32_t bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const uint8_t bitpos = (*(data + 3) & (0xFu << 4u)) >> 4u;

  BN::ExprId bitval, condition;
  BNLowLevelILLabel *t, *f;

  if (bitaddr <= 0xF) {
    bitval =
        il.And(2, il.Register(2, bitaddr), il.Const(2, 0b1u << bitpos), flags);
  } else {
    bitval = il.And(2, il.Load(2, il.ConstPointer(3, bitaddr)),
                    il.Const(2, 0b1u << bitpos), flags);
  }
  il.AddInstruction(bitval);

  condition =
      il.FlagCondition(Instruction::GetFlagCondition(Conditions::CC_NZ));
  t = il.GetLabelForAddress(arch, target);
  f = il.GetLabelForAddress(arch, addr + length);

  if (!t || !f) {  // This should never happen!
    BN::LogDebug("0x%lx: Jb::%s Failed to find true/false labels!", addr,
                 __func__);
    return false;
  }
  il.AddInstruction(il.If(condition, *t, *f));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Jbc::Lift(BN::Architecture *arch, const uint8_t *data, const uint64_t addr,
               size_t &len, BN::LowLevelILFunction &il) {
  const auto target = GetTarget(data, addr, length);
  const uint32_t bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const uint8_t bitpos = (*(data + 3) & (0xFu << 4u)) >> 4u;

  BN::ExprId condition;
  BNLowLevelILLabel *t, *f;

  if (bitaddr <= 0xF) {
    il.AddInstruction(
        il.And(2, il.Register(2, bitaddr), il.Const(2, 0b1u << bitpos), flags));
    il.AddInstruction(il.SetRegister(
        2, bitaddr,
        il.And(2, il.Register(2, bitaddr), il.Const(2, ~(0b1u << bitpos)))));
  } else {
    il.AddInstruction(il.And(2, il.Load(2, il.ConstPointer(3, bitaddr)),
                             il.Const(2, 0b1u << bitpos)));
    il.AddInstruction(
        il.Store(2, il.ConstPointer(3, bitaddr),
                 il.And(2, il.Load(2, il.ConstPointer(3, bitaddr)),
                        il.Const(2, ~(0b1u << bitpos)))));
  }

  condition =
      il.FlagCondition(Instruction::GetFlagCondition(Conditions::CC_NZ));
  t = il.GetLabelForAddress(arch, target);
  f = il.GetLabelForAddress(arch, addr + length);

  if (!t || !f) {  // This should never happen!
    BN::LogDebug("0x%lx: Jbc::%s Failed to find true/false labels!", addr,
                 __func__);
    return false;
  }
  il.AddInstruction(il.If(condition, *t, *f));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Jmpa::Lift(BN::Architecture *arch, const uint8_t *data,
                const uint64_t addr, size_t &len, BN::LowLevelILFunction &il) {
  const auto code = GetConditionCode(data, length);
  const auto target = GetTarget(data, addr, length);

  if (code == Conditions::CC_UC) {
    len = length;
    UpdateExtSequence(addr, len);

    return Instruction::JumpDirect(arch, il, target);
  } else {
    BN::ExprId condition =
        il.FlagCondition(Instruction::GetFlagCondition(code));
    BNLowLevelILLabel *t = il.GetLabelForAddress(arch, target);
    BNLowLevelILLabel *f = il.GetLabelForAddress(arch, addr + length);

    if (!t || !f) {  // This should never happen!
      BN::LogDebug("0x%lx: Jmpa::%s Failed to find true/false labels!", addr,
                   __func__);
      return false;
    }
    il.AddInstruction(il.If(condition, *t, *f));
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Jmpi::Lift(BN::Architecture *arch, const uint8_t *data,
                const uint64_t addr, size_t &len, BN::LowLevelILFunction &il) {
  const auto code = Instruction::GetData4High(data, length);
  const auto rwn = Instruction::GetData4Low(data, length);

  if (code == Conditions::CC_UC) {
    len = length;
    UpdateExtSequence(addr, len);

    return Instruction::JumpIndirect(arch, il, rwn, addr);
  } else {
    BN::LogDebug("0x%lx: Jmpi::%s -- unhandled conditional code", addr,
                 __func__);
    return false;
  }
}

bool Jmpr::Lift(BN::Architecture *arch, const uint8_t *data,
                const uint64_t addr, size_t &len, BN::LowLevelILFunction &il) {
  const auto code = GetConditionCode(data, length);
  const auto target = GetTarget(data, addr, length);

  if (code == Conditions::CC_UC) {
    len = length;
    UpdateExtSequence(addr, len);

    return Instruction::JumpDirect(arch, il, target);
  } else {
    BN::ExprId condition =
        il.FlagCondition(Instruction::GetFlagCondition(code));
    BNLowLevelILLabel *t = il.GetLabelForAddress(arch, target);
    BNLowLevelILLabel *f = il.GetLabelForAddress(arch, addr + length);

    if (!t || !f) {  // This should never happen!
      BN::LogDebug("0x%lx: Jmpr::%s Failed to find true/false labels!", addr,
                   __func__);
      return false;
    }
    il.AddInstruction(il.If(condition, *t, *f));
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Jmps::Lift(BN::Architecture *arch, const uint8_t *data,
                const uint64_t addr, size_t &len, BN::LowLevelILFunction &il) {
  len = length;
  UpdateExtSequence(addr, len);

  return Instruction::JumpDirect(arch, il, GetTarget(data, length));
}

bool Jnb::Lift(BN::Architecture *arch, const uint8_t *data, const uint64_t addr,
               size_t &len, BN::LowLevelILFunction &il) {
  const auto target = GetTarget(data, addr, length);
  const uint32_t bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const uint8_t bitpos = (*(data + 3) & (0xFu << 4u)) >> 4u;

  BN::ExprId condition;
  BNLowLevelILLabel *t, *f;

  if (bitaddr <= 0xF) {
    il.AddInstruction(
        il.And(2, il.Register(2, bitaddr), il.Const(2, 0b1u << bitpos), flags));
  } else {
    il.AddInstruction(il.And(2, il.Load(2, il.ConstPointer(3, bitaddr)),
                             il.Const(2, 0b1u << bitpos), flags));
  }

  condition = il.FlagCondition(Instruction::GetFlagCondition(Conditions::CC_Z));
  t = il.GetLabelForAddress(arch, target);
  f = il.GetLabelForAddress(arch, addr + length);

  if (!t || !f) {  // This should never happen!
    BN::LogDebug("0x%lx: Jnb::%s Failed to find true/false labels!", addr,
                 __func__);
    return false;
  }
  il.AddInstruction(il.If(condition, *t, *f));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Jnbs::Lift(BN::Architecture *arch, const uint8_t *data,
                const uint64_t addr, size_t &len, BN::LowLevelILFunction &il) {
  const auto target = GetTarget(data, addr, length);
  const uint32_t bitaddr = Instruction::TranslateBitOff(addr, *(data + 1));
  const uint8_t bitpos = (*(data + 3) & (0xFu << 4u)) >> 4u;

  BN::ExprId condition;
  BNLowLevelILLabel *t, *f;

  if (bitaddr <= 0xF) {
    il.AddInstruction(
        il.And(2, il.Register(2, bitaddr), il.Const(2, 0b1u << bitpos), flags));
    il.AddInstruction(il.SetRegister(
        2, bitaddr,
        il.Or(2, il.Register(2, bitaddr), il.Const(2, 0b1u << bitpos))));
  } else {
    il.AddInstruction(il.And(2, il.Load(2, il.ConstPointer(3, bitaddr)),
                             il.Const(2, 0b1u << bitpos)));
    il.AddInstruction(il.Store(2, il.ConstPointer(3, bitaddr),
                               il.Or(2, il.Load(2, il.ConstPointer(3, bitaddr)),
                                     il.Const(2, 0b1u << bitpos))));
  }

  condition = il.FlagCondition(Instruction::GetFlagCondition(Conditions::CC_Z));
  t = il.GetLabelForAddress(arch, target);
  f = il.GetLabelForAddress(arch, addr + length);

  if (!t || !f) {  // This should never happen!
    BN::LogDebug("0x%lx: Jnbs::%s Failed to find true/false labels!", addr,
                 __func__);
    return false;
  }
  il.AddInstruction(il.If(condition, *t, *f));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Mov::Liftx84(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  il.AddInstruction(il.Store(2, il.Register(2, rwn),
                             il.Load(2, il.ConstPointer(3, mem)), flags));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

// MOV [-Rw_m], Rw_n
// Format: 88 nm
bool Mov::Liftx88(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId DstIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  auto arch = il.GetArchitecture();
  uint32_t sp;
  if (arch.GetPtr() == nullptr) {
    BN::LogDebug("0x%lx: %s GetBN::Architecture returned nullptr", addr,
                 __PRETTY_FUNCTION__);
    sp = Registers::R0;
  } else {
    sp = arch->GetStackPointerRegister();
  }

  if (rwm == sp)
    il.AddInstruction(il.Push(2, il.Register(2, rwn)));
  else {
    il.AddInstruction(
        il.SetRegister(2, rwm, il.Sub(2, il.Register(2, rwm), il.Const(2, 2))));
    il.AddInstruction(il.Store(2, DstIndAddr, il.Register(2, rwn), flags));
  }

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Mov::Liftx94(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  il.AddInstruction(il.Store(2, il.ConstPointer(3, mem),
                             il.Load(2, il.Register(2, rwn)), flags));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

// MOV Rw_n, [Rw_m+]
// Format:
bool Mov::Liftx98(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId SrcIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  auto arch = il.GetArchitecture();
  uint32_t sp;
  if (arch.GetPtr() == nullptr) {
    BN::LogDebug("0x%lx: %s GetBN::Architecture returned nullptr", addr,
                 __PRETTY_FUNCTION__);
    sp = Registers::R0;
  } else {
    sp = arch->GetStackPointerRegister();
  }

  if (rwm == sp)
    il.AddInstruction(il.SetRegister(2, rwn, il.Pop(2)));
  else {
    il.AddInstruction(il.SetRegister(2, rwn, il.Load(2, SrcIndAddr), flags));
    il.AddInstruction(il.SetRegister(
        2, rwm, il.Add(2, il.Register(2, rwm), il.Const(2, 2))));  // [Rw_m+]
  }

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

// MOV Rw_n, [Rw_m]
// Format: A8 nm
bool Mov::LiftxA8(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId SrcIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  il.AddInstruction(il.SetRegister(2, rwn, il.Load(2, SrcIndAddr), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

// MOV [Rw_m], Rw_n
// Format: B8 nm
bool Mov::LiftxB8(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId DstIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  il.AddInstruction(il.Store(2, DstIndAddr, il.Register(2, rwn), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

// MOV [Rw_m + data16], Rw_n
// Format: C4 nm ## ##
bool Mov::LiftxC4(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);
  const auto data16 = Instruction::GetData16(data, 4);

  BN::ExprId DstIndAddr;
  uint32_t seg8, pag10;
  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr =
        Instruction::GetIndAddrExpr_Exts_Rw_data16(il, seg8, rwm, data16);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr =
        Instruction::GetIndAddrExpr_Extp_Rw_data16(il, pag10, rwm, data16);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw_data16(il, rwm, data16);
  }

  il.AddInstruction(il.Store(2, DstIndAddr, il.Register(2, rwn), flags));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

// MOV [Rw_n], [Rw_m]
// Format: C8 nm
bool Mov::LiftxC8(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId DstIndAddr, SrcIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  il.AddInstruction(il.Store(2, DstIndAddr, il.Load(2, SrcIndAddr), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

// MOV Rw_n, [Rw_m + #data16]
// Format: D4 nm ##  ##
bool Mov::LiftxD4(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);
  const auto data16 = Instruction::GetData16(data, 4);

  BN::ExprId SrcIndAddr;
  uint32_t seg8, pag10;
  if (Instruction::ShouldUseExts(addr, &seg8)) {
    SrcIndAddr =
        Instruction::GetIndAddrExpr_Exts_Rw_data16(il, seg8, rwm, data16);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    SrcIndAddr =
        Instruction::GetIndAddrExpr_Extp_Rw_data16(il, pag10, rwm, data16);
  } else {
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw_data16(il, rwm, data16);
  }

  il.AddInstruction(il.Store(2, il.Register(2, rwn), SrcIndAddr, flags));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

// MOV [Rw_n+], [Rw_m]
// Format: D8 nm
bool Mov::LiftxD8(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId DstIndAddr, SrcIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  il.AddInstruction(il.Store(2, DstIndAddr, il.Load(2, SrcIndAddr), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Add(2, il.Register(2, rwn), il.Const(2, 2))));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Mov::LiftxE0(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto data4 = Instruction::GetData4High(data, 2);

  il.AddInstruction(il.SetRegister(2, rwn, il.Const(2, data4), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Mov::LiftxE6(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));
  const auto data16 = Instruction::GetData16(data, 4);

  if (reg <= 0xF) {
    il.AddInstruction(il.SetRegister(2, reg, il.Const(2, data16), flags));
  } else {
    il.AddInstruction(
        il.Store(2, il.ConstPointer(3, reg), il.Const(2, data16), flags));
  }

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

// MOV [Rw_n], [Rw_m+]
// Format: E8 Nm
bool Mov::LiftxE8(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId DstIndAddr, SrcIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  il.AddInstruction(il.Store(2, DstIndAddr, il.Load(2, SrcIndAddr), flags));
  il.AddInstruction(
      il.SetRegister(2, rwm, il.Add(2, il.Register(2, rwm), il.Const(2, 2))));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Mov::LiftxF0(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  il.AddInstruction(il.SetRegister(2, rwn, il.Register(2, rwm), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Mov::LiftxF2(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));
  const auto mem = Instruction::GetMem(addr, data, len);

  if (reg <= 0xF) {
    il.AddInstruction(
        il.SetRegister(2, reg, il.Load(2, il.ConstPointer(3, mem)), flags));
  } else {
    il.AddInstruction(il.Store(2, il.ConstPointer(3, reg),
                               il.Load(2, il.ConstPointer(3, mem)), flags));
  }

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Mov::LiftxF6(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto mem = Instruction::GetMem(addr, data, len);
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));

  if (reg <= 0xF) {
    il.AddInstruction(
        il.Store(2, il.ConstPointer(3, mem), il.Register(2, reg), flags));
  } else {
    il.AddInstruction(il.Store(2, il.ConstPointer(3, mem),
                               Instruction::ElideReg(il, reg, 2), flags));
  }

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB [-Rw_m], Rb_n
// Format: 89 nm
bool Movb::Liftx89(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const uint32_t rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId DstIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  auto arch = il.GetArchitecture();
  uint32_t sp;
  if (arch.GetPtr() == nullptr) {
    BN::LogDebug("0x%lx: %s GetBN::Architecture returned nullptr", addr,
                 __PRETTY_FUNCTION__);
    sp = Registers::R0;
  } else {
    sp = arch->GetStackPointerRegister();
  }

  if (rwm == sp)
    il.AddInstruction(il.Push(1, il.Register(1, rbn), flags));
  else {
    il.AddInstruction(
        il.SetRegister(2, rwm, il.Sub(2, il.Register(2, rwm), il.Const(2, 1))));
    il.AddInstruction(il.Store(1, DstIndAddr, il.Register(1, rbn), flags));
  }

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB Rb_n, [Rw_m+]
// Format: 99 nm
bool Movb::Liftx99(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const uint32_t rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId SrcIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  auto arch = il.GetArchitecture();
  uint32_t sp;
  if (arch.GetPtr() == nullptr) {
    BN::LogDebug("0x%lx: %s GetBN::Architecture returned nullptr", addr,
                 __PRETTY_FUNCTION__);
    sp = Registers::R0;
  } else {
    sp = arch->GetStackPointerRegister();
  }

  if (rwm == sp)
    il.AddInstruction(il.SetRegister(1, rbn, il.Pop(2), flags));
  else {
    il.AddInstruction(il.SetRegister(1, rbn, il.Load(1, SrcIndAddr), flags));
    il.AddInstruction(il.SetRegister(
        2, rwm, il.Add(2, il.Register(2, rwm), il.Const(2, 1))));  // [Rw_m+]
  }

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB [Rw_n], mem
// Format: A4 0n MM MM
bool Movb::LiftxA4(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  BN::ExprId DstIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwn);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwn);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwn);
  }

  il.AddInstruction(
      il.Store(1, DstIndAddr, il.Load(1, il.ConstPointer(3, mem)), flags));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB mem, [Rw_n]
// Format: B4 0n MM MM
bool Movb::LiftxB4(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, 4));

  BN::ExprId SrcIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwn);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwn);
  } else {
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwn);
  }

  il.AddInstruction(
      il.Store(1, il.ConstPointer(3, mem), il.Load(1, SrcIndAddr), flags));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB Rb_n, [Rw_m]
// Format: A9 nm
bool Movb::LiftxA9(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const uint32_t rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId SrcIndAddr;
  uint32_t seg8, pag10;
  if (Instruction::ShouldUseExts(addr, &seg8)) {
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }
  il.AddInstruction(il.SetRegister(1, rbn, il.Load(1, SrcIndAddr), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB [Rw_m], Rb_n
// Format: B9 nm
bool Movb::LiftxB9(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const uint32_t rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId DstIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }
  il.AddInstruction(il.Store(1, DstIndAddr, il.Register(1, rbn), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB [Rw_n], [Rw_m]
// Format: C9 nm
bool Movb::LiftxC9(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId DstIndAddr, SrcIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  il.AddInstruction(il.Store(1, DstIndAddr, il.Load(1, SrcIndAddr), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB [Rw_n+], [Rw_m]
// Format: D9 nm
bool Movb::LiftxD9(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId DstIndAddr, SrcIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  il.AddInstruction(il.Store(1, DstIndAddr, il.Load(1, SrcIndAddr), flags));
  il.AddInstruction(
      il.SetRegister(2, rwn, il.Add(2, il.Register(2, rwn), il.Const(2, 1))));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB [Rw_m + #data16], Rb_n
// Format: E4 nm ## ##
bool Movb::LiftxE4(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const uint32_t rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);
  const auto data16 = Instruction::GetData16(data, 4);

  BN::ExprId DstIndAddr;
  uint32_t seg8, pag10;
  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr =
        Instruction::GetIndAddrExpr_Exts_Rw_data16(il, seg8, rwm, data16);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr =
        Instruction::GetIndAddrExpr_Extp_Rw_data16(il, pag10, rwm, data16);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw_data16(il, rwm, data16);
  }

  il.AddInstruction(il.Store(1, DstIndAddr, il.Register(1, rbn), flags));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB [Rw_n], [Rw_m+]
// Format: E9 nm
bool Movb::LiftxE9(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2);
  const auto rwm = Instruction::GetData4Low(data, 2);

  BN::ExprId DstIndAddr, SrcIndAddr;
  uint32_t seg8, pag10;

  if (Instruction::ShouldUseExts(addr, &seg8)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Exts_Rw(il, seg8, rwm);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    DstIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Extp_Rw(il, pag10, rwm);
  } else {
    DstIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwn);
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw(il, rwm);
  }

  il.AddInstruction(il.Store(1, DstIndAddr, il.Load(1, SrcIndAddr), flags));
  il.AddInstruction(
      il.SetRegister(2, rwm, il.Add(2, il.Register(2, rwm), il.Const(2, 1))));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movb::LiftxE1(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const uint32_t rbn = Instruction::GetData4Low(data, 2) + 16;
  const auto data4 = Instruction::GetData4High(data, 2);

  il.AddInstruction(il.SetRegister(1, rbn, il.Const(1, data4), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movb::LiftxE7(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));
  const auto data8 = Instruction::GetData8Low(data, 4);

  if (reg <= 0xF) {
    reg += 16;
    il.AddInstruction(il.SetRegister(1, reg, il.Const(1, data8), flags));
  } else {
    il.AddInstruction(
        il.Store(2, il.ConstPointer(3, reg), il.Const(1, data8), flags));
  }

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movb::LiftxF1(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2) + 16;

  il.AddInstruction(il.SetRegister(1, rwn, il.Register(1, rwm), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movb::LiftxF3(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));
  const auto mem = Instruction::GetMem(addr, data, len);

  if (reg <= 0xF) {
    reg += 16;
    il.AddInstruction(
        il.SetRegister(1, reg, il.Load(1, il.ConstPointer(3, mem)), flags));
  } else {
    il.AddInstruction(il.Store(1, il.ConstPointer(3, reg),
                               il.Load(1, il.ConstPointer(3, mem)), flags));
  }

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

// MOVB Rb_n, [Rw_m + #data16]
// Format: F4 nm ## ##
bool Movb::LiftxF4(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const uint32_t rbn = Instruction::GetData4High(data, 2) + 16;
  const auto rwm = Instruction::GetData4Low(data, 2);
  const auto data16 = Instruction::GetData16(data, 4);

  BN::ExprId SrcIndAddr;
  uint32_t seg8, pag10;
  if (Instruction::ShouldUseExts(addr, &seg8)) {
    SrcIndAddr =
        Instruction::GetIndAddrExpr_Exts_Rw_data16(il, seg8, rwm, data16);
  } else if (Instruction::ShouldUseExtp(addr, &pag10)) {
    SrcIndAddr =
        Instruction::GetIndAddrExpr_Extp_Rw_data16(il, pag10, rwm, data16);
  } else {
    SrcIndAddr = Instruction::GetIndAddrExpr_Rw_data16(il, rwm, data16);
  }

  il.AddInstruction(il.SetRegister(1, rbn, il.Load(1, SrcIndAddr), flags));

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movb::LiftxF7(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto mem = Instruction::GetMem(addr, data, len);
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));

  if (reg <= 0xF) {
    reg += 16;
    il.AddInstruction(
        il.Store(1, il.ConstPointer(3, mem), il.Register(1, reg), flags));
  } else {
    il.AddInstruction(il.Store(1, il.ConstPointer(3, mem),
                               Instruction::ElideReg(il, reg, 1), flags));
  }

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movbs::LiftxD0(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto rbm = Instruction::GetData4High(data, 2) + 16;

  il.AddInstruction(
      il.SetRegister(2, rwn, il.SignExtend(2, il.Register(1, rbm)), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movbs::LiftxD2(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));
  const auto mem = Instruction::GetMem(addr, data, len);

  if (reg <= 0xF) {
    il.AddInstruction(il.SetRegister(
        2, reg, il.SignExtend(2, il.Load(1, il.ConstPointer(3, mem))), flags));
  } else {
    il.AddInstruction(
        il.Store(2, il.ConstPointer(3, reg),
                 il.SignExtend(2, il.Load(1, il.ConstPointer(3, mem))), flags));
  }

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movbs::LiftxD5(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto mem = Instruction::GetMem(addr, data, len);
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));

  if (reg <= 0xF) {
    reg += 16;
    il.AddInstruction(il.Store(2, il.ConstPointer(3, mem),
                               il.SignExtend(2, il.Register(1, reg)), flags));
  } else {
    il.AddInstruction(
        il.Store(2, il.ConstPointer(3, mem),
                 il.SignExtend(2, il.Load(1, il.ConstPointer(3, reg))), flags));
  }

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movbz::LiftxC0(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, 2);
  const auto rbm = Instruction::GetData4High(data, 2) + 16;

  il.AddInstruction(
      il.SetRegister(2, rwn, il.ZeroExtend(2, il.Register(1, rbm)), flags));

  len = 2;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movbz::LiftxC2(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));
  const auto mem = Instruction::GetMem(addr, data, len);

  if (reg <= 0xF) {
    il.AddInstruction(il.SetRegister(
        2, reg, il.ZeroExtend(2, il.Load(1, il.ConstPointer(3, mem))), flags));
  } else {
    il.AddInstruction(
        il.Store(2, il.ConstPointer(3, reg),
                 il.ZeroExtend(2, il.Load(1, il.ConstPointer(3, mem))), flags));
  }

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Movbz::LiftxC5(const uint8_t *data, const uint64_t addr, size_t &len,
                    BN::LowLevelILFunction &il) {
  const auto mem = Instruction::GetMem(addr, data, len);
  uint32_t reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));

  if (reg <= 0xF) {
    reg += 16;
    il.AddInstruction(il.Store(2, il.ConstPointer(3, mem),
                               il.ZeroExtend(2, il.Register(1, reg)), flags));
  } else {
    il.AddInstruction(
        il.Store(2, il.ConstPointer(3, mem),
                 il.ZeroExtend(2, il.Load(1, il.ConstPointer(3, reg))), flags));
  }

  len = 4;
  UpdateExtSequence(addr, len);

  return true;
}

bool Mul::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
               BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  il.AddInstruction(
      il.Store(4, il.ConstPointer(3, Sfr::MD),
               il.MultDoublePrecSigned(4, il.Register(2, rwn),
                                       il.Register(2, rwm), flags)));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Mulu::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  il.AddInstruction(
      il.Store(4, il.ConstPointer(3, Sfr::MD),
               il.MultDoublePrecUnsigned(4, il.Register(2, rwn),
                                         il.Register(2, rwm), flags)));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Neg::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
               BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);

  il.AddInstruction(
      il.SetRegister(2, rwn, il.Neg(2, il.Register(2, rwn), flags)));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Negb::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  const uint32_t rbn = Instruction::GetData4High(data, length) + 16;

  il.AddInstruction(
      il.SetRegister(1, rbn, il.Neg(1, il.Register(1, rbn), flags)));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Nop::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
               BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  NO_OPERATION(length);
}

bool Or::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
              size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::OR_RWN_RWM:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRm(data, len, 2, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Or));
    case Opcodes::OR_RWN_RWI_DATA3:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRwiData3(addr, data, len, 2, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Or));
    case Opcodes::OR_REG_DATA16:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegData(addr, data, len, 2, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Or));
    case Opcodes::OR_REG_MEM:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegMem(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Or));
    case Opcodes::OR_MEM_REG:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpMemReg(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Or));
    default:
      BN::LogError("0x%lx: Or::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Orb::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
               size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::ORB_RBN_RBM:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRm(data, len, 1, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Or));
    case Opcodes::ORB_RBN_RWI_DATA3:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRwiData3(addr, data, len, 1, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Or));
    case Opcodes::ORB_REG_DATA8:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegData(addr, data, len, 1, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Or));
    case Opcodes::ORB_REG_MEM:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegMem(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Or));
    case Opcodes::ORB_MEM_REG:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpMemReg(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Or));
    default:
      BN::LogError("0x%lx: Orb::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Pop::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
               BN::LowLevelILFunction &il) {
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));
  if (reg <= 0xF) {
    il.AddInstruction(il.SetRegister(2, reg, il.Pop(2), flags));
  } else {
    il.AddInstruction(il.Store(2, il.ConstPointer(3, reg), il.Pop(2), flags));
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Push::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));
  if (reg <= 0xF) {
    il.AddInstruction(il.Push(2, il.Register(2, reg), flags));
  } else {
    il.AddInstruction(il.Push(2, il.Load(2, il.Const(3, reg)), flags));
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Prior::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                 BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  std::vector<BN::RegisterOrFlag> out = {BN::RegisterOrFlag::Register(rwn)};
  const std::vector<BN::ExprId> in = {il.Register(2, rwm)};

  //        il.AddInstruction(il.Intrinsic(out, 0, in, flags));
  il.AddInstruction(il.SetRegister(2, rwn, il.Unimplemented(), flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Pwrdn::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                 BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  NO_RETURN(length);
}

bool Ret::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
               BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  STACK_RETURN(length);
}

bool Reti::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  STACK_RETURN(length);
}

bool Retp::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  STACK_RETURN(length);
}

bool Rets::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  STACK_RETURN(length);
}

bool Rol::Liftx0C(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  il.AddInstruction(il.SetRegister(
      2, rwn, il.RotateLeft(2, il.Register(2, rwn), il.Register(2, rwm)),
      flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Rol::Liftx1C(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, length);
  const auto data4 = Instruction::GetData4High(data, length);

  il.AddInstruction(il.SetRegister(
      2, rwn, il.RotateLeft(2, il.Register(2, rwn), il.Const(1, data4)),
      flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Ror::Liftx2C(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  il.AddInstruction(il.SetRegister(
      2, rwn, il.RotateRight(2, il.Register(2, rwn), il.Register(2, rwm)),
      flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Ror::Liftx3C(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, length);
  const auto data4 = Instruction::GetData4High(data, length);

  il.AddInstruction(il.SetRegister(
      2, rwn, il.RotateRight(2, il.Register(2, rwn), il.Const(1, data4)),
      flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Scxt::LiftxC6(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));
  const auto data16 = Instruction::GetData16(data, len);

  if (reg <= 0xF) {
    il.AddInstruction(il.Push(2, il.Register(2, reg)));
    il.AddInstruction(il.SetRegister(2, reg, il.Const(2, data16)));
  } else {
    il.AddInstruction(il.Push(2, il.Load(2, il.Const(3, reg))));
    il.AddInstruction(
        il.Store(2, il.ConstPointer(3, reg), il.Const(2, data16)));
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Scxt::LiftxD6(const uint8_t *data, const uint64_t addr, size_t &len,
                   BN::LowLevelILFunction &il) {
  const auto reg =
      Instruction::TranslateReg(addr, Instruction::GetRegShortAddr(data, len));
  const auto mem =
      Instruction::TranslateMem(Instruction::GetMem(addr, data, length));

  if (reg <= 0xF) {
    il.AddInstruction(il.Push(2, il.Register(2, reg)));
    il.AddInstruction(
        il.SetRegister(2, reg, il.Load(2, il.ConstPointer(3, mem))));
  } else {
    il.AddInstruction(il.Push(2, il.Load(2, il.Const(3, reg))));
    il.AddInstruction(il.Store(2, il.ConstPointer(3, reg),
                               il.Load(2, il.ConstPointer(3, mem))));
  }

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Shl::Liftx4C(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  il.AddInstruction(il.SetRegister(
      2, rwn, il.ShiftLeft(2, il.Register(2, rwn), il.Register(2, rwm)),
      flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Shl::Liftx5C(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, length);
  const auto data4 = Instruction::GetData4High(data, length);

  il.AddInstruction(il.SetRegister(
      2, rwn, il.ShiftLeft(2, il.Register(2, rwn), il.Const(1, data4)), flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Shr::Liftx6C(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4High(data, length);
  const auto rwm = Instruction::GetData4Low(data, length);

  il.AddInstruction(il.SetRegister(
      2, rwn, il.LogicalShiftRight(2, il.Register(2, rwn), il.Register(2, rwm)),
      flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Shr::Liftx7C(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  const auto rwn = Instruction::GetData4Low(data, length);
  const auto data4 = Instruction::GetData4High(data, length);

  il.AddInstruction(il.SetRegister(
      2, rwn, il.LogicalShiftRight(2, il.Register(2, rwn), il.Const(1, data4)),
      flags));

  len = length;
  UpdateExtSequence(addr, len);

  return true;
}

bool Srst::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  NO_RETURN(length);
}

bool Srvwdt::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                  BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  UNIMPLEMENTED(length);
}

bool Sub::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
               size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::SUB_RWN_RWM:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRm(data, len, 2, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUB_RWN_RWI_DATA3:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRwiData3(addr, data, len, 2, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUB_REG_DATA16:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegData(addr, data, len, 2, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUB_REG_MEM:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegMem(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUB_MEM_REG:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpMemReg(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Sub));
    default:
      BN::LogError("0x%lx: Sub::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Subb::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
                size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::SUBB_RBN_RBM:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRm(data, len, 1, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBB_RBN_RWI_DATA3:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRwiData3(addr, data, len, 1, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBB_REG_DATA8:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegData(addr, data, len, 1, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBB_REG_MEM:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegMem(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBB_MEM_REG:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpMemReg(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Sub));
    default:
      BN::LogError("0x%lx: Subb::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Subc::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
                size_t &len, BN::LowLevelILFunction &il) {
  // TODO: Handle carry
  switch (op) {
    case Opcodes::SUBC_RWN_RWM:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRm(data, len, 2, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBC_RWN_RWI_DATA3:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRwiData3(addr, data, len, 2, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBC_REG_DATA16:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegData(addr, data, len, 2, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBC_REG_MEM:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegMem(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBC_MEM_REG:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpMemReg(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Sub));
    default:
      BN::LogError("0x%lx: Subc::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Subcb::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
                 size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::SUBCB_RBN_RBM:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRm(data, len, 1, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBCB_RBN_RWI_DATA3:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRwiData3(addr, data, len, 1, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBCB_REG_DATA8:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegData(addr, data, len, 1, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBCB_REG_MEM:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegMem(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Sub));
    case Opcodes::SUBCB_MEM_REG:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpMemReg(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Sub));
    default:
      BN::LogError("0x%lx: Subcb::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Trap::Lift(const uint8_t *data, const uint64_t addr, size_t &len,
                BN::LowLevelILFunction &il) {
  UpdateExtSequence(addr, length);
  UNIMPLEMENTED(length);
}

bool Xor::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
               size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::XOR_RWN_RWM:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRm(data, len, 2, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Xor));
    case Opcodes::XOR_RWN_RWI_DATA3:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRwiData3(addr, data, len, 2, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Xor));
    case Opcodes::XOR_REG_DATA16:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegData(addr, data, len, 2, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Xor));
    case Opcodes::XOR_REG_MEM:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegMem(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Xor));
    case Opcodes::XOR_MEM_REG:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpMemReg(addr, data, len, 2, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Xor));
    default:
      BN::LogError("0x%lx: Xor::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}

bool Xorb::Lift(const uint8_t op, const uint8_t *data, const uint64_t addr,
                size_t &len, BN::LowLevelILFunction &il) {
  switch (op) {
    case Opcodes::XORB_RBN_RBM:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRm(data, len, 1, flags, true, il,
                                     IL_OP(BN::LowLevelILFunction::Xor));
    case Opcodes::XORB_RBN_RWI_DATA3:
      len = 2;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRnRwiData3(addr, data, len, 1, flags, true, il,
                                           IL_OP(BN::LowLevelILFunction::Xor));
    case Opcodes::XORB_REG_DATA8:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegData(addr, data, len, 1, flags, true, il,
                                        IL_OP(BN::LowLevelILFunction::Xor));
    case Opcodes::XORB_REG_MEM:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpRegMem(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Xor));
    case Opcodes::XORB_MEM_REG:
      len = 4;
      UpdateExtSequence(addr, len);

      return Instruction::LiftOpMemReg(addr, data, len, 1, flags, true, il,
                                       IL_OP(BN::LowLevelILFunction::Xor));
    default:
      BN::LogError("0x%lx: Xorb::%s received invalid opcode: 0x%x", addr,
                   __func__, op);
      return false;
  }
}
}  // namespace C166
