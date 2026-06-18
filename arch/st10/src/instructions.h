// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#ifndef SRC_INSTRUCTIONS_H_
#define SRC_INSTRUCTIONS_H_

#include <binaryninjaapi.h>

#include <cstdint>
#include <vector>

#include "flags.h"

namespace BN = BinaryNinja;

namespace C166 {

// Indirect Addressing Expressions (using EXTS)
static BN::ExprId GetIndAddrExpr_Exts_Rw(BN::LowLevelILFunction& il,
                                         uint32_t seg8, uint32_t Rw);
static BN::ExprId GetIndAddrExpr_Exts_Rw_data16(BN::LowLevelILFunction& il,
                                                uint32_t seg8, uint32_t Rw,
                                                uint16_t data16);

// Indirect Addressing Expressions (using EXTP)
static BN::ExprId GetIndAddrExpr_Extp_Rw(BN::LowLevelILFunction& il,
                                         uint32_t pag10, uint32_t Rw);
static BN::ExprId GetIndAddrExpr_Extp_Rw_data16(BN::LowLevelILFunction& il,
                                                uint32_t pag10, uint32_t Rw,
                                                uint16_t data16);

// Indirect Addressing Expressions (Using DPP by default)
// static BN::ExprId GetIndAddrExpr_Rw(BN::LowLevelILFunction &il, uint32_t Rw);
static BN::ExprId GetIndAddrExpr_Rw_data16(BN::LowLevelILFunction& il,
                                           uint32_t Rw, uint16_t data16);

class Add {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Addb {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Addc {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Addcb {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class And {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Andb {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Ashr {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool LiftxAC(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxAC(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxBC(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxBC(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Band {
  static constexpr size_t length = 4;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Bclr {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Bcmp {
  static constexpr size_t length = 4;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Bfldh {
  static constexpr size_t length = 4;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Bfldl {
  static constexpr size_t length = 4;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Bmov {
  static constexpr size_t length = 4;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Bmovn {
  static constexpr size_t length = 4;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Bor {
  static constexpr size_t length = 4;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Bset {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Bxor {
  static constexpr size_t length = 4;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Calla {
  static constexpr size_t length = 4;
  static uint32_t GetTarget(const uint8_t* data, uint64_t addr, size_t len);
  static uint32_t GetConditionCode(const uint8_t* data, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Calli {
  static constexpr size_t length = 2;
  static uint32_t GetConditionCode(const uint8_t* data, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Callr {
  static constexpr size_t length = 2;
  static uint8_t GetRelativeOffset(const uint8_t* data, size_t len);
  static uint32_t GetTarget(const uint8_t* data, uint64_t addr, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Calls {
  static constexpr size_t length = 4;
  static uint32_t GetTarget(const uint8_t* data, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Cmp {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Cmpb {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Cmpd1 {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool LiftxA0(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxA0(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxA2(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxA2(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxA6(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxA6(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Cmpd2 {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool LiftxB0(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxB0(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxB2(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxB2(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxB6(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxB6(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Cmpi1 {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Liftx80(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx80(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx82(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx82(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx86(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx86(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Cmpi2 {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Liftx90(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx90(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx92(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx92(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx96(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx96(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Cpl {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Cplb {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Diswdt {
  static constexpr size_t length = 4;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Div {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Divl {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Divlu {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Divu {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Einit {
  static constexpr size_t length = 4;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Extprs {
  static const char* GetInstruction(const uint8_t* data, uint64_t addr,
                                    size_t len);

 public:
  static bool LiftxD7(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool LiftxDC(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxD7(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool TextxDC(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class ExtrAtomic {
  static constexpr size_t length = 2;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Idle {
  static constexpr size_t length = 4;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Jb {
  static constexpr size_t flags =
      Flags::WRITE_Z;  // Required to model bit status
  static constexpr size_t length = 4;
  static uint8_t GetRelativeOffset(const uint8_t* data, size_t len);
  static uint32_t GetTarget(const uint8_t* data, uint64_t addr, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Jbc {
  static constexpr size_t flags =
      Flags::WRITE_Z;  // Required to model bit status
  static constexpr size_t length = 4;
  static uint8_t GetRelativeOffset(const uint8_t* data, size_t len);
  static uint32_t GetTarget(const uint8_t* data, uint64_t addr, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Jmpa {
  static constexpr size_t length = 4;
  static uint32_t GetTarget(const uint8_t* data, uint64_t addr, size_t len);
  static uint32_t GetConditionCode(const uint8_t* data, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Jmpi {
  static constexpr size_t length = 2;

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Jmpr {
  static constexpr size_t length = 2;
  static uint8_t GetRelativeOffset(const uint8_t* data, size_t len);
  static uint32_t GetTarget(const uint8_t* data, uint64_t addr, size_t len);
  static uint32_t GetConditionCode(const uint8_t* data, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Jmps {
  static constexpr size_t length = 4;
  static uint32_t GetTarget(const uint8_t* data, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Jnb {
  static constexpr size_t flags =
      Flags::WRITE_Z;  // Required to model bit status
  static constexpr size_t length = 4;
  static uint8_t GetRelativeOffset(const uint8_t* data, size_t len);
  static uint32_t GetTarget(const uint8_t* data, uint64_t addr, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Jnbs {
  static constexpr size_t flags =
      Flags::WRITE_Z;  // Required to model bit status
  static constexpr size_t length = 4;
  static uint8_t GetRelativeOffset(const uint8_t* data, size_t len);
  static uint32_t GetTarget(const uint8_t* data, uint64_t addr, size_t len);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(BN::Architecture* arch, const uint8_t* data, uint64_t addr,
                   size_t& len, BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Mov {
  static constexpr uint32_t flags = Flags::WRITE_EZN;

 public:
  static bool Liftx84(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx84(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx94(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx94(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx88(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx88(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx98(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx98(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxA8(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxA8(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxB8(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxB8(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxC8(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxC8(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxC4(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxC4(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxD4(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxD4(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxD8(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxD8(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxE0(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxE0(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxE6(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxE6(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxE8(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxE8(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxF0(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxF0(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxF2(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxF2(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxF6(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxF6(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Movb {
  static constexpr uint32_t flags = Flags::WRITE_EZN;

 public:
  static bool Liftx89(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx89(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx99(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx99(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxA4(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxA4(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxA9(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxA9(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxB4(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxB4(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxB9(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxB9(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxC9(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxC9(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxD9(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxD9(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxE1(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxE1(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxE4(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxE4(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxE7(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxE7(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxE9(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxE9(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxF1(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxF1(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxF3(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxF3(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxF4(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxF4(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxF7(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxF7(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Movbs {
  static constexpr uint32_t flags = Flags::WRITE_EZN;

 public:
  static bool LiftxD0(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxD0(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxD2(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxD2(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxD5(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxD5(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Movbz {
  static constexpr uint32_t flags = Flags::WRITE_EZN;

 public:
  static bool LiftxC0(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxC0(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxC2(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxC2(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxC5(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxC5(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Mul {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Mulu {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Neg {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Negb {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Nop {
  static constexpr size_t length = 2;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Or {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Orb {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Pop {
  static constexpr uint32_t flags = Flags::WRITE_EZN;
  static constexpr size_t length = 2;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Prior {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Push {
  static constexpr uint32_t flags = Flags::WRITE_EZN;
  static constexpr size_t length = 2;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Pwrdn {
  static constexpr size_t length = 4;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Ret {
  static constexpr size_t length = 2;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Reti {
  static constexpr size_t length = 2;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Retp {
  static constexpr size_t length = 2;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Rets {
  static constexpr size_t length = 2;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Rol {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Liftx0C(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx0C(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx1C(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx1C(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Ror {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Liftx2C(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx2C(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx3C(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx3C(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Scxt {
  static constexpr size_t length = 4;

 public:
  static bool LiftxC6(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxC6(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool LiftxD6(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool TextxD6(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Shl {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Liftx4C(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx4C(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx5C(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx5C(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Shr {
  static constexpr size_t length = 2;
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Liftx6C(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx6C(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
  static bool Liftx7C(const uint8_t* data, uint64_t addr, size_t& len,
                      BN::LowLevelILFunction& il);
  static bool Textx7C(const uint8_t* data, uint64_t addr, size_t& len,
                      std::vector<BN::InstructionTextToken>& result);
};

class Srst {
  static constexpr size_t length = 4;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Srvwdt {
  static constexpr size_t length = 4;

 public:
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Sub {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Subb {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Subc {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Subcb {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Trap {
  static constexpr size_t length = 2;
  static uint32_t GetTarget(const uint8_t* data, uint64_t addr);
  static uint8_t GetTrap7(const uint8_t* data);

 public:
  static bool Info(const uint8_t* data, uint64_t addr, size_t maxLen,
                   BN::InstructionInfo& result);
  static bool Lift(const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Xor {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};

class Xorb {
  static constexpr uint32_t flags = Flags::WRITE_ALL;

 public:
  static bool Lift(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   BN::LowLevelILFunction& il);
  static bool Text(uint8_t op, const uint8_t* data, uint64_t addr, size_t& len,
                   std::vector<BN::InstructionTextToken>& result);
};
}  // namespace C166

#endif  // SRC_INSTRUCTIONS_H_
