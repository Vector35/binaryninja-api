// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#ifndef SRC_CONDITIONS_H_
#define SRC_CONDITIONS_H_

namespace C166::Conditions {
constexpr uint8_t CC_UC = 0x0;
constexpr uint8_t CC_Z = 0x2;
constexpr uint8_t CC_NZ = 0x3;
constexpr uint8_t CC_V = 0x4;
constexpr uint8_t CC_NV = 0x5;
constexpr uint8_t CC_N = 0x6;
constexpr uint8_t CC_NN = 0x7;
constexpr uint8_t CC_ULT = 0x8;
constexpr uint8_t CC_ULE = 0xF;
constexpr uint8_t CC_UGE = 0x9;
constexpr uint8_t CC_UGT = 0xE;
constexpr uint8_t CC_SLT = 0xC;
constexpr uint8_t CC_SLE = 0xB;
constexpr uint8_t CC_SGE = 0xD;
constexpr uint8_t CC_SGT = 0xA;
constexpr uint8_t CC_NET = 0x1;
}  // namespace C166::Conditions

#endif  // SRC_CONDITIONS_H_
