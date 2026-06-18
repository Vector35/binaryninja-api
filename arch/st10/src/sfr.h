// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#ifndef SRC_SFR_H_
#define SRC_SFR_H_

namespace C166::Sfr {
constexpr uint16_t DPP0 = 0xFE00;

/* Hardware Multiply/Divide Registers */
constexpr uint16_t MD = 0xFE0C;
constexpr uint16_t MDH = 0xFE0C;
constexpr uint16_t MDL = 0xFE0E;
}  // namespace C166::Sfr

#endif  // SRC_SFR_H_
