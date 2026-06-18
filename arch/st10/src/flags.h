// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#ifndef SRC_FLAGS_H_
#define SRC_FLAGS_H_

namespace C166::Flags {
constexpr uint8_t FLAG_NEGATIVE = 0;
constexpr uint8_t FLAG_CARRY = 1;
constexpr uint8_t FLAG_OVERFLOW = 2;
constexpr uint8_t FLAG_ZERO = 3;
constexpr uint8_t FLAG_E = 4;

constexpr uint8_t WRITE_ALL = 0;
constexpr uint8_t WRITE_Z = 1;
constexpr uint8_t WRITE_EZN = 2;
}  // namespace C166::Flags

#endif  // SRC_FLAGS_H_
