// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#ifndef SRC_REGISTERS_H_
#define SRC_REGISTERS_H_

namespace C166::Registers {
/* Full-Width GPRs + Stack Pointer */
constexpr uint8_t R0 = 0;
constexpr uint8_t R1 = 1;
constexpr uint8_t R2 = 2;
constexpr uint8_t R3 = 3;
constexpr uint8_t R4 = 4;
constexpr uint8_t R5 = 5;
constexpr uint8_t R6 = 6;
constexpr uint8_t R7 = 7;
constexpr uint8_t R8 = 8;
constexpr uint8_t R9 = 9;
constexpr uint8_t R10 = 10;
constexpr uint8_t R11 = 11;
constexpr uint8_t R12 = 12;
constexpr uint8_t R13 = 13;
constexpr uint8_t R14 = 14;
constexpr uint8_t R15 = 15;  // Stack Pointer

/* Byte sub-registers */
constexpr uint8_t RL0 = 16;
constexpr uint8_t RH0 = 17;
constexpr uint8_t RL1 = 18;
constexpr uint8_t RH1 = 19;
constexpr uint8_t RL2 = 20;
constexpr uint8_t RH2 = 21;
constexpr uint8_t RL3 = 22;
constexpr uint8_t RH3 = 23;
constexpr uint8_t RL4 = 24;
constexpr uint8_t RH4 = 25;
constexpr uint8_t RL5 = 26;
constexpr uint8_t RH5 = 27;
constexpr uint8_t RL6 = 28;
constexpr uint8_t RH6 = 29;
constexpr uint8_t RL7 = 30;
constexpr uint8_t RH7 = 31;

/* System Control Registers */
constexpr uint8_t CSP = 32;
constexpr uint8_t CPUCON1 = 33;
constexpr uint8_t CPUCON2 = 34;
constexpr uint8_t PSW = 35;
constexpr uint8_t CP = 36;
constexpr uint8_t VIRTUAL_LR = 37;
}  // namespace C166::Registers

#endif  // SRC_REGISTERS_H_
