#pragma once

#include "registers.h"

#include "exarmo/aarch64.h"

#include <stddef.h>

// Accessors for the fields of an exarmo operand.

// Equivalent to OperandRegisterAt(operand, 0).
Register OperandRegister(const exarmo_aarch64_operand& operand);

// The registers an operand names, in the order the architecture writes them: a register
// operand's own, a memory operand's base and then its offset register, each member of a list.
// REG_NONE past the end.
Register OperandRegisterAt(const exarmo_aarch64_operand& operand, size_t index);

// The operand's arrangement. `element` is EXARMO_AARCH64_ELEMENT_NONE if the operand has no
// arrangement.
exarmo_aarch64_arrangement OperandArrangement(const exarmo_aarch64_operand& operand);

// The element index written on an operand, or -1 where none is.
int32_t OperandLaneIndex(const exarmo_aarch64_operand& operand);

// An immediate operand's value before any shift. Zero for any other operand. Use LabelTarget for a
// label.
int64_t OperandImmediate(const exarmo_aarch64_operand& operand);

// The target of a label operand in the instruction at `addr`.
uint64_t LabelTarget(const exarmo_aarch64_operand& operand, uint64_t addr);

// The shift or extend written on an operand, and how far it shifts. A memory operand's is the
// one written on its offset register.
exarmo_aarch64_modifier OperandModifier(const exarmo_aarch64_operand& operand);
