#pragma once

#include "il.h"
#include "operands.h"
#include "registers.h"

/*
  generally:
  macros that end in "_O" operate on operands
  macros that start with "IL" construct BNIL expressions
*/

/* construct IL from a register id, immediate */
#define ILREG(R)           il.Register(RegisterSize(R), (R))
#define ILSETREG(R, VALUE) IS_ZERO_REG(R) ? (VALUE) : il.SetRegister(RegisterSize(R), (R), (VALUE))
#define ILCONST(SZ, VAL)   il.Const((SZ), (VAL))

/* helpers given a register id */
#define REGSZ(R)      RegisterSize(R) /* units: BYTES */
#define IS_W_REG(R)   ((R) >= REG_W0 && (R) <= REG_WSP)
#define IS_X_REG(R)   ((R) >= REG_X0 && (R) <= REG_SP)
#define IS_V_REG(R)   ((R) >= REG_V0 && (R) <= REG_V31)
#define IS_Z_REG(R)   ((R) >= REG_Z0 && (R) <= REG_Z31)
#define IS_P_REG(R)   ((R) >= REG_P0 && (R) <= REG_P15)
#define IS_ZERO_REG(R) ((R) == REG_XZR || (R) == REG_WZR)
#define IS_SVE_REG(R) (IS_Z_REG(R) || IS_P_REG(R))

/* access stuff from operands */
#define IMM_O(O)    OperandImmediate(O)
#define REG_O(O)    OperandRegister(O)
#define REGSZ_O(O) RegisterSize(REG_O(O)) /* units: BYTES */

/* construct IL from an operand */
#define ILREG_O(O)           ExtractRegister(il, O, 0, REGSZ_O(O), false, REGSZ_O(O))
#define ILSETREG_O(O, VALUE) IS_ZERO_REG(REG_O(O)) ? (VALUE) : il.SetRegister(REGSZ_O(O), REG_O(O), (VALUE))
#define ILADDREG_O(O, VALUE) il.Add(REGSZ_O(O), ILREG_O(O), (VALUE))
#define ILCONST_O(SZ, O)     ExtractImmediate(il, (O), SZ)

/* determine stuff from operands */
#define IS_REG_O(O)   ((O).kind == EXARMO_AARCH64_OPERAND_REG)
#define IS_COND_O(O)  ((O).kind == EXARMO_AARCH64_OPERAND_COND)
#define IS_ASIMD_O(O) (IS_REG_O(O) && IS_V_REG(REG_O(O)))
#define IS_SVE_O(O)   (IS_REG_O(O) && IS_SVE_REG(REG_O(O)))

/* misc */
#define SETFLAGS (GetFlagWriteTypeForEffect(exarmo_aarch64_instruction_flags(&instr)))
#define ONES(N)  (-1ULL >> (64 - (N)))
#define ABORT_LIFT \
	{ \
		il.AddInstruction(il.Unimplemented()); \
		break; \
	}
