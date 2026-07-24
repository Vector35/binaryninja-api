#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "feature_flags.h"
#include "operations.h"

#include "encodings_dec.h"
#include "regs.h"
#include "sysregs_gen.h"
#include "sysregs_fmt_gen.h"

#ifdef _MSC_VER
	#undef REG_NONE  // collides with winnt's define
#endif

#ifdef __cplusplus
	#define restrict __restrict
#endif

/* these are used in lookup tables elsewhere, modify with caution */
enum ArrangementSpec
{
	ARRSPEC_NONE = 0,

	ARRSPEC_FULL = 1, /* 128-bit v-reg unsplit, eg: REG_V0_Q0 */

	/* 128 bit v-reg considered as... */
	ARRSPEC_2DOUBLES = 2, /* (.2d) two 64-bit double-precision: REG_V0_D1, REG_V0_D0 */
	ARRSPEC_4SINGLES =
	    3, /* (.4s) four 32-bit single-precision: REG_V0_S3, REG_V0_S2, REG_V0_S1, REG_V0_S0 */
	ARRSPEC_8HALVES =
	    4, /* (.8h) eight 16-bit half-precision: REG_V0_H7, REG_V0_H6, (..., REG_V0_H0 */
	ARRSPEC_16BYTES = 5, /* (.16b) sixteen 8-bit values: REG_V0_B15, REG_V0_B14, (..., REG_V0_B01 */

	/* low 64-bit of v-reg considered as... */
	ARRSPEC_1DOUBLE = 6,  /* (.d) one 64-bit double-precision: REG_V0_D0 */
	ARRSPEC_2SINGLES = 7, /* (.2s) two 32-bit single-precision: REG_V0_S1, REG_V0_S0 */
	ARRSPEC_4HALVES =
	    8, /* (.4h) four 16-bit half-precision: REG_V0_H3, REG_V0_H2, REG_V0_H1, REG_V0_H0 */
	ARRSPEC_8BYTES = 9, /* (.8b) eight 8-bit values: REG_V0_B7, REG_V0_B6, (..., REG_V0_B0 */

	/* low 32-bit of v-reg considered as... */
	ARRSPEC_1SINGLE = 10, /* (.s) one 32-bit single-precision: REG_V0_S0 */
	ARRSPEC_2HALVES = 11, /* (.2h) two 16-bit half-precision: REG_V0_H1, REG_V0_H0 */
	ARRSPEC_4BYTES = 12,  /* (.4b) four 8-bit values: REG_V0_B3, REG_V0_B2, REG_V0_B1, REG_V0_B0 */

	/* low 16-bit of v-reg considered as... */
	ARRSPEC_1HALF = 13, /* (.h) one 16-bit half-precision: REG_V0_H0 */

	/* low 8-bit of v-reg considered as... */
	ARRSPEC_1BYTE = 14 /* (.b) one 8-bit byte: REG_V0_B0 */
};

enum SliceIndicator
{
	SLICE_NONE = -1,
	SLICE_HORIZONTAL = 0, /* same values as read from fields32 */
	SLICE_VERTICAL = 1
};

//-----------------------------------------------------------------------------
// decode return values
//-----------------------------------------------------------------------------

#define DECODE_STATUS_OK        0   // success! the resulting named encoding is accurate
#define DECODE_STATUS_RESERVED  -1  // spec says this space is reserved, eg: RESERVED_36_asisdsame
#define DECODE_STATUS_UNMATCHED -2  // decoding logic fell through the spec's checks
#define DECODE_STATUS_UNALLOCATED \
	-3  // spec says this space is unallocated, eg: UNALLOCATED_10_branch_reg
#define DECODE_STATUS_UNDEFINED \
	-4  // spec says this encoding is undefined, often due to a disallowed field
	    // or a missing feature, eg: "if !HaveBF16Ext() then UNDEFINED;"
#define DECODE_STATUS_END_OF_INSTRUCTION \
	-5  // spec decode EndOfInstruction(), instruction executes as NOP
#define DECODE_STATUS_LOST           -6  // descended past checks, ie: "SEE encoding_up_higher"
#define DECODE_STATUS_UNREACHABLE    -7  // ran into pcode Unreachable()
#define DECODE_STATUS_ASSERT_FAILED  -8  // failed an assert
#define DECODE_STATUS_ERROR_OPERANDS -9

//-----------------------------------------------------------------------------
// floating point condition register values
//-----------------------------------------------------------------------------

#define FPCR_AHP    ((uint64_t)1 << 26)
#define FPCR_DN     ((uint64_t)1 << 25)
#define FPCR_FZ     ((uint64_t)1 << 24)
#define FPCR_RMode  (uint64_t)0xC00000  // [23,22]
#define FPCR_Stride (uint64_t)0x300000  // [21,20]
#define FPCR_FZ16   ((uint64_t)1 << 19)
#define FPCR_Len    (uint64_t)0x30000  // [18:16]
#define FPCR_IDE    ((uint64_t)1 << 15)
#define FPCR_IXE    ((uint64_t)1 << 12)
#define FPCR_UFE    ((uint64_t)1 << 11)
#define FPCR_OFE    ((uint64_t)1 << 10)
#define FPCR_DZE    ((uint64_t)1 << 9)
#define FPCR_IOE    ((uint64_t)1 << 8)

#define FPCR_GET_AHP(X)    SLICE(X, 26, 26)
#define FPCR_GET_DN(X)     SLICE(X, 25, 25)
#define FPCR_GET_FZ(X)     SLICE(X, 24, 24)
#define FPCR_GET_RMode(X)  SLICE(X, 23, 22)
#define FPCR_GET_Stride(X) SLICE(X, 21, 20)
#define FPCR_GET_FZ16(X)   SLICE(X, 19, 19)
#define FPCR_GET_Len(X)    SLICE(X, 18, 16)
#define FPCR_GET_IDE(X)    SLICE(X, 15, 15)
#define FPCR_GET_IXE(X)    SLICE(X, 12, 12)
#define FPCR_GET_UFE(X)    SLICE(X, 11, 11)
#define FPCR_GET_OFE(X)    SLICE(X, 10, 10)
#define FPCR_GET_DZE(X)    SLICE(X, 9, 9)
#define FPCR_GET_IOE(X)    SLICE(X, 8, 8)

//-----------------------------------------------------------------------------
// <tlbi_op>: TLBI operands
//-----------------------------------------------------------------------------
#define TLBI_OP(op1, crn, crm, op2) (((op1 & 7) << 11) | ((crn & 0xF) << 7) | ((crm & 0xF) << 3) | ((op2) & 7))

//-----------------------------------------------------------------------------
// <at_op>: AT operands
//-----------------------------------------------------------------------------
#define AT_OP(op1, crm, op2) (TLBI_OP(op1, 7, crm, op2))

//-----------------------------------------------------------------------------
// <dc_op>: DC operands
//-----------------------------------------------------------------------------
#define DC_OP(op1, crm, op2) (TLBI_OP(op1, 7, crm, op2))

//-----------------------------------------------------------------------------
// disassembly context (INPUT into disassembler)
//-----------------------------------------------------------------------------

typedef struct context_
{
	uint32_t insword;
	uint64_t address;
	uint64_t decode_features[2];  // bitmask of ARCH_FEATURE_XXX
	uint64_t pcode_features[2];   // bitmask of ARCH_FEATURE_XXX
	// uint32_t exception_level; // used by AArch64.CheckSystemAccess()
	// uint32_t security_state;
	uint8_t pstate_btype;  // used by BTypeCompatible_BTI()
	uint8_t pstate_el;
	uint8_t pstate_uao;
	bool BTypeCompatible;
	uint8_t BTypeNext;
	bool halted;     // is CPU halted? used by Halted()
	uint64_t FPCR;   // floating point control register
	bool EDSCR_HDE;  // External Debug Status and Control Register, Halting debug enable

	/* specification scratchpad. The fields are declared in context_fields.h
	   and packed by gen_ctx_layout.py into context_layout.h so that fields
	   never used by the same instruction share storage. */
#include "context_layout.h"
} context;

//-----------------------------------------------------------------------------
// Instruction definition (OUTPUT from disassembler)
//-----------------------------------------------------------------------------

enum OperandClass
{                          // syntax                      example
	NONE = 0,              // --------------------------- ---------------------
	IMM32 = 1,
	IMM64 = 2,
	FIMM32 = 3,
	STR_IMM = 4,
	REG = 5,
	MULTI_REG = 6,
	SYS_REG = 7,
	MEM_REG = 8,
	MEM_PRE_IDX = 9,
	MEM_POST_IDX = 10,
	MEM_OFFSET = 11,
	MEM_EXTENDED = 12,
	SME_TILE = 13,
	INDEXED_ELEMENT = 14,        // <Pn>.<T>[<Wm>{, #<imm>}]    p12.d[w15, #15]
	ACCUM_ARRAY = 15,			// ZA[<Wv>, #<imm>]            ZA[w13, #8]
	LABEL = 16,
	CONDITION = 17,
	NAME = 18,
	IMPLEMENTATION_SPECIFIC = 19
};

enum Condition
{
	COND_EQ,
	COND_NE,
	COND_CS,
	COND_CC,
	COND_MI,
	COND_PL,
	COND_VS,
	COND_VC,
	COND_HI,
	COND_LS,
	COND_GE,
	COND_LT,
	COND_GT,
	COND_LE,
	COND_AL,
	COND_NV,
	END_CONDITION
};

enum ShiftType
{
	ShiftType_NONE,
	ShiftType_LSL,
	ShiftType_LSR,
	ShiftType_ASR,
	ShiftType_ROR,
	ShiftType_UXTW,
	ShiftType_SXTW,
	ShiftType_SXTX,
	ShiftType_UXTX,
	ShiftType_SXTB,
	ShiftType_SXTH,
	ShiftType_UXTH,
	ShiftType_UXTB,
	ShiftType_MSL,
	ShiftType_END,
};

enum Group
{
	GROUP_UNALLOCATED,
	GROUP_DATA_PROCESSING_IMM,
	GROUP_BRANCH_EXCEPTION_SYSTEM,
	GROUP_LOAD_STORE,
	GROUP_DATA_PROCESSING_REG,
	GROUP_DATA_PROCESSING_SIMD,
	GROUP_DATA_PROCESSING_SIMD2,
	END_GROUP
};

enum FlagEffect
{
	FLAGEFFECT_NONE=0, // doesn't set flags
	FLAGEFFECT_SETS=1, // sets flags, but unknown which type
	FLAGEFFECT_SETS_NORMAL=2, // sets flags after normal comparison
	FLAGEFFECT_SETS_FLOAT=3 // sets flags after float comparison
};

enum ImplSpec
{
	OP0 = 0,
	OP1 = 1,
	CRN = 2,
	CRM = 3,
	OP2 = 4
};

enum ATOp
{
	AT_OP_INVALID=-1,
	AT_OP_S1E1R=AT_OP(0b000, 0b1000, 0b000),
	AT_OP_S1E1W=AT_OP(0b000, 0b1000, 0b001),
	AT_OP_S1E0R=AT_OP(0b000, 0b1000, 0b010),
	AT_OP_S1E0W=AT_OP(0b000, 0b1000, 0b011),
	AT_OP_S1E1RP=AT_OP(0b000, 0b1001, 0b000),
	AT_OP_S1E1WP=AT_OP(0b000, 0b1001, 0b001),
	AT_OP_S1E1A=AT_OP(0b000, 0b1001, 0b010),
	AT_OP_S1E2R=AT_OP(0b100, 0b1000, 0b000),
	AT_OP_S1E2W=AT_OP(0b100, 0b1000, 0b001),
	AT_OP_S12E1R=AT_OP(0b100, 0b1000, 0b100),
	AT_OP_S12E1W=AT_OP(0b100, 0b1000, 0b101),
	AT_OP_S12E0R=AT_OP(0b100, 0b1000, 0b110),
	AT_OP_S12E0W=AT_OP(0b100, 0b1000, 0b111),
	AT_OP_S1E2A=AT_OP(0b100, 0b1001, 0b010),
	AT_OP_S1E3R=AT_OP(0b110, 0b1000, 0b000),
	AT_OP_S1E3W=AT_OP(0b110, 0b1000, 0b001),
	AT_OP_S1E3A=AT_OP(0b110, 0b1001, 0b010),
};

enum TlbiOp
{
	TLBI_INVALID=-1,
	TLBI_VMALLE1OS=TLBI_OP(0b000, 0b1000, 0b0001, 0b000),
	TLBI_VAE1OS=TLBI_OP(0b000, 0b1000, 0b0001, 0b001),
	TLBI_ASIDE1OS=TLBI_OP(0b000, 0b1000, 0b0001, 0b010),
	TLBI_VAAE1OS=TLBI_OP(0b000, 0b1000, 0b0001, 0b011),
	TLBI_VALE1OS=TLBI_OP(0b000, 0b1000, 0b0001, 0b101),
	TLBI_VAALE1OS=TLBI_OP(0b000, 0b1000, 0b0001, 0b111),
	TLBI_RVAE1IS=TLBI_OP(0b000, 0b1000, 0b0010, 0b001),
	TLBI_RVAAE1IS=TLBI_OP(0b000, 0b1000, 0b0010, 0b011),
	TLBI_RVALE1IS=TLBI_OP(0b000, 0b1000, 0b0010, 0b101),
	TLBI_RVAALE1IS=TLBI_OP(0b000, 0b1000, 0b0010, 0b111),
	TLBI_VMALLE1IS=TLBI_OP(0b000, 0b1000, 0b0011, 0b000),
	TLBI_VAE1IS=TLBI_OP(0b000, 0b1000, 0b0011, 0b001),
	TLBI_ASIDE1IS=TLBI_OP(0b000, 0b1000, 0b0011, 0b010),
	TLBI_VAAE1IS=TLBI_OP(0b000, 0b1000, 0b0011, 0b011),
	TLBI_VALE1IS=TLBI_OP(0b000, 0b1000, 0b0011, 0b101),
	TLBI_VAALE1IS=TLBI_OP(0b000, 0b1000, 0b0011, 0b111),
	TLBI_RVAE1OS=TLBI_OP(0b000, 0b1000, 0b0101, 0b001),
	TLBI_RVAAE1OS=TLBI_OP(0b000, 0b1000, 0b0101, 0b011),
	TLBI_RVALE1OS=TLBI_OP(0b000, 0b1000, 0b0101, 0b101),
	TLBI_RVAALE1OS=TLBI_OP(0b000, 0b1000, 0b0101, 0b111),
	TLBI_RVAE1=TLBI_OP(0b000, 0b1000, 0b0110, 0b001),
	TLBI_RVAAE1=TLBI_OP(0b000, 0b1000, 0b0110, 0b011),
	TLBI_RVALE1=TLBI_OP(0b000, 0b1000, 0b0110, 0b101),
	TLBI_RVAALE1=TLBI_OP(0b000, 0b1000, 0b0110, 0b111),
	TLBI_VMALLE1=TLBI_OP(0b000, 0b1000, 0b0111, 0b000),
	TLBI_VAE1=TLBI_OP(0b000, 0b1000, 0b0111, 0b001),
	TLBI_ASIDE1=TLBI_OP(0b000, 0b1000, 0b0111, 0b010),
	TLBI_VAAE1=TLBI_OP(0b000, 0b1000, 0b0111, 0b011),
	TLBI_VALE1=TLBI_OP(0b000, 0b1000, 0b0111, 0b101),
	TLBI_VAALE1=TLBI_OP(0b000, 0b1000, 0b0111, 0b111),
	TLBI_VMALLE1OSNXS=TLBI_OP(0b000, 0b1001, 0b0001, 0b000),
	TLBI_VAE1OSNXS=TLBI_OP(0b000, 0b1001, 0b0001, 0b001),
	TLBI_ASIDE1OSNXS=TLBI_OP(0b000, 0b1001, 0b0001, 0b010),
	TLBI_VAAE1OSNXS=TLBI_OP(0b000, 0b1001, 0b0001, 0b011),
	TLBI_VALE1OSNXS=TLBI_OP(0b000, 0b1001, 0b0001, 0b101),
	TLBI_VAALE1OSNXS=TLBI_OP(0b000, 0b1001, 0b0001, 0b111),
	TLBI_RVAE1ISNXS=TLBI_OP(0b000, 0b1001, 0b0010, 0b001),
	TLBI_RVAAE1ISNXS=TLBI_OP(0b000, 0b1001, 0b0010, 0b011),
	TLBI_RVALE1ISNXS=TLBI_OP(0b000, 0b1001, 0b0010, 0b101),
	TLBI_RVAALE1ISNXS=TLBI_OP(0b000, 0b1001, 0b0010, 0b111),
	TLBI_VMALLE1ISNXS=TLBI_OP(0b000, 0b1001, 0b0011, 0b000),
	TLBI_VAE1ISNXS=TLBI_OP(0b000, 0b1001, 0b0011, 0b001),
	TLBI_ASIDE1ISNXS=TLBI_OP(0b000, 0b1001, 0b0011, 0b010),
	TLBI_VAAE1ISNXS=TLBI_OP(0b000, 0b1001, 0b0011, 0b011),
	TLBI_VALE1ISNXS=TLBI_OP(0b000, 0b1001, 0b0011, 0b101),
	TLBI_VAALE1ISNXS=TLBI_OP(0b000, 0b1001, 0b0011, 0b111),
	TLBI_RVAE1OSNXS=TLBI_OP(0b000, 0b1001, 0b0101, 0b001),
	TLBI_RVAAE1OSNXS=TLBI_OP(0b000, 0b1001, 0b0101, 0b011),
	TLBI_RVALE1OSNXS=TLBI_OP(0b000, 0b1001, 0b0101, 0b101),
	TLBI_RVAALE1OSNXS=TLBI_OP(0b000, 0b1001, 0b0101, 0b111),
	TLBI_RVAE1NXS=TLBI_OP(0b000, 0b1001, 0b0110, 0b001),
	TLBI_RVAAE1NXS=TLBI_OP(0b000, 0b1001, 0b0110, 0b011),
	TLBI_RVALE1NXS=TLBI_OP(0b000, 0b1001, 0b0110, 0b101),
	TLBI_RVAALE1NXS=TLBI_OP(0b000, 0b1001, 0b0110, 0b111),
	TLBI_VMALLE1NXS=TLBI_OP(0b000, 0b1001, 0b0111, 0b000),
	TLBI_VAE1NXS=TLBI_OP(0b000, 0b1001, 0b0111, 0b001),
	TLBI_ASIDE1NXS=TLBI_OP(0b000, 0b1001, 0b0111, 0b010),
	TLBI_VAAE1NXS=TLBI_OP(0b000, 0b1001, 0b0111, 0b011),
	TLBI_VALE1NXS=TLBI_OP(0b000, 0b1001, 0b0111, 0b101),
	TLBI_VAALE1NXS=TLBI_OP(0b000, 0b1001, 0b0111, 0b111),
	TLBI_IPAS2E1IS=TLBI_OP(0b100, 0b1000, 0b0000, 0b001),
	TLBI_RIPAS2E1IS=TLBI_OP(0b100, 0b1000, 0b0000, 0b010),
	TLBI_IPAS2LE1IS=TLBI_OP(0b100, 0b1000, 0b0000, 0b101),
	TLBI_RIPAS2LE1IS=TLBI_OP(0b100, 0b1000, 0b0000, 0b110),
	TLBI_ALLE2OS=TLBI_OP(0b100, 0b1000, 0b0001, 0b000),
	TLBI_VAE2OS=TLBI_OP(0b100, 0b1000, 0b0001, 0b001),
	TLBI_ALLE1OS=TLBI_OP(0b100, 0b1000, 0b0001, 0b100),
	TLBI_VALE2OS=TLBI_OP(0b100, 0b1000, 0b0001, 0b101),
	TLBI_VMALLS12E1OS=TLBI_OP(0b100, 0b1000, 0b0001, 0b110),
	TLBI_RVAE2IS=TLBI_OP(0b100, 0b1000, 0b0010, 0b001),
	TLBI_VMALLWS2E1IS=TLBI_OP(0b100, 0b1000, 0b0010, 0b010),
	TLBI_RVALE2IS=TLBI_OP(0b100, 0b1000, 0b0010, 0b101),
	TLBI_ALLE2IS=TLBI_OP(0b100, 0b1000, 0b0011, 0b000),
	TLBI_VAE2IS=TLBI_OP(0b100, 0b1000, 0b0011, 0b001),
	TLBI_ALLE1IS=TLBI_OP(0b100, 0b1000, 0b0011, 0b100),
	TLBI_VALE2IS=TLBI_OP(0b100, 0b1000, 0b0011, 0b101),
	TLBI_VMALLS12E1IS=TLBI_OP(0b100, 0b1000, 0b0011, 0b110),
	TLBI_IPAS2E1OS=TLBI_OP(0b100, 0b1000, 0b0100, 0b000),
	TLBI_IPAS2E1=TLBI_OP(0b100, 0b1000, 0b0100, 0b001),
	TLBI_RIPAS2E1=TLBI_OP(0b100, 0b1000, 0b0100, 0b010),
	TLBI_RIPAS2E1OS=TLBI_OP(0b100, 0b1000, 0b0100, 0b011),
	TLBI_IPAS2LE1OS=TLBI_OP(0b100, 0b1000, 0b0100, 0b100),
	TLBI_IPAS2LE1=TLBI_OP(0b100, 0b1000, 0b0100, 0b101),
	TLBI_RIPAS2LE1=TLBI_OP(0b100, 0b1000, 0b0100, 0b110),
	TLBI_RIPAS2LE1OS=TLBI_OP(0b100, 0b1000, 0b0100, 0b111),
	TLBI_RVAE2OS=TLBI_OP(0b100, 0b1000, 0b0101, 0b001),
	TLBI_VMALLWS2E1OS=TLBI_OP(0b100, 0b1000, 0b0101, 0b010),
	TLBI_RVALE2OS=TLBI_OP(0b100, 0b1000, 0b0101, 0b101),
	TLBI_RVAE2=TLBI_OP(0b100, 0b1000, 0b0110, 0b001),
	TLBI_VMALLWS2E1=TLBI_OP(0b100, 0b1000, 0b0110, 0b010),
	TLBI_RVALE2=TLBI_OP(0b100, 0b1000, 0b0110, 0b101),
	TLBI_ALLE2=TLBI_OP(0b100, 0b1000, 0b0111, 0b000),
	TLBI_VAE2=TLBI_OP(0b100, 0b1000, 0b0111, 0b001),
	TLBI_ALLE1=TLBI_OP(0b100, 0b1000, 0b0111, 0b100),
	TLBI_VALE2=TLBI_OP(0b100, 0b1000, 0b0111, 0b101),
	TLBI_VMALLS12E1=TLBI_OP(0b100, 0b1000, 0b0111, 0b110),
	TLBI_IPAS2E1ISNXS=TLBI_OP(0b100, 0b1001, 0b0000, 0b001),
	TLBI_RIPAS2E1ISNXS=TLBI_OP(0b100, 0b1001, 0b0000, 0b010),
	TLBI_IPAS2LE1ISNXS=TLBI_OP(0b100, 0b1001, 0b0000, 0b101),
	TLBI_RIPAS2LE1ISNXS=TLBI_OP(0b100, 0b1001, 0b0000, 0b110),
	TLBI_ALLE2OSNXS=TLBI_OP(0b100, 0b1001, 0b0001, 0b000),
	TLBI_VAE2OSNXS=TLBI_OP(0b100, 0b1001, 0b0001, 0b001),
	TLBI_ALLE1OSNXS=TLBI_OP(0b100, 0b1001, 0b0001, 0b100),
	TLBI_VALE2OSNXS=TLBI_OP(0b100, 0b1001, 0b0001, 0b101),
	TLBI_VMALLS12E1OSNXS=TLBI_OP(0b100, 0b1001, 0b0001, 0b110),
	TLBI_RVAE2ISNXS=TLBI_OP(0b100, 0b1001, 0b0010, 0b001),
	TLBI_VMALLWS2E1ISNXS=TLBI_OP(0b100, 0b1001, 0b0010, 0b010),
	TLBI_RVALE2ISNXS=TLBI_OP(0b100, 0b1001, 0b0010, 0b101),
	TLBI_ALLE2ISNXS=TLBI_OP(0b100, 0b1001, 0b0011, 0b000),
	TLBI_VAE2ISNXS=TLBI_OP(0b100, 0b1001, 0b0011, 0b001),
	TLBI_ALLE1ISNXS=TLBI_OP(0b100, 0b1001, 0b0011, 0b100),
	TLBI_VALE2ISNXS=TLBI_OP(0b100, 0b1001, 0b0011, 0b101),
	TLBI_VMALLS12E1ISNXS=TLBI_OP(0b100, 0b1001, 0b0011, 0b110),
	TLBI_IPAS2E1OSNXS=TLBI_OP(0b100, 0b1001, 0b0100, 0b000),
	TLBI_IPAS2E1NXS=TLBI_OP(0b100, 0b1001, 0b0100, 0b001),
	TLBI_RIPAS2E1NXS=TLBI_OP(0b100, 0b1001, 0b0100, 0b010),
	TLBI_RIPAS2E1OSNXS=TLBI_OP(0b100, 0b1001, 0b0100, 0b011),
	TLBI_IPAS2LE1OSNXS=TLBI_OP(0b100, 0b1001, 0b0100, 0b100),
	TLBI_IPAS2LE1NXS=TLBI_OP(0b100, 0b1001, 0b0100, 0b101),
	TLBI_RIPAS2LE1NXS=TLBI_OP(0b100, 0b1001, 0b0100, 0b110),
	TLBI_RIPAS2LE1OSNXS=TLBI_OP(0b100, 0b1001, 0b0100, 0b111),
	TLBI_RVAE2OSNXS=TLBI_OP(0b100, 0b1001, 0b0101, 0b001),
	TLBI_VMALLWS2E1OSNXS=TLBI_OP(0b100, 0b1001, 0b0101, 0b010),
	TLBI_RVALE2OSNXS=TLBI_OP(0b100, 0b1001, 0b0101, 0b101),
	TLBI_RVAE2NXS=TLBI_OP(0b100, 0b1001, 0b0110, 0b001),
	TLBI_VMALLWS2E1NXS=TLBI_OP(0b100, 0b1001, 0b0110, 0b010),
	TLBI_RVALE2NXS=TLBI_OP(0b100, 0b1001, 0b0110, 0b101),
	TLBI_ALLE2NXS=TLBI_OP(0b100, 0b1001, 0b0111, 0b000),
	TLBI_VAE2NXS=TLBI_OP(0b100, 0b1001, 0b0111, 0b001),
	TLBI_ALLE1NXS=TLBI_OP(0b100, 0b1001, 0b0111, 0b100),
	TLBI_VALE2NXS=TLBI_OP(0b100, 0b1001, 0b0111, 0b101),
	TLBI_VMALLS12E1NXS=TLBI_OP(0b100, 0b1001, 0b0111, 0b110),
	TLBI_ALLE3OS=TLBI_OP(0b110, 0b1000, 0b0001, 0b000),
	TLBI_VAE3OS=TLBI_OP(0b110, 0b1000, 0b0001, 0b001),
	TLBI_PAALLOS=TLBI_OP(0b110, 0b1000, 0b0001, 0b100),
	TLBI_VALE3OS=TLBI_OP(0b110, 0b1000, 0b0001, 0b101),
	TLBI_RVAE3IS=TLBI_OP(0b110, 0b1000, 0b0010, 0b001),
	TLBI_RVALE3IS=TLBI_OP(0b110, 0b1000, 0b0010, 0b101),
	TLBI_ALLE3IS=TLBI_OP(0b110, 0b1000, 0b0011, 0b000),
	TLBI_VAE3IS=TLBI_OP(0b110, 0b1000, 0b0011, 0b001),
	TLBI_VALE3IS=TLBI_OP(0b110, 0b1000, 0b0011, 0b101),
	TLBI_RPAOS=TLBI_OP(0b110, 0b1000, 0b0100, 0b011),
	TLBI_RPALOS=TLBI_OP(0b110, 0b1000, 0b0100, 0b111),
	TLBI_RVAE3OS=TLBI_OP(0b110, 0b1000, 0b0101, 0b001),
	TLBI_RVALE3OS=TLBI_OP(0b110, 0b1000, 0b0101, 0b101),
	TLBI_RVAE3=TLBI_OP(0b110, 0b1000, 0b0110, 0b001),
	TLBI_RVALE3=TLBI_OP(0b110, 0b1000, 0b0110, 0b101),
	TLBI_ALLE3=TLBI_OP(0b110, 0b1000, 0b0111, 0b000),
	TLBI_VAE3=TLBI_OP(0b110, 0b1000, 0b0111, 0b001),
	TLBI_PAALL=TLBI_OP(0b110, 0b1000, 0b0111, 0b100),
	TLBI_VALE3=TLBI_OP(0b110, 0b1000, 0b0111, 0b101),
	TLBI_ALLE3OSNXS=TLBI_OP(0b110, 0b1001, 0b0001, 0b000),
	TLBI_VAE3OSNXS=TLBI_OP(0b110, 0b1001, 0b0001, 0b001),
	TLBI_VALE3OSNXS=TLBI_OP(0b110, 0b1001, 0b0001, 0b101),
	TLBI_RVAE3ISNXS=TLBI_OP(0b110, 0b1001, 0b0010, 0b001),
	TLBI_RVALE3ISNXS=TLBI_OP(0b110, 0b1001, 0b0010, 0b101),
	TLBI_ALLE3ISNXS=TLBI_OP(0b110, 0b1001, 0b0011, 0b000),
	TLBI_VAE3ISNXS=TLBI_OP(0b110, 0b1001, 0b0011, 0b001),
	TLBI_VALE3ISNXS=TLBI_OP(0b110, 0b1001, 0b0011, 0b101),
	TLBI_RVAE3OSNXS=TLBI_OP(0b110, 0b1001, 0b0101, 0b001),
	TLBI_RVALE3OSNXS=TLBI_OP(0b110, 0b1001, 0b0101, 0b101),
	TLBI_RVAE3NXS=TLBI_OP(0b110, 0b1001, 0b0110, 0b001),
	TLBI_RVALE3NXS=TLBI_OP(0b110, 0b1001, 0b0110, 0b101),
	TLBI_ALLE3NXS=TLBI_OP(0b110, 0b1001, 0b0111, 0b000),
	TLBI_VAE3NXS=TLBI_OP(0b110, 0b1001, 0b0111, 0b001),
	TLBI_VALE3NXS=TLBI_OP(0b110, 0b1001, 0b0111, 0b101),
};

enum DCOp
{
	DC_OP_INVALID=-1,
	DC_OP_IVAC=DC_OP(0b000, 0b0110, 0b001),
	DC_OP_ISW=DC_OP(0b000, 0b0110, 0b010),
	DC_OP_IGVAC=DC_OP(0b000, 0b0110, 0b011),
	DC_OP_IGSW=DC_OP(0b000, 0b0110, 0b100),
	DC_OP_IGDVAC=DC_OP(0b000, 0b0110, 0b101),
	DC_OP_IGDSW=DC_OP(0b000, 0b0110, 0b110),
	DC_OP_CSW=DC_OP(0b000, 0b1010, 0b010),
	DC_OP_CGSW=DC_OP(0b000, 0b1010, 0b100),
	DC_OP_CGDSW=DC_OP(0b000, 0b1010, 0b110),
	DC_OP_CISW=DC_OP(0b000, 0b1110, 0b010),
	DC_OP_CIGSW=DC_OP(0b000, 0b1110, 0b100),
	DC_OP_CIGDSW=DC_OP(0b000, 0b1110, 0b110),
	DC_OP_CIVAPS=DC_OP(0b000, 0b1111, 0b001),
	DC_OP_CIGDVAPS=DC_OP(0b000, 0b1111, 0b101),
	DC_OP_ZVA=DC_OP(0b011, 0b0100, 0b001),
	DC_OP_GVA=DC_OP(0b011, 0b0100, 0b011),
	DC_OP_GZVA=DC_OP(0b011, 0b0100, 0b100),
	DC_OP_CVAC=DC_OP(0b011, 0b1010, 0b001),
	DC_OP_CGVAC=DC_OP(0b011, 0b1010, 0b011),
	DC_OP_CGDVAC=DC_OP(0b011, 0b1010, 0b101),
	DC_OP_CVAOC=DC_OP(0b011, 0b1011, 0b000),
	DC_OP_CVAU=DC_OP(0b011, 0b1011, 0b001),
	DC_OP_CGDVAOC=DC_OP(0b011, 0b1011, 0b111),
	DC_OP_CVAP=DC_OP(0b011, 0b1100, 0b001),
	DC_OP_CGVAP=DC_OP(0b011, 0b1100, 0b011),
	DC_OP_CGDVAP=DC_OP(0b011, 0b1100, 0b101),
	DC_OP_CVADP=DC_OP(0b011, 0b1101, 0b001),
	DC_OP_CGVADP=DC_OP(0b011, 0b1101, 0b011),
	DC_OP_CGDVADP=DC_OP(0b011, 0b1101, 0b101),
	DC_OP_CIVAC=DC_OP(0b011, 0b1110, 0b001),
	DC_OP_CIGVAC=DC_OP(0b011, 0b1110, 0b011),
	DC_OP_CIGDVAC=DC_OP(0b011, 0b1110, 0b101),
	DC_OP_CIVAOC=DC_OP(0b011, 0b1111, 0b000),
	DC_OP_CIGDVAOC=DC_OP(0b011, 0b1111, 0b111),
	DC_OP_CIPAE=DC_OP(0b100, 0b1110, 0b000),
	DC_OP_CIGDPAE=DC_OP(0b100, 0b1110, 0b111),
	DC_OP_CIPAPA=DC_OP(0b110, 0b1110, 0b001),
	DC_OP_CIGDPAPA=DC_OP(0b110, 0b1110, 0b101),
};

#ifndef __cplusplus
typedef enum SystemReg SystemReg;
typedef enum OperandClass OperandClass;
typedef enum Register Register;
typedef enum Condition Condition;
typedef enum ShiftType ShiftType;
typedef enum Operation Operation;
typedef enum Group Group;
typedef enum ArrangementSpec ArrangementSpec;
typedef enum SliceIndicator SliceIndicator;
typedef enum ImplSpec ImplSpec;
typedef enum TlbiOp TlbiOp;
#endif

#define MAX_REGISTERS 5
#define MAX_NAME      16

struct InstructionOperand
{
	OperandClass operandClass;
	ArrangementSpec arrSpec;

	// These fields are used by disjoint sets of operand classes, so they share storage.
	union
	{
		Register reg[MAX_REGISTERS];
		char name[MAX_NAME];    // for class NAME
		Condition cond;         // for class CONDITION
		SystemReg sysreg;       // for class SYS_REG
	};

	union
	{
		struct                  // for class SME_TILE
		{
			uint16_t tile;
			SliceIndicator slice;
		};
		uint8_t implspec[MAX_REGISTERS];  // for class IMPLEMENTATION_SPECIFIC
	};

	uint32_t lane;
	uint64_t immediate;
	ShiftType shiftType;
	uint32_t shiftValue;
	bool laneUsed;
	bool shiftValueUsed;
	bool signedImm;
	char pred_qual;			// predicate register qualifier ('z' or 'm')
	bool mul_vl;			// whether MEM_OFFSET has the offset "mul vl"
};

#ifndef __cplusplus
typedef struct InstructionOperand InstructionOperand;
#endif

#define MAX_OPERANDS 5

struct Instruction
{
	uint32_t insword;
	enum ENCODING encoding;

	enum Operation operation;
	InstructionOperand operands[MAX_OPERANDS];

	enum FlagEffect setflags;
};

#ifndef __cplusplus
typedef struct Instruction Instruction;
#endif

#ifdef __cplusplus
extern "C"
{
#endif

	int aarch64_decompose(uint32_t instructionValue, Instruction* instr, uint64_t address);
	size_t aarch64_get_register_size(enum Register);

#ifdef __cplusplus
}
#endif
