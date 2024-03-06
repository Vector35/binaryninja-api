#pragma once
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_MSC_VER)
	#define snprintf _snprintf
	#define restrict __restrict
	#define inline __inline
#else
	#include <stdlib.h>
	#ifdef __cplusplus
	#define restrict __restrict
	#endif
#endif

#define MAX_OPERANDS 6

#define UNCONDITIONAL(c) (((c) == COND_NONE) || ((c) == COND_NONE2))
#define CONDITIONAL(c) (((c) != COND_NONE) && ((c) != COND_NONE2))

#ifdef __cplusplus
#define restrict __restrict

namespace armv7 {
#endif

enum Operation {
	ARMV7_UNDEFINED,
	ARMV7_UNPREDICTABLE,
	ARMV7_ADC,
	ARMV7_ADCS,
	ARMV7_ADD,
	ARMV7_ADDS,
	ARMV7_ADDW,
	ARMV7_ADR,
	ARMV7_AND,
	ARMV7_ANDS,
	ARMV7_ASR,
	ARMV7_ASRS,
	ARMV7_B,
	ARMV7_BFC,
	ARMV7_BFI,
	ARMV7_BIC,
	ARMV7_BICS,
	ARMV7_BKPT,
	ARMV7_BL,
	ARMV7_BLX,
	ARMV7_BX,
	ARMV7_BXJ,
	ARMV7_CBNZ,
	ARMV7_CBZ,
	ARMV7_CDP,
	ARMV7_CDP2,
	ARMV7_CLREX,
	ARMV7_CLZ,
	ARMV7_CMN,
	ARMV7_CMP,
	ARMV7_CPS,
	ARMV7_CPSID,
	ARMV7_CPSIE,
	ARMV7_DBG,
	ARMV7_DMB,
	ARMV7_DSB,
	ARMV7_ENTERX,
	ARMV7_EOR,
	ARMV7_EORS,
	ARMV7_ERET,
	ARMV7_FLDMDBX,
	ARMV7_FLDMIAX,
	ARMV7_FSTMDBX,
	ARMV7_FSTMIAX,
	ARMV7_FSTMX,
	ARMV7_HINT,
	ARMV7_HVC,
	ARMV7_ISB,
	ARMV7_IT,
	ARMV7_LDA,
	ARMV7_LDAB,
	ARMV7_LDAH,
	ARMV7_LDAEX, // A32
	ARMV7_LDAEXB, // A32
	ARMV7_LDAEXH, // A32
	ARMV7_LDAEXD, // A32
	ARMV7_LDC,
	ARMV7_LDC2,
	ARMV7_LDC2L,
	ARMV7_LDCL,
	ARMV7_LDM,
	ARMV7_LDMDA,
	ARMV7_LDMDB,
	ARMV7_LDMIA,
	ARMV7_LDMIB,
	ARMV7_LDR,
	ARMV7_LDRB,
	ARMV7_LDRBT,
	ARMV7_LDRD,
	ARMV7_LDREX,
	ARMV7_LDREXB,
	ARMV7_LDREXD,
	ARMV7_LDREXH,
	ARMV7_LDRH,
	ARMV7_LDRHT,
	ARMV7_LDRSB,
	ARMV7_LDRSBT,
	ARMV7_LDRSH,
	ARMV7_LDRSHT,
	ARMV7_LDRT,
	ARMV7_LEAVEX,
	ARMV7_LSL,
	ARMV7_LSLS,
	ARMV7_LSR,
	ARMV7_LSRS,
	ARMV7_MCR,
	ARMV7_MCR2,
	ARMV7_MCRR,
	ARMV7_MCRR2,
	ARMV7_MLA,
	ARMV7_MLS,
	ARMV7_MOV,
	ARMV7_MOVS,
	ARMV7_MOVT,
	ARMV7_MOVW,
	ARMV7_MRC,
	ARMV7_MRC2,
	ARMV7_MRRC,
	ARMV7_MRRC2,
	ARMV7_MRS,
	ARMV7_MSR,
	ARMV7_MUL,
	ARMV7_MULS,
	ARMV7_MVN,
	ARMV7_MVNS,
	ARMV7_NOP,
	ARMV7_ORN,
	ARMV7_ORR,
	ARMV7_ORRS,
	ARMV7_PKHBT,
	ARMV7_PKHTB,
	ARMV7_PLD,
	ARMV7_PLDW,
	ARMV7_PLI,
	ARMV7_POP,
	ARMV7_PUSH,
	ARMV7_QADD,
	ARMV7_QADD16,
	ARMV7_QADD8,
	ARMV7_QASX,
	ARMV7_QDADD,
	ARMV7_QDSUB,
	ARMV7_QSAX,
	ARMV7_QSUB,
	ARMV7_QSUB16,
	ARMV7_QSUB8,
	ARMV7_RBIT,
	ARMV7_REV,
	ARMV7_REV16,
	ARMV7_REVSH,
	ARMV7_RFE,
	ARMV7_RFEDA,
	ARMV7_RFEDB,
	ARMV7_RFEIA,
	ARMV7_RFEIB,
	ARMV7_ROR,
	ARMV7_RORS,
	ARMV7_RRX,
	ARMV7_RSB,
	ARMV7_RSBS,
	ARMV7_RSC,
	ARMV7_SADD16,
	ARMV7_SADD8,
	ARMV7_SASX,
	ARMV7_SBC,
	ARMV7_SBCS,
	ARMV7_SBFX,
	ARMV7_SDIV,
	ARMV7_SEL,
	ARMV7_SETEND,
	ARMV7_SEV,
	ARMV7_SHADD16,
	ARMV7_SHADD8,
	ARMV7_SHASX,
	ARMV7_SHSAX,
	ARMV7_SHSUB16,
	ARMV7_SHSUB8,
	ARMV7_SMC,
	ARMV7_SMLABB,
	ARMV7_SMLABT,
	ARMV7_SMLAD,
	ARMV7_SMLADX,
	ARMV7_SMLAL,
	ARMV7_SMLALBB,
	ARMV7_SMLALBT,
	ARMV7_SMLALD,
	ARMV7_SMLALDX,
	ARMV7_SMLALTB,
	ARMV7_SMLALTT,
	ARMV7_SMLATB,
	ARMV7_SMLATT,
	ARMV7_SMLAWB,
	ARMV7_SMLAWT,
	ARMV7_SMLSD,
	ARMV7_SMLSDX,
	ARMV7_SMLSLD,
	ARMV7_SMLSLDX,
	ARMV7_SMMLA,
	ARMV7_SMMLAR,
	ARMV7_SMMLS,
	ARMV7_SMMLSR,
	ARMV7_SMMUL,
	ARMV7_SMMULR,
	ARMV7_SMUAD,
	ARMV7_SMUADX,
	ARMV7_SMULBB,
	ARMV7_SMULBT,
	ARMV7_SMULL,
	ARMV7_SMULTB,
	ARMV7_SMULTT,
	ARMV7_SMULWB,
	ARMV7_SMULWT,
	ARMV7_SMUSD,
	ARMV7_SMUSDT,
	ARMV7_SMUSDX,
	ARMV7_SRS,
	ARMV7_SRSDA,
	ARMV7_SRSDB,
	ARMV7_SRSIA,
	ARMV7_SRSIB,
	ARMV7_SSAT,
	ARMV7_SSAT16,
	ARMV7_SSAX,
	ARMV7_SSUB16,
	ARMV7_SSUB8,
	ARMV7_STC,
	ARMV7_STC2,
	ARMV7_STC2L,
	ARMV7_STCL,
	ARMV7_STL, // A32
	ARMV7_STLB,
	ARMV7_STLH,
	ARMV7_STLEX, // A32
	ARMV7_STLEXB, // A32
	ARMV7_STLEXH, // A32
	ARMV7_STLEXD, // A32
	ARMV7_STM,
	ARMV7_STMBD,
	ARMV7_STMDA,
	ARMV7_STMDB,
	ARMV7_STMIA,
	ARMV7_STMIB,
	ARMV7_STR,
	ARMV7_STRB,
	ARMV7_STRBT,
	ARMV7_STRD,
	ARMV7_STREX,
	ARMV7_STREXB,
	ARMV7_STREXD,
	ARMV7_STREXH,
	ARMV7_STRH,
	ARMV7_STRHT,
	ARMV7_STRT,
	ARMV7_SUB,
	ARMV7_SUBS,
	ARMV7_SUBW,
	ARMV7_SVC,
	ARMV7_SWP,
	ARMV7_SWPB,
	ARMV7_SXTAB,
	ARMV7_SXTAB16,
	ARMV7_SXTAH,
	ARMV7_SXTB,
	ARMV7_SXTB16,
	ARMV7_SXTH,
	ARMV7_TBB,
	ARMV7_TBH,
	ARMV7_TEQ,
	ARMV7_TRAP,
	ARMV7_TRT,
	ARMV7_TST,
	ARMV7_UADD16,
	ARMV7_UADD8,
	ARMV7_UASX,
	ARMV7_UBFX,
	ARMV7_UDF,
	ARMV7_UDIV,
	ARMV7_UHADD16,
	ARMV7_UHADD8,
	ARMV7_UHASX,
	ARMV7_UHSAX,
	ARMV7_UHSUB16,
	ARMV7_UHSUB8,
	ARMV7_UMAAL,
	ARMV7_UMLAL,
	ARMV7_UMULL,
	ARMV7_UQADD16,
	ARMV7_UQADD8,
	ARMV7_UQASX,
	ARMV7_UQSAX,
	ARMV7_UQSUB16,
	ARMV7_UQSUB8,
	ARMV7_USAD8,
	ARMV7_USADA8,
	ARMV7_USAT,
	ARMV7_USAT16,
	ARMV7_USAX,
	ARMV7_USUB16,
	ARMV7_USUB8,
	ARMV7_UXTAB,
	ARMV7_UXTAB16,
	ARMV7_UXTAH,
	ARMV7_UXTB,
	ARMV7_UXTB16,
	ARMV7_UXTH,
	ARMV7_VABA,
	ARMV7_VABAL,
	ARMV7_VABD,
	ARMV7_VABDL,
	ARMV7_VABS,
	ARMV7_VACGE,
	ARMV7_VACGT,
	ARMV7_VADD,
	ARMV7_VADDHN,
	ARMV7_VADDL,
	ARMV7_VADDW,
	ARMV7_VAND,
	ARMV7_VBIC,
	ARMV7_VBIF,
	ARMV7_VBIT,
	ARMV7_VBSL,
	ARMV7_VCEQ,
	ARMV7_VCGE,
	ARMV7_VCGT,
	ARMV7_VCLE,
	ARMV7_VCLS,
	ARMV7_VCLT,
	ARMV7_VCLZ,
	ARMV7_VCMP,
	ARMV7_VCMPE,
	ARMV7_VCNT,
	ARMV7_VCVT,
	ARMV7_VCVTA,
	ARMV7_VCVTB,
	ARMV7_VCVTM,
	ARMV7_VCVTN,
	ARMV7_VCVTP,
	ARMV7_VCVTR,
	ARMV7_VCVTT,
	ARMV7_VDIV,
	ARMV7_VDUP,
	ARMV7_VEOR,
	ARMV7_VEXT,
	ARMV7_VFMA,
	ARMV7_VFMS,
	ARMV7_VFNMA,
	ARMV7_VFNMS,
	ARMV7_VHADD,
	ARMV7_VHSUB,
	ARMV7_VLD1,
	ARMV7_VLD2,
	ARMV7_VLD3,
	ARMV7_VLD4,
	ARMV7_VLDM,
	ARMV7_VLDMDB,
	ARMV7_VLDMIA,
	ARMV7_VLDR,
	ARMV7_VMAX,
	ARMV7_VMAXNM,
	ARMV7_VMIN,
	ARMV7_VMINM,
	ARMV7_VMLA,
	ARMV7_VMLAL,
	ARMV7_VMLS,
	ARMV7_VMLSL,
	ARMV7_VMOV,
	ARMV7_VMOVL,
	ARMV7_VMOVN,
	ARMV7_VMRS,
	ARMV7_VMSR,
	ARMV7_VMUL,
	ARMV7_VMULL,
	ARMV7_VMVN,
	ARMV7_VNEG,
	ARMV7_VNMLA,
	ARMV7_VNMLS,
	ARMV7_VNMUL,
	ARMV7_VORN,
	ARMV7_VORR,
	ARMV7_VPADAL,
	ARMV7_VPADD,
	ARMV7_VPADDL,
	ARMV7_VPMAX,
	ARMV7_VPMIN,
	ARMV7_VPOP,
	ARMV7_VPUSH,
	ARMV7_VQABS,
	ARMV7_VQADD,
	ARMV7_VQDMLAL,
	ARMV7_VQDMLSL,
	ARMV7_VQDMULH,
	ARMV7_VQDMULL,
	ARMV7_VQMOVN,
	ARMV7_VQMOVUN,
	ARMV7_VQNEG,
	ARMV7_VQRDMULH,
	ARMV7_VQRSHL,
	ARMV7_VQRSHRN,
	ARMV7_VQRSHRUN,
	ARMV7_VQSHL,
	ARMV7_VQSHLU,
	ARMV7_VQSHRN,
	ARMV7_VQSHRUN,
	ARMV7_VQSUB,
	ARMV7_VRADDHN,
	ARMV7_VRECPE,
	ARMV7_VRECPS,
	ARMV7_VREV16,
	ARMV7_VREV32,
	ARMV7_VREV64,
	ARMV7_VRHADD,
	ARMV7_VRHSUB,
	ARMV7_VRINTA,
	ARMV7_VRINTM,
	ARMV7_VRINTN,
	ARMV7_VRINTP,
	ARMV7_VRINTR,
	ARMV7_VRINTX,
	ARMV7_VRINTZ,
	ARMV7_VRSHL,
	ARMV7_VRSHR,
	ARMV7_VRSHRN,
	ARMV7_VRSQRTE,
	ARMV7_VRSQRTS,
	ARMV7_VRSRA,
	ARMV7_VRSUBHN,
	ARMV7_VSEL,
	ARMV7_VSHL,
	ARMV7_VSHLL,
	ARMV7_VSHR,
	ARMV7_VSHRN,
	ARMV7_VSLI,
	ARMV7_VSQRT,
	ARMV7_VSRA,
	ARMV7_VSRI,
	ARMV7_VST1,
	ARMV7_VST2,
	ARMV7_VST3,
	ARMV7_VST4,
	ARMV7_VSTM,
	ARMV7_VSTMDB,
	ARMV7_VSTMIA,
	ARMV7_VSTR,
	ARMV7_VSUB,
	ARMV7_VSUBHN,
	ARMV7_VSUBL,
	ARMV7_VSUBW,
	ARMV7_VSWP,
	ARMV7_VTBL,
	ARMV7_VTBX,
	ARMV7_VTRN,
	ARMV7_VTST,
	ARMV7_VUZP,
	ARMV7_VZIP,
	ARMV7_WFE,
	ARMV7_WFI,
	ARMV7_YIELD,
	ARMV7_END_INSTRUCTION
};

enum Shift {
	SHIFT_NONE,
	SHIFT_LSL,
	SHIFT_LSR,
	SHIFT_ASR,
	SHIFT_ROR,
	SHIFT_RRX,
	SHIFT_END
};

enum Condition {
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
	COND_NONE,
	COND_NONE2,
	COND_END
};


enum RegisterList {
	REG_LIST_R0 = 0x0001,
	REG_LIST_R1 = 0x0002,
	REG_LIST_R2 = 0x0004,
	REG_LIST_R3 = 0x0008,
	REG_LIST_R4 = 0x0010,
	REG_LIST_R5 = 0x0020,
	REG_LIST_R6 = 0x0040,
	REG_LIST_R7 = 0x0080,
	REG_LIST_R8 = 0x0100,
	REG_LIST_SB = 0x0200,
	REG_LIST_SL = 0x0400,
	REG_LIST_FP = 0x0800,
	REG_LIST_IP = 0x1000,
	REG_LIST_SP = 0x2000,
	REG_LIST_LR = 0x4000,
	REG_LIST_PC = 0x8000,
};

enum Register
{
	REG_R0 = 0,
	REG_R1,
	REG_R2,
	REG_R3,
	REG_R4,
	REG_R5,
	REG_R6,
	REG_R7,
	REG_R8,
	REG_R9,
	REG_R10,
	REG_R11,
	REG_R12,
	REG_SP, REG_R13 = 13,
	REG_LR, REG_R14 = 14,
	REG_PC, REG_R15 = 15,
	REG_S0,
	REG_S1,
	REG_S2,
	REG_S3,
	REG_S4,
	REG_S5,
	REG_S6,
	REG_S7,
	REG_S8,
	REG_S9,
	REG_S10,
	REG_S11,
	REG_S12,
	REG_S13,
	REG_S14,
	REG_S15,
	REG_S16,
	REG_S17,
	REG_S18,
	REG_S19,
	REG_S20,
	REG_S21,
	REG_S22,
	REG_S23,
	REG_S24,
	REG_S25,
	REG_S26,
	REG_S27,
	REG_S28,
	REG_S29,
	REG_S30,
	REG_S31,
	REG_D0,
	REG_D1,
	REG_D2,
	REG_D3,
	REG_D4,
	REG_D5,
	REG_D6,
	REG_D7,
	REG_D8,
	REG_D9,
	REG_D10,
	REG_D11,
	REG_D12,
	REG_D13,
	REG_D14,
	REG_D15,
	REG_D16,
	REG_D17,
	REG_D18,
	REG_D19,
	REG_D20,
	REG_D21,
	REG_D22,
	REG_D23,
	REG_D24,
	REG_D25,
	REG_D26,
	REG_D27,
	REG_D28,
	REG_D29,
	REG_D30,
	REG_D31,
	REG_Q0,
	REG_Q1,
	REG_Q2,
	REG_Q3,
	REG_Q4,
	REG_Q5,
	REG_Q6,
	REG_Q7,
	REG_Q8,
	REG_Q9,
	REG_Q10,
	REG_Q11,
	REG_Q12,
	REG_Q13,
	REG_Q14,
	REG_Q15,

	/* banked registers */
	REGB_ELR_HYP,
	REGB_LR_ABT,
	REGB_LR_FIQ,
	REGB_LR_IRQ,
	REGB_LR_MON,
	REGB_LR_SVC,
	REGB_LR_UND,
	REGB_LR_USR,
	REGB_R10_FIQ,
	REGB_R10_USR,
	REGB_R11_FIQ,
	REGB_R11_USR,
	REGB_R12_FIQ,
	REGB_R12_USR,
	REGB_R8_FIQ,
	REGB_R8_USR,
	REGB_R9_FIQ,
	REGB_R9_USR,
	REGB_SPSR_ABT,
	REGB_SPSR_FIQ,
	REGB_SPSR_HYP,
	REGB_SPSR_IRQ,
	REGB_SPSR_MON,
	REGB_SPSR_SVC,
	REGB_SPSR_UND,
	REGB_SP_ABT,
	REGB_SP_FIQ,
	REGB_SP_HYP,
	REGB_SP_IRQ,
	REGB_SP_MON,
	REGB_SP_SVC,
	REGB_SP_UND,
	REGB_SP_USR,

	/* special registers */
	REGS_APSR,
	REGS_APSR_G,
	REGS_APSR_NZCVQ,
	REGS_APSR_NZCVQG,
	REGS_CPSR,
	REGS_CPSR_C,
	REGS_CPSR_X,
	REGS_CPSR_XC,
	REGS_CPSR_S,
	REGS_CPSR_SC,
	REGS_CPSR_SX,
	REGS_CPSR_SXC,
	REGS_CPSR_F,
	REGS_CPSR_FC,
	REGS_CPSR_FX,
	REGS_CPSR_FXC,
	REGS_CPSR_FS,
	REGS_CPSR_FSC,
	REGS_CPSR_FSX,
	REGS_CPSR_FSXC,
	REGS_SPSR,
	REGS_SPSR_C,
	REGS_SPSR_X,
	REGS_SPSR_XC,
	REGS_SPSR_S,
	REGS_SPSR_SC,
	REGS_SPSR_SX,
	REGS_SPSR_SXC,
	REGS_SPSR_F,
	REGS_SPSR_FC,
	REGS_SPSR_FX,
	REGS_SPSR_FXC,
	REGS_SPSR_FS,
	REGS_SPSR_FSC,
	REGS_SPSR_FSX,
	REGS_SPSR_FSXC,
	REGS_APSR_NZCV,
	REGS_FPSID, // 0
	REGS_FPSCR, // 1
	REGS_MVFR2, // 5
	REGS_MVFR1, // 6
	REGS_MVFR0, // 7
	REGS_FPEXC, // 8
	REGS_FPINST, // 9
	REGS_FPINST2, //10
	REGS_MSP,
	REGS_PSP,

	// these are M-profile only (special)
	// but are here in ARM common (general)
	// TODO: implement "microarchitecture support"
	REGS_PRIMASK,
	REGS_BASEPRI,
	REGS_FAULTMASK,
	REGS_CONTROL,

	REG_INVALID,
};

enum CoprocRegisterC {
	REG_C0,
	REG_C1,
	REG_C2,
	REG_C3,
	REG_C4,
	REG_C5,
	REG_C6,
	REG_C7,
	REG_C8,
	REG_C9,
	REG_C10,
	REG_C11,
	REG_C12,
	REG_C13,
	REG_C14,
	REG_C15,
	REG_CEND
};

enum CoprocRegisterP {
	REG_P0,
	REG_P1,
	REG_P2,
	REG_P3,
	REG_P4,
	REG_P5,
	REG_P6,
	REG_P7,
	REG_P8,
	REG_P9,
	REG_P10,
	REG_P11,
	REG_P12,
	REG_P13,
	REG_P14,
	REG_P15,
	REG_PEND
};

enum Iflags {
	IFL_NONE, // 000
	IFL_A,    // 001
	IFL_I,    // 010
	IFL_IA,   // 011
	IFL_F,    // 100
	IFL_FA,   // 101
	IFL_FI,   // 110
	IFL_FIA,  // 111
	IFL_END   //
};

enum EndianSpec {
	ES_LE,
	ES_BE
};

enum DsbOption {
	DSB_NONE0,  // 0
	DSB_NONE1,  // 1
	DSB_OSHST,  // 2
	DSB_OSH,    // 3
	DSB_NONE4,  // 4
	DSB_NONE5,  // 5
	DSB_NSHST,  // 6
	DSB_NSH,    //7
	DSB_NONE8,  // 8
	DSB_NONE9,  // 9
	DSB_ISHST,  // 10
	DSB_ISH,    // 11
	DSB_NONE12, // 12
	DSB_NONE13, // 13
	DSB_ST,     // 14
	DSB_SY,     // 15
	DSB_END
};

enum OperandClass {
	NONE,
	IMM,
	IMM64,
	LABEL,
	REG,
	REG_LIST,
	REG_LIST_SINGLE,
	REG_LIST_DOUBLE,
	REG_SPEC,
	REG_BANKED,
	REG_COPROCC,
	REG_COPROCP,
	IFLAGS,
	ENDIAN_SPEC,
	DSB_OPTION,
	MEM_ALIGNED,
	MEM_PRE_IDX,
	MEM_POST_IDX,
	MEM_IMM,
	MEM_OPTION,
	FIMM16,
	FIMM32,
	FIMM64
};

enum DataType {
	DT_NONE = 0,
	DT_S8   = 1,
	DT_S16,
	DT_S32,
	DT_S64,
	DT_U8,
	DT_U16,
	DT_U32,
	DT_U64,
	DT_I8,
	DT_I16,
	DT_I32,
	DT_I64,
	DT_F16,
	DT_F32,
	DT_F64,
	DT_P8,
	DT_P16,
	DT_P32,
	DT_P64,
	DT_8,
	DT_16,
	DT_32,
	DT_64,
	DT_END
};

struct InstructionOperand {
	enum OperandClass cls;
	struct {
		uint32_t wb:1;  //write back?
		uint32_t add:1; //Tells whether offset should be added or subtracted
		uint32_t hasElements:1; //does the register have an array index
		uint32_t emptyElement:1;
		uint32_t offsetRegUsed:1; //Is the offset register being used
	} flags;
	union {
		enum Register reg;
		enum Register regb; /* banked reg */
		enum Register regs; /* special reg */
		enum CoprocRegisterP regp;
		enum CoprocRegisterC regc;
		enum DsbOption dsbOpt;
		enum Iflags iflag;
		enum EndianSpec endian;
		enum Condition cond;
	};
	enum Register offset;
	enum Shift shift;
	union {
		uint32_t imm;
		double immd;
		float immf;
		uint64_t imm64;
	};
};

struct Instruction{
	enum Operation operation;
	enum Condition cond;
	enum DataType dataType;
	enum DataType dataType2;
	uint32_t setsFlags;
	uint32_t unpredictable;
	struct InstructionOperand operands[MAX_OPERANDS];
};

typedef union _ieee754 {
	uint32_t value;
	struct {
		uint32_t fraction:23;
		uint32_t exponent:8;
		uint32_t sign:1;
	};
	float fvalue;
}ieee754;

typedef union _ieee754_double {
	uint64_t value;
	struct {
		uint64_t fraction:52;
		uint64_t exponent:11;
		uint64_t sign:1;
	};
	double fvalue;
}ieee754_double;

#ifndef __cplusplus
	typedef enum OperandClass OperandClass;
	typedef enum Operation Operation;
	typedef enum Shift Shift;
	typedef enum Condition Condition;
	typedef enum Register Register;
	typedef enum BankedRegister BankedRegister;
	typedef enum SpecRegister SpecRegister;
	typedef enum CoprocRegisterP CoprocRegisterP;
	typedef enum CoprocRegisterC CoprocRegisterC;
	typedef enum DataType DataType;
	typedef enum Iflags Iflags;
	typedef enum EndianSpec EndianSpec;
	typedef enum DsbOption DsbOption;
	typedef struct InstructionOperand InstructionOperand;
	typedef struct Instruction Instruction;
#endif

#ifdef __cplusplus
	extern "C" {
#endif
	uint32_t armv7_decompose(
	        uint32_t instructionValue,
	        Instruction* restrict instruction,
	        uint32_t address,
	        uint32_t littleEndian);

	uint32_t armv7_disassemble(
			Instruction* restrict instruction,
			char* outBuffer,
			uint32_t outBufferSize);

	//Helpers for disassembling the instruction operands to strings
	const char* get_operation(Operation operation);
	char* get_full_operation(char* outBuffer, size_t outBufferSize, Instruction* restrict instruction);
	const char* get_vector_data_type(DataType dataType);
	const char* get_register_name(Register reg);
	const char* get_banked_register_name(Register regb);
	const char* get_spec_register_name(Register regs);
	const char* get_coproc_register_c_name(CoprocRegisterC regc);
	const char* get_coproc_register_p_name(CoprocRegisterP regp);
	const char* get_iflag(Iflags iflag);
	const char* get_endian(EndianSpec spec);
	const char* get_dsb_option(DsbOption opt);
	const char* get_shift(Shift shift);
	const char* get_condition(Condition cond);
	uint32_t get_register_size(Register reg);
	uint32_t get_register_names(Register reg, const char** regNames, OperandClass type);
#ifdef __cplusplus
	} //end extern "C"
#endif

#ifdef __cplusplus
} //end namespace
#endif
