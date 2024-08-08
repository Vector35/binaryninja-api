#pragma once
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#if defined(_MSC_VER)
        #undef REG_NONE
        #define snprintf _snprintf
        #define restrict __restrict
        #define inline __inline
#else
        #include <stdlib.h>
        #ifdef __cplusplus
        #define restrict __restrict
        #endif
#endif

#ifdef __clang__
#define FALL_THROUGH
#elif defined(__GNUC__) && __GNUC__ >= 7
#define FALL_THROUGH __attribute__((fallthrough));
#else
#define FALL_THROUGH
#endif

#define MAX_OPERANDS 4

#ifdef __cplusplus
#define restrict __restrict

namespace mips
{
#endif
	static const uint32_t DECOMPOSE_FLAGS_PSEUDO_OP = 0x1;
	static const uint32_t DECOMPOSE_FLAGS_CAVIUM = 0x2;

	enum Operation {
		MIPS_INVALID,
		MIPS_ABS_D,
		MIPS_ABS_PS,
		MIPS_ABS_S,
		MIPS_ADD_D,
		MIPS_ADD_PS,
		MIPS_ADD_S,
		MIPS_ADD,
		MIPS_ADDI,
		MIPS_ADDIU,
		MIPS_ADDR,
		MIPS_ADDU,
		MIPS_ALIGN,
		MIPS_ALNV_PS,
		MIPS_AND,
		MIPS_ANDI,
		MIPS_B,
		MIPS_BAL,
		MIPS_BC1ANY2,
		MIPS_BC1ANY4,
		MIPS_BC1EQZ,
		MIPS_BC1F,
		MIPS_BC1FL,
		MIPS_BC1NEZ,
		MIPS_BC1T,
		MIPS_BC1TL,
		MIPS_BC2EQZ,
		MIPS_BC2F,
		MIPS_BC2FL,
		MIPS_BC2NEZ,
		MIPS_BC2T,
		MIPS_BC2TL,
		MIPS_BCNEZ,
		MIPS_BEQ,
		MIPS_BEQL,
		MIPS_BEQZ,
		MIPS_BGEZ,
		MIPS_BGEZAL,
		MIPS_BGEZALL,
		MIPS_BGEZL,
		MIPS_BGTZ,
		MIPS_BGTZL,
		MIPS_BITSWAP,
		MIPS_BLEZ,
		MIPS_BLEZL,
		MIPS_BLTZ,
		MIPS_BLTZAL,
		MIPS_BLTZALL,
		MIPS_BLTZL,
		MIPS_BNE,
		MIPS_BNEL,
		MIPS_BNEZ,
		MIPS_BNZ_B,
		MIPS_BNZ_D,
		MIPS_BNZ_H,
		MIPS_BNZ_W,
		MIPS_BREAK,
		MIPS_BSHFL,
		MIPS_BZ_B,
		MIPS_BZ_D,
		MIPS_BZ_H,
		MIPS_BZ_W,
		MIPS_C_DF_D,
		MIPS_C_EQ_D,
		MIPS_C_EQ_PS,
		MIPS_C_EQ_S,
		MIPS_C_EQ,
		MIPS_C_F_D,
		MIPS_C_F_PS,
		MIPS_C_F_S,
		MIPS_C_F,
		MIPS_C_LE_D,
		MIPS_C_LE_PS,
		MIPS_C_LE_S,
		MIPS_C_LE,
		MIPS_C_LT_D,
		MIPS_C_LT_PS,
		MIPS_C_LT_S,
		MIPS_C_LT,
		MIPS_C_NGE_D,
		MIPS_C_NGE_PS,
		MIPS_C_NGE_S,
		MIPS_C_NGE,
		MIPS_C_NGL_D,
		MIPS_C_NGL_PS,
		MIPS_C_NGL_S,
		MIPS_C_NGL,
		MIPS_C_NGLE_D,
		MIPS_C_NGLE_PS,
		MIPS_C_NGLE_S,
		MIPS_C_NGLE,
		MIPS_C_NGT_D,
		MIPS_C_NGT_PS,
		MIPS_C_NGT_S,
		MIPS_C_NGT,
		MIPS_C_OLE_D,
		MIPS_C_OLE_PS,
		MIPS_C_OLE_S,
		MIPS_C_OLE,
		MIPS_C_OLT_D,
		MIPS_C_OLT_PS,
		MIPS_C_OLT_S,
		MIPS_C_OLT,
		MIPS_C_SEQ_D,
		MIPS_C_SEQ_PS,
		MIPS_C_SEQ_S,
		MIPS_C_SEQ,
		MIPS_C_SF_D,
		MIPS_C_SF_PS,
		MIPS_C_SF_S,
		MIPS_C_SF,
		MIPS_C_UEQ_D,
		MIPS_C_UEQ_PS,
		MIPS_C_UEQ_S,
		MIPS_C_UEQ,
		MIPS_C_ULE_D,
		MIPS_C_ULE_PS,
		MIPS_C_ULE_S,
		MIPS_C_ULE,
		MIPS_C_ULT_D,
		MIPS_C_ULT_PS,
		MIPS_C_ULT_S,
		MIPS_C_ULT,
		MIPS_C_UN_D,
		MIPS_C_UN_PS,
		MIPS_C_UN_S,
		MIPS_C_UN,
		MIPS_C1,
		MIPS_C2,
		MIPS_CACHE,
		MIPS_CEIL_L_D,
		MIPS_CEIL_L_S,
		MIPS_CEIL_L,
		MIPS_CEIL_W_D,
		MIPS_CEIL_W_S,
		MIPS_CEIL_W,
		MIPS_CFC0,
		MIPS_CFC1,
		MIPS_CFC2,
		MIPS_CLASS_D,
		MIPS_CLASS_S,
		MIPS_CLO,
		MIPS_CLZ,
		MIPS_COP0,
		MIPS_COP1,
		MIPS_COP1X,
		MIPS_COP2,
		MIPS_COP3,
		MIPS_CTC0,
		MIPS_CTC1,
		MIPS_CTC2,
		MIPS_CVT_D_S,
		MIPS_CVT_D_W,
		MIPS_CVT_L_D,
		MIPS_CVT_L_S,
		MIPS_CVT_L,
		MIPS_CVT_PS_PW,
		MIPS_CVT_PS_S,
		MIPS_CVT_PS,
		MIPS_CVT_PW_PS,
		MIPS_CVT_S_D,
		MIPS_CVT_S_L,
		MIPS_CVT_S_PL,
		MIPS_CVT_S_PU,
		MIPS_CVT_S_W,
		MIPS_CVT_W_D,
		MIPS_CVT_W_S,
		MIPS_CVT_W,
		MIPS_DADD,
		MIPS_DADDI,
		MIPS_DADDIU,
		MIPS_DADDU,
		MIPS_DBSHFL,
		MIPS_DCLO,
		MIPS_DCLZ,
		MIPS_DDIV,
		MIPS_DDIVU,
		MIPS_DERET,
		MIPS_DEXT,
		MIPS_DEXTM,
		MIPS_DEXTU,
		MIPS_DI,
		MIPS_DINS,
		MIPS_DINSM,
		MIPS_DINSU,
		MIPS_DIV_D,
		MIPS_DIV_PS,
		MIPS_DIV_S,
		MIPS_DIV,
		MIPS_DIVU,
		MIPS_DMFC0,
		MIPS_DMFC1,
		MIPS_DMFC2,
		MIPS_DMULT,
		MIPS_DMULTU,
		MIPS_DMTC0,
		MIPS_DMTC1,
		MIPS_DMTC2,
		MIPS_DRET,
		MIPS_DROTR,
		MIPS_DROTR32,
		MIPS_DROTRV,
		MIPS_DSBH,
		MIPS_DSHD,
		MIPS_DSLL,
		MIPS_DSLL32,
		MIPS_DSLLV,
		MIPS_DSRA,
		MIPS_DSRA32,
		MIPS_DSRAV,
		MIPS_DSRL,
		MIPS_DSRL32,
		MIPS_DSRLV,
		MIPS_DSUB,
		MIPS_DSUBU,
		MIPS_EHB,
		MIPS_EI,
		MIPS_ERET,
		MIPS_EXT,
		MIPS_FLOOR_L_D,
		MIPS_FLOOR_L_S,
		MIPS_FLOOR_L,
		MIPS_FLOOR_W_D,
		MIPS_FLOOR_W_S,
		MIPS_FLOOR_W,
		MIPS_INS,
		MIPS_J,
		MIPS_JAL,
		MIPS_JALR_HB,
		MIPS_JALR,
		MIPS_JALX,
		MIPS_JR_HB,
		MIPS_JR,
		MIPS_LB,
		MIPS_LBU,
		MIPS_LBUX,
		MIPS_LD,
		MIPS_LDC1,
		MIPS_LDC2,
		MIPS_LDC3,
		MIPS_LDL,
		MIPS_LDR,
		MIPS_LDXC1,
		MIPS_LH,
		MIPS_LHI,
		MIPS_LHU,
		MIPS_LHX,
		MIPS_LI,
		MIPS_LL,
		MIPS_LLD,
		MIPS_LLO,
		MIPS_LUI,
		MIPS_LUXC1,
		MIPS_LW,
		MIPS_LWC1,
		MIPS_LWC2,
		MIPS_LWC3,
		MIPS_LWL,
		MIPS_LWR,
		MIPS_LWU,
		MIPS_LWX,
		MIPS_LWXC1,
		MIPS_LX,
		MIPS_MADD_D,
		MIPS_MADD_PS,
		MIPS_MADD_S,
		MIPS_MADD,
		MIPS_MADDF_D,
		MIPS_MADDF_S,
		MIPS_MADDU,
		MIPS_MFC0,
		MIPS_MFC1,
		MIPS_MFC2,
		MIPS_MFHC1,
		MIPS_MFHC2,
		MIPS_MFHI,
		MIPS_MFLO,
		MIPS_MOV_D,
		MIPS_MOV_PS,
		MIPS_MOV_S,
		MIPS_MOVCF,
		MIPS_MOVCI,
		MIPS_MOVE,
		MIPS_MOVF_D,
		MIPS_MOVF_PS,
		MIPS_MOVF_S,
		MIPS_MOVF,
		MIPS_MOVN_D,
		MIPS_MOVN_PS,
		MIPS_MOVN_S,
		MIPS_MOVN,
		MIPS_MOVT_D,
		MIPS_MOVT_PS,
		MIPS_MOVT_S,
		MIPS_MOVT,
		MIPS_MOVZ_D,
		MIPS_MOVZ_PS,
		MIPS_MOVZ_S,
		MIPS_MOVZ,
		MIPS_MSUB_D,
		MIPS_MSUB_PS,
		MIPS_MSUB_S,
		MIPS_MSUB,
		MIPS_MSUBF_D,
		MIPS_MSUBF_S,
		MIPS_MSUBU,
		MIPS_MTC0,
		MIPS_MTC1,
		MIPS_MTC2,
		MIPS_MTHC1,
		MIPS_MTHC2,
		MIPS_MTHI,
		MIPS_MTLO,
		MIPS_MUL_D,
		MIPS_MUL_PS,
		MIPS_MUL_S,
		MIPS_MUL,
		MIPS_MULR,
		MIPS_MULT,
		MIPS_MULTU,
		MIPS_NEG_D,
		MIPS_NEG_PS,
		MIPS_NEG_S,
		MIPS_NEG,
		MIPS_NEGU,
		MIPS_NMADD_D,
		MIPS_NMADD_PS,
		MIPS_NMADD_S,
		MIPS_NMSUB_D,
		MIPS_NMSUB_PS,
		MIPS_NMSUB_S,
		MIPS_NOP,
		MIPS_NOR,
		MIPS_NOT,
		MIPS_OR,
		MIPS_ORI,
		MIPS_PAUSE,
		MIPS_PLL_PS,
		MIPS_PLU_PS,
		MIPS_PREF,
		MIPS_PREFX,
		MIPS_PUL_PS,
		MIPS_PUU_PS,
		MIPS_RDHWR,
		MIPS_RDPGPR,
		MIPS_RECIP_D,
		MIPS_RECIP_S,
		MIPS_RECIP,
		MIPS_RECIP1,
		MIPS_RECIP2,
		MIPS_RINT_D,
		MIPS_RINT_S,
		MIPS_ROTR,
		MIPS_ROTRV,
		MIPS_ROUND_L_D,
		MIPS_ROUND_L_S,
		MIPS_ROUND_L,
		MIPS_ROUND_W_D,
		MIPS_ROUND_W_S,
		MIPS_ROUND_W,
		MIPS_RSQRT_D,
		MIPS_RSQRT_S,
		MIPS_RSQRT,
		MIPS_RSQRT1,
		MIPS_RSQRT2,
		MIPS_SB,
		MIPS_SC,
		MIPS_SCD,
		MIPS_SD,
		MIPS_SDBBP,
		MIPS_SDC1,
		MIPS_SDC2,
		MIPS_SDC3,
		MIPS_SDL,
		MIPS_SDR,
		MIPS_SDXC1,
		MIPS_SEB,
		MIPS_SEH,
		MIPS_SEL_D,
		MIPS_SEL_S,
		MIPS_SH,
		MIPS_SLL,
		MIPS_SLLV,
		MIPS_SLT,
		MIPS_SLTI,
		MIPS_SLTIU,
		MIPS_SLTU,
		MIPS_SQRT_D,
		MIPS_SQRT_PS,
		MIPS_SQRT_S,
		MIPS_SRA,
		MIPS_SRAV,
		MIPS_SRL,
		MIPS_SRLV,
		MIPS_SSNOP,
		MIPS_SUB_D,
		MIPS_SUB_PS,
		MIPS_SUB_S,
		MIPS_SUB,
		MIPS_SUBU,
		MIPS_SUXC1,
		MIPS_SW,
		MIPS_SWC1,
		MIPS_SWC2,
		MIPS_SWC3,
		MIPS_SWL,
		MIPS_SWR,
		MIPS_SWXC1,
		MIPS_SYNC,
		MIPS_SYNCI,
		MIPS_SYSCALL,
		MIPS_TEQ,
		MIPS_TEQI,
		MIPS_TGE,
		MIPS_TGEI,
		MIPS_TGEIU,
		MIPS_TGEU,
		MIPS_TLBINV,
		MIPS_TLBINVF,
		MIPS_TLBP,
		MIPS_TLBR,
		MIPS_TLBWI,
		MIPS_TLBWR,
		MIPS_TLT,
		MIPS_TLTI,
		MIPS_TLTIU,
		MIPS_TLTU,
		MIPS_TNE,
		MIPS_TNEI,
		MIPS_TRAP,
		MIPS_TRUNC_L_D,
		MIPS_TRUNC_L_S,
		MIPS_TRUNC_L,
		MIPS_TRUNC_W_D,
		MIPS_TRUNC_W_S,
		MIPS_TRUNC_W,
		MIPS_WAIT,
		MIPS_WRPGPR,
		MIPS_WSBH,
		MIPS_XOR,
		MIPS_XORI,

		// cavium instructions
		CNMIPS_BADDU,
		CNMIPS_BBIT0,
		CNMIPS_BBIT032,
		CNMIPS_BBIT1,
		CNMIPS_BBIT132,
		CNMIPS_CINS,
		CNMIPS_CINS32,
		CNMIPS_CVM,
		CNMIPS_DMUL,
		CNMIPS_DPOP,
		CNMIPS_EXTS,
		CNMIPS_EXTS32,
		CNMIPS_MTM0,
		CNMIPS_MTM1,
		CNMIPS_MTM2,
		CNMIPS_MTP0,
		CNMIPS_MTP1,
		CNMIPS_MTP2,
		CNMIPS_POP,
		CNMIPS_RDHWR,
		CNMIPS_SAA,
		CNMIPS_SAAD,
		CNMIPS_SEQ,
		CNMIPS_SEQI,
		CNMIPS_SNE,
		CNMIPS_SNEI,
		CNMIPS_SYNCIOBDMA,
		CNMIPS_SYNCS,
		CNMIPS_SYNCW,
		CNMIPS_SYNCWS,
		CNMIPS_V3MULU,
		CNMIPS_VMM0,
		CNMIPS_VMULU,
		CNMIPS_ZCB,
		CNMIPS_ZCBT,

		MIPS_OPERATION_END
	};



	enum Reg {
		REG_ZERO,    // Hardware constant 0
		REG_AT,      // Reserved for assembler
		REG_V0,      // Return values
		REG_V1,
		REG_A0,      // Arguments
		REG_A1,
		REG_A2,
		REG_A3,
		REG_T0,      // Temporaries, or extra arguments if N64
		REG_A4 = REG_T0,
		REG_T1,
		REG_A5 = REG_T1,
		REG_T2,
		REG_A6 = REG_T2,
		REG_T3,
		REG_A7 = REG_T3,
		REG_T4,
		REG_T5,
		REG_T6,
		REG_T7,
		REG_S0,      // Saved values
		REG_S1,
		REG_S2,
		REG_S3,
		REG_S4,
		REG_S5,
		REG_S6,
		REG_S7,
		REG_T8,      // Cont. Saved values
		REG_T9,
		REG_K0,      // Reserved for OS
		REG_K1,
		REG_GP,      // Global pointer
		REG_SP,      // Stack Pointer
		REG_FP,      // Frame Pointer
		REG_RA,       // Return Adress
		CPREG_0,
		CPREG_1,
		CPREG_2,
		CPREG_3,
		CPREG_4,
		CPREG_5,
		CPREG_6,
		CPREG_7,
		CPREG_8,
		CPREG_9,
		CPREG_10,
		CPREG_11,
		CPREG_12,
		CPREG_13,
		CPREG_14,
		CPREG_15,
		CPREG_16,
		CPREG_17,
		CPREG_18,
		CPREG_19,
		CPREG_20,
		CPREG_21,
		CPREG_22,
		CPREG_23,
		CPREG_24,
		CPREG_25,
		CPREG_26,
		CPREG_27,
		CPREG_28,
		CPREG_29,
		CPREG_30,
		CPREG_31,
		FPREG_F0,
		FPREG_F1,
		FPREG_F2,
		FPREG_F3,
		FPREG_F4,
		FPREG_F5,
		FPREG_F6,
		FPREG_F7,
		FPREG_F8,
		FPREG_F9,
		FPREG_F10,
		FPREG_F11,
		FPREG_F12,
		FPREG_F13,
		FPREG_F14,
		FPREG_F15,
		FPREG_F16,
		FPREG_F17,
		FPREG_F18,
		FPREG_F19,
		FPREG_F20,
		FPREG_F21,
		FPREG_F22,
		FPREG_F23,
		FPREG_F24,
		FPREG_F25,
		FPREG_F26,
		FPREG_F27,
		FPREG_F28,
		FPREG_F29,
		FPREG_F30,
		FPREG_F31,
		REG_LO,
		REG_HI,

		// Standardized coprocessor 0 registers (as of MIPS64 document MD00091 Rev 2.50)
		// Coprocessor 0 register 0
		// Register             // Selector
		REG_INDEX,		// 0
		REG_MVP_CONTROL,	// 1
		REG_MVP_CONF0,		// 2
		REG_MVP_CONF1,		// 3
		// Coprocessor 0 register 1
		REG_RANDOM,		// 0
		REG_VPE_CONTROL,	// 1
		REG_VPE_CONF0,		// 2
		REG_VPE_CONF1,		// 3
		REG_YQ_MASK,		// 4
		REG_VPE_SCHEDULE,	// 5
		REG_VPE_SCHE_FBACK,	// 6
		REG_VPE_OPT,		// 7
		// Coprocessor 0 register 2
		REG_ENTRY_LO0,		// 0
		REG_TC_STATUS,		// 1
		REG_TC_BIND,		// 2
		REG_TC_RESTART,		// 3
		REG_TC_HALT,		// 4
		REG_TC_CONTEXT,		// 5
		REG_TC_SCHEDULE,	// 6
		REG_TC_SCHE_FBACK,	// 7
		// Coprocessor 0 register 3
		REG_ENTRY_LO1,		// 0
		// Coprocessor 0 register 4
		REG_CONTEXT,		// 0
		REG_CONTEXT_CONFIG,	// 1
		// Coprocessor 0 register 5
		REG_PAGE_MASK,		// 0
		REG_PAGE_GRAIN,		// 1
		// Coprocessor 0 register 6
		REG_WIRED,		// 0
		REG_SRS_CONF0,		// 1
		REG_SRS_CONF1,		// 2
		REG_SRS_CONF2,		// 3
		REG_SRS_CONF3,		// 4
		REG_SRS_CONF4,		// 5
		// Coprocessor 0 register 7
		REG_HWR_ENA,		// 0
		// Coprocessor 0 register 8
		REG_BAD_VADDR,		// 0
		// Coprocessor 0 register 9
		REG_COUNT,		// 0
		// Coprocessor 0 register 10
		REG_ENTRY_HI,		// 0
		// Coprocessor 0 register 11
		REG_COMPARE,		// 0
		// Coprocessor 0 register 12
		REG_STATUS,		// 0
		REG_INT_CTL,		// 1
		REG_SRS_CTL,		// 2
		REG_SRS_MAP,		// 3
		// Coprocessor 0 register 13
		REG_CAUSE,		// 0
		// Coprocessor 0 register 14
		REG_EPC,		// 0
		// Coprocessor 0 register 15
		REG_PR_ID,		// 0
		REG_EBASE,		// 1
		// Coprocessor 0 register 16
		REG_CONFIG,		// 0
		REG_CONFIG1,		// 1
		REG_CONFIG2,		// 2
		REG_CONFIG3,		// 3
		// Coprocessor 0 register 17
		REG_LLADDR,		// 0
		// Coprocessor 0 register 18
		REG_WATCH_LO,		// 0-n
		// Coprocessor 0 register 19
		REG_WATCH_HI,		// 0-n
		// Coprocessor 0 register 20
		REG_XCONTEXT,		// 0
		// Coprocessor 0 register 23
		REG_DEBUG,		// 0
		REG_TRACE_CONTROL,	// 1
		REG_TRACE_CONTROL2,	// 2
		REG_USER_TRACE_DATA,	// 3
		REG_TRACE_BPC,		// 4
		// Coprocessor 0 register 24
		REG_DEPC,		// 0
		// Coprocessor 0 register 25
		REG_PERF_CNT,		// 0-n
		// Coprocessor 0 register 26
		REG_ERR_CTL,		// 0
		// Coprocessor 0 register 27
		REG_CACHE_ERR0,		// 0
		REG_CACHE_ERR1,		// 1
		REG_CACHE_ERR2,		// 2
		REG_CACHE_ERR3,		// 3
		// Coprocessor 0 register 28
		REG_TAG_LO,		// even selects
		REG_DATA_LO,		// odd selects
		// Coprocessor 0 register 29
		REG_TAG_HI,		// even selects
		REG_DATA_HI,		// odd selects
		// Coprocessor 0 register 30
		REG_ERROR_EPC,		// 0
		// Coprocessor 0 register 31
		REG_DESAVE,		// 0

		// cavium multiplication registers
		CNREG_MPL0,
		CNREG_MPL1,
		CNREG_MPL2,
		CNREG_P0,
		CNREG_P1,
		CNREG_P2,

		// cavium cop0 registers: see `COP0_xx` macros in cvmx-asm.h in SDK
		CNREG0_CVM_COUNT,	// implementation-defined 9, 6
		CNREG0_CVM_CTL,		// implementation-defined 9, 7
		CNREG0_POWTHROTTLE,	// implementation-defined 11, 6
		CNREG0_CVM_MEM_CTL,	// implementation-defined 11, 7
		CNREG0_MULTICORE_DBG,	// implementation-defined 22, 0

		// cavium cop2 registers
		CNREG2_0040_HSH_DAT0,
		CNREG2_0041_HSH_DAT1,
		CNREG2_0042_HSH_DAT2,
		CNREG2_0043_HSH_DAT3,
		CNREG2_0044_HSH_DAT4,
		CNREG2_0045_HSH_DAT5,
		CNREG2_0046_HSH_DAT6,

		CNREG2_0048_HSH_IV0,
		CNREG2_0049_HSH_IV1,
		CNREG2_004A_HSH_IV2,
		CNREG2_004B_HSH_IV3,

		CNREG2_0050_SHA3_DAT24,
		CNREG2_0051_SHA3_DAT15_RD,

		CNREG2_0058_GFM_MUL_REFLECT0,
		CNREG2_0059_GFM_MUL_REFLECT1,
		CNREG2_005A_GFM_RESINP_REFLECT0,
		CNREG2_005B_GFM_RESINP_REFLECT1,
		CNREG2_005C_GFM_XOR0_REFLECT,

		// also KASUMI
		CNREG2_0080_3DES_KEY0,
		CNREG2_0081_3DES_KEY1,
		CNREG2_0082_3DES_KEY2,

		CNREG2_0084_3DES_IV,
		CNREG2_0088_3DES_RESULT_RD,
		CNREG2_0098_3DES_RESULT_WR,

		// also SMS4 RESINP
		CNREG2_0100_AES_RESULT0,
		CNREG2_0101_AES_RESULT1,

		// also SMS4 IV
		CNREG2_0102_AES_IV0,
		CNREG2_0103_AES_IV1,

		// also SMS4 KEY
		CNREG2_0104_AES_KEY0,
		CNREG2_0105_AES_KEY1,
		CNREG2_0106_AES_KEY2,
		CNREG2_0107_AES_KEY3,

		// also SMS4_x
		CNREG2_0108_AES_ENC_CBC0,
		CNREG2_010A_AES_ENC0,
		CNREG2_010C_AES_DEC_CBC0,
		CNREG2_010E_AES_DEC0,

		CNREG2_0110_AES_KEYLENGTH,
		CNREG2_0111_AES_DAT0,

		CNREG2_0115_CAMELLIA_FL,
		CNREG2_0116_CAMELLIA_FLINV,

		CNREG2_0200_CRC_POLYNOMIAL,
		CNREG2_0201_CRC_IV,
		CNREG2_0202_CRC_LEN,
		CNREG2_0203_CRC_IV_REFLECT_RD,
		CNREG2_0204_CRC_BYTE,
		CNREG2_0205_CRC_HALF,
		CNREG2_0206_CRC_WORD,
		CNREG2_0211_CRC_IV_REFLECT_WR,
		CNREG2_0214_CRC_BYTE_REFLECT,
		CNREG2_0215_CRC_HALF_REFLECT,
		CNREG2_0216_CRC_WORD_REFLECT,

		// also SNOW3G_LFSR, SHA3DAT0..=14
		CNREG2_0240_HSH_DATW0,
		CNREG2_0241_HSH_DATW1,
		CNREG2_0242_HSH_DATW2,
		CNREG2_0243_HSH_DATW3,
		CNREG2_0244_HSH_DATW4,
		CNREG2_0245_HSH_DATW5,
		CNREG2_0246_HSH_DATW6,
		CNREG2_0247_HSH_DATW7,
		CNREG2_0248_HSH_DATW8,
		CNREG2_0249_HSH_DATW9,
		CNREG2_024A_HSH_DATW10,
		CNREG2_024B_HSH_DATW11,
		CNREG2_024C_HSH_DATW12,
		CNREG2_024D_HSH_DATW13,
		CNREG2_024E_HSH_DATW14,

		CNREG2_024F_SHA3_DAT15_RD,

		// also SNOW3G_RESULT (0x250), SNOW3G_SFM (0x251, 0x252, 0x253)
		CNREG2_0250_HSH_IVW0,
		CNREG2_0251_HSH_IVW1,
		CNREG2_0252_HSH_IVW2,
		CNREG2_0253_HSH_IVW3,
		CNREG2_0254_HSH_IVW4,
		CNREG2_0255_HSH_IVW5,
		CNREG2_0256_HSH_IVW6,
		CNREG2_0257_HSH_IVW7,

		CNREG2_0258_GFM_MUL0,
		CNREG2_0259_GFM_MUL1,
		CNREG2_025A_GFM_RESINP0,
		CNREG2_025B_GFM_RESINP1,
		CNREG2_025C_GFM_XOR0,
		CNREG2_025E_GFM_POLY,

		CNREG2_02C0_SHA3_XORDAT0,
		CNREG2_02C1_SHA3_XORDAT1,
		CNREG2_02C2_SHA3_XORDAT2,
		CNREG2_02C3_SHA3_XORDAT3,
		CNREG2_02C4_SHA3_XORDAT4,
		CNREG2_02C5_SHA3_XORDAT5,
		CNREG2_02C6_SHA3_XORDAT6,
		CNREG2_02C7_SHA3_XORDAT7,
		CNREG2_02C8_SHA3_XORDAT8,
		CNREG2_02C9_SHA3_XORDAT9,
		CNREG2_02CA_SHA3_XORDAT10,
		CNREG2_02CB_SHA3_XORDAT11,
		CNREG2_02CC_SHA3_XORDAT12,
		CNREG2_02CD_SHA3_XORDAT13,
		CNREG2_02CE_SHA3_XORDAT14,
		CNREG2_02CF_SHA3_XORDAT15,
		CNREG2_02D0_SHA3_XORDAT16,
		CNREG2_02D1_SHA3_XORDAT17,

		CNREG2_0400_LLM_READ_ADDR0,
		CNREG2_0401_LLM_WRITE_ADDR_INTERNAL0,
		CNREG2_0402_LLM_DATA0,
		CNREG2_0404_LLM_READ64_ADDR0,
		CNREG2_0405_LLM_WRITE64_ADDR_INTERNAL0,
		CNREG2_0408_LLM_READ_ADDR1,
		CNREG2_0409_LLM_WRITE_ADDR_INTERNAL1,
		CNREG2_040a_LLM_DATA1,
		CNREG2_040c_LLM_READ64_ADDR1,
		CNREG2_040d_LLM_WRITE64_ADDR_INTERNAL1,

		CNREG2_1202_CRC_LEN,
		CNREG2_1207_CRC_DWORD,
		CNREG2_1208_CRC_VAR,
		CNREG2_1217_CRC_DWORD_REFLECT,
		CNREG2_1218_CRC_VAR_REFLECT,

		CNREG2_3109_AES_ENC_CBC1,
		CNREG2_310B_AES_ENC1,
		CNREG2_310D_AES_DEC_CBC1,
		CNREG2_310F_AES_DEC1,

		CNREG2_3114_CAMELLIA_ROUND,

		CNREG2_3119_SMS4_ENC_CBC1,
		CNREG2_311B_SMS4_ENC1,
		CNREG2_311D_SMS4_DEC_CBC1,
		CNREG2_311F_SMS4_DEC1,

		CNREG2_4052_SHA3_STARTOP,
		CNREG2_4047_HSH_STARTMD5,
		CNREG2_404D_SNOW3G_START,
		CNREG2_4055_ZUC_START,
		CNREG2_4056_ZUC_MORE,
		CNREG2_405D_GFM_XORMUL1_REFLECT,
		CNREG2_404E_SNOW3G_MORE,
		CNREG2_404F_HSH_STARTSHA256,
		CNREG2_4057_HSH_STARTSHA,
		CNREG2_4088_3DES_ENC_CBC,
		CNREG2_4089_KAS_ENC_CBC,
		CNREG2_408A_3DES_ENC,
		CNREG2_408B_KAS_ENC,
		CNREG2_408C_3DES_DEC_CBC,
		CNREG2_408E_3DES_DEC,

		CNREG2_4200_CRC_POLYNOMIAL_WR,
		CNREG2_4210_CRC_POLYNOMIAL_REFLECT,

		CNREG2_424F_HSH_STARTSHA512,
		CNREG2_425D_GFM_XORMUL1,

		// Last valid register
		END_REG
	};

	enum Flag {
		FPCCREG_FCC0,
		FPCCREG_FCC1,
		FPCCREG_FCC2,
		FPCCREG_FCC3,
		FPCCREG_FCC4,
		FPCCREG_FCC5,
		FPCCREG_FCC6,
		FPCCREG_FCC7,
		END_FLAG
	};

	enum OperandClass {
		NONE = 0,
		REG,
		FLAG,
		IMM,
		LABEL,
		MEM_IMM,
		MEM_REG,
		HINT
	};

	enum Hint {
		LOAD,
		STORE,
		UNDEFINED2,
		UNDEFINED3,
		LOAD_STREAMED,
		STORE_STREAMED,
		LOAD_RETAINED,
		STORE_RETAINED,
		HINT_END,
	};

	enum MipsVersion {
		MIPS_1 = 1,
		MIPS_2,
		MIPS_3,
		MIPS_4,
		MIPS_32,
		MIPS_64,
		MIPS_VERSION_END
	};

#ifndef __cplusplus
	typedef enum Operation Operation;
	typedef enum Reg Reg;
	typedef enum Hint Hint;
	typedef enum MipsVersion MipsVersion;
#endif

	struct inst {
		uint32_t func_lo:3;
		uint32_t func_hi:3;
		uint32_t group1:10;
		uint32_t rt_lo:3;
		uint32_t rt_hi:2;
		uint32_t rs_lo:3;
		uint32_t rs_hi:2;
		uint32_t op_lo:3;
		uint32_t op_hi:3;
	};

	struct itype {
		int32_t immediate:16;
		uint32_t rt:5;
		uint32_t rs:5;
		uint32_t opcode:6;
	};
	struct jtype {
		uint32_t immediate:26;
		uint32_t opcode:6;
	};

	struct rtype {
		uint32_t function:6;
		uint32_t sa:5;
		uint32_t rd:5;
		uint32_t rt:5;
		uint32_t rs:5;
		uint32_t opcode:6;
	};

	struct ftype {
		uint32_t fmt:3;
		uint32_t func:3;
		uint32_t fd:5;
		uint32_t fs:5;
		uint32_t ft:5;
		uint32_t fr:5;
		uint32_t opcode:6;
	};

	struct ttype {
		uint32_t function:6;
		uint32_t code:10;
		uint32_t rt:5;
		uint32_t rs:5;
		uint32_t opcode:6;
	};

	struct stype {
		uint32_t function:6;
		uint32_t code:20;
		uint32_t opcode:6;
	};

	union combined {
		struct inst decode;
		struct itype i;
		struct jtype j;
		struct rtype r;
		struct ftype f;
		struct ttype t;
		struct stype s;
		uint32_t value;
		struct {
			uint32_t bit0:1;
			uint32_t bit1:1;
			uint32_t bit2:1;
			uint32_t bit3:1;
			uint32_t bit4:1;
			uint32_t bit5:1;
			uint32_t bit6:1;
			uint32_t bit7:1;
			uint32_t bit8:1;
			uint32_t bit9:1;
			uint32_t bit10:1;
			uint32_t bit11:1;
			uint32_t bit12:1;
			uint32_t bit13:1;
			uint32_t bit14:1;
			uint32_t bit15:1;
			uint32_t bit16:1;
			uint32_t bit17:1;
			uint32_t bit18:1;
			uint32_t bit19:1;
			uint32_t bit20:1;
			uint32_t bit21:1;
			uint32_t bit22:1;
			uint32_t bit23:1;
			uint32_t bit24:1;
			uint32_t bit25:1;
			uint32_t bit26:1;
			uint32_t bit27:1;
			uint32_t bit28:1;
			uint32_t bit29:1;
			uint32_t bit30:1;
			uint32_t bit31:1;
		} bits;
	};

	struct InstructionOperand {
		uint32_t operandClass;
		uint32_t reg;
		uint64_t immediate;
	};

#ifndef __cplusplus
	typedef struct InstructionOperand InstructionOperand;
#endif

	struct Instruction{
		Operation operation;
		InstructionOperand operands[MAX_OPERANDS];
		uint32_t size;
	};

#ifndef __cplusplus
	typedef struct Instruction Instruction;
	typedef struct inst inst;
	typedef struct itype itype;
	typedef struct jtype jtype;
	typedef struct rtype rtype;
	typedef union combined combined;
#endif


#ifdef __cplusplus
	extern "C" {
#endif
		//Given a uint32_t instructionValue decopose the instruction
		//into its components -> instruction
		uint32_t mips_decompose(
				const uint32_t* instructionValue,
				size_t maxSize,
				Instruction* restrict instruction,
				MipsVersion version,
				uint64_t address,
				uint32_t bigEndian,
				uint32_t enablePseudoOps);

		//Get a text representation of the decomposed instruction
		//into outBuffer
		uint32_t mips_disassemble(
				Instruction* restrict instruction,
				char* outBuffer,
				uint32_t outBufferSize);

		const char* get_operation(Operation operation);
		const char* get_register(Reg reg);
		const char* get_flag(enum Flag flag);
		const char* get_hint(Hint hint);
#ifdef __cplusplus
	}
}//end namespace
#endif
