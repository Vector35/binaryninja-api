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
		MIPS_DDIV,
		MIPS_DDIVU,
		MIPS_DERET,
		MIPS_DI,
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
		MIPS_DSLL,
		MIPS_DSLL32,
		MIPS_DSLLV,
		MIPS_DSLV,
		MIPS_DSRA,
		MIPS_DSRA32,
		MIPS_DSRAV,
		MIPS_DSRL,
		MIPS_DSRL32,
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
