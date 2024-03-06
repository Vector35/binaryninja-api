#pragma once

#include "armv7.h"

//*****************************************************************************
// defines, values
//*****************************************************************************

/* architectures */
#define ARCH_ARMv4T 0
#define ARCH_ARMv5T 1
#define ARCH_ARMv6 2
#define ARCH_ARMv7 4
#define ARCH_ARMv7_R 8
#define ARCH_ARMv6T2 16
#define ARCH_ThumbEE 32
#define ARCH_SECURITY_EXTENSIONS 0x40
#define ARCH_ARMv7_WITH_MP 0x80 /* eg: PLDW */
#define ARCH_ADVSIMD 0x100 /* vst, vld, etc. */
#define ARCH_VFPv2 0x200
#define ARCH_VFPv3 0x400

/* decompose statuses */
#define STATUS_OK 0
#define STATUS_NO_BIT_MATCH 1 /* travelled along the graph and hit a
                                    contradiction */
#define STATUS_ARCH_UNSUPPORTED 2 /* an encoding match was found, but is not
                                    supported on the requested architecture */
#define STATUS_UNDEFINED 4 /* */
#define STATUS_BUFFER_TOO_SMALL 8

/* instruction flags */
#define FLAG_NONE 0
#define FLAG_UNPREDICTABLE 1
#define FLAG_NOTPERMITTED 2 /* eg: instruction decodes ok, but not allowed in if-then block */
#define FLAG_ADDRMODE_AMBIGUITY 3

enum SRType { SRType_ERROR=-1, SRType_LSL=0, SRType_LSR, SRType_ASR, SRType_ROR, SRType_RRX };
enum COND { COND_EQ=0, COND_NE, COND_CS, COND_CC, COND_MI, COND_PL, COND_VS,
    COND_VC, COND_HI, COND_LS, COND_GE, COND_LT, COND_GT, COND_LE, COND_AL };

/* is in "if then" block? */
#define IFTHEN_UNKNOWN 0
#define IFTHEN_YES 1
#define IFTHEN_NO 2
#define IFTHENLAST_UNKNOWN 0
#define IFTHENLAST_YES 1
#define IFTHENLAST_NO 2

/* instruction sets */
#define INSTRSET_THUMB 0 /* 16-bit thumb instructions only (introduced in ARMv4T) */
#define INSTRSET_THUMB2 1 /* 16-bit and 32-bit instructions (introduced in ARMv6T2) */
#define INSTRSET_THUMBEE 2 /* defined in ARMv7 */

/* addressing modes */
/* these index the instruction format strings */
#define ADDRMODE_OFFSET 0 /* eaddr = base reg + offset, base reg unchanged, like [<Rn>,<offset>] */
#define ADDRMODE_PREINDEX 1 /* eaddr = base reg + offset, base reg CHANGED, like [<Rn>,<offset>]! */
#define ADDRMODE_POSTINDEX 2 /* eaddr = base reg, base reg CHANGED, like [<Rn>], <offset> */
#define ADDRMODE_UNINDEXED 3 /* eaddr = base reg */
#define ADDRMODE_ADVSIMD_0 0
#define ADDRMODE_ADVSIMD_1 1
#define ADDRMODE_ADVSIMD_2 2
#define ADDRMODE_UNSPECIFIED 255

#define IS_FIELD_PRESENT(s, elem) (!!((s)->fields_mask[(elem) >> 6] & (1LL << ((elem) & 63))))

#define MAX_FORMAT_OPERANDS 8

/* these append some specifier text on the opcode */
#define INSTR_FORMAT_FLAG_CONDITIONAL 1
#define INSTR_FORMAT_FLAG_OPTIONAL_STATUS 2
#define INSTR_FORMAT_FLAG_EFFECT 4
#define INSTR_FORMAT_FLAG_MASK 8
#define INSTR_FORMAT_FLAG_WIDE 0x10
#define INSTR_FORMAT_FLAG_INCREMENT_AFTER 0x20
#define INSTR_FORMAT_FLAG_AMODE 0x40
#define INSTR_FORMAT_FLAG_NEON_SIZE 0x80
#define INSTR_FORMAT_FLAG_VFP_DATA_SIZE 0x100
#define INSTR_FORMAT_FLAG_NEON_TYPE_SIZE 0x200
#define INSTR_FORMAT_FLAG_NEON_SINGLE_SIZE 0x400
#define INSTR_FORMAT_FLAG_F16 0x800
#define INSTR_FORMAT_FLAG_F32 0x1000
#define INSTR_FORMAT_FLAG_F64 0x2000

#define VFP_DATA_SIZE_S8 0
#define VFP_DATA_SIZE_S16 1
#define VFP_DATA_SIZE_S32 2
#define VFP_DATA_SIZE_S64 3

#define VFP_DATA_SIZE_F32 3 
#define VFP_DATA_SIZE_F64 4

#define VFP_DATA_SIZE_U8 4
#define VFP_DATA_SIZE_U16 5
#define VFP_DATA_SIZE_U32 6
#define VFP_DATA_SIZE_U64 7

#define VFP_DATA_SIZE_I8 0
#define VFP_DATA_SIZE_I16 1
#define VFP_DATA_SIZE_I32 2
#define VFP_DATA_SIZE_I64 3
#define VFP_DATA_SIZE_I_F32 4

#define VFP_DATA_SIZE_F32S32 0
#define VFP_DATA_SIZE_F32U32 1
#define VFP_DATA_SIZE_S32F32 2
#define VFP_DATA_SIZE_U32F32 3

#define VFP_DATA_SIZE_32 8

//*****************************************************************************
// structs and types
//*****************************************************************************

enum instruction_operand_format_type
{
    OPERAND_FORMAT_END,
    OPERAND_FORMAT_MEMORY_ONE_REG,
    OPERAND_FORMAT_MEMORY_ONE_REG_IMM,
    OPERAND_FORMAT_MEMORY_ONE_REG_NEG_IMM,
    OPERAND_FORMAT_MEMORY_ONE_REG_ADD_IMM,
    OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM,
    OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_ADD_IMM,
    OPERAND_FORMAT_MEMORY_ONE_REG_ALIGNED,
    OPERAND_FORMAT_MEMORY_TWO_REG,
    OPERAND_FORMAT_MEMORY_TWO_REG_SHIFT,
    OPERAND_FORMAT_MEMORY_TWO_REG_LSL_ONE,
    OPERAND_FORMAT_MEMORY_SP_IMM,
    OPERAND_FORMAT_MEMORY_SP_OPTIONAL_IMM,
    OPERAND_FORMAT_MEMORY_PC,
    OPERAND_FORMAT_FPSCR,
    OPERAND_FORMAT_IMM,
    OPERAND_FORMAT_IMM64,
    OPERAND_FORMAT_OPTIONAL_IMM,
    OPERAND_FORMAT_ADD_IMM,
    OPERAND_FORMAT_OPTIONAL_ADD_IMM,
    OPERAND_FORMAT_ZERO,
    OPERAND_FORMAT_REG,
    OPERAND_FORMAT_REG_FP, /* s0..s32, d0..d31, q0..q15 */
    OPERAND_FORMAT_REG_INDEX,
    OPERAND_FORMAT_SP,
    OPERAND_FORMAT_PC,
    OPERAND_FORMAT_LR,
    OPERAND_FORMAT_COPROC,
    OPERAND_FORMAT_COPROC_REG,
    OPERAND_FORMAT_SINGLE_REGISTERS,
    OPERAND_FORMAT_REGISTERS,
    OPERAND_FORMAT_REGISTERS_INDEXED,
    OPERAND_FORMAT_LIST,
    OPERAND_FORMAT_ENDIAN,
    OPERAND_FORMAT_SHIFT,
    OPERAND_FORMAT_IFLAGS,
    OPERAND_FORMAT_FIRSTCOND,
    OPERAND_FORMAT_LABEL,
    OPERAND_FORMAT_SPEC_REG,
    OPERAND_FORMAT_NEON_SIZE,
    OPERAND_FORMAT_BARRIER_OPTION,
    OPERAND_FORMAT_RT_MRC,
    OPERAND_FORMAT_ROTATION
};

enum instruction_operand_writeback
{
    WRITEBACK_NO,
    WRITEBACK_YES,
    WRITEBACK_OPTIONAL
};

/* "inspired" from capstone */
enum instruction_group
{
    INSN_GROUP_UNKNOWN = 0, /* so memset() will initialize to this default */
    INSN_GROUP_JUMP,
    INSN_GROUP_CRYPTO,
    INSN_GROUP_DATABARRIER,
    INSN_GROUP_DIVIDE,
    INSN_GROUP_FPARMV8,
    INSN_GROUP_MULTPRO,
    INSN_GROUP_NEON,
    INSN_GROUP_T2EXTRACTPACK,
    INSN_GROUP_THUMB2DSP,
    INSN_GROUP_TRUSTZONE,
    INSN_GROUP_V4T,
    INSN_GROUP_V5T,
    INSN_GROUP_V5TE,
    INSN_GROUP_V6,
    INSN_GROUP_V6T2,
    INSN_GROUP_V7,
    INSN_GROUP_V8,
    INSN_GROUP_VFP2,
    INSN_GROUP_VFP3,
    INSN_GROUP_VFP4,
    INSN_GROUP_ARM,
    INSN_GROUP_MCLASS,
    INSN_GROUP_NOTMCLASS,
    INSN_GROUP_THUMB,
    INSN_GROUP_THUMB1ONLY,
    INSN_GROUP_THUMB2,
    INSN_GROUP_PREV8,
    INSN_GROUP_FPVMLX,
    INSN_GROUP_MULOPS,
    INSN_GROUP_CRC,
    INSN_GROUP_DPVFP,
    INSN_GROUP_V6M,
};

/* the decomp->text function GetInstructionText will process these and in
    general emit:

    1) TEXT token    for prefix (if it exists)
    2) ???? token(s) (depending on type)
    3) TEXT token    for suffix (if it exists)
*/
struct instruction_operand_format
{
    /* what type of operand format is this?
        eg: OPERAND_FORMAT_REG, OPERAND_FORMAT_REGISTERS, etc. */
    instruction_operand_format_type type;

    /* each operand can refer to up to 2 fields */
    enum decomp_field field0, field1;

    /* text that's prepended and appended, eg "#" or "{","}" */
    const char *prefix, *suffix;

    /* where or not there's writeback (usually indicated by '!' in format) */
    instruction_operand_writeback writeback;
};

struct instruction_format
{
    const char* operation;
    uint32_t operationFlags;
    instruction_operand_format operands[MAX_FORMAT_OPERANDS];
    size_t operandCount;
};

struct decomp_request
{
    uint16_t instr_word16;
    uint32_t instr_word32;

    /* architecture, like ARCH_ARMv4T */
    uint8_t arch;
    /* instruction set */
    uint8_t instrSet;

    /* in if-then block? is last? */
    uint8_t inIfThen;
    uint8_t inIfThenLast;

    /* disassembly of some instructions affected by APSR.C */
    uint8_t carry_in;

    uint32_t addr;
};

struct decomp_result
{
    /* the result of the decomposition eg: STATUS_OK */
    uint8_t status;

    /* extra flags to decorate instruction eg: FLAG_UNPREDICTABLE */
    uint32_t flags;

    /* addressing mode of mem access instructions */
    uint8_t addrMode;

    /* instruction group */
    uint8_t group;

    /* instruction size in bits: 16 or 32 */
    uint8_t instrSize;

    /* values of the fields */
    uint32_t fields[FIELD_MAX];
    /* bit set if field present */
    uint64_t fields_mask[(FIELD_MAX + 63) / 64];

    const instruction_format* formats;
    size_t formatCount;

    const instruction_format* format;
    armv7::Operation mnem;

    uint32_t pc;
};

//*****************************************************************************
// function prototypes
//*****************************************************************************

extern int thumb_decompose(struct decomp_request *, struct decomp_result *result);
extern const char* get_thumb_condition_name(uint32_t cond);
extern bool thumb_has_writeback(struct decomp_result* result);
extern std::string get_thumb_operation_name(struct decomp_result* result);
extern int get_reg_name(int reg_idx, char *reg_name);

