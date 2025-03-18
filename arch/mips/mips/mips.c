#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include "mips.h"

#ifdef __cplusplus
using namespace mips;
#define restrict __restrict
#endif

#define REG_ reg
#define FLAG_ reg
#define FPREG_ reg
#define FPCCREG_ reg
#define CPREG_ reg
#define IMM_ immediate
#define LABEL_ immediate

#define VAR(a) a ## _
#define INS_1(A,a)\
	do { \
	instruction->operands[0].operandClass = A;\
	instruction->operands[0].VAR(A) = a;\
	} while (0);

#define INS_2(A,a,B,b)\
	do { \
	instruction->operands[0].operandClass = A;\
	instruction->operands[0].VAR(A) = a;\
	instruction->operands[1].operandClass = B;\
	instruction->operands[1].VAR(B) = b;\
	} while (0);

#define INS_3(A,a,B,b,C,c)\
	do { \
	instruction->operands[0].operandClass = A;\
	instruction->operands[0].VAR(A) = a;\
	instruction->operands[1].operandClass = B;\
	instruction->operands[1].VAR(B) = b;\
	instruction->operands[2].operandClass = C;\
	instruction->operands[2].VAR(C) = c;\
	} while (0);

#define INS_4(A,a,B,b,C,c,D,d)\
	do { \
	instruction->operands[0].operandClass = A;\
	instruction->operands[0].VAR(A) = a;\
	instruction->operands[1].operandClass = B;\
	instruction->operands[1].VAR(B) = b;\
	instruction->operands[2].operandClass = C;\
	instruction->operands[2].VAR(C) = c;\
	instruction->operands[3].operandClass = D;\
	instruction->operands[3].VAR(D) = d;\
	} while (0);


static Operation cavium_mips_base_table[8][8] = {
	{MIPS_INVALID, MIPS_INVALID, MIPS_J,       MIPS_JAL,     MIPS_BEQ,     MIPS_BNE,  MIPS_BLEZ,      MIPS_BGTZ},
	{MIPS_ADDI,    MIPS_ADDIU,   MIPS_SLTI,    MIPS_SLTIU,   MIPS_ANDI,    MIPS_ORI,  MIPS_XORI,      MIPS_LUI},
	{MIPS_COP0,    MIPS_COP1,    MIPS_COP2,    MIPS_COP1X,   MIPS_BEQL,    MIPS_BNEL, MIPS_BLEZL,     MIPS_BGTZL},
	{MIPS_DADDI,   MIPS_DADDIU,  MIPS_LDL,     MIPS_LDR,     MIPS_INVALID, MIPS_JALX, MIPS_INVALID,   MIPS_INVALID},
	{MIPS_LB,      MIPS_LH,      MIPS_LWL,     MIPS_LW,      MIPS_LBU,     MIPS_LHU,  MIPS_LWR,       MIPS_LWU},
	{MIPS_SB,      MIPS_SH,      MIPS_SWL,     MIPS_SW,      MIPS_SDL,     MIPS_SDR,  MIPS_SWR,       MIPS_CACHE},
	{MIPS_LL,      MIPS_LWC1,    CNMIPS_BBIT0, MIPS_PREF,    MIPS_LLD,     MIPS_LDC1, CNMIPS_BBIT032, MIPS_LD},
	{MIPS_SC,      MIPS_SWC1,    CNMIPS_BBIT1, MIPS_INVALID, MIPS_SCD,     MIPS_SDC1, CNMIPS_BBIT132, MIPS_SD}
};

//Fields are: [Version][opcode_high][opcode_low]
static Operation mips_base_table[6][8][8] = {
	{	//MIPS version 1
		{MIPS_INVALID, MIPS_INVALID, MIPS_J,    MIPS_JAL,     MIPS_BEQ,     MIPS_BNE,     MIPS_BLEZ,    MIPS_BGTZ},
		{MIPS_ADDI,    MIPS_ADDIU,   MIPS_SLTI, MIPS_SLTIU,   MIPS_ANDI,    MIPS_ORI,     MIPS_XORI,    MIPS_LUI},
		{MIPS_COP0,    MIPS_COP1,    MIPS_COP2, MIPS_COP3,    MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_LLO,     MIPS_LHI,     MIPS_TRAP, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_LB,      MIPS_LH,      MIPS_LWL,  MIPS_LW,      MIPS_LBU,     MIPS_LHU,     MIPS_LWR,     MIPS_INVALID},
		{MIPS_SB,      MIPS_SH,      MIPS_SWL,  MIPS_SW,      MIPS_INVALID, MIPS_INVALID, MIPS_SWR,     MIPS_INVALID},
		{MIPS_INVALID, MIPS_LWC1,    MIPS_LWC2, MIPS_LWC3,    MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_INVALID, MIPS_SWC1,    MIPS_SWC2, MIPS_SWC3,    MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID}
	},{ //MIPS version 2
		{MIPS_INVALID, MIPS_INVALID, MIPS_J,       MIPS_JAL,     MIPS_BEQ,     MIPS_BNE,     MIPS_BLEZ,    MIPS_BGTZ},
		{MIPS_ADDI,    MIPS_ADDIU,   MIPS_SLTI,    MIPS_SLTIU,   MIPS_ANDI,    MIPS_ORI,     MIPS_XORI,    MIPS_LUI},
		{MIPS_COP0,    MIPS_COP1,    MIPS_COP2,    MIPS_COP3,    MIPS_BEQL,    MIPS_BNEL,    MIPS_BLEZL,   MIPS_BGTZL},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_LB,      MIPS_LH,      MIPS_LWL,     MIPS_LW,      MIPS_LBU,     MIPS_LHU,     MIPS_LWR,     MIPS_INVALID},
		{MIPS_SB,      MIPS_SH,      MIPS_SWL,     MIPS_SW,      MIPS_INVALID, MIPS_INVALID, MIPS_SWR,     MIPS_INVALID},
		{MIPS_LL,      MIPS_LWC1,    MIPS_LWC2,    MIPS_LWC3,    MIPS_INVALID, MIPS_LDC1,    MIPS_LDC2,    MIPS_LDC3},
		{MIPS_SC,      MIPS_SWC1,    MIPS_SWC2,    MIPS_SWC3,    MIPS_INVALID, MIPS_SDC1,    MIPS_SDC2,    MIPS_SDC3}
	},{ //MIPS version 3
		{MIPS_INVALID, MIPS_INVALID, MIPS_J,    MIPS_JAL,     MIPS_BEQ,     MIPS_BNE,     MIPS_BLEZ,    MIPS_BGTZ},
		{MIPS_ADDI,    MIPS_ADDIU,   MIPS_SLTI, MIPS_SLTIU,   MIPS_ANDI,    MIPS_ORI,     MIPS_XORI,    MIPS_LUI},
		{MIPS_COP0,    MIPS_COP1,    MIPS_COP2, MIPS_INVALID, MIPS_BEQL,    MIPS_BNEL,    MIPS_BLEZL,   MIPS_BGTZL},
		{MIPS_DADDI,   MIPS_DADDIU,  MIPS_LDL,  MIPS_LDR,     MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_LB,      MIPS_LH,      MIPS_LWL,  MIPS_LW,      MIPS_LBU,     MIPS_LHU,     MIPS_LWR,     MIPS_LWU},
		{MIPS_SB,      MIPS_SH,      MIPS_SWL,  MIPS_SW,      MIPS_SDL,     MIPS_SDR,     MIPS_SWR,     MIPS_INVALID},
		{MIPS_LL,      MIPS_LWC1,    MIPS_LWC2, MIPS_INVALID, MIPS_LLD,     MIPS_LDC1,    MIPS_LDC2,    MIPS_LD},
		{MIPS_SC,      MIPS_SWC1,    MIPS_SWC2, MIPS_INVALID, MIPS_SCD,     MIPS_SDC1,    MIPS_SDC2,    MIPS_SD}
	},{ //MIPS version 4
		{MIPS_INVALID, MIPS_INVALID, MIPS_J,    MIPS_JAL,     MIPS_BEQ,     MIPS_BNE,     MIPS_BLEZ,    MIPS_BGTZ},
		{MIPS_ADDI,    MIPS_ADDIU,   MIPS_SLTI, MIPS_SLTIU,   MIPS_ANDI,    MIPS_ORI,     MIPS_XORI,    MIPS_LUI},
		{MIPS_COP0,    MIPS_COP1,    MIPS_COP2, MIPS_COP1X,   MIPS_BEQL,    MIPS_BNEL,    MIPS_BLEZL,   MIPS_BGTZL},
		{MIPS_DADDI,   MIPS_DADDIU,  MIPS_LDL,  MIPS_LDR,     MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_LB,      MIPS_LH,      MIPS_LWL,  MIPS_LW,      MIPS_LBU,     MIPS_LHU,     MIPS_LWR,     MIPS_LWU},
		{MIPS_SB,      MIPS_SH,      MIPS_SWL,  MIPS_SW,      MIPS_SDL,     MIPS_SDR,     MIPS_SWR,     MIPS_INVALID},
		{MIPS_INVALID, MIPS_LWC1,    MIPS_LWC2, MIPS_PREF,    MIPS_LLD,     MIPS_LDC1,    MIPS_LDC2,    MIPS_LD},
		{MIPS_INVALID, MIPS_SWC1,    MIPS_SWC2, MIPS_INVALID, MIPS_SCD,     MIPS_SDC1,    MIPS_SDC2,    MIPS_SD}
	},{ //MIPS version 5 (MIPS32)
		{MIPS_INVALID, MIPS_INVALID, MIPS_J,       MIPS_JAL,     MIPS_BEQ,     MIPS_BNE,  MIPS_BLEZ,    MIPS_BGTZ},
		{MIPS_ADDI,    MIPS_ADDIU,   MIPS_SLTI,    MIPS_SLTIU,   MIPS_ANDI,    MIPS_ORI,  MIPS_XORI,    MIPS_LUI},
		{MIPS_COP0,    MIPS_COP1,    MIPS_COP2,    MIPS_COP1X,   MIPS_BEQL,    MIPS_BNEL, MIPS_BLEZL,   MIPS_BGTZL},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_JALX, MIPS_INVALID, MIPS_INVALID},
		{MIPS_LB,      MIPS_LH,      MIPS_LWL,     MIPS_LW,      MIPS_LBU,     MIPS_LHU,  MIPS_LWR,     MIPS_LWU},
		{MIPS_SB,      MIPS_SH,      MIPS_SWL,     MIPS_SW,      MIPS_SDL,     MIPS_SDR,  MIPS_SWR,     MIPS_CACHE},
		{MIPS_LL,      MIPS_LWC1,    MIPS_LWC2,    MIPS_PREF,    MIPS_LLD,     MIPS_LDC1, MIPS_LDC2,    MIPS_LD},
		{MIPS_SC,      MIPS_SWC1,    MIPS_SWC2,    MIPS_INVALID, MIPS_SCD,     MIPS_SDC1, MIPS_SDC2,    MIPS_SD}
	},{ //MIPS version 6 (MIPS64)
		{MIPS_INVALID, MIPS_INVALID, MIPS_J,    MIPS_JAL,     MIPS_BEQ,     MIPS_BNE,  MIPS_BLEZ,    MIPS_BGTZ},
		{MIPS_ADDI,    MIPS_ADDIU,   MIPS_SLTI, MIPS_SLTIU,   MIPS_ANDI,    MIPS_ORI,  MIPS_XORI,    MIPS_LUI},
		{MIPS_COP0,    MIPS_COP1,    MIPS_COP2, MIPS_COP1X,   MIPS_BEQL,    MIPS_BNEL, MIPS_BLEZL,   MIPS_BGTZL},
		{MIPS_DADDI,   MIPS_DADDIU,  MIPS_LDL,  MIPS_LDR,     MIPS_INVALID, MIPS_JALX, MIPS_INVALID, MIPS_INVALID},
		{MIPS_LB,      MIPS_LH,      MIPS_LWL,  MIPS_LW,      MIPS_LBU,     MIPS_LHU,  MIPS_LWR,     MIPS_LWU},
		{MIPS_SB,      MIPS_SH,      MIPS_SWL,  MIPS_SW,      MIPS_SDL,     MIPS_SDR,  MIPS_SWR,     MIPS_CACHE},
		{MIPS_LL,      MIPS_LWC1,    MIPS_LWC2, MIPS_PREF,    MIPS_LLD,     MIPS_LDC1, MIPS_LDC2,    MIPS_LD},
		{MIPS_SC,      MIPS_SWC1,    MIPS_SWC2, MIPS_INVALID, MIPS_SCD,     MIPS_SDC1, MIPS_SDC2,    MIPS_SD}
	}
};

//Fields are: [Version][function_high][function_low]
static Operation mips_special_table[6][8][8] = {
	{	//MIPS version 1
		{MIPS_SLL,     MIPS_INVALID, MIPS_SRL,     MIPS_SRA,     MIPS_SLLV,    MIPS_INVALID, MIPS_SRLV,    MIPS_SRAV},
		{MIPS_JR,      MIPS_JALR,    MIPS_INVALID, MIPS_INVALID, MIPS_SYSCALL, MIPS_BREAK,   MIPS_INVALID, MIPS_INVALID},
		{MIPS_MFHI,    MIPS_MTHI,    MIPS_MFLO,    MIPS_MTLO,    MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_MULT,    MIPS_MULTU,   MIPS_DIV,     MIPS_DIVU,    MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_ADD,     MIPS_ADDU,    MIPS_SUB,     MIPS_SUBU,    MIPS_AND,     MIPS_OR,      MIPS_XOR,     MIPS_NOR},
		{MIPS_INVALID, MIPS_INVALID, MIPS_SLT,     MIPS_SLTU,    MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID}
	},{	//MIPS version 2
		{MIPS_SLL,     MIPS_INVALID, MIPS_SRL,     MIPS_SRA,     MIPS_SLLV,    MIPS_INVALID, MIPS_SRLV,    MIPS_SRAV},
		{MIPS_JR,      MIPS_JALR,    MIPS_INVALID, MIPS_INVALID, MIPS_SYSCALL, MIPS_BREAK,   MIPS_INVALID, MIPS_SYNC},
		{MIPS_MFHI,    MIPS_MTHI,    MIPS_MFLO,    MIPS_MTLO,    MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_MULT,    MIPS_MULTU,   MIPS_DIV,     MIPS_DIVU,    MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_ADD,     MIPS_ADDU,    MIPS_SUB,     MIPS_SUBU,    MIPS_AND,     MIPS_OR,      MIPS_XOR,     MIPS_NOR},
		{MIPS_INVALID, MIPS_INVALID, MIPS_SLT,     MIPS_SLTU,    MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_TGE,     MIPS_TGEU,    MIPS_TLT,     MIPS_TLTU,    MIPS_TEQ,     MIPS_INVALID, MIPS_TNE,     MIPS_INVALID},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID}
	},{	//MIPS version 3
		{MIPS_SLL,     MIPS_INVALID, MIPS_SRL,     MIPS_SRA,     MIPS_SLLV,    MIPS_INVALID, MIPS_SRLV,    MIPS_SRAV},
		{MIPS_JR,      MIPS_JALR,    MIPS_INVALID, MIPS_INVALID, MIPS_SYSCALL, MIPS_BREAK,   MIPS_INVALID, MIPS_SYNC},
		{MIPS_MFHI,    MIPS_MTHI,    MIPS_MFLO,    MIPS_MTLO,    MIPS_DSLLV,   MIPS_INVALID, MIPS_DSRLV,   MIPS_DSRAV},
		{MIPS_MULT,    MIPS_MULTU,   MIPS_DIV,     MIPS_DIVU,    MIPS_DMULT,   MIPS_DMULTU,  MIPS_DDIV,    MIPS_DDIVU},
		{MIPS_ADD,     MIPS_ADDU,    MIPS_SUB,     MIPS_SUBU,    MIPS_AND,     MIPS_OR,      MIPS_XOR,     MIPS_NOR},
		{MIPS_INVALID, MIPS_INVALID, MIPS_SLT,     MIPS_SLTU,    MIPS_DADD,    MIPS_DADDU,   MIPS_DSUB,    MIPS_DSUBU},
		{MIPS_TGE,     MIPS_TGEU,    MIPS_TLT,     MIPS_TLTU,    MIPS_TEQ,     MIPS_INVALID, MIPS_TNE,     MIPS_INVALID},
		{MIPS_DSLL,    MIPS_INVALID, MIPS_DSRL,    MIPS_DSRA,    MIPS_DSLL32,  MIPS_INVALID, MIPS_DSRL32,  MIPS_DSRA32}
	},{	//MIPS version 4
		{MIPS_SLL,     MIPS_MOVCI,   MIPS_SRL,  MIPS_SRA,  MIPS_SLLV,    MIPS_INVALID, MIPS_SRLV,    MIPS_SRAV},
		{MIPS_JR,      MIPS_JALR,    MIPS_MOVZ, MIPS_MOVN, MIPS_SYSCALL, MIPS_BREAK,   MIPS_INVALID, MIPS_SYNC},
		{MIPS_MFHI,    MIPS_MTHI,    MIPS_MFLO, MIPS_MTLO, MIPS_DSLLV,   MIPS_INVALID, MIPS_DSRLV,   MIPS_DSRAV},
		{MIPS_MULT,    MIPS_MULTU,   MIPS_DIV,  MIPS_DIVU, MIPS_DMULT,   MIPS_DMULTU,  MIPS_DDIV,    MIPS_DDIVU},
		{MIPS_ADD,     MIPS_ADDU,    MIPS_SUB,  MIPS_SUBU, MIPS_AND,     MIPS_OR,      MIPS_XOR,     MIPS_NOR},
		{MIPS_INVALID, MIPS_INVALID, MIPS_SLT,  MIPS_SLTU, MIPS_DADD,    MIPS_DADDU,   MIPS_DSUB,    MIPS_DSUBU},
		{MIPS_TGE,     MIPS_TGEU,    MIPS_TLT,  MIPS_TLTU, MIPS_TEQ,     MIPS_INVALID, MIPS_TNE,     MIPS_INVALID},
		{MIPS_DSLL,    MIPS_INVALID, MIPS_DSRL, MIPS_DSRA, MIPS_DSLL32,  MIPS_INVALID, MIPS_DSRL32,  MIPS_DSRA32}
	},{	//MIPS version 5
		{MIPS_SLL,     MIPS_MOVCI,   MIPS_SRL,  MIPS_SRA,  MIPS_SLLV,    MIPS_INVALID, MIPS_SRLV,    MIPS_SRAV},
		{MIPS_JR,      MIPS_JALR,    MIPS_MOVZ, MIPS_MOVN, MIPS_SYSCALL, MIPS_BREAK,   MIPS_INVALID, MIPS_SYNC},
		{MIPS_MFHI,    MIPS_MTHI,    MIPS_MFLO, MIPS_MTLO, MIPS_DSLLV,   MIPS_INVALID, MIPS_DSRLV,   MIPS_DSRAV},
		{MIPS_MULT,    MIPS_MULTU,   MIPS_DIV,  MIPS_DIVU, MIPS_DMULT,   MIPS_DMULTU,  MIPS_DDIV,    MIPS_DDIVU},
		{MIPS_ADD,     MIPS_ADDU,    MIPS_SUB,  MIPS_SUBU, MIPS_AND,     MIPS_OR,      MIPS_XOR,     MIPS_NOR},
		{MIPS_INVALID, MIPS_INVALID, MIPS_SLT,  MIPS_SLTU, MIPS_DADD,    MIPS_DADDU,   MIPS_DSUB,    MIPS_DSUBU},
		{MIPS_TGE,     MIPS_TGEU,    MIPS_TLT,  MIPS_TLTU, MIPS_TEQ,     MIPS_INVALID, MIPS_TNE,     MIPS_INVALID},
		{MIPS_DSLL,    MIPS_INVALID, MIPS_DSRL, MIPS_DSRA, MIPS_DSLL32,  MIPS_INVALID, MIPS_DSRL32,  MIPS_DSRA32}
	},{	//MIPS version 6
		{MIPS_SLL,     MIPS_MOVCI,   MIPS_SRL,  MIPS_SRA,  MIPS_SLLV,    MIPS_INVALID, MIPS_SRLV,    MIPS_SRAV},
		{MIPS_JR,      MIPS_JALR,    MIPS_MOVZ, MIPS_MOVN, MIPS_SYSCALL, MIPS_BREAK,   MIPS_INVALID, MIPS_SYNC},
		{MIPS_MFHI,    MIPS_MTHI,    MIPS_MFLO, MIPS_MTLO, MIPS_DSLLV,   MIPS_INVALID, MIPS_DSRLV,   MIPS_DSRAV},
		{MIPS_MULT,    MIPS_MULTU,   MIPS_DIV,  MIPS_DIVU, MIPS_DMULT,   MIPS_DMULTU,  MIPS_DDIV,    MIPS_DDIVU},
		{MIPS_ADD,     MIPS_ADDU,    MIPS_SUB,  MIPS_SUBU, MIPS_AND,     MIPS_OR,      MIPS_XOR,     MIPS_NOR},
		{MIPS_INVALID, MIPS_INVALID, MIPS_SLT,  MIPS_SLTU, MIPS_DADD,    MIPS_DADDU,   MIPS_DSUB,    MIPS_DSUBU},
		{MIPS_TGE,     MIPS_TGEU,    MIPS_TLT,  MIPS_TLTU, MIPS_TEQ,     MIPS_INVALID, MIPS_TNE,     MIPS_INVALID},
		{MIPS_DSLL,    MIPS_INVALID, MIPS_DSRL, MIPS_DSRA, MIPS_DSLL32,  MIPS_INVALID, MIPS_DSRL32,  MIPS_DSRA32}
	}
};

static Operation mips_regimm_table[6][4][8] = {
	{	//MIPS version 1
		{MIPS_BLTZ,    MIPS_BGEZ,    MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_BLTZAL,  MIPS_BGEZAL,  MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	},{	//MIPS version 2
		{MIPS_BLTZ,    MIPS_BGEZ,    MIPS_BLTZL,   MIPS_BGEZL,   MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_TGEI,    MIPS_TGEIU,   MIPS_TLTI,    MIPS_TLTIU,   MIPS_TEQI,    MIPS_INVALID, MIPS_TNEI,    MIPS_INVALID},
		{MIPS_BLTZAL,  MIPS_BGEZAL,  MIPS_BLTZALL, MIPS_BGEZALL, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	},{	//MIPS version 3
		{MIPS_BLTZ,    MIPS_BGEZ,    MIPS_BLTZL,   MIPS_BGEZL,   MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_TGEI,    MIPS_TGEIU,   MIPS_TLTI,    MIPS_TLTIU,   MIPS_TEQI,    MIPS_INVALID, MIPS_TNEI,    MIPS_INVALID},
		{MIPS_BLTZAL,  MIPS_BGEZAL,  MIPS_BLTZALL, MIPS_BGEZALL, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	},{	//MIPS version 4
		{MIPS_BLTZ,    MIPS_BGEZ,    MIPS_BLTZL,   MIPS_BGEZL,   MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_TGEI,    MIPS_TGEIU,   MIPS_TLTI,    MIPS_TLTIU,   MIPS_TEQI,    MIPS_INVALID, MIPS_TNEI,    MIPS_INVALID},
		{MIPS_BLTZAL,  MIPS_BGEZAL,  MIPS_BLTZALL, MIPS_BGEZALL, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	},{	//MIPS version 5
		{MIPS_BLTZ,    MIPS_BGEZ,    MIPS_BLTZL,   MIPS_BGEZL,   MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_TGEI,    MIPS_TGEIU,   MIPS_TLTI,    MIPS_TLTIU,   MIPS_TEQI,    MIPS_INVALID, MIPS_TNEI,    MIPS_INVALID},
		{MIPS_BLTZAL,  MIPS_BGEZAL,  MIPS_BLTZALL, MIPS_BGEZALL, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_SYNCI}
	},{	//MIPS version 6
		{MIPS_BLTZ,    MIPS_BGEZ,    MIPS_BLTZL,   MIPS_BGEZL,   MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_TGEI,    MIPS_TGEIU,   MIPS_TLTI,    MIPS_TLTIU,   MIPS_TEQI,    MIPS_INVALID, MIPS_TNEI,    MIPS_INVALID},
		{MIPS_BLTZAL,  MIPS_BGEZAL,  MIPS_BLTZALL, MIPS_BGEZALL, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
		{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_SYNCI}
	}
};

static Operation mips32_special2_table[8][8] = {
	{MIPS_MADD,    MIPS_MADDU,   MIPS_MUL,     MIPS_INVALID, MIPS_MSUB,    MIPS_MSUBU,   MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_CLZ,     MIPS_CLO,     MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_SDBBP}
};

static Operation mips64_special2_table[8][8] = {
	{MIPS_MADD,    MIPS_MADDU,   MIPS_MUL,     MIPS_INVALID, MIPS_MSUB,    MIPS_MSUBU,   MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_CLZ,     MIPS_CLO,     MIPS_INVALID, MIPS_INVALID, MIPS_DCLZ,    MIPS_DCLO,    MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_SDBBP}
};

static Operation cavium_mips64_special2_table[8][8] = {
	{MIPS_MADD,    MIPS_MADDU,    MIPS_MUL,     CNMIPS_DMUL,   MIPS_MSUB,    MIPS_MSUBU,   MIPS_INVALID, MIPS_INVALID},
	{CNMIPS_MTM0,  CNMIPS_MTP0,   CNMIPS_MTP1,  CNMIPS_MTP2,   CNMIPS_MTM1,  CNMIPS_MTM2,  MIPS_INVALID, CNMIPS_VMULU},
	{CNMIPS_VMM0,  CNMIPS_V3MULU, MIPS_INVALID, MIPS_INVALID,  MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{CNMIPS_SAA,   CNMIPS_SAAD,   MIPS_INVALID, MIPS_INVALID,  MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, CNMIPS_CVM},
	{MIPS_CLZ,     MIPS_CLO,      MIPS_INVALID, MIPS_INVALID,  MIPS_DCLZ,    MIPS_DCLO,    MIPS_INVALID, MIPS_INVALID},
	{CNMIPS_BADDU, MIPS_INVALID,  CNMIPS_SEQ,   CNMIPS_SNE,    CNMIPS_POP,   CNMIPS_DPOP,  CNMIPS_SEQI,  CNMIPS_SNEI},
	{MIPS_INVALID, MIPS_INVALID,  CNMIPS_CINS,  CNMIPS_CINS32, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID,  CNMIPS_EXTS,  CNMIPS_EXTS32, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_SDBBP}
};

static Operation mips32_special3_table[8][8] = {
	{MIPS_EXT,     MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INS,     MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_LX,      MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_BSHFL,   MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_RDHWR,   MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
};

static Operation mips64_special3_table[8][8] = {
	{MIPS_EXT,     MIPS_DEXTM,   MIPS_DEXTU,   MIPS_DEXT,    MIPS_INS,     MIPS_DINSM,   MIPS_DINSU,   MIPS_DINS},
	{MIPS_INVALID, MIPS_INVALID, MIPS_LX,      MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_BSHFL,   MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_DBSHFL,  MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_RDHWR,   MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID},
};

static Operation mips_v5_cop1_S_table[8][8] = {
	{MIPS_ADD_S,     MIPS_SUB_S,     MIPS_MUL_S,    MIPS_DIV_S,     MIPS_SQRT_S,    MIPS_ABS_S,     MIPS_MOV_S,    MIPS_NEG_S},
	{MIPS_ROUND_L_S, MIPS_TRUNC_L_S, MIPS_CEIL_L_S, MIPS_FLOOR_L_S, MIPS_ROUND_W_S, MIPS_TRUNC_W_S, MIPS_CEIL_W_S, MIPS_FLOOR_W_S},
	{MIPS_SEL_S,     MIPS_MOVCF,     MIPS_MOVZ_S,   MIPS_MOVN_S,    MIPS_INVALID,   MIPS_RECIP_S,   MIPS_RSQRT_S,  MIPS_INVALID},
	{MIPS_MADDF_S,   MIPS_MSUBF_S,   MIPS_RINT_S,   MIPS_CLASS_S,   MIPS_RECIP2,    MIPS_RECIP1,    MIPS_RSQRT1,   MIPS_RSQRT2},
	{MIPS_INVALID,   MIPS_CVT_D_S,   MIPS_INVALID,  MIPS_INVALID,   MIPS_CVT_W_S,   MIPS_CVT_L_S,   MIPS_CVT_PS_S, MIPS_INVALID},
	{MIPS_INVALID,   MIPS_INVALID,   MIPS_INVALID,  MIPS_INVALID,   MIPS_INVALID,   MIPS_INVALID,   MIPS_INVALID,  MIPS_INVALID},
	{MIPS_C_F_S,     MIPS_C_UN_S,    MIPS_C_EQ_S,   MIPS_C_UEQ_S,   MIPS_C_OLT_S,   MIPS_C_ULT_S,   MIPS_C_OLE_S,  MIPS_C_ULE_S},
	{MIPS_C_SF_S,    MIPS_C_NGLE_S,  MIPS_C_SEQ_S,  MIPS_C_NGL_S,   MIPS_C_LT_S,    MIPS_C_NGE_S,   MIPS_C_LE_S,   MIPS_C_NGT_S}
};
static Operation mips_v5_cop1_D_table[8][8] = {
	{MIPS_ADD_D,     MIPS_SUB_D,     MIPS_MUL_D,    MIPS_DIV_D,     MIPS_SQRT_D,    MIPS_ABS_D,     MIPS_MOV_D,    MIPS_NEG_D},
	{MIPS_ROUND_L_D, MIPS_TRUNC_L_D, MIPS_CEIL_L_D, MIPS_FLOOR_L_D, MIPS_ROUND_W_D, MIPS_TRUNC_W_D, MIPS_CEIL_W_D, MIPS_FLOOR_W_D},
	{MIPS_SEL_D,     MIPS_MOVCF,     MIPS_MOVZ_D,   MIPS_MOVN_D,    MIPS_INVALID,   MIPS_RECIP_S,   MIPS_RSQRT_S,  MIPS_INVALID},
	{MIPS_MADDF_D,   MIPS_MSUBF_D,   MIPS_RINT_D,   MIPS_CLASS_D,   MIPS_RECIP2,    MIPS_RECIP1,    MIPS_RSQRT1,   MIPS_RSQRT2},
	{MIPS_CVT_S_D,   MIPS_INVALID,   MIPS_INVALID,  MIPS_INVALID,   MIPS_CVT_W_D,   MIPS_CVT_L_D,   MIPS_INVALID,  MIPS_INVALID},
	{MIPS_INVALID,   MIPS_INVALID,   MIPS_INVALID,  MIPS_INVALID,   MIPS_INVALID,   MIPS_INVALID,   MIPS_INVALID,  MIPS_INVALID},
	{MIPS_C_F_D,     MIPS_C_UN_D,    MIPS_C_EQ_D,   MIPS_C_UEQ_D,   MIPS_C_OLT_D,   MIPS_C_ULT_D,   MIPS_C_OLE_D,  MIPS_C_ULE_D},
	{MIPS_C_SF_D,    MIPS_C_NGLE_D,  MIPS_C_SEQ_D,  MIPS_C_NGL_D,   MIPS_C_LT_D,    MIPS_C_NGE_D,   MIPS_C_LE_D,   MIPS_C_NGT_D}
};
static Operation mips_v5_cop1_LW_table[8][8] = {
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID,   MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID,   MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID,   MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID,   MIPS_INVALID},
	{MIPS_CVT_S_W, MIPS_CVT_D_W, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_CVT_PS_PW, MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID,   MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID,   MIPS_INVALID}
};

static Operation mips_v5_cop1_PS_table[8][8] = {
	{MIPS_ADD_PS,   MIPS_SUB_PS,    MIPS_MUL_PS,   MIPS_DIV_PS,   MIPS_SQRT_PS,   MIPS_ABS_PS,   MIPS_MOV_PS,   MIPS_NEG_PS},
	{MIPS_INVALID,  MIPS_INVALID,   MIPS_INVALID,  MIPS_INVALID,  MIPS_INVALID,   MIPS_INVALID,  MIPS_INVALID,  MIPS_INVALID},
	{MIPS_INVALID,  MIPS_MOVCF,     MIPS_MOVZ_PS,  MIPS_MOVN_PS,  MIPS_INVALID,   MIPS_INVALID,  MIPS_INVALID,  MIPS_INVALID},
	{MIPS_ADDR,     MIPS_INVALID,   MIPS_MULR,     MIPS_INVALID,  MIPS_RECIP2,    MIPS_RECIP1,   MIPS_RSQRT1,   MIPS_RSQRT2},
	{MIPS_CVT_S_PU, MIPS_INVALID,   MIPS_INVALID,  MIPS_INVALID,  MIPS_CVT_PW_PS, MIPS_INVALID,  MIPS_INVALID,  MIPS_INVALID},
	{MIPS_CVT_S_PL, MIPS_INVALID,   MIPS_INVALID,  MIPS_INVALID,  MIPS_PLL_PS,    MIPS_PLU_PS,   MIPS_PUL_PS,   MIPS_PUU_PS},
	{MIPS_C_F_PS,   MIPS_C_UN_PS,   MIPS_C_EQ_PS,  MIPS_C_UEQ_PS, MIPS_C_OLT_PS,  MIPS_C_ULT_PS, MIPS_C_OLE_PS, MIPS_C_ULE_PS},
	{MIPS_C_SF_PS,  MIPS_C_NGLE_PS, MIPS_C_SEQ_PS, MIPS_C_NGL_PS, MIPS_C_LT_PS,   MIPS_C_NGE_PS, MIPS_C_LE_PS,  MIPS_C_NGT_PS}
};

static Operation mips_v5_cop1x_table[8][8] = {
	{MIPS_LWXC1,   MIPS_LDXC1,   MIPS_INVALID,  MIPS_INVALID, MIPS_INVALID, MIPS_LUXC1,   MIPS_INVALID,  MIPS_INVALID},
	{MIPS_SWXC1,   MIPS_SDXC1,   MIPS_INVALID,  MIPS_INVALID, MIPS_INVALID, MIPS_SUXC1,   MIPS_INVALID,  MIPS_PREFX},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID,  MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_INVALID,  MIPS_INVALID},
	{MIPS_INVALID, MIPS_INVALID, MIPS_INVALID,  MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_ALNV_PS,  MIPS_INVALID},
	{MIPS_MADD_S,  MIPS_MADD_D,  MIPS_INVALID,  MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_MADD_PS,  MIPS_INVALID},
	{MIPS_MSUB_S,  MIPS_MSUB_D,  MIPS_INVALID,  MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_MSUB_PS,  MIPS_INVALID},
	{MIPS_NMADD_S, MIPS_NMADD_D, MIPS_INVALID,  MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_NMADD_PS, MIPS_INVALID},
	{MIPS_NMSUB_S, MIPS_NMSUB_D, MIPS_INVALID,  MIPS_INVALID, MIPS_INVALID, MIPS_INVALID, MIPS_NMSUB_PS, MIPS_INVALID},
};


static const char* const OperationStrings[] = {
		"INVALID",
		"abs.d",
		"abs.ps",
		"abs.s",
		"add.d",
		"add.ps",
		"add.s",
		"add",
		"addi",
		"addiu",
		"addr",
		"addu",
		"align",
		"alnv.ps",
		"and",
		"andi",
		"b",
		"bal",
		"bc1any2",
		"bc1any4",
		"bc1eqz",
		"bc1f",
		"bc1fl",
		"bc1nez",
		"bc1t",
		"bc1tl",
		"bc2eqz",
		"bc2f",
		"bc2fl",
		"bc2nez",
		"bc2t",
		"bc2tl",
		"bcnez",
		"beq",
		"beql",
		"beqz",
		"bgez",
		"bgezal",
		"bgezall",
		"bgezl",
		"bgtz",
		"bgtzl",
		"bitswap",
		"blez",
		"blezl",
		"bltz",
		"bltzal",
		"bltzall",
		"bltzl",
		"bne",
		"bnel",
		"bnez",
		"bnz.b",
		"bnz.d",
		"bnz.h",
		"bnz.w",
		"break",
		"bshfl",
		"bz.b",
		"bz.d",
		"bz.h",
		"bz.w",
		"c.df.d",
		"c.eq.d",
		"c.eq.ps",
		"c.eq.s",
		"c.eq",
		"c.f.d",
		"c.f.ps",
		"c.f.s",
		"c.f",
		"c.le.d",
		"c.le.ps",
		"c.le.s",
		"c.le",
		"c.lt.d",
		"c.lt.ps",
		"c.lt.s",
		"c.lt",
		"c.nge.d",
		"c.nge.ps",
		"c.nge.s",
		"c.nge",
		"c.ngl.d",
		"c.ngl.ps",
		"c.ngl.s",
		"c.ngl",
		"c.ngle.d",
		"c.ngle.ps",
		"c.ngle.s",
		"c.ngle",
		"c.ngt.d",
		"c.ngt.ps",
		"c.ngt.s",
		"c.ngt",
		"c.ole.d",
		"c.ole.ps",
		"c.ole.s",
		"c.ole",
		"c.olt.d",
		"c.olt.ps",
		"c.olt.s",
		"c.olt",
		"c.seq.d",
		"c.seq.ps",
		"c.seq.s",
		"c.seq",
		"c.sf.d",
		"c.sf.ps",
		"c.sf.s",
		"c.sf",
		"c.ueq.d",
		"c.ueq.ps",
		"c.ueq.s",
		"c.ueq",
		"c.ule.d",
		"c.ule.ps",
		"c.ule.s",
		"c.ule",
		"c.ult.d",
		"c.ult.ps",
		"c.ult.s",
		"c.ult",
		"c.un.d",
		"c.un.ps",
		"c.un.s",
		"c.un",
		"c1",
		"c2",
		"cache",
		"ceil.l.d",
		"ceil.l.s",
		"ceil.l",
		"ceil.w.d",
		"ceil.w.s",
		"ceil.w",
		"cfc0",
		"cfc1",
		"cfc2",
		"class.d",
		"class.s",
		"clo",
		"clz",
		"cop0",
		"cop1",
		"cop1x",
		"cop2",
		"cop3",
		"ctc0",
		"ctc1",
		"ctc2",
		"cvt.d.s",
		"cvt.d.w",
		"cvt.l.d",
		"cvt.l.s",
		"cvt.l",
		"cvt.ps.pw",
		"cvt.ps.s",
		"cvt.ps",
		"cvt.pw.ps",
		"cvt.s.d",
		"cvt.s.l",
		"cvt.s.pl",
		"cvt.s.pu",
		"cvt.s.w",
		"cvt.w.d",
		"cvt.w.s",
		"cvt.w",
		"dadd",
		"daddi",
		"daddiu",
		"daddu",
		"dbshfl",
		"dclo",
		"dclz",
		"ddiv",
		"ddivu",
		"deret",
		"dext",
		"dextm",
		"dextu",
		"di",
		"dins",
		"dinsm",
		"dinsu",
		"div.d",
		"div.ps",
		"div.s",
		"div",
		"divu",
		"dmfc0",
		"dmfc1",
		"dmfc2",
		"dmult",
		"dmultu",
		"dmtc0",
		"dmtc1",
		"dmtc2",
		"dret",
		"drotr",
		"drotr32",
		"drotrv",
		"dsbh",
		"dshd",
		"dsll",
		"dsll32",
		"dsllv",
		"dsra",
		"dsra32",
		"dsrav",
		"dsrl",
		"dsrl32",
		"dsrlv",
		"dsub",
		"dsubu",
		"ehb",
		"ei",
		"eret",
		"ext",
		"floor.l.d",
		"floor.l.s",
		"floor.l",
		"floor.w.d",
		"floor.w.s",
		"floor.w",
		"ins",
		"j",
		"jal",
		"jalr.hb",
		"jalr",
		"jalx",
		"jr.hb",
		"jr",
		"lb",
		"lbu",
		"lbux",
		"ld",
		"ldc1",
		"ldc2",
		"ldc3",
		"ldl",
		"ldr",
		"ldxc1",
		"lh",
		"lhi",
		"lhu",
		"lhx",
		"li",
		"ll",
		"lld",
		"llo",
		"lui",
		"luxc1",
		"lw",
		"lwc1",
		"lwc2",
		"lwc3",
		"lwl",
		"lwr",
		"lwu",
		"lwx",
		"lwxc1",
		"lx",
		"madd.d",
		"madd.ps",
		"madd.s",
		"madd",
		"maddf.d",
		"maddf.s",
		"maddu",
		"mfc0",
		"mfc1",
		"mfc2",
		"mfhc1",
		"mfhc2",
		"mfhi",
		"mflo",
		"mov.d",
		"mov.ps",
		"mov.s",
		"movcf",
		"movci",
		"move",
		"movf.d",
		"movf.ps",
		"movf.s",
		"movf",
		"movn.d",
		"movn.ps",
		"movn.s",
		"movn",
		"movt.d",
		"movt.ps",
		"movt.s",
		"movt",
		"movz.d",
		"movz.ps",
		"movz.s",
		"movz",
		"msub.d",
		"msub.ps",
		"msub.s",
		"msub",
		"msubf.d",
		"msubf.s",
		"msubu",
		"mtc0",
		"mtc1",
		"mtc2",
		"mthc1",
		"mthc2",
		"mthi",
		"mtlo",
		"mul.d",
		"mul.ps",
		"mul.s",
		"mul",
		"mulr",
		"mult",
		"multu",
		"neg.d",
		"neg.ps",
		"neg.s",
		"neg",
		"negu",
		"nmadd.d",
		"nmadd.ps",
		"nmadd.s",
		"nmsub.d",
		"nmsub.ps",
		"nmsub.s",
		"nop",
		"nor",
		"not",
		"or",
		"ori",
		"pause",
		"pll.ps",
		"plu.ps",
		"pref",
		"prefx",
		"pul.ps",
		"puu.ps",
		"rdhwr",
		"rdpgpr",
		"recip.d",
		"recip.s",
		"recip",
		"recip1",
		"recip2",
		"rint.d",
		"rint.s",
		"rotr",
		"rotrv",
		"round.l.d",
		"round.l.s",
		"round.l",
		"round.w.d",
		"round.w.s",
		"round.w",
		"rsqrt.d",
		"rsqrt.s",
		"rsqrt",
		"rsqrt1",
		"rsqrt2",
		"sb",
		"sc",
		"scd",
		"sd",
		"sdbbp",
		"sdc1",
		"sdc2",
		"sdc3",
		"sdl",
		"sdr",
		"sdxc1",
		"seb",
		"seh",
		"sel.d",
		"sel.s",
		"sh",
		"sll",
		"sllv",
		"slt",
		"slti",
		"sltiu",
		"sltu",
		"sqrt.d",
		"sqrt.ps",
		"sqrt.s",
		"sra",
		"srav",
		"srl",
		"srlv",
		"ssnop",
		"sub.d",
		"sub.ps",
		"sub.s",
		"sub",
		"subu",
		"suxc1",
		"sw",
		"swc1",
		"swc2",
		"swc3",
		"swl",
		"swr",
		"swxc1",
		"sync",
		"synci",
		"syscall",
		"teq",
		"teqi",
		"tge",
		"tgei",
		"tgeiu",
		"tgeu",
		"tlbinv",
		"tlbinvf",
		"tlbp",
		"tlbr",
		"tlbwi",
		"tlbwr",
		"tlt",
		"tlti",
		"tltiu",
		"tltu",
		"tne",
		"tnei",
		"trap",
		"trunc.l.d",
		"trunc.l.s",
		"trunc.l",
		"trunc.w.d",
		"trunc.w.s",
		"trunc.w",
		"wait",
		"wrpgpr",
		"wsbh",
		"xor",
		"xori",

		// cavium instructions
		"baddu",
		"bbit0",
		"bbit032",
		"bbit1",
		"bbit132",
		"cins",
		"cins32",
		"cvm",
		"dmul",
		"dpop",
		"exts",
		"exts32",
		"mtm0",
		"mtm1",
		"mtm2",
		"mtp0",
		"mtp1",
		"mtp2",
		"pop",
		"rdhwr",
		"saa",
		"saad",
		"seq",
		"seqi",
		"sne",
		"snei",
		"synciobdma",
		"syncs",
		"syncw",
		"syncws",
		"v3mulu",
		"vmm0",
		"vmulu",
		"zcb",
		"zcbt",

};

static const char * const RegisterStrings[] = {
    "$zero",    // Hardware constant 0
    "$at",      // Reserved for assembler
    "$v0",      // Return values
    "$v1",
    "$a0",      // Arguments
    "$a1",
    "$a2",
    "$a3",
    "$t0",      // Temporaries
    "$t1",
    "$t2",
    "$t3",
    "$t4",
    "$t5",
    "$t6",
    "$t7",
    "$s0",      // Saved values
    "$s1",
    "$s2",
    "$s3",
    "$s4",
    "$s5",
    "$s6",
    "$s7",
    "$t8",      // Cont. Saved values
    "$t9",
    "$k0",      // Reserved for OS
    "$k1",
    "$gp",      // Global pointer
    "$sp",      // Stack Pointer
    "$fp",      // Frame Pointer
    "$ra",      // Return Adress
	"$0",
	"$1",
	"$2",
	"$3",
	"$4",
	"$5",
	"$6",
	"$7",
	"$8",
	"$9",
	"$10",
	"$11",
	"$12",
	"$13",
	"$14",
	"$15",
	"$16",
	"$17",
	"$18",
	"$19",
	"$20",
	"$21",
	"$22",
	"$23",
	"$24",
	"$25",
	"$26",
	"$27",
	"$28",
	"$29",
	"$30",
	"$31",
	"$f0",
	"$f1",
	"$f2",
	"$f3",
	"$f4",
	"$f5",
	"$f6",
	"$f7",
	"$f8",
	"$f9",
	"$f10",
	"$f11",
	"$f12",
	"$f13",
	"$f14",
	"$f15",
	"$f16",
	"$f17",
	"$f18",
	"$f19",
	"$f20",
	"$f21",
	"$f22",
	"$f23",
	"$f24",
	"$f25",
	"$f26",
	"$f27",
	"$f28",
	"$f29",
	"$f30",
	"$f31",
	"$lo",
	"$hi",
	"cop0_Index",
	"cop0_MVPControl",
	"cop0_MVPConf0",
	"cop0_MVPConf1",
	"cop0_Random",
	"cop0_VPEControl",
	"cop0_VPEConf0",
	"cop0_VPEConf1",
	"cop0_YQMask",
	"cop0_VPESchedule",
	"cop0_VPEScheFBack",
	"cop0_VPEOpt",
	"cop0_EntryLo0",
	"cop0_TCStatus",
	"cop0_TCBind",
	"cop0_TCRestart",
	"cop0_TCHalt",
	"cop0_TCContext",
	"cop0_TCSchedule",
	"cop0_TCScheFBack",
	"cop0_EntryLo1",
	"cop0_Context",
	"cop0_ContextConfig",
	"cop0_PageMask",
	"cop0_PageGrain",
	"cop0_Wired",
	"cop0_SRSConf0",
	"cop0_SRSConf1",
	"cop0_SRSConf2",
	"cop0_SRSConf3",
	"cop0_SRSConf4",
	"cop0_HWREna",
	"cop0_BadVAddr",
	"cop0_Count",
	"cop0_EntryHi",
	"cop0_Compare",
	"cop0_Status",
	"cop0_IntCtl",
	"cop0_SRSCtl",
	"cop0_SRSMap",
	"cop0_Cause",
	"cop0_EPC",
	"cop0_PrId",
	"cop0_EBase",
	"cop0_Config",
	"cop0_Config1",
	"cop0_Config2",
	"cop0_Config3",
	"cop0_LLAddr",
	"cop0_WatchLo",
	"cop0_WatchHi",
	"cop0_XContext",
	"cop0_Debug",
	"cop0_TraceControl",
	"cop0_TraceControl2",
	"cop0_UserTraceData",
	"cop0_TraceBPC",
	"cop0_DEPC",
	"cop0_PerfCnt",
	"cop0_ErrCtl",
	"cop0_CacheErr0",
	"cop0_CacheErr1",
	"cop0_CacheErr2",
	"cop0_CacheErr3",
	"cop0_TagLo",
	"cop0_DataLo",
	"cop0_TagHi",
	"cop0_DataHi",
	"cop0_ErrorEPC",
	"cop0_DESAVE",

	// cavium-specific multiplication registers
	"cvm_mpl0",
	"cvm_mpl1",
	"cvm_mpl2",
	"cvm_p0",
	"cvm_p1",
	"cvm_p2",

	// cavium-specific implementation defined
	"cop0_CvmCount",
	"cop0_CvmCtl",
	"cop0_PowerThrottle",
	"cop0_CvmMemCtl",
	"cop0_MulticoreDbg",

	"CVMX_HSH_DAT0",
	"CVMX_HSH_DAT1",
	"CVMX_HSH_DAT2",
	"CVMX_HSH_DAT3",
	"CVMX_HSH_DAT4",
	"CVMX_HSH_DAT5",
	"CVMX_HSH_DAT6",
	"CVMX_HSH_IV0",
	"CVMX_HSH_IV1",
	"CVMX_HSH_IV2",
	"CVMX_HSH_IV3",
	"CVMX_SHA3_DAT24",
	"CVMX_SHA3_DAT15_RD",
	"CVMX_GFM_MUL_REFLECT0",
	"CVMX_GFM_MUL_REFLECT1",
	"CVMX_GFM_RESINP_REFLECT0",
	"CVMX_GFM_RESINP_REFLECT1",
	"CVMX_GFM_XOR0_REFLECT",

	"CVMX_3DES/KASUMI_KEY0",
	"CVMX_3DES/KASUMI_KEY1",
	"CVMX_3DES/KASUMI_KEY2",
	"CVMX_3DES_IV",
	"CVMX_3DES_RESULT_RD",
	"CVMX_3DES_RESULT_WR",

	"CVMX_AES/SMS4_RESULT0",
	"CVMX_AES/SMS4_RESULT1",
	"CVMX_AES/SMS4_IV0",
	"CVMX_AES/SMS4_IV1",
	"CVMX_AES/SMS4_KEY0",
	"CVMX_AES/SMS4_KEY1",
	"CVMX_AES/SMS4_KEY2",
	"CVMX_AES/SMS4_KEY3",

	"CVMX_AES/SMS4_ENC_CBC0",
	"CVMX_AES/SMS4_ENC0",
	"CVMX_AES/SMS4_DEC_CBC0",
	"CVMX_AES/SMS4_DEC0",

	"CVMX_AES_KEYLENGTH",
	"CVMX_AES_DAT0",

	"CVMX_CAMELLIA_FL",
	"CVMX_CAMELLIA_FLINV",

	"CVMX_CRC_POLYNOMIAL",
	"CVMX_CRC_IV",
	"CVMX_CRC_LEN",
	"CVMX_CRC_IV_REFLECT_RD",
	"CVMX_CRC_BYTE",
	"CVMX_CRC_HALF",
	"CVMX_CRC_WORD",
	"CVMX_CRC_IV_REFLECT_WR",
	"CVMX_CRC_BYTE_REFLECT",
	"CVMX_CRC_HALF_REFLECT",
	"CVMX_CRC_WORD_REFLECT",

	"CVMX_HSH_DATW0",
	"CVMX_HSH_DATW1",
	"CVMX_HSH_DATW2",
	"CVMX_HSH_DATW3",
	"CVMX_HSH_DATW4",
	"CVMX_HSH_DATW5",
	"CVMX_HSH_DATW6",
	"CVMX_HSH_DATW7",
	"CVMX_HSH_DATW8",
	"CVMX_HSH_DATW9",
	"CVMX_HSH_DATW10",
	"CVMX_HSH_DATW11",
	"CVMX_HSH_DATW12",
	"CVMX_HSH_DATW13",
	"CVMX_HSH_DATW14",

	"CVMX_SHA3_DAT15_RD",

	"CVMX_HSH_IVW0",
	"CVMX_HSH_IVW1",
	"CVMX_HSH_IVW2",
	"CVMX_HSH_IVW3",
	"CVMX_HSH_IVW4",
	"CVMX_HSH_IVW5",
	"CVMX_HSH_IVW6",
	"CVMX_HSH_IVW7",

	"CVMX_GFM_MUL0",
	"CVMX_GFM_MUL1",
	"CVMX_GFM_RESINP0",
	"CVMX_GFM_RESINP1",
	"CVMX_GFM_XOR0",
	"CVMX_GFM_POLY",

	"CVMX_SHA3_XORDAT0",
	"CVMX_SHA3_XORDAT1",
	"CVMX_SHA3_XORDAT2",
	"CVMX_SHA3_XORDAT3",
	"CVMX_SHA3_XORDAT4",
	"CVMX_SHA3_XORDAT5",
	"CVMX_SHA3_XORDAT6",
	"CVMX_SHA3_XORDAT7",
	"CVMX_SHA3_XORDAT8",
	"CVMX_SHA3_XORDAT9",
	"CVMX_SHA3_XORDAT10",
	"CVMX_SHA3_XORDAT11",
	"CVMX_SHA3_XORDAT12",
	"CVMX_SHA3_XORDAT13",
	"CVMX_SHA3_XORDAT14",
	"CVMX_SHA3_XORDAT15",
	"CVMX_SHA3_XORDAT16",
	"CVMX_SHA3_XORDAT17",

	"CVMX_LLM_READ_ADDR0",
	"CVMX_LLM_WRITE_ADDR_INTERNAL0",
	"CVMX_LLM_DATA0",
	"CVMX_LLM_READ64_ADDR0",
	"CVMX_LLM_WRITE64_ADDR_INTERNAL0",
	"CVMX_LLM_READ_ADDR1",
	"CVMX_LLM_WRITE_ADDR_INTERNAL1",
	"CVMX_LLM_DATA1",
	"CVMX_LLM_READ64_ADDR1",
	"CVMX_LLM_WRITE64_ADDR_INTERNAL1",

	"CVMX_CRC_LEN",
	"CVMX_CRC_DWORD",
	"CVMX_CRC_VAR",
	"CVMX_CRC_DWORD_REFLECT",
	"CVMX_CRC_VAR_REFLECT",

	"CVMX_AES_ENC_CBC1",
	"CVMX_AES_ENC1",
	"CVMX_AES_DEC_CBC1",
	"CVMX_AES_DEC1",

	"CVMX_CAMELLIA_ROUND",

	"CVMX_SMS4_ENC_CBC1",
	"CVMX_SMS4_ENC1",
	"CVMX_SMS4_DEC_CBC1",
	"CVMX_SMS4_DEC1",

	"CVMX_SHA3_STARTOP",
	"CVMX_HSH_STARTMD5",
	"CVMX_SNOW3G_START",
	"CVMX_ZUC_START",
	"CVMX_ZUC_MORE",
	"CVMX_GFM_XORMUL1_REFLECT",
	"CVMX_SNOW3G_MORE",
	"CVMX_HSH_STARTSHA256",
	"CVMX_HSH_STARTSHA",
	"CVMX_3DES_ENC_CBC",
	"CVMX_KAS_ENC_CBC",
	"CVMX_3DES_ENC",
	"CVMX_KAS_ENC",
	"CVMX_3DES_DEC_CBC",
	"CVMX_3DES_DEC",

	"CVMX_CRC_POLYNOMIAL_WR",
	"CVMX_CRC_POLYNOMIAL_REFLECT",

	"CVMX_HSH_STARTSHA512",
	"CVMX_GFM_XORMUL1",
};

static const char * const FlagStrings[] = {
	"$fcc0",
	"$fcc1",
	"$fcc2",
	"$fcc3",
	"$fcc4",
	"$fcc5",
	"$fcc6",
	"$fcc7"
};

static const char * const HintStrings[] = {
	"load",			  // 0
	"store",          // 1
	"l1_lru_hint",    // 2
	"3",            // 3
	"load_streamed",  // 4
	"store_streamed", // 5
	"load_retained",  // 6
	"store_retained", // 7
	"l2_operation_8",
	"l2_operation_9",
	"l2_operation_10",
	"l2_operation_11",
	"l2_operation_12",
	"l2_operation_13",
	"l2_operation_14",
	"l2_operation_15",  //15
	"l3_operation_16",  //16
	"l3_operation_17",
	"l3_operation_18",
	"l3_operation_19",
	"l3_operation_20",
	"l3_operation_21",
	"l3_operation_22",
	"l3_operation_23",  //23
	"24",    //24
	"nudge", //25
	"26",    //26
	"27",
	"28",
	"29",	 //29
	"PrepareForStore", //30
	"31"  //31
};

const char* get_operation(Operation operation)
{
	if (operation > MIPS_INVALID && operation < MIPS_OPERATION_END)
		return OperationStrings[operation];

	return NULL;
}

const char* get_register(Reg reg)
{
	if (reg >= 0 && reg < END_REG)
		return RegisterStrings[reg];
	return NULL;
}

const char* get_flag(enum Flag flag)
{
	if (flag >= 0 && flag < END_FLAG)
		return FlagStrings[flag];
	return NULL;
}

const char* get_hint(Hint hint)
{
	if (hint >= 0 && hint < HINT_END)
		return HintStrings[hint];
	return NULL;
}

uint32_t bswap32(uint32_t x)
{
	return	((x << 24) & 0xff000000 ) |
		((x <<  8) & 0x00ff0000 ) |
		((x >>  8) & 0x0000ff00 ) |
		((x >> 24) & 0x000000ff );
}

uint32_t mips_decompose_instruction(
		combined ins,
		Instruction* restrict instruction,
		uint32_t version,
		uint64_t address,
		uint32_t flags)
{
	uint64_t registerMask;

	if (version >= MIPS_VERSION_END)
		return 1;
	if (version == MIPS_64) {
		registerMask = 0xFFFFFFFFFFFFFFFFULL;
	} else {
		registerMask = 0xFFFFFFFFULL;
	}
	if (ins.value == 0)
	{
		instruction->operation = MIPS_NOP;
		return 0;
	}
	//Do initial stage 1 decoding
	switch(ins.value >> 26)
	{
		case 0:
			instruction->operation = mips_special_table[version-1][ins.decode.func_hi][ins.decode.func_lo];
			break;
		case 1:
			instruction->operation = mips_regimm_table[version-1][ins.decode.rt_hi][ins.decode.rt_lo];
			break;
		case 0x1c:
			if (version == MIPS_32)
				instruction->operation = mips32_special2_table[ins.decode.func_hi][ins.decode.func_lo];
			else if (version == MIPS_64)
			{
				if ((flags & DECOMPOSE_FLAGS_CAVIUM) == 0)
					instruction->operation = mips64_special2_table[ins.decode.func_hi][ins.decode.func_lo];
				else
				{
					instruction->operation = cavium_mips64_special2_table[ins.decode.func_hi][ins.decode.func_lo];
					if (instruction->operation == CNMIPS_CVM)
					{
						switch (ins.r.sa)
						{
							// note that CN50xx docs don't include these instructions, but they are
							// listed in the SDK (bootloader/u-boot/mips/include/asm/inst.h)
							case 0x1c: instruction->operation = CNMIPS_ZCB; break;
							case 0x1d: instruction->operation = CNMIPS_ZCBT; break;
							default: return 1;
						}
					}
				}

			}
			break;
		case 0x1f:
			if (version == MIPS_32)
				instruction->operation = mips32_special3_table[ins.decode.func_hi][ins.decode.func_lo];
			else if (version == MIPS_64)
				instruction->operation = mips64_special3_table[ins.decode.func_hi][ins.decode.func_lo];
			break;
		default:
			if ((flags & DECOMPOSE_FLAGS_CAVIUM) == 0)
				instruction->operation = mips_base_table[version-1][ins.decode.op_hi][ins.decode.op_lo];
			else
				instruction->operation = cavium_mips_base_table[ins.decode.op_hi][ins.decode.op_lo];
	}

	//Now deal with aliases and stage 2 decoding
	if (version == MIPS_32 || version == MIPS_64)
	{
		switch (instruction->operation)
		{
			case MIPS_LX:
				//MIPSDSP extension
				switch (ins.r.sa)
				{
					case 0x00: instruction->operation = MIPS_LWX; break;
					case 0x04: instruction->operation = MIPS_LHX; break;
					case 0x06: instruction->operation = MIPS_LBUX; break;
					default:
						return 1;
				}
				break;

			case MIPS_BSHFL:
				//Version 5 only but no need for a check
				switch (ins.r.sa)
				{
					case 0x00: instruction->operation = MIPS_BITSWAP; break;
					case 0x02: instruction->operation = MIPS_WSBH; break;
					case 0x08:
					case 0x09:
					case 0x0a:
					case 0x0b: instruction->operation = MIPS_ALIGN; break;
					case 0x10: instruction->operation = MIPS_SEB;  break;
					case 0x18: instruction->operation = MIPS_SEH;  break;
					default:
						return 1;
				}
				break;
			case MIPS_DBSHFL:
				switch (ins.r.sa)
				{
					case 0x02: instruction->operation = MIPS_DSBH; break;
					case 0x05: instruction->operation = MIPS_DSHD; break;
					default:
						return 1;
				}
				break;
			case MIPS_SRL:
				if (ins.bits.bit21 == 1)
					instruction->operation = MIPS_ROTR;
				break;
			case MIPS_DSRL:
				if (ins.bits.bit21 == 1)
					instruction->operation = MIPS_DROTR;
				break;
			case MIPS_DSRL32:
				if (ins.bits.bit21 == 1)
					instruction->operation = MIPS_DROTR32;
				break;
			case MIPS_SRLV:
				if (ins.bits.bit6 == 1)
					instruction->operation = MIPS_ROTRV;
				break;
			case MIPS_DSRLV:
				if (ins.bits.bit6 == 1)
					instruction->operation = MIPS_DROTRV;
				break;
			case MIPS_COP0:
				switch (ins.r.rs)
				{
					case 0:
						if (((ins.value >> 3) & 0xff) != 0)
							return 1;
						instruction->operation = MIPS_MFC0;
						break;
					case 1:
						if (((ins.value >> 3) & 0xff) != 0)
							return 1;
						instruction->operation = MIPS_DMFC0;
						break;
					case 2:  instruction->operation = MIPS_CFC0;   break;
					case 4:  instruction->operation = MIPS_MTC0;   break;
					case 5:
						if (((ins.value >> 3) & 0xff) != 0)
							return 1;
						instruction->operation = MIPS_DMTC0;
						break;
					case 6:  instruction->operation = MIPS_CTC0;    break;
					case 10: instruction->operation = MIPS_RDPGPR; break;
					case 11:
						if (ins.bits.bit5 == 1)
							instruction->operation = MIPS_EI;
						else
							instruction->operation = MIPS_DI;
						break;
					case 14: instruction->operation = MIPS_WRPGPR; break;
				}
				if (ins.r.rs > 15)
				{
					switch (ins.r.function)
					{
						case 1:  instruction->operation = MIPS_TLBR;    break;
						case 2:  instruction->operation = MIPS_TLBWI;   break;
						case 3:  instruction->operation = MIPS_TLBINV;  break;
						case 4:  instruction->operation = MIPS_TLBINVF; break;
						case 6:  instruction->operation = MIPS_TLBWR;   break;
						case 8:  instruction->operation = MIPS_TLBP;    break;
						case 24: instruction->operation = MIPS_ERET;    break;
						case 31: instruction->operation = MIPS_DERET;   break;
						case 32: instruction->operation = MIPS_WAIT;    break;
					}
				}
				break;
			case MIPS_COP1:
				switch (ins.r.rs)
				{
					case 0:  instruction->operation = MIPS_MFC1;    break;
					case 1:
						if ((ins.value & 0x7ff) != 0)
							return 1;
						instruction->operation = MIPS_DMFC1;
						break;
					case 2:  instruction->operation = MIPS_CFC1;    break;
					case 3:  instruction->operation = MIPS_MFHC1;   break;
					case 4:  instruction->operation = MIPS_MTC1;    break;
					case 5:
						if ((ins.value & 0x7ff) != 0)
							return 1;
						instruction->operation = MIPS_DMTC1;
						break;
					case 6:  instruction->operation = MIPS_CTC1;    break;
					case 7:  instruction->operation = MIPS_MTHC1;   break;
					case 8:
						switch (ins.r.rt & 3)
						{
						case 0: instruction->operation = MIPS_BC1F;  break;
						case 1: instruction->operation = MIPS_BC1T;  break;
						case 2: instruction->operation = MIPS_BC1FL; break;
						case 3: instruction->operation = MIPS_BC1TL; break;
						}
						break;
					case 9:
						instruction->operation = MIPS_BC1ANY2;
						if (ins.r.rs == 9)
							instruction->operation = MIPS_BC1EQZ;
						else if (ins.r.rs == 13)
							instruction->operation = MIPS_BC1NEZ;
						break;
					case 10: instruction->operation = MIPS_BC1ANY4; break;
					case 16: //S
						instruction->operation = mips_v5_cop1_S_table[ins.decode.func_hi][ins.decode.func_lo];
						if (instruction->operation == MIPS_MOVCF)
						{
							if (ins.bits.bit16 == 1)
								instruction->operation = MIPS_MOVT_S;
							else
								instruction->operation = MIPS_MOVF_S;
						}
						break;
					case 17: //D
						instruction->operation = mips_v5_cop1_D_table[ins.decode.func_hi][ins.decode.func_lo];
						if (instruction->operation == MIPS_MOVCF)
						{
							if (ins.bits.bit16 == 1)
								instruction->operation = MIPS_MOVT_D;
							else
								instruction->operation = MIPS_MOVF_D;
						}
						break;
					case 20: //W
					case 21: //L
						instruction->operation = mips_v5_cop1_LW_table[ins.decode.func_hi][ins.decode.func_lo];
						break;
					case 22: //PS
						instruction->operation = mips_v5_cop1_PS_table[ins.decode.func_hi][ins.decode.func_lo];
						if (instruction->operation == MIPS_MOVCF)
						{
							if (ins.bits.bit16 == 1)
								instruction->operation = MIPS_MOVT_PS;
							else
								instruction->operation = MIPS_MOVF_PS;
						}
						break;
				/*	Not yet supported
				 *	case 24:
						{
							Operation operation[8] = {MIPS_BZ_B, MIPS_BZ_H, MIPS_BZ_W, MIPS_BZ_D, MIPS_BNZ_B, MIPS_BNZ_H, MIPS_BNZ_W, MIPS_BNZ_D};
							instruction->operation = operation[ins.decode.func_lo];
						}
						break;
				*/
				}
				break;
			case MIPS_COP2:
			{
				if (ins.r.rs < 8)
				{
					static const Operation opmap[8] =
					{
						MIPS_MFC2,    // 00000
						MIPS_DMFC2,   // 00001
						MIPS_CFC2,    // 00010
						MIPS_MFHC2,   // 00011
						MIPS_MTC2,    // 00100
						MIPS_DMTC2,   // 00101
						MIPS_CTC2,    // 00110
						MIPS_MTHC2    // 00111
					};
					instruction->operation = opmap[ins.r.rs];
				}
				else if (ins.r.rs == 8)
				{
					static const Operation opmap[4] =
					{
						MIPS_BC2F,    // 01000:00
						MIPS_BC2FL,   // 01000:10
						MIPS_BC2T,    // 01000:01
						MIPS_BC2TL   // 01000:11
					};
					instruction->operation = opmap[ins.r.rt & 3];
				}
				else if (ins.r.rs < 16)
				{
					static const Operation opmap[8] =
					{
						MIPS_INVALID, // 01000
						MIPS_BC2EQZ,  // 01001
						MIPS_LWC2,    // 01010
						MIPS_SWC2,    // 01011
						MIPS_INVALID, // 01100
						MIPS_BC2NEZ,  // 01101
						MIPS_LDC2,    // 01110
						MIPS_SDC2     // 01111
					};
					instruction->operation = opmap[ins.r.rs & 7];
				}
				else
				{
					instruction->operation = MIPS_COP2;
				}
				break;
			}

			case MIPS_COP1X:
				instruction->operation = mips_v5_cop1x_table[ins.decode.func_hi][ins.decode.func_lo];
				break;
			case MIPS_SLL:
				if (ins.r.rs == 0 && ins.r.rd == 0 && ins.r.rt == 0)
				{
					if (ins.r.sa == 3)
						instruction->operation = MIPS_EHB;
					else if (ins.r.sa == 1)
						instruction->operation = MIPS_SSNOP;
					else if (ins.r.sa == 5)
						instruction->operation = MIPS_PAUSE;
					else if (ins.r.sa == 0)
						instruction->operation = MIPS_NOP;
				}
				break;
			case MIPS_JR:
				{
					uint32_t hint = ins.r.sa & 15;
					if (ins.r.rt == 0 && ins.r.rd == 0 && ins.r.sa >= 16 &&
						(hint == LOAD || hint == STORE || hint == LOAD_STREAMED ||
						hint == STORE_STREAMED || hint == LOAD_RETAINED || hint == STORE_RETAINED))
					{
						instruction->operation = MIPS_JR_HB;
					}
				}
				break;
			case MIPS_JALR:
				{
					if (ins.r.rt != 0)
						return 1;
					if (ins.r.sa >= 16)
						instruction->operation = MIPS_JALR_HB;
				}
				break;
			case MIPS_MOVCI:
				if (ins.bits.bit16 == 1)
					instruction->operation = MIPS_MOVT;
				else
					instruction->operation = MIPS_MOVF;
				break;
			case MIPS_NOR:
				if (ins.r.rt == 0)
					instruction->operation = MIPS_NOT;
				break;
			case MIPS_SUB:
				if (ins.r.rs == 0)
					instruction->operation = MIPS_NEG;
				if (ins.r.rd == 0)
					instruction->operation = MIPS_NOP;
				break;
			case MIPS_SUBU:
				if (ins.r.rs == 0)
					instruction->operation = MIPS_NEGU;
				break;
			case MIPS_OR:
				if (((ins.r.rd == ins.r.rt) || (ins.r.rd == ins.r.rs)) &&
					((ins.r.rt == ins.r.rs) || (ins.r.rt == 0) || (ins.r.rs == 0)))
				{
					instruction->operation = MIPS_NOP;
					break;
				}
				FALL_THROUGH
			case MIPS_ADDU:
				if (ins.r.rt == 0)
					instruction->operation = MIPS_MOVE;
				if (ins.r.rd == 0)
					instruction->operation = MIPS_NOP;
				break;
			case MIPS_BEQ:
				if (ins.r.rt == 0)
				{
					if (ins.r.rs == 0)
						instruction->operation = MIPS_B;
					else
						instruction->operation = MIPS_BEQZ;
				}
				break;
			case MIPS_BNE:
				if (ins.r.rt == 0)
					instruction->operation = MIPS_BNEZ;

				break;
			case MIPS_BGEZAL:
				if (ins.r.rs == 0)
					instruction->operation = MIPS_BAL;
			case MIPS_SYNC:
				if ((flags & DECOMPOSE_FLAGS_CAVIUM) != 0)
				{
					switch (ins.r.sa)
					{
						case 2: instruction->operation = CNMIPS_SYNCIOBDMA; break;
						case 4: instruction->operation = CNMIPS_SYNCW; break;
						case 5: instruction->operation = CNMIPS_SYNCWS; break;
						case 6: instruction->operation = CNMIPS_SYNCS; break;
					}
				}
				break;
			case MIPS_RDHWR:
				if ((flags & DECOMPOSE_FLAGS_CAVIUM) != 0)
				{
					switch (ins.r.rd)
					{
						case 30: instruction->operation = CNMIPS_RDHWR; break;
						case 31: instruction->operation = CNMIPS_RDHWR; break;
					}
				}
				break;
			default:
				break;
		}
	}

	//Now that we have the proper instructions aliased figure out what our operands are
	switch(instruction->operation)
	{
		//Zero operand instructions
		case MIPS_DRET:
		case MIPS_ERET:
		case MIPS_WAIT:
		case MIPS_SSNOP:
		case MIPS_NOP:
		case MIPS_PAUSE:
		case MIPS_EHB:
			break;
		case MIPS_BREAK:
		case MIPS_SYSCALL:
			if (ins.s.code != 0)
				INS_1(IMM, ins.s.code);
			break;
		case MIPS_TLBWR:
		case MIPS_TLBWI:
		case MIPS_TLBR:
		case MIPS_TLBP:
		case MIPS_TLBINV:
		case MIPS_TLBINVF:
			if (((ins.value >> 6) & 0x7ff) != 0 || ins.bits.bit25 != 1)
				return 1;
			break;
		case MIPS_SYNC:
			if (ins.r.rd + ins.r.rs + ins.r.rt != 0)
				return 1;
			if (ins.r.sa != 0)
				INS_1(IMM, ins.r.sa);
			break;
		//1 operand instructions
		case MIPS_COP2:
			INS_1(IMM, (ins.value & 0x1ffffff))
			break;
		case MIPS_SYNCI:
			instruction->operands[0].operandClass = MEM_IMM;
			instruction->operands[0].reg = ins.i.rs;
			instruction->operands[0].immediate = ins.i.immediate;
			break;
		case MIPS_SDBBP:
			INS_1(IMM, ((ins.value >> 6) & 0xfffff))
			break;
		case MIPS_JALX:
			INS_1(LABEL, (ins.j.immediate<<2));
			break;
		case MIPS_DI:
		case MIPS_EI:
			if (ins.r.rt != 0)
				INS_1(REG, ins.r.rt)
			break;
		case MIPS_MFHI:
		case MIPS_MFLO:
			INS_1(REG, ins.r.rd)
			if (ins.r.sa + ins.r.rt + ins.r.rs != 0)
				return 1;
			break;
		case MIPS_J:
		case MIPS_JAL:
			INS_1(LABEL, (address & 0xfffffffff0000000) + (((uint32_t)ins.j.immediate)<<2))
			break;
		case MIPS_JR:
			INS_1(REG, ins.r.rs)
			if (ins.r.rt + ins.r.rd + ins.r.sa != 0)
				return 1;
			break;
		case MIPS_JR_HB:
			INS_1(REG, ins.r.rs)
			break;
		case MIPS_MTHI:
		case MIPS_MTLO:
			INS_1(REG,ins.r.rs)
			if (ins.r.rd + ins.r.rt + ins.r.sa != 0)
				return 1;
			break;
		case MIPS_BAL:
		case MIPS_B:
			INS_1(LABEL, (4 + address + (ins.i.immediate<<2)) & registerMask);
			break;
		//2 operand instructions
		case MIPS_JALR_HB:
			if (ins.r.rd == 31)
			{
				INS_1(REG, ins.r.rs)
			}
			else
			{
				INS_2(REG, ins.r.rd, REG, ins.r.rs)
			}
			if (ins.r.rt != 0)
				return 1;
			break;

		case MIPS_BC1F:
		case MIPS_BC1FL:
		case MIPS_BC1T:
		case MIPS_BC1TL:
			if (((ins.value >> 18) & 7) == 0)
			{
				INS_1(LABEL, (4 + address + (ins.i.immediate<<2)) & registerMask);
			}
			else
			{
				INS_2(FLAG, (FPCCREG_FCC0 + ((ins.value >> 18) & 7)), LABEL, (4 + address + (ins.i.immediate<<2)) & registerMask);
			}
			break;
		case MIPS_CLO:
		case MIPS_CLZ:
		case MIPS_NOT:
		case MIPS_MOVE:
		case MIPS_DCLO:
		case MIPS_DCLZ:
			INS_2(REG, ins.r.rd, REG, ins.r.rs)
			break;
		case MIPS_RDHWR:
			INS_2(REG, ins.r.rt, IMM, ins.r.rd);
			break;
		case MIPS_TRUNC_W_S:
		case MIPS_TRUNC_W_D:
		case MIPS_TRUNC_L_S:
		case MIPS_TRUNC_L_D:
		case MIPS_SQRT_S:
		case MIPS_SQRT_D:
		case MIPS_RSQRT_S:
		case MIPS_RSQRT_D:
		case MIPS_ROUND_W_S:
		case MIPS_ROUND_W_D:
		case MIPS_ROUND_L_S:
		case MIPS_ROUND_L_D:
		case MIPS_RECIP_S:
		case MIPS_RECIP_D:
			INS_2(REG, ins.f.fd + FPREG_F0, REG, ins.f.fs + FPREG_F0);
			if (ins.f.ft != 0)
				return 1;
			break;
		case MIPS_BC1EQZ:
		case MIPS_BC1NEZ:
			INS_2(REG, ins.f.ft + FPREG_F0, IMM, (address + 4 + (ins.i.immediate << 2)) & registerMask);
			break;
		case MIPS_BC2EQZ:
		case MIPS_BC2NEZ:
			INS_2(REG, (CPREG_0 + ins.r.rt), IMM, (address + 4 + (ins.i.immediate << 2)) & registerMask);
			break;
		case MIPS_ABS_S:
		case MIPS_ABS_D:
		case MIPS_ABS_PS:
		case MIPS_CEIL_L_S:
		case MIPS_CEIL_L_D:
		case MIPS_CEIL_W_S:
		case MIPS_CEIL_W_D:
		case MIPS_CVT_D_S:
		case MIPS_CVT_D_W:
		case MIPS_CVT_L_S:
		case MIPS_CVT_L_D:
		case MIPS_CVT_S_D:
		case MIPS_CVT_S_W:
		case MIPS_CVT_S_L:
		case MIPS_CVT_S_PL:
		case MIPS_CVT_S_PU:
		case MIPS_CVT_W_S:
		case MIPS_CVT_W_D:
		case MIPS_FLOOR_L_S:
		case MIPS_FLOOR_L_D:
		case MIPS_FLOOR_W_S:
		case MIPS_FLOOR_W_D:
		case MIPS_NEG_S:
		case MIPS_NEG_D:
		case MIPS_NEG_PS:
			INS_2(REG, ins.f.fd + FPREG_F0, REG, ins.f.fs + FPREG_F0)
			break;
		case MIPS_MOV_S:
		case MIPS_MOV_D:
		case MIPS_MOV_PS:
			INS_2(REG, ins.f.fd + FPREG_F0, REG, ins.f.fs + FPREG_F0)
			if (ins.f.ft != 0)
				return 1;
			break;
		case MIPS_BGEZ:
		case MIPS_BGEZAL:
		case MIPS_BGEZALL:
		case MIPS_BGEZL:
		case MIPS_BLTZAL:
		case MIPS_BLTZALL:
		case MIPS_BLTZL:
		case MIPS_BEQZ:
		case MIPS_BNEZ:
			INS_2(REG, ins.i.rs, LABEL, (4 + address + (ins.i.immediate<<2)) & registerMask)
			break;
		case MIPS_BGTZ:
		case MIPS_BGTZL:
		case MIPS_BLEZ:
		case MIPS_BLEZL:
		case MIPS_BLTZ:
			INS_2(REG, ins.i.rs, LABEL, (4 + address + (ins.i.immediate<<2)) & registerMask)
			if (ins.i.rt != 0)
				return 1;
			break;
		case MIPS_TGEU:
		case MIPS_TLT:
		case MIPS_TLTU:
		case MIPS_TNE:
		case MIPS_TGE:
		case MIPS_TEQ:
			if (ins.t.code != 0)
			{
				INS_3(REG, ins.t.rs, REG, ins.t.rt, IMM, ins.t.code);
			}
			else
			{
				INS_2(REG, ins.t.rs, REG, ins.t.rt);
			}
			break;
		case MIPS_DDIV:
		case MIPS_DDIVU:
		case MIPS_DIV:
		case MIPS_DIVU:
		case MIPS_DMULT:
		case MIPS_DMULTU:
		case MIPS_MULT:
		case MIPS_MULTU:
		case MIPS_MADD:
		case MIPS_MADDU:
		case MIPS_MSUB:
		case MIPS_MSUBU:
			if (ins.r.rd != 0 || ins.r.sa != 0)
				return 1;
			INS_2(REG, ins.r.rs, REG, ins.r.rt)
			break;
		case MIPS_LUI:
			if (ins.i.rs != 0)
				return 1;
			// Unsigned immediate value
			INS_2(REG, ins.i.rt, IMM, (ins.i.immediate & 0xffff))
			break;
		case MIPS_TEQI:
		case MIPS_TGEI:
		case MIPS_TGEIU:
		case MIPS_TLTI:
		case MIPS_TLTIU:
		case MIPS_TNEI:
			INS_2(REG, ins.i.rs, IMM, ins.i.immediate)
			break;
		case MIPS_WSBH:
		case MIPS_WRPGPR:
		case MIPS_SEB:
		case MIPS_SEH:
		case MIPS_RDPGPR:
		case MIPS_NEG:
		case MIPS_NEGU:
		case MIPS_BITSWAP:
		case MIPS_DSBH:
		case MIPS_DSHD:
			INS_2(REG, ins.r.rd, REG, ins.r.rt)
			break;
		case MIPS_CFC0:
		case MIPS_CTC0:
		case MIPS_CFC1:
		case MIPS_CTC1:
			INS_2(REG, ins.r.rt, REG, ins.f.fs + CPREG_0)
			break;
		case MIPS_DMFC1:
		case MIPS_MFC1:
		case MIPS_MFHC1:
		case MIPS_DMTC1:
		case MIPS_MTC1:
		case MIPS_MTHC1:
			INS_2(REG, ins.r.rt, REG, ins.f.fs + FPREG_F0)
			if (ins.r.function + ins.r.sa != 0)
				return 1;
			break;
		case MIPS_DMFC2:
		case MIPS_MFC2:
		case MIPS_DMTC2:
		case MIPS_MTC2:
		case MIPS_CFC2:
		case MIPS_MFHC2:
		case MIPS_CTC2:
		case MIPS_MTHC2:
			INS_2(REG, ins.i.rt, IMM, ins.i.immediate);
			break;
		case MIPS_JALR:
			if (ins.r.rd == 31)
			{
				INS_1(REG, ins.r.rs);
			}
			else
			{
				INS_2(REG, ins.r.rd, REG, ins.r.rs);
			}
			break;
		case MIPS_C_F_S:
		case MIPS_C_SF_S:
		case MIPS_C_UN_S:
		case MIPS_C_EQ_S:
		case MIPS_C_UEQ_S:
		case MIPS_C_OLT_S:
		case MIPS_C_ULT_S:
		case MIPS_C_OLE_S:
		case MIPS_C_ULE_S:
		case MIPS_C_F_D:
		case MIPS_C_SF_D:
		case MIPS_C_UN_D:
		case MIPS_C_EQ_D:
		case MIPS_C_UEQ_D:
		case MIPS_C_OLT_D:
		case MIPS_C_ULT_D:
		case MIPS_C_OLE_D:
		case MIPS_C_ULE_D:
		case MIPS_C_F_PS:
		case MIPS_C_SF_PS:
		case MIPS_C_UN_PS:
		case MIPS_C_EQ_PS:
		case MIPS_C_UEQ_PS:
		case MIPS_C_OLT_PS:
		case MIPS_C_ULT_PS:
		case MIPS_C_OLE_PS:
		case MIPS_C_ULE_PS:
		case MIPS_C_NGLE_S:
		case MIPS_C_SEQ_S:
		case MIPS_C_NGL_S:
		case MIPS_C_LT_S:
		case MIPS_C_NGE_S:
		case MIPS_C_LE_S:
		case MIPS_C_NGT_S:
		case MIPS_C_NGLE_D:
		case MIPS_C_SEQ_D:
		case MIPS_C_NGL_D:
		case MIPS_C_LT_D:
		case MIPS_C_NGE_D:
		case MIPS_C_LE_D:
		case MIPS_C_NGT_D:
		case MIPS_C_NGLE_PS:
		case MIPS_C_SEQ_PS:
		case MIPS_C_NGL_PS:
		case MIPS_C_LT_PS:
		case MIPS_C_NGE_PS:
		case MIPS_C_LE_PS:
		case MIPS_C_NGT_PS:
			{
				uint32_t cc = (ins.value >> 8) & 7;
				if (cc == 0)
				{
					INS_2(REG, ins.f.fs + FPREG_F0, REG, ins.f.ft + FPREG_F0)
				}
				else
				{
					INS_3(FLAG, cc + FPCCREG_FCC0, REG, ins.f.fs + FPREG_F0, REG, ins.f.ft + FPREG_F0)
				}
			}
			break;
		case MIPS_CLASS_D:
		case MIPS_CLASS_S:
			if (ins.f.ft == 0)
				return 1;
			INS_2(REG, ins.f.fd + FPREG_F0, REG, ins.f.fs + FPREG_F0)
			break;

		case MIPS_LBUX:
		case MIPS_LHX:
		case MIPS_LWX:
			// MIPSDSP extensions
			instruction->operands[0].operandClass = REG;
			instruction->operands[1].operandClass = MEM_REG;
			instruction->operands[0].reg = ins.r.rd;
			instruction->operands[1].reg = ins.r.rs;
			instruction->operands[1].immediate = ins.r.rt;
			break;

		case MIPS_LB:
		case MIPS_LBU:
		case MIPS_LD:
		case MIPS_LDXC1:
		case MIPS_LDL:
		case MIPS_LDR:
		case MIPS_LH:
		case MIPS_LHU:
		case MIPS_LL:
		case MIPS_LLD:
		case MIPS_LW:
		case MIPS_LWL:
		case MIPS_LWR:
		case MIPS_LWU:
		case MIPS_SB:
		case MIPS_SC:
		case MIPS_SCD:
		case MIPS_SD:
		case MIPS_SDL:
		case MIPS_SDR:
		case MIPS_SH:
		case MIPS_SW:
		case MIPS_SWL:
		case MIPS_SWR:
			instruction->operands[0].operandClass = REG;
			instruction->operands[1].operandClass = MEM_IMM;
			instruction->operands[0].reg = ins.i.rt;
			instruction->operands[1].reg = ins.i.rs;
			instruction->operands[1].immediate = ins.i.immediate;
			break;
		case MIPS_PREF:
		case MIPS_PREFX:
		case MIPS_CACHE:
			instruction->operands[0].operandClass = HINT;
			instruction->operands[1].operandClass = MEM_IMM;
			instruction->operands[0].immediate = ins.i.rt;
			instruction->operands[1].reg = ins.i.rs;
			instruction->operands[1].immediate = ins.i.immediate;
			break;
		case MIPS_SUXC1:
		case MIPS_SWXC1:
		case MIPS_SDXC1:
			instruction->operands[0].operandClass = REG;
			instruction->operands[1].operandClass = MEM_REG;
			instruction->operands[0].reg = ins.f.fs + FPREG_F0;
			instruction->operands[1].immediate = ins.f.ft;
			instruction->operands[1].reg = ins.f.fr;
			break;
		case MIPS_LUXC1:
		case MIPS_LWXC1:
			if (ins.f.ft != 0)
				return 1;
			instruction->operands[0].operandClass = REG;
			instruction->operands[1].operandClass = MEM_REG;
			instruction->operands[0].reg = ins.f.fd + FPREG_F0;
			instruction->operands[1].immediate = ins.f.ft;
			instruction->operands[1].reg = ins.f.fr;
			break;
		case MIPS_SWC1:
		case MIPS_SWC2:
		case MIPS_SWC3:
		case MIPS_LDC1:
		case MIPS_LDC2:
		case MIPS_LDC3:
		case MIPS_SDC1:
		case MIPS_SDC2:
		case MIPS_SDC3:
		case MIPS_LWC1:
		case MIPS_LWC2:
		case MIPS_LWC3:
			instruction->operands[0].operandClass = IMM;
			instruction->operands[1].operandClass = MEM_IMM;
			instruction->operands[0].reg = ins.i.rt;
			instruction->operands[1].reg = ins.i.rs;
			instruction->operands[1].immediate = ins.i.immediate;
			break;
		//3 operand instructions
		case MIPS_DIV_S:
		case MIPS_DIV_D:
		case MIPS_MUL_S:
		case MIPS_MUL_D:
		case MIPS_MUL_PS:
		case MIPS_SUB_S:
		case MIPS_SUB_D:
		case MIPS_SUB_PS:
		case MIPS_PUU_PS:
		case MIPS_PUL_PS:
			INS_3(REG, ins.f.fd + FPREG_F0, REG, ins.f.fs + FPREG_F0, REG, ins.f.ft + FPREG_F0);
			break;
		case MIPS_ADD_S:
		case MIPS_ADD_D:
		case MIPS_ADD_PS:
		case MIPS_CVT_PS_S:
		case MIPS_PLU_PS:
		case MIPS_PLL_PS:
		case MIPS_SEL_D:
		case MIPS_SEL_S:
		case MIPS_MADDF_D:
		case MIPS_MADDF_S:
		case MIPS_MSUBF_D:
		case MIPS_MSUBF_S:
			INS_3(REG, ins.f.fd + FPREG_F0, REG, ins.f.fs + FPREG_F0, REG, ins.f.ft + FPREG_F0)
			break;
		case MIPS_MOVF:
		case MIPS_MOVT:
			INS_3(REG, ins.r.rd, REG, ins.r.rs, FLAG, (ins.r.rt>>2) + FPCCREG_FCC0)
			if (ins.r.sa != 0 || ins.bits.bit17 != 0)
				return 1;
			break;
		case MIPS_MOVF_S:
		case MIPS_MOVF_D:
		case MIPS_MOVF_PS:
		case MIPS_MOVT_S:
		case MIPS_MOVT_D:
		case MIPS_MOVT_PS:
			INS_3(REG, ins.f.fd + FPREG_F0, REG, ins.f.fs + FPREG_F0, FLAG, (ins.r.rt>>2) + FPCCREG_FCC0)
			if (ins.bits.bit17 != 0)
				return 1;
			break;
		case MIPS_MOVN_S:
		case MIPS_MOVN_D:
		case MIPS_MOVN_PS:
		case MIPS_MOVZ_S:
		case MIPS_MOVZ_D:
		case MIPS_MOVZ_PS:
			INS_3(REG, ins.f.fd + FPREG_F0, REG, ins.f.fs + FPREG_F0, REG, ins.r.rt)
			break;
		case MIPS_ADD:
		case MIPS_ADDU:
		case MIPS_AND:
		case MIPS_DADD:
		case MIPS_DADDU:
		case MIPS_DSUB:
		case MIPS_DSUBU:
		case MIPS_MOVN:
		case MIPS_MOVZ:
		case MIPS_NOR:
		case MIPS_OR:
		case MIPS_SLT:
		case MIPS_SLTU:
		case MIPS_SUB:
		case MIPS_SUBU:
		case MIPS_XOR:
		case MIPS_MUL:
			INS_3(REG, ins.r.rd, REG, ins.r.rs, REG, ins.r.rt)
			if (ins.r.sa != 0)
				return 1;
			break;
		case MIPS_ADDI:
		case MIPS_ADDIU:
		case MIPS_DADDI:
		case MIPS_DADDIU:
		case MIPS_SLTI:
		case MIPS_SLTIU:
			INS_3(REG, ins.i.rt, REG, ins.i.rs, IMM, ins.i.immediate)
			break;
		case MIPS_ANDI:
		case MIPS_ORI:
		case MIPS_XORI:
			INS_3(REG, ins.i.rt, REG, ins.i.rs, IMM, (ins.i.immediate & 0xffff))
			break;
		case MIPS_BEQ:
		case MIPS_BEQL:
		case MIPS_BNE:
		case MIPS_BNEL:
			INS_3(REG, ins.i.rs, REG, ins.i.rt, LABEL, (4 + address + (ins.i.immediate<<2)) & registerMask)
			break;
		case MIPS_ROTR:
		case MIPS_DROTR:
		case MIPS_DROTR32:
			INS_3(REG, ins.r.rd, REG, ins.r.rt, IMM, ins.r.sa)
			if (ins.r.rs != 1)
				return 1;
			break;
		case MIPS_DSLL:
		case MIPS_DSRA:
		case MIPS_DSRL:
		case MIPS_SLL:
		case MIPS_SRL:
		case MIPS_SRA:
			INS_3(REG, ins.r.rd, REG, ins.r.rt, IMM, ins.r.sa)
			if (ins.r.rs != 0)
				return 1;
			break;
		case MIPS_DSLL32:
		case MIPS_DSRA32:
		case MIPS_DSRL32:
			INS_3(REG, ins.r.rd, REG, ins.r.rt, IMM, ins.r.sa)
			if (ins.r.rs != 0)
				return 1;
			break;
		case MIPS_ROTRV:
		case MIPS_DROTRV:
			INS_3(REG, ins.r.rd, REG, ins.r.rt, REG, ins.r.rs)
			if (ins.r.sa != 1)
				return 1;
			break;
		case MIPS_SRLV:
		case MIPS_DSLLV:
		case MIPS_DSRAV:
		case MIPS_DSRLV:
		case MIPS_SLLV:
		case MIPS_SRAV:
			INS_3(REG, ins.r.rd, REG, ins.r.rt, REG, ins.r.rs)
			if (ins.r.sa != 0)
				return 1;
			break;
		case MIPS_DMFC0:
		case MIPS_DMTC0:
		case MIPS_MFC0:
		case MIPS_MTC0:
			INS_3(REG, ins.r.rt, IMM, ins.r.rd, IMM, (ins.r.function & 7))
			break;
		case MIPS_MADD_S:
		case MIPS_MADD_D:
		case MIPS_MADD_PS:
		case MIPS_MSUB_S:
		case MIPS_MSUB_D:
		case MIPS_MSUB_PS:
		case MIPS_NMADD_S:
		case MIPS_NMADD_D:
		case MIPS_NMADD_PS:
		case MIPS_NMSUB_S:
		case MIPS_NMSUB_D:
		case MIPS_NMSUB_PS:
			INS_4(REG, ins.f.fd + FPREG_F0,
				  REG, ins.f.fr + FPREG_F0,
				  REG, ins.f.fs + FPREG_F0,
				  REG, ins.f.ft + FPREG_F0);
			break;
		case MIPS_INS:
		case MIPS_DINS:
			INS_4(REG, ins.r.rt, REG, ins.r.rs, IMM, ins.r.sa, IMM, ((int32_t)ins.r.rd + 1) - ins.r.sa);
			break;
		case MIPS_DINSM:
			INS_4(REG, ins.r.rt, REG, ins.r.rs, IMM, ins.r.sa, IMM, ((int32_t)ins.r.rd + 33) - ins.r.sa);
			break;
		case MIPS_DINSU:
			INS_4(REG, ins.r.rt, REG, ins.r.rs, IMM, ins.r.sa + 32, IMM, ((int32_t)ins.r.rd + 1) - ins.r.sa);
			break;
		case MIPS_EXT:
		case MIPS_DEXT:
			INS_4(REG, ins.r.rt, REG, ins.r.rs, IMM, ins.r.sa, IMM, ins.r.rd + 1);
			break;
		case MIPS_DEXTM:
			INS_4(REG, ins.r.rt, REG, ins.r.rs, IMM, ins.r.sa, IMM, ins.r.rd + 33);
			break;
		case MIPS_DEXTU:
			INS_4(REG, ins.r.rt, REG, ins.r.rs, IMM, ins.r.sa + 32, IMM, ins.r.rd + 1);
			break;
		case MIPS_ALIGN:
			INS_4(REG, ins.r.rd, REG, ins.r.rs, REG, ins.r.rt, IMM, (ins.r.sa & 3));
			break;

		case CNMIPS_BADDU:
		case CNMIPS_DMUL:
		case CNMIPS_SEQ:
		case CNMIPS_SNE:
		case CNMIPS_V3MULU:
		case CNMIPS_VMM0:
		case CNMIPS_VMULU:
			INS_3(REG, ins.r.rd, REG, ins.r.rs, REG, ins.r.rt)
			if (ins.r.sa != 0)
				return 1;
			break;
		case CNMIPS_BBIT0:
		case CNMIPS_BBIT032:
		case CNMIPS_BBIT1:
		case CNMIPS_BBIT132:
			INS_3(REG, ins.i.rs, IMM, ins.i.rt, LABEL, (4 + address + (ins.i.immediate<<2)) & registerMask)
			break;
		case CNMIPS_CINS:
		case CNMIPS_CINS32:
		case CNMIPS_EXTS:
		case CNMIPS_EXTS32:
			INS_4(REG, ins.r.rt, REG, ins.r.rs, IMM, ins.r.sa, IMM, ins.r.rd)
			break;
		case CNMIPS_MTM0:
		case CNMIPS_MTM1:
		case CNMIPS_MTM2:
		case CNMIPS_MTP0:
		case CNMIPS_MTP1:
		case CNMIPS_MTP2:
			INS_1(REG, ins.r.rs)
			break;
		case CNMIPS_SAA:
		case CNMIPS_SAAD:
			instruction->operands[0].operandClass = REG;
			instruction->operands[1].operandClass = MEM_IMM;
			instruction->operands[0].reg = ins.i.rt;
			instruction->operands[1].reg = ins.i.rs;
			instruction->operands[1].immediate = 0;
			break;
		case CNMIPS_SEQI:
		case CNMIPS_SNEI:
		{
			uint32_t uimm = ins.decode.group1;

			uint32_t mask = 1u << (10 - 1);
			int32_t simm = (uimm ^ mask) - mask;

			INS_3(REG, ins.r.rt, REG, ins.r.rs, IMM, simm)
			break;
		}
		case CNMIPS_DPOP:
		case CNMIPS_POP:
			INS_2(REG, ins.r.rd, REG, ins.r.rs);
			break;

		case CNMIPS_RDHWR:
			INS_2(REG, ins.r.rt, IMM, ins.r.rd);
			break;

		case CNMIPS_SYNCIOBDMA:
		case CNMIPS_SYNCS:
		case CNMIPS_SYNCW:
		case CNMIPS_SYNCWS:
			break;

		case CNMIPS_ZCB:
		case CNMIPS_ZCBT:
			instruction->operands[0].operandClass = MEM_IMM;
			instruction->operands[0].reg = ins.i.rs;
			instruction->operands[0].immediate = 0;
			break;

		default:
			return 1;
	}
	return 0;
}

uint32_t mips_disassemble(
		Instruction* restrict instruction,
		char* outBuffer,
		uint32_t outBufferSize)
{
	char operands[MAX_OPERANDS][64] = {{0},{0},{0},{0}};
	char* operandPtr = NULL;
	for (uint32_t i = 0;
			i < MAX_OPERANDS && instruction->operands[i].operandClass != NONE; i++)
	{
		operandPtr = operands[i];
		if (i != 0)
		{
			*operandPtr++ = ',';
			*operandPtr++ = ' ';
		}
		switch(instruction->operands[i].operandClass)
		{
			case REG:
				if (instruction->operands[i].reg < END_REG)
					strcpy(operandPtr, RegisterStrings[instruction->operands[i].reg]);
				break;
			case HINT:
				if (instruction->operands[i].reg < HINT_END)
					strcpy(operandPtr, HintStrings[instruction->operands[i].reg]);
				break;
			case IMM:
			case LABEL:
				if (instruction->operands[i].immediate >= 0x80000000)
					snprintf(operandPtr, 64, "-%#x", -(int32_t)instruction->operands[i].immediate);
				else
					snprintf(operandPtr, 64, "%#" PRIx64 "", instruction->operands[i].immediate);
				break;
			case MEM_IMM:
				if (instruction->operands[i].immediate != 0)
				{
					if (instruction->operands[i].immediate >= 0x80000000)
					{
						snprintf(operandPtr, 64, "-%#x(%s)",
							-(int32_t)instruction->operands[i].immediate,
							RegisterStrings[instruction->operands[i].reg]);
					}
					else
					{
						snprintf(operandPtr, 64, "%#" PRIx64 "(%s)",
							instruction->operands[i].immediate,
							RegisterStrings[instruction->operands[i].reg]);
					}
				}
				else
				{
					snprintf(operandPtr, 64, "(%s)", RegisterStrings[instruction->operands[i].reg]);
				}
				break;
			case MEM_REG:
				snprintf(operandPtr, 64, "%s(%s)",
					RegisterStrings[instruction->operands[i].immediate],
					RegisterStrings[instruction->operands[i].reg]);
				break;
		}
	}
	if (instruction->operation != MIPS_INVALID && instruction->operation < MIPS_OPERATION_END)
	{
		snprintf(outBuffer, outBufferSize, "%s\t%s%s%s%s",
				OperationStrings[instruction->operation],
				operands[0],
				operands[1],
				operands[2],
				operands[3]);
		return 0;
	}
	return 1;
}


// flags: see DECOMPOSE_FLAGS_*
uint32_t mips_decompose(
		const uint32_t* instructionValue,
		size_t size,
		Instruction* restrict instruction,
		uint32_t version,
		uint64_t address,
		uint32_t endianBig,
		uint32_t flags)
{
	combined ins;
	if (instructionValue == NULL)
		return 1;

	if (endianBig == 1)
		ins.value = bswap32(instructionValue[0]);
	else
		ins.value = instructionValue[0];

	uint32_t result = mips_decompose_instruction(ins, instruction, version, address, flags);
	if (result != 0)
		return result;
	instruction->size = 4;
	//look for peudoinstructions by disassembling the next instruction too
	if ((flags & DECOMPOSE_FLAGS_PSEUDO_OP) && size >= 8)
	{
		if (endianBig == 1)
			ins.value = bswap32(instructionValue[1]);
		else
			ins.value = instructionValue[1];
		Instruction instruction2;
		if (instruction->operation == MIPS_LUI)
		{
			result = mips_decompose_instruction(ins, &instruction2, version, address+4, flags);
			if (result != 0)
			{
				return result;
			}
			if (instruction->operands[0].reg == instruction2.operands[0].reg &&
				instruction->operands[0].reg == instruction2.operands[1].reg)
			{
				if (instruction2.operation == MIPS_ADDIU)
				{
					instruction->operation = MIPS_LI;
					instruction->operands[1].immediate = (instruction->operands[1].immediate << 16) + instruction2.operands[2].immediate;
				}
				else if (instruction2.operation == MIPS_ORI)
				{
					instruction->operation = MIPS_LI;
					instruction->operands[1].immediate = (instruction->operands[1].immediate << 16) | (instruction2.operands[2].immediate & 0xffff);
				}
				else if (instruction2.operation == MIPS_LW)
				{
					instruction->operation = MIPS_LW;
					instruction->operands[1].operandClass = MEM_IMM;
					instruction->operands[1].immediate = (instruction->operands[1].immediate << 16) + instruction2.operands[1].immediate;
				}
				else if (instruction2.operation == MIPS_SW)
				{
					instruction->operation = MIPS_SW;
					instruction->operands[1].operandClass = MEM_IMM;
					instruction->operands[1].immediate = (instruction->operands[1].immediate << 16) + instruction2.operands[1].immediate;
				}
				else
					return 0;

				instruction->size = 8;
			}
		}
	}
	return result;
}
