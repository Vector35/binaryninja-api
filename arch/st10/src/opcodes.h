// Copyright (c) 2025. Battelle Energy Alliance, LLC
// ALL RIGHTS RESERVED

#ifndef OPCODES_H
#define OPCODES_H

#include <cstdint>

namespace C166::Opcodes {
constexpr uint8_t ADD_RWN_RWM = 0x00;
constexpr uint8_t ADD_REG_MEM = 0x02;
constexpr uint8_t ADD_MEM_REG = 0x04;
constexpr uint8_t ADD_REG_DATA16 = 0x06;
constexpr uint8_t ADD_RWN_RWI_DATA3 = 0x08;

constexpr uint8_t ADDB_RBN_RBM = 0x01;
constexpr uint8_t ADDB_REG_MEM = 0x03;
constexpr uint8_t ADDB_MEM_REG = 0x05;
constexpr uint8_t ADDB_REG_DATA8 = 0x07;
constexpr uint8_t ADDB_RBN_RWI_DATA3 = 0x09;

constexpr uint8_t ADDC_RWN_RWM = 0x10;
constexpr uint8_t ADDC_REG_MEM = 0x12;
constexpr uint8_t ADDC_MEM_REG = 0x14;
constexpr uint8_t ADDC_REG_DATA16 = 0x16;
constexpr uint8_t ADDC_RWN_RWI_DATA3 = 0x18;

constexpr uint8_t ADDCB_RBN_RBM = 0x11;
constexpr uint8_t ADDCB_REG_MEM = 0x13;
constexpr uint8_t ADDCB_MEM_REG = 0x15;
constexpr uint8_t ADDCB_REG_DATA8 = 0x17;
constexpr uint8_t ADDCB_RBN_RWI_DATA3 = 0x19;

constexpr uint8_t AND_RWN_RWM = 0x60;
constexpr uint8_t AND_REG_MEM = 0x62;
constexpr uint8_t AND_MEM_REG = 0x64;
constexpr uint8_t AND_REG_DATA16 = 0x66;
constexpr uint8_t AND_RWN_RWI_DATA3 = 0x68;

constexpr uint8_t ANDB_RBN_RBM = 0x61;
constexpr uint8_t ANDB_REG_MEM = 0x63;
constexpr uint8_t ANDB_MEM_REG = 0x65;
constexpr uint8_t ANDB_REG_DATA8 = 0x67;
constexpr uint8_t ANDB_RBN_RWI_DATA3 = 0x69;

constexpr uint8_t ASHR_RWN_RWM = 0xAC;
constexpr uint8_t ASHR_RWN_DATA4 = 0xBC;

constexpr uint8_t BAND = 0x6A;

constexpr uint8_t BCLR_0 = 0x0E;
constexpr uint8_t BCLR_1 = 0x1E;
constexpr uint8_t BCLR_2 = 0x2E;
constexpr uint8_t BCLR_3 = 0x3E;
constexpr uint8_t BCLR_4 = 0x4E;
constexpr uint8_t BCLR_5 = 0x5E;
constexpr uint8_t BCLR_6 = 0x6E;
constexpr uint8_t BCLR_7 = 0x7E;
constexpr uint8_t BCLR_8 = 0x8E;
constexpr uint8_t BCLR_9 = 0x9E;
constexpr uint8_t BCLR_A = 0xAE;
constexpr uint8_t BCLR_B = 0xBE;
constexpr uint8_t BCLR_C = 0xCE;
constexpr uint8_t BCLR_D = 0xDE;
constexpr uint8_t BCLR_E = 0xEE;
constexpr uint8_t BCLR_F = 0xFE;

constexpr uint8_t BCMP = 0x2A;

constexpr uint8_t BFLDH = 0x1A;
constexpr uint8_t BFLDL = 0x0A;

constexpr uint8_t BMOV = 0x4A;

constexpr uint8_t BMOVN = 0x3A;

constexpr uint8_t BOR = 0x5A;

constexpr uint8_t BSET_0 = 0x0F;
constexpr uint8_t BSET_1 = 0x1F;
constexpr uint8_t BSET_2 = 0x2F;
constexpr uint8_t BSET_3 = 0x3F;
constexpr uint8_t BSET_4 = 0x4F;
constexpr uint8_t BSET_5 = 0x5F;
constexpr uint8_t BSET_6 = 0x6F;
constexpr uint8_t BSET_7 = 0x7F;
constexpr uint8_t BSET_8 = 0x8F;
constexpr uint8_t BSET_9 = 0x9F;
constexpr uint8_t BSET_A = 0xAF;
constexpr uint8_t BSET_B = 0xBF;
constexpr uint8_t BSET_C = 0xCF;
constexpr uint8_t BSET_D = 0xDF;
constexpr uint8_t BSET_E = 0xEF;
constexpr uint8_t BSET_F = 0xFF;

constexpr uint8_t BXOR = 0x7A;

constexpr uint8_t CALLA = 0xCA;

constexpr uint8_t CALLI = 0xAB;

constexpr uint8_t CALLR = 0xBB;

constexpr uint8_t CALLS = 0xDA;

constexpr uint8_t CMP_RWN_RWM = 0x40;
constexpr uint8_t CMP_REG_MEM = 0x42;
constexpr uint8_t CMP_REG_DATA16 = 0x46;
constexpr uint8_t CMP_RWN_RWI_DATA3 = 0x48;

constexpr uint8_t CMPB_RBN_RBM = 0x41;
constexpr uint8_t CMPB_REG_MEM = 0x43;
constexpr uint8_t CMPB_REG_DATA8 = 0x47;
constexpr uint8_t CMPB_RBN_RWI_DATA3 = 0x49;

constexpr uint8_t CMPD1_RWN_DATA4 = 0xA0;
constexpr uint8_t CMPD1_RWN_MEM = 0xA2;
constexpr uint8_t CMPD1_RWN_DATA16 = 0xA6;

constexpr uint8_t CMPD2_RWN_DATA4 = 0xB0;
constexpr uint8_t CMPD2_RWN_MEM = 0xB2;
constexpr uint8_t CMPD2_RWN_DATA16 = 0xB6;

constexpr uint8_t CMPI1_RWN_DATA4 = 0x80;
constexpr uint8_t CMPI1_RWN_MEM = 0x82;
constexpr uint8_t CMPI1_RWN_DATA16 = 0x86;

constexpr uint8_t CMPI2_RWN_DATA4 = 0x90;
constexpr uint8_t CMPI2_RWN_MEM = 0x92;
constexpr uint8_t CMPI2_RWN_DATA16 = 0x96;

constexpr uint8_t CPL = 0x91;

constexpr uint8_t CPLB = 0xB1;

constexpr uint8_t DISWDT = 0xA5;

constexpr uint8_t DIV = 0x4B;

constexpr uint8_t DIVL = 0x6B;

constexpr uint8_t DIVLU = 0x7B;

constexpr uint8_t DIVU = 0x5B;

constexpr uint8_t EINIT = 0xB5;

constexpr uint8_t EXTPRS_PAG_SEG_COUNT = 0xD7;
constexpr uint8_t EXTPRS_RWM_COUNT = 0xDC;

constexpr uint8_t EXTR_ATOMIC = 0xD1;

constexpr uint8_t IDLE = 0x87;

constexpr uint8_t JB = 0x8A;

constexpr uint8_t JBC = 0xAA;

constexpr uint8_t JMPI = 0x9C;

constexpr uint8_t JMPA = 0xEA;

constexpr uint8_t JMPR_UC = 0x0D;
constexpr uint8_t JMPR_NET = 0x1D;
constexpr uint8_t JMPR_Z = 0x2D;
constexpr uint8_t JMPR_NZ = 0x3D;
constexpr uint8_t JMPR_V = 0x4D;
constexpr uint8_t JMPR_NV = 0x5D;
constexpr uint8_t JMPR_N = 0x6D;
constexpr uint8_t JMPR_NN = 0x7D;
constexpr uint8_t JMPR_ULT = 0x8D;
constexpr uint8_t JMPR_SGT = 0x9D;
constexpr uint8_t JMPR_UGE = 0xAD;
constexpr uint8_t JMPR_SLE = 0xBD;
constexpr uint8_t JMPR_SLT = 0xCD;
constexpr uint8_t JMPR_SGE = 0xDD;
constexpr uint8_t JMPR_UGT = 0xED;
constexpr uint8_t JMPR_ULE = 0xFD;

constexpr uint8_t JMPS = 0xFA;

constexpr uint8_t JNB = 0x9A;

constexpr uint8_t JNBS = 0xBA;

constexpr uint8_t MOV_RWN_RWM = 0xF0;
constexpr uint8_t MOV_RWN_DATA4 = 0xE0;
constexpr uint8_t MOV_REG_DATA16 = 0xE6;
constexpr uint8_t MOV_RWN_REF_RWM = 0xA8;
constexpr uint8_t MOV_RWN_REF_POST_INC_RWM = 0x98;
constexpr uint8_t MOV_REF_RWM_RWN = 0xB8;
constexpr uint8_t MOV_REF_PRE_DEC_RWM_RWN = 0x88;
constexpr uint8_t MOV_REF_RWN_REF_RWM = 0xC8;
constexpr uint8_t MOV_REF_POST_INC_RWN_REF_RWM = 0xD8;
constexpr uint8_t MOV_REF_RWN_REF_POST_INC_RWM = 0xE8;
constexpr uint8_t MOV_RWN_REF_RWM_DATA16 = 0xD4;
constexpr uint8_t MOV_REF_RWM_DATA16_RWN = 0xC4;
constexpr uint8_t MOV_REF_RWN_MEM = 0x84;
constexpr uint8_t MOV_MEM_REF_RWN = 0x94;
constexpr uint8_t MOV_REG_MEM = 0xF2;
constexpr uint8_t MOV_MEM_REG = 0xF6;

constexpr uint8_t MOVB_RBN_RBM = 0xF1;
constexpr uint8_t MOVB_RBN_DATA4 = 0xE1;
constexpr uint8_t MOVB_REG_DATA8 = 0xE7;
constexpr uint8_t MOVB_RBN_REF_RWM = 0xA9;
constexpr uint8_t MOVB_RBN_REF_POST_INC_RWM = 0x99;
constexpr uint8_t MOVB_REF_RWM_RBN = 0xB9;
constexpr uint8_t MOVB_REF_PRE_DEC_RWM_RBN = 0x89;
constexpr uint8_t MOVB_REF_RWN_REF_RWM = 0xC9;
constexpr uint8_t MOVB_REF_POST_INC_RWN_REF_RWM = 0xD9;
constexpr uint8_t MOVB_REF_RWN_REF_POST_INC_RWM = 0xE9;
constexpr uint8_t MOVB_RBN_REF_RWM_DATA16 = 0xF4;
constexpr uint8_t MOVB_REF_RWM_DATA16_RBN = 0xE4;
constexpr uint8_t MOVB_REF_RWN_MEM = 0xA4;
constexpr uint8_t MOVB_MEM_REF_RWN = 0xB4;
constexpr uint8_t MOVB_REG_MEM = 0xF3;
constexpr uint8_t MOVB_MEM_REG = 0xF7;

constexpr uint8_t MOVBS_RWN_RBM = 0xD0;
constexpr uint8_t MOVBS_REG_MEM = 0xD2;
constexpr uint8_t MOVBS_MEM_REG = 0xD5;

constexpr uint8_t MOVBZ_RWN_RBM = 0xC0;
constexpr uint8_t MOVBZ_REG_MEM = 0xC2;
constexpr uint8_t MOVBZ_MEM_REG = 0xC5;

constexpr uint8_t MUL = 0x0B;

constexpr uint8_t MULU = 0x1B;

constexpr uint8_t NEG = 0x81;

constexpr uint8_t NEGB = 0xA1;

constexpr uint8_t NOP = 0xCC;

constexpr uint8_t OR_RWN_RWM = 0x70;
constexpr uint8_t OR_RWN_RWI_DATA3 = 0x78;
constexpr uint8_t OR_REG_DATA16 = 0x76;
constexpr uint8_t OR_REG_MEM = 0x72;
constexpr uint8_t OR_MEM_REG = 0x74;

constexpr uint8_t ORB_RBN_RBM = 0x71;
constexpr uint8_t ORB_RBN_RWI_DATA3 = 0x79;
constexpr uint8_t ORB_REG_DATA8 = 0x77;
constexpr uint8_t ORB_REG_MEM = 0x73;
constexpr uint8_t ORB_MEM_REG = 0x75;

constexpr uint8_t PCALL = 0xE2;

constexpr uint8_t POP = 0xFC;

constexpr uint8_t PRIOR = 0x2B;

constexpr uint8_t PUSH = 0xEC;

constexpr uint8_t PWRDN = 0x97;

constexpr uint8_t RET = 0xCB;

constexpr uint8_t RETI = 0xFB;

constexpr uint8_t RETP = 0xEB;

constexpr uint8_t RETS = 0xDB;

constexpr uint8_t ROL_RWN_RWM = 0x0C;
constexpr uint8_t ROL_RWN_DATA4 = 0x1C;

constexpr uint8_t ROR_RWN_RWM = 0x2C;
constexpr uint8_t ROR_RWN_DATA4 = 0x3C;

constexpr uint8_t SCXT_REG_DATA16 = 0xC6;
constexpr uint8_t SCXT_REG_MEM = 0xD6;

constexpr uint8_t SHL_RWN_RWM = 0x4C;
constexpr uint8_t SHL_RWN_DATA4 = 0x5C;

constexpr uint8_t SHR_RWN_RWM = 0x6C;
constexpr uint8_t SHR_RWN_DATA4 = 0x7C;

constexpr uint8_t SRST = 0xB7;

constexpr uint8_t SRVWDT = 0xA7;

constexpr uint8_t SUB_RWN_RWM = 0x20;
constexpr uint8_t SUB_RWN_RWI_DATA3 = 0x28;
constexpr uint8_t SUB_REG_DATA16 = 0x26;
constexpr uint8_t SUB_REG_MEM = 0x22;
constexpr uint8_t SUB_MEM_REG = 0x24;

constexpr uint8_t SUBB_RBN_RBM = 0x21;
constexpr uint8_t SUBB_RBN_RWI_DATA3 = 0x29;
constexpr uint8_t SUBB_REG_DATA8 = 0x27;
constexpr uint8_t SUBB_REG_MEM = 0x23;
constexpr uint8_t SUBB_MEM_REG = 0x25;

constexpr uint8_t SUBC_RWN_RWM = 0x30;
constexpr uint8_t SUBC_RWN_RWI_DATA3 = 0x38;
constexpr uint8_t SUBC_REG_DATA16 = 0x36;
constexpr uint8_t SUBC_REG_MEM = 0x32;
constexpr uint8_t SUBC_MEM_REG = 0x34;

constexpr uint8_t SUBCB_RBN_RBM = 0x31;
constexpr uint8_t SUBCB_RBN_RWI_DATA3 = 0x39;
constexpr uint8_t SUBCB_REG_DATA8 = 0x37;
constexpr uint8_t SUBCB_REG_MEM = 0x33;
constexpr uint8_t SUBCB_MEM_REG = 0x35;

constexpr uint8_t TRAP = 0x9B;

constexpr uint8_t XOR_RWN_RWM = 0x50;
constexpr uint8_t XOR_RWN_RWI_DATA3 = 0x58;
constexpr uint8_t XOR_REG_DATA16 = 0x56;
constexpr uint8_t XOR_REG_MEM = 0x52;
constexpr uint8_t XOR_MEM_REG = 0x54;

constexpr uint8_t XORB_RBN_RBM = 0x51;
constexpr uint8_t XORB_RBN_RWI_DATA3 = 0x59;
constexpr uint8_t XORB_REG_DATA8 = 0x57;
constexpr uint8_t XORB_REG_MEM = 0x53;
constexpr uint8_t XORB_MEM_REG = 0x55;
}  // namespace C166::Opcodes

#endif  // OPCODES_H
