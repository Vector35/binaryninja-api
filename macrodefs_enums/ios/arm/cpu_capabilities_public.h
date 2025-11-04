// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/arm/cpu_capabilities_public.h

enum macro_arm_cpu_capabilities {
/*
 * Clang needs those bits to remain constant.
 * Existing entries should never be updated as they are ABI.
 * Adding new entries to the end and bumping CAP_BIT_NB is okay.
 */
/*line: 49*/    CAP_BIT_FEAT_FlagM = 0x0,  // 0
/*line: 50*/    CAP_BIT_FEAT_FlagM2 = 0x1,  // 1
/*line: 51*/    CAP_BIT_FEAT_FHM = 0x2,  // 2
/*line: 52*/    CAP_BIT_FEAT_DotProd = 0x3,  // 3
/*line: 53*/    CAP_BIT_FEAT_SHA3 = 0x4,  // 4
/*line: 54*/    CAP_BIT_FEAT_RDM = 0x5,  // 5
/*line: 55*/    CAP_BIT_FEAT_LSE = 0x6,  // 6
/*line: 56*/    CAP_BIT_FEAT_SHA256 = 0x7,  // 7
/*line: 57*/    CAP_BIT_FEAT_SHA512 = 0x8,  // 8
/*line: 58*/    CAP_BIT_FEAT_SHA1 = 0x9,  // 9
/*line: 59*/    CAP_BIT_FEAT_AES = 0xa,  // 10
/*line: 60*/    CAP_BIT_FEAT_PMULL = 0xb,  // 11
/*line: 61*/    CAP_BIT_FEAT_SPECRES = 0xc,  // 12
/*line: 62*/    CAP_BIT_FEAT_SB = 0xd,  // 13
/*line: 63*/    CAP_BIT_FEAT_FRINTTS = 0xe,  // 14
/*line: 64*/    CAP_BIT_FEAT_LRCPC = 0xf,  // 15
/*line: 65*/    CAP_BIT_FEAT_LRCPC2 = 0x10,  // 16
/*line: 66*/    CAP_BIT_FEAT_FCMA = 0x11,  // 17
/*line: 67*/    CAP_BIT_FEAT_JSCVT = 0x12,  // 18
/*line: 68*/    CAP_BIT_FEAT_PAuth = 0x13,  // 19
/*line: 69*/    CAP_BIT_FEAT_PAuth2 = 0x14,  // 20
/*line: 70*/    CAP_BIT_FEAT_FPAC = 0x15,  // 21
/*line: 71*/    CAP_BIT_FEAT_DPB = 0x16,  // 22
/*line: 72*/    CAP_BIT_FEAT_DPB2 = 0x17,  // 23
/*line: 73*/    CAP_BIT_FEAT_BF16 = 0x18,  // 24
/*line: 74*/    CAP_BIT_FEAT_I8MM = 0x19,  // 25
/*line: 75*/    CAP_BIT_FEAT_WFxT = 0x1a,  // 26
/*line: 76*/    CAP_BIT_FEAT_RPRES = 0x1b,  // 27
/*line: 77*/    CAP_BIT_FEAT_ECV = 0x1c,  // 28
/*line: 78*/    CAP_BIT_FEAT_AFP = 0x1d,  // 29
/*line: 79*/    CAP_BIT_FEAT_LSE2 = 0x1e,  // 30
/*line: 80*/    CAP_BIT_FEAT_CSV2 = 0x1f,  // 31
/*line: 81*/    CAP_BIT_FEAT_CSV3 = 0x20,  // 32
/*line: 82*/    CAP_BIT_FEAT_DIT = 0x21,  // 33
/*line: 83*/    CAP_BIT_FEAT_FP16 = 0x22,  // 34
/*line: 84*/    CAP_BIT_FEAT_SSBS = 0x23,  // 35
/*line: 85*/    CAP_BIT_FEAT_BTI = 0x24,  // 36
/* SME */
/*line: 89*/    CAP_BIT_FEAT_SME = 0x28,  // 40
/*line: 90*/    CAP_BIT_FEAT_SME2 = 0x29,  // 41
/*line: 91*/    CAP_BIT_FEAT_SME_F64F64 = 0x2a,  // 42
/*line: 92*/    CAP_BIT_FEAT_SME_I16I64 = 0x2b,  // 43
/*line: 94*/    CAP_BIT_AdvSIMD = 0x31,  // 49
/*line: 95*/    CAP_BIT_AdvSIMD_HPFPCvt = 0x32,  // 50
/*line: 96*/    CAP_BIT_FEAT_CRC32 = 0x33,  // 51
/*line: 98*/    CAP_BIT_SME_F32F32 = 0x34,  // 52
/*line: 99*/    CAP_BIT_SME_BI32I32 = 0x35,  // 53
/*line: 100*/   CAP_BIT_SME_B16F32 = 0x36,  // 54
/*line: 101*/   CAP_BIT_SME_F16F32 = 0x37,  // 55
/*line: 102*/   CAP_BIT_SME_I8I32 = 0x38,  // 56
/*line: 103*/   CAP_BIT_SME_I16I32 = 0x39,  // 57
/*line: 105*/   CAP_BIT_FEAT_PACIMP = 0x3a,  // 58
/*line: 108*/   CAP_BIT_FEAT_HBC = 0x40,  // 64
/*line: 109*/   CAP_BIT_FEAT_EBF16 = 0x41,  // 65
/*line: 110*/   CAP_BIT_FEAT_SPECRES2 = 0x42,  // 66
/*line: 111*/   CAP_BIT_FEAT_CSSC = 0x43,  // 67
/*line: 112*/   CAP_BIT_FEAT_FPACCOMBINE = 0x44,  // 68
/*line: 115*/   CAP_BIT_FP_SyncExceptions = 0x49,  // 73
/* Legacy definitions for backwards compatibility */
/*line: 118*/   CAP_BIT_CRC32 = 0x33,  // CAP_BIT_FEAT_CRC32
/* Total number of FEAT bits. */
/*line: 121*/   CAP_BIT_NB = 0x4a,  // 74
};

