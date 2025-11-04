// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/arm/thread_status.h

// Depends on identifiers
enum macro_thread_state_flavor {
/*
 *  Flavors
 */
/*line: 53*/    ARM_THREAD_STATE = 0x1,  // 1
/*line: 54*/    ARM_UNIFIED_THREAD_STATE = 0x1,  // ARM_THREAD_STATE
/*line: 55*/    ARM_VFP_STATE = 0x2,  // 2
/*line: 56*/    ARM_EXCEPTION_STATE = 0x3,  // 3
/*line: 57*/    ARM_DEBUG_STATE = 0x4, /* pre-armv8 */ // 4
/*line: 58*/    THREAD_STATE_NONE = 0x5,  // 5
/*line: 59*/    ARM_THREAD_STATE64 = 0x6,  // 6
/*line: 60*/    ARM_EXCEPTION_STATE64 = 0x7,  // 7
//      ARM_THREAD_STATE_LAST    8 /* legacy */
/*line: 62*/    ARM_THREAD_STATE32 = 0x9,  // 9
/*line: 63*/    ARM_EXCEPTION_STATE64_V2 = 0xa,  // 10
};

enum macro_arm_states {
/* API */
/*line: 67*/    ARM_DEBUG_STATE32 = 0xe,  // 14
/*line: 68*/    ARM_DEBUG_STATE64 = 0xf,  // 15
/*line: 69*/    ARM_NEON_STATE = 0x10,  // 16
/*line: 70*/    ARM_NEON_STATE64 = 0x11,  // 17
/*line: 71*/    ARM_CPMU_STATE64 = 0x12,  // 18
/*line: 74*/    ARM_PAGEIN_STATE = 0x1b,  // 27
/* API */
/*line: 77*/    ARM_SME_STATE = 0x1c,  // 28
/*line: 78*/    ARM_SVE_Z_STATE1 = 0x1d,  // 29
/*line: 79*/    ARM_SVE_Z_STATE2 = 0x1e,  // 30
/*line: 80*/    ARM_SVE_P_STATE = 0x1f,  // 31
/*line: 81*/    ARM_SME_ZA_STATE1 = 0x20,  // 32
/*line: 82*/    ARM_SME_ZA_STATE2 = 0x21,  // 33
/*line: 83*/    ARM_SME_ZA_STATE3 = 0x22,  // 34
/*line: 84*/    ARM_SME_ZA_STATE4 = 0x23,  // 35
/*line: 85*/    ARM_SME_ZA_STATE5 = 0x24,  // 36
/*line: 86*/    ARM_SME_ZA_STATE6 = 0x25,  // 37
/*line: 87*/    ARM_SME_ZA_STATE7 = 0x26,  // 38
/*line: 88*/    ARM_SME_ZA_STATE8 = 0x27,  // 39
/*line: 89*/    ARM_SME_ZA_STATE9 = 0x28,  // 40
/*line: 90*/    ARM_SME_ZA_STATE10 = 0x29,  // 41
/*line: 91*/    ARM_SME_ZA_STATE11 = 0x2a,  // 42
/*line: 92*/    ARM_SME_ZA_STATE12 = 0x2a,  // 42
/*line: 93*/    ARM_SME_ZA_STATE13 = 0x2c,  // 44
/*line: 94*/    ARM_SME_ZA_STATE14 = 0x2d,  // 45
/*line: 95*/    ARM_SME_ZA_STATE15 = 0x2e,  // 46
/*line: 96*/    ARM_SME_ZA_STATE16 = 0x2f,  // 47
/*line: 97*/    ARM_SME2_STATE = 0x30,  // 48
};

enum macro_thread_state_flavors {
/*line: 99*/    THREAD_STATE_FLAVORS = 0x32, /* This must be updated to 1 more than the highest numerical state flavor */ // 50
};

// Depends on identifiers
enum macro_thread_state {
/*line: 292*/   MACHINE_THREAD_STATE = 0x1,  // ARM_THREAD_STATE
};

// Depends on identifiers
enum macro_thread_state_max {
/*
 * Largest state on this machine:
 */
/*line: 299*/   THREAD_MACHINE_STATE_MAX = 0x510,  // THREAD_STATE_MAX
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 199
// #define ts_32 uts.ts_32

// Line: 200
// #define ts_64 uts.ts_64

// Line: 203
// #define ARM_THREAD_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_thread_state_t)/sizeof(uint32_t)))

// Line: 205
// #define ARM_THREAD_STATE32_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_thread_state32_t)/sizeof(uint32_t)))

// Line: 207
// #define ARM_THREAD_STATE64_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_thread_state64_t)/sizeof(uint32_t)))

// Line: 209
// #define ARM_UNIFIED_THREAD_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_unified_thread_state_t)/sizeof(uint32_t)))

// Line: 247
// #define ARM_VFP_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_vfp_state_t)/sizeof(uint32_t)))

// Line: 250
// #define ARM_EXCEPTION_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_exception_state_t)/sizeof(uint32_t)))

// Line: 253
// #define ARM_EXCEPTION_STATE64_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_exception_state64_t)/sizeof(uint32_t)))

// Line: 256
// #define ARM_EXCEPTION_STATE64_V2_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_exception_state64_v2_t)/sizeof(uint32_t)))

// Line: 259
// #define ARM_DEBUG_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_debug_state_t)/sizeof(uint32_t)))

// Line: 262
// #define ARM_DEBUG_STATE32_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_debug_state32_t)/sizeof(uint32_t)))

// Line: 265
// #define ARM_PAGEIN_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_pagein_state_t)/sizeof(uint32_t)))

// Line: 268
// #define ARM_DEBUG_STATE64_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_debug_state64_t)/sizeof(uint32_t)))

// Line: 271
// #define ARM_NEON_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_neon_state_t)/sizeof(uint32_t)))

// Line: 274
// #define ARM_NEON_STATE64_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_neon_state64_t)/sizeof(uint32_t)))

// Line: 277
// #define ARM_SME_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_sme_state_t)/sizeof(uint32_t)))

// Line: 280
// #define ARM_SVE_Z_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_sve_z_state_t)/sizeof(uint32_t)))

// Line: 283
// #define ARM_SVE_P_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_sve_p_state_t)/sizeof(uint32_t)))

// Line: 286
// #define ARM_SME_ZA_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_sme_za_state_t)/sizeof(uint32_t)))

// Line: 289
// #define ARM_SME2_STATE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (arm_sme2_state_t)/sizeof(uint32_t)))

// Line: 293
// #define MACHINE_THREAD_STATE_COUNT ARM_UNIFIED_THREAD_STATE_COUNT

