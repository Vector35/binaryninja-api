// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/arm/exception.h

enum macro_exception_count {
/*line: 34*/    EXC_TYPES_COUNT = 0xe, /* incl. illegal exception 0 */ // 14
};

enum macro_exception_codes {
/*line: 36*/    EXC_MASK_MACHINE = 0x0,  // 0
/*line: 38*/    EXCEPTION_CODE_MAX = 0x2, /*  code and subcode */ // 2
/*
 *      EXC_BAD_INSTRUCTION
 */
/*line: 49*/    EXC_ARM_UNDEFINED = 0x1, /* Undefined */ // 1
/*line: 50*/    EXC_ARM_SME_DISALLOWED = 0x2, /* Current thread state prohibits use of SME resources */ // 2
};

enum macro_arm_exceptions {
/*
 *      EXC_ARITHMETIC
 */
/*line: 56*/    EXC_ARM_FP_UNDEFINED = 0x0, /* Undefined Floating Point Exception */ // 0
/*line: 57*/    EXC_ARM_FP_IO = 0x1, /* Invalid Floating Point Operation */ // 1
/*line: 58*/    EXC_ARM_FP_DZ = 0x2, /* Floating Point Divide by Zero */ // 2
/*line: 59*/    EXC_ARM_FP_OF = 0x3, /* Floating Point Overflow */ // 3
/*line: 60*/    EXC_ARM_FP_UF = 0x4, /* Floating Point Underflow */ // 4
/*line: 61*/    EXC_ARM_FP_IX = 0x5, /* Inexact Floating Point Result */ // 5
/*line: 62*/    EXC_ARM_FP_ID = 0x6, /* Floating Point Denormal Input */ // 6
/*
 *      EXC_BAD_ACCESS
 *      Note: do not conflict with kern_return_t values returned by vm_fault
 */
/*line: 69*/    EXC_ARM_DA_ALIGN = 0x101, /* Alignment Fault */ // 0x101
/*line: 70*/    EXC_ARM_DA_DEBUG = 0x102, /* Debug (watch/break) Fault */ // 0x102
/*line: 71*/    EXC_ARM_SP_ALIGN = 0x103, /* SP Alignment Fault */ // 0x103
/*line: 72*/    EXC_ARM_SWP = 0x104, /* SWP instruction */ // 0x104
/*line: 73*/    EXC_ARM_PAC_FAIL = 0x105, /* PAC authentication failure */ // 0x105
};

enum macro_breakpoint_trap {
/*
 *	EXC_BREAKPOINT
 */
/*line: 80*/    EXC_ARM_BREAKPOINT = 0x1, /* breakpoint trap */ // 1
};

