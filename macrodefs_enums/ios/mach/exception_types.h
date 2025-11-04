// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/exception_types.h

enum macro_exception_codes {
/*
 *	Machine-independent exception definitions.
 */
/*line: 68*/    EXC_BAD_ACCESS = 0x1, /* Could not access memory */ // 1
/* Subcode contains bad memory address. */
/*line: 72*/    EXC_BAD_INSTRUCTION = 0x2, /* Instruction failed */ // 2
/* Illegal or undefined instruction or operand */
/*line: 75*/    EXC_ARITHMETIC = 0x3, /* Arithmetic exception */ // 3
/* Exact nature of exception is in code field */
/*line: 78*/    EXC_EMULATION = 0x4, /* Emulation instruction */ // 4
/* Details in code and subcode fields	*/
/*line: 82*/    EXC_SOFTWARE = 0x5, /* Software generated exception */ // 5
/* Codes 0x10000 - 0x1FFFF reserved for OS emulation (Unix) */
/*line: 87*/    EXC_BREAKPOINT = 0x6, /* Trace, breakpoint, etc. */ // 6
/* Details in code field. */
/*line: 90*/    EXC_SYSCALL = 0x7, /* System calls. */ // 7
/*line: 92*/    EXC_MACH_SYSCALL = 0x8, /* Mach system calls. */ // 8
/*line: 94*/    EXC_RPC_ALERT = 0x9, /* RPC alert */ // 9
/*line: 96*/    EXC_CRASH = 0xa, /* Abnormal process exit */ // 10
/*line: 98*/    EXC_RESOURCE = 0xb, /* Hit resource consumption limit */ // 11
/* Exact resource is in code field. */
/*line: 101*/   EXC_GUARD = 0xc, /* Violated guarded resource protections */ // 12
/*line: 103*/   EXC_CORPSE_NOTIFY = 0xd, /* Abnormal process exited to corpse state */ // 13
};

enum macro_exception_behavior {
/*
 *	Machine-independent exception behaviors
 */
/*line: 110*/   EXCEPTION_DEFAULT = 0x1,  // 1
/*	Send a catch_exception_raise message including the identity.
 */
/*line: 114*/   EXCEPTION_STATE = 0x2,  // 2
/*	Send a catch_exception_raise_state message including the
 *	thread state.
 */
/*line: 119*/   EXCEPTION_STATE_IDENTITY = 0x3,  // 3
/*	Send a catch_exception_raise_state_identity message including
 *	the thread identity and state.
 */
/*line: 124*/   EXCEPTION_IDENTITY_PROTECTED = 0x4,  // 4
/*	Send a catch_exception_raise_identity_protected message including protected task
 *  and thread identity.
 */
/*line: 129*/   EXCEPTION_STATE_IDENTITY_PROTECTED = 0x5,  // 5
};

// Depends on identifiers
enum macro_mach_exception {
/*	Send a catch_exception_raise_state_identity_protected message including protected task
 *  and thread identity plus the thread state.
 */
/*line: 134*/   MACH_EXCEPTION_BACKTRACE_PREFERRED = 0x20000000,  // 0x20000000
/* Prefer sending a catch_exception_raise_backtrace message, if applicable */
/*line: 137*/   MACH_EXCEPTION_ERRORS = 0x40000000,  // 0x40000000
/*	include additional exception specific errors, not used yet.  */
/*line: 140*/   MACH_EXCEPTION_CODES = 0x80000000,  // 0x80000000
/*	Send 64-bit code and subcode in the exception header */
/*line: 143*/   MACH_EXCEPTION_MASK = 0xe0000000,  // (MACH_EXCEPTION_CODES|MACH_EXCEPTION_ERRORS|MACH_EXCEPTION_BACKTRACE_PREFERRED)
};

// Depends on identifiers
enum macro_exception_masks {
/*
 * Masks for exception definitions, above
 * bit zero is unused, therefore 1 word = 31 exception types
 */
/*line: 151*/   EXC_MASK_BAD_ACCESS = 0x2,  // (1<<EXC_BAD_ACCESS)
/*line: 152*/   EXC_MASK_BAD_INSTRUCTION = 0x4,  // (1<<EXC_BAD_INSTRUCTION)
/*line: 153*/   EXC_MASK_ARITHMETIC = 0x8,  // (1<<EXC_ARITHMETIC)
/*line: 154*/   EXC_MASK_EMULATION = 0x10,  // (1<<EXC_EMULATION)
/*line: 155*/   EXC_MASK_SOFTWARE = 0x20,  // (1<<EXC_SOFTWARE)
/*line: 156*/   EXC_MASK_BREAKPOINT = 0x40,  // (1<<EXC_BREAKPOINT)
/*line: 157*/   EXC_MASK_SYSCALL = 0x80,  // (1<<EXC_SYSCALL)
/*line: 158*/   EXC_MASK_MACH_SYSCALL = 0x100,  // (1<<EXC_MACH_SYSCALL)
/*line: 159*/   EXC_MASK_RPC_ALERT = 0x200,  // (1<<EXC_RPC_ALERT)
/*line: 160*/   EXC_MASK_CRASH = 0x400,  // (1<<EXC_CRASH)
/*line: 161*/   EXC_MASK_RESOURCE = 0x800,  // (1<<EXC_RESOURCE)
/*line: 162*/   EXC_MASK_GUARD = 0x1000,  // (1<<EXC_GUARD)
/*line: 163*/   EXC_MASK_CORPSE_NOTIFY = 0x2000,  // (1<<EXC_CORPSE_NOTIFY)
/*line: 165*/   EXC_MASK_ALL = 0x1bfe,  // (EXC_MASK_BAD_ACCESS|EXC_MASK_BAD_INSTRUCTION|EXC_MASK_ARITHMETIC|EXC_MASK_EMULATION|EXC_MASK_SOFTWARE|EXC_MASK_BREAKPOINT|EXC_MASK_SYSCALL|EXC_MASK_MACH_SYSCALL|EXC_MASK_RPC_ALERT|EXC_MASK_RESOURCE|EXC_MASK_GUARD|EXC_MASK_MACHINE)
};

enum macro_first_exception {
/*line: 179*/   FIRST_EXCEPTION = 0x1, /* ZERO is illegal */ // 1
};

enum macro_software_exception_codes {
/*
 * Machine independent codes for EXC_SOFTWARE
 * Codes 0x10000 - 0x1FFFF reserved for OS emulation (Unix)
 * 0x10000 - 0x10002 in use for unix signals
 * 0x20000 - 0x2FFFF reserved for MACF
 */
/*line: 187*/   EXC_SOFT_SIGNAL = 0x10003, /* Unix signal exceptions */ // 0x10003
/*line: 189*/   EXC_MACF_MIN = 0x20000, /* MACF exceptions */ // 0x20000
/*line: 190*/   EXC_MACF_MAX = 0x2ffff,  // 0x2FFFF
};

