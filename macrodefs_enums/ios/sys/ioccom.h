// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/ioccom.h

// Depends on identifiers
enum macro_ioctl_flags {
/*
 * Ioctl's have the command encoded in the lower word, and the size of
 * any in or out parameters in the upper word.  The high 3 bits of the
 * upper word are used to encode the in/out status of the parameter.
 */
/*line: 74*/    IOCPARM_MASK = 0x1fff, /* parameter length, at most 13 bits */ // 0x1fff
/*line: 79*/    IOCPARM_MAX = 0x2000, /* max size of ioctl args */ // (IOCPARM_MASK+1)
/* no parameters */
/*line: 81*/    IOC_VOID = 0x20000000,  // (__uint32_t)0x20000000
/* copy parameters out */
/*line: 83*/    IOC_OUT = 0x40000000,  // (__uint32_t)0x40000000
/* copy parameters in */
/*line: 85*/    IOC_IN = 0x80000000,  // (__uint32_t)0x80000000
/* copy parameters in and out */
/*line: 87*/    IOC_INOUT = 0xc0000000,  // (IOC_IN|IOC_OUT)
/* mask for IN/OUT/VOID */
/*line: 89*/    IOC_DIRMASK = 0xe0000000,  // (__uint32_t)0xe0000000
};

