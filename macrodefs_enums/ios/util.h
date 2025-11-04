// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/util.h

enum macro_pidlock_flags {
/*line: 72*/    PIDLOCK_NONBLOCK = 0x1,  // 1
/*line: 73*/    PIDLOCK_USEHOSTNAME = 0x2,  // 2
};

enum macro_fparseln_flags {
/*
 * fparseln() specific operation flags.
 */
/*line: 78*/    FPARSELN_UNESCESC = 0x1,  // 0x01
/*line: 79*/    FPARSELN_UNESCCONT = 0x2,  // 0x02
/*line: 80*/    FPARSELN_UNESCCOMM = 0x4,  // 0x04
/*line: 81*/    FPARSELN_UNESCREST = 0x8,  // 0x08
/*line: 82*/    FPARSELN_UNESCALL = 0xf,  // 0x0f
};

enum macro_opendev_flags {
/*
 * opendev() specific operation flags.
 */
/*line: 87*/    OPENDEV_PART = 0x1, /* Try to open the raw partition. */ // 0x01
/*line: 88*/    OPENDEV_BLCK = 0x4, /* Open block, not character device. */ // 0x04
};

