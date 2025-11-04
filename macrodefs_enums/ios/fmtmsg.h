// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/fmtmsg.h

enum macro_message_source {
/* Source of condition is... */
/*line: 37*/    MM_HARD = 0x1, /* ...hardware. */ // 0x0001
/*line: 38*/    MM_SOFT = 0x2, /* ...software. */ // 0x0002
/*line: 39*/    MM_FIRM = 0x4, /* ...firmware. */ // 0x0004
/* Condition detected by... */
/*line: 42*/    MM_APPL = 0x10, /* ...application. */ // 0x0010
/*line: 43*/    MM_UTIL = 0x20, /* ...utility. */ // 0x0020
/*line: 44*/    MM_OPSYS = 0x40, /* ...operating system. */ // 0x0040
/* Display on... */
/*line: 47*/    MM_PRINT = 0x100, /* ...standard error. */ // 0x0100
/*line: 48*/    MM_CONSOLE = 0x200, /* ...system console. */ // 0x0200
/*line: 50*/    MM_RECOVER = 0x1000, /* Recoverable error. */ // 0x1000
/*line: 51*/    MM_NRECOV = 0x2000, /* Non-recoverable error. */ // 0x2000
};

enum macro_message_severity {
/* Severity levels. */
/*line: 54*/    MM_NOSEV = 0x0, /* No severity level provided. */ // 0
/*line: 55*/    MM_HALT = 0x1, /* Error causing application to halt. */ // 1
/*line: 56*/    MM_ERROR = 0x2, /* Non-fault fault. */ // 2
/*line: 57*/    MM_WARNING = 0x3, /* Unusual non-error condition. */ // 3
/*line: 58*/    MM_INFO = 0x4, /* Informative message. */ // 4
};

enum macro_null_options {
/* Null options. */
/*line: 61*/    MM_NULLLBL = 0x0,  // (char*)0
/*line: 62*/    MM_NULLSEV = 0x0,  // 0
/*line: 63*/    MM_NULLMC = 0x0,  // 0L
/*line: 64*/    MM_NULLTXT = 0x0,  // (char*)0
/*line: 65*/    MM_NULLACT = 0x0,  // (char*)0
/*line: 66*/    MM_NULLTAG = 0x0,  // (char*)0
};

enum macro_message_result {
/* Return values. */
/*line: 69*/    MM_OK = 0x0, /* Success. */ // 0
/*line: 70*/    MM_NOMSG = 0x1, /* Failed to output to stderr. */ // 1
/*line: 71*/    MM_NOCON = 0x2, /* Failed to output to console. */ // 2
/*line: 72*/    MM_NOTOK = 0x3, /* Failed to output anything. */ // 3
};

