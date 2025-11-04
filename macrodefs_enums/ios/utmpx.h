// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/utmpx.h

enum macro_utmpx_sizes {
/*line: 82*/    _UTX_USERSIZE = 0x100, /* matches MAXLOGNAME */ // 256
/*line: 83*/    _UTX_LINESIZE = 0x20,  // 32
/*line: 84*/    _UTX_IDSIZE = 0x4,  // 4
/*line: 85*/    _UTX_HOSTSIZE = 0x100,  // 256
};

enum macro_utmpx_entry_type {
/*line: 87*/    EMPTY = 0x0,  // 0
/*line: 88*/    RUN_LVL = 0x1,  // 1
/*line: 89*/    BOOT_TIME = 0x2,  // 2
/*line: 90*/    OLD_TIME = 0x3,  // 3
/*line: 91*/    NEW_TIME = 0x4,  // 4
/*line: 92*/    INIT_PROCESS = 0x5,  // 5
/*line: 93*/    LOGIN_PROCESS = 0x6,  // 6
/*line: 94*/    USER_PROCESS = 0x7,  // 7
/*line: 95*/    DEAD_PROCESS = 0x8,  // 8
/*line: 98*/    ACCOUNTING = 0x9,  // 9
/*line: 99*/    SIGNATURE = 0xa,  // 10
/*line: 100*/   SHUTDOWN_TIME = 0xb,  // 11
};

enum macro_utmpx_record_masks {
/*line: 102*/   UTMPX_AUTOFILL_MASK = 0x8000,  // 0x8000
/*line: 103*/   UTMPX_DEAD_IF_CORRESPONDING_MASK = 0x4000,  // 0x4000
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 79
// #define UTMPX_FILE _PATH_UTMPX

