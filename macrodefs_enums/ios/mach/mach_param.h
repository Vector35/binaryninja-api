// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/mach_param.h

enum macro_task_port_max {
/* Number of "registered" ports */
/*line: 71*/    TASK_PORT_REGISTER_MAX = 0x3,  // 3
};

enum macro_task_max_watchport_count {
/* Number of watchport for task */
/*line: 74*/    TASK_MAX_WATCHPORT_COUNT = 0x80,  // 128
};

enum macro_port_count {
/* Number of different task port flavor */
/*line: 80*/    TASK_SELF_PORT_COUNT = 0x4,  // 4
/* Number of different thread port flavor */
/*line: 83*/    THREAD_SELF_PORT_COUNT = 0x3,  // 3
};

enum macro_max_conclave_name {
/* Max length of conclave name */
/*line: 86*/    MAXCONCLAVENAME = 0x80,  // 128
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 77
// #define TASK_MAX_EXCEPTION_PORT_COUNT EXC_TYPES_COUNT

