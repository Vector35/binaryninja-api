// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpcsvc/rusers.h

enum macro_rpcgen_version {
/*line: 9*/     RPCGEN_VERSION = 0x30b52,  // 199506
};

enum macro_rusers_limits {
/*
 * Find out about remote users
 */
/*line: 16*/    RUSERS_MAXUSERLEN = 0x20,  // 32
/*line: 17*/    RUSERS_MAXLINELEN = 0x20,  // 32
/*line: 18*/    RUSERS_MAXHOSTLEN = 0x101,  // 257
};

// Depends on identifiers
enum macro_ruser_types {
/*
 * Values for ut_type field above.
 */
/*line: 54*/    RUSERS_EMPTY = 0x0,  // 0
/*line: 55*/    RUSERS_RUN_LVL = 0x1,  // 1
/*line: 56*/    RUSERS_BOOT_TIME = 0x2,  // 2
/*line: 57*/    RUSERS_OLD_TIME = 0x3,  // 3
/*line: 58*/    RUSERS_NEW_TIME = 0x4,  // 4
/*line: 59*/    RUSERS_INIT_PROCESS = 0x5,  // 5
/*line: 60*/    RUSERS_LOGIN_PROCESS = 0x6,  // 6
/*line: 61*/    RUSERS_USER_PROCESS = 0x7,  // 7
/*line: 62*/    RUSERS_DEAD_PROCESS = 0x8,  // 8
/*line: 63*/    RUSERS_ACCOUNTING = 0x9,  // 9
/*line: 65*/    RUSERSPROG = 0x186a2,  // ((rpc_uint)100002)
/*line: 66*/    RUSERSVERS_3 = 0x3,  // ((rpc_uint)3)
};

// Depends on identifiers
enum macro_rpc_user_options {
/*line: 80*/    RUSERSPROC_NUM = 0x1,  // ((rpc_uint)1)
/*line: 83*/    RUSERSPROC_NAMES = 0x2,  // ((rpc_uint)2)
/*line: 86*/    RUSERSPROC_ALLNAMES = 0x3,  // ((rpc_uint)3)
};

