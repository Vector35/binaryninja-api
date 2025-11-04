// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpcsvc/rnusers.h

enum macro_rpcgen_version {
/*line: 9*/     RPCGEN_VERSION = 0x30b52,  // 199506
};

enum macro_rusers_version {
/*
 * The following structures are used by version 2 of the rusersd protocol.
 * They were not developed with rpcgen, so they do not appear as RPCL.
 */
/*line: 18*/    RUSERSVERS_ORIG = 0x1, /* original version */ // 1
/*line: 19*/    RUSERSVERS_IDLE = 0x2,  // 2
/*line: 20*/    MAXUSERS = 0x64,  // 100
};

// Depends on identifiers
enum macro_rpc_constants {
/*line: 53*/    RUSERSVERS_1 = 0x1,  // ((rpc_uint)1)
/*line: 54*/    RUSERSVERS_2 = 0x2,  // ((rpc_uint)2)
/*line: 56*/    RUSERSPROG = 0x186a2,  // ((rpc_uint)100002)
/*line: 59*/    RUSERSPROC_NUM = 0x1,  // ((rpc_uint)1)
/*line: 62*/    RUSERSPROC_NAMES = 0x2,  // ((rpc_uint)2)
/*line: 65*/    RUSERSPROC_ALLNAMES = 0x3,  // ((rpc_uint)3)
};

