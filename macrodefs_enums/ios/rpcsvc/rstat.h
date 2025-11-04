// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpcsvc/rstat.h

enum macro_rpcgen_version {
/*line: 9*/     RPCGEN_VERSION = 0x30b52,  // 199506
};

// Depends on identifiers
enum macro_load_average_scale {
/*
 * Scale factor for scaled integers used to count load averages.
 */
/*line: 17*/    FSHIFT = 0x8, /* bits to right of fixed binary point */ // 8
/*line: 18*/    FSCALE = 0x100,  // (1<<FSHIFT)
};

enum macro_rstat_flags {
/*line: 21*/    RSTAT_CPUSTATES = 0x4,  // 4
/*line: 22*/    RSTAT_DK_NDRIVE = 0x4,  // 4
};

// Depends on identifiers
enum macro_rstat_constants {
/*line: 121*/   RSTATPROG = 0x186a1,  // ((rpc_uint)100001)
/*line: 122*/   RSTATVERS_TIME = 0x3,  // ((rpc_uint)3)
};

// Depends on identifiers
enum macro_rpc_stats {
/*line: 133*/   RSTATPROC_STATS = 0x1,  // ((rpc_uint)1)
/*line: 136*/   RSTATPROC_HAVEDISK = 0x2,  // ((rpc_uint)2)
/*line: 148*/   RSTATVERS_SWTCH = 0x2,  // ((rpc_uint)2)
/*line: 168*/   RSTATVERS_ORIG = 0x1,  // ((rpc_uint)1)
};

