// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpcsvc/rquota.h

enum macro_rpcgen_version {
/*line: 9*/     RPCGEN_VERSION = 0x30b52,  // 199506
};

enum macro_path_length {
/*line: 13*/    RQ_PATHLEN = 0x400,  // 1024
};

// Depends on identifiers
enum macro_rpc_quota {
/*line: 82*/    RQUOTAPROG = 0x186ab,  // ((rpc_uint)100011)
/*line: 83*/    RQUOTAVERS = 0x1,  // ((rpc_uint)1)
};

// Depends on identifiers
enum macro_rpc_quota_operation {
/*line: 94*/    RQUOTAPROC_GETQUOTA = 0x1,  // ((rpc_uint)1)
/*line: 97*/    RQUOTAPROC_GETACTIVEQUOTA = 0x2,  // ((rpc_uint)2)
};

