// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpcsvc/bootparam_prot.h

enum macro_rpcgen_version {
/*line: 9*/     RPCGEN_VERSION = 0x30b52,  // 199506
};

enum macro_bootparam_limits {
/*line: 19*/    MAX_MACHINE_NAME = 0xff,  // 255
/*line: 20*/    MAX_PATH_LEN = 0x400,  // 1024
/*line: 21*/    MAX_FILEID = 0x20,  // 32
/*line: 22*/    IP_ADDR_TYPE = 0x1,  // 1
};

// Depends on identifiers
enum macro_boot_params {
/*line: 143*/   BOOTPARAMPROG = 0x186ba,  // ((rpc_uint)100026)
/*line: 144*/   BOOTPARAMVERS = 0x1,  // ((rpc_uint)1)
};

// Depends on identifiers
enum macro_bootparam_proc {
/*line: 155*/   BOOTPARAMPROC_WHOAMI = 0x1,  // ((rpc_uint)1)
/*line: 158*/   BOOTPARAMPROC_GETFILE = 0x2,  // ((rpc_uint)2)
};

