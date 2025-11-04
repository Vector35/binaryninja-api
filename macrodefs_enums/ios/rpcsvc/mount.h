// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpcsvc/mount.h

enum macro_rpcgen_version {
/*line: 9*/     RPCGEN_VERSION = 0x30b52,  // 199506
};

enum macro_mount_limits {
/*line: 13*/    MNTPATHLEN = 0x400,  // 1024
/*line: 14*/    MNTNAMLEN = 0xff,  // 255
/*line: 15*/    FHSIZE = 0x20,  // 32
};

// Depends on identifiers
enum macro_mount_constants {
/*line: 137*/   MOUNTPROG = 0x186a5,  // ((rpc_uint)100005)
/*line: 138*/   MOUNTVERS = 0x1,  // ((rpc_uint)1)
};

// Depends on identifiers
enum macro_mountproc {
/*line: 164*/   MOUNTPROC_NULL = 0x0,  // ((rpc_uint)0)
/*line: 167*/   MOUNTPROC_MNT = 0x1,  // ((rpc_uint)1)
/*line: 170*/   MOUNTPROC_DUMP = 0x2,  // ((rpc_uint)2)
/*line: 173*/   MOUNTPROC_UMNT = 0x3,  // ((rpc_uint)3)
/*line: 176*/   MOUNTPROC_UMNTALL = 0x4,  // ((rpc_uint)4)
/*line: 179*/   MOUNTPROC_EXPORT = 0x5,  // ((rpc_uint)5)
/*line: 182*/   MOUNTPROC_EXPORTALL = 0x6,  // ((rpc_uint)6)
};

