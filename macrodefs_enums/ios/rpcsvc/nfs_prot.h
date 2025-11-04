// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpcsvc/nfs_prot.h

enum macro_rpcgen_version {
/*line: 9*/     RPCGEN_VERSION = 0x30b52,  // 199506
};

enum macro_nfs_protocol_constants {
/*line: 13*/    NFS_PORT = 0x801,  // 2049
/*line: 14*/    NFS_MAXDATA = 0x2000,  // 8192
/*line: 15*/    NFS_MAXPATHLEN = 0x400,  // 1024
/*line: 16*/    NFS_MAXNAMLEN = 0xff,  // 255
/*line: 17*/    NFS_FHSIZE = 0x20,  // 32
/*line: 18*/    NFS_COOKIESIZE = 0x4,  // 4
/*line: 19*/    NFS_FIFO_DEV = -0x1,  // -1
/*line: 20*/    NFSMODE_FMT = 0xf000,  // 0170000
/*line: 21*/    NFSMODE_DIR = 0x4000,  // 0040000
/*line: 22*/    NFSMODE_CHR = 0x2000,  // 0020000
/*line: 23*/    NFSMODE_BLK = 0x6000,  // 0060000
/*line: 24*/    NFSMODE_REG = 0x8000,  // 0100000
/*line: 25*/    NFSMODE_LNK = 0xa000,  // 0120000
/*line: 26*/    NFSMODE_SOCK = 0xc000,  // 0140000
/*line: 27*/    NFSMODE_FIFO = 0x1000,  // 0010000
};

// Depends on identifiers
enum macro_nfs_rpc_program_info {
/*line: 491*/   NFS_PROGRAM = 0x186a3,  // ((rpc_uint)100003)
/*line: 492*/   NFS_VERSION = 0x2,  // ((rpc_uint)2)
};

// Depends on identifiers
enum macro_nfs_procedure {
/*line: 551*/   NFSPROC_NULL = 0x0,  // ((rpc_uint)0)
/*line: 554*/   NFSPROC_GETATTR = 0x1,  // ((rpc_uint)1)
/*line: 557*/   NFSPROC_SETATTR = 0x2,  // ((rpc_uint)2)
/*line: 560*/   NFSPROC_ROOT = 0x3,  // ((rpc_uint)3)
/*line: 563*/   NFSPROC_LOOKUP = 0x4,  // ((rpc_uint)4)
/*line: 566*/   NFSPROC_READLINK = 0x5,  // ((rpc_uint)5)
/*line: 569*/   NFSPROC_READ = 0x6,  // ((rpc_uint)6)
/*line: 572*/   NFSPROC_WRITECACHE = 0x7,  // ((rpc_uint)7)
/*line: 575*/   NFSPROC_WRITE = 0x8,  // ((rpc_uint)8)
/*line: 578*/   NFSPROC_CREATE = 0x9,  // ((rpc_uint)9)
/*line: 581*/   NFSPROC_REMOVE = 0xa,  // ((rpc_uint)10)
/*line: 584*/   NFSPROC_RENAME = 0xb,  // ((rpc_uint)11)
/*line: 587*/   NFSPROC_LINK = 0xc,  // ((rpc_uint)12)
/*line: 590*/   NFSPROC_SYMLINK = 0xd,  // ((rpc_uint)13)
/*line: 593*/   NFSPROC_MKDIR = 0xe,  // ((rpc_uint)14)
/*line: 596*/   NFSPROC_RMDIR = 0xf,  // ((rpc_uint)15)
/*line: 599*/   NFSPROC_READDIR = 0x10,  // ((rpc_uint)16)
/*line: 602*/   NFSPROC_STATFS = 0x11,  // ((rpc_uint)17)
};

