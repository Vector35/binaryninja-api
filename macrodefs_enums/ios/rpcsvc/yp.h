// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpcsvc/yp.h

enum macro_rpcgen_version {
/*line: 9*/     RPCGEN_VERSION = 0x30b52,  // 199506
};

enum macro_yp_limits {
/*line: 13*/    YPMAXRECORD = 0x400,  // 1024
/*line: 14*/    YPMAXDOMAIN = 0x40,  // 64
/*line: 15*/    YPMAXMAP = 0x40,  // 64
/*line: 16*/    YPMAXPEER = 0x40,  // 64
};

enum macro_ypbind_errors {
/*line: 387*/   YPBIND_ERR_ERR = 0x1,  // 1
/*line: 388*/   YPBIND_ERR_NOSERV = 0x2,  // 2
/*line: 389*/   YPBIND_ERR_RESC = 0x3,  // 3
};

// Depends on identifiers
enum macro_yp_constants {
/*line: 472*/   YPPROG = 0x186a4,  // ((rpc_uint)100004)
/*line: 473*/   YPOLDVERS = 0x1,  // ((rpc_uint)1)
};

// Depends on identifiers
enum macro_ypoldproc {
/*line: 508*/   YPOLDPROC_NULL = 0x0,  // ((rpc_uint)0)
/*line: 511*/   YPOLDPROC_DOMAIN = 0x1,  // ((rpc_uint)1)
/*line: 514*/   YPOLDPROC_DOMAIN_NONACK = 0x2,  // ((rpc_uint)2)
/*line: 517*/   YPOLDPROC_MATCH = 0x3,  // ((rpc_uint)3)
/*line: 520*/   YPOLDPROC_FIRST = 0x4,  // ((rpc_uint)4)
/*line: 523*/   YPOLDPROC_NEXT = 0x5,  // ((rpc_uint)5)
/*line: 526*/   YPOLDPROC_POLL = 0x6,  // ((rpc_uint)6)
/*line: 529*/   YPOLDPROC_PUSH = 0x7,  // ((rpc_uint)7)
/*line: 532*/   YPOLDPROC_PULL = 0x8,  // ((rpc_uint)8)
/*line: 535*/   YPOLDPROC_GET = 0x9,  // ((rpc_uint)9)
};

// Depends on identifiers
enum macro_ypvers {
/*line: 571*/   YPVERS = 0x2,  // ((rpc_uint)2)
};

// Depends on identifiers
enum macro_yp_procedure {
/*line: 612*/   YPPROC_NULL = 0x0,  // ((rpc_uint)0)
/*line: 615*/   YPPROC_DOMAIN = 0x1,  // ((rpc_uint)1)
/*line: 618*/   YPPROC_DOMAIN_NONACK = 0x2,  // ((rpc_uint)2)
/*line: 621*/   YPPROC_MATCH = 0x3,  // ((rpc_uint)3)
/*line: 624*/   YPPROC_FIRST = 0x4,  // ((rpc_uint)4)
/*line: 627*/   YPPROC_NEXT = 0x5,  // ((rpc_uint)5)
/*line: 630*/   YPPROC_XFR = 0x6,  // ((rpc_uint)6)
/*line: 633*/   YPPROC_CLEAR = 0x7,  // ((rpc_uint)7)
/*line: 636*/   YPPROC_ALL = 0x8,  // ((rpc_uint)8)
/*line: 639*/   YPPROC_MASTER = 0x9,  // ((rpc_uint)9)
/*line: 642*/   YPPROC_ORDER = 0xa,  // ((rpc_uint)10)
/*line: 645*/   YPPROC_MAPLIST = 0xb,  // ((rpc_uint)11)
};

// Depends on identifiers
enum macro_yp_push_flags {
/*line: 688*/   YPPUSH_XFRRESPPROG = 0x40000000,  // ((rpc_uint)0x40000000)
/*line: 689*/   YPPUSH_XFRRESPVERS = 0x1,  // ((rpc_uint)1)
};

// Depends on identifiers
enum macro_yp_push_proc {
/*line: 700*/   YPPUSHPROC_NULL = 0x0,  // ((rpc_uint)0)
/*line: 703*/   YPPUSHPROC_XFRRESP = 0x1,  // ((rpc_uint)1)
/*line: 716*/   YPBINDPROG = 0x186a7,  // ((rpc_uint)100007)
/*line: 717*/   YPBINDVERS = 0x2,  // ((rpc_uint)2)
};

// Depends on identifiers
enum macro_ypbind_operation {
/*line: 731*/   YPBINDPROC_NULL = 0x0,  // ((rpc_uint)0)
/*line: 734*/   YPBINDPROC_DOMAIN = 0x1,  // ((rpc_uint)1)
/*line: 737*/   YPBINDPROC_SETDOM = 0x2,  // ((rpc_uint)2)
};

