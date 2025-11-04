// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpc/clnt.h

enum macro_clnt_ctrl {
/*
 * control operations that apply to both udp and tcp transports
 */
/*line: 239*/   CLSET_TIMEOUT = 0x1, /* set timeout (timeval) */ // 1
/*line: 240*/   CLGET_TIMEOUT = 0x2, /* get timeout (timeval) */ // 2
/*line: 241*/   CLGET_SERVER_ADDR = 0x3, /* get server's address (sockaddr) */ // 3
/*
 * udp only control operations
 */
/*line: 245*/   CLSET_RETRY_TIMEOUT = 0x4, /* set retry timeout (timeval) */ // 4
/*line: 246*/   CLGET_RETRY_TIMEOUT = 0x5, /* get retry timeout (timeval) */ // 5
};

enum macro_rpctest_constants {
/*line: 264*/   RPCTEST_PROGRAM = 0x1,  // ((unsignedint)1)
/*line: 265*/   RPCTEST_VERSION = 0x1,  // ((unsignedint)1)
/*line: 266*/   RPCTEST_NULL_PROC = 0x2,  // ((unsignedint)2)
/*line: 267*/   RPCTEST_NULL_BATCH_PROC = 0x3,  // ((unsignedint)3)
};

enum macro_nullproc {
/*line: 280*/   NULLPROC = 0x0,  // ((unsignedint)0)
};

enum macro_rpc_message_sizes {
/*line: 443*/   UDPMSGSIZE = 0x2260, /* rpc imposed limit on udp msg size */ // 8800
/*line: 444*/   RPCSMALLMSGSIZE = 0x190, /* a more reasonable packet size */ // 400
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 145
// #define re_errno ru.RE_errno

// Line: 146
// #define re_why ru.RE_why

// Line: 147
// #define re_vers ru.RE_vers

// Line: 148
// #define re_lb ru.RE_lb

