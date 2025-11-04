// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/un.h

enum macro_socket_level {
/* Level number of get/setsockopt for local domain sockets */
/*line: 85*/    SOL_LOCAL = 0x0,  // 0
};

enum macro_socket_options {
/* Socket options. */
/*line: 88*/    LOCAL_PEERCRED = 0x1, /* retrieve peer credentials */ // 0x001
/*line: 89*/    LOCAL_PEERPID = 0x2, /* retrieve peer pid */ // 0x002
/*line: 90*/    LOCAL_PEEREPID = 0x3, /* retrieve eff. peer pid */ // 0x003
/*line: 91*/    LOCAL_PEERUUID = 0x4, /* retrieve peer UUID */ // 0x004
/*line: 92*/    LOCAL_PEEREUUID = 0x5, /* retrieve eff. peer UUID */ // 0x005
/*line: 93*/    LOCAL_PEERTOKEN = 0x6, /* retrieve peer audit token */ // 0x006
};

