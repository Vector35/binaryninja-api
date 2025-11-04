// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpc/auth.h

enum macro_auth_limits {
/*line: 73*/    MAX_AUTH_BYTES = 0x190,  // 400
/*line: 74*/    MAXNETNAMELEN = 0xff, /* maximum length of network user's name */ // 255
};

enum macro_auth_types {
/*line: 213*/   AUTH_NONE = 0x0, /* no authentication */ // 0
/*line: 214*/   AUTH_NULL = 0x0, /* backward compatibility */ // 0
/*line: 215*/   AUTH_UNIX = 0x1, /* unix style (uid, gids) */ // 1
/*line: 216*/   AUTH_SHORT = 0x2, /* short hand unix style */ // 2
/*line: 217*/   AUTH_DES = 0x3, /* des style (encrypted timestamps) */ // 3
};

