// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/kauth.h

// Depends on identifiers
enum macro_kauth_ids {
/*
 * Identities.
 */
/*line: 56*/    KAUTH_UID_NONE = -0x65, /* not a valid UID */ // (~(uid_t)0-100)
/*line: 57*/    KAUTH_GID_NONE = -0x65, /* not a valid GID */ // (~(gid_t)0-100)
};

enum macro_kauth_ntsid_max_authorities {
/*line: 65*/    KAUTH_NTSID_MAX_AUTHORITIES = 0x10,  // 16
};

enum macro_kauth_ntsid_hdrsize {
/* valid byte count inside a SID structure */
/*line: 72*/    KAUTH_NTSID_HDRSIZE = 0x8,  // (8)
};

enum macro_extlookup_results {
/*line: 85*/    KAUTH_EXTLOOKUP_SUCCESS = 0x0, /* results here are good */ // 0
/*line: 86*/    KAUTH_EXTLOOKUP_BADRQ = 0x1, /* request badly formatted */ // 1
/*line: 87*/    KAUTH_EXTLOOKUP_FAILURE = 0x2, /* transient failure during lookup */ // 2
/*line: 88*/    KAUTH_EXTLOOKUP_FATAL = 0x3, /* permanent failure during lookup */ // 3
/*line: 89*/    KAUTH_EXTLOOKUP_INPROG = 0x64, /* request in progress */ // 100
/*line: 91*/    KAUTH_EXTLOOKUP_VALID_UID = 0x1,  // (1<<0)
/*line: 92*/    KAUTH_EXTLOOKUP_VALID_UGUID = 0x2,  // (1<<1)
/*line: 93*/    KAUTH_EXTLOOKUP_VALID_USID = 0x4,  // (1<<2)
/*line: 94*/    KAUTH_EXTLOOKUP_VALID_GID = 0x8,  // (1<<3)
/*line: 95*/    KAUTH_EXTLOOKUP_VALID_GGUID = 0x10,  // (1<<4)
/*line: 96*/    KAUTH_EXTLOOKUP_VALID_GSID = 0x20,  // (1<<5)
/*line: 97*/    KAUTH_EXTLOOKUP_WANT_UID = 0x40,  // (1<<6)
/*line: 98*/    KAUTH_EXTLOOKUP_WANT_UGUID = 0x80,  // (1<<7)
/*line: 99*/    KAUTH_EXTLOOKUP_WANT_USID = 0x100,  // (1<<8)
/*line: 100*/   KAUTH_EXTLOOKUP_WANT_GID = 0x200,  // (1<<9)
/*line: 101*/   KAUTH_EXTLOOKUP_WANT_GGUID = 0x400,  // (1<<10)
/*line: 102*/   KAUTH_EXTLOOKUP_WANT_GSID = 0x800,  // (1<<11)
/*line: 103*/   KAUTH_EXTLOOKUP_WANT_MEMBERSHIP = 0x1000,  // (1<<12)
/*line: 104*/   KAUTH_EXTLOOKUP_VALID_MEMBERSHIP = 0x2000,  // (1<<13)
/*line: 105*/   KAUTH_EXTLOOKUP_ISMEMBER = 0x4000,  // (1<<14)
/*line: 106*/   KAUTH_EXTLOOKUP_VALID_PWNAM = 0x8000,  // (1<<15)
/*line: 107*/   KAUTH_EXTLOOKUP_WANT_PWNAM = 0x10000,  // (1<<16)
/*line: 108*/   KAUTH_EXTLOOKUP_VALID_GRNAM = 0x20000,  // (1<<17)
/*line: 109*/   KAUTH_EXTLOOKUP_WANT_GRNAM = 0x40000,  // (1<<18)
/*line: 110*/   KAUTH_EXTLOOKUP_VALID_SUPGRPS = 0x80000,  // (1<<19)
/*line: 111*/   KAUTH_EXTLOOKUP_WANT_SUPGRPS = 0x100000,  // (1<<20)
};

enum macro_kauth_operation {
/*line: 137*/   KAUTH_EXTLOOKUP_REGISTER = 0x0,  // (0)
/*line: 138*/   KAUTH_EXTLOOKUP_RESULT = 0x1,  // (1<<0)
/*line: 139*/   KAUTH_EXTLOOKUP_WORKER = 0x2,  // (1<<1)
/*line: 140*/   KAUTH_EXTLOOKUP_DEREGISTER = 0x4,  // (1<<2)
/*line: 141*/   KAUTH_GET_CACHE_SIZES = 0x8,  // (1<<3)
/*line: 142*/   KAUTH_SET_CACHE_SIZES = 0x10,  // (1<<4)
/*line: 143*/   KAUTH_CLEAR_CACHES = 0x20,  // (1<<5)
};

