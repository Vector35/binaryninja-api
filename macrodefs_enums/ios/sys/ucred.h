// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/ucred.h

enum macro_credential_flags {
/*
 * Credential flags that can be set on a credential
 */
/*line: 93*/    CRF_NOMEMBERD = 0x1, /* memberd opt out by setgroups() */ // 0x00000001
/*line: 94*/    CRF_MAC_ENFORCE = 0x2, /* force entry through MAC Framework */ // 0x00000002
};

// Depends on identifiers
enum macro_ucred_version {
/*line: 106*/   XUCRED_VERSION = 0x0,  // 0
/*line: 109*/   NOCRED = 0x0, /* no credential available */ // ((kauth_cred_t)0)
/*line: 110*/   FSCRED = -0x1, /* filesystem credential */ // ((kauth_cred_t)-1)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 108
// #define cr_gid cr_groups[0]

