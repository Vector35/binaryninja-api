// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/quota.h

enum macro_quota_time {
/*
 * Definitions for disk quotas imposed on the average user
 * (big brother finally hits UNIX).
 *
 * The following constants define the amount of time given a user before the
 * soft limits are treated as hard limits (usually resulting in an allocation
 * failure). The timer is started when the user crosses their soft limit, it
 * is reset when they go below their soft limit.
 */
/*line: 86*/    MAX_IQ_TIME = 0x93a80, /* seconds in 1 week */ // (7*24*60*60)
/*line: 87*/    MAX_DQ_TIME = 0x93a80, /* seconds in 1 week */ // (7*24*60*60)
};

enum macro_quota_type {
/*
 * The following constants define the usage of the quota file array in the
 * file system mount structure and dquot array in the inode structure.  The semantics
 * of the elements of these arrays are defined in the routine getinoquota;
 * the remainder of the quota code treats them generically and need not be
 * inspected when changing the size of the array.
 */
/*line: 96*/    MAXQUOTAS = 0x2,  // 2
/*line: 97*/    USRQUOTA = 0x0, /* element used for user quotas */ // 0
/*line: 98*/    GRPQUOTA = 0x1, /* element used for group quotas */ // 1
};

// enum macro_quotactl_params {
// /*
//  * Command definitions for the 'quotactl' system call.  The commands are
//  * broken into a main command defined below and a subcommand that is used
//  * to convey the type of quota that is being manipulated (see above).
//  */
// /*line: 117*/   SUBCMDMASK = 0xff,  // 0x00ff
// /*line: 118*/   SUBCMDSHIFT = 0x8,  // 8
// };

enum macro_quotactl_commands {
/*line: 121*/   Q_QUOTAON = 0x100, /* enable quotas */ // 0x0100
/*line: 122*/   Q_QUOTAOFF = 0x200, /* disable quotas */ // 0x0200
/*line: 123*/   Q_GETQUOTA = 0x300, /* get limits and usage */ // 0x0300
/*line: 124*/   Q_SETQUOTA = 0x400, /* set limits and usage */ // 0x0400
/*line: 125*/   Q_SETUSE = 0x500, /* set usage */ // 0x0500
/*line: 126*/   Q_SYNC = 0x600, /* sync disk copy of a filesystems quotas */ // 0x0600
/*line: 127*/   Q_QUOTASTAT = 0x700, /* get quota on/off status */ // 0x0700
};

enum macro_qf_version {
/*line: 178*/   QF_VERSION = 0x1,  // 1
};

enum macro_quota_users_constants {
/*line: 181*/   QF_USERS_PER_GB = 0x100,  // 256
/*line: 182*/   QF_MIN_USERS = 0x800,  // 2048
/*line: 183*/   QF_MAX_USERS = 0x200000,  // (2048*1024)
};

enum macro_quota_groups_constants {
/*line: 185*/   QF_GROUPS_PER_GB = 0x20,  // 32
/*line: 186*/   QF_MIN_GROUPS = 0x800,  // 2048
/*line: 187*/   QF_MAX_GROUPS = 0x40000,  // (256*1024)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 173
// #define INITQMAGICS { \
// 	0xff31ff35,     /* USRQUOTA */ \
// 	0xff31ff27,     /* GRPQUOTA */ \
// }

