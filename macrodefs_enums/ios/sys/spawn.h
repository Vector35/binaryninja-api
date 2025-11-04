// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/spawn.h

enum macro_spawn_flags {
/*
 * Possible bit values which may be OR'ed together and provided as the second
 * parameter to posix_spawnattr_setflags() or implicit returned in the value of
 * the second parameter to posix_spawnattr_getflags().
 */
/*line: 45*/    POSIX_SPAWN_RESETIDS = 0x1, /* [SPN] R[UG]ID not E[UG]ID */ // 0x0001
/*line: 46*/    POSIX_SPAWN_SETPGROUP = 0x2, /* [SPN] set non-parent PGID */ // 0x0002
/*line: 47*/    POSIX_SPAWN_SETSIGDEF = 0x4, /* [SPN] reset sigset default */ // 0x0004
/*line: 48*/    POSIX_SPAWN_SETSIGMASK = 0x8, /* [SPN] set signal mask */ // 0x0008
/*
 * Darwin-specific flags
 */
/*line: 59*/    POSIX_SPAWN_SETEXEC = 0x40,  // 0x0040
/*line: 60*/    POSIX_SPAWN_START_SUSPENDED = 0x80,  // 0x0080
/*line: 61*/    POSIX_SPAWN_SETSID = 0x400,  // 0x0400
/*line: 62*/    POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000,  // 0x4000
};

enum macro_posix_spawn_reslide {
/*line: 64*/    _POSIX_SPAWN_RESLIDE = 0x800,  // 0x0800
};

enum macro_pcontrol_action {
/*
 * Possible values to be set for the process control actions on resource starvation.
 * POSIX_SPAWN_PCONTROL_THROTTLE indicates that the process is to be throttled on starvation.
 * POSIX_SPAWN_PCONTROL_SUSPEND indicates that the process is to be suspended on starvation.
 * POSIX_SPAWN_PCONTROL_KILL indicates that the process is to be terminated  on starvation.
 */
/*line: 72*/    POSIX_SPAWN_PCONTROL_NONE = 0x0,  // 0x0000
/*line: 73*/    POSIX_SPAWN_PCONTROL_THROTTLE = 0x1,  // 0x0001
/*line: 74*/    POSIX_SPAWN_PCONTROL_SUSPEND = 0x2,  // 0x0002
/*line: 75*/    POSIX_SPAWN_PCONTROL_KILL = 0x3,  // 0x0003
};

enum macro_spawn_panic_flags {
/*line: 77*/    POSIX_SPAWN_PANIC_ON_CRASH = 0x1,  // 0x1
/*line: 78*/    POSIX_SPAWN_PANIC_ON_NON_ZERO_EXIT = 0x2,  // 0x2
/*line: 79*/    POSIX_SPAWN_PANIC_ON_EXIT = 0x4,  // 0x4
/*line: 80*/    POSIX_SPAWN_PANIC_ON_SPAWN_FAIL = 0x8,  // 0x8
};

