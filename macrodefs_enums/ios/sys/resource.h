// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/resource.h

enum macro_priority_type {
/*
 * Possible values of the first parameter to getpriority()/setpriority(),
 * used to indicate the type of the second parameter.
 */
/*line: 100*/   PRIO_PROCESS = 0x0, /* Second argument is a PID */ // 0
/*line: 101*/   PRIO_PGRP = 0x1, /* Second argument is a GID */ // 1
/*line: 102*/   PRIO_USER = 0x2, /* Second argument is a UID */ // 2
/*line: 105*/   PRIO_DARWIN_THREAD = 0x3, /* Second argument is always 0 (current thread) */ // 3
/*line: 106*/   PRIO_DARWIN_PROCESS = 0x4, /* Second argument is a PID */ // 4
};

enum macro_priority_range {
/*
 * Range limitations for the value of the third parameter to setpriority().
 */
/*line: 112*/   PRIO_MIN = -0x14,  // -20
/*line: 113*/   PRIO_MAX = 0x14,  // 20
};

enum macro_darwin_priority {
/*
 * use PRIO_DARWIN_BG to set the current thread into "background" state
 * which lowers CPU, disk IO, and networking priorites until thread terminates
 * or "background" state is revoked
 */
/*line: 120*/   PRIO_DARWIN_BG = 0x1000,  // 0x1000
/*
 * use PRIO_DARWIN_NONUI to restrict a process's ability to make calls to
 * the GPU. (deprecated)
 */
/*line: 126*/   PRIO_DARWIN_NONUI = 0x1001,  // 0x1001
};

enum macro_rusage_scope {
/*
 * Possible values of the first parameter to getrusage(), used to indicate
 * the scope of the information to be returned.
 */
/*line: 140*/   RUSAGE_SELF = 0x0, /* Current process information */ // 0
/*line: 141*/   RUSAGE_CHILDREN = -0x1, /* Current process' children */ // -1
};

// Depends on identifiers
enum macro_rusage_info_flavor {
/*
 * Flavors for proc_pid_rusage().
 */
/*line: 186*/   RUSAGE_INFO_V0 = 0x0,  // 0
/*line: 187*/   RUSAGE_INFO_V1 = 0x1,  // 1
/*line: 188*/   RUSAGE_INFO_V2 = 0x2,  // 2
/*line: 189*/   RUSAGE_INFO_V3 = 0x3,  // 3
/*line: 190*/   RUSAGE_INFO_V4 = 0x4,  // 4
/*line: 191*/   RUSAGE_INFO_V5 = 0x5,  // 5
/*line: 192*/   RUSAGE_INFO_V6 = 0x6,  // 6
/*line: 193*/   RUSAGE_INFO_CURRENT = 0x6,  // RUSAGE_INFO_V6
};

enum macro_ru_proc_reslide {
/*
 * Flags for RUSAGE_INFO_V5
 */
/*line: 198*/   RU_PROC_RUNS_RESLIDE = 0x1, /* proc has reslid shared cache */ // 0x00000001
};

// Depends on identifiers
enum macro_resource_limit_constants {
/*
 * Symbolic constants for resource limits; since all limits are representable
 * as a type rlim_t, we are permitted to define RLIM_SAVED_* in terms of
 * RLIM_INFINITY.
 */
/*line: 435*/   RLIM_INFINITY = 0x7fffffffffffffff, /* no limit */ // (((__uint64_t)1<<63)-1)
/*line: 436*/   RLIM_SAVED_MAX = 0x7fffffffffffffff, /* Unrepresentable hard limit */ // RLIM_INFINITY
/*line: 437*/   RLIM_SAVED_CUR = 0x7fffffffffffffff, /* Unrepresentable soft limit */ // RLIM_INFINITY
};

// Depends on identifiers
enum macro_resource_kind {
/*
 * Possible values of the first parameter to getrlimit()/setrlimit(), to
 * indicate for which resource the operation is being performed.
 */
/*line: 443*/   RLIMIT_CPU = 0x0, /* cpu time per process */ // 0
/*line: 444*/   RLIMIT_FSIZE = 0x1, /* file size */ // 1
/*line: 445*/   RLIMIT_DATA = 0x2, /* data segment size */ // 2
/*line: 446*/   RLIMIT_STACK = 0x3, /* stack size */ // 3
/*line: 447*/   RLIMIT_CORE = 0x4, /* core file size */ // 4
/*line: 448*/   RLIMIT_AS = 0x5, /* address space (resident set size) */ // 5
/*line: 450*/   RLIMIT_RSS = 0x5, /* source compatibility alias */ // RLIMIT_AS
/*line: 451*/   RLIMIT_MEMLOCK = 0x6, /* locked-in-memory address space */ // 6
/*line: 452*/   RLIMIT_NPROC = 0x7, /* number of processes */ // 7
/*line: 454*/   RLIMIT_NOFILE = 0x8, /* number of open files */ // 8
/*line: 456*/   RLIM_NLIMITS = 0x9, /* total number of resource limits */ // 9
/*line: 458*/   _RLIMIT_POSIX_FLAG = 0x1000, /* Set bit for strict POSIX */ // 0x1000
};

enum macro_resource_limit_flavor {
/*
 * proc_rlimit_control()
 *
 * Resource limit flavors
 */
/*line: 475*/   RLIMIT_WAKEUPS_MONITOR = 0x1, /* Configure the wakeups monitor. */ // 0x1
/*line: 476*/   RLIMIT_CPU_USAGE_MONITOR = 0x2, /* Configure the CPU usage monitor. */ // 0x2
/*line: 477*/   RLIMIT_THREAD_CPULIMITS = 0x3, /* Configure a blocking, per-thread, CPU limits. */ // 0x3
/*line: 478*/   RLIMIT_FOOTPRINT_INTERVAL = 0x4, /* Configure memory footprint interval tracking */ // 0x4
};

enum macro_wakemon_flags {
/*
 * Flags for wakeups monitor control.
 */
/*line: 483*/   WAKEMON_ENABLE = 0x1,  // 0x01
/*line: 484*/   WAKEMON_DISABLE = 0x2,  // 0x02
/*line: 485*/   WAKEMON_GET_PARAMS = 0x4,  // 0x04
/*line: 486*/   WAKEMON_SET_DEFAULTS = 0x8,  // 0x08
/*line: 487*/   WAKEMON_MAKE_FATAL = 0x10, /* Configure the task so that violations are fatal. */ // 0x10
};

enum macro_cpu_monitor_flags {
/*
 * Flags for CPU usage monitor control.
 */
/*line: 492*/   CPUMON_MAKE_FATAL = 0x1000,  // 0x1000
};

enum macro_footprint_interval_reset {
/*
 * Flags for memory footprint interval tracking.
 */
/*line: 497*/   FOOTPRINT_INTERVAL_RESET = 0x1, /* Reset the footprint interval counter to zero */ // 0x1
};

enum macro_io_policy_type {
/* I/O type */
/*line: 507*/   IOPOL_TYPE_DISK = 0x0,  // 0
/*line: 508*/   IOPOL_TYPE_VFS_ATIME_UPDATES = 0x2,  // 2
/*line: 509*/   IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES = 0x3,  // 3
/*line: 510*/   IOPOL_TYPE_VFS_STATFS_NO_DATA_VOLUME = 0x4,  // 4
/*line: 511*/   IOPOL_TYPE_VFS_TRIGGER_RESOLVE = 0x5,  // 5
/*line: 512*/   IOPOL_TYPE_VFS_IGNORE_CONTENT_PROTECTION = 0x6,  // 6
/*line: 513*/   IOPOL_TYPE_VFS_IGNORE_PERMISSIONS = 0x7,  // 7
/*line: 514*/   IOPOL_TYPE_VFS_SKIP_MTIME_UPDATE = 0x8,  // 8
/*line: 515*/   IOPOL_TYPE_VFS_ALLOW_LOW_SPACE_WRITES = 0x9,  // 9
/*line: 516*/   IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY = 0xa,  // 10
};

enum macro_iopol_scope {
/* scope */
/*line: 519*/   IOPOL_SCOPE_PROCESS = 0x0,  // 0
/*line: 520*/   IOPOL_SCOPE_THREAD = 0x1,  // 1
/*line: 521*/   IOPOL_SCOPE_DARWIN_BG = 0x2,  // 2
};

// Depends on identifiers
enum macro_iopol_priority {
/* I/O Priority */
/*line: 524*/   IOPOL_DEFAULT = 0x0,  // 0
/*line: 525*/   IOPOL_IMPORTANT = 0x1,  // 1
/*line: 526*/   IOPOL_PASSIVE = 0x2,  // 2
/*line: 527*/   IOPOL_THROTTLE = 0x3,  // 3
/*line: 528*/   IOPOL_UTILITY = 0x4,  // 4
/*line: 529*/   IOPOL_STANDARD = 0x5,  // 5
/* compatibility with older names */
/*line: 532*/   IOPOL_APPLICATION = 0x5,  // IOPOL_STANDARD
/*line: 533*/   IOPOL_NORMAL = 0x1,  // IOPOL_IMPORTANT
};

enum macro_iopol_atime_updates {
/*line: 535*/   IOPOL_ATIME_UPDATES_DEFAULT = 0x0,  // 0
/*line: 536*/   IOPOL_ATIME_UPDATES_OFF = 0x1,  // 1
};

enum macro_iopol_materialize_dataless_files {
/*line: 538*/   IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT = 0x0,  // 0
/*line: 539*/   IOPOL_MATERIALIZE_DATALESS_FILES_OFF = 0x1,  // 1
/*line: 540*/   IOPOL_MATERIALIZE_DATALESS_FILES_ON = 0x2,  // 2
};

enum macro_iopol_opol_vfs_statfs_flags {
/*line: 542*/   IOPOL_VFS_STATFS_NO_DATA_VOLUME_DEFAULT = 0x0,  // 0
/*line: 543*/   IOPOL_VFS_STATFS_FORCE_NO_DATA_VOLUME = 0x1,  // 1
};

enum macro_iopol_vfs_trigger_resolve {
/*line: 545*/   IOPOL_VFS_TRIGGER_RESOLVE_DEFAULT = 0x0,  // 0
/*line: 546*/   IOPOL_VFS_TRIGGER_RESOLVE_OFF = 0x1,  // 1
};

enum macro_iopol_vfs_content_protection {
/*line: 548*/   IOPOL_VFS_CONTENT_PROTECTION_DEFAULT = 0x0,  // 0
/*line: 549*/   IOPOL_VFS_CONTENT_PROTECTION_IGNORE = 0x1,  // 1
};

enum macro_iopol_vfs_ignore_permissions {
/*line: 551*/   IOPOL_VFS_IGNORE_PERMISSIONS_OFF = 0x0,  // 0
/*line: 552*/   IOPOL_VFS_IGNORE_PERMISSIONS_ON = 0x1,  // 1
};

enum macro_iopol_vfs_skip_mtime_update {
/*line: 554*/   IOPOL_VFS_SKIP_MTIME_UPDATE_OFF = 0x0,  // 0
/*line: 555*/   IOPOL_VFS_SKIP_MTIME_UPDATE_ON = 0x1,  // 1
/*line: 556*/   IOPOL_VFS_SKIP_MTIME_UPDATE_IGNORE = 0x2,  // 2
};

enum macro_iopol_vfs_low_space_writes {
/*line: 558*/   IOPOL_VFS_ALLOW_LOW_SPACE_WRITES_OFF = 0x0,  // 0
/*line: 559*/   IOPOL_VFS_ALLOW_LOW_SPACE_WRITES_ON = 0x1,  // 1
};

enum macro_iopol_vfs_rw_disallow {
/*line: 561*/   IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_DEFAULT = 0x0,  // 0
/*line: 562*/   IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_ON = 0x1,  // 1
};

enum macro_iopol_vfs_no_cache_write {
/*line: 564*/   IOPOL_VFS_NOCACHE_WRITE_FS_BLKSIZE_DEFAULT = 0x0,  // 0
/*line: 565*/   IOPOL_VFS_NOCACHE_WRITE_FS_BLKSIZE_ON = 0x1,  // 1
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 164
// #define ru_first ru_ixrss

// Line: 178
// #define ru_last ru_nivcsw

