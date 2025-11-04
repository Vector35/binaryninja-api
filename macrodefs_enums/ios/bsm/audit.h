// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/bsm/audit.h

// Depends on identifiers
enum macro_audit_constants {
/*line: 38*/    AUDIT_RECORD_MAGIC = 0x828a0f1b,  // 0x828a0f1b
/*line: 39*/    MAX_AUDIT_RECORDS = 0x14,  // 20
/*line: 40*/    MAXAUDITDATA = 0x7fff,  // (0x8000-1)
/*line: 41*/    MAX_AUDIT_RECORD_SIZE = 0x7fff,  // MAXAUDITDATA
/*line: 42*/    MIN_AUDIT_FILE_SIZE = 0x80000,  // (512*1024)
};

enum macro_audit_hard_limit {
/*
 * Minimum noumber of free blocks on the filesystem containing the audit
 * log necessary to avoid a hard log rotation. DO NOT SET THIS VALUE TO 0
 * as the kernel does an unsigned compare, plus we want to leave a few blocks
 * free so userspace can terminate the log, etc.
 */
/*line: 50*/    AUDIT_HARD_LIMIT_FREE_BLOCKS = 0x4,  // 4
};

enum macro_audit_trigger {
/*
 * Triggers for the audit daemon.
 */
/*line: 55*/    AUDIT_TRIGGER_MIN = 0x1,  // 1
/*line: 56*/    AUDIT_TRIGGER_LOW_SPACE = 0x1, /* Below low watermark. */ // 1
/*line: 57*/    AUDIT_TRIGGER_ROTATE_KERNEL = 0x2, /* Kernel requests rotate. */ // 2
/*line: 58*/    AUDIT_TRIGGER_READ_FILE = 0x3, /* Re-read config file. */ // 3
/*line: 59*/    AUDIT_TRIGGER_CLOSE_AND_DIE = 0x4, /* Terminate audit. */ // 4
/*line: 60*/    AUDIT_TRIGGER_NO_SPACE = 0x5, /* Below min free space. */ // 5
/*line: 61*/    AUDIT_TRIGGER_ROTATE_USER = 0x6, /* User requests rotate. */ // 6
/*line: 62*/    AUDIT_TRIGGER_INITIALIZE = 0x7, /* User initialize of auditd. */ // 7
/*line: 63*/    AUDIT_TRIGGER_EXPIRE_TRAILS = 0x8, /* User expiration of trails. */ // 8
/*line: 64*/    AUDIT_TRIGGER_MAX = 0x8,  // 8
};

// Depends on identifiers
enum macro_audit_ids {
/*
 * Pre-defined audit IDs
 */
/*line: 75*/    AU_DEFAUDITID = -0x1,  // (uid_t)(-1)
/*line: 76*/    AU_DEFAUDITSID = 0x0,  // 0
/*line: 77*/    AU_ASSIGN_ASID = -0x1,  // -1
};

enum macro_ipc_type {
/*
 * IPC types.
 */
/*line: 82*/    AT_IPC_MSG = 0x1, /* Message IPC id. */ // ((unsignedchar)1)
/*line: 83*/    AT_IPC_SEM = 0x2, /* Semaphore IPC id. */ // ((unsignedchar)2)
/*line: 84*/    AT_IPC_SHM = 0x3, /* Shared mem IPC id. */ // ((unsignedchar)3)
};

enum macro_audit_flags {
/*
 * Audit conditions.
 */
/*line: 89*/    AUC_UNSET = 0x0,  // 0
/*line: 90*/    AUC_AUDITING = 0x1,  // 1
/*line: 91*/    AUC_NOAUDIT = 0x2,  // 2
/*line: 92*/    AUC_DISABLED = -0x1,  // -1
/*
 * auditon(2) commands.
 */
/*line: 97*/    A_OLDGETPOLICY = 0x2,  // 2
/*line: 98*/    A_OLDSETPOLICY = 0x3,  // 3
/*line: 99*/    A_GETKMASK = 0x4,  // 4
/*line: 100*/   A_SETKMASK = 0x5,  // 5
/*line: 101*/   A_OLDGETQCTRL = 0x6,  // 6
/*line: 102*/   A_OLDSETQCTRL = 0x7,  // 7
/*line: 103*/   A_GETCWD = 0x8,  // 8
/*line: 104*/   A_GETCAR = 0x9,  // 9
/*line: 105*/   A_GETSTAT = 0xc,  // 12
/*line: 106*/   A_SETSTAT = 0xd,  // 13
/*line: 107*/   A_SETUMASK = 0xe,  // 14
/*line: 108*/   A_SETSMASK = 0xf,  // 15
/*line: 109*/   A_OLDGETCOND = 0x14,  // 20
/*line: 110*/   A_OLDSETCOND = 0x15,  // 21
/*line: 111*/   A_GETCLASS = 0x16,  // 22
/*line: 112*/   A_SETCLASS = 0x17,  // 23
/*line: 113*/   A_GETPINFO = 0x18,  // 24
/*line: 114*/   A_SETPMASK = 0x19,  // 25
/*line: 115*/   A_SETFSIZE = 0x1a,  // 26
/*line: 116*/   A_GETFSIZE = 0x1b,  // 27
/*line: 117*/   A_GETPINFO_ADDR = 0x1c,  // 28
/*line: 118*/   A_GETKAUDIT = 0x1d,  // 29
/*line: 119*/   A_SETKAUDIT = 0x1e,  // 30
/*line: 120*/   A_SENDTRIGGER = 0x1f,  // 31
/*line: 121*/   A_GETSINFO_ADDR = 0x20,  // 32
/*line: 122*/   A_GETPOLICY = 0x21,  // 33
/*line: 123*/   A_SETPOLICY = 0x22,  // 34
/*line: 124*/   A_GETQCTRL = 0x23,  // 35
/*line: 125*/   A_SETQCTRL = 0x24,  // 36
/*line: 126*/   A_GETCOND = 0x25,  // 37
/*line: 127*/   A_SETCOND = 0x26,  // 38
/*line: 128*/   A_GETSFLAGS = 0x27,  // 39
/*line: 129*/   A_SETSFLAGS = 0x28,  // 40
/*line: 130*/   A_GETCTLMODE = 0x29,  // 41
/*line: 131*/   A_SETCTLMODE = 0x2a,  // 42
/*line: 132*/   A_GETEXPAFTER = 0x2b,  // 43
/*line: 133*/   A_SETEXPAFTER = 0x2c,  // 44
};

enum macro_audit_policy {
/*
 * Audit policy controls.
 */
/*line: 138*/   AUDIT_CNT = 0x1,  // 0x0001
/*line: 139*/   AUDIT_AHLT = 0x2,  // 0x0002
/*line: 140*/   AUDIT_ARGV = 0x4,  // 0x0004
/*line: 141*/   AUDIT_ARGE = 0x8,  // 0x0008
/*line: 142*/   AUDIT_SEQ = 0x10,  // 0x0010
/*line: 143*/   AUDIT_WINDATA = 0x20,  // 0x0020
/*line: 144*/   AUDIT_USER = 0x40,  // 0x0040
/*line: 145*/   AUDIT_GROUP = 0x80,  // 0x0080
/*line: 146*/   AUDIT_TRAIL = 0x100,  // 0x0100
/*line: 147*/   AUDIT_PATH = 0x200,  // 0x0200
/*line: 148*/   AUDIT_SCNT = 0x400,  // 0x0400
/*line: 149*/   AUDIT_PUBLIC = 0x800,  // 0x0800
/*line: 150*/   AUDIT_ZONENAME = 0x1000,  // 0x1000
/*line: 151*/   AUDIT_PERZONE = 0x2000,  // 0x2000
};

// Depends on identifiers
enum macro_audit_queue_limits {
/*
 * Default audit queue control parameters.
 */
/*line: 156*/   AQ_HIWATER = 0x64,  // 100
/*line: 157*/   AQ_MAXHIGH = 0x2710,  // 10000
/*line: 158*/   AQ_LOWATER = 0xa,  // 10
/*line: 159*/   AQ_BUFSZ = 0x7fff,  // MAXAUDITDATA
/*line: 160*/   AQ_MAXBUFSZ = 0x100000,  // 1048576
};

enum macro_fs_minfree {
/*
 * Default minimum percentage free space on file system.
 */
/*line: 165*/   AU_FS_MINFREE = 0x14,  // 20
};

enum macro_address_family {
/*
 * Type definitions used indicating the length of variable length addresses
 * in tokens containing addresses, such as header fields.
 */
/*line: 171*/   AU_IPv4 = 0x4,  // 4
/*line: 172*/   AU_IPv6 = 0x10,  // 16
};

enum macro_reserved_audit_class {
/*
 * Reserved audit class mask indicating which classes are unable to have
 * events added or removed by unentitled processes.
 */
/*line: 178*/   AU_CLASS_MASK_RESERVED = 0x10000000,  // 0x10000000
};

enum macro_audit_control_mode {
/*
 * Audit control modes
 */
/*line: 183*/   AUDIT_CTLMODE_NORMAL = 0x1,  // ((unsignedchar)1)
/*line: 184*/   AUDIT_CTLMODE_EXTERNAL = 0x2,  // ((unsignedchar)2)
};

enum macro_expire_op_mode {
/*
 * Audit file expire_after op modes
 */
/*line: 189*/   AUDIT_EXPIRE_OP_AND = 0x0,  // ((unsignedchar)0)
/*line: 190*/   AUDIT_EXPIRE_OP_OR = 0x1,  // ((unsignedchar)1)
};

