// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/ipc.h

enum macro_ipc_flags {
/* Mode bits */
/*line: 145*/   IPC_CREAT = 0x200, /* Create entry if key does not exist */ // 001000
/*line: 146*/   IPC_EXCL = 0x400, /* Fail if key exists */ // 002000
/*line: 147*/   IPC_NOWAIT = 0x800, /* Error if request must wait */ // 004000
};

// Depends on identifiers
enum macro_ipc_private {
/* Keys */
/*line: 150*/   IPC_PRIVATE = 0x0, /* Private key */ // ((key_t)0)
};

enum macro_ipc_control_flags {
/* Control commands */
/*line: 153*/   IPC_RMID = 0x0, /* Remove identifier */ // 0
/*line: 154*/   IPC_SET = 0x1, /* Set options */ // 1
/*line: 155*/   IPC_STAT = 0x2, /* Get options */ // 2
/* common mode bits */
/*line: 161*/   IPC_R = 0x100, /* Read permission */ // 000400
/*line: 162*/   IPC_W = 0x80, /* Write/alter permission */ // 000200
/*line: 163*/   IPC_M = 0x1000, /* Modify control info permission */ // 010000
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 116
// #define __ipc_perm_new ipc_perm

