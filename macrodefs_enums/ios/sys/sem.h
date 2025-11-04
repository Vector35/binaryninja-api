// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/sem.h

enum macro_semctl_operation {
/*
 * Possible values for the third argument to semctl()
 */
/*line: 122*/   GETNCNT = 0x3, /* [XSI] Return the value of semncnt {READ} */ // 3
/*line: 123*/   GETPID = 0x4, /* [XSI] Return the value of sempid {READ} */ // 4
/*line: 124*/   GETVAL = 0x5, /* [XSI] Return the value of semval {READ} */ // 5
/*line: 125*/   GETALL = 0x6, /* [XSI] Return semvals into arg.array {READ} */ // 6
/*line: 126*/   GETZCNT = 0x7, /* [XSI] Return the value of semzcnt {READ} */ // 7
/*line: 127*/   SETVAL = 0x8, /* [XSI] Set the value of semval to arg.val {ALTER} */ // 8
/*line: 128*/   SETALL = 0x9, /* [XSI] Set semvals from arg.array {ALTER} */ // 9
};

enum macro_sem_undo {
/*
 * Possible flag values for sem_flg
 */
/*line: 152*/   SEM_UNDO = 0x1000, /* [XSI] Set up adjust on exit entry */ // 010000
};

enum macro_sem_permissions {
/*
 * Permissions
 */
/*line: 188*/   SEM_A = 0x80, /* alter permission */ // 0200
/*line: 189*/   SEM_R = 0x100, /* read permission */ // 0400
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 84
// #define semid_ds __semid_ds_new

