// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/shm.h

enum macro_shmat_flags {
/*
 * Possible flag values which may be OR'ed into the third argument to
 * shmat()
 */
/*line: 100*/   SHM_RDONLY = 0x1000, /* [XSI] Attach read-only (else read-write) */ // 010000
/*line: 101*/   SHM_RND = 0x2000, /* [XSI] Round attach address to SHMLBA */ // 020000
};

enum macro_shmlba {
/*line: 113*/   SHMLBA = 0x4000, /* [XSI] Segment low boundary address multiple*/ // (16*1024)
};

// Depends on identifiers
enum macro_shm_access {
/* "official" access mode definitions; somewhat braindead since you have
 *  to specify (SHM_* >> 3) for group and (SHM_* >> 6) for world permissions */
/*line: 120*/   SHM_R = 0x100,  // (IPC_R)
/*line: 121*/   SHM_W = 0x80,  // (IPC_W)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 144
// #define shmid_ds __shmid_ds_new

