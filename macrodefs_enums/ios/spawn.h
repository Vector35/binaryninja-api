// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/spawn.h

enum macro_csm_flags {
/*
 * flags for CPU Security Mitigation attribute
 * POSIX_SPAWN_NP_CSM_ALL should be used in most cases,
 * the individual flags are provided only for performance evaluation etc
 */
/*line: 169*/   POSIX_SPAWN_NP_CSM_ALL = 0x1,  // 0x0001
/*line: 170*/   POSIX_SPAWN_NP_CSM_NOSMT = 0x2,  // 0x0002
/*line: 171*/   POSIX_SPAWN_NP_CSM_TECS = 0x4,  // 0x0004
};

