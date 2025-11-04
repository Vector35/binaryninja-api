// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/proc.h

enum macro_process_status {
/* Status values. */
/*line: 148*/   SIDL = 0x1, /* Process being created by fork. */ // 1
/*line: 149*/   SRUN = 0x2, /* Currently runnable. */ // 2
/*line: 150*/   SSLEEP = 0x3, /* Sleeping on an address. */ // 3
/*line: 151*/   SSTOP = 0x4, /* Process debugging or suspension. */ // 4
/*line: 152*/   SZOMB = 0x5, /* Awaiting collection by parent. */ // 5
};

// Depends on identifiers
enum macro_proc_flags {
/* These flags are kept in extern_proc.p_flag. */
/*line: 155*/   P_ADVLOCK = 0x1, /* Process may hold POSIX adv. lock */ // 0x00000001
/*line: 156*/   P_CONTROLT = 0x2, /* Has a controlling terminal */ // 0x00000002
/*line: 157*/   P_LP64 = 0x4, /* Process is LP64 */ // 0x00000004
/*line: 158*/   P_NOCLDSTOP = 0x8, /* No SIGCHLD when children stop */ // 0x00000008
/*line: 160*/   P_PPWAIT = 0x10, /* Parent waiting for chld exec/exit */ // 0x00000010
/*line: 161*/   P_PROFIL = 0x20, /* Has started profiling */ // 0x00000020
/*line: 162*/   P_SELECT = 0x40, /* Selecting; wakeup/waiting danger */ // 0x00000040
/*line: 163*/   P_CONTINUED = 0x80, /* Process was stopped and continued */ // 0x00000080
/*line: 165*/   P_SUGID = 0x100, /* Has set privileges since last exec */ // 0x00000100
/*line: 166*/   P_SYSTEM = 0x200, /* Sys proc: no sigs, stats or swap */ // 0x00000200
/*line: 167*/   P_TIMEOUT = 0x400, /* Timing out during sleep */ // 0x00000400
/*line: 168*/   P_TRACED = 0x800, /* Debugged process being traced */ // 0x00000800
/*line: 170*/   P_DISABLE_ASLR = 0x1000, /* Disable address space layout randomization */ // 0x00001000
/*line: 171*/   P_WEXIT = 0x2000, /* Working on exiting */ // 0x00002000
/*line: 172*/   P_EXEC = 0x4000, /* Process called exec. */ // 0x00004000
/* Should be moved to machine-dependent areas. */
/*line: 175*/   P_OWEUPC = 0x8000, /* Owe process an addupc() call at next ast. */ // 0x00008000
/*line: 177*/   P_AFFINITY = 0x10000, /* xxx */ // 0x00010000
/*line: 178*/   P_TRANSLATED = 0x20000, /* xxx */ // 0x00020000
/*line: 179*/   P_CLASSIC = 0x20000, /* xxx */ // P_TRANSLATED
/*line: 181*/   P_DELAYIDLESLEEP = 0x40000, /* Process is marked to delay idle sleep on disk IO */ // 0x00040000
/*line: 182*/   P_CHECKOPENEVT = 0x80000, /* check if a vnode has the OPENEVT flag set on open */ // 0x00080000
/*line: 184*/   P_DEPENDENCY_CAPABLE = 0x100000, /* process is ok to call vfs_markdependency() */ // 0x00100000
/*line: 185*/   P_REBOOT = 0x200000, /* Process called reboot() */ // 0x00200000
/*line: 186*/   P_RESV6 = 0x400000, /* used to be P_TBE */ // 0x00400000
/*line: 187*/   P_RESV7 = 0x800000, /* (P_SIGEXC)signal exceptions */ // 0x00800000
/*line: 189*/   P_THCWD = 0x1000000, /* process has thread cwd  */ // 0x01000000
/*line: 190*/   P_RESV9 = 0x2000000, /* (P_VFORK)process has vfork children */ // 0x02000000
/*line: 191*/   P_ADOPTPERSONA = 0x4000000, /* process adopted a persona (used to be P_NOATTACH) */ // 0x04000000
/*line: 192*/   P_RESV11 = 0x8000000, /* (P_INVFORK) proc in vfork */ // 0x08000000
/*line: 194*/   P_NOSHLIB = 0x10000000, /* no shared libs are in use for proc */ // 0x10000000
/* flag set on exec */
/*line: 196*/   P_FORCEQUOTA = 0x20000000, /* Force quota for root */ // 0x20000000
/*line: 197*/   P_NOCLDWAIT = 0x40000000, /* No zombies when chil procs exit */ // 0x40000000
/*line: 198*/   P_NOREMOTEHANG = 0x80000000, /* Don't hang on remote FS ops */ // 0x80000000
};

enum macro_obsolete_flags {
/*line: 200*/   P_INMEM = 0x0, /* Obsolete: retained for compilation */ // 0
/*line: 201*/   P_NOSWAP = 0x0, /* Obsolete: retained for compilation */ // 0
/*line: 202*/   P_PHYSIO = 0x0, /* Obsolete: retained for compilation */ // 0
/*line: 203*/   P_FSTRACE = 0x0, /* Obsolete: retained for compilation */ // 0
/*line: 204*/   P_SSTEP = 0x0, /* Obsolete: retained for compilation */ // 0
};

enum macro_dirty_flags {
/*line: 206*/   P_DIRTY_TRACK = 0x1, /* track dirty state */ // 0x00000001
/*line: 207*/   P_DIRTY_ALLOW_IDLE_EXIT = 0x2, /* process can be idle-exited when clean */ // 0x00000002
/*line: 208*/   P_DIRTY_DEFER = 0x4, /* defer initial opt-in to idle-exit */ // 0x00000004
/*line: 209*/   P_DIRTY = 0x8, /* process is dirty */ // 0x00000008
/*line: 210*/   P_DIRTY_SHUTDOWN = 0x10, /* process is dirty during shutdown */ // 0x00000010
/*line: 211*/   P_DIRTY_TERMINATED = 0x20, /* process has been marked for termination */ // 0x00000020
/*line: 212*/   P_DIRTY_BUSY = 0x40, /* serialization flag */ // 0x00000040
/*line: 213*/   P_DIRTY_MARKED = 0x80, /* marked dirty previously */ // 0x00000080
/*line: 214*/   P_DIRTY_AGING_IN_PROGRESS = 0x100, /* aging in one of the 'aging bands' */ // 0x00000100
/*line: 215*/   P_DIRTY_LAUNCH_IN_PROGRESS = 0x200, /* launch is in progress */ // 0x00000200
/*line: 216*/   P_DIRTY_DEFER_ALWAYS = 0x400, /* defer going to idle-exit after every dirty->clean transition.
	                                                         * For legacy jetsam policy only. This is the default with the other policies.*/ // 0x00000400
/*line: 218*/   P_DIRTY_SHUTDOWN_ON_CLEAN = 0x800, /* process should shutdown on going clean */ // 0x00000800
/*line: 220*/   P_DIRTY_IS_DIRTY = 0x18,  // (P_DIRTY|P_DIRTY_SHUTDOWN)
/*line: 221*/   P_DIRTY_IDLE_EXIT_ENABLED = 0x3,  // (P_DIRTY_TRACK|P_DIRTY_ALLOW_IDLE_EXIT)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 99
// #define p_forw p_un.p_st1.__p_forw

// Line: 100
// #define p_back p_un.p_st1.__p_back

// Line: 101
// #define p_starttime p_un.__p_starttime

