// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/wait.h

enum macro_wait_options {
/*
 * Option bits for the third argument of wait4.  WNOHANG causes the
 * wait to not hang if there are no stopped or terminated processes, rather
 * returning an error indication in this case (pid==0).  WUNTRACED
 * indicates that the caller should receive status about untraced children
 * which stop due to signals.  If children are stopped and a wait without
 * this option is done, it is as though they were still running... nothing
 * about them is returned.
 */
/*line: 121*/   WNOHANG = 0x1, /* [XSI] no hang in wait/no child to reap */ // 0x00000001
/*line: 122*/   WUNTRACED = 0x2, /* [XSI] notify on stop, untraced child */ // 0x00000002
/*line: 132*/   WCOREFLAG = 0x80,  // 0200
/*line: 137*/   _WSTOPPED = 0x7f, /* _WSTATUS if process is stopped */ // 0177
};

enum macro_wait_status {
/* WUNTRACED defined for wait4() but not for waitid() */
/*line: 168*/   WEXITED = 0x4, /* [XSI] Processes which have exitted */ // 0x00000004
/* waitid() parameter */
/*line: 171*/   WSTOPPED = 0x8, /* [XSI] Any child stopped by signal */ // 0x00000008
/*line: 173*/   WCONTINUED = 0x10, /* [XSI] Any child stopped then continued */ // 0x00000010
/*line: 174*/   WNOWAIT = 0x20, /* [XSI] Leave process returned waitable */ // 0x00000020
};

enum macro_wait_pid {
/*
 * Tokens for special values of the "pid" parameter to wait4.
 */
/*line: 183*/   WAIT_ANY = -0x1, /* any process */ // (-1)
/*line: 184*/   WAIT_MYPGRP = 0x0, /* any process in my process group */ // 0
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 229
// #define w_termsig w_T.w_Termsig

// Line: 230
// #define w_coredump w_T.w_Coredump

// Line: 231
// #define w_retcode w_T.w_Retcode

// Line: 232
// #define w_stopval w_S.w_Stopval

// Line: 233
// #define w_stopsig w_S.w_Stopsig

