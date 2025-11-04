// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/pthread/pthread.h

enum macro_pthread_create_flags {
/*
 * Thread attributes
 */
/*line: 135*/   PTHREAD_CREATE_JOINABLE = 0x1,  // 1
/*line: 136*/   PTHREAD_CREATE_DETACHED = 0x2,  // 2
};

enum macro_pthread_sched {
/*line: 138*/   PTHREAD_INHERIT_SCHED = 0x1,  // 1
/*line: 139*/   PTHREAD_EXPLICIT_SCHED = 0x2,  // 2
};

enum macro_pthread_cancel_state {
/*line: 141*/   PTHREAD_CANCEL_ENABLE = 0x1, /* Cancel takes place at next cancellation point */ // 0x01
/*line: 142*/   PTHREAD_CANCEL_DISABLE = 0x0, /* Cancel postponed */ // 0x00
/*line: 143*/   PTHREAD_CANCEL_DEFERRED = 0x2, /* Cancel waits until cancellation point */ // 0x02
/*line: 144*/   PTHREAD_CANCEL_ASYNCHRONOUS = 0x0, /* Cancel occurs immediately */ // 0x00
};

enum macro_pthread_canceled {
/* Value returned from pthread_join() when a thread is canceled */
/*line: 147*/   PTHREAD_CANCELED = 0x1,  // ((void*)1)
};

enum macro_pthread_scope {
/* We only support PTHREAD_SCOPE_SYSTEM */
/*line: 150*/   PTHREAD_SCOPE_SYSTEM = 0x1,  // 1
/*line: 151*/   PTHREAD_SCOPE_PROCESS = 0x2,  // 2
};

enum macro_pthread_process_share {
/*line: 153*/   PTHREAD_PROCESS_SHARED = 0x1,  // 1
/*line: 154*/   PTHREAD_PROCESS_PRIVATE = 0x2,  // 2
};

enum macro_mutex_protocol {
/*
 * Mutex protocol attributes
 */
/*line: 159*/   PTHREAD_PRIO_NONE = 0x0,  // 0
/*line: 160*/   PTHREAD_PRIO_INHERIT = 0x1,  // 1
/*line: 161*/   PTHREAD_PRIO_PROTECT = 0x2,  // 2
};

// Depends on identifiers
enum macro_mutex_type {
/*
 * Mutex type attributes
 */
/*line: 166*/   PTHREAD_MUTEX_NORMAL = 0x0,  // 0
/*line: 167*/   PTHREAD_MUTEX_ERRORCHECK = 0x1,  // 1
/*line: 168*/   PTHREAD_MUTEX_RECURSIVE = 0x2,  // 2
/*line: 169*/   PTHREAD_MUTEX_DEFAULT = 0x0,  // PTHREAD_MUTEX_NORMAL
};

enum macro_mutex_policy {
/*
 * Mutex policy attributes
 */
/*line: 174*/   PTHREAD_MUTEX_POLICY_FAIRSHARE_NP = 0x1,  // 1
/*line: 175*/   PTHREAD_MUTEX_POLICY_FIRSTFIT_NP = 0x3,  // 3
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 180
// #define PTHREAD_RWLOCK_INITIALIZER {_PTHREAD_RWLOCK_SIG_init, {0}}

// Line: 185
// #define PTHREAD_MUTEX_INITIALIZER {_PTHREAD_MUTEX_SIG_init, {0}}

// Line: 190
// #define PTHREAD_ERRORCHECK_MUTEX_INITIALIZER {_PTHREAD_ERRORCHECK_MUTEX_SIG_init, {0}}

// Line: 191
// #define PTHREAD_RECURSIVE_MUTEX_INITIALIZER {_PTHREAD_RECURSIVE_MUTEX_SIG_init, {0}}

// Line: 214
// #define PTHREAD_COND_INITIALIZER {_PTHREAD_COND_SIG_init, {0}}

// Line: 220
// #define PTHREAD_ONCE_INIT {_PTHREAD_ONCE_SIG_init, {0}}

