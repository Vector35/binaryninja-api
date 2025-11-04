// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/pthread/pthread_impl.h

enum macro_pthread_mutex_sig {
/*
 * [Internal] data structure signatures
 */
/*line: 41*/    _PTHREAD_MUTEX_SIG_init = 0x32aaaba7,  // 0x32AAABA7
};

enum macro_pthread_signatures {
/*line: 43*/    _PTHREAD_ERRORCHECK_MUTEX_SIG_init = 0x32aaaba1,  // 0x32AAABA1
/*line: 44*/    _PTHREAD_RECURSIVE_MUTEX_SIG_init = 0x32aaaba2,  // 0x32AAABA2
/*line: 45*/    _PTHREAD_FIRSTFIT_MUTEX_SIG_init = 0x32aaaba3,  // 0x32AAABA3
/*line: 47*/    _PTHREAD_COND_SIG_init = 0x3cb0b1bb,  // 0x3CB0B1BB
/*line: 48*/    _PTHREAD_ONCE_SIG_init = 0x30b1bcba,  // 0x30B1BCBA
/*line: 49*/    _PTHREAD_RWLOCK_SIG_init = 0x2da8b3b4,  // 0x2DA8B3B4
};

enum macro_sched_policy {
/*
 * POSIX scheduling policies
 */
/*line: 54*/    SCHED_OTHER = 0x1,  // 1
/*line: 55*/    SCHED_FIFO = 0x4,  // 4
/*line: 56*/    SCHED_RR = 0x2,  // 2
};

enum macro_sched_param_size {
/*line: 58*/    __SCHED_PARAM_SIZE__ = 0x4,  // 4
};

