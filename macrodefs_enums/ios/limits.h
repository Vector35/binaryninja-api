// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/limits.h

enum macro_posix_limits {
  /*line: 68*/ _POSIX_ARG_MAX = 0x1000,                    // 4096
  /*line: 69*/ _POSIX_CHILD_MAX = 0x19,                    // 25
  /*line: 70*/ _POSIX_LINK_MAX = 0x8,                      // 8
  /*line: 71*/ _POSIX_MAX_CANON = 0xff,                    // 255
  /*line: 72*/ _POSIX_MAX_INPUT = 0xff,                    // 255
  /*line: 73*/ _POSIX_NAME_MAX = 0xe,                      // 14
  /*line: 74*/ _POSIX_NGROUPS_MAX = 0x8,                   // 8
  /*line: 75*/ _POSIX_OPEN_MAX = 0x14,                     // 20
  /*line: 76*/ _POSIX_PATH_MAX = 0x100,                    // 256
  /*line: 77*/ _POSIX_PIPE_BUF = 0x200,                    // 512
  /*line: 78*/ _POSIX_SSIZE_MAX = 0x7fff,                  // 32767
  /*line: 79*/ _POSIX_STREAM_MAX = 0x8,                    // 8
  /*line: 80*/ _POSIX_TZNAME_MAX = 0x6,                    // 6
  /*line: 93*/ _POSIX_AIO_LISTIO_MAX = 0x2,                // 2
  /*line: 94*/ _POSIX_AIO_MAX = 0x1,                       // 1
  /*line: 95*/ _POSIX_DELAYTIMER_MAX = 0x20,               // 32
  /*line: 96*/ _POSIX_MQ_OPEN_MAX = 0x8,                   // 8
  /*line: 97*/ _POSIX_MQ_PRIO_MAX = 0x20,                  // 32
  /*line: 98*/ _POSIX_RTSIG_MAX = 0x8,                     // 8
  /*line: 99*/ _POSIX_SEM_NSEMS_MAX = 0x100,               // 256
  /*line: 100*/ _POSIX_SEM_VALUE_MAX = 0x7fff,             // 32767
  /*line: 101*/ _POSIX_SIGQUEUE_MAX = 0x20,                // 32
  /*line: 102*/ _POSIX_TIMER_MAX = 0x20,                   // 32
  /*line: 82*/ _POSIX2_BC_BASE_MAX = 0x63,                 // 99
  /*line: 83*/ _POSIX2_BC_DIM_MAX = 0x800,                 // 2048
  /*line: 84*/ _POSIX2_BC_SCALE_MAX = 0x63,                // 99
  /*line: 85*/ _POSIX2_BC_STRING_MAX = 0x3e8,              // 1000
  /*line: 86*/ _POSIX2_EQUIV_CLASS_MAX = 0x2,              // 2
  /*line: 87*/ _POSIX2_EXPR_NEST_MAX = 0x20,               // 32
  /*line: 88*/ _POSIX2_LINE_MAX = 0x800,                   // 2048
  /*line: 89*/ _POSIX2_RE_DUP_MAX = 0xff,                  // 255
  /*line: 122*/ _POSIX_HOST_NAME_MAX = 0xff,               // 255
  /*line: 123*/ _POSIX_LOGIN_NAME_MAX = 0x9,               // 9
  /*line: 124*/ _POSIX_SS_REPL_MAX = 0x4,                  // 4
  /*line: 125*/ _POSIX_SYMLINK_MAX = 0xff,                 // 255
  /*line: 126*/ _POSIX_SYMLOOP_MAX = 0x8,                  // 8
  /*line: 127*/ _POSIX_TRACE_EVENT_NAME_MAX = 0x1e,        // 30
  /*line: 128*/ _POSIX_TRACE_NAME_MAX = 0x8,               // 8
  /*line: 129*/ _POSIX_TRACE_SYS_MAX = 0x8,                // 8
  /*line: 130*/ _POSIX_TRACE_USER_EVENT_MAX = 0x20,        // 32
  /*line: 131*/ _POSIX_TTY_NAME_MAX = 0x9,                 // 9
  /*line: 132*/ _POSIX2_CHARCLASS_NAME_MAX = 0xe,          // 14
  /*line: 133*/ _POSIX2_COLL_WEIGHTS_MAX = 0x2,            // 2
  /*line: 135*/ _POSIX_RE_DUP_MAX = 0xff,                  // _POSIX2_RE_DUP_MAX
  /*line: 108*/ _POSIX_THREAD_DESTRUCTOR_ITERATIONS = 0x4, // 4
  /*line: 109*/ _POSIX_THREAD_KEYS_MAX = 0x80,             // 128
  /*line: 110*/ _POSIX_THREAD_THREADS_MAX = 0x40,          // 64
  /*line: 104*/ _POSIX_CLOCKRES_MIN = 0x1312d00,           // 20000000
  /*line: 112*/ PTHREAD_DESTRUCTOR_ITERATIONS = 0x4,       // 4
  /*line: 113*/ PTHREAD_KEYS_MAX = 0x200,                  // 512
  /*line: 115*/ PTHREAD_STACK_MIN = 0x4000,                // 16384
  /*line: 139*/ OFF_MIN = -0x8000000000000000,
  /* min value for an off_t */ // LLONG_MIN
  /*line: 140*/ OFF_MAX = 0x7fffffffffffffff,
  /* max value for an off_t */   // LLONG_MAX
  /*line: 148*/ PASS_MAX = 0x80, // 128
};

enum macro_nl_limits {
  /*line: 151*/ NL_ARGMAX = 0x9,    // 9
  /*line: 152*/ NL_LANGMAX = 0xe,   // 14
  /*line: 153*/ NL_MSGMAX = 0x7fff, // 32767
  /*line: 154*/ NL_NMAX = 0x1,      // 1
  /*line: 155*/ NL_SETMAX = 0xff,   // 255
  /*line: 156*/ NL_TEXTMAX = 0x800, // 2048
};

enum macro_xopen_limits {
  /*line: 158*/ _XOPEN_IOV_MAX = 0x10,   // 16
  /*line: 159*/ IOV_MAX = 0x400,         // 1024
  /*line: 160*/ _XOPEN_NAME_MAX = 0xff,  // 255
  /*line: 161*/ _XOPEN_PATH_MAX = 0x400, // 1024
};
