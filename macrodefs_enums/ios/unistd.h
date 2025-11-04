// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/unistd.h

enum macro_file_descriptors {
/*line: 90*/    STDIN_FILENO = 0x0, /* standard input file descriptor */ // 0
/*line: 91*/    STDOUT_FILENO = 0x1, /* standard output file descriptor */ // 1
/*line: 92*/    STDERR_FILENO = 0x2, /* standard error file descriptor */ // 2
};

enum macro_posix_xopen_version {
/* _POSIX_VERSION and _POSIX2_VERSION from sys/unistd.h */
/*line: 97*/    _XOPEN_VERSION = 0x258, /* [XSI] */ // 600
/*line: 98*/    _XOPEN_XCU_VERSION = 0x4, /* Older standard */ // 4
};

enum macro_posix_features {
/* Please keep this list in the same order as the applicable standard */
/*line: 102*/   _POSIX_ADVISORY_INFO = -0x1, /* [ADV] */ // (-1)
/*line: 103*/   _POSIX_ASYNCHRONOUS_IO = -0x1, /* [AIO] */ // (-1)
/*line: 104*/   _POSIX_BARRIERS = -0x1, /* [BAR] */ // (-1)
/*line: 105*/   _POSIX_CHOWN_RESTRICTED = 0x30db0,  // 200112L
/*line: 106*/   _POSIX_CLOCK_SELECTION = -0x1, /* [CS] */ // (-1)
/*line: 107*/   _POSIX_CPUTIME = -0x1, /* [CPT] */ // (-1)
/*line: 108*/   _POSIX_FSYNC = 0x30db0, /* [FSC] */ // 200112L
/*line: 109*/   _POSIX_IPV6 = 0x30db0,  // 200112L
/*line: 110*/   _POSIX_JOB_CONTROL = 0x30db0,  // 200112L
/*line: 111*/   _POSIX_MAPPED_FILES = 0x30db0, /* [MF] */ // 200112L
/*line: 112*/   _POSIX_MEMLOCK = -0x1, /* [ML] */ // (-1)
/*line: 113*/   _POSIX_MEMLOCK_RANGE = -0x1, /* [MR] */ // (-1)
/*line: 114*/   _POSIX_MEMORY_PROTECTION = 0x30db0, /* [MPR] */ // 200112L
/*line: 115*/   _POSIX_MESSAGE_PASSING = -0x1, /* [MSG] */ // (-1)
/*line: 116*/   _POSIX_MONOTONIC_CLOCK = -0x1, /* [MON] */ // (-1)
/*line: 117*/   _POSIX_NO_TRUNC = 0x30db0,  // 200112L
/*line: 118*/   _POSIX_PRIORITIZED_IO = -0x1, /* [PIO] */ // (-1)
/*line: 119*/   _POSIX_PRIORITY_SCHEDULING = -0x1, /* [PS] */ // (-1)
/*line: 120*/   _POSIX_RAW_SOCKETS = -0x1, /* [RS] */ // (-1)
/*line: 121*/   _POSIX_READER_WRITER_LOCKS = 0x30db0, /* [THR] */ // 200112L
/*line: 122*/   _POSIX_REALTIME_SIGNALS = -0x1, /* [RTS] */ // (-1)
/*line: 123*/   _POSIX_REGEXP = 0x30db0,  // 200112L
/*line: 124*/   _POSIX_SAVED_IDS = 0x30db0, /* XXX required */ // 200112L
/*line: 125*/   _POSIX_SEMAPHORES = -0x1, /* [SEM] */ // (-1)
/*line: 126*/   _POSIX_SHARED_MEMORY_OBJECTS = -0x1, /* [SHM] */ // (-1)
/*line: 127*/   _POSIX_SHELL = 0x30db0,  // 200112L
/*line: 128*/   _POSIX_SPAWN = 0x30db0, /* [SPN] */ // 200112L
/*line: 129*/   _POSIX_SPIN_LOCKS = -0x1, /* [SPI] */ // (-1)
/*line: 130*/   _POSIX_SPORADIC_SERVER = -0x1, /* [SS] */ // (-1)
/*line: 131*/   _POSIX_SYNCHRONIZED_IO = -0x1, /* [SIO] */ // (-1)
/*line: 132*/   _POSIX_THREAD_ATTR_STACKADDR = 0x30db0, /* [TSA] */ // 200112L
/*line: 133*/   _POSIX_THREAD_ATTR_STACKSIZE = 0x30db0, /* [TSS] */ // 200112L
/*line: 134*/   _POSIX_THREAD_CPUTIME = -0x1, /* [TCT] */ // (-1)
/*line: 135*/   _POSIX_THREAD_PRIO_INHERIT = -0x1, /* [TPI] */ // (-1)
/*line: 136*/   _POSIX_THREAD_PRIO_PROTECT = -0x1, /* [TPP] */ // (-1)
/*line: 137*/   _POSIX_THREAD_PRIORITY_SCHEDULING = -0x1, /* [TPS] */ // (-1)
/*line: 138*/   _POSIX_THREAD_PROCESS_SHARED = 0x30db0, /* [TSH] */ // 200112L
/*line: 139*/   _POSIX_THREAD_SAFE_FUNCTIONS = 0x30db0, /* [TSF] */ // 200112L
/*line: 140*/   _POSIX_THREAD_SPORADIC_SERVER = -0x1, /* [TSP] */ // (-1)
/*line: 141*/   _POSIX_THREADS = 0x30db0, /* [THR] */ // 200112L
/*line: 142*/   _POSIX_TIMEOUTS = -0x1, /* [TMO] */ // (-1)
/*line: 143*/   _POSIX_TIMERS = -0x1, /* [TMR] */ // (-1)
/*line: 144*/   _POSIX_TRACE = -0x1, /* [TRC] */ // (-1)
/*line: 145*/   _POSIX_TRACE_EVENT_FILTER = -0x1, /* [TEF] */ // (-1)
/*line: 146*/   _POSIX_TRACE_INHERIT = -0x1, /* [TRI] */ // (-1)
/*line: 147*/   _POSIX_TRACE_LOG = -0x1, /* [TRL] */ // (-1)
/*line: 148*/   _POSIX_TYPED_MEMORY_OBJECTS = -0x1, /* [TYM] */ // (-1)
};

enum macro_posix2_features {
/*line: 154*/   _POSIX2_C_BIND = 0x30db0,  // 200112L
/*line: 155*/   _POSIX2_C_DEV = 0x30db0, /* c99 command */ // 200112L
/*line: 156*/   _POSIX2_CHAR_TERM = 0x30db0,  // 200112L
/*line: 157*/   _POSIX2_FORT_DEV = -0x1, /* fort77 command */ // (-1)
/*line: 158*/   _POSIX2_FORT_RUN = 0x30db0,  // 200112L
/*line: 159*/   _POSIX2_LOCALEDEF = 0x30db0, /* localedef command */ // 200112L
/*line: 160*/   _POSIX2_PBS = -0x1,  // (-1)
/*line: 161*/   _POSIX2_PBS_ACCOUNTING = -0x1,  // (-1)
/*line: 162*/   _POSIX2_PBS_CHECKPOINT = -0x1,  // (-1)
/*line: 163*/   _POSIX2_PBS_LOCATE = -0x1,  // (-1)
/*line: 164*/   _POSIX2_PBS_MESSAGE = -0x1,  // (-1)
/*line: 165*/   _POSIX2_PBS_TRACK = -0x1,  // (-1)
/*line: 166*/   _POSIX2_SW_DEV = 0x30db0,  // 200112L
/*line: 167*/   _POSIX2_UPE = 0x30db0, /* XXXX no fc, newgrp, tabs */ // 200112L
};

enum macro_system_data_model_options {
/*line: 170*/   __ILP32_OFF32 = -0x1,  // (-1)
/*line: 171*/   __ILP32_OFFBIG = -0x1,  // (-1)
/*line: 173*/   __LP64_OFF64 = 0x1,  // (1)
/*line: 174*/   __LPBIG_OFFBIG = 0x1,  // (1)
};

enum macro_posix_v6_data_model_options {
/*line: 177*/   _POSIX_V6_ILP32_OFF32 = -0x1,  // __ILP32_OFF32
/*line: 178*/   _POSIX_V6_ILP32_OFFBIG = -0x1,  // __ILP32_OFFBIG
/*line: 179*/   _POSIX_V6_LP64_OFF64 = 0x1,  // __LP64_OFF64
/*line: 180*/   _POSIX_V6_LPBIG_OFFBIG = 0x1,  // __LPBIG_OFFBIG
};

enum macro_posix_v7_data_model_options {
/*line: 184*/   _POSIX_V7_ILP32_OFF32 = -0x1,  // __ILP32_OFF32
/*line: 185*/   _POSIX_V7_ILP32_OFFBIG = -0x1,  // __ILP32_OFFBIG
/*line: 186*/   _POSIX_V7_LP64_OFF64 = 0x1,  // __LP64_OFF64
/*line: 187*/   _POSIX_V7_LPBIG_OFFBIG = 0x1,  // __LPBIG_OFFBIG
};

// Depends on identifiers
enum macro_v6_data_model_options {
/*line: 191*/   _V6_ILP32_OFF32 = -0x1,  // __ILP32_OFF32
/*line: 192*/   _V6_ILP32_OFFBIG = -0x1,  // __ILP32_OFFBIG
/*line: 193*/   _V6_LP64_OFF64 = 0x1,  // __LP64_OFF64
/*line: 194*/   _V6_LPBIG_OFFBIG = 0x1,  // __LPBIG_OFFBIG
};

// Depends on identifiers
enum macro_off_type {
/* Removed in Issue 7 */
/*line: 199*/   _XBS5_ILP32_OFF32 = -0x1,  // __ILP32_OFF32
/*line: 200*/   _XBS5_ILP32_OFFBIG = -0x1,  // __ILP32_OFFBIG
/*line: 201*/   _XBS5_LP64_OFF64 = 0x1,  // __LP64_OFF64
/*line: 202*/   _XBS5_LPBIG_OFFBIG = 0x1,  // __LPBIG_OFFBIG
};

enum macro_xopen_features {
/*line: 206*/   _XOPEN_CRYPT = 0x1,  // (1)
/*line: 207*/   _XOPEN_ENH_I18N = 0x1, /* XXX required */ // (1)
/*line: 208*/   _XOPEN_LEGACY = -0x1, /* no ftime gcvt, wcswcs */ // (-1)
/*line: 209*/   _XOPEN_REALTIME = -0x1, /* no q'ed signals, mq_* */ // (-1)
/*line: 210*/   _XOPEN_REALTIME_THREADS = -0x1, /* no posix_spawn, et. al. */ // (-1)
/*line: 211*/   _XOPEN_SHM = 0x1,  // (1)
/*line: 212*/   _XOPEN_STREAMS = -0x1, /* Issue 6 */ // (-1)
/*line: 213*/   _XOPEN_UNIX = 0x1,  // (1)
};

enum macro_configurable_system_variables {
/* configurable system variables */
/*line: 217*/   _SC_ARG_MAX = 0x1,  // 1
/*line: 218*/   _SC_CHILD_MAX = 0x2,  // 2
/*line: 219*/   _SC_CLK_TCK = 0x3,  // 3
/*line: 220*/   _SC_NGROUPS_MAX = 0x4,  // 4
/*line: 221*/   _SC_OPEN_MAX = 0x5,  // 5
/*line: 222*/   _SC_JOB_CONTROL = 0x6,  // 6
/*line: 223*/   _SC_SAVED_IDS = 0x7,  // 7
/*line: 224*/   _SC_VERSION = 0x8,  // 8
/*line: 225*/   _SC_BC_BASE_MAX = 0x9,  // 9
/*line: 226*/   _SC_BC_DIM_MAX = 0xa,  // 10
/*line: 227*/   _SC_BC_SCALE_MAX = 0xb,  // 11
/*line: 228*/   _SC_BC_STRING_MAX = 0xc,  // 12
/*line: 229*/   _SC_COLL_WEIGHTS_MAX = 0xd,  // 13
/*line: 230*/   _SC_EXPR_NEST_MAX = 0xe,  // 14
/*line: 231*/   _SC_LINE_MAX = 0xf,  // 15
/*line: 232*/   _SC_RE_DUP_MAX = 0x10,  // 16
/*line: 233*/   _SC_2_VERSION = 0x11,  // 17
/*line: 234*/   _SC_2_C_BIND = 0x12,  // 18
/*line: 235*/   _SC_2_C_DEV = 0x13,  // 19
/*line: 236*/   _SC_2_CHAR_TERM = 0x14,  // 20
/*line: 237*/   _SC_2_FORT_DEV = 0x15,  // 21
/*line: 238*/   _SC_2_FORT_RUN = 0x16,  // 22
/*line: 239*/   _SC_2_LOCALEDEF = 0x17,  // 23
/*line: 240*/   _SC_2_SW_DEV = 0x18,  // 24
/*line: 241*/   _SC_2_UPE = 0x19,  // 25
/*line: 242*/   _SC_STREAM_MAX = 0x1a,  // 26
/*line: 243*/   _SC_TZNAME_MAX = 0x1b,  // 27
/*line: 246*/   _SC_ASYNCHRONOUS_IO = 0x1c,  // 28
/*line: 247*/   _SC_PAGESIZE = 0x1d,  // 29
/*line: 248*/   _SC_MEMLOCK = 0x1e,  // 30
/*line: 249*/   _SC_MEMLOCK_RANGE = 0x1f,  // 31
/*line: 250*/   _SC_MEMORY_PROTECTION = 0x20,  // 32
/*line: 251*/   _SC_MESSAGE_PASSING = 0x21,  // 33
/*line: 252*/   _SC_PRIORITIZED_IO = 0x22,  // 34
/*line: 253*/   _SC_PRIORITY_SCHEDULING = 0x23,  // 35
/*line: 254*/   _SC_REALTIME_SIGNALS = 0x24,  // 36
/*line: 255*/   _SC_SEMAPHORES = 0x25,  // 37
/*line: 256*/   _SC_FSYNC = 0x26,  // 38
/*line: 257*/   _SC_SHARED_MEMORY_OBJECTS = 0x27,  // 39
/*line: 258*/   _SC_SYNCHRONIZED_IO = 0x28,  // 40
/*line: 259*/   _SC_TIMERS = 0x29,  // 41
/*line: 260*/   _SC_AIO_LISTIO_MAX = 0x2a,  // 42
/*line: 261*/   _SC_AIO_MAX = 0x2b,  // 43
/*line: 262*/   _SC_AIO_PRIO_DELTA_MAX = 0x2c,  // 44
/*line: 263*/   _SC_DELAYTIMER_MAX = 0x2d,  // 45
/*line: 264*/   _SC_MQ_OPEN_MAX = 0x2e,  // 46
/*line: 265*/   _SC_MAPPED_FILES = 0x2f, /* swap _SC_PAGESIZE vs. BSD */ // 47
/*line: 266*/   _SC_RTSIG_MAX = 0x30,  // 48
/*line: 267*/   _SC_SEM_NSEMS_MAX = 0x31,  // 49
/*line: 268*/   _SC_SEM_VALUE_MAX = 0x32,  // 50
/*line: 269*/   _SC_SIGQUEUE_MAX = 0x33,  // 51
/*line: 270*/   _SC_TIMER_MAX = 0x34,  // 52
/*line: 274*/   _SC_NPROCESSORS_CONF = 0x39,  // 57
/*line: 275*/   _SC_NPROCESSORS_ONLN = 0x3a,  // 58
/*line: 279*/   _SC_2_PBS = 0x3b,  // 59
/*line: 280*/   _SC_2_PBS_ACCOUNTING = 0x3c,  // 60
/*line: 281*/   _SC_2_PBS_CHECKPOINT = 0x3d,  // 61
/*line: 282*/   _SC_2_PBS_LOCATE = 0x3e,  // 62
/*line: 283*/   _SC_2_PBS_MESSAGE = 0x3f,  // 63
/*line: 284*/   _SC_2_PBS_TRACK = 0x40,  // 64
/*line: 285*/   _SC_ADVISORY_INFO = 0x41,  // 65
/*line: 286*/   _SC_BARRIERS = 0x42,  // 66
/*line: 287*/   _SC_CLOCK_SELECTION = 0x43,  // 67
/*line: 288*/   _SC_CPUTIME = 0x44,  // 68
/*line: 289*/   _SC_FILE_LOCKING = 0x45,  // 69
/*line: 290*/   _SC_GETGR_R_SIZE_MAX = 0x46,  // 70
/*line: 291*/   _SC_GETPW_R_SIZE_MAX = 0x47,  // 71
/*line: 292*/   _SC_HOST_NAME_MAX = 0x48,  // 72
/*line: 293*/   _SC_LOGIN_NAME_MAX = 0x49,  // 73
/*line: 294*/   _SC_MONOTONIC_CLOCK = 0x4a,  // 74
/*line: 295*/   _SC_MQ_PRIO_MAX = 0x4b,  // 75
/*line: 296*/   _SC_READER_WRITER_LOCKS = 0x4c,  // 76
/*line: 297*/   _SC_REGEXP = 0x4d,  // 77
/*line: 298*/   _SC_SHELL = 0x4e,  // 78
/*line: 299*/   _SC_SPAWN = 0x4f,  // 79
/*line: 300*/   _SC_SPIN_LOCKS = 0x50,  // 80
/*line: 301*/   _SC_SPORADIC_SERVER = 0x51,  // 81
/*line: 302*/   _SC_THREAD_ATTR_STACKADDR = 0x52,  // 82
/*line: 303*/   _SC_THREAD_ATTR_STACKSIZE = 0x53,  // 83
/*line: 304*/   _SC_THREAD_CPUTIME = 0x54,  // 84
/*line: 305*/   _SC_THREAD_DESTRUCTOR_ITERATIONS = 0x55,  // 85
/*line: 306*/   _SC_THREAD_KEYS_MAX = 0x56,  // 86
/*line: 307*/   _SC_THREAD_PRIO_INHERIT = 0x57,  // 87
/*line: 308*/   _SC_THREAD_PRIO_PROTECT = 0x58,  // 88
/*line: 309*/   _SC_THREAD_PRIORITY_SCHEDULING = 0x59,  // 89
/*line: 310*/   _SC_THREAD_PROCESS_SHARED = 0x5a,  // 90
/*line: 311*/   _SC_THREAD_SAFE_FUNCTIONS = 0x5b,  // 91
/*line: 312*/   _SC_THREAD_SPORADIC_SERVER = 0x5c,  // 92
/*line: 313*/   _SC_THREAD_STACK_MIN = 0x5d,  // 93
/*line: 314*/   _SC_THREAD_THREADS_MAX = 0x5e,  // 94
/*line: 315*/   _SC_TIMEOUTS = 0x5f,  // 95
/*line: 316*/   _SC_THREADS = 0x60,  // 96
/*line: 317*/   _SC_TRACE = 0x61,  // 97
/*line: 318*/   _SC_TRACE_EVENT_FILTER = 0x62,  // 98
/*line: 319*/   _SC_TRACE_INHERIT = 0x63,  // 99
/*line: 320*/   _SC_TRACE_LOG = 0x64,  // 100
/*line: 321*/   _SC_TTY_NAME_MAX = 0x65,  // 101
/*line: 322*/   _SC_TYPED_MEMORY_OBJECTS = 0x66,  // 102
/*line: 323*/   _SC_V6_ILP32_OFF32 = 0x67,  // 103
/*line: 324*/   _SC_V6_ILP32_OFFBIG = 0x68,  // 104
/*line: 325*/   _SC_V6_LP64_OFF64 = 0x69,  // 105
/*line: 326*/   _SC_V6_LPBIG_OFFBIG = 0x6a,  // 106
/*line: 327*/   _SC_IPV6 = 0x76,  // 118
/*line: 328*/   _SC_RAW_SOCKETS = 0x77,  // 119
/*line: 329*/   _SC_SYMLOOP_MAX = 0x78,  // 120
/*line: 333*/   _SC_ATEXIT_MAX = 0x6b,  // 107
/*line: 334*/   _SC_IOV_MAX = 0x38,  // 56
/*line: 335*/   _SC_PAGE_SIZE = 0x1d,  // _SC_PAGESIZE
/*line: 336*/   _SC_XOPEN_CRYPT = 0x6c,  // 108
/*line: 337*/   _SC_XOPEN_ENH_I18N = 0x6d,  // 109
/*line: 338*/   _SC_XOPEN_LEGACY = 0x6e, /* Issue 6 */ // 110
/*line: 339*/   _SC_XOPEN_REALTIME = 0x6f, /* Issue 6 */ // 111
/*line: 340*/   _SC_XOPEN_REALTIME_THREADS = 0x70, /* Issue 6 */ // 112
/*line: 341*/   _SC_XOPEN_SHM = 0x71,  // 113
/*line: 342*/   _SC_XOPEN_STREAMS = 0x72, /* Issue 6 */ // 114
/*line: 343*/   _SC_XOPEN_UNIX = 0x73,  // 115
/*line: 344*/   _SC_XOPEN_VERSION = 0x74,  // 116
/*line: 345*/   _SC_XOPEN_XCU_VERSION = 0x79,  // 121
/* Removed in Issue 7 */
/*line: 350*/   _SC_XBS5_ILP32_OFF32 = 0x7a,  // 122
/*line: 351*/   _SC_XBS5_ILP32_OFFBIG = 0x7b,  // 123
/*line: 352*/   _SC_XBS5_LP64_OFF64 = 0x7c,  // 124
/*line: 353*/   _SC_XBS5_LPBIG_OFFBIG = 0x7d,  // 125
/*line: 357*/   _SC_SS_REPL_MAX = 0x7e,  // 126
/*line: 358*/   _SC_TRACE_EVENT_NAME_MAX = 0x7f,  // 127
/*line: 359*/   _SC_TRACE_NAME_MAX = 0x80,  // 128
/*line: 360*/   _SC_TRACE_SYS_MAX = 0x81,  // 129
/*line: 361*/   _SC_TRACE_USER_EVENT_MAX = 0x82,  // 130
/* Removed in Issue 6 */
/*line: 366*/   _SC_PASS_MAX = 0x83,  // 131
/*line: 371*/   _SC_PHYS_PAGES = 0xc8,  // 200
};

enum macro_configuration_flags {
/*line: 381*/   _CS_POSIX_V6_ILP32_OFF32_CFLAGS = 0x2,  // 2
/*line: 382*/   _CS_POSIX_V6_ILP32_OFF32_LDFLAGS = 0x3,  // 3
/*line: 383*/   _CS_POSIX_V6_ILP32_OFF32_LIBS = 0x4,  // 4
/*line: 384*/   _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = 0x5,  // 5
/*line: 385*/   _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = 0x6,  // 6
/*line: 386*/   _CS_POSIX_V6_ILP32_OFFBIG_LIBS = 0x7,  // 7
/*line: 387*/   _CS_POSIX_V6_LP64_OFF64_CFLAGS = 0x8,  // 8
/*line: 388*/   _CS_POSIX_V6_LP64_OFF64_LDFLAGS = 0x9,  // 9
/*line: 389*/   _CS_POSIX_V6_LP64_OFF64_LIBS = 0xa,  // 10
/*line: 390*/   _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = 0xb,  // 11
/*line: 391*/   _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = 0xc,  // 12
/*line: 392*/   _CS_POSIX_V6_LPBIG_OFFBIG_LIBS = 0xd,  // 13
/*line: 393*/   _CS_POSIX_V6_WIDTH_RESTRICTED_ENVS = 0xe,  // 14
/* Removed in Issue 7 */
/*line: 398*/   _CS_XBS5_ILP32_OFF32_CFLAGS = 0x14,  // 20
/*line: 399*/   _CS_XBS5_ILP32_OFF32_LDFLAGS = 0x15,  // 21
/*line: 400*/   _CS_XBS5_ILP32_OFF32_LIBS = 0x16,  // 22
/*line: 401*/   _CS_XBS5_ILP32_OFF32_LINTFLAGS = 0x17,  // 23
/*line: 402*/   _CS_XBS5_ILP32_OFFBIG_CFLAGS = 0x18,  // 24
/*line: 403*/   _CS_XBS5_ILP32_OFFBIG_LDFLAGS = 0x19,  // 25
/*line: 404*/   _CS_XBS5_ILP32_OFFBIG_LIBS = 0x1a,  // 26
/*line: 405*/   _CS_XBS5_ILP32_OFFBIG_LINTFLAGS = 0x1b,  // 27
/*line: 406*/   _CS_XBS5_LP64_OFF64_CFLAGS = 0x1c,  // 28
/*line: 407*/   _CS_XBS5_LP64_OFF64_LDFLAGS = 0x1d,  // 29
/*line: 408*/   _CS_XBS5_LP64_OFF64_LIBS = 0x1e,  // 30
/*line: 409*/   _CS_XBS5_LP64_OFF64_LINTFLAGS = 0x1f,  // 31
/*line: 410*/   _CS_XBS5_LPBIG_OFFBIG_CFLAGS = 0x20,  // 32
/*line: 411*/   _CS_XBS5_LPBIG_OFFBIG_LDFLAGS = 0x21,  // 33
/*line: 412*/   _CS_XBS5_LPBIG_OFFBIG_LIBS = 0x22,  // 34
/*line: 413*/   _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = 0x23,  // 35
};

enum macro_darwin_user_dirs {
/*line: 417*/   _CS_DARWIN_USER_DIR = 0x10000,  // 65536
/*line: 418*/   _CS_DARWIN_USER_TEMP_DIR = 0x10001,  // 65537
/*line: 419*/   _CS_DARWIN_USER_CACHE_DIR = 0x10002,  // 65538
};

enum macro_flock_operation {
/* These F_* are really XSI or Issue 6 */
/*line: 531*/   F_ULOCK = 0x0, /* unlock locked section */ // 0
/*line: 532*/   F_LOCK = 0x1, /* lock a section for exclusive use */ // 1
/*line: 533*/   F_TLOCK = 0x2, /* test and lock a section for exclusive use */ // 2
/*line: 534*/   F_TEST = 0x3, /* test a section for locks by other procs */ // 3
};

enum macro_sync_flags {
/*line: 778*/   SYNC_VOLUME_FULLSYNC = 0x1, /* Flush data and metadata to platter, not just to disk cache */ // 0x01
/*line: 779*/   SYNC_VOLUME_WAIT = 0x2, /* Wait for sync to complete */ // 0x02
};

