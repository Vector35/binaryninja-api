// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/thread_info.h

enum macro_thread_info_max {
/*line: 84*/    THREAD_INFO_MAX = 0x20, /* maximum array size */ // (32)
};

enum macro_thread_info {
/*
 *	Currently defined information.
 */
/*line: 90*/    THREAD_BASIC_INFO = 0x3, /* basic information */ // 3
/*line: 109*/   THREAD_IDENTIFIER_INFO = 0x4, /* thread id and other information */ // 4
};

enum macro_usage_scale {
/*
 *	Scale factor for usage field.
 */
/*line: 126*/   TH_USAGE_SCALE = 0x3e8,  // 1000
};

enum macro_thread_state {
/*
 *	Thread run states (state field).
 */
/*line: 132*/   TH_STATE_RUNNING = 0x1, /* thread is running normally */ // 1
/*line: 133*/   TH_STATE_STOPPED = 0x2, /* thread is stopped */ // 2
/*line: 134*/   TH_STATE_WAITING = 0x3, /* thread is waiting normally */ // 3
/*line: 135*/   TH_STATE_UNINTERRUPTIBLE = 0x4, /* thread is in an uninterruptible
	                                 *  wait */ // 4
/*line: 137*/   TH_STATE_HALTED = 0x5, /* thread is halted at a
	                                 *  clean point */ // 5
};

enum macro_thread_flags {
/*
 *	Thread flags (flags field).
 */
/*line: 143*/   TH_FLAGS_SWAPPED = 0x1, /* thread is swapped out */ // 0x1
/*line: 144*/   TH_FLAGS_IDLE = 0x2, /* thread is an idle thread */ // 0x2
/*line: 145*/   TH_FLAGS_GLOBAL_FORCED_IDLE = 0x4, /* thread performs global forced idle */ // 0x4
/*
 *  Thread extended info (returns same info as proc_pidinfo(...,PROC_PIDTHREADINFO,...)
 */
/*line: 150*/   THREAD_EXTENDED_INFO = 0x5,  // 5
/*line: 151*/   MAXTHREADNAMESIZE = 0x40,  // 64
};

enum macro_thread_debug_info {
/*line: 170*/   THREAD_DEBUG_INFO_INTERNAL = 0x6, /* for kernel development internal info */ // 6
};

enum macro_io_num_priorities {
/*line: 173*/   IO_NUM_PRIORITIES = 0x4,  // 4
};

enum macro_thread_scheduling_info {
/*
 * Obsolete interfaces.
 */
/*line: 207*/   THREAD_SCHED_TIMESHARE_INFO = 0xa,  // 10
/*line: 208*/   THREAD_SCHED_RR_INFO = 0xb,  // 11
/*line: 209*/   THREAD_SCHED_FIFO_INFO = 0xc,  // 12
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 106
// #define THREAD_BASIC_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(thread_basic_info_data_t) / sizeof(natural_t)))

// Line: 119
// #define THREAD_IDENTIFIER_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(thread_identifier_info_data_t) / sizeof(natural_t)))

// Line: 167
// #define THREAD_EXTENDED_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(thread_extended_info_data_t) / sizeof (natural_t)))

