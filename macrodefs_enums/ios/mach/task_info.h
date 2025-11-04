// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/task_info.h

enum macro_task_info_max {
/* Deprecated, use per structure _data_t's instead */
/*line: 84*/    TASK_INFO_MAX = 0x400, /* maximum array size */ // (1024)
};

enum macro_task_basic_info {
/* Don't use this, use MACH_TASK_BASIC_INFO instead */
/*line: 94*/    TASK_BASIC_INFO_32 = 0x4, /* basic information */ // 4
/*line: 95*/    TASK_BASIC2_INFO_32 = 0x6,  // 6
/*line: 143*/   TASK_BASIC_INFO_64 = 0x12,  // TASK_BASIC_INFO_64_2
/*line: 173*/   TASK_BASIC_INFO = 0x12,  // TASK_BASIC_INFO_64
};

enum macro_task_info {
/*line: 178*/   TASK_EVENTS_INFO = 0x2, /* various event counts */ // 2
/*line: 195*/   TASK_THREAD_TIMES_INFO = 0x3, /* total times for live threads -
	                                 *  only accurate if suspended */ // 3
/*line: 210*/   TASK_ABSOLUTETIME_INFO = 0x1,  // 1
/*line: 224*/   TASK_KERNELMEMORY_INFO = 0x7,  // 7
/*line: 238*/   TASK_SECURITY_TOKEN = 0xd,  // 13
/*line: 242*/   TASK_AUDIT_TOKEN = 0xf,  // 15
/*line: 247*/   TASK_AFFINITY_TAG_INFO = 0x10, /* This is experimental. */ // 16
/*line: 260*/   TASK_DYLD_INFO = 0x11,  // 17
/*line: 271*/   TASK_DYLD_ALL_IMAGE_INFO_32 = 0x0, /* format value */ // 0
/*line: 272*/   TASK_DYLD_ALL_IMAGE_INFO_64 = 0x1, /* format value */ // 1
/* Compatibility for old 32-bit mach_vm_*_t */
/*line: 278*/   TASK_BASIC_INFO_64_2 = 0x12, /* 64-bit capable basic info */ // 18
/*line: 296*/   TASK_EXTMOD_INFO = 0x13,  // 19
/*line: 308*/   MACH_TASK_BASIC_INFO = 0x14, /* always 64-bit basic info */ // 20
/*line: 326*/   TASK_POWER_INFO = 0x15,  // 21
/*line: 344*/   TASK_VM_INFO = 0x16,  // 22
/*line: 345*/   TASK_VM_INFO_PURGEABLE = 0x17,  // 23
/*line: 437*/   TASK_TRACE_MEMORY_INFO = 0x18, /* no longer supported */ // 24
/*line: 448*/   TASK_WAIT_STATE_INFO = 0x19, /* deprecated. */ // 25
/*line: 459*/   TASK_POWER_INFO_V2 = 0x1a,  // 26
/*line: 486*/   TASK_VM_INFO_PURGEABLE_ACCOUNT = 0x1b, /* Used for xnu purgeable vm unit tests */ // 27
/*line: 489*/   TASK_FLAGS_INFO = 0x1c, /* return t_flags field */ // 28
/*line: 501*/   TASK_DEBUG_INFO_INTERNAL = 0x1d, /* Used for kernel internal development tests. */ // 29
/*line: 505*/   TASK_SECURITY_CONFIG_INFO = 0x20, /* Runtime security mitigations configuration for the task */ // 32
};

enum macro_task_flags {
/*line: 498*/   TF_LP64 = 0x1, /* task has 64-bit addressing */ // 0x00000001
/*line: 499*/   TF_64B_DATA = 0x2, /* task has 64-bit data registers */ // 0x00000002
};

enum macro_exc_guard_settings {
/* EXC_GUARD optional delivery settings on a per-task basis */
/*line: 521*/   TASK_EXC_GUARD_NONE = 0x0,  // 0x00
/*line: 522*/   TASK_EXC_GUARD_VM_DELIVER = 0x1, /* Deliver virtual memory EXC_GUARD exceptions */ // 0x01
/*line: 523*/   TASK_EXC_GUARD_VM_ONCE = 0x2, /* Deliver them only once */ // 0x02
/*line: 524*/   TASK_EXC_GUARD_VM_CORPSE = 0x4, /* Deliver them via a forked corpse */ // 0x04
/*line: 525*/   TASK_EXC_GUARD_VM_FATAL = 0x8, /* Virtual Memory EXC_GUARD delivery is fatal */ // 0x08
/*line: 526*/   TASK_EXC_GUARD_VM_ALL = 0xf,  // 0x0f
/*line: 528*/   TASK_EXC_GUARD_MP_DELIVER = 0x10, /* Deliver mach port EXC_GUARD exceptions */ // 0x10
/*line: 529*/   TASK_EXC_GUARD_MP_ONCE = 0x20, /* Deliver them only once */ // 0x20
/*line: 530*/   TASK_EXC_GUARD_MP_CORPSE = 0x40, /* Deliver them via a forked corpse */ // 0x40
/*line: 531*/   TASK_EXC_GUARD_MP_FATAL = 0x80, /* mach port EXC_GUARD delivery is fatal */ // 0x80
/*line: 532*/   TASK_EXC_GUARD_MP_ALL = 0xf0,  // 0xf0
/*line: 534*/   TASK_EXC_GUARD_ALL = 0xff, /* All optional deliver settings */ // 0xff
};

enum macro_task_corpse_forking {
/*line: 543*/   TASK_CORPSE_FORKING_DISABLED_MEM_DIAG = 0x1, /* Disable corpse forking because the task is running under a diagnostic tool */ // 0x01
};

enum macro_task_sched_info {
/*
 * Obsolete interfaces.
 */
/*line: 550*/   TASK_SCHED_TIMESHARE_INFO = 0xa,  // 10
/*line: 551*/   TASK_SCHED_RR_INFO = 0xb,  // 11
/*line: 552*/   TASK_SCHED_FIFO_INFO = 0xc,  // 12
/*line: 554*/   TASK_SCHED_INFO = 0xe,  // 14
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 109
// #define TASK_BASIC_INFO_32_COUNT (sizeof(task_basic_info_32_data_t) / sizeof(natural_t))

// Line: 144
// #define TASK_BASIC_INFO_64_COUNT TASK_BASIC_INFO_64_2_COUNT

// Line: 168
// #define TASK_BASIC_INFO_COUNT (sizeof(task_basic_info_data_t) / sizeof(natural_t))

// Line: 192
// #define TASK_EVENTS_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(task_events_info_data_t) / sizeof(natural_t)))

// Line: 207
// #define TASK_THREAD_TIMES_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(task_thread_times_info_data_t) / sizeof(natural_t)))

// Line: 221
// #define TASK_ABSOLUTETIME_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof (task_absolutetime_info_data_t) / sizeof (natural_t)))

// Line: 235
// #define TASK_KERNELMEMORY_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof (task_kernelmemory_info_data_t) / sizeof (natural_t)))

// Line: 239
// #define TASK_SECURITY_TOKEN_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(security_token_t) / sizeof(natural_t)))

// Line: 243
// #define TASK_AUDIT_TOKEN_COUNT (sizeof(audit_token_t) / sizeof(natural_t))

// Line: 257
// #define TASK_AFFINITY_TAG_INFO_COUNT (sizeof(task_affinity_tag_info_data_t) / sizeof(natural_t))

// Line: 269
// #define TASK_DYLD_INFO_COUNT (sizeof(task_dyld_info_data_t) / sizeof(natural_t))

// Line: 292
// #define TASK_BASIC_INFO_64_2_COUNT (sizeof(task_basic_info_64_2_data_t) / sizeof(natural_t))

// Line: 304
// #define TASK_EXTMOD_INFO_COUNT (sizeof(task_extmod_info_data_t) / sizeof(natural_t))

// Line: 322
// #define MACH_TASK_BASIC_INFO_COUNT (sizeof(mach_task_basic_info_data_t) / sizeof(natural_t))

// Line: 339
// #define TASK_POWER_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof (task_power_info_data_t) / sizeof (natural_t)))

// Line: 413
// #define TASK_VM_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof (task_vm_info_data_t) / sizeof (natural_t)))

// Line: 418
// #define TASK_VM_INFO_REV7_COUNT TASK_VM_INFO_COUNT

// Line: 419
// #define TASK_VM_INFO_REV6_COUNT /* doesn't include neural total and peak */ \
// 	((mach_msg_type_number_t) (TASK_VM_INFO_REV7_COUNT - 4))

// Line: 421
// #define TASK_VM_INFO_REV5_COUNT /* doesn't include ledger swapins */ \
// 	((mach_msg_type_number_t) (TASK_VM_INFO_REV6_COUNT - 2))

// Line: 423
// #define TASK_VM_INFO_REV4_COUNT /* doesn't include decompressions */ \
// 	((mach_msg_type_number_t) (TASK_VM_INFO_REV5_COUNT - 1))

// Line: 425
// #define TASK_VM_INFO_REV3_COUNT /* doesn't include limit bytes */ \
// 	((mach_msg_type_number_t) (TASK_VM_INFO_REV4_COUNT - 2))

// Line: 427
// #define TASK_VM_INFO_REV2_COUNT /* doesn't include extra ledgers info */ \
// 	((mach_msg_type_number_t) (TASK_VM_INFO_REV3_COUNT - 42))

// Line: 429
// #define TASK_VM_INFO_REV1_COUNT /* doesn't include min and max address */ \
// 	((mach_msg_type_number_t) (TASK_VM_INFO_REV2_COUNT - 4))

// Line: 431
// #define TASK_VM_INFO_REV0_COUNT /* doesn't include phys_footprint */ \
// 	((mach_msg_type_number_t) (TASK_VM_INFO_REV1_COUNT - 2))

// Line: 445
// #define TASK_TRACE_MEMORY_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(task_trace_memory_info_data_t) / sizeof(natural_t)))

// Line: 456
// #define TASK_WAIT_STATE_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(task_wait_state_info_data_t) / sizeof(natural_t)))

// Line: 481
// #define TASK_POWER_INFO_V2_COUNT_OLD ((mach_msg_type_number_t) (sizeof (task_power_info_v2_data_t) - sizeof(uint64_t)*2) / sizeof (natural_t))

// Line: 483
// #define TASK_POWER_INFO_V2_COUNT ((mach_msg_type_number_t) (sizeof (task_power_info_v2_data_t) / sizeof (natural_t)))

// Line: 495
// #define TASK_FLAGS_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(task_flags_info_data_t) / sizeof (natural_t)))

// Line: 511
// #define TASK_SECURITY_CONFIG_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(struct task_security_config_info) / sizeof(natural_t)))

