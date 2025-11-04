// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/host_info.h

enum macro_host_info_max {
/*line: 80*/    HOST_INFO_MAX = 0x400, /* max array size */ // (1024)
};

enum macro_kernel_version_max {
/*line: 83*/    KERNEL_VERSION_MAX = 0x200,  // (512)
};

enum macro_kernel_boot_info_max {
/*line: 86*/    KERNEL_BOOT_INFO_MAX = 0x1000,  // (4096)
};

enum macro_host_info_type {
/*line: 94*/    HOST_BASIC_INFO = 0x1, /* basic info */ // 1
/*line: 95*/    HOST_SCHED_INFO = 0x3, /* scheduling info */ // 3
/*line: 96*/    HOST_RESOURCE_SIZES = 0x4, /* kernel struct sizes */ // 4
/*line: 97*/    HOST_PRIORITY_INFO = 0x5, /* priority information */ // 5
/*line: 98*/    HOST_SEMAPHORE_TRAPS = 0x7, /* Has semaphore traps */ // 7
/*line: 99*/    HOST_MACH_MSG_TRAP = 0x8, /* Has mach_msg_trap */ // 8
/*line: 100*/   HOST_VM_PURGABLE = 0x9, /* purg'e'able memory info */ // 9
/*line: 101*/   HOST_DEBUG_INFO_INTERNAL = 0xa, /* Used for kernel internal development tests only */ // 10
/*line: 102*/   HOST_CAN_HAS_DEBUGGER = 0xb,  // 11
/*line: 103*/   HOST_PREFERRED_USER_ARCH = 0xc, /* Get the preferred user-space architecture */ // 12
};

enum macro_host_statistics {
/* host_statistics() */
/*line: 177*/   HOST_LOAD_INFO = 0x1, /* System loading stats */ // 1
/*line: 178*/   HOST_VM_INFO = 0x2, /* Virtual memory stats */ // 2
/*line: 179*/   HOST_CPU_LOAD_INFO = 0x3, /* CPU load stats */ // 3
/* host_statistics64() */
/*line: 182*/   HOST_VM_INFO64 = 0x4, /* 64-bit virtual memory stats */ // 4
/*line: 183*/   HOST_EXTMOD_INFO64 = 0x5, /* External modification stats */ // 5
/*line: 184*/   HOST_EXPIRED_TASK_INFO = 0x6, /* Statistics for expired tasks */ // 6
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 111
// #define HOST_CAN_HAS_DEBUGGER_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(host_can_has_debugger_info_data_t)/sizeof(integer_t)))

// Line: 134
// #define HOST_BASIC_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(host_basic_info_data_t)/sizeof(integer_t)))

// Line: 144
// #define HOST_SCHED_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(host_sched_info_data_t)/sizeof(integer_t)))

// Line: 157
// #define HOST_RESOURCE_SIZES_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(kernel_resource_sizes_data_t)/sizeof(integer_t)))

// Line: 173
// #define HOST_PRIORITY_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(host_priority_info_data_t)/sizeof(integer_t)))

// Line: 195
// #define HOST_LOAD_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(host_load_info_data_t)/sizeof(integer_t)))

// Line: 200
// #define HOST_VM_PURGABLE_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(host_purgable_info_data_t)/sizeof(integer_t)))

// Line: 205
// #define HOST_VM_INFO64_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(vm_statistics64_data_t)/sizeof(integer_t)))

// Line: 209
// #define HOST_VM_INFO64_LATEST_COUNT HOST_VM_INFO64_COUNT

// Line: 210
// #define HOST_VM_INFO64_REV1_COUNT HOST_VM_INFO64_LATEST_COUNT

// Line: 212
// #define HOST_VM_INFO64_REV0_COUNT /* added compression and swapper info (14 ints) */ \
// 	((mach_msg_type_number_t) \
// 	 (HOST_VM_INFO64_REV1_COUNT - 14))

// Line: 218
// #define HOST_EXTMOD_INFO64_COUNT ((mach_msg_type_number_t) \
// 	    (sizeof(vm_extmod_statistics_data_t)/sizeof(integer_t)))

// Line: 222
// #define HOST_EXTMOD_INFO64_LATEST_COUNT HOST_EXTMOD_INFO64_COUNT

// Line: 225
// #define HOST_VM_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(vm_statistics_data_t)/sizeof(integer_t)))

// Line: 229
// #define HOST_VM_INFO_LATEST_COUNT HOST_VM_INFO_COUNT

// Line: 230
// #define HOST_VM_INFO_REV2_COUNT HOST_VM_INFO_LATEST_COUNT

// Line: 245
// #define HOST_CPU_LOAD_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof (host_cpu_load_info_data_t) / sizeof (integer_t)))

// Line: 255
// #define HOST_PREFERRED_USER_ARCH_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(host_preferred_user_arch_data_t)/sizeof(integer_t)))

