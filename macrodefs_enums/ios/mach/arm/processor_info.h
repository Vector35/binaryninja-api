// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/arm/processor_info.h

enum macro_cpu_statistics {
/*line: 34*/    PROCESSOR_CPU_STAT = 0x10000003, /* Low-level CPU statistics */ // 0x10000003
/*line: 35*/    PROCESSOR_CPU_STAT64 = 0x10000004, /* Low-level CPU statistics, in full 64-bit */ // 0x10000004
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 53
// #define PROCESSOR_CPU_STAT_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(processor_cpu_stat_data_t) / sizeof(natural_t)))

// Line: 71
// #define PROCESSOR_CPU_STAT64_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(processor_cpu_stat64_data_t) / sizeof(integer_t)))

