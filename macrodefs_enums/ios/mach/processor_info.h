// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/processor_info.h

enum macro_processor_info_max {
/*line: 80*/    PROCESSOR_INFO_MAX = 0x400, /* max array size */ // (1024)
};

enum macro_processor_set_info_max {
/*line: 86*/    PROCESSOR_SET_INFO_MAX = 0x400, /* max array size */ // (1024)
};

enum macro_processor_request_info_flavor {
/*line: 93*/    PROCESSOR_BASIC_INFO = 0x1, /* basic information */ // 1
/*line: 94*/    PROCESSOR_CPU_LOAD_INFO = 0x2, /* cpu load information */ // 2
/*line: 95*/    PROCESSOR_PM_REGS_INFO = 0x10000001, /* performance monitor register info */ // 0x10000001
/*line: 96*/    PROCESSOR_TEMPERATURE = 0x10000002, /* Processor core temperature */ // 0x10000002
};

enum macro_load_scale {
/*
 *	Scaling factor for load_average, mach_factor.
 */
/*line: 126*/   LOAD_SCALE = 0x3e8,  // 1000
};

enum macro_processor_set_info_flavor {
/*line: 129*/   PROCESSOR_SET_BASIC_INFO = 0x5, /* basic information */ // 5
/*line: 141*/   PROCESSOR_SET_LOAD_INFO = 0x4, /* scheduling statistics */ // 4
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 111
// #define PROCESSOR_BASIC_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(processor_basic_info_data_t)/sizeof(natural_t)))

// Line: 120
// #define PROCESSOR_CPU_LOAD_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(processor_cpu_load_info_data_t)/sizeof(natural_t)))

// Line: 138
// #define PROCESSOR_SET_BASIC_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(processor_set_basic_info_data_t)/sizeof(natural_t)))

// Line: 152
// #define PROCESSOR_SET_LOAD_INFO_COUNT ((mach_msg_type_number_t) \
// 	        (sizeof(processor_set_load_info_data_t)/sizeof(natural_t)))

