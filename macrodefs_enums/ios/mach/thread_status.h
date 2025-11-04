// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/thread_status.h

enum macro_thread_state_flavor {
/*line: 88*/    THREAD_STATE_FLAVOR_LIST = 0x0, /* List of valid flavors */ // 0
/*line: 89*/    THREAD_STATE_FLAVOR_LIST_NEW = 0x80,  // 128
/*line: 90*/    THREAD_STATE_FLAVOR_LIST_10_9 = 0x81,  // 129
/*line: 91*/    THREAD_STATE_FLAVOR_LIST_10_13 = 0x82,  // 130
/*line: 92*/    THREAD_STATE_FLAVOR_LIST_10_15 = 0x83,  // 131
};

enum macro_thread_state_conversion {
/*line: 97*/    THREAD_CONVERT_THREAD_STATE_TO_SELF = 0x1,  // 1
/*line: 98*/    THREAD_CONVERT_THREAD_STATE_FROM_SELF = 0x2,  // 2
};

