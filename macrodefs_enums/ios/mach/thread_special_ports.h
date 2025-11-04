// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/thread_special_ports.h

enum macro_thread_ports {
/*line: 70*/    THREAD_KERNEL_PORT = 0x1, /* The full thread port for thread. */ // 1
/*line: 72*/    THREAD_INSPECT_PORT = 0x2, /* The inspect port for thread. */ // 2
/*line: 74*/    THREAD_READ_PORT = 0x3, /* The read port for thread. */ // 3
};

// Depends on identifiers
enum macro_thread_special_ports {
/*line: 76*/    THREAD_MAX_SPECIAL_PORT = 0x3,  // THREAD_READ_PORT
};

