// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/task_special_ports.h

enum macro_task_ports {
/*line: 72*/    TASK_KERNEL_PORT = 0x1, /* The full task port for task. */ // 1
/*line: 74*/    TASK_HOST_PORT = 0x2, /* The host (priv) port for task.  */ // 2
/*line: 76*/    TASK_NAME_PORT = 0x3, /* The name port for task. */ // 3
/*line: 78*/    TASK_BOOTSTRAP_PORT = 0x4, /* Bootstrap environment for task. */ // 4
/*line: 80*/    TASK_INSPECT_PORT = 0x5, /* The inspect port for task. */ // 5
/*line: 82*/    TASK_READ_PORT = 0x6, /* The read port for task. */ // 6
/* Was TASK_GSSD_PORT          8        which transformed to a host port */
/*line: 92*/    TASK_ACCESS_PORT = 0x9, /* Permission check for task_for_pid. */ // 9
/*line: 94*/    TASK_DEBUG_CONTROL_PORT = 0xa, /* debug control port */ // 10
/*line: 96*/    TASK_RESOURCE_NOTIFY_PORT = 0xb, /* overrides host special RN port */ // 11
};

// Depends on identifiers
enum macro_task_max_special_port {
/*line: 98*/    TASK_MAX_SPECIAL_PORT = 0xb,  // TASK_RESOURCE_NOTIFY_PORT
};

