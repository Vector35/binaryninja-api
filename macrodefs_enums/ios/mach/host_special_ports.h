// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/host_special_ports.h

enum macro_host_security_port {
/*
 * Cannot be set or gotten from user space
 */
/*line: 70*/    HOST_SECURITY_PORT = 0x0,  // 0
};

// Depends on identifiers
enum macro_host_special_ports {
/*line: 72*/    HOST_MIN_SPECIAL_PORT = 0x0,  // HOST_SECURITY_PORT
/*
 * Always provided by kernel (cannot be set from user-space).
 */
/*line: 77*/    HOST_PORT = 0x1,  // 1
/*line: 78*/    HOST_PRIV_PORT = 0x2,  // 2
/*line: 79*/    HOST_IO_MAIN_PORT = 0x3,  // 3
/*line: 80*/    HOST_MAX_SPECIAL_KERNEL_PORT = 0x7, /* room to grow */ // 7
};

// Depends on identifiers
enum macro_special_ports {
/*line: 82*/    HOST_LAST_SPECIAL_KERNEL_PORT = 0x3,  // HOST_IO_MAIN_PORT
/*
 * Not provided by kernel
 */
/*line: 87*/    HOST_DYNAMIC_PAGER_PORT = 0x8,  // (1+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 88*/    HOST_AUDIT_CONTROL_PORT = 0x9,  // (2+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 89*/    HOST_USER_NOTIFICATION_PORT = 0xa,  // (3+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 90*/    HOST_AUTOMOUNTD_PORT = 0xb,  // (4+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 91*/    HOST_LOCKD_PORT = 0xc,  // (5+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 92*/    HOST_KTRACE_BACKGROUND_PORT = 0xd,  // (6+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 93*/    HOST_SEATBELT_PORT = 0xe,  // (7+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 94*/    HOST_KEXTD_PORT = 0xf,  // (8+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 95*/    HOST_LAUNCHCTL_PORT = 0x10,  // (9+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 96*/    HOST_UNFREED_PORT = 0x11,  // (10+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 97*/    HOST_AMFID_PORT = 0x12,  // (11+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 98*/    HOST_GSSD_PORT = 0x13,  // (12+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 99*/    HOST_TELEMETRY_PORT = 0x14,  // (13+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 100*/   HOST_ATM_NOTIFICATION_PORT = 0x15,  // (14+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 101*/   HOST_COALITION_PORT = 0x16,  // (15+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 102*/   HOST_SYSDIAGNOSE_PORT = 0x17,  // (16+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 103*/   HOST_XPC_EXCEPTION_PORT = 0x18,  // (17+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 104*/   HOST_CONTAINERD_PORT = 0x19,  // (18+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 105*/   HOST_NODE_PORT = 0x1a,  // (19+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 106*/   HOST_RESOURCE_NOTIFY_PORT = 0x1b,  // (20+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 107*/   HOST_CLOSURED_PORT = 0x1c,  // (21+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 108*/   HOST_SYSPOLICYD_PORT = 0x1d,  // (22+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 109*/   HOST_FILECOORDINATIOND_PORT = 0x1e,  // (23+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 110*/   HOST_FAIRPLAYD_PORT = 0x1f,  // (24+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 111*/   HOST_IOCOMPRESSIONSTATS_PORT = 0x20,  // (25+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 112*/   HOST_MEMORY_ERROR_PORT = 0x21,  // (26+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 113*/   HOST_MANAGEDAPPDISTD_PORT = 0x22,  // (27+HOST_MAX_SPECIAL_KERNEL_PORT)
/*line: 114*/   HOST_DOUBLEAGENTD_PORT = 0x23,  // (28+HOST_MAX_SPECIAL_KERNEL_PORT)
};

// Depends on identifiers
enum macro_host_max_special_port {
/*line: 116*/   HOST_MAX_SPECIAL_PORT = 0x23,  // HOST_DOUBLEAGENTD_PORT
};

// Depends on identifiers
enum macro_host_chud_port {
/* obsolete name */
/*line: 120*/   HOST_CHUD_PORT = 0x10,  // HOST_LAUNCHCTL_PORT
};

enum macro_host_local_node {
/*
 * Special node identifier to always represent the local node.
 */
/*line: 125*/   HOST_LOCAL_NODE = -0x1,  // -1
};

