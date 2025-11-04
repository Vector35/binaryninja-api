// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/notify.h

// Depends on identifiers
enum macro_notify_events {
/*
 *  An alternative specification of the notification interface
 *  may be found in mach/notify.defs.
 */
/*line: 76*/    MACH_NOTIFY_FIRST = 0x40,  // 0100
/*line: 77*/    MACH_NOTIFY_PORT_DELETED = 0x41,  // (MACH_NOTIFY_FIRST+001)
/* A send or send-once right was deleted. */
/*line: 79*/    MACH_NOTIFY_SEND_POSSIBLE = 0x42,  // (MACH_NOTIFY_FIRST+002)
/* Now possible to send using specified right */
/*line: 81*/    MACH_NOTIFY_PORT_DESTROYED = 0x45,  // (MACH_NOTIFY_FIRST+005)
/* A receive right was (would have been) deallocated */
/*line: 83*/    MACH_NOTIFY_NO_SENDERS = 0x46,  // (MACH_NOTIFY_FIRST+006)
/* Receive right has no extant send rights */
/*line: 85*/    MACH_NOTIFY_SEND_ONCE = 0x47,  // (MACH_NOTIFY_FIRST+007)
/* An extant send-once right died */
/*line: 87*/    MACH_NOTIFY_DEAD_NAME = 0x48,  // (MACH_NOTIFY_FIRST+010)
/* Send or send-once right died, leaving a dead-name */
/*line: 89*/    MACH_NOTIFY_LAST = 0x4d,  // (MACH_NOTIFY_FIRST+015)
};

