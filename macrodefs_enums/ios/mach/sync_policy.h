// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/sync_policy.h

// Depends on identifiers
enum macro_sync_policy {
/*
 *	These options define the wait ordering of the synchronizers
 */
/*line: 40*/    SYNC_POLICY_FIFO = 0x0,  // 0x0
/*line: 41*/    SYNC_POLICY_FIXED_PRIORITY = 0x1,  // 0x1
/*line: 42*/    SYNC_POLICY_REVERSED = 0x2,  // 0x2
/*line: 43*/    SYNC_POLICY_ORDER_MASK = 0x3,  // 0x3
/*line: 44*/    SYNC_POLICY_LIFO = 0x2,  // (SYNC_POLICY_FIFO|SYNC_POLICY_REVERSED)
};

