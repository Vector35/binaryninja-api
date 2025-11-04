// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach_debug/zone_info.h

enum macro_zone_name_max_len {
/*
 *	Legacy definitions for host_zone_info().  This interface, and
 *	these definitions have been deprecated in favor of the new
 *	mach_zone_info() inteface and types below.
 */
/*line: 71*/    ZONE_NAME_MAX_LEN = 0x50,  // 80
/*
 *	Remember to update the mig type definitions
 *	in mach_debug_types.defs when adding/removing fields.
 */
/*line: 100*/   MACH_ZONE_NAME_MAX_LEN = 0x50,  // 80
};

enum macro_mach_memory_info_max_name_len {
/*line: 150*/   MACH_MEMORY_INFO_NAME_MAX_LEN = 0x50,  // 80
};

enum macro_max_ztrace_depth {
/*
 * MAX_ZTRACE_DEPTH configures how deep of a stack trace is taken on each zalloc in the zone of interest.  15
 * levels is usually enough to get past all the layers of code in kalloc and IOKit and see who the actual
 * caller is up above these lower levels.
 *
 * This is used both for the zone leak detector and the zone corruption log. Make sure this isn't greater than
 * BTLOG_MAX_DEPTH defined in btlog.h. Also make sure to update the definition of zone_btrecord_t in
 * mach_debug_types.defs if this changes.
 */
/*line: 180*/   MAX_ZTRACE_DEPTH = 0xf,  // 15
};

enum macro_zone_btlog_operation {
/*
 * Opcodes for the btlog operation field:
 */
/*line: 186*/   ZOP_ALLOC = 0x1,  // 1
/*line: 187*/   ZOP_FREE = 0x0,  // 0
};

