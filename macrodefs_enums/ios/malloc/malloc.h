// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/malloc/malloc.h

enum macro_malloc_memory_region_type {
/* given a task, "reads" the memory at the given address and size
	local_memory: set to a contiguous chunk of memory; validity of local_memory is assumed to be limited (until next call) */
/*line: 455*/   MALLOC_PTR_IN_USE_RANGE_TYPE = 0x1, /* for allocated pointers */ // 1
/*line: 456*/   MALLOC_PTR_REGION_RANGE_TYPE = 0x2, /* for region containing pointers */ // 2
/*line: 457*/   MALLOC_ADMIN_REGION_RANGE_TYPE = 0x4, /* for region used internally */ // 4
/*line: 458*/   MALLOC_ZONE_SPECIFIC_FLAGS = 0xff00, /* bits reserved for zone-specific purposes */ // 0xff00
};

enum macro_malloc_verbose_print_level {
// verbose passed to print()
/*line: 494*/   MALLOC_VERBOSE_PRINT_LEVEL = 0x2,  // 2
};

