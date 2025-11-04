// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/memory_object_types.h

// Depends on identifiers
enum macro_memory_object_nulls {
/*  for creating new internal objects */
/*line: 120*/   MEMORY_OBJECT_NULL = 0x0,  // ((memory_object_t)0)
/*line: 121*/   MEMORY_OBJECT_CONTROL_NULL = 0x0,  // ((memory_object_control_t)0)
/*line: 122*/   MEMORY_OBJECT_NAME_NULL = 0x0,  // ((memory_object_name_t)0)
/*line: 123*/   MEMORY_OBJECT_DEFAULT_NULL = 0x0,  // ((memory_object_default_t)0)
};

enum macro_memory_copy_strategy {
/* How memory manager handles copy: */
/*line: 128*/   MEMORY_OBJECT_COPY_NONE = 0x0,  // 0
/* ... No special support */
/*line: 130*/   MEMORY_OBJECT_COPY_CALL = 0x1,  // 1
/* ... Make call on memory manager */
/*line: 132*/   MEMORY_OBJECT_COPY_DELAY = 0x2,  // 2
/* ... Memory manager doesn't
 *     change data externally.
 */
/*line: 136*/   MEMORY_OBJECT_COPY_TEMPORARY = 0x3,  // 3
/* ... Memory manager doesn't
 *     change data externally, and
 *     doesn't need to see changes.
 */
/*line: 141*/   MEMORY_OBJECT_COPY_SYMMETRIC = 0x4,  // 4
/* ... Memory manager doesn't
 *     change data externally,
 *     doesn't need to see changes,
 *     and object will not be
 *     multiply mapped.
 *
 *     XXX
 *     Not yet safe for non-kernel use.
 */
/*line: 152*/   MEMORY_OBJECT_COPY_INVALID = 0x5,  // 5
/* ...	An invalid copy strategy,
 *	for external objects which
 *	have not been initialized.
 *	Allows copy_strategy to be
 *	examined without also
 *	examining pager_ready and
 *	internal.
 */
/*line: 162*/   MEMORY_OBJECT_COPY_DELAY_FORK = 0x6,  // 6
};

enum macro_memory_object_return {
/* Which pages to return to manager
 *  this time (lock_request) */
/*line: 171*/   MEMORY_OBJECT_RETURN_NONE = 0x0,  // 0
/* ... don't return any. */
/*line: 173*/   MEMORY_OBJECT_RETURN_DIRTY = 0x1,  // 1
/* ... only dirty pages. */
/*line: 175*/   MEMORY_OBJECT_RETURN_ALL = 0x2,  // 2
/* ... dirty and precious pages. */
/*line: 177*/   MEMORY_OBJECT_RETURN_ANYTHING = 0x3,  // 3
};

enum macro_data_lock_request_flags {
/*
 *	Data lock request flags
 */
/*line: 184*/   MEMORY_OBJECT_DATA_FLUSH = 0x1,  // 0x1
/*line: 185*/   MEMORY_OBJECT_DATA_NO_CHANGE = 0x2,  // 0x2
/*line: 186*/   MEMORY_OBJECT_DATA_PURGE = 0x4,  // 0x4
/*line: 187*/   MEMORY_OBJECT_COPY_SYNC = 0x8,  // 0x8
/*line: 188*/   MEMORY_OBJECT_DATA_SYNC = 0x10,  // 0x10
/*line: 189*/   MEMORY_OBJECT_IO_SYNC = 0x20,  // 0x20
/*line: 190*/   MEMORY_OBJECT_DATA_FLUSH_ALL = 0x40,  // 0x40
};

enum macro_memory_object_info_max {
/*
 *	Types for the memory object flavor interfaces
 */
/*line: 196*/   MEMORY_OBJECT_INFO_MAX = 0x400,  // (1024)
};

enum macro_memory_object_info {
/*line: 202*/   MEMORY_OBJECT_PERFORMANCE_INFO = 0xb,  // 11
/*line: 203*/   MEMORY_OBJECT_ATTRIBUTE_INFO = 0xe,  // 14
/*line: 204*/   MEMORY_OBJECT_BEHAVIOR_INFO = 0xf,  // 15
};

enum macro_memory_object_flags {
/*
 * Used to support options on memory_object_release_name call
 */
/*line: 255*/   MEMORY_OBJECT_TERMINATE_IDLE = 0x1,  // 0x1
/*line: 256*/   MEMORY_OBJECT_RESPECT_CACHE = 0x2,  // 0x2
/*line: 257*/   MEMORY_OBJECT_RELEASE_NO_OP = 0x4,  // 0x4
};

enum macro_memory_flags {
/* enumerated */
/*line: 262*/   MAP_MEM_NOOP = 0x0,  // 0
/*line: 263*/   MAP_MEM_COPYBACK = 0x1,  // 1
/*line: 264*/   MAP_MEM_IO = 0x2,  // 2
/*line: 265*/   MAP_MEM_WTHRU = 0x3,  // 3
/*line: 266*/   MAP_MEM_WCOMB = 0x4, /* Write combining mode */ // 4
/* aka store gather     */
/*line: 268*/   MAP_MEM_INNERWBACK = 0x5,  // 5
/*line: 269*/   MAP_MEM_POSTED = 0x6,  // 6
/*line: 270*/   MAP_MEM_RT = 0x7,  // 7
/*line: 271*/   MAP_MEM_POSTED_REORDERED = 0x8,  // 8
/*line: 272*/   MAP_MEM_POSTED_COMBINED_REORDERED = 0x9,  // 9
/* leave room for vm_prot bits (0xFF ?) */
/*line: 282*/   MAP_MEM_PROT_MASK = 0xff,  // 0xFF
/*line: 283*/   MAP_MEM_LEDGER_TAGGED = 0x2000, /* object owned by a specific task and ledger */ // 0x002000
/*line: 284*/   MAP_MEM_PURGABLE_KERNEL_ONLY = 0x4000, /* volatility controlled by kernel */ // 0x004000
/*line: 285*/   MAP_MEM_GRAB_SECLUDED = 0x8000, /* can grab secluded pages */ // 0x008000
/*line: 286*/   MAP_MEM_ONLY = 0x10000, /* change processor caching  */ // 0x010000
/*line: 287*/   MAP_MEM_NAMED_CREATE = 0x20000, /* create extant object      */ // 0x020000
/*line: 288*/   MAP_MEM_PURGABLE = 0x40000, /* create a purgable VM object */ // 0x040000
/*line: 289*/   MAP_MEM_NAMED_REUSE = 0x80000, /* reuse provided entry if identical */ // 0x080000
/*line: 290*/   MAP_MEM_USE_DATA_ADDR = 0x100000, /* preserve address of data, rather than base of page */ // 0x100000
/*line: 291*/   MAP_MEM_VM_COPY = 0x200000, /* make a copy of a VM range */ // 0x200000
/*line: 292*/   MAP_MEM_VM_SHARE = 0x400000, /* extract a VM range for remap */ // 0x400000
/*line: 293*/   MAP_MEM_4K_DATA_ADDR = 0x800000, /* preserve 4K aligned address of data */ // 0x800000
/*line: 295*/   MAP_MEM_FLAGS_MASK = 0xffff00,  // 0x00FFFF00
/*line: 296*/   MAP_MEM_FLAGS_USER = 0xffe000,  // (MAP_MEM_PURGABLE_KERNEL_ONLY|MAP_MEM_GRAB_SECLUDED|MAP_MEM_ONLY|MAP_MEM_NAMED_CREATE|MAP_MEM_PURGABLE|MAP_MEM_NAMED_REUSE|MAP_MEM_USE_DATA_ADDR|MAP_MEM_VM_COPY|MAP_MEM_VM_SHARE|MAP_MEM_LEDGER_TAGGED|MAP_MEM_4K_DATA_ADDR)
/*line: 308*/   MAP_MEM_FLAGS_ALL = 0xffe000,  // (MAP_MEM_FLAGS_USER)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 237
// #define MEMORY_OBJECT_BEHAVE_INFO_COUNT ((mach_msg_type_number_t)       \
// 	        (sizeof(memory_object_behave_info_data_t)/sizeof(int)))

// Line: 239
// #define MEMORY_OBJECT_PERF_INFO_COUNT ((mach_msg_type_number_t)       \
// 	        (sizeof(memory_object_perf_info_data_t)/sizeof(int)))

// Line: 241
// #define MEMORY_OBJECT_ATTR_INFO_COUNT ((mach_msg_type_number_t)       \
// 	        (sizeof(memory_object_attr_info_data_t)/sizeof(int)))

