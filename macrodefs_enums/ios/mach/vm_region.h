// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/vm_region.h

enum macro_vm_region_limits{
/*
 *	Types defined:
 *
 *	vm_region_info_t	memory region attributes
 */
/*line: 66*/    VM_REGION_INFO_MAX = 0x400,  // (1024)
/*line: 318*/   VM_MAP_ENTRY_MAX = 0x100,  // (256)
};

enum macro_share_mode {
/*line: 121*/   SM_COW = 0x1,  // 1
/*line: 122*/   SM_PRIVATE = 0x2,  // 2
/*line: 123*/   SM_EMPTY = 0x3,  // 3
/*line: 124*/   SM_SHARED = 0x4,  // 4
/*line: 125*/   SM_TRUESHARED = 0x5,  // 5
/*line: 126*/   SM_PRIVATE_ALIASED = 0x6,  // 6
/*line: 127*/   SM_SHARED_ALIASED = 0x7,  // 7
/*line: 128*/   SM_LARGE_PAGE = 0x8,  // 8
};

enum macro_vm_region_flags {
/*line: 75*/    VM_REGION_BASIC_INFO_64 = 0x9,  // 9
/*
 * Passing VM_REGION_BASIC_INFO to vm_region_64
 * automatically converts it to a VM_REGION_BASIC_INFO_64.
 * Please use that explicitly instead.
 */
/*line: 97*/    VM_REGION_BASIC_INFO = 0xa,  // 10
/*
 * For submap info,  the SM flags above are overlayed when a submap
 * is encountered.  The field denotes whether or not machine level mapping
 * information is being shared.  PTE's etc.  When such sharing is taking
 * place the value returned is SM_TRUESHARED otherwise SM_PRIVATE is passed
 * back.
 */
/*line: 141*/   VM_REGION_EXTENDED_INFO = 0xd,  // 13
/*line: 164*/   VM_REGION_TOP_INFO = 0xc,  // 12
};


enum macro_vm_page_info_basic {
/*line: 334*/   VM_PAGE_INFO_BASIC = 0x1,  // 1
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 89
// #define VM_REGION_BASIC_INFO_COUNT_64 ((mach_msg_type_number_t) \
// 	(sizeof(vm_region_basic_info_data_64_t)/sizeof(int)))

// Line: 118
// #define VM_REGION_BASIC_INFO_COUNT ((mach_msg_type_number_t) \
// 	(sizeof(vm_region_basic_info_data_t)/sizeof(int)))

// Line: 157
// #define VM_REGION_EXTENDED_INFO_COUNT ((mach_msg_type_number_t)                       \
// 	 (sizeof (vm_region_extended_info_data_t) / sizeof (natural_t)))

// Line: 177
// #define VM_REGION_TOP_INFO_COUNT ((mach_msg_type_number_t)                                       \
// 	 (sizeof(vm_region_top_info_data_t) / sizeof(natural_t)))

// Line: 226
// #define VM_REGION_SUBMAP_INFO_COUNT ((mach_msg_type_number_t)                                       \
// 	 (sizeof(vm_region_submap_info_data_t) / sizeof(natural_t)))

// Line: 255
// #define VM_REGION_SUBMAP_INFO_V2_SIZE (sizeof (vm_region_submap_info_data_64_t))

// Line: 257
// #define VM_REGION_SUBMAP_INFO_V1_SIZE (VM_REGION_SUBMAP_INFO_V2_SIZE - \
// 	 sizeof (vm_object_id_t) /* object_id_full */ )

// Line: 260
// #define VM_REGION_SUBMAP_INFO_V0_SIZE (VM_REGION_SUBMAP_INFO_V1_SIZE - \
// 	 sizeof (unsigned int) /* pages_reusable */ )

// Line: 264
// #define VM_REGION_SUBMAP_INFO_V2_COUNT_64 ((mach_msg_type_number_t) \
// 	 (VM_REGION_SUBMAP_INFO_V2_SIZE / sizeof (natural_t)))

// Line: 267
// #define VM_REGION_SUBMAP_INFO_V1_COUNT_64 ((mach_msg_type_number_t) \
// 	 (VM_REGION_SUBMAP_INFO_V1_SIZE / sizeof (natural_t)))

// Line: 270
// #define VM_REGION_SUBMAP_INFO_V0_COUNT_64 ((mach_msg_type_number_t) \
// 	 (VM_REGION_SUBMAP_INFO_V0_SIZE / sizeof (natural_t)))

// Line: 275
// #define VM_REGION_SUBMAP_INFO_COUNT_64 VM_REGION_SUBMAP_INFO_V2_COUNT_64

// Line: 296
// #define VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 ((mach_msg_type_number_t)                                       \
// 	 (sizeof (vm_region_submap_short_info_data_64_t) / sizeof (natural_t)))

// Line: 346
// #define VM_PAGE_INFO_BASIC_COUNT ((mach_msg_type_number_t) \
// 	(sizeof(vm_page_info_basic_data_t)/sizeof(int)))

