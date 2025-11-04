// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/arm/vm_param.h

enum macro_byte_size {
/*line: 47*/    BYTE_SIZE = 0x8, /* byte size in bits */ // 8
};

enum macro_page_size {
/*line: 59*/    PAGE_MAX_SHIFT = 0xe,  // 14
/*line: 60*/    PAGE_MAX_SIZE = 0x4000,  // (1<<PAGE_MAX_SHIFT)
/*line: 61*/    PAGE_MAX_MASK = 0x3fff,  // (PAGE_MAX_SIZE-1)
/*line: 63*/    PAGE_MIN_SHIFT = 0xc,  // 12
/*line: 64*/    PAGE_MIN_SIZE = 0x1000,  // (1<<PAGE_MIN_SHIFT)
/*line: 65*/    PAGE_MIN_MASK = 0xfff,  // (PAGE_MIN_SIZE-1)
};

enum macro_max_page_address {
/*line: 67*/    VM_MAX_PAGE_ADDRESS = 0xfc0000000,  // MACH_VM_MAX_ADDRESS
/*line: 83*/    VM_MIN_ADDRESS = 0x0,  // ((vm_address_t)0x0000000000000000ULL)
/*line: 84*/    VM_MAX_ADDRESS = 0xf0000000,  // ((vm_address_t)0x00000000F0000000ULL)
/* system-wide values */
/*line: 87*/    MACH_VM_MIN_ADDRESS_RAW = 0x0,  // 0x0ULL
/*line: 88*/    MACH_VM_MAX_ADDRESS_RAW = 0xfc0000000,  // 0x0000000FC0000000ULL
/*
 * `MACH_VM_MAX_ADDRESS` is exported to user space, but we don't want this
 * larger value for `MACH_VM_MAX_ADDRESS` to be exposed outside the kernel.
 */
/*line: 95*/    MACH_VM_MIN_ADDRESS = 0x0,  // ((mach_vm_offset_t)MACH_VM_MIN_ADDRESS_RAW)
/*line: 96*/    MACH_VM_MAX_ADDRESS = 0xfc0000000,  // ((mach_vm_offset_t)MACH_VM_MAX_ADDRESS_RAW)
/*line: 98*/    MACH_VM_MIN_GPU_CARVEOUT_ADDRESS_RAW = 0x1000000000,  // 0x0000001000000000ULL
/*line: 99*/    MACH_VM_MAX_GPU_CARVEOUT_ADDRESS_RAW = 0x7000000000,  // 0x0000007000000000ULL
/*line: 100*/   MACH_VM_MIN_GPU_CARVEOUT_ADDRESS = 0x1000000000,  // ((mach_vm_offset_t)MACH_VM_MIN_GPU_CARVEOUT_ADDRESS_RAW)
/*line: 101*/   MACH_VM_MAX_GPU_CARVEOUT_ADDRESS = 0x7000000000,  // ((mach_vm_offset_t)MACH_VM_MAX_GPU_CARVEOUT_ADDRESS_RAW)
/*line: 107*/   VM_MAP_MIN_ADDRESS = 0x0,  // VM_MIN_ADDRESS
/*line: 108*/   VM_MAP_MAX_ADDRESS = 0xf0000000,  // VM_MAX_ADDRESS
};

enum macro_swi_syscall {
/*line: 113*/   SWI_SYSCALL = 0x80,  // 0x80
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 50
// #define PAGE_SHIFT vm_page_shift

// Line: 51
// #define PAGE_SIZE vm_page_size

// Line: 52
// #define PAGE_MASK vm_page_mask

// Line: 54
// #define VM_PAGE_SIZE vm_page_size

