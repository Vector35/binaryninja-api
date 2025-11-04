// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/vm_behavior.h

// Depends on identifiers
enum macro_vm_behavior {
/*
 * The following behaviors affect the memory region's future behavior
 * and are stored in the VM map entry data structure.
 */
/*line: 65*/    VM_BEHAVIOR_DEFAULT = 0x0, /* default */ // ((vm_behavior_t)0)
/*line: 66*/    VM_BEHAVIOR_RANDOM = 0x1, /* random */ // ((vm_behavior_t)1)
/*line: 67*/    VM_BEHAVIOR_SEQUENTIAL = 0x2, /* forward sequential */ // ((vm_behavior_t)2)
/*line: 68*/    VM_BEHAVIOR_RSEQNTL = 0x3, /* reverse sequential */ // ((vm_behavior_t)3)
/*
 * The following "behaviors" affect the memory region only at the time of the
 * call and are not stored in the VM map entry.
 */
/*line: 74*/    VM_BEHAVIOR_WILLNEED = 0x4, /* will need in near future */ // ((vm_behavior_t)4)
/*line: 75*/    VM_BEHAVIOR_DONTNEED = 0x5, /* dont need in near future */ // ((vm_behavior_t)5)
/*line: 76*/    VM_BEHAVIOR_FREE = 0x6, /* free memory without write-back */ // ((vm_behavior_t)6)
/*line: 77*/    VM_BEHAVIOR_ZERO_WIRED_PAGES = 0x7, /* zero out the wired pages of an entry if it is being deleted without unwiring them first */ // ((vm_behavior_t)7)
/*line: 78*/    VM_BEHAVIOR_REUSABLE = 0x8,  // ((vm_behavior_t)8)
/*line: 79*/    VM_BEHAVIOR_REUSE = 0x9,  // ((vm_behavior_t)9)
/*line: 80*/    VM_BEHAVIOR_CAN_REUSE = 0xa,  // ((vm_behavior_t)10)
/*line: 81*/    VM_BEHAVIOR_PAGEOUT = 0xb, /* force page-out of the pages in range (development only) */ // ((vm_behavior_t)11)
/*line: 82*/    VM_BEHAVIOR_ZERO = 0xc, /* zero pages without faulting in additional pages */ // ((vm_behavior_t)12)
/*line: 84*/    VM_BEHAVIOR_LAST_VALID = 0xc,  // (VM_BEHAVIOR_ZERO)
};

