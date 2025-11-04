// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/vm_sync.h

// Depends on identifiers
enum macro_vm_sync_flags {
/*
 *	Synchronization flags, defined as bits within the vm_sync_t type
 *
 *  When making a new VM_SYNC_*, update tests vm_parameter_validation_[user|kern]
 *  and their expected results; they deliberately call VM functions with invalid
 *  sync values and you may be turning one of those invalid syncs valid.
 */
/*line: 76*/    VM_SYNC_ASYNCHRONOUS = 0x1,  // ((vm_sync_t)0x01)
/*line: 77*/    VM_SYNC_SYNCHRONOUS = 0x2,  // ((vm_sync_t)0x02)
/*line: 78*/    VM_SYNC_INVALIDATE = 0x4,  // ((vm_sync_t)0x04)
/*line: 79*/    VM_SYNC_KILLPAGES = 0x8,  // ((vm_sync_t)0x08)
/*line: 80*/    VM_SYNC_DEACTIVATE = 0x10,  // ((vm_sync_t)0x10)
/*line: 81*/    VM_SYNC_CONTIGUOUS = 0x20,  // ((vm_sync_t)0x20)
/*line: 82*/    VM_SYNC_REUSABLEPAGES = 0x40,  // ((vm_sync_t)0x40)
};

