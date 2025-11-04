// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/vm_prot.h

// Depends on identifiers
enum macro_vm_protection {
/*
 *	Protection values, defined as bits within the vm_prot_t type
 *
 *  When making a new VM_PROT_*, update tests vm_parameter_validation_[user|kern]
 *  and their expected results; they deliberately call VM functions with invalid
 *  vm_prot values and you may be turning one of those invalid protections valid.
 */
/*line: 85*/    VM_PROT_NONE = 0x0,  // ((vm_prot_t)0x00)
/*line: 87*/    VM_PROT_READ = 0x1, /* read permission */ // ((vm_prot_t)0x01)
/*line: 88*/    VM_PROT_WRITE = 0x2, /* write permission */ // ((vm_prot_t)0x02)
/*line: 89*/    VM_PROT_EXECUTE = 0x4, /* execute permission */ // ((vm_prot_t)0x04)
};

// Depends on identifiers
enum macro_vm_prot {
/*
 *	The default protection for newly-created virtual memory
 */
/*line: 95*/    VM_PROT_DEFAULT = 0x3,  // (VM_PROT_READ|VM_PROT_WRITE)
/*
 *	The maximum privileges possible, for parameter checking.
 */
/*line: 101*/   VM_PROT_ALL = 0x7,  // (VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE)
};

// Depends on identifiers
enum macro_vm_prot_rorw_tp {
/*
 *	This is an alias to VM_PROT_EXECUTE to identify callers that
 *	want to allocate an hardware assisted Read-only/read-write
 *	trusted path in userland.
 */
/*line: 108*/   VM_PROT_RORW_TP = 0x4,  // (VM_PROT_EXECUTE)
};

// Depends on identifiers
enum macro_vm_prot_flags {
/*
 *	An invalid protection value.
 *	Used only by memory_object_lock_request to indicate no change
 *	to page locks.  Using -1 here is a bad idea because it
 *	looks like VM_PROT_ALL and then some.
 */
/*line: 117*/   VM_PROT_NO_CHANGE_LEGACY = 0x8,  // ((vm_prot_t)0x08)
/*line: 118*/   VM_PROT_NO_CHANGE = 0x1000000,  // ((vm_prot_t)0x01000000)
};

// Depends on identifiers
enum macro_vm_prot_copy {
/*
 *      When a caller finds that he cannot obtain write permission on a
 *      mapped entry, the following flag can be used.  The entry will
 *      be made "needs copy" effectively copying the object (using COW),
 *      and write permission will be added to the maximum protections
 *      for the associated entry.
 */
/*line: 128*/   VM_PROT_COPY = 0x10,  // ((vm_prot_t)0x10)
};

// Depends on identifiers
enum macro_vm_protection_flags {
/*
 *	Another invalid protection value.
 *	Used only by memory_object_data_request upon an object
 *	which has specified a copy_call copy strategy. It is used
 *	when the kernel wants a page belonging to a copy of the
 *	object, and is only asking the object as a result of
 *	following a shadow chain. This solves the race between pages
 *	being pushed up by the memory manager and the kernel
 *	walking down the shadow chain.
 */
/*line: 142*/   VM_PROT_WANTS_COPY = 0x10,  // ((vm_prot_t)0x10)
/*
 *      Another invalid protection value.
 *	Indicates that the other protection bits are to be applied as a mask
 *	against the actual protection bits of the map entry.
 */
/*line: 150*/   VM_PROT_IS_MASK = 0x40,  // ((vm_prot_t)0x40)
/*
 * Another invalid protection value to support execute-only protection.
 * VM_PROT_STRIP_READ is a special marker that tells mprotect to not
 * set VM_PROT_READ. We have to do it this way because existing code
 * expects the system to set VM_PROT_READ if VM_PROT_EXECUTE is set.
 * VM_PROT_EXECUTE_ONLY is just a convenience value to indicate that
 * the memory should be executable and explicitly not readable. It will
 * be ignored on platforms that do not support this type of protection.
 */
/*line: 161*/   VM_PROT_STRIP_READ = 0x80,  // ((vm_prot_t)0x80)
/*line: 162*/   VM_PROT_EXECUTE_ONLY = 0x84,  // (VM_PROT_EXECUTE|VM_PROT_STRIP_READ)
};

// Depends on identifiers
enum macro_vm_prot_tpro {
/*
 * Another invalid protection value to support pager TPRO protection.
 * VM_PROT_TPRO is a special marker that tells the a pager to
 * set TPRO flags on a given entry. We do it this way to prevent
 * bloating the pager structures and it allows dyld to pass through
 * this flag in lieue of specifying explicit VM flags, allowing us to handle
 * the final permissions internally.
 */
/*line: 173*/   VM_PROT_TPRO = 0x200,  // ((vm_prot_t)0x200)
};

// Depends on identifiers
enum macro_vm_prot_allexec {
/*line: 175*/   VM_PROT_ALLEXEC = 0x4,  // (VM_PROT_EXECUTE)
};

