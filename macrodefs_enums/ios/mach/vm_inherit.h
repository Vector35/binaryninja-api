// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/vm_inherit.h

// Depends on identifiers
enum macro_vm_inherit {
/*
 *	Enumeration of valid values for vm_inherit_t.
 *
 *  When making a new VM_INHERIT_*, update tests vm_parameter_validation_[user|kern]
 *  and their expected results; they deliberately call VM functions with invalid
 *  inherit values and you may be turning one of those invalid inherits valid.
 */
/*line: 85*/    VM_INHERIT_SHARE = 0x0, /* share with child */ // ((vm_inherit_t)0)
/*line: 86*/    VM_INHERIT_COPY = 0x1, /* copy into child */ // ((vm_inherit_t)1)
/*line: 87*/    VM_INHERIT_NONE = 0x2, /* absent from child */ // ((vm_inherit_t)2)
/*line: 88*/    VM_INHERIT_DONATE_COPY = 0x3, /* copy and delete */ // ((vm_inherit_t)3)
/*line: 90*/    VM_INHERIT_DEFAULT = 0x1,  // VM_INHERIT_COPY
/*line: 91*/    VM_INHERIT_LAST_VALID = 0x2,  // VM_INHERIT_NONE
};

