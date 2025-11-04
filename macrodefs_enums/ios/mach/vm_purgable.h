// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/vm_purgable.h

// Depends on identifiers
enum macro_vm_purgable_state {
/*
 *	Enumeration of valid values for vm_purgable_t.
 *
 *  When making a new VM_PURGABLE_*, update tests vm_parameter_validation_[user|kern]
 *  and their expected results; they deliberately call VM functions with invalid
 *  values and you may be turning one of those invalid bits valid.
 */
/*line: 62*/    VM_PURGABLE_SET_STATE = 0x0, /* set state of purgeable object */ // ((vm_purgable_t)0)
/*line: 63*/    VM_PURGABLE_GET_STATE = 0x1, /* get state of purgeable object */ // ((vm_purgable_t)1)
/*line: 64*/    VM_PURGABLE_PURGE_ALL = 0x2, /* purge all volatile objects now */ // ((vm_purgable_t)2)
/*line: 65*/    VM_PURGABLE_SET_STATE_FROM_KERNEL = 0x3, /* set state from kernel */ // ((vm_purgable_t)3)
};

enum macro_purgable_aging {
/*
 * Purgeable state:
 *
 *  31 15 14 13 12 11 10 8 7 6 5 4 3 2 1 0
 * +-----+--+-----+--+----+-+-+---+---+---+
 * |     |NA|DEBUG|  | GRP| |B|ORD|   |STA|
 * +-----+--+-----+--+----+-+-+---+---+---+
 * " ": unused (i.e. reserved)
 * STA: purgeable state
 *      see: VM_PURGABLE_NONVOLATILE=0 to VM_PURGABLE_DENY=3
 * ORD: order
 *      see:VM_VOLATILE_ORDER_*
 * B: behavior
 *      see: VM_PURGABLE_BEHAVIOR_*
 * GRP: group
 *      see: VM_VOLATILE_GROUP_*
 * DEBUG: debug
 *      see: VM_PURGABLE_DEBUG_*
 * NA: no aging
 *      see: VM_PURGABLE_NO_AGING*
 */
/*line: 89*/    VM_PURGABLE_NO_AGING_SHIFT = 0x10,  // 16
/*line: 90*/    VM_PURGABLE_NO_AGING_MASK = 0x10000,  // (0x1<<VM_PURGABLE_NO_AGING_SHIFT)
/*line: 91*/    VM_PURGABLE_NO_AGING = 0x10000,  // (0x1<<VM_PURGABLE_NO_AGING_SHIFT)
};

// Depends on identifiers
enum macro_purgable_debug {
/*line: 93*/    VM_PURGABLE_DEBUG_SHIFT = 0xc,  // 12
/*line: 94*/    VM_PURGABLE_DEBUG_MASK = 0x3000,  // (0x3<<VM_PURGABLE_DEBUG_SHIFT)
/*line: 95*/    VM_PURGABLE_DEBUG_EMPTY = 0x1000,  // (0x1<<VM_PURGABLE_DEBUG_SHIFT)
/*line: 96*/    VM_PURGABLE_DEBUG_FAULT = 0x2000,  // (0x2<<VM_PURGABLE_DEBUG_SHIFT)
};

enum macro_volatile_group {
/*
 * Volatile memory ordering groups (group zero objects are purged before group 1, etc...
 * It is implementation dependent as to whether these groups are global or per-address space.
 * (for the moment, they are global).
 */
/*line: 103*/   VM_VOLATILE_GROUP_SHIFT = 0x8,  // 8
/*line: 104*/   VM_VOLATILE_GROUP_MASK = 0x700,  // (7<<VM_VOLATILE_GROUP_SHIFT)
/*line: 105*/   VM_VOLATILE_GROUP_DEFAULT = 0x0,  // VM_VOLATILE_GROUP_0
/*line: 107*/   VM_VOLATILE_GROUP_0 = 0x0,  // (0<<VM_VOLATILE_GROUP_SHIFT)
/*line: 108*/   VM_VOLATILE_GROUP_1 = 0x100,  // (1<<VM_VOLATILE_GROUP_SHIFT)
/*line: 109*/   VM_VOLATILE_GROUP_2 = 0x200,  // (2<<VM_VOLATILE_GROUP_SHIFT)
/*line: 110*/   VM_VOLATILE_GROUP_3 = 0x300,  // (3<<VM_VOLATILE_GROUP_SHIFT)
/*line: 111*/   VM_VOLATILE_GROUP_4 = 0x400,  // (4<<VM_VOLATILE_GROUP_SHIFT)
/*line: 112*/   VM_VOLATILE_GROUP_5 = 0x500,  // (5<<VM_VOLATILE_GROUP_SHIFT)
/*line: 113*/   VM_VOLATILE_GROUP_6 = 0x600,  // (6<<VM_VOLATILE_GROUP_SHIFT)
/*line: 114*/   VM_VOLATILE_GROUP_7 = 0x700,  // (7<<VM_VOLATILE_GROUP_SHIFT)
};

enum macro_purgable_behavior {
/*
 * Purgeable behavior
 * Within the same group, FIFO objects will be emptied before objects that are added later.
 * LIFO objects will be emptied after objects that are added later.
 * - Input only, not returned on state queries.
 */
/*line: 122*/   VM_PURGABLE_BEHAVIOR_SHIFT = 0x6,  // 6
/*line: 123*/   VM_PURGABLE_BEHAVIOR_MASK = 0x40,  // (1<<VM_PURGABLE_BEHAVIOR_SHIFT)
/*line: 124*/   VM_PURGABLE_BEHAVIOR_FIFO = 0x0,  // (0<<VM_PURGABLE_BEHAVIOR_SHIFT)
/*line: 125*/   VM_PURGABLE_BEHAVIOR_LIFO = 0x40,  // (1<<VM_PURGABLE_BEHAVIOR_SHIFT)
};

enum macro_purgable_ordering {
/*
 * Obsolete object.
 * Disregard volatile group, and put object into obsolete queue instead, so it is the next object
 * to be purged.
 * - Input only, not returned on state queries.
 */
/*line: 133*/   VM_PURGABLE_ORDERING_SHIFT = 0x5,  // 5
/*line: 134*/   VM_PURGABLE_ORDERING_MASK = 0x20,  // (1<<VM_PURGABLE_ORDERING_SHIFT)
/*line: 135*/   VM_PURGABLE_ORDERING_OBSOLETE = 0x20,  // (1<<VM_PURGABLE_ORDERING_SHIFT)
/*line: 136*/   VM_PURGABLE_ORDERING_NORMAL = 0x0,  // (0<<VM_PURGABLE_ORDERING_SHIFT)
};

enum macro_vm_volatile_order {
/*
 * Obsolete parameter - do not use
 */
/*line: 142*/   VM_VOLATILE_ORDER_SHIFT = 0x4,  // 4
/*line: 143*/   VM_VOLATILE_ORDER_MASK = 0x10,  // (1<<VM_VOLATILE_ORDER_SHIFT)
/*line: 144*/   VM_VOLATILE_MAKE_FIRST_IN_GROUP = 0x10,  // (1<<VM_VOLATILE_ORDER_SHIFT)
/*line: 145*/   VM_VOLATILE_MAKE_LAST_IN_GROUP = 0x0,  // (0<<VM_VOLATILE_ORDER_SHIFT)
};

enum macro_purgable_state_limits {
/*
 * Valid states of a purgeable object.
 */
/*line: 150*/   VM_PURGABLE_STATE_MIN = 0x0, /* minimum purgeable object state value */ // 0
/*line: 151*/   VM_PURGABLE_STATE_MAX = 0x3, /* maximum purgeable object state value */ // 3
/*line: 152*/   VM_PURGABLE_STATE_MASK = 0x3, /* mask to separate state from group */ // 3
};

enum macro_purgeable_flags {
/*line: 154*/   VM_PURGABLE_NONVOLATILE = 0x0, /* purgeable object is non-volatile */ // 0
/*line: 155*/   VM_PURGABLE_VOLATILE = 0x1, /* purgeable object is volatile */ // 1
/*line: 156*/   VM_PURGABLE_EMPTY = 0x2, /* purgeable object is volatile and empty */ // 2
/*line: 157*/   VM_PURGABLE_DENY = 0x3, /* (mark) object not purgeable */ // 3
};

enum macro_purgable_masks {
/*line: 159*/   VM_PURGABLE_ALL_MASKS = 0x13773,  // (VM_PURGABLE_STATE_MASK|VM_VOLATILE_ORDER_MASK|VM_PURGABLE_ORDERING_MASK|VM_PURGABLE_BEHAVIOR_MASK|VM_VOLATILE_GROUP_MASK|VM_PURGABLE_DEBUG_MASK|VM_PURGABLE_NO_AGING_MASK)
};

