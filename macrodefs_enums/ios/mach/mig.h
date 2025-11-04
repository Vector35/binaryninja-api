// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/mig.h

enum macro_mig_type_check {
/* default MIG type checking on */
/*line: 63*/    __MigTypeCheck = 0x1,  // 1
};

enum macro_mig_pack_structs {
/*
 * Pack MIG message structs.
 * This is an indicator of the need to view shared structs in a
 * binary-compatible format - and MIG message structs are no different.
 */
/*line: 73*/    __MigPackStructs = 0x1,  // 1
};

// Depends on identifiers
enum macro_mig_routine_arg_descriptor_null {
/*line: 103*/   MIG_ROUTINE_ARG_DESCRIPTOR_NULL = 0x0,  // ((mig_routine_arg_descriptor_t)0)
};

// Depends on identifiers
enum macro_mig_routine_descriptor {
/*line: 119*/   MIG_ROUTINE_DESCRIPTOR_NULL = 0x0,  // ((mig_routine_descriptor_t)0)
};

// Depends on identifiers
enum macro_mig_subsystem {
/*line: 132*/   MIG_SUBSYSTEM_NULL = 0x0,  // ((mig_subsystem_t)0)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 150
// #define MIG_SERVER_ROUTINE __attribute__((mig_server_routine))

