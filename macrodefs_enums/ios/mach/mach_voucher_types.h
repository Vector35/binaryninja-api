// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/mach_voucher_types.h

// enum macro_voucher_null {
// /*line: 55*/    MACH_VOUCHER_NULL = 0x0,  // ((mach_voucher_t)0)
// };

// enum macro_voucher_name {
// /*line: 58*/    MACH_VOUCHER_NAME_NULL = 0x0,  // ((mach_voucher_name_t)0)
// };

// enum macro_voucher_null {
// /*line: 61*/    MACH_VOUCHER_NAME_ARRAY_NULL = 0x0,  // ((mach_voucher_name_array_t)0)
// };

// enum macro_ipc_voucher_null {
// /*line: 68*/    IPC_VOUCHER_NULL = 0x0,  // ((ipc_voucher_t)0)
// };

enum macro_voucher_selector {
/*line: 76*/    MACH_VOUCHER_SELECTOR_CURRENT = 0x0,  // ((mach_voucher_selector_t)0)
/*line: 77*/    MACH_VOUCHER_SELECTOR_EFFECTIVE = 0x1,  // ((mach_voucher_selector_t)1)
};

enum macro_voucher_attr_keys {
/*line: 88*/    MACH_VOUCHER_ATTR_KEY_ALL = -0x1,  // ((mach_voucher_attr_key_t)~0)
/*line: 89*/    MACH_VOUCHER_ATTR_KEY_NONE = 0x0,  // ((mach_voucher_attr_key_t)0)
/* other well-known-keys will be added here */
/*line: 92*/    MACH_VOUCHER_ATTR_KEY_ATM = 0x1,  // ((mach_voucher_attr_key_t)1)
/*line: 93*/    MACH_VOUCHER_ATTR_KEY_IMPORTANCE = 0x2,  // ((mach_voucher_attr_key_t)2)
/*line: 94*/    MACH_VOUCHER_ATTR_KEY_BANK = 0x3,  // ((mach_voucher_attr_key_t)3)
/* following keys have been removed from embedded platforms */
/*line: 97*/    MACH_VOUCHER_ATTR_KEY_PTHPRIORITY = 0x4,  // ((mach_voucher_attr_key_t)4)
/*line: 98*/    MACH_VOUCHER_ATTR_KEY_USER_DATA = 0x7,  // ((mach_voucher_attr_key_t)7)
/*line: 99*/    MACH_VOUCHER_ATTR_KEY_BITS = 0x7,  // MACH_VOUCHER_ATTR_KEY_USER_DATA
/*line: 100*/   MACH_VOUCHER_ATTR_KEY_TEST = 0x8,  // ((mach_voucher_attr_key_t)8)
/*line: 103*/   MACH_VOUCHER_ATTR_KEY_NUM_WELL_KNOWN = 0x8,  // MACH_VOUCHER_ATTR_KEY_TEST
};

// Depends on identifiers
enum macro_voucher_command {
/*line: 132*/   MACH_VOUCHER_ATTR_NOOP = 0x0,  // ((mach_voucher_attr_recipe_command_t)0)
/*line: 133*/   MACH_VOUCHER_ATTR_COPY = 0x1,  // ((mach_voucher_attr_recipe_command_t)1)
/*line: 134*/   MACH_VOUCHER_ATTR_REMOVE = 0x2,  // ((mach_voucher_attr_recipe_command_t)2)
/*line: 135*/   MACH_VOUCHER_ATTR_SET_VALUE_HANDLE = 0x3,  // ((mach_voucher_attr_recipe_command_t)3)
/*line: 136*/   MACH_VOUCHER_ATTR_AUTO_REDEEM = 0x4,  // ((mach_voucher_attr_recipe_command_t)4)
/*line: 137*/   MACH_VOUCHER_ATTR_SEND_PREPROCESS = 0x5,  // ((mach_voucher_attr_recipe_command_t)5)
/* redeem is on its way out? */
/*line: 140*/   MACH_VOUCHER_ATTR_REDEEM = 0xa,  // ((mach_voucher_attr_recipe_command_t)10)
/* recipe command(s) for importance attribute manager */
/*line: 143*/   MACH_VOUCHER_ATTR_IMPORTANCE_SELF = 0xc8,  // ((mach_voucher_attr_recipe_command_t)200)
/* recipe command(s) for bit-store attribute manager */
/*line: 146*/   MACH_VOUCHER_ATTR_USER_DATA_STORE = 0xd3,  // ((mach_voucher_attr_recipe_command_t)211)
/*line: 147*/   MACH_VOUCHER_ATTR_BITS_STORE = 0xd3, /* deprecated */ // MACH_VOUCHER_ATTR_USER_DATA_STORE
/* recipe command(s) for test attribute manager */
/*line: 150*/   MACH_VOUCHER_ATTR_TEST_STORE = 0xd3,  // MACH_VOUCHER_ATTR_USER_DATA_STORE
/*line: 175*/   MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE = 0x1400,  // 5120
/*line: 176*/   MACH_VOUCHER_TRAP_STACK_LIMIT = 0x100,  // 256
};

// enum macro_voucher_manager {
// /*line: 191*/   MACH_VOUCHER_ATTR_MANAGER_NULL = 0x0,  // ((mach_voucher_attr_manager_t)0)
// };

// enum macro_voucher_control {
// /*line: 200*/   MACH_VOUCHER_ATTR_CONTROL_NULL = 0x0,  // ((mach_voucher_attr_control_t)0)
// };

// enum macro_ipc_voucher_null {
// /*line: 209*/   IPC_VOUCHER_ATTR_MANAGER_NULL = 0x0,  // ((ipc_voucher_attr_manager_t)0)
// /*line: 210*/   IPC_VOUCHER_ATTR_CONTROL_NULL = 0x0,  // ((ipc_voucher_attr_control_t)0)
// };

enum macro_max_nested_vouchers {
/*line: 222*/   MACH_VOUCHER_ATTR_VALUE_MAX_NESTED = 0x4,  // ((mach_voucher_attr_value_handle_array_size_t)4)
};

enum macro_voucher_flags {
/*line: 226*/   MACH_VOUCHER_ATTR_VALUE_FLAGS_NONE = 0x0,  // ((mach_voucher_attr_value_flags_t)0)
/*line: 227*/   MACH_VOUCHER_ATTR_VALUE_FLAGS_PERSIST = 0x1,  // ((mach_voucher_attr_value_flags_t)1)
};

enum macro_voucher_importance {
// /*line: 231*/   MACH_VOUCHER_ATTR_CONTROL_FLAGS_NONE = 0x0,  // ((mach_voucher_attr_control_flags_t)0)

/*
 * Commands and types for the IPC Importance Attribute Manager
 *
 * These are the valid mach_voucher_attr_command() options with the
 * MACH_VOUCHER_ATTR_KEY_IMPORTANCE key.
 */
/*line: 239*/   MACH_VOUCHER_IMPORTANCE_ATTR_ADD_EXTERNAL = 0x1, /* Add some number of external refs (not supported) */ // 1
/*line: 240*/   MACH_VOUCHER_IMPORTANCE_ATTR_DROP_EXTERNAL = 0x2, /* Drop some number of external refs */ // 2
};

enum macro_activity_id_count {
/*
 * Activity id Generation defines
 */
/*line: 246*/   MACH_ACTIVITY_ID_COUNT_MAX = 0x10,  // 16
};

