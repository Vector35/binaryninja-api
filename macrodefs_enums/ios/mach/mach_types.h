// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/mach_types.h

enum macro_null_handles {
/*line: 227*/   TASK_NULL = 0x0,  // ((task_t)0)
/*line: 228*/   TASK_NAME_NULL = 0x0,  // ((task_name_t)0)
/*line: 229*/   TASK_INSPECT_NULL = 0x0,  // ((task_inspect_t)0)
/*line: 230*/   TASK_READ_NULL = 0x0,  // ((task_read_t)0)
/*line: 231*/   THREAD_NULL = 0x0,  // ((thread_t)0)
/*line: 232*/   THREAD_INSPECT_NULL = 0x0,  // ((thread_inspect_t)0)
/*line: 233*/   THREAD_READ_NULL = 0x0,  // ((thread_read_t)0)
/*line: 234*/   TID_NULL = 0x0,  // ((uint64_t)0)
/*line: 235*/   THR_ACT_NULL = 0x0,  // ((thread_act_t)0)
/*line: 236*/   IPC_SPACE_NULL = 0x0,  // ((ipc_space_t)0)
/*line: 237*/   IPC_SPACE_READ_NULL = 0x0,  // ((ipc_space_read_t)0)
/*line: 238*/   IPC_SPACE_INSPECT_NULL = 0x0,  // ((ipc_space_inspect_t)0)
/*line: 239*/   COALITION_NULL = 0x0,  // ((coalition_t)0)
/*line: 240*/   HOST_NULL = 0x0,  // ((host_t)0)
/*line: 241*/   HOST_PRIV_NULL = 0x0,  // ((host_priv_t)0)
/*line: 242*/   HOST_SECURITY_NULL = 0x0,  // ((host_security_t)0)
/*line: 243*/   PROCESSOR_SET_NULL = 0x0,  // ((processor_set_t)0)
/*line: 244*/   PROCESSOR_NULL = 0x0,  // ((processor_t)0)
/*line: 245*/   SEMAPHORE_NULL = 0x0,  // ((semaphore_t)0)
/*line: 246*/   LOCK_SET_NULL = 0x0,  // ((lock_set_t)0)
/*line: 247*/   LEDGER_NULL = 0x0,  // ((ledger_t)0)
/*line: 248*/   ALARM_NULL = 0x0,  // ((alarm_t)0)
/*line: 249*/   CLOCK_NULL = 0x0,  // ((clock_t)0)
/*line: 250*/   UND_SERVER_NULL = 0x0,  // ((UNDServerRef)0)
/*line: 251*/   ARCADE_REG_NULL = 0x0,  // ((arcade_register_t)0)
/*line: 252*/   MACH_EVENTLINK_NULL = 0x0,  // ((mach_eventlink_t)0)
/*line: 253*/   IPC_EVENTLINK_NULL = 0x0,  // ((ipc_eventlink_t)0)
/*line: 254*/   TASK_ID_TOKEN_NULL = 0x0,  // ((task_id_token_t)0)
/*line: 255*/   KCDATA_OBJECT_NULL = 0x0,  // ((kcdata_object_t)0)
};

enum macro_task_flavor {
/*line: 262*/   TASK_FLAVOR_CONTROL = 0x0, /* a task_t */ // 0
/*line: 263*/   TASK_FLAVOR_READ = 0x1, /* a task_read_t */ // 1
/*line: 264*/   TASK_FLAVOR_INSPECT = 0x2, /* a task_inspect_t */ // 2
/*line: 265*/   TASK_FLAVOR_NAME = 0x3, /* a task_name_t */ // 3
/*line: 267*/   TASK_FLAVOR_MAX = 0x3,  // TASK_FLAVOR_NAME
};

enum macro_thread_flavor {
/*line: 271*/   THREAD_FLAVOR_CONTROL = 0x0, /* a thread_t */ // 0
/*line: 272*/   THREAD_FLAVOR_READ = 0x1, /* a thread_read_t */ // 1
/*line: 273*/   THREAD_FLAVOR_INSPECT = 0x2, /* a thread_inspect_t */ // 2
/*line: 275*/   THREAD_FLAVOR_MAX = 0x2,  // THREAD_FLAVOR_INSPECT
};

enum macro_ledger_infinity {
/*line: 279*/   LEDGER_ITEM_INFINITY = -0x1,  // ((ledger_item_t)(~0))
};

enum macro_ledger_limit {
/*line: 282*/   LEDGER_LIMIT_INFINITY = 0x7fffffffffffffff,  // ((ledger_amount_t)((1ULL<<63)-1))
};

