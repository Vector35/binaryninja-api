// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/task_policy.h

enum macro_task_policy {
/*
 * TASK_CATEGORY_POLICY:
 *
 * This provides information to the kernel about the role
 * of the task in the system.
 *
 * Parameters:
 *
 * role: Enumerated as follows:
 *
 * TASK_UNSPECIFIED is the default, since the role is not
 * inherited from the parent.
 *
 * TASK_FOREGROUND_APPLICATION should be assigned when the
 * task is a normal UI application in the foreground from
 * the HI point of view.
 * **N.B. There may be more than one of these at a given time.
 *
 * TASK_BACKGROUND_APPLICATION should be assigned when the
 * task is a normal UI application in the background from
 * the HI point of view.
 *
 * TASK_CONTROL_APPLICATION should be assigned to the unique
 * UI application which implements the pop-up application dialog.
 * There can only be one task at a time with this designation,
 * which is assigned FCFS.
 *
 * TASK_GRAPHICS_SERVER should be assigned to the graphics
 * management (window) server.  There can only be one task at
 * a time with this designation, which is assigned FCFS.
 */
/*line: 104*/   TASK_CATEGORY_POLICY = 0x1,  // 1
/*line: 106*/   TASK_SUPPRESSION_POLICY = 0x3,  // 3
/*line: 107*/   TASK_POLICY_STATE = 0x4,  // 4
/*line: 108*/   TASK_BASE_QOS_POLICY = 0x8,  // 8
/*line: 109*/   TASK_OVERRIDE_QOS_POLICY = 0x9,  // 9
/*line: 110*/   TASK_BASE_LATENCY_QOS_POLICY = 0xa,  // 10
/*line: 111*/   TASK_BASE_THROUGHPUT_QOS_POLICY = 0xb,  // 11
};

// Depends on identifiers
enum macro_proc_flags {
/* These should be removed - they belong in proc_info.h */
/*line: 172*/   PROC_FLAG_DARWINBG = 0x8000, /* process in darwin background */ // 0x8000
/*line: 173*/   PROC_FLAG_EXT_DARWINBG = 0x10000, /* process in darwin background - external enforcement */ // 0x10000
/*line: 174*/   PROC_FLAG_IOS_APPLEDAEMON = 0x20000, /* process is apple ios daemon */ // 0x20000
/*line: 175*/   PROC_FLAG_IOS_IMPPROMOTION = 0x80000, /* process is able to receive an importance donation */ // 0x80000
/*line: 176*/   PROC_FLAG_ADAPTIVE = 0x100000, /* Process is adaptive */ // 0x100000
/*line: 177*/   PROC_FLAG_ADAPTIVE_IMPORTANT = 0x200000, /* Process is adaptive, and is currently important */ // 0x200000
/*line: 178*/   PROC_FLAG_IMPORTANCE_DONOR = 0x400000, /* Process is marked as an importance donor */ // 0x400000
/*line: 179*/   PROC_FLAG_SUPPRESSED = 0x800000, /* Process is suppressed */ // 0x800000
/*line: 180*/   PROC_FLAG_APPLICATION = 0x1000000, /* Process is an application */ // 0x1000000
/*line: 181*/   PROC_FLAG_IOS_APPLICATION = 0x1000000, /* Process is an application */ // PROC_FLAG_APPLICATION
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 133
// #define TASK_CATEGORY_POLICY_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (task_category_policy_data_t) / sizeof (integer_t)))

// Line: 157
// #define LATENCY_QOS_LAUNCH_DEFAULT_TIER LATENCY_QOS_TIER_3

// Line: 158
// #define THROUGHPUT_QOS_LAUNCH_DEFAULT_TIER THROUGHPUT_QOS_TIER_3

// Line: 168
// #define TASK_QOS_POLICY_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (struct task_qos_policy) / sizeof (integer_t)))

