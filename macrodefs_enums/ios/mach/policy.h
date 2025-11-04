// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/policy.h

enum macro_scheduling_policy {
/*
 *	Policy definitions.  Policies should be powers of 2,
 *	but cannot be or'd together other than to test for a
 *	policy 'class'.
 */
/*line: 89*/    POLICY_NULL = 0x0, /* none			*/ // 0
/*line: 90*/    POLICY_TIMESHARE = 0x1, /* timesharing		*/ // 1
/*line: 91*/    POLICY_RR = 0x2, /* fixed round robin	*/ // 2
/*line: 92*/    POLICY_FIFO = 0x4, /* fixed fifo		*/ // 4
};

// Depends on identifiers
enum macro_policy_class_fixedpri {
/*
 *	Check if policy is of 'class' fixed-priority.
 */
/*line: 99*/    POLICYCLASS_FIXEDPRI = 0x6,  // (POLICY_RR|POLICY_FIFO)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 136
// #define POLICY_TIMESHARE_BASE_COUNT ((mach_msg_type_number_t) \
// 	(sizeof(struct policy_timeshare_base)/sizeof(integer_t)))

// Line: 138
// #define POLICY_TIMESHARE_LIMIT_COUNT ((mach_msg_type_number_t) \
// 	(sizeof(struct policy_timeshare_limit)/sizeof(integer_t)))

// Line: 140
// #define POLICY_TIMESHARE_INFO_COUNT ((mach_msg_type_number_t) \
// 	(sizeof(struct policy_timeshare_info)/sizeof(integer_t)))

// Line: 170
// #define POLICY_RR_BASE_COUNT ((mach_msg_type_number_t)       \
// 	(sizeof(struct policy_rr_base)/sizeof(integer_t)))

// Line: 172
// #define POLICY_RR_LIMIT_COUNT ((mach_msg_type_number_t)       \
// 	(sizeof(struct policy_rr_limit)/sizeof(integer_t)))

// Line: 174
// #define POLICY_RR_INFO_COUNT ((mach_msg_type_number_t)       \
// 	(sizeof(struct policy_rr_info)/sizeof(integer_t)))

// Line: 202
// #define POLICY_FIFO_BASE_COUNT ((mach_msg_type_number_t)       \
// 	(sizeof(struct policy_fifo_base)/sizeof(integer_t)))

// Line: 204
// #define POLICY_FIFO_LIMIT_COUNT ((mach_msg_type_number_t)       \
// 	(sizeof(struct policy_fifo_limit)/sizeof(integer_t)))

// Line: 206
// #define POLICY_FIFO_INFO_COUNT ((mach_msg_type_number_t)       \
// 	(sizeof(struct policy_fifo_info)/sizeof(integer_t)))

