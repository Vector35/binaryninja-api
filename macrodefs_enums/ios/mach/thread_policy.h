// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/thread_policy.h

enum macro_thread_policy {
/*
 * THREAD_STANDARD_POLICY:
 *
 * This is the standard (fair) scheduling mode, assigned to new
 * threads.  The thread will be given processor time in a manner
 * which apportions approximately equal share to long running
 * computations.
 *
 * Parameters:
 *	[none]
 */
/*line: 84*/    THREAD_STANDARD_POLICY = 0x1,  // 1
// /*line: 93*/    THREAD_STANDARD_POLICY_COUNT = 0x0,  // 0
/*
 * THREAD_EXTENDED_POLICY:
 *
 * Extended form of THREAD_STANDARD_POLICY, which supplies a
 * hint indicating whether this is a long running computation.
 *
 * Parameters:
 *
 * timeshare: TRUE (the default) results in identical scheduling
 * behavior as THREAD_STANDARD_POLICY.
 */
/*line: 107*/   THREAD_EXTENDED_POLICY = 0x1,  // 1
/*
 * THREAD_TIME_CONSTRAINT_POLICY:
 *
 * This scheduling mode is for threads which have real time
 * constraints on their execution.
 *
 * Parameters:
 *
 * period: This is the nominal amount of time between separate
 * processing arrivals, specified in absolute time units.  A
 * value of 0 indicates that there is no inherent periodicity in
 * the computation.
 *
 * computation: This is the nominal amount of computation
 * time needed during a separate processing arrival, specified
 * in absolute time units.  The thread may be preempted after
 * the computation time has elapsed.
 * If (computation < constraint/2) it will be forced to
 * constraint/2 to avoid unintended preemption and associated
 * timer interrupts.
 *
 * constraint: This is the maximum amount of real time that
 * may elapse from the start of a separate processing arrival
 * to the end of computation for logically correct functioning,
 * specified in absolute time units.  Must be (>= computation).
 * Note that latency = (constraint - computation).
 *
 * preemptible: IGNORED (This indicates that the computation may be
 * interrupted, subject to the constraint specified above.)
 */
/*line: 150*/   THREAD_TIME_CONSTRAINT_POLICY = 0x2,  // 2
/*
 * THREAD_PRECEDENCE_POLICY:
 *
 * This may be used to indicate the relative value of the
 * computation compared to the other threads in the task.
 *
 * Parameters:
 *
 * importance: The importance is specified as a signed value.
 */
/*line: 178*/   THREAD_PRECEDENCE_POLICY = 0x3,  // 3
/*
 * THREAD_AFFINITY_POLICY:
 *
 * This policy is experimental.
 * This may be used to express affinity relationships
 * between threads in the task. Threads with the same affinity tag will
 * be scheduled to share an L2 cache if possible. That is, affinity tags
 * are a hint to the scheduler for thread placement.
 *
 * The namespace of affinity tags is generally local to one task. However,
 * a child task created after the assignment of affinity tags by its parent
 * will share that namespace. In particular, a family of forked processes
 * may be created with a shared affinity namespace.
 *
 * Parameters:
 * tag: The affinity set identifier.
 */
/*line: 208*/   THREAD_AFFINITY_POLICY = 0x4,  // 4
// /*line: 214*/   THREAD_AFFINITY_TAG_NULL = 0x0,  // 0
/*
 * THREAD_BACKGROUND_POLICY:
 */
/*line: 226*/   THREAD_BACKGROUND_POLICY = 0x5,  // 5
/*line: 241*/   THREAD_LATENCY_QOS_POLICY = 0x7,  // 7
/*line: 254*/   THREAD_THROUGHPUT_QOS_POLICY = 0x8,  // 8
};

enum macro_thread_background_policy {
/*line: 232*/   THREAD_BACKGROUND_POLICY_DARWIN_BG = 0x1000,  // 0x1000
};


/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 116
// #define THREAD_EXTENDED_POLICY_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (thread_extended_policy_data_t) / sizeof (integer_t)))

// Line: 164
// #define THREAD_TIME_CONSTRAINT_POLICY_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (thread_time_constraint_policy_data_t) / sizeof (integer_t)))

// Line: 187
// #define THREAD_PRECEDENCE_POLICY_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (thread_precedence_policy_data_t) / sizeof (integer_t)))

// Line: 219
// #define THREAD_AFFINITY_POLICY_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (thread_affinity_policy_data_t) / sizeof (integer_t)))

// Line: 237
// #define THREAD_BACKGROUND_POLICY_COUNT ((mach_msg_type_number_t) \
// 	(sizeof (thread_background_policy_data_t) / sizeof (integer_t)))

// Line: 251
// #define THREAD_LATENCY_QOS_POLICY_COUNT ((mach_msg_type_number_t)       \
// 	    (sizeof (thread_latency_qos_policy_data_t) / sizeof (integer_t)))

// Line: 264
// #define THREAD_THROUGHPUT_QOS_POLICY_COUNT ((mach_msg_type_number_t) \
// 	    (sizeof (thread_throughput_qos_policy_data_t) / sizeof (integer_t)))

