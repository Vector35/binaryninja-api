// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/dispatch/queue.h

// enum macro_dispatch_apply_auto {
// /*line: 453*/   DISPATCH_APPLY_AUTO_AVAILABLE = 0x1,  // 1
// };

// Depends on identifiers
enum macro_dispatch_apply_auto {
  /*line: 477*/ DISPATCH_APPLY_AUTO = 0x0, // ((dispatch_queue_t_Nonnull)0)
};

enum macro_dispatch_queue_priority {
  /*!
   * @typedef dispatch_queue_priority_t
   * Type of dispatch_queue_priority
   *
   * @constant DISPATCH_QUEUE_PRIORITY_HIGH
   * Items dispatched to the queue will run at high priority,
   * i.e. the queue will be scheduled for execution before
   * any default priority or low priority queue.
   *
   * @constant DISPATCH_QUEUE_PRIORITY_DEFAULT
   * Items dispatched to the queue will run at the default
   * priority, i.e. the queue will be scheduled for execution
   * after all high priority queues have been scheduled, but
   * before any low priority queues have been scheduled.
   *
   * @constant DISPATCH_QUEUE_PRIORITY_LOW
   * Items dispatched to the queue will run at low priority,
   * i.e. the queue will be scheduled for execution after all
   * default priority and high priority queues have been
   * scheduled.
   *
   * @constant DISPATCH_QUEUE_PRIORITY_BACKGROUND
   * Items dispatched to the queue will run at background priority, i.e. the
   * queue will be scheduled for execution after all higher priority queues have
   * been scheduled and the system will run items on this queue on a thread with
   * background status as per setpriority(2) (i.e. disk I/O is throttled and the
   * thread's scheduling priority is set to lowest value).
   */
  /*line: 652*/ DISPATCH_QUEUE_PRIORITY_HIGH = 0x2,    // 2
  /*line: 653*/ DISPATCH_QUEUE_PRIORITY_DEFAULT = 0x0, // 0
  /*line: 654*/ DISPATCH_QUEUE_PRIORITY_LOW = -0x2,    // (-2)
};

// Depends on identifiers
enum macro_dispatch_queue_serial {
  /*!
   * @const DISPATCH_QUEUE_SERIAL
   *
   * @discussion
   * An attribute that can be used to create a dispatch queue that invokes
   * blocks serially in FIFO order.
   *
   * See dispatch_queue_serial_t.
   */
  /*line: 721*/ DISPATCH_QUEUE_SERIAL = 0x0, // NULL
};

// Depends on identifiers
enum macro_queue_serial_inactive {
  /*!
   * @const DISPATCH_QUEUE_SERIAL_INACTIVE
   *
   * @discussion
   * An attribute that can be used to create a dispatch queue that invokes
   * blocks serially in FIFO order, and that is initially inactive.
   *
   * See dispatch_queue_attr_make_initially_inactive().
   */
  /*line: 732*/ DISPATCH_QUEUE_SERIAL_INACTIVE =
      0x0, // dispatch_queue_attr_make_initially_inactive(DISPATCH_QUEUE_SERIAL)
};

// Depends on identifiers
enum macro_default_target_queue {
  /*!
   * @const DISPATCH_TARGET_QUEUE_DEFAULT
   * @discussion Constant to pass to the dispatch_queue_create_with_target(),
   * dispatch_set_target_queue() and dispatch_source_create() functions to
   * indicate that the default target queue for the object type in question
   * should be used.
   */
  /*line: 980*/ DISPATCH_TARGET_QUEUE_DEFAULT = 0x0, // NULL
};

// Depends on identifiers
enum macro_current_queue_label {
  /*!
   * @const DISPATCH_CURRENT_QUEUE_LABEL
   * @discussion Constant to pass to the dispatch_queue_get_label() function to
   * retrieve the label of the current queue.
   */
  /*line: 1099*/ DISPATCH_CURRENT_QUEUE_LABEL = 0x0, // NULL
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 454
// #define DISPATCH_APPLY_QUEUE_ARG_NULLABILITY _Nullable

// Line: 655
// #define DISPATCH_QUEUE_PRIORITY_BACKGROUND INT16_MIN

// Line: 745
// #define DISPATCH_QUEUE_CONCURRENT
// DISPATCH_GLOBAL_OBJECT(dispatch_queue_attr_t, \
// 		_dispatch_queue_attr_concurrent)

// Line: 762
// #define DISPATCH_QUEUE_CONCURRENT_INACTIVE
// dispatch_queue_attr_make_initially_inactive(DISPATCH_QUEUE_CONCURRENT)

// Line: 812
// #define DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL
// dispatch_queue_attr_make_with_autorelease_frequency(\ 				DISPATCH_QUEUE_SERIAL,
// DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM)

// Line: 827
// #define DISPATCH_QUEUE_CONCURRENT_WITH_AUTORELEASE_POOL
// dispatch_queue_attr_make_with_autorelease_frequency(\
// 				DISPATCH_QUEUE_CONCURRENT,
// DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM)
