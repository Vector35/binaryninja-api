// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/qos.h

enum macro_qos_min_priority {
/*!
 * @constant QOS_MIN_RELATIVE_PRIORITY
 * @abstract The minimum relative priority that may be specified within a
 * QOS class. These priorities are relative only within a given QOS class
 * and meaningful only for the current process.
 */
/*line: 153*/   QOS_MIN_RELATIVE_PRIORITY = -0xf,  // (-15)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 114
// #define __QOS_ENUM (name, type, ...) enum { __VA_ARGS__ }; typedef type name##_t

// Line: 115
// #define __QOS_CLASS_AVAILABLE (...)

// Line: 126
// #define __QOS_CLASS_AVAILABLE __API_AVAILABLE

