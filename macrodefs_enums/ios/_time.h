// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/_time.h

// Depends on identifiers
enum macro_clocks_per_sec {
/*line: 93*/    CLOCKS_PER_SEC = 0xf4240, /* [XSI] */ // ((clock_t)1000000)
};

enum macro_time_utc {
/* ISO/IEC 9899:201x 7.27.2.5 The timespec_get function */
/*line: 200*/   TIME_UTC = 0x1, /* time elapsed since epoch */ // 1
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 151
// #define __CLOCK_AVAILABILITY __OSX_AVAILABLE(10.12) __IOS_AVAILABLE(10.0) __TVOS_AVAILABLE(10.0) __WATCHOS_AVAILABLE(3.0)

// Line: 158
// #define CLOCK_REALTIME _CLOCK_REALTIME

// Line: 160
// #define CLOCK_MONOTONIC _CLOCK_MONOTONIC

// Line: 163
// #define CLOCK_MONOTONIC_RAW _CLOCK_MONOTONIC_RAW

// Line: 165
// #define CLOCK_MONOTONIC_RAW_APPROX _CLOCK_MONOTONIC_RAW_APPROX

// Line: 167
// #define CLOCK_UPTIME_RAW _CLOCK_UPTIME_RAW

// Line: 169
// #define CLOCK_UPTIME_RAW_APPROX _CLOCK_UPTIME_RAW_APPROX

// Line: 172
// #define CLOCK_PROCESS_CPUTIME_ID _CLOCK_PROCESS_CPUTIME_ID

// Line: 174
// #define CLOCK_THREAD_CPUTIME_ID _CLOCK_THREAD_CPUTIME_ID

