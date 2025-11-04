// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/clock_types.h

enum macro_clock_id {
/*
 * Reserved clock id values for default clocks.
 */
/*line: 70*/    SYSTEM_CLOCK = 0x0,  // 0
/*line: 71*/    CALENDAR_CLOCK = 0x1,  // 1
};

enum macro_realtime_clock {
/*line: 73*/    REALTIME_CLOCK = 0x0,  // 0
};

enum macro_clock_attributes {
/*
 * Attribute names.
 */
/*line: 78*/    CLOCK_GET_TIME_RES = 0x1, /* get_time call resolution */ // 1
/*							2	 * was map_time call resolution */
/*line: 80*/    CLOCK_ALARM_CURRES = 0x3, /* current alarm resolution */ // 3
/*line: 81*/    CLOCK_ALARM_MINRES = 0x4, /* minimum alarm resolution */ // 4
/*line: 82*/    CLOCK_ALARM_MAXRES = 0x5, /* maximum alarm resolution */ // 5
};

enum macro_alarm_type {
/*
 * Alarm parameter defines.
 */
/*line: 121*/   ALRMTYPE = 0xff, /* type (8-bit field) */ // 0xff
/*line: 122*/   TIME_ABSOLUTE = 0x0, /* absolute time */ // 0x00
/*line: 123*/   TIME_RELATIVE = 0x1, /* relative time */ // 0x01
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 84
// #define NSEC_PER_USEC 1000ull

// Line: 85
// #define USEC_PER_SEC 1000000ull

// Line: 86
// #define NSEC_PER_SEC 1000000000ull

// Line: 87
// #define NSEC_PER_MSEC 1000000ull

