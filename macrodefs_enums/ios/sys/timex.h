// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/timex.h

enum macro_sys_timex_h {
/*line: 64*/    _SYS_TIMEX_H_ = 0x1,  // 1
};

enum macro_ntp_api {
/*line: 68*/    NTP_API = 0x4, /* NTP API version */ // 4
};

enum macro_time_constants {
/*
 * The following defines establish the performance envelope of the
 * kernel discipline loop. Phase or frequency errors greater than
 * NAXPHASE or MAXFREQ are clamped to these maxima. For update intervals
 * less than MINSEC, the loop always operates in PLL mode; while, for
 * update intervals greater than MAXSEC, the loop always operates in FLL
 * mode. Between these two limits the operating mode is selected by the
 * STA_FLL bit in the status word.
 */
/*line: 80*/    MAXPHASE = 0x1dcd6500, /* max phase error (ns) */ // 500000000L
/*line: 81*/    MAXFREQ = 0x7a120, /* max freq error (ns/s) */ // 500000L
/*line: 82*/    MINSEC = 0x100, /* min FLL update interval (s) */ // 256
/*line: 83*/    MAXSEC = 0x800, /* max PLL update interval (s) */ // 2048
/*line: 84*/    NANOSECOND = 0x3b9aca00, /* nanoseconds in one second */ // 1000000000L
/*line: 86*/    MAXTC = 0xa, /* max time constant */ // 10
};

enum macro_timex_modes {
/*
 * Control mode codes (timex.modes)
 */
/*line: 95*/    MOD_OFFSET = 0x1, /* set time offset */ // 0x0001
/*line: 96*/    MOD_FREQUENCY = 0x2, /* set frequency offset */ // 0x0002
/*line: 97*/    MOD_MAXERROR = 0x4, /* set maximum time error */ // 0x0004
/*line: 98*/    MOD_ESTERROR = 0x8, /* set estimated time error */ // 0x0008
/*line: 99*/    MOD_STATUS = 0x10, /* set clock status bits */ // 0x0010
/*line: 100*/   MOD_TIMECONST = 0x20, /* set PLL time constant */ // 0x0020
/*line: 101*/   MOD_PPSMAX = 0x40, /* set PPS maximum averaging time */ // 0x0040
/*line: 102*/   MOD_TAI = 0x80, /* set TAI offset */ // 0x0080
/*line: 103*/   MOD_MICRO = 0x1000, /* select microsecond resolution */ // 0x1000
/*line: 104*/   MOD_NANO = 0x2000, /* select nanosecond resolution */ // 0x2000
/*line: 105*/   MOD_CLKB = 0x4000, /* select clock B */ // 0x4000
/*line: 106*/   MOD_CLKA = 0x8000, /* select clock A */ // 0x8000
};

enum macro_timex_status {
/*
 * Status codes (timex.status)
 */
/*line: 111*/   STA_PLL = 0x1, /* enable PLL updates (rw) */ // 0x0001
/*line: 112*/   STA_PPSFREQ = 0x2, /* enable PPS freq discipline (rw) */ // 0x0002
/*line: 113*/   STA_PPSTIME = 0x4, /* enable PPS time discipline (rw) */ // 0x0004
/*line: 114*/   STA_FLL = 0x8, /* enable FLL mode (rw) */ // 0x0008
/*line: 115*/   STA_INS = 0x10, /* insert leap (rw) */ // 0x0010
/*line: 116*/   STA_DEL = 0x20, /* delete leap (rw) */ // 0x0020
/*line: 117*/   STA_UNSYNC = 0x40, /* clock unsynchronized (rw) */ // 0x0040
/*line: 118*/   STA_FREQHOLD = 0x80, /* hold frequency (rw) */ // 0x0080
/*line: 119*/   STA_PPSSIGNAL = 0x100, /* PPS signal present (ro) */ // 0x0100
/*line: 120*/   STA_PPSJITTER = 0x200, /* PPS signal jitter exceeded (ro) */ // 0x0200
/*line: 121*/   STA_PPSWANDER = 0x400, /* PPS signal wander exceeded (ro) */ // 0x0400
/*line: 122*/   STA_PPSERROR = 0x800, /* PPS signal calibration error (ro) */ // 0x0800
/*line: 123*/   STA_CLOCKERR = 0x1000, /* clock hardware fault (ro) */ // 0x1000
/*line: 124*/   STA_NANO = 0x2000, /* resolution (0 = us, 1 = ns) (ro) */ // 0x2000
/*line: 125*/   STA_MODE = 0x4000, /* mode (0 = PLL, 1 = FLL) (ro) */ // 0x4000
/*line: 126*/   STA_CLK = 0x8000, /* clock source (0 = A, 1 = B) (ro) */ // 0x8000
};

// Depends on identifiers
enum macro_status_flags {
/*line: 128*/   STA_RONLY = 0xff00,  // (STA_PPSSIGNAL|STA_PPSJITTER|STA_PPSWANDER|STA_PPSERROR|STA_CLOCKERR|STA_NANO|STA_MODE|STA_CLK)
};

// Depends on identifiers
enum macro_time_status {
/*line: 131*/   STA_SUPPORTED = 0xf0c9,  // (STA_PLL|STA_FLL|STA_UNSYNC|STA_FREQHOLD|STA_CLOCKERR|STA_NANO|STA_MODE|STA_CLK)
};

enum macro_time_state {
/*
 * Clock states (ntptimeval.time_state)
 */
/*line: 137*/   TIME_OK = 0x0, /* no leap second warning */ // 0
/*line: 138*/   TIME_INS = 0x1, /* insert leap second warning */ // 1
/*line: 139*/   TIME_DEL = 0x2, /* delete leap second warning */ // 2
/*line: 140*/   TIME_OOP = 0x3, /* leap second in progress */ // 3
/*line: 141*/   TIME_WAIT = 0x4, /* leap second has occurred */ // 4
/*line: 142*/   TIME_ERROR = 0x5, /* error (see status word) */ // 5
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 85
// #define SCALE_PPM (65536 / 1000)

