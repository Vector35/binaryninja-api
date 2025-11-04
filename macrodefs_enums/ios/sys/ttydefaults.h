// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/ttydefaults.h

// Depends on identifiers
enum macro_ttydefaults {
/*line: 89*/    CEOL = 0xff, /* XXX avoid _POSIX_VDISABLE */ // 0xff
/*line: 90*/    CERASE = 0x7f,  // 0177
/*line: 94*/    CMIN = 0x1,  // 1
/*line: 95*/    CQUIT = 0x1c, /* FS, ^\ */ // 034
/*line: 97*/    CTIME = 0x0,  // 0
/* compat */
/*line: 107*/   CBRK = 0xff,  // CEOL
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 78
// #define TTYDEF_IFLAG (BRKINT	| ICRNL	| IMAXBEL | IXON | IXANY)

// Line: 79
// #define TTYDEF_OFLAG (OPOST | ONLCR)

// Line: 80
// #define TTYDEF_LFLAG (ECHO | ICANON | ISIG | IEXTEN | ECHOE|ECHOKE|ECHOCTL)

// Line: 81
// #define TTYDEF_CFLAG (CREAD | CS8 | HUPCL)

// Line: 82
// #define TTYDEF_SPEED (B9600)

// Line: 88
// #define CEOF CTRL('d')

// Line: 91
// #define CINTR CTRL('c')

// Line: 92
// #define CSTATUS CTRL('t')

// Line: 93
// #define CKILL CTRL('u')

// Line: 96
// #define CSUSP CTRL('z')

// Line: 98
// #define CDSUSP CTRL('y')

// Line: 99
// #define CSTART CTRL('q')

// Line: 100
// #define CSTOP CTRL('s')

// Line: 101
// #define CLNEXT CTRL('v')

// Line: 102
// #define CDISCARD CTRL('o')

// Line: 103
// #define CWERASE CTRL('w')

// Line: 104
// #define CREPRINT CTRL('r')

// Line: 105
// #define CEOT CEOF

// Line: 108
// #define CRPRNT CREPRINT

// Line: 109
// #define CFLUSH CDISCARD

