// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/ttycom.h

// Depends on identifiers
enum macro_tty_control {
/*line: 91*/    TIOCM_LE = 0x1, /* line enable */ // 0001
/*line: 92*/    TIOCM_DTR = 0x2, /* data terminal ready */ // 0002
/*line: 93*/    TIOCM_RTS = 0x4, /* request to send */ // 0004
/*line: 94*/    TIOCM_ST = 0x8, /* secondary transmit */ // 0010
/*line: 95*/    TIOCM_SR = 0x10, /* secondary receive */ // 0020
/*line: 96*/    TIOCM_CTS = 0x20, /* clear to send */ // 0040
/*line: 97*/    TIOCM_CAR = 0x40, /* carrier detect */ // 0100
/*line: 98*/    TIOCM_CD = 0x40,  // TIOCM_CAR
/*line: 99*/    TIOCM_RNG = 0x80, /* ring */ // 0200
/*line: 100*/   TIOCM_RI = 0x80,  // TIOCM_RNG
/*line: 101*/   TIOCM_DSR = 0x100, /* data set ready */ // 0400
/*line: 128*/   TIOCPKT_DATA = 0x0, /* data packet */ // 0x00
/*line: 129*/   TIOCPKT_FLUSHREAD = 0x1, /* flush packet */ // 0x01
/*line: 130*/   TIOCPKT_FLUSHWRITE = 0x2, /* flush packet */ // 0x02
/*line: 131*/   TIOCPKT_STOP = 0x4, /* stop output */ // 0x04
/*line: 132*/   TIOCPKT_START = 0x8, /* start output */ // 0x08
/*line: 133*/   TIOCPKT_NOSTOP = 0x10, /* no more ^S, ^Q */ // 0x10
/*line: 134*/   TIOCPKT_DOSTOP = 0x20, /* now do ^S ^Q */ // 0x20
/*line: 135*/   TIOCPKT_IOCTL = 0x40, /* state change of pty driver */ // 0x40
};

enum macro_tty_discipline {
/*line: 168*/   TTYDISC = 0x0, /* termios tty line discipline */ // 0
/*line: 169*/   TABLDISC = 0x3, /* tablet discipline */ // 3
/*line: 170*/   SLIPDISC = 0x4, /* serial IP discipline */ // 4
/*line: 171*/   PPPDISC = 0x5, /* PPP discipline */ // 5
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 89
// #define TIOCMODG _IOR('t', 3, int)

// Line: 90
// #define TIOCMODS _IOW('t', 4, int)

// Line: 103
// #define TIOCEXCL _IO('t', 13)

// Line: 104
// #define TIOCNXCL _IO('t', 14)

// Line: 106
// #define TIOCFLUSH _IOW('t', 16, int)

// Line: 108
// #define TIOCGETA _IOR('t', 19, struct termios)

// Line: 109
// #define TIOCSETA _IOW('t', 20, struct termios)

// Line: 110
// #define TIOCSETAW _IOW('t', 21, struct termios)

// Line: 111
// #define TIOCSETAF _IOW('t', 22, struct termios)

// Line: 112
// #define TIOCGETD _IOR('t', 26, int)

// Line: 113
// #define TIOCSETD _IOW('t', 27, int)

// Line: 114
// #define TIOCIXON _IO('t', 129)

// Line: 115
// #define TIOCIXOFF _IO('t', 128)

// Line: 117
// #define TIOCSBRK _IO('t', 123)

// Line: 118
// #define TIOCCBRK _IO('t', 122)

// Line: 119
// #define TIOCSDTR _IO('t', 121)

// Line: 120
// #define TIOCCDTR _IO('t', 120)

// Line: 121
// #define TIOCGPGRP _IOR('t', 119, int)

// Line: 122
// #define TIOCSPGRP _IOW('t', 118, int)

// Line: 124
// #define TIOCOUTQ _IOR('t', 115, int)

// Line: 125
// #define TIOCSTI _IOW('t', 114, char)

// Line: 126
// #define TIOCNOTTY _IO('t', 113)

// Line: 127
// #define TIOCPKT _IOW('t', 112, int)

// Line: 136
// #define TIOCSTOP _IO('t', 111)

// Line: 137
// #define TIOCSTART _IO('t', 110)

// Line: 138
// #define TIOCMSET _IOW('t', 109, int)

// Line: 139
// #define TIOCMBIS _IOW('t', 108, int)

// Line: 140
// #define TIOCMBIC _IOW('t', 107, int)

// Line: 141
// #define TIOCMGET _IOR('t', 106, int)

// Line: 143
// #define TIOCGWINSZ _IOR('t', 104, struct winsize)

// Line: 144
// #define TIOCSWINSZ _IOW('t', 103, struct winsize)

// Line: 145
// #define TIOCUCNTL _IOW('t', 102, int)

// Line: 146
// #define TIOCSTAT _IO('t', 101)

// Line: 148
// #define TIOCSCONS _IO('t', 99)

// Line: 149
// #define TIOCCONS _IOW('t', 98, int)

// Line: 150
// #define TIOCSCTTY _IO('t', 97)

// Line: 151
// #define TIOCEXT _IOW('t', 96, int)

// Line: 152
// #define TIOCSIG _IO('t', 95)

// Line: 153
// #define TIOCDRAIN _IO('t', 94)

// Line: 154
// #define TIOCMSDTRWAIT _IOW('t', 91, int)

// Line: 155
// #define TIOCMGDTRWAIT _IOR('t', 90, int)

// Line: 156
// #define TIOCTIMESTAMP _IOR('t', 89, struct timeval)

// Line: 158
// #define TIOCDCDTIMESTAMP _IOR('t', 88, struct timeval)

// Line: 160
// #define TIOCSDRAINWAIT _IOW('t', 87, int)

// Line: 161
// #define TIOCGDRAINWAIT _IOR('t', 86, int)

// Line: 162
// #define TIOCDSIMICROCODE _IO('t', 85)

// Line: 164
// #define TIOCPTYGRANT _IO('t', 84)

// Line: 165
// #define TIOCPTYGNAME _IOC(IOC_OUT, 't', 83, 128)

// Line: 166
// #define TIOCPTYUNLK _IO('t', 82)

