// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/termios.h

enum macro_termios_cc_index {
/*
 * Special Control Characters
 *
 * Index into c_cc[] character array.
 *
 *	Name	     Subscript	Enabled by
 */
/*line: 76*/    VEOF = 0x0, /* ICANON */ // 0
/*line: 77*/    VEOL = 0x1, /* ICANON */ // 1
/*line: 79*/    VEOL2 = 0x2, /* ICANON together with IEXTEN */ // 2
/*line: 81*/    VERASE = 0x3, /* ICANON */ // 3
/*line: 83*/    VWERASE = 0x4, /* ICANON together with IEXTEN */ // 4
/*line: 85*/    VKILL = 0x5, /* ICANON */ // 5
/*line: 87*/    VREPRINT = 0x6, /* ICANON together with IEXTEN */ // 6
/*			7	   spare 1 */
/*line: 90*/    VINTR = 0x8, /* ISIG */ // 8
/*line: 91*/    VQUIT = 0x9, /* ISIG */ // 9
/*line: 92*/    VSUSP = 0xa, /* ISIG */ // 10
/*line: 94*/    VDSUSP = 0xb, /* ISIG together with IEXTEN */ // 11
/*line: 96*/    VSTART = 0xc, /* IXON, IXOFF */ // 12
/*line: 97*/    VSTOP = 0xd, /* IXON, IXOFF */ // 13
/*line: 99*/    VLNEXT = 0xe, /* IEXTEN */ // 14
/*line: 100*/   VDISCARD = 0xf, /* IEXTEN */ // 15
/*line: 102*/   VMIN = 0x10, /* !ICANON */ // 16
/*line: 103*/   VTIME = 0x11, /* !ICANON */ // 17
/*line: 105*/   VSTATUS = 0x12, /* ICANON together with IEXTEN */ // 18
/*line: 108*/   NCCS = 0x14,  // 20
};

enum macro_termios_input_flags {
/*
 * Input flags - software input processing
 */
/*line: 119*/   IGNBRK = 0x1, /* ignore BREAK condition */ // 0x00000001
/*line: 120*/   BRKINT = 0x2, /* map BREAK to SIGINTR */ // 0x00000002
/*line: 121*/   IGNPAR = 0x4, /* ignore (discard) parity errors */ // 0x00000004
/*line: 122*/   PARMRK = 0x8, /* mark parity and framing errors */ // 0x00000008
/*line: 123*/   INPCK = 0x10, /* enable checking of parity errors */ // 0x00000010
/*line: 124*/   ISTRIP = 0x20, /* strip 8th bit off chars */ // 0x00000020
/*line: 125*/   INLCR = 0x40, /* map NL into CR */ // 0x00000040
/*line: 126*/   IGNCR = 0x80, /* ignore CR */ // 0x00000080
/*line: 127*/   ICRNL = 0x100, /* map CR to NL (ala CRMOD) */ // 0x00000100
/*line: 128*/   IXON = 0x200, /* enable output flow control */ // 0x00000200
/*line: 129*/   IXOFF = 0x400, /* enable input flow control */ // 0x00000400
/*line: 130*/   IXANY = 0x800, /* any char will restart after stop */ // 0x00000800
/*line: 132*/   IMAXBEL = 0x2000, /* ring bell on input queue full */ // 0x00002000
/*line: 133*/   IUTF8 = 0x4000, /* maintain state for UTF-8 VERASE */ // 0x00004000
};

enum macro_termios_output_flags {
/*
 * Output flags - software output processing
 */
/*line: 139*/   OPOST = 0x1, /* enable following output processing */ // 0x00000001
/*line: 140*/   ONLCR = 0x2, /* map NL to CR-NL (ala CRMOD) */ // 0x00000002
/*line: 142*/   OXTABS = 0x4, /* expand tabs to spaces */ // 0x00000004
/*line: 143*/   ONOEOT = 0x8, /* discard EOT's (^D) on output) */ // 0x00000008
/*
 * The following block of features is unimplemented.  Use of these flags in
 * programs will currently result in unexpected behaviour.
 *
 * - Begin unimplemented features
 */
/*line: 151*/   OCRNL = 0x10, /* map CR to NL on output */ // 0x00000010
/*line: 152*/   ONOCR = 0x20, /* no CR output at column 0 */ // 0x00000020
/*line: 153*/   ONLRET = 0x40, /* NL performs CR function */ // 0x00000040
/*line: 154*/   OFILL = 0x80, /* use fill characters for delay */ // 0x00000080
/*line: 155*/   NLDLY = 0x300, /* \n delay */ // 0x00000300
/*line: 156*/   TABDLY = 0xc04, /* horizontal tab delay */ // 0x00000c04
/*line: 157*/   CRDLY = 0x3000, /* \r delay */ // 0x00003000
/*line: 158*/   FFDLY = 0x4000, /* form feed delay */ // 0x00004000
/*line: 159*/   BSDLY = 0x8000, /* \b delay */ // 0x00008000
/*line: 160*/   VTDLY = 0x10000, /* vertical tab delay */ // 0x00010000
/*line: 161*/   OFDEL = 0x20000, /* fill is DEL, else NUL */ // 0x00020000
/*
 * These manifest constants have the same names as those in the header
 * <sys/ioctl_compat.h>, so you are not permitted to have both definitions
 * in scope simultaneously in the same compilation unit.  Nevertheless,
 * they are required to be in scope when _POSIX_C_SOURCE is requested;
 * this means that including the <sys/ioctl_compat.h> header before this
 * one when _POSIX_C_SOURCE is in scope will result in redefintions.  We
 * attempt to maintain these as the same values so as to avoid this being
 * an outright error in most compilers.
 */
/*line: 173*/   NL0 = 0x0,  // 0x00000000
/*line: 174*/   NL1 = 0x100,  // 0x00000100
/*line: 176*/   NL2 = 0x200,  // 0x00000200
/*line: 177*/   NL3 = 0x300,  // 0x00000300
/*line: 179*/   TAB0 = 0x0,  // 0x00000000
/*line: 180*/   TAB1 = 0x400,  // 0x00000400
/*line: 181*/   TAB2 = 0x800,  // 0x00000800
/* not in sys/ioctl_compat.h, use OXTABS value */
/*line: 183*/   TAB3 = 0x4,  // 0x00000004
/*line: 184*/   CR0 = 0x0,  // 0x00000000
/*line: 185*/   CR1 = 0x1000,  // 0x00001000
/*line: 186*/   CR2 = 0x2000,  // 0x00002000
/*line: 187*/   CR3 = 0x3000,  // 0x00003000
/*line: 188*/   FF0 = 0x0,  // 0x00000000
/*line: 189*/   FF1 = 0x4000,  // 0x00004000
/*line: 190*/   BS0 = 0x0,  // 0x00000000
/*line: 191*/   BS1 = 0x8000,  // 0x00008000
/*line: 192*/   VT0 = 0x0,  // 0x00000000
/*line: 193*/   VT1 = 0x10000,  // 0x00010000
};

// Depends on identifiers
enum macro_termios_control_flags {
/*line: 203*/   CIGNORE = 0x1, /* ignore control flags */ // 0x00000001
/*line: 205*/   CSIZE = 0x300, /* character size mask */ // 0x00000300
/*line: 206*/   CS5 = 0x0, /* 5 bits (pseudo) */ // 0x00000000
/*line: 207*/   CS6 = 0x100, /* 6 bits */ // 0x00000100
/*line: 208*/   CS7 = 0x200, /* 7 bits */ // 0x00000200
/*line: 209*/   CS8 = 0x300, /* 8 bits */ // 0x00000300
/*line: 210*/   CSTOPB = 0x400, /* send 2 stop bits */ // 0x00000400
/*line: 211*/   CREAD = 0x800, /* enable receiver */ // 0x00000800
/*line: 212*/   PARENB = 0x1000, /* parity enable */ // 0x00001000
/*line: 213*/   PARODD = 0x2000, /* odd parity, else even */ // 0x00002000
/*line: 214*/   HUPCL = 0x4000, /* hang up on last close */ // 0x00004000
/*line: 215*/   CLOCAL = 0x8000, /* ignore modem status lines */ // 0x00008000
/*line: 217*/   CCTS_OFLOW = 0x10000, /* CTS flow control of output */ // 0x00010000
/*line: 218*/   CRTSCTS = 0x30000,  // (CCTS_OFLOW|CRTS_IFLOW)
/*line: 219*/   CRTS_IFLOW = 0x20000, /* RTS flow control of input */ // 0x00020000
/*line: 220*/   CDTR_IFLOW = 0x40000, /* DTR flow control of input */ // 0x00040000
/*line: 221*/   CDSR_OFLOW = 0x80000, /* DSR flow control of output */ // 0x00080000
/*line: 222*/   CCAR_OFLOW = 0x100000, /* DCD flow control of output */ // 0x00100000
/*line: 223*/   MDMBUF = 0x100000, /* old name for CCAR_OFLOW */ // 0x00100000
};

enum macro_termios_local_flags {
/*line: 236*/   ECHOKE = 0x1, /* visual erase for line kill */ // 0x00000001
/*line: 238*/   ECHOE = 0x2, /* visually erase chars */ // 0x00000002
/*line: 239*/   ECHOK = 0x4, /* echo NL after line kill */ // 0x00000004
/*line: 240*/   ECHO = 0x8, /* enable echoing */ // 0x00000008
/*line: 241*/   ECHONL = 0x10, /* echo NL even if ECHO is off */ // 0x00000010
/*line: 243*/   ECHOPRT = 0x20, /* visual erase mode for hardcopy */ // 0x00000020
/*line: 244*/   ECHOCTL = 0x40, /* echo control chars as ^(Char) */ // 0x00000040
/*line: 246*/   ISIG = 0x80, /* enable signals INTR, QUIT, [D]SUSP */ // 0x00000080
/*line: 247*/   ICANON = 0x100, /* canonicalize input lines */ // 0x00000100
/*line: 249*/   ALTWERASE = 0x200, /* use alternate WERASE algorithm */ // 0x00000200
/*line: 251*/   IEXTEN = 0x400, /* enable DISCARD and LNEXT */ // 0x00000400
/*line: 253*/   EXTPROC = 0x800, /* external processing */ // 0x00000800
/*line: 255*/   TOSTOP = 0x400000, /* stop background jobs from output */ // 0x00400000
/*line: 257*/   FLUSHO = 0x800000, /* output being flushed (state) */ // 0x00800000
/*line: 258*/   NOKERNINFO = 0x2000000, /* no kernel output from VSTATUS */ // 0x02000000
/*line: 259*/   PENDIN = 0x20000000, /* XXX retype pending input (state) */ // 0x20000000
/*line: 261*/   NOFLSH = 0x80000000, /* don't flush after interrupt */ // 0x80000000
};

enum macro_tcsetattr_flags {
/*
 * Commands passed to tcsetattr() for setting the termios structure.
 */
/*line: 281*/   TCSANOW = 0x0, /* make change immediate */ // 0
/*line: 282*/   TCSADRAIN = 0x1, /* drain output, then change */ // 1
/*line: 283*/   TCSAFLUSH = 0x2, /* drain output, flush input */ // 2
/*line: 285*/   TCSASOFT = 0x10, /* flag - don't alter h.w. state */ // 0x10
};

enum macro_baud_rates {
/*
 * Standard speeds
 */
/*line: 291*/   B0 = 0x0,  // 0
/*line: 292*/   B50 = 0x32,  // 50
/*line: 293*/   B75 = 0x4b,  // 75
/*line: 294*/   B110 = 0x6e,  // 110
/*line: 295*/   B134 = 0x86,  // 134
/*line: 296*/   B150 = 0x96,  // 150
/*line: 297*/   B200 = 0xc8,  // 200
/*line: 298*/   B300 = 0x12c,  // 300
/*line: 299*/   B600 = 0x258,  // 600
/*line: 300*/   B1200 = 0x4b0,  // 1200
/*line: 301*/   B1800 = 0x708,  // 1800
/*line: 302*/   B2400 = 0x960,  // 2400
/*line: 303*/   B4800 = 0x12c0,  // 4800
/*line: 304*/   B9600 = 0x2580,  // 9600
/*line: 305*/   B19200 = 0x4b00,  // 19200
/*line: 306*/   B38400 = 0x9600,  // 38400
/*line: 308*/   B7200 = 0x1c20,  // 7200
/*line: 309*/   B14400 = 0x3840,  // 14400
/*line: 310*/   B28800 = 0x7080,  // 28800
/*line: 311*/   B57600 = 0xe100,  // 57600
/*line: 312*/   B76800 = 0x12c00,  // 76800
/*line: 313*/   B115200 = 0x1c200,  // 115200
/*line: 314*/   B230400 = 0x38400,  // 230400
/*line: 315*/   EXTA = 0x4b00,  // 19200
/*line: 316*/   EXTB = 0x9600,  // 38400
};

enum macro_terminal_io_control_actions {
/*line: 320*/   TCIFLUSH = 0x1,  // 1
/*line: 321*/   TCOFLUSH = 0x2,  // 2
/*line: 322*/   TCIOFLUSH = 0x3,  // 3
/*line: 323*/   TCOOFF = 0x1,  // 1
/*line: 324*/   TCOON = 0x2,  // 2
/*line: 325*/   TCIOFF = 0x3,  // 3
/*line: 326*/   TCION = 0x4,  // 4
};

