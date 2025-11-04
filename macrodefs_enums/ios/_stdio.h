// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/_stdio.h

enum macro_stdio_flags {
/*line: 172*/   __SLBF = 0x1, /* line buffered */ // 0x0001
/*line: 173*/   __SNBF = 0x2, /* unbuffered */ // 0x0002
/*line: 174*/   __SRD = 0x4, /* OK to read */ // 0x0004
/*line: 175*/   __SWR = 0x8, /* OK to write */ // 0x0008
/* RD and WR are never simultaneously asserted */
/*line: 177*/   __SRW = 0x10, /* open for reading & writing */ // 0x0010
/*line: 178*/   __SEOF = 0x20, /* found EOF */ // 0x0020
/*line: 179*/   __SERR = 0x40, /* found error */ // 0x0040
/*line: 180*/   __SMBF = 0x80, /* _buf is from malloc */ // 0x0080
/*line: 181*/   __SAPP = 0x100, /* fdopen()ed in append mode */ // 0x0100
/*line: 182*/   __SSTR = 0x200, /* this is an sprintf/snprintf string */ // 0x0200
/*line: 183*/   __SOPT = 0x400, /* do fseek() optimisation */ // 0x0400
/*line: 184*/   __SNPT = 0x800, /* do not do fseek() optimisation */ // 0x0800
/*line: 185*/   __SOFF = 0x1000, /* set iff _offset is in fact correct */ // 0x1000
/*line: 186*/   __SMOD = 0x2000, /* true => fgetln modified _p text */ // 0x2000
/*line: 187*/   __SALC = 0x4000, /* allocate string space dynamically */ // 0x4000
/*line: 188*/   __SIGN = 0x8000, /* ignore this file in _fwalk */ // 0x8000
};

enum macro_buffering_mode {
/*
 * The following three definitions are for ANSI C, which took them
 * from System V, which brilliantly took internal interface macros and
 * made them official arguments to setvbuf(), without renaming them.
 * Hence, these ugly _IOxxx names are *supposed* to appear in user code.
 *
 * Although numbered as their counterparts above, the implementation
 * does not rely on this.
 */
/*line: 199*/   _IOFBF = 0x0, /* setvbuf should set fully buffered */ // 0
/*line: 200*/   _IOLBF = 0x1, /* setvbuf should set line buffered */ // 1
/*line: 201*/   _IONBF = 0x2, /* setvbuf should set unbuffered */ // 2
};

enum macro_stdio_constants {
/*line: 203*/   BUFSIZ = 0x400, /* size of buffer used by setbuf */ // 1024
/*line: 204*/   EOF = -0x1,  // (-1)
};

enum macro_system_limits {
/* must be == _POSIX_STREAM_MAX <limits.h> */
/*line: 207*/   FOPEN_MAX = 0x14, /* must be <= OPEN_MAX <sys/syslimits.h> */ // 20
/*line: 208*/   FILENAME_MAX = 0x400, /* must be <= PATH_MAX <sys/syslimits.h> */ // 1024
/*line: 214*/   L_tmpnam = 0x400, /* XXX must be == PATH_MAX */ // 1024
/*line: 215*/   TMP_MAX = 0x1269ae40,  // 308915776
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 217
// #define stdin __stdinp

// Line: 218
// #define stdout __stdoutp

// Line: 219
// #define stderr __stderrp

