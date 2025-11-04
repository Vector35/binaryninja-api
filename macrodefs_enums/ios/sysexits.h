// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sysexits.h

enum macro_sysexits {
/*
 *  SYSEXITS.H -- Exit status codes for system programs.
 *
 *	This include file attempts to categorize possible error
 *	exit statuses for system programs, notably delivermail
 *	and the Berkeley network.
 *
 *	Error numbers begin at EX__BASE to reduce the possibility of
 *	clashing with other exit statuses that random programs may
 *	already return.  The meaning of the codes is approximately
 *	as follows:
 *
 *	EX_USAGE -- The command was used incorrectly, e.g., with
 *		the wrong number of arguments, a bad flag, a bad
 *		syntax in a parameter, or whatever.
 *	EX_DATAERR -- The input data was incorrect in some way.
 *		This should only be used for user's data & not
 *		system files.
 *	EX_NOINPUT -- An input file (not a system file) did not
 *		exist or was not readable.  This could also include
 *		errors like "No message" to a mailer (if it cared
 *		to catch it).
 *	EX_NOUSER -- The user specified did not exist.  This might
 *		be used for mail addresses or remote logins.
 *	EX_NOHOST -- The host specified did not exist.  This is used
 *		in mail addresses or network requests.
 *	EX_UNAVAILABLE -- A service is unavailable.  This can occur
 *		if a support program or file does not exist.  This
 *		can also be used as a catchall message when something
 *		you wanted to do doesn't work, but you don't know
 *		why.
 *	EX_SOFTWARE -- An internal software error has been detected.
 *		This should be limited to non-operating system related
 *		errors as possible.
 *	EX_OSERR -- An operating system error has been detected.
 *		This is intended to be used for such things as "cannot
 *		fork", "cannot create pipe", or the like.  It includes
 *		things like getuid returning a user that does not
 *		exist in the passwd file.
 *	EX_OSFILE -- Some system file (e.g., /etc/passwd, /etc/utmp,
 *		etc.) does not exist, cannot be opened, or has some
 *		sort of error (e.g., syntax error).
 *	EX_CANTCREAT -- A (user specified) output file cannot be
 *		created.
 *	EX_IOERR -- An error occurred while doing I/O on some file.
 *	EX_TEMPFAIL -- temporary failure, indicating something that
 *		is not really an error.  In sendmail, this means
 *		that a mailer (e.g.) could not create a connection,
 *		and the request should be reattempted later.
 *	EX_PROTOCOL -- the remote system returned something that
 *		was "not possible" during a protocol exchange.
 *	EX_NOPERM -- You did not have sufficient permission to
 *		perform the operation.  This is not intended for
 *		file system problems, which should use NOINPUT or
 *		CANTCREAT, but rather for higher level permissions.
 */
/*line: 96*/    EX_OK = 0x0, /* successful termination */ // 0
};

enum macro_ex_base {
/*line: 98*/    EX__BASE = 0x40, /* base value for error messages */ // 64
};

enum macro_exit_codes {
/*line: 100*/   EX_USAGE = 0x40, /* command line usage error */ // 64
/*line: 101*/   EX_DATAERR = 0x41, /* data format error */ // 65
/*line: 102*/   EX_NOINPUT = 0x42, /* cannot open input */ // 66
/*line: 103*/   EX_NOUSER = 0x43, /* addressee unknown */ // 67
/*line: 104*/   EX_NOHOST = 0x44, /* host name unknown */ // 68
/*line: 105*/   EX_UNAVAILABLE = 0x45, /* service unavailable */ // 69
/*line: 106*/   EX_SOFTWARE = 0x46, /* internal software error */ // 70
/*line: 107*/   EX_OSERR = 0x47, /* system error (e.g., can't fork) */ // 71
/*line: 108*/   EX_OSFILE = 0x48, /* critical OS file missing */ // 72
/*line: 109*/   EX_CANTCREAT = 0x49, /* can't create (user) output file */ // 73
/*line: 110*/   EX_IOERR = 0x4a, /* input/output error */ // 74
/*line: 111*/   EX_TEMPFAIL = 0x4b, /* temp failure; user is invited to retry */ // 75
/*line: 112*/   EX_PROTOCOL = 0x4c, /* remote error in protocol */ // 76
/*line: 113*/   EX_NOPERM = 0x4d, /* permission denied */ // 77
/*line: 114*/   EX_CONFIG = 0x4e, /* configuration error */ // 78
};

enum macro_ex_max {
/*line: 116*/   EX__MAX = 0x4e, /* maximum listed value */ // 78
};

