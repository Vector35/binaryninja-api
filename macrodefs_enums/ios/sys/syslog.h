// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/syslog.h

enum macro_syslog_priority {
/*
 * priorities/facilities are encoded into a single 32-bit quantity, where the
 * bottom 3 bits are the priority (0-7) and the top 28 bits are the facility
 * (0-big number).  Both the priorities and the facilities map roughly
 * one-to-one to strings in the syslogd(8) source code.  This mapping is
 * included in this file.
 *
 * priorities (these are ordered)
 */
/*line: 78*/    LOG_EMERG = 0x0, /* system is unusable */ // 0
/*line: 79*/    LOG_ALERT = 0x1, /* action must be taken immediately */ // 1
/*line: 80*/    LOG_CRIT = 0x2, /* critical conditions */ // 2
/*line: 81*/    LOG_ERR = 0x3, /* error conditions */ // 3
/*line: 82*/    LOG_WARNING = 0x4, /* warning conditions */ // 4
/*line: 83*/    LOG_NOTICE = 0x5, /* normal but significant condition */ // 5
/*line: 84*/    LOG_INFO = 0x6, /* informational */ // 6
/*line: 85*/    LOG_DEBUG = 0x7, /* debug-level messages */ // 7
};

enum macro_log_priority_mask {
/*line: 87*/    LOG_PRIMASK = 0x7, /* mask to extract priority part (internal) */ // 0x07
};

enum macro_log_facility {
/* facility codes */
/*line: 119*/   LOG_KERN = 0x0, /* kernel messages */ // (0<<3)
/*line: 120*/   LOG_USER = 0x8, /* random user-level messages */ // (1<<3)
/*line: 121*/   LOG_MAIL = 0x10, /* mail system */ // (2<<3)
/*line: 122*/   LOG_DAEMON = 0x18, /* system daemons */ // (3<<3)
/*line: 123*/   LOG_AUTH = 0x20, /* authorization messages */ // (4<<3)
/*line: 124*/   LOG_SYSLOG = 0x28, /* messages generated internally by syslogd */ // (5<<3)
/*line: 125*/   LOG_LPR = 0x30, /* line printer subsystem */ // (6<<3)
/*line: 126*/   LOG_NEWS = 0x38, /* network news subsystem */ // (7<<3)
/*line: 127*/   LOG_UUCP = 0x40, /* UUCP subsystem */ // (8<<3)
/*line: 128*/   LOG_CRON = 0x48, /* clock daemon */ // (9<<3)
/*line: 129*/   LOG_AUTHPRIV = 0x50, /* authorization messages (private) */ // (10<<3)
/* event logging.                          */
/*line: 133*/   LOG_FTP = 0x58, /* ftp daemon */ // (11<<3)
//#define	LOG_CONSOLE	(14<<3) /* /dev/console output */
/*line: 137*/   LOG_NETINFO = 0x60, /* NetInfo */ // (12<<3)
/*line: 138*/   LOG_REMOTEAUTH = 0x68, /* remote authentication/authorization */ // (13<<3)
/*line: 139*/   LOG_INSTALL = 0x70, /* installer subsystem */ // (14<<3)
/*line: 140*/   LOG_RAS = 0x78, /* Remote Access Service (VPN / PPP) */ // (15<<3)
};

enum macro_local_facility {
/* other codes through 15 reserved for system use */
/*line: 143*/   LOG_LOCAL0 = 0x80, /* reserved for local use */ // (16<<3)
/*line: 144*/   LOG_LOCAL1 = 0x88, /* reserved for local use */ // (17<<3)
/*line: 145*/   LOG_LOCAL2 = 0x90, /* reserved for local use */ // (18<<3)
/*line: 146*/   LOG_LOCAL3 = 0x98, /* reserved for local use */ // (19<<3)
/*line: 147*/   LOG_LOCAL4 = 0xa0, /* reserved for local use */ // (20<<3)
/*line: 148*/   LOG_LOCAL5 = 0xa8, /* reserved for local use */ // (21<<3)
/*line: 149*/   LOG_LOCAL6 = 0xb0, /* reserved for local use */ // (22<<3)
/*line: 150*/   LOG_LOCAL7 = 0xb8, /* reserved for local use */ // (23<<3)
};

enum macro_launchd_log_level {
/*line: 152*/   LOG_LAUNCHD = 0xc0, /* launchd - general bootstrap daemon */ // (24<<3)
};

enum macro_log_facilities {
/*line: 154*/   LOG_NFACILITIES = 0x19, /* current number of facilities */ // 25
/*line: 155*/   LOG_FACMASK = 0x3f8, /* mask to extract facility part */ // 0x03f8
};

enum macro_syslog_options {
/*
 * Option flags for openlog.
 *
 * LOG_ODELAY no longer does anything.
 * LOG_NDELAY is the inverse of what it used to be.
 */
/*line: 205*/   LOG_PID = 0x1, /* log the pid with each message */ // 0x01
/*line: 206*/   LOG_CONS = 0x2, /* log on the console if errors in sending */ // 0x02
/*line: 207*/   LOG_ODELAY = 0x4, /* delay open until first syslog() (default) */ // 0x04
/*line: 208*/   LOG_NDELAY = 0x8, /* don't delay open */ // 0x08
/*line: 209*/   LOG_NOWAIT = 0x10, /* don't wait for console forks: DEPRECATED */ // 0x10
/*line: 210*/   LOG_PERROR = 0x20, /* log to stderr as well */ // 0x20
};

