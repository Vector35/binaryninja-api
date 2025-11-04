// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/poll.h

// Depends on identifiers
enum macro_poll_events {
/*
 * Requestable events.  If poll(2) finds any of these set, they are
 * copied to revents on return.
 */
/*line: 68*/    POLLIN = 0x1, /* any readable data available */ // 0x0001
/*line: 69*/    POLLPRI = 0x2, /* OOB/Urgent readable data */ // 0x0002
/*line: 70*/    POLLOUT = 0x4, /* file descriptor is writeable */ // 0x0004
/*line: 71*/    POLLRDNORM = 0x40, /* non-OOB/URG data available */ // 0x0040
/*line: 72*/    POLLWRNORM = 0x4, /* no write type differentiation */ // POLLOUT
/*line: 73*/    POLLRDBAND = 0x80, /* OOB/Urgent readable data */ // 0x0080
/*line: 74*/    POLLWRBAND = 0x100, /* OOB/Urgent data can be written */ // 0x0100
/*
 * FreeBSD extensions: polling on a regular file might return one
 * of these events (currently only supported on local filesystems).
 */
/*line: 80*/    POLLEXTEND = 0x200, /* file may have been extended */ // 0x0200
/*line: 81*/    POLLATTRIB = 0x400, /* file attributes may have changed */ // 0x0400
/*line: 82*/    POLLNLINK = 0x800, /* (un)link/rename may have happened */ // 0x0800
/*line: 83*/    POLLWRITE = 0x1000, /* file's contents may have changed */ // 0x1000
/*
 * These events are set if they occur regardless of whether they were
 * requested.
 */
/*line: 89*/    POLLERR = 0x8, /* some poll error occurred */ // 0x0008
/*line: 90*/    POLLHUP = 0x10, /* file descriptor was "hung up" */ // 0x0010
/*line: 91*/    POLLNVAL = 0x20, /* requested events "invalid" */ // 0x0020
/*line: 93*/    POLLSTANDARD = 0x1ff,  // (POLLIN|POLLPRI|POLLOUT|POLLRDNORM|POLLRDBAND|POLLWRBAND|POLLERR|POLLHUP|POLLNVAL)
};

