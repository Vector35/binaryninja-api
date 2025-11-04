// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/aio.h

enum macro_aio_status {
/*
 * none of the requested operations could be canceled since they are
 * already complete.
 */
/*line: 84*/    AIO_ALLDONE = 0x1,  // 0x1
/* all requested operations have been canceled */
/*line: 87*/    AIO_CANCELED = 0x2,  // 0x2
};

enum macro_aio_notcanceled {
/*
 * some of the requested operations could not be canceled since
 * they are in progress
 */
/*line: 93*/    AIO_NOTCANCELED = 0x4,  // 0x4
};

enum macro_lio_operation {
/*
 * lio_listio operation options
 */
/*line: 100*/   LIO_NOP = 0x0, /* option indicating that no transfer is requested */ // 0x0
/*line: 101*/   LIO_READ = 0x1, /* option requesting a read */ // 0x1
/*line: 102*/   LIO_WRITE = 0x2, /* option requesting a write */ // 0x2
};

enum macro_lio_sync_operation {
/*
 * A lio_listio() synchronization operation indicating
 * that the calling thread is to continue execution while
 * the lio_listio() operation is being performed, and no
 * notification is given when the operation is complete
 */
/*line: 114*/   LIO_NOWAIT = 0x1,  // 0x1
/*
 * A lio_listio() synchronization operation indicating
 * that the calling thread is to suspend until the
 * lio_listio() operation is complete.
 */
/*line: 121*/   LIO_WAIT = 0x2,  // 0x2
};

enum macro_aio_listio_max {
/*
 * Maximum number of operations in single lio_listio call
 */
/*line: 126*/   AIO_LISTIO_MAX = 0x10,  // 16
};

