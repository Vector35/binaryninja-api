// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/dispatch/io.h

enum macro_io_type {
/*!
 * @typedef dispatch_io_type_t
 * The type of a dispatch I/O channel:
 *
 * @const DISPATCH_IO_STREAM	A dispatch I/O channel representing a stream of
 * bytes. Read and write operations on a channel of this type are performed
 * serially (in order of creation) and read/write data at the file pointer
 * position that is current at the time the operation starts executing.
 * Operations of different type (read vs. write) may be performed simultaneously.
 * Offsets passed to operations on a channel of this type are ignored.
 *
 * @const DISPATCH_IO_RANDOM	A dispatch I/O channel representing a random
 * access file. Read and write operations on a channel of this type may be
 * performed concurrently and read/write data at the specified offset. Offsets
 * are interpreted relative to the file pointer position current at the time the
 * I/O channel is created. Attempting to create a channel of this type for a
 * file descriptor that is not seekable will result in an error.
 */
/*line: 191*/   DISPATCH_IO_STREAM = 0x0,  // 0
/*line: 192*/   DISPATCH_IO_RANDOM = 0x1,  // 1
};

enum macro_io_stop {
/*!
 * @typedef dispatch_io_close_flags_t
 * The type of flags you can set on a dispatch_io_close() call
 *
 * @const DISPATCH_IO_STOP	Stop outstanding operations on a channel when
 *				the channel is closed.
 */
/*line: 438*/   DISPATCH_IO_STOP = 0x1,  // 0x1
};

enum macro_io_strict_interval {
/*!
 * @typedef dispatch_io_interval_flags_t
 * Type of flags to set on dispatch_io_set_interval()
 *
 * @const DISPATCH_IO_STRICT_INTERVAL	Enqueue I/O handlers at a channel's
 * interval setting even if the amount of data ready to be delivered is inferior
 * to the low water mark (or zero).
 */
/*line: 577*/   DISPATCH_IO_STRICT_INTERVAL = 0x1,  // 0x1
};

