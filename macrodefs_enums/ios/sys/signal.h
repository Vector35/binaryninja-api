// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/signal.h

enum macro_signal_limits {
/*line: 76*/    __DARWIN_NSIG = 0x20, /* counting 0; could be 33 (mask is 1-32) */ // 32
/*line: 79*/    NSIG = 0x20,  // __DARWIN_NSIG
};

// Depends on identifiers
enum macro_signum {
/*line: 84*/    SIGHUP = 0x1, /* hangup */ // 1
/*line: 85*/    SIGINT = 0x2, /* interrupt */ // 2
/*line: 86*/    SIGQUIT = 0x3, /* quit */ // 3
/*line: 87*/    SIGILL = 0x4, /* illegal instruction (not reset when caught) */ // 4
/*line: 88*/    SIGTRAP = 0x5, /* trace trap (not reset when caught) */ // 5
/*line: 89*/    SIGABRT = 0x6, /* abort() */ // 6
/*line: 93*/    SIGIOT = 0x6, /* compatibility */ // SIGABRT
/*line: 94*/    SIGEMT = 0x7, /* EMT instruction */ // 7
/*line: 96*/    SIGFPE = 0x8, /* floating point exception */ // 8
/*line: 97*/    SIGKILL = 0x9, /* kill (cannot be caught or ignored) */ // 9
/*line: 98*/    SIGBUS = 0xa, /* bus error */ // 10
/*line: 99*/    SIGSEGV = 0xb, /* segmentation violation */ // 11
/*line: 100*/   SIGSYS = 0xc, /* bad argument to system call */ // 12
/*line: 101*/   SIGPIPE = 0xd, /* write on a pipe with no one to read it */ // 13
/*line: 102*/   SIGALRM = 0xe, /* alarm clock */ // 14
/*line: 103*/   SIGTERM = 0xf, /* software termination signal from kill */ // 15
/*line: 104*/   SIGURG = 0x10, /* urgent condition on IO channel */ // 16
/*line: 105*/   SIGSTOP = 0x11, /* sendable stop signal not from tty */ // 17
/*line: 106*/   SIGTSTP = 0x12, /* stop signal from tty */ // 18
/*line: 107*/   SIGCONT = 0x13, /* continue a stopped process */ // 19
/*line: 108*/   SIGCHLD = 0x14, /* to parent on child stop or exit */ // 20
/*line: 109*/   SIGTTIN = 0x15, /* to readers pgrp upon background tty read */ // 21
/*line: 110*/   SIGTTOU = 0x16, /* like TTIN for output if (tp->t_local&LTOSTOP) */ // 22
/*line: 112*/   SIGIO = 0x17, /* input/output possible signal */ // 23
/*line: 114*/   SIGXCPU = 0x18, /* exceeded CPU time limit */ // 24
/*line: 115*/   SIGXFSZ = 0x19, /* exceeded file size limit */ // 25
/*line: 116*/   SIGVTALRM = 0x1a, /* virtual time alarm */ // 26
/*line: 117*/   SIGPROF = 0x1b, /* profiling time alarm */ // 27
/*line: 119*/   SIGWINCH = 0x1c, /* window size changes */ // 28
/*line: 120*/   SIGINFO = 0x1d, /* information request */ // 29
/*line: 122*/   SIGUSR1 = 0x1e, /* user defined signal 1 */ // 30
/*line: 123*/   SIGUSR2 = 0x1f, /* user defined signal 2 */ // 31
};

enum macro_signal_actions {
/*
 * Language spec sez we must list exactly one parameter, even though we
 * actually supply three.  Ugh!
 * SIG_HOLD is chosen to avoid KERN_SIG_* values in <sys/signalvar.h>
 */
/*line: 131*/   SIG_DFL = 0x0,  // (void(*)(int))0
/*line: 132*/   SIG_IGN = 0x1,  // (void(*)(int))1
/*line: 133*/   SIG_HOLD = 0x5,  // (void(*)(int))5
/*line: 134*/   SIG_ERR = -0x1,  // ((void(*)(int))-1)
};

enum macro_sigev_notification {
/*line: 164*/   SIGEV_NONE = 0x0, /* No async notification */ // 0
/*line: 165*/   SIGEV_SIGNAL = 0x1, /* aio - completion notification */ // 1
/*line: 166*/   SIGEV_THREAD = 0x3, /* [NOTIMP] [RTS] call notification function */ // 3
};

enum macro_ill_errors {
/*line: 206*/   ILL_NOOP = 0x0, /* if only I knew... */ // 0
/*line: 208*/   ILL_ILLOPC = 0x1, /* [XSI] illegal opcode */ // 1
/*line: 209*/   ILL_ILLTRP = 0x2, /* [XSI] illegal trap */ // 2
/*line: 210*/   ILL_PRVOPC = 0x3, /* [XSI] privileged opcode */ // 3
/*line: 211*/   ILL_ILLOPN = 0x4, /* [XSI] illegal operand -NOTIMP */ // 4
/*line: 212*/   ILL_ILLADR = 0x5, /* [XSI] illegal addressing mode -NOTIMP */ // 5
/*line: 213*/   ILL_PRVREG = 0x6, /* [XSI] privileged register -NOTIMP */ // 6
/*line: 214*/   ILL_COPROC = 0x7, /* [XSI] coprocessor error -NOTIMP */ // 7
/*line: 215*/   ILL_BADSTK = 0x8, /* [XSI] internal stack error -NOTIMP */ // 8
};

enum macro_fpe_signals {
/*line: 219*/   FPE_NOOP = 0x0, /* if only I knew... */ // 0
/*line: 221*/   FPE_FLTDIV = 0x1, /* [XSI] floating point divide by zero */ // 1
/*line: 222*/   FPE_FLTOVF = 0x2, /* [XSI] floating point overflow */ // 2
/*line: 223*/   FPE_FLTUND = 0x3, /* [XSI] floating point underflow */ // 3
/*line: 224*/   FPE_FLTRES = 0x4, /* [XSI] floating point inexact result */ // 4
/*line: 225*/   FPE_FLTINV = 0x5, /* [XSI] invalid floating point operation */ // 5
/*line: 226*/   FPE_FLTSUB = 0x6, /* [XSI] subscript out of range -NOTIMP */ // 6
/*line: 227*/   FPE_INTDIV = 0x7, /* [XSI] integer divide by zero */ // 7
/*line: 228*/   FPE_INTOVF = 0x8, /* [XSI] integer overflow */ // 8
};

enum macro_segv_flags {
/*line: 232*/   SEGV_NOOP = 0x0, /* if only I knew... */ // 0
/*line: 234*/   SEGV_MAPERR = 0x1, /* [XSI] address not mapped to object */ // 1
/*line: 235*/   SEGV_ACCERR = 0x2, /* [XSI] invalid permission for mapped object */ // 2
};

enum macro_bus_errors {
/*line: 239*/   BUS_NOOP = 0x0, /* if only I knew... */ // 0
/*line: 241*/   BUS_ADRALN = 0x1, /* [XSI] Invalid address alignment */ // 1
/*line: 242*/   BUS_ADRERR = 0x2, /* [XSI] Nonexistent physical address -NOTIMP */ // 2
/*line: 243*/   BUS_OBJERR = 0x3, /* [XSI] Object-specific HW error - NOTIMP */ // 3
};

enum macro_trap_codes {
/* Codes for SIGTRAP */
/*line: 246*/   TRAP_BRKPT = 0x1, /* [XSI] Process breakpoint -NOTIMP */ // 1
/*line: 247*/   TRAP_TRACE = 0x2, /* [XSI] Process trace trap -NOTIMP */ // 2
};

enum macro_child_status {
/*line: 251*/   CLD_NOOP = 0x0, /* if only I knew... */ // 0
/*line: 253*/   CLD_EXITED = 0x1, /* [XSI] child has exited */ // 1
/*line: 254*/   CLD_KILLED = 0x2, /* [XSI] terminated abnormally, no core file */ // 2
/*line: 255*/   CLD_DUMPED = 0x3, /* [XSI] terminated abnormally, core file */ // 3
/*line: 256*/   CLD_TRAPPED = 0x4, /* [XSI] traced child has trapped */ // 4
/*line: 257*/   CLD_STOPPED = 0x5, /* [XSI] child has stopped */ // 5
/*line: 258*/   CLD_CONTINUED = 0x6, /* [XSI] stopped child has continued */ // 6
};

enum macro_poll_events {
/* Codes for SIGPOLL */
/*line: 261*/   POLL_IN = 0x1, /* [XSR] Data input available */ // 1
/*line: 262*/   POLL_OUT = 0x2, /* [XSR] Output buffers available */ // 2
/*line: 263*/   POLL_MSG = 0x3, /* [XSR] Input message available */ // 3
/*line: 264*/   POLL_ERR = 0x4, /* [XSR] I/O error */ // 4
/*line: 265*/   POLL_PRI = 0x5, /* [XSR] High priority input available */ // 5
/*line: 266*/   POLL_HUP = 0x6, /* [XSR] Device disconnected */ // 6
};

enum macro_sigaction_flags {
/*line: 298*/   SA_ONSTACK = 0x1, /* take signal on signal stack */ // 0x0001
/*line: 299*/   SA_RESTART = 0x2, /* restart system on signal return */ // 0x0002
/*line: 300*/   SA_RESETHAND = 0x4, /* reset to SIG_DFL when taking signal */ // 0x0004
/*line: 301*/   SA_NOCLDSTOP = 0x8, /* do not generate SIGCHLD on child stop */ // 0x0008
/*line: 302*/   SA_NODEFER = 0x10, /* don't mask the signal we're delivering */ // 0x0010
/*line: 303*/   SA_NOCLDWAIT = 0x20, /* don't keep zombies around */ // 0x0020
/*line: 304*/   SA_SIGINFO = 0x40, /* signal handler with SA_SIGINFO args */ // 0x0040
/*line: 306*/   SA_USERTRAMP = 0x100, /* do not bounce off kernel's sigtramp */ // 0x0100
/* This will provide 64bit register set in a 32bit user address space */
/*line: 308*/   SA_64REGSET = 0x200, /* signal handler with SA_SIGINFO args with 64bit regs information */ // 0x0200
/* the following are the only bits we support from user space, the
 * rest are for kernel use only.
 */
/*line: 314*/   SA_USERSPACE_MASK = 0x7f,  // (SA_ONSTACK|SA_RESTART|SA_RESETHAND|SA_NOCLDSTOP|SA_NODEFER|SA_NOCLDWAIT|SA_SIGINFO)
};

enum macro_sigprocmask_flags {
/*
 * Flags for sigprocmask:
 */
/*line: 319*/   SIG_BLOCK = 0x1, /* block specified signal set */ // 1
/*line: 320*/   SIG_UNBLOCK = 0x2, /* unblock specified signal set */ // 2
/*line: 321*/   SIG_SETMASK = 0x3, /* set specified signal set */ // 3
};

enum macro_siginfo_code {
/* POSIX 1003.1b required values. */
/*line: 324*/   SI_USER = 0x10001, /* [CX] signal from kill() */ // 0x10001
/*line: 325*/   SI_QUEUE = 0x10002, /* [CX] signal from sigqueue() */ // 0x10002
/*line: 326*/   SI_TIMER = 0x10003, /* [CX] timer expiration */ // 0x10003
/*line: 327*/   SI_ASYNCIO = 0x10004, /* [CX] aio request completion */ // 0x10004
/*line: 328*/   SI_MESGQ = 0x10005, /* [CX]	from message arrival on empty queue */ // 0x10005
};

enum macro_sigaltstack_flags {
/*
 * Structure used in sigaltstack call.
 */
/*line: 338*/   SS_ONSTACK = 0x1, /* take signal on signal stack */ // 0x0001
/*line: 339*/   SS_DISABLE = 0x4, /* disable taking signals on alternate stack */ // 0x0004
/*line: 340*/   MINSIGSTKSZ = 0x8000, /* (32K)minimum allowable stack */ // 32768
/*line: 341*/   SIGSTKSZ = 0x20000, /* (128K)recommended stack size */ // 131072
};

// Depends on identifiers
enum macro_sigvector_flags {
/*line: 354*/   SV_ONSTACK = 0x1,  // SA_ONSTACK
/*line: 355*/   SV_INTERRUPT = 0x2, /* same bit, opposite sense */ // SA_RESTART
/*line: 356*/   SV_RESETHAND = 0x4,  // SA_RESETHAND
/*line: 357*/   SV_NODEFER = 0x10,  // SA_NODEFER
/*line: 358*/   SV_NOCLDSTOP = 0x8,  // SA_NOCLDSTOP
/*line: 359*/   SV_SIGINFO = 0x40,  // SA_SIGINFO
};

// Depends on identifiers
enum macro_bad_sig {
/*line: 380*/   BADSIG = -0x1,  // SIG_ERR
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 295
// #define sa_handler __sigaction_u.__sa_handler

// Line: 296
// #define sa_sigaction __sigaction_u.__sa_sigaction

// Line: 361
// #define sv_onstack sv_flags

