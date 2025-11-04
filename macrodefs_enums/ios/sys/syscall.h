// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/syscall.h

enum macro_syscall_numbers {
/*line: 40*/    SYS_syscall = 0x0,  // 0
/*line: 41*/    SYS_exit = 0x1,  // 1
/*line: 42*/    SYS_fork = 0x2,  // 2
/*line: 43*/    SYS_read = 0x3,  // 3
/*line: 44*/    SYS_write = 0x4,  // 4
/*line: 45*/    SYS_open = 0x5,  // 5
/*line: 46*/    SYS_close = 0x6,  // 6
/*line: 47*/    SYS_wait4 = 0x7,  // 7
/* 8  old creat */
/*line: 49*/    SYS_link = 0x9,  // 9
/*line: 50*/    SYS_unlink = 0xa,  // 10
/* 11  old execv */
/*line: 52*/    SYS_chdir = 0xc,  // 12
/*line: 53*/    SYS_fchdir = 0xd,  // 13
/*line: 54*/    SYS_mknod = 0xe,  // 14
/*line: 55*/    SYS_chmod = 0xf,  // 15
/*line: 56*/    SYS_chown = 0x10,  // 16
/* 17  old break */
/*line: 58*/    SYS_getfsstat = 0x12,  // 18
/* 19  old lseek */
/*line: 60*/    SYS_getpid = 0x14,  // 20
/* 22  old umount */
/*line: 63*/    SYS_setuid = 0x17,  // 23
/*line: 64*/    SYS_getuid = 0x18,  // 24
/*line: 65*/    SYS_geteuid = 0x19,  // 25
/*line: 66*/    SYS_ptrace = 0x1a,  // 26
/*line: 67*/    SYS_recvmsg = 0x1b,  // 27
/*line: 68*/    SYS_sendmsg = 0x1c,  // 28
/*line: 69*/    SYS_recvfrom = 0x1d,  // 29
/*line: 70*/    SYS_accept = 0x1e,  // 30
/*line: 71*/    SYS_getpeername = 0x1f,  // 31
/*line: 72*/    SYS_getsockname = 0x20,  // 32
/*line: 73*/    SYS_access = 0x21,  // 33
/*line: 74*/    SYS_chflags = 0x22,  // 34
/*line: 75*/    SYS_fchflags = 0x23,  // 35
/*line: 76*/    SYS_sync = 0x24,  // 36
/*line: 77*/    SYS_kill = 0x25,  // 37
/*line: 78*/    SYS_crossarch_trap = 0x26,  // 38
/*line: 79*/    SYS_getppid = 0x27,  // 39
/* 40  old lstat */
/*line: 81*/    SYS_dup = 0x29,  // 41
/*line: 82*/    SYS_pipe = 0x2a,  // 42
/*line: 83*/    SYS_getegid = 0x2b,  // 43
/* 45  old ktrace */
/*line: 86*/    SYS_sigaction = 0x2e,  // 46
/*line: 87*/    SYS_getgid = 0x2f,  // 47
/*line: 88*/    SYS_sigprocmask = 0x30,  // 48
/*line: 89*/    SYS_getlogin = 0x31,  // 49
/*line: 90*/    SYS_setlogin = 0x32,  // 50
/*line: 91*/    SYS_acct = 0x33,  // 51
/*line: 92*/    SYS_sigpending = 0x34,  // 52
/*line: 93*/    SYS_sigaltstack = 0x35,  // 53
/*line: 94*/    SYS_ioctl = 0x36,  // 54
/*line: 95*/    SYS_reboot = 0x37,  // 55
/*line: 96*/    SYS_revoke = 0x38,  // 56
/*line: 97*/    SYS_symlink = 0x39,  // 57
/*line: 98*/    SYS_readlink = 0x3a,  // 58
/*line: 99*/    SYS_execve = 0x3b,  // 59
/*line: 100*/   SYS_umask = 0x3c,  // 60
/*line: 101*/   SYS_chroot = 0x3d,  // 61
/* 64  old getpagesize */
/*line: 105*/   SYS_msync = 0x41,  // 65
/*line: 106*/   SYS_vfork = 0x42,  // 66
/*line: 107*/   SYS_oslog_coproc_reg = 0x43,  // 67
/*line: 108*/   SYS_oslog_coproc = 0x44,  // 68
/* 72  old vadvise */
/*line: 113*/   SYS_munmap = 0x49,  // 73
/*line: 114*/   SYS_mprotect = 0x4a,  // 74
/*line: 115*/   SYS_madvise = 0x4b,  // 75
/* 77  old vlimit */
/*line: 118*/   SYS_mincore = 0x4e,  // 78
/*line: 119*/   SYS_getgroups = 0x4f,  // 79
/*line: 120*/   SYS_setgroups = 0x50,  // 80
/*line: 121*/   SYS_getpgrp = 0x51,  // 81
/*line: 122*/   SYS_setpgid = 0x52,  // 82
/*line: 123*/   SYS_setitimer = 0x53,  // 83
/* 84  old wait */
/*line: 125*/   SYS_swapon = 0x55,  // 85
/*line: 126*/   SYS_getitimer = 0x56,  // 86
/* 88  old sethostname */
/*line: 129*/   SYS_getdtablesize = 0x59,  // 89
/*line: 130*/   SYS_dup2 = 0x5a,  // 90
/* 91  old getdopt */
/*line: 132*/   SYS_fcntl = 0x5c,  // 92
/*line: 133*/   SYS_select = 0x5d,  // 93
/* 94  old setdopt */
/*line: 135*/   SYS_fsync = 0x5f,  // 95
/*line: 136*/   SYS_setpriority = 0x60,  // 96
/*line: 137*/   SYS_socket = 0x61,  // 97
/*line: 138*/   SYS_connect = 0x62,  // 98
/* 99  old accept */
/*line: 140*/   SYS_getpriority = 0x64,  // 100
/* 103  old sigreturn */
/*line: 144*/   SYS_bind = 0x68,  // 104
/*line: 145*/   SYS_setsockopt = 0x69,  // 105
/*line: 146*/   SYS_listen = 0x6a,  // 106
/* 110  old sigsetmask */
/*line: 151*/   SYS_sigsuspend = 0x6f,  // 111
/* 115  old vtrace */
/*line: 156*/   SYS_gettimeofday = 0x74,  // 116
/*line: 157*/   SYS_getrusage = 0x75,  // 117
/*line: 158*/   SYS_getsockopt = 0x76,  // 118
/* 119  old resuba */
/*line: 160*/   SYS_readv = 0x78,  // 120
/*line: 161*/   SYS_writev = 0x79,  // 121
/*line: 162*/   SYS_settimeofday = 0x7a,  // 122
/*line: 163*/   SYS_fchown = 0x7b,  // 123
/*line: 164*/   SYS_fchmod = 0x7c,  // 124
/* 125  old recvfrom */
/*line: 166*/   SYS_setreuid = 0x7e,  // 126
/*line: 167*/   SYS_setregid = 0x7f,  // 127
/*line: 168*/   SYS_rename = 0x80,  // 128
/* 130  old ftruncate */
/*line: 171*/   SYS_flock = 0x83,  // 131
/*line: 172*/   SYS_mkfifo = 0x84,  // 132
/*line: 173*/   SYS_sendto = 0x85,  // 133
/*line: 174*/   SYS_shutdown = 0x86,  // 134
/*line: 175*/   SYS_socketpair = 0x87,  // 135
/*line: 176*/   SYS_mkdir = 0x88,  // 136
/*line: 177*/   SYS_rmdir = 0x89,  // 137
/*line: 178*/   SYS_utimes = 0x8a,  // 138
/*line: 179*/   SYS_futimes = 0x8b,  // 139
/*line: 180*/   SYS_adjtime = 0x8c,  // 140
/* 141  old getpeername */
/*line: 182*/   SYS_gethostuuid = 0x8e,  // 142
/* 146  old killpg */
/*line: 187*/   SYS_setsid = 0x93,  // 147
/* 150  old getsockname */
/*line: 191*/   SYS_getpgid = 0x97,  // 151
/*line: 192*/   SYS_setprivexec = 0x98,  // 152
/*line: 193*/   SYS_pread = 0x99,  // 153
/*line: 194*/   SYS_pwrite = 0x9a,  // 154
/*line: 195*/   SYS_nfssvc = 0x9b,  // 155
/* 156  old getdirentries */
/*line: 197*/   SYS_statfs = 0x9d,  // 157
/*line: 198*/   SYS_fstatfs = 0x9e,  // 158
/*line: 199*/   SYS_unmount = 0x9f,  // 159
/* 160  old async_daemon */
/*line: 201*/   SYS_getfh = 0xa1,  // 161
/* 164  */
/*line: 205*/   SYS_quotactl = 0xa5,  // 165
/* 166  old exportfs */
/*line: 207*/   SYS_mount = 0xa7,  // 167
/* 168  old ustat */
/*line: 209*/   SYS_csops = 0xa9,  // 169
/*line: 210*/   SYS_csops_audittoken = 0xaa,  // 170
/* 172  old rpause */
/*line: 213*/   SYS_waitid = 0xad,  // 173
/* 176  old add_profil */
/*line: 217*/   SYS_kdebug_typefilter = 0xb1,  // 177
/*line: 218*/   SYS_kdebug_trace_string = 0xb2,  // 178
/*line: 219*/   SYS_kdebug_trace64 = 0xb3,  // 179
/*line: 220*/   SYS_kdebug_trace = 0xb4,  // 180
/*line: 221*/   SYS_setgid = 0xb5,  // 181
/*line: 222*/   SYS_setegid = 0xb6,  // 182
/*line: 223*/   SYS_seteuid = 0xb7,  // 183
/*line: 224*/   SYS_sigreturn = 0xb8,  // 184
/*line: 225*/   SYS_panic_with_data = 0xb9,  // 185
/*line: 226*/   SYS_thread_selfcounts = 0xba,  // 186
/*line: 227*/   SYS_fdatasync = 0xbb,  // 187
/*line: 228*/   SYS_stat = 0xbc,  // 188
/*line: 229*/   SYS_fstat = 0xbd,  // 189
/*line: 230*/   SYS_lstat = 0xbe,  // 190
/*line: 231*/   SYS_pathconf = 0xbf,  // 191
/*line: 232*/   SYS_fpathconf = 0xc0,  // 192
/* 193  old getfsstat */
/*line: 234*/   SYS_getrlimit = 0xc2,  // 194
/*line: 235*/   SYS_setrlimit = 0xc3,  // 195
/*line: 236*/   SYS_getdirentries = 0xc4,  // 196
/*line: 237*/   SYS_mmap = 0xc5,  // 197
/* 198  old __syscall */
/*line: 239*/   SYS_lseek = 0xc7,  // 199
/*line: 240*/   SYS_truncate = 0xc8,  // 200
/*line: 241*/   SYS_ftruncate = 0xc9,  // 201
/*line: 242*/   SYS_sysctl = 0xca,  // 202
/*line: 243*/   SYS_mlock = 0xcb,  // 203
/*line: 244*/   SYS_munlock = 0xcc,  // 204
/*line: 245*/   SYS_undelete = 0xcd,  // 205
/* 215  */
/*line: 256*/   SYS_open_dprotected_np = 0xd8,  // 216
/*line: 257*/   SYS_fsgetpath_ext = 0xd9,  // 217
/*line: 258*/   SYS_openat_dprotected_np = 0xda,  // 218
/* 219  old fstatv */
/*line: 260*/   SYS_getattrlist = 0xdc,  // 220
/*line: 261*/   SYS_setattrlist = 0xdd,  // 221
/*line: 262*/   SYS_getdirentriesattr = 0xde,  // 222
/*line: 263*/   SYS_exchangedata = 0xdf,  // 223
/* 224  old checkuseraccess or fsgetpath */
/*line: 265*/   SYS_searchfs = 0xe1,  // 225
/*line: 266*/   SYS_delete = 0xe2,  // 226
/*line: 267*/   SYS_copyfile = 0xe3,  // 227
/*line: 268*/   SYS_fgetattrlist = 0xe4,  // 228
/*line: 269*/   SYS_fsetattrlist = 0xe5,  // 229
/*line: 270*/   SYS_poll = 0xe6,  // 230
/* 233  old modwatch */
/*line: 274*/   SYS_getxattr = 0xea,  // 234
/*line: 275*/   SYS_fgetxattr = 0xeb,  // 235
/*line: 276*/   SYS_setxattr = 0xec,  // 236
/*line: 277*/   SYS_fsetxattr = 0xed,  // 237
/*line: 278*/   SYS_removexattr = 0xee,  // 238
/*line: 279*/   SYS_fremovexattr = 0xef,  // 239
/*line: 280*/   SYS_listxattr = 0xf0,  // 240
/*line: 281*/   SYS_flistxattr = 0xf1,  // 241
/*line: 282*/   SYS_fsctl = 0xf2,  // 242
/*line: 283*/   SYS_initgroups = 0xf3,  // 243
/*line: 284*/   SYS_posix_spawn = 0xf4,  // 244
/*line: 285*/   SYS_ffsctl = 0xf5,  // 245
/* 247  old nfsclnt */
/*line: 288*/   SYS_fhopen = 0xf8,  // 248
/* 249  */
/*line: 290*/   SYS_minherit = 0xfa,  // 250
/*line: 291*/   SYS_semsys = 0xfb,  // 251
/*line: 292*/   SYS_msgsys = 0xfc,  // 252
/*line: 293*/   SYS_shmsys = 0xfd,  // 253
/*line: 294*/   SYS_semctl = 0xfe,  // 254
/*line: 295*/   SYS_semget = 0xff,  // 255
/*line: 296*/   SYS_semop = 0x100,  // 256
/* 257  old semconfig */
/*line: 298*/   SYS_msgctl = 0x102,  // 258
/*line: 299*/   SYS_msgget = 0x103,  // 259
/*line: 300*/   SYS_msgsnd = 0x104,  // 260
/*line: 301*/   SYS_msgrcv = 0x105,  // 261
/*line: 302*/   SYS_shmat = 0x106,  // 262
/*line: 303*/   SYS_shmctl = 0x107,  // 263
/*line: 304*/   SYS_shmdt = 0x108,  // 264
/*line: 305*/   SYS_shmget = 0x109,  // 265
/*line: 306*/   SYS_shm_open = 0x10a,  // 266
/*line: 307*/   SYS_shm_unlink = 0x10b,  // 267
/*line: 308*/   SYS_sem_open = 0x10c,  // 268
/*line: 309*/   SYS_sem_close = 0x10d,  // 269
/*line: 310*/   SYS_sem_unlink = 0x10e,  // 270
/*line: 311*/   SYS_sem_wait = 0x10f,  // 271
/*line: 312*/   SYS_sem_trywait = 0x110,  // 272
/*line: 313*/   SYS_sem_post = 0x111,  // 273
/*line: 314*/   SYS_sysctlbyname = 0x112,  // 274
/* 276  old sem_destroy */
/*line: 317*/   SYS_open_extended = 0x115,  // 277
/*line: 318*/   SYS_umask_extended = 0x116,  // 278
/*line: 319*/   SYS_stat_extended = 0x117,  // 279
/*line: 320*/   SYS_lstat_extended = 0x118,  // 280
/*line: 321*/   SYS_fstat_extended = 0x119,  // 281
/*line: 322*/   SYS_chmod_extended = 0x11a,  // 282
/*line: 323*/   SYS_fchmod_extended = 0x11b,  // 283
/*line: 324*/   SYS_access_extended = 0x11c,  // 284
/*line: 325*/   SYS_settid = 0x11d,  // 285
/*line: 326*/   SYS_gettid = 0x11e,  // 286
/*line: 327*/   SYS_setsgroups = 0x11f,  // 287
/*line: 328*/   SYS_getsgroups = 0x120,  // 288
/*line: 329*/   SYS_setwgroups = 0x121,  // 289
/*line: 330*/   SYS_getwgroups = 0x122,  // 290
/*line: 331*/   SYS_mkfifo_extended = 0x123,  // 291
/*line: 332*/   SYS_mkdir_extended = 0x124,  // 292
/*line: 333*/   SYS_identitysvc = 0x125,  // 293
/*line: 334*/   SYS_shared_region_check_np = 0x126,  // 294
/* 295  old shared_region_map_np */
/*line: 336*/   SYS_vm_pressure_monitor = 0x128,  // 296
/*line: 337*/   SYS_psynch_rw_longrdlock = 0x129,  // 297
/*line: 338*/   SYS_psynch_rw_yieldwrlock = 0x12a,  // 298
/*line: 339*/   SYS_psynch_rw_downgrade = 0x12b,  // 299
/*line: 340*/   SYS_psynch_rw_upgrade = 0x12c,  // 300
/*line: 341*/   SYS_psynch_mutexwait = 0x12d,  // 301
/*line: 342*/   SYS_psynch_mutexdrop = 0x12e,  // 302
/*line: 343*/   SYS_psynch_cvbroad = 0x12f,  // 303
/*line: 344*/   SYS_psynch_cvsignal = 0x130,  // 304
/*line: 345*/   SYS_psynch_cvwait = 0x131,  // 305
/*line: 346*/   SYS_psynch_rw_rdlock = 0x132,  // 306
/*line: 347*/   SYS_psynch_rw_wrlock = 0x133,  // 307
/*line: 348*/   SYS_psynch_rw_unlock = 0x134,  // 308
/*line: 349*/   SYS_psynch_rw_unlock2 = 0x135,  // 309
/*line: 350*/   SYS_getsid = 0x136,  // 310
/*line: 351*/   SYS_settid_with_pid = 0x137,  // 311
/*line: 352*/   SYS_psynch_cvclrprepost = 0x138,  // 312
/*line: 353*/   SYS_aio_fsync = 0x139,  // 313
/*line: 354*/   SYS_aio_return = 0x13a,  // 314
/*line: 355*/   SYS_aio_suspend = 0x13b,  // 315
/*line: 356*/   SYS_aio_cancel = 0x13c,  // 316
/*line: 357*/   SYS_aio_error = 0x13d,  // 317
/*line: 358*/   SYS_aio_read = 0x13e,  // 318
/*line: 359*/   SYS_aio_write = 0x13f,  // 319
/*line: 360*/   SYS_lio_listio = 0x140,  // 320
/* 321  old __pthread_cond_wait */
/*line: 362*/   SYS_iopolicysys = 0x142,  // 322
/*line: 363*/   SYS_process_policy = 0x143,  // 323
/*line: 364*/   SYS_mlockall = 0x144,  // 324
/*line: 365*/   SYS_munlockall = 0x145,  // 325
/* 326  */
/*line: 367*/   SYS_issetugid = 0x147,  // 327
/*line: 368*/   SYS___pthread_kill = 0x148,  // 328
/*line: 369*/   SYS___pthread_sigmask = 0x149,  // 329
/*line: 370*/   SYS___sigwait = 0x14a,  // 330
/*line: 371*/   SYS___disable_threadsignal = 0x14b,  // 331
/*line: 372*/   SYS___pthread_markcancel = 0x14c,  // 332
/*line: 373*/   SYS___pthread_canceled = 0x14d,  // 333
/*line: 374*/   SYS___semwait_signal = 0x14e,  // 334
/* 335  old utrace */
/*line: 376*/   SYS_proc_info = 0x150,  // 336
/*line: 377*/   SYS_sendfile = 0x151,  // 337
/*line: 378*/   SYS_stat64 = 0x152,  // 338
/*line: 379*/   SYS_fstat64 = 0x153,  // 339
/*line: 380*/   SYS_lstat64 = 0x154,  // 340
/*line: 381*/   SYS_stat64_extended = 0x155,  // 341
/*line: 382*/   SYS_lstat64_extended = 0x156,  // 342
/*line: 383*/   SYS_fstat64_extended = 0x157,  // 343
/*line: 384*/   SYS_getdirentries64 = 0x158,  // 344
/*line: 385*/   SYS_statfs64 = 0x159,  // 345
/*line: 386*/   SYS_fstatfs64 = 0x15a,  // 346
/*line: 387*/   SYS_getfsstat64 = 0x15b,  // 347
/*line: 388*/   SYS___pthread_chdir = 0x15c,  // 348
/*line: 389*/   SYS___pthread_fchdir = 0x15d,  // 349
/*line: 390*/   SYS_audit = 0x15e,  // 350
/*line: 391*/   SYS_auditon = 0x15f,  // 351
/* 352  */
/*line: 393*/   SYS_getauid = 0x161,  // 353
/*line: 394*/   SYS_setauid = 0x162,  // 354
/* 356  old setaudit */
/*line: 397*/   SYS_getaudit_addr = 0x165,  // 357
/*line: 398*/   SYS_setaudit_addr = 0x166,  // 358
/*line: 399*/   SYS_auditctl = 0x167,  // 359
/*line: 400*/   SYS_bsdthread_create = 0x168,  // 360
/*line: 401*/   SYS_bsdthread_terminate = 0x169,  // 361
/*line: 402*/   SYS_kqueue = 0x16a,  // 362
/*line: 403*/   SYS_kevent = 0x16b,  // 363
/*line: 404*/   SYS_lchown = 0x16c,  // 364
/* 365  old stack_snapshot */
/*line: 406*/   SYS_bsdthread_register = 0x16e,  // 366
/*line: 407*/   SYS_workq_open = 0x16f,  // 367
/*line: 408*/   SYS_workq_kernreturn = 0x170,  // 368
/*line: 409*/   SYS_kevent64 = 0x171,  // 369
/* 371  old __semwait_signal */
/*line: 412*/   SYS_thread_selfid = 0x174,  // 372
/*line: 413*/   SYS_ledger = 0x175,  // 373
/*line: 414*/   SYS_kevent_qos = 0x176,  // 374
/*line: 415*/   SYS_kevent_id = 0x177,  // 375
/* 379  */
/*line: 420*/   SYS___mac_execve = 0x17c,  // 380
/*line: 421*/   SYS___mac_syscall = 0x17d,  // 381
/*line: 422*/   SYS___mac_get_file = 0x17e,  // 382
/*line: 423*/   SYS___mac_set_file = 0x17f,  // 383
/*line: 424*/   SYS___mac_get_link = 0x180,  // 384
/*line: 425*/   SYS___mac_set_link = 0x181,  // 385
/*line: 426*/   SYS___mac_get_proc = 0x182,  // 386
/*line: 427*/   SYS___mac_set_proc = 0x183,  // 387
/*line: 428*/   SYS___mac_get_fd = 0x184,  // 388
/*line: 429*/   SYS___mac_set_fd = 0x185,  // 389
/*line: 430*/   SYS___mac_get_pid = 0x186,  // 390
/* 393  */
/*line: 434*/   SYS_pselect = 0x18a,  // 394
/*line: 435*/   SYS_pselect_nocancel = 0x18b,  // 395
/*line: 436*/   SYS_read_nocancel = 0x18c,  // 396
/*line: 437*/   SYS_write_nocancel = 0x18d,  // 397
/*line: 438*/   SYS_open_nocancel = 0x18e,  // 398
/*line: 439*/   SYS_close_nocancel = 0x18f,  // 399
/*line: 440*/   SYS_wait4_nocancel = 0x190,  // 400
/*line: 441*/   SYS_recvmsg_nocancel = 0x191,  // 401
/*line: 442*/   SYS_sendmsg_nocancel = 0x192,  // 402
/*line: 443*/   SYS_recvfrom_nocancel = 0x193,  // 403
/*line: 444*/   SYS_accept_nocancel = 0x194,  // 404
/*line: 445*/   SYS_msync_nocancel = 0x195,  // 405
/*line: 446*/   SYS_fcntl_nocancel = 0x196,  // 406
/*line: 447*/   SYS_select_nocancel = 0x197,  // 407
/*line: 448*/   SYS_fsync_nocancel = 0x198,  // 408
/*line: 449*/   SYS_connect_nocancel = 0x199,  // 409
/*line: 450*/   SYS_sigsuspend_nocancel = 0x19a,  // 410
/*line: 451*/   SYS_readv_nocancel = 0x19b,  // 411
/*line: 452*/   SYS_writev_nocancel = 0x19c,  // 412
/*line: 453*/   SYS_sendto_nocancel = 0x19d,  // 413
/*line: 454*/   SYS_pread_nocancel = 0x19e,  // 414
/*line: 455*/   SYS_pwrite_nocancel = 0x19f,  // 415
/*line: 456*/   SYS_waitid_nocancel = 0x1a0,  // 416
/*line: 457*/   SYS_poll_nocancel = 0x1a1,  // 417
/*line: 458*/   SYS_msgsnd_nocancel = 0x1a2,  // 418
/*line: 459*/   SYS_msgrcv_nocancel = 0x1a3,  // 419
/*line: 460*/   SYS_sem_wait_nocancel = 0x1a4,  // 420
/*line: 461*/   SYS_aio_suspend_nocancel = 0x1a5,  // 421
/*line: 462*/   SYS___sigwait_nocancel = 0x1a6,  // 422
/*line: 463*/   SYS___semwait_signal_nocancel = 0x1a7,  // 423
/*line: 464*/   SYS___mac_mount = 0x1a8,  // 424
/*line: 465*/   SYS___mac_get_mount = 0x1a9,  // 425
/*line: 466*/   SYS___mac_getfsstat = 0x1aa,  // 426
/*line: 467*/   SYS_fsgetpath = 0x1ab,  // 427
/*line: 468*/   SYS_audit_session_self = 0x1ac,  // 428
/*line: 469*/   SYS_audit_session_join = 0x1ad,  // 429
/*line: 470*/   SYS_fileport_makeport = 0x1ae,  // 430
/*line: 471*/   SYS_fileport_makefd = 0x1af,  // 431
/*line: 472*/   SYS_audit_session_port = 0x1b0,  // 432
/*line: 473*/   SYS_pid_suspend = 0x1b1,  // 433
/*line: 474*/   SYS_pid_resume = 0x1b2,  // 434
/*line: 475*/   SYS_pid_hibernate = 0x1b3,  // 435
/*line: 476*/   SYS_pid_shutdown_sockets = 0x1b4,  // 436
/* 438  old shared_region_map_and_slide_np */
/*line: 479*/   SYS_kas_info = 0x1b7,  // 439
/*line: 480*/   SYS_memorystatus_control = 0x1b8,  // 440
/*line: 481*/   SYS_guarded_open_np = 0x1b9,  // 441
/*line: 482*/   SYS_guarded_close_np = 0x1ba,  // 442
/*line: 483*/   SYS_guarded_kqueue_np = 0x1bb,  // 443
/*line: 484*/   SYS_change_fdguard_np = 0x1bc,  // 444
/*line: 485*/   SYS_usrctl = 0x1bd,  // 445
/*line: 486*/   SYS_proc_rlimit_control = 0x1be,  // 446
/*line: 487*/   SYS_connectx = 0x1bf,  // 447
/*line: 488*/   SYS_disconnectx = 0x1c0,  // 448
/*line: 489*/   SYS_peeloff = 0x1c1,  // 449
/*line: 490*/   SYS_socket_delegate = 0x1c2,  // 450
/*line: 491*/   SYS_telemetry = 0x1c3,  // 451
/*line: 492*/   SYS_proc_uuid_policy = 0x1c4,  // 452
/*line: 493*/   SYS_memorystatus_get_level = 0x1c5,  // 453
/*line: 494*/   SYS_system_override = 0x1c6,  // 454
/*line: 495*/   SYS_vfs_purge = 0x1c7,  // 455
/*line: 496*/   SYS_sfi_ctl = 0x1c8,  // 456
/*line: 497*/   SYS_sfi_pidctl = 0x1c9,  // 457
/*line: 498*/   SYS_coalition = 0x1ca,  // 458
/*line: 499*/   SYS_coalition_info = 0x1cb,  // 459
/*line: 500*/   SYS_necp_match_policy = 0x1cc,  // 460
/*line: 501*/   SYS_getattrlistbulk = 0x1cd,  // 461
/*line: 502*/   SYS_clonefileat = 0x1ce,  // 462
/*line: 503*/   SYS_openat = 0x1cf,  // 463
/*line: 504*/   SYS_openat_nocancel = 0x1d0,  // 464
/*line: 505*/   SYS_renameat = 0x1d1,  // 465
/*line: 506*/   SYS_faccessat = 0x1d2,  // 466
/*line: 507*/   SYS_fchmodat = 0x1d3,  // 467
/*line: 508*/   SYS_fchownat = 0x1d4,  // 468
/*line: 509*/   SYS_fstatat = 0x1d5,  // 469
/*line: 510*/   SYS_fstatat64 = 0x1d6,  // 470
/*line: 511*/   SYS_linkat = 0x1d7,  // 471
/*line: 512*/   SYS_unlinkat = 0x1d8,  // 472
/*line: 513*/   SYS_readlinkat = 0x1d9,  // 473
/*line: 514*/   SYS_symlinkat = 0x1da,  // 474
/*line: 515*/   SYS_mkdirat = 0x1db,  // 475
/*line: 516*/   SYS_getattrlistat = 0x1dc,  // 476
/*line: 517*/   SYS_proc_trace_log = 0x1dd,  // 477
/*line: 518*/   SYS_bsdthread_ctl = 0x1de,  // 478
/*line: 519*/   SYS_openbyid_np = 0x1df,  // 479
/*line: 520*/   SYS_recvmsg_x = 0x1e0,  // 480
/*line: 521*/   SYS_sendmsg_x = 0x1e1,  // 481
/*line: 522*/   SYS_thread_selfusage = 0x1e2,  // 482
/*line: 523*/   SYS_csrctl = 0x1e3,  // 483
/*line: 524*/   SYS_guarded_open_dprotected_np = 0x1e4,  // 484
/*line: 525*/   SYS_guarded_write_np = 0x1e5,  // 485
/*line: 526*/   SYS_guarded_pwrite_np = 0x1e6,  // 486
/*line: 527*/   SYS_guarded_writev_np = 0x1e7,  // 487
/*line: 528*/   SYS_renameatx_np = 0x1e8,  // 488
/*line: 529*/   SYS_mremap_encrypted = 0x1e9,  // 489
/*line: 530*/   SYS_netagent_trigger = 0x1ea,  // 490
/*line: 531*/   SYS_stack_snapshot_with_config = 0x1eb,  // 491
/*line: 532*/   SYS_microstackshot = 0x1ec,  // 492
/*line: 533*/   SYS_grab_pgo_data = 0x1ed,  // 493
/*line: 534*/   SYS_persona = 0x1ee,  // 494
/* 495  */
/*line: 536*/   SYS_mach_eventlink_signal = 0x1f0,  // 496
/*line: 537*/   SYS_mach_eventlink_wait_until = 0x1f1,  // 497
/*line: 538*/   SYS_mach_eventlink_signal_wait_until = 0x1f2,  // 498
/*line: 539*/   SYS_work_interval_ctl = 0x1f3,  // 499
/*line: 540*/   SYS_getentropy = 0x1f4,  // 500
/*line: 541*/   SYS_necp_open = 0x1f5,  // 501
/*line: 542*/   SYS_necp_client_action = 0x1f6,  // 502
/*line: 543*/   SYS___nexus_open = 0x1f7,  // 503
/*line: 544*/   SYS___nexus_register = 0x1f8,  // 504
/*line: 545*/   SYS___nexus_deregister = 0x1f9,  // 505
/*line: 546*/   SYS___nexus_create = 0x1fa,  // 506
/*line: 547*/   SYS___nexus_destroy = 0x1fb,  // 507
/*line: 548*/   SYS___nexus_get_opt = 0x1fc,  // 508
/*line: 549*/   SYS___nexus_set_opt = 0x1fd,  // 509
/*line: 550*/   SYS___channel_open = 0x1fe,  // 510
/*line: 551*/   SYS___channel_get_info = 0x1ff,  // 511
/*line: 552*/   SYS___channel_sync = 0x200,  // 512
/*line: 553*/   SYS___channel_get_opt = 0x201,  // 513
/*line: 554*/   SYS___channel_set_opt = 0x202,  // 514
/*line: 555*/   SYS_ulock_wait = 0x203,  // 515
/*line: 556*/   SYS_ulock_wake = 0x204,  // 516
/*line: 557*/   SYS_fclonefileat = 0x205,  // 517
/*line: 558*/   SYS_fs_snapshot = 0x206,  // 518
/*line: 559*/   SYS_register_uexc_handler = 0x207,  // 519
/*line: 560*/   SYS_terminate_with_payload = 0x208,  // 520
/*line: 561*/   SYS_abort_with_payload = 0x209,  // 521
/*line: 562*/   SYS_necp_session_open = 0x20a,  // 522
/*line: 563*/   SYS_necp_session_action = 0x20b,  // 523
/*line: 564*/   SYS_setattrlistat = 0x20c,  // 524
/*line: 565*/   SYS_net_qos_guideline = 0x20d,  // 525
/*line: 566*/   SYS_fmount = 0x20e,  // 526
/*line: 567*/   SYS_ntp_adjtime = 0x20f,  // 527
/*line: 568*/   SYS_ntp_gettime = 0x210,  // 528
/*line: 569*/   SYS_os_fault_with_payload = 0x211,  // 529
/*line: 570*/   SYS_kqueue_workloop_ctl = 0x212,  // 530
/*line: 571*/   SYS___mach_bridge_remote_time = 0x213,  // 531
/*line: 572*/   SYS_coalition_ledger = 0x214,  // 532
/*line: 573*/   SYS_log_data = 0x215,  // 533
/*line: 574*/   SYS_memorystatus_available_memory = 0x216,  // 534
/*line: 575*/   SYS_objc_bp_assist_cfg_np = 0x217,  // 535
/*line: 576*/   SYS_shared_region_map_and_slide_2_np = 0x218,  // 536
/*line: 577*/   SYS_pivot_root = 0x219,  // 537
/*line: 578*/   SYS_task_inspect_for_pid = 0x21a,  // 538
/*line: 579*/   SYS_task_read_for_pid = 0x21b,  // 539
/*line: 580*/   SYS_preadv = 0x21c,  // 540
/*line: 581*/   SYS_pwritev = 0x21d,  // 541
/*line: 582*/   SYS_preadv_nocancel = 0x21e,  // 542
/*line: 583*/   SYS_pwritev_nocancel = 0x21f,  // 543
/*line: 584*/   SYS_ulock_wait2 = 0x220,  // 544
/*line: 585*/   SYS_proc_info_extended_id = 0x221,  // 545
/*line: 586*/   SYS_tracker_action = 0x222,  // 546
/*line: 587*/   SYS_debug_syscall_reject = 0x223,  // 547
/*line: 588*/   SYS_debug_syscall_reject_config = 0x224,  // 548
/*line: 589*/   SYS_graftdmg = 0x225,  // 549
/*line: 590*/   SYS_map_with_linking_np = 0x226,  // 550
/*line: 591*/   SYS_freadlink = 0x227,  // 551
/*line: 592*/   SYS_record_system_event = 0x228,  // 552
/*line: 593*/   SYS_mkfifoat = 0x229,  // 553
/*line: 594*/   SYS_mknodat = 0x22a,  // 554
/*line: 595*/   SYS_ungraftdmg = 0x22b,  // 555
/*line: 596*/   SYS_coalition_policy_set = 0x22c,  // 556
/*line: 597*/   SYS_coalition_policy_get = 0x22d,  // 557
/*line: 598*/   SYS_MAXSYSCALL = 0x22e,  // 558
/*line: 599*/   SYS_invalid = 0x3f,  // 63
};

