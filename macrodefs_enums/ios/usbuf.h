// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/usbuf.h

enum macro_usbuf_flags {
/*line: 91*/    USBUF_FIXEDLEN = 0x0, /* fixed length buffer (default) */ // 0x00000000
/*line: 92*/    USBUF_AUTOEXTEND = 0x1, /* automatically extend buffer */ // 0x00000001
/*line: 93*/    USBUF_INCLUDENUL = 0x2, /* nulterm byte is counted in len */ // 0x00000002
/*line: 94*/    USBUF_DRAINTOEOR = 0x4, /* use section 0 as drain EOR marker */ // 0x00000004
/*line: 95*/    USBUF_NOWAIT = 0x8, /* Extend with non-blocking malloc */ // 0x00000008
/*line: 96*/    USBUF_USRFLAGMSK = 0xffff, /* mask of flags the user may specify */ // 0x0000ffff
/*line: 97*/    USBUF_DYNAMIC = 0x10000, /* s_buf must be freed */ // 0x00010000
/*line: 98*/    USBUF_FINISHED = 0x20000, /* set by sbuf_finish() */ // 0x00020000
/*line: 99*/    USBUF_DYNSTRUCT = 0x80000, /* sbuf must be freed */ // 0x00080000
/*line: 100*/   USBUF_INSECTION = 0x100000, /* set by sbuf_start_section() */ // 0x00100000
/*line: 101*/   USBUF_DRAINATEOL = 0x200000, /* drained contents ended in \n */ // 0x00200000
};

enum macro_header_flags {
/*line: 121*/   HD_COLUMN_MASK = 0xff,  // 0xff
/*line: 122*/   HD_DELIM_MASK = 0xff00,  // 0xff00
/*line: 123*/   HD_OMIT_COUNT = 0x10000,  // (1<<16)
/*line: 124*/   HD_OMIT_HEX = 0x20000,  // (1<<17)
/*line: 125*/   HD_OMIT_CHARS = 0x40000,  // (1<<18)
};

// Depends on identifiers
enum macro_sbuf_flags {
/*line: 129*/   SBUF_FIXEDLEN = 0x0,  // USBUF_FIXEDLEN
/*line: 130*/   SBUF_AUTOEXTEND = 0x1,  // USBUF_AUTOEXTEND
/*line: 131*/   SBUF_INCLUDENUL = 0x2,  // USBUF_INCLUDENUL
/*line: 132*/   SBUF_DRAINTOEOR = 0x4,  // USBUF_DRAINTOEOR
/*line: 133*/   SBUF_NOWAIT = 0x8,  // USBUF_NOWAIT
/*line: 134*/   SBUF_USRFLAGMSK = 0xffff,  // USBUF_USRFLAGMSK
/*line: 135*/   SBUF_DYNAMIC = 0x10000,  // USBUF_DYNAMIC
/*line: 136*/   SBUF_FINISHED = 0x20000,  // USBUF_FINISHED
/*line: 137*/   SBUF_DYNSTRUCT = 0x80000,  // USBUF_DYNSTRUCT
/*line: 138*/   SBUF_INSECTION = 0x100000,  // USBUF_INSECTION
/*line: 139*/   SBUF_DRAINATEOL = 0x200000,  // USBUF_DRAINATEOL
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 43
// #define sbuf usbuf

// Line: 44
// #define sbuf_drain_func usbuf_drain_func

// Line: 45
// #define sbuf_new usbuf_new

// Line: 46
// #define sbuf_new_auto usbuf_new_auto

// Line: 47
// #define sbuf_get_flags usbuf_get_flags

// Line: 48
// #define sbuf_clear_flags usbuf_clear_flags

// Line: 49
// #define sbuf_set_flags usbuf_set_flags

// Line: 50
// #define sbuf_clear usbuf_clear

// Line: 51
// #define sbuf_setpos usbuf_setpos

// Line: 52
// #define sbuf_bcat usbuf_bcat

// Line: 53
// #define sbuf_bcpy usbuf_bcpy

// Line: 54
// #define sbuf_cat usbuf_cat

// Line: 55
// #define sbuf_cpy usbuf_cpy

// Line: 56
// #define sbuf_printf usbuf_printf

// Line: 57
// #define sbuf_vprintf usbuf_vprintf

// Line: 58
// #define sbuf_nl_terminate usbuf_nl_terminate

// Line: 59
// #define sbuf_putc usbuf_putc

// Line: 60
// #define sbuf_set_drain usbuf_set_drain

// Line: 61
// #define sbuf_drain usbuf_drain

// Line: 62
// #define sbuf_trim usbuf_trim

// Line: 63
// #define sbuf_error usbuf_error

// Line: 64
// #define sbuf_finish usbuf_finish

// Line: 65
// #define sbuf_data usbuf_data

// Line: 66
// #define sbuf_len usbuf_len

// Line: 67
// #define sbuf_done usbuf_done

// Line: 68
// #define sbuf_delete usbuf_delete

// Line: 69
// #define sbuf_start_section usbuf_start_section

// Line: 70
// #define sbuf_end_section usbuf_end_section

// Line: 71
// #define sbuf_hexdump usbuf_hexdump

// Line: 72
// #define sbuf_count_drain usbuf_count_drain

// Line: 73
// #define sbuf_printf_drain usbuf_printf_drain

// Line: 74
// #define sbuf_putbuf usbuf_putbuf

