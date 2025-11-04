// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpcsvc/nlm_prot.h

// enum macro_rpcgen_version {
// /*line: 9*/     RPCGEN_VERSION = 0x30b52,  // 199506
// };

// Depends on identifiers
enum macro_nlm_limits {
/*line: 13*/    LM_MAXSTRLEN = 0x400,  // 1024
/*line: 14*/    MAXNAMELEN = 0x401,  // LM_MAXSTRLEN+1
};

// Depends on identifiers
enum macro_nlm_program {
/*line: 540*/   NLM_PROG = 0x186b5,  // ((rpc_uint)100021)
/*line: 541*/   NLM_SM = 0x0,  // ((rpc_uint)0)
};

// Depends on identifiers
enum macro_nlm_sm_notify {
/*line: 549*/   NLM_SM_NOTIFY = 0x1,  // ((rpc_uint)1)
};

// // Depends on identifiers
// enum macro_nlm_version {
// /*line: 558*/   NLM_VERS = 0x1,  // ((rpc_uint)1)
// };

// Depends on identifiers
enum macro_nlm_operations {
/*line: 608*/   NLM_TEST = 0x1,  // ((rpc_uint)1)
/*line: 611*/   NLM_LOCK = 0x2,  // ((rpc_uint)2)
/*line: 614*/   NLM_CANCEL = 0x3,  // ((rpc_uint)3)
/*line: 617*/   NLM_UNLOCK = 0x4,  // ((rpc_uint)4)
/*line: 620*/   NLM_GRANTED = 0x5,  // ((rpc_uint)5)
/*line: 623*/   NLM_TEST_MSG = 0x6,  // ((rpc_uint)6)
/*line: 626*/   NLM_LOCK_MSG = 0x7,  // ((rpc_uint)7)
/*line: 629*/   NLM_CANCEL_MSG = 0x8,  // ((rpc_uint)8)
/*line: 632*/   NLM_UNLOCK_MSG = 0x9,  // ((rpc_uint)9)
/*line: 635*/   NLM_GRANTED_MSG = 0xa,  // ((rpc_uint)10)
/*line: 638*/   NLM_TEST_RES = 0xb,  // ((rpc_uint)11)
/*line: 641*/   NLM_LOCK_RES = 0xc,  // ((rpc_uint)12)
/*line: 644*/   NLM_CANCEL_RES = 0xd,  // ((rpc_uint)13)
/*line: 647*/   NLM_UNLOCK_RES = 0xe,  // ((rpc_uint)14)
/*line: 650*/   NLM_GRANTED_RES = 0xf,  // ((rpc_uint)15)


/*line: 778*/   NLM_SHARE = 0x14,  // ((rpc_uint)20)
/*line: 781*/   NLM_UNSHARE = 0x15,  // ((rpc_uint)21)
/*line: 784*/   NLM_NM_LOCK = 0x16,  // ((rpc_uint)22)
/*line: 787*/   NLM_FREE_ALL = 0x17,  // ((rpc_uint)23)
};

// // Depends on identifiers
// enum macro_nlm_versx {
// /*line: 701*/   NLM_VERSX = 0x3,  // ((rpc_uint)3)
// };

// // Depends on identifiers
// enum macro_nlm_version {
// /*line: 835*/   NLM_VERS4 = 0x4,  // ((rpc_uint)4)
// };

// Depends on identifiers
enum macro_nlm4_operations {
/*line: 897*/   NLM4_TEST = 0x1,  // ((rpc_uint)1)
/*line: 900*/   NLM4_LOCK = 0x2,  // ((rpc_uint)2)
/*line: 903*/   NLM4_CANCEL = 0x3,  // ((rpc_uint)3)
/*line: 906*/   NLM4_UNLOCK = 0x4,  // ((rpc_uint)4)
/*line: 909*/   NLM4_GRANTED = 0x5,  // ((rpc_uint)5)
/*line: 912*/   NLM4_TEST_MSG = 0x6,  // ((rpc_uint)6)
/*line: 915*/   NLM4_LOCK_MSG = 0x7,  // ((rpc_uint)7)
/*line: 918*/   NLM4_CANCEL_MSG = 0x8,  // ((rpc_uint)8)
/*line: 921*/   NLM4_UNLOCK_MSG = 0x9,  // ((rpc_uint)9)
/*line: 924*/   NLM4_GRANTED_MSG = 0xa,  // ((rpc_uint)10)
/*line: 927*/   NLM4_TEST_RES = 0xb,  // ((rpc_uint)11)
/*line: 930*/   NLM4_LOCK_RES = 0xc,  // ((rpc_uint)12)
/*line: 933*/   NLM4_CANCEL_RES = 0xd,  // ((rpc_uint)13)
/*line: 936*/   NLM4_UNLOCK_RES = 0xe,  // ((rpc_uint)14)
/*line: 939*/   NLM4_GRANTED_RES = 0xf,  // ((rpc_uint)15)
/*line: 942*/   NLM4_SHARE = 0x14,  // ((rpc_uint)20)
/*line: 945*/   NLM4_UNSHARE = 0x15,  // ((rpc_uint)21)
/*line: 948*/   NLM4_NM_LOCK = 0x16,  // ((rpc_uint)22)
/*line: 951*/   NLM4_FREE_ALL = 0x17,  // ((rpc_uint)23)
};

