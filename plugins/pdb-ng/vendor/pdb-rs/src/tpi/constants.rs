// Copyright 2017 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(unused, non_upper_case_globals)]

// TODO: special types
//   https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/include/cvinfo.h#L328

// A list of known type kinds:
//   https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/include/cvinfo.h#L772

// leaf indices starting records but referenced from symbol records

pub const LF_MODIFIER_16t: u16 = 0x0001;
pub const LF_POINTER_16t: u16 = 0x0002;
pub const LF_ARRAY_16t: u16 = 0x0003;
pub const LF_CLASS_16t: u16 = 0x0004;
pub const LF_STRUCTURE_16t: u16 = 0x0005;
pub const LF_UNION_16t: u16 = 0x0006;
pub const LF_ENUM_16t: u16 = 0x0007;
pub const LF_PROCEDURE_16t: u16 = 0x0008;
pub const LF_MFUNCTION_16t: u16 = 0x0009;
pub const LF_VTSHAPE: u16 = 0x000a;
pub const LF_COBOL0_16t: u16 = 0x000b;
pub const LF_COBOL1: u16 = 0x000c;
pub const LF_BARRAY_16t: u16 = 0x000d;
pub const LF_LABEL: u16 = 0x000e;
pub const LF_NULL: u16 = 0x000f;
pub const LF_NOTTRAN: u16 = 0x0010;
pub const LF_DIMARRAY_16t: u16 = 0x0011;
pub const LF_VFTPATH_16t: u16 = 0x0012;
pub const LF_PRECOMP_16t: u16 = 0x0013; // not referenced from symbol
pub const LF_ENDPRECOMP: u16 = 0x0014; // not referenced from symbol
pub const LF_OEM_16t: u16 = 0x0015; // oem definable type string
pub const LF_TYPESERVER_ST: u16 = 0x0016; // not referenced from symbol

// leaf indices starting records but referenced only from type records

pub const LF_SKIP_16t: u16 = 0x0200;
pub const LF_ARGLIST_16t: u16 = 0x0201;
pub const LF_DEFARG_16t: u16 = 0x0202;
pub const LF_LIST: u16 = 0x0203;
pub const LF_FIELDLIST_16t: u16 = 0x0204;
pub const LF_DERIVED_16t: u16 = 0x0205;
pub const LF_BITFIELD_16t: u16 = 0x0206;
pub const LF_METHODLIST_16t: u16 = 0x0207;
pub const LF_DIMCONU_16t: u16 = 0x0208;
pub const LF_DIMCONLU_16t: u16 = 0x0209;
pub const LF_DIMVARU_16t: u16 = 0x020a;
pub const LF_DIMVARLU_16t: u16 = 0x020b;
pub const LF_REFSYM: u16 = 0x020c;

pub const LF_BCLASS_16t: u16 = 0x0400;
pub const LF_VBCLASS_16t: u16 = 0x0401;
pub const LF_IVBCLASS_16t: u16 = 0x0402;
pub const LF_ENUMERATE_ST: u16 = 0x0403;
pub const LF_FRIENDFCN_16t: u16 = 0x0404;
pub const LF_INDEX_16t: u16 = 0x0405;
pub const LF_MEMBER_16t: u16 = 0x0406;
pub const LF_STMEMBER_16t: u16 = 0x0407;
pub const LF_METHOD_16t: u16 = 0x0408;
pub const LF_NESTTYPE_16t: u16 = 0x0409;
pub const LF_VFUNCTAB_16t: u16 = 0x040a;
pub const LF_FRIENDCLS_16t: u16 = 0x040b;
pub const LF_ONEMETHOD_16t: u16 = 0x040c;
pub const LF_VFUNCOFF_16t: u16 = 0x040d;

// 32-bit type index versions of leaves  all have the 0x1000 bit set
//
pub const LF_TI16_MAX: u16 = 0x1000;

pub const LF_MODIFIER: u16 = 0x1001;
pub const LF_POINTER: u16 = 0x1002;
pub const LF_ARRAY_ST: u16 = 0x1003;
pub const LF_CLASS_ST: u16 = 0x1004;
pub const LF_STRUCTURE_ST: u16 = 0x1005;
pub const LF_UNION_ST: u16 = 0x1006;
pub const LF_ENUM_ST: u16 = 0x1007;
pub const LF_PROCEDURE: u16 = 0x1008;
pub const LF_MFUNCTION: u16 = 0x1009;
pub const LF_COBOL0: u16 = 0x100a;
pub const LF_BARRAY: u16 = 0x100b;
pub const LF_DIMARRAY_ST: u16 = 0x100c;
pub const LF_VFTPATH: u16 = 0x100d;
pub const LF_PRECOMP_ST: u16 = 0x100e; // not referenced from symbol
pub const LF_OEM: u16 = 0x100f; // oem definable type string
pub const LF_ALIAS_ST: u16 = 0x1010; // alias (typedef) type
pub const LF_OEM2: u16 = 0x1011; // oem definable type string

// leaf indices starting records but referenced only from type records

pub const LF_SKIP: u16 = 0x1200;
pub const LF_ARGLIST: u16 = 0x1201;
pub const LF_DEFARG_ST: u16 = 0x1202;
pub const LF_FIELDLIST: u16 = 0x1203;
pub const LF_DERIVED: u16 = 0x1204;
pub const LF_BITFIELD: u16 = 0x1205;
pub const LF_METHODLIST: u16 = 0x1206;
pub const LF_DIMCONU: u16 = 0x1207;
pub const LF_DIMCONLU: u16 = 0x1208;
pub const LF_DIMVARU: u16 = 0x1209;
pub const LF_DIMVARLU: u16 = 0x120a;

pub const LF_BCLASS: u16 = 0x1400;
pub const LF_VBCLASS: u16 = 0x1401;
pub const LF_IVBCLASS: u16 = 0x1402;
pub const LF_FRIENDFCN_ST: u16 = 0x1403;
pub const LF_INDEX: u16 = 0x1404;
pub const LF_MEMBER_ST: u16 = 0x1405;
pub const LF_STMEMBER_ST: u16 = 0x1406;
pub const LF_METHOD_ST: u16 = 0x1407;
pub const LF_NESTTYPE_ST: u16 = 0x1408;
pub const LF_VFUNCTAB: u16 = 0x1409;
pub const LF_FRIENDCLS: u16 = 0x140a;
pub const LF_ONEMETHOD_ST: u16 = 0x140b;
pub const LF_VFUNCOFF: u16 = 0x140c;
pub const LF_NESTTYPEEX_ST: u16 = 0x140d;
pub const LF_MEMBERMODIFY_ST: u16 = 0x140e;
pub const LF_MANAGED_ST: u16 = 0x140f;

// Types w/ SZ names

pub const LF_ST_MAX: u16 = 0x1500;

pub const LF_TYPESERVER: u16 = 0x1501; // not referenced from symbol
pub const LF_ENUMERATE: u16 = 0x1502;
pub const LF_ARRAY: u16 = 0x1503;
pub const LF_CLASS: u16 = 0x1504;
pub const LF_STRUCTURE: u16 = 0x1505;
pub const LF_UNION: u16 = 0x1506;
pub const LF_ENUM: u16 = 0x1507;
pub const LF_DIMARRAY: u16 = 0x1508;
pub const LF_PRECOMP: u16 = 0x1509; // not referenced from symbol
pub const LF_ALIAS: u16 = 0x150a; // alias (typedef) type
pub const LF_DEFARG: u16 = 0x150b;
pub const LF_FRIENDFCN: u16 = 0x150c;
pub const LF_MEMBER: u16 = 0x150d;
pub const LF_STMEMBER: u16 = 0x150e;
pub const LF_METHOD: u16 = 0x150f;
pub const LF_NESTTYPE: u16 = 0x1510;
pub const LF_ONEMETHOD: u16 = 0x1511;
pub const LF_NESTTYPEEX: u16 = 0x1512;
pub const LF_MEMBERMODIFY: u16 = 0x1513;
pub const LF_MANAGED: u16 = 0x1514;
pub const LF_TYPESERVER2: u16 = 0x1515;

pub const LF_STRIDED_ARRAY: u16 = 0x1516; // same as LF_ARRAY  but with stride between adjacent elements
pub const LF_HLSL: u16 = 0x1517;
pub const LF_MODIFIER_EX: u16 = 0x1518;
pub const LF_INTERFACE: u16 = 0x1519;
pub const LF_BINTERFACE: u16 = 0x151a;
pub const LF_VECTOR: u16 = 0x151b;
pub const LF_MATRIX: u16 = 0x151c;

pub const LF_VFTABLE: u16 = 0x151d; // a virtual function table
pub const LF_ENDOFLEAFRECORD: u16 = LF_VFTABLE;

pub const LF_TYPE_LAST: u16 = LF_ENDOFLEAFRECORD + 1; // one greater than the last type record
pub const LF_TYPE_MAX: u16 = LF_TYPE_LAST - 1;

pub const LF_FUNC_ID: u16 = 0x1601; // global func ID
pub const LF_MFUNC_ID: u16 = 0x1602; // member func ID
pub const LF_BUILDINFO: u16 = 0x1603; // build info: tool  version  command line  src/pdb file
pub const LF_SUBSTR_LIST: u16 = 0x1604; // similar to LF_ARGLIST  for list of sub strings
pub const LF_STRING_ID: u16 = 0x1605; // string ID

pub const LF_UDT_SRC_LINE: u16 = 0x1606; // source and line on where an UDT is defined
                                         // only generated by compiler

pub const LF_UDT_MOD_SRC_LINE: u16 = 0x1607; // module  source and line on where an UDT is defined
                                             // only generated by linker

pub const LF_CLASS2: u16 = 0x1608;
pub const LF_STRUCTURE2: u16 = 0x1609;
pub const LF_UNION2: u16 = 0x160a;
pub const LF_INTERFACE2: u16 = 0x160b;

pub const LF_ID_LAST: u16 = LF_UDT_MOD_SRC_LINE + 1; // one greater than the last ID record
pub const LF_ID_MAX: u16 = LF_ID_LAST - 1;

pub const LF_NUMERIC: u16 = 0x8000;
pub const LF_CHAR: u16 = 0x8000;
pub const LF_SHORT: u16 = 0x8001;
pub const LF_USHORT: u16 = 0x8002;
pub const LF_LONG: u16 = 0x8003;
pub const LF_ULONG: u16 = 0x8004;
pub const LF_REAL32: u16 = 0x8005;
pub const LF_REAL64: u16 = 0x8006;
pub const LF_REAL80: u16 = 0x8007;
pub const LF_REAL128: u16 = 0x8008;
pub const LF_QUADWORD: u16 = 0x8009;
pub const LF_UQUADWORD: u16 = 0x800a;
pub const LF_REAL48: u16 = 0x800b;
pub const LF_COMPLEX32: u16 = 0x800c;
pub const LF_COMPLEX64: u16 = 0x800d;
pub const LF_COMPLEX80: u16 = 0x800e;
pub const LF_COMPLEX128: u16 = 0x800f;
pub const LF_VARSTRING: u16 = 0x8010;

pub const LF_OCTWORD: u16 = 0x8017;
pub const LF_UOCTWORD: u16 = 0x8018;

pub const LF_DECIMAL: u16 = 0x8019;
pub const LF_DATE: u16 = 0x801a;
pub const LF_UTF8STRING: u16 = 0x801b;

pub const LF_REAL16: u16 = 0x801c;

pub const LF_PAD0: u16 = 0xf0;
pub const LF_PAD1: u16 = 0xf1;
pub const LF_PAD2: u16 = 0xf2;
pub const LF_PAD3: u16 = 0xf3;
pub const LF_PAD4: u16 = 0xf4;
pub const LF_PAD5: u16 = 0xf5;
pub const LF_PAD6: u16 = 0xf6;
pub const LF_PAD7: u16 = 0xf7;
pub const LF_PAD8: u16 = 0xf8;
pub const LF_PAD9: u16 = 0xf9;
pub const LF_PAD10: u16 = 0xfa;
pub const LF_PAD11: u16 = 0xfb;
pub const LF_PAD12: u16 = 0xfc;
pub const LF_PAD13: u16 = 0xfd;
pub const LF_PAD14: u16 = 0xfe;
pub const LF_PAD15: u16 = 0xff;
