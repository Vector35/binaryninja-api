// Copyright (c) 2026 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "apple_vendor.h"

#include <algorithm>

#include <string.h>

#include "lowlevelilinstruction.h"

#include "registers.h"

using namespace BinaryNinja;
using namespace std;

namespace {

enum AppleVendorOp
{
	AV_NONE,
	AV_GENTER,
	AV_GEXIT,
	AV_SDSB,
	AV_WKDMC,
	AV_WKDMD,
	AV_AT_AS1ELX,
	AV_MUL53LO,
	AV_MUL53HI,
	AV_AMX,
};

struct AppleVendorInsn
{
	AppleVendorOp op = AV_NONE;
	uint32_t imm = 0;  // genter selector, sdsb domain
	uint32_t rd = 0;   // destination register field, or the single operand of at
	uint32_t rs = 0;   // source register field
};

// Apple's system registers, in the S3_<op1>_c11_* and S3_<op1>_c15_* encodings that ARM leaves
// IMPLEMENTATION DEFINED.
//
// TODO: No source is recorded for these names, and some look specific to one SoC revision. Check
// each against documentation, starting with the AsahiLinux register notes, and remove any that
// can't be sourced.
const std::pair<uint32_t, std::string_view> VENDOR_SYSTEM_REGISTERS[] = {
    {0xC580, "ctrr_c_lwr_el1"},  // S3_0_c11_c0_0
    {0xC581, "ctrr_c_upr_el1"},  // S3_0_c11_c0_1
    {0xC582, "ctrr_d_lwr_el1"},  // S3_0_c11_c0_2
    {0xC583, "ctrr_d_upr_el1"},  // S3_0_c11_c0_3
    {0xC584, "ctrr_c_lwr_el12"},  // S3_0_c11_c0_4
    {0xC585, "ctrr_c_upr_el12"},  // S3_0_c11_c0_5
    {0xC586, "ctrr_d_lwr_el12"},  // S3_0_c11_c0_6
    {0xC587, "ctrr_d_upr_el12"},  // S3_0_c11_c0_7
    {0xC588, "ctrr_c_lwr_el2"},  // S3_0_c11_c1_0
    {0xC589, "ctrr_c_upr_el2"},  // S3_0_c11_c1_1
    {0xC58A, "ctrr_d_lwr_el2"},  // S3_0_c11_c1_2
    {0xC58B, "ctrr_d_upr_el2"},  // S3_0_c11_c1_3
    {0xC58C, "ctrr_c_ctl_el1"},  // S3_0_c11_c1_4
    {0xC58D, "ctrr_d_ctl_el1"},  // S3_0_c11_c1_5
    {0xC58E, "ctrr_c_ctl_el12"},  // S3_0_c11_c1_6
    {0xC58F, "ctrr_d_ctl_el12"},  // S3_0_c11_c1_7
    {0xC590, "ctrr_c_ctl_el2"},  // S3_0_c11_c2_0
    {0xC591, "ctrr_d_ctl_el2"},  // S3_0_c11_c2_1
    {0xC592, "ctxr_a_lwr_el1"},  // S3_0_c11_c2_2
    {0xC593, "ctxr_a_upr_el1"},  // S3_0_c11_c2_3
    {0xC594, "ctxr_b_lwr_el1"},  // S3_0_c11_c2_4
    {0xC595, "ctxr_b_upr_el1"},  // S3_0_c11_c2_5
    {0xC596, "ctxr_c_lwr_el1"},  // S3_0_c11_c2_6
    {0xC597, "ctxr_c_upr_el1"},  // S3_0_c11_c2_7
    {0xC598, "ctxr_d_lwr_el1"},  // S3_0_c11_c3_0
    {0xC599, "ctxr_d_upr_el1"},  // S3_0_c11_c3_1
    {0xC59A, "ctxr_a_lwr_el12"},  // S3_0_c11_c3_2
    {0xC59B, "ctxr_a_upr_el12"},  // S3_0_c11_c3_3
    {0xC59C, "ctxr_b_lwr_el12"},  // S3_0_c11_c3_4
    {0xC59D, "ctxr_b_upr_el12"},  // S3_0_c11_c3_5
    {0xC59E, "ctxr_c_lwr_el12"},  // S3_0_c11_c3_6
    {0xC59F, "ctxr_c_upr_el12"},  // S3_0_c11_c3_7
    {0xC5A0, "ctxr_d_lwr_el12"},  // S3_0_c11_c4_0
    {0xC5A1, "ctxr_d_upr_el12"},  // S3_0_c11_c4_1
    {0xC5A2, "ctxr_a_lwr_el2"},  // S3_0_c11_c4_2
    {0xC5A3, "ctxr_a_upr_el2"},  // S3_0_c11_c4_3
    {0xC5A4, "ctxr_b_lwr_el2"},  // S3_0_c11_c4_4
    {0xC5A5, "ctxr_b_upr_el2"},  // S3_0_c11_c4_5
    {0xC5A6, "ctxr_c_lwr_el2"},  // S3_0_c11_c4_6
    {0xC5A7, "ctxr_c_upr_el2"},  // S3_0_c11_c4_7
    {0xC5A8, "ctxr_d_lwr_el2"},  // S3_0_c11_c5_0
    {0xC5A9, "ctxr_d_upr_el2"},  // S3_0_c11_c5_1
    {0xC5AA, "ctxr_a_ctl_el1"},  // S3_0_c11_c5_2
    {0xC5AB, "ctxr_b_ctl_el1"},  // S3_0_c11_c5_3
    {0xC5AC, "ctxr_c_ctl_el1"},  // S3_0_c11_c5_4
    {0xC5AD, "ctxr_d_ctl_el1"},  // S3_0_c11_c5_5
    {0xC5AE, "ctxr_a_ctl_el12"},  // S3_0_c11_c5_6
    {0xC5AF, "ctxr_b_ctl_el12"},  // S3_0_c11_c5_7
    {0xC5B0, "ctxr_c_ctl_el12"},  // S3_0_c11_c6_0
    {0xC5B1, "ctxr_d_ctl_el12"},  // S3_0_c11_c6_1
    {0xC5B2, "ctxr_a_ctl_el2"},  // S3_0_c11_c6_2
    {0xC5B3, "ctxr_b_ctl_el2"},  // S3_0_c11_c6_3
    {0xC5B4, "ctxr_c_ctl_el2"},  // S3_0_c11_c6_4
    {0xC5B5, "ctxr_d_ctl_el2"},  // S3_0_c11_c6_5
    {0xC5B6, "acc_ctrr_c_lwr_el2"},  // S3_0_c11_c6_6
    {0xC5B7, "acc_ctrr_c_upr_el2"},  // S3_0_c11_c6_7
    {0xC5B8, "acc_ctrr_d_lwr_el2"},  // S3_0_c11_c7_0
    {0xC5B9, "acc_ctrr_d_upr_el2"},  // S3_0_c11_c7_1
    {0xC5BA, "acc_ctxr_a_lwr_el2"},  // S3_0_c11_c7_2
    {0xC5BB, "acc_ctxr_a_upr_el2"},  // S3_0_c11_c7_3
    {0xC5BC, "acc_ctxr_b_lwr_el2"},  // S3_0_c11_c7_4
    {0xC5BD, "acc_ctxr_b_upr_el2"},  // S3_0_c11_c7_5
    {0xC5BE, "acc_ctxr_c_lwr_el2"},  // S3_0_c11_c7_6
    {0xC5BF, "acc_ctxr_c_upr_el2"},  // S3_0_c11_c7_7
    {0xC5C0, "acc_ctxr_d_lwr_el2"},  // S3_0_c11_c8_0
    {0xC5C1, "acc_ctxr_d_upr_el2"},  // S3_0_c11_c8_1
    {0xC5C2, "acc_ctrr_c_ctl_el2"},  // S3_0_c11_c8_2
    {0xC5C3, "acc_ctrr_d_ctl_el2"},  // S3_0_c11_c8_3
    {0xC5C4, "acc_ctxr_a_ctl_el2"},  // S3_0_c11_c8_4
    {0xC5C5, "acc_ctxr_b_ctl_el2"},  // S3_0_c11_c8_5
    {0xC5C6, "acc_ctxr_c_ctl_el2"},  // S3_0_c11_c8_6
    {0xC5C7, "acc_ctxr_d_ctl_el2"},  // S3_0_c11_c8_7
    {0xC780, "hid0"},  // S3_0_c15_c0_0
    {0xC782, "hid25"},  // S3_0_c15_c0_2
    {0xC783, "hid26"},  // S3_0_c15_c0_3
    {0xC784, "hid27"},  // S3_0_c15_c0_4
    {0xC785, "hid28"},  // S3_0_c15_c0_5
    {0xC786, "hid29"},  // S3_0_c15_c0_6
    {0xC787, "hid34"},  // S3_0_c15_c0_7
    {0xC788, "hid1"},  // S3_0_c15_c1_0
    {0xC78B, "hid21"},  // S3_0_c15_c1_3
    {0xC78C, "biuvcscupcmdcrd"},  // S3_0_c15_c1_4
    {0xC78D, "biuvcscupdatcrd"},  // S3_0_c15_c1_5
    {0xC790, "hid2"},  // S3_0_c15_c2_0
    {0xC793, "hid30"},  // S3_0_c15_c2_3
    {0xC794, "hid31"},  // S3_0_c15_c2_4
    {0xC795, "hid32"},  // S3_0_c15_c2_5
    {0xC797, "hid33"},  // S3_0_c15_c2_7
    {0xC798, "hid3"},  // S3_0_c15_c3_0
    {0xC79A, "biuvcscupcmdcrdc2"},  // S3_0_c15_c3_2
    {0xC79B, "biuvcscupdatcrdc2"},  // S3_0_c15_c3_3
    {0xC7A0, "hid4"},  // S3_0_c15_c4_0
    {0xC7A8, "hid5"},  // S3_0_c15_c5_0
    {0xC7B0, "hid6"},  // S3_0_c15_c6_0
    {0xC7B8, "hid7"},  // S3_0_c15_c7_0
    {0xC7C0, "hid8"},  // S3_0_c15_c8_0
    {0xC7C8, "hid9"},  // S3_0_c15_c9_0
    {0xC7D0, "hid10"},  // S3_0_c15_c10_0
    {0xC7D2, "block_cmaint_cfg"},  // S3_0_c15_c10_2
    {0xC7D8, "hid11"},  // S3_0_c15_c11_0
    {0xC7DA, "hid18"},  // S3_0_c15_c11_2
    {0xC7DC, "hid36"},  // S3_0_c15_c11_4
    {0xC7DD, "hid37"},  // S3_0_c15_c11_5
    {0xC7E0, "hid12"},  // S3_0_c15_c12_0
    {0xC7E1, "hid15"},  // S3_0_c15_c12_1
    {0xC7E2, "hid19"},  // S3_0_c15_c12_2
    {0xC7E8, "biu_tlimit"},  // S3_0_c15_c13_0
    {0xC7F0, "hid13"},  // S3_0_c15_c14_0
    {0xC7F2, "hid_rctx_g0ctl"},  // S3_0_c15_c14_2
    {0xC7F3, "hid_rctx_g1ctl"},  // S3_0_c15_c14_3
    {0xC7F8, "hid14"},  // S3_0_c15_c15_0
    {0xC7FA, "hid16"},  // S3_0_c15_c15_2
    {0xC7FB, "llc_wrr2"},  // S3_0_c15_c15_3
    {0xC7FC, "biu_afi_cfg"},  // S3_0_c15_c15_4
    {0xC7FD, "hid17"},  // S3_0_c15_c15_5
    {0xC7FE, "hid24"},  // S3_0_c15_c15_6
    {0xC7FF, "hid35"},  // S3_0_c15_c15_7
    {0xCF80, "pmcr0_el1"},  // S3_1_c15_c0_0
    {0xCF81, "appl_contextptr"},  // S3_1_c15_c0_1
    {0xCF82, "ld_latprof_ctl_el1"},  // S3_1_c15_c0_2
    {0xCF83, "aon_cpu_mstall_ctl01_el1"},  // S3_1_c15_c0_3
    {0xCF84, "pm_memflt_ctl23_el1"},  // S3_1_c15_c0_4
    {0xCF85, "agtcntv_ctl_el0"},  // S3_1_c15_c0_5
    {0xCF86, "agtcntvctss_noredir_el0"},  // S3_1_c15_c0_6
    {0xCF88, "pmcr1_el1"},  // S3_1_c15_c1_0
    {0xCF8A, "ld_latprof_ctr_el1"},  // S3_1_c15_c1_2
    {0xCF8B, "aon_cpu_mstall_ctl23_el1"},  // S3_1_c15_c1_3
    {0xCF8C, "pm_memflt_ctl45_el1"},  // S3_1_c15_c1_4
    {0xCF8D, "agtcntrdir_el1"},  // S3_1_c15_c1_5
    {0xCF8E, "agtcntkctl_noredir_el1"},  // S3_1_c15_c1_6
    {0xCF90, "pmcr2_el1"},  // S3_1_c15_c2_0
    {0xCF92, "ld_latprof_sts_el1"},  // S3_1_c15_c2_2
    {0xCF93, "aon_cpu_mstall_ctl45_el1"},  // S3_1_c15_c2_3
    {0xCF94, "agtcnthp_cval_el2"},  // S3_1_c15_c2_4
    {0xCF95, "cntvct_noredir_el0"},  // S3_1_c15_c2_5
    {0xCF96, "agtcntp_cval_noredir_el0"},  // S3_1_c15_c2_6
    {0xCF98, "pmcr3_el1"},  // S3_1_c15_c3_0
    {0xCF9A, "ld_latprof_inf_el1"},  // S3_1_c15_c3_2
    {0xCF9B, "aon_cpu_mstall_ctl67_el1"},  // S3_1_c15_c3_3
    {0xCF9C, "agtcnthp_tval_el2"},  // S3_1_c15_c3_4
    {0xCF9D, "cntpctss_noredir_el0"},  // S3_1_c15_c3_5
    {0xCF9E, "agtcntp_tval_noredir_el0"},  // S3_1_c15_c3_6
    {0xCFA0, "pmcr4_el1"},  // S3_1_c15_c4_0
    {0xCFA2, "ld_latprof_ctl_el2"},  // S3_1_c15_c4_2
    {0xCFA3, "aon_cpu_memflt_ctl01_el1"},  // S3_1_c15_c4_3
    {0xCFA4, "agtcnthp_ctl_el2"},  // S3_1_c15_c4_4
    {0xCFA5, "cntvctss_noredir_el0"},  // S3_1_c15_c4_5
    {0xCFA6, "agtcntp_ctl_noredir_el0"},  // S3_1_c15_c4_6
    {0xCFA8, "pmesr0_el1"},  // S3_1_c15_c5_0
    {0xCFAA, "ld_latprof_cmd_el1"},  // S3_1_c15_c5_2
    {0xCFAB, "aon_cpu_memflt_ctl23_el1"},  // S3_1_c15_c5_3
    {0xCFAC, "agtcnthv_cval_el2"},  // S3_1_c15_c5_4
    {0xCFAE, "agtcntv_cval_noredir_el0"},  // S3_1_c15_c5_6
    {0xCFB0, "pmesr1_el1"},  // S3_1_c15_c6_0
    {0xCFB2, "pmcr1_el2"},  // S3_1_c15_c6_2
    {0xCFB3, "aon_cpu_memflt_ctl45_el1"},  // S3_1_c15_c6_3
    {0xCFB4, "agtcnthv_tval_el2"},  // S3_1_c15_c6_4
    {0xCFB5, "cntkctl_noredir_el1"},  // S3_1_c15_c6_5
    {0xCFB6, "agtcntv_tval_noredir_el0"},  // S3_1_c15_c6_6
    {0xCFB8, "opmat0_el1"},  // S3_1_c15_c7_0
    {0xCFBA, "pmcr1_el12"},  // S3_1_c15_c7_2
    {0xCFBB, "aon_cpu_memflt_ctl67_el1"},  // S3_1_c15_c7_3
    {0xCFBC, "agtcnthv_ctl_el2"},  // S3_1_c15_c7_4
    {0xCFBD, "cntp_cval_noredir_el0"},  // S3_1_c15_c7_5
    {0xCFBE, "agtcntv_ctl_noredir_el0"},  // S3_1_c15_c7_6
    {0xCFC0, "opmat1_el1"},  // S3_1_c15_c8_0
    {0xCFC2, "pmcr1_gl12"},  // S3_1_c15_c8_2
    {0xCFC3, "aon_cpu_mstall_ctr0_el1"},  // S3_1_c15_c8_3
    {0xCFC4, "agtcntfrq_el0"},  // S3_1_c15_c8_4
    {0xCFC5, "cntp_tval_noredir_el0"},  // S3_1_c15_c8_5
    {0xCFC6, "cntpct_noredir_el0"},  // S3_1_c15_c8_6
    {0xCFC8, "opmsk0_el1"},  // S3_1_c15_c9_0
    {0xCFCA, "ld_latprof_ctl_el12"},  // S3_1_c15_c9_2
    {0xCFCB, "aon_cpu_mstall_ctr1_el1"},  // S3_1_c15_c9_3
    {0xCFCC, "agtcntvoff_el2"},  // S3_1_c15_c9_4
    {0xCFCD, "cntp_ctl_noredir_el0"},  // S3_1_c15_c9_5
    {0xCFCE, "cntv_ctl_noredir_el0"},  // S3_1_c15_c9_6
    {0xCFD0, "opmsk1_el1"},  // S3_1_c15_c10_0
    {0xCFD2, "ld_latprof_inf_el2"},  // S3_1_c15_c10_2
    {0xCFD3, "aon_cpu_mstall_ctr2_el1"},  // S3_1_c15_c10_3
    {0xCFD4, "agtcntp_cval_el0"},  // S3_1_c15_c10_4
    {0xCFD5, "cntv_cval_noredir_el0"},  // S3_1_c15_c10_5
    {0xCFD6, "agtcntpct_noredir_el0"},  // S3_1_c15_c10_6
    {0xCFDB, "aon_cpu_mstall_ctr3_el1"},  // S3_1_c15_c11_3
    {0xCFDC, "agtcntp_tval_el0"},  // S3_1_c15_c11_4
    {0xCFDD, "cntv_tval_noredir_el0"},  // S3_1_c15_c11_5
    {0xCFDE, "vmsa_hv_lock_el2"},  // S3_1_c15_c11_6
    {0xCFE0, "pmswctrl_el1"},  // S3_1_c15_c12_0
    {0xCFE1, "pmcr5_el0"},  // S3_1_c15_c12_1
    {0xCFE3, "aon_cpu_mstall_ctr4_el1"},  // S3_1_c15_c12_3
    {0xCFE4, "pmcompare0_el1"},  // S3_1_c15_c12_4
    {0xCFE5, "pmcompare1_el1"},  // S3_1_c15_c12_5
    {0xCFE6, "vmsa_nv_lock_el2"},  // S3_1_c15_c12_6
    {0xCFE8, "pmsr_el1"},  // S3_1_c15_c13_0
    {0xCFEB, "aon_cpu_mstall_ctr5_el1"},  // S3_1_c15_c13_3
    {0xCFEC, "agtcntp_ctl_el0"},  // S3_1_c15_c13_4
    {0xCFED, "pmcompare5_el1"},  // S3_1_c15_c13_5
    {0xCFEE, "pmcompare6_el1"},  // S3_1_c15_c13_6
    {0xCFEF, "pmcompare7_el1"},  // S3_1_c15_c13_7
    {0xCFF0, "pmcr_bvrng4_el1"},  // S3_1_c15_c14_0
    {0xCFF1, "pm_pmi_pc"},  // S3_1_c15_c14_1
    {0xCFF3, "aon_cpu_mstall_ctr6_el1"},  // S3_1_c15_c14_3
    {0xCFF4, "agtcntv_cval_el0"},  // S3_1_c15_c14_4
    {0xCFF5, "agtcntvct_noredir_el0"},  // S3_1_c15_c14_5
    {0xCFF8, "pmcr_bvrng5_el1"},  // S3_1_c15_c15_0
    {0xCFFB, "aon_cpu_mstall_ctr7_el1"},  // S3_1_c15_c15_3
    {0xCFFC, "agtcntv_tval_el0"},  // S3_1_c15_c15_4
    {0xCFFD, "agtcntpctss_noredir_el0"},  // S3_1_c15_c15_5
    {0xD780, "pmc0"},  // S3_2_c15_c0_0
    {0xD781, "upmcfilter0"},  // S3_2_c15_c0_1
    {0xD782, "upmcfilter1"},  // S3_2_c15_c0_2
    {0xD783, "upmcfilter2"},  // S3_2_c15_c0_3
    {0xD784, "upmcfilter3"},  // S3_2_c15_c0_4
    {0xD785, "upmcfilter4"},  // S3_2_c15_c0_5
    {0xD786, "upmcfilter5"},  // S3_2_c15_c0_6
    {0xD787, "upmcfilter6"},  // S3_2_c15_c0_7
    {0xD788, "pmc1"},  // S3_2_c15_c1_0
    {0xD789, "upmcfilter7"},  // S3_2_c15_c1_1
    {0xD790, "pmc2"},  // S3_2_c15_c2_0
    {0xD798, "pmc3"},  // S3_2_c15_c3_0
    {0xD7A0, "pmc4"},  // S3_2_c15_c4_0
    {0xD7A8, "pmc5"},  // S3_2_c15_c5_0
    {0xD7B0, "pmc6"},  // S3_2_c15_c6_0
    {0xD7B8, "pmc7"},  // S3_2_c15_c7_0
    {0xD7C8, "pmc8"},  // S3_2_c15_c9_0
    {0xD7D0, "pmc9"},  // S3_2_c15_c10_0
    {0xD7E0, "pmtrhld6_el1"},  // S3_2_c15_c12_0
    {0xD7E8, "pmtrhld4_el1"},  // S3_2_c15_c13_0
    {0xD7F0, "pmtrhld2_el1"},  // S3_2_c15_c14_0
    {0xD7F8, "pmmmap_el1"},  // S3_2_c15_c15_0
    {0xDF80, "lsu_err_sts"},  // S3_3_c15_c0_0
    {0xDF84, "aflatctl1_el1"},  // S3_3_c15_c0_4
    {0xDF85, "aflatvalbin0_el1"},  // S3_3_c15_c0_5
    {0xDF86, "aflatinflo_el1"},  // S3_3_c15_c0_6
    {0xDF88, "lsu_err_ctl"},  // S3_3_c15_c1_0
    {0xDF8C, "aflatctl2_el1"},  // S3_3_c15_c1_4
    {0xDF8D, "aflatvalbin1_el1"},  // S3_3_c15_c1_5
    {0xDF8E, "aflatinfhi_el1"},  // S3_3_c15_c1_6
    {0xDF94, "aflatctl3_el1"},  // S3_3_c15_c2_4
    {0xDF95, "aflatvalbin2_el1"},  // S3_3_c15_c2_5
    {0xDF9C, "aflatctl4_el1"},  // S3_3_c15_c3_4
    {0xDF9D, "aflatvalbin3_el1"},  // S3_3_c15_c3_5
    {0xDFA0, "llc_fill_ctl"},  // S3_3_c15_c4_0
    {0xDFA4, "aflatctl5_lo_el1"},  // S3_3_c15_c4_4
    {0xDFA5, "aflatvalbin4_el1"},  // S3_3_c15_c4_5
    {0xDFA6, "aflatctl5_hi_el1"},  // S3_3_c15_c4_6
    {0xDFA8, "llc_fill_dat"},  // S3_3_c15_c5_0
    {0xDFAD, "aflatvalbin5_el1"},  // S3_3_c15_c5_5
    {0xDFB5, "aflatvalbin6_el1"},  // S3_3_c15_c6_5
    {0xDFB8, "llc_ram_config"},  // S3_3_c15_c7_0
    {0xDFBD, "aflatvalbin7_el1"},  // S3_3_c15_c7_5
    {0xDFC0, "llc_err_sts"},  // S3_3_c15_c8_0
    {0xDFC1, "cmaint_bcast_list_0"},  // S3_3_c15_c8_1
    {0xDFC2, "cmaint_bcast_list_1"},  // S3_3_c15_c8_2
    {0xDFC3, "cmaint_bcast_ctl"},  // S3_3_c15_c8_3
    {0xDFC8, "llc_err_adr"},  // S3_3_c15_c9_0
    {0xDFC9, "llc_err_ctl"},  // S3_3_c15_c9_1
    {0xDFCA, "llc_err_inj"},  // S3_3_c15_c9_2
    {0xDFD0, "llc_err_inf"},  // S3_3_c15_c10_0
    {0xDFD1, "usertagsel_el1"},  // S3_3_c15_c10_1
    {0xDFD2, "uusertag_el0"},  // S3_3_c15_c10_2
    {0xDFD3, "kusertag_el1"},  // S3_3_c15_c10_3
    {0xDFD4, "husertag_el2"},  // S3_3_c15_c10_4
    {0xDFD8, "llc_trace_ctl0"},  // S3_3_c15_c11_0
    {0xDFE0, "llc_trace_ctl1"},  // S3_3_c15_c12_0
    {0xDFE8, "llc_up_req_vc"},  // S3_3_c15_c13_0
    {0xDFE9, "llc_up_req_vc_thresh"},  // S3_3_c15_c13_1
    {0xDFEA, "llc_up_req_vc_2"},  // S3_3_c15_c13_2
    {0xDFEB, "llc_up_req_vc_thresh_2"},  // S3_3_c15_c13_3
    {0xDFEC, "llc_dram_hash0"},  // S3_3_c15_c13_4
    {0xDFED, "llc_dram_hash1"},  // S3_3_c15_c13_5
    {0xDFEE, "llc_dram_hash2"},  // S3_3_c15_c13_6
    {0xDFEF, "llc_dram_hash3"},  // S3_3_c15_c13_7
    {0xDFF0, "llc_trace_ctl2"},  // S3_3_c15_c14_0
    {0xDFF1, "llc_dram_hash4"},  // S3_3_c15_c14_1
    {0xDFF2, "llc_up_req_vc_3"},  // S3_3_c15_c14_2
    {0xDFF3, "llc_up_req_vc_thresh_3"},  // S3_3_c15_c14_3
    {0xDFF4, "llc_up_req_vc_4"},  // S3_3_c15_c14_4
    {0xDFF5, "llc_up_req_vc_thresh_4"},  // S3_3_c15_c14_5
    {0xDFF8, "llc_hash0"},  // S3_3_c15_c15_0
    {0xDFF9, "llc_hash1"},  // S3_3_c15_c15_1
    {0xDFFA, "llc_hash2"},  // S3_3_c15_c15_2
    {0xDFFB, "llc_hash3"},  // S3_3_c15_c15_3
    {0xDFFC, "llc_wrr"},  // S3_3_c15_c15_4
    {0xDFFD, "llc_dram_hash5"},  // S3_3_c15_c15_5
    {0xDFFE, "llc_dram_hash6"},  // S3_3_c15_c15_6
    {0xE780, "fed_err_sts"},  // S3_4_c15_c0_0
    {0xE781, "fed_err_ctl"},  // S3_4_c15_c0_1
    {0xE784, "apctl_el1"},  // S3_4_c15_c0_4
    {0xE788, "kernkeylo_el1"},  // S3_4_c15_c1_0
    {0xE789, "kernkeyhi_el1"},  // S3_4_c15_c1_1
    {0xE78A, "vmsa_lock_el1"},  // S3_4_c15_c1_2
    {0xE78B, "amx_state_t_el1"},  // S3_4_c15_c1_3
    {0xE78C, "amx_config_el1"},  // S3_4_c15_c1_4
    {0xE78D, "vmsa_lock_el2"},  // S3_4_c15_c1_5
    {0xE78E, "ctrr_b_upr_el1"},  // S3_4_c15_c1_6
    {0xE78F, "ctrr_b_lwr_el1"},  // S3_4_c15_c1_7
    {0xE790, "sp_setup_gl1"},  // S3_4_c15_c2_0
    {0xE791, "sp_setup_gl2"},  // S3_4_c15_c2_1
    {0xE792, "ctrr_b_ctl_el1"},  // S3_4_c15_c2_2
    {0xE793, "ctrr_a_lwr_el1"},  // S3_4_c15_c2_3
    {0xE794, "ctrr_a_upr_el1"},  // S3_4_c15_c2_4
    {0xE795, "ctrr_a_ctl_el1"},  // S3_4_c15_c2_5
    {0xE796, "vmsa_lock_el12"},  // S3_4_c15_c2_6
    {0xE797, "agtcntv_ctl_el02"},  // S3_4_c15_c2_7
    {0xE798, "amx_state_el1"},  // S3_4_c15_c3_0
    {0xE79E, "amx_status_el1"},  // S3_4_c15_c3_6
    {0xE7A1, "agtcntp_cval_el02"},  // S3_4_c15_c4_1
    {0xE7A2, "redir_acntp_tval_el02"},  // S3_4_c15_c4_2
    {0xE7A3, "agtcntp_ctl_el02"},  // S3_4_c15_c4_3
    {0xE7A4, "agtcntv_cval_el02"},  // S3_4_c15_c4_4
    {0xE7A5, "agtcntv_tval_el02"},  // S3_4_c15_c4_5
    {0xE7A6, "amx_config_el12"},  // S3_4_c15_c4_6
    {0xE7A7, "amx_config_el2"},  // S3_4_c15_c4_7
    {0xE7A9, "sprr_huperm_el0"},  // S3_4_c15_c5_1
    {0xE7AA, "sprr_vuperm_el0"},  // S3_4_c15_c5_2
    {0xE7B2, "ctrr_a_ctl_el2"},  // S3_4_c15_c6_2
    {0xE7B3, "ctrr_b_ctl_el2"},  // S3_4_c15_c6_3
    {0xE7B4, "ctrr_a_lwr_el2"},  // S3_4_c15_c6_4
    {0xE7B5, "ctrr_a_upr_el2"},  // S3_4_c15_c6_5
    {0xE7B6, "ctrr_b_lwr_el2"},  // S3_4_c15_c6_6
    {0xE7B7, "ctrr_b_upr_el2"},  // S3_4_c15_c6_7
    {0xE7B8, "sprr_humprr_el2"},  // S3_4_c15_c7_0
    {0xE7B9, "sprr_huperm_sh01_el2"},  // S3_4_c15_c7_1
    {0xE7BA, "sprr_huperm_sh02_el2"},  // S3_4_c15_c7_2
    {0xE7BB, "sprr_huperm_sh03_el2"},  // S3_4_c15_c7_3
    {0xE7BC, "sprr_huperm_sh04_el2"},  // S3_4_c15_c7_4
    {0xE7BD, "sprr_huperm_sh05_el2"},  // S3_4_c15_c7_5
    {0xE7BE, "sprr_huperm_sh06_el2"},  // S3_4_c15_c7_6
    {0xE7BF, "sprr_huperm_sh07_el2"},  // S3_4_c15_c7_7
    {0xE7C0, "sprr_vumprr_el1"},  // S3_4_c15_c8_0
    {0xE7C1, "sprr_vuperm_sh01_el1"},  // S3_4_c15_c8_1
    {0xE7C2, "sprr_vuperm_sh02_el1"},  // S3_4_c15_c8_2
    {0xE7C3, "sprr_vuperm_sh03_el1"},  // S3_4_c15_c8_3
    {0xE7C4, "sprr_vuperm_sh04_el1"},  // S3_4_c15_c8_4
    {0xE7C5, "sprr_vuperm_sh05_el1"},  // S3_4_c15_c8_5
    {0xE7C6, "sprr_vuperm_sh06_el1"},  // S3_4_c15_c8_6
    {0xE7C7, "sprr_vuperm_sh07_el1"},  // S3_4_c15_c8_7
    {0xE7C8, "ctrr_a_lwr_el12"},  // S3_4_c15_c9_0
    {0xE7C9, "ctrr_a_upr_el12"},  // S3_4_c15_c9_1
    {0xE7CA, "ctrr_b_lwr_el12"},  // S3_4_c15_c9_2
    {0xE7CB, "ctrr_b_upr_el12"},  // S3_4_c15_c9_3
    {0xE7CC, "ctrr_a_ctl_el12"},  // S3_4_c15_c9_4
    {0xE7CD, "ctrr_b_ctl_el12"},  // S3_4_c15_c9_5
    {0xE7CE, "agtcntkctl_el1"},  // S3_4_c15_c9_6
    {0xE7CF, "agtcntkctl_el12"},  // S3_4_c15_c9_7
    {0xE7D0, "predakeylo_el1"},  // S3_4_c15_c10_0
    {0xE7D1, "predakeyhi_el1"},  // S3_4_c15_c10_1
    {0xE7D2, "predbkeylo_el1"},  // S3_4_c15_c10_2
    {0xE7D3, "predbkeyhi_el1"},  // S3_4_c15_c10_3
    {0xE7D4, "siq_cfg_el1"},  // S3_4_c15_c10_4
    {0xE7D5, "agtcntpctss_el0"},  // S3_4_c15_c10_5
    {0xE7D6, "agtcntvctss_el0"},  // S3_4_c15_c10_6
    {0xE7D7, "avncr_el2"},  // S3_4_c15_c10_7
    {0xE7D8, "acc_ctrr_a_lwr_el2"},  // S3_4_c15_c11_0
    {0xE7D9, "acc_ctrr_a_upr_el2"},  // S3_4_c15_c11_1
    {0xE7DA, "acc_ctrr_b_lwr_el2"},  // S3_4_c15_c11_2
    {0xE7DB, "acc_ctrr_b_upr_el2"},  // S3_4_c15_c11_3
    {0xE7DC, "acc_ctrr_a_ctl_el2"},  // S3_4_c15_c11_4
    {0xE7DD, "acc_ctrr_b_ctl_el2"},  // S3_4_c15_c11_5
    {0xE7DE, "agtcntpct_el0"},  // S3_4_c15_c11_6
    {0xE7DF, "agtcntvct_el0"},  // S3_4_c15_c11_7
    {0xE7E0, "acfg_el1"},  // S3_4_c15_c12_0
    {0xE7E1, "ahcr_el2"},  // S3_4_c15_c12_1
    {0xE7E2, "apl_intstatus_el1"},  // S3_4_c15_c12_2
    {0xE7E3, "apl_intstatus_el2"},  // S3_4_c15_c12_3
    {0xE7E6, "agtcnthctl_el2"},  // S3_4_c15_c12_6
    {0xE7E8, "japiakeylo_el2"},  // S3_4_c15_c13_0
    {0xE7E9, "japiakeyhi_el2"},  // S3_4_c15_c13_1
    {0xE7EA, "japibkeylo_el2"},  // S3_4_c15_c13_2
    {0xE7EB, "japibkeyhi_el2"},  // S3_4_c15_c13_3
    {0xE7EC, "japiakeylo_el1"},  // S3_4_c15_c13_4
    {0xE7ED, "japiakeyhi_el1"},  // S3_4_c15_c13_5
    {0xE7EE, "japibkeylo_el1"},  // S3_4_c15_c13_6
    {0xE7EF, "japibkeyhi_el1"},  // S3_4_c15_c13_7
    {0xE7F0, "japiakeylo_el12"},  // S3_4_c15_c14_0
    {0xE7F1, "japiakeyhi_el12"},  // S3_4_c15_c14_1
    {0xE7F2, "japibkeylo_el12"},  // S3_4_c15_c14_2
    {0xE7F3, "japibkeyhi_el12"},  // S3_4_c15_c14_3
    {0xE7F5, "agtcntrdir_el2"},  // S3_4_c15_c14_5
    {0xE7F6, "agtcntrdir_el12"},  // S3_4_c15_c14_6
    {0xE7F8, "jrange_el2"},  // S3_4_c15_c15_0
    {0xE7F9, "jrange_el1"},  // S3_4_c15_c15_1
    {0xE7FA, "jrange_el12"},  // S3_4_c15_c15_2
    {0xE7FB, "jctl_el2"},  // S3_4_c15_c15_3
    {0xE7FC, "jctl_el1"},  // S3_4_c15_c15_4
    {0xE7FD, "jctl_el12"},  // S3_4_c15_c15_5
    {0xE7FE, "jctl_el0"},  // S3_4_c15_c15_6
    {0xE7FF, "amdscr_el1"},  // S3_4_c15_c15_7
    {0xEF80, "ipi_rr_local_el1"},  // S3_5_c15_c0_0
    {0xEF81, "ipi_rr_global_el1"},  // S3_5_c15_c0_1
    {0xEF82, "af_err_cfg0"},  // S3_5_c15_c0_2
    {0xEF83, "ap_err_cfg0"},  // S3_5_c15_c0_3
    {0xEF84, "af_err_src_ids"},  // S3_5_c15_c0_4
    {0xEF85, "dpc_err_sts"},  // S3_5_c15_c0_5
    {0xEF86, "dpc_err_ctl"},  // S3_5_c15_c0_6
    {0xEF87, "prod_trc_core_cfg_el1"},  // S3_5_c15_c0_7
    {0xEF88, "trace_core_cfg"},  // S3_5_c15_c1_0
    {0xEF89, "ipi_sr"},  // S3_5_c15_c1_1
    {0xEF8A, "apl_lrtmr_el2"},  // S3_5_c15_c1_2
    {0xEF8B, "apl_intenable_el2"},  // S3_5_c15_c1_3
    {0xEF8C, "ktrace_message"},  // S3_5_c15_c1_4
    {0xEF8D, "trace_core_cfg_ext"},  // S3_5_c15_c1_5
    {0xEF8E, "prod_trc_core_cfg_el2"},  // S3_5_c15_c1_6
    {0xEF8F, "hid_prod_trc_core_cfg_el1"},  // S3_5_c15_c1_7
    {0xEF90, "dbg_wrap_glb"},  // S3_5_c15_c2_0
    {0xEF91, "trace_stream_base"},  // S3_5_c15_c2_1
    {0xEF92, "trace_stream_fill"},  // S3_5_c15_c2_2
    {0xEF93, "trace_stream_base1"},  // S3_5_c15_c2_3
    {0xEF94, "trace_stream_fill1"},  // S3_5_c15_c2_4
    {0xEF95, "trace_stream_irq"},  // S3_5_c15_c2_5
    {0xEF96, "watchdogdiag0"},  // S3_5_c15_c2_6
    {0xEF97, "watchdogdiag1"},  // S3_5_c15_c2_7
    {0xEF98, "trace_aux_ctl"},  // S3_5_c15_c3_0
    {0xEF99, "ipi_cr"},  // S3_5_c15_c3_1
    {0xEF9A, "utrig_event"},  // S3_5_c15_c3_2
    {0xEF9B, "hid_prod_trc_mask_el1"},  // S3_5_c15_c3_3
    {0xEF9C, "trace_ctl"},  // S3_5_c15_c3_4
    {0xEF9D, "trace_dat"},  // S3_5_c15_c3_5
    {0xEF9E, "prod_trc_strm_base0_gl2"},  // S3_5_c15_c3_6
    {0xEF9F, "prod_trc_strm_base1_gl2"},  // S3_5_c15_c3_7
    {0xEFA0, "cpu_cfg"},  // S3_5_c15_c4_0
    {0xEFA1, "pblk_sts"},  // S3_5_c15_c4_1
    {0xEFA3, "prod_trc_ctl_el1"},  // S3_5_c15_c4_3
    {0xEFA4, "prod_trc_strm_base0_gl1"},  // S3_5_c15_c4_4
    {0xEFA5, "prod_trc_strm_base1_gl1"},  // S3_5_c15_c4_5
    {0xEFA6, "prod_trc_strm_fiq_el1"},  // S3_5_c15_c4_6
    {0xEFA8, "cpu_ovrd"},  // S3_5_c15_c5_0
    {0xEFAA, "pblk_exe_st"},  // S3_5_c15_c5_2
    {0xEFAD, "prod_trc_core_gl_ctl_gl1"},  // S3_5_c15_c5_5
    {0xEFAE, "prod_trc_core_gl_ctl_gl2"},  // S3_5_c15_c5_6
    {0xEFB0, "acc_ovrd"},  // S3_5_c15_c6_0
    {0xEFB1, "acc_ovrd1"},  // S3_5_c15_c6_1
    {0xEFB2, "cpm_pwrdn_ctl"},  // S3_5_c15_c6_2
    {0xEFB4, "prod_trc_buf_restore0_gl1"},  // S3_5_c15_c6_4
    {0xEFB5, "prod_trc_buf_restore1_gl1"},  // S3_5_c15_c6_5
    {0xEFB6, "prod_trc_en_gl1"},  // S3_5_c15_c6_6
    {0xEFB8, "pre_llcflush_tmr"},  // S3_5_c15_c7_0
    {0xEFBC, "biuintfctl_cfg"},  // S3_5_c15_c7_4
    {0xEFBD, "biuintfwrr_cfg"},  // S3_5_c15_c7_5
    {0xEFC0, "pre_td_tmr"},  // S3_5_c15_c8_0
    {0xEFC1, "acc_slp_wake_up_tmr"},  // S3_5_c15_c8_1
    {0xEFC8, "pblk_psw_dly"},  // S3_5_c15_c9_0
    {0xEFD0, "cpu_sts"},  // S3_5_c15_c10_0
    {0xEFD1, "hist_trig"},  // S3_5_c15_c10_1
    {0xEFD4, "prod_trc_buf_restore0_gl2"},  // S3_5_c15_c10_4
    {0xEFD5, "prod_trc_buf_restore1_gl2"},  // S3_5_c15_c10_5
    {0xEFD6, "prod_trc_strm_fill0_el1"},  // S3_5_c15_c10_6
    {0xEFD7, "prod_trc_strm_fill1_el1"},  // S3_5_c15_c10_7
    {0xEFD8, "array_index"},  // S3_5_c15_c11_0
    {0xEFD9, "prod_trc_ctl_el2"},  // S3_5_c15_c11_1
    {0xEFDA, "prod_trc_en_gl2"},  // S3_5_c15_c11_2
    {0xEFDB, "prod_trc_strm_fiq_el2"},  // S3_5_c15_c11_3
    {0xEFDC, "prod_trc_cpmu_dump_trig_el1"},  // S3_5_c15_c11_4
    {0xEFDD, "prod_loss_count_el1"},  // S3_5_c15_c11_5
    {0xEFDE, "sw_trace_data_el0"},  // S3_5_c15_c11_6
    {0xEFE0, "il1_data0"},  // S3_5_c15_c12_0
    {0xEFE1, "il1_data1"},  // S3_5_c15_c12_1
    {0xEFE2, "dl1_data0"},  // S3_5_c15_c12_2
    {0xEFE3, "dl1_data1"},  // S3_5_c15_c12_3
    {0xEFE4, "mmudata0"},  // S3_5_c15_c12_4
    {0xEFE5, "mmudata1"},  // S3_5_c15_c12_5
    {0xEFE6, "dl1_data2"},  // S3_5_c15_c12_6
    {0xEFE7, "il1_data2"},  // S3_5_c15_c12_7
    {0xEFEC, "llc_data0"},  // S3_5_c15_c13_4
    {0xEFED, "llc_data1"},  // S3_5_c15_c13_5
    {0xF780, "mmu_err_sts"},  // S3_6_c15_c0_0
    {0xF781, "afsr1_gl1"},  // S3_6_c15_c0_1
    {0xF782, "afsr1_gl2"},  // S3_6_c15_c0_2
    {0xF783, "afsr1_gl12"},  // S3_6_c15_c0_3
    {0xF784, "bp_objc_adr_el1"},  // S3_6_c15_c0_4
    {0xF785, "bp_objc_ctl_el1"},  // S3_6_c15_c0_5
    {0xF786, "sp_gl11"},  // S3_6_c15_c0_6
    {0xF787, "mmu_sesr_el2"},  // S3_6_c15_c0_7
    {0xF788, "sprr_config_el1"},  // S3_6_c15_c1_0
    {0xF789, "hpfar_gl2"},  // S3_6_c15_c1_1
    {0xF78A, "gxf_config_el1"},  // S3_6_c15_c1_2
    {0xF78B, "sprr_amrange_el1"},  // S3_6_c15_c1_3
    {0xF78C, "gxf_config_el2"},  // S3_6_c15_c1_4
    {0xF78D, "sprr_uperm_el0"},  // S3_6_c15_c1_5
    {0xF78E, "sprr_pperm_el1"},  // S3_6_c15_c1_6
    {0xF78F, "sprr_pperm_el2"},  // S3_6_c15_c1_7
    {0xF791, "apgakeylo_el12"},  // S3_6_c15_c2_1
    {0xF792, "apgakeyhi_el12"},  // S3_6_c15_c2_2
    {0xF793, "kernkeylo_el12"},  // S3_6_c15_c2_3
    {0xF794, "kernkeyhi_el12"},  // S3_6_c15_c2_4
    {0xF795, "afpcr_el0"},  // S3_6_c15_c2_5
    {0xF796, "sp_gl22"},  // S3_6_c15_c2_6
    {0xF797, "amxidr_el1"},  // S3_6_c15_c2_7
    {0xF798, "sprr_umprr_el1"},  // S3_6_c15_c3_0
    {0xF799, "sprr_pmprr_el1"},  // S3_6_c15_c3_1
    {0xF79A, "sprr_pmprr_el2"},  // S3_6_c15_c3_2
    {0xF79B, "sprr_uperm_sh01_el1"},  // S3_6_c15_c3_3
    {0xF79C, "sprr_uperm_sh02_el1"},  // S3_6_c15_c3_4
    {0xF79D, "sprr_uperm_sh03_el1"},  // S3_6_c15_c3_5
    {0xF79E, "sprr_uperm_sh04_el1"},  // S3_6_c15_c3_6
    {0xF79F, "sprr_uperm_sh05_el1"},  // S3_6_c15_c3_7
    {0xF7A0, "sprr_uperm_sh06_el1"},  // S3_6_c15_c4_0
    {0xF7A1, "sprr_uperm_sh07_el1"},  // S3_6_c15_c4_1
    {0xF7A2, "sprr_pperm_sh01_el1"},  // S3_6_c15_c4_2
    {0xF7A3, "sprr_pperm_sh02_el1"},  // S3_6_c15_c4_3
    {0xF7A4, "sprr_pperm_sh03_el1"},  // S3_6_c15_c4_4
    {0xF7A5, "sprr_pperm_sh04_el1"},  // S3_6_c15_c4_5
    {0xF7A6, "sprr_pperm_sh05_el1"},  // S3_6_c15_c4_6
    {0xF7A7, "sprr_pperm_sh06_el1"},  // S3_6_c15_c4_7
    {0xF7A8, "sprr_pperm_sh07_el1"},  // S3_6_c15_c5_0
    {0xF7A9, "sprr_pperm_sh01_el2"},  // S3_6_c15_c5_1
    {0xF7AA, "sprr_pperm_sh02_el2"},  // S3_6_c15_c5_2
    {0xF7AB, "sprr_pperm_sh03_el2"},  // S3_6_c15_c5_3
    {0xF7AC, "sprr_pperm_sh04_el2"},  // S3_6_c15_c5_4
    {0xF7AD, "sprr_pperm_sh05_el2"},  // S3_6_c15_c5_5
    {0xF7AE, "sprr_pperm_sh06_el2"},  // S3_6_c15_c5_6
    {0xF7AF, "sprr_pperm_sh07_el2"},  // S3_6_c15_c5_7
    {0xF7B0, "sprr_pmprr_el12"},  // S3_6_c15_c6_0
    {0xF7B1, "sprr_pperm_sh01_el12"},  // S3_6_c15_c6_1
    {0xF7B2, "sprr_pperm_sh02_el12"},  // S3_6_c15_c6_2
    {0xF7B3, "sprr_pperm_sh03_el12"},  // S3_6_c15_c6_3
    {0xF7B4, "sprr_pperm_sh04_el12"},  // S3_6_c15_c6_4
    {0xF7B5, "sprr_pperm_sh05_el12"},  // S3_6_c15_c6_5
    {0xF7B6, "sprr_pperm_sh06_el12"},  // S3_6_c15_c6_6
    {0xF7B7, "sprr_pperm_sh07_el12"},  // S3_6_c15_c6_7
    {0xF7B8, "apiakeylo_el12"},  // S3_6_c15_c7_0
    {0xF7B9, "apiakeyhi_el12"},  // S3_6_c15_c7_1
    {0xF7BA, "apibkeylo_el12"},  // S3_6_c15_c7_2
    {0xF7BB, "apibkeyhi_el12"},  // S3_6_c15_c7_3
    {0xF7BC, "apdakeylo_el12"},  // S3_6_c15_c7_4
    {0xF7BD, "apdakeyhi_el12"},  // S3_6_c15_c7_5
    {0xF7BE, "apdbkeylo_el12"},  // S3_6_c15_c7_6
    {0xF7BF, "apdbkeyhi_el12"},  // S3_6_c15_c7_7
    {0xF7C0, "currentg"},  // S3_6_c15_c8_0
    {0xF7C1, "gxf_entry_el1"},  // S3_6_c15_c8_1
    {0xF7C2, "gxf_pabentry_el1"},  // S3_6_c15_c8_2
    {0xF7C3, "aspsr_el1"},  // S3_6_c15_c8_3
    {0xF7C4, "adspsr_el0"},  // S3_6_c15_c8_4
    {0xF7C5, "pmcr1_gl2"},  // S3_6_c15_c8_5
    {0xF7C6, "aspsr_el2"},  // S3_6_c15_c8_6
    {0xF7C7, "pmcr1_gl1"},  // S3_6_c15_c8_7
    {0xF7CA, "vbar_gl12"},  // S3_6_c15_c9_2
    {0xF7CB, "spsr_gl12"},  // S3_6_c15_c9_3
    {0xF7CC, "aspsr_gl12"},  // S3_6_c15_c9_4
    {0xF7CD, "esr_gl12"},  // S3_6_c15_c9_5
    {0xF7CE, "elr_gl12"},  // S3_6_c15_c9_6
    {0xF7CF, "far_gl12"},  // S3_6_c15_c9_7
    {0xF7D0, "sp_gl1"},  // S3_6_c15_c10_0
    {0xF7D1, "tpidr_gl1"},  // S3_6_c15_c10_1
    {0xF7D2, "vbar_gl1"},  // S3_6_c15_c10_2
    {0xF7D3, "spsr_gl1"},  // S3_6_c15_c10_3
    {0xF7D4, "aspsr_gl1"},  // S3_6_c15_c10_4
    {0xF7D5, "esr_gl1"},  // S3_6_c15_c10_5
    {0xF7D6, "elr_gl1"},  // S3_6_c15_c10_6
    {0xF7D7, "far_gl1"},  // S3_6_c15_c10_7
    {0xF7D8, "sp_gl2"},  // S3_6_c15_c11_0
    {0xF7D9, "tpidr_gl2"},  // S3_6_c15_c11_1
    {0xF7DA, "vbar_gl2"},  // S3_6_c15_c11_2
    {0xF7DB, "spsr_gl2"},  // S3_6_c15_c11_3
    {0xF7DC, "aspsr_gl2"},  // S3_6_c15_c11_4
    {0xF7DD, "esr_gl2"},  // S3_6_c15_c11_5
    {0xF7DE, "elr_gl2"},  // S3_6_c15_c11_6
    {0xF7DF, "far_gl2"},  // S3_6_c15_c11_7
    {0xF7E0, "gxf_entry_el2"},  // S3_6_c15_c12_0
    {0xF7E1, "gxf_pabentry_el2"},  // S3_6_c15_c12_1
    {0xF7E2, "apctl_el2"},  // S3_6_c15_c12_2
    {0xF7E3, "apsts_el2"},  // S3_6_c15_c12_3
    {0xF7E4, "apsts_el1"},  // S3_6_c15_c12_4
    {0xF7E5, "kernkeylo_el2"},  // S3_6_c15_c12_5
    {0xF7E6, "kernkeyhi_el2"},  // S3_6_c15_c12_6
    {0xF7E7, "aspsr_el12"},  // S3_6_c15_c12_7
    {0xF7E8, "apiakeylo_el2"},  // S3_6_c15_c13_0
    {0xF7E9, "apiakeyhi_el2"},  // S3_6_c15_c13_1
    {0xF7EA, "apibkeylo_el2"},  // S3_6_c15_c13_2
    {0xF7EB, "apibkeyhi_el2"},  // S3_6_c15_c13_3
    {0xF7EC, "apdakeylo_el2"},  // S3_6_c15_c13_4
    {0xF7ED, "apdakeyhi_el2"},  // S3_6_c15_c13_5
    {0xF7EE, "apdbkeylo_el2"},  // S3_6_c15_c13_6
    {0xF7EF, "apdbkeyhi_el2"},  // S3_6_c15_c13_7
    {0xF7F0, "apgakeylo_el2"},  // S3_6_c15_c14_0
    {0xF7F1, "apgakeyhi_el2"},  // S3_6_c15_c14_1
    {0xF7F2, "sprr_config_el2"},  // S3_6_c15_c14_2
    {0xF7F3, "sprr_amrange_el2"},  // S3_6_c15_c14_3
    {0xF7F4, "vmkeylo_el2"},  // S3_6_c15_c14_4
    {0xF7F5, "vmkeyhi_el2"},  // S3_6_c15_c14_5
    {0xF7F6, "mmu_sfar_el2"},  // S3_6_c15_c14_6
    {0xF7F7, "apsts_el12"},  // S3_6_c15_c14_7
    {0xF7F8, "apctl_el12"},  // S3_6_c15_c15_0
    {0xF7F9, "gxf_config_el12"},  // S3_6_c15_c15_1
    {0xF7FA, "gxf_entry_el12"},  // S3_6_c15_c15_2
    {0xF7FB, "gxf_pabentry_el12"},  // S3_6_c15_c15_3
    {0xF7FC, "sprr_config_el12"},  // S3_6_c15_c15_4
    {0xF7FD, "sprr_amrange_el12"},  // S3_6_c15_c15_5
    {0xF7FE, "mmu_sesr_ctl_el2"},  // S3_6_c15_c15_6
    {0xF7FF, "sprr_pperm_el12"},  // S3_6_c15_c15_7
    {0xFF80, "pwrdnsave0"},  // S3_7_c15_c0_0
    {0xFF81, "nrg_acc_ctl"},  // S3_7_c15_c0_1
    {0xFF82, "aon_cnt0"},  // S3_7_c15_c0_2
    {0xFF83, "cpu_cnt0"},  // S3_7_c15_c0_3
    {0xFF84, "upmcr0_el1"},  // S3_7_c15_c0_4
    {0xFF85, "upmc8"},  // S3_7_c15_c0_5
    {0xFF86, "aon_cnt8"},  // S3_7_c15_c0_6
    {0xFF88, "pwrdnsave1"},  // S3_7_c15_c1_0
    {0xFF89, "core_nrg_acc_dat"},  // S3_7_c15_c1_1
    {0xFF8A, "aon_cnt_ctl0"},  // S3_7_c15_c1_2
    {0xFF8B, "cpu_cnt_ctl0"},  // S3_7_c15_c1_3
    {0xFF8C, "upmesr0_el1"},  // S3_7_c15_c1_4
    {0xFF8D, "upmc9"},  // S3_7_c15_c1_5
    {0xFF8E, "aon_cnt_ctl8"},  // S3_7_c15_c1_6
    {0xFF90, "acc_pwr_dn_save"},  // S3_7_c15_c2_0
    {0xFF91, "cpm_nrg_acc_dat"},  // S3_7_c15_c2_1
    {0xFF92, "aon_cnt1"},  // S3_7_c15_c2_2
    {0xFF93, "cpu_cnt1"},  // S3_7_c15_c2_3
    {0xFF94, "upmswctrl_el1"},  // S3_7_c15_c2_4
    {0xFF95, "upmc10"},  // S3_7_c15_c2_5
    {0xFF96, "aon_cnt9"},  // S3_7_c15_c2_6
    {0xFF99, "core_srm_nrg_acc_dat"},  // S3_7_c15_c3_1
    {0xFF9A, "aon_cnt_ctl1"},  // S3_7_c15_c3_2
    {0xFF9B, "cpu_cnt_ctl1"},  // S3_7_c15_c3_3
    {0xFF9C, "upmecm0_el1"},  // S3_7_c15_c3_4
    {0xFF9D, "upmc11"},  // S3_7_c15_c3_5
    {0xFF9E, "aon_cnt_ctl9"},  // S3_7_c15_c3_6
    {0xFFA0, "aon_cnt_ctl"},  // S3_7_c15_c4_0
    {0xFFA1, "cpm_srm_nrg_acc_dat"},  // S3_7_c15_c4_1
    {0xFFA2, "aon_cnt2"},  // S3_7_c15_c4_2
    {0xFFA3, "cpu_cnt2"},  // S3_7_c15_c4_3
    {0xFFA4, "upmecm1_el1"},  // S3_7_c15_c4_4
    {0xFFA5, "upmc12"},  // S3_7_c15_c4_5
    {0xFFA6, "aon_cnt10"},  // S3_7_c15_c4_6
    {0xFFA8, "cpu_cnt_ctl"},  // S3_7_c15_c5_0
    {0xFFAA, "aon_cnt_ctl2"},  // S3_7_c15_c5_2
    {0xFFAB, "cpu_cnt_ctl2"},  // S3_7_c15_c5_3
    {0xFFAC, "upmpcm_el1"},  // S3_7_c15_c5_4
    {0xFFAD, "upmc13"},  // S3_7_c15_c5_5
    {0xFFAE, "aon_cnt_ctl10"},  // S3_7_c15_c5_6
    {0xFFB2, "aon_cnt3"},  // S3_7_c15_c6_2
    {0xFFB3, "cpu_cnt3"},  // S3_7_c15_c6_3
    {0xFFB4, "upmsr_el1"},  // S3_7_c15_c6_4
    {0xFFB5, "upmc14"},  // S3_7_c15_c6_5
    {0xFFB6, "aon_cnt11"},  // S3_7_c15_c6_6
    {0xFFBA, "aon_cnt_ctl3"},  // S3_7_c15_c7_2
    {0xFFBB, "cpu_cnt_ctl3"},  // S3_7_c15_c7_3
    {0xFFBC, "upmc0"},  // S3_7_c15_c7_4
    {0xFFBD, "upmc15"},  // S3_7_c15_c7_5
    {0xFFBE, "aon_cnt_ctl11"},  // S3_7_c15_c7_6
    {0xFFC2, "aon_cnt4"},  // S3_7_c15_c8_2
    {0xFFC3, "cpu_cnt4"},  // S3_7_c15_c8_3
    {0xFFC4, "upmc1"},  // S3_7_c15_c8_4
    {0xFFC5, "upmecm2_el1"},  // S3_7_c15_c8_5
    {0xFFCA, "aon_cnt_ctl4"},  // S3_7_c15_c9_2
    {0xFFCB, "cpu_cnt_ctl4"},  // S3_7_c15_c9_3
    {0xFFCC, "upmc2"},  // S3_7_c15_c9_4
    {0xFFCD, "upmecm3_el1"},  // S3_7_c15_c9_5
    {0xFFD2, "aon_cnt5"},  // S3_7_c15_c10_2
    {0xFFD3, "cpu_cnt5"},  // S3_7_c15_c10_3
    {0xFFD4, "upmc3"},  // S3_7_c15_c10_4
    {0xFFD5, "upmcr1_el1"},  // S3_7_c15_c10_5
    {0xFFDA, "aon_cnt_ctl5"},  // S3_7_c15_c11_2
    {0xFFDB, "cpu_cnt_ctl5"},  // S3_7_c15_c11_3
    {0xFFDC, "upmc4"},  // S3_7_c15_c11_4
    {0xFFDD, "upmesr1_el1"},  // S3_7_c15_c11_5
    {0xFFE2, "aon_cnt6"},  // S3_7_c15_c12_2
    {0xFFE3, "cpu_cnt6"},  // S3_7_c15_c12_3
    {0xFFE4, "upmc5"},  // S3_7_c15_c12_4
    {0xFFEA, "aon_cnt_ctl6"},  // S3_7_c15_c13_2
    {0xFFEB, "cpu_cnt_ctl6"},  // S3_7_c15_c13_3
    {0xFFEC, "upmc6"},  // S3_7_c15_c13_4
    {0xFFF2, "aon_cnt7"},  // S3_7_c15_c14_2
    {0xFFF3, "cpu_cnt7"},  // S3_7_c15_c14_3
    {0xFFF4, "upmc7"},  // S3_7_c15_c14_4
    {0xFFFA, "aon_cnt_ctl7"},  // S3_7_c15_c15_2
    {0xFFFB, "cpu_cnt_ctl7"},  // S3_7_c15_c15_3
};


const char* const SDSB_DOMAIN[4] = {"osh", "nsh", "ish", "sy"};

// AMX operation names indexed by the op field (bits [9:5])
// Op 17 is the enable/disable pair (set/clr) and is rendered specially.
// https://github.com/corsix/amx
const char* const AMX_OPS[23] = {
	"ldx", "ldy", "stx", "sty", "ldz", "stz", "ldzi", "stzi", "extrx", "extry", "fma64", "fms64",
	"fma32", "fms32", "mac16", "fma16", "fms16", "set", "vecint", "vecfp", "matint", "matfp", "genlut",
};

bool Decode(uint32_t insn, AppleVendorInsn& out)
{
	if ((insn & 0xffffffe0) == 0x00201420)  // genter #imm5
	{
		out.op = AV_GENTER;
		out.imm = insn & 0x1f;
		return true;
	}
	if (insn == 0x00201400)  // gexit
	{
		out.op = AV_GEXIT;
		return true;
	}
	if ((insn & 0xfffffffc) == 0x00201460)  // sdsb <domain>
	{
		out.op = AV_SDSB;
		out.imm = insn & 0x3;
		return true;
	}
	if ((insn & 0xffffffe0) == 0x00201440)  // at_as1elx <Xt>
	{
		out.op = AV_AT_AS1ELX;
		out.rd = insn & 0x1f;
		return true;
	}
	if ((insn & 0xfffffc00) == 0x00200800)  // wkdmc <Xd>, <Xs>
	{
		out.op = AV_WKDMC;
		out.rd = (insn >> 5) & 0x1f;
		out.rs = insn & 0x1f;
		return true;
	}
	if ((insn & 0xfffffc00) == 0x00200c00)  // wkdmd <Xd>, <Xs>
	{
		out.op = AV_WKDMD;
		out.rd = (insn >> 5) & 0x1f;
		out.rs = insn & 0x1f;
		return true;
	}
	if ((insn & 0xfffffc00) == 0x00201000)  // AMX: 0x00201000 | op<<5 | operand
	{
		uint32_t op = (insn >> 5) & 0x1f;
		if (op <= 22)  // ops 23-31 are reserved holes that fault as undefined
		{
			out.op = AV_AMX;
			out.imm = op;           // AMX operation number
			out.rd = insn & 0x1f;   // GPR operand (or set/clr selector for op 17)
			return true;
		}
	}
	if ((insn & 0xfffff800) == 0x00200000)  // mul53lo/mul53hi <Vd>.2d, <Vm>.2d
	{
		// Bit 10 selects hi vs lo. The source field is at bits [9:5]. This placement (rather than
		// [12:8]) is the only one consistent with bit 10 acting as the lo/hi selector.
		//
		// TODO: Confirm how the source vector register is encoded.
		out.op = (insn & 0x400) ? AV_MUL53HI : AV_MUL53LO;
		out.rd = insn & 0x1f;
		out.rs = (insn >> 5) & 0x1f;
		return true;
	}
	return false;
}

string GprName(uint32_t field)
{
	return field == 31 ? "xzr" : "x" + to_string(field);
}

string VecName(uint32_t field)
{
	return "v" + to_string(field);
}

uint32_t GprReg(uint32_t field)
{
	return field == 31 ? REG_XZR : (REG_X0 + field);
}

uint32_t VecReg(uint32_t field)
{
	return REG_V0 + field;
}

void EmitMnemonic(const char* mnemonic, vector<InstructionTextToken>& result)
{
	result.emplace_back(InstructionToken, mnemonic);
	size_t len = strlen(mnemonic);
	string pad = len < 8 ? string(8 - len, ' ') : string(1, ' ');
	result.emplace_back(TextToken, pad);
}

void EmitRegister(const string& name, vector<InstructionTextToken>& result)
{
	result.emplace_back(RegisterToken, name);
}

}  // namespace

bool AppleVendorGetInstructionInfo(uint32_t insn, uint64_t addr, InstructionInfo& result)
{
	(void)addr;
	AppleVendorInsn decoded;
	if (!Decode(insn, decoded))
		return false;

	result.length = 4;
	switch (decoded.op)
	{
	case AV_GENTER:
		// genter enters the monitor like an exception entry. Control returns after the handler for
		// the common (non-terminal) selectors.
		result.AddBranch(SystemCall);
		break;
	case AV_GEXIT:
		// gexit returns from guarded mode and does not fall through, like eret.
		result.AddBranch(FunctionReturn);
		break;
	default:
		break;
	}
	return true;
}

bool AppleVendorGetInstructionText(uint32_t insn, vector<InstructionTextToken>& result)
{
	AppleVendorInsn decoded;
	if (!Decode(insn, decoded))
		return false;

	switch (decoded.op)
	{
	case AV_GENTER:
		EmitMnemonic("genter", result);
		result.emplace_back(TextToken, "#");
		result.emplace_back(IntegerToken, fmt::format("{:#x}", decoded.imm), decoded.imm);
		break;
	case AV_GEXIT:
		EmitMnemonic("gexit", result);
		break;
	case AV_SDSB:
		EmitMnemonic("sdsb", result);
		result.emplace_back(TextToken, SDSB_DOMAIN[decoded.imm]);
		break;
	case AV_WKDMC:
	case AV_WKDMD:
		EmitMnemonic(decoded.op == AV_WKDMC ? "wkdmc" : "wkdmd", result);
		EmitRegister(GprName(decoded.rd), result);
		result.emplace_back(OperandSeparatorToken, ", ");
		EmitRegister(GprName(decoded.rs), result);
		break;
	case AV_AT_AS1ELX:
		EmitMnemonic("at_as1elx", result);
		EmitRegister(GprName(decoded.rd), result);
		break;
	case AV_MUL53LO:
	case AV_MUL53HI:
		EmitMnemonic(decoded.op == AV_MUL53LO ? "mul53lo" : "mul53hi", result);
		EmitRegister(VecName(decoded.rd), result);
		result.emplace_back(TextToken, ".2d");
		result.emplace_back(OperandSeparatorToken, ", ");
		EmitRegister(VecName(decoded.rs), result);
		result.emplace_back(TextToken, ".2d");
		break;
	case AV_AMX:
	{
		// Op 17 is the enable/disable pair (amx_set/amx_clr) and carries no register operand.
		// Every other op takes a single GPR that holds a packed pointer/configuration word.
		string mnemonic = decoded.imm == 17 ? (decoded.rd == 1 ? "amx_clr" : "amx_set")
		                                    : string("amx_") + AMX_OPS[decoded.imm];
		EmitMnemonic(mnemonic.c_str(), result);
		if (decoded.imm != 17)
			EmitRegister(GprName(decoded.rd), result);
		break;
	}
	default:
		return false;
	}
	return true;
}

optional<bool> AppleVendorGetInstructionLowLevelIL(uint32_t insn, LowLevelILFunction& il)
{
	AppleVendorInsn decoded;
	if (!Decode(insn, decoded))
		return nullopt;

	switch (decoded.op)
	{
	case AV_GENTER:
		il.AddInstruction(il.Intrinsic({}, APPLE_INTRIN_GENTER, {il.Const(4, decoded.imm)}));
		break;
	case AV_GEXIT:
		// gexit returns from guarded mode like eret and does not fall through.
		il.AddInstruction(il.Intrinsic({}, APPLE_INTRIN_GEXIT, {}));
		il.AddInstruction(il.Trap(0));
		return false;
	case AV_SDSB:
		il.AddInstruction(il.Intrinsic({}, APPLE_INTRIN_SDSB, {il.Const(4, decoded.imm)}));
		break;
	case AV_WKDMC:
	case AV_WKDMD:
		// Xd and Xs are addresses. The result is written to the memory at Xd, and the only register
		// written is Xs, which receives a status word.
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(GprReg(decoded.rs))},
		    decoded.op == AV_WKDMC ? APPLE_INTRIN_WKDMC : APPLE_INTRIN_WKDMD,
		    {il.Register(8, GprReg(decoded.rd)), il.Register(8, GprReg(decoded.rs))}));
		break;
	case AV_AT_AS1ELX:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(GprReg(decoded.rd))}, APPLE_INTRIN_AT_AS1ELX,
		    {il.Register(8, GprReg(decoded.rd))}));
		break;
	case AV_MUL53LO:
	case AV_MUL53HI:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(VecReg(decoded.rd))},
		    decoded.op == AV_MUL53LO ? APPLE_INTRIN_MUL53LO : APPLE_INTRIN_MUL53HI,
		    {il.Register(16, VecReg(decoded.rd)), il.Register(16, VecReg(decoded.rs))}));
		break;
	case AV_AMX:
		// Not yet lifted.
		il.AddInstruction(il.Unimplemented());
		break;
	default:
		break;
	}
	return true;
}

std::string_view AppleVendorSystemRegisterName(uint32_t reg)
{
	auto found = std::lower_bound(std::begin(VENDOR_SYSTEM_REGISTERS),
	    std::end(VENDOR_SYSTEM_REGISTERS), reg,
	    [](const std::pair<uint32_t, std::string_view>& entry, uint32_t value) {
		    return entry.first < value;
	    });

	if (found == std::end(VENDOR_SYSTEM_REGISTERS) || found->first != reg)
		return {};

	return found->second;
}


void AppleVendorGetSystemRegisters(std::vector<uint32_t>& result)
{
	for (const auto& entry : VENDOR_SYSTEM_REGISTERS)
		result.push_back(entry.first);
}


bool AppleVendorIsIntrinsic(uint32_t intrinsic)
{
	return intrinsic >= APPLE_INTRIN_GENTER && intrinsic < APPLE_INTRIN_END;
}

void AppleVendorGetAllIntrinsics(vector<uint32_t>& result)
{
	for (uint32_t id = APPLE_INTRIN_GENTER; id < APPLE_INTRIN_END; id++)
		result.push_back(id);
}

string AppleVendorGetIntrinsicName(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case APPLE_INTRIN_GENTER:
		return "__genter";
	case APPLE_INTRIN_GEXIT:
		return "__gexit";
	case APPLE_INTRIN_SDSB:
		return "__sdsb";
	case APPLE_INTRIN_WKDMC:
		return "__wkdmc";
	case APPLE_INTRIN_WKDMD:
		return "__wkdmd";
	case APPLE_INTRIN_AT_AS1ELX:
		return "__at_as1elx";
	case APPLE_INTRIN_MUL53LO:
		return "__mul53lo";
	case APPLE_INTRIN_MUL53HI:
		return "__mul53hi";
	default:
		return "";
	}
}

BNIntrinsicClass AppleVendorGetIntrinsicClass(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case APPLE_INTRIN_WKDMC:
	case APPLE_INTRIN_WKDMD:
		return MemoryIntrinsicClass;
	default:
		return GeneralIntrinsicClass;
	}
}

vector<NameAndType> AppleVendorGetIntrinsicInputs(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case APPLE_INTRIN_GENTER:
		return {NameAndType("imm", Type::IntegerType(4, false))};
	case APPLE_INTRIN_SDSB:
		return {NameAndType("domain", Type::IntegerType(4, false))};
	case APPLE_INTRIN_WKDMC:
	case APPLE_INTRIN_WKDMD:
		return {NameAndType("dest", Type::PointerType(8, Type::VoidType())),
		    NameAndType("src", Type::PointerType(8, Type::VoidType()))};
	case APPLE_INTRIN_AT_AS1ELX:
		return {NameAndType(Type::IntegerType(8, false))};
	case APPLE_INTRIN_MUL53LO:
	case APPLE_INTRIN_MUL53HI:
		return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(16, false))};
	default:
		return {};
	}
}

vector<Confidence<Ref<Type>>> AppleVendorGetIntrinsicOutputs(uint32_t intrinsic)
{
	switch (intrinsic)
	{
	case APPLE_INTRIN_WKDMC:
	case APPLE_INTRIN_WKDMD:
	case APPLE_INTRIN_AT_AS1ELX:
		return {Type::IntegerType(8, false)};
	case APPLE_INTRIN_MUL53LO:
	case APPLE_INTRIN_MUL53HI:
		return {Type::IntegerType(16, false)};
	default:
		return {};
	}
}
